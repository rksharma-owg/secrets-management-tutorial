# =============================================================================
# AWS Secrets Manager - Production Terraform Configuration
# =============================================================================
# This module provisions AWS Secrets Manager resources for securely storing
# and rotating application secrets such as database credentials, API keys,
# and JWT configuration.
#
# SECURITY MODEL:
#   - Secrets are encrypted at rest using AWS KMS (default AWS-managed key)
#   - Automatic rotation reduces the window of credential compromise
#   - IAM roles follow least-privilege: applications only read specific secrets
#   - No long-lived IAM access keys are used; short-lived role assumptions only
# =============================================================================

terraform {
  # Enforce Terraform 1.5+ for improved plan output and test framework support
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# -----------------------------------------------------------------------------
# AWS Provider
# -----------------------------------------------------------------------------
# The provider authenticates using standard AWS credential chains. In production,
# prefer IAM roles (e.g., assumed via an OIDC provider for CI/CD) rather than
# long-lived access keys. Access keys can be leaked, rotated poorly, and lack
# fine-grained session controls that IAM roles provide (duration, MFA, conditions).
# -----------------------------------------------------------------------------
provider "aws" {
  region = var.region

  default_tags {
    tags = var.tags
  }
}

# =============================================================================
# Secrets Manager - Core Secret Resources
# =============================================================================

# -----------------------------------------------------------------------------
# Database Credentials Secret
# -----------------------------------------------------------------------------
# Stores database connection credentials as a JSON string. Using a structured
# JSON payload (rather than separate secrets for username/password) keeps
# related credentials atomic — they rotate together, reducing the risk of
# mismatched credentials during rotation windows.
#
# SECURITY: This secret is encrypted with the default AWS-managed KMS key
# (aws/secretsmanager). For regulatory compliance (HIPAA, PCI-DSS), consider
# a customer-managed KMS key with a key policy that restricts decryption
# to specific IAM roles.
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "database_credentials" {
  name                    = "${var.project_name}-${var.environment}/database/credentials"
  description             = "PostgreSQL database credentials for ${var.project_name} ${var.environment}"
  recovery_window_in_days = 30

  # Tags enable cost allocation, compliance auditing, and automated
  # lifecycle policies across environments.
  tags = {
    SecretType = "database"
    ManagedBy  = "terraform"
  }

  lifecycle {
    # Prevent accidental destruction of production secrets. A deleted secret
    # requires a 30-day recovery window and all dependent applications will
    # lose access immediately.
    prevent_destroy = var.environment == "prod" ? true : false
  }
}

# -----------------------------------------------------------------------------
# Database Credentials - Initial Version
# -----------------------------------------------------------------------------
# Sets the initial secret value. In production, the actual JSON value should
# be provided via a .tfvars file (gitignored) or fetched from a secure store.
#
# WARNING: Never commit actual secret values to version control. The value
# below is a placeholder. Real credentials MUST be supplied through
# terraform.tfvars, environment variables, or a secret store like HashiCorp Vault.
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret_version" "database_credentials" {
  secret_id = aws_secretsmanager_secret.database_credentials.id

  # WARNING: Never commit actual secret values to version control.
  # Provide real values via a gitignored .tfvars file.
  secret_string = jsonencode({
    username = "db_admin"
    password = "CHANGE_ME_IN_TFVARS"
    host     = "db.internal.example.com"
    port     = 5432
    database = "app_production"
    engine   = "postgresql"
  })
}

# -----------------------------------------------------------------------------
# OpenAI API Key Secret
# -----------------------------------------------------------------------------
# Stores the OpenAI API key as a plain-text string (not JSON), since it is
# a single value. Keeping this separate from database credentials follows
# the principle of secret isolation — a compromised application component
# that needs only the LLM key should not have access to database credentials.
#
# SECURITY: Rotate API keys regularly. OpenAI supports key rotation with
# a grace period, which should align with the rotation schedule below.
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "openai_api_key" {
  name                    = "${var.project_name}-${var.environment}/integrations/openai-api-key"
  description             = "OpenAI API key for ${var.project_name} ${var.environment}"
  recovery_window_in_days = 30

  tags = {
    SecretType = "api-key"
    ManagedBy  = "terraform"
  }

  lifecycle {
    prevent_destroy = var.environment == "prod" ? true : false
  }
}

resource "aws_secretsmanager_secret_version" "openai_api_key" {
  secret_id = aws_secretsmanager_secret.openai_api_key.id

  # WARNING: Never commit actual secret values to version control.
  # Provide real values via a gitignored .tfvars file.
  secret_string = "sk-PLACEHOLDER_REPLACE_IN_TFVARS"
}

# -----------------------------------------------------------------------------
# JWT Configuration Secret
# -----------------------------------------------------------------------------
# Stores JWT signing keys and configuration as a JSON payload. The secret key
# is used for signing and verifying authentication tokens. Rotating this secret
# requires coordination with token lifetime to avoid invalidating active sessions.
#
# SECURITY: Use a minimum 256-bit key for HS256. For higher security, store
# an asymmetric key pair and use RS256. Consider storing the public key in a
# non-secret location since it is not sensitive.
# -----------------------------------------------------------------------------
resource "aws_secretsmanager_secret" "jwt_config" {
  name                    = "${var.project_name}-${var.environment}/auth/jwt-config"
  description             = "JWT signing key and configuration for ${var.project_name} ${var.environment}"
  recovery_window_in_days = 30

  tags = {
    SecretType = "auth"
    ManagedBy  = "terraform"
  }

  lifecycle {
    prevent_destroy = var.environment == "prod" ? true : false
  }
}

resource "aws_secretsmanager_secret_version" "jwt_config" {
  secret_id = aws_secretsmanager_secret.jwt_config.id

  # WARNING: Never commit actual secret values to version control.
  # Provide real values via a gitignored .tfvars file.
  secret_string = jsonencode({
    algorithm        = "HS256"
    secret_key       = "CHANGE_ME_GENERATE_256BIT_KEY"
    token_expiry_min = 60
    refresh_expiry_h = 24
    issuer           = "${var.project_name}-${var.environment}"
  })
}

# =============================================================================
# Automatic Secret Rotation
# =============================================================================
# Rotation automatically updates secrets on a schedule without manual
# intervention. This is critical for compliance (SOC 2, PCI-DSS require
# credential rotation) and reduces the blast radius of credential theft.
#
# The rotation uses a Lambda function (not defined here) that implements
# the Secrets Manager rotation template. The Lambda must have permission
# to read/write the secret and access the target system (e.g., database)
# to validate new credentials.
# =============================================================================
resource "aws_secretsmanager_secret_rotation" "database_rotation" {
  # Only enable rotation when explicitly requested and a Lambda function ARN
  # is available. Attempting to enable rotation without a valid Lambda
  # will cause a perpetual rotation error.
  count = var.rotation_enabled ? 1 : 0

  secret_id           = aws_secretsmanager_secret.database_credentials.id
  rotation_lambda_arn = "arn:aws:lambda:${var.region}:123456789012:function:${var.project_name}-secret-rotation"

  # Automatically rotate secrets every 30 days (configurable).
  # Ensure this aligns with your organization's credential rotation policy.
  # Shorter intervals improve security but increase operational risk if
  # the rotation Lambda fails.
  rotation_rules {
    # Automatically schedule rotation every 30 days
    schedule_expression = "cron(0 12 ${var.rotation_schedule} * ? *)"

    # Window during which rotation can occur (UTC). Stagger rotation
    # windows across environments to avoid overwhelming shared resources.
    window_duration = "3h"
  }
}

# =============================================================================
# IAM - Least-Privilege Access
# =============================================================================
# WHY IAM ROLES OVER ACCESS KEYS:
#   1. No static credentials to leak or rotate manually.
#   2. Roles provide short-lived, dynamically scoped credentials via STS.
#   3. Role assumption can require MFA, source IP conditions, or external ID.
#   4. Access keys embedded in code/config are the #1 cause of cloud breaches.
#   5. Roles support cross-account access without distributing long-lived keys.
#
# This policy grants read-only access to ONLY the specific secrets this
# application needs. It does NOT grant access to create, delete, or rotate
# secrets — those are administrative actions reserved for CI/CD pipelines.
# =============================================================================

# -----------------------------------------------------------------------------
# Application IAM Role
# -----------------------------------------------------------------------------
# This role is assumed by the application runtime (ECS task, EKS pod, Lambda,
# or EC2 instance via instance profile). It has NO inline policies — all
# permissions are attached via managed policy references, making auditing
# and revocation straightforward.
# -----------------------------------------------------------------------------
resource "aws_iam_role" "application" {
  name = "${var.project_name}-${var.environment}-secrets-reader"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "ecs-tasks.amazonaws.com"
        }
        Action = "sts:AssumeRole"
        Condition = {
          # Restrict role assumption to the expected account. Prevents
          # confused deputy attacks from other AWS accounts.
          ArnLike = {
            "aws:SourceArn" = "arn:aws:ecs:${var.region}:${data.aws_caller_identity.current.account_id}:*"
          }
        }
      }
    ]
  })

  # Enforce a maximum session duration of 1 hour. Even if a compromised
  # process obtains credentials, they expire within this window.
  max_session_duration = 3600

  tags = {
    Purpose = "secrets-read-only"
  }
}

data "aws_caller_identity" "current" {}

# -----------------------------------------------------------------------------
# Least-Privilege Secrets Read Policy
# -----------------------------------------------------------------------------
# This policy grants ONLY GetSecretValue and DescribeSecret on the specific
# secrets this application needs. It explicitly does NOT grant:
#   - DeleteSecret, RestoreSecret (destructive operations)
#   - CreateSecret, UpdateSecret (write operations)
#   - RotateSecret (administrative operation)
#   - ListSecrets (discovery / information disclosure)
#
# The secret ARNs are specified individually rather than using a wildcard
# (e.g., "arn:aws:secretsmanager:*:*:secret:${var.project_name}-*") to
# prevent access to any future secrets created under the same prefix.
# -----------------------------------------------------------------------------
resource "aws_iam_policy" "secrets_read_only" {
  name        = "${var.project_name}-${var.environment}-secrets-readonly"
  description = "Read-only access to specific ${var.project_name} secrets (least privilege)"
  path        = "/application/"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "GetSecretValue"
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "secretsmanager:DescribeSecret"
        ]
        Resource = [
          aws_secretsmanager_secret.database_credentials.arn,
          aws_secretsmanager_secret.openai_api_key.arn,
          aws_secretsmanager_secret.jwt_config.arn,
        ]
      },
      {
        Sid    = "DecryptSecret"
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        # Allow decryption with the default Secrets Manager KMS key.
        # If using a customer-managed KMS key, replace with that key ARN.
        Resource = "arn:aws:kms:${var.region}:${data.aws_caller_identity.current.account_id}:key/*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "secretsmanager.${var.region}.amazonaws.com"
          }
        }
      }
    ]
  })
}

# -----------------------------------------------------------------------------
# Policy Attachment
# -----------------------------------------------------------------------------
# Attaches the least-privilege policy to the application role. Using
# aws_iam_role_policy_attachment (rather than inline policies) ensures
# the policy can be audited, detached, and reattached independently
# of the role lifecycle.
# -----------------------------------------------------------------------------
resource "aws_iam_role_policy_attachment" "secrets_read_only" {
  role       = aws_iam_role.application.name
  policy_arn = aws_iam_policy.secrets_read_only.arn
}