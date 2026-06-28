# =============================================================================
# AWS Secrets Manager - Output Values
# =============================================================================
# These outputs expose resource identifiers needed by downstream consumers:
#   - Application configurations (ECS task definitions, Lambda env vars)
#   - CI/CD pipelines that reference secret ARNs
#   - Monitoring and alerting systems
#
# SECURITY NOTE: Outputs are stored in terraform.tfstate in PLAINTEXT.
# These outputs contain ARNs and identifiers only — NOT secret values.
# Ensure your state file is stored securely (encrypted S3 backend + DynamoDB locking).
# =============================================================================

# -----------------------------------------------------------------------------
# Secret ARNs (Map)
# -----------------------------------------------------------------------------
# Provides a map of logical secret names to their ARNs. Applications use
# these ARNs with the AWS SDK (GetSecretValue API) or container environment
# variable references (e.g., arn:aws:secretsmanager:... in ECS task definition).
# -----------------------------------------------------------------------------
output "secret_arns" {
  description = "Map of secret logical names to their AWS ARNs. Used by applications to fetch secret values at runtime via the AWS SDK."
  value = {
    database_credentials = aws_secretsmanager_secret.database_credentials.arn
    openai_api_key       = aws_secretsmanager_secret.openai_api_key.arn
    jwt_config           = aws_secretsmanager_secret.jwt_config.arn
  }
}

# -----------------------------------------------------------------------------
# IAM Role ARN
# -----------------------------------------------------------------------------
# The ARN of the IAM role that applications should assume to read secrets.
# This role should be attached to ECS task definitions, EKS pod service
# accounts, Lambda functions, or EC2 instance profiles — never embedded as
# a static credential in application code.
# -----------------------------------------------------------------------------
output "iam_role_arn" {
  description = "ARN of the IAM role with read-only access to secrets. Attach this role to application compute resources (ECS, EKS, Lambda, EC2)."
  value       = aws_iam_role.application.arn
}

# -----------------------------------------------------------------------------
# Secrets Manager Endpoint
# -----------------------------------------------------------------------------
# The regional endpoint for Secrets Manager API calls. Applications should
# be configured to use VPC endpoints (interface endpoints) for Secrets Manager
# to keep traffic within the AWS network and avoid traversing the public internet.
# -----------------------------------------------------------------------------
output "secret_manager_endpoint" {
  description = "Regional AWS Secrets Manager service endpoint. Configure VPC endpoints for private network access."
  value       = "https://secretsmanager.${var.region}.amazonaws.com"
}