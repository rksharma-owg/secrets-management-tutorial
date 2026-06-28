# =============================================================================
# HashiCorp Vault - Production Terraform Configuration
# =============================================================================
# This module configures Vault resources for secrets management. It assumes
# a Vault server is already running and accessible. The module creates:
#   - KV v2 secrets engine mount with versioned secrets
#   - Application secrets (database, OpenAI, JWT)
#   - Least-privilege IAM policies
#   - Kubernetes auth method for workload identity
#   - Audit logging for compliance
#
# SECURITY MODEL:
#   - Secrets are encrypted at rest by Vault's barrier (AES-256-GCM)
#   - Kubernetes auth eliminates static credentials — pods authenticate
#     via their service account tokens (short-lived, auto-rotated by K8s)
#   - Policies follow least privilege: each application reads only its secrets
#   - Audit logs capture every secret access for forensics and compliance
# =============================================================================

terraform {
  # Enforce Terraform 1.5+ for improved plan output and test framework support
  required_version = ">= 1.5"

  required_providers {
    vault = {
      source  = "hashicorp/vault"
      version = "~> 4.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Vault Provider
# -----------------------------------------------------------------------------
# The Vault provider authenticates using a token. In production CI/CD pipelines:
#   1. Use the JWT/OIDC auth method to obtain a short-lived token
#   2. NEVER hardcode tokens in CI configuration — use pipeline secret stores
#   3. The token must have permissions to create mounts, policies, and secrets
# -----------------------------------------------------------------------------
provider "vault" {
  address = var.vault_addr

  # The token should be set via VAULT_TOKEN environment variable,
  # NOT hardcoded here. For CI/CD, use Vault's JWT auth to generate
  # a short-lived token with the minimum required permissions.
  # token = var.vault_token  # Prefer environment variable
}

# =============================================================================
# KV v2 Secrets Engine
# =============================================================================
# KV v2 provides versioned secrets with automatic version history, rollback,
# and soft-delete. Unlike KV v1, it maintains a full history of every secret
# version, enabling audit trails and point-in-time recovery.
#
# SECURITY: Mount the secrets engine at a non-default path to avoid
# collisions with other applications sharing the same Vault cluster.
# =============================================================================
resource "vault_mount" "kv_secrets" {
  path        = "secret-${var.environment}"
  type        = "kv"
  description = "KV v2 secrets engine for ${var.environment} environment"
  options     = { version = "2" }

  # Prevent accidental deletion of the secrets engine in production.
  # Deleting a mount destroys all secrets and their version history.
  lifecycle {
    prevent_destroy = var.environment == "prod" ? true : false
  }
}

# =============================================================================
# Secrets - Application Credentials
# =============================================================================

# -----------------------------------------------------------------------------
# Database Credentials
# -----------------------------------------------------------------------------
# Stored as versioned key-value pairs. The KV v2 engine automatically
# maintains version history, allowing rollback if a new version is corrupted.
#
# SECURITY: Database credentials should be rotated by Vault's dynamic secrets
# (database secrets engine) in production. Static secrets (this approach)
# are acceptable when:
#   1. The database does not support dynamic credential generation
#   2. Rotation is handled by an external automation (e.g., AWS Secrets Manager)
#   3. The secret is a read-only replica credential with limited blast radius
# -----------------------------------------------------------------------------
resource "vault_kv_secret_v2" "database_credentials" {
  mount = vault_mount.kv_secrets.path
  path  = "database/credentials"

  # WARNING: Never commit actual secret values to version control.
  # Provide real values via a gitignored .tfvars file or external secret store.
  data_json = jsonencode({
    username = "db_app_user"
    password = "CHANGE_ME_IN_TFVARS"
    host     = "postgres-vault.internal.example.com"
    port     = 5432
    database = "app_${var.environment}"
    engine   = "postgresql"
    sslmode  = "require"
  })

  # Metadata helps with audit and secret discovery without exposing values
  custom_metadata = {
    rotated_by   = "terraform"
    last_review  = "2025-01-01"
    classification = "confidential"
  }
}

# -----------------------------------------------------------------------------
# OpenAI API Key
# -----------------------------------------------------------------------------
# Stored as a flat key-value pair since it is a single credential value.
# Keeping API keys in Vault (rather than environment variables) enables:
#   1. Centralized rotation across multiple application instances
#   2. Audit logging of every access
#   3. Instant revocation without redeploying applications
# -----------------------------------------------------------------------------
resource "vault_kv_secret_v2" "openai_api_key" {
  mount = vault_mount.kv_secrets.path
  path  = "integrations/openai"

  # WARNING: Never commit actual secret values to version control.
  data_json = jsonencode({
    api_key  = "sk-PLACEHOLDER_REPLACE_IN_TFVARS"
    model    = "gpt-4"
    endpoint = "https://api.openai.com/v1"
  })

  custom_metadata = {
    classification = "confidential"
    owner          = "ml-team"
  }
}

# -----------------------------------------------------------------------------
# JWT Configuration
# -----------------------------------------------------------------------------
# Stores JWT signing material and token configuration. The secret key is
# the most sensitive value — it can be used to forge authentication tokens.
#
# SECURITY: For production, consider using Vault's Transit secrets engine
# to perform signing operations server-side, so the private key never
# leaves Vault. This approach eliminates the risk of key exfiltration.
# -----------------------------------------------------------------------------
resource "vault_kv_secret_v2" "jwt_config" {
  mount = vault_mount.kv_secrets.path
  path  = "auth/jwt-config"

  # WARNING: Never commit actual secret values to version control.
  data_json = jsonencode({
    algorithm        = "HS256"
    secret_key       = "CHANGE_ME_GENERATE_256BIT_KEY"
    token_expiry_min = 60
    refresh_expiry_h = 24
    issuer           = "${var.environment}.app.example.com"
  })

  custom_metadata = {
    classification = "confidential"
    owner          = "auth-team"
  }
}

# =============================================================================
# Policy - Least Privilege Access
# =============================================================================
# Vault policies are written in HCL and define exact capabilities on
# specific paths. This policy grants read-only access ("read") to the
# three secret paths. It explicitly does NOT grant:
#   - "create", "update", "delete" — no write or destructive operations
#   - "list" on parent paths — prevents secret path discovery/enumeration
#   - "sudo" — no admin escalation
#
# The capabilities are specified individually per path rather than using
# wildcards to enforce strict least privilege.
# =============================================================================
resource "vault_policy" "application_secrets_reader" {
  name = "${var.environment}-application-secrets-reader"

  # HCL policy document
  policy = <<EOT
# =============================================================================
# Application Secrets Reader Policy — ${var.environment}
# =============================================================================
# Grants read-only access to specific secret paths required by the application.
# This policy follows the principle of least privilege: no write, no delete,
# no listing of sibling secrets.
# =============================================================================

# Database credentials — read only
path "${vault_mount.kv_secrets.path}/data/database/credentials" {
  capabilities = ["read"]
}

# OpenAI API key — read only
path "${vault_mount.kv_secrets.path}/data/integrations/openai" {
  capabilities = ["read"]
}

# JWT configuration — read only
path "${vault_mount.kv_secrets.path}/data/auth/jwt-config" {
  capabilities = ["read"]
}

# Deny all other paths explicitly (defense in depth)
# Even if additional policies are attached, this ensures
# no accidental broad access is granted.
path "${vault_mount.kv_secrets.path}/*" {
  capabilities = ["deny"]
}
EOT
}

# =============================================================================
# Kubernetes Authentication Method
# =============================================================================
# Kubernetes auth allows pods to authenticate to Vault using their
# Kubernetes service account tokens. This eliminates the need for:
#   1. Static Vault tokens embedded in container images
#   2. AppRole role IDs and secret IDs passed as environment variables
#   3. Manual token distribution to Kubernetes workloads
#
# SECURITY: The Kubernetes API server JWT is verified against the cluster's
# CA certificate, preventing spoofed tokens from being used for authentication.
# =============================================================================
resource "vault_auth_backend" "kubernetes" {
  type = "kubernetes"
  path = "kubernetes-${var.environment}"

  description = "Kubernetes auth method for ${var.environment} cluster workloads"

  lifecycle {
    prevent_destroy = var.environment == "prod" ? true : false
  }
}

# -----------------------------------------------------------------------------
# Kubernetes Auth Backend Configuration
# -----------------------------------------------------------------------------
# Configures the auth backend to trust the target Kubernetes cluster by
# validating tokens against the cluster's API server and CA certificate.
# -----------------------------------------------------------------------------
resource "vault_kubernetes_auth_backend_config" "kubernetes" {
  backend                = vault_auth_backend.kubernetes.path
  kubernetes_host        = var.kubernetes_host
  kubernetes_ca_cert     = var.kubernetes_ca_cert

  # Disable JWT validation ONLY in development. In production, always
  # validate the issuer claim to prevent token confusion attacks.
  disable_local_ca_jwt_verification = var.environment == "dev" ? true : false
}

# =============================================================================
# Kubernetes Auth Roles
# =============================================================================
# Each Kubernetes auth role maps a specific service account (namespace + name)
# to one or more Vault policies. When a pod authenticates, Vault verifies:
#   1. The service account token against the Kubernetes API server
#   2. The namespace and service account name match the role binding
#   3. The audience claim matches the configured audience
#
# This creates a secure, automatic credential flow:
#   Pod SA token → Vault Kubernetes auth → Vault policies → Secret access
# =============================================================================
resource "vault_kubernetes_auth_backend_role" "application" {
  count = length(var.application_names)

  backend                          = vault_auth_backend.kubernetes.path
  role_name                        = "${var.application_names[count.index]}-${var.environment}"
  bound_service_account_names      = ["${var.application_names[count.index]}-sa"]
  bound_service_account_namespaces = ["${var.environment}-${var.application_names[count.index]}"]
  token_policies                   = [vault_policy.application_secrets_reader.name]
  token_ttl                        = 3600      # 1 hour — align with pod restart frequency
  token_max_ttl                    = 14400     # 4 hours — absolute maximum
  token_num_uses                   = 0         # Unlimited uses within TTL

  # Audience claim on the service account token. Must match the
  # --service-account-issuer flag on the Kubernetes API server.
  audience = "vault"

  # Restrict which namespaces this role can generate tokens for.
  # This prevents a compromised pod in one namespace from accessing
  # secrets intended for a different namespace.
  token_bound_audiences = ["vault"]
}

# =============================================================================
# Audit Logging
# =============================================================================
# Audit logs record EVERY Vault API request including:
#   - Who authenticated (auth method, entity ID)
#   - What path was accessed
#   - Whether the request succeeded or failed
#
# SECURITY: Audit logs are critical for:
#   1. Forensic investigation after a security incident
#   2. Compliance requirements (SOC 2, HIPAA, PCI-DSS)
#   3. Detecting anomalous access patterns (e.g., a service reading
#      secrets it has never accessed before)
#   4. Alerting on failed authentication attempts
#
# In production, send audit logs to a tamper-evident storage system
# (e.g., Splunk, Datadog, or a file-based log shipped to S3 with
# object lock enabled).
# =============================================================================
resource "vault_audit" "file_audit" {
  type        = "file"
  path        = "file-${var.environment}"
  description = "File-based audit logging for ${var.environment}"

  options = {
    file_path = "/vault/audit/audit-${var.environment}.log"
    # Log format: jsonx (JSON with extra fields) for structured parsing
    format = "jsonx"
    # Prevent Vault from logging the secret values themselves.
    # Only the request path and metadata are logged.
    log_raw = false
  }
}