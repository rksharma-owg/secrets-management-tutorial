# =============================================================================
# HashiCorp Vault - Output Values
# =============================================================================
# These outputs expose resource identifiers for downstream configuration:
#   - Application startup scripts (to verify secret paths exist)
#   - Monitoring/alerting systems (to validate policy attachments)
#   - CI/CD pipelines (for integration testing)
#
# SECURITY NOTE: These outputs contain paths and names only — NOT secret values.
# Vault secret values never pass through Terraform state.
# =============================================================================

# -----------------------------------------------------------------------------
# Secret Paths
# -----------------------------------------------------------------------------
# The full Vault paths where secrets are stored. Applications reference these
# paths in their Vault client libraries (e.g., vault_client.kv.v2.read()).
# The paths are environment-scoped to prevent cross-environment access.
# -----------------------------------------------------------------------------
output "secret_paths" {
  description = "Map of secret logical names to their Vault KV v2 paths. Applications use these paths to read secrets at runtime."
  value = {
    database_credentials = "${vault_mount.kv_secrets.path}/data/database/credentials"
    openai_api_key       = "${vault_mount.kv_secrets.path}/data/integrations/openai"
    jwt_config           = "${vault_mount.kv_secrets.path}/data/auth/jwt-config"
  }
}

# -----------------------------------------------------------------------------
# Policy Names
# -----------------------------------------------------------------------------
# The names of Vault policies created by this module. Useful for auditing
# and for attaching additional policies in downstream Terraform modules.
# -----------------------------------------------------------------------------
output "policy_names" {
  description = "List of Vault policy names created by this module. Used for auditing and downstream policy composition."
  value       = [vault_policy.application_secrets_reader.name]
}

# -----------------------------------------------------------------------------
# Auth Backend Path
# -----------------------------------------------------------------------------
# The mount path of the Kubernetes auth method. Applications configure their
# Vault agent or client libraries to authenticate against this path.
# -----------------------------------------------------------------------------
output "auth_backend_path" {
  description = "Mount path of the Kubernetes auth method. Applications configure Vault login with this path."
  value       = vault_auth_backend.kubernetes.path
}

# -----------------------------------------------------------------------------
# Auth Role Names
# -----------------------------------------------------------------------------
# The names of Kubernetes auth roles. Each role maps a K8s service account
# to Vault policies. Verify these match your Kubernetes service account
# definitions to ensure authentication succeeds.
# -----------------------------------------------------------------------------
output "auth_role_names" {
  description = "List of Kubernetes auth role names. Each maps a K8s service account to Vault policies."
  value       = vault_kubernetes_auth_backend_role.application[*].role_name
}