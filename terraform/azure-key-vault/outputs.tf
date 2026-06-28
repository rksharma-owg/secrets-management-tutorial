# =============================================================================
# Azure Key Vault - Output Values
# =============================================================================
# These outputs expose resource identifiers needed by downstream consumers:
#   - Application configurations (App Service settings, AKS pod identity)
#   - CI/CD pipelines that reference the vault URI
#   - Monitoring and cost allocation systems
#
# SECURITY NOTE: Outputs are stored in terraform.tfstate. These outputs
# contain identifiers and URIs only — NOT secret values. Ensure your
# state file is stored in an encrypted backend (Azure Storage with
# customer-managed keys).
# =============================================================================

# -----------------------------------------------------------------------------
# Key Vault URI
# -----------------------------------------------------------------------------
# The DNS URI used by the Azure SDK to connect to Key Vault. Applications
# configure this URI (e.g., via AZURE_KEY_VAULT_ENDPOINT environment variable
# or app configuration) to read secrets at runtime.
# -----------------------------------------------------------------------------
output "key_vault_uri" {
  description = "Key Vault DNS URI used by the Azure SDK to read secrets at runtime (e.g., https://kv-myapp-dev.vault.azure.net/)."
  value       = azurerm_key_vault.main.vault_uri
}

# -----------------------------------------------------------------------------
# Key Vault Name
# -----------------------------------------------------------------------------
output "key_vault_name" {
  description = "Key Vault resource name. Used for Azure CLI commands and portal navigation."
  value       = azurerm_key_vault.main.name
}

# -----------------------------------------------------------------------------
# Secret Names
# -----------------------------------------------------------------------------
# The list of secret names provisioned in the vault. Useful for CI/CD
# pipelines that need to verify all expected secrets exist before deployment.
# -----------------------------------------------------------------------------
output "secret_names" {
  description = "List of secret names provisioned in the Key Vault. Used for verification in CI/CD pipelines."
  value = [
    azurerm_key_vault_secret.database_username.name,
    azurerm_key_vault_secret.database_password.name,
    azurerm_key_vault_secret.openai_api_key.name,
    azurerm_key_vault_secret.jwt_secret_key.name,
  ]
}

# -----------------------------------------------------------------------------
# Managed Identity Principal ID
# -----------------------------------------------------------------------------
# The principal (object) ID of the User-Assigned Managed Identity. This ID
# is used in role assignments and as the identity reference in compute
# resources (VMSS, App Service, Container Apps).
# -----------------------------------------------------------------------------
output "managed_identity_principal_id" {
  description = "Principal ID of the User-Assigned Managed Identity. Assign this identity to application compute resources."
  value       = azurerm_user_assigned_identity.application.principal_id
}