# =============================================================================
# Azure Key Vault - Production Terraform Configuration
# =============================================================================
# This module provisions Azure Key Vault resources for securely storing
# and managing application secrets, encryption keys, and certificates.
#
# SECURITY MODEL:
#   - Secrets are encrypted at rest with Azure's platform-managed RSA keys
#   - Network isolation via private endpoints (optional but recommended)
#   - Access Policies or RBAC for fine-grained access control
#   - Soft delete + purge protection prevent accidental data loss
#   - Managed Identity eliminates static credentials for application access
# =============================================================================

terraform {
  # Enforce Terraform 1.5+ for improved plan output and test framework support
  required_version = ">= 1.5"

  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

# -----------------------------------------------------------------------------
# Azure Provider
# -----------------------------------------------------------------------------
# Authenticate using Azure CLI (`az login`), Managed Identity, or service
# principal. For CI/CD, use OIDC federation (workload identity) to obtain
# short-lived tokens — never use long-lived client secrets.
# -----------------------------------------------------------------------------
provider "azurerm" {
  features {}
}

# =============================================================================
# Resource Group
# =============================================================================
# A dedicated resource group for Key Vault resources enables:
#   1. Scope-limited RBAC assignments
#   2. Clean teardown of all Key Vault resources
#   3. Cost tracking and budgeting at the resource group level
# =============================================================================
resource "azurerm_resource_group" "key_vault" {
  name     = "rg-${var.project_name}-${var.environment}-kv"
  location = var.location
  tags     = var.tags
}

# =============================================================================
# Key Vault
# =============================================================================
# Azure Key Vault is the central secrets management service. This configuration
# applies security hardening recommended by the Azure Security Benchmark:
#
# SECURITY FEATURES:
#   - soft_delete_retention_days = 90: Deleted secrets/vaults are recoverable
#     for 90 days, protecting against accidental or malicious deletion
#   - purge_protection_enabled = true: Even after the retention period,
#     vaults cannot be permanently purged — requires a support ticket
#   - public_network_access_enabled = false: Disables all public internet
#     access. Secrets can only be accessed via approved private endpoints
#     or trusted Microsoft services. This is the single most important
#     network-level protection for a Key Vault.
#   - sku_name = "standard": Software-backed HSM. Use "premium" for
#     FIPS 140-2 Level 2 / HSM-backed keys for regulatory compliance.
# =============================================================================
resource "azurerm_key_vault" "main" {
  name                        = "kv-${var.project_name}-${var.environment}"
  location                    = azurerm_resource_group.key_vault.location
  resource_group_name         = azurerm_resource_group.key_vault.name
  tenant_id                   = data.azurerm_client_config.current.tenant_id
  sku_name                    = "standard"

  # -------------------------------------------------------------------------
  # Soft Delete & Purge Protection
  # -------------------------------------------------------------------------
  # Soft delete retains deleted secrets, keys, and certificates for the
  # retention period. Without this, a deleted secret is permanently gone.
  # Purge protection goes further: even after retention expires, the vault
  # cannot be purged without Microsoft support intervention.
  #
  # COMPLIANCE: Required for SOC 2, ISO 27001, and many regulatory frameworks.
  # -------------------------------------------------------------------------
  soft_delete_retention_days = 90
  purge_protection_enabled   = true

  # -------------------------------------------------------------------------
  # Network Security
  # -------------------------------------------------------------------------
  # Disabling public network access is the strongest network isolation.
  # All access must come through:
  #   1. Private endpoints (recommended for production)
  #   2. Trusted Azure services (if enabled via network_acls)
  #
  # When public_network_access_enabled = false, you MUST configure a
  # private endpoint (below) or no client can reach the vault.
  # -------------------------------------------------------------------------
  public_network_access_enabled = false

  # -------------------------------------------------------------------------
  # Access Policies vs RBAC
  # -------------------------------------------------------------------------
  # Key Vault supports TWO authorization models:
  #
  # ACCESS POLICIES (legacy, used here for demonstration):
  #   + Fine-grained control over secret/key/certificate permissions
  #   + Familiar to teams migrating from older deployments
  #   - Limited to 1024 policies per vault
  #   - Cannot use Azure ABAC (attribute-based access control)
  #   - Harder to audit at scale
  #
  # RBAC (recommended for new deployments):
  #   + Consistent with Azure-wide IAM model
  #   + Supports Azure ABAC conditions (e.g., time-based access)
  #   + Easier to audit via Azure Activity Log + Microsoft.Authorization/*
  #   + No 1024 policy limit
  #   - Coarser-grained (built-in roles like "Key Vault Secrets User")
  #
  # This module demonstrates BOTH approaches. In production, choose one.
  # To use RBAC exclusively, set enable_rbac_authorization = true and
  # remove the access_policy block.
  # -------------------------------------------------------------------------

  tags = merge(var.tags, {
    Purpose   = "secrets-management"
    ManagedBy = "terraform"
  })

  lifecycle {
    # Prevent accidental destruction of the Key Vault. A destroyed vault
    # requires a 90-day recovery window and all dependent applications
    # will immediately lose access to secrets.
    prevent_destroy = var.environment == "prod" ? true : false
  }
}

data "azurerm_client_config" "current" {}

# =============================================================================
# Secrets
# =============================================================================
# Each secret is stored individually in Key Vault. This follows the principle
# of secret isolation — different application components can be granted
# access to specific secrets without exposing others.
#
# SECURITY: The secret values below are PLACEHOLDERS. Real values must be
# supplied via a gitignored .tfvars file. The actual values are encrypted
# by Azure Key Vault and are NEVER stored in plaintext.
# =============================================================================

# -----------------------------------------------------------------------------
# Database Username
# -----------------------------------------------------------------------------
# Stored as a separate secret (not combined with password) to support
# scenarios where different components need the username but not the password
# (e.g., connection string builders in a CI/CD pipeline).
# -----------------------------------------------------------------------------
resource "azurerm_key_vault_secret" "database_username" {
  name         = "database-username"
  value        = "db_admin"
  key_vault_id = azurerm_key_vault.main.id

  # Content type aids in secret discovery and tooling integration.
  # Azure SDK clients can filter by content type.
  content_type = "text/plain"

  # WARNING: Never commit actual secret values to version control.
  tags = {
    SecretType = "database"
  }
}

# -----------------------------------------------------------------------------
# Database Password
# -----------------------------------------------------------------------------
# SECURITY: Database passwords should meet your organization's password
# policy (minimum 16 characters, mixed case, numbers, symbols). Azure
# Key Vault does not enforce password complexity — that is the caller's
# responsibility when setting the value.
# -----------------------------------------------------------------------------
resource "azurerm_key_vault_secret" "database_password" {
  name         = "database-password"
  value        = "CHANGE_ME_IN_TFVARS"
  key_vault_id = azurerm_key_vault.main.id

  content_type = "password"

  # WARNING: Never commit actual secret values to version control.
  tags = {
    SecretType = "database"
  }
}

# -----------------------------------------------------------------------------
# OpenAI API Key
# -----------------------------------------------------------------------------
# API keys for external services. Storing these in Key Vault (rather than
# application configuration) enables centralized rotation and immediate
# revocation across all application instances.
# -----------------------------------------------------------------------------
resource "azurerm_key_vault_secret" "openai_api_key" {
  name         = "openai-api-key"
  value        = "sk-PLACEHOLDER_REPLACE_IN_TFVARS"
  key_vault_id = azurerm_key_vault.main.id

  content_type = "api-key"

  # WARNING: Never commit actual secret values to version control.
  tags = {
    SecretType = "api-key"
  }
}

# -----------------------------------------------------------------------------
# JWT Secret Key
# -----------------------------------------------------------------------------
# The HMAC signing key for JWT tokens. Compromise of this key allows an
# attacker to forge authentication tokens and impersonate any user.
#
# SECURITY: Use a minimum 256-bit (32-byte) key for HS256. Consider using
# Azure Key Vault's KEY resource (RSA/EC) and signing tokens via the
# Key Vault API to keep the private key material server-side.
# -----------------------------------------------------------------------------
resource "azurerm_key_vault_secret" "jwt_secret_key" {
  name         = "jwt-secret-key"
  value        = "CHANGE_ME_GENERATE_256BIT_KEY"
  key_vault_id = azurerm_key_vault.main.id

  content_type = "secret-key"

  # WARNING: Never commit actual secret values to version control.
  tags = {
    SecretType = "auth"
  }
}

# =============================================================================
# Access Policy - Application (Least Privilege)
# =============================================================================
# This access policy grants a specific application identity read-only access
# to secrets. It follows the principle of least privilege:
#   - secret_permissions: "Get" and "List" only
#   - No "Set", "Delete", "Purge", "Backup", or "Restore" permissions
#   - No key or certificate permissions
#   - No access to storage account keys
#
# ACCESS POLICIES VS RBAC:
# Access policies are evaluated FIRST, then RBAC. If an access policy
# explicitly denies (not supported — absence is denial), it takes precedence.
# For new deployments, prefer RBAC with built-in roles like:
#   - "Key Vault Secrets User" (read-only secrets)
#   - "Key Vault Secrets Officer" (manage secrets)
# =============================================================================
resource "azurerm_key_vault_access_policy" "application" {
  key_vault_id = azurerm_key_vault.main.id

  # The object_id should be the application's Managed Identity principal ID
  # or a user/service principal. In production, use a Managed Identity
  # assigned to the application's compute resource (VMSS, App Service, AKS pod).
  object_id = data.azurerm_client_config.current.object_id
  tenant_id = data.azurerm_client_config.current.tenant_id

  secret_permissions = [
    "Get",   # Read a specific secret by name
    "List",  # List all secret names (not values)
  ]

  # Explicitly deny key and certificate access by not listing permissions.
  # Key Vault denies by default — unlisted permissions are implicitly denied.
}

# =============================================================================
# Managed Identity + RBAC (Alternative to Access Policies)
# =============================================================================
# This demonstrates the RBAC approach, which is recommended for new deployments.
# A User-Assigned Managed Identity is created and assigned the built-in
# "Key Vault Secrets User" role on the Key Vault.
#
# RBAC ADVANTAGES:
#   1. Consistent with Azure-wide IAM model (one system to learn)
#   2. Supports conditional access (e.g., require MFA, time-based)
#   3. No 1024 access policy limit
#   4. Role assignments are audited in Azure Activity Log
#   5. Can use Azure ABAC for attribute-based policies
# =============================================================================

# User-Assigned Managed Identity for the application
resource "azurerm_user_assigned_identity" "application" {
  name                = "id-${var.project_name}-${var.environment}-app"
  location            = azurerm_resource_group.key_vault.location
  resource_group_name = azurerm_resource_group.key_vault.name
  tags                = var.tags
}

# Grant the Managed Identity read-only access to secrets via RBAC
resource "azurerm_role_assignment" "key_vault_secrets_user" {
  scope                = azurerm_key_vault.main.id
  role_definition_name = "Key Vault Secrets User"
  principal_id         = azurerm_user_assigned_identity.application.principal_id
}

# =============================================================================
# Private Endpoint (Network Isolation)
# =============================================================================
# A private endpoint creates a network interface inside your VNet that
# routes Key Vault traffic over the Azure backbone — it never traverses
# the public internet. This is essential for:
#   1. Regulatory compliance (data must not traverse public networks)
#   2. Defense in depth (even if vault credentials leak, attackers cannot
#      reach the vault without network access)
#   3. DNS-based access control (the private DNS zone overrides the
#      public Key Vault endpoint, directing all traffic to the private endpoint)
# =============================================================================
resource "azurerm_private_endpoint" "key_vault" {
  count = var.enable_private_endpoint ? 1 : 0

  name                = "pe-${azurerm_key_vault.main.name}"
  location            = azurerm_resource_group.key_vault.location
  resource_group_name = azurerm_resource_group.key_vault.name
  subnet_id           = var.subnet_id

  # Private DNS zone group ensures that DNS queries for the Key Vault
  # endpoint resolve to the private endpoint IP. This is critical —
  # without it, applications may still try to reach the public endpoint.
  private_dns_zone_group {
    name                 = "default"
    private_dns_zone_ids = [var.private_dns_zone_id]
  }

  private_service_connection {
    name                           = "psc-${azurerm_key_vault.main.name}"
    private_connection_resource_id = azurerm_key_vault.main.id
    is_manual_connection           = false
    subresource_names              = ["vault"]
  }

  tags = var.tags
}

# Required variables for private endpoint (with defaults for dev)
variable "subnet_id" {
  description = "Subnet ID for the private endpoint. Required when enable_private_endpoint = true."
  type        = string
  default     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-dev-network/providers/Microsoft.Network/virtualNetworks/vnet-dev/subnets/default"
}

variable "private_dns_zone_id" {
  description = "Private DNS zone ID for Key Vault (privatelink.vaultcore.azure.net)."
  type        = string
  default     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-dev-network/providers/Microsoft.Network/privateDnsZones/privatelink.vaultcore.azure.net"
}