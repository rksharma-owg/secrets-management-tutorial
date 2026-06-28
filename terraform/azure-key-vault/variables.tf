# =============================================================================
# Azure Key Vault - Input Variables
# =============================================================================
# These variables control the provisioning of Azure Key Vault resources.
# Sensitive values (actual secret contents) should NEVER be defined here.
# Supply them via a gitignored terraform.tfvars file.
# =============================================================================

# -----------------------------------------------------------------------------
# Location
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Key Vault is region-scoped. Secrets encrypted in one
# region cannot be decrypted in another (encryption is tied to the region's
# HSM). Ensure your application and Key Vault are in the same region to
# avoid cross-region latency and data residency compliance issues.
# -----------------------------------------------------------------------------
variable "location" {
  description = "Azure region for Key Vault and resource group. Must match the application's region for data residency."
  type        = string
  default     = "East US"
}

# -----------------------------------------------------------------------------
# Resource Group Name
# -----------------------------------------------------------------------------
variable "resource_group_name" {
  description = "Name of the resource group (generated automatically if not provided). Override for existing resource groups."
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Key Vault Name
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Key Vault names are globally unique across all Azure
# tenants. The name is part of the public endpoint URL. Do NOT include
# sensitive information (project names, environments) in the vault name
# if the vault is accidentally exposed to the public internet.
#
# Must be 3-24 characters, alphanumeric and hyphens only.
# -----------------------------------------------------------------------------
variable "key_vault_name" {
  description = "Globally unique name for the Key Vault. If empty, generated as 'kv-<project>-<env>'."
  type        = string
  default     = ""
}

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Controls lifecycle protections (prevent_destroy in
# prod), naming conventions, and tag values. Production vaults should always
# have purge protection and private endpoints enabled.
# -----------------------------------------------------------------------------
variable "environment" {
  description = "Deployment environment (dev, staging, prod). Controls lifecycle protections and naming."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# -----------------------------------------------------------------------------
# Project Name
# -----------------------------------------------------------------------------
variable "project_name" {
  description = "Project name used as a prefix for all resource names and tags"
  type        = string
  default     = "myapp"
}

# -----------------------------------------------------------------------------
# Secret Names (Map)
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: The map keys become the secret names in Key Vault.
# The VALUES in this map are the initial secret contents. In production,
# these MUST be supplied via a gitignored .tfvars file — never committed
# to version control.
#
# WARNING: The default values are placeholders. Real secrets MUST be
# provided via terraform.tfvars that is listed in .gitignore.
# -----------------------------------------------------------------------------
variable "secret_names" {
  description = "Map of secret name to initial value. Actual values should be supplied via a gitignored .tfvars file."
  type        = map(string)
  default = {
    database-username = "db_admin"
    database-password = "CHANGE_ME"
    openai-api-key    = "sk-PLACEHOLDER"
    jwt-secret-key    = "CHANGE_ME"
  }
  sensitive = true
}

# -----------------------------------------------------------------------------
# Enable Private Endpoint
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: When true, a private endpoint is created and public
# network access is disabled. This is the strongest network isolation and
# should be true for staging and production. Set to false only in development
# environments where network isolation adds unnecessary complexity.
# -----------------------------------------------------------------------------
variable "enable_private_endpoint" {
  description = "Create a private endpoint and disable public network access. Should be true for staging and production."
  type        = bool
  default     = false
}

# -----------------------------------------------------------------------------
# Tags
# -----------------------------------------------------------------------------
variable "tags" {
  description = "Tags applied to all resources for cost allocation and compliance tracking."
  type        = map(string)
  default = {
    ManagedBy = "terraform"
  }
}