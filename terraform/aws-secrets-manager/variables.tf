# =============================================================================
# AWS Secrets Manager - Input Variables
# =============================================================================
# These variables control the provisioning of Secrets Manager resources.
# Sensitive values (actual secret contents) should NEVER be defined here.
# Instead, supply them via a gitignored terraform.tfvars file or a
# secret store such as HashiCorp Vault.
# =============================================================================

# -----------------------------------------------------------------------------
# AWS Region
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Secrets are region-scoped. Cross-region replication
# of secrets is NOT automatic. If your application runs in multiple regions,
# you must provision secrets in each region or use a cross-region read pattern
# (e.g., VPC endpoints pointing to a primary region).
# -----------------------------------------------------------------------------
variable "region" {
  description = "AWS region where secrets will be provisioned"
  type        = string
  default     = "us-east-1"
}

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Environment tagging is critical for:
#   1. Ensuring production secrets have stricter protections (prevent_destroy)
#   2. Enforcing environment-specific rotation policies
#   3. Cost attribution and budget alerts per environment
#   4. Audit trail clarity — knowing which env a secret belongs to
# -----------------------------------------------------------------------------
variable "environment" {
  description = "Deployment environment (dev, staging, prod). Controls lifecycle protections and tagging."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# -----------------------------------------------------------------------------
# Project Name
# -----------------------------------------------------------------------------
# Used as a naming prefix for all resources. A consistent prefix enables:
#   1. IAM policy scoping (e.g., secretsmanager:GetSecretValue on arn:*:secret:myapp-*)
#   2. Cost grouping in AWS Cost Explorer
#   3. Clear identification of resource ownership
# -----------------------------------------------------------------------------
variable "project_name" {
  description = "Project name used as a prefix for all resource names and tags"
  type        = string
  default     = "myapp"
}

# -----------------------------------------------------------------------------
# Secret Names
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Defining secret names as a variable allows the same
# module to be reused across environments with different secret sets. However,
# the actual secret VALUES should never be passed through this variable —
# they must be supplied via secure means (tfvars, Vault, environment variables).
# -----------------------------------------------------------------------------
variable "secret_names" {
  description = "List of logical secret names to provision. Actual values should be supplied via terraform.tfvars."
  type        = list(string)
  default     = ["database-credentials", "openai-api-key", "jwt-config"]
}

# -----------------------------------------------------------------------------
# Rotation Enabled
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Disabling rotation in non-production environments can
# reduce operational complexity during development. However, production secrets
# MUST have rotation enabled to meet compliance requirements (SOC 2, PCI-DSS,
# HIPAA) and to limit the blast radius of credential compromise.
# -----------------------------------------------------------------------------
variable "rotation_enabled" {
  description = "Enable automatic secret rotation. Should be true for production."
  type        = bool
  default     = true
}

# -----------------------------------------------------------------------------
# Rotation Schedule
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Shorter rotation intervals reduce the window of
# exposure if a secret is compromised, but increase the risk of application
# disruption if rotation fails. Align this with your organization's security
# policy — 30 days is a common industry standard.
# -----------------------------------------------------------------------------
variable "rotation_schedule" {
  description = "Day of month for automatic secret rotation (used in cron expression)"
  type        = string
  default     = "30d"
}

# -----------------------------------------------------------------------------
# Tags
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Tags are metadata only and do not affect access control
# directly, but they are essential for:
#   1. Cost allocation per team/project/environment
#   2. Compliance audit trails
#   3. Automated lifecycle policies (e.g., tag-based backup rules)
#   4. Identifying orphaned resources for cleanup
# -----------------------------------------------------------------------------
variable "tags" {
  description = "Tags applied to all resources for cost allocation and compliance tracking"
  type        = map(string)
  default = {
    ManagedBy = "terraform"
  }
}