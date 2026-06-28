# =============================================================================
# HashiCorp Vault - Input Variables
# =============================================================================
# These variables configure the Vault provider and the Kubernetes auth
# method. Sensitive values (Vault token, Kubernetes CA cert) should be
# supplied via environment variables or gitignored .tfvars files.
# =============================================================================

# -----------------------------------------------------------------------------
# Vault Address
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Ensure this uses HTTPS (TLS). An unencrypted
# connection exposes auth tokens and secret values to network interception.
# In production, Vault should be behind a load balancer with TLS termination
# and network policies restricting access to authorized CIDR ranges.
# -----------------------------------------------------------------------------
variable "vault_addr" {
  description = "Vault server address. Must use HTTPS in production (e.g., https://vault.internal.example.com:8200)"
  type        = string
  default     = "https://vault.internal.example.com:8200"
}

# -----------------------------------------------------------------------------
# Kubernetes Host
# -----------------------------------------------------------------------------
# The API server URL that Vault will use to verify service account tokens.
# Must be reachable from the Vault server's network.
# -----------------------------------------------------------------------------
variable "kubernetes_host" {
  description = "Kubernetes API server URL for token verification (e.g., https://kubernetes.default.svc)"
  type        = string
  default     = "https://kubernetes.default.svc"
}

# -----------------------------------------------------------------------------
# Kubernetes CA Certificate
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: The CA certificate is used to verify the Kubernetes
# API server's identity. An incorrect or compromised CA cert could allow
# Vault to trust a spoofed API server. Retrieve this from the Kubernetes
# cluster: kubectl get configmap kube-root-ca.crt -o jsonpath='{.data.ca\.crt}'
# -----------------------------------------------------------------------------
variable "kubernetes_ca_cert" {
  description = "Kubernetes cluster CA certificate (PEM-encoded). Used to verify service account tokens."
  type        = string
  sensitive   = true
}

# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Controls policy naming, auth method paths, and
# lifecycle protections. Production environments get prevent_destroy
# guards and stricter token TTLs.
# -----------------------------------------------------------------------------
variable "environment" {
  description = "Deployment environment (dev, staging, prod). Controls naming, lifecycle protections, and policy scoping."
  type        = string

  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

# -----------------------------------------------------------------------------
# Application Names
# -----------------------------------------------------------------------------
# SECURITY IMPLICATION: Each application gets its own Kubernetes auth role
# mapping its service account to Vault policies. This ensures application
# isolation — a compromised application cannot access another application's
# secrets even if they share the same Vault cluster.
# -----------------------------------------------------------------------------
variable "application_names" {
  description = "List of application names. Each gets a dedicated Kubernetes auth role mapping to the secrets reader policy."
  type        = list(string)
  default     = ["api-server", "worker", "auth-service"]
}