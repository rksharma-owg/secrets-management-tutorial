# HashiCorp Vault - Terraform Module

This module configures [HashiCorp Vault](https://www.vaultproject.io/) resources for secrets management including KV v2 secrets, least-privilege policies, Kubernetes authentication, and audit logging. It assumes a Vault server is **already running** — this module manages the configuration, not the infrastructure.

## Prerequisites

- **Vault server** running and accessible (self-hosted, HCP Vault, or Vault Enterprise)
- **Terraform** >= 1.5.0 with the Vault provider plugin (`terraform init`)
- **Vault token** with permissions to create mounts, policies, secrets, and auth methods
- **Kubernetes cluster** with service accounts that will authenticate to Vault
- **Vault provider token** — set via `VAULT_TOKEN` environment variable (never hardcode)

## Provider Authentication

The Vault provider requires a token with sufficient permissions:

```bash
# Option 1: Environment variable (recommended for CI/CD)
export VAULT_ADDR="https://vault.internal.example.com:8200"
export VAULT_TOKEN="s.xxxxxxxxxxxx"

# Option 2: For local development with Vault dev server
export VAULT_ADDR="http://127.0.0.1:8200"
export VAULT_TOKEN="devroot"
```

## Usage

```bash
# Initialize
terraform init

# Create a terraform.tfvars (gitignored) with:
#   kubernetes_ca_cert = <PEM cert from kubectl get configmap kube-root-ca.crt>
#   environment = "dev"

# Preview changes
terraform plan -var-file="terraform.tfvars"

# Apply
terraform apply -var-file="terraform.tfvars"
```

## Resources Created

| Resource | Purpose |
|----------|---------|
| `vault_mount` | KV v2 secrets engine at `secret-<env>` |
| `vault_kv_secret_v2` (x3) | Database credentials, OpenAI key, JWT config |
| `vault_policy` | Least-privilege read-only policy (explicit deny on all other paths) |
| `vault_auth_backend` | Kubernetes auth method for workload identity |
| `vault_kubernetes_auth_backend_config` | K8s cluster trust configuration |
| `vault_kubernetes_auth_backend_role` (xN) | Per-application roles mapping K8s SAs to Vault policies |
| `vault_audit` | File-based audit logging in JSON format |

## Kubernetes Auth Flow

The Kubernetes auth method eliminates static credentials. The authentication flow:

1. A Kubernetes pod starts with a service account token (mounted automatically at `/var/run/secrets/kubernetes.io/serviceaccount/token`)
2. The **Vault Agent** or **Vault client library** (in the pod) sends the SA token to Vault's Kubernetes auth endpoint
3. Vault validates the token against the Kubernetes API server using the configured CA certificate
4. Vault checks if the SA name and namespace match a configured auth role
5. If valid, Vault issues a short-lived token with the role's attached policies
6. The application uses this token to read secrets from the KV v2 engine

No long-lived tokens or secrets are ever stored in the pod specification or container image.

## Security Considerations

1. **Token TTLs**: Auth role tokens have a 1-hour TTL and 4-hour max. Adjust based on pod lifecycle and restart frequency.
2. **Audit logs**: Every secret access is logged. Ship audit logs to a tamper-evident system (Splunk, Datadog, S3 Object Lock) for compliance.
3. **Policy deny rules**: The default-deny on `secret-<env>/*` ensures no accidental broad access even if additional policies are attached.
4. **TLS only**: The Vault address must use HTTPS. An unencrypted connection exposes tokens and secrets to network interception.
5. **Kubernetes CA verification**: JWT validation is disabled in `dev` only. Production must verify the issuer claim to prevent token confusion attacks.
6. **Dynamic secrets**: For production databases, prefer Vault's database secrets engine over static KV secrets for automatic credential generation and revocation.