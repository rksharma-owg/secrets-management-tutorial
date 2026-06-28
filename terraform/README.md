# Terraform — Infrastructure as Code for Secrets Management

This directory contains production-quality Terraform configurations for provisioning secrets management infrastructure across three major cloud and on-premises platforms. Each module is self-contained, well-commented, and follows security best practices.

## Directory Structure

```
terraform/
├── README.md                    # This file
├── aws-secrets-manager/         # AWS Secrets Manager module
│   ├── main.tf                  # Resources: secrets, IAM, rotation
│   ├── variables.tf             # Input variables
│   ├── outputs.tf               # Output values
│   └── README.md               # AWS-specific documentation
├── hashicorp-vault/            # HashiCorp Vault configuration module
│   ├── main.tf                  # Resources: KV v2, policies, K8s auth, audit
│   ├── variables.tf             # Input variables
│   ├── outputs.tf               # Output values
│   └── README.md               # Vault-specific documentation
└── azure-key-vault/            # Azure Key Vault module
    ├── main.tf                  # Resources: Key Vault, secrets, RBAC, private endpoint
    ├── variables.tf             # Input variables
    ├── outputs.tf               # Output values
    └── README.md               # Azure-specific documentation
```

## How to Use Each Module

Each module is independent — use one, two, or all three depending on your cloud strategy:

### AWS Secrets Manager

```bash
cd aws-secrets-manager
cp terraform.tfvars.example terraform.tfvars  # Edit with real values
terraform init && terraform plan && terraform apply
```

### HashiCorp Vault

```bash
cd hashicorp-vault
export VAULT_ADDR="https://vault.internal:8200"
export VAULT_TOKEN="s.xxx"  # Or use JWT/OIDC auth
terraform init && terraform plan && terraform apply
```

### Azure Key Vault

```bash
cd azure-key-vault
az login
terraform init && terraform plan -var-file="terraform.tfvars" && terraform apply
```

## Security Best Practices for Terraform with Secrets

### 1. NEVER Store Secret Values in `.tfstate`

Terraform state files contain all resource attributes in **plaintext**. If secret values pass through Terraform, they end up in state. Instead:

- Use Terraform to create the secret **container** (the Key Vault, Secrets Manager secret, Vault mount)
- Populate secret **values** after provisioning via the provider's CLI or SDK
- If you must set values via Terraform, mark variables as `sensitive = true`

### 2. Use Encrypted Remote State

Never store state locally or in unencrypted storage:

```hcl
# AWS S3 backend with server-side encryption
terraform {
  backend "s3" {
    bucket         = "myapp-terraform-state"
    key            = "secrets-management/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

# Azure Storage backend with customer-managed key
terraform {
  backend "azurerm" {
    resource_group_name  = "rg-terraform"
    storage_account_name = "tfstateXXXX"
    container_name       = "tfstate"
    key                  = "secrets-management.tfstate"
    encryption_key_vault_key_id = "https://kv-terraform.vault.azure.net/keys/state-key/..."
  }
}
```

### 3. Gitignore Variable Files

Add to your `.gitignore`:

```
*.tfvars
*.tfvars.json
.terraform/
*.tfstate
*.tfstate.backup
crash.log
override.tf
override.tf.json
*_override.tf
*_override.tf.json
```

### 4. Use Secure Variable Storage

| Method | Best For | Security |
|--------|----------|----------|
| `terraform.tfvars` (gitignored) | Local development | Medium — files on disk |
| Terraform Cloud / Spacelift variables | Team CI/CD | High — encrypted at rest, audit logged |
| HashiCorp Vault provider | Enterprise automation | Highest — dynamic secrets, audit |
| Environment variables | CI/CD pipelines | Medium — process memory only |

### 5. Provider Authentication Best Practices

- **AWS**: Use IAM roles (OIDC for CI/CD, instance profiles for compute). Never use long-lived access keys.
- **Azure**: Use Managed Identity or OIDC federation. Never use service principal client secrets in CI/CD.
- **Vault**: Use JWT/OIDC auth to obtain short-lived tokens. Never hardcode root tokens.

### 6. Lifecycle Protections

All modules include `lifecycle { prevent_destroy = true }` for production environments. This prevents a mistaken `terraform destroy` from permanently deleting secrets and locking out applications.

## Quick Start by Provider

| Provider | Secrets Created | Auth Method | Rotation | Est. Monthly Cost |
|----------|-----------------|-------------|----------|-------------------|
| AWS Secrets Manager | 3 (DB, OpenAI, JWT) | IAM Role | Lambda-based (30d) | ~$1-3 |
| HashiCorp Vault | 3 (DB, OpenAI, JWT) | Kubernetes SA | Manual / Dynamic | Vault license cost |
| Azure Key Vault | 4 (DB user, DB pass, OpenAI, JWT) | Managed Identity + RBAC | External automation | ~$1-15 |

## Contributing

When adding new modules or resources:

1. Add `# SECURITY IMPLICATION:` comments on every resource and variable
2. Mark all secret values with `# WARNING: Never commit actual secret values`
3. Use `sensitive = true` on variables that hold secret contents
4. Include `lifecycle { prevent_destroy }` for production resources
5. Follow least-privilege: grant the minimum permissions required
6. Document the auth flow in the module's README