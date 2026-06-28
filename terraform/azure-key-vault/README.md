# Azure Key Vault - Terraform Module

This module provisions [Azure Key Vault](https://learn.microsoft.com/en-us/azure/key-vault/) resources for securely storing application secrets with network isolation, soft delete protection, and least-privilege access control.

## Prerequisites

- **Azure subscription** with permissions to create Key Vault, Resource Groups, Managed Identities, and Private Endpoints
- **Terraform** >= 1.5.0
- **Azure CLI** installed and authenticated (`az login`)
- **Virtual Network and Subnet** (if `enable_private_endpoint = true`)

## Usage

### 1. Authenticate

```bash
az login
az account set --subscription "<subscription-id>"
```

### 2. Create a `terraform.tfvars` file (NEVER commit this)

```hcl
# WARNING: This file contains sensitive values. Add it to .gitignore.
location               = "East US"
environment            = "dev"
project_name           = "myapp"
enable_private_endpoint = false

secret_names = {
  database-username = "app_db_user"
  database-password = "YourSecureP@ssw0rd!"
  openai-api-key    = "sk-your-real-api-key"
  jwt-secret-key    = "your-256-bit-hmac-key-here"
}
```

### 3. Initialize and apply

```bash
terraform init
terraform plan -var-file="terraform.tfvars"
terraform apply -var-file="terraform.tfvars"
```

## Resources Created

| Resource | Purpose |
|----------|---------|
| `azurerm_resource_group` | Dedicated resource group for Key Vault resources |
| `azurerm_key_vault` | Key Vault with soft delete, purge protection, public access disabled |
| `azurerm_key_vault_secret` (x4) | Database username/password, OpenAI API key, JWT secret key |
| `azurerm_key_vault_access_policy` | Application read-only access (Get/List) |
| `azurerm_user_assigned_identity` | Managed Identity for RBAC-based access |
| `azurerm_role_assignment` | "Key Vault Secrets User" RBAC role on the Managed Identity |
| `azurerm_private_endpoint` | Network-isolated endpoint (when enabled) |

## Access Policies vs RBAC

This module demonstrates **both** authorization models:

| Feature | Access Policies | RBAC |
|---------|----------------|------|
| Granularity | Per-secret, per-permission | Built-in roles (Secrets User, Officer) |
| Max assignments | 1,024 per vault | No limit |
| ABAC support | No | Yes (conditional access) |
| Audit model | Key Vault diagnostics | Azure Activity Log |
| Recommendation | Legacy deployments | **New deployments** |

For new projects, set `enable_rbac_authorization = true` on the Key Vault and remove the access policy block.

## Private Endpoint Configuration

When `enable_private_endpoint = true`:

1. A `subnet_id` with `private_endpoint_network_policies = "Disabled"` is required
2. A private DNS zone for `privatelink.vaultcore.azure.net` must exist
3. Public network access is automatically disabled
4. All traffic routes through the Azure backbone — never the public internet

## Cost Estimation

- **Key Vault (Standard)**: ~$0.03 per 10,000 secret operations
- **Managed Identity**: Free
- **Private Endpoint**: ~$7.30/month + $0.01/hour data processing
- **Estimated monthly cost**: ~$10-15 with private endpoint, ~$1-3 without

## Security Considerations

1. **State file security**: Use Azure Storage backend with customer-managed keys for the Terraform state file.
2. **Purge protection**: Enabled with 90-day soft delete. Even after 90 days, vaults require a Microsoft support ticket to purge.
3. **Network isolation**: `public_network_access_enabled = false` ensures secrets are inaccessible from the public internet.
4. **Least privilege**: The access policy grants only `Get` and `List` — no write, delete, or backup permissions.
5. **Managed Identity**: Preferred over service principals. No credentials to rotate, no secrets to store.
6. **Secret values**: The `secret_names` variable is marked `sensitive = true` to prevent accidental logging.