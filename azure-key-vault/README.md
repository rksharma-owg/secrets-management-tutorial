# Azure Key Vault - Implementation Guide

## Overview

Azure Key Vault is a cloud service for securely storing and accessing secrets, keys, and certificates. It provides centralized secret management with tight integration into the Azure ecosystem, managed identities for authentication, and comprehensive logging through Azure Monitor.

### Key Features

- **Secrets management** - store connection strings, API keys, passwords
- **Key management** - create and manage RSA/ECC encryption keys (HSM-backed option)
- **Certificate management** - provision, manage, and renew TLS/SSL certificates
- **Managed HSM** - dedicated, FIPS 140-2 Level 3 validated HSMs
- **Azure AD integration** - authenticate using managed identities (no credentials needed)
- **Soft delete and purge protection** - recovery from accidental deletion
- **Network isolation** - private endpoints, firewall rules, service endpoints

## Prerequisites

### 1. Azure CLI Installed

```bash
# macOS
brew install azure-cli

# Linux (Ubuntu/Debian)
curl -sL https://aka.ms/InstallAzureCLIDeb | sudo bash

# Verify
az --version

# Login
az login

# Set default subscription
az account set --subscription "Your Subscription Name"
```

### 2. Required Permissions

The principal creating and managing the Key Vault needs:

- `Microsoft.KeyVault/vaults/create` - create a vault
- `Microsoft.KeyVault/vaults/write` - update vault settings
- `Microsoft.KeyVault/vaults/delete` - delete a vault
- `Microsoft.ManagedIdentity/userAssignedIdentities/write` - create managed identities

## Creating a Key Vault

### Create a Vault with Default Settings

```bash
# Create a resource group (if needed)
az group create \
  --name my-app-rg \
  --location eastus

# Create a Key Vault
az keyvault create \
  --name my-app-kv \
  --resource-group my-app-rg \
  --location eastus \
  --enable-soft-delete true \
  --enable-purge-protection true \
  --default-action Deny \
  --bypass AzureServices \
  --sku standard

# For HSM-backed keys, use premium SKU
az keyvault create \
  --name my-app-kv-hsm \
  --resource-group my-app-rg \
  --location eastus \
  --enable-soft-delete true \
  --enable-purge-protection true \
  --sku premium
```

### Important Vault Settings

| Setting | Recommended Value | Why |
|---------|------------------|-----|
| `--enable-soft-delete` | `true` | Recover deleted secrets for 90 days |
| `--enable-purge-protection` | `true` | Prevent permanent deletion during retention |
| `--default-action` | `Deny` | Block all network access by default |
| `--bypass` | `AzureServices` | Allow Azure services to reach the vault |
| `--sku` | `standard` | AES-256 encryption, sufficient for most use cases |
| `--retention-days` | `90` | Soft-delete retention period |

## Adding and Managing Secrets

### Create a Secret

```bash
# Create a simple text secret
az keyvault secret set \
  --vault-name my-app-kv \
  --name DatabasePassword \
  --value "MyS3cur3P@ssw0rd!"

# Create a secret with tags and content type
az keyvault secret set \
  --vault-name my-app-kv \
  --name ConnectionString \
  --value "Server=tcp:myserver.database.windows.net,1433;Database=mydb;User ID=appuser;Password=MyS3cur3P@ssw0rd!;" \
  --tags environment=production application=my-app \
  --content-type "connection-string"

# Create a secret with a custom expiry
az keyvault secret set \
  --vault-name my-app-kv \
  --name ApiKey \
  --value "sk-abc123xyz789" \
  --expires "2025-12-31T23:59:59Z"
```

### Retrieve a Secret

```bash
# Get the latest version of a secret (value displayed)
az keyvault secret show \
  --vault-name my-app-kv \
  --name DatabasePassword \
  --query value -o tsv

# Get secret metadata (without value)
az keyvault secret show \
  --vault-name my-app-kv \
  --name DatabasePassword \
  --query '{name:name, version:attributes.created, enabled:attributes.enabled, expires:attributes.exp}'

# List all secrets
az keyvault secret list \
  --vault-name my-app-kv

# List all versions of a secret
az keyvault secret list-versions \
  --vault-name my-app-kv \
  --name DatabasePassword

# Get a specific version
az keyvault secret show \
  --vault-name my-app-kv \
  --name DatabasePassword \
  --version "abc123def456..."
```

### Update and Delete Secrets

```bash
# Update a secret value (creates a new version)
az keyvault secret set \
  --vault-name my-app-kv \
  --name DatabasePassword \
  --value "N3wP@ssw0rd!"

# Disable a secret (without deleting)
az keyvault secret set-attributes \
  --vault-name my-app-kv \
  --name OldApiKey \
  --enabled false

# Delete a secret (goes to soft-delete, recoverable for 90 days)
az keyvault secret delete \
  --vault-name my-app-kv \
  --name OldApiKey

# Recover a deleted secret
az keyvault secret recover \
  --vault-name my-app-kv \
  --name OldApiKey

# Permanently purge a deleted secret (irreversible)
az keyvault secret purge \
  --vault-name my-app-kv \
  --name OldApiKey
```

## Access Policies vs. RBAC

Azure Key Vault supports **two authorization models**. You must choose one per vault.

### Model 1: Access Policies (Legacy, Vault-Level)

```bash
# Grant a user access to secrets
az keyvault set-policy \
  --vault-name my-app-kv \
  --upn user@example.com \
  --secret-permissions get list

# Grant an application (service principal) access
az keyvault set-policy \
  --vault-name my-app-kv \
  --spn <application-id> \
  --secret-permissions get list \
  --key-permissions encrypt decrypt \
  --certificate-permissions get list

# Grant a managed identity access
az keyvault set-policy \
  --vault-name my-app-kv \
  --object-id <managed-identity-object-id> \
  --secret-permissions get

# Show current policies
az keyvault show \
  --vault-name my-app-kv \
  --query "properties.accessPolicies"
```

### Model 2: Azure RBAC (Recommended, Resource-Level)

```bash
# Set the vault to use RBAC authorization
az keyvault update \
  --name my-app-kv \
  --resource-group my-app-rg \
  --enable-rbac-authorization true

# Grant Get/List secret permissions using RBAC
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <user-or-service-principal-id> \
  --scope /subscriptions/<sub-id>/resourceGroups/my-app-rg/providers/Microsoft.KeyVault/vaults/my-app-kv

# Grant all secret permissions (admin)
az role assignment create \
  --role "Key Vault Secrets Officer" \
  --assignee <user-id> \
  --scope /subscriptions/<sub-id>/resourceGroups/my-app-rg/providers/Microsoft.KeyVault/vaults/my-app-kv

# Built-in RBAC roles for Key Vault:
# - Key Vault Secrets User: get, list secrets (read-only)
# - Key Vault Secrets Officer: all secret operations
# - Key Vault Crypto User: encrypt, decrypt, sign, verify
# - Key Vault Crypto Officer: all crypto operations
# - Key Vault Certificate User: get, list certificates
# - Key Vault Contributor: manage vault settings (not secrets)
```

**Why RBAC is recommended:**
- Consistent with Azure resource management across all services
- Supports Azure AD groups for team-based access
- Fine-grained control at the secret, key, or certificate level
- Easier audit and compliance reporting
- Supports Conditional Access Policies

## Managed Identities

Managed identities eliminate the need for credentials in your code. Azure automatically manages the identity's lifecycle.

### System-Assigned Managed Identity

```bash
# Enable system-assigned managed identity on a VM
az vm identity assign \
  --name my-app-vm \
  --resource-group my-app-rg

# Enable on an App Service
az webapp identity assign \
  --name my-app-service \
  --resource-group my-app-rg

# Enable on an AKS cluster (per-node pool)
az aks update \
  --name my-cluster \
  --resource-group my-app-rg \
  --enable-managed-identity

# Get the identity's object ID (needed for Key Vault access)
az vm identity show \
  --name my-app-vm \
  --resource-group my-app-rg \
  --query principalId -o tsv
```

### User-Assigned Managed Identity

```bash
# Create a user-assigned managed identity
az identity create \
  --name my-app-identity \
  --resource-group my-app-rg \
  --location eastus

# Assign to a VM
az vm identity assign \
  --name my-app-vm \
  --resource-group my-app-rg \
  --identities /subscriptions/<sub-id>/resourceGroups/my-app-rg/providers/Microsoft.ManagedIdentity/userAssignedIdentities/my-app-identity

# Get details
az identity show \
  --name my-app-identity \
  --resource-group my-app-rg
```

### Grant Managed Identity Access to Key Vault

```bash
# Using RBAC (recommended)
az role assignment create \
  --role "Key Vault Secrets User" \
  --assignee <managed-identity-principal-id> \
  --scope /subscriptions/<sub-id>/resourceGroups/my-app-rg/providers/Microsoft.KeyVault/vaults/my-app-kv

# Using access policies
az keyvault set-policy \
  --vault-name my-app-kv \
  --object-id <managed-identity-object-id> \
  --secret-permissions get list
```

## Code Examples

### Python (azure-identity + azure-keyvault-secrets)

```python
import os
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# DefaultAzureCredential automatically tries:
# 1. Environment variables
# 2. Managed identity (on Azure VM, App Service, AKS, etc.)
# 3. Visual Studio Code
# 4. Azure CLI
# 5. Interactive browser (for local dev)
credential = DefaultAzureCredential()

# Create the Key Vault client
vault_url = f"https://my-app-kv.vault.azure.net/"
client = SecretClient(vault_url=vault_url, credential=credential)

# Get a secret
secret = client.get_secret("DatabasePassword")
print(f"Secret version: {secret.properties.version}")
print(f"Secret name: {secret.name}")
# NEVER print: secret.value

# Get a secret with a specific version
secret_v1 = client.get_secret("DatabasePassword", version="abc123...")

# List all secrets
for secret_properties in client.list_properties_of_secrets():
    print(f"  - {secret_properties.name}")

# Set a new secret version
new_secret = client.set_secret(
    "DatabasePassword",
    "N3wP@ssw0rd!",
    tags={"environment": "production"}
)
```

### Python with Rotation Detection

```python
import hashlib
import logging
from datetime import datetime, timedelta
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

logger = logging.getLogger(__name__)

class AzureSecretWithRotation:
    """Monitors a Key Vault secret for rotation."""

    def __init__(self, vault_url: str, secret_name: str,
                 check_interval: int = 300):
        credential = DefaultAzureCredential()
        self.client = SecretClient(vault_url=vault_url, credential=credential)
        self.secret_name = secret_name
        self.check_interval = check_interval
        self._last_version = None
        self._last_check = None
        self._value = None

    def get_value(self) -> str:
        now = datetime.utcnow()
        if (self._last_check is None or
            (now - self._last_check).total_seconds() > self.check_interval):
            self._refresh()
        return self._value

    def _refresh(self):
        secret = self.client.get_secret(self.secret_name)
        if self._last_version and secret.properties.version != self._last_version:
            logger.info(
                "Secret rotation detected for %s: %s -> %s",
                self.secret_name,
                self._last_version[:8],
                secret.properties.version[:8]
            )
            # Trigger your connection refresh logic here

        self._last_version = secret.properties.version
        self._last_check = datetime.utcnow()
        self._value = secret.value

# Usage
kv_secret = AzureSecretWithRotation(
    vault_url="https://my-app-kv.vault.azure.net/",
    secret_name="DatabasePassword"
)
password = kv_secret.get_value()
```

### Node.js (@azure/identity + @azure/keyvault-secrets)

```javascript
import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";

// DefaultAzureCredential works the same as Python:
// Managed identity on Azure, Azure CLI locally, etc.
const credential = new DefaultAzureCredential();

const vaultUrl = "https://my-app-kv.vault.azure.net/";
const client = new SecretClient(vaultUrl, credential);

// Get a secret
const secret = await client.getSecret("DatabasePassword");
console.log(`Secret version: ${secret.properties.version}`);
console.log(`Secret name: ${secret.name}`);
// NEVER log: secret.value

// List all secrets
for await (const secretProperties of client.listPropertiesOfSecrets()) {
  console.log(`  - ${secretProperties.name}`);
}

// Set a new secret version
const newSecret = await client.setSecret("DatabasePassword", "N3wP@ssw0rd!", {
  tags: { environment: "production" },
});

// Delete a secret (soft delete - recoverable)
const deleteResult = await client.beginDeleteSecret("OldApiKey");
await deleteResult.pollUntilDone();
console.log("Secret deleted (recoverable for 90 days)");
```

### Node.js with Rotation Detection

```javascript
import { DefaultAzureCredential } from "@azure/identity";
import { SecretClient } from "@azure/keyvault-secrets";

class AzureRotatingSecret {
  constructor(vaultUrl, secretName, { checkIntervalMs = 300_000 } = {}) {
    const credential = new DefaultAzureCredential();
    this.client = new SecretClient(vaultUrl, credential);
    this.secretName = secretName;
    this.checkIntervalMs = checkIntervalMs;
    this.lastVersion = null;
    this.lastCheck = null;
    this.value = null;
  }

  async getValue() {
    const now = Date.now();
    if (!this.lastCheck || (now - this.lastCheck) > this.checkIntervalMs) {
      await this.refresh();
    }
    return this.value;
  }

  async refresh() {
    const secret = await this.client.getSecret(this.secretName);
    if (this.lastVersion && secret.properties.version !== this.lastVersion) {
      console.log(
        `Secret rotation detected for ${this.secretName}: ` +
        `${this.lastVersion.substring(0, 8)} -> ${secret.properties.version.substring(0, 8)}`
      );
      // Trigger your connection refresh logic here
    }

    this.lastVersion = secret.properties.version;
    this.lastCheck = Date.now();
    this.value = secret.value;
  }
}

// Usage
const secret = new AzureRotatingSecret(
  "https://my-app-kv.vault.azure.net/",
  "DatabasePassword"
);
const password = await secret.getValue();
```

## Cost Overview

| Operation | Standard Tier | Premium Tier |
|-----------|--------------|-------------|
| Secret operations | $0.03/10K operations | $0.03/10K operations |
| Key operations (RSA 2K) | $0.03/10K operations | $0.03/10K operations |
| HSM-protected keys | Not available | $1.00/key/month |
| Certificate operations | $3.00/certificate/renewal | $3.00/certificate/renewal |
| Vault | Free | $1.00/vault/month |

**Typical production cost estimate (Standard tier):**
- 20 secrets, 100K operations/month: $0.30/month
- 5 certificates: $15.00/month (one-time + renewal)
- **Total: ~$15-20/month** for a typical production workload

> Key Vault has a **90-day free trial** with 10K operations/month and 2 keys.

## Security Considerations Specific to Azure

### Network Security

```bash
# Restrict access to specific IP ranges
az keyvault network-rule add \
  --vault-name my-app-kv \
  --ip-address 10.0.0.0/16 203.0.113.0/24

# Allow access from a virtual network subnet
az keyvault network-rule add \
  --vault-name my-app-kv \
  --subnet /subscriptions/<sub-id>/resourceGroups/my-app-rg/providers/Microsoft.Network/virtualNetworks/my-vnet/subnets/apps

# Create a private endpoint (most secure)
az network private-endpoint create \
  --name my-kv-private-endpoint \
  --resource-group my-app-rg \
  --vnet-name my-vnet \
  --subnet my-endpoints-subnet \
  --private-connection-resource-id /subscriptions/<sub-id>/resourceGroups/my-app-rg/providers/Microsoft.KeyVault/vaults/my-app-kv \
  --group-id vault \
  --connection-name my-kv-connection

# Then set default action to Deny and remove AzureServices bypass
az keyvault update \
  --name my-app-kv \
  --resource-group my-app-rg \
  --default-action Deny \
  --bypass None
```

### Logging and Monitoring

```bash
# Enable diagnostic settings to send logs to a Log Analytics workspace
az monitor diagnostic-settings create \
  --name kv-logs-to-la \
  --resource /subscriptions/<sub-id>/resourceGroups/my-app-rg/providers/Microsoft.KeyVault/vaults/my-app-kv \
  --workspace /subscriptions/<sub-id>/resourcegroups/my-app-rg/providers/microsoft.operationalinsights/workspaces/my-law \
  --logs '[{"category": "AuditEvent","enabled": true},{"category": "AzurePolicyEvaluationDetails","enabled": true}]' \
  --metrics '[{"category": "AllMetrics","enabled": true}]'
```

### Soft Delete and Purge Protection

- **Always enable** `--enable-soft-delete` and `--enable-purge-protection`
- Soft delete retains deleted secrets for **90 days** by default
- Purge protection prevents **anyone** (even admins) from permanently purging during retention
- This protects against ransomware and accidental deletion

### Naming Convention

```
{application}-{environment}-{secret-type}
```

Examples:
- `myapp-prod-db-password`
- `payment-svc-staging-api-key`
- `auth-prod-jwt-signing-key`

This convention works well with Azure RBAC role assignments at the secret level.

## Next Steps

- [../architecture/02-secure-runtime-retrieval.md](../architecture/02-secure-runtime-retrieval.md) - Architecture overview
- [../architecture/04-kubernetes-secret-injection.md](../architecture/04-kubernetes-secret-injection.md) - Kubernetes integration with Azure
- [../aws-secrets-manager/README.md](../aws-secrets-manager/README.md) - Compare with AWS approach