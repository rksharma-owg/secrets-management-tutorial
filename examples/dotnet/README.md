# .NET / ASP.NET Core Secrets Management Examples

Production-quality C# examples demonstrating how to retrieve and use secrets from AWS Secrets Manager, HashiCorp Vault, and Azure Key Vault in ASP.NET Core 8 applications.

> **Core principle:** Secrets are NEVER in source code, configuration files, or Docker images. They are retrieved at runtime from a secrets manager using identity-based authentication.

---

## Prerequisites

| Tool | Purpose | Install |
|------|---------|---------|
| .NET 8 SDK | Build & run | [dotnet.microsoft.com](https://dotnet.microsoft.com/download/dotnet/8.0) |
| AWS CLI (optional) | Local AWS auth for development | `winget install Amazon.AWSCLI` |
| Azure CLI (optional) | Local Azure auth for development | `winget install Microsoft.AzureCLI` |
| Docker (optional) | Run Vault dev server | [docker.com](https://www.docker.com/) |

---

## Quick Start

### 1. Choose a secret provider and set environment variables

**AWS Secrets Manager:**
```bash
export SECRET_PROVIDER=aws
export AWS_REGION=us-east-1
# Authentication: IAM role on EC2/EKS, or `aws configure` for local dev
```

**HashiCorp Vault:**
```bash
export SECRET_PROVIDER=vault
export VAULT_ADDR=http://127.0.0.1:8201  # dev server
export VAULT_TOKEN=root                   # ONLY for dev mode
# In production on K8s: use Kubernetes JWT auth (no VAULT_TOKEN needed)
```

**Azure Key Vault:**
```bash
export SECRET_PROVIDER=azure
export AZURE_VAULT_URL=https://myapp-kv.vault.azure.net/
# Authentication: Managed Identity on Azure, or `az login` for local dev
```

### 2. (Optional) Configure secret names

```bash
export SECRET_NAME_DB=myapp/database       # default
export SECRET_NAME_JWT=myapp/jwt-config     # default
export SECRET_NAME_OPENAI=myapp/openai-config # default
```

### 3. Run the application

```bash
cd examples/dotnet
dotnet restore
dotnet run
```

The application performs a **fail-fast startup validation**: it fetches all required secrets before accepting any HTTP requests. If a secret is missing, the app exits with code 1.

### 4. Test the endpoints

```bash
# Health check (no secrets involved)
curl http://localhost:5000/api/health

# Non-sensitive configuration (provider name, secret names, JWT issuer/audience)
curl http://localhost:5000/api/config

# Trigger secret refresh (cache invalidation + re-fetch)
curl -X POST http://localhost:5000/api/secrets/refresh \
  -H "Content-Type: application/json" \
  -d '{"secretName":"myapp/database"}'

# Test database connectivity (response contains no credentials)
curl -X POST http://localhost:5000/api/db/test

# Simulated OpenAI chat (response contains no API key)
curl -X POST http://localhost:5000/api/ai/chat \
  -H "Content-Type: application/json" \
  -d '{"message":"Hello, world!"}'
```

---

## How ASP.NET Core Configuration Providers Work

ASP.NET Core's `IConfiguration` system supports multiple configuration sources, layered in registration order (last wins):

```
appsettings.json          → safe defaults (no secrets)
appsettings.{env}.json    → environment-specific overrides
Environment variables     → container/orchestrator overrides
Secret Manager provider   → secrets from AWS/Vault/Azure (OVERRIDES everything above)
```

The `SecretManagerExtensions.AddSecretManager()` method in `Configuration/` registers a custom `IConfigurationSource` that pulls secrets into this chain. This means any code using `IConfiguration` (Options pattern, `[FromConfiguration]` binding, etc.) automatically gets secrets from the vault.

**Key insight:** Secrets are NOT stored in `IConfiguration` permanently. They are loaded at startup. For hot rotation, use `ISecretManagerService` directly.

---

## How to Inject Secrets via Dependency Injection

Application code depends on the `ISecretManagerService` interface — never on a concrete provider:

```csharp
public class MyService
{
    private readonly ISecretManagerService _secrets;

    public MyService(ISecretManagerService secrets)
    {
        _secrets = secrets;
    }

    public async Task DoWorkAsync(CancellationToken ct)
    {
        // Get typed, validated credentials from the secret manager
        var dbCreds = await _secrets.GetDatabaseCredentialsAsync("myapp/database", ct);

        // Use the credentials directly with the database driver
        await using var connection = new SqlConnection(dbCreds.GetConnectionString());
        await connection.OpenAsync(ct);
        // ...
    }
}
```

The concrete implementation (`AwsSecretsManagerService`, `VaultSecretsService`, or `AzureKeyVaultService`) is registered in `Program.cs` based on the `SECRET_PROVIDER` environment variable. **Zero application code changes needed to switch providers.**

---

## How Managed Identity Works (Azure)

When running on Azure App Service, AKS, or Azure VMs:

```
┌─────────────────┐     ┌──────────────────┐     ┌──────────────┐
│  Your ASP.NET   │────▶│  IMDS endpoint   │────▶│  Azure AD    │
│  Application    │     │  169.254.169.254 │     │  (token)     │
└─────────────────┘     └──────────────────┘     └──────┬───────┘
                                                         │
                                                OAuth2 token
                                                (auto-refreshed)
                                                         │
                                                ┌────────▼───────┐
                                                │  Azure Key     │
                                                │  Vault         │
                                                │  (secrets)     │
                                                └────────────────┘
```

1. `DefaultAzureCredential` discovers the managed identity from the instance metadata service (IMDS).
2. It obtains an OAuth2 access token from Azure AD — automatically refreshed before expiry.
3. The token is sent with each Key Vault request. The application never sees or stores it.
4. Key Vault verifies the token against Azure RBAC policies and returns the secret.

**No certificates, no secrets, no configuration files** — just the compute identity.

### Enabling Managed Identity

**Azure App Service:**
```bash
az webapp identity assign --resource-group myRG --name myApp
az keyvault set-policy -n myapp-kv --secret-permissions get \
  --object-id $(az webapp identity show -g myRG -n myApp --query principalId -o tsv)
```

**Azure Kubernetes Service (AKS):**
```bash
# Enable OIDC issuer on the cluster
az aks update -g myRG -n myCluster --enable-oidc-issuer

# Create a federated identity credential
az identity federated-credential create \
  --name myAppFederatedIdentity \
  --identity-name myAppIdentity \
  --resource-group myRG \
  --issuer $(az aks show -g myRG -n myCluster --query oidcIssuerProfile.issuerUrl -o tsv) \
  --subject system:serviceaccount:default:my-app-sa \
  --audiences api://AzureADTokenExchange

# Grant Key Vault access
az keyvault set-policy -n myapp-kv --secret-permissions get \
  --object-id $(az identity show -n myAppIdentity -g myRG --query principalId -o tsv)
```

---

## How to Rotate Secrets Without Restart

The `POST /api/secrets/refresh` endpoint triggers a cache invalidation and re-fetch:

1. Rotate the secret in the backend (AWS rotation Lambda, Vault dynamic secret, manual Azure update).
2. Call `POST /api/secrets/refresh` with the secret name.
3. The service clears its in-memory cache, fetches the new version, and updates the cache.
4. Subsequent requests use the new credentials.

For **automatic rotation without external triggers**, implement a background service (`IHostedService`) that periodically polls the secret version and refreshes when it changes:

```csharp
public class SecretRotationBackgroundService : BackgroundService
{
    private readonly ISecretManagerService _secrets;
    private readonly TimeSpan _pollInterval = TimeSpan.FromMinutes(5);

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            await _secrets.RefreshSecretAsync("myapp/database", ct);
            await Task.Delay(_pollInterval, ct);
        }
    }
}
```

---

## Project Structure

```
examples/dotnet/
├── SecretsTutorial.csproj          # Project file (no secrets in package refs)
├── Program.cs                       # App entry point, DI setup, fail-fast validation
├── appsettings.json                 # Non-sensitive defaults ONLY
├── Configuration/
│   └── SecretManagerExtensions.cs   # IConfigurationSource bridge
├── Services/
│   ├── ISecretManagerService.cs     # Interface + SecretRetrievalException
│   ├── AwsSecretsManagerService.cs  # AWS implementation (IAM auth)
│   ├── VaultSecretsService.cs       # Vault implementation (KV v2 + leases)
│   └── AzureKeyVaultService.cs      # Azure implementation (Managed Identity)
├── Models/
│   ├── DatabaseCredentials.cs       # DB creds with [JsonIgnore] on Password
│   ├── JwtConfig.cs                 # JWT config with key validation
│   └── OpenAIConfig.cs              # OpenAI config with safe key prefix
├── Controllers/
│   └── SecretsController.cs         # API endpoints (sanitized responses only)
└── README.md                        # This file
```

---

## Security Checklist

- [ ] No secrets in `appsettings.json`
- [ ] No secrets in source code
- [ ] No secrets in Docker image or environment variables in docker-compose
- [ ] All secret-valued properties marked `[JsonIgnore]`
- [ ] Secret manager uses identity-based auth (IAM role / Managed Identity / K8s SA)
- [ ] Connection strings built at runtime from typed credential objects
- [ ] Health check does not depend on secret manager availability
- [ ] Error responses are generic (no secret names, no stack traces)
- [ ] Swagger disabled in production
- [ ] Secret-bearing schemas removed from OpenAPI document
- [ ] Fail-fast startup: app refuses to start if required secrets are missing

---

## Links

- [Main repository README](../../README.md)
- [AWS Secrets Manager guide](../../aws-secrets-manager/README.md)
- [HashiCorp Vault guide](../../hashicorp-vault/README.md)
- [Azure Key Vault guide](../../azure-key-vault/README.md)
- [Kubernetes secrets patterns](../../kubernetes/README.md)