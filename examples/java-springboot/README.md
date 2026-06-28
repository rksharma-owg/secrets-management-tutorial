# Java Spring Boot — Secrets Management Examples

Production-quality Spring Boot 3.2 application demonstrating secure secrets management with **HashiCorp Vault**, **AWS Secrets Manager**, and **Azure Key Vault**.

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    Your Application Code                        │
│  Controllers / Services — depend only on SecretManagerService   │
└────────────────────────┬────────────────────────────────────────┘
                         │ (interface)
┌────────────────────────┴────────────────────────────────────────┐
│                  SecretManagerService (Interface)                │
│  getSecret() / getDatabaseCredentials() / getJwtConfig() / ...  │
└──┬──────────────────┬──────────────────┬────────────────────────┘
   │                  │                  │
   ▼                  ▼                  ▼
┌─────────┐    ┌──────────┐    ┌──────────────┐
│  Vault  │    │   AWS    │    │    Azure     │
│ Service │    │  Service │    │   Service    │
└────┬────┘    └────┬─────┘    └──────┬───────┘
     │              │                 │
     ▼              ▼                 ▼
┌─────────┐  ┌───────────┐  ┌───────────────┐
│  Vault  │  │  AWS SM   │  │ Azure Key     │
│ Server  │  │           │  │ Vault         │
└─────────┘  └───────────┘  └───────────────┘
```

**Key design decision:** Switch providers by changing ONE environment variable (`SECRET_PROVIDER`). No code changes required.

## Prerequisites

| Requirement | Version | Purpose |
|---|---|---|
| Java JDK | 17+ | Spring Boot 3.2 requires Java 17 minimum |
| Maven | 3.8+ | Build tool |
| Docker | — | Run Vault locally (optional) |

**Optional — Provider Accounts:**
- **Vault**: Run locally via Docker (see below) or connect to an existing cluster
- **AWS**: AWS account with IAM role (or `aws` CLI configured for local dev)
- **Azure**: Azure account with Key Vault and Managed Identity

## Quick Start

### 1. Build

```bash
cd examples/java-springboot
mvn clean package -DskipTests
```

### 2. Run with HashiCorp Vault (Default)

```bash
# Start a dev Vault instance
docker run -d --name vault-dev \
  -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=devroot' \
  hashicorp/vault:1.15

# Seed secrets into Vault
export VAULT_ADDR='http://localhost:8200'
export VAULT_TOKEN='devroot'

# Write database credentials
vault kv put secret/myapp/database \
  username="app_user" \
  password="S3cureP@ssw0rd!" \
  host="localhost" \
  port=5432 \
  databaseName="myapp"

# Write JWT configuration
vault kv put secret/myapp/jwt \
  secretKey="aVeryLongRandomKeyThatIsAtLeast32BytesLongForHS256!" \
  algorithm="HS256" \
  issuer="secrets-tutorial" \
  expiryHours=8

# Write OpenAI configuration
vault kv put secret/myapp/openai \
  apiKey="sk-proj-abcdefghijklmnopqrstuvwxyz1234567890" \
  model="gpt-3.5-turbo" \
  maxTokens=4096

# Run the application
SECRET_PROVIDER=vault \
VAULT_ADDR=http://localhost:8200 \
VAULT_TOKEN=devroot \
java -jar target/secrets-tutorial-1.0.0-SNAPSHOT.jar
```

### 3. Run with AWS Secrets Manager

```bash
# Option A: Using AWS CLI credentials (local dev)
aws secretsmanager create-secret \
  --name secrets-tutorial/database \
  --secret-string '{"username":"app_user","password":"S3cureP@ssw0rd!","host":"localhost","port":5432,"databaseName":"myapp"}'

aws secretsmanager create-secret \
  --name secrets-tutorial/jwt \
  --secret-string '{"secretKey":"aVeryLongRandomKeyThatIsAtLeast32BytesLongForHS256!","algorithm":"HS256","issuer":"secrets-tutorial","expiryHours":8}'

aws secretsmanager create-secret \
  --name secrets-tutorial/openai \
  --secret-string '{"apiKey":"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890","model":"gpt-3.5-turbo","maxTokens":4096}'

# Option B: Using IAM role (production on EKS/ECS/EC2)
# No credentials needed — IAM role provides access automatically

SECRET_PROVIDER=aws \
AWS_REGION=us-east-1 \
java -jar target/secrets-tutorial-1.0.0-SNAPSHOT.jar
```

### 4. Run with Azure Key Vault

```bash
# Create a Key Vault and add secrets (one-time setup)
az keyvault create --name my-vault-name --resource-group my-rg --location eastus
az keyvault secret set --vault-name my-vault-name --name myapp-database \
  --value '{"username":"app_user","password":"S3cureP@ssw0rd!","host":"localhost","port":5432,"databaseName":"myapp"}'
az keyvault secret set --vault-name my-vault-name --name myapp-jwt \
  --value '{"secretKey":"aVeryLongRandomKeyThatIsAtLeast32BytesLongForHS256!","algorithm":"HS256","issuer":"secrets-tutorial","expiryHours":8}'
az keyvault secret set --vault-name my-vault-name --name myapp-openai \
  --value '{"apiKey":"sk-proj-abcdefghijklmnopqrstuvwxyz1234567890","model":"gpt-3.5-turbo","maxTokens":4096}'

# Run with Azure CLI auth (dev) or Managed Identity (prod)
SECRET_PROVIDER=azure \
AZURE_VAULT_URL=https://my-vault-name.vault.azure.net/ \
java -jar target/secrets-tutorial-1.0.0-SNAPSHOT.jar
```

## API Endpoints

| Method | Path | Description | Returns Secrets? |
|---|---|---|---|
| GET | `/actuator/health` | Spring Actuator health check | ❌ No |
| GET | `/api/config` | Non-sensitive config info | ❌ No |
| GET | `/api/secrets/status` | Secret loading status | ❌ No (names only) |
| POST | `/api/secrets/refresh?name=X` | Force refresh a secret | ❌ No |
| GET | `/api/db/test` | Database connectivity test | ⚠️ Username only |
| POST | `/api/ai/chat` | OpenAI chat (demo mode) | ❌ No |

## How Spring Cloud Vault Auto-Configuration Works

When `SECRET_PROVIDER=vault`, Spring Cloud Vault automatically:

1. **Connects** to Vault at `VAULT_ADDR` using the configured authentication
2. **Reads** secrets from the KV v2 backend at startup
3. **Injects** them into the Spring Environment as properties

This means you can access Vault secrets via `@Value`:

```java
@Value("${my-secret-key}")
private String mySecret;
```

The lookup order (most specific first):
1. `secret/secrets-tutorial/{profile}` (e.g., `secret/secrets-tutorial/prod`)
2. `secret/secrets-tutorial`
3. `secret/application/{profile}`
4. `secret/application`

### Vault Agent Sidecar Pattern (Kubernetes)

In production Kubernetes, use Vault's Agent Injector to eliminate tokens from the application entirely:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: myapp
  annotations:
    vault.hashicorp.com/agent-inject: "true"
    vault.hashicorp.com/role: "myapp"
    vault.hashicorp.com/agent-inject-secret-config: "secret/data/myapp"
spec:
  # ... no VAULT_TOKEN needed!
```

## How Secret Rotation Works Without Restart

### AWS Secrets Manager (Automatic)
1. Configure a Lambda rotation function in AWS
2. Lambda creates a new secret version
3. Call `POST /api/secrets/refresh?name=database` to pick up the new version
4. The service detects the version change and invalidates its cache

### Vault (Dynamic Secrets)
1. Use Vault's `database` secrets engine for dynamic database credentials
2. Each request gets a fresh username/password with a TTL
3. Spring Cloud Vault auto-renews leases via `LeaseListener`
4. No manual refresh needed — credentials are regenerated automatically

### Azure Key Vault (Manual/Event Grid)
1. Rotate the secret via Azure CLI, Portal, or Event Grid + Function
2. Call `POST /api/secrets/refresh?name=myapp-database`
3. The service fetches the latest version (no client-side caching)

## Security Checklist

- [x] No hardcoded credentials in any file
- [x] All configuration via environment variables
- [x] Secrets never logged (only names and operations)
- [x] Secrets never returned in API responses
- [x] Password fields annotated with `@JsonIgnore`
- [x] JWT key length validated at runtime (minimum 32 bytes)
- [x] Weak/placeholder key detection at startup
- [x] Fail-fast on missing secrets (configurable)
- [x] Actuator `/env` endpoint disabled by default
- [x] Custom exception never includes secret values
- [x] Provider-agnostic interface (no vendor lock-in)
- [x] IAM role / Managed Identity authentication (no static keys)

## File Structure

```
java-springboot/
├── pom.xml                                    # Maven config with security-annotated deps
├── README.md                                  # This file
└── src/main/
    ├── resources/
    │   └── application.yml                    # Config from env vars ONLY (no secrets)
    └── java/com/tutorial/secrets/
        ├── SecretsTutorialApplication.java    # Entry point + startup validation
        ├── config/
        │   ├── SecretManagerConfig.java       # Provider selection (factory pattern)
        │   └── VaultConfig.java               # Spring Cloud Vault documentation
        ├── service/
        │   ├── SecretManagerService.java      # Provider-agnostic interface
        │   ├── AwsSecretsService.java         # AWS Secrets Manager implementation
        │   ├── VaultSecretsService.java       # HashiCorp Vault implementation
        │   └── AzureKeyVaultService.java      # Azure Key Vault implementation
        ├── model/
        │   ├── DatabaseCredentials.java       # DB creds (password @JsonIgnore)
        │   ├── JwtConfig.java                 # JWT config (key strength validation)
        │   ├── OpenAIConfig.java              # OpenAI config (API key @JsonIgnore)
        │   └── SecretRetrievalException.java  # Safe exception (no secret values)
        └── controller/
            └── HealthController.java          # REST API (sanitized responses)
```

## Related Documentation

- [Main Tutorial README](../../README.md)
- [HashiCorp Vault Guide](../../hashicorp-vault/README.md)
- [AWS Secrets Manager Guide](../../aws-secrets-manager/README.md)
- [Azure Key Vault Guide](../../azure-key-vault/README.md)
- [Architecture: Secure Runtime Retrieval](../../architecture/02-secure-runtime-retrieval.md)
- [Architecture: Secret Rotation](../../architecture/05-secret-rotation.md)