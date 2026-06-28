# Architecture: Secure Runtime Secret Retrieval

> **Recommended approach:** Secrets are never stored in code, images, or CI/CD. They are retrieved at runtime from a dedicated secret manager.

## Diagram

```mermaid
flowchart TB
    subgraph app_start["🚀 Application Startup"]
        direction TB
        A["<b>Application Process</b><br/>Starts with NO secrets<br/>on disk or in env vars"]
    end

    subgraph auth["🔐 Identity & Authentication"]
        direction TB
        B1["<b>IAM Role</b><br/>AWS STS assumes role<br/>via instance profile"]
        B2["<b>AppRole / JWT</b><br/>Vault authentication<br/>via Kubernetes SA token"]
        B3["<b>Managed Identity</b><br/>Azure AD token<br/>via IMDS endpoint"]
    end

    subgraph managers["🗄️ Secret Managers"]
        direction TB
        subgraph aws_flow["AWS Secrets Manager"]
            C1["<b>GetSecretValue API</b><br/>Returns secret JSON<br/>Encrypted in transit<br/>Encrypted at rest"]
            C1a["<b>Secret Value</b><br/>DB password, API key,<br/>connection string"]
        end
        subgraph vault_flow["HashiCorp Vault"]
            C2["<b>kv/v2/secret/data/...</b><br/>Read secret from<br/>KV v2 engine"]
            C2a["<b>Secret Value</b><br/>Lease-based access<br/>With TTL and renew"]
        end
        subgraph azure_flow["Azure Key Vault"]
            C3["<b>Get Secret / Get Key</b><br/>Azure REST API<br/>TLS encrypted"]
            C3a["<b>Secret Value</b><br/>Secret, Certificate,<br/>or Cryptographic Key"]
        end
    end

    subgraph memory["🧠 In-Memory Only"]
        direction TB
        D["<b>Application Memory</b><br/>Secrets stored as<br/>Python/Node.js variables<br/>⚠️ Never written to disk<br/>⚠️ Never logged<br/>✅ GC'd on shutdown"]
        E["<b>Application Uses Secrets</b><br/>Database connections<br/>API authentication<br/>TLS certificates"]
    end

    subgraph never["🚫 Secrets NEVER Touch"]
        direction LR
        N1["Git Repository"]
        N2["CI/CD Pipeline"]
        N3["Docker Image"]
        N4["Container Registry"]
        N5["Disk / Filesystem"]
    end

    A -->|"1. Identify self<br/>via metadata service"| B1
    A -->|"1. Authenticate<br/>with Vault token"| B2
    A -->|"1. Get token<br/>from IMDS"| B3

    B1 -->|"2. STS temp<br/>credentials"| C1
    B2 -->|"2. Vault client<br/>token"| C2
    B3 -->|"2. Azure AD<br/>access token"| C3

    C1 -->|"3. Decrypt &<br/>return secret"| C1a
    C2 -->|"3. Read &<br/>return secret"| C2a
    C3 -->|"3. Decrypt &<br/>return secret"| C3a

    C1a -->|"4. Secret value<br/>in HTTP response"| D
    C2a -->|"4. Secret value<br/>in HTTP response"| D
    C3a -->|"4. Secret value<br/>in HTTP response"| D

    D -->|"5. Used by<br/>application code"| E

    style A fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style B1 fill:#c8e6c9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
    style B2 fill:#c8e6c9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
    style B3 fill:#c8e6c9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
    style C1 fill:#a5d6a7,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style C2 fill:#a5d6a7,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style C3 fill:#a5d6a7,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style C1a fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style C2a fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style C3a fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style D fill:#d4edda,stroke:#28a745,stroke-width:3px,color:#155724
    style E fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style N1 fill:#f8d7da,stroke:#dc3545,stroke-width:2px,color:#721c24
    style N2 fill:#f8d7da,stroke:#dc3545,stroke-width:2px,color:#721c24
    style N3 fill:#f8d7da,stroke:#dc3545,stroke-width:2px,color:#721c24
    style N4 fill:#f8d7da,stroke:#dc3545,stroke-width:2px,color:#721c24
    style N5 fill:#f8d7da,stroke:#dc3545,stroke-width:2px,color:#721c24

    style app_start fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
    style auth fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
    style managers fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
    style memory fill:#c8e6c9,stroke:#388e3c,stroke-width:3px
    style never fill:#ffebee,stroke:#f44336,stroke-width:2px
```

## How Secure Runtime Retrieval Works

### Step 1: Identity & Authentication

Instead of storing static credentials, the application **proves its identity** to the secret manager. This is done through the cloud platform's identity system:

- **AWS:** The EC2 instance or EKS pod assumes an IAM role via the instance metadata service. Temporary STS credentials are automatically rotated.
- **HashiCorp Vault:** The Kubernetes Service Account token (JWT) is exchanged for a Vault token via the Kubernetes auth method. Tokens have a TTL and can be renewed.
- **Azure:** The managed identity assigned to the VM or App Service retrieves an Azure AD token from the Instance Metadata Service (IMDS).

### Step 2: Secret Retrieval

Using the authenticated identity, the application makes an API call to retrieve the secret:

- All communication is over **TLS (HTTPS)**
- Secrets are **encrypted at rest** in the secret manager
- Access is logged by the secret manager's **audit trail**
- The API call includes the **minimum permissions** needed (principle of least privilege)

### Step 3: In-Memory Storage

The secret value is loaded directly into the application's memory:

- **Never written to disk** - no `.env` file, no temp file, no swap (ideally)
- **Never committed to git** - the code references a secret ID/name, not the value
- **Never baked into Docker images** - the image is identical across all environments
- **Never visible in CI/CD** - pipelines build images without any secrets

### Step 4: Graceful Shutdown

When the application shuts down or is restarted:

- In-memory secrets are **garbage collected** with the process
- No secrets remain on the filesystem
- New instances retrieve fresh secrets on startup
- If rotation occurred, the new instance automatically gets the latest version

## Key Security Properties

| Property | Traditional .env | Runtime Retrieval |
|----------|-----------------|-------------------|
| Secrets in git? | ❌ Yes | ✅ No (only secret names) |
| Secrets in CI/CD? | ❌ Yes | ✅ No |
| Secrets in Docker image? | ❌ Yes (baked in) | ✅ No (image is clean) |
| Secrets in registry? | ❌ Yes | ✅ No |
| Secrets on disk? | ❌ Yes (.env file) | ✅ No (in-memory only) |
| Rotation support? | ❌ Manual redeploy | ✅ Automatic / on-demand |
| Audit trail? | ❌ None | ✅ Full API logging |
| Access control? | ❌ Everyone with repo | ✅ IAM policies / Vault policies |
| Revocation? | ❌ Impossible | ✅ Instant (revoke IAM/policy) |

## What Changes in Your Code

The application code changes are minimal. Instead of reading from environment variables or `.env` files, you call the secret manager API at startup:

```python
# Before (insecure - reads from .env)
import os
db_password = os.environ["DB_PASSWORD"]

# After (secure - retrieves from secret manager at runtime)
import boto3
client = boto3.client("secretsmanager")
secret = client.get_secret_value(SecretId="prod/db/password")
db_password = secret["SecretString"]
```

The key insight is that **the code references a secret by name/ID, not by value**. The actual secret value only exists in the secret manager and in the application's memory at runtime.

## Next Steps

- [03-cicd-integration.md](./03-cicd-integration.md) - How this fits into CI/CD pipelines
- [04-kubernetes-secret-injection.md](./04-kubernetes-secret-injection.md) - Kubernetes-specific patterns
- [05-secret-rotation.md](./05-secret-rotation.md) - How secret rotation works