# HashiCorp Vault - Implementation Guide

## Overview

HashiCorp Vault is a tool for securely accessing secrets. A secret is anything that you want to tightly control access to, such as API keys, passwords, certificates, and encryption keys. Vault provides a unified interface to any secret, while providing tight access control and recording a complete audit trail.

### Key Features

- **Dynamic secrets** - generates unique, short-lived credentials on demand
- **Encryption as a service** - encrypt/decrypt data without managing keys
- **Lease and renewal** - every secret has a TTL and can be renewed
- **Revocation** - instant revocation of any secret or token
- **Multiple auth methods** - Kubernetes, IAM, JWT, LDAP, OIDC, AppRole
- **Audit logging** - detailed log of every access and operation

## Prerequisites

### 1. Install Vault

```bash
# macOS
brew install vault

# Linux (Ubuntu/Debian)
sudo apt-get update && sudo apt-get install -y wget unzip
wget https://releases.hashicorp.com/vault/1.17.4/vault_1.17.4_linux_amd64.zip
unzip vault_1.17.4_linux_amd64.zip
sudo mv vault /usr/local/bin/
sudo chmod +x /usr/local/bin/vault

# Verify
vault version
```

### 2. Install Vault CLI autocomplete (optional)

```bash
vault -autocomplete-install
complete -C /usr/local/bin/vault vault
```

## Dev Server Setup

> **Warning:** The dev server is for local development only. It stores everything in memory and resets on restart. Never use in production.

```bash
# Start dev server (auto-unseals, root token displayed)
vault server -dev -dev-root-token-id="root" -dev-listen-address="127.0.0.1:8200"

# In another terminal, set environment variables
export VAULT_ADDR='http://127.0.0.1:8200'
export VAULT_TOKEN='root'

# Verify
vault status
```

## Enabling Secret Engines

### KV v2 (Key-Value Version 2) - Recommended for Static Secrets

```bash
# Enable KV v2 engine at the "secret" path
vault secrets enable -path=secret kv-v2

# Write a secret (KV v2 wraps data in a "data" key)
vault kv put secret/my-app/database \
  username=app_user \
  password="MyS3cur3P@ssw0rd!" \
  host="db.example.com" \
  port=5432 \
  database="myapp_production"

# Read a secret
vault kv get secret/my-app/database

# Read as JSON (for scripting)
vault kv get -format=json secret/my-app/database | jq -r '.data.data'

# List secrets at a path
vault kv list secret/my-app/

# Create a new version (KV v2 maintains version history)
vault kv put secret/my-app/database password="N3wP@ssw0rd!"

# View version history
vault kv metadata get secret/my-app/database

# Rollback to a previous version
vault kv undelete -versions=1 secret/my-app/database
```

### Database Secrets Engine - Dynamic Credentials

```bash
# Enable the database secrets engine
vault secrets enable database

# Configure PostgreSQL connection
vault write database/config/my-postgresql \
  plugin_name=postgresql-database-plugin \
  allowed_roles="my-app-readonly","my-app-readwrite" \
  connection_url="postgresql://{{username}}:{{password}}@db.example.com:5432/mydb?sslmode=require" \
  username="vault_admin" \
  password="vault_admin_password"

# Create a role that generates read-only credentials
vault write database/roles/my-app-readonly \
  db_name=my-postgresql \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"

# Create a role that generates read-write credentials
vault write database/roles/my-app-readwrite \
  db_name=my-postgresql \
  creation_statements="CREATE ROLE \"{{name}}\" WITH LOGIN PASSWORD '{{password}}' VALID UNTIL '{{expiration}}'; GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \"{{name}}\";" \
  default_ttl="1h" \
  max_ttl="24h"

# Generate dynamic credentials (each call creates a unique username/password)
vault read database/creds/my-app-readonly

# Output example:
# Key                Value
# ---                -----
# lease_id           database/creds/my-app-readonly/abc123
# lease_duration     1h
# lease_renewable    true
# password           vault-generated-random-password
# username           v_token_my-app-readonly_abc123
```

### Transit Secrets Engine - Encryption as a Service

```bash
# Enable transit engine
vault secrets enable transit

# Create an encryption key
vault write -f transit/keys/my-app-encryption

# Encrypt data
vault write transit/encrypt/my-app-encryption \
  plaintext=$(base64 <<< "sensitive data to encrypt")

# Decrypt data
vault write transit/decrypt/my-app-encryption \
  ciphertext="vault:v1:encrypted-output-here"

# Generate a data encryption key (DEK) wrapped by the transit key
vault write transit/datakey/plaintext/my-app-encryption
```

## Policy Examples (HCL)

### Application Read-Only Policy

```hcl
# policies/my-app-readonly.hcl
# Allow application to read its specific secrets

path "secret/data/my-app/*" {
  capabilities = ["read"]
}

# Allow listing secrets under my-app
path "secret/metadata/my-app/" {
  capabilities = ["list"]
}

# Deny everything else
path "secret/*" {
  capabilities = ["deny"]
}
```

### Database Dynamic Credentials Policy

```hcl
# policies/my-app-database.hcl
# Allow application to generate dynamic database credentials

path "database/creds/my-app-readonly" {
  capabilities = ["read"]
}

# Allow lease renewal (to extend credential lifetime)
path "sys/leases/renew" {
  capabilities = ["update"]
}

# Allow lease lookup
path "sys/leases/lookup" {
  capabilities = ["update"]
}
```

### Admin Policy (Restricted)

```hcl
# policies/secrets-admin.hcl
# Manage secrets (but NOT Vault configuration)

path "secret/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Manage database engine configurations
path "database/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Manage policies
path "sys/policies/acl/*" {
  capabilities = ["create", "read", "update", "delete", "list"]
}

# Read audit logs
path "sys/audit" {
  capabilities = ["read", "list"]
}
```

### Write and Apply Policies

```bash
# Write a policy file
cat > policies/my-app-readonly.hcl << 'EOF'
path "secret/data/my-app/*" {
  capabilities = ["read"]
}
path "secret/metadata/my-app/" {
  capabilities = ["list"]
}
EOF

# Apply the policy
vault policy write my-app-readonly policies/my-app-readonly.hcl

# List all policies
vault policy list

# Read a policy
vault policy read my-app-readonly
```

## Kubernetes Authentication Setup

```bash
# Enable Kubernetes auth method
vault auth enable kubernetes

# Configure Kubernetes auth (use the K8s API from within the cluster)
vault write auth/kubernetes/config \
  kubernetes_host="https://kubernetes.default.svc:443" \
  kubernetes_ca_cert=@/var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  token_reviewer_jwt="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"

# Create a Vault role that maps to a K8s ServiceAccount
vault write auth/kubernetes/role/my-app \
  bound_service_account_names=my-app-sa \
  bound_service_account_namespaces=default,production \
  policies=my-app-readonly,my-app-database \
  ttl=1h \
  max_ttl=24h
```

## Audit Logging Configuration

### File Audit Log

```bash
# Enable file-based audit logging
vault audit enable file file_path=/var/log/vault-audit.log

# Enable with JSON formatting
vault audit enable file file_path=/var/log/vault-audit.log log_format=json

# List enabled audit devices
vault audit list

# Disable an audit device
vault audit disable file/
```

### Syslog Audit Log

```bash
# Enable syslog audit logging
vault audit enable syslog \
  tag="vault-audit" \
  facility="AUTH" \
  log_level="info"
```

### Audit Log Format

Each audit log entry is a JSON object containing:
- `type` - request or response
- `time` - ISO 8601 timestamp
- `auth` - authentication details (token, policies, accessor)
- `request` - API path, operation, data (with secrets hashed)
- `response` - HTTP status, data (with secrets hashed)

> **Important:** Vault **never logs secret values**. Secret values in request/response data are replaced with HMAC hashes for audit verification without exposure.

## Code Examples

### Python (hvac library)

```python
import hvac
import os

# Authenticate using Kubernetes ServiceAccount token
client = hvac.Client(url="https://vault.example.com:8200")

# Method 1: Kubernetes auth (recommended for K8s deployments)
with open("/var/run/secrets/kubernetes.io/serviceaccount/token") as f:
    jwt_token = f.read().strip()

client.auth.kubernetes.login(
    role="my-app",
    jwt=jwt_token
)

# Method 2: AppRole auth (for non-K8s deployments)
client.auth.approle.login(
    role_id=os.environ["VAULT_ROLE_ID"],
    secret_id=os.environ["VAULT_SECRET_ID"]
)

# Read a KV v2 secret
response = client.secrets.kv.v2.read_secret_version(
    path="my-app/database",
    mount_point="secret"
)
db_config = response["data"]["data"]
print(f"Connected to: {db_config['host']}")  # Never print the password!

# Generate dynamic database credentials
creds = client.secrets.database.generate_credentials(
    name="my-app-readonly"
)
print(f"DB User: {creds['data']['username']}")
print(f"DB Pass: {creds['data']['password']}")  # Use immediately, expires in 1h!
print(f"Lease ID: {creds['lease_id']}")
print(f"Lease Duration: {creds['lease_duration']}s")

# Renew a lease before it expires
client.sys.renew_lease(lease_id=creds["lease_id"], increment=3600)

# Encrypt data using Transit engine
plaintext = "sensitive data"
import base64
encoded = base64.b64encode(plaintext.encode()).decode()
encrypt_response = client.secrets.transit.encrypt_data(
    name="my-app-encryption",
    plaintext=encoded
)
ciphertext = encrypt_response["data"]["ciphertext"]
```

### Node.js (node-vault library)

```javascript
import Vault from "node-vault";
import fs from "fs";

const vault = Vault({
  apiVersion: "v1",
  endpoint: "https://vault.example.com:8200",
  token: process.env.VAULT_TOKEN, // Or use Kubernetes auth below
});

// Kubernetes authentication
async function loginWithK8s() {
  const jwt = fs.readFileSync(
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "utf8"
  ).trim();

  const result = await vault.write("auth/kubernetes/login", {
    role: "my-app",
    jwt: jwt,
  });

  vault.token = result.auth.client_token;
  return result.auth;
}

// Read a KV v2 secret
async function getSecret(path) {
  const result = await vault.read(`secret/data/${path}`);
  return result.data.data;
}

// Usage
const dbConfig = await getSecret("my-app/database");
console.log(`Connected to: ${dbConfig.host}`);

// Generate dynamic database credentials
async function getDbCredentials(role) {
  const result = await vault.read(`database/creds/${role}`);
  return {
    username: result.data.username,
    password: result.data.password,
    leaseId: result.lease_id,
    leaseDuration: result.lease_duration,
  };
}

// Encrypt using Transit engine
import { encode } from "base64-arraybuffer";

async function encryptData(plaintext) {
  const encoded = Buffer.from(plaintext).toString("base64");
  const result = await vault.write("transit/encrypt/my-app-encryption", {
    plaintext: encoded,
  });
  return result.data.ciphertext;
}
```

## Production Deployment Considerations

### High Availability

- Deploy Vault in **HA mode** with Raft storage (integrated storage)
- Minimum **3 nodes** for quorum and fault tolerance
- Use **auto-unseal** with AWS KMS, Azure Key Vault, or GCP KMS
- Place Vault behind a **load balancer** with health checks

### Auto-Unseal with AWS KMS

```hcl
# vault-config.hcl
storage "raft" {
  path    = "/opt/vault/raft"
  node_id = "vault-node-1"
}

listener "tcp" {
  address     = "0.0.0.0:8200"
  tls_cert_file = "/etc/vault/tls/vault.crt"
  tls_key_file  = "/etc/vault/tls/vault.key"
  tls_client_ca_file = "/etc/vault/tls/ca.crt"
}

api_addr = "https://vault-internal.example.com:8200"
cluster_addr = "https://vault-node-1.example.com:8201"

seal "awskms" {
  region     = "us-east-1"
  access_key = "..."  # Use IAM role instead
  secret_key = "..."  # Use IAM role instead
  kms_key_id = "arn:aws:kms:us-east-1:123456789012:key/your-key-id"
}

ui = true
disable_mlock = false
```

### TLS Configuration

- **Always use TLS** in production (never HTTP)
- Use certificates from your internal CA or Let's Encrypt
- Set `tls_client_ca_file` for mTLS (client certificate verification)
- Enable `tls_min_version = "tls12"` or higher

### Backup and Recovery

- Raft storage supports **built-in snapshots**
- Take regular snapshots: `vault operator raft snapshot save backup.snap`
- Store snapshots in encrypted, access-controlled storage (S3, etc.)
- Test **restore procedures** regularly in a non-production environment

### Monitoring

- Expose Vault **Telemetry** (Prometheus format) at `/v1/sys/metrics`
- Monitor key metrics:
  - `vault.core.unsealed` (should be 1)
  - `vault.audit.log.request.*` (request counts)
  - `vault.token.count` (active tokens)
  - `vault.lease.count` (active leases)
- Set up alerts for **seal status changes** and **auth failures**

## Next Steps

- [../architecture/02-secure-runtime-retrieval.md](../architecture/02-secure-runtime-retrieval.md) - Architecture overview
- [../architecture/04-kubernetes-secret-injection.md](../architecture/04-kubernetes-secret-injection.md) - Vault Agent Injector pattern
- [../aws-secrets-manager/README.md](../aws-secrets-manager/README.md) - Compare with AWS approach