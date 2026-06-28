# AWS Secrets Manager - Implementation Guide

## Overview

AWS Secrets Manager is a fully managed service that helps you protect access to your applications, services, and IT resources without the upfront investment and on-going maintenance costs of operating your own infrastructure. It enables you to rotate, manage, and retrieve database credentials, API keys, and other secrets throughout their lifecycle.

### Key Features

- **Automatic rotation** with built-in Lambda rotation functions for RDS, DocumentDB, and Redshift
- **Fine-grained access control** via IAM policies
- **Encryption at rest** using AWS KMS (customer-managed or AWS-managed keys)
- **Audit logging** through AWS CloudTrail
- **Cross-account access** via resource-based policies
- **Secret versioning** with the ability to revert to previous versions

## Prerequisites

### 1. AWS CLI Installed and Configured

```bash
# Install AWS CLI (macOS)
brew install awscli

# Install AWS CLI (Linux)
curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"
unzip awscliv2.zip
sudo ./aws/install

# Verify installation
aws --version

# Configure credentials
aws configure
# AWS Access Key ID: [your key]
# AWS Secret Access Key: [your secret]
# Default region: us-east-1
# Default output format: json
```

### 2. Required IAM Permissions

The principal creating and managing secrets needs at minimum:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:CreateSecret",
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:DeleteSecret",
        "secretsmanager:DescribeSecret",
        "secretsmanager:RotateSecret",
        "secretsmanager:UpdateSecretVersionStage",
        "secretsmanager:ListSecretVersionIds"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/*"
    }
  ]
}
```

## Creating Secrets

### Using the AWS CLI

#### Create a Simple Secret (Plaintext)

```bash
# Create a secret with a plaintext string value
aws secretsmanager create-secret \
  --name prod/my-app/database-password \
  --description "Production database password for my-app" \
  --secret-string "MyS3cur3P@ssw0rd!" \
  --tags Key=Environment,Value=production Key=Application,Value=my-app
```

#### Create a Secret with JSON Structure

```bash
# Create a secret containing a JSON object (recommended for multiple values)
aws secretsmanager create-secret \
  --name prod/my-app/database-config \
  --description "Production database configuration" \
  --secret-string '{
    "username": "app_user",
    "password": "MyS3cur3P@ssw0rd!",
    "host": "prod-db.cluster-abc123.us-east-1.rds.amazonaws.com",
    "port": 5432,
    "database": "myapp_production",
    "ssl_mode": "require"
  }'
```

#### Create a Secret for an RDS Database (with rotation)

```bash
# Create a secret for RDS with automatic rotation
aws secretsmanager create-secret \
  --name prod/my-app/rds-credentials \
  --description "RDS PostgreSQL credentials with auto-rotation" \
  --secret-string '{
    "username": "app_user",
    "password": "InitialP@ssw0rd!"
  }' \
  --generate-client-secret-token
```

### Retrieve a Secret

```bash
# Get the current secret value
aws secretsmanager get-secret-value \
  --secret-id prod/my-app/database-config

# Get a specific version
aws secretsmanager get-secret-value \
  --secret-id prod/my-app/database-config \
  --version-stage AWSCURRENT

# List all versions of a secret
aws secretsmanager list-secret-version-ids \
  --secret-id prod/my-app/database-config
```

## Configuring Automatic Rotation

### Enable Rotation for RDS PostgreSQL

#### Step 1: Create the Rotation Lambda Function

AWS provides managed Lambda rotation templates. Use the appropriate template:

```bash
# Clone the rotation templates
git clone https://github.com/aws-samples/aws-secrets-manager-rotation-lambdas.git

# Deploy the appropriate template (e.g., SecretsManagerRDSPostgreSQLRotationSingleUser)
cd aws-secrets-manager-rotation-lambdas
aws lambda create-function \
  --function-name rotate-rds-postgresql-secret \
  --runtime python3.12 \
  --role arn:aws:iam::123456789012:role/lambda-secret-rotation-role \
  --handler SecretsManagerRDSPostgreSQLRotationSingleUser.handler \
  --zip-file fileb://SecretsManagerRDSPostgreSQLRotationSingleUser.zip \
  --environment Variables={
    SECRETS_MANAGER_ENDPOINT="https://secretsmanager.us-east-1.amazonaws.com"
  }
```

#### Step 2: Grant Lambda Permission to Rotate

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:PutSecretValue",
        "secretsmanager:DescribeSecret",
        "secretsmanager:UpdateSecretVersionStage"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/my-app/rds-credentials-*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "rds-db:connect"
      ],
      "Resource": "arn:aws:rds-db:us-east-1:123456789012:dbuser:*/app_user"
    },
    {
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/*"
    }
  ]
}
```

#### Step 3: Enable Rotation on the Secret

```bash
aws secretsmanager rotate-secret \
  --secret-id prod/my-app/rds-credentials \
  --rotation-lambda-arn arn:aws:lambda:us-east-1:123456789012:function:rotate-rds-postgresql-secret \
  --rotation-rules AutomaticallyAfterDays=30
```

### Enable Rotation for Non-RDS Secrets

For API keys and other non-database secrets, use a custom Lambda function:

```bash
aws secretsmanager rotate-secret \
  --secret-id prod/my-app/api-key \
  --rotation-lambda-arn arn:aws:lambda:us-east-1:123456789012:function:rotate-api-key \
  --rotation-rules AutomaticallyAfterDays=90
```

## Application Access IAM Policy

### Minimum Policy for Application to Read a Secret

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowReadSpecificSecret",
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue"
      ],
      "Resource": "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/my-app/database-config-*"
    },
    {
      "Sid": "AllowKMSDecrypt",
      "Effect": "Allow",
      "Action": [
        "kms:Decrypt"
      ],
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/your-kms-key-id",
      "Condition": {
        "StringEquals": {
          "kms:Decrypt": "true"
        }
      }
    }
  ]
}
```

### IAM Role for EKS Pod (IRSA)

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "secretsmanager:GetSecretValue",
        "secretsmanager:DescribeSecret"
      ],
      "Resource": [
        "arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/my-app/*"
      ]
    }
  ]
}
```

## Code Examples

### Python (boto3)

```python
import boto3
import json
import os

def get_secret(secret_id: str, region: str = "us-east-1") -> dict:
    """Retrieve a secret from AWS Secrets Manager.

    Uses IAM role credentials automatically when running on EC2 or EKS.
    """
    client = boto3.client("secretsmanager", region_name=region)

    response = client.get_secret_value(SecretId=secret_id)

    if "SecretString" in response:
        return json.loads(response["SecretString"])
    else:
        # Binary secret (e.g., certificate)
        return response["SecretBinary"]

# Usage
secret = get_secret("prod/my-app/database-config")
db_url = (
    f"postgresql://{secret['username']}:{secret['password']}"
    f"@{secret['host']}:{secret['port']}/{secret['database']}"
)
print(f"Connected to: {secret['host']}")  # Never print the password!
```

### Python with Connection Pooling and Rotation Support

```python
import boto3
import json
import hashlib
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

class SecretWithRotation:
    """Manages a secret that supports automatic rotation detection."""

    def __init__(self, secret_id: str, region: str = "us-east-1",
                 check_interval: int = 300):
        self.secret_id = secret_id
        self.client = boto3.client("secretsmanager", region_name=region)
        self.check_interval = check_interval
        self._last_hash = None
        self._last_check = None
        self._value = None

    def get_value(self) -> dict:
        """Get the current secret value, checking for rotation."""
        now = datetime.utcnow()
        if (self._last_check is None or
            (now - self._last_check).total_seconds() > self.check_interval):
            self._refresh()
        return self._value

    def _refresh(self):
        """Fetch the latest secret and detect rotation."""
        response = self.client.get_secret_value(SecretId=self.secret_id)
        raw = response["SecretString"]
        current_hash = hashlib.sha256(raw.encode()).digest()

        if self._last_hash and current_hash != self._last_hash:
            logger.info("Secret rotation detected for %s", self.secret_id)
            # Trigger connection refresh in your application

        self._last_hash = current_hash
        self._last_check = datetime.utcnow()
        self._value = json.loads(raw)
```

### Node.js (AWS SDK v3)

```javascript
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

const client = new SecretsManagerClient({ region: "us-east-1" });

async function getSecret(secretId) {
  const command = new GetSecretValueCommand({ SecretId: secretId });
  const response = await client.send(command);

  if (response.SecretString) {
    return JSON.parse(response.SecretString);
  }
  throw new Error("Binary secrets not supported in this example");
}

// Usage
const config = await getSecret("prod/my-app/database-config");
const dbUrl = `postgresql://${config.username}:${config.password}@${config.host}:${config.port}/${config.database}`;
console.log(`Connected to: ${config.host}`); // Never log the password!
```

### Node.js with Rotation Detection

```javascript
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";
import { createHash } from "crypto";

const client = new SecretsManagerClient({ region: "us-east-1" });

class RotatingSecret {
  constructor(secretId, { checkIntervalMs = 300_000 } = {}) {
    this.secretId = secretId;
    this.checkIntervalMs = checkIntervalMs;
    this.lastHash = null;
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
    const command = new GetSecretValueCommand({ SecretId: this.secretId });
    const response = await client.send(command);
    const raw = response.SecretString;
    const currentHash = createHash("sha256").update(raw).digest();

    if (this.lastHash && !currentHash.equals(this.lastHash)) {
      console.log(`Secret rotation detected for ${this.secretId}`);
      // Trigger your connection refresh logic here
    }

    this.lastHash = currentHash;
    this.lastCheck = Date.now();
    this.value = JSON.parse(raw);
  }
}
```

## Cost Overview

| Component | Free Tier | Paid |
|-----------|-----------|------|
| Secrets stored | 30 secrets/month | $0.40/secret/month |
| API calls (10,000) | 10,000/month (free) | $0.05/10,000 calls |
| Rotation (Lambda) | 1M GB-seconds free | Per Lambda pricing |

**Typical production cost estimate:**
- 20 secrets: $8.00/month
- 100K API calls/month: $0.45/month
- Rotation Lambda: ~$0.50/month (minimal)
- **Total: ~$9/month** for a typical production workload

## Security Considerations

### Encryption

- All secrets are encrypted at rest using **AWS KMS**
- Default encryption uses `aws/secretsmanager` (AWS-managed key)
- **Use a customer-managed KMS key** for production to enable:
  - Key rotation
  - Cross-account access
  - Custom key policies
  - Audit via CloudTrail

```bash
# Create a KMS key for secrets encryption
aws kms create-key \
  --description "KMS key for Secrets Manager encryption" \
  --tag Key=Purpose,Value=secrets-manager-encryption

# Create a secret with a customer-managed key
aws secretsmanager create-secret \
  --name prod/my-app/secret \
  --kms-key-id arn:aws:kms:us-east-1:123456789012:key/your-key-id \
  --secret-string "secret-value"
```

### Least Privilege

- Each application should have an IAM policy that allows access to **only its own secrets**
- Use **resource-level permissions** (ARN-based) not wildcard
- The rotation Lambda should only be able to rotate the secrets it's responsible for
- Consider using **resource-based policies** for cross-account access instead of IAM role assumption

### Audit and Monitoring

- All Secrets Manager API calls are logged to **AWS CloudTrail**
- Enable **CloudTrail** in all regions where you use Secrets Manager
- Set up **CloudWatch Alarms** for:
  - `DeleteSecret` calls (should be rare)
  - Failed `GetSecretValue` calls (permission issues)
  - Rotation failures
  - Access from unexpected IP addresses or IAM principals

### Secret Naming Convention

```
{environment}/{application}/{service}/{secret-type}
```

Examples:
- `prod/payment-service/database/password`
- `staging/auth-service/api/jwt-signing-key`
- `dev/notification-service/twilio/api-key`

This convention enables:
- IAM policies with path-based wildcards: `prod/payment-service/*`
- Easy identification of what a secret is for
- Clear environment separation

## Next Steps

- [../architecture/02-secure-runtime-retrieval.md](../architecture/02-secure-runtime-retrieval.md) - Architecture overview
- [../architecture/04-kubernetes-secret-injection.md](../architecture/04-kubernetes-secret-injection.md) - Kubernetes IRSA setup
- [../architecture/05-secret-rotation.md](../architecture/05-secret-rotation.md) - Rotation lifecycle details