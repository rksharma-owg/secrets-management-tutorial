# AWS Secrets Manager - Terraform Module

This module provisions [AWS Secrets Manager](https://aws.amazon.com/secrets-manager/) resources for securely storing and rotating application secrets including database credentials, API keys, and JWT configuration.

## Prerequisites

- **AWS Account** with appropriate IAM permissions (`secretsmanager:*`, `iam:*`, `kms:*`)
- **Terraform** >= 1.5.0 installed locally or in CI/CD
- **AWS CLI** configured with credentials that have permissions to create the above resources
- **Lambda function** for secret rotation (if `rotation_enabled = true`). Use the [AWS rotation templates](https://docs.aws.amazon.com/secretsmanager/latest/userguide/rotate-secrets_lambda-functions.html) as a starting point.

## Usage

### 1. Create a `terraform.tfvars` file (NEVER commit this)

```hcl
# WARNING: This file contains sensitive values. Add it to .gitignore.
region      = "us-east-1"
environment = "dev"
project_name = "myapp"
```

### 2. Initialize and apply

```bash
# Initialize providers and download plugins
terraform init

# Preview changes — ALWAYS review before applying
terraform plan -var-file="terraform.tfvars"

# Apply changes
terraform apply -var-file="terraform.tfvars"
```

### 3. Update secret values after provisioning

After Terraform creates the secret containers, populate actual values:

```bash
aws secretsmanager put-secret-value \
  --secret-id "myapp-dev/database/credentials" \
  --secret-string '{"username":"admin","password":"RealP@ssw0rd!","host":"db.internal","port":5432,"database":"app_dev","engine":"postgresql"}'
```

## Resources Created

| Resource | Purpose |
|----------|---------|
| `aws_secretsmanager_secret` (x3) | Encrypted secret containers for DB creds, OpenAI key, JWT config |
| `aws_secretsmanager_secret_version` (x3) | Initial placeholder values |
| `aws_secretsmanager_secret_rotation` (x1) | Automatic 30-day rotation for DB credentials |
| `aws_iam_role` (x1) | Application role for secret access (no access keys) |
| `aws_iam_policy` (x1) | Least-privilege read-only policy scoped to specific secrets |
| `aws_iam_role_policy_attachment` (x1) | Attaches the policy to the role |

## Application Integration

Applications should retrieve secrets at **runtime** (not build time):

```python
import boto3
import json

client = boto3.client('secretsmanager')
response = client.get_secret_value(SecretId="myapp-dev/database/credentials")
creds = json.loads(response['SecretString'])
# Use creds['username'], creds['password'], etc.
```

## Cost Estimation

- **Secrets Manager**: $0.40 per secret per month + $0.05 per 10,000 API calls
- **IAM Role/Policy**: Free
- **Estimated monthly cost**: ~$1.20 for 3 secrets with moderate API usage
- See the [AWS Secrets Manager pricing page](https://aws.amazon.com/secrets-manager/pricing/)

## Security Considerations

1. **State file security**: Terraform state contains secret ARNs but should NEVER contain secret values. Use an encrypted S3 backend with DynamoDB state locking.
2. **Least privilege**: The IAM policy grants `GetSecretValue` and `DescribeSecret` only on the three specific secrets — no wildcards, no write access.
3. **Roles over keys**: The module provisions an IAM role (not access keys). Applications assume this role at runtime for short-lived credentials.
4. **Rotation**: Automatic rotation is enabled by default for production. Ensure your rotation Lambda function is tested and can handle the target system's password change mechanics.
5. **VPC Endpoints**: For production, create VPC interface endpoints for Secrets Manager to keep API calls off the public internet.
6. **KMS**: For regulatory compliance, replace the default AWS-managed KMS key with a customer-managed key and apply a restrictive key policy.
