# Kubernetes Secrets Management — Manifest Files

This directory contains production-quality Kubernetes manifest files demonstrating multiple approaches to secrets management. Each file is extensively commented for educational purposes.

## Prerequisites

- **Kubernetes cluster** (v1.24+ recommended)
- **kubectl** configured with cluster access
- **Helm 3** (for Vault installation)
- **Cloud provider CLI** (AWS CLI, Azure CLI) if using cloud secret managers
- **Appropriate IAM/permissions** for your chosen secret management approach

## Manifest Files (Use in Order)

### 1. `01-vault-install.yaml` — HashiCorp Vault Reference Deployment

A reference deployment showing the key Kubernetes resources behind a Vault installation. **Use the Helm chart for actual installation** (this file is for understanding the concepts).

```bash
# Reference only — install Vault via Helm:
helm repo add hashicorp https://helm.releases.hashicorp.com
helm install vault hashicorp/vault --namespace vault --create-namespace
```

### 2. `02-vault-agent-injector.yaml` — Vault Agent Sidecar Injection

Demonstrates how the Vault Agent Injector mutates pods at creation time to inject secrets as environment variables and files. Includes:

- ConfigMap with Vault Agent HCL configuration
- Consul Template files for secret rendering
- Deployment with comprehensive `vault.hashicorp.com/*` annotations
- Examples for database credentials, API keys, and JWT secrets

### 3. `03-external-secrets-operator.yaml` — External Secrets Operator

Complete ESO examples showing synchronization from three providers:

| Resource | Provider |
|----------|----------|
| `SecretStore` + `ExternalSecret` | AWS Secrets Manager |
| `SecretStore` + `ExternalSecret` | Azure Key Vault |
| `SecretStore` + `ExternalSecret` | HashiCorp Vault |
| `ClusterSecretStore` | AWS (cluster-wide) |

### 4. `04-irsa-aws-secrets.yaml` — IAM Roles for Service Accounts (IRSA)

Demonstrates the AWS EKS IRSA pattern for credential-less secret access:

- ServiceAccount with `eks.amazonaws.com/role-arn` annotation
- IAM policy and trust policy documentation (as comments)
- Detailed explanation of the OIDC federation flow
- Example using AWS SDK directly and via ESO

### 5. `05-native-k8s-secrets.yaml` — Native Kubernetes Secrets (With Caveats)

Shows the built-in K8s Secret mechanism with extensive warnings about its limitations:

- Secret with base64-encoded values
- Deployment consuming secrets via environment variables
- Deployment consuming secrets via volume mounts
- Detailed explanation of why native secrets are not recommended for production

## Comparison of Approaches

| Feature | Native K8s Secrets | Vault Agent Injector | External Secrets Operator |
|---------|-------------------|---------------------|--------------------------|
| **Secret storage** | etcd (base64) | Vault (encrypted) | External provider |
| **Encryption at rest** | Optional (etcd encryption) | Yes (built-in) | Provider-dependent |
| **Automatic rotation** | No | Yes (lease renewal) | Yes (refresh interval) |
| **Audit logging** | Limited (API audit) | Comprehensive | Provider-dependent |
| **Fine-grained RBAC** | K8s RBAC (resource-level) | Vault policies (path-level) | K8s RBAC + provider IAM |
| **Multi-cluster support** | No (manual sync) | Yes (shared Vault) | Yes (shared external store) |
| **Secret versioning** | No | Yes | Yes (AWS SM, Vault) |
| **Operational complexity** | Low | High | Medium |
| **App code changes** | None | None | None |
| **Cost** | Free | Compute (Vault cluster) | Free (operator) + cloud costs |

## Recommended Approach by Use Case

| Use Case | Recommended |
|----------|------------|
| Quick dev/testing | Native K8s Secrets |
| Production single-cluster, multi-provider | External Secrets Operator |
| Production with dynamic secrets (DB creds) | Vault Agent Injector |
| AWS EKS workloads | IRSA + External Secrets Operator |
| Maximum security/compliance | Vault (full deployment) |
| GitOps with sealed secrets | Sealed Secrets + ESO |

## Security Considerations

1. **Never commit secrets to Git** — Use Sealed Secrets, SOPS, or ESO to keep secrets out of source control.
2. **Enable etcd encryption** — Even if using ESO or Vault, encrypt etcd to protect any remaining native secrets.
3. **Use IRSA / Workload Identity** — Never store static cloud credentials in K8s Secrets.
4. **Apply least-privilege RBAC** — ServiceAccounts should only have access to the secrets they need.
5. **Use network policies** — Restrict pod-to-Vault and pod-to-cloud-API traffic.
6. **Rotate regularly** — Even with automation, test your rotation procedures.
7. **Audit access** — Enable Vault audit logs and AWS CloudTrail for secret access auditing.
8. **Scan for leaked secrets** — Use tools like TruffleHog, Gitleaks, or AWS's built-in scanning.