# Architecture: Kubernetes Secret Injection Patterns

> Three production-ready approaches for injecting secrets into Kubernetes Pods, each with different tradeoffs.

## Diagram

```mermaid
flowchart TB
    subgraph approach1["🔵 Approach 1: Vault Agent Injector (Sidecar Pattern)"]
        direction TB
        A1["<b>1. Mutating Webhook</b><br/>Vault Agent Injector intercepts<br/>Pod creation request"]
        A2["<b>2. Vault Agent Sidecar</b><br/>Injected as init container +<br/>running sidecar container"]
        A3["<b>3. Authenticate</b><br/>Sidecar authenticates to<br/>Vault using K8s SA token"]
        A4["<b>4. Retrieve Secrets</b><br/>Agent fetches secrets<br/>from Vault KV engine"]
        A5["<b>5. Render Templates</b><br/>Consul Template renders<br/>secrets into files"]
        A6["<b>6. Shared Volume</b><br/>Secrets written to<br/>shared emptyDir volume"]
        A7["<b>7. App Reads</b><br/>Application reads secrets<br/>from shared volume"]
        A8["<b>8. Continuous Sync</b><br/>Sidecar watches for<br/>changes & re-renders"]

        A1 --> A2 --> A3 --> A4 --> A5 --> A6 --> A7
        A8 -.->|"watches &<br/>updates"| A6
    end

    subgraph approach2["🟠 Approach 2: External Secrets Operator (CRD-Based Sync)"]
        direction TB
        B1["<b>1. ExternalSecret CRD</b><br/>Developer creates<br/>ExternalSecret manifest"]
        B2["<b>2. Operator Reconciles</b><br/>External Secrets Operator<br/>watches for CRD resources"]
        B3["<b>3. Authenticate</b><br/>Operator uses configured<br/>credentials (SA, IAM, etc.)"]
        B4["<b>4. Fetch from Provider</b><br/>Operator calls Vault,<br/>AWS SM, or Azure KV"]
        B5["<b>5. Create K8s Secret</b><br/>Operator creates/updates<br/>native K8s Secret object"]
        B6["<b>6. Pod Mounts Secret</b><br/>Pod references the<br/>K8s Secret via volumes<br/>or env vars"]
        B7["<b>7. App Reads</b><br/>Application reads from<br/>mounted volume or env"]
        B8["<b>8. Sync Interval</b><br/>Operator refreshes<br/>at configurable interval"]

        B1 --> B2 --> B3 --> B4 --> B5 --> B6 --> B7
        B8 -.->|"periodic<br/>refresh"| B4
    end

    subgraph approach3["🟢 Approach 3: IRSA for AWS (OIDC Federation)"]
        direction TB
        C1["<b>1. Pod Starts</b><br/>Pod created with<br/>ServiceAccount annotated<br/>with IAM role ARN"]
        C2["<b>2. EKS OIDC</b><br/>EKS cluster has OIDC<br/>identity provider<br/>configured"]
        C3["<b>3. Pod IAM Token</b><br/>kubelet injects projected<br/>service account token<br/>into pod"]
        C4["<b>4. STS AssumeRole</b><br/>App calls AWS STS with<br/>OIDC token to assume<br/>IAM role"]
        C5["<b>5. Temp Credentials</b><br/>STS returns temporary<br/>AWS credentials<br/>(1 hour TTL)"]
        C6["<b>6. Call Secrets Mgr</b><br/>App uses temp creds<br/>to call Secrets Manager<br/>GetSecretValue API"]
        C7["<b>7. In-Memory Only</b><br/>Secret loaded into<br/>application memory<br/>no disk, no K8s Secret"]
        C8["<b>8. Cred Auto-Rotation</b><br/>AWS SDK auto-refreshes<br/>STS creds before expiry"]

        C1 --> C2 --> C3 --> C4 --> C5 --> C6 --> C7
        C8 -.->|"auto-refresh<br/>before expiry"| C5
    end

    style A1 fill:#e3f2fd,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    style A2 fill:#bbdefb,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    style A3 fill:#bbdefb,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    style A4 fill:#90caf9,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    style A5 fill:#90caf9,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    style A6 fill:#64b5f6,stroke:#1565c0,stroke-width:2px,color:#ffffff
    style A7 fill:#64b5f6,stroke:#1565c0,stroke-width:2px,color:#ffffff
    style A8 fill:#bbdefb,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    style approach1 fill:#e8eaf6,stroke:#3f51b5,stroke-width:2px

    style B1 fill:#fff3e0,stroke:#e65100,stroke-width:2px,color:#bf360c
    style B2 fill:#ffe0b2,stroke:#e65100,stroke-width:2px,color:#bf360c
    style B3 fill:#ffe0b2,stroke:#e65100,stroke-width:2px,color:#bf360c
    style B4 fill:#ffcc80,stroke:#e65100,stroke-width:2px,color:#bf360c
    style B5 fill:#ffb74d,stroke:#e65100,stroke-width:2px,color:#3e2723
    style B6 fill:#ffcc80,stroke:#e65100,stroke-width:2px,color:#bf360c
    style B7 fill:#ffcc80,stroke:#e65100,stroke-width:2px,color:#bf360c
    style B8 fill:#ffe0b2,stroke:#e65100,stroke-width:2px,color:#bf360c
    style approach2 fill:#fff8e1,stroke:#ff8f00,stroke-width:2px

    style C1 fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style C2 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style C3 fill:#c8e6c9,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style C4 fill:#a5d6a7,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style C5 fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#ffffff
    style C6 fill:#81c784,stroke:#2e7d32,stroke-width:2px,color:#ffffff
    style C7 fill:#66bb6a,stroke:#2e7d32,stroke-width:3px,color:#ffffff
    style C8 fill:#a5d6a7,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style approach3 fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
```

## Approach Comparison

| Feature | Vault Agent Injector | External Secrets Operator | IRSA (AWS) |
|---------|---------------------|--------------------------|------------|
| **Provider** | HashiCorp Vault | Multi-provider | AWS Only |
| **Secret Location** | Shared emptyDir volume | K8s Secret object | Application memory |
| **Sidecar Needed?** | Yes (Vault Agent) | No (cluster-wide operator) | No |
| **Secret on Disk?** | Yes (emptyDir, RAM-backed) | Yes (etcd, encrypted) | No |
| **Rotation** | Continuous (sidecar watches) | Periodic (configurable interval) | On fetch |
| **Setup Complexity** | Medium | Medium | Low (if on EKS) |
| **Multi-Cloud?** | Yes | Yes | No |
| **Native K8s Integration** | Medium (mutation webhook) | High (CRDs) | High (IAM roles for SA) |
| **Zero-Trust?** | Yes (Vault policies) | Medium (depends on provider) | Yes (IAM policies) |

---

## Approach 1: Vault Agent Injector (Sidecar Pattern)

### How It Works

The Vault Agent Injector is a Kubernetes **Mutating Admission Webhook** that automatically:

1. **Intercepts** Pod creation requests that have specific Vault annotations
2. **Injects** a Vault Agent sidecar container alongside your application container
3. **Injects** a shared `emptyDir` volume (can be backed by `memory` medium)
4. The sidecar **authenticates** to Vault using the pod's Kubernetes ServiceAccount token
5. The sidecar **retrieves** secrets from Vault's KV engine
6. **Consul Template** renders the secrets into configuration files on the shared volume
7. The sidecar **continuously watches** for secret changes and re-renders

### Key Configuration

```yaml
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    metadata:
      annotations:
        vault.hashicorp.com/agent-inject: "true"
        vault.hashicorp.com/role: "my-app"
        vault.hashicorp.com/secret-volume-path: "/vault/secrets"
        vault.hashicorp.com/agent-inject-secret-config: "secret/data/my-app/config"
        vault.hashicorp.com/agent-inject-template-config: |
          {{- with secret "secret/data/my-app/config" -}}
          DATABASE_URL={{ .Data.data.db_url }}
          {{- end }}
    spec:
      serviceAccountName: my-app-sa
      containers:
        - name: my-app
          volumeMounts:
            - name: vault-secrets
              mountPath: /vault/secrets
      volumes:
        - name: vault-secrets
          emptyDir:
            medium: Memory  # RAM-backed, never hits disk
```

### Pros
- **Continuous sync** - secrets updated automatically without pod restart
- **Template rendering** - transform secrets into any config format
- **Fine-grained access** - Vault policies per application
- **Multi-cloud** - works with any Kubernetes cluster

### Cons
- **Sidecar overhead** - extra container per pod (CPU/memory)
- **EmptyDir on disk** unless you use `medium: Memory`
- **Vault dependency** - requires running Vault infrastructure

---

## Approach 2: External Secrets Operator (CRD-Based Sync)

### How It Works

The External Secrets Operator (ESO) is a **Kubernetes operator** that:

1. **Watches** for `ExternalSecret` custom resources
2. **Authenticates** to the external secret provider using configured credentials
3. **Fetches** secrets from the provider (Vault, AWS SM, Azure KV, GCP SM, etc.)
4. **Creates or updates** a native Kubernetes `Secret` object
5. **Periodically refreshes** at a configurable interval (default: 1m)

### Key Configuration

```yaml
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: my-app-secrets
spec:
  refreshInterval: 15m
  secretStoreRef:
    name: aws-secrets-store
    kind: ClusterSecretStore
  target:
    name: my-app-secrets
    creationPolicy: Owner
  data:
    - secretKey: db_password
      remoteRef:
        key: prod/db/password
    - secretKey: api_key
      remoteRef:
        key: prod/api/key
---
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: my-app
          env:
            - name: DB_PASSWORD
              valueFrom:
                secretKeyRef:
                  name: my-app-secrets
                  key: db_password
```

### Pros
- **Native Kubernetes UX** - uses CRDs, works with existing Secret references
- **Multi-provider** - Vault, AWS, Azure, GCP, 1Password, CyberArk, etc.
- **No sidecar** - single operator for the whole cluster
- **Familiar pattern** - secrets end up as K8s Secrets that pods already know how to use

### Cons
- **Secrets in etcd** - K8s Secrets are stored in etcd (should be encrypted at rest)
- **Periodic sync** - not real-time (configurable interval)
- **Operator dependency** - another operator to maintain in the cluster
- **Blast radius** - anyone with `get secret` permission can read secrets

---

## Approach 3: IRSA for AWS (OIDC Federation)

### How It Works

IAM Roles for Service Accounts (IRSA) uses **OIDC federation** to map Kubernetes ServiceAccounts to AWS IAM roles:

1. **EKS cluster** is configured with an OIDC identity provider (using AWS IAM OpenID Connect)
2. **IAM role** has a trust policy that allows the K8s ServiceAccount to assume it
3. **ServiceAccount** is annotated with the IAM role ARN
4. **kubelet** injects a projected ServiceAccount token (OIDC JWT) into the pod
5. **AWS SDK** automatically discovers the token and calls STS `AssumeRoleWithWebIdentity`
6. **STS** returns temporary AWS credentials (1-hour TTL, auto-refreshed)
7. **Application** uses the credentials to call Secrets Manager directly
8. **Secrets loaded into memory** - never touch disk or K8s etcd

### Key Configuration

```yaml
# IAM Trust Policy
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::111122223333:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:sub": "system:serviceaccount:default:my-app-sa",
        "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B716D3041E:aud": "sts.amazonaws.com"
      }
    }
  }]
}
```

```yaml
# Kubernetes ServiceAccount
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-app-sa
  namespace: default
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::111122223333:role/my-app-role
```

### Pros
- **No secrets on disk** - pure in-memory, the most secure option
- **No sidecar** - no additional containers or operators needed
- **Automatic credential rotation** - AWS SDK handles STS token refresh
- **Fine-grained IAM** - per-pod IAM policies
- **Simplest to implement** on EKS

### Cons
- **AWS-only** - requires EKS (or self-managed K8s with OIDC setup)
- **Application code changes** - app must call AWS SDK directly
- **No secret rendering** - raw secret values returned, app must parse them
- **Cold start delay** - STS assume role adds ~100-200ms to startup

---

## Which Approach Should You Choose?

| Scenario | Recommended Approach |
|----------|---------------------|
| Running on EKS with AWS-only secrets | **IRSA** - simplest, most secure |
| Multi-cloud or hybrid environment | **External Secrets Operator** - provider-agnostic |
| Already using Vault enterprise features | **Vault Agent Injector** - full Vault feature set |
| Need dynamic database credentials | **Vault Agent Injector** - Vault's database engine |
| Want simplest migration from K8s Secrets | **External Secrets Operator** - same UX |
| Maximum security (zero disk) | **IRSA** or **Vault with memory-backed emptyDir** |
| Need secret rendering/templates | **Vault Agent Injector** - Consul Template |

## Next Steps

- [05-secret-rotation.md](./05-secret-rotation.md) - How rotation works with each approach
- [../hashicorp-vault/README.md](../hashicorp-vault/README.md) - Vault setup guide
- [../aws-secrets-manager/README.md](../aws-secrets-manager/README.md) - AWS Secrets Manager guide