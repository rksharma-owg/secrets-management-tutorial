# Architecture: CI/CD Integration with Runtime Secret Retrieval

> The goal: CI/CD pipelines build and deploy **identical, secret-free artifacts**. Secrets are completely outside the CI/CD flow.

## Diagram

```mermaid
flowchart TB
    subgraph dev["💻 Developer"]
        direction TB
        A["<b>Developer</b><br/>Writes application code<br/>References secrets by NAME<br/>e.g. 'prod/db/password'<br/>✅ No secret values"]
    end

    subgraph git_repo["📁 Git Repository"]
        direction TB
        B["<b>Source Code</b><br/>Application logic<br/>Dockerfile<br/>Kubernetes manifests<br/>✅ Clean - no secrets"]
        B1["<b>.env.example</b><br/>Placeholder values only<br/>✅ Safe template"]
    end

    subgraph cicd["🔧 CI/CD Pipeline"]
        direction TB
        C["<b>Build Stage</b><br/>npm install / pip install<br/>Run unit tests (with mocks)<br/>Build Docker image<br/>✅ No secrets needed"]
        C1["<b>Test Stage</b><br/>Integration tests use<br/>test/CI-specific secrets<br/>or mock services<br/>✅ Test secrets only"]
        C2["<b>Push Stage</b><br/>Push image to registry<br/>Update deployment manifest<br/>Trigger deploy<br/>✅ No production secrets"]
    end

    subgraph registry["📦 Container Registry"]
        direction TB
        D["<b>Docker Image</b><br/>App code + dependencies<br/>NO secrets baked in<br/>Same image for all envs<br/>✅ Clean artifact"]
    end

    subgraph k8s["☸️ Kubernetes Cluster"]
        direction TB
        E["<b>Deployment Controller</b><br/>Pulls image from registry<br/>Creates new Pods<br/>✅ No secrets in manifest"]
        E1["<b>Pod Spec</b><br/>References IAM role /<br/>ServiceAccount / ManagedIdentity<br/>✅ Identity config only"]
        E2["<b>Pod Running</b><br/>Application starts<br/>Authenticates via identity<br/>Requests secrets at runtime"]
    end

    subgraph secrets["🔐 Secret Manager - OUTSIDE CI/CD"]
        direction TB
        F["<b>AWS Secrets Manager</b><br/>or HashiCorp Vault<br/>or Azure Key Vault<br/>✅ Secrets stored here"]
        F1["<b>Secret Rotation</b><br/>Automatic schedule<br/>Independent of deploys<br/>✅ Rotates on its own"]
    end

    subgraph runtime["🧠 Runtime Secret Flow"]
        direction TB
        G["<b>Pod authenticates</b><br/>IAM role / Vault token<br/>Azure managed identity"]
        H["<b>Secret retrieved</b><br/>Via TLS API call<br/>Into memory only"]
        I["<b>App uses secrets</b><br/>DB connections<br/>API calls<br/>✅ In-memory only"]
    end

    A -->|"git push<br/>code + .env.example"} B
    B -->|"webhook / trigger"} C
    C --> C1
    C1 --> C2
    C2 -->|"docker push"} D
    C2 -->|"kubectl apply"} E
    D -->|"image pull"} E
    E --> E1
    E1 --> E2
    E2 --> G
    G -->|"authenticated request"} F
    F -->|"returns secret"} H
    H --> I

    F1 -.->|"rotates secret<br/>independently"} F
    I -.->|"on next fetch<br/>gets new version"} F1

    style A fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style B fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style B1 fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style C fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style C1 fill:#fff3cd,stroke:#ffc107,stroke-width:2px,color:#856404
    style C2 fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style D fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style E fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style E1 fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style E2 fill:#c8e6c9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
    style F fill:#bbdefb,stroke:#1565c0,stroke-width:3px,color:#0d47a1
    style F1 fill:#bbdefb,stroke:#1565c0,stroke-width:2px,color:#0d47a1
    style G fill:#c8e6c9,stroke:#388e3c,stroke-width:2px,color:#1b5e20
    style H fill:#a5d6a7,stroke:#2e7d32,stroke-width:2px,color:#1b5e20
    style I fill:#a5d6a7,stroke:#2e7d32,stroke-width:2px,color:#1b5e20

    style dev fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
    style git_repo fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
    style cicd fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
    style registry fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
    style k8s fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
    style secrets fill:#e3f2fd,stroke:#1565c0,stroke-width:3px
    style runtime fill:#c8e6c9,stroke:#388e3c,stroke-width:2px
```

## How CI/CD Works Without Secrets

### Build Stage

The CI/CD pipeline builds the application **without any production secrets**:

- **Unit tests** use mock objects or test doubles instead of real database credentials
- **Docker image** contains only application code and dependencies
- **No `.env` files** are copied into the image
- The Dockerfile uses `ARG` for build-time variables only (e.g., `NODE_ENV=production`)

### Test Stage

Integration and end-to-end tests need secrets, but these are handled separately:

- **CI-specific test secrets** can be stored in the CI platform's secret store (GitHub Secrets, GitLab Variables)
- These are **different credentials** from production (least privilege for CI)
- Prefer **mock services** or **ephemeral test databases** over real credentials
- CI secrets should be scoped to the pipeline and rotated regularly

### Push & Deploy Stage

The deployment stage is just orchestration:

- Push the **secret-free image** to the container registry
- Apply **Kubernetes manifests** that reference IAM roles, ServiceAccounts, or managed identities
- The manifest tells Kubernetes *how* the pod will authenticate, not *what* the secrets are
- No secrets are needed to deploy

### Runtime Secret Retrieval (Post-Deploy)

Only after the pod is running does it interact with the secret manager:

1. The pod's **identity** (IAM role, ServiceAccount token, managed identity) authenticates it
2. The application **calls the secret manager API** to retrieve secrets
3. Secrets are stored **in memory only**
4. The application functions normally

## Secret Rotation is Independent

One of the most powerful aspects of this architecture is that **secret rotation is decoupled from deployments**:

- **AWS Secrets Manager** can automatically rotate secrets on a schedule (e.g., every 30 days)
- **HashiCorp Vault** can generate dynamic credentials with short TTLs (minutes/hours)
- **Azure Key Vault** supports automatic rotation of certificates and secrets
- When a secret is rotated, the application simply **fetches the new version on next startup or refresh**
- No new Docker image, no new deployment, no CI/CD pipeline run needed

## Handling CI/CD Secrets

Your CI/CD pipeline itself may need some secrets (e.g., Docker registry credentials, deployment keys). These should be:

1. **Stored in the CI platform's native secret store** (GitHub Secrets, GitLab CI/CD Variables)
2. **Never logged** - use masking features in your CI platform
3. **Scoped to the minimum needed** - separate secrets for build vs. deploy stages
4. **Rotated regularly** - treat CI secrets with the same care as production secrets
5. **Distinct from application secrets** - CI secrets grant pipeline permissions, not application data access

## Comparison: Before vs. After

| Aspect | Before (Secrets in CI/CD) | After (Runtime Retrieval) |
|--------|--------------------------|--------------------------|
| Docker image | Contains secrets | Clean, reusable artifact |
| Registry | Stores secrets | Stores code only |
| Deployment | Requires secrets | Requires identity config only |
| Rotation | Rebuild + redeploy | Automatic, no deploy needed |
| Blast radius | Image + registry + git | Secret manager only |
| Compliance | Secrets scattered everywhere | Secrets in one audited location |

## Next Steps

- [04-kubernetes-secret-injection.md](./04-kubernetes-secret-injection.md) - Detailed Kubernetes patterns
- [05-secret-rotation.md](./05-secret-rotation.md) - Secret rotation strategies
- [../aws-secrets-manager/README.md](../aws-secrets-manager/README.md) - AWS implementation guide