# Architecture: Traditional .env Approach and Its Risks

> **Warning:** This diagram illustrates an anti-pattern. Do NOT manage secrets this way in production.

## Diagram

```mermaid
flowchart LR
    subgraph dev["💻 Developer Workstation"]
        direction TB
        A["<b>Developer</b><br/>Creates .env file<br/>with DB passwords,<br/>API keys, tokens"]
    end

    subgraph git["📁 Git Repository"]
        direction TB
        B["<b>.env file</b><br/>committed to git<br/>⚡ RISK: Secrets in<br/>version history"]
        B1["<b>.env.example</b><br/>placeholder values<br/>✅ Safe"]
    end

    subgraph ci["🔧 CI/CD Pipeline"]
        direction TB
        C["<b>Pipeline Runner</b><br/>Reads .env at build time<br/>⚡ RISK: Secrets in<br/>build logs & artifacts"]
        C1["<b>CI Environment Vars</b><br/>Injected via UI/config<br/>⚠️ RISK: Visible to<br/>pipeline admins"]
    end

    subgraph docker["🐳 Docker Build"]
        direction TB
        D["<b>Dockerfile</b><br/>COPY .env .env<br/>or ENV vars during build<br/>⚡ RISK: Secrets baked<br/>into image layers"]
        D1["<b>Docker Image</b><br/>Contains secrets in<br/>plaintext in layers<br/>⚡ RISK: Anyone who<br/>pulls the image"]
    end

    subgraph registry["📦 Container Registry"]
        direction TB
        E["<b>Image Registry</b><br/>Docker Hub, ECR, GCR<br/>⚡ RISK: Secrets stored<br/>in registry storage<br/>accessible to anyone<br/>with pull access"]
    end

    subgraph deploy["🚀 Deployment"]
        direction TB
        F["<b>Production Server</b><br/>Secrets on disk<br/>in container filesystem<br/>⚡ RISK: Insider threat,<br/>container escape"]
        F1["<b>Environment Variables</b><br/>visible via /proc/environ<br/>and docker inspect<br/>⚡ RISK: Any process<br/>on the host can read"]
    end

    A -->|"git add .env<br/>git commit"} B
    A -.->|"template only"} B1
    B -->|"git push"} C
    C1 -->|"injected"} C
    C -->|"docker build"} D
    D -->|"docker push"} D1
    D1 -->|"stored"} E
    E -->|"docker pull"} F
    C -->|"env vars passed"} F1

    style A fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style B1 fill:#d4edda,stroke:#28a745,stroke-width:2px,color:#155724
    style B fill:#f8d7da,stroke:#dc3545,stroke-width:3px,color:#721c24
    style C fill:#f8d7da,stroke:#dc3545,stroke-width:3px,color:#721c24
    style C1 fill:#fff3cd,stroke:#ffc107,stroke-width:2px,color:#856404
    style D fill:#f8d7da,stroke:#dc3545,stroke-width:3px,color:#721c24
    style D1 fill:#f8d7da,stroke:#dc3545,stroke-width:3px,color:#721c24
    style E fill:#f8d7da,stroke:#dc3545,stroke-width:3px,color:#721c24
    style F fill:#f8d7da,stroke:#dc3545,stroke-width:3px,color:#721c24
    style F1 fill:#f8d7da,stroke:#dc3545,stroke-width:3px,color:#721c24

    style dev fill:#e8f5e9,stroke:#4caf50,stroke-width:2px
    style git fill:#ffebee,stroke:#f44336,stroke-width:2px
    style ci fill:#fff3e0,stroke:#ff9800,stroke-width:2px
    style docker fill:#ffebee,stroke:#f44336,stroke-width:2px
    style registry fill:#ffebee,stroke:#f44336,stroke-width:2px
    style deploy fill:#ffebee,stroke:#f44336,stroke-width:2px
```

## Risk Analysis

### 1. Secrets Exposed in Git History (CRITICAL)

When a `.env` file containing real credentials is committed to git, those secrets become a **permanent part of the repository history**. Even if you delete the file in a subsequent commit, the secrets remain accessible in previous commits. This means:

- **Every collaborator** with repository access has seen the secrets
- **Forks and clones** retain the full history including secrets
- **Accidental public repos** expose secrets to the entire internet
- **Git history rewriting** (`git filter-branch`, `BFG`) is complex and error-prone
- **Automated secret scanners** (GitHub, GitLab) will flag your repo

> **Real-world impact:** Thousands of API keys, database passwords, and cloud credentials are found on GitHub daily. Companies have been breached because developers committed `.env` files to public repositories.

### 2. Secrets Baked into Docker Images (CRITICAL)

When `.env` files are copied into Docker images or environment variables are set during `docker build`, secrets become **permanently embedded in the image layers**:

- **Every image layer** is a tarball that can be extracted and inspected
- `docker history` and image layer inspection tools can expose secrets
- **Image sharing** (Docker Hub, private registries) distributes the secrets
- **`docker pull`** by any authenticated user gives them the secrets
- Images are often **cached and replicated** across registries, making cleanup impossible

```dockerfile
# DANGEROUS: These patterns bake secrets into the image
COPY .env /app/.env                    # Secret in image layer
ENV DATABASE_URL=postgres://user:pass  # Secret in image config
ARG DB_PASSWORD=mysecret               # Secret in build metadata
```

### 3. Secrets in Container Registry (HIGH)

Once an image with baked-in secrets is pushed to a registry, the attack surface expands:

- **Registry compromise** exposes all stored secrets
- **Broad pull permissions** (common in organizations) give many people access
- **Image tags are mutable** - someone could pull, inspect, and extract secrets
- **Backup and replication** systems copy secrets to multiple locations
- **Compliance violations** - secrets in registries violate PCI, HIPAA, SOC2 requirements

### 4. Secrets in CI/CD Pipeline (HIGH)

CI/CD systems like GitHub Actions, GitLab CI, Jenkins, and CircleCI often store secrets as environment variables:

- **Build logs** can accidentally print secrets (debug output, error messages)
- **Pipeline artifacts** may contain secrets if `.env` is included
- **Third-party integrations** and plugins may have access to pipeline secrets
- **Audit logs** for CI/CD systems may expose secrets
- **Former employees** with pipeline admin access retain secret visibility

### 5. Secrets on Disk in Production (MEDIUM-HIGH)

Even if secrets make it to production, storing them in `.env` files or environment variables on disk is risky:

- **Container inspect** (`docker inspect`) reveals all environment variables
- **`/proc/<pid>/environ`** is readable by other processes on the host
- **File system access** by anyone with container access exposes secrets
- **Logging and monitoring** tools may capture environment variables
- **Backup systems** capture secrets from disk

## Why This Approach Is Dangerous: Summary

| Stage | Risk Level | Secrets Location | Attack Vector |
|-------|-----------|-----------------|---------------|
| Developer | Medium | Local `.env` file | Lost laptop, malware |
| Git Commit | **Critical** | Version history | Repo access, public exposure |
| CI/CD Pipeline | High | Build environment | Pipeline logs, artifacts |
| Docker Build | **Critical** | Image layers | Image inspection, layer extraction |
| Container Registry | High | Registry storage | Registry compromise, pull access |
| Production | Medium-High | Disk / env vars | Container escape, process inspection |

**The fundamental problem:** With the traditional `.env` approach, secrets are **materialized at every stage** of the delivery pipeline. Each materialization point is a potential leak point. A secure approach should minimize the number of places where secrets exist, ideally keeping them **only in memory at runtime**.

## What to Do Instead

See the next diagram: [02-secure-runtime-retrieval.md](./02-secure-runtime-retrieval.md) for the recommended secure approach.