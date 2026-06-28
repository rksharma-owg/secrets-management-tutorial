"""
Secret Manager Factory
=======================
This module implements the *Factory pattern* to decouple application code
from any specific secrets provider (AWS, Vault, Azure).

Why this matters for security and maintainability
-------------------------------------------------
* **Zero vendor lock-in:** Switching from AWS to Vault (or vice versa)
  requires changing ONE environment variable (SECRET_PROVIDER) and
  ensuring the right SDK is installed — no application code changes.
* **Single responsibility:** Every provider implements the same interface.
  Application modules (auth, database, etc.) depend only on the abstract
  interface, never on concrete provider classes.
* **Testability:** In tests you can supply a mock or in-memory provider
  that implements `SecretManager` without spinning up real infrastructure.
* **Auditable:** The abstract base class documents exactly which secrets
  the application expects, making security reviews straightforward.
"""

import logging
import os
from abc import ABC, abstractmethod
from typing import Any

# ---------------------------------------------------------------------------
# Logging — same "no secrets in logs" policy as provider modules.
# ---------------------------------------------------------------------------
logger = logging.getLogger("secret_factory")
logger.setLevel(logging.INFO)


class SecretManager(ABC):
    """Abstract interface that every secrets provider must implement.

    This is the *contract* between the application and its secret store.
    Only methods that the application actually needs are included, keeping
    the surface area small and auditable.
    """

    @abstractmethod
    def get_secret(self, secret_name: str) -> dict[str, Any]:
        """Fetch a generic secret by name and return its data dict."""
        ...

    @abstractmethod
    def get_database_credentials(self) -> dict[str, Any]:
        """Fetch structured database connection parameters."""
        ...

    @abstractmethod
    def get_jwt_config(self) -> dict[str, Any]:
        """Fetch JWT signing configuration."""
        ...

    @abstractmethod
    def get_openai_config(self) -> dict[str, Any]:
        """Fetch OpenAI API configuration."""
        ...


# ---------------------------------------------------------------------------
# Provider-specific imports — we use lazy imports inside factory functions
# so that code depending only on the ABC (e.g. tests) does not require
# all three SDKs to be installed.
# ---------------------------------------------------------------------------

def _create_aws_manager() -> SecretManager:
    """Build an AWSSecretsManager instance.

    All configuration (region, secret names) comes from environment
    variables — see aws_secrets.py for details.
    """
    # Lazy import so Azure/Vault SDKs are not required if unused.
    from aws_secrets import AWSSecretsManager

    logger.info({"event": "creating_provider", "provider": "aws"})
    return AWSSecretsManager()


def _create_vault_manager() -> SecretManager:
    """Build a VaultSecretsManager instance.

    Requires VAULT_ADDR and VAULT_TOKEN environment variables.
    """
    from vault_secrets import VaultSecretsManager

    logger.info({"event": "creating_provider", "provider": "vault"})
    return VaultSecretsManager()


def _create_azure_manager() -> SecretManager:
    """Build an AzureKeyVaultManager instance.

    Requires AZURE_VAULT_URL.  Auth via DefaultAzureCredential.
    """
    from azure_secrets import AzureKeyVaultManager

    logger.info({"event": "creating_provider", "provider": "azure"})
    return AzureKeyVaultManager()


# ---------------------------------------------------------------------------
# Factory registry
# ---------------------------------------------------------------------------
_PROVIDERS: dict[str, type] = {
    "aws": None,   # populated lazily
    "vault": None,
    "azure": None,
}

# We store callables rather than classes to keep imports lazy.
_PROVIDER_FACTORIES: dict[str, Any] = {
    "aws": _create_aws_manager,
    "vault": _create_vault_manager,
    "azure": _create_azure_manager,
}


def get_secret_manager(provider: str | None = None) -> SecretManager:
    """Factory method: return a SecretManager for the given provider.

    The provider is determined by (in priority order):
      1. The ``provider`` argument passed to this function.
      2. The ``SECRET_PROVIDER`` environment variable.
      3. Raises ``ValueError`` if neither is set.

    Valid provider values: "aws", "vault", "azure".

    SECURITY: We log which provider was selected but never any
    configuration values (URLs, tokens, etc.) that could leak.
    """
    resolved = provider or os.getenv("SECRET_PROVIDER")

    if not resolved:
        raise ValueError(
            "No secret provider specified. Set the SECRET_PROVIDER "
            "environment variable to 'aws', 'vault', or 'azure'."
        )

    resolved = resolved.lower().strip()

    factory = _PROVIDER_FACTORIES.get(resolved)
    if factory is None:
        raise ValueError(
            f"Unknown secret provider '{resolved}'. "
            f"Supported: {list(_PROVIDER_FACTORIES.keys())}"
        )

    logger.info({"event": "provider_selected", "provider": resolved})
    return factory()


# ---------------------------------------------------------------------------
# Convenience: a module-level singleton (created on first access)
# ---------------------------------------------------------------------------
_manager_instance: SecretManager | None = None


def get_manager() -> SecretManager:
    """Return a cached SecretManager singleton.

    This avoids creating multiple clients (and thus multiple network
    connections) when different modules in the same process all need
    secrets.  The singleton is created on first call.
    """
    global _manager_instance
    if _manager_instance is None:
        _manager_instance = get_secret_manager()
    return _manager_instance


# ---------------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Simulate selecting a provider via env var
    os.environ.setdefault("SECRET_PROVIDER", "aws")

    try:
        mgr = get_manager()
        print(f"Provider type: {type(mgr).__name__}")
        print("Factory pattern working — application code is provider-agnostic.")
    except Exception as exc:
        print(f"Expected error in local dev (no cloud creds): {exc}")