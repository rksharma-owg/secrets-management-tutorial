"""
Azure Key Vault Integration Module
====================================
This module demonstrates how to securely fetch secrets from Azure Key Vault
using the azure-identity and azure-keyvault-secrets SDKs.

Security rationale
------------------
* Authentication uses `DefaultAzureCredential`, which tries multiple identity
  providers in order (Managed Identity → Environment Variables → Visual
  Studio Code → Azure CLI → Interactive Browser).  This means:
  - On Azure (VMs, App Service, AKS): Managed Identity is used automatically
    with NO credentials in the environment at all — the identity is bound to
    the compute resource.
  - In local dev: Azure CLI or VS Code credentials are picked up.
  - No service principals or client secrets need to be stored anywhere.
* The Key Vault URL is the only configuration needed, sourced from the
  AZURE_VAULT_URL environment variable.
* Key Vault supports secret versioning, expiration dates, and access
  policies that restrict which identities can read which secrets.
* All secret values remain in memory and are never logged.

Prerequisites
-------------
  pip install azure-identity azure-keyvault-secrets
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from azure.core.exceptions import HttpResponseError, ResourceNotFoundError
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import KeyVaultSecret, SecretClient

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("azure_secrets")
logger.setLevel(logging.INFO)


def _log_event(event: str, secret_name: str | None = None, **extra: Any) -> None:
    """Emit a structured log entry, redacting any sensitive keys."""
    payload = {"event": event, "secret_name": secret_name, **extra}
    for k, v in payload.items():
        if any(s in k.lower() for s in ("key", "token", "secret", "password", "value")):
            payload[k] = "***REDACTED***"
    logger.info(payload)


class AzureKeyVaultManager:
    """High-level wrapper around Azure Key Vault for secret retrieval.

    Each secret in Key Vault can be a simple string or a JSON blob.
    For structured config (DB creds, JWT settings, OpenAI keys) we store
    a JSON string and parse it here, giving us typed access.
    """

    DEFAULT_OPENAI_SECRET = "openai-config"
    DEFAULT_DB_SECRET = "database-credentials"
    DEFAULT_JWT_SECRET = "jwt-config"

    def __init__(
        self,
        vault_url: str | None = None,
        openai_secret_name: str | None = None,
        db_secret_name: str | None = None,
        jwt_secret_name: str | None = None,
    ) -> None:
        # ------------------------------------------------------------------
        # Bootstrapping from environment variables:
        #   AZURE_VAULT_URL    — e.g. "https://my-vault.vault.azure.net/"
        #   AZURE_TENANT_ID    — optional, helps DefaultAzureCredential
        #   AZURE_CLIENT_ID    — optional, for service principal fallback
        #   AZURE_CLIENT_SECRET — optional, for service principal fallback
        #
        # SECURITY: Prefer Managed Identity when running on Azure.
        # Service principal credentials are a fallback for environments
        # where Managed Identity is not available.
        # ------------------------------------------------------------------
        self._vault_url = vault_url or os.environ["AZURE_VAULT_URL"]

        _log_event(
            "azure_kv_init",
            extra={
                "vault_url": self._vault_url,
                "tenant_id_set": bool(os.getenv("AZURE_TENANT_ID")),
                "client_id_set": bool(os.getenv("AZURE_CLIENT_ID")),
                "client_secret_set": bool(os.getenv("AZURE_CLIENT_SECRET")),
            },
        )

        # DefaultAzureCredential automatically selects the right auth
        # method based on the runtime environment.
        self._credential = DefaultAzureCredential()

        # Verify connectivity eagerly
        try:
            self._client = SecretClient(
                vault_url=self._vault_url,
                credential=self._credential,
            )
            # The Azure SDK is lazy — force a lightweight call to confirm
            # auth works (get_properties_of_secrets is a list operation).
            list(self._client.get_properties_of_secrets().by_page())
        except HttpResponseError as exc:
            _log_event("azure_kv_auth_failed", error=str(exc))
            raise

        # Resolve secret names
        self._openai_secret = (
            openai_secret_name
            or os.getenv("AZURE_SECRET_OPENAI", self.DEFAULT_OPENAI_SECRET)
        )
        self._db_secret = (
            db_secret_name
            or os.getenv("AZURE_SECRET_DB", self.DEFAULT_DB_SECRET)
        )
        self._jwt_secret = (
            jwt_secret_name
            or os.getenv("AZURE_SECRET_JWT", self.DEFAULT_JWT_SECRET)
        )

    # ------------------------------------------------------------------
    # Core fetch
    # ------------------------------------------------------------------
    def get_secret(self, secret_name: str, version: str | None = None) -> str:
        """Fetch a raw secret value by name.

        Args:
            secret_name: The name of the secret in Key Vault.
            version:     Optional version ID (a GUID).  Omit for latest.

        Returns:
            The raw string value of the secret.

        Raises:
            ResourceNotFoundError: secret does not exist.
            HttpResponseError:     permission denied or service error.
        """
        _log_event("fetching_secret", secret_name=secret_name, version=version)

        try:
            if version:
                secret: KeyVaultSecret = self._client.get_secret(
                    secret_name, version=version
                )
            else:
                secret = self._client.get_secret(secret_name)
        except ResourceNotFoundError:
            _log_event("secret_not_found", secret_name=secret_name)
            raise
        except HttpResponseError as exc:
            _log_event(
                "fetch_secret_error",
                secret_name=secret_name,
                status_code=exc.status_code,
            )
            raise

        _log_event(
            "secret_fetched",
            secret_name=secret_name,
            version=secret.properties.version,
            expires_on=str(secret.properties.expires_on or "never"),
        )
        return secret.value

    def get_secret_json(self, secret_name: str, version: str | None = None) -> dict[str, Any]:
        """Fetch a secret and parse it as JSON.

        Key Vault stores everything as strings.  For structured configuration
        we store JSON and parse it here.  This gives us type-safe access.
        """
        raw = self.get_secret(secret_name, version)
        try:
            return json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Secret '{secret_name}' is not valid JSON"
            ) from exc

    # ------------------------------------------------------------------
    # Typed convenience methods
    # ------------------------------------------------------------------
    def get_database_credentials(self) -> dict[str, Any]:
        """Return database connection parameters from Key Vault.

        Expected JSON shape:
        {
            "engine": "postgresql",
            "host": "mydb.postgres.database.azure.com",
            "port": 5432,
            "username": "app_user",
            "password": "<sensitive>",
            "dbname": "app_db",
            "ssl_mode": "require"
        }
        """
        creds = self.get_secret_json(self._db_secret)
        required = {"host", "username", "password", "dbname"}
        missing = required - set(creds.keys())
        if missing:
            raise ValueError(f"DB secret missing fields: {missing}")
        return creds

    def get_jwt_config(self) -> dict[str, Any]:
        """Return JWT signing configuration from Key Vault.

        Expected JSON shape:
        {
            "algorithm": "RS256",
            "secret_key": "<signing-key>",
            "access_token_ttl_minutes": 15,
            "refresh_token_ttl_days": 7
        }
        """
        config = self.get_secret_json(self._jwt_secret)
        if "secret_key" not in config:
            raise ValueError("JWT secret missing 'secret_key' field")
        return config

    def get_openai_config(self) -> dict[str, Any]:
        """Return OpenAI API configuration from Key Vault.

        Expected JSON shape:
        {
            "api_key": "sk-...",
            "organization_id": "org-...",
            "default_model": "gpt-4"
        }
        """
        config = self.get_secret_json(self._openai_secret)
        if "api_key" not in config:
            raise ValueError("OpenAI secret missing 'api_key' field")
        return config

    # ------------------------------------------------------------------
    # Metadata helpers
    # ------------------------------------------------------------------
    def get_secret_metadata(self, secret_name: str) -> dict[str, Any]:
        """Return metadata about a secret (not the value itself).

        Useful for auditing: when was it created/updated?  Does it expire?
        """
        props = self._client.get_secret_properties(secret_name)
        return {
            "name": secret_name,
            "version": props.version,
            "created_on": str(props.created_on),
            "updated_on": str(props.updated_on),
            "expires_on": str(props.expires_on or "never"),
            "enabled": props.enabled,
            "content_type": props.content_type,
        }


# ---------------------------------------------------------------------------
# Quick-start demonstration
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    try:
        mgr = AzureKeyVaultManager()
        db = mgr.get_database_credentials()
        print(f"DB host: {db['host']}")
        meta = mgr.get_secret_metadata(mgr._db_secret)
        print(f"DB secret version: {meta['version']}")
    except KeyError as exc:
        print(f"AZURE_VAULT_URL not set (expected in local dev): {exc}")
    except Exception as exc:
        print(f"Azure Key Vault error (expected in local dev): {exc}")