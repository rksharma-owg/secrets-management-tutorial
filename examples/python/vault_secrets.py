"""
HashiCorp Vault Integration Module
====================================
This module demonstrates how to securely fetch secrets from a HashiCorp
Vault KV v2 secret engine using the `hvac` Python client.

Security rationale
------------------
* The Vault address and authentication token are read from environment
  variables (VAULT_ADDR, VAULT_TOKEN).  In production you would use
  short-lived tokens issued by Vault's auth methods (AppRole, Kubernetes,
  JWT/OIDC) rather than long-lived root tokens.
* Vault's KV v2 engine versions every secret write, so you can roll back
  to a previous value if a rotation goes wrong.
* Dynamic secrets (e.g. database credentials generated on-the-fly) have
  a built-in lease / TTL, meaning credentials are automatically revoked
  after a configurable period — even if the application crashes.
* All secret values stay in memory and are never logged.
"""

import logging
import os
from typing import Any

import hvac
from hvac.exceptions import InvalidRequest, VaultError

# ---------------------------------------------------------------------------
# Structured logging — same pattern as aws_secrets.py.
# We log *which* secret was accessed and *whether* it succeeded, never the
# actual secret material.
# ---------------------------------------------------------------------------
logger = logging.getLogger("vault_secrets")
logger.setLevel(logging.INFO)


def _log_event(event: str, path: str | None = None, **extra: Any) -> None:
    """Emit a structured log entry, redacting any sensitive-looking keys."""
    payload = {"event": event, "vault_path": path, **extra}
    for k, v in payload.items():
        if any(s in k.lower() for s in ("key", "token", "secret", "password")):
            payload[k] = "***REDACTED***"
    logger.info(payload)


class VaultSecretsManager:
    """High-level wrapper around HashiCorp Vault KV v2 secrets.

    Vault KV v2 paths look like:  secret/data/<mount>/<name>
    The actual data lives under response["data"]["data"].
    Metadata (version, created time, custom metadata) lives under
    response["data"]["metadata"].
    """

    # Default paths — override via constructor args or env vars.
    DEFAULT_MOUNT = "secret"
    DEFAULT_OPENAI_PATH = "openai/config"
    DEFAULT_DB_PATH = "database/credentials"
    DEFAULT_JWT_PATH = "jwt/config"

    def __init__(
        self,
        vault_addr: str | None = None,
        token: str | None = None,
        mount: str | None = None,
        namespace: str | None = None,
        verify_tls: bool = True,
    ) -> None:
        # ------------------------------------------------------------------
        # Bootstrapping from environment variables:
        #   VAULT_ADDR  — URL of the Vault server (required)
        #   VAULT_TOKEN — client token for authentication
        #   VAULT_NAMESPACE — Vault enterprise namespace (optional)
        #
        # SECURITY: Tokens should be short-lived and obtained via an
        # auth method (AppRole, K8s, JWT/OIDC), NOT a root token.
        # ------------------------------------------------------------------
        self._addr = vault_addr or os.environ["VAULT_ADDR"]
        self._token = token or os.environ.get("VAULT_TOKEN", "")
        self._mount = mount or os.getenv("VAULT_KV_MOUNT", self.DEFAULT_MOUNT)
        self._namespace = namespace or os.getenv("VAULT_NAMESPACE")

        _log_event(
            "vault_client_init",
            extra={
                "addr": self._addr,  # URL is not secret
                "mount": self._mount,
                "has_token": bool(self._token),  # log presence, not value
            },
        )

        self._client = hvac.Client(
            url=self._addr,
            token=self._token,
            namespace=self._namespace,
            verify=verify_tls,
        )

        # Verify connectivity at construction time so we fail fast.
        if not self._client.is_authenticated():
            raise VaultError(
                "Vault client is not authenticated — check VAULT_ADDR and VAULT_TOKEN"
            )

        # Resolve secret paths
        self._openai_path = os.getenv(
            "VAULT_SECRET_OPENAI", self.DEFAULT_OPENAI_PATH
        )
        self._db_path = os.getenv(
            "VAULT_SECRET_DB", self.DEFAULT_DB_PATH
        )
        self._jwt_path = os.getenv(
            "VAULT_SECRET_JWT", self.DEFAULT_JWT_PATH
        )

    # ------------------------------------------------------------------
    # Core fetch
    # ------------------------------------------------------------------
    def get_secret(self, path: str, version: int | None = None) -> dict[str, Any]:
        """Read a secret from KV v2 and return its data dict.

        Args:
            path:    Secret path *relative to the mount* (e.g. "database/creds").
            version: Optional version number to fetch a specific version.

        In KV v2 the API is:  GET /v1/secret/data/<path>
        The hvac client handles the "secret/data/" prefix for us when
        using ``kv.v2.read_secret_version()``.

        Raises:
            InvalidRequest: secret does not exist or access is denied.
            VaultError:     generic Vault communication error.
        """
        full_path = f"{self._mount}/{path}"
        _log_event("fetching_secret", path=full_path, requested_version=version)

        try:
            read_kwargs: dict[str, Any] = {"path": path, "mount_point": self._mount}
            if version is not None:
                read_kwargs["version"] = version
            response = self._client.secrets.kv.v2.read_secret_version(**read_kwargs)
        except InvalidRequest as exc:
            _log_event("fetch_secret_denied", path=full_path)
            raise
        except VaultError as exc:
            _log_event("fetch_secret_error", path=full_path, error=str(exc))
            raise

        # KV v2 nests actual data under "data" → "data"
        data: dict[str, Any] = response["data"]["data"]
        metadata: dict[str, Any] = response["data"]["metadata"]

        _log_event(
            "secret_fetched",
            path=full_path,
            version=metadata.get("version"),
            created_time=metadata.get("created_time"),
        )
        return data

    # ------------------------------------------------------------------
    # Typed convenience methods
    # ------------------------------------------------------------------
    def get_database_credentials(self) -> dict[str, Any]:
        """Return database credentials from Vault.

        Expected secret shape:
        {
            "engine": "postgresql",
            "host": "db.example.com",
            "port": 5432,
            "username": "app_user",
            "password": "<sensitive>",
            "dbname": "app_db"
        }

        NOTE: For truly dynamic credentials, use Vault's database secrets
        engine which generates a new username/password pair with a lease
        TTL.  That approach is even more secure because credentials are
        automatically revoked when the lease expires.
        """
        creds = self.get_secret(self._db_path)
        required = {"host", "username", "password", "dbname"}
        missing = required - set(creds.keys())
        if missing:
            raise ValueError(f"DB secret missing fields: {missing}")
        return creds

    def get_jwt_config(self) -> dict[str, Any]:
        """Return JWT signing configuration from Vault.

        Expected shape: {"algorithm": "HS256", "secret_key": "...", ...}
        """
        config = self.get_secret(self._jwt_path)
        if "secret_key" not in config:
            raise ValueError("JWT secret missing 'secret_key' field")
        return config

    def get_openai_config(self) -> dict[str, Any]:
        """Return OpenAI API configuration from Vault.

        Expected shape: {"api_key": "sk-...", "organization_id": "org-...", ...}
        """
        config = self.get_secret(self._openai_path)
        if "api_key" not in config:
            raise ValueError("OpenAI secret missing 'api_key' field")
        return config

    # ------------------------------------------------------------------
    # Versioning helpers
    # ------------------------------------------------------------------
    def get_secret_versions(self, path: str) -> list[int]:
        """List all versions of a KV v2 secret.

        Vault keeps every version by default, which is invaluable for
        auditing and rollback.  This method returns a list of version
        numbers.
        """
        try:
            metadata = self._client.secrets.kv.v2.read_secret_metadata(
                path=path, mount_point=self._mount
            )
        except InvalidRequest:
            _log_event("list_versions_denied", path=path)
            raise

        versions = list(metadata["data"]["versions"].keys())
        _log_event("versions_listed", path=path, count=len(versions))
        return [int(v) for v in versions]

    def get_previous_version(self, path: str) -> dict[str, Any]:
        """Fetch the previous version of a secret (useful for rollback)."""
        versions = self.get_secret_versions(path)
        if len(versions) < 2:
            raise ValueError(f"Secret '{path}' has only one version — no previous")
        previous = versions[-2]
        return self.get_secret(path, version=previous)


# ---------------------------------------------------------------------------
# Quick-start demonstration
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    try:
        mgr = VaultSecretsManager()
        db = mgr.get_database_credentials()
        print(f"DB host: {db['host']}")
    except KeyError as exc:
        print(f"VAULT_ADDR or VAULT_TOKEN not set (expected in local dev): {exc}")
    except Exception as exc:
        print(f"Vault error (expected in local dev): {exc}")