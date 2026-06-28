"""
AWS Secrets Manager Integration Module
=======================================
This module demonstrates how to securely fetch secrets from AWS Secrets Manager
using boto3. All configuration is bootstrapped from environment variables —
never from hardcoded values — so the same code works across dev, staging, and
production with zero changes.

Security rationale
------------------
* Credentials (access key, secret key, session token) come from the
  environment or an IAM instance/profile role.  Nothing is baked into
  source control.
* boto3 resolves credentials transparently via its credential provider
  chain (env vars → ~/.aws/credentials → IAM role).  This means we
  never see or handle raw AWS credentials in application code.
* Secret values are never logged; we log only the *name* of the secret
  that was fetched and whether the operation succeeded.
* SecretString payloads are expected to be JSON, giving us type-safe
  access to structured configuration (e.g. DB host, port, username).
"""

import json
import logging
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError

# ---------------------------------------------------------------------------
# Structured logging — we use JSON-like formatting so log aggregators
# (Datadog, CloudWatch, ELK) can parse fields automatically.
# IMPORTANT: we never include secret *values* in log output.
# ---------------------------------------------------------------------------
logger = logging.getLogger("aws_secrets")
logger.setLevel(logging.INFO)


def _log_event(event: str, secret_name: str | None = None, **extra: Any) -> None:
    """Emit a structured log entry without exposing secret values."""
    payload = {"event": event, "secret_name": secret_name, **extra}
    # Mask any key that looks like it could contain a value
    for k, v in payload.items():
        if any(s in k.lower() for s in ("key", "token", "secret", "password")):
            payload[k] = "***REDACTED***"
    logger.info(payload)


class AWSSecretsManager:
    """High-level wrapper around AWS Secrets Manager.

    Each public method fetches a *specific* secret by name and returns a
    typed, validated dictionary.  Keeping the mapping from secret name
    to expected shape in one place makes it easy to audit what secrets
    the application depends on.
    """

    # Default secret names — override via constructor or env vars so that
    # different environments (dev/stage/prod) can point at different secrets
    # without code changes.
    DEFAULT_OPENAI_SECRET = "prod/openai/config"
    DEFAULT_DB_SECRET = "prod/database/credentials"
    DEFAULT_JWT_SECRET = "prod/jwt/config"

    def __init__(
        self,
        region_name: str | None = None,
        openai_secret_name: str | None = None,
        db_secret_name: str | None = None,
        jwt_secret_name: str | None = None,
    ) -> None:
        # ------------------------------------------------------------------
        # Environment-variable bootstrapping:
        # We read AWS_REGION, AWS_ACCESS_KEY_ID etc. from the environment.
        # boto3's credential chain handles the rest automatically, so we
        # only pass region_name explicitly when the caller provides one
        # (or when AWS_REGION is set).
        # ------------------------------------------------------------------
        self._region = region_name or os.getenv("AWS_REGION", "us-east-1")

        # Log only the region, never the keys themselves
        _log_event("aws_client_init", extra={"region": self._region})

        # Create a boto3 session — this is the recommended way to configure
        # the SDK because it isolates our client from global state.
        session = boto3.session.Session()
        self._client = session.client(
            service_name="secretsmanager",
            region_name=self._region,
        )

        # Resolve secret names: constructor arg > env var > class default
        self._openai_secret = (
            openai_secret_name
            or os.getenv("AWS_SECRET_OPENAI", self.DEFAULT_OPENAI_SECRET)
        )
        self._db_secret = (
            db_secret_name
            or os.getenv("AWS_SECRET_DB", self.DEFAULT_DB_SECRET)
        )
        self._jwt_secret = (
            jwt_secret_name
            or os.getenv("AWS_SECRET_JWT", self.DEFAULT_JWT_SECRET)
        )

    # ------------------------------------------------------------------
    # Core fetch method
    # ------------------------------------------------------------------
    def get_secret(self, secret_name: str) -> dict[str, Any]:
        """Fetch a single secret by name and return it as a parsed dict.

        The secret value stored in AWS Secrets Manager is expected to be a
        JSON string (the AWS console encourages this).  If parsing fails we
        raise a ValueError rather than returning opaque data.

        Raises:
            ClientError: on AWS API failures (access denied, not found, …)
            ValueError: when the secret payload is not valid JSON.
        """
        _log_event("fetching_secret", secret_name=secret_name)
        try:
            response = self._client.get_secret_value(SecretId=secret_name)
        except ClientError as exc:
            # Log the *error code* (e.g. ResourceNotFoundException) but
            # never the raw response body which could leak information.
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            _log_event(
                "fetch_secret_failed",
                secret_name=secret_name,
                error_code=error_code,
            )
            raise

        # Secrets Manager may return SecretString or SecretBinary.
        if "SecretString" in response:
            secret_payload = response["SecretString"]
        elif "SecretBinary" in response:
            # Binary secrets are base64-encoded bytes — decode if needed.
            secret_payload = response["SecretBinary"].decode("utf-8")
        else:
            raise ValueError(f"Secret '{secret_name}' has no string or binary payload")

        try:
            parsed: dict[str, Any] = json.loads(secret_payload)
        except json.JSONDecodeError as exc:
            raise ValueError(
                f"Secret '{secret_name}' is not valid JSON"
            ) from exc

        _log_event("secret_fetched", secret_name=secret_name)
        return parsed

    # ------------------------------------------------------------------
    # Typed convenience methods
    # ------------------------------------------------------------------
    def get_database_credentials(self) -> dict[str, Any]:
        """Return database connection parameters from Secrets Manager.

        Expected secret shape:
        {
            "engine": "postgresql",
            "host": "db.example.com",
            "port": 5432,
            "username": "app_user",
            "password": "<sensitive>",
            "dbname": "app_db",
            "ssl_mode": "require"
        }

        SECURITY NOTE: The password is present in the returned dict.
        The caller must ensure it is never logged or serialized to disk.
        """
        creds = self.get_secret(self._db_secret)
        required_fields = {"host", "username", "password", "dbname"}
        missing = required_fields - set(creds.keys())
        if missing:
            raise ValueError(f"DB secret missing fields: {missing}")
        return creds

    def get_jwt_config(self) -> dict[str, Any]:
        """Return JWT signing configuration from Secrets Manager.

        Expected secret shape:
        {
            "algorithm": "HS256",
            "secret_key": "<signing-key>",
            "access_token_ttl_minutes": 15,
            "refresh_token_ttl_days": 7
        }
        """
        config = self.get_secret(self._jwt_secret)
        required_fields = {"algorithm", "secret_key"}
        missing = required_fields - set(config.keys())
        if missing:
            raise ValueError(f"JWT secret missing fields: {missing}")
        return config

    def get_openai_config(self) -> dict[str, Any]:
        """Return OpenAI API configuration from Secrets Manager.

        Expected secret shape:
        {
            "api_key": "sk-...",
            "organization_id": "org-...",
            "default_model": "gpt-4",
            "max_tokens": 2048
        }
        """
        config = self.get_secret(self._openai_secret)
        if "api_key" not in config:
            raise ValueError("OpenAI secret missing 'api_key' field")
        return config

    # ------------------------------------------------------------------
    # Secret rotation awareness
    # ------------------------------------------------------------------
    def describe_rotation(self, secret_name: str) -> dict[str, Any]:
        """Check whether automatic rotation is configured for a secret.

        Rotation is critical for long-lived secrets like database passwords.
        AWS Secrets Manager can invoke a Lambda function on a schedule to
        rotate the value transparently.  This method lets the application
        verify at startup that rotation is enabled.
        """
        try:
            response = self._client.describe_secret(SecretId=secret_name)
        except ClientError as exc:
            error_code = exc.response.get("Error", {}).get("Code", "Unknown")
            _log_event("describe_rotation_failed", secret_name=secret_name, error_code=error_code)
            raise

        rotation_enabled = response.get("RotationEnabled", False)
        rotation_lambda = response.get("RotationLambdaARN", "")

        _log_event(
            "rotation_status",
            secret_name=secret_name,
            rotation_enabled=rotation_enabled,
            # Log only the Lambda ARN — not any secret material
            rotation_lambda_arn=rotation_lambda or "none",
        )
        return {
            "secret_name": secret_name,
            "rotation_enabled": rotation_enabled,
            "rotation_lambda_arn": rotation_lambda,
        }


# ---------------------------------------------------------------------------
# Quick-start demonstration (run as a script)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    mgr = AWSSecretsManager()

    # Demonstrate fetching each type of secret
    try:
        db_creds = mgr.get_database_credentials()
        print(f"DB host: {db_creds['host']}")  # safe — not a secret
    except Exception as exc:
        print(f"Could not fetch DB creds (expected in local dev): {exc}")

    try:
        jwt_cfg = mgr.get_jwt_config()
        print(f"JWT algorithm: {jwt_cfg['algorithm']}")
    except Exception as exc:
        print(f"Could not fetch JWT config (expected in local dev): {exc}")

    try:
        rotation = mgr.describe_rotation(mgr._db_secret)
        print(f"DB rotation enabled: {rotation['rotation_enabled']}")
    except Exception as exc:
        print(f"Could not describe rotation (expected in local dev): {exc}")