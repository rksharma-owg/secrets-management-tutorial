"""
JWT Authentication Module
============================
This module handles JWT token creation and verification using signing
secrets fetched from a secret manager at application startup.

Security rationale
------------------
* The signing key is NEVER hardcoded.  It is loaded once from the secret
  manager and held in memory for the lifetime of the process.
* We use short-lived access tokens (default 15 min) and longer-lived
  refresh tokens (default 7 days) to limit the window of abuse if a
  token is compromised.
* Token rotation: when a refresh token is used, the old access token
  is implicitly invalidated because it expires quickly.  A full rotation
  scheme would revoke the refresh token family and issue a new one.
* Tokens include an ``iss`` (issuer) and ``aud`` (audience) claim to
  prevent token confusion attacks between services.
* The ``verify_token`` method checks expiry, issuer, and audience.
"""

import hashlib
import hmac
import logging
import os
import time
from datetime import datetime, timedelta, timezone
from typing import Any

import jwt

# ---------------------------------------------------------------------------
# Structured logging — NEVER log tokens or signing keys.
# ---------------------------------------------------------------------------
logger = logging.getLogger("auth")
logger.setLevel(logging.INFO)


def _safe_log(event: str, **extra: Any) -> None:
    """Log with redaction of any key containing 'token', 'key', or 'secret'."""
    payload = {"event": event, **extra}
    for k in list(payload.keys()):
        if any(s in k.lower() for s in ("token", "key", "secret", "password")):
            payload[k] = "***REDACTED***"
    logger.info(payload)


class JWTAuthManager:
    """Manages JWT creation and verification using secrets from a secret manager.

    Usage:
        config = secret_manager.get_jwt_config()
        auth = JWTAuthManager(config)

        access_token = auth.create_access_token(user_id="u-123")
        payload = auth.verify_token(access_token)
    """

    def __init__(self, jwt_config: dict[str, Any]) -> None:
        """
        Args:
            jwt_config: Dictionary from the secret manager containing at
                minimum "secret_key" and "algorithm".  Optional keys:
                "access_token_ttl_minutes", "refresh_token_ttl_days",
                "issuer", "audience".
        """
        self._secret_key: str = jwt_config["secret_key"]
        self._algorithm: str = jwt_config.get("algorithm", "HS256")
        self._access_ttl: int = jwt_config.get("access_token_ttl_minutes", 15)
        self._refresh_ttl: int = jwt_config.get("refresh_token_ttl_days", 7)
        self._issuer: str = jwt_config.get("issuer", "secrets-tutorial")
        self._audience: str = jwt_config.get("audience", "secrets-tutorial-api")

        # SECURITY: Verify the key length is appropriate for the algorithm.
        # HS256 needs ≥ 256 bits (32 bytes).  Shorter keys are trivially
        # brute-forced.
        key_bytes = len(self._secret_key.encode("utf-8"))
        if self._algorithm.startswith("HS") and key_bytes < 32:
            raise ValueError(
                f"Signing key is only {key_bytes} bytes — "
                f"minimum 32 for {self._algorithm}. Rotate immediately."
            )

        _safe_log(
            "auth_manager_init",
            algorithm=self._algorithm,
            access_ttl_minutes=self._access_ttl,
            refresh_ttl_days=self._refresh_ttl,
            issuer=self._issuer,
        )

    # ------------------------------------------------------------------
    # Token creation
    # ------------------------------------------------------------------
    def create_access_token(
        self,
        user_id: str,
        roles: list[str] | None = None,
        extra_claims: dict[str, Any] | None = None,
    ) -> str:
        """Create a short-lived access token.

        Args:
            user_id:      Unique identifier for the authenticated user.
            roles:        List of role strings (e.g. ["admin", "editor"]).
            extra_claims: Additional custom claims to embed.

        Returns:
            Encoded JWT string.
        """
        now = datetime.now(timezone.utc)
        payload: dict[str, Any] = {
            "sub": user_id,
            "iss": self._issuer,
            "aud": self._audience,
            "iat": now,
            "exp": now + timedelta(minutes=self._access_ttl),
            "type": "access",
        }
        if roles:
            payload["roles"] = roles
        if extra_claims:
            payload.update(extra_claims)

        token = jwt.encode(payload, self._secret_key, algorithm=self._algorithm)
        _safe_log("access_token_created", user_id=user_id)
        return token

    def create_refresh_token(self, user_id: str) -> str:
        """Create a longer-lived refresh token.

        Refresh tokens are used to obtain new access tokens without
        requiring the user to re-authenticate.  They should be stored
        securely (HttpOnly cookie, not localStorage).
        """
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "iss": self._issuer,
            "aud": self._audience,
            "iat": now,
            "exp": now + timedelta(days=self._refresh_ttl),
            "type": "refresh",
        }

        token = jwt.encode(payload, self._secret_key, algorithm=self._algorithm)
        # SECURITY: Log the user_id but NOT the token value.
        _safe_log("refresh_token_created", user_id=user_id)
        return token

    # ------------------------------------------------------------------
    # Token verification
    # ------------------------------------------------------------------
    def verify_token(self, token: str, expected_type: str = "access") -> dict[str, Any]:
        """Verify and decode a JWT.

        Args:
            token:         The encoded JWT string.
            expected_type: "access" or "refresh" — ensures the token was
                           created for the intended purpose.

        Returns:
            Decoded payload dict.

        Raises:
            jwt.ExpiredSignatureError: token has expired.
            jwt.InvalidTokenError:     token is malformed or tampered.
            ValueError:                token type mismatch.
        """
        try:
            payload = jwt.decode(
                token,
                self._secret_key,
                algorithms=[self._algorithm],
                issuer=self._issuer,
                audience=self._audience,
            )
        except jwt.ExpiredSignatureError:
            _safe_log("token_expired", expected_type=expected_type)
            raise
        except jwt.InvalidTokenError as exc:
            _safe_log("token_invalid", expected_type=expected_type)
            raise

        if payload.get("type") != expected_type:
            _safe_log(
                "token_type_mismatch",
                got=payload.get("type"),
                expected=expected_type,
            )
            raise ValueError(f"Expected {expected_type} token, got {payload.get('type')}")

        _safe_log("token_verified", user_id=payload.get("sub"))
        return payload

    # ------------------------------------------------------------------
    # Token rotation
    # ------------------------------------------------------------------
    def rotate_access_token(self, refresh_token: str) -> str:
        """Exchange a valid refresh token for a new access token.

        This is the "token rotation" pattern:
        1. Verify the refresh token is valid and unexpired.
        2. Extract the user_id.
        3. Issue a fresh access token.

        In a production system you would also:
        - Track refresh token families to detect token theft.
        - Revoke the old refresh token after use (one-time use).
        - Store refresh tokens server-side (not just in JWT).
        """
        payload = self.verify_token(refresh_token, expected_type="refresh")
        user_id: str = payload["sub"]
        roles: list[str] = payload.get("roles", [])

        _safe_log("access_token_rotated", user_id=user_id)
        return self.create_access_token(user_id=user_id, roles=roles)

    # ------------------------------------------------------------------
    # Key fingerprinting (for auditing)
    # ------------------------------------------------------------------
    def key_fingerprint(self) -> str:
        """Return a SHA-256 prefix of the signing key for log correlation.

        SECURITY: We never log the key itself, but a fingerprint lets us
        verify in logs which key was used (useful after key rotation).
        """
        digest = hashlib.sha256(self._secret_key.encode("utf-8")).hexdigest()
        return digest[:16]  # first 16 hex chars


# ---------------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Simulate a config from a secret manager
    mock_config = {
        "secret_key": os.urandom(48).hex(),  # 96-char hex = 384 bits
        "algorithm": "HS256",
        "access_token_ttl_minutes": 15,
        "refresh_token_ttl_days": 7,
    }

    auth = JWTAuthManager(mock_config)
    print(f"Key fingerprint: {auth.key_fingerprint()}")

    access = auth.create_access_token(user_id="user-42", roles=["admin"])
    refresh = auth.create_refresh_token(user_id="user-42")

    # Verify
    decoded = auth.verify_token(access)
    print(f"Access token subject: {decoded['sub']}")

    # Rotate
    new_access = auth.rotate_access_token(refresh)
    new_decoded = auth.verify_token(new_access)
    print(f"Rotated token subject: {new_decoded['sub']}")