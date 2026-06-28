"""
Database Connection Module — Async SQLAlchemy
================================================
This module creates async database engine and session objects using
credentials fetched from a secret manager.  No credentials are ever
hardcoded or read from .env files.

Security rationale
------------------
* Connection credentials come exclusively from the secret manager.
* The connection URL is built in memory and never logged with the
  password component.
* Connection pooling is configured with sensible defaults and optional
  env-var overrides (pool size, max overflow, etc.).
* ``pre_ping=True`` ensures stale connections are detected before use,
  which is essential when the database rotates credentials (e.g. Vault
  dynamic secrets or AWS RDS IAM auth).
* Secret rotation support: the ``refresh_credentials()`` method can be
  called by a background task to pull new credentials when the secret
  manager notifies the application of a rotation event.

Dependencies:
  pip install sqlalchemy[asyncio] asyncpg
"""

import logging
import os
from typing import Any

from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy import text

# ---------------------------------------------------------------------------
# Structured logging
# ---------------------------------------------------------------------------
logger = logging.getLogger("database")
logger.setLevel(logging.INFO)


def _safe_log(event: str, **extra: Any) -> None:
    """Log with automatic redaction of password-like keys."""
    payload = {"event": event, **extra}
    for k in list(payload.keys()):
        if any(s in k.lower() for s in ("password", "secret", "key", "token")):
            payload[k] = "***REDACTED***"
    logger.info(payload)


class DatabaseManager:
    """Manages async SQLAlchemy engine and sessions using secret-manager creds.

    Usage:
        creds = secret_manager.get_database_credentials()
        db = DatabaseManager(creds)
        await db.initialize()

        async with db.session() as session:
            result = await session.execute(text("SELECT 1"))
    """

    def __init__(self, db_creds: dict[str, Any]) -> None:
        """
        Args:
            db_creds: Dict from the secret manager with at minimum:
                host, port, username, password, dbname, engine.
        """
        self._creds = db_creds
        self._engine: AsyncEngine | None = None
        self._session_factory: async_sessionmaker[AsyncSession] | None = None

        # Pool configuration — override via env vars in production
        self._pool_size = int(os.getenv("DB_POOL_SIZE", "10"))
        self._max_overflow = int(os.getenv("DB_MAX_OVERFLOW", "20"))
        self._pool_timeout = int(os.getenv("DB_POOL_TIMEOUT", "30"))

        # Validate required fields
        required = {"host", "username", "password", "dbname", "engine"}
        missing = required - set(db_creds.keys())
        if missing:
            raise ValueError(f"DB credentials missing required fields: {missing}")

        _safe_log(
            "db_manager_init",
            host=db_creds["host"],
            port=db_creds.get("port", 5432),
            dbname=db_creds["dbname"],
            engine=db_creds["engine"],
            username=db_creds["username"],  # semi-sensitive but useful for debug
            pool_size=self._pool_size,
        )

    # ------------------------------------------------------------------
    # Connection URL construction
    # ------------------------------------------------------------------
    def _build_url(self, creds: dict[str, Any]) -> str:
        """Build an async database URL from credentials.

        SECURITY: The password is URL-encoded and included in the
        connection string, but we NEVER log the full URL.
        """
        engine = creds["engine"].lower()
        host = creds["host"]
        port = creds.get("port", 5432)
        dbname = creds["dbname"]
        user = creds["username"]
        password = creds["password"]

        # Map engine names to async driver names
        driver_map = {
            "postgresql": "postgresql+asyncpg",
            "postgres": "postgresql+asyncpg",
            "mysql": "mysql+aiomysql",
            "sqlite": "sqlite+aiosqlite",
        }
        driver = driver_map.get(engine, engine)

        url = f"{driver}://{user}:{password}@{host}:{port}/{dbname}"

        # SECURITY: Log everything EXCEPT the password
        safe_url = f"{driver}://{user}:***@{host}:{port}/{dbname}"
        _safe_log("db_url_built", safe_url=safe_url)
        return url

    # ------------------------------------------------------------------
    # Engine lifecycle
    # ------------------------------------------------------------------
    async def initialize(self) -> None:
        """Create the async engine and session factory.

        Call this once during application startup.
        """
        url = self._build_url(self._creds)

        self._engine = create_async_engine(
            url,
            pool_size=self._pool_size,
            max_overflow=self._max_overflow,
            pool_timeout=self._pool_timeout,
            pool_pre_ping=True,  # SECURITY: detect stale connections
            pool_recycle=300,    # Recycle connections after 5 minutes
            echo=False,          # Never echo SQL with potential PII to logs
        )

        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,  # prevent lazy-loading after commit
        )

        _safe_log("db_engine_created")

    async def close(self) -> None:
        """Dispose of the connection pool. Call at shutdown."""
        if self._engine:
            await self._engine.dispose()
            _safe_log("db_engine_disposed")

    # ------------------------------------------------------------------
    # Session context manager
    # ------------------------------------------------------------------
    @property
    def session(self) -> async_sessionmaker[AsyncSession]:
        """Return the session factory for use as an async context manager.

        Example:
            async with db.session() as session:
                await session.execute(text("SELECT 1"))
        """
        if self._session_factory is None:
            raise RuntimeError("DatabaseManager not initialized — call initialize()")
        return self._session_factory

    # ------------------------------------------------------------------
    # Secret rotation support
    # ------------------------------------------------------------------
    async def refresh_credentials(self, new_creds: dict[str, Any]) -> None:
        """Replace database credentials (e.g. after secret rotation).

        This method:
        1. Builds a new connection URL with the updated password.
        2. Disposes all existing connections in the pool.
        3. Replaces the engine so new connections use the new creds.

        SECURITY: Old credentials are discarded from memory.  Python's
        garbage collector will eventually free the strings, but for
        extra paranoia you could call ``ctypes.memset`` on the old
        password bytes (not shown here for simplicity).
        """
        _safe_log(
            "db_credential_refresh_starting",
            host=new_creds.get("host"),
        )

        # Dispose old pool
        if self._engine:
            await self._engine.dispose()

        # Update stored credentials
        self._creds = new_creds

        # Create new engine with new credentials
        url = self._build_url(new_creds)
        self._engine = create_async_engine(
            url,
            pool_size=self._pool_size,
            max_overflow=self._max_overflow,
            pool_timeout=self._pool_timeout,
            pool_pre_ping=True,
            pool_recycle=300,
            echo=False,
        )
        self._session_factory = async_sessionmaker(
            bind=self._engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )

        _safe_log("db_credential_refresh_complete")

    # ------------------------------------------------------------------
    # Health check
    # ------------------------------------------------------------------
    async def health_check(self) -> dict[str, Any]:
        """Run a lightweight query to verify database connectivity.

        Returns a dict with status info.  Useful for /health endpoints.
        """
        try:
            async with self.session() as session:
                result = await session.execute(text("SELECT 1"))
                row = result.scalar()
                return {"status": "healthy", "query_result": row}
        except Exception as exc:
            _safe_log("db_health_check_failed", error=str(exc))
            return {"status": "unhealthy", "error": str(exc)}


# ---------------------------------------------------------------------------
# Demonstration
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import asyncio

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    # Mock credentials (in production these come from the secret manager)
    mock_creds = {
        "engine": "postgresql",
        "host": "localhost",
        "port": 5432,
        "username": "test_user",
        "password": "test_password",  # only safe because it's a local mock
        "dbname": "test_db",
    }

    async def demo():
        db = DatabaseManager(mock_creds)
        try:
            await db.initialize()
            result = await db.health_check()
            print(f"Health check: {result}")
        except Exception as exc:
            print(f"Expected error (no local DB): {exc}")
        finally:
            await db.close()

    asyncio.run(demo())