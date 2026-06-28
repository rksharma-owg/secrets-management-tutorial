"""
FastAPI Application — Runtime Secret Fetching
===============================================
This application demonstrates how a FastAPI service fetches secrets from
a configured secret manager AT STARTUP, then uses those secrets for
JWT authentication, database connections, and OpenAI integration.

Critical security principle
----------------------------
Secrets are fetched once during the ``lifespan`` context manager and stored
in ``app.state``.  They are NEVER:
  - Hardcoded in source files
  - Read from .env files committed to git
  - Logged or included in error responses
  - Exposed through any API endpoint

The /config endpoint returns *only* non-sensitive metadata (provider name,
secret names fetched) — never the actual secret values.
"""

import logging
import sys
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

# Add parent directory to path so we can import the factory module
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "python"))

from secret_manager_factory import get_secret_manager, SecretManager

# ---------------------------------------------------------------------------
# Structured logging — JSON-friendly, no secret values ever.
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":%(message)s}',
    stream=sys.stdout,
)
logger = logging.getLogger("fastapi_app")


def _safe_log(event: str, **extra: Any) -> None:
    """Log with automatic redaction of sensitive keys."""
    payload = {"event": event, **extra}
    for k in list(payload.keys()):
        if any(s in k.lower() for s in ("key", "token", "secret", "password")):
            payload[k] = "***REDACTED***"
    logger.info(payload)


# ---------------------------------------------------------------------------
# Lifespan: fetch all secrets at startup
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan — runs once at startup and shutdown.

    SECURITY: We fetch secrets eagerly so that a misconfigured secret
    manager causes the application to fail at startup (fail-fast) rather
    than at first request time when it would be harder to diagnose.
    """
    _safe_log("app_starting")

    try:
        # The factory reads SECRET_PROVIDER from the environment
        manager: SecretManager = get_secret_manager()
        app.state.secret_manager = manager

        # Fetch all required secrets upfront and cache them
        db_creds = manager.get_database_credentials()
        jwt_config = manager.get_jwt_config()
        openai_config = manager.get_openai_config()

        # Store on app.state so dependency-injected endpoints can access
        app.state.db_creds = db_creds
        app.state.jwt_config = jwt_config
        app.state.openai_config = openai_config

        _safe_log(
            "secrets_loaded",
            db_host=db_creds.get("host"),  # host is not a secret
            jwt_algorithm=jwt_config.get("algorithm"),
            openai_model=openai_config.get("default_model"),
        )
    except Exception as exc:
        _safe_log("startup_failed", error=str(exc))
        raise SystemExit(f"FATAL: Could not load secrets — {exc}") from exc

    yield  # application is now running

    _safe_log("app_shutting_down")


# ---------------------------------------------------------------------------
# Application instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="Secrets Management Tutorial",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,  # reduce attack surface — only one doc UI
)

# ---------------------------------------------------------------------------
# Middleware: security headers
# ---------------------------------------------------------------------------
@app.middleware("http")
async def security_headers(request: Request, call_next):
    """Add defense-in-depth HTTP headers to every response.

    These headers mitigate common web vulnerabilities:
    - X-Content-Type-Options: prevents MIME-type sniffing
    - X-Frame-Options: prevents clickjacking
    - X-XSS-Protection: legacy XSS filter (belt-and-suspenders)
    - Referrer-Policy: limits referrer leakage
    - Content-Security-Policy: restricts resource loading
    - Cache-Control: prevents caching of API responses
    """
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    return response


# CORS — restrict to known origins in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(","),
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Authorization", "Content-Type"],
)


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health_check(request: Request):
    """Liveness probe — returns 200 if the app is running.

    SECURITY: We do NOT reveal whether secrets loaded successfully here.
    An attacker probing /health should not learn internal state.
    """
    return {"status": "ok"}


@app.get("/config")
async def get_config(request: Request):
    """Return non-sensitive configuration metadata.

    SECURITY: This endpoint returns ONLY:
    - Which secret provider is active
    - The *names* of secrets that were loaded (not their values)
    This is useful for ops debugging without leaking secrets.
    """
    mgr: SecretManager = request.app.state.secret_manager
    return {
        "provider": type(mgr).__name__,
        "secrets_loaded": [
            "database_credentials",
            "jwt_config",
            "openai_config",
        ],
        # Expiry info helps ops detect stale secrets
        "startup_time": True,
    }


@app.get("/db-test")
async def db_test(request: Request):
    """Test database connectivity using secrets from the secret manager.

    In production this would create a real connection; here we demonstrate
    the *pattern* of using secrets fetched at startup.
    """
    creds: dict = request.app.state.db_creds

    # SECURITY: We log the host (not a secret) but never the password
    _safe_log(
        "db_test_attempt",
        db_host=creds["host"],
        db_name=creds.get("dbname"),
        db_user=creds["username"],  # username is semi-sensitive
    )

    # In a real app you would use the database.py module:
    #   engine = await create_async_engine(creds)
    #   async with engine.connect() as conn:
    #       result = await conn.execute(text("SELECT 1"))
    return {
        "status": "simulated",
        "message": "Database connection would use credentials from secret manager",
        "host": creds["host"],  # host is safe to expose
        "dbname": creds["dbname"],
    }


@app.post("/ai/chat")
async def ai_chat(request: Request, body: dict):
    """Example endpoint using OpenAI secrets from the secret manager.

    The API key is fetched once at startup and passed to the OpenAI client.
    It is NEVER included in request/response bodies or logs.
    """
    config: dict = request.app.state.openai_config
    user_message = body.get("message", "")

    if not user_message:
        raise HTTPException(status_code=400, detail="message is required")

    _safe_log(
        "ai_chat_request",
        model=config.get("default_model", "gpt-4"),
    )

    # In production:
    #   client = AsyncOpenAI(api_key=config["api_key"])
    #   response = await client.chat.completions.create(...)
    return {
        "status": "simulated",
        "model": config.get("default_model"),
        "message": "OpenAI integration would use API key from secret manager",
    }


# ---------------------------------------------------------------------------
# Global exception handler — never leak secrets in 500 responses
# ---------------------------------------------------------------------------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Catch-all handler that prevents secrets from leaking in error output.

    SECURITY: Stack traces can contain environment variable names, file
    paths, or secret manager responses.  We log the full error internally
    but return a generic message to the client.
    """
    _safe_log("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal server error"},
    )


if __name__ == "__main__":
    import uvicorn

    port = int(os.getenv("APP_PORT", "8000"))
    uvicorn.run(app, host="0.0.0.0", port=port, log_level="info")