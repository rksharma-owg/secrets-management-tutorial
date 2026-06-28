/**
 * Express.js Server — Runtime Secret Fetching Demonstration
 *
 * This server demonstrates how to build an Express application that fetches
 * its secrets from a centralized secret manager at startup, rather than
 * reading from .env files or hardcoded values.
 *
 * SECURITY ARCHITECTURE:
 * - Secrets are fetched ONCE at startup and held in memory
 * - For long-running processes, implement periodic secret refresh
 * - JWT middleware uses the secret from the secret manager (not hardcoded)
 * - No secret values appear in logs, HTTP responses, or error messages
 *
 * STARTUP:
 *   SECRET_PROVIDER=aws  AWS_REGION=us-east-1  node server.js
 *   SECRET_PROVIDER=vault VAULT_ADDR=https://vault:8200 VAULT_TOKEN=... node server.js
 *   SECRET_PROVIDER=azure AZURE_VAULT_URL=https://...vault.azure.net/ node server.js
 */

const express = require("express");
const helmet = require("helmet");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const { createSecretManager } = require("./secret-manager-factory");
const { authenticate } = require("./middleware/auth");
const { getPool } = require("./config/database");

const winston = require("winston");

// ── Logger Configuration ──────────────────────────────────────────────────
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()],
});

// ── Application State ─────────────────────────────────────────────────────
// Secrets fetched from the secret manager are stored here at startup.
// SECURITY: These are in-memory only — never serialized, never logged.
let appSecrets = null;
let secretManager = null;

const app = express();
const PORT = parseInt(process.env.PORT || "3000", 10);

// ── Security Middleware ───────────────────────────────────────────────────
// Helmet sets security-focused HTTP headers to protect against common
// vulnerabilities: XSS, clickjacking, MIME sniffing, etc.
app.use(helmet());

// Morgan for HTTP request logging.
// SECURITY: We use the "combined" format which does NOT log request bodies,
// so even if a request contains a secret (e.g., login payload), it won't
// appear in the access logs.
app.use(morgan("combined", {
  skip: (req) => req.path === "/health", // Don't spam logs with health checks
}));

// Parse JSON request bodies (with a 100KB limit to prevent oversized payloads)
app.use(express.json({ limit: "100kb" }));

// ── Secret Initialization ────────────────────────────────────────────────
/**
 * Fetches all required secrets at startup.
 *
 * WHY AT STARTUP? Fetching secrets once (vs. on every request) is faster
 * and avoids rate limits. The tradeoff is that rotated secrets aren't
 * picked up until restart. For long-running services, implement a
 * background refresh loop that re-fetches secrets every N minutes.
 */
async function initializeSecrets() {
  logger.info("Initializing secrets from configured provider...");

  try {
    secretManager = createSecretManager();

    // Fetch all secrets in parallel for faster startup
    const [dbCredentials, jwtConfig] = await Promise.all([
      secretManager.getDatabaseCredentials(),
      secretManager.getJwtConfig(),
    ]);

    appSecrets = { dbCredentials, jwtConfig };

    logger.info("All secrets loaded successfully", {
      provider: secretManager.getProviderName(),
      dbHost: dbCredentials.host || dbCredentials.connectionString
        ? "[REDACTED]" : "N/A",
      jwtAlgorithm: jwtConfig.algorithm || "HS256",
      jwtSecretKey: "[REDACTED]",
    });
  } catch (error) {
    // SECURITY: Log the error type but not any leaked credentials
    logger.error("FATAL: Failed to initialize secrets — server cannot start safely", {
      error: error.message,
      stack: process.env.NODE_ENV === "development" ? error.stack : undefined,
    });
    process.exit(1);
  }
}

// ── Routes ────────────────────────────────────────────────────────────────

/**
 * GET /health
 * Simple health check that does NOT expose any secret-related information.
 * Load balancers use this to check if the service is alive.
 */
app.get("/health", (_req, res) => {
  // SECURITY: Never include secret status, versions, or provider details
  // in health responses. Only report basic liveness.
  res.json({
    status: "ok",
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

/**
 * GET /config
 * Returns non-sensitive application configuration.
 * SECURITY: This endpoint deliberately returns only safe metadata.
 * No secret values, partial values, or key prefixes are included.
 */
app.get("/config", (_req, res) => {
  res.json({
    provider: secretManager ? secretManager.getProviderName() : "not initialized",
    secretsLoaded: !!appSecrets,
    environment: process.env.NODE_ENV || "development",
    // We confirm secrets are loaded but never reveal their contents
  });
});

/**
 * POST /db-test
 * Tests the database connection using credentials from the secret manager.
 * This endpoint is protected by JWT authentication.
 */
app.post("/db-test", authenticate(appSecrets), async (_req, res) => {
  try {
    const pool = getPool(appSecrets.dbCredentials);
    // Run a lightweight query to verify connectivity
    const result = await pool.query("SELECT 1 AS health_check");
    res.json({
      status: "connected",
      result: result.rows ? result.rows[0] : result,
    });
  } catch (error) {
    // SECURITY: Don't expose connection details (host, user, password) in errors
    logger.error("Database connection test failed", {
      error: error.message,
    });
    res.status(503).json({
      error: "Database connection failed",
      // Intentionally vague — no host, user, or connection string details
    });
  }
});

/**
 * POST /token
 * Creates a JWT token using the signing key from the secret manager.
 * In production, this would be part of a full login flow with password verification.
 */
app.post("/token", (req, res) => {
  const { userId, role } = req.body;

  if (!userId) {
    return res.status(400).json({ error: "userId is required" });
  }

  try {
    const token = jwt.sign(
      { sub: userId, role: role || "user", iat: Math.floor(Date.now() / 1000) },
      appSecrets.jwtConfig.secretKey,
      {
        algorithm: appSecrets.jwtConfig.algorithm || "HS256",
        expiresIn: appSecrets.jwtConfig.expiresIn || "15m",
        issuer: appSecrets.jwtConfig.issuer || "secrets-management-app",
      }
    );

    logger.info("JWT token issued", { userId, role: role || "user" });
    // SECURITY: Never log the token itself

    res.json({ token, expiresIn: appSecrets.jwtConfig.expiresIn || "15m" });
  } catch (error) {
    logger.error("Failed to issue JWT token", { error: error.message });
    res.status(500).json({ error: "Failed to create token" });
  }
});

// ── Error Handling Middleware ─────────────────────────────────────────────
// This catches all unhandled errors. SECURITY: We never leak stack traces
// or internal details in production responses.
app.use((err, _req, res, _next) => {
  logger.error("Unhandled error", {
    error: err.message,
    stack: process.env.NODE_ENV === "development" ? err.stack : undefined,
  });

  res.status(err.status || 500).json({
    error: process.env.NODE_ENV === "development"
      ? err.message
      : "An internal error occurred",
    // In production, this is intentionally vague to avoid information leakage
  });
});

// ── Server Startup ────────────────────────────────────────────────────────
async function start() {
  await initializeSecrets();
  app.listen(PORT, () => {
    logger.info("Server started", {
      port: PORT,
      environment: process.env.NODE_ENV || "development",
      provider: secretManager.getProviderName(),
    });
  });
}

// Handle unhandled promise rejections gracefully
process.on("unhandledRejection", (reason) => {
  logger.error("Unhandled promise rejection", {
    reason: reason?.message || String(reason),
  });
});

start().catch((err) => {
  logger.error("Server failed to start", { error: err.message });
  process.exit(1);
});

module.exports = { app, initializeSecrets };