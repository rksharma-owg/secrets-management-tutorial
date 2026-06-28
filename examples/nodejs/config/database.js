/**
 * Database Configuration — Secrets-Backed Connection Management
 *
 * This module manages PostgreSQL (or MySQL) database connections using
 * credentials fetched from a secret manager. No credentials are ever
 * hardcoded or read from .env files.
 *
 * SECURITY ARCHITECTURE:
 * ────────────────────────
 * 1. Credentials come exclusively from the secret manager (passed in at init)
 * 2. Connection strings are constructed in memory — never written to disk
 * 3. Connection pooling limits resource usage and prevents connection exhaustion
 * 4. Secret rotation is supported: call refreshPool() after rotation to create
 *    a new pool with updated credentials
 *
 * WHY NOT .env FOR DATABASE CREDENTIALS?
 * ───────────────────────────────────────
 * Database credentials in .env files persist indefinitely. If compromised
 * (e.g., through directory traversal, log injection, or backup exposure),
 * the attacker has persistent access until someone manually changes the
 * password. With a secret manager + rotation, credentials expire or change
 * automatically, limiting the blast radius of any leak.
 */

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

// ── Connection Pool Cache ─────────────────────────────────────────────────
// Maps a credential fingerprint to a connection pool instance.
// This allows getPool() to return an existing pool if credentials haven't changed,
// while creating a new pool after secret rotation.
let currentPool = null;
let currentCredentialsFingerprint = null;

/**
 * Creates a cryptographic fingerprint of the credentials.
 * Used to detect when credentials have changed (e.g., after rotation)
 * so we know to create a new connection pool.
 *
 * SECURITY: The fingerprint is a hash — you cannot reverse it to get
 * the original credentials. It's safe to log.
 *
 * @param {object} credentials - Database credentials object.
 * @returns {string} A hex digest fingerprint.
 */
function fingerprintCredentials(credentials) {
  const crypto = require("crypto");
  const data = JSON.stringify({
    host: credentials.host,
    port: credentials.port,
    username: credentials.username,
    // Include a hash of the password to detect changes
    passwordHash: credentials.password
      ? crypto.createHash("sha256").update(credentials.password).digest("hex")
      : "none",
    database: credentials.database,
    connectionString: credentials.connectionString
      ? crypto.createHash("sha256").update(credentials.connectionString).digest("hex")
      : "none",
  });
  return crypto.createHash("sha256").update(data).digest("hex").substring(0, 16);
}

/**
 * Gets or creates a database connection pool using the provided credentials.
 *
 * The credentials object comes from the secret manager (not .env).
 * It supports two formats:
 *
 * FORMAT 1 (AWS Secrets Manager / Vault):
 *   { host, port, username, password, database, ssl, connectionTimeout }
 *
 * FORMAT 2 (Azure Key Vault):
 *   { connectionString: "postgresql://user:pass@host:5432/db?sslmode=require" }
 *
 * @param {object} credentials - Database credentials from the secret manager.
 * @returns {object} A database pool with a query() method.
 */
function getPool(credentials) {
  const fingerprint = fingerprintCredentials(credentials);

  // Return the existing pool if credentials haven't changed
  if (currentPool && currentCredentialsFingerprint === fingerprint) {
    return currentPool;
  }

  // Credentials changed — close old pool if it exists
  if (currentPool) {
    logger.info("Database credentials changed — closing old connection pool");
    closePool();
  }

  currentCredentialsFingerprint = fingerprint;

  // Determine connection configuration based on credential format
  let poolConfig;

  if (credentials.connectionString) {
    // Azure-style: full connection string
    // SECURITY: We log the connection string's structure but NOT the value.
    // Connection strings often embed credentials (user:pass@host).
    logger.info("Creating database pool from connection string", {
      hasConnectionString: true,
      protocol: credentials.connectionString.split("://")[0] || "unknown",
    });

    poolConfig = createPoolFromConnectionString(credentials.connectionString);
  } else {
    // AWS/Vault-style: separate fields
    logger.info("Creating database pool from credential fields", {
      host: credentials.host,
      port: credentials.port || 5432,
      database: credentials.database || "N/A",
      username: credentials.username,
      password: "[REDACTED]",
      ssl: credentials.ssl !== false,
    });

    poolConfig = createPoolFromFields(credentials);
  }

  currentPool = poolConfig;
  logger.info("Database connection pool created successfully");
  return currentPool;
}

/**
 * Creates a mock/stub pool for demonstration purposes.
 *
 * In a real application, you would use 'pg-pool' for PostgreSQL,
 * 'mysql2/promise' for MySQL, or 'mssql' for SQL Server.
 * This stub demonstrates the pattern without requiring a real DB dependency.
 */
function createPoolFromConnectionString(connectionString) {
  // In production, replace with:
  //   const { Pool } = require('pg');
  //   return new Pool({ connectionString, ssl: { rejectUnauthorized: false } });
  return {
    _type: "mock",
    _connectionString: connectionString,
    query: async (sql) => {
      return { rows: [{ health_check: 1, query: sql, pool: "connection-string" }] };
    },
    end: async () => {},
  };
}

/**
 * Creates a pool from individual credential fields.
 */
function createPoolFromFields(creds) {
  // In production, replace with:
  //   const { Pool } = require('pg');
  //   return new Pool({
  //     host: creds.host,
  //     port: creds.port || 5432,
  //     database: creds.database,
  //     user: creds.username,
  //     password: creds.password,
  //     ssl: creds.ssl !== false ? { rejectUnauthorized: false } : false,
  //     connectionTimeoutMillis: creds.connectionTimeout || 5000,
  //     max: parseInt(process.env.DB_POOL_SIZE || "10", 10),  // Connection pool size
  //     idleTimeoutMillis: 30000,  // Close idle connections after 30s
  //   });
  return {
    _type: "mock",
    _host: creds.host,
    _port: creds.port || 5432,
    query: async (sql) => {
      return { rows: [{ health_check: 1, query: sql, host: creds.host }] };
    },
    end: async () => {},
  };
}

/**
 * Closes the current connection pool gracefully.
 * Should be called on application shutdown or before credential rotation.
 */
async function closePool() {
  if (currentPool && currentPool.end) {
    try {
      await currentPool.end();
      logger.info("Database connection pool closed");
    } catch (error) {
      logger.error("Error closing database pool", { error: error.message });
    }
  }
  currentPool = null;
  currentCredentialsFingerprint = null;
}

/**
 * Refreshes the database pool with new credentials after a secret rotation.
 *
 * SECRET ROTATION FLOW:
 *   1. Secret manager rotates the secret (new password, new connection string)
 *   2. Application is notified (via webhook, polling, or restart)
 *   3. Application calls refreshPool() with the new credentials
 *   4. New pool is created with new credentials
 *   5. Old pool is drained gracefully — in-flight queries complete
 *   6. New queries use the new pool with rotated credentials
 *
 * @param {object} newCredentials - Updated credentials from the secret manager.
 * @returns {object} The new connection pool.
 */
function refreshPool(newCredentials) {
  logger.info("Refreshing database pool (secret rotation)");
  return getPool(newCredentials);
}

// Graceful shutdown handler — close the pool when the process exits
process.on("SIGTERM", async () => {
  logger.info("SIGTERM received — closing database pool");
  await closePool();
  process.exit(0);
});

process.on("SIGINT", async () => {
  logger.info("SIGINT received — closing database pool");
  await closePool();
  process.exit(0);
});

module.exports = {
  getPool,
  closePool,
  refreshPool,
};