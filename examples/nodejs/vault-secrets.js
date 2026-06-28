/**
 * HashiCorp Vault Integration
 *
 * WHY VAULT OVER .env FILES:
 * ───────────────────────────
 * Vault provides dynamic secrets (short-lived credentials generated on demand),
 * encryption-as-a-service, and detailed audit logging. Unlike .env files:
 *   - Vault secrets can auto-expire (TTL-based) — leaked credentials become useless
 *   - Every access is logged to an audit backend (file, syslog, etc.)
 *   - Vault supports policies (e.g., "app" role can read /secret/data/app/*")
 *   - Dynamic database credentials mean each app instance gets its own DB user
 *
 * SECURITY NOTE ON VAULT TOKENS:
 * The VAULT_TOKEN env var here is a "bootstrap" token. In production you
 * should use Vault Agent or the Kubernetes/Auth method so tokens are
 * injected at runtime and never appear in environment variables at all.
 */

const vault = require("node-vault");
const winston = require("winston");

// ── Logger Configuration ──────────────────────────────────────────────────
// NEVER log secret values. Use [REDACTED] to indicate a value was retrieved.
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()],
});

// ── Vault Client Initialization ───────────────────────────────────────────
let vaultClient;

/**
 * Creates and returns a configured Vault client.
 *
 * BOOTSTRAPPING FROM ENVIRONMENT:
 *   VAULT_ADDR  - URL of the Vault server (e.g., https://vault.example.com:8200)
 *   VAULT_TOKEN - Authentication token (in production, use Vault Agent instead)
 *   VAULT_NAMESPACE - Optional namespace for Vault Enterprise multi-tenancy
 *
 * SECURITY: The Vault address should use HTTPS. If VAULT_ADDR starts with
 * "http://" (not "https://"), we log a warning because secrets travel
 * unencrypted over the network.
 */
function getClient() {
  if (!vaultClient) {
    const vaultAddr = process.env.VAULT_ADDR;
    const vaultToken = process.env.VAULT_TOKEN;

    if (!vaultAddr) {
      throw new Error(
        "VAULT_ADDR environment variable is required. " +
        "Example: https://vault.example.com:8200"
      );
    }
    if (!vaultToken) {
      throw new Error(
        "VAULT_TOKEN environment variable is required. " +
        "In production, prefer Vault Agent or Kubernetes auth to avoid " +
        "placing tokens in environment variables."
      );
    }

    // Warn if not using TLS — secrets will be sent in plaintext
    if (vaultAddr.startsWith("http://")) {
      logger.warn("Vault address is NOT using HTTPS — secrets are unencrypted in transit", {
        vaultAddr,
      });
    }

    const config = {
      endpoint: vaultAddr,
      token: vaultToken,
      // Increase timeout for large secret payloads or slow networks
      "request-timeout": parseInt(process.env.VAULT_TIMEOUT || "30000", 10),
    };

    // Vault Enterprise namespaces allow multi-tenancy within a single Vault cluster
    if (process.env.VAULT_NAMESPACE) {
      config.namespace = process.env.VAULT_NAMESPACE;
      logger.info("Using Vault Enterprise namespace", {
        namespace: config.namespace,
      });
    }

    vaultClient = vault(config);
    logger.info("Vault client initialized", {
      vaultAddr,
      tokenPrefix: `${vaultToken.substring(0, 6)}...[REDACTED]`,
    });
  }
  return vaultClient;
}

/**
 * Fetches a KV v2 secret from Vault.
 *
 * Vault KV v2 stores secrets at the path: secret/data/<mount>/path
 * The actual secret values are nested under a "data.data" wrapper because
 * KV v2 tracks metadata (versions, custom metadata, deletion time) separately.
 *
 * @param {string} path - The secret path (e.g., "secret/data/app/database")
 * @returns {Promise<object>} The secret key-value pairs.
 */
async function getSecret(path) {
  const client = getClient();

  logger.info("Fetching secret from Vault", { path });

  try {
    const response = await client.read(path);

    // KV v2 engine wraps secret data under response.data.data
    // KV v1 engine has data directly under response.data
    const secretData = response.data?.data || response.data || {};

    logger.info("Secret retrieved successfully", {
      path,
      keyCount: Object.keys(secretData).length,
      value: "[REDACTED]",
      // KV v2 exposes version info — useful for debugging rotation
      version: response.data?.metadata?.version || "N/A",
    });

    return secretData;
  } catch (error) {
    if (error.message?.includes("permission denied") || error.statusCode === 403) {
      logger.error("Access denied to Vault secret — check Vault policies", {
        path,
        error: error.message,
      });
      throw new Error(`Permission denied for Vault path '${path}'`);
    }
    if (error.statusCode === 404) {
      logger.error("Secret path not found in Vault", { path });
      throw new Error(`Vault secret at '${path}' not found`);
    }
    logger.error("Failed to fetch secret from Vault", {
      path,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Fetches database credentials from Vault.
 *
 * DYNAMIC SECRETS: Vault can generate short-lived database credentials
 * on demand via its database secrets engine. Instead of reading a static
 * secret, you request a lease — Vault creates a new DB user, returns the
 * credentials, and automatically revokes them when the lease expires.
 *
 * @param {string} credsPath - Dynamic creds role path (e.g., "database/creds/app-readonly")
 * @returns {Promise<object>} Database credentials with lease info.
 */
async function getDatabaseCredentials(credsPath = "database/creds/app-readonly") {
  const client = getClient();

  logger.info("Requesting dynamic database credentials from Vault", {
    credsPath,
  });

  try {
    const response = await client.read(credsPath);
    const data = response.data;

    // Dynamic secrets include lease information — the credentials will
    // be automatically revoked after lease_duration seconds
    logger.info("Dynamic database credentials generated", {
      credsPath,
      username: data.username,
      password: "[REDACTED]",
      leaseId: data.lease_id ? `${data.lease_id.substring(0, 20)}...` : "N/A",
      leaseDuration: data.lease_duration,
      renewable: data.renewable || false,
    });

    return {
      username: data.username,
      password: data.password,
      leaseId: data.lease_id,
      leaseDuration: data.lease_duration,
      renewable: data.renewable || false,
    };
  } catch (error) {
    logger.error("Failed to generate dynamic database credentials", {
      credsPath,
      error: error.message,
    });
    throw new Error(`Vault database credentials error: ${error.message}`);
  }
}

/**
 * Fetches JWT configuration from Vault.
 *
 * @param {string} path - KV path to JWT config (e.g., "secret/data/app/jwt")
 * @returns {Promise<object>} JWT configuration.
 */
async function getJwtConfig(path = "secret/data/app/jwt") {
  const secret = await getSecret(path);

  if (!secret.secretKey) {
    logger.error("JWT secret missing secretKey field", { path });
    throw new Error(`Vault secret at '${path}' must contain a 'secretKey' field`);
  }

  logger.info("JWT configuration retrieved", {
    path,
    algorithm: secret.algorithm || "HS256",
    secretKey: "[REDACTED]",
  });

  return {
    algorithm: secret.algorithm || "HS256",
    secretKey: secret.secretKey,
    issuer: secret.issuer || "secrets-management-app",
    expiresIn: secret.expiresIn || "15m",
  };
}

/**
 * Fetches a generic API key from Vault.
 *
 * @param {string} path - KV path to the API key secret.
 * @param {string} keyField - Field name containing the key (default: "apiKey").
 * @returns {Promise<object>} Configuration object with the API key.
 */
async function getApiKey(path, keyField = "apiKey") {
  const secret = await getSecret(path);

  if (!secret[keyField]) {
    logger.error("API key secret missing required field", { path, keyField });
    throw new Error(`Secret at '${path}' must contain '${keyField}'`);
  }

  logger.info("API key retrieved", {
    path,
    keyField,
    apiKeyPrefix: `${secret[keyField].substring(0, 7)}...`,
  });

  return {
    [keyField]: secret[keyField],
    ...Object.fromEntries(
      Object.entries(secret).filter(([k]) => k !== keyField)
    ),
  };
}

module.exports = {
  getSecret,
  getDatabaseCredentials,
  getJwtConfig,
  getApiKey,
  getClient,
};