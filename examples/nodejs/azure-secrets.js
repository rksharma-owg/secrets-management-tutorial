/**
 * Azure Key Vault Integration
 *
 * WHY AZURE KEY VAULT OVER .env FILES:
 * ────────────────────────────────────
 * Azure Key Vault provides centralized secret management with:
 *   - Hardware Security Modules (HSMs) for FIPS 140-2 Level 2 / Level 3 protection
 *   - Automatic certificate management and renewal
 *   - Role-Based Access Control (RBAC) via Azure AD / Entra ID
 *   - Soft-delete and purge protection (accidental deletion recovery)
 *   - Network isolation via Private Endpoints (no public internet exposure)
 *
 * AUTHENTICATION: We use DefaultAzureCredential which tries multiple auth
 * methods in order: Environment variables → Managed Identity → VS Code →
 * Azure CLI → Azure PowerShell. This means the same code works locally
 * (with az login) and in production (with Managed Identity) with zero changes.
 */

const { SecretClient } = require("@azure/keyvault-secrets");
const { DefaultAzureCredential } = require("@azure/identity");
const winston = require("winston");

// ── Logger Configuration ──────────────────────────────────────────────────
// SECURITY RULE: Never log secret values. Always use [REDACTED].
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()],
});

// ── Azure Key Vault Client Initialization ─────────────────────────────────
let secretClient;

/**
 * Creates and returns an Azure Key Vault SecretClient.
 *
 * BOOTSTRAPPING FROM ENVIRONMENT:
 *   AZURE_VAULT_URL - The Key Vault URI (e.g., https://myapp-vault.vault.azure.net/)
 *
 * AUTHENTICATION CHAIN (DefaultAzureCredential tries in order):
 *   1. AZURE_TENANT_ID, AZURE_CLIENT_ID, AZURE_CLIENT_SECRET env vars
 *   2. Azure Managed Identity (for VMs, App Service, AKS, etc.)
 *   3. Visual Studio Code Azure authentication
 *   4. Azure CLI (az login) — useful for local development
 *   5. Azure PowerShell — useful for local development
 *
 * This chain means developers can use `az login` locally while production
 * uses Managed Identity — no code changes required.
 */
function getClient() {
  if (!secretClient) {
    const vaultUrl = process.env.AZURE_VAULT_URL;

    if (!vaultUrl) {
      throw new Error(
        "AZURE_VAULT_URL environment variable is required. " +
        "Example: https://myapp-vault.vault.azure.net/"
      );
    }

    // Validate the URL format to catch misconfigurations early
    if (!vaultUrl.startsWith("https://")) {
      logger.warn("AZURE_VAULT_URL should use HTTPS", { vaultUrl });
    }

    // DefaultAzureCredential automatically selects the right auth method
    // based on the runtime environment. No hardcoded credentials needed.
    const credential = new DefaultAzureCredential();

    secretClient = new SecretClient(vaultUrl, credential);

    logger.info("Azure Key Vault client initialized", {
      vaultUrl,
      // We don't log which credential type was selected to avoid leaking
      // infrastructure details, but in debug mode this is useful
    });

    // Verify connectivity by checking if the vault is accessible
    // (This is a lightweight operation — it doesn't fetch any secrets)
    credential
      .getToken("https://vault.azure.net/.default")
      .then(() => logger.debug("Azure credential successfully acquired"))
      .catch((err) => {
        logger.error("Failed to acquire Azure credential — check your auth setup", {
          error: err.message,
        });
      });
  }
  return secretClient;
}

/**
 * Fetches a secret by name from Azure Key Vault.
 *
 * Azure Key Vault stores each secret as a named value with versioning.
 * By default, getSecret() returns the latest version. You can pin to
 * a specific version by appending "?version=xyz" — but latest is
 * recommended so you pick up rotations automatically.
 *
 * @param {string} secretName - The name of the secret in Key Vault.
 * @param {string} [version] - Optional specific version ID.
 * @returns {Promise<string>} The secret value.
 */
async function getSecret(secretName, version) {
  const client = getClient();

  logger.info("Fetching secret from Azure Key Vault", {
    secretName,
    version: version || "latest",
  });

  try {
    const options = version ? { version } : {};
    const response = await client.getSecret(secretName, options);

    logger.info("Secret retrieved successfully", {
      secretName,
      version: response.properties?.version || "unknown",
      value: "[REDACTED]",
      enabled: response.properties?.enabled,
      expiresOn: response.properties?.expiresOn || "never",
    });

    return response.value;
  } catch (error) {
    if (error.statusCode === 404) {
      logger.error("Secret not found in Azure Key Vault", {
        secretName,
        version: version || "latest",
      });
      throw new Error(`Secret '${secretName}' not found in Key Vault`);
    }
    if (error.statusCode === 403) {
      logger.error("Access denied to Azure Key Vault secret — check RBAC / Access Policies", {
        secretName,
        error: error.message,
      });
      throw new Error(`Access denied for secret '${secretName}'`);
    }
    logger.error("Failed to fetch secret from Azure Key Vault", {
      secretName,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Fetches database connection string from Key Vault.
 *
 * Azure convention: Store connection strings as a single secret value
 * rather than separate username/password/host fields. This matches how
 * Azure services (App Service, Functions) inject connection strings.
 *
 * ROTATION SUPPORT: When you update a secret in Key Vault (new version),
 * the application fetches the new value on the next getSecret() call.
 * For zero-downtime rotation, implement a secret refresh interval.
 *
 * @param {string} secretName - Secret name (default: "DatabaseConnectionString")
 * @returns {Promise<string>} The connection string.
 */
async function getDatabaseConnectionString(secretName = "DatabaseConnectionString") {
  const connectionString = await getSecret(secretName);

  if (!connectionString) {
    logger.error("Database connection string is empty", { secretName });
    throw new Error(`Secret '${secretName}' returned an empty connection string`);
  }

  // SECURITY: Log that we got the string, but never the string itself.
  // Even connection strings can contain embedded credentials.
  logger.info("Database connection string retrieved", {
    secretName,
    length: connectionString.length,
    hasPassword: connectionString.includes("Password=") ||
                 connectionString.includes("pwd=") ||
                 connectionString.includes("password="),
    prefix: connectionString.substring(0, connectionString.indexOf("://") + 3),
  });

  return connectionString;
}

/**
 * Fetches JWT signing key from Key Vault.
 *
 * @param {string} secretName - Secret name (default: "JwtSigningKey")
 * @returns {Promise<string>} The JWT secret key.
 */
async function getJwtSigningKey(secretName = "JwtSigningKey") {
  const key = await getSecret(secretName);

  if (!key) {
    logger.error("JWT signing key is empty", { secretName });
    throw new Error(`Secret '${secretName}' returned an empty JWT key`);
  }

  logger.info("JWT signing key retrieved", {
    secretName,
    keyLength: key.length,
    value: "[REDACTED]",
  });

  return key;
}

/**
 * Fetches an API key from Key Vault.
 *
 * Many third-party services require API keys. Storing them in Key Vault
 * means you can rotate keys without redeploying. Azure Key Vault also
 * supports secret expiration dates — set one to ensure keys are reviewed
 * and rotated on a regular schedule.
 *
 * @param {string} secretName - Secret name for the API key.
 * @returns {Promise<string>} The API key value.
 */
async function getApiKey(secretName) {
  const apiKey = await getSecret(secretName);

  if (!apiKey) {
    logger.error("API key is empty", { secretName });
    throw new Error(`Secret '${secretName}' returned an empty API key`);
  }

  // Log a prefix (e.g., "sk-proj...") to aid debugging without exposing
  // the full key. Most API keys have recognizable prefixes.
  const prefix = apiKey.length > 8 ? `${apiKey.substring(0, 7)}...` : "[REDACTED]";

  logger.info("API key retrieved", {
    secretName,
    apiKeyPrefix: prefix,
    keyLength: apiKey.length,
  });

  return apiKey;
}

module.exports = {
  getSecret,
  getDatabaseConnectionString,
  getJwtSigningKey,
  getApiKey,
  getClient,
};