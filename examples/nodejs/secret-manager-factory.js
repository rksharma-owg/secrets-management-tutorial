/**
 * Secret Manager Factory — Abstracting Away Provider Details
 *
 * WHY A FACTORY PATTERN?
 * ───────────────────────
 * 1. AVOID VENDOR LOCK-IN: Your application code shouldn't care whether secrets
 *    come from AWS, Azure, or Vault. If you switch cloud providers, you only
 *    change one environment variable (SECRET_PROVIDER), not your entire codebase.
 *
 * 2. CONSISTENT INTERFACE: All providers implement the same methods, so
 *    calling code is identical regardless of backend.
 *
 * 3. EASY TESTING: Swap in a mock provider for unit tests without touching
 *    production code or needing real credentials.
 *
 * 4. MULTI-CLOUD: In complex organizations, different teams may use different
 *    providers. The factory lets each team configure their own while sharing
 *    the same application code.
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

// ── Base SecretManager Interface ──────────────────────────────────────────
// This defines the contract that ALL providers must fulfill.
// In TypeScript this would be an interface; in JavaScript we document it clearly.

/**
 * @abstract
 * Base class defining the secret manager interface.
 * All provider implementations must extend this class.
 */
class SecretManager {
  /**
   * Fetches a generic secret by name.
   * @param {string} name - Secret identifier (name, path, or ARN).
   * @returns {Promise<object|string>} The secret value.
   */
  async getSecret(name) {
    throw new Error("getSecret() must be implemented by subclass");
  }

  /**
   * Fetches database credentials.
   * @returns {Promise<object>} Database connection parameters.
   */
  async getDatabaseCredentials() {
    throw new Error("getDatabaseCredentials() must be implemented by subclass");
  }

  /**
   * Fetches JWT signing configuration.
   * @returns {Promise<object>} JWT configuration with algorithm and secret.
   */
  async getJwtConfig() {
    throw new Error("getJwtConfig() must be implemented by subclass");
  }

  /**
   * Returns the provider name for logging/debugging.
   * @returns {string}
   */
  getProviderName() {
    throw new Error("getProviderName() must be implemented by subclass");
  }
}

// ── AWS Secrets Manager Implementation ────────────────────────────────────
class AWSSecretManager extends SecretManager {
  constructor() {
    super();
    // Lazy import to avoid requiring @aws-sdk/client-secrets-manager
    // when using a different provider
    this._aws = null;
  }

  _getModule() {
    if (!this._aws) {
      this._aws = require("./aws-secrets");
    }
    return this._aws;
  }

  async getSecret(name) {
    return this._getModule().getSecret(name);
  }

  async getDatabaseCredentials() {
    return this._getModule().getDatabaseCredentials(
      process.env.AWS_DB_SECRET_NAME || "prod/database/credentials"
    );
  }

  async getJwtConfig() {
    return this._getModule().getJwtConfig(
      process.env.AWS_JWT_SECRET_NAME || "prod/jwt/config"
    );
  }

  getProviderName() {
    return "AWS Secrets Manager";
  }
}

// ── HashiCorp Vault Implementation ────────────────────────────────────────
class VaultSecretManager extends SecretManager {
  constructor() {
    super();
    this._vault = null;
  }

  _getModule() {
    if (!this._vault) {
      this._vault = require("./vault-secrets");
    }
    return this._vault;
  }

  async getSecret(name) {
    return this._getModule().getSecret(name);
  }

  async getDatabaseCredentials() {
    return this._getModule().getDatabaseCredentials(
      process.env.VAULT_DB_CREDS_PATH || "database/creds/app-readonly"
    );
  }

  async getJwtConfig() {
    return this._getModule().getJwtConfig(
      process.env.VAULT_JWT_PATH || "secret/data/app/jwt"
    );
  }

  getProviderName() {
    return "HashiCorp Vault";
  }
}

// ── Azure Key Vault Implementation ────────────────────────────────────────
class AzureSecretManager extends SecretManager {
  constructor() {
    super();
    this._azure = null;
  }

  _getModule() {
    if (!this._azure) {
      this._azure = require("./azure-secrets");
    }
    return this._azure;
  }

  /**
   * Azure Key Vault returns raw strings, so we wrap them in an object
   * to match the interface expected by the rest of the application.
   */
  async getSecret(name) {
    const value = await this._getModule().getSecret(name);
    return { value, name };
  }

  async getDatabaseCredentials() {
    // Azure convention: connection strings are single secret values
    const connStr = await this._getModule().getDatabaseConnectionString(
      process.env.AZURE_DB_SECRET_NAME || "DatabaseConnectionString"
    );
    return { connectionString: connStr };
  }

  async getJwtConfig() {
    const secretKey = await this._getModule().getJwtSigningKey(
      process.env.AZURE_JWT_SECRET_NAME || "JwtSigningKey"
    );
    return {
      algorithm: process.env.JWT_ALGORITHM || "HS256",
      secretKey,
      issuer: process.env.JWT_ISSUER || "secrets-management-app",
      expiresIn: process.env.JWT_EXPIRES_IN || "15m",
    };
  }

  getProviderName() {
    return "Azure Key Vault";
  }
}

// ── Factory Function ──────────────────────────────────────────────────────
// Supported provider values for the SECRET_PROVIDER environment variable:
//   "aws"     — AWS Secrets Manager
//   "vault"   — HashiCorp Vault
//   "azure"   — Azure Key Vault

/**
 * Creates a SecretManager instance based on the SECRET_PROVIDER environment variable.
 *
 * USAGE:
 *   SECRET_PROVIDER=aws node server.js
 *   SECRET_PROVIDER=vault node server.js
 *   SECRET_PROVIDER=azure node server.js
 *
 * The factory pattern ensures the rest of your application never imports
 * provider-specific modules directly — it only depends on the base interface.
 *
 * @param {string} [provider] - Override provider (defaults to SECRET_PROVIDER env var).
 * @returns {SecretManager} A configured secret manager instance.
 */
function createSecretManager(provider) {
  const selected = (provider || process.env.SECRET_PROVIDER || "").toLowerCase().trim();

  if (!selected) {
    throw new Error(
      "SECRET_PROVIDER environment variable is required.\n" +
      "Supported values: 'aws', 'vault', 'azure'\n" +
      "Example: SECRET_PROVIDER=aws node server.js"
    );
  }

  let manager;

  switch (selected) {
    case "aws":
      manager = new AWSSecretManager();
      break;
    case "vault":
      manager = new VaultSecretManager();
      break;
    case "azure":
      manager = new AzureSecretManager();
      break;
    default:
      throw new Error(
        `Unsupported SECRET_PROVIDER '${selected}'. ` +
        `Supported values: 'aws', 'vault', 'azure'`
      );
  }

  logger.info("Secret manager initialized via factory", {
    provider: selected,
    providerName: manager.getProviderName(),
  });

  return manager;
}

// Export both the factory and individual classes for direct use if needed
module.exports = {
  createSecretManager,
  SecretManager,
  AWSSecretManager,
  VaultSecretManager,
  AzureSecretManager,
};