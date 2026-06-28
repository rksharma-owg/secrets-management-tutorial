/**
 * AWS Secrets Manager Integration
 *
 * WHY THIS APPROACH OVER .env FILES:
 * ─────────────────────────────────
 * .env files are risky because:
 *   1. They are typically committed to version control (even accidentally)
 *   2. They sit on disk in plaintext — any process/user with read access can leak them
 *   3. There's no built-in rotation — a compromised secret stays compromised
 *   4. They don't scale across multiple environments or services
 *   5. They lack audit trails — you can't track who accessed what and when
 *
 * AWS Secrets Manager solves these problems by:
 *   - Storing secrets encrypted at rest (AES-256)
 *   - Providing automatic secret rotation via Lambda functions
 *   - Offering fine-grained IAM policies for access control
 *   - Emitting CloudTrail logs for every access event
 *   - Integrating with ECS, EKS, Lambda, EC2 via IAM roles (no credentials needed)
 */

const { SecretsManagerClient, GetSecretValueCommand } = require("@aws-sdk/client-secrets-manager");
const winston = require("winston");

// ── Logger Configuration ──────────────────────────────────────────────────
// CRITICAL: Never log secret values. Even partial values can be used in
// credential stuffing attacks. Always use the [REDACTED] placeholder.
const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || "info",
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  transports: [new winston.transports.Console()],
});

// ── AWS SDK Client Initialization ──────────────────────────────────────────
// The region is read from AWS_REGION (or AWS_DEFAULT_REGION) environment variable.
// This is the standard AWS convention — never hardcode a region because
// deployments may span multiple regions for disaster recovery.
let secretsClient;

/**
 * Initializes the AWS Secrets Manager client.
 * Called lazily so the module can be imported without requiring AWS credentials
 * at import time (useful for testing or non-AWS environments).
 */
function getClient() {
  if (!secretsClient) {
    const region = process.env.AWS_REGION || process.env.AWS_DEFAULT_REGION;
    if (!region) {
      throw new Error(
        "AWS_REGION environment variable is required. " +
        "Set it to your deployment region (e.g., 'us-east-1')."
      );
    }
    secretsClient = new SecretsManagerClient({ region });
    logger.info("AWS Secrets Manager client initialized", { region });
  }
  return secretsClient;
}

/**
 * Fetches a secret by its name/ARN from AWS Secrets Manager.
 *
 * SECURITY NOTE: We parse the SecretString as JSON if possible. Many teams
 * store multiple key-value pairs in a single secret (e.g., both username
 * and password). The returned object gives callers structured access without
 * exposing the raw string.
 *
 * @param {string} secretName - The name or ARN of the secret in AWS.
 * @returns {Promise<object|string>} Parsed JSON object or raw string.
 */
async function getSecret(secretName) {
  const client = getClient();

  logger.info("Fetching secret from AWS Secrets Manager", {
    secretName,
    // NEVER log the secret value or even a partial value
  });

  try {
    const command = new GetSecretValueCommand({ SecretId: secretName });
    const response = await client.send(command);

    // Secrets Manager may return the value as a binary blob (SecretBinary)
    // or a UTF-8 string (SecretString). We handle both.
    if (response.SecretString) {
      try {
        // Most secrets are stored as JSON strings for structured access
        const parsed = JSON.parse(response.SecretString);
        logger.info("Secret retrieved successfully", {
          secretName,
          keyCount: Object.keys(parsed).length,
          value: "[REDACTED]",
        });
        return parsed;
      } catch {
        // Not JSON — return the raw string (e.g., a plaintext API key)
        logger.info("Secret retrieved (raw string)", {
          secretName,
          value: "[REDACTED]",
        });
        return response.SecretString;
      }
    }

    if (response.SecretBinary) {
      // Binary secrets (e.g., certificates) are returned as Base64-encoded Buffers
      logger.info("Secret retrieved (binary)", {
        secretName,
        value: "[REDACTED]",
      });
      return Buffer.from(response.SecretBinary, "base64");
    }

    throw new Error("Secret returned neither SecretString nor SecretBinary");
  } catch (error) {
    // Distinguish between "secret doesn't exist" and "access denied" errors
    if (error.name === "ResourceNotFoundException") {
      logger.error("Secret not found in AWS Secrets Manager", { secretName });
      throw new Error(`Secret '${secretName}' does not exist or you lack access`);
    }
    if (error.name === "AccessDeniedException") {
      // SECURITY: Log the denial but don't expose IAM details to callers
      logger.error("Access denied to secret — check IAM permissions", {
        secretName,
        errorCode: error.Code,
      });
      throw new Error("Permission denied when accessing secret");
    }
    logger.error("Failed to fetch secret from AWS", {
      secretName,
      error: error.message,
    });
    throw error;
  }
}

/**
 * Fetches database credentials from a named secret.
 *
 * Expected secret structure (JSON):
 *   { "username": "app_user", "password": "s3cret!", "engine": "postgres",
 *     "host": "db.example.com", "port": 5432, "dbname": "myapp" }
 *
 * ROTATION CONCEPT: AWS Secrets Manager supports automatic rotation via
 * Lambda functions. When a database password rotates, the Lambda:
 *   1. Generates a new password
 *   2. Updates the secret in Secrets Manager
 *   3. Updates the password in the database
 *   4. (Optionally) invalidates existing connections
 *
 * Our application simply re-fetches the secret to get the new credentials.
 * No code change or redeployment is needed.
 *
 * @param {string} secretName - Secret name (default: "prod/database/credentials")
 * @returns {Promise<object>} Database connection parameters.
 */
async function getDatabaseCredentials(secretName = "prod/database/credentials") {
  const secret = await getSecret(secretName);

  // Validate the secret contains expected database fields
  const required = ["username", "password", "host"];
  for (const field of required) {
    if (!secret[field]) {
      logger.error("Database secret missing required field", {
        secretName,
        missingField: field,
      });
      throw new Error(`Database secret '${secretName}' is missing field '${field}'`);
    }
  }

  logger.info("Database credentials retrieved", {
    secretName,
    host: secret.host,
    port: secret.port || 5432,
    engine: secret.engine || "unknown",
    username: secret.username,
    password: "[REDACTED]",
  });

  return {
    host: secret.host,
    port: secret.port || 5432,
    database: secret.dbname || secret.database,
    username: secret.username,
    password: secret.password, // Passed programmatically, never logged
    ssl: secret.ssl !== false, // Default to SSL enabled
    connectionTimeout: secret.connectionTimeout || 5000,
  };
}

/**
 * Fetches JWT signing configuration from Secrets Manager.
 *
 * Expected secret structure (JSON):
 *   { "algorithm": "HS256", "secretKey": "your-256-bit-secret",
 *     "issuer": "myapp", "expiresIn": "15m" }
 *
 * @param {string} secretName - Secret name (default: "prod/jwt/config")
 * @returns {Promise<object>} JWT configuration.
 */
async function getJwtConfig(secretName = "prod/jwt/config") {
  const secret = await getSecret(secretName);

  logger.info("JWT configuration retrieved", {
    secretName,
    algorithm: secret.algorithm || "HS256",
    issuer: secret.issuer || "[REDACTED]",
    secretKey: "[REDACTED]",
  });

  return {
    algorithm: secret.algorithm || "HS256",
    secretKey: secret.secretKey,
    issuer: secret.issuer || "secrets-management-app",
    audience: secret.audience,
    expiresIn: secret.expiresIn || "15m",
  };
}

/**
 * Fetches OpenAI API configuration from Secrets Manager.
 *
 * This demonstrates fetching third-party API credentials. Storing these
 * in Secrets Manager (not .env) ensures they can be rotated independently
 * and audited. If an API key is compromised, you rotate it in one place
 * and all services pick up the new key on next fetch.
 *
 * @param {string} secretName - Secret name (default: "prod/openai/config")
 * @returns {Promise<object>} OpenAI configuration.
 */
async function getOpenaiConfig(secretName = "prod/openai/config") {
  const secret = await getSecret(secretName);

  if (!secret.apiKey) {
    logger.error("OpenAI secret missing apiKey field", { secretName });
    throw new Error(`Secret '${secretName}' must contain an 'apiKey' field`);
  }

  logger.info("OpenAI configuration retrieved", {
    secretName,
    organization: secret.organization || "default",
    apiKey: "[REDACTED]",
    apiKeyPrefix: secret.apiKey ? `${secret.apiKey.substring(0, 7)}...` : "[REDACTED]",
    // Logging only the prefix (e.g., "sk-proj...") is generally safe
    // and helps debug which key is in use without exposing the full value.
  });

  return {
    apiKey: secret.apiKey,
    organization: secret.organization,
    model: secret.model || "gpt-4",
    maxTokens: secret.maxTokens || 2048,
  };
}

module.exports = {
  getSecret,
  getDatabaseCredentials,
  getJwtConfig,
  getOpenaiConfig,
};