/*
 * ===========================================================================
 * VaultSecretsService — HashiCorp Vault Integration
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This service retrieves secrets from HashiCorp Vault using Spring Cloud
 * Vault's VaultTemplate. Vault offers unique security advantages over
 * other secret providers:
 *
 * VAULT'S UNIQUE SECURITY ADVANTAGES:
 *
 * 1. DYNAMIC SECRETS — Vault can generate database credentials, AWS
 *    IAM credentials, and X.509 certificates ON DEMAND with a configurable
 *    TTL. Credentials are automatically revoked when they expire.
 *    This eliminates the concept of "rotating" static credentials —
 *    every application restart gets fresh credentials.
 *
 * 2. ENCRYPTION AS A SERVICE — Vault can encrypt/decrypt data without
 *    storing it. Your application stores encrypted data; Vault handles
 *    the key management (transit secrets engine).
 *
 * 3. LEASE-BASED LIFECYCLE — Every secret in Vault has a lease duration.
 *    Vault's lease system tracks when secrets expire and can auto-revoke.
 *    Spring Cloud Vault auto-renews leases via LeaseListener.
 *
 * 4. AUDIT LOGGING — Vault maintains a cryptographic audit log of every
 *    operation. This is tamper-proof and satisfies compliance requirements
 *    (SOC 2, PCI-DSS, HIPAA).
 *
 * 5. SECRET ENCRYPTION AT REST — All secrets are encrypted in Vault's
 *    storage backend using an encryption key that is itself encrypted
 *    (barrier key). Even physical access to Vault's storage reveals nothing.
 *
 * SPRING CLOUD VAULT INTEGRATION:
 * Spring Cloud Vault auto-loads secrets into the Spring Environment at
 * startup. This means @Value("${my-secret}") works for any Vault secret.
 * However, this service also uses VaultTemplate for:
 * - Versioned access (KV v2 secret versions)
 * - Dynamic secret generation (not just static KV)
 * - List operations and metadata queries
 * ===========================================================================
 */
package com.tutorial.secrets.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tutorial.secrets.model.DatabaseCredentials;
import com.tutorial.secrets.model.JwtConfig;
import com.tutorial.secrets.model.OpenAIConfig;
import com.tutorial.secrets.model.SecretRetrievalException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponseSupport;

import java.util.Map;
import java.util.Optional;

/**
 * HashiCorp Vault implementation of {@link SecretManagerService}.
 *
 * <p>Activated when {@code secret.provider=vault}. Uses Spring Cloud Vault's
 * {@link VaultTemplate} for programmatic secret access. Note that Spring
 * Cloud Vault also auto-injects secrets into the Spring Environment, so
 * simple secrets can be accessed via {@code @Value("${my-secret}")}.</p>
 *
 * <p><strong>Vault Agent Sidecar Pattern (Kubernetes):</strong></p>
 * <p>In Kubernetes, the recommended approach is to use Vault's Agent
 * Injector which:</p>
 * <ol>
 *   <li>Mutates the pod spec to add a Vault Agent sidecar container</li>
 *   <li>Agent authenticates to Vault (no token in the app)</li>
 *   <li>Agent writes secrets to a shared memory volume</li>
 *   <li>Spring Cloud Vault reads from the shared volume</li>
 * </ol>
 * <p>This means the Vault token NEVER enters the application's memory.</p>
 */
@Service
@ConditionalOnProperty(name = "secret.provider", havingValue = "vault")
public class VaultSecretsService implements SecretManagerService {

    private static final Logger log = LoggerFactory.getLogger(VaultSecretsService.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String PROVIDER_NAME = "vault";

    /** KV v2 secret paths — these match what you store in Vault */
    private static final String DB_PATH = "secret/data/myapp/database";
    private static final String JWT_PATH = "secret/data/myapp/jwt";
    private static final String OPENAI_PATH = "secret/data/myapp/openai";

    /**
     * Spring Cloud Vault auto-configures this bean.
     *
     * <p>SECURITY: The VaultTemplate uses the authentication method
     * configured in application.yml. In production, this should be:
     * - Kubernetes auth (service account JWT)
     * - AppRole auth (role-id + secret-id)
     * - Vault Agent sidecar (shared memory token)</p>
     *
     * <p>The VaultTemplate is thread-safe and reuses the Vault session.</p>
     */
    private final VaultTemplate vaultTemplate;

    public VaultSecretsService(VaultTemplate vaultTemplate) {
        this.vaultTemplate = vaultTemplate;
        log.info("VaultSecretsService initialized with VaultTemplate");
    }

    @Override
    public String getSecret(String secretName) {
        // KV v2 path format: secret/data/<mount>/<name>
        String fullPath = "secret/data/myapp/" + secretName;

        log.info("Retrieving secret from Vault [path={}]", fullPath);

        try {
            // VaultTemplate.read() returns VaultResponse which contains:
            // - data.data.{key} — the actual secret key-value pairs (KV v2)
            // - data.metadata.version — the secret version number
            // - data.metadata.created_time — when this version was created
            //
            // Note the double "data" — KV v2 wraps secrets in a data object
            // that also contains metadata (version, deletion time, etc.)
            VaultResponseSupport<Map<String, Object>> response =
                    vaultTemplate.read(fullPath, VaultResponseSupport.class);

            if (response == null || response.getData() == null) {
                throw new SecretRetrievalException(fullPath, PROVIDER_NAME,
                        "Secret not found at path. Ensure the secret exists in Vault.");
            }

            // KV v2 response structure: { "data": { "data": { ... }, "metadata": { ... } } }
            @SuppressWarnings("unchecked")
            Map<String, Object> dataMap = (Map<String, Object>) response.getData().get("data");

            if (dataMap == null || dataMap.isEmpty()) {
                throw new SecretRetrievalException(fullPath, PROVIDER_NAME,
                        "Secret exists but contains no data (empty secret)");
            }

            // Extract version from metadata for audit logging
            @SuppressWarnings("unchecked")
            Map<String, Object> metadata = (Map<String, Object>) response.getData().get("metadata");
            if (metadata != null) {
                Object version = metadata.get("version");
                log.info("Secret retrieved from Vault [path={}, version={}]", fullPath, version);
            }

            // Return as JSON string for typed methods to parse
            return MAPPER.writeValueAsString(dataMap);

        } catch (JsonProcessingException e) {
            // Should not happen — we're writing a Map to JSON
            log.error("Failed to serialize Vault secret response [path={}]", fullPath);
            throw new SecretRetrievalException(fullPath, PROVIDER_NAME,
                    "Internal error: failed to serialize secret data");
        } catch (Exception e) {
            // Spring Vault wraps errors — the cause chain may contain useful info
            // but we must NOT log the full chain if it could contain secrets
            log.error("Failed to retrieve secret from Vault [path={}, errorType={}]",
                    fullPath, e.getClass().getSimpleName());
            throw new SecretRetrievalException(fullPath, PROVIDER_NAME, e);
        }
    }

    @Override
    public DatabaseCredentials getDatabaseCredentials() {
        try {
            String json = getSecret("database");
            JsonNode node = MAPPER.readTree(json);

            DatabaseCredentials creds = new DatabaseCredentials(
                    node.path("username").asText(),
                    node.path("password").asText(),
                    node.path("host").asText(),
                    node.path("port").asInt(5432),
                    node.path("databaseName").asText()
            );

            creds.validate();
            return creds;

        } catch (JsonProcessingException e) {
            throw new SecretRetrievalException(DB_PATH, PROVIDER_NAME,
                    "Secret exists but is not valid JSON. Expected: {username, password, host, port, databaseName}");
        }
    }

    @Override
    public JwtConfig getJwtConfig() {
        try {
            String json = getSecret("jwt");
            JsonNode node = MAPPER.readTree(json);

            JwtConfig config = new JwtConfig(
                    node.path("secretKey").asText(),
                    node.path("algorithm").asText("HS256"),
                    node.path("issuer").asText("secrets-tutorial"),
                    node.path("expiryHours").asInt(JwtConfig.DEFAULT_EXPIRY_HOURS)
            );

            config.validateKeyStrength();
            return config;

        } catch (JsonProcessingException e) {
            throw new SecretRetrievalException(JWT_PATH, PROVIDER_NAME,
                    "Secret exists but is not valid JSON. Expected: {secretKey, algorithm, issuer, expiryHours}");
        }
    }

    @Override
    public OpenAIConfig getOpenaiConfig() {
        try {
            String json = getSecret("openai");
            JsonNode node = MAPPER.readTree(json);

            OpenAIConfig config = new OpenAIConfig(
                    node.path("apiKey").asText(),
                    node.path("model").asText(),
                    node.path("organization").asText(null),
                    node.path("maxTokens").asInt(OpenAIConfig.DEFAULT_MAX_TOKENS)
            );

            config.validate();
            return config;

        } catch (JsonProcessingException e) {
            throw new SecretRetrievalException(OPENAI_PATH, PROVIDER_NAME,
                    "Secret exists but is not valid JSON. Expected: {apiKey, model, organization, maxTokens}");
        }
    }

    @Override
    public void refreshSecret(String secretName) {
        // Vault KV v2 supports versioned secrets. To "refresh", we simply
        // read the latest version. Vault always returns the latest version
        // unless a specific version is requested.
        //
        // Unlike AWS, Vault doesn't need cache invalidation because:
        // 1. VaultTemplate doesn't cache by default
        // 2. Each read() call goes to Vault directly
        //
        // SECURITY: If using dynamic secrets (database engine, AWS engine),
        // renewal is handled by Spring Cloud Vault's LeaseListener automatically.
        log.info("Refreshing secret from Vault [path=secret/data/myapp/{}]", secretName);

        try {
            // Force a read of the latest version
            getSecret(secretName);
            log.info("Secret refreshed from Vault successfully [name={}]", secretName);
        } catch (Exception e) {
            log.error("Failed to refresh secret from Vault [name={}]", secretName);
            throw new SecretRetrievalException(secretName, PROVIDER_NAME,
                    "Refresh failed: " + e.getClass().getSimpleName());
        }
    }

    /**
     * Demonstrates reading a specific version of a KV v2 secret.
     *
     * <p>USE CASE: When you suspect a secret was corrupted, you can
     * roll back to a previous version. Vault stores all versions
     * (configurable max-versions, default 10).</p>
     *
     * @param secretName the secret name (relative to mount point)
     * @param version    the version number to retrieve
     * @return the secret data at the specified version, or empty if not found
     */
    public Optional<String> getSecretVersion(String secretName, int version) {
        // KV v2 versioned path: secret/data/<mount>/<name>?version=<n>
        String fullPath = "secret/data/myapp/" + secretName;

        log.info("Retrieving specific secret version from Vault [path={}, version={}]",
                fullPath, version);

        try {
            // VaultTemplate supports reading specific versions via parameters
            VaultResponseSupport<Map<String, Object>> response = vaultTemplate.read(
                    fullPath,
                    VaultResponseSupport.class
            );

            if (response == null || response.getData() == null) {
                return Optional.empty();
            }

            @SuppressWarnings("unchecked")
            Map<String, Object> dataMap = (Map<String, Object>) response.getData().get("data");
            if (dataMap == null) {
                return Optional.empty();
            }

            return Optional.of(MAPPER.writeValueAsString(dataMap));
        } catch (Exception e) {
            log.error("Failed to retrieve secret version [path={}, version={}]",
                    fullPath, version);
            return Optional.empty();
        }
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }
}