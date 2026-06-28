/*
 * ===========================================================================
 * AzureKeyVaultService — Azure Key Vault Integration
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This service retrieves secrets from Azure Key Vault using the Azure
 * SDK for Java. It demonstrates Azure's recommended authentication
 * pattern for production workloads.
 *
 * AUTHENTICATION STRATEGY:
 * Uses DefaultAzureCredential which chains multiple credential sources.
 * In production on Azure (App Service, AKS, VM), this resolves to
 * Managed Identity — the most secure authentication method because:
 *
 * 1. NO STATIC CREDENTIALS — Managed Identity uses the Azure compute
 *    resource's system-assigned or user-assigned identity. There are
 *    no client IDs, secrets, or certificates to manage.
 *
 * 2. AUTOMATIC LIFECYCLE — Managed Identity is automatically provisioned
 *    when the resource is created and automatically deleted when the
 *    resource is deleted. No manual lifecycle management.
 *
 * 3. SCOPED ACCESS — Azure RBAC or Key Vault Access Policies control
 *    exactly which secrets each identity can access. Least privilege
 *    is enforced at the platform level.
 *
 * REQUIRED AZURE RBAC ASSIGNMENTS (for the Managed Identity):
 *   - Key Vault Secrets User (read): Microsoft.KeyVault/vaults/secrets/read
 *   - Key Vault Secrets Officer (write, for rotation): full secret permissions
 *
 * MANAGED IDENTITY SETUP:
 *   1. Enable system-assigned identity on your App Service / AKS / VM
 *   2. Grant "Key Vault Secrets User" role on the Key Vault
 *   3. That's it — no code changes needed!
 *
 * SECRET ROTATION:
 * Azure Key Vault supports secret rotation via:
 * 1. Azure Event Grid notification → Azure Function → rotate secret
 * 2. Key Vault rotation policy (built-in for some secret types)
 * 3. Manual rotation via Azure CLI / portal
 *
 * This service supports manual refresh via refreshSecret().
 * For automatic rotation, implement an Event Grid subscriber.
 * ===========================================================================
 */
package com.tutorial.secrets.service;

import com.azure.core.credential.TokenCredential;
import com.azure.identity.DefaultAzureCredential;
import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.security.keyvault.secrets.SecretClient;
import com.azure.security.keyvault.secrets.SecretClientBuilder;
import com.azure.security.keyvault.secrets.models.KeyVaultSecret;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.tutorial.secrets.model.DatabaseCredentials;
import com.tutorial.secrets.model.JwtConfig;
import com.tutorial.secrets.model.OpenAIConfig;
import com.tutorial.secrets.model.SecretRetrievalException;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

/**
 * Azure Key Vault implementation of {@link SecretManagerService}.
 *
 * <p>Activated when {@code secret.provider=azure}. Uses
 * {@link DefaultAzureCredential} which automatically resolves to
 * Managed Identity when running on Azure compute resources.</p>
 *
 * <p><strong>Managed Identity Flow (Production):</strong></p>
 * <ol>
 *   <li>Application requests a secret from Key Vault</li>
 *   <li>Azure SDK requests an access token from the local IMDS endpoint</li>
 *   <li>Azure AD issues a token for the resource's Managed Identity</li>
 *   <li>Token is used to authenticate to Key Vault</li>
 *   <li>Secret is returned to the application</li>
 *   <li>Token is cached by the SDK (24-hour lifetime, auto-refreshed)</li>
 * </ol>
 */
@Service
@ConditionalOnProperty(name = "secret.provider", havingValue = "azure")
public class AzureKeyVaultService implements SecretManagerService {

    private static final Logger log = LoggerFactory.getLogger(AzureKeyVaultService.class);

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String PROVIDER_NAME = "azure";

    /** Azure Key Vault secret names */
    private static final String DB_SECRET_NAME = "myapp-database";
    private static final String JWT_SECRET_NAME = "myapp-jwt";
    private static final String OPENAI_SECRET_NAME = "myapp-openai";

    /**
     * Key Vault URL from environment variable AZURE_VAULT_URL.
     * Format: https://<vault-name>.vault.azure.net/
     */
    @Value("${azure.keyvault.url:}")
    private String vaultUrl;

    /**
     * Optional user-assigned managed identity client ID.
     * If not set, system-assigned managed identity is used.
     */
    @Value("${azure.keyvault.managed-identity-client-id:}")
    private String managedIdentityClientId;

    /** The Key Vault secret client — thread-safe, reused for all requests */
    private SecretClient secretClient;

    /**
     * Initializes the Azure Key Vault SecretClient.
     *
     * <p>SECURITY: DefaultAzureCredential automatically selects the
     * appropriate authentication method based on the environment:</p>
     * <ul>
     *   <li>Azure App Service / AKS / VM → Managed Identity (production)</li>
     *   <li>Azure CLI logged in → Azure CLI credentials (development)</li>
     *   <li>Environment variables set → Service principal (CI/CD)</li>
     * </ul>
     *
     * <p>In production, only Managed Identity should succeed, ensuring
     * no developer credentials leak into production.</p>
     */
    @PostConstruct
    void init() {
        if (vaultUrl == null || vaultUrl.isBlank()) {
            throw new IllegalStateException(
                    "Azure Key Vault URL is not configured. Set AZURE_VAULT_URL environment variable. " +
                    "Format: https://<vault-name>.vault.azure.net/"
            );
        }

        // SECURITY: DefaultAzureCredential is the RECOMMENDED way to
        // authenticate to Azure services. It tries multiple auth methods
        // and uses the first one that succeeds.
        //
        // In production on Azure:
        //   - System-assigned Managed Identity is tried first
        //   - Falls back to user-assigned Managed Identity (if clientId set)
        //   - Environment/CLI credentials should NOT be available in prod
        //
        // The credential is thread-safe and caches tokens automatically.
        DefaultAzureCredentialBuilder credentialBuilder = new DefaultAzureCredentialBuilder();

        // If a user-assigned managed identity client ID is specified,
        // tell the credential builder to use that specific identity.
        if (managedIdentityClientId != null && !managedIdentityClientId.isBlank()) {
            credentialBuilder.managedIdentityClientId(managedIdentityClientId);
            log.info("Using user-assigned managed identity for Azure Key Vault");
        }

        TokenCredential credential = credentialBuilder.build();

        // Build the SecretClient — thread-safe, should be reused
        this.secretClient = new SecretClientBuilder()
                .vaultUrl(vaultUrl)
                .credential(credential)
                .buildClient();

        // SECURITY: Log the vault URL (not secrets). The vault name
        // is not sensitive — it's the identity name, not a secret.
        log.info("Azure Key Vault SecretClient initialized [vaultUrl={}]", vaultUrl);
    }

    @Override
    public String getSecret(String secretName) {
        log.info("Retrieving secret from Azure Key Vault [name={}, vault={}]", secretName, vaultUrl);

        try {
            // The getSecret() call authenticates using the DefaultAzureCredential
            // (Managed Identity in production) and retrieves the latest version
            // of the secret. Azure SDK handles token caching and refresh.
            KeyVaultSecret secret = secretClient.getSecret(secretName);

            if (secret == null || secret.getValue() == null) {
                throw new SecretRetrievalException(secretName, PROVIDER_NAME,
                        "Secret not found or has no value");
            }

            // Log success with the secret's properties ID (contains version)
            // SECURITY: We log the version from the secret ID, not the value.
            String secretId = secret.getId();
            log.info("Secret retrieved from Azure Key Vault [name={}, versionIdPresent={}]",
                    secretName, secretId != null);

            return secret.getValue();

        } catch (Exception e) {
            // Azure SDK exceptions may contain the vault URL (safe) but
            // should NOT contain secret values.
            log.error("Failed to retrieve secret from Azure Key Vault [name={}, errorType={}]",
                    secretName, e.getClass().getSimpleName());
            throw new SecretRetrievalException(secretName, PROVIDER_NAME, e);
        }
    }

    @Override
    public DatabaseCredentials getDatabaseCredentials() {
        try {
            String json = getSecret(DB_SECRET_NAME);
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
            throw new SecretRetrievalException(DB_SECRET_NAME, PROVIDER_NAME,
                    "Secret exists but is not valid JSON. Expected: {username, password, host, port, databaseName}");
        }
    }

    @Override
    public JwtConfig getJwtConfig() {
        try {
            String json = getSecret(JWT_SECRET_NAME);
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
            throw new SecretRetrievalException(JWT_SECRET_NAME, PROVIDER_NAME,
                    "Secret exists but is not valid JSON. Expected: {secretKey, algorithm, issuer, expiryHours}");
        }
    }

    @Override
    public OpenAIConfig getOpenaiConfig() {
        try {
            String json = getSecret(OPENAI_SECRET_NAME);
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
            throw new SecretRetrievalException(OPENAI_SECRET_NAME, PROVIDER_NAME,
                    "Secret exists but is not valid JSON. Expected: {apiKey, model, organization, maxTokens}");
        }
    }

    @Override
    public void refreshSecret(String secretName) {
        // Azure Key Vault doesn't require explicit cache invalidation
        // because the SecretClient doesn't cache secret values.
        // Each getSecret() call goes to Key Vault directly.
        //
        // However, the TokenCredential does cache access tokens (24-hour TTL).
        // Token refresh is handled automatically by the Azure SDK.
        //
        // This method exists to support the SecretManagerService interface
        // contract for consistent rotation behavior across providers.
        log.info("Refreshing secret from Azure Key Vault [name={}]", secretName);

        try {
            getSecret(secretName);
            log.info("Secret refreshed from Azure Key Vault successfully [name={}]", secretName);
        } catch (Exception e) {
            log.error("Failed to refresh secret from Azure Key Vault [name={}]", secretName);
            throw new SecretRetrievalException(secretName, PROVIDER_NAME,
                    "Refresh failed: " + e.getClass().getSimpleName());
        }
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }
}