/*
 * ===========================================================================
 * SecretManagerConfig — Provider Selection Configuration
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This configuration class demonstrates the FACTORY PATTERN for secret
 * provider selection. It ensures that exactly ONE secret provider is
 * active at a time, selected via the SECRET_PROVIDER environment variable.
 *
 * WHY A FACTORY PATTERN INSTEAD OF DIRECT INJECTION?
 *
 * 1. VENDOR LOCK-IN PREVENTION — If you directly @Autowire VaultTemplate,
 *    you're locked into Vault. With this factory, switching to AWS or
 *    Azure requires changing ONE environment variable. No code changes.
 *
 * 2. CONSISTENT INTERFACE — All application code depends on
 *    SecretManagerService, not on VaultTemplate or SecretsManagerClient.
 *    This means:
 *    - Controllers don't know which provider is active
 *    - Tests can use a mock implementation
 *    - New providers can be added without changing consumers
 *
 * 3. SINGLE RESPONSIBILITY — Each provider implementation handles its
 *    own SDK specifics. This class handles only selection logic.
 *
 * 4. FAIL-FAST — If SECRET_PROVIDER is set to an unsupported value,
 *    the application fails at startup with a clear error message.
 *    Better to fail at deploy time than at 3 AM when a secret is needed.
 *
 * MIGRATION SCENARIO:
 * You start with Vault in your on-premises data center. A year later,
 * you migrate to AWS. The migration steps are:
 *   1. Export secrets from Vault → import to AWS Secrets Manager
 *   2. Grant IAM role permissions to Secrets Manager
 *   3. Set SECRET_PROVIDER=aws in your deployment
 *   4. Deploy. That's it. No code changes.
 *
 * This is the power of the abstraction layer.
 * ===========================================================================
 */
package com.tutorial.secrets.config;

import com.tutorial.secrets.service.AwsSecretsService;
import com.tutorial.secrets.service.AzureKeyVaultService;
import com.tutorial.secrets.service.SecretManagerService;
import com.tutorial.secrets.service.VaultSecretsService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

/**
 * Central configuration that selects the active secret provider implementation.
 *
 * <p>This class uses Spring's {@code @ConditionalOnProperty} mechanism
 * indirectly — each service implementation has its own condition. This
 * class exists to provide a clear, documented entry point for the
 * provider selection pattern.</p>
 *
 * <p><strong>How it works:</strong></p>
 * <ol>
 *   <li>Set {@code SECRET_PROVIDER} environment variable to "vault", "aws", or "azure"</li>
 *   <li>Spring creates only the matching service implementation bean</li>
 *   <li>All other beans inject {@link SecretManagerService} (the interface)</li>
 *   <li>Spring resolves the interface to the single available implementation</li>
 * </ol>
 *
 * <p><strong>Adding a new provider:</strong></p>
 * <ol>
 *   <li>Create a new class implementing {@link SecretManagerService}</li>
 *   <li>Annotate with {@code @Service} and
 *       {@code @ConditionalOnProperty(name = "secret.provider", havingValue = "gcp")}</li>
 *   <li>Import the class here with {@code @Import(GcpSecretsService.class)}</li>
 *   <li>That's it — no changes to controllers or business logic</li>
 * </ol>
 */
@Configuration
@Import({
        // Import all provider implementations. Spring will only instantiate
        // the one whose @ConditionalOnProperty matches SECRET_PROVIDER.
        // The others are completely ignored (no network calls, no beans created).
        VaultSecretsService.class,
        AwsSecretsService.class,
        AzureKeyVaultService.class
})
public class SecretManagerConfig {

    private static final Logger log = LoggerFactory.getLogger(SecretManagerConfig.class);

    /**
     * The active secret provider, read from the SECRET_PROVIDER environment variable.
     * Valid values: "vault", "aws", "azure".
     */
    @Value("${secret.provider:}")
    private String activeProvider;

    /**
     * Validates at startup that a known provider is configured.
     *
     * <p>This method runs during bean initialization. If the provider
     * value is invalid, the application fails immediately with a clear
     * error message. This is the FAIL-FAST pattern — better to fail
     * at startup than at runtime when a secret is first requested.</p>
     *
     * <p>SECURITY: A misconfigured provider could mean secrets are
     * loaded from the wrong source (e.g., dev secrets in production).
     * Validating at startup prevents this scenario.</p>
     *
     * @throws IllegalStateException if the provider is invalid
     */
    @jakarta.annotation.PostConstruct
    void validateProvider() {
        boolean valid = switch (activeProvider) {
            case "vault", "aws", "azure" -> true;
            default -> false;
        };

        if (!valid) {
            String errorMsg = """
                    Invalid secret provider: '%s'. Must be one of: vault, aws, azure.
                    Set the SECRET_PROVIDER environment variable.
                    
                    Examples:
                      SECRET_PROVIDER=vault java -jar app.jar    # HashiCorp Vault
                      SECRET_PROVIDER=aws   java -jar app.jar    # AWS Secrets Manager
                      SECRET_PROVIDER=azure java -jar app.jar    # Azure Key Vault
                    """.formatted(activeProvider);
            log.error(errorMsg);
            throw new IllegalStateException(errorMsg);
        }

        log.info("Secret provider configured: {} (via SECRET_PROVIDER environment variable)", activeProvider);

        // SECURITY WARNING: Log a reminder if using the default (vault) without
        // explicit configuration. This catches cases where the env var was
        // forgotten and the app is running with a potentially insecure default.
        if ("vault".equals(activeProvider) &&
                System.getenv("VAULT_TOKEN") == null &&
                System.getenv("VAULT_ADDR") == null) {
            log.warn("""
                    SECURITY WARNING: Vault is configured as the secret provider, but
                    neither VAULT_TOKEN nor VAULT_ADDR are set. The application will
                    attempt to connect to http://localhost:8200 with no authentication.
                    This is ONLY safe for local development with a dev Vault server.
                    NEVER deploy this configuration to production.
                    """);
        }
    }

    /**
     * Provides a convenience bean for accessing the provider name.
     *
     * <p>This bean is safe to inject and log — it contains no secrets.</p>
     *
     * @return the active provider identifier
     */
    @Bean
    public String activeSecretProvider() {
        return activeProvider;
    }
}