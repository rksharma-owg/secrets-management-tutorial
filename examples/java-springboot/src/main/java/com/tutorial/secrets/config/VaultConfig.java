/*
 * ===========================================================================
 * VaultConfig — Spring Cloud Vault Auto-Configuration Details
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This configuration class documents and extends Spring Cloud Vault's
 * auto-configuration. While Spring Cloud Vault works out of the box,
 * this class adds explicit documentation and optional customization
 * for production-hardened deployments.
 *
 * SPRING CLOUD VAULT AUTO-CONFIGURATION:
 * When spring-cloud-starter-vault-config is on the classpath, Spring Boot
 * automatically:
 *
 *   1. Creates a VaultTemplate bean for programmatic access
 *   2. Reads secrets from Vault's KV store at startup
 *   3. Injects secrets as properties into the Spring Environment
 *   4. Makes secrets available via @Value("${...}") annotations
 *
 * The secret lookup order (most specific first):
 *   secret/{application-name}/{profile}
 *   secret/{application-name}
 *   secret/application/{profile}    (shared across apps)
 *   secret/application               (shared across apps and profiles)
 *
 * For our app (name=secrets-tutorial, profile=prod):
 *   1. secret/secrets-tutorial/prod   ← most specific
 *   2. secret/secrets-tutorial
 *   3. secret/application/prod
 *   4. secret/application
 *
 * VAULT AGENT SIDECAR PATTERN (Kubernetes):
 * In production Kubernetes deployments, use Vault's Agent Injector
 * instead of direct Vault authentication:
 *
 *   1. Annotate your pod with: annotations: vault.hashicorp.com/agent-inject: "true"
 *   2. Vault Agent sidecar authenticates to Vault (no token in app)
 *   3. Agent renders secrets as files in a shared memory volume
 *   4. Spring Cloud Vault reads from the file-based token
 *   5. The Vault token NEVER enters the application's JVM memory
 *
 * SECRET VERSION PINNING:
 * For reproducible deployments, you can pin a specific secret version:
 *   spring.cloud.vault.kv.default-context=secret/data/myapp
 *   spring.cloud.vault.kv.profiles=prod
 *   spring.cloud.vault.kv.application-name=myapp
 *
 * For version pinning, use VaultTemplate directly (see VaultSecretsService).
 * ===========================================================================
 */
package com.tutorial.secrets.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponseSupport;

import java.util.Map;

/**
 * Vault-specific configuration and documentation.
 *
 * <p>This class is activated by the "vault" profile (or when
 * {@code SECRET_PROVIDER=vault}). It demonstrates how Spring Cloud
 * Vault auto-configuration works and provides helper methods for
 * common Vault operations.</p>
 *
 * <p><strong>Important:</strong> Most Vault integration works via
 * auto-configuration. This class exists to document the pattern
 * and provide version pinning / advanced operations.</p>
 */
@Configuration
@Profile("vault")
public class VaultConfig {

    private static final Logger log = LoggerFactory.getLogger(VaultConfig.class);

    /**
     * The Vault address — logged at startup for diagnostics.
     * SECURITY: The Vault address is not a secret. It's the
     * infrastructure endpoint (like a database host).
     */
    @Value("${spring.cloud.vault.uri:}")
    private String vaultUri;

    /**
     * VaultTemplate is auto-configured by Spring Cloud Vault.
     * We inject it here to verify connectivity at startup.
     *
     * <p>SECURITY: The VaultTemplate handles authentication internally
     * using the configured method (token, AppRole, Kubernetes, etc.).
     * The application code never directly handles authentication.</p>
     */
    private final VaultTemplate vaultTemplate;

    public VaultConfig(VaultTemplate vaultTemplate) {
        this.vaultTemplate = vaultTemplate;
    }

    /**
     * Verifies Vault connectivity at startup by reading the
     * Vault health status (unauthenticated endpoint).
     *
     * <p>This is a lightweight check — the health endpoint doesn't
     * require authentication and doesn't access any secrets.</p>
     *
     * <p>SECURITY: This only checks connectivity, not authorization.
     * Authorization is verified when the first secret is fetched.</p>
     */
    @jakarta.annotation.PostConstruct
    void verifyVaultConnectivity() {
        log.info("Verifying Vault connectivity [uri={}]", vaultUri);

        try {
            // Read the sys/health endpoint — unauthenticated, just checks if
            // Vault is initialized and unsealed
            VaultResponseSupport<Map<String, Object>> health =
                    vaultTemplate.read("sys/health", VaultResponseSupport.class);

            if (health != null && health.getData() != null) {
                boolean initialized = Boolean.TRUE.equals(health.getData().get("initialized"));
                boolean sealed = Boolean.TRUE.equals(health.getData().get("sealed"));

                if (!initialized) {
                    log.error("Vault is not initialized! Run 'vault operator init' first.");
                } else if (sealed) {
                    log.error("Vault is SEALED! Run 'vault operator unseal' first. " +
                            "Secrets cannot be read while Vault is sealed.");
                } else {
                    log.info("Vault is healthy and unsealed [uri={}, initialized=true, sealed=false]",
                            vaultUri);
                }
            }

            // Log how Spring Cloud Vault injection works (for tutorial purposes)
            log.info("""
                    
                    ╔══════════════════════════════════════════════════════════════╗
                    ║  SPRING CLOUD VAULT — AUTO-INJECTION ACTIVE               ║
                    ╠══════════════════════════════════════════════════════════════╣
                    ║  Secrets are loaded into Spring Environment at startup.   ║
                    ║  Access them via @Value("${secret-key}") in any bean.    ║
                    ║                                                              ║
                    ║  Lookup order (most specific first):                       ║
                    ║    1. secret/secrets-tutorial/{profile}                     ║
                    ║    2. secret/secrets-tutorial                               ║
                    ║    3. secret/application/{profile}                          ║
                    ║    4. secret/application                                    ║
                    ║                                                              ║
                    ║  For versioned access, use VaultTemplate directly.         ║
                    ║  See VaultSecretsService for examples.                      ║
                    ╚══════════════════════════════════════════════════════════════╝
                    """);

        } catch (Exception e) {
            log.warn("""
                    
                    WARNING: Cannot connect to Vault at [{}].
                    Secret auto-injection from Vault will not work.
                    
                    Possible causes:
                    - Vault is not running (start with: vault server -dev)
                    - Wrong VAULT_ADDR (check environment variable)
                    - Network/firewall blocking connection
                    
                    The application will continue but secret retrieval will fail.
                    Ensure Vault is accessible before deploying.
                    """, vaultUri);
        }
    }
}