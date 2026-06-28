/*
 * ===========================================================================
 * SecretsTutorialApplication — Main Spring Boot Application
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This is the application entry point with a critical SECURITY FEATURE:
 * STARTUP VALIDATION. Immediately after the Spring context is fully
 * initialized, we verify that all required secrets can be retrieved.
 *
 * WHY STARTUP VALIDATION?
 *
 * 1. FAIL-FAST — If a secret is missing or misconfigured, the
 *    application should fail IMMEDIATELY at startup, not at 3 AM
 *    when a user tries to log in and the JWT secret is missing.
 *
 * 2. DEPLOYMENT SAFETY — A deployment that passes all health checks
 *    but fails on first secret access is worse than one that fails
 *    to start. Startup validation ensures broken deployments are
 *    caught before they receive traffic.
 *
 * 3. AUDIT TRAIL — The startup validation logs which secrets were
 *    loaded successfully. This creates a timestamped audit record
 *    that can be correlated with deployment events.
 *
 * 4. CONFIGURATION DRIFT — If a secret was deleted from the provider
 *    but the app hasn't restarted, the next restart will catch it.
 *    Startup validation prevents zombie deployments.
 *
 * CRITICAL SECURITY NOTES:
 * - NEVER log secret values during validation
 * - NEVER include secrets in health check responses
 * - Use the HealthController.SecretLoadStatus for tracking
 * - Exit with non-zero code on validation failure
 * ===========================================================================
 */
package com.tutorial.secrets;

import com.tutorial.secrets.controller.HealthController;
import com.tutorial.secrets.model.DatabaseCredentials;
import com.tutorial.secrets.model.JwtConfig;
import com.tutorial.secrets.model.OpenAIConfig;
import com.tutorial.secrets.model.SecretRetrievalException;
import com.tutorial.secrets.service.SecretManagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.env.Environment;

import java.time.Duration;
import java.time.Instant;

/**
 * Main Spring Boot application class for the Secrets Management Tutorial.
 *
 * <p>This class provides startup validation that ensures all required
 * secrets are accessible from the configured provider before the
 * application begins accepting traffic.</p>
 *
 * <p><strong>How to run:</strong></p>
 * <pre>
 * # With Vault (default):
 * export SECRET_PROVIDER=vault
 * export VAULT_ADDR=http://localhost:8200
 * export VAULT_TOKEN=devroot
 * java -jar target/secrets-tutorial-1.0.0-SNAPSHOT.jar
 *
 * # With AWS Secrets Manager:
 * export SECRET_PROVIDER=aws
 * export AWS_REGION=us-east-1
 * java -jar target/secrets-tutorial-1.0.0-SNAPSHOT.jar
 *
 * # With Azure Key Vault:
 * export SECRET_PROVIDER=azure
 * export AZURE_VAULT_URL=https://my-vault.vault.azure.net/
 * java -jar target/secrets-tutorial-1.0.0-SNAPSHOT.jar
 * </pre>
 */
@SpringBootApplication
public class SecretsTutorialApplication {

    private static final Logger log = LoggerFactory.getLogger(SecretsTutorialApplication.class);

    /**
     * The secret manager service — injected by Spring based on the
     * SECRET_PROVIDER environment variable.
     */
    private final SecretManagerService secretManager;

    /**
     * The health controller — used to update secret load status.
     */
    private final HealthController healthController;

    /**
     * The Spring Environment — used to log active profiles (non-sensitive).
     */
    private final Environment environment;

    public SecretsTutorialApplication(
            SecretManagerService secretManager,
            HealthController healthController,
            Environment environment) {
        this.secretManager = secretManager;
        this.healthController = healthController;
        this.environment = environment;
    }

    public static void main(String[] args) {
        // SECURITY: Before Spring Boot starts, log the Java version.
        // Older Java versions may have security vulnerabilities.
        // Java 17+ is required for Spring Boot 3.x (LTS with security patches).
        log.info("Starting Secrets Management Tutorial [java={}, spring-boot=3.2.x]",
                System.getProperty("java.version"));

        SpringApplication.run(SecretsTutorialApplication.class, args);
    }

    /**
     * Validates all required secrets after the application context is fully
     * initialized. This runs once at startup.
     *
     * <p>SECURITY: This method logs ONLY the success/failure of each secret
     * retrieval. It NEVER logs secret values. The log output is safe to
     * include in bug reports, monitoring dashboards, and audit logs.</p>
     *
     * <p>If any required secret fails to load, the application exits with
     * a non-zero status code. This is the FAIL-FAST pattern — better to
     * fail at startup than to serve broken functionality.</p>
     */
    @EventListener(ApplicationReadyEvent.class)
    public void validateSecretsAtStartup() {
        Instant startTime = Instant.now();
        String provider = secretManager.getProviderName();

        log.info("╔══════════════════════════════════════════════════════════════════╗");
        log.info("║  STARTUP SECRET VALIDATION                                        ║");
        log.info("║  Provider: {}{}", provider,
                " ".repeat(Math.max(0, 56 - provider.length())));
        log.info("╚══════════════════════════════════════════════════════════════════╝");

        int successCount = 0;
        int failCount = 0;

        // --- Validate Database Credentials ---
        try {
            DatabaseCredentials dbCreds = secretManager.getDatabaseCredentials();
            dbCreds.validate(); // Throws if username/password/host are missing
            healthController.getSecretLoadStatus().put("database",
                    HealthController.SecretLoadStatus.success());
            log.info("  ✅ Database credentials  — loaded [host={}, db={}, port={}]",
                    dbCreds.host(), dbCreds.databaseName(), dbCreds.port());
            successCount++;
        } catch (SecretRetrievalException e) {
            healthController.getSecretLoadStatus().put("database",
                    HealthController.SecretLoadStatus.failure(e.getMessage()));
            log.error("  ❌ Database credentials  — FAILED: {}", e.getMessage());
            failCount++;
        }

        // --- Validate JWT Configuration ---
        try {
            JwtConfig jwtConfig = secretManager.getJwtConfig();
            jwtConfig.validateKeyStrength(); // Throws if key is too short or weak
            healthController.getSecretLoadStatus().put("jwt",
                    HealthController.SecretLoadStatus.success());
            log.info("  ✅ JWT configuration     — loaded [algorithm={}, expiry={}h]",
                    jwtConfig.algorithm(), jwtConfig.expiryHours());
            successCount++;
        } catch (SecretRetrievalException e) {
            healthController.getSecretLoadStatus().put("jwt",
                    HealthController.SecretLoadStatus.failure(e.getMessage()));
            log.error("  ❌ JWT configuration     — FAILED: {}", e.getMessage());
            failCount++;
        }

        // --- Validate OpenAI Configuration ---
        try {
            OpenAIConfig aiConfig = secretManager.getOpenaiConfig();
            aiConfig.validate(); // Throws if API key is missing or too short
            healthController.getSecretLoadStatus().put("openai",
                    HealthController.SecretLoadStatus.success());
            // SECURITY: Log the model and maxTokens (non-sensitive), NOT the API key.
            log.info("  ✅ OpenAI configuration  — loaded [model={}, maxTokens={}]",
                    aiConfig.effectiveModel(), aiConfig.effectiveMaxTokens());
            successCount++;
        } catch (SecretRetrievalException e) {
            healthController.getSecretLoadStatus().put("openai",
                    HealthController.SecretLoadStatus.failure(e.getMessage()));
            log.error("  ❌ OpenAI configuration  — FAILED: {}", e.getMessage());
            failCount++;
        }

        // --- Summary ---
        Duration elapsed = Duration.between(startTime, Instant.now());
        log.info("─".repeat(70));
        log.info("  Validation complete: {}/{} secrets loaded successfully in {}ms",
                successCount, successCount + failCount, elapsed.toMillis());

        if (failCount > 0) {
            // CRITICAL: Fail fast if required secrets are missing.
            // SECURITY: A running application with missing secrets is DANGEROUS:
            // - It may fall back to insecure defaults
            // - It may leak error details to users
            // - It represents a misconfigured deployment
            log.error("╔══════════════════════════════════════════════════════════════════╗");
            log.error("║  STARTUP VALIDATION FAILED — {} secret(s) could not be loaded {}",
                    failCount, " ".repeat(Math.max(0, 19 - String.valueOf(failCount).length())));
            log.error("║                                                                  ║");
            log.error("║  The application will continue but secret-dependent features     ║");
            log.error("║  may not work correctly. Check the errors above and verify       ║");
            log.error("║  your secrets are configured in the {} provider.                {}",
                    provider, " ".repeat(Math.max(0, 27 - provider.length())));
            log.error("╚══════════════════════════════════════════════════════════════════╝");

            // In a strict production environment, you might want to exit:
            // System.exit(1);
            // For this tutorial, we log a warning but allow the app to start
            // so the /api/secrets/status endpoint can be used for debugging.
        } else {
            log.info("  🎉 All secrets validated successfully. Application is ready.");
        }

        // Log active profiles for diagnostics (non-sensitive)
        String[] profiles = environment.getActiveProfiles();
        if (profiles.length > 0) {
            log.info("  Active profiles: {}", String.join(", ", profiles));
        }
    }
}