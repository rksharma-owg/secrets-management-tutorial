/*
 * ===========================================================================
 * SecretManagerService — Provider-Agnostic Secret Access Contract
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This interface defines the contract for all secret providers. By
 * programming to this interface (not a specific implementation), your
 * application code becomes:
 *
 * 1. PROVIDER-INDEPENDENT — Switch from Vault to AWS to Azure by
 *    changing ONE environment variable (SECRET_PROVIDER). No code changes.
 *
 * 2. TESTABLE — Mock this interface in tests without needing a real
 *    secret provider. Use a simple Map-backed implementation for tests.
 *
 * 3. AUDITABLE — Every secret access goes through these methods, making
 *    it easy to add logging, metrics, or access tracking.
 *
 * 4. MIGRATABLE — Migrating between providers requires only implementing
 *    this interface. No scattered provider-specific code to refactor.
 *
 * WHY AN INTERFACE (NOT AN ABSTRACT CLASS)?
 * - Java supports single inheritance but multiple interface implementation
 * - Interfaces work better with Spring's @ConditionalOnProperty
 * - No shared state between providers (each is independent)
 * - Enables mocking with Mockito without class hierarchy issues
 *
 * SECRET ROTATION PATTERN:
 * The refreshSecret() method supports push-based rotation where:
 * 1. Provider detects new version (AWS SecretVersion, Vault version)
 * 2. Application calls refreshSecret() to update in-memory cache
 * 3. For databases, also triggers HikariCP connection pool reset
 *
 * For pull-based rotation, implement a @Scheduled method that polls
 * for version changes at a configurable interval.
 * ===========================================================================
 */
package com.tutorial.secrets.service;

import com.tutorial.secrets.model.DatabaseCredentials;
import com.tutorial.secrets.model.JwtConfig;
import com.tutorial.secrets.model.OpenAIConfig;

/**
 * Provider-agnostic interface for retrieving secrets from any secret
 * management system (Vault, AWS Secrets Manager, Azure Key Vault).
 *
 * <p>All implementations are selected at startup via
 * {@code @ConditionalOnProperty(name = "secret.provider", havingValue = "...")}
 * and registered as a Spring bean.</p>
 *
 * <p><strong>Security contract:</strong> Implementations MUST:</p>
 * <ul>
 *   <li>Never log secret values (log the secret NAME and OPERATION only)</li>
 *   <li>Never cache secrets indefinitely (respect TTL/lease duration)</li>
 *   <li>Never throw exceptions containing secret values</li>
 *   <li>Validate secret format/length before returning</li>
 * </ul>
 */
public interface SecretManagerService {

    /**
     * Retrieves a raw secret value by name from the configured provider.
     *
     * <p>Use this for arbitrary secrets not covered by the typed methods.
     * The returned string should be handled with extreme care — never log it,
     * never include it in error messages, and zero it from memory when done.</p>
     *
     * @param secretName the name/path of the secret in the provider
     * @return the secret value as a string
     * @throws com.tutorial.secrets.model.SecretRetrievalException if retrieval fails
     */
    String getSecret(String secretName);

    /**
     * Retrieves database credentials from the secret provider.
     *
     * <p>The secret is expected to be stored as a JSON object with fields:
     * username, password, host, port, databaseName.</p>
     *
     * <p>In production, prefer dynamic database credentials (Vault's
     * database secrets engine, AWS RDS IAM authentication) over static
     * credentials. Dynamic credentials have a limited TTL and are
     * automatically revoked.</p>
     *
     * @return validated database credentials
     * @throws com.tutorial.secrets.model.SecretRetrievalException if retrieval fails
     */
    DatabaseCredentials getDatabaseCredentials();

    /**
     * Retrieves JWT signing configuration from the secret provider.
     *
     * <p>The secret is expected to be stored as a JSON object with fields:
     * secretKey, algorithm, issuer, expiryHours.</p>
     *
     * @return validated JWT configuration
     * @throws com.tutorial.secrets.model.SecretRetrievalException if retrieval fails
     */
    JwtConfig getJwtConfig();

    /**
     * Retrieves OpenAI API configuration from the secret provider.
     *
     * <p>The secret is expected to be stored as a JSON object with fields:
     * apiKey, model, organization, maxTokens.</p>
     *
     * @return validated OpenAI configuration
     * @throws com.tutorial.secrets.model.SecretRetrievalException if retrieval fails
     */
    OpenAIConfig getOpenaiConfig();

    /**
     * Triggers a refresh of a specific secret, useful after rotation.
     *
     * <p>Secret rotation is the process of updating a secret without
     * application downtime. The flow is typically:</p>
     * <ol>
     *   <li>Admin rotates the secret in the provider (new version created)</li>
     *   <li>Provider notifies the application (webhook, SQS, etc.)</li>
     *   <li>Application calls refreshSecret() to fetch the new version</li>
     *   <li>Application updates in-memory references (DataSource, etc.)</li>
     * </ol>
     *
     * <p>For databases, this should also reset the connection pool
     * to use the new credentials.</p>
     *
     * @param secretName the name of the secret to refresh
     * @throws com.tutorial.secrets.model.SecretRetrievalException if refresh fails
     */
    void refreshSecret(String secretName);

    /**
     * Returns the name of the active secret provider for diagnostic purposes.
     *
     * <p>This is safe to log and expose in API responses — it does not
     * contain any secret material.</p>
     *
     * @return provider name (e.g., "vault", "aws", "azure")
     */
    String getProviderName();
}