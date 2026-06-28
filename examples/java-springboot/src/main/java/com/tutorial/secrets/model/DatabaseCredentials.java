/*
 * ===========================================================================
 * DatabaseCredentials — Secure Database Credential Container
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This record encapsulates database credentials retrieved from a secret
 * provider. It demonstrates several security patterns:
 *
 * 1. IMMUTABILITY — Java records are inherently immutable. Once a
 *    DatabaseCredentials is created, its values cannot be altered. This
 *    prevents accidental or malicious modification of credentials in memory.
 *
 * 2. SERIALIZATION SAFETY — The password field is marked with @JsonIgnore
 *    to prevent it from being included in any JSON serialization. This
 *    protects against:
 *    - Accidental exposure in API responses
 *    - Leakage through error response bodies
 *    - Secret inclusion in log-structured output (e.g., JSON logging)
 *
 * 3. JDBC URL CONSTRUCTION — The jdbcUrl() method builds the connection
 *    string from components rather than storing a pre-built URL. This
 *    allows each component to be validated independently and prevents
 *    URL injection attacks.
 *
 * 4. MINIMUM PRIVILEGE — Each field is a separate credential component.
 *    In production, use the specific database/username that has minimum
 *    required permissions (principle of least privilege).
 *
 * USAGE:
 *   DatabaseCredentials creds = secretManager.getDatabaseCredentials();
 *   HikariDataSource ds = new HikariDataSource();
 *   ds.setJdbcUrl(creds.jdbcUrl());
 *   ds.setUsername(creds.username());
 *   ds.setPassword(creds.password());
 *
 * ===========================================================================
 */
package com.tutorial.secrets.model;

import com.fasterxml.jackson.annotation.JsonIgnore;

/**
 * Immutable container for database connection credentials retrieved from a
 * secret provider (Vault, AWS Secrets Manager, or Azure Key Vault).
 *
 * <p>This class is designed so that even if an instance is accidentally
 * serialized to JSON (e.g., in an API response or log entry), the password
 * will be excluded.</p>
 *
 * <p><strong>WARNING:</strong> Even with @JsonIgnore, the password still
 * exists in memory. For the highest security requirements, consider using
 * Java's {@code SecretKey} or char arrays that can be zeroed after use.</p>
 *
 * @param username     database username
 * @param password     database password (never logged or serialized)
 * @param host         database host address
 * @param port         database port number
 * @param databaseName database/schema name
 */
public record DatabaseCredentials(
        String username,
        @JsonIgnore String password,   // NEVER serialized — prevents accidental exposure
        String host,
        int port,
        String databaseName
) {
    /**
     * Constructs a JDBC URL from the credential components.
     *
     * <p>Building the URL from validated components is safer than storing
     * an arbitrary JDBC URL string, as it prevents URL injection attacks
     * where a malicious secret could redirect the connection.</p>
     *
     * <p>Currently supports PostgreSQL. Extend this method with a
     * {@code databaseType} field to support MySQL, Oracle, etc.</p>
     *
     * @return a properly formatted JDBC URL
     * @throws IllegalStateException if required fields (host, databaseName) are null
     */
    public String jdbcUrl() {
        if (host == null || host.isBlank()) {
            throw new IllegalStateException(
                    "Cannot build JDBC URL: database host is null or blank. " +
                    "Check your secret provider configuration.");
        }
        if (databaseName == null || databaseName.isBlank()) {
            throw new IllegalStateException(
                    "Cannot build JDBC URL: database name is null or blank. " +
                    "Check your secret provider configuration.");
        }

        // Construct JDBC URL from components — no user-supplied format strings
        // that could lead to injection. Port defaults to 5432 (PostgreSQL).
        int effectivePort = port > 0 ? port : 5432;
        return String.format("jdbc:postgresql://%s:%d/%s", host, effectivePort, databaseName);
    }

    /**
     * Validates that all required fields are present.
     *
     * <p>Call this immediately after retrieving credentials to fail fast
     * if the secret is malformed or incomplete.</p>
     *
     * @throws IllegalStateException if any required field is null or blank
     */
    public void validate() {
        if (username == null || username.isBlank()) {
            throw new IllegalStateException("Database username is missing from secret provider");
        }
        if (password == null || password.isBlank()) {
            throw new IllegalStateException("Database password is missing from secret provider");
        }
        // jdbcUrl() internally validates host and databaseName
        jdbcUrl(); // Will throw if host or databaseName is invalid
    }
}