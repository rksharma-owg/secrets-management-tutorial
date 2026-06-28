/*
 * ===========================================================================
 * SecretRetrievalException — Security-Safe Exception for Secret Operations
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This custom exception is thrown when secret retrieval fails. It is
 * designed to NEVER include secret values in its message, stack trace,
 * or any other output mechanism.
 *
 * WHY A CUSTOM EXCEPTION?
 * 1. Catching generic Exception makes it easy to accidentally log the
 *    cause chain which may contain secret values in provider SDK messages.
 * 2. A custom exception lets us control the message format to ensure
 *    no secret material leaks.
 * 3. It provides a clear signal to callers that this is a secrets-specific
 *    error, enabling appropriate handling (fail-fast, retry, alert).
 *
 * IMPORTANT: Never pass a secret value to this exception's constructor.
 * If you need context, use the secret NAME, never the secret VALUE.
 * ===========================================================================
 */
package com.tutorial.secrets.model;

/**
 * Thrown when a secret cannot be retrieved from the configured provider.
 *
 * <p>This exception deliberately does NOT store the secret value. Only the
 * secret name and provider are included for diagnostic purposes.</p>
 */
public class SecretRetrievalException extends RuntimeException {

    private final String secretName;
    private final String provider;

    /**
     * Creates a new exception for a failed secret retrieval.
     *
     * @param secretName the NAME of the secret that failed (never the value)
     * @param provider   the name of the secret provider (vault, aws, azure)
     * @param cause      the underlying cause (message is safe — no secret values)
     */
    public SecretRetrievalException(String secretName, String provider, Throwable cause) {
        // SECURITY: Only include secretName and provider in the message.
        // NEVER include the cause message directly if it could contain secret values.
        // Some SDKs include partial secret values in error messages.
        super(String.format(
                "Failed to retrieve secret '%s' from provider '%s': %s",
                secretName,
                provider,
                sanitizeCauseMessage(cause)
        ), cause);
        this.secretName = secretName;
        this.provider = provider;
    }

    /**
     * Creates a new exception with a custom message (for non-SDK errors).
     *
     * @param secretName the NAME of the secret that failed
     * @param provider   the name of the secret provider
     * @param message    a safe, human-readable error message
     */
    public SecretRetrievalException(String secretName, String provider, String message) {
        super(String.format("Secret '%s' [%s]: %s", secretName, provider, message));
        this.secretName = secretName;
        this.provider = provider;
    }

    public String getSecretName() {
        return secretName;
    }

    public String getProvider() {
        return provider;
    }

    /**
     * Sanitizes the cause's message to remove potential secret values.
     *
     * <p>Some SDK error messages include the secret name with additional
     * context that could leak information. This method extracts only
     * safe diagnostic information.</p>
     *
     * @param cause the original exception
     * @return a sanitized error message
     */
    private static String sanitizeCauseMessage(Throwable cause) {
        if (cause == null || cause.getMessage() == null) {
            return "unknown error";
        }

        String msg = cause.getMessage();

        // Truncate long messages — they may contain encoded secret values
        if (msg.length() > 200) {
            return msg.substring(0, 200) + "... [truncated for security]";
        }

        return msg;
    }
}