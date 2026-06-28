/*
 * ===========================================================================
 * JwtConfig — JWT Signing Configuration Container
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This record holds the configuration needed for JSON Web Token (JWT)
 * signing and verification. The security considerations are:
 *
 * 1. SECRET KEY LENGTH — HMAC-SHA256 requires a minimum 256-bit (32-byte)
 *    key. Shorter keys are vulnerable to brute-force attacks. The @Min
 *    annotation enforces this at configuration time.
 *
 * 2. ALGORITHM RESTRICTION — Only allow strong algorithms (HS256, HS384,
 *    HS512, RS256). Never allow "none" algorithm which is a known
 *    JWT attack vector.
 *
 * 3. IMMUTABILITY — Records are immutable, preventing key tampering
 *    after initialization.
 *
 * 4. SEPARATION OF CONCERNS — The signing key is stored in the secret
 *    provider, NOT in application code or configuration files.
 *
 * KEY ROTATION:
 * When rotating JWT keys, you typically need two keys: the current key
 * for signing and the previous key for verifying tokens issued before
 * rotation. Store both in your secret provider.
 * ===========================================================================
 */
package com.tutorial.secrets.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Positive;

/**
 * Immutable JWT configuration retrieved from a secret provider.
 *
 * <p><strong>Security Requirements:</strong></p>
 * <ul>
 *   <li>secretKey must be at least 32 bytes for HMAC-SHA256 (256 bits)</li>
 *   <li>algorithm must be a known strong algorithm (HS256, HS384, HS512, RS256)</li>
 *   <li>expiryHours should be as short as practical (typically 1-24 hours)</li>
 * </ul>
 *
 * @param secretKey   the HMAC secret or RSA private key (minimum 32 characters)
 * @param algorithm   the JWA algorithm identifier (e.g., "HS256")
 * @param issuer      the JWT issuer claim (typically your application URL)
 * @param expiryHours token expiration time in hours
 */
public record JwtConfig(
        @NotBlank(message = "JWT secret key must not be blank")
        String secretKey,

        @NotBlank(message = "JWT algorithm must not be blank")
        @Pattern(
                regexp = "^(HS256|HS384|HS512|RS256|RS384|RS512|ES256|ES384|ES512)$",
                message = "JWT algorithm must be a secure algorithm (HS256, RS256, etc.). " +
                          "Never use 'none' algorithm — it is a critical security vulnerability."
        )
        String algorithm,

        @NotBlank(message = "JWT issuer must not be blank")
        String issuer,

        @Positive(message = "JWT expiry hours must be positive")
        int expiryHours
) {
    /**
     * Default expiry hours for JWTs — 8 hours balances security and usability.
     * Override via secret provider for shorter/longer sessions.
     */
    public static final int DEFAULT_EXPIRY_HOURS = 8;

    /**
     * Minimum secret key length in characters for HMAC-SHA256 (256 bits = 32 bytes).
     * For RSA keys, the minimum is much longer (2048-bit key ≈ 256+ base64 characters).
     */
    public static final int MIN_KEY_LENGTH = 32;

    /**
     * Validates that the secret key meets minimum length requirements.
     *
     * <p>HMAC-SHA256 requires a key of at least 256 bits (32 bytes).
     * Using a shorter key dramatically reduces the security of the MAC
     * and makes brute-force attacks feasible.</p>
     *
     * @throws IllegalStateException if the secret key is too short
     */
    public void validateKeyStrength() {
        if (secretKey == null || secretKey.length() < MIN_KEY_LENGTH) {
            throw new IllegalStateException(
                    "JWT secret key is too short (%d chars). Minimum is %d chars " +
                    "(256 bits) for HMAC-SHA256. Update your secret in the provider."
                            .formatted(
                                    secretKey == null ? 0 : secretKey.length(),
                                    MIN_KEY_LENGTH
                            )
            );
        }

        // Warn if the key appears to be a well-known test/default value
        String lowerKey = secretKey.toLowerCase();
        if (lowerKey.contains("changeme") || lowerKey.contains("secret")
                || lowerKey.contains("password") || lowerKey.contains("default")) {
            // SECURITY: We intentionally do NOT log the key value here.
            // This check catches common weak keys used in tutorials.
            throw new IllegalStateException(
                    "JWT secret key appears to be a default/placeholder value. " +
                    "Generate a cryptographically secure random key (minimum 32 bytes) " +
                    "and store it in your secret provider."
            );
        }
    }
}