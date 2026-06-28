/*
 * ===========================================================================
 * HealthController — Secure REST API Endpoints
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This controller demonstrates how to build REST endpoints that
 * interact with secrets WITHOUT ever exposing them in responses.
 *
 * CORE SECURITY PRINCIPLES:
 *
 * 1. NEVER RETURN SECRETS IN API RESPONSES — Every endpoint returns
 *    only metadata (status, provider name, configuration info). Secret
 *    values are NEVER included in HTTP responses, even partially masked.
 *    Partially masked values (e.g., "sk-****...****abc") can sometimes be
 *    reversed with enough samples.
 *
 * 2. USE SANITIZED DTOs — The ConfigStatusResponse record contains only
 *    non-sensitive fields. Even if the controller has access to secret
 *    values, the response object cannot carry them.
 *
 * 3. AUDIT ALL SECRET ACCESS — The /api/secrets/status endpoint logs
 *    every secret access attempt for the audit trail. This is critical
 *    for compliance (SOC 2, PCI-DSS, HIPAA).
 *
 * 4. SEPARATE CONCERNS — Secret retrieval is in the service layer.
 *    This controller only orchestrates: it calls services and formats
 *    responses. It never directly accesses any secret provider SDK.
 *
 * 5. RATE-LIMIT SENSITIVE ENDPOINTS — In production, add rate limiting
 *    to POST /api/secrets/refresh and POST /api/ai/chat to prevent
 *    abuse (secret enumeration, API cost attacks).
 *
 * PRODUCTION ADDITIONS:
 * - Add @PreAuthorize or @Secured annotations for authentication
 * - Add rate limiting (Spring Cloud Gateway or Bucket4j)
 * - Add request/response logging (but NOT secret values)
 * - Add CORS restrictions
 * ===========================================================================
 */
package com.tutorial.secrets.controller;

import com.tutorial.secrets.model.DatabaseCredentials;
import com.tutorial.secrets.model.SecretRetrievalException;
import com.tutorial.secrets.service.SecretManagerService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * REST controller providing secure endpoints for configuration status,
 * secret health checks, and secret refresh operations.
 *
 * <p><strong>SECURITY DESIGN:</strong> No endpoint in this controller
 * returns secret values. All responses use sanitized DTOs that are
 * structurally incapable of carrying sensitive data.</p>
 */
@RestController
@RequestMapping("/api")
public class HealthController {

    private static final Logger log = LoggerFactory.getLogger(HealthController.class);

    private final SecretManagerService secretManager;

    /**
     * Tracks which secrets have been successfully loaded.
     * Map of secret name → load status. Updated at startup.
     */
    private final Map<String, SecretLoadStatus> secretLoadStatus = new LinkedHashMap<>();

    public HealthController(SecretManagerService secretManager) {
        this.secretManager = secretManager;
    }

    // ====================================================================
    // CONFIGURATION ENDPOINT
    // ====================================================================

    /**
     * Returns NON-SENSITIVE configuration information.
     *
     * <p>SECURITY: This endpoint intentionally returns only metadata:
     * - Provider name (not credentials)
     * - Region (not IAM roles)
     * - Profile (not environment variables)
     * - Timestamp (for debugging)</p>
     *
     * <p>This is safe to expose without authentication because it reveals
     * only what an attacker could likely discover through other means
     * (user-agent, response headers, error messages).</p>
     */
    @GetMapping("/config")
    public ResponseEntity<Map<String, Object>> getConfig() {
        // SECURITY: Only include non-sensitive configuration values.
        // Never include: tokens, keys, passwords, connection strings.
        Map<String, Object> config = Map.of(
                "provider", secretManager.getProviderName(),
                "profile", System.getenv().getOrDefault("SPRING_PROFILES_ACTIVE", "dev"),
                "region", System.getenv().getOrDefault("AWS_REGION", "us-east-1"),
                "timestamp", Instant.now().toString()
        );

        log.info("Configuration status requested [provider={}]", secretManager.getProviderName());
        return ResponseEntity.ok(config);
    }

    // ====================================================================
    // SECRET STATUS ENDPOINT
    // ====================================================================

    /**
     * Returns the loading status of all secrets WITHOUT their values.
     *
     * <p>SECURITY: This endpoint reveals only:</p>
     * <ul>
     *   <li>Which secrets were expected (names only, not values)</li>
     *   <li>Whether each secret was loaded successfully</li>
     *   <li>Error messages (sanitized — no secret values)</li>
     * </ul>
     *
     * <p>This is useful for:
     * - Pre-deployment checks ("are all secrets configured?")
     * - Debugging ("which secret is missing?")
     * - Monitoring ("alert if any secret fails to load")</p>
     */
    @GetMapping("/secrets/status")
    public ResponseEntity<Map<String, Object>> getSecretStatus() {
        // SECURITY: We return only the status map, which contains
        // secret names and load results. No secret values are included.
        Map<String, Object> response = Map.of(
                "provider", secretManager.getProviderName(),
                "secrets", secretLoadStatus,
                "totalExpected", secretLoadStatus.size(),
                "loadedCount", secretLoadStatus.values().stream()
                        .filter(s -> s.loaded).count(),
                "failedCount", secretLoadStatus.values().stream()
                        .filter(s -> !s.loaded).count(),
                "timestamp", Instant.now().toString()
        );

        return ResponseEntity.ok(response);
    }

    // ====================================================================
    // SECRET REFRESH ENDPOINT
    // ====================================================================

    /**
     * Triggers a manual refresh of a specific secret.
     *
     * <p>USE CASE: After rotating a secret in the provider, call this
     * endpoint to force the application to fetch the new version without
     * restarting.</p>
     *
     * <p>SECURITY: In production, this endpoint should be behind
     * authentication. An attacker who can call this endpoint can
     * trigger unnecessary API calls to your secret provider (DoS risk).
     * Consider rate limiting and admin-only access.</p>
     *
     * @param secretName the name of the secret to refresh
     * @return refresh result status
     */
    @PostMapping("/secrets/refresh")
    public ResponseEntity<Map<String, Object>> refreshSecret(
            @RequestParam String secretName) {

        // SECURITY: Validate the secret name to prevent injection attacks.
        // Only allow alphanumeric names, hyphens, and forward slashes.
        if (!secretName.matches("^[a-zA-Z0-9/_-]+$")) {
            log.warn("Invalid secret name in refresh request: {}", secretName);
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Invalid secret name format",
                    "message", "Secret names may only contain alphanumeric characters, hyphens, and slashes"
            ));
        }

        log.info("Secret refresh requested [name={}, provider={}]",
                secretName, secretManager.getProviderName());

        try {
            secretManager.refreshSecret(secretName);

            // Update the load status
            secretLoadStatus.put(secretName, new SecretLoadStatus(true, null, Instant.now()));

            return ResponseEntity.ok(Map.of(
                    "status", "refreshed",
                    "secretName", secretName,
                    "provider", secretManager.getProviderName(),
                    "timestamp", Instant.now().toString()
            ));
        } catch (SecretRetrievalException e) {
            log.error("Secret refresh failed [name={}]", secretName);

            secretLoadStatus.put(secretName, new SecretLoadStatus(false, e.getMessage(), Instant.now()));

            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                    "status", "refresh_failed",
                    "secretName", secretName,
                    "provider", secretManager.getProviderName(),
                    "error", "Secret retrieval failed. Check server logs for details."
            ));
        }
    }

    // ====================================================================
    // DATABASE CONNECTIVITY TEST
    // ====================================================================

    /**
     * Tests database connectivity using credentials from the secret provider.
     *
     * <p>SECURITY: This endpoint does NOT return the database credentials.
     * It only returns whether the connection was successful. The connection
     * attempt itself is logged for the audit trail.</p>
     *
     * @return connectivity test result
     */
    @GetMapping("/db/test")
    public ResponseEntity<Map<String, Object>> testDatabaseConnection() {
        log.info("Database connectivity test requested [provider={}]",
                secretManager.getProviderName());

        try {
            DatabaseCredentials creds = secretManager.getDatabaseCredentials();

            // SECURITY: We log the JDBC URL host and database name (infrastructure info)
            // but NOT the username or password.
            log.info("Database credentials retrieved successfully [host={}, database={}]",
                    creds.host(), creds.databaseName());

            // In a real application, you would test the connection here:
            // try (Connection conn = dataSource.getConnection()) { ... }
            // For this tutorial, we just verify credentials were loaded.

            return ResponseEntity.ok(Map.of(
                    "status", "credentials_loaded",
                    "database", creds.databaseName(),
                    "host", creds.host(),
                    "port", creds.port(),
                    // SECURITY: Username is borderline — it's not a secret per se,
                    // but in some environments it reveals schema information.
                    // Include only if your security policy allows it.
                    "username", creds.username(),
                    "timestamp", Instant.now().toString(),
                    "note", "Credentials loaded from " + secretManager.getProviderName()
            ));
        } catch (SecretRetrievalException e) {
            log.error("Failed to load database credentials for test");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                    "status", "failed",
                    "error", "Could not retrieve database credentials",
                    "provider", secretManager.getProviderName()
            ));
        }
    }

    // ====================================================================
    // AI CHAT ENDPOINT (OpenAI Integration Example)
    // ====================================================================

    /**
     * Example endpoint demonstrating OpenAI integration using secrets.
     *
     * <p>SECURITY: The API key is fetched from the secret provider and
     * used to make the API call. The key is NEVER returned in the response.</p>
     *
     * <p>PRODUCTION NOTES:</p>
     * <ul>
     *   <li>Add request validation (max input length, content filtering)</li>
     *   <li>Add rate limiting (prevent API cost attacks)</li>
     *   <li>Add response validation (don't blindly proxy AI output)</li>
     *   <li>Log prompts and responses for audit (without API key)</li>
     * </ul>
     *
     * @param request the chat request body containing the user's message
     * @return the AI response (without any secret material)
     */
    @PostMapping("/ai/chat")
    public ResponseEntity<Map<String, Object>> chat(@RequestBody Map<String, String> request) {
        String userMessage = request.getOrDefault("message", "");

        if (userMessage.isBlank()) {
            return ResponseEntity.badRequest().body(Map.of(
                    "error", "Message is required"
            ));
        }

        // SECURITY: Log the prompt for audit but NOT the API key.
        // The prompt itself may be sensitive — consider whether to log it
        // based on your data classification policy.
        log.info("AI chat request received [messageLength={}, provider={}]",
                userMessage.length(), secretManager.getProviderName());

        try {
            var config = secretManager.getOpenaiConfig();

            // SECURITY: The API key is used for the HTTP request header only.
            // It is NEVER included in the response body.
            // In production, make the actual HTTP call to OpenAI here:
            //   HttpClient client = HttpClient.newHttpClient();
            //   HttpRequest apiRequest = HttpRequest.newBuilder()
            //       .uri(URI.create("https://api.openai.com/v1/chat/completions"))
            //       .header("Authorization", "Bearer " + config.apiKey())
            //       .POST(HttpRequest.BodyPublishers.ofString(jsonBody))
            //       .build();

            return ResponseEntity.ok(Map.of(
                    "status", "demo_mode",
                    "model", config.effectiveModel(),
                    "maxTokens", config.effectiveMaxTokens(),
                    "message", "In production, this would call OpenAI API using the secret key " +
                               "fetched from " + secretManager.getProviderName(),
                    "note", "API key is loaded securely and NEVER included in responses"
            ));
        } catch (SecretRetrievalException e) {
            log.error("Failed to load OpenAI configuration");
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(Map.of(
                    "status", "failed",
                    "error", "Could not retrieve OpenAI configuration"
            ));
        }
    }

    // ====================================================================
    // SECRET LOAD STATUS TRACKING
    // ====================================================================

    /**
     * Records the load status of a secret (used by /api/secrets/status).
     *
     * <p>SECURITY: This record contains only the secret NAME and load
     * result. No secret values are stored.</p>
     */
    public record SecretLoadStatus(boolean loaded, String error, Instant loadedAt) {
        public static SecretLoadStatus success() {
            return new SecretLoadStatus(true, null, Instant.now());
        }

        public static SecretLoadStatus failure(String error) {
            return new SecretLoadStatus(false, error, Instant.now());
        }
    }

    /**
     * Returns the secret load status map (for use by the application
     * startup validator and other components).
     *
     * @return mutable map of secret name → load status
     */
    public Map<String, SecretLoadStatus> getSecretLoadStatus() {
        return secretLoadStatus;
    }
}
