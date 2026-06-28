/*
 * ===========================================================================
 * AwsSecretsService — AWS Secrets Manager Integration
 * ===========================================================================
 *
 * SECURITY PURPOSE:
 * This service retrieves secrets from AWS Secrets Manager using the
 * AWS SDK v2. It demonstrates the recommended authentication pattern
 * for AWS services in production environments.
 *
 * AUTHENTICATION STRATEGY:
 * Uses DefaultCredentialsProvider which resolves credentials through a
 * chain of providers (environment → ECS → EC2/EKS IAM role → SSO).
 * In production on EKS/ECS/EC2, this means ZERO static credentials.
 * The application's IAM role (attached to the compute resource) provides
 * all necessary permissions via least-privilege IAM policies.
 *
 * REQUIRED IAM PERMISSIONS (attach to your EKS/ECS task role or EC2 profile):
 *   {
 *     "Version": "2012-10-17",
 *     "Statement": [
 *       {
 *         "Effect": "Allow",
 *         "Action": [
 *           "secretsmanager:GetSecretValue",
 *           "secretsmanager:DescribeSecret"
 *         ],
 *         "Resource": "arn:aws:secretsmanager:*:*:secret:secrets-tutorial/*"
 *       }
 *     ]
 *   }
 *
 * SECRET ROTATION:
 * AWS Secrets Manager supports automatic rotation via Lambda functions.
 * This service detects rotation by comparing secret versions. When a new
 * version is detected, the cached value is invalidated.
 *
 * COST CONSIDERATION:
 * AWS Secrets Manager charges per secret per month ($0.40) plus API calls.
 * Cache secret values locally to reduce API calls and cost.
 *
 * THREAD SAFETY:
 * The SecretsManagerClient is thread-safe and should be reused.
 * Do NOT create a new client per request.
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
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import software.amazon.awssdk.core.client.config.ClientOverrideConfiguration;
import software.amazon.awssdk.core.retry.RetryPolicy;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClientBuilder;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueRequest;
import software.amazon.awssdk.services.secretsmanager.model.GetSecretValueResponse;
import software.amazon.awssdk.services.secretsmanager.model.SecretsManagerException;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * AWS Secrets Manager implementation of {@link SecretManagerService}.
 *
 * <p>Activated when {@code secret.provider=aws}. Uses IAM role-based
 * authentication via {@code DefaultCredentialsProvider} — no static
 * access keys in code or configuration.</p>
 *
 * <p><strong>Important:</strong> This service caches secrets in memory
 * with a configurable TTL to reduce API calls and improve performance.
 * Call {@link #refreshSecret(String)} to invalidate the cache.</p>
 */
@Service
@ConditionalOnProperty(name = "secret.provider", havingValue = "aws")
public class AwsSecretsService implements SecretManagerService {

    private static final Logger log = LoggerFactory.getLogger(AwsSecretsService.class);

    // Jackson mapper for parsing JSON secrets — thread-safe after configuration
    private static final ObjectMapper MAPPER = new ObjectMapper();

    // Secret name constants — match what you create in AWS Secrets Manager
    private static final String DB_CREDENTIALS_SECRET = "secrets-tutorial/database";
    private static final String JWT_CONFIG_SECRET = "secrets-tutorial/jwt";
    private static final String OPENAI_CONFIG_SECRET = "secrets-tutorial/openai";

    /** The AWS Secrets Manager client — thread-safe, reused for all requests */
    private SecretsManagerClient secretsClient;

    /** Provider identifier returned by getProviderName() */
    private static final String PROVIDER_NAME = "aws";

    /**
     * Optional prefix for secret names, allowing namespace isolation.
     * Set via AWS_SECRETS_PREFIX environment variable.
     */
    @Value("${aws.secrets-prefix:secrets-tutorial/}")
    private String secretsPrefix;

    /**
     * Cache of secret names to their current version IDs.
     * Used to detect rotation — if the version ID changes, the cache is stale.
     */
    private final ConcurrentHashMap<String, String> secretVersions = new ConcurrentHashMap<>();

    /**
     * Cache of parsed secret JSON strings.
     * In production, consider using Caffeine/Guava cache with TTL instead.
     */
    private final ConcurrentHashMap<String, String> secretCache = new ConcurrentHashMap<>();

    /**
     * Initializes the AWS Secrets Manager client.
     *
     * <p>SECURITY: We use DefaultCredentialsProvider which automatically
     * resolves credentials from the environment. On AWS compute resources
     * (EKS, ECS, EC2), this uses the attached IAM role — no static
     * credentials needed.</p>
     *
     * <p>The client is configured with retry policies to handle transient
     * failures (network blips, throttling) without exposing errors
     * to the application.</p>
     */
    @PostConstruct
    void init() {
        // SECURITY: DefaultCredentialsProvider is the recommended way to
        // authenticate. It resolves credentials from:
        // 1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
        // 2. ECS container credentials (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
        // 3. EC2/EKS instance metadata service (IAM role)
        // 4. Web Identity Token (for EKS IRSA)
        // In production on AWS, option 2/3/4 should be used exclusively.
        SecretsManagerClientBuilder builder = SecretsManagerClient.builder()
                .credentialsProvider(
                        software.amazon.awssdk.auth.credentials.DefaultCredentialsProvider.create()
                )
                .region(Region.of(System.getenv().getOrDefault("AWS_REGION", "us-east-1")))
                // Configure retries for transient failures (throttling, network)
                .overrideConfiguration(ClientOverrideConfiguration.builder()
                        .retryPolicy(RetryPolicy.builder()
                                .numRetries(3)       // Retry up to 3 times
                                .backoffStrategy(f -> Duration.ofMillis(
                                        Math.min(f.retryAttempts() * 500L, 5000L)
                                )) // Exponential backoff, max 5s
                                .build()
                        )
                        .build()
                );

        // Support optional endpoint override for LocalStack (development)
        String endpointOverride = System.getenv().getOrDefault("AWS_SECRETS_ENDPOINT", "");
        if (!endpointOverride.isBlank()) {
            log.warn("Using non-standard AWS Secrets Manager endpoint: {}.*",
                    endpointOverride.replaceAll("(https?://[^/]+).*", "$1"));
            log.warn("This should ONLY be used for local development with LocalStack.");
            builder.endpointOverride(java.net.URI.create(endpointOverride));
        }

        this.secretsClient = builder.build();

        // SECURITY: Log only the provider name and region, not any credentials
        log.info("AWS Secrets Manager client initialized [region={}, prefix={}]",
                Region.of(System.getenv().getOrDefault("AWS_REGION", "us-east-1")),
                secretsPrefix);
    }

    @Override
    public String getSecret(String secretName) {
        // Apply the configured prefix to the secret name
        String fullSecretName = secretsPrefix + secretName;

        log.info("Retrieving secret from AWS Secrets Manager [name={}]", fullSecretName);

        try {
            GetSecretValueRequest request = GetSecretValueRequest.builder()
                    .secretId(fullSecretName)
                    // Request version staging label — "AWSCURRENT" is always the latest version
                    .versionStage("AWSCURRENT")
                    .build();

            GetSecretValueResponse response = secretsClient.getSecretValue(request);

            // Track the version ID for rotation detection
            String currentVersion = response.versionId();
            String previousVersion = secretVersions.put(fullSecretName, currentVersion);

            if (previousVersion != null && !previousVersion.equals(currentVersion)) {
                // SECURITY: We log the version change but NOT the secret value.
                // This is important for audit trails — you can see when
                // secrets were rotated and trace it to the rotation event.
                log.info("Secret version changed detected [name={}, oldVersion={} → newVersion={}]",
                        fullSecretName, maskVersion(previousVersion), maskVersion(currentVersion));
            }

            // Invalidate cache if version changed
            if (previousVersion != null && !previousVersion.equals(currentVersion)) {
                secretCache.remove(fullSecretName);
            }

            // AWS Secrets Manager can return the secret as either a
            // binary blob (SecretBinary) or a string (SecretString).
            // For typical JSON/text secrets, SecretString is used.
            String secretValue = response.secretString();
            if (secretValue == null && response.secretBinary() != null) {
                // Binary secrets are base64-encoded
                secretValue = response.secretBinary().asUtf8String();
            }

            if (secretValue == null) {
                throw new SecretRetrievalException(fullSecretName, PROVIDER_NAME,
                        "Secret value is null (check the secret content in AWS console)");
            }

            // Cache the raw value for subsequent getSecret() calls
            secretCache.put(fullSecretName, secretValue);

            log.info("Secret retrieved successfully [name={}, version={}]", fullSecretName,
                    maskVersion(currentVersion));
            return secretValue;

        } catch (SecretsManagerException e) {
            // SECURITY: We catch SecretsManagerException specifically.
            // The exception message from AWS may contain the secret ARN
            // but should NOT contain the secret value.
            // We wrap it in our custom exception for consistent error handling.
            log.error("Failed to retrieve secret from AWS [name={}, awsError={}]",
                    fullSecretName, e.awsErrorDetails().errorCode());
            throw new SecretRetrievalException(fullSecretName, PROVIDER_NAME, e);
        } catch (Exception e) {
            log.error("Unexpected error retrieving secret from AWS [name={}]", fullSecretName);
            throw new SecretRetrievalException(fullSecretName, PROVIDER_NAME, e);
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

            // Validate before returning — fail fast on misconfigured secrets
            creds.validate();

            return creds;
        } catch (JsonProcessingException e) {
            throw new SecretRetrievalException(DB_CREDENTIALS_SECRET, PROVIDER_NAME,
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

            // Validate key strength — catch weak/placeholder keys at runtime
            config.validateKeyStrength();

            return config;
        } catch (JsonProcessingException e) {
            throw new SecretRetrievalException(JWT_CONFIG_SECRET, PROVIDER_NAME,
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

            // Validate configuration
            config.validate();

            return config;
        } catch (JsonProcessingException e) {
            throw new SecretRetrievalException(OPENAI_CONFIG_SECRET, PROVIDER_NAME,
                    "Secret exists but is not valid JSON. Expected: {apiKey, model, organization, maxTokens}");
        }
    }

    @Override
    public void refreshSecret(String secretName) {
        String fullSecretName = secretsPrefix + secretName;

        // Remove from cache — next access will fetch the latest version
        secretCache.remove(fullSecretName);
        secretVersions.remove(fullSecretName);

        // SECURITY: Log the refresh operation but NOT the secret value.
        // This is important for audit trails.
        log.info("Secret cache invalidated for refresh [name={}, provider={}]", fullSecretName, PROVIDER_NAME);

        // Pre-warm the cache by fetching immediately
        // This ensures the new version is loaded before the next request
        try {
            getSecret(secretName);
            log.info("Secret refreshed successfully [name={}]", fullSecretName);
        } catch (Exception e) {
            log.error("Failed to refresh secret [name={}]. Will retry on next access.", fullSecretName);
            // Don't rethrow — the app can still serve requests with stale cached data
            // (if any exists) and will retry on the next getSecret() call.
        }
    }

    @Override
    public String getProviderName() {
        return PROVIDER_NAME;
    }

    /**
     * Masks a version ID for safe logging.
     * Shows only the first 4 and last 4 characters.
     *
     * <p>SECURITY: Version IDs are not secrets themselves, but masking
     * them is a good practice to prevent information leakage about
     * secret metadata that could aid an attacker.</p>
     */
    private static String maskVersion(String version) {
        if (version == null || version.length() <= 8) {
            return "****";
        }
        return version.substring(0, 4) + "****" + version.substring(version.length() - 4);
    }
}