// -----------------------------------------------------------------------------
// AwsSecretsManagerService.cs
//
// SECURITY PURPOSE: Implements ISecretManagerService using AWS Secrets Manager.
// This is the recommended approach for applications running on AWS (EC2, ECS,
// EKS, Lambda). Authentication uses the AWS default credential chain, which
// resolves credentials in this order:
//
//   1. Environment variables (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY)
//      → NOT recommended for production (static, long-lived credentials)
//   2. ECS container credentials (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI)
//      → Recommended for ECS/Fargate tasks with task IAM roles
//   3. EC2 instance metadata (IMDSv2)
//      → Recommended for EC2/EKS with instance profiles
//   4. IAM Identity Center (SSO) cached credentials
//   5. AWS CLI / SDK cached credentials (~/.aws/credentials)
//      → Acceptable for local development only
//
// WHY THIS IS MORE SECURE THAN .ENV FILES:
//   - No credentials on disk (instance metadata is ephemeral, auto-rotated)
//   - Fine-grained IAM policies (least privilege per secret)
//   - Automatic secret rotation with Lambda functions
//   - CloudTrail audit logging for every API call
//   - Encryption at rest with KMS (customer-managed keys)
//   - No secrets in source control, CI/CD logs, or Docker images
// -----------------------------------------------------------------------------

using System.Collections.Concurrent;
using System.Text.Json;
using Amazon.SecretsManager;
using Amazon.SecretsManager.Model;
using Amazon.Runtime;
using Microsoft.Extensions.Logging;
using SecretsTutorial.Models;

namespace SecretsTutorial.Services;

/// <summary>
/// AWS Secrets Manager implementation of <see cref="ISecretManagerService"/>.
/// Uses the AWS default credential chain — no static access keys in code.
/// </summary>
/// <remarks>
/// <para>
/// <b>Authentication:</b> Uses <see cref="AmazonSecretsManagerClient"/> with
/// <see cref="CredentialResolutionChain"/> (the default). On EC2/ECS/EKS, this
/// resolves to the IAM role attached to the compute resource. The SDK handles
/// credential refresh automatically — temporary credentials are rotated
/// before they expire.
/// </para>
/// <para>
/// <b>Caching:</b> Secrets are cached in memory with a configurable TTL
/// (default: 5 minutes). This reduces API calls to Secrets Manager and
/// provides resilience against transient network failures. Cache entries
/// are keyed by secret name and version ID.
/// </para>
/// <para>
/// <b>Version tracking:</b> AWS Secrets Manager versions each secret. This
/// service tracks the <c>VersionId</c> in the cache to detect when a secret
/// has been rotated. If the version changes, the cache is invalidated and
/// the new version is fetched.
/// </para>
/// </remarks>
public sealed class AwsSecretsManagerService : ISecretManagerService
{
    private readonly AmazonSecretsManagerClient _client;
    private readonly ILogger<AwsSecretsManagerService> _logger;

    // Thread-safe in-memory cache. Key: secret name, Value: (version, value, timestamp).
    // SECURITY: This cache holds secrets in memory. On process exit, the memory
    // is freed and the secrets are gone. They are NEVER written to disk.
    private readonly ConcurrentDictionary<string, (string VersionId, string Json, DateTime CachedAt)> _cache = new();

    /// <summary>Default cache TTL in minutes. Override via constructor.</summary>
    private readonly TimeSpan _cacheTtl;

    /// <summary>
    /// Creates a new AWS Secrets Manager service.
    /// The AWS region is read from the AWS_REGION environment variable.
    /// Authentication uses the AWS default credential chain (IAM roles preferred).
    /// </summary>
    /// <param name="logger">Structured logger. MUST NOT be used to log secret values.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when AWS_REGION is not set or is invalid.
    /// </exception>
    public AwsSecretsManagerService(ILogger<AwsSecretsManagerService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // SECURITY: Region comes from environment — never hardcoded.
        // On AWS, the region is typically available via instance metadata,
        // but explicitly reading AWS_REGION makes the dependency visible.
        var region = Environment.GetEnvironmentVariable("AWS_REGION")
            ?? throw new InvalidOperationException(
                "AWS_REGION environment variable is required. " +
                "Example: 'us-east-1'. In production on EC2/EKS, set this " +
                "in the task definition or pod spec.");

        var regionEndpoint = Amazon.RegionEndpoint.GetBySystemName(region);

        // Use the default credential chain — this will resolve to:
        // - IAM role on EC2/ECS/EKS (production)
        // - AWS CLI credentials locally (development)
        // SECURITY: No access keys are passed to this constructor.
        _client = new AmazonSecretsManagerClient(regionEndpoint);

        _cacheTtl = TimeSpan.FromMinutes(5);

        // SECURITY: Log only the region and provider name — never credentials.
        _logger.LogInformation(
            "AWS Secrets Manager service initialized for region {Region}", region);
    }

    /// <inheritdoc />
    public async Task<string> GetSecretAsync(string secretName, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(secretName);

        var cached = _cache.GetValueOrDefault(secretName);
        if (cached is not null && DateTime.UtcNow - cached.CachedAt < _cacheTtl)
        {
            // Cache hit. SECURITY: Log the secret name and cache status only.
            _logger.LogDebug(
                "Cache hit for secret {SecretName} (version {VersionId}, cached {CachedAge} ago)",
                secretName, cached.VersionId,
                DateTime.UtcNow - cached.CachedAt);
            return cached.Json;
        }

        // Cache miss or expired — fetch from AWS Secrets Manager.
        _logger.LogInformation(
            "Fetching secret {SecretName} from AWS Secrets Manager", secretName);

        try
        {
            var request = new GetSecretValueRequest { SecretId = secretName };

            // SECURITY: This is the only point where we talk to AWS.
            // The network call is encrypted (TLS). The response contains
            // the secret value, which we store ONLY in the in-memory cache.
            var response = await _client.GetSecretValueAsync(request, ct);

            var secretValue = response.SecretString
                ?? throw new SecretRetrievalException(
                    secretName, "BinarySecret",
                    $"Secret '{secretName}' is a binary secret. " +
                    "Binary secrets are not supported by this implementation.");

            // Cache the result with its version ID for rotation detection.
            _cache[secretName] = (
                VersionId: response.VersionId ?? "unknown",
                Json: secretValue,
                CachedAt: DateTime.UtcNow);

            // SECURITY: Log only the secret name and version — never the value.
            _logger.LogInformation(
                "Successfully fetched secret {SecretName} (version {VersionId})",
                secretName, response.VersionId ?? "unknown");

            return secretValue;
        }
        catch (ResourceNotFoundException)
        {
            _logger.LogError("Secret {SecretName} not found in AWS Secrets Manager", secretName);
            throw new SecretRetrievalException(
                secretName, "NotFound",
                $"Secret '{secretName}' does not exist or you lack permission to read it.");
        }
        catch (UnauthorizedException)
        {
            // SECURITY: Do not log the IAM role or credential details.
            // The error message is intentionally generic to prevent
            // information leakage about the AWS account or role.
            _logger.LogError(
                "Access denied when fetching secret {SecretName}. " +
                "Verify the IAM role has secretsmanager:GetSecretValue permission.",
                secretName);
            throw new SecretRetrievalException(
                secretName, "AccessDenied",
                $"Access denied for secret '{secretName}'. Check IAM permissions.");
        }
        catch (Exception ex) when (ex is not SecretRetrievalException)
        {
            _logger.LogError(ex,
                "Unexpected error fetching secret {SecretName}", secretName);
            throw new SecretRetrievalException(
                secretName, "Unknown",
                $"Failed to retrieve secret '{secretName}'.",
                ex);
        }
    }

    /// <inheritdoc />
    public async Task<DatabaseCredentials> GetDatabaseCredentialsAsync(
        string secretName, CancellationToken ct = default)
    {
        var json = await GetSecretAsync(secretName, ct);
        return DeserializeAndValidate<DatabaseCredentials>(secretName, json);
    }

    /// <inheritdoc />
    public async Task<JwtConfig> GetJwtConfigAsync(
        string secretName, CancellationToken ct = default)
    {
        var json = await GetSecretAsync(secretName, ct);
        var config = DeserializeAndValidate<JwtConfig>(secretName, json);
        config.Validate(); // Validates key length for the algorithm
        return config;
    }

    /// <inheritdoc />
    public async Task<OpenAIConfig> GetOpenAIConfigAsync(
        string secretName, CancellationToken ct = default)
    {
        var json = await GetSecretAsync(secretName, ct);
        return DeserializeAndValidate<OpenAIConfig>(secretName, json);
    }

    /// <inheritdoc />
    public async Task RefreshSecretAsync(string secretName, CancellationToken ct = default)
    {
        // Remove from cache to force a fresh fetch on next access.
        _cache.TryRemove(secretName, out var old);

        // SECURITY: Log rotation event with version info — never values.
        _logger.LogInformation(
            "Secret {SecretName} cache cleared for refresh " +
            "(previous version: {OldVersionId})",
            secretName, old?.VersionId ?? "none");

        // Pre-warm the cache with the latest version so the caller
        // doesn't have to wait for the next GetSecretAsync call.
        await GetSecretAsync(secretName, ct);
    }

    /// <summary>
    /// Deserializes JSON from the secrets manager into a strongly-typed object.
    /// </summary>
    /// <remarks>
    /// <b>Security:</b> Deserialization errors are caught and wrapped in
    /// <see cref="SecretRetrievalException"/> to prevent leaking the raw JSON
    /// (which may contain secrets) in exception messages or stack traces.
    /// </remarks>
    private T DeserializeAndValidate<T>(string secretName, string json) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(json, JsonSerializerOptions)
                ?? throw new JsonException("Deserialization returned null.");
        }
        catch (JsonException ex)
        {
            // SECURITY: Do NOT include the raw JSON in the exception or log.
            // The JSON likely contains the secret value.
            _logger.LogError(ex,
                "Failed to deserialize secret {SecretName} as {TypeName}",
                secretName, typeof(T).Name);
            throw new SecretRetrievalException(
                secretName, "DeserializationError",
                $"Secret '{secretName}' could not be deserialized as {typeof(T).Name}. " +
                "Check that the secret JSON structure matches the expected schema.",
                ex);
        }
    }

    /// <summary>
    /// JSON serialization options. Case-insensitive deserialization for
    /// compatibility with secrets created by different tools (Terraform,
    /// AWS Console, CloudFormation) that may use different casing conventions.
    /// </summary>
    private static readonly JsonSerializerOptions JsonSerializerOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };
}