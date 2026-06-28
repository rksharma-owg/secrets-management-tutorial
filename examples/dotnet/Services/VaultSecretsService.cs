// -----------------------------------------------------------------------------
// VaultSecretsService.cs
//
// SECURITY PURPOSE: Implements ISecretManagerService using HashiCorp Vault.
// Vault provides capabilities beyond simple secret storage:
//
//   1. Dynamic Secrets — Vault generates credentials on-demand with a TTL.
//      For example, a database secret can be a short-lived username/password
//      that Vault creates in PostgreSQL and automatically revokes when it
//      expires. No long-lived database passwords exist.
//
//   2. Encryption as a Service (Transit engine) — Encrypt data without
//      exposing the encryption key to the application. The key never leaves
//      Vault's memory. Applications send plaintext to Vault and receive
//      ciphertext (or vice versa).
//
//   3. Lease Tracking — Every secret Vault issues has a lease duration.
//      The application must renew leases before expiry or the secret is
//      automatically revoked. This forces regular credential rotation.
//
//   4. Audit Logging — Vault logs every operation (read, write, delete)
//      with a tamper-evident hash chain. Useful for compliance and
//      incident investigation.
//
// AUTHENTICATION METHODS (in order of production preference):
//   1. Kubernetes JWT auth — pod ServiceAccount token → Vault → short-lived
//      Vault token. No static tokens needed on Kubernetes.
//   2. AppRole auth — role ID + secret ID (the secret ID can come from
//      AWS Secrets Manager, creating a chain of trust).
//   3. Token auth (used in this example) — simplest but least secure.
//      Only acceptable for local development with dev-mode Vault.
// -----------------------------------------------------------------------------

using System.Collections.Concurrent;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using SecretsTutorial.Models;
using VaultSharp;
using VaultSharp.Core;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.SecretsEngines;

namespace SecretsTutorial.Services;

/// <summary>
/// HashiCorp Vault implementation of <see cref="ISecretManagerService"/>.
/// Supports KV v2 secrets engine with lease tracking for dynamic secrets.
/// </summary>
/// <remarks>
/// <para>
/// <b>Authentication:</b> Reads VAULT_ADDR and VAULT_TOKEN from environment
/// variables. In production on Kubernetes, use the Kubernetes auth method
/// (JWT token from ServiceAccount) instead of static tokens.
/// </para>
/// <para>
/// <b>Dynamic secrets:</b> Vault can generate database credentials,
/// cloud credentials, and X.509 certificates on demand. These secrets
/// have a lease duration and must be renewed or revoked. This service
/// tracks lease IDs and renewal deadlines for each secret.
/// </para>
/// </remarks>
public sealed class VaultSecretsService : ISecretManagerService
{
    private readonly IVaultClient _client;
    private readonly ILogger<VaultSecretsService> _logger;

    // In-memory cache for secret values. Key: secret path, Value: cached JSON.
    private readonly ConcurrentDictionary<string, (string Json, DateTime CachedAt)> _cache = new();

    // Lease tracking for dynamic secrets. Key: secret path, Value: (leaseId, expireAt).
    // SECURITY: Lease IDs are not secrets — they are used to renew/revoke access.
    private readonly ConcurrentDictionary<string, (string LeaseId, DateTime ExpiresAt)> _leases = new();

    private readonly TimeSpan _cacheTtl = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Creates a new Vault secrets service.
    /// Bootstraps VAULT_ADDR and VAULT_TOKEN from environment variables.
    /// </summary>
    /// <param name="logger">Structured logger. MUST NOT be used to log secret values.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when VAULT_ADDR or VAULT_TOKEN is not set.
    /// </exception>
    public VaultSecretsService(ILogger<VaultSecretsService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // SECURITY: These are configuration values, not secrets. VAULT_ADDR
        // is the Vault server URL (like https://vault.example.com:8200).
        // It's safe to log for debugging connectivity issues.
        var vaultAddr = Environment.GetEnvironmentVariable("VAULT_ADDR")
            ?? throw new InvalidOperationException(
                "VAULT_ADDR environment variable is required. " +
                "Example: 'https://vault.example.com:8200'");

        var vaultToken = Environment.GetEnvironmentVariable("VAULT_TOKEN")
            ?? throw new InvalidOperationException(
                "VAULT_TOKEN environment variable is required for token auth. " +
                "In production on Kubernetes, use the Kubernetes auth method " +
                "(JWT) instead of static tokens to eliminate long-lived tokens.");

        // SECURITY: Warn if Vault is accessed over HTTP (no TLS).
        // In production, Vault MUST use HTTPS. HTTP is only for dev mode.
        if (vaultAddr.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
        {
            _logger.LogWarning(
                "Vault is configured with HTTP (no TLS). " +
                "This is ONLY acceptable for local development. " +
                "Production Vault MUST use HTTPS to protect tokens and secrets in transit.");
        }

        // Configure VaultSharp with token authentication.
        // In production, replace IAuthMethodInfo with KubernetesAuthMethodInfo
        // or AppRoleAuthMethodInfo.
        var authMethodInfo = new TokenAuthMethodInfo(vaultToken);

        var vaultClientSettings = new VaultClientSettings(vaultAddr, authMethodInfo)
        {
            // VaultSharp will verify TLS certificates by default.
            // For dev mode with self-signed certs, you may need to disable this:
            // ContinueAsyncTasksOnCapturedContext = false,
            // MyHttpClientProviderFunc = () => new HttpClient(...),
        };

        _client = new VaultClient(vaultClientSettings);

        // SECURITY: Log only the Vault address (not the token).
        _logger.LogInformation(
            "Vault service initialized with address {VaultAddr}", vaultAddr);
    }

    /// <inheritdoc />
    public async Task<string> GetSecretAsync(string secretName, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(secretName);

        // Check cache first
        var cached = _cache.GetValueOrDefault(secretName);
        if (cached is not null && DateTime.UtcNow - cached.CachedAt < _cacheTtl)
        {
            _logger.LogDebug("Cache hit for secret {SecretPath}", secretName);
            return cached.Json;
        }

        _logger.LogInformation("Fetching secret {SecretPath} from Vault KV v2", secretName);

        try
        {
            // KV v2 API: the actual data is nested under "data.data".
            // VaultSharp handles this automatically when using the KV v2 secrets engine.
            Secret<SecretData> secret = await _client.V1.Secrets.KeyValue.V2
                .ReadSecretAsync(path: secretName, mountPoint: "secret");

            var json = secret.Data.Data != null
                ? JsonSerializer.Serialize(secret.Data.Data)
                : throw new SecretRetrievalException(
                    secretName, "EmptySecret",
                    $"Vault secret '{secretName}' exists but contains no data.");

            // Track lease information for dynamic secrets.
            // Static KV secrets have a lease_duration of 0 or a very long duration.
            if (secret.LeaseDuration > 0 && secret.LeaseId is not null)
            {
                _leases[secretName] = (
                    LeaseId: secret.LeaseId,
                    ExpiresAt: DateTime.UtcNow.AddSeconds(secret.LeaseDuration));

                _logger.LogInformation(
                    "Secret {SecretPath} has a lease (ID: {LeaseId}, duration: {LeaseDuration}s). " +
                    "Ensure lease renewal is configured for production workloads.",
                    secretName,
                    // SECURITY: LeaseId is safe to log (it's a reference, not a secret).
                    secret.LeaseId,
                    secret.LeaseDuration);
            }

            // Update cache
            _cache[secretName] = (Json: json, CachedAt: DateTime.UtcNow);

            // SECURITY: Log only the secret path — never the value.
            _logger.LogInformation(
                "Successfully fetched secret {SecretPath} (version {Version})",
                secretName,
                secret.Data.Metadata?.Version.ToString() ?? "unknown");

            return json;
        }
        catch (VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.NotFound)
        {
            _logger.LogError("Secret {SecretPath} not found in Vault", secretName);
            throw new SecretRetrievalException(
                secretName, "NotFound",
                $"Secret '{secretName}' does not exist in Vault or you lack permission.");
        }
        catch (VaultApiException ex) when (ex.HttpStatusCode == System.Net.HttpStatusCode.Forbidden)
        {
            // SECURITY: Do not log the Vault token or policy details.
            _logger.LogError(
                "Access denied when fetching secret {SecretPath}. " +
                "Verify the Vault token has read permission on this path.",
                secretName);
            throw new SecretRetrievalException(
                secretName, "AccessDenied",
                $"Access denied for secret '{secretName}'. Check Vault policies.");
        }
        catch (Exception ex) when (ex is not SecretRetrievalException)
        {
            _logger.LogError(ex,
                "Unexpected error fetching secret {SecretPath} from Vault", secretName);
            throw new SecretRetrievalException(
                secretName, "Unknown",
                $"Failed to retrieve secret '{secretName}' from Vault.",
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
        config.Validate();
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
        // Check if there's a lease to revoke before refreshing.
        if (_leases.TryRemove(secretName, out var oldLease))
        {
            try
            {
                // Revoke the old lease so the old credentials are invalidated
                // in Vault. This is critical for security — old credentials
                // must not remain valid after rotation.
                await _client.V1.System.RevokeLeaseAsync(oldLease.LeaseId);

                _logger.LogInformation(
                    "Revoked old lease {LeaseId} for secret {SecretPath}",
                    oldLease.LeaseId, secretName);
            }
            catch (Exception ex)
            {
                // Lease revocation failure is non-fatal. The lease will
                // expire naturally. Log but don't block the refresh.
                _logger.LogWarning(ex,
                    "Failed to revoke lease {LeaseId} for secret {SecretPath}. " +
                    "The lease will expire naturally.",
                    oldLease.LeaseId, secretName);
            }
        }

        // Clear the cache and re-fetch.
        _cache.TryRemove(secretName, out _);
        _logger.LogInformation(
            "Secret {SecretPath} cache cleared for refresh", secretName);

        await GetSecretAsync(secretName, ct);
    }

    /// <summary>
    /// Deserializes JSON from Vault into a strongly-typed object.
    /// </summary>
    private T DeserializeAndValidate<T>(string secretName, string json) where T : class
    {
        try
        {
            return JsonSerializer.Deserialize<T>(json, _jsonOptions)
                ?? throw new JsonException("Deserialization returned null.");
        }
        catch (JsonException ex)
        {
            // SECURITY: Do NOT include the raw JSON in the exception or log.
            _logger.LogError(ex,
                "Failed to deserialize Vault secret {SecretPath} as {TypeName}",
                secretName, typeof(T).Name);
            throw new SecretRetrievalException(
                secretName, "DeserializationError",
                $"Vault secret '{secretName}' could not be deserialized as {typeof(T).Name}.",
                ex);
        }
    }

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };
}