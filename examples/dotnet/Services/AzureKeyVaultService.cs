// -----------------------------------------------------------------------------
// AzureKeyVaultService.cs
//
// SECURITY PURPOSE: Implements ISecretManagerService using Azure Key Vault.
// Key Vault is Azure's managed secret storage service with hardware security
// module (HSM) backing for the most sensitive keys.
//
// WHY MANAGED IDENTITY ELIMINATES STATIC CREDENTIALS ENTIRELY:
//
//   When running on Azure App Service, AKS, Azure Functions, or Azure VMs,
//   the runtime automatically obtains an identity from the Azure Instance
//   Metadata Service (IMDS) at 169.254.169.254. This identity is bound to
//   the compute resource — it cannot be stolen and used from another machine.
//
//   The DefaultAzureCredential class tries these sources in order:
//     1. Managed Identity (App Service / AKS / VM) ← PRODUCTION
//     2. Visual Studio credentials ← LOCAL DEV
//     3. Azure CLI (az login) ← LOCAL DEV
//     4. Environment variables (AZURE_TENANT_ID, etc.) ← CI/CD
//     5. Shared token cache ← FALLBACK
//
//   In production, step 1 succeeds immediately. No secrets, no tokens,
//   no certificates — just the compute identity. This is the gold standard
//   for cloud-native authentication.
//
//   Key Vault access is controlled via Azure RBAC:
//     - Key Vault Secrets User (read) — for application runtime
//     - Key Vault Secrets Officer (read/write) — for CI/CD deployment
//     - Key Vault Administrator (full) — for break-glass scenarios only
// -----------------------------------------------------------------------------

using System.Collections.Concurrent;
using System.Text.Json;
using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Secrets;
using Microsoft.Extensions.Logging;
using SecretsTutorial.Models;

namespace SecretsTutorial.Services;

/// <summary>
/// Azure Key Vault implementation of <see cref="ISecretManagerService"/>.
/// Uses <see cref="DefaultAzureCredential"/> for authentication — supports
/// Managed Identity in production and developer tooling locally.
/// </summary>
/// <remarks>
/// <para>
/// <b>Authentication chain (DefaultAzureCredential):</b>
/// <list type="number">
///   <item><b>EnvironmentCredential</b> — reads AZURE_CLIENT_ID,
///         AZURE_CLIENT_SECRET, AZURE_TENANT_ID. Useful in CI/CD.</item>
///   <item><b>ManagedIdentityCredential</b> — uses the compute resource's
///         system-assigned or user-assigned managed identity. Zero
///         configuration on Azure App Service / AKS / VMs.</item>
///   <item><b>VisualStudioCredential</b> — uses the authenticated Azure
///         account in Visual Studio. For local development.</item>
///   <item><b>AzureCliCredential</b> — uses "az login" credentials.
///         For local development and debugging.</item>
///   <item><b>AzurePowerShellCredential</b> — uses "Connect-AzAccount".
///         For local development.</item>
/// </list>
/// </para>
/// <para>
/// <b>Security:</b> Key Vault secrets are encrypted at rest with Azure's
/// storage encryption (256-bit AES) and can optionally use customer-managed
/// keys in Azure Key Vault itself (double encryption). Network access can
/// be restricted to specific subnets via Private Endpoints.
/// </para>
/// </remarks>
public sealed class AzureKeyVaultService : ISecretManagerService
{
    private readonly SecretClient _client;
    private readonly ILogger<AzureKeyVaultService> _logger;

    // Thread-safe in-memory cache. Key: secret name, Value: (version, value, timestamp).
    // SECURITY: Secrets exist in process memory only. Never persisted to disk.
    private readonly ConcurrentDictionary<string, (string Version, string Json, DateTime CachedAt)> _cache = new();

    private readonly TimeSpan _cacheTtl = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Creates a new Azure Key Vault service.
    /// Bootstraps AZURE_VAULT_URL from environment variables.
    /// Uses DefaultAzureCredential for authentication (Managed Identity in production).
    /// </summary>
    /// <param name="logger">Structured logger. MUST NOT be used to log secret values.</param>
    /// <exception cref="InvalidOperationException">
    /// Thrown when AZURE_VAULT_URL is not set.
    /// </exception>
    public AzureKeyVaultService(ILogger<AzureKeyVaultService> logger)
    {
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // SECURITY: AZURE_VAULT_URL is a configuration value (not a secret).
        // It's the DNS name of your Key Vault (e.g., https://myapp-kv.vault.azure.net/).
        // Safe to log for debugging.
        var vaultUrl = Environment.GetEnvironmentVariable("AZURE_VAULT_URL")
            ?? throw new InvalidOperationException(
                "AZURE_VAULT_URL environment variable is required. " +
                "Example: 'https://myapp-kv.vault.azure.net/'. " +
                "The URL is publicly resolvable — the secrets are protected " +
                "by Azure AD authentication and RBAC, not by network obscurity.");

        // SECURITY: DefaultAzureCredential is the recommended way to authenticate
        // with Azure services. It works seamlessly across:
        //   - Local development (VS, Azure CLI, PowerShell)
        //   - CI/CD (service principal via environment variables)
        //   - Production (Managed Identity — no credentials at all)
        //
        // The credential is NOT a secret — it's a mechanism for obtaining
        // short-lived OAuth2 tokens from Azure AD. Tokens are cached and
        // refreshed automatically before expiry.
        var credential = new DefaultAzureCredential();

        _client = new SecretClient(
            new Uri(vaultUrl),
            credential);

        // SECURITY: Log only the vault URL — never the credential type details
        // or any token information.
        _logger.LogInformation(
            "Azure Key Vault service initialized for {VaultUrl} (auth: DefaultAzureCredential)",
            vaultUrl);
    }

    /// <inheritdoc />
    public async Task<string> GetSecretAsync(string secretName, CancellationToken ct = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(secretName);

        // Check cache first
        var cached = _cache.GetValueOrDefault(secretName);
        if (cached is not null && DateTime.UtcNow - cached.CachedAt < _cacheTtl)
        {
            _logger.LogDebug(
                "Cache hit for secret {SecretName} (version {Version})",
                secretName, cached.Version);
            return cached.Json;
        }

        _logger.LogInformation(
            "Fetching secret {SecretName} from Azure Key Vault", secretName);

        try
        {
            // Fetch the latest version of the secret from Key Vault.
            // The DefaultAzureCredential automatically obtains an OAuth2 token
            // from Azure AD and includes it in the request. This token is
            // never exposed to application code.
            KeyVaultSecret secret = await _client.GetSecretAsync(secretName, cancellationToken: ct);

            var secretValue = secret.Value
                ?? throw new SecretRetrievalException(
                    secretName, "EmptySecret",
                    $"Key Vault secret '{secretName}' exists but has no value.");

            // Cache with version tracking for rotation detection.
            // Key Vault versions are immutable — each version has a unique ID.
            var version = secret.Properties.Version;
            _cache[secretName] = (
                Version: version,
                Json: secretValue,
                CachedAt: DateTime.UtcNow);

            // SECURITY: Log secret name and version — never the value.
            // The version is a Base64 string, not a secret.
            _logger.LogInformation(
                "Successfully fetched secret {SecretName} (version {Version}, " +
                "created: {CreatedOn}, expires: {ExpiresOn})",
                secretName,
                version,
                secret.Properties.CreatedOn,
                secret.Properties.ExpiresOn);

            return secretValue;
        }
        catch (RequestFailedException ex) when (ex.Status == 404)
        {
            _logger.LogError(
                "Secret {SecretName} not found in Azure Key Vault", secretName);
            throw new SecretRetrievalException(
                secretName, "NotFound",
                $"Secret '{secretName}' does not exist in Key Vault or you lack RBAC permission.");
        }
        catch (RequestFailedException ex) when (ex.Status == 403)
        {
            // SECURITY: Do not log the managed identity object ID,
            // tenant ID, or any auth details.
            _logger.LogError(
                "Access denied (403) when fetching secret {SecretName}. " +
                "Verify the managed identity or service principal has " +
                "'Key Vault Secrets User' RBAC role on this vault.",
                secretName);
            throw new SecretRetrievalException(
                secretName, "AccessDenied",
                $"Access denied for secret '{secretName}'. Check Key Vault RBAC assignments.");
        }
        catch (Exception ex) when (ex is not SecretRetrievalException)
        {
            _logger.LogError(ex,
                "Unexpected error fetching secret {SecretName} from Key Vault",
                secretName);
            throw new SecretRetrievalException(
                secretName, "Unknown",
                $"Failed to retrieve secret '{secretName}' from Key Vault.",
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
        // Remove from cache to force a fresh fetch.
        _cache.TryRemove(secretName, out var old);

        // SECURITY: Log version info only — never secret values.
        _logger.LogInformation(
            "Secret {SecretName} cache cleared for refresh " +
            "(previous version: {OldVersion})",
            secretName, old?.Version ?? "none");

        // Pre-warm the cache with the latest version.
        await GetSecretAsync(secretName, ct);
    }

    /// <summary>
    /// Deserializes JSON from Key Vault into a strongly-typed object.
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
                "Failed to deserialize Key Vault secret {SecretName} as {TypeName}",
                secretName, typeof(T).Name);
            throw new SecretRetrievalException(
                secretName, "DeserializationError",
                $"Key Vault secret '{secretName}' could not be deserialized as {typeof(T).Name}.",
                ex);
        }
    }

    private static readonly JsonSerializerOptions _jsonOptions = new()
    {
        PropertyNameCaseInsensitive = true
    };
}