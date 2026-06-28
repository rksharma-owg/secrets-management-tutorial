// -----------------------------------------------------------------------------
// ISecretManagerService.cs
//
// SECURITY PURPOSE: Defines the contract for retrieving secrets from any backend
// (AWS Secrets Manager, HashiCorp Vault, Azure Key Vault). Application code
// depends only on this interface — never on a concrete provider.
//
// WHY INTERFACE ABSTRACTION MATTERS:
//   1. Vendor Independence — Switch from AWS to Vault to Azure by changing DI
//      registration in Program.cs. No application code changes needed.
//   2. Testability — In unit tests, inject a mock that returns deterministic
//      values without connecting to any real secret store.
//   3. Security Boundary — The interface defines the minimal surface area.
//      Implementations handle provider-specific auth, caching, and rotation.
//      Application code only calls Get*Async methods and gets typed objects.
//   4. Auditability — All secret access flows through known methods, making
//      it easy to add logging, metrics, or access controls in one place.
//
// DESIGN DECISIONS:
//   - Typed getters (GetDatabaseCredentialsAsync, GetJwtConfigAsync) reduce
//     deserialization errors and provide compile-time safety.
//   - CancellationToken support enables graceful shutdown during secret fetches.
//   - RefreshSecretAsync supports explicit rotation triggers from the controller.
// -----------------------------------------------------------------------------

namespace SecretsTutorial.Services;

using SecretsTutorial.Models;

/// <summary>
/// Abstraction over a secrets management backend. Implementations retrieve
/// secrets from AWS Secrets Manager, HashiCorp Vault, or Azure Key Vault.
/// </summary>
/// <remarks>
/// <para>
/// All implementations MUST:
/// <list type="bullet">
///   <item>Never log secret values — only log secret names and status.</item>
///   <item>Throw <see cref="SecretRetrievalException"/> on failure with a
///         sanitized message (no credential details in the exception).</item>
///   <item>Support cancellation via <see cref="CancellationToken"/>.</item>
///   <item>Cache secrets in memory with a configurable TTL to reduce API calls.</item>
/// </list>
/// </para>
/// </remarks>
public interface ISecretManagerService
{
    /// <summary>
    /// Retrieves a raw secret string by name from the configured secret store.
    /// </summary>
    /// <param name="secretName">
    /// The name or path of the secret in the backend.
    /// Examples: "myapp/db-credentials", "myapp/jwt-config".
    /// </param>
    /// <param name="ct">Token to cancel the asynchronous operation.</param>
    /// <returns>The secret value as a string.</returns>
    /// <exception cref="SecretRetrievalException">
    /// Thrown when the secret cannot be retrieved (not found, access denied,
    /// network error, etc.). The exception message is sanitized for safety.
    /// </exception>
    /// <remarks>
    /// <para>
    /// <b>Security:</b> Callers must ensure the returned value is never logged,
    /// serialized to API responses, or written to disk. Always use the typed
    /// getters when possible — they return objects with [JsonIgnore] on
    /// sensitive properties.
    /// </para>
    /// </remarks>
    Task<string> GetSecretAsync(string secretName, CancellationToken ct = default);

    /// <summary>
    /// Retrieves database credentials as a strongly-typed
    /// <see cref="DatabaseCredentials"/> object.
    /// </summary>
    /// <param name="secretName">
    /// The secret name containing a JSON object with database connection fields
    /// (Username, Password, Host, Port, DatabaseName).
    /// </param>
    /// <param name="ct">Token to cancel the asynchronous operation.</param>
    /// <returns>
    /// A <see cref="DatabaseCredentials"/> instance. The Password property is
    /// marked [JsonIgnore] to prevent accidental exposure in API responses.
    /// </returns>
    /// <exception cref="SecretRetrievalException">On retrieval failure.</exception>
    Task<DatabaseCredentials> GetDatabaseCredentialsAsync(
        string secretName, CancellationToken ct = default);

    /// <summary>
    /// Retrieves JWT configuration as a strongly-typed <see cref="JwtConfig"/> object.
    /// </summary>
    /// <param name="secretName">
    /// The secret name containing a JSON object with JWT signing configuration
    /// (SecretKey, Algorithm, Issuer, Audience, ExpiryMinutes).
    /// </param>
    /// <param name="ct">Token to cancel the asynchronous operation.</param>
    /// <returns>
    /// A <see cref="JwtConfig"/> instance. The SecretKey property is marked
    /// [JsonIgnore] to prevent accidental exposure.
    /// </returns>
    /// <exception cref="SecretRetrievalException">On retrieval failure.</exception>
    /// <remarks>
    /// <para>
    /// <b>Security:</b> The returned JwtConfig validates that the key length
    /// meets the minimum requirement for the specified algorithm (e.g., 256 bits
    /// for HS256). An invalid key throws during validation, not at signing time.
    /// </para>
    /// </remarks>
    Task<JwtConfig> GetJwtConfigAsync(
        string secretName, CancellationToken ct = default);

    /// <summary>
    /// Retrieves OpenAI API configuration as a strongly-typed
    /// <see cref="OpenAIConfig"/> object.
    /// </summary>
    /// <param name="secretName">
    /// The secret name containing a JSON object with OpenAI configuration
    /// (ApiKey, Model, Organization, MaxTokens).
    /// </param>
    /// <param name="ct">Token to cancel the asynchronous operation.</param>
    /// <returns>
    /// An <see cref="OpenAIConfig"/> instance. The ApiKey property is marked
    /// [JsonIgnore] to prevent accidental exposure.
    /// </returns>
    /// <exception cref="SecretRetrievalException">On retrieval failure.</exception>
    Task<OpenAIConfig> GetOpenAIConfigAsync(
        string secretName, CancellationToken ct = default);

    /// <summary>
    /// Forces a refresh of a cached secret, picking up the latest version
    /// from the backend. Used to support hot rotation without application restart.
    /// </summary>
    /// <param name="secretName">The name of the secret to refresh.</param>
    /// <param name="ct">Token to cancel the asynchronous operation.</param>
    /// <remarks>
    /// <para>
    /// <b>Rotation workflow:</b> When a secret is rotated in the backend
    /// (e.g., AWS automatic rotation, Vault dynamic secret renewal), call this
    /// method to fetch the new version. The implementation should:
    /// <list type="number">
    ///   <item>Fetch the latest version from the backend.</item>
    ///   <item>Update the in-memory cache.</item>
    ///   <item>Optionally drain and recreate connection pools.</item>
    /// </list>
    /// </para>
    /// <para>
    /// <b>Security:</b> Rotation events should be logged (secret name, timestamp,
    /// success/failure) but NEVER the old or new secret values.
    /// </para>
    /// </remarks>
    Task RefreshSecretAsync(string secretName, CancellationToken ct = default);
}

/// <summary>
/// Custom exception thrown when a secret cannot be retrieved from the backend.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security:</b> This exception intentionally carries ONLY the secret name
/// and a sanitized error category — never the secret value, auth tokens, or
/// stack traces from the underlying SDK. This prevents credential leakage
/// through error logs, API error responses, or crash dumps.
/// </para>
/// </remarks>
public class SecretRetrievalException : Exception
{
    /// <summary>The name of the secret that could not be retrieved.</summary>
    public string SecretName { get; }

    /// <summary>Category of the failure (e.g., "NotFound", "AccessDenied", "Timeout").</summary>
    public string ErrorCategory { get; }

    public SecretRetrievalException(string secretName, string errorCategory, string message)
        : base(message)
    {
        SecretName = secretName;
        ErrorCategory = errorCategory;
    }

    public SecretRetrievalException(string secretName, string errorCategory, string message, Exception inner)
        : base(message, inner)
    {
        SecretName = secretName;
        ErrorCategory = errorCategory;
    }
}