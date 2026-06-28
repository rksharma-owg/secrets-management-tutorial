// -----------------------------------------------------------------------------
// JwtConfig.cs
//
// SECURITY PURPOSE: Strongly-typed JWT configuration retrieved from the secrets
// manager. The signing key is the most sensitive value in this record — it can
// be used to forge authentication tokens.
//
// The SecretKey property is decorated with [JsonIgnore] as a defense-in-depth
// measure. If this object is accidentally serialized in an API response, log,
// or diagnostic dump, the signing key will be omitted.
// -----------------------------------------------------------------------------

using System.Text.Json.Serialization;

namespace SecretsTutorial.Models;

/// <summary>
/// JWT signing configuration retrieved from the secrets manager.
/// Contains the signing key and token validation parameters.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security:</b> The signing key determines the trust boundary for all
/// JWTs issued by this application. If an attacker obtains the key, they can
/// forge tokens and impersonate any user. This is why the key MUST come from
/// a secrets manager — never from appsettings.json, environment variables
/// in docker-compose, or source code.
/// </para>
/// </remarks>
public sealed record JwtConfig
{
    /// <summary>
    /// HMAC signing key. MUST be at least 256 bits (32 bytes) for HS256.
    /// </summary>
    /// <remarks>
    /// <b>Security:</b> This value is NEVER logged, serialized, or exposed.
    /// Use <c>KeyFingerprint</c> for log correlation (a SHA-256 prefix).
    /// </remarks>
    [JsonIgnore]
    public required string SecretKey { get; init; }

    /// <summary>
    /// JWT signing algorithm. Defaults to "HS256".
    /// </summary>
    /// <remarks>
    /// <b>Security:</b> Always specify the algorithm explicitly to prevent
    /// algorithm confusion attacks (e.g., switching from RS256 to "none").
    /// </remarks>
    public string Algorithm { get; init; } = "HS256";

    /// <summary>Token issuer claim (iss). Should match your application's public URL.</summary>
    public required string Issuer { get; init; }

    /// <summary>Expected audience claim (aud).</summary>
    public required string Audience { get; init; }

    /// <summary>Access token expiry in minutes. Defaults to 15.</summary>
    public int ExpiryMinutes { get; init; } = 15;

    /// <summary>
    /// Computes a short fingerprint of the signing key for log correlation.
    /// This is safe to log because it is a one-way hash — the key cannot be
    /// recovered from the fingerprint.
    /// </summary>
    /// <returns>
    /// A string like "a3f2..." (first 4 hex characters of SHA-256 of the key).
    /// </returns>
    public string KeyFingerprint()
    {
        var hash = System.Security.Cryptography.SHA256.HashData(
            System.Text.Encoding.UTF8.GetBytes(SecretKey));
        return Convert.ToHexString(hash)[..4].ToLowerInvariant();
    }

    /// <summary>
    /// Validates that the signing key meets the minimum length requirement
    /// for the configured algorithm. Throws if the key is too short.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// Thrown when the key is shorter than the algorithm requires.
    /// </exception>
    /// <remarks>
    /// <para><b>HS256:</b> Minimum 32 bytes (256 bits).</para>
    /// <para><b>HS384:</b> Minimum 48 bytes (384 bits).</para>
    /// <para><b>HS512:</b> Minimum 64 bytes (512 bits).</para>
    /// </remarks>
    public void Validate()
    {
        var keyBytes = System.Text.Encoding.UTF8.GetBytes(SecretKey);
        var minLength = Algorithm.ToUpperInvariant() switch
        {
            "HS256" => 32,
            "HS384" => 48,
            "HS512" => 64,
            _ => 32 // Default to the most restrictive requirement
        };

        if (keyBytes.Length < minLength)
        {
            // SECURITY: Do NOT log the actual key length or the key value.
            // An attacker can use key length information to narrow brute-force
            // searches. We only log the algorithm and the required minimum.
            throw new InvalidOperationException(
                $"JWT signing key for algorithm '{Algorithm}' must be at least " +
                $"{minLength} bytes ({minLength * 8} bits). " +
                "Rotate the secret in your secrets manager to use a longer key.");
        }
    }
}