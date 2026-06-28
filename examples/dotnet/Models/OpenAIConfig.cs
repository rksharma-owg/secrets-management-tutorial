// -----------------------------------------------------------------------------
// OpenAIConfig.cs
//
// SECURITY PURPOSE: Strongly-typed OpenAI API configuration. The API key is
// the primary secret — it grants access to the OpenAI API on your account
// and can incur costs if leaked.
//
// The ApiKey property uses [JsonIgnore] to prevent accidental exposure
// through API responses, Swagger documentation, or diagnostic serialization.
// -----------------------------------------------------------------------------

using System.Text.Json.Serialization;

namespace SecretsTutorial.Models;

/// <summary>
/// OpenAI API configuration retrieved from the secrets manager.
/// Contains the API key and model selection parameters.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security:</b> OpenAI API keys are scoped to your organization's billing.
/// A leaked key allows attackers to make API calls at your expense, potentially
/// running up significant costs. Always store API keys in a secrets manager
/// with regular rotation and usage monitoring.
/// </para>
/// </remarks>
public sealed record OpenAIConfig
{
    /// <summary>
    /// OpenAI API key (starts with "sk-...").
    /// </summary>
    /// <remarks>
    /// <b>Security:</b> NEVER log this value. For debug logging, use the
    /// <c>ApiKeyPrefix</c> property which returns only the first few characters.
    /// </remarks>
    [JsonIgnore]
    public required string ApiKey { get; init; }

    /// <summary>OpenAI model identifier (e.g., "gpt-4", "gpt-3.5-turbo").</summary>
    public string Model { get; init; } = "gpt-4";

    /// <summary>
    /// OpenAI organization ID for organizations with multiple workspaces.
    /// </summary>
    public string? Organization { get; init; }

    /// <summary>Maximum tokens for completion responses. Defaults to 2048.</summary>
    public int MaxTokens { get; init; } = 2048;

    /// <summary>
    /// Returns a safe-to-log prefix of the API key (e.g., "sk-proj...a1b2").
    /// Only the first 7 and last 4 characters are shown — enough for
    /// debugging (which key is being used) but not enough to be useful to
    /// an attacker.
    /// </summary>
    public string ApiKeyPrefix()
    {
        if (ApiKey.Length <= 11) return "***REDACTED***";
        return $"{ApiKey[..7]}...{ApiKey[^4..]}";
    }
}