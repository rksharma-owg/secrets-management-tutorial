// -----------------------------------------------------------------------------
// SecretsController.cs
//
// SECURITY PURPOSE: This controller demonstrates the correct pattern for using
// secrets in ASP.NET Core API endpoints. Key security principles:
//
//   1. NEVER return secret values in API responses.
//      All responses use sanitized DTOs — even if a model with [JsonIgnore]
//      is accidentally returned, the secret properties are stripped.
//
//   2. Health endpoints MUST NOT depend on secret managers.
//      A /health endpoint that calls the secret manager creates a circular
//      dependency: the health check itself can fail if the secret manager
//      is down, making it impossible to monitor the application.
//
//   3. Error responses MUST be generic in production.
//      Never expose internal errors, secret names, or provider details
//      to API consumers. Use ProblemDetails with sanitized messages.
//
//   4. Database test endpoints MUST use sanitized responses.
//      The response confirms connectivity but never returns query results
//      or connection string details.
// -----------------------------------------------------------------------------

using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Data.SqlClient;
using SecretsTutorial.Models;
using SecretsTutorial.Services;

namespace SecretsTutorial.Controllers;

/// <summary>
/// API controller demonstrating secure secret usage patterns.
/// All endpoints return sanitized DTOs — secret values are NEVER included.
/// </summary>
[ApiController]
[Produces("application/json")]
[Route("api")]
public sealed class SecretsController : ControllerBase
{
    private readonly ISecretManagerService _secrets;
    private readonly ILogger<SecretsController> _logger;

    // Secret names are configurable via environment variables with safe defaults.
    private readonly string _dbSecretName;
    private readonly string _jwtSecretName;
    private readonly string _openAiSecretName;

    public SecretsController(
        ISecretManagerService secrets,
        ILogger<SecretsController> logger)
    {
        _secrets = secrets ?? throw new ArgumentNullException(nameof(secrets));
        _logger = logger ?? throw new ArgumentNullException(nameof(logger));

        // Read secret names from environment. These are NOT secrets —
        // they are the names/paths used to look up secrets in the vault.
        _dbSecretName = Environment.GetEnvironmentVariable("SECRET_NAME_DB") ?? "myapp/database";
        _jwtSecretName = Environment.GetEnvironmentVariable("SECRET_NAME_JWT") ?? "myapp/jwt-config";
        _openAiSecretName = Environment.GetEnvironmentVariable("SECRET_NAME_OPENAI") ?? "myapp/openai-config";
    }

    /// <summary>
    /// Health check endpoint — NO secrets involved.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Security:</b> This endpoint intentionally does NOT call the secret
    /// manager. Health checks must be independently verifiable — if the secret
    /// manager is down, the health check should still return 200 so that
    /// load balancers and orchestrators can detect the secret manager failure
    /// as a separate issue.
    /// </para>
    /// <para>
    /// <b>Information leakage:</b> This endpoint returns the MINIMUM information
    /// needed for a health check. No internal state, no configuration, no
    /// secret manager status, no version numbers.
    /// </para>
    /// </remarks>
    [HttpGet("health")]
    public IActionResult Health()
    {
        return Ok(new { status = "healthy", timestamp = DateTime.UtcNow });
    }

    /// <summary>
    /// Returns non-sensitive configuration information only.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Security:</b> This endpoint returns ONLY the provider name and the
    /// names of the secrets configured. No secret values, no vault URLs,
    /// no authentication details. This is safe to expose to authenticated
    /// users for debugging "which secrets are configured?" questions.
    /// </para>
    /// </remarks>
    [HttpGet("config")]
    public async Task<IActionResult> GetConfig(CancellationToken ct)
    {
        try
        {
            // Fetch JWT config to extract non-sensitive fields (issuer, audience, algorithm).
            // SECURITY: The SecretKey is [JsonIgnore] so even if we accidentally
            // return the full object, the key is stripped.
            var jwtConfig = await _secrets.GetJwtConfigAsync(_jwtSecretName, ct);

            return Ok(new
            {
                secretProvider = _secrets.GetType().Name,
                configuredSecrets = new[]
                {
                    new { name = _dbSecretName, purpose = "database-credentials" },
                    new { name = _jwtSecretName, purpose = "jwt-configuration" },
                    new { name = _openAiSecretName, purpose = "openai-configuration" }
                },
                // Non-sensitive JWT settings — these are public configuration, not secrets.
                jwtIssuer = jwtConfig.Issuer,
                jwtAudience = jwtConfig.Audience,
                jwtAlgorithm = jwtConfig.Algorithm,
                jwtExpiryMinutes = jwtConfig.ExpiryMinutes,
                // SECURITY: Safe to log — this is a one-way hash prefix.
                jwtKeyFingerprint = jwtConfig.KeyFingerprint()
            });
        }
        catch (SecretRetrievalException ex)
        {
            // SECURITY: Return generic error. Don't expose secret names or error details.
            _logger.LogWarning(ex, "Failed to load configuration for /api/config");
            return StatusCode((int)HttpStatusCode.ServiceUnavailable, new
            {
                error = "Configuration not available",
                message = "One or more secrets could not be retrieved. Check application logs."
            });
        }
    }

    /// <summary>
    /// Triggers a secret refresh (cache invalidation + re-fetch).
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Security:</b> This endpoint should be protected by authentication
    /// and authorization in production. Only operators should be able to
    /// trigger secret refreshes.
    /// </para>
    /// <para>
    /// <b>Use case:</b> After a secret is rotated in the backend, call this
    /// endpoint to pick up the new version without restarting the application.
    /// </para>
    /// </remarks>
    [HttpPost("secrets/refresh")]
    public async Task<IActionResult> RefreshSecret(
        [FromBody] RefreshRequest? request,
        CancellationToken ct)
    {
        var secretName = request?.SecretName ?? _dbSecretName;

        _logger.LogInformation(
            "Secret refresh requested for {SecretName} by user",
            secretName);

        try
        {
            await _secrets.RefreshSecretAsync(secretName, ct);

            return Ok(new
            {
                status = "refreshed",
                secretName,
                // SECURITY: Only return the name and status. No values.
                message = $"Secret '{secretName}' cache invalidated and re-fetched."
            });
        }
        catch (SecretRetrievalException ex)
        {
            _logger.LogError(ex, "Secret refresh failed for {SecretName}", secretName);

            // SECURITY: Generic error — don't leak whether the secret exists
            // or what the specific error was.
            return StatusCode((int)HttpStatusCode.InternalServerError, new
            {
                error = "Refresh failed",
                message = "Unable to refresh the secret. Check application logs."
            });
        }
    }

    /// <summary>
    /// Tests database connectivity using credentials from the secret manager.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Security:</b> The response confirms connectivity but NEVER returns:
    /// <list type="bullet">
    ///   <item>The connection string</item>
    ///   <item>The database credentials</item>
    ///   <item>Query results (even from SELECT 1)</item>
    ///   <item>The database server hostname or port</item>
    /// </list>
    /// </para>
    /// </remarks>
    [HttpPost("db/test")]
    public async Task<IActionResult> TestDatabase(CancellationToken ct)
    {
        try
        {
            var creds = await _secrets.GetDatabaseCredentialsAsync(_dbSecretName, ct);

            // SECURITY: GetConnectionString() contains the password.
            // We pass it directly to SqlClient — it never touches logs or responses.
            var connectionString = creds.GetConnectionString();

            await using var connection = new SqlConnection(connectionString);
            await connection.OpenAsync(ct);

            // Run a minimal health query. We don't return the result.
            var result = await connection.ExecuteScalarAsync<int>("SELECT 1", cancellationToken: ct);

            // SECURITY: Response contains NO database details.
            return Ok(new
            {
                status = "connected",
                database = creds.DatabaseName, // Database name is not a secret
                message = "Database connection test successful."
            });
        }
        catch (SecretRetrievalException ex)
        {
            _logger.LogError(ex, "Failed to retrieve database credentials");
            return StatusCode((int)HttpStatusCode.ServiceUnavailable, new
            {
                error = "Database test failed",
                message = "Could not retrieve database credentials."
            });
        }
        catch (SqlException ex)
        {
            // SECURITY: Don't expose SQL error details (they can reveal
            // database structure, hostname, or authentication details).
            _logger.LogError(ex, "Database connectivity test failed");
            return StatusCode((int)HttpStatusCode.ServiceUnavailable, new
            {
                error = "Database test failed",
                message = "Could not connect to the database."
            });
        }
    }

    /// <summary>
    /// Simulated OpenAI chat endpoint using secrets from the secret manager.
    /// </summary>
    /// <remarks>
    /// <para>
    /// <b>Security:</b> The API key is retrieved from the secret manager and
    /// used ONLY in the HTTP request to OpenAI. It is never logged (we use
    /// the safe ApiKeyPrefix() method for debug logging) and never returned
    /// in the response.
    /// </para>
    /// </remarks>
    [HttpPost("ai/chat")]
    public async Task<IActionResult> Chat(
        [FromBody] ChatRequest? request,
        CancellationToken ct)
    {
        var userMessage = request?.Message;
        if (string.IsNullOrWhiteSpace(userMessage))
        {
            return BadRequest(new { error = "Message is required." });
        }

        try
        {
            var config = await _secrets.GetOpenAIConfigAsync(_openAiSecretName, ct);

            // SECURITY: Log only the API key prefix for debugging.
            _logger.LogInformation(
                "Processing chat request with OpenAI model {Model} (key: {KeyPrefix})",
                config.Model, config.ApiKeyPrefix());

            // In a real implementation, you would call:
            //   var httpClient = new HttpClient();
            //   httpClient.DefaultRequestHeaders.Authorization =
            //       new AuthenticationHeaderValue("Bearer", config.ApiKey);
            //   // ... POST to https://api.openai.com/v1/chat/completions

            // Simulated response for the tutorial.
            return Ok(new
            {
                model = config.Model,
                message = $"[Simulated] Response to: '{userMessage}'",
                // SECURITY: No API key, no organization details.
                provider = "openai"
            });
        }
        catch (SecretRetrievalException ex)
        {
            _logger.LogError(ex, "Failed to retrieve OpenAI configuration");
            return StatusCode((int)HttpStatusCode.ServiceUnavailable, new
            {
                error = "Chat unavailable",
                message = "Could not retrieve API configuration."
            });
        }
    }
}

// -----------------------------------------------------------------------------
// Request DTOs — these are safe to serialize/deserialize and contain NO secrets.
// -----------------------------------------------------------------------------

/// <summary>Request body for the refresh endpoint.</summary>
public sealed record RefreshRequest(string? SecretName);

/// <summary>Request body for the chat endpoint.</summary>
public sealed record ChatRequest(string Message);