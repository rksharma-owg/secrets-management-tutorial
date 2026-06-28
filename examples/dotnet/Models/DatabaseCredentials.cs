// -----------------------------------------------------------------------------
// DatabaseCredentials.cs
//
// SECURITY PURPOSE: Strongly-typed container for database credentials retrieved
// from a secrets manager. This record is NEVER constructed with hardcoded values
// — it is always deserialized from a secret store response.
//
// CRITICAL: The Password property is decorated with [JsonIgnore] so that if this
// object is accidentally returned in an API response, logged via JSON
// serialization, or written to a diagnostic dump, the password is omitted.
// This is a defense-in-depth measure — controllers should use DTOs, but
// [JsonIgnore] protects against accidental exposure through framework features
// like ProblemDetails, Swagger examples, or middleware serialization.
// -----------------------------------------------------------------------------

using System.Text.Json.Serialization;

namespace SecretsTutorial.Models;

/// <summary>
/// Strongly-typed database credentials retrieved from the secrets manager.
/// Contains all fields needed to build a SQL Server connection string.
/// </summary>
/// <remarks>
/// <para>
/// <b>Security:</b> This type is designed so that the password can ONLY reach
/// the database driver. The [JsonIgnore] attribute on Password prevents
/// serialization in any direction (API responses, logs, config dumps).
/// The GetConnectionString() method is the ONLY approved way to use these
/// credentials — it builds a connection string consumed directly by
/// <c>Microsoft.Data.SqlClient</c>.
/// </para>
/// <para>
/// <b>Why not ConnectionString directly?</b> Storing a full connection string
/// as a single secret makes rotation harder (you must rotate the entire string)
/// and makes it harder to audit which part changed. Storing individual fields
//  allows partial rotation and better monitoring.
/// </para>
/// </remarks>
public sealed record DatabaseCredentials
{
    /// <summary>Database username for SQL authentication.</summary>
    public required string Username { get; init; }

    /// <summary>
    /// Database password for SQL authentication.
    /// NEVER log, serialize, or expose this value.
    /// </summary>
    [JsonIgnore]
    public required string Password { get; init; }

    /// <summary>Database server hostname or IP address.</summary>
    public required string Host { get; init; }

    /// <summary>Database server TCP port. Defaults to 1433 (SQL Server default).</summary>
    public int Port { get; init; } = 1433;

    /// <summary>Logical database name within the SQL Server instance.</summary>
    public required string DatabaseName { get; init; }

    /// <summary>
    /// Builds a SQL Server connection string from these credentials.
    /// </summary>
    /// <returns>
    /// A connection string suitable for <c>Microsoft.Data.SqlClient.SqlConnection</c>.
    /// </returns>
    /// <remarks>
    /// <para>
    /// <b>Security considerations in the connection string:</b>
    /// <list type="bullet">
    ///   <item><c>Encrypt=True</c> — forces TLS encryption of all data in transit,
    ///         including the password during authentication.</item>
    ///   <item><c>TrustServerCertificate=False</c> — prevents MITM attacks by
    ///         requiring the server to present a trusted TLS certificate.</item>
    ///   <item><c>Connection Timeout=10</c> — fails fast if the DB is unreachable,
    ///         preventing hanging requests that could be exploited for DoS.</item>
    /// </list>
    /// </para>
    /// <para>
    /// <b>WARNING:</b> The returned string contains the password. It must be
    /// passed ONLY to the database driver and NEVER logged.
    /// </para>
    /// </remarks>
    public string GetConnectionString()
    {
        return $"Server={Host},{Port};" +
               $"Database={DatabaseName};" +
               $"User Id={Username};" +
               $"Password={Password};" +
               "Encrypt=True;" +
               "TrustServerCertificate=False;" +
               "Connection Timeout=10;" +
               "MultipleActiveResultSets=False;";
    }
}