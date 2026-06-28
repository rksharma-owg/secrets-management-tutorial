// -----------------------------------------------------------------------------
// Program.cs
//
// SECURITY PURPOSE: This is the application entry point. It wires up:
//   1. Secret provider selection via environment variable (SECRET_PROVIDER)
//   2. Dependency injection for ISecretManagerService (the concrete impl
//      depends on SECRET_PROVIDER — application code never knows)
//   3. Startup validation (fail-fast if required secrets are missing)
//   4. Security headers middleware
//   5. Swagger with redacted example values
//
// WHY FAIL-FAST AT STARTUP:
//   If a required secret is missing, the application should refuse to start
//   rather than running in a degraded state. This prevents:
//     - Requests failing at runtime with confusing errors
//     - Security incidents where a missing secret causes fallback to
//       insecure defaults
//     - Alerting gaps where the app appears healthy but can't function
// -----------------------------------------------------------------------------

using Microsoft.AspNetCore.Diagnostics;
using Microsoft.OpenApi.Models;
using SecretsTutorial.Configuration;
using SecretsTutorial.Services;

var builder = WebApplication.CreateBuilder(args);

// ---------------------------------------------------------------------------
// Configuration: Read SECRET_PROVIDER from environment and register the
// appropriate secret manager implementation.
//
// SECURITY: SECRET_PROVIDER is a configuration value (not a secret). It tells
// the application which vault to use but does not grant access to any vault.
// ---------------------------------------------------------------------------
var secretProvider = Environment.GetEnvironmentVariable("SECRET_PROVIDER")
    ?? throw new InvalidOperationException(
        "SECRET_PROVIDER environment variable is not set. " +
        "Supported values: aws, vault, azure. " +
        "This single variable determines which secrets backend is used.");

// Register the appropriate ISecretManagerService implementation based on
// SECRET_PROVIDER. Application code depends only on the interface — changing
// the provider requires zero code changes, only the env var.
switch (secretProvider.Trim().ToLowerInvariant())
{
    case "aws":
        builder.Services.AddSingleton<ISecretManagerService, AwsSecretsManagerService>();
        break;
    case "vault":
        builder.Services.AddSingleton<ISecretManagerService, VaultSecretsService>();
        break;
    case "azure":
        builder.Services.AddSingleton<ISecretManagerService, AzureKeyVaultService>();
        break;
    default:
        throw new InvalidOperationException(
            $"Unsupported SECRET_PROVIDER: '{secretProvider}'. " +
            "Supported values: aws, vault, azure.");
}

// ---------------------------------------------------------------------------
// ASP.NET Core services
// ---------------------------------------------------------------------------
builder.Services.AddControllers();

// Add Swagger with security-conscious configuration.
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new()
    {
        Title = "Secrets Management Tutorial API",
        Version = "v1",
        Description = "Demonstrates secure secret retrieval from AWS, Vault, or Azure."
    });

    // SECURITY: Filter out schemas that contain [JsonIgnore] properties from
    // Swagger output. We don't want DatabaseCredentials, JwtConfig, or
    // OpenAIConfig appearing in the schema at all — their response DTOs
    // should be the only thing documented.
    c.DocumentFilter<RedactSecretSchemasFilter>();
});

// ---------------------------------------------------------------------------
// Security headers middleware
//
// SECURITY: These headers protect against common web vulnerabilities:
//   - X-Content-Type-Options: nosniff → prevents MIME type sniffing
//   - X-Frame-Options: DENY → prevents clickjacking
//   - X-XSS-Protection: 0 → disables buggy XSS filter (modern browsers
//     use CSP instead; the XSS filter can actually introduce vulnerabilities)
//   - Referrer-Policy: strict-origin-when-cross-origin → limits referrer leakage
//   - Content-Security-Policy: restricts resource loading
//   - Cache-Control: no-store → prevents caching of API responses
//     (which might contain sensitive data)
// ---------------------------------------------------------------------------
var app = builder.Build();

app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    context.Response.Headers["X-XSS-Protection"] = "0";
    context.Response.Headers["Referrer-Policy"] = "strict-origin-when-cross-origin";
    context.Response.Headers["Content-Security-Policy"] =
        "default-src 'none'; frame-ancestors 'none'";
    context.Response.Headers["Cache-Control"] = "no-store, no-cache, must-revalidate";

    await next();
});

// ---------------------------------------------------------------------------
// Startup validation: Fetch all required secrets at startup to fail-fast.
//
// SECURITY: If any required secret is missing, the app REFUSES TO START.
// This is better than running with missing secrets because:
//   1. Load balancers and orchestrators see the crash and can alert.
//   2. The app doesn't serve requests that might fail unpredictably.
//   3. There's no risk of "falling back" to insecure defaults.
// ---------------------------------------------------------------------------
using (var scope = app.Services.CreateScope())
{
    var secrets = scope.ServiceProvider.GetRequiredService<ISecretManagerService>();
    var logger = scope.ServiceProvider.GetRequiredService<ILogger<Program>>();

    var dbSecret = Environment.GetEnvironmentVariable("SECRET_NAME_DB") ?? "myapp/database";
    var jwtSecret = Environment.GetEnvironmentVariable("SECRET_NAME_JWT") ?? "myapp/jwt-config";

    logger.LogInformation(
        "Validating required secrets at startup (provider: {Provider})...",
        secretProvider);

    try
    {
        // Validate database credentials are available
        var dbCreds = await secrets.GetDatabaseCredentialsAsync(dbSecret);
        logger.LogInformation(
            "Database secret validated: {Database}@{Host}:{Port}",
            dbCreds.DatabaseName, dbCreds.Host, dbCreds.Port);

        // Validate JWT config is available and the key is strong enough
        var jwtConfig = await secrets.GetJwtConfigAsync(jwtSecret);
        logger.LogInformation(
            "JWT config validated: issuer={Issuer}, algorithm={Algorithm}, key={KeyFingerprint}...",
            jwtConfig.Issuer, jwtConfig.Algorithm, jwtConfig.KeyFingerprint());

        logger.LogInformation("All required secrets validated successfully.");
    }
    catch (SecretRetrievalException ex)
    {
        // SECURITY: Log the error category and secret name (not values).
        logger.LogCritical(ex,
            "STARTUP FAILED: Could not retrieve secret '{SecretName}' ({Category}). " +
            "The application will not start until the secret is available.",
            ex.SecretName, ex.ErrorCategory);

        // Exit with a non-zero code so the container orchestrator marks
        // the pod/container as unhealthy and can restart or alert.
        Environment.Exit(1);
        return; // Unreachable, but satisfies the compiler.
    }
}

// ---------------------------------------------------------------------------
// Pipeline configuration
// ---------------------------------------------------------------------------
if (app.Environment.IsDevelopment())
{
    // Swagger only in development. Never expose API documentation in production
    // — it helps attackers understand your API surface.
    app.UseSwagger();
    app.UseSwaggerUI();
}

// Global exception handler: prevent secrets/stack traces in error responses.
app.UseExceptionHandler(errApp =>
{
    errApp.Run(async context =>
    {
        var exceptionHandlerFeature = context.Features.Get<IExceptionHandlerFeature>();
        var logger = context.RequestServices.GetRequiredService<ILogger<Program>>();

        // SECURITY: Log the full exception internally (with structured logging),
        // but return a generic error to the client. Never expose stack traces,
        // secret names, or internal details in API responses.
        logger.LogError(exceptionHandlerFeature?.Error,
            "Unhandled exception on {Method} {Path}",
            context.Request.Method, context.Request.Path);

        context.Response.StatusCode = 500;
        context.Response.ContentType = "application/json";
        await context.Response.WriteAsJsonAsync(new
        {
            error = "Internal server error",
            traceId = System.Diagnostics.Activity.Current?.Id
                ?? context.TraceIdentifier
        });
    });
});

app.MapControllers();

// ---------------------------------------------------------------------------
// Start the application
// ---------------------------------------------------------------------------
app.Run();

// -----------------------------------------------------------------------------
// Swagger schema filter — removes secret-bearing model types from the
// OpenAPI document to prevent their structure from being documented.
// SECURITY: Even property names like "Password" or "SecretKey" leak
// information about your secret structure. Removing the entire schema
// is safer than trying to redact individual properties.
// -----------------------------------------------------------------------------

public sealed class RedactSecretSchemasFilter : Swashbuckle.AspNetCore.Swagger.IDocumentFilter
{
    private static readonly HashSet<string> SecretSchemaNames =
    [
        "DatabaseCredentials",
        "JwtConfig",
        "OpenAIConfig"
    ];

    public void Apply(OpenApiDocument swaggerDoc, DocumentFilterContext context)
    {
        foreach (var schemaName in SecretSchemaNames)
        {
            swaggerDoc.Components.Schemas.Remove(schemaName);
        }
    }
}