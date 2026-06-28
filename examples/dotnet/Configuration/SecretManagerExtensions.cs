// -----------------------------------------------------------------------------
// SecretManagerExtensions.cs
//
// SECURITY PURPOSE: Demonstrates how to integrate an external secrets manager
// into ASP.NET Core's built-in IConfiguration system. Instead of placing secrets
// in appsettings.json (which gets committed to source control) or .env files
// (which sit on disk unencrypted), this extension registers a configuration
// source that pulls values from AWS Secrets Manager, HashiCorp Vault, or
// Azure Key Vault at startup.
//
// WHY THIS MATTERS:
//   - ASP.NET Core's IConfiguration is used throughout the framework (Options
//     pattern, [Configuration] binding, logging, etc.). By bridging your
//     secret manager into IConfiguration, all existing code that reads config
//     "just works" — but the secrets come from a secure vault instead of a file.
//   - Secrets loaded this way OVERRIDE appsettings.json values because this
//     provider is registered after the default JSON providers. This is intentional:
//     you keep safe defaults in appsettings.json and let the vault override them.
//   - The SECRET_PROVIDER environment variable determines the backend at runtime.
//     The same compiled binary works with any provider — no recompilation needed.
// -----------------------------------------------------------------------------

using System.Security.Cryptography;
using Microsoft.Extensions.Configuration;

namespace SecretsTutorial.Configuration;

/// <summary>
/// Extension methods for registering a secrets manager as an
/// <see cref="IConfigurationProvider"/> in the ASP.NET Core configuration pipeline.
/// </summary>
public static class SecretManagerExtensions
{
    /// <summary>
    /// Reads the <c>SECRET_PROVIDER</c> environment variable and registers the
    /// appropriate <see cref="IConfigurationSource"/> that pulls secrets into
    /// the ASP.NET Core <see cref="IConfiguration"/> system at startup.
    /// </summary>
    /// <param name="builder">The <see cref="IConfigurationBuilder"/> to extend.</param>
    /// <param name="provider">
    /// Optional override for the secret provider name. If <c>null</c>, the value is
    /// read from the <c>SECRET_PROVIDER</c> environment variable.
    /// Supported values: <c>aws</c>, <c>vault</c>, <c>azure</c>.
    /// </param>
    /// <returns>The same <see cref="IConfigurationBuilder"/> for chaining.</returns>
    /// <exception cref="InvalidOperationException">
    /// Thrown when <c>SECRET_PROVIDER</c> is not set or contains an unsupported value.
    /// </exception>
    /// <remarks>
    /// <para>
    /// <b>Security note:</b> This method must be called AFTER the default JSON
    /// providers so that vault values take precedence. The order of registration
    /// in <see cref="IConfigurationBuilder"/> determines priority (last wins).
    /// </para>
    /// <para>
    /// <b>Rotation:</b> This provider loads secrets once at startup. For hot
    /// rotation without restart, use <see cref="ISecretManagerService"/> directly
    /// or implement <see cref="IConfigurationSource"/> with a reload trigger.
    /// </para>
    /// </remarks>
    public static IConfigurationBuilder AddSecretManager(
        this IConfigurationBuilder builder,
        string? provider = null)
    {
        // Determine which provider to use. Prefer explicit parameter, fall back
        // to the SECRET_PROVIDER environment variable. This is the single place
        // where the provider is resolved — application code never knows the backend.
        var providerName = provider
            ?? Environment.GetEnvironmentVariable("SECRET_PROVIDER")
            ?? throw new InvalidOperationException(
                "SECRET_PROVIDER environment variable is not set. " +
                "Supported values: aws, vault, azure. " +
                "This variable determines which secrets backend to use at runtime.");

        // Normalize to lowercase for case-insensitive comparison
        var normalizedProvider = providerName.Trim().ToLowerInvariant();

        // Register the appropriate configuration source based on the provider.
        // Each source is a thin wrapper that implements IConfigurationSource
        // and builds an IConfigurationProvider that fetches from the vault.
        IConfigurationSource source = normalizedProvider switch
        {
            "aws" => new AwsSecretsConfigurationSource(),
            "vault" => new VaultSecretsConfigurationSource(),
            "azure" => new AzureKeyVaultConfigurationSource(),
            _ => throw new InvalidOperationException(
                $"Unsupported secret provider: '{providerName}'. " +
                "Supported values: aws, vault, azure.")
        };

        builder.Add(source);

        // Log which provider was selected — but NEVER log any secret values,
        // vault addresses, or authentication details.
        Console.WriteLine(
            $"[SecretManager] Configuration source registered: {normalizedProvider}");

        return builder;
    }
}

// -----------------------------------------------------------------------------
// Configuration source base classes
//
// SECURITY PURPOSE: Each source encapsulates the provider-specific setup
// (region, vault address, vault URL) and produces an IConfigurationProvider
// that ASP.NET Core calls during startup to populate the configuration tree.
//
// These are intentionally minimal implementations for the tutorial. In a real
// production system, each provider would also implement:
//   - Automatic reload on secret version change (polling or event-based)
//   - Secret name prefix filtering (e.g., only load secrets under "myapp/")
//   - Connection pooling and retry with exponential backoff
//   - Metrics (secret fetch count, latency, error rate)
// -----------------------------------------------------------------------------

/// <summary>
/// Base class for all secret manager configuration sources.
/// Centralizes common configuration and provides a consistent builder pattern.
/// </summary>
public abstract class SecretManagerConfigurationSource : IConfigurationSource
{
    /// <summary>
    /// Builds the <see cref="IConfigurationProvider"/> that fetches secrets
    /// from the underlying secret store.
    /// </summary>
    public abstract IConfigurationProvider Build(IConfigurationBuilder builder);
}

/// <summary>
/// Configuration source for AWS Secrets Manager.
/// Reads AWS_REGION from the environment to determine the service endpoint.
/// </summary>
public sealed class AwsSecretsConfigurationSource : SecretManagerConfigurationSource
{
    public override IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        var region = Environment.GetEnvironmentVariable("AWS_REGION")
            ?? throw new InvalidOperationException(
                "AWS_REGION environment variable is required for AWS Secrets Manager.");

        return new AwsSecretsConfigurationProvider(region);
    }
}

/// <summary>
/// Configuration source for HashiCorp Vault.
/// Reads VAULT_ADDR and VAULT_TOKEN from the environment.
/// </summary>
public sealed class VaultSecretsConfigurationSource : SecretManagerConfigurationSource
{
    public override IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        var vaultAddr = Environment.GetEnvironmentVariable("VAULT_ADDR")
            ?? throw new InvalidOperationException(
                "VAULT_ADDR environment variable is required for HashiCorp Vault.");

        var vaultToken = Environment.GetEnvironmentVariable("VAULT_TOKEN")
            ?? throw new InvalidOperationException(
                "VAULT_TOKEN environment variable is required for HashiCorp Vault " +
                "(use Kubernetes JWT auth in production instead of static tokens).");

        return new VaultSecretsConfigurationProvider(vaultAddr, vaultToken);
    }
}

/// <summary>
/// Configuration source for Azure Key Vault.
/// Reads AZURE_VAULT_URL from the environment.
/// Uses DefaultAzureCredential for authentication (Managed Identity in production).
/// </summary>
public sealed class AzureKeyVaultConfigurationSource : SecretManagerConfigurationSource
{
    public override IConfigurationProvider Build(IConfigurationBuilder builder)
    {
        var vaultUrl = Environment.GetEnvironmentVariable("AZURE_VAULT_URL")
            ?? throw new InvalidOperationException(
                "AZURE_VAULT_URL environment variable is required for Azure Key Vault.");

        return new AzureKeyVaultConfigurationProvider(vaultUrl);
    }
}

// -----------------------------------------------------------------------------
// Configuration provider stubs
//
// SECURITY PURPOSE: These providers implement IConfigurationProvider to load
// secrets into the ASP.NET Core configuration tree. They fetch ALL secrets at
// startup and populate a dictionary that IConfiguration reads from.
//
// In production, you would implement these with actual SDK calls to fetch
// and flatten secrets into the configuration hierarchy. For example, a secret
// named "myapp/database" with JSON {"Host":"db.example.com","Port":5432}
// would populate configuration keys "myapp:database:Host" and "myapp:database:Port".
// -----------------------------------------------------------------------------

/// <summary>
/// AWS Secrets Manager configuration provider stub.
/// In production, this would use AmazonSecretsManagerClient to list and fetch secrets.
/// </summary>
public sealed class AwsSecretsConfigurationProvider : ConfigurationProvider
{
    private readonly string _region;

    public AwsSecretsConfigurationProvider(string region) => _region = region;

    public override void Load()
    {
        // SECURITY: In production, this method calls AWS Secrets Manager to
        // fetch secrets and populate Data dictionary. The data is held in
        // memory only — never written to disk or logs.
        //
        // Example: Data["Database:Host"] = secretValue["Host"];
        Console.WriteLine(
            $"[AwsSecretsProvider] Loading secrets from AWS region: {_region}");
    }
}

/// <summary>
/// HashiCorp Vault configuration provider stub.
/// In production, this would use VaultSharp to read KV v2 secrets.
/// </summary>
public sealed class VaultSecretsConfigurationProvider : ConfigurationProvider
{
    private readonly string _vaultAddr;

    public VaultSecretsConfigurationProvider(string vaultAddr, string _)
        => _vaultAddr = vaultAddr;

    public override void Load()
    {
        // SECURITY: Vault address is logged for debugging (it's not a secret),
        // but the token and secret values are NEVER logged.
        Console.WriteLine(
            $"[VaultSecretsProvider] Loading secrets from Vault: {_vaultAddr}");
    }
}

/// <summary>
/// Azure Key Vault configuration provider stub.
/// In production, this would use SecretClient with DefaultAzureCredential.
/// </summary>
public sealed class AzureKeyVaultConfigurationProvider : ConfigurationProvider
{
    private readonly string _vaultUrl;

    public AzureKeyVaultConfigurationProvider(string vaultUrl) => _vaultUrl = vaultUrl;

    public override void Load()
    {
        // SECURITY: Vault URL is logged for debugging, but secret values
        // and Managed Identity details are NEVER logged.
        Console.WriteLine(
            $"[AzureKeyVaultProvider] Loading secrets from Key Vault: {_vaultUrl}");
    }
}