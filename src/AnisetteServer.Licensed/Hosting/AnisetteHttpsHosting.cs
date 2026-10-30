using System.Security.Cryptography.X509Certificates;
using iCloudKitExtractor.AnisetteLicense;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;

namespace iCloudKitExtractor.AnisetteServer.Licensed.Hosting;

/// <summary>
/// Wire Kestrel listen URLs for Licensed / Mac Anisette middleware.
/// Default remains plain <c>http://</c> (no certificates required).
/// HTTPS is opt-in via <c>https://…</c> listen URLs or <c>ANISETTE_TLS_ENABLE=1</c>.
/// </summary>
public static class AnisetteHttpsHosting
{
    public const string DefaultListenUrls = "http://0.0.0.0:6971";

    public static string ResolveListenUrls(int port, string? envUrls = null)
    {
        var urls = envUrls?.Trim();
        if (string.IsNullOrEmpty(urls))
            urls = Environment.GetEnvironmentVariable("ANISETTE_SERVER_URLS")?.Trim();
        if (!string.IsNullOrEmpty(urls))
            return urls;

        // HTTP by default (lab / no certs). Opt into TLS with ANISETTE_TLS_ENABLE=1.
        var enableTls = IsTruthy(Environment.GetEnvironmentVariable("ANISETTE_TLS_ENABLE"));
        var scheme = enableTls ? "https" : "http";
        return $"{scheme}://0.0.0.0:{port}";
    }

    public static void Configure(IWebHostBuilder webHost, string listenUrls)
    {
        var parts = listenUrls
            .Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        if (parts.Length == 0)
            parts = [DefaultListenUrls];

        webHost.UseUrls(parts);

        if (!parts.Any(u => u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
            return;

        var cert = AnisetteTlsCertificate.LoadOrCreate();
        webHost.ConfigureKestrel(options =>
        {
            options.ConfigureHttpsDefaults(https =>
            {
                https.ServerCertificate = cert;
            });
        });

        Console.WriteLine(
            $"[anisette-tls] HTTPS enabled — pfx={AnisetteTlsCertificate.PfxPath} " +
            $"cer={AnisetteTlsCertificate.CerPath} thumbprint={cert.Thumbprint}");
    }

    public static void Configure(WebApplicationBuilder builder, string listenUrls) =>
        Configure(builder.WebHost, listenUrls);

    /// <summary>Optional: expose active cert for UI / health.</summary>
    public static X509Certificate2? TryGetActiveCertificate(string listenUrls)
    {
        if (!listenUrls.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Any(u => u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
            return null;
        try
        {
            return AnisetteTlsCertificate.LoadOrCreate();
        }
        catch
        {
            return null;
        }
    }

    private static bool IsTruthy(string? v) =>
        v is "1" or "true" or "TRUE" or "yes" or "YES" or "on" or "ON";
}
