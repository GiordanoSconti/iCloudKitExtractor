using System.Net;
using System.Security.Cryptography.X509Certificates;
using iCloudKitExtractor.AnisetteLicense;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace iCloudKitExtractor.AnisetteServer.Licensed.Hosting;

/// <summary>
/// Wire Kestrel listen endpoints for Licensed / Mac Anisette middleware.
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

        X509Certificate2? httpsCert = null;
        if (parts.Any(u => u.StartsWith("https://", StringComparison.OrdinalIgnoreCase)))
        {
            // Generate/load before Listen so macOS does not fall back to the ASP.NET
            // "development certificate" path (which hangs / fails outside Windows).
            httpsCert = AnisetteTlsCertificate.LoadOrCreate();
            Console.WriteLine(
                $"[anisette-tls] HTTPS enabled — pfx={AnisetteTlsCertificate.PfxPath} " +
                $"cer={AnisetteTlsCertificate.CerPath} thumbprint={httpsCert.Thumbprint}");
        }

        // Prefer explicit Listen* over UseUrls: UseUrls("https://…") on macOS often
        // blocks waiting for a missing dotnet-dev-certs HTTPS certificate.
        webHost.ConfigureKestrel(options =>
        {
            foreach (var raw in parts)
                BindEndpoint(options, raw, httpsCert);
        });
    }

    public static void Configure(WebApplicationBuilder builder, string listenUrls) =>
        Configure(builder.WebHost, listenUrls);

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

    private static void BindEndpoint(KestrelServerOptions options, string raw, X509Certificate2? httpsCert)
    {
        if (!TryParseListenUrl(raw, out var address, out var port, out var https))
            throw new InvalidOperationException($"Invalid listen URL: '{raw}'");

        options.Listen(address, port, listen =>
        {
            if (!https)
                return;
            if (httpsCert is null)
                throw new InvalidOperationException("HTTPS listen URL but no server certificate was loaded.");
            listen.UseHttps(httpsCert);
        });
    }

    internal static bool TryParseListenUrl(string raw, out IPAddress address, out int port, out bool https)
    {
        address = IPAddress.Any;
        port = 6971;
        https = false;

        var text = raw.Trim();
        if (text.Length == 0)
            return false;

        if (!text.Contains("://", StringComparison.Ordinal))
            text = "http://" + text;

        if (!Uri.TryCreate(text, UriKind.Absolute, out var uri))
            return false;

        https = uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        if (!https && !uri.Scheme.Equals(Uri.UriSchemeHttp, StringComparison.OrdinalIgnoreCase))
            return false;

        port = uri.IsDefaultPort
            ? (https ? 443 : 80)
            : uri.Port;

        var host = uri.IdnHost;
        if (string.IsNullOrEmpty(host)
            || host is "0.0.0.0" or "*" or "+"
            || host.Equals("any", StringComparison.OrdinalIgnoreCase))
        {
            address = IPAddress.Any;
        }
        else if (host is "::" or "[::]")
        {
            address = IPAddress.IPv6Any;
        }
        else if (host is "localhost" or "127.0.0.1")
        {
            address = IPAddress.Loopback;
        }
        else if (host is "::1")
        {
            address = IPAddress.IPv6Loopback;
        }
        else if (IPAddress.TryParse(host, out var parsed))
        {
            address = parsed;
        }
        else
        {
            // Hostname bind → all interfaces (Kestrel resolves separately if needed).
            address = IPAddress.Any;
        }

        return port is > 0 and <= 65535;
    }

    private static bool IsTruthy(string? v) =>
        v is "1" or "true" or "TRUE" or "yes" or "YES" or "on" or "ON";
}
