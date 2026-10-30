using System.IO;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Dedicated HttpClient for remote Anisette HTTPS (does not share Apple cert policy).
/// Lab: loopback / private IP self-signed accepted by default; public hosts need a
/// real chain, <c>ANISETTE_TLS_INSECURE=1</c>, thumbprint, or CA file.
/// </summary>
public static class AnisetteRemoteHttp
{
    public static HttpClient Create(string baseUrl)
    {
        var handler = new SocketsHttpHandler
        {
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        };

        if (Uri.TryCreate(baseUrl, UriKind.Absolute, out var uri)
            && uri.Scheme.Equals(Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase))
        {
            var settings = AnisetteUserSettings.Load();
            handler.SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = (sender, cert, chain, errors) =>
                    Validate(uri, cert, errors, settings),
            };
        }

        return new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(2) };
    }

    private static bool Validate(
        Uri target,
        X509Certificate? certificate,
        SslPolicyErrors errors,
        AnisetteUserSettings settings)
    {
        if (errors == SslPolicyErrors.None)
            return true;

        if (IsTruthy(Environment.GetEnvironmentVariable("ANISETTE_TLS_INSECURE"))
            || settings.TlsInsecure == true)
            return true;

        if (certificate is null)
            return false;

        using var cert2 = certificate as X509Certificate2 ?? new X509Certificate2(certificate);

        var expectedThumb =
            Environment.GetEnvironmentVariable("ANISETTE_TLS_THUMBPRINT")?.Trim()
            ?? settings.TlsThumbprint?.Trim();
        if (!string.IsNullOrEmpty(expectedThumb)
            && string.Equals(cert2.Thumbprint, expectedThumb, StringComparison.OrdinalIgnoreCase))
            return true;

        var caPath =
            Environment.GetEnvironmentVariable("ANISETTE_TLS_CA")?.Trim()
            ?? settings.TlsCaPath?.Trim();
        if (!string.IsNullOrEmpty(caPath) && File.Exists(caPath))
        {
            try
            {
                using var ca = X509CertificateLoader.LoadCertificateFromFile(caPath);
                if (string.Equals(cert2.Thumbprint, ca.Thumbprint, StringComparison.OrdinalIgnoreCase)
                    || string.Equals(cert2.Issuer, ca.Subject, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            catch
            {
                // ignore bad CA file
            }
        }

        // Lab middleware often uses a self-signed cert on LAN / localhost.
        if (IsLabHost(target.Host))
            return true;

        return false;
    }

    private static bool IsLabHost(string host)
    {
        if (string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase))
            return true;
        if (!IPAddress.TryParse(host, out var ip))
            return false;
        if (IPAddress.IsLoopback(ip))
            return true;
#if NET6_0_OR_GREATER
        return ip.IsIPv6LinkLocal
            || ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork
                && IsPrivateIpv4(ip);
#else
        return IsPrivateIpv4(ip);
#endif
    }

    private static bool IsPrivateIpv4(IPAddress ip)
    {
        var b = ip.GetAddressBytes();
        if (b.Length != 4)
            return false;
        return b[0] == 10
            || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
            || (b[0] == 192 && b[1] == 168)
            || (b[0] == 169 && b[1] == 254);
    }

    private static bool IsTruthy(string? v) =>
        v is "1" or "true" or "TRUE" or "yes" or "YES" or "on" or "ON";
}
