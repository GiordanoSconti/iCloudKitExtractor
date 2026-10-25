using System.Net.Security;
using System.Reflection;
using System.Security.Cryptography.X509Certificates;

namespace iCloudKitExtractor.Services.Http;

/// <summary>
/// gsa.apple.com and related GSA hosts use Apple's private PKI (Apple Server Authentication CA),
/// which is not in the Windows default trust store. Native Apple apps trust these roots explicitly.
/// </summary>
internal static class AppleCertificateTrust
{
    private static readonly Lazy<X509Certificate2> ServerAuthCa = new(LoadServerAuthCa);
    private static readonly Lazy<X509Certificate2> RootCa = new(LoadRootCa);

    public static bool ValidateServerCertificate(
        object sender,
        X509Certificate? certificate,
        X509Chain? chain,
        SslPolicyErrors sslPolicyErrors)
    {
        if (sslPolicyErrors == SslPolicyErrors.None)
            return true;

        if (certificate is not X509Certificate2 leaf)
            return false;

        if (!IsAppleHost(sender))
            return false;

        return BuildAppleChain(leaf);
    }

    private static bool IsAppleHost(object sender)
    {
        var host = sender switch
        {
            HttpRequestMessage req => req.RequestUri?.Host,
            SslStream ssl => ssl.TargetHostName,
            _ => null
        };

        return host is not null &&
               (host.EndsWith(".apple.com", StringComparison.OrdinalIgnoreCase) ||
                host.Equals("apple.com", StringComparison.OrdinalIgnoreCase));
    }

    private static bool BuildAppleChain(X509Certificate2 leaf)
    {
        using var customChain = new X509Chain();
        customChain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
        customChain.ChainPolicy.CustomTrustStore.Add(RootCa.Value);
        customChain.ChainPolicy.ExtraStore.Add(ServerAuthCa.Value);
        customChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
        return customChain.Build(leaf);
    }

    private static X509Certificate2 LoadServerAuthCa() =>
        LoadEmbeddedCert("AppleServerAuthenticationCA.der");

    private static X509Certificate2 LoadRootCa() =>
        LoadEmbeddedCert("AppleRootCA.cer");

    private static X509Certificate2 LoadEmbeddedCert(string resourceName)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var fullName = assembly.GetManifestResourceNames()
            .FirstOrDefault(n => n.EndsWith(resourceName, StringComparison.OrdinalIgnoreCase))
            ?? throw new InvalidOperationException($"Certificato incorporato non trovato: {resourceName}");

        using var stream = assembly.GetManifestResourceStream(fullName)
            ?? throw new InvalidOperationException($"Stream certificato non trovato: {resourceName}");

        var bytes = new byte[stream.Length];
        _ = stream.Read(bytes, 0, bytes.Length);
        return X509CertificateLoader.LoadCertificate(bytes);
    }
}
