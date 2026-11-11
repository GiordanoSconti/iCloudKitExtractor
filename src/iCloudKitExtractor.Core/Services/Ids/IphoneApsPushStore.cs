using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Frida-captured iPhone APSClientIdentity (push cert + private key) for Madrid
/// <c>x-push-sig</c> — must match the iPhone push token / validation-data.
/// Path: %AppData%/iCloudKitExtractor/madrid-persona/iphone-push.*.pem
/// </summary>
public static class IphoneApsPushStore
{
    public static string CertPemPath =>
        Path.Combine(MadridDevicePersona.DirectoryPath, "iphone-push.cert.pem");

    public static string KeyPemPath =>
        Path.Combine(MadridDevicePersona.DirectoryPath, "iphone-push.key.pem");

    public static bool HasCredentials()
    {
        try
        {
            return File.Exists(CertPemPath) && File.Exists(KeyPemPath)
                   && new FileInfo(CertPemPath).Length > 64
                   && new FileInfo(KeyPemPath).Length > 64;
        }
        catch
        {
            return false;
        }
    }

    public static (string KeyPem, string CertPem)? TryLoad()
    {
        if (!HasCredentials())
            return null;
        try
        {
            var key = File.ReadAllText(KeyPemPath);
            var cert = File.ReadAllText(CertPemPath);
            if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(cert))
                return null;
            if (!key.Contains("PRIVATE KEY", StringComparison.Ordinal)
                || !cert.Contains("CERTIFICATE", StringComparison.Ordinal))
                return null;
            // Fail fast if PEM is unusable for RSA-SHA1 push signatures.
            using var rsa = RSA.Create();
            rsa.ImportFromPem(key);
            using var x509 = X509Certificate2.CreateFromPem(cert);
            _ = x509.GetCertHashString();
            return (key, cert);
        }
        catch
        {
            return null;
        }
    }

    public static void Save(string keyPem, string certPem)
    {
        Directory.CreateDirectory(MadridDevicePersona.DirectoryPath);
        File.WriteAllText(KeyPemPath, keyPem.Trim() + Environment.NewLine);
        File.WriteAllText(CertPemPath, certPem.Trim() + Environment.NewLine);
    }

    public static string FormatStatusSummary()
    {
        if (!HasCredentials())
        {
            return "iPhone APS push: missing — expected "
                   + CertPemPath
                   + " (+ .key.pem). Run fetch_aps_push_identity.py";
        }

        var loaded = TryLoad();
        if (loaded is null)
        {
            return "iPhone APS push: PEM present but unreadable/invalid at "
                   + CertPemPath;
        }

        try
        {
            using var x509 = X509Certificate2.CreateFromPem(loaded.Value.CertPem);
            var cn = x509.GetNameInfo(X509NameType.SimpleName, false);
            return $"iPhone APS push: OK cn={cn} cert={new FileInfo(CertPemPath).Length}B "
                   + $"key={new FileInfo(KeyPemPath).Length}B";
        }
        catch
        {
            return "iPhone APS push: cert+key files OK (cn parse failed)";
        }
    }
}
