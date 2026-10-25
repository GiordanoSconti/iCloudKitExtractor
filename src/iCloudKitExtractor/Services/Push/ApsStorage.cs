using System.IO;
using iCloudKitExtractor.Services.Auth;

namespace iCloudKitExtractor.Services.Push;

/// <summary>Persistenza cert/key/token APS sotto %AppData%/iCloudKitExtractor/aps.</summary>
public static class ApsStorage
{
    public static string DirectoryPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "iCloudKitExtractor",
        "aps");

    public static string KeyPemPath => Path.Combine(DirectoryPath, "push.key.pem");
    public static string CertPemPath => Path.Combine(DirectoryPath, "push.cert.pem");
    public static string TokenPath => Path.Combine(DirectoryPath, "push.token.bin");
    public static string MetaPath => Path.Combine(DirectoryPath, "push.meta.txt");

    public static void EnsureDirectory() => Directory.CreateDirectory(DirectoryPath);

    public static bool HasCertificate() =>
        File.Exists(KeyPemPath) && File.Exists(CertPemPath)
        && new FileInfo(KeyPemPath).Length > 0
        && new FileInfo(CertPemPath).Length > 0;

    public static void SaveCertificate(string keyPem, string certPem, string serial, string udid)
    {
        EnsureDirectory();
        File.WriteAllText(KeyPemPath, keyPem.Trim() + Environment.NewLine);
        File.WriteAllText(CertPemPath, certPem.Trim() + Environment.NewLine);
        File.WriteAllText(MetaPath,
            $"serial={serial}{Environment.NewLine}udid={udid}{Environment.NewLine}savedUtc={DateTime.UtcNow:O}{Environment.NewLine}");
    }

    public static (string KeyPem, string CertPem) LoadCertificate()
    {
        if (!HasCertificate())
            throw new InvalidOperationException("Certificato APS assente — esegui attivazione Albert.");
        return (File.ReadAllText(KeyPemPath), File.ReadAllText(CertPemPath));
    }

    public static void SaveToken(byte[] token)
    {
        EnsureDirectory();
        File.WriteAllBytes(TokenPath, token);
    }

    public static byte[]? TryLoadToken()
    {
        if (!File.Exists(TokenPath))
            return null;
        var bytes = File.ReadAllBytes(TokenPath);
        return bytes.Length == 0 ? null : bytes;
    }

    public static string TokenHex(byte[]? token) =>
        token is null || token.Length == 0
            ? ""
            : Convert.ToHexString(token);

    /// <summary>Identità Windows coerente con Anisette/GSA.</summary>
    public static (string Serial, string Udid) ResolveWindowsIdentity()
    {
        var store = new AnisetteDeviceStore(AdiDeviceProfile.Windows);
        return (store.GetOrCreateSerialNumber(), store.GetOrCreateDeviceUuid());
    }
}
