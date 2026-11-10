using System.IO;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>Persistenza enroll IDS sotto %AppData%/iCloudKitExtractor/ids.</summary>
public static class IdsStorage
{
    public static string DirectoryPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "iCloudKitExtractor",
        "ids");

    public static string AuthKeyPemPath => Path.Combine(DirectoryPath, "ids-auth.key.pem");
    public static string AuthCertPemPath => Path.Combine(DirectoryPath, "ids-auth.cert.pem");
    public static string IdKeyPemPath => Path.Combine(DirectoryPath, "ids-id.key.pem");
    public static string IdCertPemPath => Path.Combine(DirectoryPath, "ids-id.cert.pem");
    public static string MadridIdCertPemPath => Path.Combine(DirectoryPath, "ids-madrid-id.cert.pem");
    public static string MadridMetaPath => Path.Combine(DirectoryPath, "ids-madrid-meta.json");
    public static string IdentityKeyPemPath => Path.Combine(DirectoryPath, "ids-identity-ec.key.pem");
    public static string EncryptionKeyPemPath => Path.Combine(DirectoryPath, "ids-enc-rsa.key.pem");
    public static string DeviceKeyPemPath => Path.Combine(DirectoryPath, "ids-ngm-device.key.pem");
    public static string PreKeyPemPath => Path.Combine(DirectoryPath, "ids-ngm-pre.key.pem");
    public static string MetaPath => Path.Combine(DirectoryPath, "ids-meta.json");

    public static void EnsureDirectory() => Directory.CreateDirectory(DirectoryPath);

    public static bool HasAuthCertificate() =>
        File.Exists(AuthKeyPemPath) && File.Exists(AuthCertPemPath)
        && new FileInfo(AuthKeyPemPath).Length > 0
        && new FileInfo(AuthCertPemPath).Length > 0;

    public static bool HasRegistration() =>
        HasAuthCertificate()
        && File.Exists(IdCertPemPath)
        && new FileInfo(IdCertPemPath).Length > 0;

    public static bool HasMadridRegistration() =>
        HasAuthCertificate()
        && File.Exists(MadridIdCertPemPath)
        && new FileInfo(MadridIdCertPemPath).Length > 0;

    public static void SaveAuthKeyPair(string keyPem, string certPem)
    {
        EnsureDirectory();
        File.WriteAllText(AuthKeyPemPath, keyPem.Trim() + Environment.NewLine);
        File.WriteAllText(AuthCertPemPath, certPem.Trim() + Environment.NewLine);
    }

    public static void SaveIdCertificate(string certPem)
    {
        EnsureDirectory();
        File.WriteAllText(IdCertPemPath, certPem.Trim() + Environment.NewLine);
        // ID cert is issued against the auth CSR — always keep id key == auth key.
        if (File.Exists(AuthKeyPemPath))
            File.Copy(AuthKeyPemPath, IdKeyPemPath, overwrite: true);
    }

    public static void SaveMadridIdCertificate(string certPem)
    {
        EnsureDirectory();
        File.WriteAllText(MadridIdCertPemPath, certPem.Trim() + Environment.NewLine);
        // Prefer Madrid cert as the active ID cert for lookup/send.
        File.WriteAllText(IdCertPemPath, certPem.Trim() + Environment.NewLine);
        // Must overwrite: a stale ids-id.key.pem from an older enroll → HTTP 401 on id-query.
        if (File.Exists(AuthKeyPemPath))
            File.Copy(AuthKeyPemPath, IdKeyPemPath, overwrite: true);
    }

    public static void SaveMadridMeta(IdsEnrollmentMeta meta)
    {
        EnsureDirectory();
        var json = JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(MadridMetaPath, json);
    }

    public static IdsEnrollmentMeta? TryLoadMadridMeta()
    {
        if (!File.Exists(MadridMetaPath))
            return null;
        try
        {
            return JsonSerializer.Deserialize<IdsEnrollmentMeta>(File.ReadAllText(MadridMetaPath));
        }
        catch
        {
            return null;
        }
    }

    public static void SaveMeta(IdsEnrollmentMeta meta)
    {
        EnsureDirectory();
        var json = JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(MetaPath, json);
    }

    public static IdsEnrollmentMeta? TryLoadMeta()
    {
        if (!File.Exists(MetaPath))
            return null;
        try
        {
            return JsonSerializer.Deserialize<IdsEnrollmentMeta>(File.ReadAllText(MetaPath));
        }
        catch
        {
            return null;
        }
    }

    public static string FormatStatusSummary()
    {
        var meta = TryLoadMeta();
        var lines = new List<string>
        {
            $"IDS dir: {DirectoryPath}",
            $"Auth cert: {(HasAuthCertificate() ? "OK" : "missing")}",
            $"ID cert (Find My): {(HasRegistration() ? "OK" : "missing")}",
            $"ID cert (Madrid): {(HasMadridRegistration() ? "OK" : "missing")}",
        };
        if (meta is not null)
        {
            lines.Add($"Profile ID: {meta.ProfileId ?? "(n/a)"}");
            lines.Add($"Handles: {(meta.Handles is { Count: > 0 } ? string.Join(", ", meta.Handles) : "(n/a)")}");
            lines.Add($"RegisteredUtc: {meta.RegisteredUtc ?? "(n/a)"}");
            if (!string.IsNullOrEmpty(meta.LastError))
                lines.Add($"LastError: {meta.LastError}");
        }

        var madrid = TryLoadMadridMeta();
        if (madrid is not null)
        {
            lines.Add($"Madrid RegisteredUtc: {madrid.RegisteredUtc ?? "(n/a)"}");
            lines.Add($"Madrid Handles: {(madrid.Handles is { Count: > 0 } ? string.Join(", ", madrid.Handles) : "(n/a)")}");
            if (!string.IsNullOrEmpty(madrid.LastError))
                lines.Add($"Madrid LastError: {madrid.LastError}");
        }

        return string.Join(Environment.NewLine, lines);
    }
}

public sealed class IdsEnrollmentMeta
{
    public string? ProfileId { get; set; }
    public string? AppleId { get; set; }
    public List<string> Handles { get; set; } = [];
    public string? RegisteredUtc { get; set; }
    public string? LastError { get; set; }
    public int? LastStatus { get; set; }
}
