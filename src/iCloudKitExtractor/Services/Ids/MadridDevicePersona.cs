using System.IO;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Mac-shaped NAC / Madrid persona (serial, MLB, ROM, …) used by pypush <c>data.plist</c>.
/// iPhone Frida supplies Anisette; validation-data needs these Mac IOKit values.
/// Import a full <c>data.plist</c> captured from a real Mac that already runs iMessage.
/// </summary>
public static class MadridDevicePersona
{
    public static string DirectoryPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "iCloudKitExtractor",
        "madrid-persona");

    public static string DataPlistPath => Path.Combine(DirectoryPath, "data.plist");
    public static string MetaJsonPath => Path.Combine(DirectoryPath, "persona-meta.json");

    public static bool HasPersona() =>
        File.Exists(DataPlistPath) && new FileInfo(DataPlistPath).Length > 64;

    public static void EnsureDirectory() => Directory.CreateDirectory(DirectoryPath);

    /// <summary>
    /// Import a complete NAC <c>data.plist</c> (from Mac ioreg / nacserver extractor / Frida dump).
    /// </summary>
    public static MadridPersonaInfo ImportDataPlist(string sourcePath, string? note = null)
    {
        if (string.IsNullOrWhiteSpace(sourcePath) || !File.Exists(sourcePath))
            throw new FileNotFoundException("data.plist not found.", sourcePath);

        var bytes = File.ReadAllBytes(sourcePath);
        if (bytes.Length < 64)
            throw new InvalidOperationException("data.plist too small — need a full Mac NAC dump.");

        // Validate shape: must expose iokit + root_disk_uuid (xml or bplist).
        var info = ParsePersonaInfo(bytes);
        if (string.IsNullOrWhiteSpace(info.SerialNumber))
            throw new InvalidOperationException(
                "data.plist missing IOPlatformSerialNumber — capture a full Mac persona.");

        EnsureDirectory();
        File.WriteAllBytes(DataPlistPath, bytes);

        info = info with
        {
            ImportedUtc = DateTime.UtcNow.ToString("O"),
            SourcePath = sourcePath,
            Note = note,
            DataPlistPath = DataPlistPath,
        };
        File.WriteAllText(
            MetaJsonPath,
            JsonSerializer.Serialize(info, new JsonSerializerOptions { WriteIndented = true }));
        return info;
    }

    public static MadridPersonaInfo? TryLoadMeta()
    {
        if (!HasPersona())
            return null;
        try
        {
            if (File.Exists(MetaJsonPath))
            {
                var meta = JsonSerializer.Deserialize<MadridPersonaInfo>(File.ReadAllText(MetaJsonPath));
                if (meta is not null)
                    return meta with { DataPlistPath = DataPlistPath };
            }
        }
        catch
        {
            // fall through to re-parse plist
        }

        try
        {
            var info = ParsePersonaInfo(File.ReadAllBytes(DataPlistPath));
            return info with { DataPlistPath = DataPlistPath };
        }
        catch
        {
            return new MadridPersonaInfo { DataPlistPath = DataPlistPath, SerialNumber = "?" };
        }
    }

    public static string FormatStatusSummary()
    {
        if (!HasPersona())
        {
            return "Madrid persona: missing — import a Mac data.plist (NAC). "
                 + "iPhone Frida ≠ NAC IOKit (MLB/ROM/serial).";
        }

        var m = TryLoadMeta();
        return $"Madrid persona: OK serial={m?.SerialNumber ?? "?"} "
             + $"hw={m?.HardwareVersion ?? "?"} uuid={Trim(m?.PlatformUuid, 8)} "
             + $"plist={DataPlistPath}";
    }

    /// <summary>Parse serial / uuid / product from xml or binary plist bytes.</summary>
    public static MadridPersonaInfo ParsePersonaInfo(byte[] plistBytes)
    {
        // Prefer XML parse for the stock pypush data.plist; bplist falls back to light scan.
        if (LooksLikeXml(plistBytes))
            return ParseXmlPersona(plistBytes);

        return ParseBinaryHeuristic(plistBytes);
    }

    private static MadridPersonaInfo ParseXmlPersona(byte[] bytes)
    {
        var text = Encoding.UTF8.GetString(bytes);
        var doc = XDocument.Parse(text);
        var iokit = FindDictForKey(doc.Root, "iokit");
        var serial = GetStringValue(iokit, "IOPlatformSerialNumber");
        var uuid = GetStringValue(iokit, "IOPlatformUUID");
        var productRaw = GetDataValue(iokit, "product-name");
        var product = DecodeCStringData(productRaw);
        var rootDisk = GetStringValue(FindDict(doc.Root), "root_disk_uuid")
                       ?? GetStringValue(doc.Root, "root_disk_uuid");

        return new MadridPersonaInfo
        {
            SerialNumber = serial,
            PlatformUuid = uuid,
            HardwareVersion = string.IsNullOrWhiteSpace(product) ? "MacBookPro18,3" : product,
            RootDiskUuid = rootDisk,
            OsVersion = "macOS,13.2.1,22D68",
            SoftwareVersion = "22D68",
        };
    }

    private static MadridPersonaInfo ParseBinaryHeuristic(byte[] bytes)
    {
        // bplist: pull printable IOPlatformSerialNumber-like tokens (C0… Mac serials).
        var ascii = Encoding.ASCII.GetString(bytes);
        string? serial = null;
        foreach (System.Text.RegularExpressions.Match m in
                 System.Text.RegularExpressions.Regex.Matches(ascii, @"C0[0-9A-Z]{8,12}"))
        {
            serial = m.Value;
            break;
        }

        return new MadridPersonaInfo
        {
            SerialNumber = serial ?? "",
            HardwareVersion = "MacBookPro18,3",
            OsVersion = "macOS,13.2.1,22D68",
            SoftwareVersion = "22D68",
        };
    }

    private static bool LooksLikeXml(byte[] b) =>
        b.Length > 5 && (b[0] == (byte)'<' || (b[0] == 0xEF && b.Length > 3));

    private static XElement? FindDict(XElement? root)
    {
        if (root is null) return null;
        if (root.Name.LocalName == "dict") return root;
        return root.Elements().FirstOrDefault(e => e.Name.LocalName == "dict");
    }

    private static XElement? FindDictForKey(XElement? root, string key)
    {
        var dict = FindDict(root);
        if (dict is null) return null;
        var nodes = dict.Elements().ToList();
        for (var i = 0; i < nodes.Count - 1; i++)
        {
            if (nodes[i].Name.LocalName == "key" && nodes[i].Value == key
                && nodes[i + 1].Name.LocalName == "dict")
                return nodes[i + 1];
        }

        return null;
    }

    private static string? GetStringValue(XElement? dict, string key)
    {
        if (dict is null) return null;
        var nodes = dict.Elements().ToList();
        for (var i = 0; i < nodes.Count - 1; i++)
        {
            if (nodes[i].Name.LocalName == "key" && nodes[i].Value == key
                && nodes[i + 1].Name.LocalName == "string")
                return nodes[i + 1].Value;
        }

        return null;
    }

    private static byte[]? GetDataValue(XElement? dict, string key)
    {
        if (dict is null) return null;
        var nodes = dict.Elements().ToList();
        for (var i = 0; i < nodes.Count - 1; i++)
        {
            if (nodes[i].Name.LocalName == "key" && nodes[i].Value == key
                && nodes[i + 1].Name.LocalName == "data")
            {
                var b64 = string.Concat(nodes[i + 1].Value.Where(c => !char.IsWhiteSpace(c)));
                try { return Convert.FromBase64String(b64); }
                catch { return null; }
            }
        }

        return null;
    }

    private static string? DecodeCStringData(byte[]? data)
    {
        if (data is null || data.Length == 0) return null;
        var end = Array.IndexOf(data, (byte)0);
        if (end < 0) end = data.Length;
        return Encoding.UTF8.GetString(data, 0, end).Trim();
    }

    private static string Trim(string? s, int n) =>
        string.IsNullOrEmpty(s) ? "?" : (s.Length <= n ? s : s[..n] + "…");
}

public sealed record MadridPersonaInfo
{
    public string? SerialNumber { get; init; }
    public string? PlatformUuid { get; init; }
    public string? HardwareVersion { get; init; }
    public string? RootDiskUuid { get; init; }
    public string? OsVersion { get; init; }
    public string? SoftwareVersion { get; init; }
    public string? DataPlistPath { get; init; }
    public string? SourcePath { get; init; }
    public string? ImportedUtc { get; init; }
    public string? Note { get; init; }
}
