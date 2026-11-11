using System.IO;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Frida-captured iPhone IDS register identity (push token + device plist fields).
/// Path: %AppData%/iCloudKitExtractor/madrid-persona/iphone-ids-identity.json
/// </summary>
public static class IphoneIdsIdentityStore
{
    public static string PathJson =>
        System.IO.Path.Combine(MadridDevicePersona.DirectoryPath, "iphone-ids-identity.json");

    public static bool HasIdentity() =>
        File.Exists(PathJson) && new FileInfo(PathJson).Length > 32;

    public static IphoneIdsIdentity? TryLoad()
    {
        if (!HasIdentity())
            return null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(PathJson));
            var root = doc.RootElement;
            var id = new IphoneIdsIdentity();

            if (root.TryGetProperty("push_token_hex", out var pth))
                id.PushTokenHex = pth.GetString();
            if (root.TryGetProperty("push_token_b64", out var ptb))
                id.PushTokenB64 = ptb.GetString();
            if (root.TryGetProperty("headers", out var hdrs)
                && hdrs.ValueKind == JsonValueKind.Object
                && hdrs.TryGetProperty("User-Agent", out var ua))
                id.UserAgent = ua.GetString();

            if (root.TryGetProperty("register", out var reg) && reg.ValueKind == JsonValueKind.Object)
            {
                id.DeviceName = GetStr(reg, "device-name");
                id.HardwareVersion = GetStr(reg, "hardware-version");
                id.OsVersion = GetStr(reg, "os-version");
                id.SoftwareVersion = GetStr(reg, "software-version");
                id.Language = GetStr(reg, "language");
                if (reg.TryGetProperty("has_madrid", out var hm)
                    && (hm.ValueKind is JsonValueKind.True or JsonValueKind.False))
                    id.HasMadrid = hm.GetBoolean();
                if (reg.TryGetProperty("uris", out var uris) && uris.ValueKind == JsonValueKind.Array)
                {
                    id.Uris = new List<string>();
                    foreach (var u in uris.EnumerateArray())
                    {
                        var s = u.GetString();
                        if (!string.IsNullOrWhiteSpace(s))
                            id.Uris.Add(s!);
                    }
                }
                if (reg.TryGetProperty("services", out var svcs) && svcs.ValueKind == JsonValueKind.Array)
                {
                    id.Services = new List<string>();
                    foreach (var s in svcs.EnumerateArray())
                    {
                        var name = s.GetString();
                        if (!string.IsNullOrWhiteSpace(name))
                            id.Services.Add(name!);
                    }
                }
                if (reg.TryGetProperty("private-device-data", out var pdd)
                    && pdd.ValueKind == JsonValueKind.Object)
                {
                    id.PrivateDeviceData = new Dictionary<string, object?>();
                    foreach (var prop in pdd.EnumerateObject())
                        id.PrivateDeviceData[prop.Name] = JsonElementToPlistValue(prop.Value);
                }
            }

            return id;
        }
        catch
        {
            return null;
        }
    }

    public static string FormatStatusSummary()
    {
        var id = TryLoad();
        if (id is null)
            return "iPhone IDS identity: missing — re-run fetch_ids_validation.py";
        var tok = id.PushTokenHex is { Length: > 8 } h ? h[..8] + "…" : "?";
        var madrid = id.HasMadrid is true ? "madrid=yes" : "madrid=NO";
        var uriBit = id.Uris is { Count: > 0 }
            ? string.Join(",", id.Uris.Where(u => u.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)).Take(2))
            : "uris=?";
        return $"iPhone IDS identity: hw={id.HardwareVersion ?? "?"} os={id.OsVersion ?? "?"} push={tok} {madrid} {uriBit}";
    }

    private static string? GetStr(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) ? v.GetString() : null;

    private static object? JsonElementToPlistValue(JsonElement el) =>
        el.ValueKind switch
        {
            JsonValueKind.String => el.GetString(),
            JsonValueKind.Number when el.TryGetInt64(out var i) => i,
            JsonValueKind.Number => el.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Null => null,
            _ => el.ToString(),
        };
}

public sealed class IphoneIdsIdentity
{
    public string? PushTokenHex { get; set; }
    public string? PushTokenB64 { get; set; }
    public string? UserAgent { get; set; }
    public string? DeviceName { get; set; }
    public string? HardwareVersion { get; set; }
    public string? OsVersion { get; set; }
    public string? SoftwareVersion { get; set; }
    public string? Language { get; set; }
    public bool? HasMadrid { get; set; }
    public List<string>? Uris { get; set; }
    public List<string>? Services { get; set; }
    public Dictionary<string, object?>? PrivateDeviceData { get; set; }
}
