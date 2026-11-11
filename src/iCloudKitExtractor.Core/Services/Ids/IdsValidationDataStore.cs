using System.IO;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Stores a Frida-captured IDS <c>validation-data</c> blob for Madrid enroll experiments.
/// Prefer fresh captures (&lt; ~10–30 min); hardware-bound to the capturing iPhone.
/// </summary>
public static class IdsValidationDataStore
{
    public static string DirectoryPath => MadridDevicePersona.DirectoryPath;
    public static string BlobPath => Path.Combine(DirectoryPath, "validation-data.b64");
    public static string MetaPath => Path.Combine(DirectoryPath, "validation-data.json");

    public static bool HasBlob() =>
        File.Exists(BlobPath) && new FileInfo(BlobPath).Length > 32;

    public static void SaveBase64(string b64, string? source = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(b64);
        // Allow raw JSON line from Frida marker.
        b64 = b64.Trim();
        if (b64.StartsWith("{", StringComparison.Ordinal))
        {
            using var doc = JsonDocument.Parse(b64);
            if (!doc.RootElement.TryGetProperty("validation_data_b64", out var el))
                throw new InvalidOperationException("JSON missing validation_data_b64.");
            b64 = el.GetString() ?? throw new InvalidOperationException("validation_data_b64 null.");
        }

        // Strip whitespace / PEM-ish noise.
        b64 = string.Concat(b64.Where(c => !char.IsWhiteSpace(c)));
        _ = Convert.FromBase64String(b64); // validate

        MadridDevicePersona.EnsureDirectory();
        File.WriteAllText(BlobPath, b64 + Environment.NewLine);
        var meta = new
        {
            savedUtc = DateTime.UtcNow.ToString("O"),
            length = Convert.FromBase64String(b64).Length,
            source = source ?? "import",
        };
        File.WriteAllText(MetaPath, JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }));
    }

    public static byte[]? TryLoad(out string? detail)
    {
        detail = null;
        if (!HasBlob())
        {
            detail = "no Frida validation-data blob";
            return null;
        }

        try
        {
            var b64 = File.ReadAllText(BlobPath).Trim();
            var bytes = Convert.FromBase64String(string.Concat(b64.Where(c => !char.IsWhiteSpace(c))));
            DateTimeOffset? saved = null;
            if (File.Exists(MetaPath))
            {
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(MetaPath));
                    if (doc.RootElement.TryGetProperty("savedUtc", out var s)
                        && DateTimeOffset.TryParse(s.GetString(), out var dto))
                        saved = dto;
                }
                catch { /* ignore */ }
            }

            var age = saved is null ? "?" : (DateTimeOffset.UtcNow - saved.Value).TotalMinutes.ToString("0.0") + " min";
            detail = $"Frida validation-data {bytes.Length} B (age={age}) from {BlobPath}";
            if (saved is not null && DateTimeOffset.UtcNow - saved.Value > TimeSpan.FromMinutes(45))
                detail += " — STALE (>45m), re-capture recommended";
            return bytes;
        }
        catch (Exception ex)
        {
            detail = "validation-data load failed: " + ex.Message;
            return null;
        }
    }

    public static string FormatStatusSummary()
    {
        if (!HasBlob())
            return "Frida validation-data: missing — run scripts/ios_akd_probe/fetch_ids_validation.py";
        _ = TryLoad(out var detail);
        return detail ?? "Frida validation-data: present";
    }
}
