using System.Text.Json;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Parser boot_args da GET gsa.apple.com/auth (macless-haystack / pypush_gsa_icloud).
/// </summary>
public static class GsaAuthBootArgsParser
{
    private static readonly Regex BootArgsScript = new(
        """<script[^>]*class="boot_args"[^>]*>\s*(.*?)\s*</script>""",
        RegexOptions.Singleline | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

    public static int? TryParsePhoneId(string html)
    {
        var json = TryExtractBootArgsJson(html);
        if (json is null)
            return null;

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (TryReadPhoneId(root, "direct", out var id))
                return id;
            if (TryReadPhoneId(root, "indirect", out id))
                return id;
        }
        catch (JsonException)
        {
            // JSON boot_args non valido
        }

        return null;
    }

    private static string? TryExtractBootArgsJson(string html)
    {
        var match = BootArgsScript.Match(html);
        return match.Success ? match.Groups[1].Value.Trim() : null;
    }

    private static bool TryReadPhoneId(JsonElement root, string branch, out int id)
    {
        id = 0;
        if (!root.TryGetProperty(branch, out var direct))
            return false;

        if (!direct.TryGetProperty("phoneNumberVerification", out var pnv))
            return false;

        if (pnv.TryGetProperty("trustedPhoneNumber", out var single)
            && single.TryGetProperty("id", out var singleId)
            && singleId.TryGetInt32(out id))
        {
            return true;
        }

        if (pnv.TryGetProperty("trustedPhoneNumbers", out var arr)
            && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in arr.EnumerateArray())
            {
                if (item.TryGetProperty("id", out var arrId) && arrId.TryGetInt32(out id))
                    return true;
            }
        }

        return false;
    }
}
