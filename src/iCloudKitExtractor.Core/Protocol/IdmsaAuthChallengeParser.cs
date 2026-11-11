using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Parser risposta GET idmsa <c>/appleauth/auth</c> (JSON o HTML con twoSV / bridgeInitiateData).
/// </summary>
public static class IdmsaAuthChallengeParser
{
    public static PhoneVerificationOptions Parse(string body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return new PhoneVerificationOptions();

        var trimmed = body.TrimStart();
        if (trimmed.StartsWith('{') || trimmed.StartsWith('['))
        {
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                return ParseRoot(doc.RootElement);
            }
            catch (JsonException)
            {
                // fall through
            }
        }

        foreach (var json in ExtractJsonCandidates(body))
        {
            try
            {
                using var doc = JsonDocument.Parse(json);
                var opts = ParseRoot(doc.RootElement);
                if (opts.TrustedPhoneNumbers.Count > 0 || opts.TrustedDeviceCount > 0)
                    return opts;
            }
            catch (JsonException)
            {
                // try next
            }
        }

        return new PhoneVerificationOptions();
    }

    private static PhoneVerificationOptions ParseRoot(JsonElement root)
    {
        JsonElement? pnv = null;
        if (TryGetPath(root, out var a, "twoSV", "phoneNumberVerification"))
            pnv = a;
        else if (TryGetPath(root, out var b, "twoSV", "bridgeInitiateData", "phoneNumberVerification"))
            pnv = b;
        else if (TryGetPath(root, out var c, "phoneNumberVerification"))
            pnv = c;
        else if (TryGetPath(root, out var d, "direct", "twoSV", "phoneNumberVerification"))
            pnv = d;
        else if (TryGetPath(root, out var e, "direct", "twoSV", "bridgeInitiateData", "phoneNumberVerification"))
            pnv = e;

        var deviceCount = 0;
        if (root.TryGetProperty("trustedDeviceCount", out var dc) && dc.TryGetInt32(out var n))
            deviceCount = n;
        else if (TryGetPath(root, out var twoSv, "twoSV")
                 && twoSv.TryGetProperty("trustedDeviceCount", out var tdc)
                 && tdc.TryGetInt32(out var n2))
            deviceCount = n2;

        if (pnv is null)
            return GsaPhoneVerificationParser.Parse(root);

        var synthJson =
            "{\"trustedDeviceCount\":" + deviceCount
            + ",\"phoneNumberVerification\":" + pnv.Value.GetRawText() + "}";
        using var synth = JsonDocument.Parse(synthJson);
        return GsaPhoneVerificationParser.Parse(synth.RootElement);
    }

    private static IEnumerable<string> ExtractJsonCandidates(string html)
    {
        var boot = Regex.Match(
            html,
            @"boot_args\s*=\s*(\{[\s\S]*?\})\s*;",
            RegexOptions.CultureInvariant);
        if (boot.Success)
            yield return boot.Groups[1].Value;

        var script = Regex.Match(
            html,
            @"<script[^>]*type=[""']application/json[""'][^>]*>([\s\S]*?)</script>",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (script.Success)
            yield return script.Groups[1].Value.Trim();

        var rx = new Regex(
            @"\{[^{}]{0,120}""trustedPhoneNumbers""[\s\S]{0,12000}?\}(?=\s*[;<]|\s*$)",
            RegexOptions.CultureInvariant);
        foreach (Match m in rx.Matches(html))
            yield return m.Value;
    }

    private static bool TryGetPath(JsonElement root, out JsonElement result, params string[] path)
    {
        result = root;
        foreach (var p in path)
        {
            if (result.ValueKind != JsonValueKind.Object
                || !result.TryGetProperty(p, out result))
            {
                result = default;
                return false;
            }
        }

        return true;
    }
}
