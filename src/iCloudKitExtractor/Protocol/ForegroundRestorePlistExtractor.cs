using System.Text;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Metadati MMCS Foreground Restore estratti da payload di risposta (batch &amp;S:, Lock, D:).
/// </summary>
public sealed record ForegroundRestorePlist(
    string ProtoVersion,
    string PlistSha256Base64,
    string PlistVersion,
    string HardwareIdHex,
    string? MmeClientInfo);

public static class ForegroundRestorePlistExtractor
{
    private static readonly Regex HardwareIdRegex = new(
        @"\b([0-9A-Fa-f]{64})\b",
        RegexOptions.Compiled);

    private static readonly Regex PlistShaRegex = new(
        @"x-apple-mmcs-plist-sha256[\x00-\x20]{0,8}([A-Za-z0-9+/]{43}=)",
        RegexOptions.Compiled);

    private static readonly Regex ProtoVersionRegex = new(
        @"x-apple-mmcs-proto-version[\x00-\x20]{0,8}([0-9]+\.[0-9]+)",
        RegexOptions.Compiled);

    private static readonly Regex PlistVersionRegex = new(
        @"x-apple-mmcs-plist-version[\x00-\x20]{0,8}(v[0-9.]+)",
        RegexOptions.Compiled);

    private static readonly Regex ClientInfoRegex = new(
        @"x-mme-client-info[\x00-\x20]{0,8}(<[^>]{8,200}>)",
        RegexOptions.Compiled);

    private static readonly Regex DeviceSessionRegex = new(
        @"([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",
        RegexOptions.Compiled);

    public static ForegroundRestorePlist? Extract(byte[]? payload)
    {
        if (payload is not { Length: > 64 })
            return null;

        var text = Encoding.Latin1.GetString(payload);
        if (text.Contains("Foreground Restore", StringComparison.Ordinal))
        {
            var built = BuildFromText(text);
            if (IsValid(built))
                return built;
        }

        return TryExtractLoose(payload);
    }

    /// <summary>
    /// Estrae hw/plist-sha MMCS anche senza la stringa letterale "Foreground Restore"
    /// (es. risposte batch S: parziali o record snapshot).
    /// </summary>
    public static ForegroundRestorePlist? TryExtractLoose(byte[]? payload)
    {
        if (payload is not { Length: > 128 })
            return null;

        var text = Encoding.Latin1.GetString(payload);
        var plistSha = Sanitize(FirstMatch(PlistShaRegex, text));
        if (plistSha.Length < 40)
            return null;

        var proto = Sanitize(FirstMatch(ProtoVersionRegex, text));
        if (string.IsNullOrWhiteSpace(proto))
            proto = "5.0";

        var plistVer = Sanitize(FirstMatch(PlistVersionRegex, text));
        if (string.IsNullOrWhiteSpace(plistVer))
            plistVer = "v1.0";

        var clientInfo = Sanitize(FirstMatch(ClientInfoRegex, text));
        var hardwareId = FindHardwareNearMmcs(text);
        if (hardwareId.Length != 64)
            return null;

        var built = new ForegroundRestorePlist(
            proto,
            plistSha,
            plistVer,
            hardwareId,
            string.IsNullOrWhiteSpace(clientInfo) ? null : clientInfo);

        return IsValid(built) ? built : null;
    }

    /// <summary>Primo Foreground valido tra i payload (nessun fallback a template).</summary>
    public static ForegroundRestorePlist? Resolve(params byte[]?[] payloads)
    {
        foreach (var payload in payloads)
        {
            var extracted = Extract(payload);
            if (IsValid(extracted))
                return extracted;
        }

        return null;
    }

    public static string? ExtractDeviceSessionId(byte[]? payload)
    {
        if (payload is not { Length: > 32 })
            return null;

        var text = Encoding.Latin1.GetString(payload);
        var backupdIndex = text.IndexOf("com.apple.backupd", StringComparison.Ordinal);
        if (backupdIndex < 0)
            return null;

        var window = text[backupdIndex..Math.Min(text.Length, backupdIndex + 96)];
        var match = DeviceSessionRegex.Match(window);
        return match.Success ? match.Value.ToLowerInvariant() : null;
    }

    private static ForegroundRestorePlist BuildFromText(string text)
    {
        var proto = Sanitize(FirstMatch(ProtoVersionRegex, text));
        var plistSha = Sanitize(FirstMatch(PlistShaRegex, text));
        var plistVer = Sanitize(FirstMatch(PlistVersionRegex, text));
        var clientInfo = Sanitize(FirstMatch(ClientInfoRegex, text));
        var hardwareId = FindHardwareNearMmcs(text);

        return new ForegroundRestorePlist(
            proto,
            plistSha,
            plistVer,
            hardwareId,
            string.IsNullOrWhiteSpace(clientInfo) ? null : clientInfo);
    }

    private static string FindHardwareNearMmcs(string text)
    {
        ReadOnlySpan<string> markers =
        [
            "x-apple-mmcs-plist-sha256",
            "x-apple-mmcs-proto-version",
            "Foreground Restore"
        ];

        foreach (var marker in markers)
        {
            var idx = text.IndexOf(marker, StringComparison.Ordinal);
            if (idx < 0)
                continue;

            var window = text[Math.Max(0, idx - 200)..Math.Min(text.Length, idx + 200)];
            var match = HardwareIdRegex.Match(window);
            if (match.Success)
                return match.Groups[1].Value.ToUpperInvariant();
        }

        return string.Empty;
    }

    private static string FirstMatch(Regex regex, string text)
    {
        var match = regex.Match(text);
        return match.Success ? match.Groups[1].Value : string.Empty;
    }

    private static string Sanitize(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return string.Empty;

        var sb = new StringBuilder(value.Length);
        foreach (var c in value.Trim())
        {
            if (c is >= ' ' and <= '~')
                sb.Append(c);
            else if (sb.Length > 0)
                break;
        }

        return sb.ToString().TrimStart(',');
    }

    private static bool IsValid(ForegroundRestorePlist? plist)
    {
        if (plist is null)
            return false;

        return plist.PlistSha256Base64.Length >= 40
               && plist.PlistSha256Base64.All(static c =>
                   char.IsLetterOrDigit(c) || c is '+' or '/' or '=')
               && plist.ProtoVersion.Contains('.', StringComparison.Ordinal)
               && plist.HardwareIdHex.Length == 64;
    }
}
