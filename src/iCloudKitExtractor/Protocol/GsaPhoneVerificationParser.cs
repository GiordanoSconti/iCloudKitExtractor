using System.Text.Json;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Parser risposta GET gsa.apple.com/auth/verify/trusteddevice (phoneNumberVerification).
/// </summary>
public static class GsaPhoneVerificationParser
{
    public static PhoneVerificationOptions Parse(byte[] body)
    {
        if (body.Length == 0)
            return new PhoneVerificationOptions();

        using var doc = JsonDocument.Parse(body);
        return Parse(doc.RootElement);
    }

    public static PhoneVerificationOptions Parse(JsonElement root)
    {
        var deviceCount = root.TryGetProperty("trustedDeviceCount", out var dc) && dc.TryGetInt32(out var n)
            ? n
            : 0;

        var codeLen = 6;
        if (root.TryGetProperty("securityCode", out var sc)
            && sc.TryGetProperty("length", out var lenEl)
            && lenEl.TryGetInt32(out var len))
        {
            codeLen = len;
        }

        if (!root.TryGetProperty("phoneNumberVerification", out var pnv))
        {
            return new PhoneVerificationOptions
            {
                TrustedDeviceCount = deviceCount,
                SecurityCodeLength = codeLen,
            };
        }

        if (pnv.TryGetProperty("securityCode", out var pnvSc)
            && pnvSc.TryGetProperty("length", out var pnvLen)
            && pnvLen.TryGetInt32(out var pnvCodeLen))
        {
            codeLen = pnvCodeLen;
        }

        var phones = new List<TrustedPhoneNumber>();
        if (pnv.TryGetProperty("trustedPhoneNumbers", out var arr) && arr.ValueKind == JsonValueKind.Array)
        {
            foreach (var item in arr.EnumerateArray())
                phones.Add(ParsePhone(item));
        }
        else if (pnv.TryGetProperty("trustedPhoneNumber", out var single))
        {
            phones.Add(ParsePhone(single));
        }

        return new PhoneVerificationOptions
        {
            TrustedPhoneNumbers = phones,
            TrustedDeviceCount = deviceCount,
            SecurityCodeLength = codeLen,
        };
    }

    private static TrustedPhoneNumber ParsePhone(JsonElement item) =>
        new()
        {
            Id = item.TryGetProperty("id", out var id) && id.TryGetInt32(out var pid) ? pid : 1,
            ObfuscatedNumber = GetString(item, "obfuscatedNumber"),
            NumberWithDialCode = GetString(item, "numberWithDialCode"),
            LastTwoDigits = GetString(item, "lastTwoDigits"),
            PushMode = GetString(item, "pushMode") ?? "sms",
            NonFteu = item.TryGetProperty("nonFTEU", out var nf) && nf.ValueKind == JsonValueKind.True,
        };

    private static string? GetString(JsonElement item, string name) =>
        item.TryGetProperty(name, out var el) && el.ValueKind == JsonValueKind.String
            ? el.GetString()
            : null;
}
