using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>Package C blob (token + public_key) as stored in the License field.</summary>
public sealed class AnisetteLicenseBundle
{
    [JsonPropertyName("token")]
    public string Token { get; set; } = "";

    [JsonPropertyName("public_key")]
    public string PublicKey { get; set; } = "";

    [JsonPropertyName("license_id")]
    public string LicenseId { get; set; } = "";

    [JsonPropertyName("issued_at")]
    public long IssuedAtUnix { get; set; }

    public static bool TryParse(string? raw, out AnisetteLicenseBundle? bundle)
    {
        bundle = null;
        if (string.IsNullOrWhiteSpace(raw))
            return false;
        var s = raw.Trim();
        if (s.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            s = s[7..].Trim();
        try
        {
            var bytes = Convert.FromBase64String(Pad(s));
            if (bytes.Length == 0 || bytes[0] is not ((byte)'{' or (byte)'['))
                return false;
            bundle = JsonSerializer.Deserialize<AnisetteLicenseBundle>(bytes);
            return bundle is not null && !string.IsNullOrWhiteSpace(bundle.Token);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Bearer value: prefer raw token from bundle; else pass-through.</summary>
    public static string ResolveBearerToken(string? licenseField)
    {
        if (string.IsNullOrWhiteSpace(licenseField))
            return "";
        if (TryParse(licenseField, out var bundle) && bundle is not null)
            return bundle.Token;
        return licenseField.Trim();
    }

    private static string Pad(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return padded;
    }
}
