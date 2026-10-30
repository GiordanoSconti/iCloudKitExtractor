using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace iCloudKitExtractor.AnisetteLicense;

/// <summary>
/// Package C: signed Ed25519 token + server public key, stored/transmitted as one Base64 blob.
/// </summary>
public sealed class LicenseBundle
{
    [JsonPropertyName("token")]
    public string Token { get; set; } = "";

    [JsonPropertyName("public_key")]
    public string PublicKey { get; set; } = "";

    [JsonPropertyName("license_id")]
    public string LicenseId { get; set; } = "";

    [JsonPropertyName("issued_at")]
    public long IssuedAtUnix { get; set; }

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    public string ToBase64()
    {
        var json = JsonSerializer.Serialize(this, JsonOpts);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(json));
    }

    public static bool TryParseBase64(string? raw, out LicenseBundle? bundle, out string error)
    {
        bundle = null;
        error = "";
        if (string.IsNullOrWhiteSpace(raw))
        {
            error = "empty bundle";
            return false;
        }

        var s = raw.Trim();
        // Strip accidental "Bearer " prefix
        if (s.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            s = s[7..].Trim();

        try
        {
            // Bundle is standard Base64 of JSON. Raw tokens look like payload.sig (Base64Url).
            if (s.Contains('.') && !LooksLikeJsonBase64(s))
            {
                error = "not a license bundle (looks like raw token)";
                return false;
            }

            byte[] bytes;
            try
            {
                bytes = Convert.FromBase64String(PadBase64(s));
            }
            catch
            {
                error = "invalid Base64";
                return false;
            }

            var json = Encoding.UTF8.GetString(bytes);
            bundle = JsonSerializer.Deserialize<LicenseBundle>(json, JsonOpts);
            if (bundle is null || string.IsNullOrWhiteSpace(bundle.Token))
            {
                error = "bundle missing token";
                bundle = null;
                return false;
            }

            return true;
        }
        catch (Exception ex)
        {
            error = "bundle parse: " + ex.Message;
            return false;
        }
    }

    private static bool LooksLikeJsonBase64(string s)
    {
        try
        {
            var bytes = Convert.FromBase64String(PadBase64(s));
            if (bytes.Length == 0)
                return false;
            var c = (char)bytes[0];
            return c is '{' or '[';
        }
        catch
        {
            return false;
        }
    }

    private static string PadBase64(string s)
    {
        var padded = s.Trim().Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return padded;
    }
}
