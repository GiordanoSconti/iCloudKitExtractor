using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Auth;

public static class GsaSpdDecoder
{
    public static byte[] DecryptSpd(byte[] sessionKey, byte[] encryptedSpd)
    {
        var extraDataKey = Hmac(sessionKey, "extra data key:");
        var extraDataIv = Hmac(sessionKey, "extra data iv:")[..16];

        using var aes = Aes.Create();
        aes.Key = extraDataKey;
        aes.IV = extraDataIv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var decryptor = aes.CreateDecryptor();
        return decryptor.TransformFinalBlock(encryptedSpd, 0, encryptedSpd.Length);
    }

    public static (string Adsid, string GsIdmsToken)? TryParseCredentials(byte[] decryptedSpd)
    {
        foreach (var payload in EnumeratePlistPayloads(decryptedSpd))
        {
            try
            {
                var dict = AppleXmlPlist.Parse(payload);
                var credentials = FindCredentialsRecursive(dict);
                if (credentials is not null)
                    return credentials;
            }
            catch
            {
                // try next payload shape
            }
        }

        return null;
    }

    public static string BuildIdentityToken(string adsid, string gsIdmsToken) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"{adsid}:{gsIdmsToken}"));

    /// <summary>
    /// Mappa <c>t</c> dello spd: servizio → token stringa (PET, icloud.auth, …).
    /// Capture Account Info: appleid/settings usa Basic adsid:token lungo (~476),
    /// tipicamente da <c>com.apple.gs.icloud.auth</c> / cognato in <c>t</c>, non il
    /// GsIdmsToken corto (~260) usato solo per validate.
    /// </summary>
    public static Dictionary<string, string> TryParseServiceTokens(byte[] decryptedSpd)
    {
        var result = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var payload in EnumeratePlistPayloads(decryptedSpd))
        {
            try
            {
                var dict = AppleXmlPlist.Parse(payload);
                CollectServiceTokensRecursive(dict, result);
            }
            catch
            {
                // try next payload shape
            }
        }

        return result;
    }

    /// <summary>Token com.apple.gs.idms.pet da spd (stesso valore decodificato da X-Apple-PE-Token).</summary>
    public static string? TryParsePetToken(byte[] decryptedSpd)
    {
        var map = TryParseServiceTokens(decryptedSpd);
        if (map.TryGetValue("com.apple.gs.idms.pet", out var pet) && !string.IsNullOrEmpty(pet))
            return pet;
        return null;
    }

    public static string EncodeIdmsPetHeader(string petToken) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes($"com.apple.gs.idms.pet:{petToken}"));

    private static void CollectServiceTokensRecursive(object? node, Dictionary<string, string> into)
    {
        if (node is Dictionary<string, object?> dict)
        {
            if (dict.TryGetValue("t", out var tokensNode)
                && tokensNode is Dictionary<string, object?> tokens)
            {
                foreach (var (service, raw) in tokens)
                {
                    if (raw is not Dictionary<string, object?> entry)
                        continue;
                    var tok = GetToken(entry, "token");
                    if (!string.IsNullOrEmpty(tok))
                        into[service] = tok!;
                }
            }

            foreach (var value in dict.Values)
                CollectServiceTokensRecursive(value, into);
        }
        else if (node is IList<object?> list)
        {
            foreach (var item in list)
                CollectServiceTokensRecursive(item, into);
        }
    }

    private static (string Adsid, string GsIdmsToken)? FindCredentialsRecursive(object? node)
    {
        if (node is Dictionary<string, object?> dict)
        {
            var adsid = GetString(dict, "adsid");
            // Preferisci il GsIdmsToken più lungo se ce ne sono più (evita token corti nested).
            string? bestTok = null;
            CollectGsIdmsTokens(dict, ref bestTok);
            if (!string.IsNullOrEmpty(adsid) && !string.IsNullOrEmpty(bestTok))
                return (adsid, bestTok);

            // Fallback: primo adsid+GsIdmsToken nello stesso dict.
            var idmsToken = GetToken(dict, "GsIdmsToken");
            if (!string.IsNullOrEmpty(adsid) && !string.IsNullOrEmpty(idmsToken))
                return (adsid, idmsToken);

            foreach (var value in dict.Values)
            {
                var nested = FindCredentialsRecursive(value);
                if (nested is not null)
                    return nested;
            }
        }
        else if (node is IList<object?> list)
        {
            foreach (var item in list)
            {
                var nested = FindCredentialsRecursive(item);
                if (nested is not null)
                    return nested;
            }
        }

        return null;
    }

    private static void CollectGsIdmsTokens(Dictionary<string, object?> dict, ref string? bestTok)
    {
        var tok = GetToken(dict, "GsIdmsToken");
        if (!string.IsNullOrEmpty(tok)
            && (bestTok is null || tok!.Length > bestTok.Length))
            bestTok = tok;

        foreach (var value in dict.Values)
        {
            if (value is Dictionary<string, object?> child)
                CollectGsIdmsTokens(child, ref bestTok);
            else if (value is IList<object?> list)
            {
                foreach (var item in list)
                {
                    if (item is Dictionary<string, object?> d)
                        CollectGsIdmsTokens(d, ref bestTok);
                }
            }
        }
    }

    private static IEnumerable<byte[]> EnumeratePlistPayloads(byte[] decryptedSpd)
    {
        yield return decryptedSpd;

        var text = Encoding.UTF8.GetString(decryptedSpd);
        if (text.TrimStart().StartsWith("<dict", StringComparison.Ordinal))
        {
            yield return Encoding.UTF8.GetBytes(
                """
                <?xml version="1.0" encoding="UTF-8"?>
                <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
                <plist version="1.0">
                """ + text.Trim() + "</plist>");
        }
    }

    private static string? GetString(Dictionary<string, object?> dict, string key) =>
        dict.TryGetValue(key, out var value) ? value as string : null;

    private static string? GetToken(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value))
            return null;

        return value switch
        {
            string text => text,
            byte[] bytes => Convert.ToBase64String(bytes),
            _ => null
        };
    }

    private static byte[] Hmac(byte[] sessionKey, string label)
    {
        using var hmac = new HMACSHA256(sessionKey);
        return hmac.ComputeHash(Encoding.UTF8.GetBytes(label));
    }
}
