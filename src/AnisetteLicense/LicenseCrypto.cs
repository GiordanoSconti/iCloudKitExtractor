using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Crypto.Signers;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Utilities.IO.Pem;

namespace iCloudKitExtractor.AnisetteLicense;

public static class LicenseCrypto
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = null,
        WriteIndented = false,
        DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull,
    };

    public static void GenerateKeyPair(string privatePath, string publicPath)
    {
        var gen = new Ed25519KeyPairGenerator();
        gen.Init(new Ed25519KeyGenerationParameters(new SecureRandom()));
        var pair = gen.GenerateKeyPair();
        var priv = (Ed25519PrivateKeyParameters)pair.Private;
        var pub = (Ed25519PublicKeyParameters)pair.Public;

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(privatePath))!);
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(publicPath))!);

        WritePem(privatePath, "PRIVATE KEY", priv.GetEncoded());
        WritePem(publicPath, "PUBLIC KEY", pub.GetEncoded());
    }

    public static string IssueToken(LicensePayload payload, string privateKeyPath)
    {
        var payloadJson = JsonSerializer.Serialize(payload, JsonOpts);
        var payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        var priv = LoadPrivateKey(privateKeyPath);
        var signer = new Ed25519Signer();
        signer.Init(true, priv);
        var msg = Encoding.UTF8.GetBytes(payloadB64);
        signer.BlockUpdate(msg, 0, msg.Length);
        var sig = signer.GenerateSignature();
        return payloadB64 + "." + Base64UrlEncode(sig);
    }

    /// <summary>Package C: Base64(JSON{token, public_key, license_id, issued_at}).</summary>
    public static LicenseBundle IssueBundle(LicensePayload payload, string privateKeyPath, string publicKeyPath)
    {
        var token = IssueToken(payload, privateKeyPath);
        var pubRaw = LoadPublicKey(publicKeyPath).GetEncoded();
        return new LicenseBundle
        {
            Token = token,
            PublicKey = Convert.ToBase64String(pubRaw),
            LicenseId = payload.LicenseId,
            IssuedAtUnix = payload.IssuedAtUnix,
        };
    }

    public static string IssueBundleBase64(LicensePayload payload, string privateKeyPath, string publicKeyPath) =>
        IssueBundle(payload, privateKeyPath, publicKeyPath).ToBase64();

    /// <summary>
    /// Accepts either a Package-C Base64 bundle or a raw <c>payload.sig</c> token.
    /// Returns the Ed25519 token used for signature verification.
    /// </summary>
    public static bool TryExtractToken(string? bearerOrBundle, out string token, out LicenseBundle? bundle, out string error)
    {
        token = "";
        bundle = null;
        error = "";
        if (string.IsNullOrWhiteSpace(bearerOrBundle))
        {
            error = "empty license";
            return false;
        }

        var s = bearerOrBundle.Trim();
        if (s.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            s = s[7..].Trim();

        if (LicenseBundle.TryParseBase64(s, out bundle, out _))
        {
            token = bundle!.Token;
            return true;
        }

        // Raw token: payload.signature
        if (s.Contains('.') && s.Split('.').Length == 2)
        {
            token = s;
            return true;
        }

        error = "license must be Base64 bundle or payload.signature token";
        return false;
    }

    public static string ReadPublicKeyBase64(string publicKeyPath)
    {
        var pub = LoadPublicKey(publicKeyPath);
        return Convert.ToBase64String(pub.GetEncoded());
    }

    public static bool PublicKeyMatches(string publicKeyPath, string? bundlePublicKeyBase64)
    {
        if (string.IsNullOrWhiteSpace(bundlePublicKeyBase64))
            return true;
        try
        {
            var expected = ReadPublicKeyBase64(publicKeyPath);
            var a = Convert.FromBase64String(PadStd(bundlePublicKeyBase64.Trim()));
            var b = Convert.FromBase64String(PadStd(expected));
            return CryptographicEquals(a, b);
        }
        catch
        {
            return false;
        }
    }

    private static string PadStd(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return padded;
    }

    private static bool CryptographicEquals(byte[] a, byte[] b)
    {
        if (a.Length != b.Length)
            return false;
        var diff = 0;
        for (var i = 0; i < a.Length; i++)
            diff |= a[i] ^ b[i];
        return diff == 0;
    }

    public static bool TryVerify(string token, string publicKeyPath, out LicensePayload? payload, out string error)
    {
        payload = null;
        error = "";
        var parts = token.Split('.', 2);
        if (parts.Length != 2)
        {
            error = "token format must be payload.signature";
            return false;
        }

        byte[] payloadBytes;
        byte[] sigBytes;
        try
        {
            payloadBytes = Base64UrlDecode(parts[0]);
            sigBytes = Base64UrlDecode(parts[1]);
        }
        catch (Exception ex)
        {
            error = "base64url decode failed: " + ex.Message;
            return false;
        }

        var pub = LoadPublicKey(publicKeyPath);
        var verifier = new Ed25519Signer();
        verifier.Init(false, pub);
        var msg = Encoding.UTF8.GetBytes(parts[0]);
        verifier.BlockUpdate(msg, 0, msg.Length);
        if (!verifier.VerifySignature(sigBytes))
        {
            error = "invalid signature";
            return false;
        }

        try
        {
            payload = JsonSerializer.Deserialize<LicensePayload>(payloadBytes, JsonOpts);
        }
        catch (Exception ex)
        {
            error = "payload JSON: " + ex.Message;
            return false;
        }

        if (payload is null || string.IsNullOrWhiteSpace(payload.LicenseId))
        {
            error = "missing license_id";
            return false;
        }

        var now = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        if (payload.ExpiresAtUnix is long exp && exp < now)
        {
            error = "license expired";
            return false;
        }

        return true;
    }

    public static Ed25519PrivateKeyParameters LoadPrivateKey(string path)
    {
        var raw = ReadPemBody(path);
        return new Ed25519PrivateKeyParameters(raw, 0);
    }

    public static Ed25519PublicKeyParameters LoadPublicKey(string path)
    {
        var raw = ReadPemBody(path);
        return new Ed25519PublicKeyParameters(raw, 0);
    }

    private static void WritePem(string path, string type, byte[] body)
    {
        using var sw = new StreamWriter(path, false, new UTF8Encoding(false));
        var writer = new PemWriter(sw);
        writer.WriteObject(new PemObject(type, body));
    }

    private static byte[] ReadPemBody(string path)
    {
        using var sr = new StreamReader(path, Encoding.UTF8);
        var reader = new PemReader(sr);
        var obj = reader.ReadPemObject()
            ?? throw new InvalidOperationException("Empty PEM: " + path);
        return obj.Content;
    }

    public static string Base64UrlEncode(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static byte[] Base64UrlDecode(string s)
    {
        var padded = s.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}
