using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>Firma richiesta IDS (pypush <c>add_auth_signature</c>).</summary>
public static class IdsSigning
{
    public static byte[] GenerateNonce()
    {
        var nonce = new byte[1 + 8 + 8];
        nonce[0] = 0x01;
        var ms = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        BinaryPrimitives.WriteUInt64BigEndian(nonce.AsSpan(1, 8), ms);
        RandomNumberGenerator.Fill(nonce.AsSpan(9, 8));
        return nonce;
    }

    public static byte[] BuildPayload(
        string bagKey,
        string queryString,
        byte[] pushToken,
        byte[] body,
        byte[] nonce)
    {
        var bag = Encoding.UTF8.GetBytes(bagKey);
        var query = Encoding.UTF8.GetBytes(queryString ?? "");
        body ??= [];
        pushToken ??= [];

        using var ms = new MemoryStream();
        ms.Write(nonce);
        WriteLenPrefixed(ms, bag);
        WriteLenPrefixed(ms, query);
        WriteLenPrefixed(ms, body);
        WriteLenPrefixed(ms, pushToken);
        return ms.ToArray();
    }

    public static (string SigB64, string NonceB64) Sign(
        string privateKeyPem,
        string bagKey,
        string queryString,
        byte[] pushToken,
        byte[] body,
        byte[]? nonce = null)
    {
        nonce ??= GenerateNonce();
        var payload = BuildPayload(bagKey, queryString, pushToken, body, nonce);
        var key = LoadPrivateKey(privateKeyPem);
        var signer = SignerUtilities.GetSigner("SHA1withRSA");
        signer.Init(true, key);
        signer.BlockUpdate(payload, 0, payload.Length);
        var sig = signer.GenerateSignature();
        var prefixed = new byte[2 + sig.Length];
        prefixed[0] = 0x01;
        prefixed[1] = 0x01;
        Buffer.BlockCopy(sig, 0, prefixed, 2, sig.Length);
        return (Convert.ToBase64String(prefixed), Convert.ToBase64String(nonce));
    }

    public static void AddAuthAndPushSignatures(
        IDictionary<string, string> headers,
        byte[] body,
        string bagKey,
        string authKeyPem,
        string authCertPem,
        string pushKeyPem,
        string pushCertPem,
        byte[] pushToken,
        int? authNumber = 0)
    {
        var pushTokenB64 = Convert.ToBase64String(pushToken);
        var (pushSig, pushNonce) = Sign(pushKeyPem, bagKey, "", pushToken, body);
        headers["x-push-sig"] = pushSig;
        headers["x-push-nonce"] = pushNonce;
        headers["x-push-cert"] = DearmourPem(pushCertPem);
        headers["x-push-token"] = pushTokenB64;

        var (authSig, authNonce) = Sign(authKeyPem, bagKey, "", pushToken, body);
        var postfix = authNumber is null ? "" : "-" + authNumber.Value;
        headers["x-auth-sig" + postfix] = authSig;
        headers["x-auth-nonce" + postfix] = authNonce;
        headers["x-auth-cert" + postfix] = DearmourPem(authCertPem);
    }

    public static string DearmourPem(string pem)
    {
        var lines = pem.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .Where(l => !l.StartsWith("-----", StringComparison.Ordinal))
            .Select(l => l.Trim());
        return string.Concat(lines);
    }

    public static string ArmourCertDer(byte[] der)
    {
        var b64 = Convert.ToBase64String(der);
        var sb = new StringBuilder();
        sb.AppendLine("-----BEGIN CERTIFICATE-----");
        for (var i = 0; i < b64.Length; i += 64)
            sb.AppendLine(b64.Substring(i, Math.Min(64, b64.Length - i)));
        sb.Append("-----END CERTIFICATE-----");
        return sb.ToString();
    }

    public static byte[] GzipMtime0(byte[] data)
    {
        using var ms = new MemoryStream();
        using (var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionLevel.Optimal, leaveOpen: true))
            gz.Write(data, 0, data.Length);
        var compressed = ms.ToArray();
        if (compressed.Length >= 8)
        {
            compressed[4] = 0;
            compressed[5] = 0;
            compressed[6] = 0;
            compressed[7] = 0;
        }

        return compressed;
    }

    public static byte[]? TryGunzip(byte[] data)
    {
        if (data.Length < 2 || data[0] != 0x1F || data[1] != 0x8B)
            return null;
        try
        {
            using var input = new MemoryStream(data);
            using var gz = new System.IO.Compression.GZipStream(input, System.IO.Compression.CompressionMode.Decompress);
            using var output = new MemoryStream();
            gz.CopyTo(output);
            return output.ToArray();
        }
        catch
        {
            return null;
        }
    }

    private static void WriteLenPrefixed(Stream stream, byte[] data)
    {
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)data.Length);
        stream.Write(len);
        stream.Write(data);
    }

    private static AsymmetricKeyParameter LoadPrivateKey(string pem)
    {
        using var reader = new StringReader(pem);
        var obj = new PemReader(reader).ReadObject();
        return obj switch
        {
            AsymmetricCipherKeyPair pair => pair.Private,
            AsymmetricKeyParameter key => key,
            _ => throw new InvalidOperationException($"Chiave PEM non valida: {obj?.GetType().Name}"),
        };
    }

    public static string CompactWhitespace(string s) => Regex.Replace(s, @"\s+", "");
}
