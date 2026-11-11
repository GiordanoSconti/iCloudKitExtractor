using System.IO;
using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Services.Ids;

namespace iCloudKitExtractor.Services.IMessage;

/// <summary>
/// Minimal Madrid payload helpers for the text MVP.
/// Full NGM pairwise sessions (pypush/rustpush) are iterated once live captures confirm wire format;
/// for now we wrap plaintext in a tagged envelope so send/receive plumbing can be tested end-to-end
/// against our own lab devices, and decrypt clear/legacy payloads when Apple delivers them.
/// </summary>
public static class MadridMessageCrypto
{
    private static readonly byte[] Magic = "IKE1"u8.ToArray();

    public static byte[] EncryptForRemote(string plaintext, IdsRemoteIdentity remote, IdsIdentity local)
    {
        ArgumentNullException.ThrowIfNull(local);
        var body = Encoding.UTF8.GetBytes(plaintext ?? "");
        // Prefer RSA-OAEP against remote legacy identity when present (pypush-style first hop).
        if (remote.PublicIdentity is { Length: > 0 }
            && TryEncryptRsaOaep(remote.PublicIdentity, body, out var cipher))
        {
            return Prefixed(0x01, cipher);
        }

        // Lab fallback: AES-GCM with key derived from local device key fingerprint (not production E2E).
        using var aes = new AesGcm(DeriveLabKey(local), 16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        var tag = new byte[16];
        var ct = new byte[body.Length];
        aes.Encrypt(nonce, body, ct, tag);
        var packed = new byte[nonce.Length + tag.Length + ct.Length];
        Buffer.BlockCopy(nonce, 0, packed, 0, nonce.Length);
        Buffer.BlockCopy(tag, 0, packed, nonce.Length, tag.Length);
        Buffer.BlockCopy(ct, 0, packed, nonce.Length + tag.Length, ct.Length);
        return Prefixed(0x02, packed);
    }

    public static bool TryDecrypt(byte[] payload, IdsIdentity local, out string plaintext)
    {
        plaintext = "";
        if (payload is null || payload.Length == 0)
            return false;

        // Clear UTF-8 text (some system/control messages).
        if (LooksLikeUtf8Text(payload))
        {
            plaintext = Encoding.UTF8.GetString(payload).Trim();
            return plaintext.Length > 0;
        }

        if (payload.Length > Magic.Length + 1
            && payload.AsSpan(0, Magic.Length).SequenceEqual(Magic))
        {
            var kind = payload[Magic.Length];
            var body = payload.AsSpan(Magic.Length + 1).ToArray();
            if (kind == 0x01 && TryDecryptRsaOaep(local, body, out var clear))
            {
                plaintext = Encoding.UTF8.GetString(clear);
                return true;
            }

            if (kind == 0x02 && body.Length > 28)
            {
                try
                {
                    var nonce = body.AsSpan(0, 12);
                    var tag = body.AsSpan(12, 16);
                    var ct = body.AsSpan(28);
                    var pt = new byte[ct.Length];
                    using var aes = new AesGcm(DeriveLabKey(local), 16);
                    aes.Decrypt(nonce, ct, tag, pt);
                    plaintext = Encoding.UTF8.GetString(pt);
                    return true;
                }
                catch
                {
                    return false;
                }
            }
        }

        // Best-effort: extract printable ASCII runs (debug).
        var sb = new StringBuilder();
        foreach (var b in payload)
        {
            if (b is >= 32 and <= 126)
                sb.Append((char)b);
            else if (sb.Length > 0 && sb[^1] != ' ')
                sb.Append(' ');
        }
        var guess = sb.ToString().Trim();
        if (guess.Length >= 3)
        {
            plaintext = guess;
            return true;
        }

        return false;
    }

    private static byte[] Prefixed(byte kind, byte[] body)
    {
        var all = new byte[Magic.Length + 1 + body.Length];
        Buffer.BlockCopy(Magic, 0, all, 0, Magic.Length);
        all[Magic.Length] = kind;
        Buffer.BlockCopy(body, 0, all, Magic.Length + 1, body.Length);
        return all;
    }

    private static byte[] DeriveLabKey(IdsIdentity local)
    {
        var material = local.EncodeLegacyIdentity();
        return SHA256.HashData(material);
    }

    private static bool LooksLikeUtf8Text(byte[] data)
    {
        if (data.Length == 0 || data.Length > 4096)
            return false;
        var printable = 0;
        foreach (var b in data)
        {
            if (b is 9 or 10 or 13 or (>= 32 and <= 126) or >= 0xC0)
                printable++;
        }
        return printable >= data.Length * 0.85;
    }

    private static bool TryEncryptRsaOaep(byte[] publicBlob, byte[] plaintext, out byte[] cipher)
    {
        cipher = [];
        try
        {
            // Legacy IDS identity often embeds an RSA SPKI; try ImportSubjectPublicKeyInfo.
            using var rsa = RSA.Create();
            rsa.ImportSubjectPublicKeyInfo(publicBlob, out _);
            cipher = rsa.Encrypt(plaintext, RSAEncryptionPadding.OaepSHA1);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryDecryptRsaOaep(IdsIdentity local, byte[] cipher, out byte[] clear)
    {
        clear = [];
        try
        {
            // IdsIdentity persists enc RSA key under IdsStorage.
            if (!File.Exists(IdsStorage.EncryptionKeyPemPath))
                return false;
            var pem = File.ReadAllText(IdsStorage.EncryptionKeyPemPath);
            using var rsa = RSA.Create();
            rsa.ImportFromPem(pem);
            clear = rsa.Decrypt(cipher, RSAEncryptionPadding.OaepSHA1);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
