using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// <c>PCSFPCopyDecryptedData</c> (+0x909010) — envelope field CloudKit.
/// Diverso da <see cref="PcsGcmDataA"/> (InflatableDonkey: tag dopo IV).
/// Layout: AAD(header) ‖ IV12 ‖ CT ‖ tag; seconda AAD = CreateDecryptionLabel.
/// </summary>
public static class PcsFpFieldCrypto
{
    /// <summary>
    /// Decifra envelope PCSFP. <paramref name="fieldKey16"/> = HMAC(unwrap,"encryption key key m")[:16].
    /// <paramref name="decryptionLabel"/> = bytes di CreateDecryptionLabel (KeyID string), può essere vuoto.
    /// </summary>
    public static byte[] Decrypt(
        ReadOnlySpan<byte> fieldKey16,
        ReadOnlySpan<byte> envelope,
        ReadOnlySpan<byte> decryptionLabel = default)
    {
        if (fieldKey16.Length < 16)
            throw new CryptographicException("PCSFP field key richiede 16 B");
        if (envelope.IsEmpty)
            throw new CryptographicException("PCSFP envelope vuoto");

        var encType = envelope[0];
        var (tagLen, headerLen) = encType switch
        {
            0 => (8, 1),
            1 => (12, 1),
            2 => (12, 3),
            3 when envelope.Length >= 4 => (12, 3 + envelope[3] + 1),
            _ => throw new CryptographicException($"Unsupported encryption type {encType}")
        };

        // Oracle: IV sempre 12 (anche type 0).
        const int ivLen = 12;
        var overhead = headerLen + ivLen + tagLen;
        if (envelope.Length < overhead)
            throw new CryptographicException("PCSFP envelope troppo corto");

        var aad = envelope[..headerLen].ToArray();
        var iv = envelope.Slice(headerLen, ivLen).ToArray();
        var tag = envelope[^tagLen..].ToArray();
        var ct = envelope.Slice(headerLen + ivLen, envelope.Length - overhead).ToArray();

        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(
            false,
            new AeadParameters(new KeyParameter(fieldKey16[..16].ToArray()), tagLen * 8, iv, aad));
        if (!decryptionLabel.IsEmpty)
            cipher.ProcessAadBytes(decryptionLabel.ToArray(), 0, decryptionLabel.Length);

        var input = new byte[ct.Length + tag.Length];
        Buffer.BlockCopy(ct, 0, input, 0, ct.Length);
        Buffer.BlockCopy(tag, 0, input, ct.Length, tag.Length);
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var n = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        n += cipher.DoFinal(output, n);
        return output.AsSpan(0, n).ToArray();
    }

    public static byte[]? TryDecrypt(
        ReadOnlySpan<byte> fieldKey16,
        ReadOnlySpan<byte> envelope,
        ReadOnlySpan<byte> decryptionLabel = default)
    {
        try
        {
            return Decrypt(fieldKey16, envelope, decryptionLabel);
        }
        catch
        {
            return null;
        }
    }

    public static byte[]? TryDecryptWithLabels(
        ReadOnlySpan<byte> fieldKey16,
        ReadOnlySpan<byte> envelope,
        params string[] labels)
    {
        foreach (var label in labels)
        {
            if (string.IsNullOrEmpty(label))
                continue;
            var pt = TryDecrypt(fieldKey16, envelope, Encoding.UTF8.GetBytes(label));
            if (pt is { Length: > 0 })
                return pt;
        }

        return TryDecrypt(fieldKey16, envelope);
    }
}
