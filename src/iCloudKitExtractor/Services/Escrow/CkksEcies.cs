using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Octagon/CKKS ECIES (appleservices <c>octagon.UnwrapECIES</c>):
/// P-384 ECDH → X9.63-KDF-SHA256(48) → AES-256-GCM nonce=16.
/// Blob = ephPub(97) ‖ ciphertext ‖ tag(16).
/// </summary>
public static class CkksEcies
{
    public const int P384PointLen = 97;
    public const int KdfLen = 48;
    public const int NonceLen = 16;
    public const int TagLen = 16;

    public static byte[] Unwrap(byte[] recipientPkcs8, ReadOnlySpan<byte> blob)
    {
        if (blob.Length < P384PointLen + TagLen)
            throw new CryptographicException($"ECIES blob troppo corto: {blob.Length} B");

        using var priv = ECDiffieHellman.Create();
        priv.ImportPkcs8PrivateKey(recipientPkcs8, out _);

        var ephPubBytes = blob[..P384PointLen].ToArray();
        if (ephPubBytes[0] != 0x04)
            throw new CryptographicException("ECIES ephemeral non uncompressed (atteso 0x04)");

        using var eph = ECDiffieHellman.Create();
        eph.ImportParameters(new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP384,
            Q = new ECPoint
            {
                X = ephPubBytes.AsSpan(1, 48).ToArray(),
                Y = ephPubBytes.AsSpan(49, 48).ToArray()
            }
        });

        var z = priv.DeriveRawSecretAgreement(eph.PublicKey);
        var material = X963KdfSha256(z, ephPubBytes, KdfLen);
        var aesKey = material.AsSpan(0, 32).ToArray();
        var nonce = material.AsSpan(32, NonceLen).ToArray();
        var sealedCt = blob[P384PointLen..].ToArray(); // ct ‖ tag

        return AesGcmOpen(aesKey, nonce, sealedCt);
    }

    private static byte[] X963KdfSha256(byte[] z, byte[] sharedInfo, int outLen)
    {
        var outBuf = new byte[((outLen + 31) / 32) * 32];
        var filled = 0;
        Span<byte> counter = stackalloc byte[4];
        uint c = 1;
        while (filled < outLen)
        {
            BinaryPrimitives.WriteUInt32BigEndian(counter, c++);
            var block = SHA256.HashData(Concat(z, counter.ToArray(), sharedInfo));
            Buffer.BlockCopy(block, 0, outBuf, filled, block.Length);
            filled += block.Length;
        }

        return outBuf.AsSpan(0, outLen).ToArray();
    }

    private static byte[] AesGcmOpen(byte[] key, byte[] nonce, byte[] ciphertextAndTag)
    {
        if (ciphertextAndTag.Length < TagLen)
            throw new CryptographicException("ECIES GCM ciphertext troppo corto");

        var ctLen = ciphertextAndTag.Length - TagLen;
        var ciphertext = ciphertextAndTag.AsSpan(0, ctLen).ToArray();
        var tag = ciphertextAndTag.AsSpan(ctLen, TagLen).ToArray();

        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(false, new AeadParameters(new KeyParameter(key), TagLen * 8, nonce));
        var input = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, input, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, input, ciphertext.Length, tag.Length);
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        len += cipher.DoFinal(output, len);
        return output[..len];
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var n = parts.Sum(p => p.Length);
        var buf = new byte[n];
        var o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, buf, o, p.Length);
            o += p.Length;
        }

        return buf;
    }
}
