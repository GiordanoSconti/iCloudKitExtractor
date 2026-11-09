using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Agreement;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Cifratura NGM / pair-ec (OuterMessage / InnerMessage) per messaging Alloy.
/// Allineata alla descrizione Apple Wiki + rustpush ids.proto.
/// </summary>
public static class IdsNgmCrypto
{
    private static readonly byte[] HkdfSalt = Encoding.UTF8.GetBytes("LastPawn-MessageKeys");

    public static byte[] Encrypt(
        IdsIdentity local,
        byte[] peerPreKeyCompact,
        byte[] peerDevicePublicCompact,
        byte[] plaintext,
        uint counter)
    {
        ArgumentNullException.ThrowIfNull(local);
        ArgumentNullException.ThrowIfNull(peerPreKeyCompact);
        ArgumentNullException.ThrowIfNull(peerDevicePublicCompact);
        ArgumentNullException.ThrowIfNull(plaintext);

        var inner = new ProtobufWriter();
        inner.WriteBytes(1, plaintext);
        inner.WriteVarint(2, counter);
        var innerBytes = PadToBlock(inner.ToArray());

        var ephPriv = GenerateCompactPrivate();
        var ephPub = CompactPublicFromPrivate(ephPriv);
        var shared = EcdhCompact(ephPriv, peerPreKeyCompact);
        var (aesKey, iv) = DeriveMessageKeys(shared);
        var ciphertext = AesCtr64(aesKey, iv, innerBytes);

        // Signature: shared || targetPreKey || msgEph || targetDevice || ciphertext
        using var sigPayload = new MemoryStream();
        sigPayload.Write(shared);
        sigPayload.Write(peerPreKeyCompact);
        sigPayload.Write(ephPub);
        sigPayload.Write(peerDevicePublicCompact);
        sigPayload.Write(ciphertext);
        var digest = SHA256.HashData(sigPayload.ToArray());
        var sigRaw = SignDevice(local.DeviceKeyPem, digest);

        var validator = BuildValidator(
            CompactPublicFromPrivate(LoadEcPrivate(local.DeviceKeyPem)),
            peerDevicePublicCompact,
            peerPreKeyCompact);

        var outer = new ProtobufWriter();
        outer.WriteBytes(1, ciphertext); // payload
        outer.WriteBytes(2, ephPub); // key (ephemeral)
        outer.WriteBytes(3, sigRaw); // signature
        outer.WriteBytes(99, validator);
        return outer.ToArray();
    }

    public static byte[]? TryDecrypt(
        IdsIdentity local,
        byte[] outerMessage,
        out string? error)
    {
        error = null;
        try
        {
            byte[]? payload = null;
            byte[]? ephKey = null;
            byte[]? signature = null;
            var reader = new ProtobufReader(outerMessage);
            while (reader.HasMore)
            {
                var (fn, wt) = reader.ReadTag();
                if (wt != 2)
                {
                    reader.SkipField(wt);
                    continue;
                }

                var data = reader.ReadLengthDelimited();
                switch (fn)
                {
                    case 1: payload = data; break;
                    case 2: ephKey = data; break;
                    case 3: signature = data; break;
                }
            }

            if (payload is null || ephKey is null)
            {
                error = "OuterMessage incompleto.";
                return null;
            }

            var prePub = CompactPublicFromPrivate(LoadEcPrivate(local.PreKeyPem));
            var shared = EcdhCompact(LoadEcPrivate(local.PreKeyPem), ephKey);
            // Also try device key as ECDH peer if prekey fails structurally — keep prekey path.
            _ = prePub;
            _ = signature;

            var (aesKey, iv) = DeriveMessageKeys(shared);
            var innerPadded = AesCtr64(aesKey, iv, payload);
            var inner = StripPadding(innerPadded);
            var innerReader = new ProtobufReader(inner);
            while (innerReader.HasMore)
            {
                var (fn, wt) = innerReader.ReadTag();
                if (fn == 1 && wt == 2)
                    return innerReader.ReadLengthDelimited();
                innerReader.SkipField(wt);
            }

            error = "InnerMessage senza field message.";
            return null;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return null;
        }
    }

    /// <summary>Estrae la prekey compact (32 B) da PreKeyData protobuf.</summary>
    public static byte[]? TryParsePreKeyPublic(byte[]? preKeyData)
    {
        if (preKeyData is null || preKeyData.Length == 0)
            return null;
        try
        {
            var reader = new ProtobufReader(preKeyData);
            while (reader.HasMore)
            {
                var (fn, wt) = reader.ReadTag();
                if (fn == 1 && wt == 2)
                    return reader.ReadLengthDelimited();
                reader.SkipField(wt);
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    public static uint NextCounter(IdsIdentity local, byte[] peerPreKey, byte[] peerDevice)
    {
        var selfDev = CompactPublicFromPrivate(LoadEcPrivate(local.DeviceKeyPem));
        using var ms = new MemoryStream();
        ms.Write(selfDev);
        ms.Write(peerPreKey);
        ms.Write(peerDevice);
        var hash = SHA256.HashData(ms.ToArray());
        return BinaryPrimitives.ReadUInt32BigEndian(hash.AsSpan(0, 4));
    }

    private static (byte[] AesKey, byte[] Iv) DeriveMessageKeys(byte[] sharedSecret)
    {
        // HKDF-SHA256, salt LastPawn-MessageKeys, info empty → 48 bytes
        var prk = HKDF.Extract(HashAlgorithmName.SHA256, sharedSecret, HkdfSalt);
        var okm = HKDF.Expand(HashAlgorithmName.SHA256, prk, 48, info: Array.Empty<byte>());
        return (okm[..32], okm[32..48]);
    }

    private static byte[] AesCtr64(byte[] key, byte[] iv, byte[] data)
    {
        // Contatore 64-bit nella seconda metà del blocco (nonstandard Apple).
        var output = new byte[data.Length];
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        using var enc = aes.CreateEncryptor();
        var counterBlock = new byte[16];
        Buffer.BlockCopy(iv, 0, counterBlock, 0, Math.Min(16, iv.Length));
        ulong counter = BinaryPrimitives.ReadUInt64BigEndian(counterBlock.AsSpan(8, 8));
        var keystream = new byte[16];
        var offset = 0;
        while (offset < data.Length)
        {
            BinaryPrimitives.WriteUInt64BigEndian(counterBlock.AsSpan(8, 8), counter);
            enc.TransformBlock(counterBlock, 0, 16, keystream, 0);
            var n = Math.Min(16, data.Length - offset);
            for (var i = 0; i < n; i++)
                output[offset + i] = (byte)(data[offset + i] ^ keystream[i]);
            offset += n;
            counter++;
        }

        return output;
    }

    private static byte[] PadToBlock(byte[] data)
    {
        var pad = 16 - (data.Length % 16);
        if (pad == 0)
            pad = 16;
        var output = new byte[data.Length + pad + 4];
        Buffer.BlockCopy(data, 0, output, 0, data.Length);
        RandomNumberGenerator.Fill(output.AsSpan(data.Length, pad));
        BinaryPrimitives.WriteUInt32LittleEndian(output.AsSpan(data.Length + pad, 4), (uint)pad);
        return output;
    }

    private static byte[] StripPadding(byte[] data)
    {
        if (data.Length < 4)
            return data;
        var pad = BinaryPrimitives.ReadUInt32LittleEndian(data.AsSpan(data.Length - 4, 4));
        if (pad > 16 || pad + 4 > data.Length)
            return data;
        return data[..(data.Length - (int)pad - 4)];
    }

    private static byte[] BuildValidator(byte[] selfDevice, byte[] peerDevice, byte[] peerPre)
    {
        // 7 byte: first 2 of each key + 0x0c
        var v = new byte[7];
        v[0] = selfDevice[0];
        v[1] = selfDevice[1];
        v[2] = peerDevice[0];
        v[3] = peerDevice[1];
        v[4] = peerPre[0];
        v[5] = peerPre[1];
        v[6] = 0x0c;
        return v;
    }

    private static byte[] SignDevice(string deviceKeyPem, byte[] digest)
    {
        var priv = LoadEcPrivate(deviceKeyPem);
        var signer = SignerUtilities.GetSigner("NONEwithECDSA");
        signer.Init(true, priv);
        signer.BlockUpdate(digest, 0, digest.Length);
        var der = signer.GenerateSignature();
        return DerEcdsaToRaw64(der);
    }

    private static byte[] DerEcdsaToRaw64(byte[] der)
    {
        var i = 0;
        if (der[i++] != 0x30)
            throw new InvalidOperationException("ECDSA DER.");
        _ = ReadDerLen(der, ref i);
        if (der[i++] != 0x02)
            throw new InvalidOperationException("ECDSA r.");
        var rLen = ReadDerLen(der, ref i);
        var r = der.AsSpan(i, rLen).ToArray();
        i += rLen;
        if (der[i++] != 0x02)
            throw new InvalidOperationException("ECDSA s.");
        var sLen = ReadDerLen(der, ref i);
        var s = der.AsSpan(i, sLen).ToArray();
        if (r.Length > 0 && r[0] == 0)
            r = r[1..];
        if (s.Length > 0 && s[0] == 0)
            s = s[1..];
        var raw = new byte[64];
        Buffer.BlockCopy(PadLeft(r, 32), 0, raw, 0, 32);
        Buffer.BlockCopy(PadLeft(s, 32), 0, raw, 32, 32);
        return raw;
    }

    private static int ReadDerLen(byte[] data, ref int i)
    {
        var b = data[i++];
        if (b < 0x80)
            return b;
        var n = b & 0x7F;
        var len = 0;
        for (var k = 0; k < n; k++)
            len = (len << 8) | data[i++];
        return len;
    }

    private static ECPrivateKeyParameters GenerateCompactPrivate()
    {
        var curve = SecNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
        var dom = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H);
        for (var attempt = 0; attempt < 64; attempt++)
        {
            var gen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            gen.Init(new ECKeyGenerationParameters(dom, new SecureRandom()));
            var pair = gen.GenerateKeyPair();
            var pub = (ECPublicKeyParameters)pair.Public;
            var y = pub.Q.AffineYCoord.ToBigInteger();
            var p = pub.Parameters.Curve.Field.Characteristic;
            if (y.CompareTo(p.Subtract(y)) <= 0)
                return (ECPrivateKeyParameters)pair.Private;
        }

        throw new InvalidOperationException("Ephemeral EC compact non generabile.");
    }

    private static byte[] CompactPublicFromPrivate(ECPrivateKeyParameters priv)
    {
        var q = priv.Parameters.G.Multiply(priv.D).Normalize();
        return PadLeft(q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(), 32);
    }

    private static byte[] EcdhCompact(ECPrivateKeyParameters priv, byte[] peerCompactX)
    {
        var peerPub = DecompressCompact(peerCompactX, priv.Parameters);
        var agree = new ECDHBasicAgreement();
        agree.Init(priv);
        var shared = agree.CalculateAgreement(peerPub);
        return PadLeft(shared.ToByteArrayUnsigned(), 32);
    }

    private static ECPublicKeyParameters DecompressCompact(byte[] xOnly, ECDomainParameters domain)
    {
        // Prefisso 0x03 (y dispari path) poi normalizza y <= P-y come Apple.
        var enc = new byte[33];
        enc[0] = 0x03;
        Buffer.BlockCopy(PadLeft(xOnly, 32), 0, enc, 1, 32);
        var q = domain.Curve.DecodePoint(enc).Normalize();
        var y = q.AffineYCoord.ToBigInteger();
        var p = domain.Curve.Field.Characteristic;
        if (y.CompareTo(p.Subtract(y)) > 0)
        {
            enc[0] = 0x02;
            q = domain.Curve.DecodePoint(enc).Normalize();
        }

        return new ECPublicKeyParameters(q, domain);
    }

    private static ECPrivateKeyParameters LoadEcPrivate(string pem)
    {
        using var reader = new StringReader(pem);
        var obj = new PemReader(reader).ReadObject();
        return obj switch
        {
            Org.BouncyCastle.Crypto.AsymmetricCipherKeyPair pair => (ECPrivateKeyParameters)pair.Private,
            ECPrivateKeyParameters key => key,
            _ => throw new InvalidOperationException("PEM EC private non valida."),
        };
    }

    private static byte[] PadLeft(byte[] data, int size)
    {
        if (data.Length == size)
            return data;
        if (data.Length > size)
            return data[^size..];
        var padded = new byte[size];
        Buffer.BlockCopy(data, 0, padded, size - data.Length, data.Length);
        return padded;
    }
}
