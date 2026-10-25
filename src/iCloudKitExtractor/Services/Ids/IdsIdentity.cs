using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Security;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Identità messaggio IDS legacy (EC+RSA) + NGM v13 / KT v5 per register Find My.
/// </summary>
public sealed class IdsIdentity
{
    public required string SigningKeyPem { get; init; }
    public required string EncryptionKeyPem { get; init; }
    public required string DeviceKeyPem { get; init; }
    public required string PreKeyPem { get; init; }

    public static IdsIdentity LoadOrCreate()
    {
        IdsStorage.EnsureDirectory();
        var signing = LoadOrCreateEc(IdsStorage.IdentityKeyPemPath);
        var enc = LoadOrCreateRsa(IdsStorage.EncryptionKeyPemPath, 1280);
        var device = LoadOrCreateEc(IdsStorage.DeviceKeyPemPath, lowY: true);
        var pre = LoadOrCreateEc(IdsStorage.PreKeyPemPath, lowY: true);
        return new IdsIdentity
        {
            SigningKeyPem = signing,
            EncryptionKeyPem = enc,
            DeviceKeyPem = device,
            PreKeyPem = pre,
        };
    }

    /// <summary>Encoding legacy <c>public-message-identity-key</c> (pypush IDSIdentity.encode).</summary>
    public byte[] EncodeLegacyIdentity()
    {
        var ec = (ECPublicKeyParameters)GetPublicKey(SigningKeyPem);
        var rsa = (RsaKeyParameters)GetPublicKey(EncryptionKeyPem);

        var x = ec.Q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned();
        var y = ec.Q.AffineYCoord.ToBigInteger().ToByteArrayUnsigned();
        x = PadLeft(x, 32);
        y = PadLeft(y, 32);

        var modulus = PadLeft(rsa.Modulus.ToByteArrayUnsigned(), 161);

        using var rawRsa = new MemoryStream();
        rawRsa.WriteByte(0x00);
        rawRsa.WriteByte(0xAC);
        rawRsa.Write([0x30, 0x81, 0xA9]);
        rawRsa.Write([0x02, 0x81, 0xA1]);
        rawRsa.Write(modulus);
        rawRsa.Write([0x02, 0x03, 0x01, 0x00, 0x01]);

        using var output = new MemoryStream();
        output.Write([0x30, 0x81, 0xF6, 0x81, 0x43]);
        output.Write([0x00, 0x41, 0x04]);
        output.Write(x);
        output.Write(y);
        output.Write([0x82, 0x81, 0xAE]);
        output.Write(rawRsa.ToArray());
        return output.ToArray();
    }

    public byte[] BuildPreKeyData()
    {
        var prePub = CompressDevicePublic(PreKeyPem);
        var devicePriv = (ECPrivateKeyParameters)GetPrivateKey(DeviceKeyPem);
        var seconds = DateTimeOffset.UtcNow.ToUnixTimeSeconds();
        var tsDouble = (double)seconds;

        // "NGMPrekeySignature" + prekey + float64 LE timestamp
        using var toSign = new MemoryStream();
        toSign.Write(Encoding.UTF8.GetBytes("NGMPrekeySignature"));
        toSign.Write(prePub);
        Span<byte> tsLe = stackalloc byte[8];
        BinaryPrimitives.WriteDoubleLittleEndian(tsLe, tsDouble);
        toSign.Write(tsLe);
        var digest = SHA256.HashData(toSign.ToArray());

        var signer = SignerUtilities.GetSigner("SHA-256withECDSA");
        signer.Init(true, devicePriv);
        signer.BlockUpdate(digest, 0, digest.Length);
        var derSig = signer.GenerateSignature();
        var (r, s) = ParseEcdsaDer(derSig);
        var sigRaw = new byte[64];
        Buffer.BlockCopy(PadLeft(r, 32), 0, sigRaw, 0, 32);
        Buffer.BlockCopy(PadLeft(s, 32), 0, sigRaw, 32, 32);

        var w = new ProtobufWriter();
        w.WriteBytes(1, prePub);
        w.WriteBytes(2, sigRaw);
        var prefix = w.ToArray();
        // field 3, wire type 1 (64-bit) = tag 0x19 + IEEE754 LE double
        Span<byte> tsBytes = stackalloc byte[8];
        BinaryPrimitives.WriteDoubleLittleEndian(tsBytes, tsDouble);
        var result = new byte[prefix.Length + 1 + 8];
        Buffer.BlockCopy(prefix, 0, result, 0, prefix.Length);
        result[prefix.Length] = 0x19;
        tsBytes.CopyTo(result.AsSpan(prefix.Length + 1));
        return result;
    }

    public byte[] BuildKtLoggableData()
    {
        var pub = CompressDevicePublic(DeviceKeyPem);
        // Nested NgmPublicIdentity { publicKey = 1 }
        var inner = new ProtobufWriter();
        inner.WriteBytes(1, pub);
        var innerBytes = inner.ToArray();

        var outer = new ProtobufWriter();
        outer.WriteBytes(1, innerBytes); // deviceIdentity
        outer.WriteVarint(2, 13); // ngmVersion
        outer.WriteVarint(3, 5); // ktVersion
        return outer.ToArray();
    }

    private static byte[] CompressDevicePublic(string keyPem)
    {
        var pub = (ECPublicKeyParameters)GetPublicKey(keyPem);
        var x = PadLeft(pub.Q.AffineXCoord.ToBigInteger().ToByteArrayUnsigned(), 32);
        return x;
    }

    private static (byte[] R, byte[] S) ParseEcdsaDer(byte[] der)
    {
        // SEQUENCE { INTEGER r, INTEGER s }
        var i = 0;
        if (der[i++] != 0x30)
            throw new InvalidOperationException("ECDSA DER non SEQUENCE.");
        _ = ReadLen(der, ref i);
        if (der[i++] != 0x02)
            throw new InvalidOperationException("ECDSA DER r mancante.");
        var rLen = ReadLen(der, ref i);
        var r = der.AsSpan(i, rLen).ToArray();
        i += rLen;
        if (der[i++] != 0x02)
            throw new InvalidOperationException("ECDSA DER s mancante.");
        var sLen = ReadLen(der, ref i);
        var s = der.AsSpan(i, sLen).ToArray();
        // strip leading 00
        if (r.Length > 0 && r[0] == 0)
            r = r[1..];
        if (s.Length > 0 && s[0] == 0)
            s = s[1..];
        return (r, s);
    }

    private static int ReadLen(byte[] data, ref int i)
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

    private static string LoadOrCreateEc(string path, bool lowY = false)
    {
        if (File.Exists(path) && new FileInfo(path).Length > 0)
            return File.ReadAllText(path);

        for (var attempt = 0; attempt < 64; attempt++)
        {
            var gen = new ECKeyPairGenerator();
            gen.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
            var pair = gen.GenerateKeyPair();
            var pub = (ECPublicKeyParameters)pair.Public;
            if (lowY)
            {
                var y = pub.Q.AffineYCoord.ToBigInteger();
                var p = pub.Parameters.Curve.Field.Characteristic;
                if (y.CompareTo(p.Subtract(y)) > 0)
                    continue;
            }

            var pem = ToPem(pair.Private);
            File.WriteAllText(path, pem);
            return pem;
        }

        throw new InvalidOperationException("Impossibile generare EC key con y <= P-y.");
    }

    private static string LoadOrCreateRsa(string path, int bits)
    {
        if (File.Exists(path) && new FileInfo(path).Length > 0)
            return File.ReadAllText(path);

        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), bits));
        var pair = gen.GenerateKeyPair();
        var pem = ToPem(pair.Private);
        File.WriteAllText(path, pem);
        return pem;
    }

    private static string ToPem(AsymmetricKeyParameter key)
    {
        using var sw = new StringWriter();
        var pw = new PemWriter(sw);
        pw.WriteObject(key);
        pw.Writer.Flush();
        return sw.ToString();
    }

    private static AsymmetricKeyParameter GetPrivateKey(string pem)
    {
        using var reader = new StringReader(pem);
        var obj = new PemReader(reader).ReadObject();
        return obj switch
        {
            AsymmetricCipherKeyPair pair => pair.Private,
            AsymmetricKeyParameter key => key,
            _ => throw new InvalidOperationException("PEM private key non valida."),
        };
    }

    private static AsymmetricKeyParameter GetPublicKey(string privateKeyPem)
    {
        var priv = GetPrivateKey(privateKeyPem);
        return priv switch
        {
            ECPrivateKeyParameters ec => new ECPublicKeyParameters(
                ec.Parameters.G.Multiply(ec.D).Normalize(),
                ec.Parameters),
            RsaPrivateCrtKeyParameters rsa => new RsaKeyParameters(false, rsa.Modulus, rsa.PublicExponent),
            _ => throw new InvalidOperationException($"Tipo chiave non supportato: {priv.GetType().Name}"),
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
