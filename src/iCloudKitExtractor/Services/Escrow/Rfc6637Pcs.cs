using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// RFC6637 secp256r1 unwrap (compact EC) + AES-GCM DataB — InflatableDonkey
/// <c>PZDataUnwrap</c> / <c>GCMDataB</c>.
/// </summary>
public static class Rfc6637Pcs
{
    /// <summary>ASCII <c>fingerprint</c> + NUL pad a 20 B (PZDataUnwrap).</summary>
    public static readonly byte[] Fingerprint =
        Encoding.ASCII.GetBytes("fingerprint\0\0\0\0\0\0\0\0\0");

    // formattedOid = DER(OID) senza tag 0x06 → secp256r1 = 1.2.840.10045.3.1.7
    private static readonly byte[] FormattedOid =
        Convert.FromHexString("082A8648CE3D030107");

    private static readonly byte[] AnonymousSender =
        Encoding.ASCII.GetBytes("Anonymous Sender    ");

    private const byte PublicKeyAlgEcdh = 18;
    private const byte SymAlgAes128 = 7;
    private const byte KdfHashSha256 = 8;

    public static byte[] UnwrapSecp256R1(ReadOnlySpan<byte> wrappedPacket, ReadOnlySpan<byte> privateD)
    {
        if (wrappedPacket.Length < 3 + 32 + 1 + 16)
            throw new CryptographicException("wrappedKey RFC6637 troppo corto");

        var wKeyBits = BinaryPrimitives.ReadUInt16BigEndian(wrappedPacket);
        var wKeyLen = (wKeyBits + 7) / 8;
        if (2 + wKeyLen + 1 > wrappedPacket.Length)
            throw new CryptographicException("wrappedKey: wKey length overflow");

        var wKey = wrappedPacket.Slice(2, wKeyLen);
        var wrappedSize = wrappedPacket[2 + wKeyLen];
        var wrappedOff = 3 + wKeyLen;
        if (wrappedOff + wrappedSize > wrappedPacket.Length)
            throw new CryptographicException("wrappedKey: wrapped size overflow");
        var wrapped = wrappedPacket.Slice(wrappedOff, wrappedSize);

        var zb = EcdhSharedX(wKey, privateD);
        var kek = Kdf(zb, Fingerprint)[..16];
        var unwrapped = AesKeyWrap.Unwrap(kek, wrapped);
        return FinalizeRfc6637(unwrapped);
    }

    public static byte[] GcmDecryptDataB(ReadOnlySpan<byte> key, ReadOnlySpan<byte> packet)
    {
        const int nonceLen = 16;
        const int tagLen = 16;
        if (packet.Length < nonceLen + tagLen)
            throw new CryptographicException("GCMDataB troppo corto");

        var nonce = packet[..nonceLen].ToArray();
        var input = packet[nonceLen..].ToArray(); // ciphertext ‖ tag

        // .NET AesGcm non accetta nonce 16 B — BouncyCastle sì (GCMDataB).
        var cipher = new GcmBlockCipher(new AesEngine());
        var parameters = new AeadParameters(new KeyParameter(key.ToArray()), tagLen * 8, nonce);
        cipher.Init(false, parameters);
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        len += cipher.DoFinal(output, len);
        return output.AsSpan(0, len).ToArray();
    }

    private static byte[] EcdhSharedX(ReadOnlySpan<byte> ephemeralPublic, ReadOnlySpan<byte> privateD)
    {
        var curve = ECNamedCurveTable.GetByName("secp256r1")
                    ?? throw new CryptographicException("secp256r1 non disponibile");
        var domain = new ECDomainParameters(curve.Curve, curve.G, curve.N, curve.H, curve.GetSeed());

        Org.BouncyCastle.Math.EC.ECPoint q = DecodePoint(curve.Curve, ephemeralPublic);
        var d = new Org.BouncyCastle.Math.BigInteger(1, privateD.ToArray());
        var s = q.Multiply(d).Normalize();
        if (s.IsInfinity)
            throw new CryptographicException("ECDH punto all'infinito");
        return s.AffineXCoord.GetEncoded();
    }

    private static Org.BouncyCastle.Math.EC.ECPoint DecodePoint(
        Org.BouncyCastle.Math.EC.ECCurve curve,
        ReadOnlySpan<byte> data)
    {
        var fieldLen = (curve.FieldSize + 7) / 8;
        if (data.Length == fieldLen)
        {
            // Compact: y = min(y', p-y') — draft-jivsov-ecc-compact
            var x = new Org.BouncyCastle.Math.BigInteger(1, data.ToArray());
            var X = curve.FromBigInteger(x);
            var rhs = X.Square().Add(curve.A).Multiply(X).Add(curve.B);
            var yTilde = rhs.Sqrt()
                         ?? throw new CryptographicException("compact EC: non è un punto");
            var yT = yTilde.ToBigInteger();
            var yTn = yTilde.Negate().ToBigInteger();
            var y = yT.CompareTo(yTn) < 0 ? yT : yTn;
            return curve.CreatePoint(x, y);
        }

        return curve.DecodePoint(data.ToArray());
    }

    private static byte[] Kdf(ReadOnlySpan<byte> zb, ReadOnlySpan<byte> fingerprint)
    {
        var h = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
        h.AppendData([0x00, 0x00, 0x00, 0x01]);
        h.AppendData(zb);
        h.AppendData(FormattedOid);
        h.AppendData([PublicKeyAlgEcdh]);
        h.AppendData([0x03, 0x01]);
        h.AppendData([KdfHashSha256]);
        h.AppendData([SymAlgAes128]);
        h.AppendData(AnonymousSender);
        h.AppendData(fingerprint);
        return h.GetHashAndReset();
    }

    /// <summary>
    /// <c>sym_alg_id ‖ key ‖ checksum(2) ‖ PKCS5 padding</c> → key.
    /// </summary>
    internal static byte[] FinalizeRfc6637(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4)
            throw new CryptographicException("RFC6637 finalize: troppo corto");

        var buf = data.ToArray();
        var i = buf.Length - 1;
        var paddedBytes = buf[i];
        if (paddedBytes > buf.Length - 3)
            throw new CryptographicException("RFC6637 finalize: bad padding length");

        if (paddedBytes > 0)
        {
            while (true)
            {
                var oldI = i;
                i--;
                if (oldI <= buf.Length - paddedBytes)
                    break;
                if (buf[i] != paddedBytes)
                    throw new CryptographicException("RFC6637 finalize: bad padding");
            }
        }

        var checksum = (int)buf[i];
        i--;
        checksum += buf[i] << 8;

        var t = 0;
        while (true)
        {
            var oldI = i;
            i--;
            if (oldI <= 1)
                break;
            t += buf[i];
        }

        if ((t & 0xFFFF) != checksum)
            throw new CryptographicException("RFC6637 finalize: bad checksum");

        var outLen = buf.Length - paddedBytes - 3;
        return buf.AsSpan(1, outLen).ToArray();
    }
}
