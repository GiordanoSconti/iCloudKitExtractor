using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;
using BcBigInt = Org.BouncyCastle.Math.BigInteger;
using BcECPoint = Org.BouncyCastle.Math.EC.ECPoint;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Octagon Recovery Key KDF (Apple <c>RecoveryKeySet</c> / TrustedPeersHelper):
/// HKDF-SHA384(ikm=UTF8(rk), salt=UTF8(altDSID), info, 56)
/// → <c>ccec_generate_key_deterministic(P-384, FIPS extrabits)</c>
/// → peerID <c>RK-</c> + Base64(SHA384(signingPub.keyData)).
/// </summary>
public static class OctagonRecoveryKey
{
    private const string InfoSigning = "Recovery Signing Private Key";
    private const string InfoEncryption = "Recovery Encryption Private Key";
    private const int HkdfLen = 56; // P-384 order bits + 64 extrabits → 56 B
    private const int P384CoordLen = 48;
    private const int P384PointLen = 1 + P384CoordLen * 2; // 0x04||X||Y
    private const int P384KeyDataLen = P384PointLen + P384CoordLen; // + D

    // NIST P-384 group order.
    private static readonly BigInteger P384Order = BigInteger.Parse(
        "00FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973",
        System.Globalization.NumberStyles.HexNumber);

    public sealed record Derived(
        string PeerId,
        byte[] SigningKeyData,
        byte[] EncryptionKeyData,
        byte[] SigningPkcs8,
        byte[] EncryptionPkcs8,
        byte[] SigningPublicKeyData,
        byte[] EncryptionPublicKeyData);

    /// <summary>
    /// Derive Octagon RK peer keys. <paramref name="recoveryKeyString"/> is the
    /// user-facing string (hyphens kept). <paramref name="recoverySalt"/> is altDSID/adsid.
    /// </summary>
    public static Derived Derive(string recoveryKeyString, string recoverySalt)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(recoveryKeyString);
        ArgumentException.ThrowIfNullOrWhiteSpace(recoverySalt);

        var secret = Encoding.UTF8.GetBytes(recoveryKeyString);
        var salt = Encoding.UTF8.GetBytes(recoverySalt);

        var signing = DeriveKeyPair(secret, salt, InfoSigning);
        var encryption = DeriveKeyPair(secret, salt, InfoEncryption);

        // PeerID hashes signing public keyData (X9.63 uncompressed), NOT SPKI.
        var peerId = "RK-" + Convert.ToBase64String(SHA384.HashData(signing.PublicKeyData));

        return new Derived(
            peerId,
            signing.KeyData,
            encryption.KeyData,
            signing.Pkcs8,
            encryption.Pkcs8,
            signing.PublicKeyData,
            encryption.PublicKeyData);
    }

    /// <summary>
    /// True if <paramref name="candidatePeerId"/> matches this RK under the given salt.
    /// Accepts truncated wire captures (trailing protobuf junk stripped to 64 b64 chars).
    /// </summary>
    public static bool MatchesPeerId(string recoveryKeyString, string recoverySalt, string candidatePeerId)
    {
        var derived = Derive(recoveryKeyString, recoverySalt);
        var want = NormalizeRkPeerId(candidatePeerId);
        var got = NormalizeRkPeerId(derived.PeerId);
        return string.Equals(want, got, StringComparison.Ordinal);
    }

    public static string NormalizeRkPeerId(string peerId)
    {
        if (string.IsNullOrWhiteSpace(peerId))
            return "";
        peerId = peerId.Trim();
        if (!peerId.StartsWith("RK-", StringComparison.Ordinal))
            return peerId;
        var b64 = peerId[3..];
        // SHA384 digest → 64 base64 chars (no padding).
        if (b64.Length > 64)
            b64 = b64[..64];
        return "RK-" + b64;
    }

    /// <summary>
    /// Custodian Recovery Key peer id: same 64-char body as RK, prefix <c>CRK-</c>.
    /// Wire captures often append a trailing junk letter — strip to 64 b64 chars.
    /// </summary>
    public static string NormalizeCrkPeerId(string peerId)
    {
        if (string.IsNullOrWhiteSpace(peerId))
            return "";
        peerId = peerId.Trim();
        if (!peerId.StartsWith("CRK-", StringComparison.Ordinal))
            return peerId;
        var b64 = peerId[4..];
        if (b64.Length > 64)
            b64 = b64[..64];
        return "CRK-" + b64;
    }

    /// <summary>Map <c>RK-…</c> ↔ <c>CRK-…</c> keeping the same key-hash body.</summary>
    public static string ToCrkPeerId(string rkOrCrkPeerId)
    {
        var s = rkOrCrkPeerId.Trim();
        if (s.StartsWith("CRK-", StringComparison.Ordinal))
            return NormalizeCrkPeerId(s);
        if (s.StartsWith("RK-", StringComparison.Ordinal))
            return "CRK-" + NormalizeRkPeerId(s)[3..];
        return s;
    }

    private readonly record struct KeyPairMaterial(byte[] KeyData, byte[] PublicKeyData, byte[] Pkcs8);

    private static KeyPairMaterial DeriveKeyPair(byte[] secret, byte[] salt, string info)
    {
        var entropy = HkdfSha384(secret, salt, Encoding.UTF8.GetBytes(info), HkdfLen);
        var d = FipsExtrabitsScalar(entropy);
        var (x, y) = MultiplyG(d);

        var keyData = new byte[P384KeyDataLen];
        keyData[0] = 0x04;
        Buffer.BlockCopy(x, 0, keyData, 1, P384CoordLen);
        Buffer.BlockCopy(y, 0, keyData, 1 + P384CoordLen, P384CoordLen);
        Buffer.BlockCopy(d, 0, keyData, P384PointLen, P384CoordLen);

        var pub = keyData.AsSpan(0, P384PointLen).ToArray();
        var pkcs8 = ToPkcs8(d, x, y);
        return new KeyPairMaterial(keyData, pub, pkcs8);
    }

    /// <summary>
    /// Apple <c>ccec_generate_scalar_fips_extrabits</c>:
    /// k = (entropy_be mod (q-1)) + 1.
    /// </summary>
    private static byte[] FipsExtrabitsScalar(byte[] entropy)
    {
        var c = new BigInteger(entropy, isUnsigned: true, isBigEndian: true);
        var k = (c % (P384Order - 1)) + 1;
        return ToFixedUnsigned(k, P384CoordLen);
    }

    private static (byte[] X, byte[] Y) MultiplyG(byte[] d)
    {
        X9ECParameters p384 = SecNamedCurves.GetByName("secp384r1");
        var domain = new ECDomainParameters(p384.Curve, p384.G, p384.N, p384.H);
        var k = new BcBigInt(1, d);
        BcECPoint q = domain.G.Multiply(k).Normalize();
        var x = ToFixedUnsigned(q.AffineXCoord.ToBigInteger(), P384CoordLen);
        var y = ToFixedUnsigned(q.AffineYCoord.ToBigInteger(), P384CoordLen);
        return (x, y);
    }

    private static byte[] ToPkcs8(byte[] d, byte[] x, byte[] y)
    {
        var ec = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP384,
            D = d,
            Q = new System.Security.Cryptography.ECPoint { X = x, Y = y }
        };
        using var ecdsa = ECDsa.Create(ec);
        return ecdsa.ExportPkcs8PrivateKey();
    }

    private static byte[] ToFixedUnsigned(BigInteger v, int len)
    {
        var raw = v.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length == len)
            return raw;
        if (raw.Length > len)
            return raw[^len..];
        var pad = new byte[len];
        Buffer.BlockCopy(raw, 0, pad, len - raw.Length, raw.Length);
        return pad;
    }

    private static byte[] ToFixedUnsigned(BcBigInt v, int len)
    {
        var raw = v.ToByteArrayUnsigned();
        if (raw.Length == len)
            return raw;
        if (raw.Length > len)
            return raw[^len..];
        var pad = new byte[len];
        Buffer.BlockCopy(raw, 0, pad, len - raw.Length, raw.Length);
        return pad;
    }

    private static byte[] HkdfSha384(byte[] ikm, byte[] salt, byte[] info, int length)
    {
        const int hashLen = 48;
        if (salt.Length == 0)
            salt = new byte[hashLen];
        var prk = HMACSHA384.HashData(salt, ikm);
        var n = (length + hashLen - 1) / hashLen;
        var okm = new byte[n * hashLen];
        var t = Array.Empty<byte>();
        var offset = 0;
        for (var i = 1; i <= n; i++)
        {
            var input = new byte[t.Length + info.Length + 1];
            Buffer.BlockCopy(t, 0, input, 0, t.Length);
            Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
            input[^1] = (byte)i;
            t = HMACSHA384.HashData(prk, input);
            Buffer.BlockCopy(t, 0, okm, offset, t.Length);
            offset += t.Length;
        }

        return okm.AsSpan(0, length).ToArray();
    }
}
