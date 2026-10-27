using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using BCPoint = Org.BouncyCastle.Math.EC.ECPoint;
using BCCurve = Org.BouncyCastle.Math.EC.ECCurve;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// ProtectionInfo "light" InflatableDonkey <c>PZAssistantLight</c>:
/// <c>0xFF ‖ compactPubX(32) ‖ AES-KW(wrapped) ‖ tag(2)</c>,
/// ECDH → HKDF-SHA256(salt=myPubX, info="EagleDance") → AES-KW → master.
/// </summary>
public static class PcsProtectionLight
{
    private static readonly byte[] EagleDanceInfo = Encoding.ASCII.GetBytes("EagleDance");
    private const int FieldLen = 32;
    private const int KeyLen = 16;

    /// <summary>
    /// Light PI: prova prima wrap 24 B (AES-KW di 16 B — caso Photos/MMCS tipico),
    /// poi 40/48 solo se serve. Cache pub X già provate per evitare ECDH ripetuti.
    /// </summary>
    public static List<ProtectionZoneKeys> TryUnwrapAll(
        ReadOnlySpan<byte> payload,
        IReadOnlyList<PcsCompactPrivateKey> keys)
    {
        var results = new List<ProtectionZoneKeys>();
        if (keys.Count == 0 || payload.Length < 1 + FieldLen + 24 + 2)
            return results;

        try
        {
            return TryUnwrapAllCore(payload, keys);
        }
        catch
        {
            return results;
        }
    }

    private static List<ProtectionZoneKeys> TryUnwrapAllCore(
        ReadOnlySpan<byte> payload,
        IReadOnlyList<PcsCompactPrivateKey> keys)
    {
        var results = new List<ProtectionZoneKeys>();
        var seenMasters = new HashSet<string>(StringComparer.Ordinal);
        var okPub = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var failPub = new HashSet<string>(StringComparer.Ordinal);

        for (var i = 0; i + FieldLen + 3 < payload.Length; i++)
        {
            if (payload[i] != 0xFF)
                continue;

            if (i + 1 + FieldLen > payload.Length)
                break;
            var pub = payload.Slice(i + 1, FieldLen);
            var pubId = Convert.ToHexString(pub);
            if (failPub.Contains(pubId))
                continue;

            byte[]? master;
            var usedWrap = 24;
            if (okPub.TryGetValue(pubId, out var cachedMaster))
            {
                master = cachedMaster;
            }
            else
            {
                // Decode EC una volta per pub; poi prova wrap 24→40→48 × keys (già ordered).
                BCPoint q;
                try
                {
                    var curve = ECNamedCurveTable.GetByName("secp256r1")
                                ?? throw new CryptographicException("secp256r1 non disponibile");
                    q = DecodeCompact(curve.Curve, pub);
                }
                catch
                {
                    failPub.Add(pubId);
                    continue;
                }

                master = null;
                foreach (var wrapLen in new[] { 24, 40, 48 })
                {
                    var total = 1 + FieldLen + wrapLen + 2;
                    if (i + total > payload.Length)
                        continue;

                    var wrapped = payload.Slice(i + 1 + FieldLen, wrapLen);
                    master = TryMasterKey(q, wrapped, keys);
                    if (master is null)
                        continue;
                    usedWrap = wrapLen;
                    break;
                }

                if (master is null)
                {
                    failPub.Add(pubId);
                    continue;
                }

                okPub[pubId] = master;
            }

            var id = Convert.ToHexString(master);
            if (!seenMasters.Add(id))
            {
                i += 1 + FieldLen + usedWrap + 1;
                continue;
            }

            var pubArr = pub.ToArray();
            var decryptKey = PcsNistKdf.CtrHmacSha256(master, Encoding.ASCII.GetBytes("encryption key key m"), 16);
            results.Add(new ProtectionZoneKeys(
                master,
                decryptKey,
                null,
                null,
                pubArr,
                Convert.ToHexString(PcsDer.KeyIdOf(pubArr))));
            i += 1 + FieldLen + usedWrap + 1;
        }

        return results;
    }

    private static byte[]? TryMasterKey(
        BCPoint q,
        ReadOnlySpan<byte> wrappedKey,
        IReadOnlyList<PcsCompactPrivateKey> keys)
    {
        var wrappedArr = wrappedKey.ToArray();
        // Preferisci non-82: SearchParty non apre light PI Photos/backup tipici.
        // L'ordine del pool (preferred KeyId in testa) riduce ECDH medi.
        foreach (var key in keys)
        {
            if (key.Service == PcsPrivateKeyDer.SearchPartyServiceType)
                continue;
            try
            {
                var d = new BigInteger(1, key.PrivateD);
                var s = q.Multiply(d).Normalize();
                if (s.IsInfinity)
                    continue;
                var sharedX = s.AffineXCoord.GetEncoded();
                var kek = HkdfSha256(sharedX, key.PublicX, EagleDanceInfo, KeyLen);
                return AesKeyWrap.Unwrap(kek, wrappedArr);
            }
            catch
            {
                // next key / invalid wrap
            }
        }

        return null;
    }

    private static BCPoint DecodeCompact(
        BCCurve curve,
        ReadOnlySpan<byte> xBytes)
    {
        var x = new BigInteger(1, xBytes.ToArray());
        var X = curve.FromBigInteger(x);
        var rhs = X.Square().Add(curve.A).Multiply(X).Add(curve.B);
        var yTilde = rhs.Sqrt()
                     ?? throw new CryptographicException("compact EC: non è un punto");
        var yT = yTilde.ToBigInteger();
        var yTn = yTilde.Negate().ToBigInteger();
        // draft-jivsov-ecc-compact: y = min(y, p-y)
        var y = yT.CompareTo(yTn) < 0 ? yT : yTn;
        return curve.CreatePoint(x, y);
    }

    private static byte[] HkdfSha256(
        ReadOnlySpan<byte> ikm,
        ReadOnlySpan<byte> salt,
        ReadOnlySpan<byte> info,
        int length)
    {
        var hkdf = new HkdfBytesGenerator(new Sha256Digest());
        hkdf.Init(new HkdfParameters(ikm.ToArray(), salt.ToArray(), info.ToArray()));
        var okm = new byte[length];
        hkdf.GenerateBytes(okm, 0, okm.Length);
        return okm;
    }
}
