using System.Formats.Asn1;
using System.Security.Cryptography;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Parser <c>PCSPrivateKey</c> (rustpush <c>pcs.rs</c>):
/// V1 SEQUENCE{ key OCTET, public? } oppure V2 APPLICATION 5 { data = ProtoPCSKey }.
/// <c>key</c> = compact P-256 <c>x‖d</c> (64 B).
/// </summary>
public static class PcsPrivateKeyDer
{
    /// <summary>Find My / searchparty service type (rustpush <c>FIND_MY_SERVICE.r#type</c>).</summary>
    public const int SearchPartyServiceType = 82;

    public static List<PcsCompactPrivateKey> TryParseAll(ReadOnlySpan<byte> data, int? serviceHint = null)
    {
        var list = new List<PcsCompactPrivateKey>();
        if (TryParse(data, serviceHint, out var one) && one is not null)
            list.Add(one);

        // Fallback: KeySet appl[2] (alcuni export).
        try
        {
            list.AddRange(PcsDer.ParseKeySetPrivateKeys(data));
        }
        catch
        {
            // ignore
        }

        return Dedup(list);
    }

    public static bool TryParse(
        ReadOnlySpan<byte> data, int? serviceHint, out PcsCompactPrivateKey? key)
    {
        key = null;
        if (data.Length < 32)
            return false;

        // V2: APPLICATION 5
        if (TryParseV2(data, serviceHint, out key))
            return true;

        // V1: SEQUENCE { OCTET STRING key, … }
        if (TryParseV1(data, serviceHint, out key))
            return true;

        // Raw compact x‖d
        if (data.Length >= 64 && LooksLikeCompact(data[..64]))
        {
            var x = data[..32].ToArray();
            var d = data.Slice(32, 32).ToArray();
            key = new PcsCompactPrivateKey(x, d, PcsDer.KeyIdOf(x), serviceHint);
            return true;
        }

        return false;
    }

    private static bool TryParseV2(
        ReadOnlySpan<byte> data, int? serviceHint, out PcsCompactPrivateKey? key)
    {
        key = null;
        try
        {
            var reader = new AsnReader(data.ToArray(), AsnEncodingRules.DER);
            var tag = new Asn1Tag(TagClass.Application, 5, isConstructed: true);
            if (!reader.PeekTag().HasSameClassAndValue(tag))
            {
                // anche primitive appl[5]
                tag = new Asn1Tag(TagClass.Application, 5, isConstructed: false);
                if (!reader.PeekTag().HasSameClassAndValue(tag))
                    return false;
                var oct = reader.ReadOctetString(tag);
                return TryParseProtoPcsKey(oct, serviceHint, out key);
            }

            var app = reader.ReadSequence(tag);
            var inner = app.ReadOctetString();
            return TryParseProtoPcsKey(inner, serviceHint, out key);
        }
        catch
        {
            return false;
        }
    }

    private static bool TryParseV1(
        ReadOnlySpan<byte> data, int? serviceHint, out PcsCompactPrivateKey? key)
    {
        key = null;
        try
        {
            var reader = new AsnReader(data.ToArray(), AsnEncodingRules.DER);
            if (reader.PeekTag() != Asn1Tag.Sequence)
                return false;
            var seq = reader.ReadSequence();
            var priv = seq.ReadOctetString();
            int? service = serviceHint;
            byte[]? pubX = null;

            if (seq.HasData)
            {
                // public PCSPublicKey (SEQUENCE o embedded)
                try
                {
                    var pubDer = seq.ReadEncodedValue().ToArray();
                    TryParsePublicService(pubDer, out service, out pubX);
                }
                catch
                {
                    // ignore trailing
                }
            }

            if (priv.Length == 64 && LooksLikeCompact(priv))
            {
                pubX ??= priv.AsSpan(0, 32).ToArray();
                var d = priv.AsSpan(32, 32).ToArray();
                key = new PcsCompactPrivateKey(pubX, d, PcsDer.KeyIdOf(pubX), service);
                return true;
            }

            if (priv.Length == 32 && pubX is { Length: 32 })
            {
                key = new PcsCompactPrivateKey(pubX, priv, PcsDer.KeyIdOf(pubX), service);
                return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryParseProtoPcsKey(
        ReadOnlySpan<byte> proto, int? serviceHint, out PcsCompactPrivateKey? key)
    {
        key = null;
        // ProtoPCSKey { encryptionKey = 1 { key = 1, public = 2 }, signingKey = 2 }
        byte[]? encKey = null;
        byte[]? encPub = null;
        var r = new ProtobufReader(proto);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field != 1)
                continue;
            var ir = new ProtobufReader(payload);
            while (ir.HasMore)
            {
                var (f2, w2) = ir.ReadTag();
                if (w2 != 2)
                {
                    ir.SkipField(w2);
                    continue;
                }

                var inner = ir.ReadLengthDelimited();
                if (f2 == 1)
                    encKey = inner;
                else if (f2 == 2)
                    encPub = inner;
            }
        }

        if (encKey is null)
            return false;

        int? service = serviceHint;
        byte[]? pubX = null;
        if (encPub is { Length: > 0 })
            TryParsePublicService(encPub, out service, out pubX);

        if (encKey.Length == 64 && LooksLikeCompact(encKey))
        {
            pubX ??= encKey.AsSpan(0, 32).ToArray();
            key = new PcsCompactPrivateKey(
                pubX, encKey.AsSpan(32, 32).ToArray(), PcsDer.KeyIdOf(pubX), service ?? serviceHint);
            return true;
        }

        if (encKey.Length == 32 && pubX is { Length: 32 })
        {
            key = new PcsCompactPrivateKey(pubX, encKey, PcsDer.KeyIdOf(pubX), service ?? serviceHint);
            return true;
        }

        return false;
    }

    /// <summary>
    /// PCSPublicKey DER: SEQUENCE { pcsservice INTEGER, unk1 INTEGER, pub_key OCTET, … }.
    /// </summary>
    private static bool TryParsePublicService(
        ReadOnlySpan<byte> der, out int? service, out byte[]? pubX)
    {
        service = null;
        pubX = null;
        try
        {
            var reader = new AsnReader(der.ToArray(), AsnEncodingRules.DER);
            if (reader.PeekTag() != Asn1Tag.Sequence)
                return false;
            var seq = reader.ReadSequence();
            service = (int)seq.ReadInteger();
            if (seq.HasData)
                _ = seq.ReadInteger(); // unk1
            if (seq.HasData)
            {
                var pub = seq.ReadOctetString();
                pubX = pub.Length switch
                {
                    32 => pub,
                    65 when pub[0] == 0x04 => pub.AsSpan(1, 32).ToArray(),
                    >= 32 => pub.AsSpan(0, 32).ToArray(),
                    _ => null
                };
            }

            return pubX is { Length: 32 };
        }
        catch
        {
            return false;
        }
    }

    private static bool LooksLikeCompact(ReadOnlySpan<byte> xOrXd)
    {
        if (xOrXd.Length < 32)
            return false;
        var any = false;
        for (var i = 0; i < 32; i++)
            if (xOrXd[i] != 0) { any = true; break; }
        return any;
    }

    private static List<PcsCompactPrivateKey> Dedup(List<PcsCompactPrivateKey> keys)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var outList = new List<PcsCompactPrivateKey>();
        foreach (var k in keys)
        {
            if (seen.Add(Convert.ToHexString(k.KeyId)))
                outList.Add(k);
        }

        return outList;
    }
}
