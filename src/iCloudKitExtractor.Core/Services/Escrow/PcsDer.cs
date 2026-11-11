using System.Formats.Asn1;
using System.Security.Cryptography;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>Chiave EC privata compact: <c>x‖d</c> (32+32 su secp256r1).</summary>
public sealed record PcsCompactPrivateKey(
    byte[] PublicX,
    byte[] PrivateD,
    byte[] KeyId,
    int? Service);

/// <summary>BackupEscrow DER (appl[4]) da <c>kPCSMetadataEscrowedKeys</c>.</summary>
public sealed record BackupEscrowBlob(
    byte[] WrappedKey,
    byte[] Data,
    byte[] X,
    int Y,
    byte[] MasterKeyPublic);

/// <summary>Parser DER minimale KeySet / BackupEscrow (InflatableDonkey).</summary>
public static class PcsDer
{
    public static bool TryParseBackupEscrow(ReadOnlySpan<byte> der, out BackupEscrowBlob? escrow)
    {
        escrow = null;
        try
        {
            var reader = new AsnReader(der.ToArray(), AsnEncodingRules.DER);
            var app = reader.ReadApplication(4);
            var seq = app.ReadSequence();
            var wrapped = seq.ReadOctetString();
            var data = seq.ReadOctetString();
            var x = seq.ReadOctetString();
            var y = (int)seq.ReadInteger();
            var master = seq.ReadOctetString();
            seq.ThrowIfNotEmpty();
            app.ThrowIfNotEmpty();
            reader.ThrowIfNotEmpty();
            escrow = new BackupEscrowBlob(wrapped, data, x, y, master);
            return wrapped.Length > 0 && data.Length > 32 && master.Length is 32 or 65;
        }
        catch
        {
            return false;
        }
    }

    public static List<PcsCompactPrivateKey> ParseKeySetPrivateKeys(ReadOnlySpan<byte> der)
    {
        var list = new List<PcsCompactPrivateKey>();
        var reader = new AsnReader(der.ToArray(), AsnEncodingRules.DER);
        var app = reader.ReadApplication(2);
        var seq = app.ReadSequence();
        _ = seq.ReadCharacterString(UniversalTagNumber.UTF8String); // "ks"

        var keysSet = seq.ReadSetOf();
        while (keysSet.HasData)
        {
            var keySeq = keysSet.ReadSequence();
            var priv = keySeq.ReadOctetString();
            int? service = null;
            byte[]? pubX = null;

            if (keySeq.HasData &&
                keySeq.PeekTag().HasSameClassAndValue(new Asn1Tag(TagClass.Application, 1, isConstructed: true)))
            {
                var pubApp = keySeq.ReadApplication(1);
                var pubSeq = pubApp.ReadSequence();
                service = (int)pubSeq.ReadInteger();
                _ = pubSeq.ReadInteger(); // type
                var pubKey = pubSeq.ReadOctetString();
                pubX = pubKey.Length switch
                {
                    32 => pubKey,
                    65 when pubKey[0] == 0x04 => pubKey.AsSpan(1, 32).ToArray(),
                    _ => pubKey.Length >= 32 ? pubKey.AsSpan(0, 32).ToArray() : null,
                };
            }

            // Compact export: x‖d (pari). Fallback SEC: solo d.
            if (priv.Length == 64)
            {
                var x = priv.AsSpan(0, 32).ToArray();
                var d = priv.AsSpan(32, 32).ToArray();
                pubX ??= x;
                list.Add(new PcsCompactPrivateKey(pubX, d, KeyIdOf(pubX), service));
            }
            else if (priv.Length == 32 && pubX is { Length: 32 })
            {
                list.Add(new PcsCompactPrivateKey(pubX, priv, KeyIdOf(pubX), service));
            }
        }

        // serviceKeyIDs / checksum / flags — ignorati
        return list;
    }

    public static byte[] KeyIdOf(ReadOnlySpan<byte> publicExport)
        => SHA256.HashData(publicExport)[..20];

    /// <summary>
    /// Indice PublicX/KeyId riusabile per un pool (TryUnwrapAll × N DER).
    /// Evita di ricostruire Dictionary a ogni <see cref="FindByPublicX"/>.
    /// </summary>
    public sealed class PublicKeyIndex
    {
        private readonly Dictionary<string, PcsCompactPrivateKey> _byPub;
        private readonly Dictionary<string, PcsCompactPrivateKey> _byId;

        public PublicKeyIndex(IReadOnlyList<PcsCompactPrivateKey> keys)
        {
            _byPub = new Dictionary<string, PcsCompactPrivateKey>(keys.Count, StringComparer.Ordinal);
            _byId = new Dictionary<string, PcsCompactPrivateKey>(keys.Count, StringComparer.Ordinal);
            foreach (var k in keys)
            {
                _byPub.TryAdd(Convert.ToHexString(k.PublicX), k);
                _byId.TryAdd(Convert.ToHexString(k.KeyId), k);
            }
        }

        public PcsCompactPrivateKey? Find(ReadOnlySpan<byte> masterPublicX)
        {
            if (_byPub.TryGetValue(Convert.ToHexString(masterPublicX), out var hit))
                return hit;
            return _byId.TryGetValue(Convert.ToHexString(KeyIdOf(masterPublicX)), out hit)
                ? hit
                : null;
        }
    }

    public static PublicKeyIndex IndexOf(IReadOnlyList<PcsCompactPrivateKey> keys)
        => new(keys);

    public static PcsCompactPrivateKey? FindByPublicX(
        IEnumerable<PcsCompactPrivateKey> keys,
        ReadOnlySpan<byte> masterPublicX)
    {
        // Lookup singolo: scan lineare (ricostruire un dict per 1 hit costa di più).
        foreach (var k in keys)
        {
            if (k.PublicX.AsSpan().SequenceEqual(masterPublicX))
                return k;
        }

        var wantId = KeyIdOf(masterPublicX);
        foreach (var k in keys)
        {
            if (k.KeyId.AsSpan().SequenceEqual(wantId))
                return k;
        }

        return null;
    }

    public static PcsCompactPrivateKey? FindByPublicX(
        PublicKeyIndex index,
        ReadOnlySpan<byte> masterPublicX)
        => index.Find(masterPublicX);
}

file static class AsnReaderAppExtensions
{
    public static AsnReader ReadApplication(this AsnReader reader, int tagNumber)
    {
        var tag = new Asn1Tag(TagClass.Application, tagNumber, isConstructed: true);
        return reader.ReadSequence(tag);
    }
}
