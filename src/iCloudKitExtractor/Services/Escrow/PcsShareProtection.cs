using System.Buffers.Binary;
using System.Formats.Asn1;
using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// KDF HMAC oneshot (<c>+0x3af760</c> / PCSFP):
/// <c>HMAC-SHA256(key, counter‖label_pad25)[:outLen]</c>.
/// Diverso da <see cref="PcsNistKdf"/> (CTR-HMAC InflatableDonkey).
/// </summary>
public static class PcsHmacKdf
{
    public static readonly byte[] EncryptionKeyLabel =
        PadLabel(Encoding.ASCII.GetBytes("encryption key key m"));

    public static readonly byte[] MasterKeyIdLabel =
        PadLabel(Encoding.ASCII.GetBytes("master key id labell"));

    public static readonly byte[] MasterKeyIdStep2 =
        Encoding.ASCII.GetBytes("M key input data 2 u");

    public static readonly byte[] WrappingKeyLabel =
        PadLabel(Encoding.ASCII.GetBytes("wrapping key wrap me"));

    public static readonly byte[] FullMasterKeySalt =
        Encoding.ASCII.GetBytes("full master key");

    /// <summary>CreateKeyIDFromKey (+0x9045f0): due HMAC → KeyID 20 B.</summary>
    public static byte[] CreateKeyIdFromKey(ReadOnlySpan<byte> keyBytes)
    {
        // Step1: HMAC(key, BE32(1) || "master key id labell" pad25)
        var h1 = HmacSha256(keyBytes, BuildCountedLabel(MasterKeyIdLabel, bigEndianCounter: true));
        // Step2: HMAC(?, "M key input data 2 u")[:20] — prova h1 poi raw key.
        foreach (var seed in new[] { h1, keyBytes.ToArray() })
        {
            var h2 = HmacSha256(seed, MasterKeyIdStep2);
            if (h2.Length >= 20)
                return h2.AsSpan(0, 20).ToArray();
        }

        return h1.AsSpan(0, Math.Min(20, h1.Length)).ToArray();
    }

    /// <summary>
    /// Chiave AES-128 per <c>PCSFPCopyDecryptedData</c> (+0x909010):
    /// HMAC(unwrap, counter‖"encryption key key m" pad)[:16].
    /// </summary>
    public static byte[] DeriveAes128Key(ReadOnlySpan<byte> unwrapKey, byte[]? label = null)
    {
        var lab = label is { Length: > 0 } ? PadLabel(label) : EncryptionKeyLabel;
        foreach (var be in new[] { true, false })
        {
            var dk = HmacSha256(unwrapKey, BuildCountedLabel(lab, be));
            if (dk.Length >= 16)
                return dk.AsSpan(0, 16).ToArray();
        }

        return HmacSha256(unwrapKey, lab).AsSpan(0, 16).ToArray();
    }

    /// <summary>KEK candidata per AES-KW asset wrap (stesso pattern, label wrapping).</summary>
    public static byte[] DeriveWrappingKek(ReadOnlySpan<byte> unwrapKey)
        => DeriveAes128Key(unwrapKey, Encoding.ASCII.GetBytes("wrapping key wrap me"));

    /// <summary>
    /// PBKDF2 branch CreateWithExported: pass=identity material, salt="full master key", iter=10, 32 B.
    /// </summary>
    public static byte[] Pbkdf2FullMasterKey(ReadOnlySpan<byte> password)
        => Rfc2898DeriveBytes.Pbkdf2(password, FullMasterKeySalt, 10, HashAlgorithmName.SHA256, 32);

    public static byte[] HmacSha256(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data)
    {
        using var h = new HMACSHA256(key.ToArray());
        return h.ComputeHash(data.ToArray());
    }

    public static byte[] PadLabel(ReadOnlySpan<byte> label, int length = 25)
    {
        var buf = new byte[length];
        var n = Math.Min(label.Length, length);
        label[..n].CopyTo(buf);
        return buf;
    }

    public static byte[] BuildCountedLabel(ReadOnlySpan<byte> labelPad25, bool bigEndianCounter)
    {
        var buf = new byte[4 + labelPad25.Length];
        if (bigEndianCounter)
            BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(0, 4), 1);
        else
            BinaryPrimitives.WriteUInt32LittleEndian(buf.AsSpan(0, 4), 1);
        labelPad25.CopyTo(buf.AsSpan(4));
        return buf;
    }
}

/// <summary>
/// ShareProtection materializzato (CreatePcsShareProtection / CreateWithExported)
/// + selettore <c>CreateUnwrappingKey</c> (solo lookup KeyID).
/// </summary>
public sealed class PcsShareProtection
{
    private readonly Dictionary<string, byte[]> _keysById = new(StringComparer.Ordinal);
    private byte[]? _defaultKey;
    private string? _defaultKeyIdHex;

    public IReadOnlyDictionary<string, byte[]> KeysById => _keysById;
    public byte[]? DefaultKey => _defaultKey;
    public string? DefaultKeyIdHex => _defaultKeyIdHex;
    public int KeyCount => _keysById.Count + (_defaultKey is null ? 0 : 1);

    /// <summary>
    /// CUWK: <c>map[KeyID] ?? default/asset</c>. Ritorna 16 B (o troncati/padded).
    /// </summary>
    public byte[]? CreateUnwrappingKey(ReadOnlySpan<byte> keyId)
    {
        if (keyId.Length > 0)
        {
            var hex = Convert.ToHexString(keyId);
            if (_keysById.TryGetValue(hex, out var hit))
                return Normalize16(hit);

            // KeyID a volte è ASCII hex o raw 20 B già come string hex lowercase.
            if (_keysById.TryGetValue(hex.ToLowerInvariant(), out hit))
                return Normalize16(hit);
        }

        return _defaultKey is null ? null : Normalize16(_defaultKey);
    }

    public byte[]? CreateUnwrappingKeyHex(string? keyIdHex)
    {
        if (string.IsNullOrWhiteSpace(keyIdHex))
            return _defaultKey is null ? null : Normalize16(_defaultKey);

        var cleaned = keyIdHex.Replace("-", "", StringComparison.Ordinal).Trim();
        if (_keysById.TryGetValue(cleaned.ToUpperInvariant(), out var hit)
            || _keysById.TryGetValue(cleaned, out hit))
            return Normalize16(hit);

        try
        {
            return CreateUnwrappingKey(Convert.FromHexString(cleaned));
        }
        catch
        {
            return _defaultKey is null ? null : Normalize16(_defaultKey);
        }
    }

    /// <summary>
    /// Costruisce ShareProtection da zone già unwrapped (RFC6637 path nostro)
    /// + parse ElementKeyData dal nested plaintext se presente.
    /// </summary>
    public static PcsShareProtection FromZoneKeys(IEnumerable<ProtectionZoneKeys> zones)
    {
        var share = new PcsShareProtection();
        foreach (var z in zones)
        {
            share.AddKeyMaterial(z.DecryptKey, preferDefault: share._defaultKey is null);
            share.AddKeyMaterial(z.MasterKey, preferDefault: false);

            // KeyID ufficiale zona (SHA256[:20] del public) — CUWK può chiedere questo.
            if (!string.IsNullOrWhiteSpace(z.MasterKeyIdHex))
                share.Install(z.MasterKeyIdHex, z.DecryptKey, asDefault: share._defaultKey is null);

            foreach (var nk in z.NestedPrivateKeys)
            {
                share.AddKeyMaterial(nk.PrivateD, preferDefault: false);
                share.AddKeyMaterial(nk.PublicX, preferDefault: false);
                share.Install(Convert.ToHexString(nk.KeyId), nk.PrivateD.Length >= 16
                    ? nk.PrivateD.AsSpan(0, 16).ToArray()
                    : nk.PrivateD, asDefault: false);
            }

            if (z.NestedProtectionObject is { Length: > 8 } nested)
                share.TryIngestElementKeyData(nested);
        }

        return share;
    }

    /// <summary>
    /// Unwrap zone/record ProtectionInfo + identities → ShareProtection.
    /// </summary>
    public static PcsShareProtection CreateFromProtectionInfo(
        ReadOnlySpan<byte> protectionInfoOrPayload,
        IReadOnlyList<PcsCompactPrivateKey> identities)
    {
        var zones = PcsProtectionZone.TryUnwrapAll(protectionInfoOrPayload, identities);
        return FromZoneKeys(zones);
    }

    /// <summary>
    /// Decrypt campo PCS (GCM DataA) con chiave CUWK + derive/NIST.
    /// </summary>
    public byte[]? TryDecryptField(
        ReadOnlySpan<byte> ciphertext,
        ReadOnlySpan<byte> keyId,
        params string[] aadCandidates)
    {
        var unwrap = CreateUnwrappingKey(keyId) ?? _defaultKey;
        if (unwrap is null)
            return null;

        foreach (var fieldKey in EnumerateFieldKeys(unwrap))
        {
            foreach (var aad in ExpandAad(aadCandidates))
            {
                try
                {
                    return aad.Length == 0
                        ? PcsGcmDataA.Decrypt(fieldKey, ciphertext)
                        : PcsGcmDataA.Decrypt(fieldKey, ciphertext, aad);
                }
                catch
                {
                    // next
                }
            }
        }

        return null;
    }

    /// <summary>
    /// Prova AES-KW sul wrap Asset.protectionInfo (24 B → 16 B, 40 B → 32 B)
    /// con tutte le chiavi share (+ NIST derive).
    /// </summary>
    public byte[]? TryUnwrapAssetWrap(ReadOnlySpan<byte> wrapped)
    {
        if (wrapped.Length is not (24 or 40))
            return null;

        foreach (var seed in EnumerateAllKeySeeds())
        {
            foreach (var kek in EnumerateWrappingKeks(seed))
            {
                var plain = TryUnwrapDirect(kek, wrapped);
                if (plain is { Length: > 0 })
                    return plain;
            }
        }

        return null;
    }

    private static byte[]? TryUnwrapDirect(ReadOnlySpan<byte> kek16, ReadOnlySpan<byte> wrapped)
    {
        if (kek16.Length != 16 || wrapped.Length is not (24 or 40))
            return null;
        try
        {
            return EscrowAesKeyWrap.Unwrap(kek16, wrapped);
        }
        catch
        {
            return null;
        }
    }

    public IEnumerable<byte[]> EnumerateAllKeySeeds()
    {
        if (_defaultKey is { Length: > 0 })
            yield return _defaultKey;
        foreach (var kv in _keysById)
        {
            if (kv.Value is { Length: > 0 })
                yield return kv.Value;
        }
    }

    private void AddKeyMaterial(byte[]? material, bool preferDefault)
    {
        if (material is not { Length: > 0 })
            return;

        var asKey = Normalize16(material);
        var kid = PcsHmacKdf.CreateKeyIdFromKey(asKey);
        Install(Convert.ToHexString(kid), asKey, asDefault: preferDefault && _defaultKey is null);

        if (material.Length >= 20)
        {
            var kid2 = PcsHmacKdf.CreateKeyIdFromKey(material);
            Install(Convert.ToHexString(kid2), asKey, asDefault: false);
        }
    }

    private void Install(string keyIdHex, byte[] keyBytes, bool asDefault)
    {
        var norm = Normalize16(keyBytes);
        _keysById[keyIdHex.ToUpperInvariant()] = norm;
        if (asDefault || _defaultKey is null)
        {
            _defaultKey = norm;
            _defaultKeyIdHex = keyIdHex.ToUpperInvariant();
        }
    }

    private void TryIngestElementKeyData(byte[] nestedPlain)
    {
        foreach (var keyBytes in ExtractElementKeyDataOctets(nestedPlain))
            AddKeyMaterial(keyBytes, preferDefault: _defaultKey is null);
    }

    /// <summary>Parse best-effort ElementKeyData CHOICE[1] → KeyData.keyData OCTET STRING.</summary>
    public static List<byte[]> ExtractElementKeyDataOctets(ReadOnlySpan<byte> derOrBlob)
    {
        var found = new List<byte[]>();
        try
        {
            WalkAsn1(derOrBlob.ToArray(), found);
        }
        catch
        {
            // best-effort
        }

        // Heuristica: OCTET STRING 16/32 B vicini a tag context [1].
        for (var i = 0; i + 2 < derOrBlob.Length; i++)
        {
            if (derOrBlob[i] != 0x04)
                continue;
            var len = derOrBlob[i + 1];
            if (len is not (16 or 32 or 64))
                continue;
            if (i + 2 + len > derOrBlob.Length)
                continue;
            var slice = derOrBlob.Slice(i + 2, len).ToArray();
            if (!found.Any(f => f.AsSpan().SequenceEqual(slice)))
                found.Add(slice);
        }

        return found;
    }

    private static void WalkAsn1(byte[] data, List<byte[]> found)
    {
        try
        {
            var reader = new AsnReader(data, AsnEncodingRules.BER);
            while (reader.HasData)
                WalkValue(reader, found);
        }
        catch
        {
            // ignore
        }
    }

    private static void WalkValue(AsnReader reader, List<byte[]> found)
    {
        var tag = reader.PeekTag();
        if (tag.TagClass == TagClass.Universal && tag.TagValue == (int)UniversalTagNumber.OctetString)
        {
            var oct = reader.ReadOctetString();
            if (oct.Length is 16 or 32 or 64)
                found.Add(oct);
            return;
        }

        if (tag.IsConstructed)
        {
            var nested = reader.ReadSequence(tag);
            while (nested.HasData)
                WalkValue(nested, found);
            return;
        }

        reader.ReadEncodedValue();
    }

    private static IEnumerable<byte[]> EnumerateFieldKeys(byte[] unwrap16)
    {
        var list = new List<byte[]> { PcsHmacKdf.DeriveAes128Key(unwrap16), unwrap16 };
        try
        {
            list.Add(PcsNistKdf.CtrHmacSha256(
                unwrap16, Encoding.ASCII.GetBytes("encryption key key m"), 16));
        }
        catch
        {
            // ignore
        }

        return list;
    }

    private static IEnumerable<byte[]> EnumerateWrappingKeks(byte[] seed)
    {
        var list = new List<byte[]>
        {
            PcsHmacKdf.DeriveWrappingKek(seed),
            PcsHmacKdf.DeriveAes128Key(seed),
            Normalize16(seed)
        };
        try
        {
            list.Add(PcsNistKdf.CtrHmacSha256(
                seed.Length >= 16 ? seed : Normalize16(seed),
                Encoding.ASCII.GetBytes("wrapping key wrap me"),
                16));
        }
        catch
        {
            // ignore
        }

        if (seed.Length >= 32)
        {
            try
            {
                list.Add(PcsNistKdf.CtrHmacSha256(
                    seed, Encoding.ASCII.GetBytes("wrapping key wrap me"), 16));
            }
            catch
            {
                // ignore
            }
        }

        return list;
    }

    private static IEnumerable<byte[]> ExpandAad(string[] candidates)
    {
        // CreateDecryptionLabel: AAD = nome campo (UTF-8/ASCII) prima di empty.
        foreach (var c in candidates)
        {
            if (string.IsNullOrEmpty(c))
                continue;
            yield return Encoding.UTF8.GetBytes(c);
            yield return Encoding.ASCII.GetBytes(c);
        }

        yield return [];
    }

    private static byte[] Normalize16(byte[] key)
    {
        if (key.Length == 16)
            return key;
        if (key.Length > 16)
            return key.AsSpan(0, 16).ToArray();
        var padded = new byte[16];
        key.CopyTo(padded, 0);
        return padded;
    }
}

/// <summary>RFC 3394 AES-KW per Escrow (AesKeyWrap in Protocol è internal file-local).</summary>
file static class EscrowAesKeyWrap
{
    public static byte[] Unwrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrapped)
    {
        if (wrapped.Length % 8 != 0 || wrapped.Length < 24)
            throw new CryptographicException("wrap lunghezza non valida");
        if (kek.Length is not (16 or 24 or 32))
            throw new CryptographicException("KEK lunghezza non valida");

        var n = wrapped.Length / 8 - 1;
        var a = BinaryPrimitives.ReadUInt64BigEndian(wrapped);
        var r = new ulong[n];
        for (var i = 0; i < n; i++)
            r[i] = BinaryPrimitives.ReadUInt64BigEndian(wrapped.Slice(8 + i * 8, 8));

        using var aes = Aes.Create();
        aes.Key = kek.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        for (var j = 5; j >= 0; j--)
        {
            for (var i = n; i >= 1; i--)
            {
                var t = (ulong)(n * j + i);
                var b = new byte[16];
                BinaryPrimitives.WriteUInt64BigEndian(b, a ^ t);
                BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(8), r[i - 1]);
                using var dec = aes.CreateDecryptor();
                var y = dec.TransformFinalBlock(b, 0, 16);
                a = BinaryPrimitives.ReadUInt64BigEndian(y);
                r[i - 1] = BinaryPrimitives.ReadUInt64BigEndian(y.AsSpan(8));
            }
        }

        if (a != 0xA6A6A6A6A6A6A6A6UL)
            throw new CryptographicException("AES-KW IV mismatch");

        var plain = new byte[n * 8];
        for (var i = 0; i < n; i++)
            BinaryPrimitives.WriteUInt64BigEndian(plain.AsSpan(i * 8), r[i]);
        return plain;
    }
}
