using System.Buffers.Binary;
using System.Formats.Asn1;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>AES-GCM DataA (header ‖ nonce ‖ tag ‖ ciphertext) — InflatableDonkey <c>GCMDataA</c>.</summary>
public static class PcsGcmDataA
{
    public static byte[] Decrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> data, ReadOnlySpan<byte> extraAad = default)
    {
        if (data.IsEmpty)
            throw new CryptographicException("GCMDataA vuoto");

        var version = data[0];
        int headerLen = version switch
        {
            0 => 1,
            1 => 1,
            2 => 3,
            3 => data.Length >= 4 ? 4 + data[3] : throw new CryptographicException("GCMDataA v3 corto"),
            _ => throw new CryptographicException($"GCMDataA version non supportata: {version}"),
        };
        var nonceLen = version == 0 ? 8 : 12;
        var tagLen = version == 0 ? 8 : 12;
        if (data.Length < headerLen + nonceLen + tagLen)
            throw new CryptographicException("GCMDataA troppo corto");

        var header = data[..headerLen].ToArray();
        var nonce = data.Slice(headerLen, nonceLen).ToArray();
        var tag = data.Slice(headerLen + nonceLen, tagLen).ToArray();
        var enc = data[(headerLen + nonceLen + tagLen)..].ToArray();

        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(false, new AeadParameters(new KeyParameter(key.ToArray()), tagLen * 8, nonce, header));
        if (!extraAad.IsEmpty)
            cipher.ProcessAadBytes(extraAad.ToArray(), 0, extraAad.Length);

        var input = new byte[enc.Length + tag.Length];
        Buffer.BlockCopy(enc, 0, input, 0, enc.Length);
        Buffer.BlockCopy(tag, 0, input, enc.Length, tag.Length);
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var n = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        n += cipher.DoFinal(output, n);
        return output.AsSpan(0, n).ToArray();
    }
}

/// <summary>NIST SP800-108 CTR-HMAC-SHA256 — InflatableDonkey <c>NISTKDF.ctrHMac</c>.</summary>
public static class PcsNistKdf
{
    public static byte[] CtrHmacSha256(ReadOnlySpan<byte> keyDerivationKey, ReadOnlySpan<byte> label, int keyLengthBytes)
    {
        var fixedInput = new byte[label.Length + 5];
        label.CopyTo(fixedInput);
        fixedInput[label.Length] = 0;
        BinaryPrimitives.WriteInt32BigEndian(fixedInput.AsSpan(label.Length + 1), keyLengthBytes * 8);

        var gen = new KdfCounterBytesGenerator(new HMac(new Sha256Digest()));
        gen.Init(new KdfCounterParameters(keyDerivationKey.ToArray(), fixedInput, 32));
        var dk = new byte[keyLengthBytes];
        gen.GenerateBytes(dk, 0, dk.Length);
        return dk;
    }
}

public sealed record ProtectionZoneKeys(
    byte[] MasterKey,
    byte[] DecryptKey,
    string? ProtectionInfoTag,
    byte[]? NestedProtectionObject,
    byte[] MasterPublicMatched,
    string MasterKeyIdHex,
    IReadOnlyList<PcsCompactPrivateKey> NestedPrivateKeys)
{
    public ProtectionZoneKeys(
        byte[] masterKey,
        byte[] decryptKey,
        string? protectionInfoTag,
        byte[]? nestedProtectionObject,
        byte[] masterPublicMatched,
        string masterKeyIdHex)
        : this(
            masterKey,
            decryptKey,
            protectionInfoTag,
            nestedProtectionObject,
            masterPublicMatched,
            masterKeyIdHex,
            Array.Empty<PcsCompactPrivateKey>())
    {
    }
}

/// <summary>
/// Unwrap CloudKit/CloudDocs zone <c>ProtectionInfo</c> (DER appl[1]) con chiavi PCS escrowed.
/// Il KeySet escrow è multi-service: CloudDocs usa BLADERUNNER (service 2), non un path separato.
/// </summary>
public static class PcsProtectionZone
{
    private static readonly byte[] DecryptKeyLabel =
        Encoding.ASCII.GetBytes("encryption key key m");

    private static readonly byte[] WrappingKeyLabel =
        Encoding.ASCII.GetBytes("wrapping key wrap me");

    /// <summary>
    /// InflatableDonkey <c>PZKeyUnwrap</c>: NISTKDF(<paramref name="masterKey"/>, "wrapping key wrap me")
    /// → AES-KW su <paramref name="wrappedKey"/>
    /// (Asset.protectionInfo: 24 B → chiave 16 B, oppure 40 B → chiave 32 B).
    /// </summary>
    public static byte[]? TryUnwrapWrappingKey(ReadOnlySpan<byte> masterKey, ReadOnlySpan<byte> wrappedKey)
    {
        if (wrappedKey.Length is not (24 or 40) || masterKey.IsEmpty)
            return null;
        try
        {
            var kek = PcsNistKdf.CtrHmacSha256(masterKey, WrappingKeyLabel, 16);
            return AesKeyWrap.Unwrap(kek, wrappedKey);
        }
        catch
        {
            return null;
        }
    }

    public static bool TryExtractProtectionInfoDer(ReadOnlySpan<byte> payload, out byte[]? der)
    {
        var list = TryExtractProtectionInfoCandidates(payload);
        der = list.Count > 0 ? list[0] : null;
        return der is not null;
    }

    public static List<byte[]> TryExtractProtectionInfoCandidates(ReadOnlySpan<byte> payload)
    {
        var list = new List<byte[]>();
        for (var i = 0; i + 4 < payload.Length; i++)
        {
            if (payload[i] != 0x61)
                continue;
            if (!TrySliceTlv(payload, i, out var slice))
                continue;
            if (slice.Length < 64)
                continue;
            // Evita falsi positivi ASCII ("aultZone", URL, …): content = SEQUENCE 0x30.
            if (!TryReadTagLen(slice, 0, out _, out _, out _, out var cOff, out _, out _)
                || cOff >= slice.Length
                || slice[cOff] != 0x30)
                continue;
            list.Add(slice.ToArray());
        }

        // Preferisci i blob più lunghi (zone PI tipicamente >200 B).
        return list.OrderByDescending(static b => b.Length).ToList();
    }

    public static ProtectionZoneKeys? TryUnwrap(
        ReadOnlySpan<byte> protectionInfoPayload,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        string? protectionInfoTag = null)
        => TryUnwrapAll(protectionInfoPayload, seedKeys, protectionInfoTag).FirstOrDefault();

    /// <summary>
    /// Unwrap di tutti i candidati DER ProtectionInfo nel payload (zone PI + recordProtectionInfo).
    /// zone/retrieve per WhatsApp espone tipicamente 2–3 appl[1] vicino alla zona.
    /// </summary>
    public static List<ProtectionZoneKeys> TryUnwrapAll(
        ReadOnlySpan<byte> protectionInfoPayload,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        string? protectionInfoTag = null,
        IReadOnlyList<PcsCompactPrivateKey>? lightKeys = null,
        bool includeLight = true,
        bool includeDer = true)
    {
        // Try*: mai propagare (scan CPL multi-MB può colpire TLV/span malformati → AOR).
        try
        {
            return TryUnwrapAllCore(
                protectionInfoPayload, seedKeys, protectionInfoTag, lightKeys,
                includeLight, includeDer);
        }
        catch (Exception ex)
        {
            AgentWaLog(
                "H-AOR-UNWRAP",
                "TryUnwrapAll_swallowed",
                new
                {
                    type = ex.GetType().FullName,
                    msg = ex.Message,
                    param = (ex as ArgumentOutOfRangeException)?.ParamName,
                    payloadLen = protectionInfoPayload.Length,
                    seeds = seedKeys.Count,
                });
            return [];
        }
    }

    private static List<ProtectionZoneKeys> TryUnwrapAllCore(
        ReadOnlySpan<byte> protectionInfoPayload,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        string? protectionInfoTag,
        IReadOnlyList<PcsCompactPrivateKey>? lightKeys,
        bool includeLight,
        bool includeDer)
    {
        var results = new List<ProtectionZoneKeys>();
        var seenMasters = new HashSet<string>(StringComparer.Ordinal);
        // Un indice per tutto il batch DER (N candidati × M EncryptedKeys).
        var index = seedKeys.Count > 0 ? PcsDer.IndexOf(seedKeys) : null;

        if (includeDer)
        {
            foreach (var der in TryExtractProtectionInfoCandidates(protectionInfoPayload))
            {
                ProtectionZoneKeys? result;
                try
                {
                    result = TryUnwrapDer(der, seedKeys, protectionInfoTag, index);
                }
                catch
                {
                    continue;
                }

                if (result is null)
                    continue;
                var id = Convert.ToHexString(result.MasterKey);
                if (!seenMasters.Add(id))
                    continue;
                results.Add(result);
            }

            if (results.Count == 0)
            {
                try
                {
                    var scan = TryUnwrapByPublicScan(protectionInfoPayload, seedKeys, protectionInfoTag);
                    if (scan is not null)
                        results.Add(scan);
                }
                catch
                {
                    // scan pubblico best-effort
                }
            }
        }

        // Light ProtectionInfo: preferisci lightKeys (tipicamente solo escrow seed).
        // Su pagine CPL multi-MB: includeDer:false + includeLight:true (i master MMCS
        // escono dallo scan 0xFF, non dai falsi positivi DER 0x61).
        if (includeLight)
        {
            var forLight = lightKeys ?? seedKeys;
            foreach (var light in PcsProtectionLight.TryUnwrapAll(protectionInfoPayload, forLight))
            {
                var id = Convert.ToHexString(light.MasterKey);
                if (seenMasters.Add(id))
                    results.Add(light);
            }
        }

        return results;
    }

    /// <summary>
    /// Unwrap iterativo: le nested keys di un PI (MasterKeySet) aprono altri PI
    /// nello stesso payload (CreateWithExported chain). Es. PI mbksync 572 B
    /// → nested → PI ~401 B (_defaultZone content) → master per wrap fileList.
    /// </summary>
    public static List<ProtectionZoneKeys> TryUnwrapAllIterative(
        ReadOnlySpan<byte> protectionInfoPayload,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        string? protectionInfoTag = null,
        int maxRounds = 4,
        bool includeLight = true)
    {
        var payload = protectionInfoPayload.ToArray();
        var pool = seedKeys.ToList();
        var all = new List<ProtectionZoneKeys>();
        var seenMaster = new HashSet<string>(StringComparer.Ordinal);

        for (var round = 0; round < maxRounds; round++)
        {
            // Backup mbksync/catalog: solo DER (light 0xFF×N seed = minuti su ADP).
            var found = TryUnwrapAll(
                payload, pool, protectionInfoTag, includeLight: includeLight);
            var added = 0;
            foreach (var z in found)
            {
                var id = Convert.ToHexString(z.MasterKey);
                if (!seenMaster.Add(id))
                    continue;
                all.Add(z);
                added++;
            }

            if (added == 0)
                break;

            pool = MergeKeys(pool, found);
        }

        return all;
    }

    /// <summary>
    /// Chiavi EC aggregate: seed escrow + eventuali nested MasterKeySet da ogni PI unwrapped.
    /// </summary>
    public static List<PcsCompactPrivateKey> MergeKeys(
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        IEnumerable<ProtectionZoneKeys> zones)
    {
        var map = new Dictionary<string, PcsCompactPrivateKey>(StringComparer.Ordinal);
        void Add(PcsCompactPrivateKey k)
        {
            var id = Convert.ToHexString(k.KeyId);
            map.TryAdd(id, k);
        }

        foreach (var k in seedKeys)
            Add(k);
        foreach (var z in zones)
        {
            foreach (var k in z.NestedPrivateKeys)
                Add(k);
        }

        return map.Values.ToList();
    }

    private static ProtectionZoneKeys? TryUnwrapDer(
        byte[] der,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        string? protectionInfoTag,
        PcsDer.PublicKeyIndex? index = null)
    {
        // Cont[0] dataBlob: sempre via ExtractDataBlob (strip OCTET STRING).
        // Il walk in TryParseProtectionInfo a volte lascia il wrapper 0x04 → GCM ver≠3.
        var dataBlob = ExtractDataBlob(der);

        if (TryParseProtectionInfo(der, out var encryptedKeys, out var parsedBlob) && encryptedKeys.Count > 0)
        {
            dataBlob ??= parsedBlob;
            foreach (var ek in encryptedKeys)
            {
                var match = index is not null
                    ? PcsDer.FindByPublicX(index, ek.MasterPublic)
                    : PcsDer.FindByPublicX(seedKeys, ek.MasterPublic);
                if (match is null)
                    continue;

                // CreateWithExported (+0x905390): PBKDF2 "full master key" → AES-KW prima di ECDH.
                if (TryCreateWithExportedUnwrap(ek.WrappedKey, match, out var fillMaster))
                    return BuildZoneKeys(fillMaster, match, dataBlob, protectionInfoTag);

                try
                {
                    var master = Rfc6637Pcs.UnwrapSecp256R1(ek.WrappedKey, match.PrivateD);
                    return BuildZoneKeys(master, match, dataBlob, protectionInfoTag);
                }
                catch
                {
                    // next encrypted key
                }
            }
        }

        // Fallback per-DER: stesso public-scan limitato a questo blob (evita di perdere
        // recordProtectionInfo quando EncryptedKeys ASN.1 non parsa).
        return TryUnwrapByPublicScan(der, seedKeys, protectionInfoTag, dataBlob);
    }

    private static ProtectionZoneKeys? TryUnwrapByPublicScan(
        ReadOnlySpan<byte> payload,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        string? protectionInfoTag,
        byte[]? preferredDataBlob = null)
    {
        var bytes = payload.ToArray();
        // Skip SearchParty (82): non wrappa zone backup; con 100+ Manatee è costo puro.
        foreach (var key in seedKeys)
        {
            if (key.Service == PcsPrivateKeyDer.SearchPartyServiceType)
                continue;
            var idx = IndexOf(bytes, key.PublicX);
            if (idx < 0)
                continue;
            for (var i = idx; i < bytes.Length - 2 && i < idx + 96; i++)
            {
                if (bytes[i] != 0x04 || bytes[i + 1] != 0x53)
                    continue;
                if (i + 2 + 83 > bytes.Length)
                    break;
                var wrapped = bytes.AsSpan(i + 2, 83).ToArray();

                // CreateWithExported primary
                if (TryCreateWithExportedUnwrap(wrapped, key, out var fillMaster))
                {
                    var dataBlob = preferredDataBlob;
                    if (dataBlob is null || dataBlob.Length == 0)
                    {
                        foreach (var der in TryExtractProtectionInfoCandidates(payload))
                        {
                            dataBlob = ExtractDataBlob(der);
                            if (dataBlob is { Length: > 0 })
                                break;
                        }
                    }

                    return BuildZoneKeys(fillMaster, key, dataBlob, protectionInfoTag);
                }

                try
                {
                    var master = Rfc6637Pcs.UnwrapSecp256R1(wrapped, key.PrivateD);
                    var dataBlob = preferredDataBlob;
                    if (dataBlob is null || dataBlob.Length == 0)
                    {
                        foreach (var der in TryExtractProtectionInfoCandidates(payload))
                        {
                            dataBlob = ExtractDataBlob(der);
                            if (dataBlob is { Length: > 0 })
                                break;
                        }
                    }

                    return BuildZoneKeys(master, key, dataBlob, protectionInfoTag);
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
    /// corecrypto::utils::CreateWithExported: PBKDF2(pass, "full master key", iter=10) → AES-KW.
    /// Solo wrap AES-KW (24/40). Wrap 83 B è Rfc6637/ECDH (runtime: CW fail ×N poi ECDH ok).
    /// </summary>
    private static bool TryCreateWithExportedUnwrap(
        ReadOnlySpan<byte> wrappedKey,
        PcsCompactPrivateKey identity,
        out byte[] masterKey)
    {
        masterKey = [];
        if (wrappedKey.Length is not (24 or 40))
            return false;

        var attempts = 0;
        foreach (var pass in new[] { identity.PrivateD, identity.PublicX })
        {
            if (pass.Length < 8)
                continue;

            var kek32 = PcsHmacKdf.Pbkdf2FullMasterKey(pass);
            foreach (var kek16 in new[]
                     {
                         kek32.AsSpan(0, 16).ToArray(),
                         kek32.Length >= 32 ? kek32.AsSpan(16, 16).ToArray() : kek32,
                     })
            {
                foreach (var wrapLen in new[] { wrappedKey.Length })
                {
                    if (wrapLen > wrappedKey.Length)
                        continue;
                    attempts++;
                    try
                    {
                        var plain = AesKeyWrap.Unwrap(kek16, wrappedKey[..wrapLen]);
                        if (plain.Length >= 16)
                        {
                            masterKey = plain.Length >= 32 ? plain.AsSpan(0, 32).ToArray() : plain;
                            // #region agent log
                            AgentWaLog(
                                "H-BP5",
                                "create_with_exported_ok",
                                new
                                {
                                    wrapLen = wrappedKey.Length,
                                    usedLen = wrapLen,
                                    passLen = pass.Length,
                                    passIsD = pass.Length == identity.PrivateD.Length
                                        && pass.SequenceEqual(identity.PrivateD),
                                    plainLen = masterKey.Length,
                                    pub8 = Convert.ToHexString(
                                        identity.PublicX.AsSpan(0, Math.Min(8, identity.PublicX.Length))),
                                });
                            // #endregion
                            return true;
                        }
                    }
                    catch
                    {
                        // next candidate
                    }
                }
            }
        }

        // #region agent log
        // Rate-limit: fail log su ogni wrap candidate congela catalog MB-sized.
        var failN = System.Threading.Interlocked.Increment(ref s_cwFailLogged);
        if (failN <= 5 || failN % 500 == 0)
        {
            AgentWaLog(
                "H-HANG1",
                "create_with_exported_fail",
                new
                {
                    wrapLen = wrappedKey.Length,
                    wrapHead = Convert.ToHexString(wrappedKey[..Math.Min(4, wrappedKey.Length)]),
                    attempts,
                    failN,
                    pub8 = Convert.ToHexString(identity.PublicX.AsSpan(0, Math.Min(8, identity.PublicX.Length))),
                });
        }
        // #endregion
        return false;
    }

    private static ProtectionZoneKeys BuildZoneKeys(
        byte[] master,
        PcsCompactPrivateKey match,
        byte[]? dataBlob,
        string? protectionInfoTag)
    {
        var decryptKey = PcsNistKdf.CtrHmacSha256(master, DecryptKeyLabel, 16);
        byte[]? nested = null;
        var nestedKeys = new List<PcsCompactPrivateKey>();
        if (dataBlob is { Length: > 0 })
        {
            nested = TryDecryptDataBlob(decryptKey, master, dataBlob);
            if (nested is { Length: > 0 })
                nestedKeys.AddRange(TryParseProtectionObjectKeys(nested));
        }

        // #region agent log
        var zbN = System.Threading.Interlocked.Increment(ref s_zoneBuildLogged);
        if (zbN <= 8 || zbN % 50 == 0)
        {
            AgentWaLog(
                "H-BP2",
                "zone_build",
                new
                {
                    n = zbN,
                    keyIdPrefix = Convert.ToHexString(match.KeyId.AsSpan(0, Math.Min(8, match.KeyId.Length))),
                    masterLen = master.Length,
                    blobLen = dataBlob?.Length ?? 0,
                    blobVer = dataBlob is { Length: > 0 } ? (int)dataBlob[0] : -1,
                    nestedLen = nested?.Length ?? 0,
                    nestedKeys = nestedKeys.Count,
                });
        }
        // #endregion

        return new ProtectionZoneKeys(
            master,
            decryptKey,
            protectionInfoTag,
            nested,
            match.PublicX,
            Convert.ToHexString(match.KeyId),
            nestedKeys);
    }

    /// <summary>GCMDataA su dataBlob zone/record (decryptKey poi master; strip OCTET STRING se presente).</summary>
    private static byte[]? TryDecryptDataBlob(byte[] decryptKey, byte[] master, byte[] dataBlob)
    {
        foreach (var blob in DataBlobVariants(dataBlob))
        {
            foreach (var key in new[] { decryptKey, master })
            {
                try
                {
                    return PcsGcmDataA.Decrypt(key, blob);
                }
                catch
                {
                    // next
                }
            }
        }

        return null;
    }

    private static IEnumerable<byte[]> DataBlobVariants(byte[] dataBlob)
    {
        yield return dataBlob;
        // Cont[0] a volte passato ancora come OCTET STRING (04 …).
        if (dataBlob.Length > 2 && dataBlob[0] == 0x04 &&
            TryReadTagLen(dataBlob, 0, out _, out _, out _, out var off, out var len, out _))
        {
            yield return dataBlob.AsSpan(off, len).ToArray();
        }
    }

    // #region agent log
    private static int s_cwFailLogged;
    private static int s_zoneBuildLogged;

    private static void AgentWaLog(string hypothesisId, string message, object data)
    {
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "backup-pcs1",
                ["hypothesisId"] = hypothesisId,
                ["location"] = "PcsProtectionZone",
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            File.AppendAllText(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                line + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    public static List<PcsCompactPrivateKey> TryParseProtectionObjectKeys(ReadOnlySpan<byte> protectionObjectDer)
    {
        var list = new List<PcsCompactPrivateKey>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        void AddRange(IEnumerable<PcsCompactPrivateKey> keys)
        {
            foreach (var k in keys)
            {
                var id = Convert.ToHexString(k.KeyId);
                if (seen.Add(id))
                    list.Add(k);
            }
        }

        try
        {
            var data = protectionObjectDer.ToArray();
            if (!TryReadTagLen(data, 0, out var tc, out var tv, out _, out var cOff, out var cLen, out _))
                return ScanAppl2KeySets(protectionObjectDer, AddRange, list);
            if (tc != (int)TagClass.Universal || tv != (int)UniversalTagNumber.Sequence)
                return ScanAppl2KeySets(protectionObjectDer, AddRange, list);

            var seq = data.AsSpan(cOff, cLen);
            var off = 0;
            while (off < seq.Length)
            {
                if (off >= seq.Length)
                    break;
                var tagByte = seq[off];
                if (!TryReadTagLen(seq, off, out var tagClass, out var tagValue, out _,
                        out var contentOff, out var contentLen, out var next))
                    break;
                var content = seq.Slice(contentOff, contentLen);

                // Cont[1] NOS singolo, Cont[2] SET OF NOS — match anche su byte tag.
                var isCont1 = tagByte is 0xA1 or 0x81
                              || (tagClass == (int)TagClass.ContextSpecific && tagValue == 1);
                var isCont2 = tagByte is 0xA2 or 0x82
                              || (tagClass == (int)TagClass.ContextSpecific && tagValue == 2);

                if (isCont2)
                {
                    ReadOnlySpan<byte> setContent = content;
                    if (content.Length > 0 && content[0] == 0x31 &&
                        TryReadTagLen(content, 0, out _, out _, out _, out var sOff, out var sLen, out _))
                        setContent = content.Slice(sOff, sLen);

                    var sOff2 = 0;
                    while (sOff2 < setContent.Length)
                    {
                        if (!TryReadTagLen(setContent, sOff2, out _, out _, out _,
                                out var nOff, out var nLen, out var nNext))
                            break;
                        var nosKey = TryExtractNosKeyOctet(setContent.Slice(nOff, nLen));
                        if (nosKey is { Length: > 0 })
                        {
                            try { AddRange(PcsDer.ParseKeySetPrivateKeys(nosKey)); }
                            catch { /* NOS.key non-KeySet */ }
                        }

                        sOff2 = nNext;
                    }
                }
                else if (isCont1)
                {
                    var nosKey = TryExtractNosKeyOctet(content);
                    if (nosKey is { Length: > 0 })
                    {
                        try { AddRange(PcsDer.ParseKeySetPrivateKeys(nosKey)); }
                        catch { /* ignore */ }
                    }
                }

                off = next;
            }
        }
        catch
        {
            // fall through to scan
        }

        if (list.Count == 0)
            ScanAppl2KeySets(protectionObjectDer, AddRange, list);

        return list;
    }

    private static List<PcsCompactPrivateKey> ScanAppl2KeySets(
        ReadOnlySpan<byte> data,
        Action<IEnumerable<PcsCompactPrivateKey>> addRange,
        List<PcsCompactPrivateKey> list)
    {
        var bytes = data.ToArray();
        for (var i = 0; i + 4 < bytes.Length; i++)
        {
            if (bytes[i] != 0x62)
                continue;
            if (!TryReadTagLen(bytes, i, out var tc, out var tv, out _, out _, out _, out var next))
                continue;
            if (tc != (int)TagClass.Application || tv != 2)
                continue;
            if (next - i < 40)
                continue;
            try
            {
                addRange(PcsDer.ParseKeySetPrivateKeys(bytes.AsSpan(i, next - i)));
                i = next - 1;
            }
            catch
            {
                // false positive 0x62
            }
        }

        return list;
    }

    private static byte[]? TryExtractNosKeyOctet(ReadOnlySpan<byte> nosSeqContent)
    {
        // NOS: INTEGER, [INTEGER], OCTET STRING
        // nosSeqContent may be SEQUENCE content or full SEQUENCE TLV
        ReadOnlySpan<byte> seq = nosSeqContent;
        if (nosSeqContent.Length > 0 && nosSeqContent[0] == 0x30 &&
            TryReadTagLen(nosSeqContent, 0, out _, out _, out _, out var off, out var len, out _))
            seq = nosSeqContent.Slice(off, len);

        var i = 0;
        // skip first INTEGER
        if (!TryReadTagLen(seq, i, out _, out _, out _, out _, out _, out i))
            return null;
        // optional second INTEGER or OCTET
        if (i >= seq.Length)
            return null;
        if (!TryReadTagLen(seq, i, out var tc, out var tv, out _, out var cOff, out var cLen, out var next))
            return null;
        if (tc == (int)TagClass.Universal && tv == (int)UniversalTagNumber.Integer)
        {
            i = next;
            if (!TryReadTagLen(seq, i, out tc, out tv, out _, out cOff, out cLen, out _))
                return null;
        }

        if (tc == (int)TagClass.Universal && tv == (int)UniversalTagNumber.OctetString)
            return seq.Slice(cOff, cLen).ToArray();
        return null;
    }

    /// <summary>Cerca DER appl[1] ProtectionInfo nel window di un record CloudDocs.</summary>
    public static byte[]? TryExtractRecordProtectionInfoDer(ReadOnlySpan<byte> recordWindow)
    {
        var best = (byte[]?)null;
        for (var i = 0; i + 4 < recordWindow.Length; i++)
        {
            if (recordWindow[i] != 0x61)
                continue;
            if (!TrySliceTlv(recordWindow, i, out var slice))
                continue;
            // Record PI tipicamente ~400 B (zone ~570+, recordProtectionInfo ~1500)
            if (slice.Length is < 200 or > 900)
                continue;
            if (best is null || slice.Length > best.Length)
                best = slice.ToArray();
        }

        return best;
    }

    public static byte[]? TryDecryptField(
        byte[] decryptKey,
        ReadOnlySpan<byte> ciphertext,
        params string[] identifiers)
    {
        foreach (var id in identifiers)
        {
            try
            {
                return PcsGcmDataA.Decrypt(decryptKey, ciphertext, Encoding.UTF8.GetBytes(id));
            }
            catch
            {
                // next
            }
        }

        try
        {
            return PcsGcmDataA.Decrypt(decryptKey, ciphertext);
        }
        catch
        {
            return null;
        }
    }

    private static byte[]? ExtractDataBlob(byte[] der)
    {
        // Walk TLV con match su byte di tag (0xA0/0x80), senza dipendere da TagClass enum.
        if (der.Length < 4 || der[0] != 0x61)
            return null;
        if (!TryReadTagLen(der, 0, out _, out _, out _, out var aOff, out var aLen, out _))
            return null;
        var app = der.AsSpan(aOff, aLen);
        if (app.Length < 2 || app[0] != 0x30)
            return null;
        if (!TryReadTagLen(app, 0, out _, out _, out _, out var sOff, out var sLen, out _))
            return null;
        var seq = app.Slice(sOff, sLen);
        var off = 0;
        while (off < seq.Length)
        {
            if (off >= seq.Length)
                break;
            var tagByte = seq[off];
            if (!TryReadTagLen(seq, off, out _, out _, out _, out var cOff, out var cLen, out var next))
                break;
            // Context [0] constructed 0xA0 o primitive 0x80
            if (tagByte is 0xA0 or 0x80)
            {
                var content = seq.Slice(cOff, cLen);
                if (content.Length > 0 && content[0] == 0x04 &&
                    TryReadTagLen(content, 0, out _, out _, out _, out var iOff, out var iLen, out _))
                    return content.Slice(iOff, iLen).ToArray();
                return content.ToArray();
            }

            off = next;
        }

        return null;
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        for (var i = 0; i <= hay.Length - needle.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length; j++)
                if (hay[i + j] != needle[j]) { ok = false; break; }
            if (ok) return i;
        }

        return -1;
    }

    public static byte[]? TryDecryptField(
        ProtectionZoneKeys zone,
        ReadOnlySpan<byte> ciphertext,
        params string[] identifiers)
    {
        foreach (var id in identifiers)
        {
            try
            {
                return PcsGcmDataA.Decrypt(zone.DecryptKey, ciphertext, Encoding.UTF8.GetBytes(id));
            }
            catch
            {
                // next
            }
        }

        try
        {
            return PcsGcmDataA.Decrypt(zone.DecryptKey, ciphertext);
        }
        catch
        {
            return null;
        }
    }

    private sealed record EncryptedKeyItem(byte[] MasterPublic, byte[] WrappedKey);

    private static bool TryParseProtectionInfo(
        byte[] der,
        out List<EncryptedKeyItem> encryptedKeys,
        out byte[]? dataBlob)
    {
        encryptedKeys = [];
        dataBlob = null;
        try
        {
            // Solo walk TLV manuale (AsnReader BER fallisce su alcuni PI CloudDocs grandi).
            if (!TrySliceTlv(der, 0, out var appTlv))
                return false;
            if (!TryReadTagLen(appTlv, 0, out var appTc, out var appTv, out _, out var appOff, out var appLen, out _))
                return false;
            if (appTc != (int)TagClass.Application || appTv != 1)
                return false;

            var appValue = appTlv.Slice(appOff, appLen);
            if (!TryReadTagLen(appValue, 0, out var seqTc, out var seqTv, out _, out var seqOff, out var seqLen, out _))
                return false;
            if (seqTc != (int)TagClass.Universal || seqTv != (int)UniversalTagNumber.Sequence)
                return false;

            var seqValue = appValue.Slice(seqOff, seqLen);
            var off = 0;
            while (off < seqValue.Length)
            {
                if (!TryReadTagLen(seqValue, off, out var tagClass, out var tagValue, out _,
                        out var contentOff, out var contentLen, out var next))
                    break;
                var content = seqValue.Slice(contentOff, contentLen);

                if (tagClass == (int)TagClass.Universal &&
                    tagValue == (int)UniversalTagNumber.Sequence &&
                    encryptedKeys.Count == 0)
                {
                    ParseEncryptedKeys(content.ToArray(), encryptedKeys);
                }
                else if (tagClass == (int)TagClass.ContextSpecific && tagValue == 0
                         || seqValue[off] is 0xA0 or 0x80)
                {
                    if (content.Length > 0 && content[0] == 0x04 &&
                        TryReadTagLen(content, 0, out _, out _, out _,
                            out var iOff, out var iLen, out _))
                        dataBlob = content.Slice(iOff, iLen).ToArray();
                    else
                        dataBlob = content.ToArray();
                }

                off = next;
            }

            return encryptedKeys.Count > 0;
        }
        catch
        {
            return false;
        }
    }

    private static void ParseEncryptedKeys(byte[] ekSeqContent, List<EncryptedKeyItem> into)
    {
        // EncryptedKeys SEQUENCE content: INTEGER x, SET OF EncryptedKey, optional tagged
        var seqReader = new AsnReader(
            BuildSequence(ekSeqContent),
            AsnEncodingRules.BER).ReadSequence();
        _ = seqReader.ReadInteger();
        var set = seqReader.ReadSetOf();
        while (set.HasData)
        {
            var item = set.ReadSequence();
            var nos = item.ReadSequence();
            _ = nos.ReadInteger();
            if (nos.HasData &&
                nos.PeekTag().TagClass == TagClass.Universal &&
                nos.PeekTag().TagValue == (int)UniversalTagNumber.Integer)
                _ = nos.ReadInteger();
            var masterPub = nos.ReadOctetString();
            var wrapped = item.ReadOctetString();
            into.Add(new EncryptedKeyItem(masterPub, wrapped));
        }
    }

    private static byte[] BuildSequence(ReadOnlySpan<byte> content)
    {
        var len = content.Length;
        byte[] header;
        if (len < 128)
            header = [(byte)0x30, (byte)len];
        else if (len <= 0xFF)
            header = [0x30, 0x81, (byte)len];
        else
            header = [0x30, 0x82, (byte)(len >> 8), (byte)len];
        var result = new byte[header.Length + len];
        header.CopyTo(result, 0);
        content.CopyTo(result.AsSpan(header.Length));
        return result;
    }

    private static bool TryReadTagLen(
        ReadOnlySpan<byte> buf,
        int offset,
        out int tagClass,
        out int tagValue,
        out bool constructed,
        out int contentOffset,
        out int contentLength,
        out int nextOffset)
    {
        tagClass = 0;
        tagValue = 0;
        constructed = false;
        contentOffset = offset;
        contentLength = 0;
        nextOffset = offset;
        if (offset >= buf.Length)
            return false;

        var tagByte = buf[offset];
        if ((tagByte & 0x1F) == 0x1F)
            return false; // long tag non gestito

        tagClass = (tagByte >> 6) & 0x3;
        tagValue = tagByte & 0x1F;
        constructed = (tagByte & 0x20) != 0;

        var i = offset + 1;
        if (i >= buf.Length)
            return false;
        var lb = buf[i++];
        int len;
        if ((lb & 0x80) == 0)
        {
            len = lb;
        }
        else
        {
            var n = lb & 0x7F;
            if (n is 0 or > 4 || i + n > buf.Length)
                return false;
            len = 0;
            for (var k = 0; k < n; k++)
                len = (len << 8) | buf[i++];
            if (len < 0)
                return false;
        }

        if (i + len > buf.Length)
            return false;
        contentOffset = i;
        contentLength = len;
        nextOffset = i + len;
        return true;
    }

    private static bool TrySliceTlv(ReadOnlySpan<byte> buf, int offset, out ReadOnlySpan<byte> fullTlv)
    {
        fullTlv = default;
        if (!TryReadTagLen(buf, offset, out _, out _, out _, out _, out _, out var next))
            return false;
        fullTlv = buf[offset..next];
        return true;
    }
}
