using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Estrae bottle/metadata da <c>get_records</c> (campo <c>metadata</c> = bplist base64).
/// Per <c>com.apple.protectedcloudstorage.record</c> espone i campi SecureBackup / PCS
/// (<c>kPCSMetadataEscrowedKeys</c>, KeyRegistry, IdentityPublicData, …).
/// </summary>
public static class EscrowBottlesParser
{
    public const string PcsRecordLabel = "com.apple.protectedcloudstorage.record";

    /// <summary>
    /// Variante ADP / dual-escrow: spesso contiene <c>kPCSMetadataEscrowedKeys</c>
    /// quando il record primario ha solo iCDP metadata.
    /// </summary>
    public const string PcsRecordLabelDouble = "com.apple.protectedcloudstorage.record.double";

    public static async Task SaveBottlesJsonAsync(
        string outputDirectory,
        byte[] getRecordsXmlOrBin,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var bottles = Parse(getRecordsXmlOrBin);
        var path = Path.Combine(outputDirectory, "escrow_bottles.json");
        var json = JsonSerializer.Serialize(new
        {
            count = bottles.Count,
            bottles = bottles.Select(b => new
            {
                b.Label,
                b.RecordStatus,
                b.SilentAttemptAllowed,
                b.RemainingAttempts,
                b.Serial,
                b.Build,
                b.BottleId,
                b.BackupKeybagDigestBase64,
                b.SecureBackupUsesMultipleICSCs,
                b.Timestamp,
                b.MetadataKeys,
                pcs = b.Pcs is null ? null : new
                {
                    b.Pcs.ClientVersion,
                    b.Pcs.IcdpArmed,
                    hasEscrowedKeys = b.Pcs.EscrowedKeys is { Length: > 0 },
                    escrowedKeysBytes = b.Pcs.EscrowedKeys?.Length,
                    hasKeyRegistry = b.Pcs.KeyRegistry is { Length: > 0 },
                    keyRegistryBytes = b.Pcs.KeyRegistry?.Length,
                    hasIdentityPublicData = b.Pcs.IdentityPublicData is { Length: > 0 },
                    identityPublicDataBytes = b.Pcs.IdentityPublicData?.Length,
                    hasStableMetadata = b.Pcs.StableMetadata is { Length: > 0 },
                    hasIcloudDataProtection = b.Pcs.IcloudDataProtection is { Length: > 0 },
                    b.Pcs.IcdpKeys,
                    b.Pcs.DataProtectionKeys
                }
            })
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(path, json, ct);

        // Preferisci il record che ha EscrowedKeys (ADP: spesso solo .double).
        var pcsBottle = PickPcsBottleWithEscrowedKeys(bottles);
        if (pcsBottle?.Pcs is { } p)
            await SavePcsArtifactsAsync(outputDirectory, pcsBottle, p, ct);
    }

    /// <summary>
    /// Sceglie il bottle PCS da cui materializzare <c>pcs_escrowed_keys.bin</c>.
    /// Ordine: primario con keys → .double con keys → qualunque con keys → primario (altri artifact).
    /// </summary>
    internal static EscrowBottleInfo? PickPcsBottleWithEscrowedKeys(
        IReadOnlyList<EscrowBottleInfo> bottles)
    {
        static bool HasKeys(EscrowBottleInfo b) =>
            b.Pcs?.EscrowedKeys is { Length: > 32 };

        var primary = bottles.FirstOrDefault(b =>
            b.Label.Equals(PcsRecordLabel, StringComparison.Ordinal));
        if (primary is not null && HasKeys(primary))
            return primary;

        var dbl = bottles.FirstOrDefault(b =>
            b.Label.Equals(PcsRecordLabelDouble, StringComparison.Ordinal));
        if (dbl is not null && HasKeys(dbl))
            return dbl;

        var any = bottles.FirstOrDefault(HasKeys);
        if (any is not null)
            return any;

        return primary ?? dbl;
    }

    private static async Task SavePcsArtifactsAsync(
        string outputDirectory,
        EscrowBottleInfo bottle,
        PcsRecordMetadata pcs,
        CancellationToken ct)
    {
        if (bottle.RawMetadataBplist is { Length: > 0 } raw)
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "pcs_metadata.bplist"), raw, ct);

        if (pcs.EscrowedKeys is { Length: > 0 } keys)
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "pcs_escrowed_keys.bin"), keys, ct);

        if (pcs.KeyRegistry is { Length: > 0 } reg)
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "pcs_key_registry.bin"), reg, ct);

        if (pcs.IdentityPublicData is { Length: > 0 } idPub)
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "pcs_identity_public.bin"), idPub, ct);

        if (pcs.StableMetadata is { Length: > 0 } stable)
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "pcs_stable_metadata.bin"), stable, ct);

        if (pcs.IcloudDataProtection is { Length: > 0 } idp)
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "pcs_icloud_data_protection.bin"), idp, ct);

        if (!string.IsNullOrEmpty(bottle.BackupKeybagDigestBase64))
        {
            await File.WriteAllTextAsync(
                Path.Combine(outputDirectory, "pcs_backup_keybag_digest.b64"),
                bottle.BackupKeybagDigestBase64,
                ct);
        }

        var summary = new
        {
            label = bottle.Label,
            bottle.Timestamp,
            bottle.BackupKeybagDigestBase64,
            pcs.ClientVersion,
            pcs.IcdpArmed,
            escrowedKeysBytes = pcs.EscrowedKeys?.Length,
            keyRegistryBytes = pcs.KeyRegistry?.Length,
            identityPublicDataBytes = pcs.IdentityPublicData?.Length,
            note =
                "get_records metadata = materiale pubblico/client PCS. " +
                "Le chiavi private arrivano da recover (AES-CBC con K_SRP). " +
                "Auth label PCS = MME; x=SHA(salt|SHA(dsid:secret)) (HITCON 2017 p.33).",
        };
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "pcs_metadata_summary.json"),
            JsonSerializer.Serialize(summary, new JsonSerializerOptions { WriteIndented = true }),
            ct);
    }

    public static IReadOnlyList<EscrowBottleInfo> Parse(byte[] getRecordsBody)
    {
        if (getRecordsBody is not { Length: > 0 })
            return [];

        Dictionary<string, object?> root;
        try
        {
            root = AppleXmlPlist.Parse(NormalizeXmlBody(getRecordsBody));
        }
        catch
        {
            try
            {
                var text = Encoding.UTF8.GetString(getRecordsBody).TrimStart('\uFEFF', '\uFFFD', '\0');
                root = AppleXmlPlist.Parse(Encoding.UTF8.GetBytes(text));
            }
            catch
            {
                return [];
            }
        }

        if (!root.TryGetValue("metadataList", out var listObj) || listObj is not IList<object?> list)
            return [];

        var bottles = new List<EscrowBottleInfo>();
        foreach (var item in list)
        {
            if (item is not Dictionary<string, object?> dict)
                continue;

            var label = AppleXmlPlist.GetString(dict, "label") ?? "";
            var status = AppleXmlPlist.GetString(dict, "recordStatus");
            var silent = dict.TryGetValue("silentAttemptAllowed", out var sa) && sa is true;
            var remaining = ParseRemaining(dict);
            var metaB64 = AppleXmlPlist.GetString(dict, "metadata");
            var metaBytes = AppleXmlPlist.GetData(dict, "metadata");
            var decoded = DecodeMetadata(metaBytes, metaB64);

            bottles.Add(new EscrowBottleInfo(
                label,
                status,
                silent,
                remaining,
                decoded.Serial,
                decoded.Build,
                decoded.BottleId,
                decoded.BackupKeybagDigestBase64,
                decoded.SecureBackupUsesMultipleICSCs,
                decoded.Timestamp,
                decoded.Keys,
                decoded.RawBplist,
                decoded.Pcs));
        }

        return bottles;
    }

    private static byte[] NormalizeXmlBody(byte[] body)
    {
        // Capture MITM a volte salvano gzip: prova inflate best-effort.
        if (body.Length > 2 && body[0] == 0x1F && body[1] == 0x8B)
        {
            try
            {
                using var ms = new MemoryStream(body);
                using var gz = new System.IO.Compression.GZipStream(ms, System.IO.Compression.CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                gz.CopyTo(outMs);
                return outMs.ToArray();
            }
            catch
            {
                // fallback: cerca <?xml nel blob parziale
                var idx = IndexOf(body, "<?xml"u8);
                if (idx < 0)
                    idx = IndexOf(body, "<plist"u8);
                if (idx >= 0)
                    return body[idx..];
            }
        }

        return body;
    }

    private static int IndexOf(ReadOnlySpan<byte> hay, ReadOnlySpan<byte> needle)
    {
        for (var i = 0; i <= hay.Length - needle.Length; i++)
        {
            if (hay[i..].StartsWith(needle))
                return i;
        }

        return -1;
    }

    private static int? ParseRemaining(Dictionary<string, object?> dict)
    {
        if (dict.TryGetValue("remainingAttempts", out var v))
        {
            return v switch
            {
                int i => i,
                long l => (int)l,
                string s when int.TryParse(s, out var n) => n,
                _ => null
            };
        }

        return null;
    }

    private static MetadataFields DecodeMetadata(byte[]? rawData, string? base64)
    {
        byte[]? raw = rawData;
        if (raw is null && !string.IsNullOrWhiteSpace(base64))
        {
            try
            {
                raw = Convert.FromBase64String(
                    base64.Replace("\n", "", StringComparison.Ordinal)
                        .Replace("\r", "", StringComparison.Ordinal)
                        .Replace(" ", "", StringComparison.Ordinal));
            }
            catch
            {
                return default;
            }
        }

        if (raw is not { Length: > 8 })
            return default;

        if (AppleBinaryPlist.TryParseDict(raw, out var dict, out _))
            return FromParsedDict(raw, dict);

        // Fallback euristico (capture corrotti / bplist troncati).
        return FromHeuristicScan(raw);
    }

    private static MetadataFields FromParsedDict(byte[] raw, Dictionary<string, object?> dict)
    {
        var keys = dict.Keys.OrderBy(k => k, StringComparer.Ordinal).ToList();
        CollectAsciiKeys(raw, keys);
        var digest = AsBytes(dict, "BackupKeybagDigest");
        var pcs = TryBuildPcs(dict);
        pcs = EnrichPcsWithRawEscrowedKeys(raw, pcs);

        return new MetadataFields(
            AsString(dict, "serial") ?? AsString(dict, "Serial"),
            AsString(dict, "build") ?? AsString(dict, "Build"),
            AsString(dict, "bottleID") ?? AsString(dict, "BottleID"),
            digest is null ? null : Convert.ToBase64String(digest),
            AsBool(dict, "SecureBackupUsesMultipleICSCs")
            || AsBool(dict, "SecureBackupUsesMultipleiCSCs"),
            AsString(dict, "com.apple.securebackup.timestamp"),
            keys.Distinct(StringComparer.Ordinal).OrderBy(k => k, StringComparer.Ordinal).ToList(),
            raw,
            pcs);
    }

    private static PcsRecordMetadata? EnrichPcsWithRawEscrowedKeys(byte[] raw, PcsRecordMetadata? pcs)
    {
        if (pcs?.EscrowedKeys is { Length: > 32 })
            return pcs;

        var extracted = TryExtractEscrowedKeysFromRawBplist(raw);
        if (extracted is null)
            return pcs;

        if (pcs is null)
        {
            return new PcsRecordMetadata(
                null, null, null, null, null,
                extracted, null, null,
                ["kPCSMetadataEscrowedKeys"],
                ["(heuristic-raw-bplist)"]);
        }

        return pcs with { EscrowedKeys = extracted };
    }

    private static PcsRecordMetadata? TryBuildPcs(Dictionary<string, object?> dict)
    {
        var hasPcsMarker =
            dict.ContainsKey("SecureBackupiCloudDataProtection")
            || dict.ContainsKey("SecureBackupKeyRegistry")
            || dict.ContainsKey("kPCSMetadataEscrowedKeys")
            || dict.ContainsKey("SecureBackupiCloudIdentityPublicData");
        if (!hasPcsMarker)
            return null;

        byte[]? escrowedKeys = null;
        byte[]? icdp = null;
        bool? icdpArmed = null;
        var idpKeys = new List<string>();
        var dpKeys = new List<string>();

        if (dict.TryGetValue("SecureBackupiCloudDataProtection", out var idpObj))
        {
            var idpDict = AsDict(idpObj) ?? TryParseNestedDict(idpObj);
            if (idpDict is not null)
            {
                dpKeys.AddRange(idpDict.Keys);
                escrowedKeys = AsBytes(idpDict, "kPCSMetadataEscrowedKeys")
                               ?? AsBytes(idpDict, "EscrowedKeys")
                               ?? AsBytes(idpDict, "escrowedKeys");
                icdp = AsBytes(idpDict, "kPCSMetadataiCDP") ?? AsBytes(idpDict, "iCDP");
                if (idpDict.TryGetValue("kPCSMetadataiCDPArmed", out var armed))
                    icdpArmed = armed is true || armed is bool b && b;
            }
            else if (idpObj is byte[] idpBlob)
            {
                dpKeys.Add("(raw-bplist)");
                if (AppleBinaryPlist.TryParseDict(idpBlob, out var nested, out _))
                {
                    dpKeys.Clear();
                    dpKeys.AddRange(nested.Keys);
                    escrowedKeys = AsBytes(nested, "kPCSMetadataEscrowedKeys");
                    icdp = AsBytes(nested, "kPCSMetadataiCDP");
                    if (nested.TryGetValue("kPCSMetadataiCDPArmed", out var armed))
                        icdpArmed = armed is true;
                }

                escrowedKeys ??= TryExtractEscrowedKeysFromRawBplist(idpBlob);
            }
        }

        // A volte EscrowedKeys è al top-level.
        escrowedKeys ??= AsBytes(dict, "kPCSMetadataEscrowedKeys");

        return new PcsRecordMetadata(
            AsString(dict, "SecureBackupClientVersion"),
            AsBytes(dict, "SecureBackupKeyRegistry"),
            AsBytes(dict, "SecureBackupiCloudIdentityPublicData"),
            AsBytes(dict, "SecureBackupStableMetadata"),
            AsBytes(dict, "SecureBackupiCloudDataProtection")
            ?? (dict.TryGetValue("SecureBackupiCloudDataProtection", out var idp) && idp is byte[] bb
                ? bb
                : null),
            escrowedKeys,
            icdp,
            icdpArmed,
            idpKeys,
            dpKeys);
    }

    /// <summary>
    /// Estrae <c>kPCSMetadataEscrowedKeys</c> (BackupEscrow DER appl[4]=0x64) dal bplist
    /// anche quando il dict parser vede solo poche chiavi top-level (caso tipico PCS ~15 KiB).
    /// </summary>
    public static byte[]? TryExtractEscrowedKeysFromRawBplist(byte[] raw)
    {
        if (raw.Length < 64)
            return null;

        // 1) Nested bplist dentro data objects / ClientMetadata.
        for (var i = 0; i + 8 < raw.Length; i++)
        {
            if (raw[i] != (byte)'b' || i + 8 > raw.Length)
                continue;
            if (!raw.AsSpan(i, 6).SequenceEqual("bplist"u8))
                continue;
            if (i == 0)
                continue; // skip root magic
            // Prova sotto-buffer fino al trailer verosimile (max 64 KiB).
            var maxLen = Math.Min(raw.Length - i, 65536);
            for (var len = maxLen; len >= 64; len -= 16)
            {
                var slice = raw.AsSpan(i, len);
                if (!AppleBinaryPlist.TryParseDict(slice, out var nested, out _))
                    continue;
                var fromNested = TryBuildPcs(nested)?.EscrowedKeys
                                 ?? AsBytes(nested, "kPCSMetadataEscrowedKeys");
                if (fromNested is { Length: > 32 })
                    return fromNested;
                break;
            }
        }

        // 2) Dopo il nome chiave: oggetto data bplist (0x4F ‖ int16-len ‖ payload)
        //    oppure DER BackupEscrow (0x64 …).
        var keyIdx = IndexOfAscii(raw, "kPCSMetadataEscrowedKeys");
        if (keyIdx < 0)
            return null;

        var from = keyIdx + "kPCSMetadataEscrowedKeys".Length;
        for (var i = from; i < Math.Min(raw.Length - 8, from + 96); i++)
        {
            // bplist data, extended size with 2-byte length: 0x4F 0x11 LL LL
            if (raw[i] == 0x4F && i + 4 < raw.Length && (raw[i + 1] & 0xF0) == 0x10)
            {
                var sizeInfo = raw[i + 1] & 0x0F;
                var nbytes = 1 << sizeInfo;
                if (i + 2 + nbytes > raw.Length)
                    continue;
                var len = 0;
                for (var k = 0; k < nbytes; k++)
                    len = (len << 8) | raw[i + 2 + k];
                var dataStart = i + 2 + nbytes;
                if (len is < 32 or > 200_000 || dataStart + len > raw.Length)
                    continue;
                var payload = raw.AsSpan(dataStart, len).ToArray();
                if (payload[0] == 0x64 || LooksLikeBackupEscrow(payload))
                    return payload;
            }

            if (raw[i] == 0x64)
            {
                var der = TryReadDerAppl4(raw, i);
                if (der is not null)
                    return der;
            }
        }

        // 3) Scan globale primo BackupEscrow vicino alla chiave.
        for (var i = from; i < Math.Min(raw.Length - 4, from + 4096); i++)
        {
            if (raw[i] != 0x64)
                continue;
            var der = TryReadDerAppl4(raw, i);
            if (der is { Length: > 64 })
                return der;
        }

        return null;
    }

    private static bool LooksLikeBackupEscrow(byte[] data) =>
        data.Length > 8 && (data[0] == 0x64 || IndexOfAscii(data, "BackupEscrow") >= 0);

    private static byte[]? TryReadDerAppl4(byte[] data, int offset)
    {
        if (offset < 0 || offset + 2 >= data.Length || data[offset] != 0x64)
            return null;

        var p = offset + 1;
        int contentLen;
        var lenByte = data[p++];
        if ((lenByte & 0x80) == 0)
        {
            contentLen = lenByte;
        }
        else
        {
            var n = lenByte & 0x7F;
            if (n is < 1 or > 3 || p + n > data.Length)
                return null;
            contentLen = 0;
            for (var i = 0; i < n; i++)
                contentLen = (contentLen << 8) | data[p++];
        }

        if (contentLen is < 32 or > 100_000 || p + contentLen > data.Length)
            return null;

        return data.AsSpan(offset, (p - offset) + contentLen).ToArray();
    }

    private static Dictionary<string, object?>? TryParseNestedDict(object? obj)
    {
        if (obj is byte[] blob && AppleBinaryPlist.TryParseDict(blob, out var d, out _))
            return d;
        return null;
    }

    private static MetadataFields FromHeuristicScan(byte[] raw)
    {
        var keys = new List<string>();
        CollectAsciiKeys(raw, keys);

        string? GetNear(string key)
        {
            var idx = IndexOfAscii(raw, key);
            if (idx < 0)
                return null;
            return ExtractFollowingAsciiString(raw, idx + key.Length);
        }

        byte[]? digest = null;
        var digIdx = IndexOfAscii(raw, "BackupKeybagDigest");
        if (digIdx >= 0)
            digest = ExtractFollowingDataBlob(raw, digIdx + "BackupKeybagDigest".Length);

        return new MetadataFields(
            GetNear("serial") ?? GetNear("Serial"),
            GetNear("build") ?? GetNear("Build"),
            GetNear("bottleID") ?? GetNear("BottleID"),
            digest is null ? null : Convert.ToBase64String(digest),
            keys.Any(k => k.Contains("SecureBackupUsesMultipleICSCs", StringComparison.Ordinal)
                          || k.Contains("SecureBackupUsesMultipleiCSCs", StringComparison.Ordinal)),
            GetNear("com.apple.securebackup.timestamp"),
            keys,
            raw,
            EnrichPcsWithRawEscrowedKeys(
                raw,
                keys.Any(k => k.Contains("kPCSMetadata", StringComparison.Ordinal)
                              || k.Contains("SecureBackupiCloudDataProtection", StringComparison.Ordinal))
                    ? new PcsRecordMetadata(
                        GetNear("SecureBackupClientVersion"),
                        null, null, null, null, null, null, null,
                        keys.Where(k => k.StartsWith("kPCS", StringComparison.Ordinal)).ToList(),
                        keys.Where(k => k.Contains("SecureBackup", StringComparison.Ordinal)).ToList())
                    : null));
    }

    private static string? AsString(Dictionary<string, object?> dict, string key) =>
        dict.TryGetValue(key, out var v) ? v as string : null;

    private static byte[]? AsBytes(Dictionary<string, object?> dict, string key) =>
        dict.TryGetValue(key, out var v) ? v as byte[] : null;

    private static bool AsBool(Dictionary<string, object?> dict, string key) =>
        dict.TryGetValue(key, out var v) && v is true;

    private static Dictionary<string, object?>? AsDict(object? obj) =>
        obj as Dictionary<string, object?>;

    private static void CollectAsciiKeys(byte[] data, List<string> sink)
    {
        var interesting = new[]
        {
            "serial", "build", "bottleID", "BackupKeybagDigest", "escrowedSPKI",
            "SecureBackupUsesMultipleICSCs", "SecureBackupUsesMultipleiCSCs",
            "ClientMetadata", "peerInfo", "com.apple.securebackup.timestamp",
            "SecureBackupiCloudDataProtection", "SecureBackupKeyRegistry",
            "SecureBackupClientVersion", "SecureBackupStableMetadata",
            "SecureBackupiCloudIdentityPublicData",
            "kPCSMetadataiCDPArmed", "kPCSMetadataiCDP", "kPCSMetadataEscrowedKeys"
        };
        foreach (var key in interesting)
        {
            if (IndexOfAscii(data, key) >= 0)
                sink.Add(key);
        }
    }

    private static int IndexOfAscii(byte[] data, string ascii)
    {
        var needle = Encoding.ASCII.GetBytes(ascii);
        for (var i = 0; i <= data.Length - needle.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (data[i + j] != needle[j])
                {
                    ok = false;
                    break;
                }
            }

            if (ok)
                return i;
        }

        return -1;
    }

    private static string? ExtractFollowingAsciiString(byte[] data, int from)
    {
        for (var i = from; i < Math.Min(data.Length, from + 64); i++)
        {
            if (data[i] is >= 0x20 and < 0x7F and not (byte)'$')
            {
                var start = i;
                while (i < data.Length && data[i] is >= 0x20 and < 0x7F)
                    i++;
                var s = Encoding.ASCII.GetString(data, start, i - start);
                if (s.Length >= 4 && !s.StartsWith("bplist", StringComparison.Ordinal))
                    return s;
            }
        }

        return null;
    }

    private static byte[]? ExtractFollowingDataBlob(byte[] data, int from)
    {
        for (var len = 32; len >= 16; len -= 4)
        {
            for (var i = from; i <= Math.Min(data.Length - len, from + 48); i++)
            {
                var slice = data.AsSpan(i, len);
                var ascii = 0;
                foreach (var b in slice)
                {
                    if (b is >= 0x20 and < 0x7F)
                        ascii++;
                }

                if (ascii < len / 2)
                    return slice.ToArray();
            }
        }

        return null;
    }

    private readonly record struct MetadataFields(
        string? Serial,
        string? Build,
        string? BottleId,
        string? BackupKeybagDigestBase64,
        bool SecureBackupUsesMultipleICSCs,
        string? Timestamp,
        IReadOnlyList<string> Keys,
        byte[]? RawBplist,
        PcsRecordMetadata? Pcs);
}

public sealed record PcsRecordMetadata(
    string? ClientVersion,
    byte[]? KeyRegistry,
    byte[]? IdentityPublicData,
    byte[]? StableMetadata,
    byte[]? IcloudDataProtection,
    byte[]? EscrowedKeys,
    byte[]? Icdp,
    bool? IcdpArmed,
    IReadOnlyList<string> IcdpKeys,
    IReadOnlyList<string> DataProtectionKeys);

public sealed record EscrowBottleInfo(
    string Label,
    string? RecordStatus,
    bool SilentAttemptAllowed,
    int? RemainingAttempts,
    string? Serial,
    string? Build,
    string? BottleId,
    string? BackupKeybagDigestBase64,
    bool SecureBackupUsesMultipleICSCs,
    string? Timestamp,
    IReadOnlyList<string> MetadataKeys,
    byte[]? RawMetadataBplist = null,
    PcsRecordMetadata? Pcs = null);
