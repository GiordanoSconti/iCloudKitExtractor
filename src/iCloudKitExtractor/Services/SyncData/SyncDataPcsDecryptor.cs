using System.IO;
using System.IO.Compression;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Decrypt Sync Data CloudKit: PCS GCM DataA su campi type=20.
/// Classic (Notes/Drive): AAD = fieldName (InflatableDonkey).
/// Manatee (Find My / BeaconStore): AAD = <c>{zone}-{record}-{field}</c>
/// (rustpush <c>PCSEncryptor.decrypt_data</c>).
/// </summary>
public static class SyncDataPcsDecryptor
{
    public sealed record DecryptSummary(
        int FieldCount,
        int DecryptedCount,
        int ZoneKeys,
        string Message);

    public static DecryptSummary DecryptPayload(
        ICloudSession session,
        byte[]? zonesPayload,
        byte[] recordSyncPayload,
        string outputDirectory,
        string? containerHint = null,
        IProgress<string>? log = null)
    {
        if (recordSyncPayload is not { Length: > 64 })
            return new DecryptSummary(0, 0, 0, "payload vuoto");

        var seedKeys = CollectSeedKeys(session, log);
        if (seedKeys.Count == 0)
            return new DecryptSummary(0, 0, 0, "PCS KeySet assente (Escrow + Manatee)");

        var preferred = PreferredFieldsForContainer(containerHint);
        var fields = CloudKitEncryptedFieldScanner.Scan(recordSyncPayload, preferred);
        if (fields.Count == 0)
            return new DecryptSummary(0, 0, 0, "nessun campo type=20");

        var poolKeys = new List<PcsCompactPrivateKey>(seedKeys);
        var zones = new List<ProtectionZoneKeys>();

        log?.Report($"  PCS: {fields.Count} ciphertext type=20 — unwrap zone…");
        if (zonesPayload is { Length: > 32 })
        {
            var fromZones = PcsProtectionZone.TryUnwrapAll(zonesPayload, seedKeys);
            if (fromZones.Count > 0)
            {
                zones.AddRange(fromZones);
                poolKeys = PcsProtectionZone.MergeKeys(seedKeys, fromZones);
            }
        }

        var fromRecords = PcsProtectionZone.TryUnwrapAllIterative(recordSyncPayload, poolKeys);
        if (fromRecords.Count > 0)
        {
            zones.AddRange(fromRecords);
            poolKeys = PcsProtectionZone.MergeKeys(poolKeys, fromRecords);
        }

        log?.Report($"  PCS: zoneKeys={zones.Count} poolKeys={poolKeys.Count}");
        if (zones.Count == 0)
        {
            // Se nessuna PublicX del KeySet compare in zone/sync, il grind per-field
            // è inutile (tipico BeaconStore/Manatee: identità CKKS fuori da Escrow).
            var publicHits = CountPublicXHits(zonesPayload, recordSyncPayload, seedKeys);
            if (publicHits == 0)
            {
                log?.Report(
                    "  PCS: nessun PublicX (Escrow/Manatee) nel payload " +
                    "(zoneKeys=0, publicHits=0) — skip decrypt campi. " +
                    "BeaconStore richiede CKKS OpenVault → view Manatee (PCS service 82).");
                Directory.CreateDirectory(outputDirectory);
                File.WriteAllText(
                    Path.Combine(outputDirectory, "decrypt_blocked.txt"),
                    "zoneKeys=0 publicHits=0 — KeySet Escrow/Manatee non unwrapa ProtectionInfo. " +
                    "Esegui Escrow OTBottle/Peer + CKKS OpenVault (Manatee).");
                return new DecryptSummary(
                    fields.Count, 0, 0,
                    $"bloccato: nessuna seed key matcha PI ({fields.Count} ciphertext)");
            }

            log?.Report(
                $"  PCS: nessuna zone key da PI — unwrap per-field " +
                $"(publicHits={publicHits}, più lento)");
        }

        Directory.CreateDirectory(outputDirectory);
        var plainDir = Path.Combine(outputDirectory, "plaintext");
        Directory.CreateDirectory(plainDir);
        var metaPath = Path.Combine(outputDirectory, "decrypt_index.tsv");
        var recordsPath = Path.Combine(outputDirectory, "field_records.tsv");
        var decrypted = 0;
        var failed = 0;
        var previewOk = 0;
        var lines = new List<string> { "field\tlargest_plain\tpath\tnote" };
        var recordLines = new List<string> { "field\tidx\trecord_name\toffset\tplain_path\ttext" };

        var flat = fields.ToList();
        var total = flat.Count;
        var byName = flat.GroupBy(f => f.FieldName, StringComparer.Ordinal);
        var done = 0;
        foreach (var group in byName)
        {
            var fieldName = group.Key;
            var fieldDir = Path.Combine(plainDir, Sanitize(fieldName));
            Directory.CreateDirectory(fieldDir);
            var idx = 0;
            var okInGroup = 0;
            var failInGroup = 0;

            foreach (var field in group)
            {
                idx++;
                done++;
                if (done == 1 || done == total || done % 5 == 0)
                {
                    log?.Report(
                        $"  PCS decrypt {done}/{total} «{fieldName}» " +
                        $"(ok={decrypted} fail={failed})");
                }

                var zoneHint = ZoneHintForContainer(containerHint);
                var recordName = ResolveRecordName(
                    recordSyncPayload, field.Offset, fieldName) ?? "";
                var plain = TryDecryptCipher(
                    field.Ciphertext,
                    fieldName,
                    zones,
                    poolKeys,
                    recordSyncPayload,
                    field.Offset,
                    zoneHint,
                    recordName);
                if (plain is not { Length: > 0 })
                {
                    failInGroup++;
                    failed++;
                    continue;
                }

                okInGroup++;
                decrypted++;
                var decoded = NotesPlaintextDecoder.DecodeField(fieldName, plain);
                var processed = PostProcess(fieldName, decoded.Processed);
                var ext = GuessExtension(processed);
                var path = Path.Combine(fieldDir, $"{idx:D4}{ext}");
                File.WriteAllBytes(path, processed);

                string? textPreview = decoded.TextPreview;
                if (string.IsNullOrWhiteSpace(textPreview) && LooksLikeUtf8Text(processed))
                    textPreview = Encoding.UTF8.GetString(processed).TrimEnd('\0').Trim();

                if (!string.IsNullOrWhiteSpace(textPreview))
                {
                    previewOk++;
                    var txt = Path.Combine(fieldDir, $"{idx:D4}.txt");
                    File.WriteAllText(txt, textPreview);
                }

                recordLines.Add(
                    $"{fieldName}\t{idx}\t{recordName}\t{field.Offset}\t{path}\t{EscapeTsv(textPreview)}");
            }

            lines.Add($"{fieldName}\t{group.Count()}\t{fieldDir}\tok={okInGroup}");
            if (okInGroup > 0 || failInGroup > 0)
                log?.Report($"  decrypt {fieldName}: {okInGroup}/{group.Count()}" +
                            (failInGroup > 0 ? $" fail={failInGroup}" : ""));
        }


        File.WriteAllLines(metaPath, lines);
        File.WriteAllLines(recordsPath, recordLines);
        var msg = decrypted > 0
            ? $"ok {decrypted}/{fields.Count} campi (zoneKeys={zones.Count})"
            : $"nessun decrypt ({fields.Count} ciphertext, zoneKeys={zones.Count})";
        return new DecryptSummary(fields.Count, decrypted, zones.Count, msg);
    }

    /// <summary>
    /// Decrypt tutti i <c>record_sync_*.bin</c> sotto una cartella container,
    /// usando il <c>zones_*.bin</c> più ricco come PI.
    /// </summary>
    public static DecryptSummary DecryptContainerDirectory(
        ICloudSession session,
        string containerDirectory,
        string? containerId = null,
        IProgress<string>? log = null)
    {
        if (!Directory.Exists(containerDirectory))
            return new DecryptSummary(0, 0, 0, "dir assente");

        var zoneFiles = Directory.GetFiles(containerDirectory, "zones_*.bin");
        byte[]? richestZones = null;
        foreach (var zf in zoneFiles)
        {
            var data = File.ReadAllBytes(zf);
            if (richestZones is null || data.Length > richestZones.Length)
                richestZones = data;
        }

        var syncFiles = Directory.GetFiles(containerDirectory, "record_sync_*.bin")
            .Concat(Directory.GetFiles(containerDirectory, "query_*.bin"))
            .ToArray();
        if (syncFiles.Length == 0)
            return new DecryptSummary(0, 0, 0, "nessun record_sync/query");

        var totalFields = 0;
        var totalDecrypted = 0;
        var maxZones = 0;
        var cryptoRoot = Path.Combine(containerDirectory, "crypto");
        Directory.CreateDirectory(cryptoRoot);

        for (var i = 0; i < syncFiles.Length; i++)
        {
            var sf = syncFiles[i];
            var payload = File.ReadAllBytes(sf);
            var tag = Path.GetFileNameWithoutExtension(sf);
            log?.Report($"  PCS file {i + 1}/{syncFiles.Length}: {tag} ({payload.Length:N0} B)");
            var outDir = Path.Combine(cryptoRoot, tag);
            var summary = DecryptPayload(
                session, richestZones, payload, outDir, containerId, log);
            totalFields += summary.FieldCount;
            totalDecrypted += summary.DecryptedCount;
            maxZones = Math.Max(maxZones, summary.ZoneKeys);
        }

        var msg = totalDecrypted > 0
            ? $"ok {totalDecrypted}/{totalFields}"
            : totalFields == 0
                ? "nessun type=20"
                : $"fallito 0/{totalFields}";
        log?.Report($"  PCS decrypt: {msg} (zoneKeys≤{maxZones})");
        return new DecryptSummary(totalFields, totalDecrypted, maxZones, msg);
    }

    /// <summary>Escrow ∪ Manatee (incluso svc 82) — Sync Data / ADP / BeaconStore.</summary>
    private static List<PcsCompactPrivateKey> CollectSeedKeys(
        ICloudSession session, IProgress<string>? log) =>
        PcsSessionSeedKeys.CollectForSyncData(session, log);

    private static int CountPublicXHits(
        byte[]? zonesPayload,
        byte[] recordSyncPayload,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys)
    {
        var hits = 0;
        foreach (var key in seedKeys)
        {
            if (key.PublicX is not { Length: > 0 })
                continue;
            if (zonesPayload is { Length: > 0 } && IndexOf(zonesPayload, key.PublicX) >= 0)
            {
                hits++;
                continue;
            }

            if (IndexOf(recordSyncPayload, key.PublicX) >= 0)
                hits++;
        }

        return hits;
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        if (needle.Length == 0 || hay.Length < needle.Length)
            return -1;
        var span = hay.AsSpan();
        for (var i = 0; i <= span.Length - needle.Length; i++)
        {
            if (span.Slice(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }

    private static byte[]? TryDecryptCipher(
        byte[] ciphertext,
        string fieldName,
        List<ProtectionZoneKeys> zones,
        List<PcsCompactPrivateKey> poolKeys,
        byte[] recordSyncPayload,
        int fieldOffset,
        string? zoneName = null,
        string? recordName = null)
    {
        recordName ??= ResolveRecordName(recordSyncPayload, fieldOffset, fieldName);
        var aadCandidates = AadCandidates(fieldName, zoneName, recordName);

        // 1) Zone già unwrapped (veloce) — percorso tipico Sync Data / Manatee.
        foreach (var zone in zones)
        {
            var plain = TryDecryptWithZone(zone, ciphertext, aadCandidates);
            if (plain is { Length: > 0 })
                return plain;
        }

        // 2) PI locale nella finestra record (record ProtectionInfo Manatee).
        var localZones = BuildLocalZones(zones, poolKeys, recordSyncPayload, fieldOffset);
        foreach (var zone in localZones)
        {
            if (zones.Contains(zone))
                continue;
            var plain = TryDecryptWithZone(zone, ciphertext, aadCandidates);
            if (plain is { Length: > 0 })
                return plain;
        }

        // 3) PI light nel ciphertext.
        if (ciphertext.Length >= 32)
        {
            var embedded = PcsProtectionZone.TryUnwrapAll(ciphertext, poolKeys);
            foreach (var zone in embedded)
            {
                var plain = TryDecryptWithZone(zone, ciphertext, aadCandidates);
                if (plain is { Length: > 0 })
                    return plain;
            }
        }

        return null;
    }

    private static byte[]? TryDecryptWithZone(
        ProtectionZoneKeys zone, byte[] ciphertext, string[] aadCandidates)
    {
        var plain = PcsProtectionZone.TryDecryptField(zone, ciphertext, aadCandidates);
        if (plain is { Length: > 0 })
            return plain;

        // Fallback: stessa KDF su MasterKey (PCSKey 16 B) se DecryptKey non matcha key_id.
        if (zone.MasterKey is { Length: > 0 }
            && !zone.MasterKey.AsSpan().SequenceEqual(zone.DecryptKey))
        {
            try
            {
                var alt = PcsNistKdf.CtrHmacSha256(
                    zone.MasterKey,
                    Encoding.ASCII.GetBytes("encryption key key m"),
                    16);
                plain = PcsProtectionZone.TryDecryptField(alt, ciphertext, aadCandidates);
                if (plain is { Length: > 0 })
                    return plain;
            }
            catch
            {
                // ignore
            }
        }

        return null;
    }

    private static List<ProtectionZoneKeys> BuildLocalZones(
        List<ProtectionZoneKeys> globalZones,
        List<PcsCompactPrivateKey> poolKeys,
        byte[] payload,
        int fieldOffset)
    {
        var local = new List<ProtectionZoneKeys>(globalZones);
        var window = ExtractRecordWindow(payload, fieldOffset);
        if (window.Length < 64)
            return local;

        var keys = new List<PcsCompactPrivateKey>(poolKeys);
        foreach (var der in PcsProtectionZone.TryExtractProtectionInfoCandidates(window.AsSpan()))
        {
            if (der.Length is < 64 or > 1200)
                continue;
            var zone = PcsProtectionZone.TryUnwrap(der, keys);
            if (zone is null)
                continue;
            local.Insert(0, zone);
            keys = PcsProtectionZone.MergeKeys(keys, [zone]);
        }

        return local;
    }

    private static byte[] ExtractRecordWindow(byte[] payload, int fieldOffset)
    {
        if (payload is not { Length: > 64 })
            return [];
        // BeaconStore records sono più grandi (PI + molti campi): finestra ampia.
        var start = Math.Max(0, fieldOffset - 2048);
        var len = Math.Min(payload.Length - start, 8192);
        return payload.AsSpan(start, len).ToArray();
    }

    private static string[] AadCandidates(
        string fieldName, string? zoneName = null, string? recordName = null)
    {
        var list = new List<string>();

        // Manatee / rustpush PCSEncryptor: "{zone}-{record}-{field}"
        if (!string.IsNullOrWhiteSpace(zoneName) && !string.IsNullOrWhiteSpace(recordName))
            list.Add($"{zoneName}-{recordName}-{fieldName}");
        if (!string.IsNullOrWhiteSpace(recordName))
        {
            list.Add($"{recordName}-{fieldName}");
            // Zone di default Find My se non passata
            if (string.IsNullOrWhiteSpace(zoneName))
                list.Add($"BeaconStore-{recordName}-{fieldName}");
        }

        list.Add(fieldName);
        if (fieldName.EndsWith("Encrypted", StringComparison.Ordinal))
            list.Add(fieldName[..^"Encrypted".Length]);
        if (fieldName.EndsWith("Enc", StringComparison.Ordinal))
            list.Add(fieldName[..^3]);

        return list.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static string? ZoneHintForContainer(string? containerId)
    {
        if (string.IsNullOrWhiteSpace(containerId))
            return null;
        if (containerId.Contains("searchparty", StringComparison.OrdinalIgnoreCase))
            return "BeaconStore";
        return null;
    }

    private static string? ResolveRecordName(byte[] payload, int fieldOffset, string fieldName)
    {
        var uuid = CplPhotosRecordParser.TryFindUuidForEncryptedField(
            payload, fieldOffset, fieldName);
        if (!string.IsNullOrWhiteSpace(uuid))
            return uuid;

        // Fallback: GUID ASCII più vicino prima del campo (BeaconStore record names).
        var windowStart = Math.Max(0, fieldOffset - 1500);
        var windowLen = Math.Min(payload.Length - windowStart, fieldOffset - windowStart + 64);
        if (windowLen < 36)
            return null;
        var text = Encoding.ASCII.GetString(payload, windowStart, windowLen);
        string? best = null;
        var bestDist = int.MaxValue;
        for (var i = 0; i + 36 <= text.Length; i++)
        {
            if (text[i + 8] != '-' || text[i + 13] != '-' || text[i + 18] != '-' || text[i + 23] != '-')
                continue;
            var cand = text.AsSpan(i, 36);
            if (!LooksLikeGuid(cand))
                continue;
            var abs = windowStart + i;
            var dist = fieldOffset - abs;
            if (dist < 0 || dist >= bestDist)
                continue;
            bestDist = dist;
            best = cand.ToString();
        }

        return best;
    }

    private static bool LooksLikeGuid(ReadOnlySpan<char> s)
    {
        if (s.Length != 36)
            return false;
        for (var i = 0; i < 36; i++)
        {
            if (i is 8 or 13 or 18 or 23)
            {
                if (s[i] != '-')
                    return false;
                continue;
            }

            var c = s[i];
            if (c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F'))
                continue;
            return false;
        }

        return true;
    }

    private static byte[] PostProcess(string fieldName, byte[] plain)
    {
        // Notes TextDataEncrypted: spesso gzip/zlib dopo PCS.
        if (fieldName.Contains("TextData", StringComparison.OrdinalIgnoreCase)
            || fieldName.Contains("StandardizedContent", StringComparison.OrdinalIgnoreCase))
        {
            if (TryGunzip(plain, out var gz))
                return gz;
            if (TryZlib(plain, out var zl))
                return zl;
        }

        return plain;
    }

    private static bool TryGunzip(byte[] data, out byte[] plain)
    {
        plain = [];
        if (data.Length < 3 || data[0] != 0x1f || data[1] != 0x8b)
            return false;
        try
        {
            using var ms = new MemoryStream(data);
            using var gz = new GZipStream(ms, CompressionMode.Decompress);
            using var outMs = new MemoryStream();
            gz.CopyTo(outMs);
            plain = outMs.ToArray();
            return plain.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryZlib(byte[] data, out byte[] plain)
    {
        plain = [];
        if (data.Length < 2 || data[0] != 0x78)
            return false;
        try
        {
            using var ms = new MemoryStream(data);
            using var zlib = new ZLibStream(ms, CompressionMode.Decompress);
            using var outMs = new MemoryStream();
            zlib.CopyTo(outMs);
            plain = outMs.ToArray();
            return plain.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    private static string GuessExtension(byte[] data)
    {
        if (data.Length >= 6 && data.AsSpan(0, 6).SequenceEqual("bplist"u8))
            return ".bplist";
        if (data.Length >= 5 && data.AsSpan(0, 5).SequenceEqual("<?xml"u8))
            return ".xml";
        if (data.Length >= 2 && data[0] == 0x1f && data[1] == 0x8b)
            return ".gz";
        if (LooksLikeUtf8Text(data))
            return ".bin"; // anche .txt separato
        return ".bin";
    }

    private static bool LooksLikeUtf8Text(byte[] data)
    {
        if (data.Length == 0 || data.Length > 64_000)
            return false;
        var printable = 0;
        foreach (var b in data)
        {
            if (b is 9 or 10 or 13 || b is >= 32 and < 127)
                printable++;
            else if (b >= 128)
                printable++; // utf-8 lead ok-ish
            else
                return false;
        }

        return printable >= data.Length * 0.85;
    }

    private static IEnumerable<string>? PreferredFieldsForContainer(string? containerId)
    {
        if (string.IsNullOrWhiteSpace(containerId))
            return null;
        if (containerId.Contains("notes", StringComparison.OrdinalIgnoreCase))
        {
            return
            [
                "TitleEncrypted", "TextDataEncrypted", "SnippetEncrypted",
                "ReplicaIDToNotesVersionDataEncrypted", "ReplicaIDToUserIDEncrypted",
                "StandardizedContentEncrypted", "DisplayTextEncrypted",
                "MergeablePreferredViewSizeEncrypted"
            ];
        }

        if (containerId.Contains("Safari", StringComparison.OrdinalIgnoreCase)
            || containerId.Contains("Bookmark", StringComparison.OrdinalIgnoreCase)
            || containerId.Contains("CloudTabs", StringComparison.OrdinalIgnoreCase)
            || containerId.Contains("History", StringComparison.OrdinalIgnoreCase))
        {
            return ["Title", "URL", "ShowIconOnly", "Key", "ImageURL"];
        }

        if (containerId.Contains("VoiceMemo", StringComparison.OrdinalIgnoreCase))
            return ["mediaMetaDataEnc"];

        if (containerId.Contains("photos", StringComparison.OrdinalIgnoreCase))
        {
            return
            [
                "albumNameEnc", "importedByBundleIdentifierEnc", "importedByDisplayNameEnc",
                "mediaMetaDataEnc", "filenameEnc", "originalFilenameEnc"
            ];
        }

        if (containerId.Contains("searchparty", StringComparison.OrdinalIgnoreCase))
        {
            return
            [
                "name", "emoji", "associatedBeacon", "roleId",
                "productId", "stableIdentifier", "pairingDate", "batteryLevel",
                "privateKey", "sharedSecret", "sharedSecret2", "publicKey",
                "secureLocationsSharedSecret", "systemVersion", "model",
                "vendorId", "isZeus", "ownerHandle", "shareIdentifier",
                "correlationIdentifier", "beaconIdentifier",
            ];
        }

        return null;
    }

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        return sb.Length == 0 ? "field" : sb.ToString();
    }

    private static string EscapeTsv(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        return value.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
    }

}
