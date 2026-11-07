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
        IProgress<string>? log = null,
        string? zoneNameHint = null)
    {
        if (recordSyncPayload is not { Length: > 64 })
            return new DecryptSummary(0, 0, 0, "payload vuoto");

        var seedKeys = CollectSeedKeys(session, log);
        if (seedKeys.Count == 0)
            return new DecryptSummary(0, 0, 0, "PCS KeySet assente (Escrow + Manatee)");

        var preferred = PreferredFieldsForContainer(containerHint);
        var fields = CloudKitEncryptedFieldScanner.Scan(recordSyncPayload, preferred);
        // Photos/Notes/…: ignora type=20 anonimi e campi SyncData generici fuori lista —
        // altrimenti CPL multi-MB tenta migliaia di ciphertext inutili (lento sui fail).
        if (preferred is not null)
        {
            var allow = new HashSet<string>(preferred, StringComparer.Ordinal);
            var before = fields.Count;
            fields = fields.Where(f => allow.Contains(f.FieldName)).ToList();
            if (before != fields.Count)
                log?.Report($"  PCS: filtra campi {before}→{fields.Count} (preferred container)");
        }

        if (fields.Count == 0)
            return new DecryptSummary(0, 0, 0, "nessun campo type=20");

        var poolKeys = new List<PcsCompactPrivateKey>(seedKeys);
        var zones = new List<ProtectionZoneKeys>();
        // DecryptKey/MasterKey → wire record name (CPLMaster del PI che ha prodotto la zona).
        var keyToRecord = new Dictionary<string, string>(StringComparer.Ordinal);

        log?.Report($"  PCS: {fields.Count} ciphertext type=20 — unwrap zone…");
        if (zonesPayload is { Length: > 32 })
        {
            // rustpush: zone PI → nested EC; then record_protection_info decode →
            // default_record_keys (master + nest symm 04 10) for field GCM.
            // Messages/SyncData: light ON (Backup lo tiene sempre OFF).
            var fromZones = PcsProtectionZone.TryUnwrapAll(
                zonesPayload, seedKeys, includeLight: true);
            if (fromZones.Count > 0)
            {
                zones.AddRange(fromZones);
                poolKeys = PcsProtectionZone.MergeKeys(seedKeys, fromZones);
            }

            for (var round = 0; round < 3; round++)
            {
                var more = PcsProtectionZone.TryUnwrapAll(
                    zonesPayload, poolKeys, includeLight: true);
                var added = 0;
                foreach (var z in more)
                {
                    var id = Convert.ToHexString(z.MasterKey);
                    if (zones.Any(x => Convert.ToHexString(x.MasterKey) == id))
                        continue;
                    zones.Add(z);
                    added++;
                }

                if (added == 0)
                    break;
                poolKeys = PcsProtectionZone.MergeKeys(poolKeys, more);
                log?.Report($"  PCS: zones nested round +{added} (record_prot / symm keys)");
            }
        }

        // CPL Photos multi-MB: TryUnwrapAllIterative + light brute = decine di minuti
        // bloccati su "unwrap zone…" (query_cplasset_p* ~2–3 MB × 200 Manatee keys).
        const int largePayloadBytes = 200_000;
        List<ProtectionZoneKeys> fromRecords;
        if (recordSyncPayload.Length >= largePayloadBytes)
        {
            log?.Report(
                $"  PCS: payload grande ({recordSyncPayload.Length:N0} B) — " +
                "PI 200–900 + light indexed (no iterative/brute)…");
            fromRecords = UnwrapLargeRecordPayload(recordSyncPayload, poolKeys, keyToRecord);
        }
        else
        {
            fromRecords = PcsProtectionZone.TryUnwrapAllIterative(
                recordSyncPayload, poolKeys, includeLight: true);
            IndexZonesByNearbyMaster(recordSyncPayload, fromRecords, keyToRecord);
        }

        if (fromRecords.Count > 0)
        {
            zones.AddRange(fromRecords);
            poolKeys = PcsProtectionZone.MergeKeys(poolKeys, fromRecords);
        }

        // Cap alto: i PI ~535 ADP sono uno-per-asset; 128 tagliava i DecryptKey utili
        // a filenameEnc. Il percorso locale (finestra 48 KB) resta il preferito.
        if (recordSyncPayload.Length >= largePayloadBytes && zones.Count > 2048)
        {
            var before = zones.Count;
            zones = CapZonesForFieldDecrypt(zones, max: 2048);
            log?.Report($"  PCS: cap zoneKeys {before}→{zones.Count} per decrypt campi");
        }

        log?.Report($"  PCS: zoneKeys={zones.Count} poolKeys={poolKeys.Count}");
        if (zones.Count == 0)
        {
            // Se nessuna PublicX del KeySet compare in zone/sync, il grind per-field
            // è inutile (tipico BeaconStore/Messages: identità CKKS fuori da Escrow).
            var publicHits = CountPublicXHits(zonesPayload, recordSyncPayload, seedKeys);
            if (publicHits == 0)
            {
                var hint = PcsBlockedHint(containerHint);
                log?.Report(
                    "  PCS: nessun PublicX (Escrow/Manatee/Engram) nel payload " +
                    $"(zoneKeys=0, publicHits=0) — skip decrypt campi. {hint}");
                Directory.CreateDirectory(outputDirectory);
                File.WriteAllText(
                    Path.Combine(outputDirectory, "decrypt_blocked.txt"),
                    "zoneKeys=0 publicHits=0 — seed PCS non unwrapa ProtectionInfo. " + hint);
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
        var failLines = new List<string>
        {
            "field\tidx\toffset\tnear_name\tzone_hint\tkey_id4\tct_head\taad0",
        };

        var flat = fields.ToList();
        var total = flat.Count;
        var byName = flat.GroupBy(f => f.FieldName, StringComparer.Ordinal);
        var done = 0;
        var consecutiveFail = 0;
        var messagesContainer = !string.IsNullOrWhiteSpace(containerHint)
            && containerHint.Contains("messages", StringComparison.OrdinalIgnoreCase);
        // Messages: PI già unwrapped a livello zona — local PI ×230 seed è solo grind.
        var skipLocal = keyToRecord.Count >= 16
                        || (messagesContainer && zones.Count > 0);
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

                // Con zoneKeys>0 ma 0 hit: AAD/recordName sbagliati — non bruciare 1600 campi.
                if (zones.Count > 0 && consecutiveFail >= 24 && decrypted == 0)
                {
                    log?.Report(
                        $"  PCS: abort dopo {consecutiveFail} fail consecutivi " +
                        $"(zoneKeys={zones.Count}, 0 ok) — AAD/record name?");
                    failed += total - done + 1;
                    File.WriteAllLines(metaPath, lines);
                    File.WriteAllLines(recordsPath, recordLines);
                    return new DecryptSummary(
                        fields.Count, 0, zones.Count,
                        $"abort: 0 decrypt dopo {consecutiveFail} fail (zoneKeys={zones.Count})");
                }

                var zoneHint = zoneNameHint ?? ZoneHintForContainer(containerHint);
                var nearName = ResolveRecordName(
                    recordSyncPayload, field.Offset, fieldName);
                // Con keyToRecord già popolato dal full-PI scan (payload grandi),
                // salta unwrap PI locale per-campo (48+12 KB × N DER × seed) —
                // era ~1 campo/s e rendeva il re-decrypt multi-ora.
                var (plain, openZone) = TryDecryptCipher(
                    field.Ciphertext,
                    fieldName,
                    zones,
                    poolKeys,
                    recordSyncPayload,
                    field.Offset,
                    zoneHint,
                    nearName,
                    skipLocalPi: skipLocal,
                    keyToRecord: keyToRecord);
                if (plain is null)
                {
                    failInGroup++;
                    failed++;
                    consecutiveFail++;
                    var ct = field.Ciphertext;
                    var kid4 = ct.Length >= 6 && ct[0] == 3 && ct[3] == 2
                        ? Convert.ToHexString(new byte[] { ct[1], ct[2], ct[4], ct[5] })
                        : "";
                    var head = Convert.ToHexString(ct.AsSpan(0, Math.Min(8, ct.Length)));
                    var aad0 = nearName is { Length: > 0 } && zoneHint is { Length: > 0 }
                        ? $"{zoneHint}-{nearName}-{fieldName}"
                        : nearName is { Length: > 0 }
                            ? $"{nearName}-{fieldName}"
                            : fieldName;
                    failLines.Add(
                        $"{fieldName}\t{idx}\t{field.Offset}\t{nearName}\t{zoneHint}\t{kid4}\t{head}\t{aad0}");
                    continue;
                }

                consecutiveFail = 0;

                // Photos CPL: il PI che apre il ciphertext identifica il record.
                // Messages Manatee: molte record condividono lo stesso master PCS —
                // TryRecordNameForZone collassa tutto su un solo nome; preferisci
                // il 64-hex più vicino al campo (nearName).
                string? recordName;
                if (messagesContainer
                    && nearName is { Length: 64 }
                    && nearName.All(static c => Uri.IsHexDigit(c)))
                {
                    recordName = nearName;
                }
                else
                {
                    recordName = TryRecordNameForZone(keyToRecord, openZone);
                    if (string.IsNullOrWhiteSpace(recordName)
                        && openZone is not null
                        && !string.IsNullOrWhiteSpace(nearName))
                    {
                        RememberZoneRecord(keyToRecord, openZone, nearName);
                        recordName = nearName;
                    }

                    recordName ??= nearName ?? "";
                }

                okInGroup++;
                decrypted++;
                // Notes TextData: spesso gzip DOPO PCS — decodifica testo solo sul plain espanso.
                var processed = PostProcess(fieldName, plain);
                var decoded = NotesPlaintextDecoder.DecodeField(fieldName, processed);
                processed = decoded.Processed;
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
        if (failLines.Count > 1)
        {
            File.WriteAllLines(Path.Combine(outputDirectory, "decrypt_fails.tsv"), failLines);
            log?.Report($"  PCS fails detail: {failLines.Count - 1} → decrypt_fails.tsv");
        }

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

        // Notes: i ciphertext (TitleEncrypted / TextDataEncrypted) stanno nei
        // record/retrieve batch, non nel record/sync (solo metadati/delta).
        var syncFiles = Directory.GetFiles(containerDirectory, "record_sync_*.bin")
            .Concat(Directory.GetFiles(containerDirectory, "query_*.bin"))
            .Concat(EnumerateRecordRetrieveBatchBins(containerDirectory))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (syncFiles.Length == 0)
            return new DecryptSummary(0, 0, 0, "nessun record_sync/query/retrieve");

        var totalFields = 0;
        var totalDecrypted = 0;
        var maxZones = 0;
        var cryptoRoot = Path.Combine(containerDirectory, "crypto");
        Directory.CreateDirectory(cryptoRoot);

        for (var i = 0; i < syncFiles.Length; i++)
        {
            var sf = syncFiles[i];
            var payload = File.ReadAllBytes(sf);
            var tag = CryptoTagForPayloadFile(sf, containerDirectory);
            log?.Report($"  PCS file {i + 1}/{syncFiles.Length}: {tag} ({payload.Length:N0} B)");
            var outDir = Path.Combine(cryptoRoot, tag);
            var zoneFromTag = TryParseZoneFromSyncTag(tag);
            var summary = DecryptPayload(
                session, richestZones, payload, outDir, containerId, log,
                zoneNameHint: zoneFromTag);
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

    /// <summary>
    /// Unwrap su query CPL multi-MB: tutti i PI record 200–900 B (Photos ADP:
    /// ~400 e ~535) + light indexed-only. Niente DER full-page né ECDH brute.
    /// Popola <paramref name="keyToRecord"/> con DecryptKey/MasterKey → CPLMaster.
    /// </summary>
    private static List<ProtectionZoneKeys> UnwrapLargeRecordPayload(
        byte[] payload,
        IReadOnlyList<PcsCompactPrivateKey> poolKeys,
        Dictionary<string, string>? keyToRecord = null)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<ProtectionZoneKeys>();

        void AddZone(ProtectionZoneKeys z, string? recordName)
        {
            if (!seen.Add(Convert.ToHexString(z.MasterKey)))
            {
                if (keyToRecord is not null && !string.IsNullOrWhiteSpace(recordName))
                    RememberZoneRecord(keyToRecord, z, recordName);
                return;
            }

            list.Add(z);
            if (keyToRecord is not null && !string.IsNullOrWhiteSpace(recordName))
                RememberZoneRecord(keyToRecord, z, recordName);
        }

        // Scansione TLV con offset: serve per associare ogni PI al CPLMaster proprietario.
        for (var i = 0; i + 4 < payload.Length; i++)
        {
            if (payload[i] != 0x61)
                continue;
            if (!TrySliceAppl1(payload, i, out var der) || der.Length is < 200 or > 900)
                continue;

            var recordName = FindCplMasterNameBefore(payload, i);
            foreach (var z in PcsProtectionZone.TryUnwrapAll(
                         der, poolKeys, includeLight: false, includeDer: true))
                AddZone(z, recordName);
        }

        foreach (var z in PcsProtectionLight.TryUnwrapAll(
                     payload, poolKeys, bruteForceUnknownPub: false))
            AddZone(z, recordName: null);

        return list;
    }

    private static void IndexZonesByNearbyMaster(
        byte[] payload,
        IReadOnlyList<ProtectionZoneKeys> zones,
        Dictionary<string, string> keyToRecord)
    {
        var known = new HashSet<string>(StringComparer.Ordinal);
        foreach (var z in zones)
            known.Add(Convert.ToHexString(z.MasterKey));

        for (var i = 0; i + 4 < payload.Length; i++)
        {
            if (payload[i] != 0x61)
                continue;
            if (!TrySliceAppl1(payload, i, out var der) || der.Length is < 200 or > 900)
                continue;
            var recordName = FindCplMasterNameBefore(payload, i);
            if (string.IsNullOrWhiteSpace(recordName))
                continue;

            // Le zone sono già in `zones`: se il MasterKey del PI matcha, registra il record.
            // Re-unwrap richiederebbe i seed; confrontiamo fingerprint del DER già visto
            // tramite MasterKey dopo unwrap light dal ciphertext del PI stesso.
            foreach (var z in zones)
            {
                if (!known.Contains(Convert.ToHexString(z.MasterKey)))
                    continue;
                // Heuristica: se il Public matched compare nel DER, è questo PI.
                if (z.MasterPublicMatched is { Length: > 0 }
                    && IndexOf(der, z.MasterPublicMatched) >= 0)
                    RememberZoneRecord(keyToRecord, z, recordName);
            }
        }
    }

    private static void RememberZoneRecord(
        Dictionary<string, string> keyToRecord,
        ProtectionZoneKeys zone,
        string recordName)
    {
        keyToRecord[Convert.ToHexString(zone.DecryptKey)] = recordName;
        keyToRecord[Convert.ToHexString(zone.MasterKey)] = recordName;
    }

    private static string? TryRecordNameForZone(
        IReadOnlyDictionary<string, string> keyToRecord,
        ProtectionZoneKeys? zone)
    {
        if (zone is null || keyToRecord.Count == 0)
            return null;
        if (keyToRecord.TryGetValue(Convert.ToHexString(zone.DecryptKey), out var byDec))
            return byDec;
        if (keyToRecord.TryGetValue(Convert.ToHexString(zone.MasterKey), out var byMaster))
            return byMaster;
        return null;
    }

    private static bool ZoneMapsToRecord(
        IReadOnlyDictionary<string, string> keyToRecord,
        ProtectionZoneKeys zone,
        string recordName) =>
        (keyToRecord.TryGetValue(Convert.ToHexString(zone.DecryptKey), out var a)
         && string.Equals(a, recordName, StringComparison.Ordinal))
        || (keyToRecord.TryGetValue(Convert.ToHexString(zone.MasterKey), out var b)
            && string.Equals(b, recordName, StringComparison.Ordinal));

    private static string? FindCplMasterNameBefore(byte[] payload, int before)
    {
        if (before <= 0)
            return null;
        var lookback = Math.Min(before, 12_000);
        var start = before - lookback;
        var span = payload.AsSpan(start, lookback);
        var rel = span.LastIndexOf("CPLMaster"u8);
        if (rel < 0)
            return null;
        return CplPhotosRecordParser.TryExtractWireRecordNameBefore(
                   payload, start + rel, "CPLMaster"u8)
               ?? CplPhotosRecordParser.TryFindNearestUuidBefore(payload, start + rel, 256);
    }

    private static bool TrySliceAppl1(byte[] data, int offset, out byte[] der)
    {
        der = [];
        try
        {
            if (offset < 0 || offset >= data.Length || data[offset] != 0x61)
                return false;
            // Delegato all'estrattore esistente sulla finestra locale.
            var window = data.AsSpan(offset, Math.Min(data.Length - offset, 1200));
            var all = PcsProtectionZone.TryExtractAllRecordProtectionInfoDer(window);
            if (all.Count == 0)
                return false;
            der = all[0];
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static List<ProtectionZoneKeys> CapZonesForFieldDecrypt(
        List<ProtectionZoneKeys> zones,
        int max)
    {
        if (zones.Count <= max)
            return zones;

        // Preferisci PI con nested ProtectionObject (tipico ~535 ADP) e nested EC.
        return zones
            .OrderByDescending(static z => z.NestedProtectionObject?.Length ?? 0)
            .ThenByDescending(static z => z.NestedPrivateKeys.Count)
            .ThenByDescending(static z => z.ProtectionInfoTag is null ? 0 : 1)
            .ThenByDescending(static z => z.MasterKey.Length)
            .Take(max)
            .ToList();
    }

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

    private static (byte[]? Plain, ProtectionZoneKeys? Zone) TryDecryptCipher(
        byte[] ciphertext,
        string fieldName,
        List<ProtectionZoneKeys> zones,
        List<PcsCompactPrivateKey> poolKeys,
        byte[] recordSyncPayload,
        int fieldOffset,
        string? zoneName = null,
        string? recordName = null,
        bool skipLocalPi = false,
        IReadOnlyDictionary<string, string>? keyToRecord = null)
    {
        recordName ??= ResolveRecordName(recordSyncPayload, fieldOffset, fieldName);
        var aadCandidates = AadCandidates(fieldName, zoneName, recordName);

        // 1) PI locale: finestra che include anche il PI *dopo* i campi cifrati
        //    (su CPL mediaMeta sta prima del ProtectionInfo dello stesso master).
        //    Skip su payload grandi già indicizzati (key→record): costo proibitivo.
        if (!skipLocalPi)
        {
            var localZones = BuildLocalZones([], poolKeys, recordSyncPayload, fieldOffset);
            foreach (var zone in localZones)
            {
                var plain = TryDecryptWithZone(zone, ciphertext, aadCandidates);
                if (plain is not null)
                    return (plain, zone);
            }
        }

        // 2) Zone già unwrapped globali — Notes / Sync Data classico / CPL large.
        //    Prova prima le zone già mappate sul nearName (1–2 hit tipici).
        if (keyToRecord is { Count: > 0 } && !string.IsNullOrWhiteSpace(recordName))
        {
            foreach (var zone in zones)
            {
                if (!ZoneMapsToRecord(keyToRecord, zone, recordName))
                    continue;
                var plain = TryDecryptWithZone(zone, ciphertext, aadCandidates);
                if (plain is not null)
                    return (plain, zone);
            }
        }

        foreach (var zone in zones)
        {
            if (keyToRecord is { Count: > 0 }
                && !string.IsNullOrWhiteSpace(recordName)
                && ZoneMapsToRecord(keyToRecord, zone, recordName))
                continue; // già provata sopra
            var plain = TryDecryptWithZone(zone, ciphertext, aadCandidates);
            if (plain is not null)
                return (plain, zone);
        }

        // 3) PI light nel ciphertext (solo se poche zone globali) — Sync Data only.
        if (ciphertext.Length >= 32 && zones.Count < 64)
        {
            var embedded = PcsProtectionZone.TryUnwrapAll(
                ciphertext, poolKeys, includeLight: true);
            foreach (var zone in embedded)
            {
                var plain = TryDecryptWithZone(zone, ciphertext, aadCandidates);
                if (plain is not null)
                    return (plain, zone);
            }
        }

        return (null, null);
    }

    private static byte[]? TryDecryptWithZone(
        ProtectionZoneKeys zone, byte[] ciphertext, string[] aadCandidates)
    {
        // Expanded: DecryptKey + Master/KDF + nested wrap-ref + nested PCS (Messages).
        // plain.Length==0 è successo GCM (campo vuoto) — non confondere con fail.
        // Non usare TryDecryptField(zone) (solo DecryptKey): serve al path backup veloce.
        return PcsProtectionZone.TryDecryptFieldExpanded(zone, ciphertext, aadCandidates);
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
        // Preferisci candidati record-sized (200–900); include ~535 ADP.
        foreach (var der in PcsProtectionZone.TryExtractAllRecordProtectionInfoDer(window))
        {
            var zone = PcsProtectionZone.TryUnwrap(der, keys);
            if (zone is null)
                continue;
            local.Insert(0, zone);
            keys = PcsProtectionZone.MergeKeys(keys, [zone]);
        }

        if (local.Count == globalZones.Count)
        {
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
        }

        return local;
    }

    private static byte[] ExtractRecordWindow(byte[] payload, int fieldOffset)
    {
        if (payload is not { Length: > 64 })
            return [];
        // Photos CPL: PI del master spesso *dopo* mediaMetaDataEnc/filenameEnc
        // (stesso record). Serve lookahead ampio oltre al lookback classico.
        const int lookback = 48 * 1024;
        const int lookahead = 12 * 1024;
        var start = Math.Max(0, fieldOffset - lookback);
        var end = Math.Min(payload.Length, fieldOffset + lookahead);
        return payload.AsSpan(start, end - start).ToArray();
    }

    private static string[] AadCandidates(
        string fieldName, string? zoneName = null, string? recordName = null)
    {
        var list = new List<string>();

        // Manatee / rustpush PCSEncryptor: "{zone}-{record}-{field}"
        // Messages: record = "_"+32hex (MessageEncryptedV3).
        void AddZoneRecordField(string zone, string record)
        {
            list.Add($"{zone}-{record}-{fieldName}");
            if (record.StartsWith('_') && record.Length > 1)
                list.Add($"{zone}-{record[1..]}-{fieldName}");
        }

        if (!string.IsNullOrWhiteSpace(zoneName) && !string.IsNullOrWhiteSpace(recordName))
            AddZoneRecordField(zoneName, recordName);
        if (!string.IsNullOrWhiteSpace(recordName))
        {
            list.Add($"{recordName}-{fieldName}");
            if (recordName.StartsWith('_') && recordName.Length > 1)
                list.Add($"{recordName[1..]}-{fieldName}");
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

    private static IEnumerable<string> EnumerateRecordRetrieveBatchBins(string containerDirectory)
    {
        if (!Directory.Exists(containerDirectory))
            yield break;

        foreach (var dir in Directory.GetDirectories(containerDirectory, "record_retrieve_*"))
        {
            foreach (var bin in Directory.GetFiles(dir, "batch*.bin"))
                yield return bin;
        }
    }

    /// <summary>
    /// Tag stabile sotto <c>crypto/</c>: sync → nome file; retrieve →
    /// <c>record_retrieve_Notes_batch01</c>.
    /// </summary>
    private static string CryptoTagForPayloadFile(string filePath, string containerDirectory)
    {
        var file = Path.GetFileNameWithoutExtension(filePath);
        var parent = Path.GetFileName(Path.GetDirectoryName(filePath) ?? "");
        if (parent.StartsWith("record_retrieve_", StringComparison.OrdinalIgnoreCase))
            return $"{parent}_{file}";
        return file;
    }

    /// <summary>
    /// <c>record_sync_messageManateeZone_p1</c> → <c>messageManateeZone</c>;
    /// <c>record_retrieve_Notes_batch01</c> → <c>Notes</c>.
    /// </summary>
    private static string? TryParseZoneFromSyncTag(string tag)
    {
        const string syncPrefix = "record_sync_";
        const string retrievePrefix = "record_retrieve_";
        string rest;
        if (tag.StartsWith(syncPrefix, StringComparison.OrdinalIgnoreCase))
        {
            rest = tag[syncPrefix.Length..];
            var pIdx = rest.LastIndexOf("_p", StringComparison.OrdinalIgnoreCase);
            if (pIdx > 0
                && pIdx + 2 < rest.Length
                && rest[(pIdx + 2)..].All(char.IsDigit))
                rest = rest[..pIdx];
        }
        else if (tag.StartsWith(retrievePrefix, StringComparison.OrdinalIgnoreCase))
        {
            rest = tag[retrievePrefix.Length..];
            var batchIdx = rest.LastIndexOf("_batch", StringComparison.OrdinalIgnoreCase);
            if (batchIdx > 0)
                rest = rest[..batchIdx];
        }
        else
            return null;

        return string.IsNullOrWhiteSpace(rest) ? null : rest;
    }

    private static string PcsBlockedHint(string? containerHint)
    {
        if (!string.IsNullOrWhiteSpace(containerHint)
            && containerHint.Contains("messages", StringComparison.OrdinalIgnoreCase))
        {
            return "Messages richiede CKKS OpenVault → view Engram + Manatee " +
                   "(PCS identities per messageManateeZone/chatManateeZone).";
        }

        if (!string.IsNullOrWhiteSpace(containerHint)
            && containerHint.Contains("searchparty", StringComparison.OrdinalIgnoreCase))
        {
            return "BeaconStore richiede CKKS OpenVault → view Manatee (PCS service 82).";
        }

        return "Esegui Escrow OTBottle/Peer + CKKS OpenVault (Manatee + Engram).";
    }

    private static bool IsMessagesManateeField(string fieldName) =>
        fieldName is "svc" or "guid" or "sender" or "chatID" or "msgProto"
            or "dcId" or "time" or "flags" or "eCode" or "msgType"
            or "msgProto2" or "msgProto3" or "msgProto4";

    private static string? ResolveRecordName(byte[] payload, int fieldOffset, string fieldName)
    {
        // Photos CPLMaster UUID — must NOT run for Messages: the sync header UUID
        // (device/user) is nearer than the 64-hex record name → wrong AAD (51/2200 fails).
        if (!IsMessagesManateeField(fieldName))
        {
            var uuid = CplPhotosRecordParser.TryFindUuidForEncryptedField(
                payload, fieldOffset, fieldName);
            if (!string.IsNullOrWhiteSpace(uuid))
                return uuid;
        }

        // Finestra prima del campo: 64-hex record (Messages) / GUID / "_"+32hex owner.
        var lookback = IsMessagesManateeField(fieldName) ? 12_000 : 1500;
        var windowStart = Math.Max(0, fieldOffset - lookback);
        var windowLen = Math.Min(payload.Length - windowStart, fieldOffset - windowStart + 64);
        if (windowLen < 33)
            return null;
        var text = Encoding.ASCII.GetString(payload, windowStart, windowLen);
        string? best = null;
        var bestDist = int.MaxValue;

        void Consider(int relativeIndex, int length)
        {
            var abs = windowStart + relativeIndex;
            var dist = fieldOffset - abs;
            if (dist < 0 || dist >= bestDist)
                return;
            bestDist = dist;
            best = text.Substring(relativeIndex, length);
        }

        // Messages: record name = 64 hex. Prefer over GUID/owner always.
        for (var i = 0; i + 64 <= text.Length; i++)
        {
            if (!LooksLikeHex64(text.AsSpan(i, 64)))
                continue;
            if (i > 0 && IsAsciiHex(text[i - 1]))
                continue;
            if (i + 64 < text.Length && IsAsciiHex(text[i + 64]))
                continue;
            Consider(i, 64);
        }

        if (best is { Length: 64 })
            return best;

        for (var i = 0; i + 33 <= text.Length; i++)
        {
            if (text[i] == '_' && i + 33 <= text.Length && LooksLikeHex32(text.AsSpan(i + 1, 32)))
            {
                if (i > 0 && IsAsciiHex(text[i - 1]))
                    continue;
                Consider(i, 33);
                continue;
            }

            if (i + 36 > text.Length)
                continue;
            if (text[i + 8] != '-' || text[i + 13] != '-' || text[i + 18] != '-' || text[i + 23] != '-')
                continue;
            if (!LooksLikeGuid(text.AsSpan(i, 36)))
                continue;
            Consider(i, 36);
        }

        return best;
    }

    private static bool LooksLikeHex64(ReadOnlySpan<char> s)
    {
        if (s.Length != 64)
            return false;
        foreach (var c in s)
        {
            if (!IsAsciiHex(c))
                return false;
        }

        return true;
    }

    private static bool LooksLikeHex32(ReadOnlySpan<char> s)
    {
        if (s.Length != 32)
            return false;
        foreach (var c in s)
        {
            if (!IsAsciiHex(c))
                return false;
        }

        return true;
    }

    private static bool IsAsciiHex(char c) =>
        c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');

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
        // Notes TextDataEncrypted / Messages msgProto*: spesso gzip/zlib dopo PCS.
        if (fieldName.Contains("TextData", StringComparison.OrdinalIgnoreCase)
            || fieldName.Contains("StandardizedContent", StringComparison.OrdinalIgnoreCase)
            || fieldName.StartsWith("msgProto", StringComparison.OrdinalIgnoreCase))
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
        {
            // Core Data: type=20 su CD_versionedAudioFuture; titolo spesso type=3+GCM.
            return
            [
                "CD_versionedAudioFuture",
                "CD_encryptedTitle",
                "CD_customLabel",
            ];
        }

        if (containerId.Contains("CallHistory", StringComparison.OrdinalIgnoreCase)
            || containerId.Contains("callhistory", StringComparison.OrdinalIgnoreCase))
            return null; // niente filtro stretto finché non mappiamo i campi

        if (containerId.Contains("messages", StringComparison.OrdinalIgnoreCase))
        {
            // HITB / CloudKit Messages: campi type=20 tipici in messageManateeZone.
            return
            [
                "msgProto", "msgProto2", "msgProto3", "msgProto4",
                "chatID", "dcId", "flags", "guid",
                "sender", "svc", "time",
                // eCode / msgType are unencrypted on wire (rustpush) — omit.
            ];
        }

        if (containerId.Contains("photos", StringComparison.OrdinalIgnoreCase))
        {
            return
            [
                "albumNameEnc", "importedByBundleIdentifierEnc", "importedByDisplayNameEnc",
                "mediaMetaDataEnc", "filenameEnc", "originalFilenameEnc",
                "locationEnc"
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
