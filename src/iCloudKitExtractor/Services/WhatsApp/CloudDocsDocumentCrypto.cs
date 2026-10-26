using System.IO;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Download;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.WhatsApp;

/// <summary>
/// Crypto CloudDocs sul materiale di questa run: zone/retrieve + FetchRecords live,
/// KeySet PCS in <see cref="ICloudSession"/>. I file sotto <c>crypto/</c> sono solo
/// artifact della run corrente (non input da dump storici).
/// </summary>
public sealed class CloudDocsDocumentCrypto
{
    private static readonly Regex DocumentContentRegex = new(
        @"documentContent/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
        RegexOptions.Compiled);

    private static readonly Regex DocumentStructureRegex = new(
        @"documentStructure/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}",
        RegexOptions.Compiled);

    private static readonly Regex LastEditorJsonRegex = new(
        @"\{""name"":""([^""]*)"",""type"":""([^""]*)""\}",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    private static readonly Regex DirectoryRecordRegex = new(
        @"(?:\.directory/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|directory/root)",
        RegexOptions.Compiled);

    private static readonly Regex DirectoryParentRegex = new(
        @"(?:\.directory|directory)/(?:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|root)",
        RegexOptions.Compiled);

    private readonly HttpClient _http;

    public CloudDocsDocumentCrypto(HttpClient http) => _http = http;

    public async Task ProcessAsync(
        ICloudSession session,
        string fetchDir,
        string zone,
        byte[]? zonePayload,
        IProgress<string>? log = null,
        string? pcsKeysDirectory = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(fetchDir);
        var cryptoDir = Path.Combine(fetchDir, "crypto");
        Directory.CreateDirectory(cryptoDir);

        var syncBins = EnumerateSyncPayloadFiles(fetchDir);
        // #region agent log
        try
        {
            var zoneTag = TryZoneTagFromFetchDir(fetchDir);
            var parentHits = syncBins.Count(p =>
            {
                var parent = Directory.GetParent(fetchDir)?.FullName;
                return parent is not null
                       && Path.GetDirectoryName(p) is { } d
                       && d.Equals(parent, StringComparison.OrdinalIgnoreCase);
            });
            AgentLogCrypto(
                "H-CD1",
                "CloudDocsDocumentCrypto.cs:EnumerateSyncPayloadFiles",
                "sync_bins_scoped",
                new
                {
                    zone,
                    zoneTag,
                    totalBins = syncBins.Count,
                    parentHits,
                    sample = syncBins.Select(Path.GetFileName).Take(12).ToList(),
                });
        }
        catch { /* ignore */ }
        // #endregion
        var entries = new List<DocumentCryptoEntry>();
        var directories = new List<DirectoryCryptoEntry>();
        foreach (var bin in syncBins)
        {
            var payload = await File.ReadAllBytesAsync(bin, ct);
            var source = Path.GetFileName(bin);
            entries.AddRange(ParseDocumentContents(payload, source));
            directories.AddRange(ParseDirectoryRecords(payload, source));
        }

        // Dedup per record name: unisci stub record/sync + payload FetchRecords (batch vince su stub).
        var byName = new Dictionary<string, List<DocumentCryptoEntry>>(StringComparer.Ordinal);
        foreach (var e in entries)
        {
            if (!byName.TryGetValue(e.RecordName, out var list))
            {
                list = [];
                byName[e.RecordName] = list;
            }

            list.Add(e);
        }

        entries = byName.Values
            .Select(MergeDocumentSpans)
            .OrderBy(static e => e.RecordName, StringComparer.Ordinal)
            .ToList();

        await EnrichEntriesWithStructureMetadata(entries, syncBins, ct);

        directories = directories
            .GroupBy(static d => NormalizeDirectoryRecordName(d.RecordName), StringComparer.Ordinal)
            .Select(static g => MergeDirectorySpans(g.ToList()))
            .OrderBy(static d => d.RecordName, StringComparer.Ordinal)
            .ToList();

        if (zonePayload is { Length: > 0 })
        {
            var zoneCrypto = Path.Combine(cryptoDir, "zone_protection.bin");
            await File.WriteAllBytesAsync(zoneCrypto, zonePayload, ct);
            var tags = ExtractProtectionTags(zonePayload);
            if (tags.Count > 0)
                await File.WriteAllLinesAsync(
                    Path.Combine(cryptoDir, "zone_protection_tags.txt"), tags, ct);
            log?.Report(
                $"  crypto: zone ProtectionInfo live → {zoneCrypto} ({zonePayload.Length} B, tags={tags.Count})");
        }

        var inventoryPath = Path.Combine(cryptoDir, "inventory.json");
        await File.WriteAllTextAsync(
            inventoryPath,
            JsonSerializer.Serialize(entries, new JsonSerializerOptions { WriteIndented = true }),
            ct);

        var withAuth = entries.Count(static e => !string.IsNullOrWhiteSpace(e.MmcsAuth));
        var withBasename = entries.Count(static e => e.EncryptedBasenameHex is { Length: > 0 });
        var withTimestamps = entries.Count(static e => e.ModifiedUtc is not null || e.CreatedUtc is not null);
        var multiAuth = entries.Count(static e => e.AdditionalMmcsAuths is { Count: > 0 });
        var largeIncompleteCandidates = entries.Count(static e =>
            e.SizeBytes is > 32 * 1024 * 1024 && !string.IsNullOrWhiteSpace(e.MmcsAuth));
        log?.Report(
            $"  crypto: inventory {entries.Count} documentContent " +
            $"(mmcsAuth={withAuth} multiAuth={multiAuth} encryptedBasename={withBasename} timestamps={withTimestamps}) → {inventoryPath}");
        log?.Report(
            $"  crypto: parsed {directories.Count} directory records from sync " +
            $"(record_changes + batch)");

        // #region agent log
        AgentLogCrypto(
            "H-WA-IKE3",
            "CloudDocsDocumentCrypto.ProcessAsync",
            "inventory_summary",
            new
            {
                zone,
                entries = entries.Count,
                withAuth,
                multiAuth,
                withBasename,
                directories = directories.Count,
                largeWithAuth = largeIncompleteCandidates,
                syncBins = syncBins.Count,
                sample = entries
                    .OrderByDescending(static e => e.SizeBytes ?? 0)
                    .Take(8)
                    .Select(static e => new
                    {
                        name = ShortName(e.RecordName),
                        e.SizeBytes,
                        hasAuth = !string.IsNullOrWhiteSpace(e.MmcsAuth),
                        extraAuths = e.AdditionalMmcsAuths?.Count ?? 0,
                        e.HasFileContent,
                        parent = e.ParentDirectory,
                    })
                    .ToList(),
            });
        // #endregion

        // Dump basename cifrati individuali.
        var basenamesDir = Path.Combine(cryptoDir, "encrypted_basenames");
        Directory.CreateDirectory(basenamesDir);
        foreach (var e in entries)
        {
            if (e.EncryptedBasenameHex is not { Length: > 0 })
                continue;
            var bytes = Convert.FromHexString(e.EncryptedBasenameHex);
            var file = Path.Combine(basenamesDir, Sanitize(e.RecordName) + ".bin");
            await File.WriteAllBytesAsync(file, bytes, ct);
        }

        var (zoneKeys, allZoneKeys, seedKeys) = await TryUnwrapZoneAsync(
            session, cryptoDir, zonePayload, pcsKeysDirectory ?? session.PcsKeysDirectory, log, ct);

        var basenameOk = 0;
        var directoryBasenameOk = 0;
        IReadOnlyDictionary<string, byte[]> recordMasters = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        IReadOnlyDictionary<string, string> plainBasenames = new Dictionary<string, string>(StringComparer.Ordinal);
        IReadOnlyDictionary<string, string> plainDirectoryNames = new Dictionary<string, string>(StringComparer.Ordinal);
        IReadOnlyList<(DocumentCryptoEntry Entry, ProtectionZoneKeys Zone)> recordZones = [];
        IReadOnlyDictionary<string, string> directoryRelativePaths = new Dictionary<string, string>(StringComparer.Ordinal);
        if (zoneKeys is not null && seedKeys is not null)
        {
            var basenameResult = await TryDecryptBasenamesAsync(
                cryptoDir, fetchDir, entries, zoneKeys, allZoneKeys, seedKeys, log, ct);
            basenameOk = basenameResult.Ok;
            recordMasters = basenameResult.RecordMasters;
            plainBasenames = basenameResult.PlainBasenames;
            recordZones = basenameResult.RecordZones;

            var dirBasenameResult = await TryDecryptDirectoryBasenamesAsync(
                cryptoDir, fetchDir, directories, zoneKeys, allZoneKeys, seedKeys, recordZones, log, ct);
            directoryBasenameOk = dirBasenameResult.Ok;
            plainDirectoryNames = dirBasenameResult.PlainBasenames;
            directoryRelativePaths = BuildDirectoryRelativePaths(directories, plainDirectoryNames);
            await WriteDirectoryPathArtifactsAsync(
                cryptoDir, zone, directories, plainDirectoryNames, directoryRelativePaths, log, ct);
        }

        await WriteDecryptStatusAsync(
            cryptoDir, zone, entries, directories, zoneKeys, basenameOk, directoryBasenameOk, log, ct);

        if (zoneKeys is null)
        {
            log?.Report(
                "  crypto: skip authorizeGet/download — senza seed PCS / zone unwrap " +
                "i ciphertext non sarebbero decifrabili. Unlock EscrowedKeys oppure " +
                "Octagon → CKKS OpenVault (Manatee), poi rilancia.");
            return;
        }

        if (recordMasters.Count == 0)
        {
            log?.Report(
                "  crypto: ATTENZIONE — 0 record master (basename/PI). " +
                "Download MMCS comunque; decrypt file probabilmente skip.");
        }

        if (withAuth == 0)
        {
            log?.Report("  crypto: nessun MMCS auth associabile — skip authorizeGet.");
            return;
        }

        var downloadDir = Path.Combine(cryptoDir, "ciphertext");
        var plainDir = Path.Combine(cryptoDir, "plaintext");
        Directory.CreateDirectory(downloadDir);
        Directory.CreateDirectory(plainDir);

        var entriesByFileSig = entries
            .Where(static e => e.FileSignatureHex is { Length: > 0 })
            .GroupBy(static e => e.FileSignatureHex!, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static g => g.Key, static g => g.First(), StringComparer.OrdinalIgnoreCase);

        var downloaded = 0;
        var decrypted = 0;
        foreach (var e in entries.Where(static x => !string.IsNullOrWhiteSpace(x.MmcsAuth)))
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var result = await TryDownloadAndDecryptAsync(
                    session, zone, e, fetchDir, downloadDir, plainDir,
                    recordMasters, plainBasenames, zoneKeys!, allZoneKeys, recordZones,
                    seedKeys ?? [], entriesByFileSig, directoryRelativePaths, log, ct);
                if (result.Downloaded)
                    downloaded++;
                if (result.Decrypted)
                    decrypted++;
            }
            catch (Exception ex)
            {
                log?.Report($"  crypto download {ShortName(e.RecordName)}: {ex.Message}");
            }
        }

        log?.Report(
            $"  crypto: ciphertext {downloaded}/{withAuth}, plaintext MMCS {decrypted}/{withAuth}");

        // #region agent log
        try
        {
            var plainRoot = Path.Combine(cryptoDir, "plaintext");
            var topDirs = Directory.Exists(plainRoot)
                ? Directory.GetDirectories(plainRoot)
                    .SelectMany(static z =>
                    {
                        var kids = Directory.GetDirectories(z);
                        return kids.Length > 0
                            ? kids.Select(Path.GetFileName)!
                            : new[] { "(files-at-zone-root)" };
                    })
                    .Where(static s => !string.IsNullOrWhiteSpace(s))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .OrderBy(static s => s, StringComparer.OrdinalIgnoreCase)
                    .Take(40)
                    .ToList()
                : [];
            var plainFiles = Directory.Exists(plainRoot)
                ? Directory.GetFiles(plainRoot, "*", SearchOption.AllDirectories).Length
                : 0;
            AgentDirectoryPathDebugLog(
                "H-WA1",
                "CloudDocsDocumentCrypto.ProcessAsync",
                "plaintext_layout_summary",
                new
                {
                    zone,
                    downloaded,
                    decrypted,
                    withAuth,
                    directoryRelativePaths = directoryRelativePaths.Count,
                    plainFiles,
                    topLevelUnderZone = topDirs,
                },
                runId: "wa-docs-post");
        }
        catch
        {
            // ignore
        }
        // #endregion
    }

    private static async Task<(
            ProtectionZoneKeys? Primary,
            IReadOnlyList<ProtectionZoneKeys> All,
            List<PcsCompactPrivateKey>? SeedKeys)>
        TryUnwrapZoneAsync(
            ICloudSession session,
            string cryptoDir,
            byte[]? zonePayload,
            string? pcsKeysDirectory,
            IProgress<string>? log,
            CancellationToken ct)
    {
        if (zonePayload is null || zonePayload.Length == 0)
        {
            log?.Report("  crypto: nessun zone payload live — skip ProtectionInfo unwrap.");
            return (null, Array.Empty<ProtectionZoneKeys>(), null);
        }

        var resolved = await ResolvePcsKeySetAsync(session, pcsKeysDirectory, log, ct)
            .ConfigureAwait(false);
        if (resolved is null)
            return (null, Array.Empty<ProtectionZoneKeys>(), null);

        var (keys, source) = resolved.Value;
        var seedKind = PcsSessionSeedKeys.IsManateePrimary(session) ? "Manatee" : "Escrow";
        log?.Report($"  crypto: PCS seed ← {source} ({keys.Count} private, {seedKind})");

        var tag = ExtractProtectionTags(zonePayload).FirstOrDefault();
        // #region agent log
        var zonePiStats = SummarizeZoneProtectionCandidates(zonePayload);
        AgentLogCrypto(
            "H-WA-MISSING-LARGE-PI",
            "CloudDocsDocumentCrypto.TryUnwrapZoneAsync",
            "zone_pi_structure",
            new
            {
                payloadLen = zonePayload.Length,
                zonePiStats.candidateCount,
                zonePiStats.maxDerLen,
                zonePiStats.maxCont0BlobLen,
                zonePiStats.largePiPresent,
                zonePiStats.cont0BlobLens,
            });
        // #endregion
        log?.Report(
            $"  crypto: decifrando zone ProtectionInfo ({zonePayload.Length:N0} B × {keys.Count} keys, {seedKind})…");
        // CPU-bound: non sul thread UI (Progress può riprendere sul dispatcher).
        var all = await Task.Run(
                () => PcsProtectionZone.TryUnwrapAll(zonePayload, keys, tag), ct)
            .ConfigureAwait(false);
        log?.Report(
            all.Count > 0
                ? $"  crypto: zone ProtectionInfo decifrata — {all.Count} unwrap OK"
                : "  crypto: zone ProtectionInfo — nessun unwrap");
        if (all.Count == 0)
        {
            log?.Report(
                "  crypto: zone ProtectionInfo unwrap FALLITO — nessun match KeyID " +
                "(atteso BLADERUNNER / service 2 nel KeySet escrow, oppure compact Manatee/PCS).");
            return (null, all, keys);
        }

        // Preferisci il PI con nested plaintext / più nested keys (spesso recordProtectionInfo).
        var zoneKeys = all
            .OrderByDescending(static z => z.NestedPrivateKeys.Count)
            .ThenByDescending(static z => z.NestedProtectionObject?.Length ?? 0)
            .ThenByDescending(static z => z.MasterKey.Length)
            .First();

        await File.WriteAllBytesAsync(
            Path.Combine(cryptoDir, "zone_master_key.bin"), zoneKeys.MasterKey, ct);
        await File.WriteAllBytesAsync(
            Path.Combine(cryptoDir, "zone_decrypt_key.bin"), zoneKeys.DecryptKey, ct);
        if (zoneKeys.NestedProtectionObject is { Length: > 0 } nested)
            await File.WriteAllBytesAsync(Path.Combine(cryptoDir, "zone_pi_plain.bin"), nested, ct);

        var nestedKeyTotal = all.Sum(static z => z.NestedPrivateKeys.Count);
        await File.WriteAllTextAsync(
            Path.Combine(cryptoDir, "zone_unwrap_meta.json"),
            JsonSerializer.Serialize(new
            {
                success = true,
                keySetSource = source,
                protectionInfoUnwrapped = all.Count,
                masterKeyIdHex = zoneKeys.MasterKeyIdHex,
                protectionInfoTag = zoneKeys.ProtectionInfoTag,
                masterKeyBytes = zoneKeys.MasterKey.Length,
                decryptKeyBytes = zoneKeys.DecryptKey.Length,
                nestedProtectionObjectBytes = zoneKeys.NestedProtectionObject?.Length ?? 0,
                nestedPrivateKeys = nestedKeyTotal,
                zonePayloadBytes = zonePayload.Length,
                maxDerLen = zonePiStats.maxDerLen,
                maxCont0BlobLen = zonePiStats.maxCont0BlobLen,
                largeZonePiPresent = zonePiStats.largePiPresent,
                allKeyIds = all.Select(static z => z.MasterKeyIdHex).ToList(),
                dynamic = true,
                note =
                    "Solo payload zone/retrieve di questa run + KeySet in ICloudSession. " +
                    "Nessuna rilettura di dump o whatsapp_docs_* precedenti. " +
                    "largeZonePiPresent=false ⇒ manca il Cont[0] ~884 B (MasterKeySet) tipico dopo com.apple.CloudDocs.",
            }, new JsonSerializerOptions { WriteIndented = true }),
            ct);

        log?.Report(
            $"  crypto: ZONE UNWRAP OK ×{all.Count} KeyID={zoneKeys.MasterKeyIdHex} " +
            $"(nestedPlain={zoneKeys.NestedProtectionObject?.Length ?? 0} B, " +
            $"nestedKeys={nestedKeyTotal})");
        if (nestedKeyTotal == 0)
            log?.Report(
                "  crypto: nested MasterKeySet vuoto — record ProtectionInfo " +
                "probabilmente non unwrap-abile finché GCM dataBlob zona non decifra.");

        return (zoneKeys, all, keys);
    }

    /// <summary>
    /// Seed PCS per CloudDocs/Drive:
    /// (1) <see cref="ICloudSession.PcsEscrowedKeySet"/> (file/unlock offline);
    /// (2) se manca Escrow, compact Manatee/PCS da CKKS OpenVault
    ///     (<see cref="ICloudSession.PcsManateeCompactKeys"/> / disco Octagon).
    /// Stesso criterio di backup ADP: Escrow preferito; Manatee solo in assenza.
    /// </summary>
    private static async Task<(List<PcsCompactPrivateKey> Keys, string Source)?> ResolvePcsKeySetAsync(
        ICloudSession session,
        string? pcsKeysDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var dir = EscrowPcsSession.ResolvePcsKeysDirectory(
            pcsKeysDirectory,
            session.PcsKeysDirectory,
            session.OctagonKeysDirectory);
        if (!string.IsNullOrWhiteSpace(dir))
            session.PcsKeysDirectory = dir;

        // HttpClient non disponibile qui: load da sessione/file/unlock offline.
        // Recover live / OpenVault sono fatti da MainWindow/Ensure prima del probe.
        if (session.PcsEscrowedKeySet is not { Length: > 32 }
            && !string.IsNullOrWhiteSpace(dir))
        {
            var unlocked = EscrowPcsSession.FindUnlockedKeysFile(dir);
            if (unlocked is not null)
            {
                try
                {
                    var der = await File.ReadAllBytesAsync(unlocked, ct);
                    session.PcsEscrowedKeySet = der;
                    session.PcsKeysDirectory = Path.GetDirectoryName(unlocked) ?? dir;
                    log?.Report(
                        $"  crypto: KeySet ← {Path.GetFileName(unlocked)} ({der.Length} B)");
                }
                catch (Exception ex)
                {
                    log?.Report($"  crypto: lettura KeySet fallita: {ex.Message}");
                }
            }
            else
            {
                var bag = Path.Combine(dir, EscrowPcsKeyUnwrap.BackupBagPasswordFileName);
                var escrowed = EscrowPcsUnlock.ResolveEscrowedKeysPath(dir);
                if (File.Exists(bag) && escrowed is not null)
                {
                    log?.Report("  crypto: Unlock EscrowedKeys offline…");
                    var unlock = await EscrowPcsUnlock.UnlockFromDirectoryAsync(dir, log, ct);
                    if (unlock.Success && unlock.Plaintext is { Length: > 32 } pt)
                    {
                        session.PcsEscrowedKeySet = pt;
                        session.PcsKeysDirectory = dir;
                    }
                    else
                        log?.Report($"  crypto: unlock fallito — {unlock.Message}");
                }
            }
        }

        if (session.PcsEscrowedKeySet is { Length: > 32 } mem)
        {
            try
            {
                return (PcsDer.ParseKeySetPrivateKeys(mem), "session.PcsEscrowedKeySet");
            }
            catch (Exception ex)
            {
                log?.Report($"  crypto: KeySet Escrow non valido: {ex.Message}");
            }
        }

        // ADP / solo Octagon: niente Escrow → Manatee compact (OpenVault / disco).
        if (session.PcsManateeCompactKeys is not { Count: > 0 }
            && !string.IsNullOrWhiteSpace(dir))
        {
            _ = EscrowPcsSession.TryLoadManateeFromDisk(session, dir, log);
        }

        if (PcsSessionSeedKeys.IsManateePrimary(session))
        {
            var manatee = PcsSessionSeedKeys.Collect(session, log);
            if (manatee.Count > 0)
                return (manatee, "session.PcsManateeCompactKeys");
        }

        log?.Report(
            "  crypto: nessun seed PCS — Unlock EscrowedKeys (iCSC) oppure " +
            "Unlock Octagon → CKKS OpenVault (Manatee), poi rilancia.");
        return null;
    }

    /// <summary>
    /// Path del KeySet PCS sbloccato nella cartella Decrypt corrente.
    /// Non cerca dump di probe storici (<c>whatsapp_docs_*</c>).
    /// </summary>
    public static string? ResolvePcsKeySetPath(string directory) =>
        EscrowPcsSession.FindUnlockedKeysFile(directory);

    private static async Task<(
            int Ok,
            Dictionary<string, byte[]> RecordMasters,
            Dictionary<string, string> PlainBasenames,
            List<(DocumentCryptoEntry Entry, ProtectionZoneKeys Zone)> RecordZones)>
        TryDecryptBasenamesAsync(
        string cryptoDir,
        string fetchDir,
        IReadOnlyList<DocumentCryptoEntry> entries,
        ProtectionZoneKeys zoneKeys,
        IReadOnlyList<ProtectionZoneKeys> allZoneKeys,
        List<PcsCompactPrivateKey> seedKeys,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var outDir = Path.Combine(cryptoDir, "decrypted_basenames");
        Directory.CreateDirectory(outDir);
        var recordPiDir = Path.Combine(cryptoDir, "record_protection");
        Directory.CreateDirectory(recordPiDir);

        var recordMasters = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        var plainBasenames = new Dictionary<string, string>(StringComparer.Ordinal);

        var workingKeys = PcsProtectionZone.MergeKeys(seedKeys, allZoneKeys);
        var withRecordPi = entries.Count(static x => x.RecordProtectionInfoDerHex != null);
        log?.Report(
            $"  crypto: keyring per record PI = {workingKeys.Count} " +
            $"(seed={seedKeys.Count} + nested zone)");
        log?.Report(
            $"  crypto: decifrando record ProtectionInfo ({withRecordPi} record)…");

        // Pass 1: unwrap tutti i record PI (CPU-bound → thread pool).
        var unwrapped = await Task.Run(() =>
        {
            var list = new List<(DocumentCryptoEntry Entry, ProtectionZoneKeys Zone, byte[] Master)>();
            foreach (var e in entries)
            {
                if (e.RecordProtectionInfoDerHex is not { Length: > 0 })
                    continue;
                var recordDer = Convert.FromHexString(e.RecordProtectionInfoDerHex);
                var zones = PcsProtectionZone.TryUnwrapAll(recordDer, workingKeys);
                if (zones.Count == 0)
                    continue;
                foreach (var recordZone in zones)
                    list.Add((e, recordZone, recordZone.MasterKey));
            }

            return list;
        }, ct).ConfigureAwait(false);

        var recordZones = new List<(DocumentCryptoEntry Entry, ProtectionZoneKeys Zone)>();
        foreach (var (e, recordZone, master) in unwrapped)
        {
            recordZones.Add((e, recordZone));
            await File.WriteAllBytesAsync(
                Path.Combine(recordPiDir, Sanitize(e.RecordName) + "_master.bin"),
                master,
                ct).ConfigureAwait(false);
            if (!recordMasters.ContainsKey(e.RecordName))
                recordMasters[e.RecordName] = master;
        }

        log?.Report($"  crypto: record PI unwrap {recordZones.Count}/{withRecordPi}");
        var decryptPool = allZoneKeys
            .Concat(recordZones.Select(static r => r.Zone))
            .Prepend(zoneKeys)
            .DistinctBy(static z => Convert.ToHexString(z.MasterKey))
            .ToList();

        var keyPool = PcsProtectionZone.MergeKeys(seedKeys, decryptPool);

        // Pass 2: basename (CPU + I/O disco sync) → thread pool.
        var withBasename = entries.Count(static x => x.EncryptedBasenameHex != null);
        log?.Report($"  crypto: decifrando encryptedBasename ({withBasename})…");
        var basenameHits = await Task.Run(() =>
        {
            var hits = new List<(string RecordName, byte[] Plain, string Text)>();
            foreach (var e in entries)
            {
                if (e.EncryptedBasenameHex is not { Length: > 0 })
                    continue;
                var ctBytes = Convert.FromHexString(e.EncryptedBasenameHex);
                var structureName = e.RecordName.Replace(
                    "documentContent/", "documentStructure/", StringComparison.Ordinal);
                var aads = new[]
                {
                    "encryptedBasename", "basename", e.RecordName, structureName,
                    ShortName(e.RecordName),
                };

                var tryZones = new List<ProtectionZoneKeys>();
                foreach (var z in recordZones
                             .Where(r => r.Entry.RecordName == e.RecordName)
                             .Select(static r => r.Zone))
                    tryZones.Add(z);
                tryZones.AddRange(CollectRecordWindowZones(fetchDir, e, keyPool));
                tryZones.AddRange(decryptPool);

                byte[]? plain = null;
                var seenZone = new HashSet<string>(StringComparer.Ordinal);
                foreach (var zk in tryZones)
                {
                    var id = Convert.ToHexString(zk.MasterKey);
                    if (!seenZone.Add(id))
                        continue;
                    plain = PcsProtectionZone.TryDecryptField(zk, ctBytes, aads);
                    if (plain is not null)
                        break;
                }

                if (plain is null)
                    continue;
                hits.Add((e.RecordName, plain, Encoding.UTF8.GetString(plain)));
            }

            return hits;
        }, ct).ConfigureAwait(false);

        foreach (var (recordName, plain, text) in basenameHits)
        {
            plainBasenames[recordName] = text;
            var baseName = Sanitize(recordName);
            await File.WriteAllBytesAsync(Path.Combine(outDir, baseName + ".bin"), plain, ct)
                .ConfigureAwait(false);
            await File.WriteAllTextAsync(Path.Combine(outDir, baseName + ".txt"), text, ct)
                .ConfigureAwait(false);
        }

        var ok = basenameHits.Count;
        log?.Report(
            ok > 0
                ? $"  crypto: decryptedBasename {ok}/{withBasename}"
                : "  crypto: encryptedBasename non decifrati — verificare pairing record↔PI e AAD.");
        return (ok, recordMasters, plainBasenames, recordZones);
    }

    private static List<string> EnumerateSyncPayloadFiles(string fetchDir)
    {
        var files = new List<string>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var zoneTag = TryZoneTagFromFetchDir(fetchDir);
        void AddDir(string dir, bool parentScope)
        {
            if (!Directory.Exists(dir))
                return;
            // Parent clouddocs_ck: solo sync della STESSA zona (evita riscaricare
            // tutti i documentContent di com.apple.CloudDocs per ogni zona app).
            var patterns = parentScope
                ? new[] { "record_changes_*.bin", "record_sync_*.bin" }
                : new[]
                {
                    "batch*.bin", "dirparent_*.bin", "childbatch_*.bin", "dirchildren_*.bin",
                    "record_sync_*.bin", "record_changes_*.bin",
                };
            foreach (var pattern in patterns)
            {
                foreach (var path in Directory.EnumerateFiles(dir, pattern)
                             .OrderBy(static p => p, StringComparer.Ordinal))
                {
                    if (parentScope
                        && zoneTag is not null
                        && !MatchesZoneSyncFile(path, zoneTag))
                        continue;
                    if (seen.Add(path))
                        files.Add(path);
                }
            }
        }

        AddDir(fetchDir, parentScope: false);
        var docsDir = Directory.GetParent(fetchDir)?.FullName;
        if (!string.IsNullOrEmpty(docsDir))
            AddDir(docsDir, parentScope: true);
        return files;
    }

    /// <summary>
    /// <c>fetch_com_apple_CloudDocs</c> → <c>com_apple_CloudDocs</c> (tag usato in record_sync_*).
    /// </summary>
    private static string? TryZoneTagFromFetchDir(string fetchDir)
    {
        var name = Path.GetFileName(
            fetchDir.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar));
        if (string.IsNullOrWhiteSpace(name))
            return null;
        const string prefix = "fetch_";
        if (name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            return name[prefix.Length..];
        return null;
    }

    private static bool MatchesZoneSyncFile(string path, string zoneTag)
    {
        var file = Path.GetFileName(path);
        if (string.IsNullOrWhiteSpace(file) || string.IsNullOrWhiteSpace(zoneTag))
            return false;
        // record_sync_{tag}_p1.bin / record_changes_{tag}.bin
        return file.StartsWith("record_sync_" + zoneTag, StringComparison.OrdinalIgnoreCase)
               || file.StartsWith("record_changes_" + zoneTag, StringComparison.OrdinalIgnoreCase);
    }

    // #region agent log
    private static void AgentLogCrypto(string hypothesisId, string location, string message, object data)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                sessionId = "7dabb5",
                hypothesisId,
                location,
                message,
                data,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                runId = "wa-v3-large-pi",
            });
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "PROGRAMMAZIONE", "Projects", "iCloudDownloader", "debug-7dabb5.log");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.AppendAllText(path, payload + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }

    /// <summary>
    /// Diagnostica strutturale zone PI: l'account OK ha Cont[0] ~884 B (DER ~1534);
    /// senza quel blob GCM nestedPlain resta 0.
    /// </summary>
    private static (
        int candidateCount,
        int maxDerLen,
        int maxCont0BlobLen,
        bool largePiPresent,
        int[] cont0BlobLens)
        SummarizeZoneProtectionCandidates(byte[] zonePayload)
    {
        var cands = PcsProtectionZone.TryExtractProtectionInfoCandidates(zonePayload);
        var blobLens = new List<int>();
        var maxDer = 0;
        var maxBlob = 0;
        foreach (var der in cands)
        {
            if (der.Length > maxDer)
                maxDer = der.Length;
            var blob = TryExtractCont0Blob(der);
            if (blob is null)
                continue;
            blobLens.Add(blob.Length);
            if (blob.Length > maxBlob)
                maxBlob = blob.Length;
        }

        return (
            cands.Count,
            maxDer,
            maxBlob,
            maxBlob >= 400 || maxDer >= 900,
            blobLens.OrderByDescending(static x => x).Take(12).ToArray());
    }

    private static byte[]? TryExtractCont0Blob(byte[] der)
    {
        if (der.Length < 4 || der[0] != 0x61)
            return null;
        if (!TryReadSimpleTagLen(der, 0, out var aOff, out var aLen))
            return null;
        if (aOff + aLen > der.Length)
            return null;
        var app = der.AsSpan(aOff, aLen);
        if (app.Length < 2 || app[0] != 0x30)
            return null;
        if (!TryReadSimpleTagLen(app, 0, out var sOff, out var sLen))
            return null;
        var seq = app.Slice(sOff, sLen);
        var off = 0;
        while (off < seq.Length)
        {
            var tag = seq[off];
            if (!TryReadSimpleTagLen(seq, off, out var cOff, out var cLen, out var next))
                break;
            if (tag is 0xA0 or 0x80)
            {
                var content = seq.Slice(cOff, cLen);
                if (content.Length > 0 && content[0] == 0x04 &&
                    TryReadSimpleTagLen(content, 0, out var iOff, out var iLen))
                    return content.Slice(iOff, iLen).ToArray();
                return content.ToArray();
            }

            off = next;
        }

        return null;
    }

    private static bool TryReadSimpleTagLen(
        ReadOnlySpan<byte> buf, int off, out int contentOff, out int contentLen)
        => TryReadSimpleTagLen(buf, off, out contentOff, out contentLen, out _);

    private static bool TryReadSimpleTagLen(
        ReadOnlySpan<byte> buf, int off, out int contentOff, out int contentLen, out int next)
    {
        contentOff = 0;
        contentLen = 0;
        next = off;
        if (off + 1 >= buf.Length)
            return false;
        var o = off + 1;
        int ln;
        if ((buf[o] & 0x80) != 0)
        {
            var n = buf[o] & 0x7F;
            o++;
            if (n is 0 or > 4 || o + n > buf.Length)
                return false;
            ln = 0;
            for (var i = 0; i < n; i++)
                ln = (ln << 8) | buf[o++];
        }
        else
            ln = buf[o++];

        if (ln < 0 || o + ln > buf.Length)
            return false;
        contentOff = o;
        contentLen = ln;
        next = o + ln;
        return true;
    }
    // #endregion

    public static IReadOnlyList<DirectoryCryptoEntry> ParseDirectoryRecords(byte[] payload, string source)
    {
        var text = Encoding.Latin1.GetString(payload);
        var matches = DirectoryRecordRegex.Matches(text);
        var perRecord = new Dictionary<string, List<DirectoryCryptoEntry>>(StringComparer.Ordinal);
        for (var i = 0; i < matches.Count; i++)
        {
            var m = matches[i];
            var recordName = NormalizeDirectoryRecordName(m.Value);
            var start = m.Index;
            // Parent refs in documentStructure: "...parent... .directory/UUID" + file encryptedBasename.
            if (IsParentFieldReference(payload, start))
                continue;

            var end = Math.Min(payload.Length, m.Index + 1200);
            if (end <= start)
                continue;
            var window = payload.AsSpan(start, end - start).ToArray();
            if (!LooksLikeDirectoryRecordWindow(window, recordName))
                continue;
            var parsed = ParseOneDirectory(recordName, window, source, start);
            if (parsed.EncryptedBasenameHex is null && parsed.ParentDirectory is null)
                continue;
            if (!perRecord.TryGetValue(recordName, out var list))
            {
                list = [];
                perRecord[recordName] = list;
            }

            list.Add(parsed);
        }

        return perRecord.Values
            .Select(MergeDirectorySpans)
            .OrderBy(static e => e.RecordName, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// True se l'offset punta al valore del campo <c>parent</c> (non al record Directory).
    /// </summary>
    private static bool IsParentFieldReference(byte[] payload, int directoryNameOffset)
    {
        if (directoryNameOffset <= 0)
            return false;
        var from = Math.Max(0, directoryNameOffset - 64);
        var len = directoryNameOffset - from;
        if (len < 6)
            return false;
        return ContainsAscii(payload.AsSpan(from, len).ToArray(), "parent");
    }

    private static DirectoryCryptoEntry MergeDirectorySpans(IReadOnlyList<DirectoryCryptoEntry> spans)
    {
        DirectoryCryptoEntry? best = null;
        string? parent = null;
        string? eb = null;
        string? pi = null;
        int? piBytes = null;
        foreach (var s in spans
                     .OrderByDescending(ScoreDirectoryEntry)
                     .ThenBy(static e => e.PayloadOffset))
        {
            if (parent is null
                && s.ParentDirectory is { Length: > 0 } p
                && !p.Equals(s.RecordName, StringComparison.Ordinal)
                && !p.Equals(NormalizeDirectoryRecordName(s.RecordName), StringComparison.Ordinal))
                parent = s.ParentDirectory;
            if (eb is null && s.EncryptedBasenameHex is { Length: > 0 })
                eb = s.EncryptedBasenameHex;
            pi ??= s.RecordProtectionInfoDerHex;
            piBytes ??= s.RecordProtectionInfoBytes;
            best ??= s;
        }

        if (best is null)
            throw new InvalidOperationException("MergeDirectorySpans: empty span list.");

        if (parent == best.ParentDirectory
            && eb == best.EncryptedBasenameHex
            && pi == best.RecordProtectionInfoDerHex)
            return best;

        return new DirectoryCryptoEntry
        {
            RecordName = best.RecordName,
            Source = best.Source,
            PayloadOffset = best.PayloadOffset,
            ParentDirectory = parent ?? best.ParentDirectory,
            EncryptedBasenameHex = eb ?? best.EncryptedBasenameHex,
            EncryptedBasenameBytes = (eb ?? best.EncryptedBasenameHex)?.Length / 2,
            RecordProtectionInfoDerHex = pi ?? best.RecordProtectionInfoDerHex,
            RecordProtectionInfoBytes = piBytes ?? best.RecordProtectionInfoBytes,
        };
    }

    private static bool LooksLikeDirectoryRecordWindow(byte[] window, string recordName)
    {
        // Dopo esclusione parent-ref: encryptedBasename della cartella (hits==1 tipico in sync).
        if (!ContainsAscii(window, "encryptedBasename"))
            return false;

        var nameBytes = Encoding.ASCII.GetBytes(recordName);
        var nameAt = IndexOf(window, nameBytes, 0, window.Length);
        var nameEnd = nameAt >= 0 ? nameAt + nameBytes.Length : 0;
        var bodyArr = window.AsSpan(nameEnd).ToArray();
        var eb = IndexOf(bodyArr, "encryptedBasename"u8.ToArray(), 0, bodyArr.Length);
        if (eb < 0)
            return false;

        var dc = IndexOf(bodyArr, "documentContent/"u8.ToArray(), 0, bodyArr.Length);
        var ds = IndexOf(bodyArr, "documentStructure/"u8.ToArray(), 0, bodyArr.Length);
        if (dc >= 0 && dc < eb)
            return false;
        if (ds >= 0 && ds < eb)
            return false;
        return true;
    }

    private static DirectoryCryptoEntry ParseOneDirectory(
        string recordName,
        byte[] window,
        string source,
        int payloadOffset = 0)
    {
        var bodyStart = FindDirectoryRecordBodyStart(window, recordName);
        var body = window.AsSpan(bodyStart).ToArray();
        var basename = TryExtractEncryptedBasename(body);
        var parent = TryExtractDirectoryParent(body, minOffset: 0);
        var recordPi = PcsProtectionZone.TryExtractRecordProtectionInfoDer(body)
                       ?? PcsProtectionZone.TryExtractRecordProtectionInfoDer(window);
        return new DirectoryCryptoEntry
        {
            RecordName = recordName,
            Source = source,
            PayloadOffset = payloadOffset,
            ParentDirectory = parent,
            EncryptedBasenameHex = basename is null ? null : Convert.ToHexString(basename),
            EncryptedBasenameBytes = basename?.Length,
            RecordProtectionInfoDerHex = recordPi is null ? null : Convert.ToHexString(recordPi),
            RecordProtectionInfoBytes = recordPi?.Length,
        };
    }

    /// <summary>
    /// CloudDocs directory record: stub + full header — campi dopo la 2ª occorrenza del record name.
    /// </summary>
    private static int FindDirectoryRecordBodyStart(byte[] window, string recordName)
    {
        var nameBytes = Encoding.ASCII.GetBytes(recordName);
        if (nameBytes.Length == 0)
            return 0;

        var first = IndexOf(window, nameBytes, 0, window.Length);
        if (first < 0)
            return 0;

        if (recordName.Equals("directory/root", StringComparison.Ordinal))
            return first + nameBytes.Length;

        var second = IndexOf(window, nameBytes, first + nameBytes.Length, window.Length);
        return second >= 0 ? second + nameBytes.Length : first + nameBytes.Length;
    }

    private static int ScoreDirectoryEntry(DirectoryCryptoEntry e) =>
        (e.EncryptedBasenameHex is { Length: > 0 } ? 400 : 0)
        + (e.ParentDirectory is { Length: > 0 } ? 300 : 0)
        + (e.RecordProtectionInfoBytes ?? 0)
        + Math.Min(e.Source.StartsWith("record_changes", StringComparison.Ordinal) ? 200 : 0, 200);

    private static string? TryExtractDirectoryParent(byte[] window, int minOffset = 80)
    {
        var marker = "parent"u8;
        var basenameIdx = IndexOf(window, "encryptedBasename"u8.ToArray(), 0, window.Length);
        var searchEnd = basenameIdx >= minOffset ? basenameIdx : window.Length;
        string? best = null;
        var bestOffset = -1;
        for (var i = minOffset; i <= searchEnd - marker.Length; i++)
        {
            if (!window.AsSpan(i, marker.Length).SequenceEqual(marker))
                continue;

            var regionEnd = Math.Min(window.Length, i + marker.Length + 128);
            var regionText = Encoding.Latin1.GetString(window, i, regionEnd - i);
            var m = DirectoryParentRegex.Match(regionText);
            if (!m.Success)
                continue;
            if (i <= bestOffset)
                continue;
            bestOffset = i;
            best = NormalizeDirectoryRecordName(m.Value);
        }

        return best;
    }

    public static string NormalizeDirectoryRecordName(string recordName)
    {
        if (recordName.Equals("directory/root", StringComparison.Ordinal))
            return recordName;
        if (recordName.StartsWith("directory/", StringComparison.Ordinal)
            && !recordName.StartsWith("directory/root", StringComparison.Ordinal))
            return "." + recordName;
        return recordName;
    }

    private static string SanitizeZoneFolderName(string zone)
    {
        var name = zone.Replace('.', '~');
        return SanitizeFileName(name);
    }

    private static async Task<(
            int Ok,
            Dictionary<string, string> PlainBasenames)>
        TryDecryptDirectoryBasenamesAsync(
            string cryptoDir,
            string fetchDir,
            IReadOnlyList<DirectoryCryptoEntry> directories,
            ProtectionZoneKeys zoneKeys,
            IReadOnlyList<ProtectionZoneKeys> allZoneKeys,
            List<PcsCompactPrivateKey> seedKeys,
            IReadOnlyList<(DocumentCryptoEntry Entry, ProtectionZoneKeys Zone)> documentRecordZones,
            IProgress<string>? log,
            CancellationToken ct)
    {
        var outDir = Path.Combine(cryptoDir, "decrypted_directory_basenames");
        Directory.CreateDirectory(outDir);
        var plainBasenames = new Dictionary<string, string>(StringComparer.Ordinal);
        if (directories.Count == 0)
            return (0, plainBasenames);

        var workingKeys = PcsProtectionZone.MergeKeys(seedKeys, allZoneKeys);
        var withDirPi = directories.Count(static x => x.RecordProtectionInfoDerHex != null);
        var withDirBasename = directories.Count(static x => x.EncryptedBasenameHex != null);
        log?.Report(
            $"  crypto: decifrando directory ProtectionInfo/basename " +
            $"({withDirPi} PI, {withDirBasename} basename)…");

        var basenameHits = await Task.Run(() =>
        {
            var zones = new List<(DirectoryCryptoEntry Entry, ProtectionZoneKeys Zone)>();
            foreach (var e in directories)
            {
                if (e.RecordProtectionInfoDerHex is not { Length: > 0 })
                    continue;
                var recordDer = Convert.FromHexString(e.RecordProtectionInfoDerHex);
                foreach (var recordZone in PcsProtectionZone.TryUnwrapAll(recordDer, workingKeys))
                    zones.Add((e, recordZone));
            }

            var decryptPool = allZoneKeys
                .Concat(zones.Select(static r => r.Zone))
                .Concat(documentRecordZones.Select(static r => r.Zone))
                .Prepend(zoneKeys)
                .DistinctBy(static z => Convert.ToHexString(z.MasterKey))
                .ToList();
            var keyPool = PcsProtectionZone.MergeKeys(seedKeys, decryptPool);

            var hits = new List<(string RecordName, byte[] Plain, string Text)>();
            foreach (var e in directories)
            {
                if (e.EncryptedBasenameHex is not { Length: > 0 })
                    continue;
                var ctBytes = Convert.FromHexString(e.EncryptedBasenameHex);
                var altName = e.RecordName.StartsWith(".directory/", StringComparison.Ordinal)
                    ? e.RecordName[".".Length..]
                    : e.RecordName;
                var aads = new[]
                {
                    "encryptedBasename", "basename", e.RecordName, altName,
                    ShortDirectoryName(e.RecordName),
                };

                var tryZones = new List<ProtectionZoneKeys>();
                foreach (var z in zones
                             .Where(r => r.Entry.RecordName == e.RecordName)
                             .Select(static r => r.Zone))
                    tryZones.Add(z);
                tryZones.AddRange(CollectDirectoryWindowZones(fetchDir, e, keyPool));
                tryZones.AddRange(decryptPool);

                byte[]? plain = null;
                var seenZone = new HashSet<string>(StringComparer.Ordinal);
                foreach (var zk in tryZones)
                {
                    var id = Convert.ToHexString(zk.MasterKey);
                    if (!seenZone.Add(id))
                        continue;
                    plain = PcsProtectionZone.TryDecryptField(zk, ctBytes, aads);
                    if (plain is not null)
                        break;
                }

                if (plain is null)
                    continue;
                hits.Add((e.RecordName, plain, Encoding.UTF8.GetString(plain)));
            }

            return hits;
        }, ct).ConfigureAwait(false);

        foreach (var (recordName, plain, text) in basenameHits)
        {
            plainBasenames[recordName] = text;
            var baseName = Sanitize(recordName);
            await File.WriteAllBytesAsync(Path.Combine(outDir, baseName + ".bin"), plain, ct)
                .ConfigureAwait(false);
            await File.WriteAllTextAsync(Path.Combine(outDir, baseName + ".txt"), text, ct)
                .ConfigureAwait(false);
        }

        var ok = basenameHits.Count;
        log?.Report(
            ok > 0
                ? $"  crypto: directoryBasename {ok}/{withDirBasename}"
                : "  crypto: directory encryptedBasename non decifrati.");
        return (ok, plainBasenames);
    }

    private static List<ProtectionZoneKeys> CollectDirectoryWindowZones(
        string fetchDir,
        DirectoryCryptoEntry entry,
        IReadOnlyList<PcsCompactPrivateKey> keyPool)
    {
        var zones = new List<ProtectionZoneKeys>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var window = TryLoadDirectoryWindow(fetchDir, entry);
        if (window is not { Length: > 64 })
            return zones;

        foreach (var z in PcsProtectionZone.TryUnwrapAll(window, keyPool))
        {
            var id = Convert.ToHexString(z.MasterKey);
            if (!seen.Add(id))
                continue;
            zones.Add(z);
        }

        foreach (var z in PcsProtectionZone.TryUnwrapAllIterative(window, keyPool))
        {
            var id = Convert.ToHexString(z.MasterKey);
            if (!seen.Add(id))
                continue;
            zones.Add(z);
        }

        return zones;
    }

    private static byte[]? TryLoadDirectoryWindow(string fetchDir, DirectoryCryptoEntry entry)
    {
        if (string.IsNullOrWhiteSpace(entry.Source))
            return null;

        foreach (var syncPath in EnumerateSyncPayloadFiles(fetchDir))
        {
            if (!syncPath.EndsWith(entry.Source, StringComparison.OrdinalIgnoreCase)
                && Path.GetFileName(syncPath) != entry.Source)
                continue;
            if (!File.Exists(syncPath))
                continue;

            var payload = File.ReadAllBytes(syncPath);
            var text = Encoding.Latin1.GetString(payload);
            var matches = DirectoryRecordRegex.Matches(text);
            byte[]? best = null;
            var bestScore = -1;
            for (var i = 0; i < matches.Count; i++)
            {
                if (!NormalizeDirectoryRecordName(matches[i].Value)
                        .Equals(entry.RecordName, StringComparison.Ordinal))
                    continue;
                var start = matches[i].Index;
                var end = Math.Min(payload.Length, start + 4500);
                if (end <= start)
                    continue;
                var window = payload.AsSpan(start, end - start).ToArray();
                if (!LooksLikeDirectoryRecordWindow(window, entry.RecordName))
                    continue;
                var score = ScoreDirectoryEntry(ParseOneDirectory(entry.RecordName, window, entry.Source));
                if (score <= bestScore)
                    continue;
                bestScore = score;
                best = window;
            }

            if (best is not null)
                return best;
        }

        return null;
    }

    internal static IReadOnlyDictionary<string, string> BuildDirectoryRelativePaths(
        IReadOnlyList<DirectoryCryptoEntry> directories,
        IReadOnlyDictionary<string, string> plainDirectoryNames)
    {
        var parentByRecord = new Dictionary<string, string?>(StringComparer.Ordinal);
        foreach (var d in directories)
            parentByRecord[d.RecordName] = string.IsNullOrWhiteSpace(d.ParentDirectory)
                ? null
                : NormalizeDirectoryRecordName(d.ParentDirectory);

        var relativeByRecord = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var d in directories)
        {
            var rel = BuildRelativePathSegments(d.RecordName, parentByRecord, plainDirectoryNames);
            if (rel.Length > 0)
                relativeByRecord[d.RecordName] = rel;
        }

        // #region agent log
        {
            var withPlain = plainDirectoryNames.Count(static kv => !string.IsNullOrWhiteSpace(kv.Value));
            var withParent = directories.Count(static d => !string.IsNullOrWhiteSpace(d.ParentDirectory));
            var withRel = relativeByRecord.Count(static kv => !string.IsNullOrWhiteSpace(kv.Value));
            var topSegments = relativeByRecord.Values
                .Where(static v => !string.IsNullOrWhiteSpace(v))
                .Select(static v => v.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)[0])
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static s => s, StringComparer.OrdinalIgnoreCase)
                .Take(40)
                .ToList();
            AgentDirectoryPathDebugLog(
                "H-WA8",
                "CloudDocsDocumentCrypto.BuildDirectoryRelativePaths",
                "directory_paths_built",
                new
                {
                    dirRecords = directories.Count,
                    withPlain,
                    withParent,
                    withRel,
                    topSegments,
                    sample = directories.Take(12).Select(x => new
                    {
                        rec = ShortName(x.RecordName),
                        hasEnc = x.EncryptedBasenameHex is { Length: > 0 },
                        hasParent = !string.IsNullOrWhiteSpace(x.ParentDirectory),
                        plain = plainDirectoryNames.GetValueOrDefault(x.RecordName),
                        rel = relativeByRecord.GetValueOrDefault(x.RecordName),
                    }).ToList(),
                },
                runId: "wa-docs-post");
        }
        // #endregion

        return relativeByRecord;
    }

    private static string BuildRelativePathSegments(
        string recordName,
        IReadOnlyDictionary<string, string?> parentByRecord,
        IReadOnlyDictionary<string, string> plainDirectoryNames)
    {
        var segments = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var current = NormalizeDirectoryRecordName(recordName);
        while (!string.IsNullOrEmpty(current) && seen.Add(current))
        {
            if (plainDirectoryNames.TryGetValue(current, out var plain)
                && !string.IsNullOrWhiteSpace(plain))
            {
                var seg = SanitizeFileName(plain);
                if (segments.Count == 0
                    || !segments[^1].Equals(seg, StringComparison.OrdinalIgnoreCase))
                    segments.Add(seg);
            }

            if (!parentByRecord.TryGetValue(current, out var parent)
                || string.IsNullOrWhiteSpace(parent)
                || parent.Equals(current, StringComparison.Ordinal))
                break;
            current = parent;
        }

        segments.Reverse();
        return segments.Count == 0 ? "" : Path.Combine(segments.ToArray());
    }

    private static string? ResolveFileRelativeDirectoryPath(
        string? parentDirectory,
        IReadOnlyDictionary<string, string> directoryRelativePaths)
    {
        if (string.IsNullOrWhiteSpace(parentDirectory))
            return null;
        var key = NormalizeDirectoryRecordName(parentDirectory);
        //  file con parent directory/root stanno nella root della zona, non in una cartella "root".
        if (key.Equals("directory/root", StringComparison.Ordinal))
            return null;
        if (directoryRelativePaths.TryGetValue(key, out var rel) && !string.IsNullOrWhiteSpace(rel))
            return rel;
        // Fallback: separa i backup multipli anche senza basename directory decifrato.
        var shortId = ShortDirectoryName(key);
        if (string.IsNullOrWhiteSpace(shortId)
            || shortId.Equals("root", StringComparison.OrdinalIgnoreCase))
            return null;
        return SanitizeFileName(shortId);
    }

    private static async Task WriteDirectoryPathArtifactsAsync(
        string cryptoDir,
        string zone,
        IReadOnlyList<DirectoryCryptoEntry> directories,
        IReadOnlyDictionary<string, string> plainDirectoryNames,
        IReadOnlyDictionary<string, string> directoryRelativePaths,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var inventoryPath = Path.Combine(cryptoDir, "directory_inventory.json");
        var payload = directories.Select(d => new
        {
            d.RecordName,
            d.Source,
            d.ParentDirectory,
            d.EncryptedBasenameHex,
            PlainBasename = plainDirectoryNames.GetValueOrDefault(d.RecordName),
            RelativePath = directoryRelativePaths.GetValueOrDefault(d.RecordName),
        }).ToList();
        await File.WriteAllTextAsync(
            inventoryPath,
            JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }),
            ct);

        var mapPath = Path.Combine(cryptoDir, "directory_path_map.json");
        await File.WriteAllTextAsync(
            mapPath,
            JsonSerializer.Serialize(directoryRelativePaths, new JsonSerializerOptions { WriteIndented = true }),
            ct);
        log?.Report(
            $"  crypto: directory inventory {directories.Count} " +
            $"(plain={plainDirectoryNames.Count} paths={directoryRelativePaths.Count}) → {inventoryPath}");
    }

    private static string ShortDirectoryName(string record) =>
        record.StartsWith(".directory/", StringComparison.Ordinal)
            ? record[".directory/".Length..]
            : record.Equals("directory/root", StringComparison.Ordinal) ? "root" : record;

    public static IReadOnlyList<DocumentCryptoEntry> ParseDocumentContents(
        byte[] payload,
        string source)
    {
        var text = Encoding.Latin1.GetString(payload);
        var matches = DocumentContentRegex.Matches(text);
        // CloudDocs: ogni record compare 2× (stub ~135 B + payload pieno) — parse separato, merge campi.
        var perRecord = new Dictionary<string, List<DocumentCryptoEntry>>(StringComparer.Ordinal);
        for (var i = 0; i < matches.Count; i++)
        {
            var m = matches[i];
            if (!m.Value.StartsWith("documentContent/", StringComparison.Ordinal))
                continue;
            var start = m.Index;
            var end = i + 1 < matches.Count
                ? matches[i + 1].Index
                : Math.Min(payload.Length, m.Index + 4500);
            if (end <= start)
                continue;
            var window = payload.AsSpan(start, end - start).ToArray();
            var parsed = ParseOne(m.Value, window, source);
            if (!perRecord.TryGetValue(m.Value, out var list))
            {
                list = [];
                perRecord[m.Value] = list;
            }

            list.Add(parsed);
        }

        var merged = perRecord.Values
            .Select(MergeDocumentSpans)
            .OrderBy(static e => e.RecordName, StringComparer.Ordinal)
            .ToList();
        if (merged.Count > 0)
            return merged;

        // WA deep sync: asset embedded senza documentContent/ ASCII.
        return ParseEmbeddedMmcsEntries(payload, source);
    }

    /// <summary>
    /// WhatsApp deep sync a volte espone asset MMCS (CAog / edge firmati) senza
    /// marker ASCII <c>documentContent/UUID</c>. Costruisce entry scaricabili dagli auth
    /// strutturati e, in fallback, dai template edge + CAog FG validi.
    /// </summary>
    public static IReadOnlyList<DocumentCryptoEntry> ParseEmbeddedMmcsEntries(
        byte[] payload,
        string source)
    {
        var list = new List<DocumentCryptoEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var a in MmcsAuthBuilder.ExtractStructuredAuths(payload))
        {
            if (string.IsNullOrWhiteSpace(a.Header) || !seen.Add(a.Header))
                continue;
            var name = !string.IsNullOrWhiteSpace(a.RecordName)
                ? (a.RecordName!.StartsWith("documentContent/", StringComparison.Ordinal)
                    ? a.RecordName
                    : "documentContent/" + a.RecordName)
                : "documentContent/mmcs-" + Convert.ToHexString(
                    System.Security.Cryptography.SHA256.HashData(
                        Encoding.UTF8.GetBytes(a.Header)).AsSpan(0, 8));
            list.Add(new DocumentCryptoEntry
            {
                RecordName = name,
                Source = source,
                MmcsAuth = a.Header,
            });
        }

        foreach (var header in MmcsAuthBuilder.ExtractAllReadyMadeAuths(payload))
        {
            if (string.IsNullOrWhiteSpace(header) || !seen.Add(header))
                continue;
            var name = "documentContent/mmcs-" + Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(
                    Encoding.UTF8.GetBytes(header)).AsSpan(0, 8));
            list.Add(new DocumentCryptoEntry
            {
                RecordName = name,
                Source = source,
                MmcsAuth = header,
            });
        }

        if (list.Count > 0)
            return list;

        // Fallback live: template edge firmati + CAog FG (sync senza documentContent ASCII).
        var edges = UbChunkBuilder.ParseAuthorizeGetResponse(payload);
        var fgCaogs = ExtractForegroundCaogTokens(payload);
        if (edges.Count == 0 || fgCaogs.Count == 0)
            return list;

        var n = Math.Min(edges.Count, fgCaogs.Count);
        for (var i = 0; i < n; i++)
        {
            var edge = edges[i];
            var caog = fgCaogs[i];
            var sigB64 = edge.EdgeHeaders?.Signature;
            if (string.IsNullOrWhiteSpace(sigB64))
                continue;

            byte[]? sig20 = null;
            try
            {
                sig20 = Convert.FromBase64String(sigB64);
            }
            catch
            {
                try
                {
                    var s = sigB64.Replace('-', '+').Replace('_', '/');
                    while (s.Length % 4 != 0)
                        s += "=";
                    sig20 = Convert.FromBase64String(s);
                }
                catch
                {
                    continue;
                }
            }

            if (sig20 is not { Length: 20 or 21 })
                continue;

            var sig21 = sig20.Length == 21
                ? sig20
                : new byte[] { 0x01 }.Concat(sig20).ToArray();
            var hex = Convert.ToHexString(sig21).ToLowerInvariant();
            var header = $"{hex} {hex} {caog}";
            if (!seen.Add(header))
                continue;

            var oid = edge.EdgeHeaders?.ObjectId ?? $"edge{i}";
            var size = edge.ByteRange is { } r ? r.End + 1 : (long?)null;
            list.Add(new DocumentCryptoEntry
            {
                RecordName = "documentContent/mmcs-" + Sanitize(oid),
                Source = source,
                MmcsAuth = header,
                SizeBytes = size,
                HasFileContent = true,
            });
        }

        return list;
    }

    /// <summary>Estrae token CAog FG validi (decode → Foreground Restore), anche se troncati in coda.</summary>
    private static List<string> ExtractForegroundCaogTokens(byte[] payload)
    {
        var text = Encoding.Latin1.GetString(payload);
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var i = 0;
        while ((i = text.IndexOf("CAog", i, StringComparison.Ordinal)) >= 0)
        {
            var end = i + 4;
            while (end < text.Length && end - i < 400
                   && (char.IsLetterOrDigit(text[end]) || text[end] is '_' or '-' or '='))
                end++;
            var raw = text[i..end];
            string? best = null;
            for (var len = raw.Length; len >= 80; len--)
            {
                var tok = raw[..len];
                try
                {
                    var pad = tok.Replace('-', '+').Replace('_', '/');
                    pad += (pad.Length % 4) switch
                    {
                        2 => "==",
                        3 => "=",
                        _ => string.Empty,
                    };
                    var decoded = Convert.FromBase64String(pad);
                    if (decoded.Length >= 40
                        && decoded[0] == 0x08 && decoded[1] == 0x0A && decoded[2] == 0x20
                        && IndexOf(decoded, "Foreground Restore"u8.ToArray(), 0, decoded.Length) >= 0)
                    {
                        best = tok;
                        break;
                    }
                }
                catch
                {
                    // try shorter
                }
            }

            if (best is not null && seen.Add(best))
                list.Add(best);
            i = end;
        }

        return list;
    }

    /// <summary>Unisce stub + full span: preferisce sempre la occorrenza con fileContent / PI / auth.</summary>
    private static DocumentCryptoEntry MergeDocumentSpans(IReadOnlyList<DocumentCryptoEntry> spans)
    {
        DocumentCryptoEntry? best = null;
        string? contentKind = null;
        DateTimeOffset? modifiedUtc = null;
        DateTimeOffset? createdUtc = null;
        string? lastEditor = null;
        string? parentDirectory = null;
        var authUnion = new List<string>();
        foreach (var s in spans)
        {
            contentKind ??= s.ContentKind;
            modifiedUtc ??= s.ModifiedUtc;
            createdUtc ??= s.CreatedUtc;
            lastEditor ??= s.LastEditorName;
            parentDirectory ??= s.ParentDirectory;
            best = best is null ? s : PreferRicherEntry(best, s);
            if (!string.IsNullOrWhiteSpace(s.MmcsAuth))
                authUnion.Add(s.MmcsAuth!);
            if (s.AdditionalMmcsAuths is { Count: > 0 })
                authUnion.AddRange(s.AdditionalMmcsAuths);
        }

        if (best is null)
            throw new InvalidOperationException("MergeDocumentSpans: empty span list.");

        authUnion = authUnion
            .Where(static a => !string.IsNullOrWhiteSpace(a))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var primary = best.MmcsAuth;
        if (string.IsNullOrWhiteSpace(primary) && authUnion.Count > 0)
            primary = authUnion[0];
        var additional = authUnion
            .Where(a => !string.Equals(a, primary, StringComparison.Ordinal))
            .ToList();

        if (string.IsNullOrEmpty(best.ContentKind) && !string.IsNullOrEmpty(contentKind)
            || best.ModifiedUtc is null && modifiedUtc is not null
            || best.CreatedUtc is null && createdUtc is not null
            || string.IsNullOrEmpty(best.LastEditorName) && !string.IsNullOrEmpty(lastEditor)
            || string.IsNullOrEmpty(best.ParentDirectory) && !string.IsNullOrEmpty(parentDirectory)
            || !string.Equals(best.MmcsAuth, primary, StringComparison.Ordinal)
            || (additional.Count > 0
                && (best.AdditionalMmcsAuths is null
                    || best.AdditionalMmcsAuths.Count != additional.Count)))
        {
            return new DocumentCryptoEntry
            {
                RecordName = best.RecordName,
                Source = best.Source,
                SizeBytes = best.SizeBytes,
                ContentBaseUrl = best.ContentBaseUrl,
                DownloadTokenPrefix = best.DownloadTokenPrefix,
                FileSignatureHex = best.FileSignatureHex,
                ReferenceSignatureHex = best.ReferenceSignatureHex,
                EncryptedBasenameHex = best.EncryptedBasenameHex,
                EncryptedBasenameBytes = best.EncryptedBasenameBytes,
                MmcsAuth = primary,
                AdditionalMmcsAuths = additional.Count > 0 ? additional : null,
                HasFileContent = best.HasFileContent,
                RecordProtectionInfoDerHex = best.RecordProtectionInfoDerHex,
                RecordProtectionInfoBytes = best.RecordProtectionInfoBytes,
                AssetProtectionInfoHex = best.AssetProtectionInfoHex,
                ContentKind = contentKind ?? best.ContentKind,
                ModifiedUtc = best.ModifiedUtc ?? modifiedUtc,
                CreatedUtc = best.CreatedUtc ?? createdUtc,
                LastEditorName = best.LastEditorName ?? lastEditor,
                ParentDirectory = best.ParentDirectory ?? parentDirectory,
            };
        }

        return best;
    }

    private static DocumentCryptoEntry CopyEntry(
        DocumentCryptoEntry e,
        string? contentKind = null,
        DateTimeOffset? modifiedUtc = null,
        DateTimeOffset? createdUtc = null,
        string? lastEditorName = null,
        string? parentDirectory = null)
    {
        return new DocumentCryptoEntry
        {
            RecordName = e.RecordName,
            Source = e.Source,
            SizeBytes = e.SizeBytes,
            ContentBaseUrl = e.ContentBaseUrl,
            DownloadTokenPrefix = e.DownloadTokenPrefix,
            FileSignatureHex = e.FileSignatureHex,
            ReferenceSignatureHex = e.ReferenceSignatureHex,
            EncryptedBasenameHex = e.EncryptedBasenameHex,
            EncryptedBasenameBytes = e.EncryptedBasenameBytes,
            MmcsAuth = e.MmcsAuth,
            AdditionalMmcsAuths = e.AdditionalMmcsAuths,
            HasFileContent = e.HasFileContent,
            RecordProtectionInfoDerHex = e.RecordProtectionInfoDerHex,
            RecordProtectionInfoBytes = e.RecordProtectionInfoBytes,
            AssetProtectionInfoHex = e.AssetProtectionInfoHex,
            ContentKind = contentKind ?? e.ContentKind,
            ModifiedUtc = modifiedUtc ?? e.ModifiedUtc,
            CreatedUtc = createdUtc ?? e.CreatedUtc,
            LastEditorName = lastEditorName ?? e.LastEditorName,
            ParentDirectory = parentDirectory ?? e.ParentDirectory,
        };
    }

    private static DocumentCryptoEntry PreferRicherEntry(DocumentCryptoEntry a, DocumentCryptoEntry b)
    {
        int Score(DocumentCryptoEntry e) =>
            (e.HasFileContent ? 1000 : 0)
            + (e.MmcsAuth is { Length: > 0 } ? 500 : 0)
            + (e.RecordProtectionInfoBytes ?? 0)
            + (e.AssetProtectionInfoHex is { Length: > 0 } ? 200 : 0)
            + (e.EncryptedBasenameHex is { Length: > 0 } ? 100 : 0)
            + (int)Math.Min(e.SizeBytes ?? 0, 1000)
            + (e.Source.StartsWith("batch", StringComparison.OrdinalIgnoreCase) ? 80 : 0)
            - (e.Source.StartsWith("record_changes", StringComparison.OrdinalIgnoreCase) ? 40 : 0);

        return Score(b) > Score(a) ? b : a;
    }

    private static bool TryParseMmcsAuthSignatures(
        string? mmcsAuth,
        out byte[]? fileSignature,
        out byte[]? referenceSignature)
    {
        fileSignature = null;
        referenceSignature = null;
        if (string.IsNullOrWhiteSpace(mmcsAuth))
            return false;
        var parts = mmcsAuth.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            return false;
        if (!TryParseWireSignature(parts[0], out var sig1)
            || !TryParseWireSignature(parts[1], out var sig2))
            return false;
        fileSignature = sig1;
        referenceSignature = sig2;
        return true;
    }

    private static string SignatureHexForInventory(ReadOnlySpan<byte> wireSignature)
    {
        if (wireSignature.Length == 21 && wireSignature[0] is 0x01 or 0x04)
            return Convert.ToHexString(wireSignature[1..]);
        return Convert.ToHexString(wireSignature);
    }

    private static DocumentCryptoEntry ParseOne(string recordName, byte[] window, string source)
    {
        var basename = TryExtractEncryptedBasename(window);
        var contentKind = TryExtractContentKind(window);
        var fc = IndexOf(window, "fileContent"u8.ToArray(), 0, window.Length);
        // Asset reale (fileContent): se ci sono 2 CAog, il primo è stub (~66 B), il secondo dopo fileContent.
        var assetRegionStart = fc >= 0 ? fc : 0;
        var caog = TryExtractCaog(window, assetRegionStart)
                   ?? TryExtractCaog(window, 0);

        string? mmcsAuth = null;
        var structured = MmcsAuthBuilder.ExtractStructuredAuths(window);
        //  package/large file → più CAog nello stesso record (fileContent/pkgContent).
        var allAuthHeaders = structured
            .Select(static a => a.Header)
            .Where(static h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (caog is not null && structured.Count > 0)
        {
            var match = structured.FirstOrDefault(a =>
                a.Header.Contains(caog, StringComparison.Ordinal));
            if (match is not null)
                mmcsAuth = match.Header;
        }

        if (mmcsAuth is null && structured.Count > 0)
        {
            var afterFc = structured.LastOrDefault(a =>
            {
                var tok = a.Header.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
                return tok is not null && IndexOf(window, Encoding.ASCII.GetBytes(tok), assetRegionStart, window.Length) >= 0;
            });
            mmcsAuth = afterFc?.Header ?? structured[^1].Header;
        }

        byte[]? wireFileSig = null;
        byte[]? wireRefSig = null;
        if (TryParseMmcsAuthSignatures(mmcsAuth, out var authFileSig, out var authRefSig))
        {
            wireFileSig = authFileSig;
            wireRefSig = authRefSig;
        }

        var signatures = new List<string>();
        if (wireFileSig is not null)
            signatures.Add(SignatureHexForInventory(wireFileSig));
        if (wireRefSig is not null)
            signatures.Add(SignatureHexForInventory(wireRefSig));
        if (signatures.Count == 0)
        {
            signatures = ExtractHexSignatures(window, assetRegionStart);
            if (signatures.Count == 0)
                signatures = ExtractHexSignatures(window, 0);
        }

        if (mmcsAuth is null && caog is not null && signatures.Count >= 2)
            mmcsAuth = $"01{signatures[0]} 01{signatures[1]} {caog}";
        else if (mmcsAuth is null && caog is not null && signatures.Count == 1)
            mmcsAuth = $"01{signatures[0]} 01{signatures[0]} {caog}";

        if (mmcsAuth is not null && !allAuthHeaders.Contains(mmcsAuth, StringComparer.Ordinal))
            allAuthHeaders.Insert(0, mmcsAuth);

        var additionalAuths = allAuthHeaders
            .Where(h => !string.Equals(h, mmcsAuth, StringComparison.Ordinal))
            .ToList();

        var size = TryExtractSizeNearMarker(window, "size"u8, preferAfter: assetRegionStart)
                   ?? TryExtractSizeNearMarker(window, "size"u8, preferAfter: 0);
        var contentUrl = TryExtractContentUrl(window);
        var recordPi = fc >= 0
            ? TryExtractRecordProtectionInfoDer(window, fc)
            : null;
        recordPi ??= PcsProtectionZone.TryExtractRecordProtectionInfoDer(window);

        byte[]? assetWrap = null;
        if (wireFileSig is not null)
        {
            assetWrap = CloudKitAssetProto.TryGetWrapForSignature(window, wireFileSig)
                        ?? CloudKitAssetProto.TryGetWrapForReferenceSignature(window, wireFileSig);
        }

        assetWrap ??= ResolveAssetProtectionWrap(window, signatures);

        return new DocumentCryptoEntry
        {
            RecordName = recordName,
            Source = source,
            SizeBytes = size,
            ContentBaseUrl = contentUrl,
            DownloadTokenPrefix = caog is null ? null : caog[..Math.Min(48, caog.Length)],
            FileSignatureHex = signatures.ElementAtOrDefault(0),
            ReferenceSignatureHex = signatures.ElementAtOrDefault(1),
            EncryptedBasenameHex = basename is null ? null : Convert.ToHexString(basename),
            EncryptedBasenameBytes = basename?.Length,
            MmcsAuth = mmcsAuth,
            AdditionalMmcsAuths = additionalAuths.Count > 0 ? additionalAuths : null,
            HasFileContent = fc >= 0,
            RecordProtectionInfoDerHex = recordPi is null ? null : Convert.ToHexString(recordPi),
            RecordProtectionInfoBytes = recordPi?.Length,
            AssetProtectionInfoHex = assetWrap is null ? null : Convert.ToHexString(assetWrap),
            ContentKind = contentKind,
            ModifiedUtc = TryExtractCloudDocsUnixTime(window, "mtime"u8),
            LastEditorName = TryExtractLastEditorName(window),
        };
    }

    private static byte[]? TryExtractRecordProtectionInfoDer(byte[] window, int preferAfter)
    {
        if (preferAfter > 0 && preferAfter < window.Length)
        {
            var tail = window.AsSpan(preferAfter);
            var pi = PcsProtectionZone.TryExtractRecordProtectionInfoDer(tail);
            if (pi is not null)
                return pi;
        }

        return PcsProtectionZone.TryExtractRecordProtectionInfoDer(window);
    }

    /// <summary>
    /// Marker CloudDocs: campo record <c>extension</c> → <c>pdf:2</c>, <c>enc:2</c>, ecc.
    /// WhatsApp/Drive: il marker sta ~240–300 B prima di <c>fileContent</c>, non nel lookback 128 B.
    /// </summary>
    private static string? TryExtractContentKind(byte[] window)
    {
        var fc = IndexOf(window, "fileContent"u8.ToArray(), 0, window.Length);
        var extMarker = "extension"u8;
        string? bestKind = null;
        var bestDistance = int.MaxValue;

        for (var i = 0; i <= window.Length - extMarker.Length; i++)
        {
            if (!window.AsSpan(i, extMarker.Length).SequenceEqual(extMarker))
                continue;

            if (fc >= 0 && i > fc)
                continue;

            var regionEnd = Math.Min(window.Length, i + extMarker.Length + 64);
            var regionText = Encoding.Latin1.GetString(window, i, regionEnd - i);
            var m = ContentKindRegex.Match(regionText);
            if (!m.Success)
                continue;

            var kind = NormalizeContentKind(m.Groups[1].Value);
            if (kind.Length == 0)
                continue;

            var distance = fc >= 0 ? fc - i : i;
            if (distance < bestDistance)
            {
                bestDistance = distance;
                bestKind = kind;
            }
        }


        return bestKind;
    }

    /// <summary>
    /// CloudDocs date field: <c>mtime</c> / <c>birthtime</c> → nested protobuf con unix seconds (field 4).
    /// </summary>
    private static DateTimeOffset? TryExtractCloudDocsUnixTime(byte[] window, ReadOnlySpan<byte> marker)
    {
        var markerBytes = marker.ToArray();
        for (var i = 0; i <= window.Length - markerBytes.Length; i++)
        {
            if (!window.AsSpan(i, markerBytes.Length).SequenceEqual(marker))
                continue;

            var tailStart = i + markerBytes.Length;
            if (tailStart + 2 >= window.Length || window[tailStart] != 0x12)
                continue;

            var len = window[tailStart + 1];
            if ((len & 0x80) != 0 || tailStart + 2 + len > window.Length)
                continue;

            if (TryParseCloudDocsDateInner(window.AsSpan(tailStart + 2, len), out var unix))
                return DateTimeOffset.FromUnixTimeSeconds(unix);
        }

        return null;
    }

    private static bool TryParseCloudDocsDateInner(ReadOnlySpan<byte> inner, out long unixSeconds)
    {
        unixSeconds = 0;
        var i = 0;
        while (i < inner.Length)
        {
            if (i >= inner.Length)
                break;
            var tag = inner[i++];
            var field = tag >> 3;
            var wire = tag & 7;
            if (wire != 0)
                return false;
            if (!TryReadProtobufVarint(inner, ref i, out var value))
                return false;
            if (field == 4 && value is >= 1_000_000_000 and < 10_000_000_000)
            {
                unixSeconds = (long)value;
                return true;
            }
        }

        return false;
    }

    private static bool TryReadProtobufVarint(ReadOnlySpan<byte> data, ref int i, out ulong value)
    {
        value = 0;
        var shift = 0;
        while (i < data.Length)
        {
            var b = data[i++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
            if (shift > 63)
                return false;
        }

        return false;
    }

    private static string? TryExtractLastEditorName(byte[] window)
    {
        var marker = "lastEditorName"u8;
        for (var i = 0; i <= window.Length - marker.Length; i++)
        {
            if (!window.AsSpan(i, marker.Length).SequenceEqual(marker))
                continue;

            var regionEnd = Math.Min(window.Length, i + marker.Length + 96);
            var regionText = Encoding.UTF8.GetString(window, i, regionEnd - i);
            var m = LastEditorJsonRegex.Match(regionText);
            if (!m.Success)
                continue;

            var name = m.Groups[1].Value.Trim();
            var type = m.Groups[2].Value.Trim();
            if (name.Length == 0)
                continue;
            return type.Length > 0 ? $"{name} ({type})" : name;
        }

        return null;
    }

    private static string? TryExtractParentDirectory(byte[] window)
    {
        var marker = "parent"u8;
        for (var i = 0; i <= window.Length - marker.Length; i++)
        {
            if (!window.AsSpan(i, marker.Length).SequenceEqual(marker))
                continue;

            var regionEnd = Math.Min(window.Length, i + marker.Length + 128);
            var regionText = Encoding.Latin1.GetString(window, i, regionEnd - i);
            var m = DirectoryParentRegex.Match(regionText);
            if (m.Success)
                return m.Value;
        }

        return null;
    }

    private static string? ExtractRecordUuid(string recordName)
    {
        var slash = recordName.LastIndexOf('/');
        if (slash < 0 || slash + 1 >= recordName.Length)
            return null;
        var uuid = recordName[(slash + 1)..];
        return uuid.Length == 36 ? uuid : null;
    }

    private static async Task EnrichEntriesWithStructureMetadata(
        IList<DocumentCryptoEntry> entries,
        IReadOnlyList<string> syncBins,
        CancellationToken ct)
    {
        var createdByUuid = new Dictionary<string, DateTimeOffset>(StringComparer.OrdinalIgnoreCase);
        var parentByUuid = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var bin in syncBins)
        {
            ct.ThrowIfCancellationRequested();
            var payload = await File.ReadAllBytesAsync(bin, ct);
            var text = Encoding.Latin1.GetString(payload);
            var matches = DocumentStructureRegex.Matches(text);
            for (var i = 0; i < matches.Count; i++)
            {
                var m = matches[i];
                var start = m.Index;
                var end = i + 1 < matches.Count
                    ? matches[i + 1].Index
                    : Math.Min(payload.Length, m.Index + 4500);
                if (end <= start)
                    continue;

                var window = payload.AsSpan(start, end - start).ToArray();
                var uuid = ExtractRecordUuid(m.Value);
                if (uuid is null)
                    continue;

                var created = TryExtractCloudDocsUnixTime(window, "birthtime"u8);
                if (created is not null)
                    createdByUuid[uuid] = created.Value;

                var parent = TryExtractParentDirectory(window);
                if (!string.IsNullOrWhiteSpace(parent))
                    parentByUuid[uuid] = parent;
            }
        }

        for (var idx = 0; idx < entries.Count; idx++)
        {
            var e = entries[idx];
            var uuid = ExtractRecordUuid(e.RecordName);
            if (uuid is null)
                continue;

            DateTimeOffset? created = e.CreatedUtc;
            string? parent = e.ParentDirectory;
            if (createdByUuid.TryGetValue(uuid, out var c))
                created ??= c;
            if (parentByUuid.TryGetValue(uuid, out var p))
                parent ??= p;

            if (created != e.CreatedUtc || parent != e.ParentDirectory)
                entries[idx] = CopyEntry(e, createdUtc: created, parentDirectory: parent);
        }
    }

    private static void TryApplyCloudDocsFileTimes(
        string path,
        DocumentCryptoEntry entry,
        IProgress<string>? log)
    {
        if (entry.CreatedUtc is null && entry.ModifiedUtc is null)
            return;

        try
        {
            if (entry.CreatedUtc is { } created)
                File.SetCreationTimeUtc(path, created.UtcDateTime);
            if (entry.ModifiedUtc is { } modified)
            {
                File.SetLastWriteTimeUtc(path, modified.UtcDateTime);
                File.SetLastAccessTimeUtc(path, modified.UtcDateTime);
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  crypto timestamps {Path.GetFileName(path)}: {ex.Message}");
        }
    }

    private static string FormatCloudDocsTimestamp(DateTimeOffset? value) =>
        value is null ? "-" : value.Value.UtcDateTime.ToString("yyyy-MM-dd HH:mm:ss'Z'");

    private static readonly Regex ContentKindRegex =
        new(@":[^a-zA-Z]*([a-zA-Z0-9_.-]+):2", RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static string NormalizeContentKind(string raw)
    {
        var kind = raw.Trim().ToLowerInvariant();
        if (kind.StartsWith("public.", StringComparison.Ordinal))
            kind = kind["public.".Length..];
        if (kind.StartsWith("dyn.", StringComparison.Ordinal))
            kind = kind["dyn.".Length..];
        var slash = kind.IndexOf('/');
        if (slash >= 0)
            kind = kind[(slash + 1)..];
        return kind;
    }

    private static List<ProtectionZoneKeys> CollectRecordWindowZones(
        string fetchDir,
        DocumentCryptoEntry entry,
        IReadOnlyList<PcsCompactPrivateKey> keyPool)
    {
        var zones = new List<ProtectionZoneKeys>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var window = TryLoadRecordWindow(fetchDir, entry);
        if (window is not { Length: > 64 })
            return zones;

        void Add(IEnumerable<ProtectionZoneKeys> found)
        {
            foreach (var z in found)
            {
                var id = Convert.ToHexString(z.MasterKey);
                if (!seen.Add(id))
                    continue;
                zones.Add(z);
            }
        }

        Add(PcsProtectionZone.TryUnwrapAll(window, keyPool));
        Add(PcsProtectionZone.TryUnwrapAllIterative(window, keyPool));
        return zones;
    }

    private static byte[]? ResolveAssetProtectionWrap(byte[] window, IReadOnlyList<string> signatures)
    {
        if (signatures.Count > 0
            && TryParseHexSignature(signatures[0], out var fileSig))
        {
            foreach (var sig21 in ExpandCloudKitSignatureCandidates(fileSig))
            {
                var wrap = CloudKitAssetProto.TryGetWrapForSignature(window, sig21);
                if (wrap is { Length: 24 or 40 })
                    return wrap;
            }
        }

        if (signatures.Count > 1
            && TryParseHexSignature(signatures[1], out var refSig))
        {
            foreach (var sig21 in ExpandCloudKitSignatureCandidates(refSig))
            {
                var wrap = CloudKitAssetProto.TryGetWrapForReferenceSignature(window, sig21)
                           ?? CloudKitAssetProto.TryGetWrapForSignature(window, sig21)
                           ?? MmcsAssetProtection.TryExtractForSignature(window, sig21);
                if (wrap is { Length: 24 or 40 })
                    return wrap;
            }
        }

        return MmcsAssetProtection.TryExtract(window);
    }

    private static IEnumerable<byte[]> ExpandCloudKitSignatureCandidates(byte[] sig20)
    {
        if (sig20.Length != 20)
            yield break;
        foreach (var lead in new byte[] { 0x04, 0x01 })
        {
            var sig21 = new byte[21];
            sig21[0] = lead;
            Buffer.BlockCopy(sig20, 0, sig21, 1, 20);
            yield return sig21;
        }
    }

    private static bool TryParseWireSignature(string hex, out byte[] signature)
    {
        signature = Array.Empty<byte>();
        hex = hex.Trim();
        if (hex.Length is not (40 or 42))
            return false;
        try
        {
            signature = Convert.FromHexString(hex);
            return signature.Length is 20 or 21;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryParseHexSignature(string hex, out byte[] signature)
    {
        signature = Array.Empty<byte>();
        if (TryParseWireSignature(hex, out var wire))
        {
            signature = wire.Length == 21 ? wire[1..].ToArray() : wire;
            return signature.Length == 20;
        }

        return false;
    }

    private static byte[]? TryExtractAssetProtectionInfo(byte[] window) =>
        MmcsAssetProtection.TryExtract(window);

    private static byte[]? TryExtractEncryptedBasename(byte[] window)
    {
        var marker = "encryptedBasename"u8;
        for (var i = 0; i <= window.Length - marker.Length; i++)
        {
            if (!window.AsSpan(i, marker.Length).SequenceEqual(marker))
                continue;
            // …encryptedBasename 12 <outerLen> 08 14 12 <innerLen> <bytes>
            var p = i + marker.Length;
            if (p + 5 >= window.Length || window[p] != 0x12)
                continue;
            // skip outer length varint
            p++;
            while (p < window.Length && (window[p - 1] & 0x80) != 0)
                p++;
            // after first length byte(s): expect 08 14 12 len
            // Re-scan from marker end for 08 14 12
            var idx = IndexOf(window, [0x08, 0x14, 0x12], i + marker.Length, i + marker.Length + 16);
            if (idx < 0 || idx + 3 >= window.Length)
                continue;
            var len = window[idx + 3];
            var start = idx + 4;
            if (start + len > window.Length || len is < 8 or > 200)
                continue;
            return window.AsSpan(start, len).ToArray();
        }

        return null;
    }

    private static string? TryExtractCaog(byte[] window, int start = 0)
    {
        var idx = IndexOf(window, "CAog"u8.ToArray(), start, window.Length);
        if (idx < 0)
            return null;
        var end = idx;
        while (end < window.Length && IsBase64Url(window[end]))
            end++;
        if (end - idx < 32)
            return null;
        return Encoding.ASCII.GetString(window, idx, end - idx);
    }

    private static List<string> ExtractHexSignatures(byte[] window, int start = 0)
    {
        var list = new List<string>();
        var from = Math.Clamp(start, 0, window.Length);
        var text = Encoding.Latin1.GetString(window, from, window.Length - from);
        foreach (Match m in Regex.Matches(text, @"(?:^|[^0-9A-Fa-f])([0-9A-Fa-f]{40})(?:[^0-9A-Fa-f]|$)"))
        {
            var h = m.Groups[1].Value.ToUpperInvariant();
            if (!list.Contains(h, StringComparer.Ordinal))
                list.Add(h);
            if (list.Count >= 4)
                break;
        }

        return list;
    }

    private static long? TryExtractSizeNearMarker(byte[] window, ReadOnlySpan<byte> marker, int preferAfter = 0)
    {
        var searchFrom = Math.Clamp(preferAfter, 0, window.Length);
        var idx = IndexOf(window, marker.ToArray(), searchFrom, window.Length);
        if (idx < 0 && preferAfter > 0)
            idx = IndexOf(window, marker.ToArray(), 0, window.Length);
        if (idx < 0)
            return null;
        // After "size" look for protobuf varint value pattern … 20 <varint> (type INT64)
        for (var i = idx; i < Math.Min(window.Length - 3, idx + 24); i++)
        {
            if (window[i] != 0x20)
                continue;
            var p = i + 1;
            long val = 0;
            var shift = 0;
            while (p < window.Length && shift <= 63)
            {
                var c = window[p++];
                val |= (long)(c & 0x7f) << shift;
                if ((c & 0x80) == 0)
                    return val is > 0 and < 10_000_000_000L ? val : null;
                shift += 7;
            }
        }

        return null;
    }

    private static string? TryExtractContentUrl(byte[] window)
    {
        var idx = IndexOf(window, "https://"u8.ToArray(), 0, window.Length);
        if (idx < 0)
            return null;
        var end = idx;
        while (end < window.Length && window[end] >= 32 && window[end] < 127)
            end++;
        var url = Encoding.ASCII.GetString(window, idx, end - idx);
        // Taglia junk protobuf dopo /content
        var content = url.IndexOf("/content", StringComparison.Ordinal);
        if (content >= 0)
            url = url[..(content + "/content".Length)];
        return url;
    }

    private static IReadOnlyList<string> ExtractProtectionTags(byte[] zonePayload)
    {
        var text = Encoding.Latin1.GetString(zonePayload);
        return Regex.Matches(text, @"[0-9A-Fa-f]{40,64}")
            .Select(static m => m.Value.ToUpperInvariant())
            .Distinct(StringComparer.Ordinal)
            .Take(20)
            .ToList();
    }

    private async Task WriteDecryptStatusAsync(
        string cryptoDir,
        string zone,
        IReadOnlyList<DocumentCryptoEntry> entries,
        IReadOnlyList<DirectoryCryptoEntry> directories,
        ProtectionZoneKeys? zoneKeys,
        int basenameOk,
        int directoryBasenameOk,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var lines = new[]
        {
            "CloudDocs WhatsApp — stato decrittografia",
            $"zone={zone}",
            $"documentContent={entries.Count}",
            $"directories={directories.Count}",
            "",
            "Modello chiavi (solo live):",
            "- KeySet PCS in ICloudSession (Escrow recover/unlock → sessione)",
            "- zone/retrieve + record/sync + FetchRecords di questa run (byte in memoria)",
            "- Artifact sotto crypto/ = output della run, non input da dump storici",
            "",
            $"Zone unwrap: {(zoneKeys is null ? "PENDING/FAIL" : "OK KeyID=" + zoneKeys.MasterKeyIdHex)}",
            $"nested MasterKeySet: {zoneKeys?.NestedPrivateKeys.Count ?? 0} keys / nestedPlain={zoneKeys?.NestedProtectionObject?.Length ?? 0} B",
            $"record ProtectionInfo in inventory: {entries.Count(e => e.RecordProtectionInfoDerHex != null)}",
            $"encryptedBasename decrypt: {basenameOk}/{entries.Count(e => e.EncryptedBasenameHex != null)}",
            $"directory encryptedBasename decrypt: {directoryBasenameOk}/{directories.Count(e => e.EncryptedBasenameHex != null)}",
            $"Asset.protectionInfo (wrap24): {entries.Count(e => e.AssetProtectionInfoHex != null)}",
            "",
            "Artifact (solo output di questa run):",
            $"- inventory.json ({entries.Count} entry)",
            $"- directory_inventory.json / directory_path_map.json",
            $"- zone_unwrap_meta.json / zone_decrypt_key.bin (se unwrap OK)",
            $"- zone_pi_plain.bin (nested ProtectionObject se GCM OK)",
            $"- record_protection/*_master.bin (se record PI unwrap OK)",
            $"- decrypted_basenames/* (se AAD match)",
            $"- decrypted_directory_basenames/* (path)",
            $"- plaintext/{{zone~sanitized}}/{{path}}/ (MMCS decrypt)",
            $"- ciphertext/*.bin (MMCS edge, compact)",
            $"- MMCS auth: {entries.Count(e => !string.IsNullOrWhiteSpace(e.MmcsAuth))}",
            "",
            basenameOk > 0
                ? "Basename OK; file content = Asset.protectionInfo → KEK → chunk key → AES-CFB."
                : "Basename ancora 0: verificare nested MasterKeySet e AAD encryptedBasename.",
        };
        var path = Path.Combine(cryptoDir, "DECRYPT_STATUS.txt");
        await File.WriteAllLinesAsync(path, lines, ct);
        log?.Report($"  crypto: {path}");
    }

    private async Task<(bool Downloaded, bool Decrypted)> TryDownloadAndDecryptAsync(
        ICloudSession session,
        string zone,
        DocumentCryptoEntry entry,
        string fetchDir,
        string downloadDir,
        string plainDir,
        IReadOnlyDictionary<string, byte[]> recordMasters,
        IReadOnlyDictionary<string, string> plainBasenames,
        ProtectionZoneKeys zoneKeys,
        IReadOnlyList<ProtectionZoneKeys> allZoneKeys,
        IReadOnlyList<(DocumentCryptoEntry Entry, ProtectionZoneKeys Zone)> recordZones,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        IReadOnlyDictionary<string, DocumentCryptoEntry> entriesByFileSig,
        IReadOnlyDictionary<string, string> directoryRelativePaths,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(entry.MmcsAuth) || string.IsNullOrWhiteSpace(session.Dsid))
            return (false, false);

        var hosts = MmcsContentEndpoints.BuildAuthorizeGetHosts(session, entry.ContentBaseUrl);
        var mmcsZone = CloudKitContainerBinding.CloudDocs.ContainerId;
        // Auth secondari solo per riempire buchi (multi-round). AG di tutti gli auth
        // in parallelo duplicava gli stessi ObjectId/range (URL diverse) → ciphertext 2× cryptoSum.
        var primaryAuth = entry.MmcsAuth!;
        var fillAuths = (entry.AdditionalMmcsAuths ?? Array.Empty<string>())
            .Where(a => !string.IsNullOrWhiteSpace(a)
                        && !string.Equals(a, primaryAuth, StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        Exception? last = null;
        foreach (var host in hosts)
        {
            try
            {
                var mergedChunks = new List<SignedUrlChunk>();
                var seenRange = new HashSet<string>(StringComparer.Ordinal);
                byte[]? lastAuthBody = null;
                var agRounds = 0;
                var fillAuthsUsed = 0;
                const int maxAgRounds = 12;

                void MergeChunks(IReadOnlyList<SignedUrlChunk> chunks)
                {
                    foreach (var c in chunks)
                    {
                        // Dedup per object+range (non URL): AG diversi firmano lo stesso range.
                        var key =
                            $"{c.EdgeHeaders?.ObjectId}|{c.ByteRange?.Start}|{c.ByteRange?.End}";
                        if (!seenRange.Add(key))
                            continue;
                        mergedChunks.Add(c);
                    }
                }

                async Task<bool> AuthorizeAndMergeAsync(string auth)
                {
                    if (agRounds >= maxAgRounds)
                        return false;
                    var authBody = await AuthorizeGetAsync(session, host, auth, mmcsZone, ct);
                    agRounds++;
                    if (authBody is null || authBody.Length == 0)
                        return false;
                    lastAuthBody = authBody;
                    var before = mergedChunks.Count;
                    MergeChunks(UbChunkBuilder.ParseAuthorizeGetResponse(authBody));
                    return mergedChunks.Count > before;
                }

                // 1) Primary auth
                await AuthorizeAndMergeAsync(primaryAuth);

                // 2) Solo se coverage incompleta: auth secondari + re-AG primary
                var fillIdx = 0;
                while (agRounds < maxAgRounds
                       && MmcsContentEndpoints.IsAuthorizeGetIncomplete(
                           mergedChunks, entry.SizeBytes))
                {
                    var progressed = false;
                    if (fillIdx < fillAuths.Count)
                    {
                        progressed = await AuthorizeAndMergeAsync(fillAuths[fillIdx]);
                        fillIdx++;
                        fillAuthsUsed = fillIdx;
                    }
                    else
                    {
                        // Re-AG primary: a volte ottiene range residui con lo stesso CAog.
                        progressed = await AuthorizeAndMergeAsync(primaryAuth);
                        if (!progressed)
                            break;
                    }

                    if (!progressed && fillIdx >= fillAuths.Count)
                        break;
                }

                if (mergedChunks.Count == 0 || lastAuthBody is null)
                    continue;

                var incomplete = MmcsContentEndpoints.IsAuthorizeGetIncomplete(
                    mergedChunks, entry.SizeBytes);
                if (incomplete)
                {
                    log?.Report(
                        $"  crypto {ShortName(entry.RecordName)}: authorizeGet parziale " +
                        $"(chunks={mergedChunks.Count}, fillAuths={fillAuths.Count}, rounds={agRounds}, " +
                        $"declared={entry.SizeBytes:N0}) — scarico i range disponibili");
                }

                // #region agent log
                AgentLogCrypto(
                    "H-WA-IKE2",
                    "CloudDocsDocumentCrypto.TryDownloadAndDecryptAsync",
                    "ag_multi_auth_coverage",
                    new
                    {
                        record = ShortName(entry.RecordName),
                        host,
                        authCount = 1 + fillAuths.Count,
                        fillAuthsUsed,
                        agRounds,
                        chunkCount = mergedChunks.Count,
                        declared = entry.SizeBytes,
                        incomplete,
                        rangeSum = mergedChunks
                            .Where(static c => c.ByteRange.HasValue)
                            .Select(static c =>
                                c.ByteRange!.Value.End - c.ByteRange!.Value.Start + 1)
                            .DefaultIfEmpty(0)
                            .Sum(),
                        runId = "post-fix",
                    });
                // #endregion

                var tag = Sanitize(entry.RecordName);
                await File.WriteAllBytesAsync(
                    Path.Combine(downloadDir, tag + "_authorizeGet.bin"), lastAuthBody, ct);

                var outFile = Path.Combine(downloadDir, tag + ".bin");
                var len = await DownloadChunksCompactAsync(outFile, mergedChunks, mmcsZone, ct);
                var declared = entry.SizeBytes;
                var rangeLen = mergedChunks
                    .Where(static c => c.ByteRange.HasValue)
                    .Select(static c => c.ByteRange!.Value.End - c.ByteRange!.Value.Start + 1)
                    .DefaultIfEmpty(len)
                    .Sum();
                if (declared is > 1024 && rangeLen > 0 && rangeLen < declared / 10)
                {
                    log?.Report(
                        $"  crypto {ShortName(entry.RecordName)}: ATTENZIONE authorizeGet " +
                        $"{rangeLen:N0} B << size dichiarato {declared:N0} B — possibile asset stub");
                }

                var plan = UbChunkBuilder.BuildDecryptPlan(lastAuthBody);
                log?.Report(
                    $"  crypto {ShortName(entry.RecordName)}: ciphertext {len:N0} B ← {host} " +
                    $"({mergedChunks.Count} edge/{agRounds} AG, {plan.TotalCryptoChunks} crypto-chunk, " +
                    $"refs={plan.References.Count}, sum={plan.TotalCryptoBytes:N0})");
                await File.WriteAllTextAsync(
                    Path.Combine(downloadDir, tag + ".meta.txt"),
                    $"record={entry.RecordName}\nhost={host}\nedgeChunks={mergedChunks.Count}\n" +
                    $"agRounds={agRounds}\nfillAuths={fillAuths.Count}\nfillUsed={fillAuthsUsed}\n" +
                    $"cryptoChunks={plan.TotalCryptoChunks}\nrefs={plan.References.Count}\n" +
                    $"cryptoSum={plan.TotalCryptoBytes}\nbytes={len}\n" +
                    $"assetWrap={(entry.AssetProtectionInfoHex is null ? "missing" : "ok")}\n" +
                    $"mmcsAuth={entry.MmcsAuth}\n",
                    ct);

                var decrypted = await TryDecryptDownloadedAsync(
                    entry, zone, fetchDir, outFile, lastAuthBody, mergedChunks, plainDir,
                    recordMasters, plainBasenames, zoneKeys, allZoneKeys, recordZones,
                    seedKeys, entriesByFileSig, directoryRelativePaths, log, ct);
                return (true, decrypted);
            }
            catch (Exception ex)
            {
                last = ex;
            }
        }

        if (last is not null)
            log?.Report($"  crypto {ShortName(entry.RecordName)}: authorizeGet fallito — {last.Message}");
        return (false, false);
    }

    /// <summary>
    /// Scarica i chunk in file contiguo (ordine authorizeGet; niente reorder per Start —
    /// i multi-object CloudDocs hanno tutti range 0-N con signature diverse).
    /// </summary>
    private async Task<long> DownloadChunksCompactAsync(
        string outputFile,
        IReadOnlyList<SignedUrlChunk> chunks,
        string mmcsZone,
        CancellationToken ct)
    {
        var ordered = chunks
            .Where(static c => !string.IsNullOrEmpty(c.Url))
            .ToList();

        await using var output = new FileStream(
            outputFile, FileMode.Create, FileAccess.Write, FileShare.None);
        long downloaded = 0;
        var chunkIndex = 0;
        foreach (var chunk in ordered)
        {
            ct.ThrowIfCancellationRequested();
            chunkIndex++;
            using var request = new HttpRequestMessage(HttpMethod.Get, chunk.Url);
            if (chunk.ByteRange is { } range)
                request.Headers.Range = new RangeHeaderValue(range.Start, range.End);

            // CloudDocs edge: container=clouddocs, zones=clouddocs (non CK zone name).
            Download.BackupDownloadService.ApplyEdgeHeaders(
                request,
                chunk.EdgeHeaders,
                cloudKitContainer: CloudKitContainerBinding.CloudDocs.ContainerId,
                cloudKitZone: mmcsZone);

            using var response = await _http.SendAsync(
                request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"edge GET HTTP {(int)response.StatusCode} chunk {chunkIndex}/{ordered.Count} " +
                    $"range={chunk.ByteRange?.Start}-{chunk.ByteRange?.End} " +
                    $"obj={chunk.EdgeHeaders?.ObjectId} " +
                    $"sig={(chunk.EdgeHeaders?.Signature?.Length > 0 ? "ok" : "MISSING")}");
            }

            await using var stream = await response.Content.ReadAsStreamAsync(ct);
            var buffer = new byte[81920];
            int read;
            while ((read = await stream.ReadAsync(buffer, ct)) > 0)
            {
                await output.WriteAsync(buffer.AsMemory(0, read), ct);
                downloaded += read;
            }
        }

        return downloaded;
    }

    private static byte[]? TryLoadRecordWindow(string fetchDir, DocumentCryptoEntry entry)
    {
        byte[]? best = null;
        var bestScore = -1;
        foreach (var syncPath in EnumerateSyncPayloadFiles(fetchDir))
        {
            if (!File.Exists(syncPath))
                continue;

            var payload = File.ReadAllBytes(syncPath);
            var text = Encoding.Latin1.GetString(payload);
            var matches = DocumentContentRegex.Matches(text);
            for (var i = 0; i < matches.Count; i++)
            {
                if (!matches[i].Value.Equals(entry.RecordName, StringComparison.Ordinal))
                    continue;
                var start = matches[i].Index;
                var end = Math.Min(payload.Length, start + 4500);
                if (end <= start)
                    continue;
                var window = payload.AsSpan(start, end - start).ToArray();
                var fc = IndexOf(window, "fileContent"u8.ToArray(), 0, window.Length);
                var score = (fc >= 0 ? 1000 : 0) + window.Length;
                if (Path.GetFileName(syncPath).StartsWith("batch", StringComparison.OrdinalIgnoreCase))
                    score += 80;
                if (score <= bestScore)
                    continue;
                bestScore = score;
                best = window;
            }
        }

        return best;
    }

    private static List<byte[]> CollectAssetWrapCandidates(DocumentCryptoEntry entry, string fetchDir)
    {
        var wraps = new List<byte[]>();
        void AddWrap(byte[]? w)
        {
            if (w is not { Length: 24 or 40 })
                return;
            var hex = Convert.ToHexString(w);
            if (wraps.All(existing => !Convert.ToHexString(existing).Equals(hex, StringComparison.OrdinalIgnoreCase)))
                wraps.Add(w);
        }

        if (entry.AssetProtectionInfoHex is { Length: > 0 })
            AddWrap(Convert.FromHexString(entry.AssetProtectionInfoHex));

        var recordWindow = TryLoadRecordWindow(fetchDir, entry);
        if (recordWindow is not { Length: > 0 })
            return wraps;

        if (TryParseMmcsAuthSignatures(entry.MmcsAuth, out var fileSig, out var refSig))
        {
            AddWrap(CloudKitAssetProto.TryGetWrapForSignature(recordWindow, fileSig!));
            AddWrap(CloudKitAssetProto.TryGetWrapForReferenceSignature(recordWindow, refSig!));
            AddWrap(CloudKitAssetProto.TryGetWrapForSignature(recordWindow, refSig!));
        }

        var sigs = new List<string>();
        if (entry.FileSignatureHex is { Length: > 0 })
            sigs.Add(entry.FileSignatureHex);
        if (entry.ReferenceSignatureHex is { Length: > 0 })
            sigs.Add(entry.ReferenceSignatureHex);
        AddWrap(ResolveAssetProtectionWrap(recordWindow, sigs));

        return wraps;
    }

    private static List<(byte[] Key, string Source)> BuildAssetMasterPool(
        DocumentCryptoEntry entry,
        IReadOnlyDictionary<string, byte[]> recordMasters,
        IReadOnlyDictionary<string, DocumentCryptoEntry> entriesByFileSig,
        ProtectionZoneKeys zoneKeys,
        IReadOnlyList<ProtectionZoneKeys> allZoneKeys,
        IReadOnlyList<(DocumentCryptoEntry Entry, ProtectionZoneKeys Zone)> recordZones,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        byte[]? recordWindow)
    {
        var masters = new List<(byte[] Key, string Source)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var zonePool = allZoneKeys
            .Concat(recordZones.Select(static r => r.Zone))
            .Prepend(zoneKeys)
            .DistinctBy(static z => Convert.ToHexString(z.MasterKey))
            .ToList();
        var keyPool = PcsProtectionZone.MergeKeys(seedKeys, zonePool);

        void Add(byte[] key, string source)
        {
            var id = Convert.ToHexString(key);
            if (!seen.Add(id))
                return;
            masters.Add((key, source));
        }

        if (recordMasters.TryGetValue(entry.RecordName, out var self))
            Add(self, "record-self");

        foreach (var (e, z) in recordZones.Where(r => r.Entry.RecordName == entry.RecordName))
            Add(z.MasterKey, $"record-pi-{ShortName(e.RecordName)}");

        if (entry.ReferenceSignatureHex is { Length: > 0 }
            && entriesByFileSig.TryGetValue(entry.ReferenceSignatureHex, out var canonical))
        {
            foreach (var (e, z) in recordZones.Where(r => r.Entry.RecordName == canonical.RecordName))
                Add(z.MasterKey, "reference-canonical");
            if (recordMasters.TryGetValue(canonical.RecordName, out var canonicalMaster))
                Add(canonicalMaster, "reference-canonical-master");
        }

        foreach (var (e, z) in recordZones)
        {
            Add(z.MasterKey, ShortName(e.RecordName));
            if (e.RecordProtectionInfoDerHex is not { Length: > 0 })
                continue;
            var der = Convert.FromHexString(e.RecordProtectionInfoDerHex);
            foreach (var z2 in PcsProtectionZone.TryUnwrapAll(der, keyPool))
                Add(z2.MasterKey, $"pi-all-{ShortName(e.RecordName)}");
        }

        Add(zoneKeys.MasterKey, "zone-primary");
        foreach (var z in allZoneKeys)
            Add(z.MasterKey, "zone-pool");

        if (recordWindow is { Length: > 64 })
        {
            foreach (var z in PcsProtectionZone.TryUnwrapAll(recordWindow, keyPool))
                Add(z.MasterKey, "record-window-pi");
            foreach (var z in PcsProtectionZone.TryUnwrapAllIterative(recordWindow, keyPool))
                Add(z.MasterKey, "record-window-iter");
        }

        return masters;
    }

    private static (byte[]? Kek, byte[]? WrapUsed, string? MasterSource) TryResolveAssetKek(
        DocumentCryptoEntry entry,
        IReadOnlyList<byte[]> wrapCandidates,
        IReadOnlyDictionary<string, byte[]> recordMasters,
        IReadOnlyDictionary<string, DocumentCryptoEntry> entriesByFileSig,
        ProtectionZoneKeys zoneKeys,
        IReadOnlyList<ProtectionZoneKeys> allZoneKeys,
        IReadOnlyList<(DocumentCryptoEntry Entry, ProtectionZoneKeys Zone)> recordZones,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        byte[]? recordWindow)
    {
        var masters = BuildAssetMasterPool(
            entry, recordMasters, entriesByFileSig, zoneKeys, allZoneKeys, recordZones, seedKeys, recordWindow);

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var wrap in wrapCandidates)
        {
            foreach (var (key, source) in masters)
            {
                var id = Convert.ToHexString(key);
                if (!seen.Add(id + "|" + Convert.ToHexString(wrap)))
                    continue;
                var kek = PcsProtectionZone.TryUnwrapWrappingKey(key, wrap);
                if (kek is not null)
                    return (kek, wrap, source);
            }
        }

        return (null, null, null);
    }

    private static async Task<bool> TryDecryptDownloadedAsync(
        DocumentCryptoEntry entry,
        string zone,
        string fetchDir,
        string ciphertextPath,
        byte[] authorizeGetBody,
        IReadOnlyList<SignedUrlChunk> edgeChunks,
        string plainDir,
        IReadOnlyDictionary<string, byte[]> recordMasters,
        IReadOnlyDictionary<string, string> plainBasenames,
        ProtectionZoneKeys zoneKeys,
        IReadOnlyList<ProtectionZoneKeys> allZoneKeys,
        IReadOnlyList<(DocumentCryptoEntry Entry, ProtectionZoneKeys Zone)> recordZones,
        IReadOnlyList<PcsCompactPrivateKey> seedKeys,
        IReadOnlyDictionary<string, DocumentCryptoEntry> entriesByFileSig,
        IReadOnlyDictionary<string, string> directoryRelativePaths,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var recordWindow = TryLoadRecordWindow(fetchDir, entry);
        var wrapCandidates = CollectAssetWrapCandidates(entry, fetchDir);
        if (wrapCandidates.Count == 0)
        {
            log?.Report($"  crypto {ShortName(entry.RecordName)}: skip decrypt — Asset.protectionInfo assente");
            return false;
        }

        var (kek, _, _) = TryResolveAssetKek(
            entry, wrapCandidates, recordMasters, entriesByFileSig,
            zoneKeys, allZoneKeys, recordZones, seedKeys, recordWindow);
        if (kek is null)
        {
            log?.Report($"  crypto {ShortName(entry.RecordName)}: Asset wrap unwrap FALLITO");
            return false;
        }

        var ciphertext = await File.ReadAllBytesAsync(ciphertextPath, ct);
        if (ciphertext.Length == 0)
            return false;

        var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
        if (plan.TotalCryptoChunks == 0)
        {
            // Fallback legacy: 1 chiave per edge path.
            if (edgeChunks.Count == 0 || edgeChunks.All(c => c.ChunkEncryptionKey is not { Length: > 0 }))
            {
                log?.Report($"  crypto {ShortName(entry.RecordName)}: nessuna ChunkInfo/encryption key");
                return false;
            }

            var legacyContainers = edgeChunks
                .Select(c => (IReadOnlyList<AuthorizeGetCryptoChunk>)new[]
                {
                    new AuthorizeGetCryptoChunk
                    {
                        EncryptionKey = c.ChunkEncryptionKey!,
                        Length = c.ByteRange is { } r ? (int)(r.End - r.Start + 1) : 0
                    }
                })
                .ToList();
            var legacyRefs = Enumerable.Range(0, legacyContainers.Count)
                .Select(i => new AuthorizeGetChunkRef { ContainerIndex = i, ChunkIndex = 0 })
                .ToList();
            plan = new AuthorizeGetDecryptPlan
            {
                Containers = legacyContainers,
                References = legacyRefs
            };
        }

        byte[] plain;
        try
        {
            plain = MmcsChunkCrypto.DecryptAndAssemble(ciphertext, plan, kek);
        }
        catch (Exception ex)
        {
            log?.Report($"  crypto {ShortName(entry.RecordName)}: decrypt/assemble FALLITO — {ex.Message}");
            return false;
        }

        string? bn = null;
        var outName = plainBasenames.TryGetValue(entry.RecordName, out bn) && !string.IsNullOrWhiteSpace(bn)
            ? ResolvePlaintextFileName(bn!, entry.ContentKind, plain)
            : ResolvePlaintextFileName(Sanitize(entry.RecordName), entry.ContentKind, plain);

        var relDir = ResolveFileRelativeDirectoryPath(entry.ParentDirectory, directoryRelativePaths);
        var zoneFolder = SanitizeZoneFolderName(zone);
        var targetDir = string.IsNullOrWhiteSpace(relDir)
            ? Path.Combine(plainDir, zoneFolder)
            : Path.Combine(plainDir, zoneFolder, relDir);
        Directory.CreateDirectory(targetDir);

        var outPath = Path.Combine(targetDir, outName);
        // Collisioni basename (es. tante "Изображение PNG"): suffisso UUID corto, non documentContent_….
        if (File.Exists(outPath))
            outPath = Path.Combine(targetDir, MakeCollisionFileName(outName, entry.RecordName));

        // #region agent log
        if (outName.Contains("documentContent_", StringComparison.Ordinal)
            || (relDir is not null && relDir.Equals("root", StringComparison.OrdinalIgnoreCase))
            || !string.Equals(Path.GetFileName(outPath), outName, StringComparison.Ordinal))
        {
            AgentLogCrypto(
                "H-DRV1",
                "CloudDocsDocumentCrypto.TryDecryptDownloadedAsync",
                "plaintext_path_resolve",
                new
                {
                    record = ShortName(entry.RecordName),
                    parent = entry.ParentDirectory,
                    relDir,
                    basename = bn,
                    outName,
                    finalName = Path.GetFileName(outPath),
                    collision = !string.Equals(Path.GetFileName(outPath), outName, StringComparison.Ordinal),
                });
        }
        // #endregion

        await File.WriteAllBytesAsync(outPath, plain, ct);
        TryApplyCloudDocsFileTimes(outPath, entry, log);

        var kind = entry.ContentKind ?? "";
        var kindHint = kind.Equals("tar", StringComparison.OrdinalIgnoreCase) &&
                       plain.Length >= 262 &&
                       plain.AsSpan(257, 5).SequenceEqual("ustar"u8)
            ? "ustar-ok"
            : kind;
        var tsHint = entry.CreatedUtc is not null || entry.ModifiedUtc is not null
            ? $" ts c={FormatCloudDocsTimestamp(entry.CreatedUtc)} m={FormatCloudDocsTimestamp(entry.ModifiedUtc)}"
            : "";
        var pathHint = string.IsNullOrWhiteSpace(relDir) ? zoneFolder : $"{zoneFolder}/{relDir}";
        log?.Report(
            $"  crypto {ShortName(entry.RecordName)}: plaintext {plain.Length:N0} B " +
            $"({plan.Containers.Count} edge / {plan.TotalCryptoChunks} CFB, refs={plan.References.Count}) " +
            $"→ {pathHint}/{Path.GetFileName(outPath)} [{kindHint}]{tsHint}");
        return true;
    }

    private async Task<byte[]?> AuthorizeGetAsync(
        ICloudSession session,
        string contentHost,
        string mmcsAuth,
        string mmcsZone,
        CancellationToken ct)
    {
        var url = $"{contentHost.TrimEnd('/')}/{session.Dsid}/authorizeGet";
        var body = UbChunkBuilder.BuildAuthorizeGetRequest(mmcsAuth);

        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType =
            new MediaTypeHeaderValue("application/vnd.com.apple.me.ubchunk+protobuf");
        request.Headers.TryAddWithoutValidation("Accept", "application/vnd.com.apple.me.ubchunk+protobuf");
        request.Headers.TryAddWithoutValidation("x-apple-mme-dsid", session.Dsid);
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-proto-version", "4.0");
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-dataclass", "com.apple.Dataclass.CloudKit");
        request.Headers.TryAddWithoutValidation("X-CloudKit-Container", CloudKitContainerBinding.CloudDocs.ContainerId);
        request.Headers.TryAddWithoutValidation("X-CloudKit-Zones", mmcsZone);
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-auth", mmcsAuth);
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.MmcsUserAgent);
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", AppleClientInfo.CloudKitDaemonClientInfo);

        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            var err = await response.Content.ReadAsStringAsync(ct);
            throw new InvalidOperationException(
                $"HTTP {(int)response.StatusCode} @ {contentHost}: {Trim(err)}");
        }

        return await response.Content.ReadAsByteArrayAsync(ct);
    }

    private static bool ContainsAscii(byte[] data, string ascii)
    {
        var needle = Encoding.ASCII.GetBytes(ascii);
        return IndexOf(data, needle, 0, data.Length) >= 0;
    }

    private static int IndexOf(byte[] hay, byte[] needle, int start, int end)
    {
        end = Math.Min(end, hay.Length);
        for (var i = start; i <= end - needle.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (hay[i + j] != needle[j])
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

    private static bool IsBase64Url(byte b) =>
        b is (>= (byte)'A' and <= (byte)'Z')
            or (>= (byte)'a' and <= (byte)'z')
            or (>= (byte)'0' and <= (byte)'9')
            or (byte)'-' or (byte)'_';

    private static string Sanitize(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name.Length > 100 ? name[..100] : name;
    }

    private static string SanitizeFileName(string name)
    {
        name = name.Trim().Replace('\\', '_').Replace('/', '_');
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name.Length > 180 ? name[..180] : name;
    }

    /// <summary>
    /// Collisione basename: <c>name.ext</c> → <c>name_&lt;uuid8&gt;.ext</c> (non documentContent_…).
    /// </summary>
    private static string MakeCollisionFileName(string outName, string recordName)
    {
        var stem = Path.GetFileNameWithoutExtension(outName);
        var ext = Path.GetExtension(outName);
        var id = ShortName(recordName);
        if (id.Length > 8)
            id = id[..8];
        return SanitizeFileName($"{stem}_{id}{ext}");
    }

    /// <summary>
    /// Nome file in uscita: basename decifrato + estensione da marker record o magic bytes.
    /// Non aggiunge mai .tar di default — solo se il record lo dichiara esplicitamente.
    /// </summary>
    public static string ResolvePlaintextFileName(
        string basename,
        string? contentKind,
        ReadOnlySpan<byte> plain = default)
    {
        var name = SanitizeFileName(basename);
        var kind = NormalizeContentKind(contentKind ?? "");

        // enc:2 = blob ancora cifrato a livello app (es. Sticker.sqlite → Sticker.sqlite.enc).
        if (kind.Equals("enc", StringComparison.OrdinalIgnoreCase)
            && !name.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
        {
            var encName = name + ".enc";
            return encName;
        }

        if (Path.HasExtension(name))
            return name;

        var ext = ContentKindToExtension(contentKind);
        if (ext is null && !plain.IsEmpty)
            ext = SniffExtension(plain);
        if (ext is null)
            return name;

        var resolved = name + ext;
        return resolved;
    }


    private static string? ContentKindToExtension(string? contentKind)
    {
        var kind = NormalizeContentKind(contentKind ?? "");
        if (kind.Length == 0)
            return null;

        return kind switch
        {
            "pdf" => ".pdf",
            "plist" => ".plist",
            "tar" => ".tar",
            "enc" => ".enc",
            "jpeg" or "jpg" or "jpeg2000" => ".jpg",
            "png" => ".png",
            "gif" => ".gif",
            "heic" or "heif" => ".heic",
            "movie" or "quicktime" or "mov" => ".mov",
            "mpeg4" or "mp4" => ".mp4",
            "zip" => ".zip",
            "gzip" => ".gz",
            "text" or "plain-text" or "txt" => ".txt",
            "html" => ".html",
            "xml" => ".xml",
            "json" => ".json",
            "sqlite" => ".sqlite",
            "doc" or "docx" or "word" => ".docx",
            "xls" or "xlsx" or "excel" => ".xlsx",
            "ppt" or "pptx" => ".pptx",
            "pkpass" => ".pkpass",
            _ => kind.StartsWith('.') ? kind : "." + kind,
        };
    }

    private static string? SniffExtension(ReadOnlySpan<byte> plain)
    {
        if (plain.Length >= 5 && plain.StartsWith("%PDF-"u8))
            return ".pdf";
        if (plain.Length >= 8 && plain.StartsWith("\x89PNG\r\n\x1a\n"u8))
            return ".png";
        if (plain.Length >= 3 && plain[0] == 0xFF && plain[1] == 0xD8 && plain[2] == 0xFF)
            return ".jpg";
        if (plain.Length >= 4 && plain.StartsWith("PK\x03\x04"u8))
            return ".zip";
        if (plain.Length >= 2 && plain[0] == 0x1F && plain[1] == 0x8B)
            return ".gz";
        if (plain.Length >= 262
            && plain[257..].StartsWith("ustar"u8))
            return ".tar";
        if (plain.Length >= 6
            && (plain.StartsWith("<?xml"u8) || plain.StartsWith("<plist"u8)))
            return ".plist";
        if (plain.Length >= 4 && plain.StartsWith("bplist"u8))
            return ".plist";
        return null;
    }

    private static string ShortName(string record) =>
        record.StartsWith("documentContent/", StringComparison.Ordinal)
            ? record["documentContent/".Length..]
            : record;

    private static string Trim(string s) =>
        s.Length <= 180 ? s.Trim() : s.Trim()[..180] + "…";

    // #region agent log
    private static void AgentDirectoryPathDebugLog(
        string hypothesisId,
        string location,
        string message,
        object data,
        string runId = "wa-docs-pre")
    {
        try
        {
            var logPath =
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log");
            var payload = new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = runId,
                ["hypothesisId"] = hypothesisId,
                ["location"] = location,
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            };
            File.AppendAllText(logPath, JsonSerializer.Serialize(payload) + Environment.NewLine);
        }
        catch
        {
            // ignore debug log failures
        }
    }
    // #endregion
}

public sealed class DocumentCryptoEntry
{
    public string RecordName { get; init; } = "";
    public string Source { get; init; } = "";
    public long? SizeBytes { get; init; }
    public string? ContentBaseUrl { get; init; }
    public string? DownloadTokenPrefix { get; init; }
    public string? FileSignatureHex { get; init; }
    public string? ReferenceSignatureHex { get; init; }
    public string? EncryptedBasenameHex { get; init; }
    public int? EncryptedBasenameBytes { get; init; }
    public string? MmcsAuth { get; init; }
    /// <summary>
    ///  un document/package può avere più CAog (chunk MMCS). Ogni auth richiede
    /// un authorizeGet; i range vanno uniti fino a coprire <see cref="SizeBytes"/>.
    /// </summary>
    public IReadOnlyList<string>? AdditionalMmcsAuths { get; init; }
    public bool HasFileContent { get; init; }
    public string? RecordProtectionInfoDerHex { get; init; }
    public int? RecordProtectionInfoBytes { get; init; }
    /// <summary>Asset.protectionInfo.protectionInfo — 24 B AES-KW (KEK wrap).</summary>
    public string? AssetProtectionInfoHex { get; init; }
    /// <summary>Marker CloudDocs extension field, es. <c>pdf:2</c>, <c>enc:2</c>.</summary>
    public string? ContentKind { get; init; }
    /// <summary><c>documentContent</c> → campo <c>mtime</c> (unix UTC).</summary>
    public DateTimeOffset? ModifiedUtc { get; init; }
    /// <summary><c>documentStructure</c> → campo <c>birthtime</c> (unix UTC).</summary>
    public DateTimeOffset? CreatedUtc { get; init; }
    /// <summary><c>documentContent</c> → <c>lastEditorName</c> JSON.</summary>
    public string? LastEditorName { get; init; }
    /// <summary><c>documentStructure</c> → <c>parent</c> directory record.</summary>
    public string? ParentDirectory { get; init; }
}

public sealed class DirectoryCryptoEntry
{
    public string RecordName { get; init; } = "";
    public string Source { get; init; } = "";
    /// <summary>Offset regex nel payload sync (tie-break merge span).</summary>
    public int PayloadOffset { get; init; }
    public string? ParentDirectory { get; init; }
    public string? EncryptedBasenameHex { get; init; }
    public int? EncryptedBasenameBytes { get; init; }
    public string? RecordProtectionInfoDerHex { get; init; }
    public int? RecordProtectionInfoBytes { get; init; }
}
