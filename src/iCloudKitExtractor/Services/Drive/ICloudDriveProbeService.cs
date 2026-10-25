using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.WhatsApp;

namespace iCloudKitExtractor.Services.Drive;

/// <summary>
/// iCloud Drive / iCloud Files (<c>capture_icloud_drive_20260905_072447</c>):
/// ckAppInit → zone/retrieve → record/sync (CKDFetchRecordChangesOperation, types=1,
/// requestedFields) → FetchRecords (content + structure + directory wire) →
/// parent-chase path tree → authorizeGet/edge via <see cref="CloudDocsDocumentCrypto"/>.
/// Modalità Files: tutte le zone (CloudDocs + WhatsApp + app), come output
/// <c>ICLOUD FILES</c>.
/// </summary>
public sealed class ICloudDriveProbeService
{
    private static readonly Regex DocumentRecordRegex = new(
        @"(?:documentContent|documentStructure|\.directory)/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|directory/root",
        RegexOptions.Compiled);

    private const int FetchRecordsBatchSize = 8;
    private const int MaxSyncPages = 48;
    private const int MaxParentChaseRounds = 8;

    // #region agent log
    private static readonly string AgentLogPath = Path.GetFullPath(Path.Combine(
        AppContext.BaseDirectory, "..", "..", "..", "..", "..", "..",
        "iCloudDownloader", "debug-7dabb5.log"));

    private static void AgentLog(string hypothesisId, string location, string message, object data)
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
                runId = "icloud-files-impl",
            });
            var paths = new[]
            {
                AgentLogPath,
                Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                    "PROGRAMMAZIONE", "Projects", "iCloudDownloader", "debug-7dabb5.log"),
            };
            foreach (var p in paths.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(p)!);
                    File.AppendAllText(p, payload + "\n");
                }
                catch { /* ignore */ }
            }
        }
        catch { /* ignore */ }
    }
    // #endregion

    private readonly HttpClient _http;
    private readonly ICloudBackupOrchestrator _orchestrator;
    private readonly CloudKitGatewayClient _gateway;

    public ICloudDriveProbeService(HttpClient http, ICloudBackupOrchestrator orchestrator)
    {
        _http = http;
        _orchestrator = orchestrator;
        _gateway = new CloudKitGatewayClient(http);
        _gateway.SetUnauthorizedRefresh(async (session, ct) =>
        {
            await _orchestrator.RefreshAnisetteOnlyAsync(session, log: null, ct)
                .ConfigureAwait(false);
            _gateway.ClearUnauthorized();
        });
    }

    public Task<ICloudDriveProbeResult> ProbeAsync(
        ICloudSession session,
        string outputDirectory,
        bool includeAppZones,
        IProgress<string>? log = null,
        IProgress<ICloudDriveProgress>? progress = null,
        string? pcsKeysDirectory = null,
        CancellationToken ct = default) =>
        ProbeAsync(
            session,
            outputDirectory,
            ICloudDriveProbeOptions.Drive(includeAppZones),
            log,
            progress,
            pcsKeysDirectory,
            ct);

    public async Task<ICloudDriveProbeResult> ProbeAsync(
        ICloudSession session,
        string outputDirectory,
        ICloudDriveProbeOptions options,
        IProgress<string>? log = null,
        IProgress<ICloudDriveProgress>? progress = null,
        string? pcsKeysDirectory = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var prefix = string.IsNullOrWhiteSpace(options.OutputFolderPrefix)
            ? "icloud_drive"
            : options.OutputFolderPrefix.Trim();
        var outDir = Path.Combine(outputDirectory, $"{prefix}_{stamp}");
        Directory.CreateDirectory(outDir);

        var pcsDir = pcsKeysDirectory ?? session.PcsKeysDirectory ?? outputDirectory;
        var modeLabel = options.Mode == ICloudDriveProbeMode.Files ? "iCloud Files" : "iCloud Drive";
        log?.Report($"{modeLabel} probe → {outDir}");
        log?.Report(
            "Flusso 20260905: ckAppInit → zone/retrieve → record/sync " +
            "(requestedFields) → FetchRecords → directory parent chase → crypto/MMCS");

        var binding = CloudKitContainerBinding.CloudDocs;
        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;
        var docsDir = Path.Combine(outDir, "clouddocs_ck");
        Directory.CreateDirectory(docsDir);

        var zonesProcessed = 0;
        var recordsFetched = 0;
        var zoneSummaries = new List<object>();

        try
        {
            progress?.Report(new ICloudDriveProgress("anisette", 3, "refresh…"));
            await _orchestrator.RefreshAnisetteOnlyAsync(session, log, ct).ConfigureAwait(false);
            _gateway.ClearUnauthorized();

            progress?.Report(new ICloudDriveProgress("ckAppInit", 5, "com.apple.clouddocs…"));
            log?.Report($"CloudDocs CK: container={binding.ContainerId}");
            await EnsureCloudDocsCkAppInitAsync(session, binding.ContainerId, log, ct);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
                || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            {
                log?.Report("  ckAppInit CloudDocs incompleto — abort.");
                return new ICloudDriveProbeResult(outDir, false, 0, 0, 0, "ckAppInit incompleto");
            }

            log?.Report($"  ckUserId={session.CloudKitUserId}");

            progress?.Report(new ICloudDriveProgress("zone/retrieve", 12, "default…"));
            byte[]? defaultZoneRetrieve = null;
            var zones = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "com.apple.CloudDocs.container-metadata",
                "com.apple.CloudDocs",
            };

            log?.Report("  zone/retrieve → default…");
            try
            {
                var body = CloudKitDelimitedRequest.BuildZoneRetrieve(
                    session.CloudKitUserId, ["default"], container: binding);
                defaultZoneRetrieve = await _gateway.ZoneRetrieveAsync(
                    session, body, ct, container: binding);
                await File.WriteAllBytesAsync(
                    Path.Combine(docsDir, "zones_default_retrieve.bin"), defaultZoneRetrieve, ct);
                var dStrings = CloudKitResponseParser.ExtractDiagnosticStrings(defaultZoneRetrieve);
                await File.WriteAllLinesAsync(
                    Path.Combine(docsDir, "zones_default_retrieve_strings.txt"), dStrings, ct);
                log?.Report($"  zone/retrieve default → {defaultZoneRetrieve.Length:N0} B");

                foreach (var s in dStrings)
                {
                    var n = WhatsAppCloudKitProbeService.NormalizeZoneName(s);
                    if (ShouldIncludeZone(n, options))
                        zones.Add(n);
                }

                foreach (var s in WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(dStrings))
                {
                    if (ShouldIncludeZone(s, options))
                        zones.Add(s);
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  zone/retrieve default: {ex.Message}");
            }

            var ordered = OrderDriveZones(zones, options);
            log?.Report($"  zone da processare ({ordered.Count}): {string.Join(", ", ordered)}");
            // #region agent log
            AgentLog("H-IF1", "ICloudDriveProbeService.cs:zones", "zones_selected", new
            {
                mode = options.Mode.ToString(),
                includeWa = options.IncludeWhatsAppZones,
                includeApps = options.IncludeAppZones,
                count = ordered.Count,
                zones = ordered.Take(40).ToList(),
                whatsapp = ordered.Count(IsWhatsAppZone),
                apps = ordered.Count(IsAppDocumentZone),
            });
            // #endregion

            var zoneIndex = 0;
            foreach (var zone in ordered)
            {
                ct.ThrowIfCancellationRequested();
                zoneIndex++;
                var zonePct = 15 + (int)(70.0 * zoneIndex / Math.Max(1, ordered.Count));
                progress?.Report(new ICloudDriveProgress("zone", zonePct, zone));

                log?.Report($"  zone/retrieve → {zone}");
                byte[] zonePayload;
                try
                {
                    var zBody = CloudKitDelimitedRequest.BuildZoneRetrieve(
                        session.CloudKitUserId, [zone], container: binding);
                    zonePayload = await _gateway.ZoneRetrieveAsync(
                        session, zBody, ct, container: binding);
                    var tag = Sanitize(zone);
                    await File.WriteAllBytesAsync(
                        Path.Combine(docsDir, $"zones_{tag}.bin"), zonePayload, ct);
                    log?.Report($"    {zonePayload.Length:N0} B");
                }
                catch (Exception ex)
                {
                    log?.Report($"    ERRORE zone/retrieve: {ex.Message}");
                    continue;
                }

                if (CloudKitResponseParser.IsCloudKitErrorPayload(zonePayload, out var zerr))
                {
                    log?.Report($"    skip: {zerr}");
                    continue;
                }

                var zonePayloadLive = SelectRichestZonePayload(defaultZoneRetrieve, zonePayload);
                var allRecordNames = new HashSet<string>(StringComparer.Ordinal);
                var syncTotalBytes = 0L;

                log?.Report($"  record/sync → {zone} (CKDFetchRecordChangesOperation)…");
                byte[]? token = null;
                var pages = 0;
                for (var page = 1; page <= MaxSyncPages; page++)
                {
                    ct.ThrowIfCancellationRequested();
                    try
                    {
                        var changesBody = CloudKitDelimitedRequest.BuildCloudDocsRecordRetrieveChanges(
                            session.CloudKitUserId, zone, token, binding);
                        var changesPayload = await _gateway.RecordChangesAsync(
                            session, changesBody, ct, binding);
                        pages++;
                        syncTotalBytes += changesPayload.Length;
                        var tag = Sanitize(zone);
                        await File.WriteAllBytesAsync(
                            Path.Combine(docsDir, $"record_sync_{tag}_p{page}.bin"),
                            changesPayload, ct);
                        // Compat crypto: anche record_changes_*.bin
                        if (page == 1)
                        {
                            await File.WriteAllBytesAsync(
                                Path.Combine(docsDir, $"record_changes_{tag}.bin"),
                                changesPayload, ct);
                        }

                        var changeStrings = CloudKitResponseParser.ExtractDiagnosticStrings(changesPayload);
                        foreach (var name in CollectDocumentRecordNames(changesPayload, changeStrings))
                            allRecordNames.Add(name);

                        var cont = CloudKitResponseParser.TryExtractRecordSyncContinuation(changesPayload);
                        var pageNames = CollectDocumentRecordNames(changesPayload, changeStrings);
                        var pageRecordCount = pageNames.Count;
                        var contentN = allRecordNames.Count(static n =>
                            n.StartsWith("documentContent/", StringComparison.Ordinal));
                        var stringMore = changeStrings.Any(static s =>
                            s.Contains("moreComing", StringComparison.OrdinalIgnoreCase));
                        var sentToken = token ?? ReadOnlySpan<byte>.Empty;
                        var hasToken = cont.SyncContinuationToken is { Length: > 0 };
                        var shouldContinue = CloudKitResponseParser.ShouldContinueRecordSyncPagination(
                            cont, sentToken, pageRecordCount, stringMore);
                        var tokenFollowUp = shouldContinue && pageRecordCount == 0 && hasToken;
                        log?.Report(
                            $"    p{page} {changesPayload.Length:N0} B" +
                            $" content={contentN} total={allRecordNames.Count} pageRec={pageRecordCount}" +
                            $" more={cont.MoreComing}" +
                            (hasToken ? $" token={cont.SyncContinuationToken!.Length}B" : "") +
                            (tokenFollowUp ? " token→next" : ""));

                        if (!shouldContinue)
                            break;

                        if (token is not null
                            && token.AsSpan().SequenceEqual(cont.SyncContinuationToken!))
                        {
                            log?.Report("    syncToken invariato — stop");
                            break;
                        }

                        token = cont.SyncContinuationToken;
                        await Task.Delay(100, ct);
                    }
                    catch (Exception ex)
                    {
                        log?.Report($"    record/sync p{page}: {ex.Message}");
                        break;
                    }
                }

                ExpandPairedContentFromStructures(allRecordNames, log);
                var fetchRecords = OrderRecordsForFetch(allRecordNames);

                log?.Report(
                    $"  record/sync {zone}: {pages} pagina/e, {syncTotalBytes:N0} B, " +
                    $"content={fetchRecords.Count(static n => n.StartsWith("documentContent/", StringComparison.Ordinal))} " +
                    $"structure={fetchRecords.Count(static n => n.StartsWith("documentStructure/", StringComparison.Ordinal))} " +
                    $"directory={fetchRecords.Count(static n => n.StartsWith("directory/", StringComparison.Ordinal))}");
                // #region agent log
                AgentLog("H-IF2", "ICloudDriveProbeService.cs:sync", "zone_sync_catalog", new
                {
                    zone,
                    pages,
                    syncTotalBytes,
                    content = fetchRecords.Count(static n => n.StartsWith("documentContent/", StringComparison.Ordinal)),
                    structure = fetchRecords.Count(static n => n.StartsWith("documentStructure/", StringComparison.Ordinal)),
                    directory = fetchRecords.Count(static n => n.StartsWith("directory/", StringComparison.Ordinal)),
                    totalFetch = fetchRecords.Count,
                });
                // #endregion

                if (IsMetadataCatalogZone(zone))
                {
                    await File.WriteAllTextAsync(
                        Path.Combine(docsDir, $"catalog_{Sanitize(zone)}.json"),
                        JsonSerializer.Serialize(new
                        {
                            zone,
                            pages,
                            syncTotalBytes,
                            note = "catalog MIME/BRContainer — no documentContent",
                        }),
                        ct);
                    if (pages > 0)
                        zonesProcessed++;
                    zoneSummaries.Add(new { zone, pages, syncTotalBytes, content = 0, kind = "metadata" });
                    continue;
                }

                if (fetchRecords.Count == 0 && pages == 0)
                    continue;

                zonesProcessed++;
                if (allRecordNames.Count > 0)
                    WriteDocumentIndex(docsDir, zone, allRecordNames.ToList(), log);

                var fetched = await FetchDocumentRecordsAsync(
                    session, binding, docsDir, zone, fetchRecords,
                    zonePayloadLive, pcsDir, options.RebuildDirectoryPaths, log, ct);
                recordsFetched += fetched;
                zoneSummaries.Add(new
                {
                    zone,
                    pages,
                    syncTotalBytes,
                    content = fetched,
                    kind = "documents",
                });
            }

            await WriteFilesManifestAsync(outDir, docsDir, zoneSummaries, log, ct);

            progress?.Report(new ICloudDriveProgress("done", 100, "completato"));
            log?.Report(
                $"{modeLabel} finito: zone={zonesProcessed} contentFetch={recordsFetched} → {outDir}");
            return new ICloudDriveProbeResult(
                outDir, true, zonesProcessed, recordsFetched, 0, null);
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    private async Task<int> FetchDocumentRecordsAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string docsDir,
        string zone,
        IReadOnlyList<string> fetchRecords,
        byte[] zonePayloadLive,
        string pcsKeysDirectory,
        bool rebuildDirectoryPaths,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var fetchDir = Path.Combine(docsDir, $"fetch_{Sanitize(zone)}");
        Directory.CreateDirectory(fetchDir);

        var zoneTag = Sanitize(zone);
        foreach (var syncPath in Directory.GetFiles(docsDir, $"record_sync_{zoneTag}_*.bin"))
        {
            var dest = Path.Combine(fetchDir, Path.GetFileName(syncPath));
            if (!File.Exists(dest))
                File.Copy(syncPath, dest);
        }

        foreach (var syncPath in Directory.GetFiles(docsDir, $"record_changes_{zoneTag}.bin"))
        {
            var dest = Path.Combine(fetchDir, Path.GetFileName(syncPath));
            if (!File.Exists(dest))
                File.Copy(syncPath, dest);
        }

        var contentCount = fetchRecords.Count(static n =>
            n.StartsWith("documentContent/", StringComparison.Ordinal));

        if (fetchRecords.Count > 0)
        {
            log?.Report(
                $"  FetchRecords → {zone} ({fetchRecords.Count} record, " +
                $"content={contentCount}, batch={FetchRecordsBatchSize})…");
            for (var offset = 0; offset < fetchRecords.Count; offset += FetchRecordsBatchSize)
            {
                ct.ThrowIfCancellationRequested();
                var batch = fetchRecords.Skip(offset).Take(FetchRecordsBatchSize).ToList();
                var batchIndex = offset / FetchRecordsBatchSize + 1;
                var batchTag = $"batch{batchIndex:00}";

                try
                {
                    var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
                        session.CloudKitUserId, zone, batch, container: binding);
                    var payload = await _gateway.RecordRetrieveAsync(
                        session, body, ct, container: binding);
                    await File.WriteAllBytesAsync(
                        Path.Combine(fetchDir, $"{batchTag}.bin"), payload, ct);
                    await File.WriteAllLinesAsync(
                        Path.Combine(fetchDir, $"{batchTag}_names.txt"), batch, ct);

                    var note = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err)
                        ? err
                        : CloudKitResponseParser.DescribeCompactPayload(payload);
                    log?.Report(
                        $"    {batchTag}: {batch.Count} record → {payload.Length:N0} B" +
                        (note is null ? "" : $" — {note}"));
                }
                catch (Exception ex)
                {
                    log?.Report($"    {batchTag}: ERRORE {ex.Message}");
                }
            }
        }
        else
        {
            log?.Report($"  FetchRecords skip — MMCS da record/sync in {fetchDir}");
        }

        if (rebuildDirectoryPaths)
        {
            await ChaseDirectoryParentChainAsync(
                session, binding, fetchDir, zone, log, ct);
        }

        try
        {
            var crypto = new CloudDocsDocumentCrypto(_http);
            await crypto.ProcessAsync(
                session, fetchDir, zone, zonePayloadLive, log,
                pcsKeysDirectory: pcsKeysDirectory, ct: ct);
            // #region agent log
            var plainDir = Path.Combine(fetchDir, "crypto", "plaintext");
            var plainCount = Directory.Exists(plainDir)
                ? Directory.EnumerateFiles(plainDir, "*", SearchOption.AllDirectories).Count()
                : 0;
            AgentLog("H-IF4", "ICloudDriveProbeService.cs:crypto", "crypto_plaintext", new
            {
                zone,
                plainCount,
                fetchDir = Path.GetFileName(fetchDir),
            });
            // #endregion
        }
        catch (Exception ex)
        {
            log?.Report($"  crypto/download: {ex.Message}");
            // #region agent log
            AgentLog("H-IF4", "ICloudDriveProbeService.cs:crypto", "crypto_error", new
            {
                zone,
                error = ex.Message,
            });
            // #endregion
        }

        return contentCount;
    }

    /// <summary>
    /// Runtime WA/Drive: FetchRecords <c>.directory/UUID</c> → Record not found;
    /// forma wire <c>directory/UUID</c> restituisce parent + encryptedBasename.
    /// </summary>
    private async Task ChaseDirectoryParentChainAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string fetchDir,
        string zone,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var resolvedOrAttempted = new HashSet<string>(StringComparer.Ordinal);
        var totalFetched = 0;

        for (var round = 1; round <= MaxParentChaseRounds; round++)
        {
            ct.ThrowIfCancellationRequested();
            var known = CollectParsedDirectories(fetchDir);
            foreach (var name in known.Keys)
                resolvedOrAttempted.Add(name);

            var missing = new HashSet<string>(StringComparer.Ordinal);
            foreach (var d in known.Values)
            {
                if (string.IsNullOrWhiteSpace(d.ParentDirectory))
                    continue;
                var parent = CloudDocsDocumentCrypto.NormalizeDirectoryRecordName(d.ParentDirectory);
                if (parent.Equals("directory/root", StringComparison.Ordinal))
                    continue;
                if (!parent.StartsWith(".directory/", StringComparison.Ordinal))
                    continue;
                if (known.ContainsKey(parent) || resolvedOrAttempted.Contains(parent))
                    continue;
                missing.Add(parent);
            }

            if (missing.Count == 0)
            {
                if (round > 1 || totalFetched > 0)
                    log?.Report(
                        $"  directory parent chase: completo " +
                        $"(round={round - 1} fetched={totalFetched} known={known.Count})");
                // #region agent log
                AgentLog("H-IF3", "ICloudDriveProbeService.cs:chase", "parent_chase_done", new
                {
                    zone,
                    round,
                    totalFetched,
                    known = known.Count,
                });
                // #endregion
                return;
            }

            var batch = missing.OrderBy(static s => s, StringComparer.Ordinal).ToList();
            var wireNames = batch.Select(ToDirectoryFetchRecordName).ToList();
            log?.Report(
                $"  directory parent chase round {round}: fetch {batch.Count} " +
                $"→ {string.Join(", ", batch.Select(ShortDir).Take(6))}" +
                (batch.Count > 6 ? "…" : ""));

            for (var offset = 0; offset < batch.Count; offset += FetchRecordsBatchSize)
            {
                ct.ThrowIfCancellationRequested();
                var sliceCanonical = batch.Skip(offset).Take(FetchRecordsBatchSize).ToList();
                var sliceWire = wireNames.Skip(offset).Take(FetchRecordsBatchSize).ToList();
                var batchTag = $"dirparent_r{round}_{offset / FetchRecordsBatchSize + 1:00}";
                try
                {
                    var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
                        session.CloudKitUserId, zone, sliceWire, container: binding);
                    var payload = await _gateway.RecordRetrieveAsync(
                        session, body, ct, container: binding);
                    await File.WriteAllBytesAsync(
                        Path.Combine(fetchDir, $"{batchTag}.bin"), payload, ct);
                    await File.WriteAllLinesAsync(
                        Path.Combine(fetchDir, $"{batchTag}_names.txt"), sliceWire, ct);
                    var parsed = CloudDocsDocumentCrypto.ParseDirectoryRecords(payload, batchTag + ".bin");
                    totalFetched += sliceWire.Count;
                    foreach (var n in sliceCanonical)
                        resolvedOrAttempted.Add(n);
                    log?.Report(
                        $"    {batchTag}: wire={sliceWire.Count} → {payload.Length} B; parsedDirs={parsed.Count}");
                }
                catch (Exception ex)
                {
                    foreach (var n in sliceCanonical)
                        resolvedOrAttempted.Add(n);
                    log?.Report($"    {batchTag}: ERRORE {ex.Message}");
                }
            }
        }
    }

    private static Dictionary<string, DirectoryCryptoEntry> CollectParsedDirectories(string fetchDir)
    {
        var map = new Dictionary<string, DirectoryCryptoEntry>(StringComparer.Ordinal);
        void Absorb(string path)
        {
            if (!File.Exists(path))
                return;
            byte[] payload;
            try
            {
                payload = File.ReadAllBytes(path);
            }
            catch
            {
                return;
            }

            foreach (var d in CloudDocsDocumentCrypto.ParseDirectoryRecords(payload, Path.GetFileName(path)))
            {
                var key = CloudDocsDocumentCrypto.NormalizeDirectoryRecordName(d.RecordName);
                if (!map.TryGetValue(key, out var prev)
                    || (d.EncryptedBasenameHex?.Length ?? 0) > (prev.EncryptedBasenameHex?.Length ?? 0)
                    || (string.IsNullOrEmpty(prev.ParentDirectory) && !string.IsNullOrEmpty(d.ParentDirectory)))
                {
                    map[key] = d;
                }
            }
        }

        foreach (var pattern in new[]
                 {
                     "batch*.bin", "dirparent_*.bin", "record_sync_*.bin", "record_changes_*.bin",
                 })
        {
            foreach (var path in Directory.EnumerateFiles(fetchDir, pattern))
                Absorb(path);
        }

        var docsDir = Directory.GetParent(fetchDir)?.FullName;
        var zoneTag = Path.GetFileName(fetchDir);
        if (zoneTag.StartsWith("fetch_", StringComparison.OrdinalIgnoreCase))
            zoneTag = zoneTag["fetch_".Length..];
        else
            zoneTag = "";
        if (!string.IsNullOrEmpty(docsDir))
        {
            foreach (var pattern in new[] { "record_sync_*.bin", "record_changes_*.bin" })
            {
                foreach (var path in Directory.EnumerateFiles(docsDir, pattern))
                {
                    var file = Path.GetFileName(path);
                    if (!string.IsNullOrEmpty(zoneTag)
                        && !file.StartsWith("record_sync_" + zoneTag, StringComparison.OrdinalIgnoreCase)
                        && !file.StartsWith("record_changes_" + zoneTag, StringComparison.OrdinalIgnoreCase))
                        continue;
                    Absorb(path);
                }
            }
        }

        return map;
    }

    private static void ExpandPairedContentFromStructures(
        HashSet<string> allRecordNames,
        IProgress<string>? log)
    {
        var paired = new List<string>();
        foreach (var name in allRecordNames
                     .Where(static n => n.StartsWith("documentStructure/", StringComparison.Ordinal))
                     .ToList())
        {
            var uuid = name["documentStructure/".Length..];
            var content = "documentContent/" + uuid;
            if (allRecordNames.Add(content))
                paired.Add(content);
        }

        if (paired.Count > 0)
            log?.Report($"  pair structure→content: +{paired.Count}");
    }

    private static async Task WriteFilesManifestAsync(
        string outDir,
        string docsDir,
        IReadOnlyList<object> zoneSummaries,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var files = new List<object>();
        foreach (var plainRoot in Directory.EnumerateDirectories(docsDir, "fetch_*", SearchOption.TopDirectoryOnly))
        {
            var plaintext = Path.Combine(plainRoot, "crypto", "plaintext");
            if (!Directory.Exists(plaintext))
                continue;
            foreach (var path in Directory.EnumerateFiles(plaintext, "*", SearchOption.AllDirectories))
            {
                var rel = Path.GetRelativePath(plaintext, path);
                files.Add(new
                {
                    zoneFetch = Path.GetFileName(plainRoot),
                    relativePath = rel.Replace('\\', '/'),
                    bytes = new FileInfo(path).Length,
                });
            }
        }

        var manifest = new
        {
            generatedAt = DateTimeOffset.Now.ToString("O"),
            captureRef = "capture_icloud_drive_20260905_072447",
            zones = zoneSummaries,
            fileCount = files.Count,
            files,
        };
        var pathOut = Path.Combine(outDir, "icloud_files_manifest.json");
        await File.WriteAllTextAsync(
            pathOut,
            JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true }),
            ct);
        log?.Report($"  manifest → {Path.GetFileName(pathOut)} ({files.Count} file plaintext)");
        // #region agent log
        AgentLog("H-IF5", "ICloudDriveProbeService.cs:manifest", "manifest_written", new
        {
            path = Path.GetFileName(pathOut),
            fileCount = files.Count,
            zones = zoneSummaries.Count,
        });
        // #endregion
    }

    private async Task EnsureCloudDocsCkAppInitAsync(
        ICloudSession session,
        string containerId,
        IProgress<string>? log,
        CancellationToken ct)
    {
        try
        {
            await _orchestrator.CkAppInitAsync(session, containerId, log, ct).ConfigureAwait(false);
        }
        catch (InvalidOperationException ex) when (ex.Message.Contains("401", StringComparison.Ordinal))
        {
            log?.Report("  ckAppInit 401 — remint Anisette (OTP) e retry…");
            await _orchestrator
                .RefreshAnisetteOnlyAsync(session, log, ct, forceRemint: true)
                .ConfigureAwait(false);
            _gateway.ClearUnauthorized();
            await _orchestrator.CkAppInitAsync(session, containerId, log, ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// content → structure → directory (forma wire <c>directory/UUID</c>).
    /// </summary>
    private static IReadOnlyList<string> OrderRecordsForFetch(IEnumerable<string> recordNames)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var n in recordNames)
        {
            if (n.StartsWith("documentContent/", StringComparison.Ordinal)
                || n.StartsWith("documentStructure/", StringComparison.Ordinal))
            {
                set.Add(n);
            }
            else if (n.Equals("directory/root", StringComparison.Ordinal)
                     || n.StartsWith(".directory/", StringComparison.Ordinal)
                     || n.StartsWith("directory/", StringComparison.Ordinal))
            {
                set.Add(ToDirectoryFetchRecordName(
                    CloudDocsDocumentCrypto.NormalizeDirectoryRecordName(n)));
            }
        }

        if (!set.Contains("directory/root"))
            set.Add("directory/root");

        return set
            .OrderBy(static n => n.StartsWith("documentContent/", StringComparison.Ordinal) ? 0
                : n.StartsWith("documentStructure/", StringComparison.Ordinal) ? 1 : 2)
            .ThenBy(static n => n, StringComparer.Ordinal)
            .ToList();
    }

    private static string ToDirectoryFetchRecordName(string canonicalOrWire)
    {
        if (string.IsNullOrWhiteSpace(canonicalOrWire))
            return canonicalOrWire;
        if (canonicalOrWire.Equals("directory/root", StringComparison.Ordinal))
            return canonicalOrWire;
        if (canonicalOrWire.StartsWith(".directory/", StringComparison.Ordinal))
            return canonicalOrWire[1..];
        return canonicalOrWire;
    }

    private static string ShortDir(string record) =>
        record.StartsWith(".directory/", StringComparison.Ordinal)
            ? record[".directory/".Length..]
            : record;

    private static bool IsMetadataCatalogZone(string zone) =>
        zone.Equals("com.apple.CloudDocs.container-metadata", StringComparison.OrdinalIgnoreCase);

    private static bool IsWhatsAppZone(string zone) =>
        zone.Contains("whatsapp", StringComparison.OrdinalIgnoreCase)
        || zone.StartsWith("57T9237FN3", StringComparison.Ordinal);

    private static bool IsAppDocumentZone(string zone)
    {
        if (string.IsNullOrWhiteSpace(zone))
            return false;
        if (WhatsAppCloudKitProbeService.IsDefaultZone(zone))
            return false;
        if (IsWhatsAppZone(zone))
            return false;
        if (zone.Equals("com.apple.CloudDocs", StringComparison.OrdinalIgnoreCase)
            || zone.StartsWith("com.apple.CloudDocs.", StringComparison.OrdinalIgnoreCase))
            return false;
        return zone.StartsWith("com.apple.", StringComparison.OrdinalIgnoreCase)
               || zone.StartsWith("iCloud.", StringComparison.OrdinalIgnoreCase);
    }

    private static bool ShouldIncludeZone(string zone, ICloudDriveProbeOptions options)
    {
        if (string.IsNullOrWhiteSpace(zone))
            return false;
        if (zone.Equals("com.apple.CloudDocs", StringComparison.OrdinalIgnoreCase)
            || zone.StartsWith("com.apple.CloudDocs.", StringComparison.OrdinalIgnoreCase))
            return true;
        if (options.IncludeWhatsAppZones && IsWhatsAppZone(zone))
            return true;
        if (options.IncludeAppZones && IsAppDocumentZone(zone))
            return true;
        return false;
    }

    internal static bool IsDriveZone(string zone, bool includeAppZones)
    {
        if (zone.Equals("com.apple.CloudDocs", StringComparison.OrdinalIgnoreCase)
            || zone.StartsWith("com.apple.CloudDocs.", StringComparison.OrdinalIgnoreCase))
            return true;
        return includeAppZones && IsAppDocumentZone(zone);
    }

    private static IReadOnlyList<string> OrderDriveZones(
        IEnumerable<string> zones,
        ICloudDriveProbeOptions options)
    {
        return zones
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static z =>
                z.Equals("com.apple.CloudDocs.container-metadata", StringComparison.OrdinalIgnoreCase) ? 0
                : z.Equals("com.apple.CloudDocs", StringComparison.OrdinalIgnoreCase) ? 1
                : IsWhatsAppZone(z) ? 2
                : 3)
            .ThenBy(static z => z, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static byte[] SelectRichestZonePayload(byte[]? preferred, byte[] fallback)
    {
        if (preferred is null or { Length: 0 })
            return fallback;
        if (fallback.Length == 0)
            return preferred;
        var prefScore = ScoreProtectionInfoPayload(preferred);
        var fallScore = ScoreProtectionInfoPayload(fallback);
        if (prefScore != fallScore)
            return prefScore > fallScore ? preferred : fallback;
        return preferred.Length >= fallback.Length ? preferred : fallback;
    }

    private static int ScoreProtectionInfoPayload(byte[] payload)
    {
        var score = 0;
        for (var i = 0; i + 4 < payload.Length; i++)
        {
            if (payload[i] != 0x61)
                continue;
            var lb = payload[i + 1];
            int len;
            if ((lb & 0x80) == 0)
                len = lb;
            else if ((lb & 0x7F) == 2 && i + 3 < payload.Length)
                len = (payload[i + 2] << 8) | payload[i + 3];
            else if ((lb & 0x7F) == 1 && i + 2 < payload.Length)
                len = payload[i + 2];
            else
                continue;
            if (len >= 200)
                score++;
        }

        return score;
    }

    private static IReadOnlyList<string> CollectDocumentRecordNames(
        byte[] payload,
        IReadOnlyList<string> diagnosticStrings)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in DocumentRecordRegex.Matches(Encoding.Latin1.GetString(payload)))
            names.Add(m.Value);
        foreach (var s in diagnosticStrings)
        {
            var n = WhatsAppCloudKitProbeService.NormalizeZoneName(s);
            if (n.StartsWith("documentContent/", StringComparison.Ordinal)
                || n.StartsWith("documentStructure/", StringComparison.Ordinal)
                || n.StartsWith(".directory/", StringComparison.Ordinal)
                || n.Equals("directory/root", StringComparison.Ordinal))
                names.Add(n);
            foreach (Match m in DocumentRecordRegex.Matches(s))
                names.Add(m.Value);
        }

        return names.OrderBy(static s => s, StringComparer.Ordinal).ToList();
    }

    private static void WriteDocumentIndex(
        string docsDir,
        string zone,
        IReadOnlyList<string> recordNames,
        IProgress<string>? log)
    {
        var path = Path.Combine(docsDir, $"index_{Sanitize(zone)}.txt");
        File.WriteAllLines(path, recordNames);
        var nContent = recordNames.Count(s => s.StartsWith("documentContent/", StringComparison.Ordinal));
        var nStruct = recordNames.Count(s => s.StartsWith("documentStructure/", StringComparison.Ordinal));
        var nDir = recordNames.Count(s =>
            s.StartsWith(".directory/", StringComparison.Ordinal)
            || s.StartsWith("directory/", StringComparison.Ordinal));
        log?.Report(
            $"    indice → {Path.GetFileName(path)} " +
            $"(content={nContent} structure={nStruct} directory={nDir})");
    }

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        var s = sb.ToString();
        return s.Length > 80 ? s[..80] : s;
    }
}

public sealed record ICloudDriveProbeResult(
    string OutputDirectory,
    bool Success,
    int ZonesProcessed,
    int RecordsFetched,
    int FilesDownloaded,
    string? Error);

public sealed record ICloudDriveProgress(string Phase, int Percent, string Detail);
