using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;

namespace iCloudKitExtractor.Services.WhatsApp;

/// <summary>
/// Probe documenti WhatsApp via CloudKit <c>com.apple.clouddocs</c> (flusso):
/// ckAppInit → zone/retrieve → record/sync (CKDFetchRecordChanges + requestedFields
/// fileContent/pkgContent/parent/…) paginato → MMCS authorizeGet/edge da sync →
/// crypto PCS. FetchRecords è solo enrichment directory/path, non la fonte MMCS.
/// </summary>
public sealed class WhatsAppDocumentsProbeService
{
    private static readonly Regex DocumentRecordRegex = new(
        @"(?:documentContent|documentStructure|\.?directory)/[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|directory/root",
        RegexOptions.Compiled);

    private static readonly Regex HttpsUrlRegex = new(
        @"https://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%\-]{12,500}",
        RegexOptions.Compiled);

    private const int FetchRecordsBatchSize = 8;
    private const int MaxSyncPages = 48;

    private readonly HttpClient _http;
    private readonly ICloudBackupOrchestrator _orchestrator;
    private readonly CloudKitGatewayClient _gateway;

    public WhatsAppDocumentsProbeService(
        HttpClient http,
        ICloudBackupOrchestrator orchestrator)
    {
        _http = http;
        _orchestrator = orchestrator;
        _gateway = new CloudKitGatewayClient(http);
    }

    public async Task ProbeAsync(
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log = null,
        string? pcsKeysDirectory = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var outDir = Path.Combine(outputDirectory, $"whatsapp_docs_{stamp}");
        Directory.CreateDirectory(outDir);

        var pcsDir = pcsKeysDirectory
                     ?? session.PcsKeysDirectory
                     ?? outputDirectory;

        log?.Report($"WhatsApp Documents probe → {outDir}");
        log?.Report($"  PCS keys dir (dinamico)={pcsDir}");

        await ProbeCloudDocsNativeAsync(session, outDir, pcsDir, log, ct);
        log?.Report("Documents probe completato.");
    }

    private async Task ProbeCloudDocsNativeAsync(
        ICloudSession session,
        string outDir,
        string pcsKeysDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var binding = CloudKitContainerBinding.CloudDocs;
        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;
        var docsDir = Path.Combine(outDir, "clouddocs_ck");
        Directory.CreateDirectory(docsDir);

        try
        {
            log?.Report($"CloudDocs CK: container={binding.ContainerId}");
            await _orchestrator.CkAppInitAsync(session, binding.ContainerId, log, ct);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
                || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            {
                log?.Report("  ckAppInit CloudDocs incompleto — skip native.");
                return;
            }

            log?.Report($"  ckUserId={session.CloudKitUserId}");

            // zone/retrieve "default" —  un colpo sola restituisce tutte le zone + PI.
            // Niente zone/sync: getChanges/sync non è supportato su AppDefaultZone.
            // Su account BAD il default omette Cont[0] MasterKeySet (~884); provo anche le zone
            // com.apple.CloudDocs* e le unisco nel bag crypto (H-WA-CLOUDDOCS-ZONE-PI).
            var zones = new HashSet<string>(StringComparer.Ordinal);
            byte[]? defaultZoneRetrieve = null;
            byte[]? pcsPiBag = null;
            log?.Report("  zone/retrieve → default (CKDFetchRecordZonesOperation)…");
            try
            {
                var body = CloudKitDelimitedRequest.BuildZoneRetrieve(
                    session.CloudKitUserId, ["default"], container: binding);
                defaultZoneRetrieve = await _gateway.ZoneRetrieveAsync(
                    session, body, ct, container: binding);
                await File.WriteAllBytesAsync(
                    Path.Combine(docsDir, "zones_default_retrieve.bin"), defaultZoneRetrieve, ct);
                var dStrings = CloudKitResponseParser.ExtractDiagnosticStrings(defaultZoneRetrieve);
                File.WriteAllLines(Path.Combine(docsDir, "zones_default_retrieve_strings.txt"), dStrings);
                var dNote = CloudKitResponseParser.IsCloudKitErrorPayload(defaultZoneRetrieve, out var derr)
                    ? derr
                    : CloudKitResponseParser.DescribeCompactPayload(defaultZoneRetrieve);
                log?.Report(
                    $"  zone/retrieve default → {defaultZoneRetrieve.Length} B" +
                    (dNote is null ? "" : $" — {dNote}"));
                foreach (var s in dStrings.Where(IsInteresting).Take(40))
                    log?.Report($"    «{s}»");

                if (!CloudKitResponseParser.IsCloudKitErrorPayload(defaultZoneRetrieve, out _))
                {
                    foreach (var s in WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(dStrings))
                    {
                        if (IsWhatsAppCloudDocsZone(s))
                            zones.Add(s);
                    }

                    foreach (var s in dStrings)
                    {
                        var n = WhatsAppCloudKitProbeService.NormalizeZoneName(s);
                        if (IsWhatsAppCloudDocsZone(n))
                            zones.Add(n);
                    }
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  zone/retrieve default: {ex.Message}");
            }

            // Seed PI: zone servizio CloudDocs (Drive le richiede esplicitamente).
            var seedZonePayloads = new List<(string Name, byte[] Payload)>();
            if (defaultZoneRetrieve is { Length: > 0 })
                seedZonePayloads.Add(("default", defaultZoneRetrieve));

            foreach (var seedZone in new[]
                     {
                         "com.apple.CloudDocs",
                         "com.apple.CloudDocs.container-metadata",
                     })
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    var seedBody = CloudKitDelimitedRequest.BuildZoneRetrieve(
                        session.CloudKitUserId, [seedZone], container: binding);
                    var seedPayload = await _gateway.ZoneRetrieveAsync(
                        session, seedBody, ct, container: binding);
                    var seedTag = Sanitize(seedZone);
                    await File.WriteAllBytesAsync(
                        Path.Combine(docsDir, $"zones_{seedTag}.bin"), seedPayload, ct);
                    if (CloudKitResponseParser.IsCloudKitErrorPayload(seedPayload, out var seedErr))
                    {
                        log?.Report($"  zone/retrieve {seedZone}: skip — {seedErr}");
                        continue;
                    }

                    seedZonePayloads.Add((seedZone, seedPayload));
                    log?.Report($"  zone/retrieve {seedZone} → {seedPayload.Length} B");
                }
                catch (Exception ex)
                {
                    log?.Report($"  zone/retrieve {seedZone}: {ex.Message}");
                }
            }

            pcsPiBag = ConcatZonePayloads(seedZonePayloads.Select(static x => x.Payload));
            // #region agent log
            AgentWaDocsDebugLog(
                "H-WA-CLOUDDOCS-ZONE-PI",
                "WhatsAppDocumentsProbeService.ProbeCloudDocsNativeAsync",
                "seed_zone_pi_bag",
                new
                {
                    seeds = seedZonePayloads.Select(static x => new
                    {
                        x.Name,
                        len = x.Payload.Length,
                        score = ScoreProtectionInfoPayload(x.Payload),
                        maxDer = MaxAppl1DerLen(x.Payload),
                    }).ToList(),
                    bagLen = pcsPiBag?.Length ?? 0,
                    bagScore = pcsPiBag is { Length: > 0 } ? ScoreProtectionInfoPayload(pcsPiBag) : 0,
                    bagMaxDer = pcsPiBag is { Length: > 0 } ? MaxAppl1DerLen(pcsPiBag) : 0,
                },
                runId: "wa-v5-clouddocs-zone");
            // #endregion
            if (pcsPiBag is { Length: > 0 }
                && defaultZoneRetrieve is { Length: > 0 }
                && pcsPiBag.Length > defaultZoneRetrieve.Length)
            {
                log?.Report(
                    $"  crypto PI bag ← default+CloudDocs* ({pcsPiBag.Length} B > default {defaultZoneRetrieve.Length} B)");
            }

            if (zones.Count == 0)
            {
                log?.Report(
                    "  nessuna zona WhatsApp in zone/retrieve — " +
                    "attesa 57T9237FN3.net.whatsapp.WhatsApp.");
                return;
            }

            // Solo zone WhatsApp (niente iMovie/Pages/mail/…).
            var ordered = zones
                .OrderByDescending(z => z.StartsWith("57T9237FN3", StringComparison.Ordinal))
                .ThenBy(z => z, StringComparer.Ordinal)
                .ToList();
            log?.Report($"  zone WhatsApp da processare: {string.Join(", ", ordered)}");

            foreach (var zone in ordered)
            {
                ct.ThrowIfCancellationRequested();
                log?.Report($"  zone/retrieve → {zone}");
                try
                {
                    var body = CloudKitDelimitedRequest.BuildZoneRetrieve(
                        session.CloudKitUserId, [zone], container: binding);
                    var payload = await _gateway.ZoneRetrieveAsync(
                        session, body, ct, container: binding);
                    var tag = Sanitize(zone);
                    await File.WriteAllBytesAsync(Path.Combine(docsDir, $"zones_{tag}.bin"), payload, ct);
                    var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                    File.WriteAllLines(Path.Combine(docsDir, $"zones_{tag}_strings.txt"), strings);
                    var note = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err)
                        ? err
                        : CloudKitResponseParser.DescribeCompactPayload(payload);
                    log?.Report($"    {payload.Length} B" + (note is null ? "" : $" — {note}"));
                    foreach (var s in strings.Where(IsInteresting).Take(20))
                        log?.Report($"      «{s}»");

                    if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _))
                        continue;

                    // Crypto: unisci seed bag (default+CloudDocs*) + zone WA così non si perde
                    // un Cont[0] MasterKeySet presente solo su una delle risposte.
                    var zonePayloadLive = ConcatZonePayloads(
                        new[] { pcsPiBag, payload }
                            .Where(static p => p is { Length: > 0 })
                            .Cast<byte[]>());
                    if (zonePayloadLive.Length > payload.Length)
                    {
                        log?.Report(
                            $"    crypto PI ← seed bag+zone " +
                            $"({zonePayloadLive.Length} B ≥ zone-specific {payload.Length} B)");
                    }

                    // #region agent log
                    AgentWaDocsDebugLog(
                        "H-WA-CLOUDDOCS-ZONE-PI",
                        "WhatsAppDocumentsProbeService.ProbeCloudDocsNativeAsync",
                        "crypto_pi_source",
                        new
                        {
                            zone,
                            zoneLen = payload.Length,
                            defaultLen = defaultZoneRetrieve?.Length ?? 0,
                            bagLen = pcsPiBag?.Length ?? 0,
                            cryptoLen = zonePayloadLive.Length,
                            cryptoMaxDer = MaxAppl1DerLen(zonePayloadLive),
                            cryptoScore = ScoreProtectionInfoPayload(zonePayloadLive),
                        },
                        runId: "wa-v5-clouddocs-zone");
                    // #endregion

                    // CloudDocs: CKDFetchRecordChangesOperation (types=1, maxChanges=1000)
                    // include i record Directory; types=3 (ZoneChanges) spesso solo content/structure
                    // con parent ref → FetchRecords .directory = Record not found.
                    log?.Report($"  record/sync → {zone} (CloudDocs Drive-style, paginato)…");
                    try
                    {
                        var allRecordNames = new HashSet<string>(StringComparer.Ordinal);
                        byte[]? token = null;
                        var pages = 0;
                        var syncTotalBytes = 0L;
                        var lastMore = false;
                        var lastTokenBytes = 0;

                        for (var page = 1; page <= MaxSyncPages; page++)
                        {
                            ct.ThrowIfCancellationRequested();
                            var changesBody = CloudKitDelimitedRequest.BuildCloudDocsRecordRetrieveChanges(
                                session.CloudKitUserId, zone, token, binding);
                            var changesPayload = await _gateway.RecordChangesAsync(
                                session, changesBody, ct, binding);
                            pages++;
                            syncTotalBytes += changesPayload.Length;

                            await File.WriteAllBytesAsync(
                                Path.Combine(docsDir, $"record_sync_{tag}_p{page}.bin"),
                                changesPayload, ct);
                            // Compat crypto EnumerateSyncPayloadFiles (record_changes_*.bin).
                            if (page == 1)
                            {
                                await File.WriteAllBytesAsync(
                                    Path.Combine(docsDir, $"record_changes_{tag}.bin"),
                                    changesPayload, ct);
                            }

                            var changeStrings = CloudKitResponseParser.ExtractDiagnosticStrings(changesPayload);
                            File.WriteAllLines(
                                Path.Combine(docsDir, $"record_sync_{tag}_p{page}_strings.txt"),
                                changeStrings);
                            if (page == 1)
                            {
                                File.WriteAllLines(
                                    Path.Combine(docsDir, $"record_changes_{tag}_strings.txt"),
                                    changeStrings);
                            }

                            var pageNames = CollectDocumentRecordNames(changesPayload, changeStrings);
                            foreach (var name in pageNames)
                                allRecordNames.Add(name);

                            var cont = CloudKitResponseParser.TryExtractRecordSyncContinuation(changesPayload);
                            var stringMore = changeStrings.Any(static s =>
                                s.Contains("moreComing", StringComparison.OrdinalIgnoreCase));
                            lastMore = cont.MoreComing || stringMore;
                            lastTokenBytes = cont.SyncContinuationToken?.Length ?? 0;
                            var shouldContinue = CloudKitResponseParser.ShouldContinueRecordSyncPagination(
                                cont, token ?? ReadOnlySpan<byte>.Empty, pageNames.Count, stringMore);

                            // #region agent log
                            AgentWaDocsDebugLog(
                                "H-WA-IKE4",
                                "WhatsAppDocumentsProbeService.ProbeCloudDocsNativeAsync",
                                "sync_page_continuation",
                                new
                                {
                                    zone,
                                    page,
                                    payloadBytes = changesPayload.Length,
                                    pageRec = pageNames.Count,
                                    totalRec = allRecordNames.Count,
                                    moreComing = cont.MoreComing,
                                    stringMore,
                                    shouldContinue,
                                    tokenBytes = lastTokenBytes,
                                    syncStatusHint = cont.MoreComing ? "f4=1_or_f3" : "complete_or_unknown",
                                },
                                runId: "wa-ike-paginated");
                            // #endregion

                            var changesNote = CloudKitResponseParser.IsCloudKitErrorPayload(changesPayload, out var cerr)
                                ? cerr
                                : CloudKitResponseParser.DescribeCompactPayload(changesPayload);
                            log?.Report(
                                $"    p{page} {changesPayload.Length:N0} B pageRec={pageNames.Count} " +
                                $"total={allRecordNames.Count} more={cont.MoreComing}" +
                                (lastTokenBytes > 0 ? $" token={lastTokenBytes}B" : "") +
                                (shouldContinue ? " → continua" : "") +
                                (changesNote is null ? "" : $" — {changesNote}"));
                            if (page == 1)
                            {
                                foreach (var s in changeStrings.Where(IsInteresting).Take(40))
                                    log?.Report($"      «{s}»");
                            }

                            if (CloudKitResponseParser.IsCloudKitErrorPayload(changesPayload, out _))
                                break;

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

                        // Structure senza content nello sync (es. CA1503FF .tar): prova comunque
                        // FetchRecords documentContent/UUID — può esistere fuori dal change stream.
                        ExpandPairedContentFromStructures(allRecordNames, log);

                        var recordNames = allRecordNames
                            .OrderBy(static s => s, StringComparer.Ordinal)
                            .ToList();
                        WriteDocumentIndex(docsDir, zone, recordNames, log);

                        //  MMCS nasce dal record/sync (requestedFields), non da FetchRecords.
                        // Materializza sempre fetchDir + sync pages, poi crypto; FetchRecords
                        // solo se ci sono nomi record (path tree / enrichment).
                        var fetchDir = Path.Combine(docsDir, $"fetch_{tag}");
                        Directory.CreateDirectory(fetchDir);
                        foreach (var syncPath in Directory.GetFiles(docsDir, $"record_sync_{tag}_*.bin"))
                        {
                            var dest = Path.Combine(fetchDir, Path.GetFileName(syncPath));
                            if (!File.Exists(dest))
                                File.Copy(syncPath, dest);
                        }

                        foreach (var syncPath in Directory.GetFiles(docsDir, $"record_changes_{tag}.bin"))
                        {
                            var dest = Path.Combine(fetchDir, Path.GetFileName(syncPath));
                            if (!File.Exists(dest))
                                File.Copy(syncPath, dest);
                        }

                        // #region agent log
                        {
                            var nContent = recordNames.Count(static s =>
                                s.StartsWith("documentContent/", StringComparison.Ordinal));
                            var nStruct = recordNames.Count(static s =>
                                s.StartsWith("documentStructure/", StringComparison.Ordinal));
                            var nDir = recordNames.Count(static s =>
                                s.StartsWith(".directory/", StringComparison.Ordinal)
                                || s.Equals("directory/root", StringComparison.Ordinal));
                            var edgeInSync = 0;
                            foreach (var sp in Directory.GetFiles(docsDir, $"record_sync_{tag}_*.bin"))
                            {
                                try
                                {
                                    edgeInSync += UbChunkBuilder
                                        .ParseAuthorizeGetResponse(File.ReadAllBytes(sp)).Count;
                                }
                                catch { /* ignore */ }
                            }

                            AgentWaDocsDebugLog(
                                "H-WA-IKE1",
                                "WhatsAppDocumentsProbeService.ProbeCloudDocsNativeAsync",
                                "sync_primary",
                                new
                                {
                                    zone,
                                    pages,
                                    syncTotalBytes,
                                    moreComing = lastMore,
                                    tokenBytes = lastTokenBytes,
                                    totalRecords = recordNames.Count,
                                    nContent,
                                    nStruct,
                                    nDir,
                                    embeddedEdgeChunks = edgeInSync,
                                    requestFlavor =
                                        "BuildCloudDocsRecordRetrieveChanges(types=1,maxChanges=1000,requestedFields=IKE)",
                                },
                                runId: "wa-ike-flow");
                        }
                        // #endregion

                        if (recordNames.Count > 0)
                        {
                            await FetchDocumentRecordsAsync(
                                session, binding, docsDir, zone, recordNames,
                                zonePayloadLive, pcsKeysDirectory, log, ct,
                                skipCrypto: true);
                        }
                        else
                        {
                            log?.Report(
                                "  FetchRecords skip — nessun documentContent ASCII nello sync; " +
                                " MMCS da record/sync embedded → crypto diretto");
                        }

                        try
                        {
                            var crypto = new CloudDocsDocumentCrypto(_http);
                            await crypto.ProcessAsync(
                                session,
                                fetchDir,
                                zone,
                                zonePayloadLive,
                                log,
                                pcsKeysDirectory: pcsKeysDirectory,
                                ct: ct);
                        }
                        catch (Exception ex)
                        {
                            log?.Report($"  crypto Documents: {ex.Message}");
                        }
                    }
                    catch (Exception ex)
                    {
                        log?.Report($"    ERRORE record/sync: {ex.Message}");
                    }
                }
                catch (Exception ex)
                {
                    log?.Report($"    ERRORE zone/retrieve: {ex.Message}");
                }
            }
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    private async Task FetchDocumentRecordsAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string docsDir,
        string zone,
        IReadOnlyList<string> recordNames,
        byte[] zonePayloadLive,
        string pcsKeysDirectory,
        IProgress<string>? log,
        CancellationToken ct,
        bool skipCrypto = false)
    {
        var fetchDir = Path.Combine(docsDir, $"fetch_{Sanitize(zone)}");
        Directory.CreateDirectory(fetchDir);

        // Priorità: content (MMCS) → directory (path tree) → structure.
        // Directory in batch dedicati (anche alias senza leading '.') — Record not found
        // se mischiate con content/structure orfani.
        var content = recordNames
            .Where(static n => n.StartsWith("documentContent/", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static n => n, StringComparer.Ordinal)
            .ToList();
        var structures = recordNames
            .Where(static n => n.StartsWith("documentStructure/", StringComparison.Ordinal))
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static n => n, StringComparer.Ordinal)
            .ToList();
        var directories = ExpandDirectoryFetchNames(recordNames);

        var ordered = new List<string>(content.Count + directories.Count + structures.Count);
        ordered.AddRange(content);
        ordered.AddRange(directories);
        ordered.AddRange(structures);

        log?.Report(
            $"  FetchRecords → {zone} ({ordered.Count} record, " +
            $"content={content.Count} dir={directories.Count} struct={structures.Count}, " +
            $"batch={FetchRecordsBatchSize})…");

        // #region agent log
        AgentWaDocsDebugLog(
            "H-WA7",
            "WhatsAppDocumentsProbeService.FetchDocumentRecordsAsync",
            "fetch_plan",
            new
            {
                zone,
                content = content.Count,
                directories = directories.Count,
                structures = structures.Count,
                directoryNames = directories.Take(20).ToList(),
            },
            runId: "wa-docs-post");
        // #endregion

        var summary = new List<string>
        {
            $"zone={zone}",
            $"records={ordered.Count}",
            $"stamp={DateTime.Now:O}",
            "",
        };

        var mmcsHits = 0;
        var urlHits = 0;
        var errorHits = 0;

        for (var offset = 0; offset < ordered.Count; offset += FetchRecordsBatchSize)
        {
            ct.ThrowIfCancellationRequested();
            var batch = ordered.Skip(offset).Take(FetchRecordsBatchSize).ToList();
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
                File.WriteAllLines(
                    Path.Combine(fetchDir, $"{batchTag}_names.txt"), batch);

                var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                File.WriteAllLines(
                    Path.Combine(fetchDir, $"{batchTag}_strings.txt"), strings);

                var isError = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err);
                if (isError)
                    errorHits++;

                var structured = MmcsAuthBuilder.ExtractStructuredAuths(payload);
                var readyAuths = MmcsAuthBuilder.ExtractAllReadyMadeAuths(payload);
                var urls = ExtractHttpsUrls(payload);
                if (structured.Count > 0 || readyAuths.Count > 0)
                    mmcsHits++;
                if (urls.Count > 0)
                    urlHits++;

                // Dump per-record: slice grezzo non disponibile → un file note per nome.
                foreach (var name in batch)
                {
                    var notePath = Path.Combine(fetchDir, SanitizeFileName(name) + ".txt");
                    var auth = MmcsAuthBuilder.BuildFromRecordPayload(payload, name)
                               ?? readyAuths.FirstOrDefault(a =>
                                   a.Contains(name, StringComparison.Ordinal));
                    var lines = new List<string>
                    {
                        $"record={name}",
                        $"zone={zone}",
                        $"batch={batchTag}",
                        $"payloadBytes={payload.Length}",
                        $"error={(isError ? err ?? "yes" : "no")}",
                        $"hasFileContentMarker={ContainsAscii(payload, "fileContent")}",
                        $"hasEncryptedBasename={ContainsAscii(payload, "encryptedBasename")}",
                        $"mmcsAuth={(string.IsNullOrWhiteSpace(auth) ? "(none)" : Trim(auth))}",
                    };
                    if (urls.Count > 0)
                    {
                        lines.Add("urls:");
                        lines.AddRange(urls.Take(20).Select(u => "  " + u));
                    }

                    File.WriteAllLines(notePath, lines);
                }

                // Catalogo auth del batch.
                if (structured.Count > 0 || readyAuths.Count > 0 || urls.Count > 0)
                {
                    var authLines = new List<string>();
                    foreach (var a in structured)
                        authLines.Add($"structured\t{a.RecordName ?? "-"}\t{a.Header}");
                    foreach (var a in readyAuths)
                        authLines.Add($"ready\t-\t{a}");
                    foreach (var u in urls)
                        authLines.Add($"url\t-\t{u}");
                    File.WriteAllLines(Path.Combine(fetchDir, $"{batchTag}_mmcs.txt"), authLines);
                }

                var note = isError
                    ? err
                    : CloudKitResponseParser.DescribeCompactPayload(payload);
                log?.Report(
                    $"    {batchTag}: {batch.Count} record → {payload.Length} B" +
                    (note is null ? "" : $" — {note}") +
                    $"; mmcsStruct={structured.Count} ready={readyAuths.Count} urls={urls.Count}");

                summary.Add(
                    $"{batchTag}\trecords={batch.Count}\tbytes={payload.Length}\t" +
                    $"error={(isError ? "1" : "0")}\tmmcs={structured.Count + readyAuths.Count}\turls={urls.Count}");
                foreach (var name in batch)
                    summary.Add($"  {name}");
            }
            catch (Exception ex)
            {
                errorHits++;
                log?.Report($"    {batchTag}: ERRORE {ex.Message}");
                summary.Add($"{batchTag}\tERROR\t{ex.Message}");
            }
        }

        summary.Insert(3, $"batchesWithMmcs={mmcsHits}");
        summary.Insert(4, $"batchesWithUrls={urlHits}");
        summary.Insert(5, $"batchesWithError={errorHits}");
        var summaryPath = Path.Combine(fetchDir, "summary.txt");
        File.WriteAllLines(summaryPath, summary);
        log?.Report(
            $"  FetchRecords finito → {fetchDir} " +
            $"(mmcsBatches={mmcsHits} urlBatches={urlHits} errBatches={errorHits})");

        // path: WhatsApp/Accounts/<phone>/backup — risali i parent Directory mancanti.
        await ChaseDirectoryParentChainAsync(
            session, binding, fetchDir, zone, log, ct);

        LogDirectoryCountMetricsGap(fetchDir, zone, log);

        //  crypto gira una sola volta sul fetchDir (sync pages + eventuali batch FetchRecords).
        if (skipCrypto)
            return;

        try
        {
            var crypto = new CloudDocsDocumentCrypto(_http);
            await crypto.ProcessAsync(
                session,
                fetchDir,
                zone,
                zonePayloadLive,
                log,
                pcsKeysDirectory: pcsKeysDirectory,
                ct: ct);
        }
        catch (Exception ex)
        {
            log?.Report($"  crypto pipeline: {ex.Message}");
        }
    }

    /// <summary>
    /// Per ogni <c>documentStructure/UUID</c> aggiunge <c>documentContent/UUID</c> se assente.
    /// Runtime: sync può elencare structure orfane (es. .tar) senza la riga content.
    /// </summary>
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
        {
            log?.Report(
                $"  pair structure→content: +{paired.Count} " +
                $"→ {string.Join(", ", paired.Select(static s => s.Replace("documentContent/", "", StringComparison.Ordinal)).Take(6))}" +
                (paired.Count > 6 ? "…" : ""));
        }

        // #region agent log
        AgentWaDocsDebugLog(
            "H-WA12",
            "WhatsAppDocumentsProbeService.ExpandPairedContentFromStructures",
            "pair_structure_content",
            new
            {
                added = paired.Count,
                addedSample = paired.Take(20).ToList(),
                catalogTotal = allRecordNames.Count,
            },
            runId: "wa-docs-post");
        // #endregion
    }

    /// <summary>
    /// Confronta countMetrics (bytes/items/children) dei Directory FetchRecords
    /// con quanti documentContent abbiamo nello sync — gap verso.
    /// </summary>
    private static void LogDirectoryCountMetricsGap(
        string fetchDir,
        string zone,
        IProgress<string>? log)
    {
        var dirs = CollectParsedDirectories(fetchDir);
        var contentParents = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var pattern in new[] { "batch*.bin", "record_sync_*.bin", "record_changes_*.bin" })
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(fetchDir, pattern);
            }
            catch
            {
                continue;
            }

            foreach (var path in files)
            {
                byte[] payload;
                try
                {
                    payload = File.ReadAllBytes(path);
                }
                catch
                {
                    continue;
                }

                // Conta parent .directory/UUID vicino a documentContent (euristica leggera).
                var text = Encoding.Latin1.GetString(payload);
                var idx = 0;
                while (true)
                {
                    var c = text.IndexOf("documentContent/", idx, StringComparison.Ordinal);
                    if (c < 0)
                        break;
                    var windowStart = Math.Max(0, c - 200);
                    var window = text.AsSpan(windowStart, Math.Min(400, text.Length - windowStart));
                    var p = window.LastIndexOf(".directory/".AsSpan(), StringComparison.Ordinal);
                    if (p >= 0 && p + 47 <= window.Length)
                    {
                        var parent = window.Slice(p, 47).ToString();
                        if (parent.Length >= 47)
                            contentParents[parent] = contentParents.GetValueOrDefault(parent) + 1;
                    }

                    idx = c + 16;
                }
            }
        }

        var samples = new List<object>();
        foreach (var d in dirs.Values
                     .Where(static x => x.RecordName.StartsWith(".directory/", StringComparison.Ordinal))
                     .OrderBy(static x => x.RecordName, StringComparer.Ordinal))
        {
            var metrics = TryParseCountMetricsNearRecord(fetchDir, d.RecordName);
            var syncChildrenApprox = contentParents.GetValueOrDefault(d.RecordName);
            samples.Add(new
            {
                d.RecordName,
                metrics,
                syncContentNearParent = syncChildrenApprox,
            });
            if (metrics is { } m)
            {
                log?.Report(
                    $"  countMetrics {ShortDir(d.RecordName)}: " +
                    $"items≈{m.ItemCount} children≈{m.ChildCount} " +
                    $"syncContentNear={syncChildrenApprox}");
            }
        }

        // #region agent log
        AgentWaDocsDebugLog(
            "H-WA12",
            "WhatsAppDocumentsProbeService.LogDirectoryCountMetricsGap",
            "count_metrics_gap",
            new { zone, samples },
            runId: "wa-docs-post");
        // #endregion
    }

    private readonly record struct DirCountMetrics(long? ByteCount, int? ItemCount, int? ChildCount);

    private static DirCountMetrics? TryParseCountMetricsNearRecord(string fetchDir, string recordName)
    {
        foreach (var pattern in new[] { "dirparent_*.bin", "batch*.bin" })
        {
            foreach (var path in Directory.EnumerateFiles(fetchDir, pattern))
            {
                byte[] d;
                try
                {
                    d = File.ReadAllBytes(path);
                }
                catch
                {
                    continue;
                }

                var marker = Encoding.ASCII.GetBytes(recordName);
                var i = IndexOfBytes(d, marker);
                if (i < 0)
                    continue;
                var j = IndexOfBytes(d, "countMetrics"u8.ToArray(), i, Math.Min(d.Length, i + 2500));
                if (j < 0)
                    continue;
                var k = j + "countMetrics".Length;
                if (k >= d.Length || d[k] != 0x12)
                    continue;
                k++;
                if (!TryReadVarint(d, ref k, out var vlen))
                    continue;
                var end = k + (int)vlen;
                if (end > d.Length)
                    continue;
                long? bytes = null;
                int? items = null;
                int? children = null;
                var values = new List<long>();
                while (k < end)
                {
                    var tag = d[k++];
                    var wt = tag & 7;
                    if (wt == 2)
                    {
                        if (!TryReadVarint(d, ref k, out var ln))
                            break;
                        var subEnd = k + (int)ln;
                        long? v = null;
                        while (k < subEnd)
                        {
                            var tg = d[k++];
                            if ((tg & 7) != 0)
                            {
                                if ((tg & 7) == 2)
                                {
                                    if (!TryReadVarint(d, ref k, out var ln2))
                                        break;
                                    k += (int)ln2;
                                }
                                else
                                    break;
                                continue;
                            }

                            if (!TryReadVarint(d, ref k, out var val))
                                break;
                            if ((tg >> 3) == 4)
                                v = (long)val;
                        }

                        if (v is not null)
                            values.Add(v.Value);
                    }
                    else if (wt == 0)
                    {
                        if (!TryReadVarint(d, ref k, out _))
                            break;
                    }
                    else
                        break;
                }

                // Euristica da runtime: [bytes, items, 0, 0, children]
                if (values.Count >= 2)
                    items = (int)values[1];
                if (values.Count >= 1)
                    bytes = values[0];
                if (values.Count >= 5)
                    children = (int)values[^1];
                return new DirCountMetrics(bytes, items, children);
            }
        }

        return null;
    }

    private static int IndexOfBytes(byte[] hay, byte[] needle, int start = 0, int end = -1)
    {
        if (end < 0)
            end = hay.Length;
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

    private static bool TryReadVarint(byte[] buf, ref int i, out ulong val)
    {
        val = 0;
        var shift = 0;
        while (i < buf.Length && shift < 64)
        {
            var b = buf[i++];
            val |= (ulong)(b & 0x7f) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
        }

        return false;
    }

    /// <summary>
    /// Dopo il fetch iniziale, i record <c>backup</c> puntano a parent
    /// (<c>.directory/phone</c> → Accounts → WhatsApp → root) non presenti nell'indice sync.
    /// Li FetchRecords in batch dedicati con forma wire <c>directory/UUID</c> (senza punto:
    /// <c>.directory/UUID</c> restituisce Record not found) fino a root.
    /// </summary>
    private async Task ChaseDirectoryParentChainAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string fetchDir,
        string zone,
        IProgress<string>? log,
        CancellationToken ct)
    {
        const int maxRounds = 8;
        // Canonical (.directory/…) già presenti o per cui abbiamo esaurito i tentativi.
        var resolvedOrAttempted = new HashSet<string>(StringComparer.Ordinal);
        var round = 0;
        var totalFetched = 0;

        while (round < maxRounds)
        {
            ct.ThrowIfCancellationRequested();
            round++;

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
                log?.Report(
                    $"  directory parent chase: completo " +
                    $"(round={round - 1} fetched={totalFetched} known={known.Count})");
                // #region agent log
                AgentWaDocsDebugLog(
                    "H-WA9",
                    "WhatsAppDocumentsProbeService.ChaseDirectoryParentChainAsync",
                    "chase_complete",
                    new
                    {
                        zone,
                        rounds = round - 1,
                        totalFetched,
                        known = known.Count,
                        sample = known.Values.Take(12).Select(d => new
                        {
                            d.RecordName,
                            d.ParentDirectory,
                            hasEnc = d.EncryptedBasenameHex is { Length: > 0 },
                        }).ToList(),
                    },
                    runId: "wa-docs-post");
                // #endregion
                return;
            }

            var batch = missing.OrderBy(static s => s, StringComparer.Ordinal).ToList();
            // Wire name: senza leading '.' — runtime: .directory/UUID → Record not found.
            var wireNames = batch.Select(ToDirectoryFetchRecordName).ToList();
            log?.Report(
                $"  directory parent chase round {round}: fetch {batch.Count} " +
                $"→ {string.Join(", ", batch.Select(ShortDir).Take(6))}" +
                (batch.Count > 6 ? "…" : ""));

            // #region agent log
            AgentWaDocsDebugLog(
                "H-WA9",
                "WhatsAppDocumentsProbeService.ChaseDirectoryParentChainAsync",
                "chase_round",
                new { zone, round, missing = batch, wireNames },
                runId: "wa-docs-post");
            // #endregion

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
                    File.WriteAllLines(
                        Path.Combine(fetchDir, $"{batchTag}_names.txt"), sliceWire);
                    var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                    File.WriteAllLines(
                        Path.Combine(fetchDir, $"{batchTag}_strings.txt"), strings);

                    var isError = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err);
                    var parsed = CloudDocsDocumentCrypto.ParseDirectoryRecords(payload, batchTag + ".bin");
                    var rnf = CountAsciiOccurrences(payload, "Record not found");
                    totalFetched += sliceWire.Count;

                    // Un tentativo per parent con forma wire corretta; evita loop su RNF.
                    foreach (var n in sliceCanonical)
                        resolvedOrAttempted.Add(n);

                    log?.Report(
                        $"    {batchTag}: wire={sliceWire.Count} → {payload.Length} B" +
                        (isError ? $" — {err ?? "error"}" : "") +
                        $"; parsedDirs={parsed.Count} rnf={rnf}");

                    // #region agent log
                    AgentWaDocsDebugLog(
                        "H-WA9",
                        "WhatsAppDocumentsProbeService.ChaseDirectoryParentChainAsync",
                        "chase_batch_result",
                        new
                        {
                            zone,
                            round,
                            batchTag,
                            wireNames = sliceWire,
                            payloadBytes = payload.Length,
                            parsedDirs = parsed.Count,
                            rnf,
                            parsed = parsed.Select(p => new
                            {
                                p.RecordName,
                                p.ParentDirectory,
                                hasEnc = p.EncryptedBasenameHex is { Length: > 0 },
                            }).ToList(),
                        },
                        runId: "wa-docs-post");
                    // #endregion
                }
                catch (Exception ex)
                {
                    foreach (var n in sliceCanonical)
                        resolvedOrAttempted.Add(n);
                    log?.Report($"    {batchTag}: ERRORE {ex.Message}");
                }
            }
        }

        log?.Report($"  directory parent chase: stop dopo {maxRounds} round (fetched={totalFetched})");
    }

    /// <summary>
    /// Nome da passare a FetchRecords: <c>directory/UUID</c> o <c>directory/root</c>.
    /// La forma canonica interna resta <c>.directory/UUID</c>.
    /// </summary>
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

    private static int CountAsciiOccurrences(byte[] payload, string ascii)
    {
        if (payload.Length == 0 || string.IsNullOrEmpty(ascii))
            return 0;
        var needle = Encoding.ASCII.GetBytes(ascii);
        var count = 0;
        for (var i = 0; i <= payload.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (payload[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
                count++;
        }

        return count;
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
                     "batch*.bin", "dirparent_*.bin", "childbatch_*.bin", "dirchildren_*.bin",
                     "record_sync_*.bin", "record_changes_*.bin",
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

    private static string ShortDir(string record) =>
        record.StartsWith(".directory/", StringComparison.Ordinal)
            ? record[".directory/".Length..]
            : record;

    private static bool IsWhatsAppCloudDocsZone(string zone)
    {
        if (string.IsNullOrWhiteSpace(zone))
            return false;
        if (WhatsAppCloudKitProbeService.IsDefaultZone(zone))
            return false;
        return zone.Contains("whatsapp", StringComparison.OrdinalIgnoreCase)
               || zone.StartsWith("57T9237FN3", StringComparison.Ordinal);
    }

    private static byte[] ConcatZonePayloads(IEnumerable<byte[]> parts)
    {
        var list = parts.Where(static p => p.Length > 0).ToList();
        if (list.Count == 0)
            return [];
        if (list.Count == 1)
            return list[0];
        var total = list.Sum(static p => p.Length);
        var bag = new byte[total];
        var o = 0;
        foreach (var p in list)
        {
            Buffer.BlockCopy(p, 0, bag, o, p.Length);
            o += p.Length;
        }

        return bag;
    }

    private static int MaxAppl1DerLen(byte[] payload)
    {
        var max = 0;
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
            // TLV content length; DER size ≈ 2–4 + len
            var derApprox = len + 2 + ((lb & 0x80) != 0 ? (lb & 0x7F) : 0);
            if (derApprox > max)
                max = derApprox;
        }

        return max;
    }

    /// <summary>
    /// Sceglie il payload zone/retrieve con più candidati ProtectionInfo DER (appl[1]),
    /// tipicamente la risposta "default"-style rispetto al retrieve single-zone.
    /// </summary>
    private static byte[] SelectRichestZonePayload(byte[]? preferred, byte[] fallback)
    {
        if (preferred is null || preferred.Length == 0)
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
            // Bonus forte per DER ~1500 (MasterKeySet Cont[0] ~884): conta più dei PI piccoli ~570.
            if (len >= 900)
                score += 100;
            else if (len >= 200)
                score++;
        }

        return score;
    }

    private static void WriteDocumentIndex(
        string docsDir,
        string zone,
        IReadOnlyList<string> recordNames,
        IProgress<string>? log)
    {
        if (recordNames.Count == 0)
            return;

        var path = Path.Combine(docsDir, $"index_{Sanitize(zone)}.txt");
        File.WriteAllLines(path, recordNames);
        var nContent = recordNames.Count(s => s.StartsWith("documentContent/", StringComparison.Ordinal));
        var nStruct = recordNames.Count(s => s.StartsWith("documentStructure/", StringComparison.Ordinal));
        var nDir = recordNames.Count(s => s.StartsWith(".directory/", StringComparison.Ordinal));
        log?.Report(
            $"    indice documenti → {path} " +
            $"(content={nContent} structure={nStruct} directory={nDir})");
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
                || n.StartsWith("directory/", StringComparison.Ordinal)
                || n.Equals("directory/root", StringComparison.Ordinal))
            {
                names.Add(n.StartsWith("directory/", StringComparison.Ordinal)
                          && !n.Equals("directory/root", StringComparison.Ordinal)
                    ? "." + n
                    : n);
            }

            foreach (Match m in DocumentRecordRegex.Matches(s))
                names.Add(m.Value);
        }

        return names
            .OrderBy(static s => s, StringComparer.Ordinal)
            .ToList();
    }

    private static IReadOnlyList<string> ExtractHttpsUrls(byte[] payload)
    {
        var text = Encoding.Latin1.GetString(payload);
        return HttpsUrlRegex.Matches(text)
            .Select(static m => m.Value.TrimEnd('"', '\'', ')', ']', '>', ',', ';'))
            .Where(static u => u.Contains("icloud", StringComparison.OrdinalIgnoreCase)
                               || u.Contains("apple", StringComparison.OrdinalIgnoreCase)
                               || u.Contains("mmcs", StringComparison.OrdinalIgnoreCase)
                               || u.Contains("content", StringComparison.OrdinalIgnoreCase))
            .Distinct(StringComparer.Ordinal)
            .Take(40)
            .ToList();
    }

    private static bool ContainsAscii(byte[] data, string ascii)
    {
        if (string.IsNullOrEmpty(ascii) || data.Length < ascii.Length)
            return false;
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
                return true;
        }

        return false;
    }

    private static bool IsInteresting(string s)
    {
        if (s.Length < 4)
            return false;
        if (Guid.TryParse(s.TrimStart('$'), out _))
            return false;
        return s.Contains("whatsapp", StringComparison.OrdinalIgnoreCase)
               || s.Contains("CloudDocs", StringComparison.OrdinalIgnoreCase)
               || s.Contains("ChatStorage", StringComparison.OrdinalIgnoreCase)
               || s.Contains("Accounts", StringComparison.OrdinalIgnoreCase)
               || s.Contains("appDocuments_", StringComparison.OrdinalIgnoreCase)
               || s.Contains("backup", StringComparison.OrdinalIgnoreCase)
               || s.Contains("error", StringComparison.OrdinalIgnoreCase)
               || s.Contains("not exist", StringComparison.OrdinalIgnoreCase)
               || s.Contains("not support", StringComparison.OrdinalIgnoreCase)
               || s.StartsWith('_');
    }

    /// <summary>
    /// Nomi directory da fetchare: forma CK <c>.directory/UUID</c> e alias
    /// <c>directory/UUID</c> (come nei parent ref). Sempre include <c>directory/root</c>.
    /// </summary>
    private static List<string> ExpandDirectoryFetchNames(IEnumerable<string> recordNames)
    {
        // Solo forma wire directory/UUID (senza '.'): .directory/UUID → Record not found.
        var set = new HashSet<string>(StringComparer.Ordinal) { "directory/root" };
        foreach (var n in recordNames)
        {
            if (n.Equals("directory/root", StringComparison.Ordinal)
                || n.StartsWith(".directory/", StringComparison.Ordinal)
                || n.StartsWith("directory/", StringComparison.Ordinal))
            {
                set.Add(ToDirectoryFetchRecordName(
                    CloudDocsDocumentCrypto.NormalizeDirectoryRecordName(n)));
            }
        }

        return set
            .OrderBy(static n => n.Equals("directory/root", StringComparison.Ordinal) ? 0 : 1)
            .ThenBy(static n => n, StringComparer.Ordinal)
            .ToList();
    }

    // #region agent log
    private static void AgentWaDocsDebugLog(
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

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        var s = sb.ToString();
        return s.Length > 80 ? s[..80] : s;
    }

    private static string SanitizeFileName(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name;
    }

    private static string Trim(string s) =>
        s.Length <= 240 ? s.Trim() : s.Trim()[..240] + "…";
}
