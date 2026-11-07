using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.Forensics;
using iCloudKitExtractor.Services.WhatsApp;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Probe iCloud Sync Data (capture <c>capture_http_20260802_054842</c>):
/// Escrow KeySet già in sessione → per ogni container
/// ckAppInit → zone/retrieve(default) → zone/sync →
/// per zona custom: zone/retrieve → record/sync → record/retrieve.
/// (AppDefaultZone: getChanges non supportato — ck1e0lk64 / ck13ujr18.)
/// </summary>
public sealed class ICloudSyncDataProbeService
{
    private const int RecordRetrieveBatchSize = 8;

    private readonly HttpClient _http;
    private readonly ICloudBackupOrchestrator _orchestrator;
    private readonly CloudKitGatewayClient _gateway;

    public ICloudSyncDataProbeService(HttpClient http, ICloudBackupOrchestrator orchestrator)
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

    public async Task<SyncDataProbeResult> ProbeAsync(
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        IReadOnlyList<string>? selectedCategoryIds = null,
        IProgress<SyncDataProgressReport>? progress = null,
        bool buildPhotosRecordMetadata = false)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Sessione senza dsid — effettua il login.");
        if (string.IsNullOrWhiteSpace(session.CloudKitAuthToken)
            && string.IsNullOrWhiteSpace(session.MobileMeAuthToken)
            && string.IsNullOrWhiteSpace(session.CloudKitGsToken)
            && string.IsNullOrWhiteSpace(session.IdentityToken)
            && string.IsNullOrWhiteSpace(session.GsIdmsToken))
        {
            throw new InvalidOperationException("Sessione senza token CloudKit/MME/Identity.");
        }

        var ids = selectedCategoryIds is { Count: > 0 }
            ? selectedCategoryIds
            : [SyncDataCategoryCatalog.PhotosId];

        Directory.CreateDirectory(outputDirectory);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var outDir = Path.Combine(outputDirectory, $"sync_data_{stamp}");

        // Ripresa dinamica: solo l'ULTIMA sync_data_* locale. Se è incompleta, riusala;
        // se è completa (o assente), crea una nuova cartella con stamp fresco.
        var wantsPhotos = ids.Any(static id =>
            string.Equals(id, SyncDataCategoryCatalog.PhotosId, StringComparison.OrdinalIgnoreCase));
        if (wantsPhotos)
        {
            var latestIncomplete = PhotosCloudSyncService.TryGetLatestIncompletePhotosSession(outputDirectory);
            if (latestIncomplete is not null)
            {
                outDir = latestIncomplete;
                stamp = Path.GetFileName(latestIncomplete)
                    .Replace("sync_data_", "", StringComparison.OrdinalIgnoreCase);
            }
        }

        Directory.CreateDirectory(outDir);
        var runLogPath = Path.Combine(outDir, "sync_data.log");
        var runLogLock = new object();
        void WriteRunLog(string msg)
        {
            var line = $"[{DateTime.Now:HH:mm:ss}] {msg}";
            lock (runLogLock)
            {
                try { File.AppendAllText(runLogPath, line + Environment.NewLine); }
                catch { /* ignore */ }
            }

            log?.Report(msg);
        }

        IProgress<string> teeLog = new Progress<string>(WriteRunLog);

        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;
        var containerResults = new List<SyncDataContainerResult>();

        try
        {
            WriteRunLog($"iCloud Sync Data → {outDir}");
            if (wantsPhotos
                && PhotosCloudSyncService.LooksLikeIncompletePhotosCloudDir(
                    Path.Combine(outDir, "ck", "apple.photos.cloud")))
            {
                WriteRunLog(
                    $"Photos: ultima sessione locale incompleta → ripresa {Path.GetFileName(outDir)} (no re-download)");
            }
            WriteRunLog($"Log file → {runLogPath}");
            await _orchestrator.RefreshAnisetteOnlyAsync(session, teeLog, ct).ConfigureAwait(false);
            _gateway.ClearUnauthorized();
            var anisetteRefresh = new SyncDataAnisetteRefresh(
                _orchestrator.RefreshAnisetteOnlyAsync,
                _gateway);
            anisetteRefresh.MarkFresh();
            File.WriteAllText(
                Path.Combine(outDir, "session.txt"),
                $"dsid={session.Dsid}\r\n" +
                $"partition={session.Partition}\r\n" +
                $"pcsKeySet={session.PcsEscrowedKeySet?.Length ?? 0} B\r\n" +
                $"pcsManatee={session.PcsManateeCompactKeys?.Count ?? 0}\r\n" +
                $"stamp={stamp}\r\n" +
                $"categories={string.Join(",", selectedCategoryIds ?? [])}\r\n" +
                $"runLog={runLogPath}\r\n");

            var includeAccountInfo = SyncDataCategoryCatalog.SelectionIncludesAccountInfo(ids);
            if (includeAccountInfo)
            {
                progress?.Report(new SyncDataProgressReport("Account Info…", 2, IsIndeterminate: true));
                await DumpAccountInfoAsync(session, outDir, teeLog, progress, anisetteRefresh, ct);
            }

            var containers = SyncDataCategoryCatalog.ContainersForSelection(ids);
            if (containers.Count == 0 && !includeAccountInfo)
                throw new InvalidOperationException("Nessuna categoria Sync Data selezionata.");

            if (containers.Count == 0)
            {
                WriteRunLog(
                    includeAccountInfo
                        ? "CloudKit Sync — skip (solo Account Info)"
                        : "CloudKit Sync — skip (nessun container)");
                progress?.Report(new SyncDataProgressReport(
                    "Completato (senza CloudKit container)", 100));
                return new SyncDataProbeResult(outDir, containerResults, runLogPath);
            }

            WriteRunLog($"CloudKit Sync: {containers.Count} container ({string.Join(", ", ids)})…");
            progress?.Report(new SyncDataProgressReport(
                $"CloudKit Sync ({containers.Count} container)…", 5));


            var nContainers = Math.Max(1, containers.Count);
            for (var i = 0; i < containers.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var binding = containers[i];
                var progressBase = 5 + 90.0 * i / nContainers;
                var progressSpan = 90.0 / nContainers;
                progress?.Report(new SyncDataProgressReport(
                    $"Container {i + 1}/{containers.Count}: {ShortContainerName(binding.ContainerId)}",
                    progressBase,
                    PhaseLabel: ShortContainerName(binding.ContainerId),
                    PhasePercent: 0,
                    PhaseIndeterminate: true));
                containerResults.Add(
                    await ProbeContainerAsync(
                        session, binding, outDir, teeLog, progress, anisetteRefresh, ct,
                        buildPhotosRecordMetadata,
                        progressBase, progressSpan,
                        containerIndex: i + 1,
                        containerCount: containers.Count));
                // Distanzia i container: evita cascata cknegrxn → HTTP 503.
                await Task.Delay(900, ct);
            }

            var ok = containerResults.Count(static r => r.Ok);
            WriteRunLog($"Sync Data completato: {ok}/{containerResults.Count} container OK → {outDir}");
            try
            {
                WriteRunLog("Calcolo firme HASH (SHA-256)…");
                await OutputHashManifest.WriteForDirectoryAsync(
                        outDir,
                        new Progress<string>(WriteRunLog),
                        ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                WriteRunLog($"HASH: {ex.Message}");
            }

            progress?.Report(new SyncDataProgressReport(
                $"Completato: {ok}/{containerResults.Count} container OK", 100,
                ClearPhase: true));
            return new SyncDataProbeResult(outDir, containerResults, runLogPath);
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    private async Task DumpAccountInfoAsync(
        ICloudSession session,
        string outDir,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        SyncDataAnisetteRefresh anisetteRefresh,
        CancellationToken ct)
    {
        var dir = Path.Combine(outDir, "accountinfo");
        Directory.CreateDirectory(dir);
        log?.Report("Account Info (GSA appleid + getPhoto)…");
        progress?.Report(new SyncDataProgressReport("Account Info…", 4, IsIndeterminate: true));
        try
        {
            var client = new AccountInfoSyncClient(_http);
            var result = await client.DumpAsync(session, dir, log, anisetteRefresh, ct)
                .ConfigureAwait(false);
            log?.Report(
                $"  Account Info OK: devices={result.DeviceCount} images={result.ImageCount} " +
                $"({result.TotalBytes:N0} B)");
        }
        catch (Exception ex)
        {
            log?.Report($"  Account Info ERRORE: {ex.Message}");
        }
    }

    private async Task<SyncDataContainerResult> ProbeContainerAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string rootOut,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        SyncDataAnisetteRefresh anisetteRefresh,
        CancellationToken ct,
        bool buildPhotosRecordMetadata = false,
        double progressBase = 0,
        double progressSpan = 90,
        int containerIndex = 1,
        int containerCount = 1)
    {
        var shortName = ShortContainerName(binding.ContainerId);
        var outDir = Path.Combine(rootOut, "ck", Sanitize(shortName));
        Directory.CreateDirectory(outDir);
        log?.Report($"—— {binding.ContainerId} ——");

        void Report(
            string detail,
            double frac,
            string phase,
            double? phasePct = null,
            bool phaseIndeterminate = false)
        {
            var overall = progressBase + progressSpan * Math.Clamp(frac, 0, 1);
            progress?.Report(new SyncDataProgressReport(
                $"[{containerIndex}/{containerCount}] {shortName}: {detail}",
                Percent: overall,
                PhaseLabel: phase,
                PhasePercent: phasePct,
                PhaseIndeterminate: phaseIndeterminate));
        }

        try
        {
            await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
            Report("ckAppInit…", 0.02, "ckAppInit", phaseIndeterminate: true);
            await _orchestrator.CkAppInitAsync(session, binding.ContainerId, log, ct);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
                || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            {
                log?.Report("  ckAppInit incompleto — skip");
                Report("ckAppInit incompleto — skip", 1.0, "skip", 100);
                return new SyncDataContainerResult(binding.ContainerId, false, 0, "ckAppInit incompleto");
            }

            File.WriteAllText(
                Path.Combine(outDir, "session.txt"),
                $"container={binding.ContainerId}\r\n" +
                $"bundle={binding.BundleId}\r\n" +
                $"ckUserId={session.CloudKitUserId}\r\n");

            if (binding.ContainerId.Equals("com.apple.photos.cloud", StringComparison.OrdinalIgnoreCase))
            {
                Report("Photos recover…", 0.05, "Photos", phaseIndeterminate: true);
                var photos = new PhotosCloudSyncService(_http, _gateway);
                photos.SetAnisetteRefresh(anisetteRefresh);
                return await photos.RecoverAsync(
                    session, binding, outDir, log, progress, ct,
                    buildRecordMetadata: buildPhotosRecordMetadata);
            }

            if (binding.ContainerId.Equals("com.apple.notes", StringComparison.OrdinalIgnoreCase))
            {
                Report("Notes recover…", 0.05, "Notes", phaseIndeterminate: true);
                var notes = new NotesCloudSyncService(_gateway);
                notes.SetAnisetteRefresh(anisetteRefresh);
                return await notes.RecoverAsync(session, binding, outDir, log, progress, ct);
            }

            var zones = new HashSet<string>(StringComparer.Ordinal);
            long totalBytes = 0;
            var callsContainer = IsCallHistoryContainer(binding.ContainerId);
            var sawHttp503 = false;

            // zone/retrieve solo su zone di sistema CloudKit (niente nomi inventati).
            foreach (var zoneHint in new[] { "default", "_defaultZone" })
            {
                ct.ThrowIfCancellationRequested();
                Report($"zone/retrieve {zoneHint}…", 0.08, "zone/retrieve", phaseIndeterminate: true);
                await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
                var (ok, bytes, names, errNote) = await ZoneRetrieveAsync(
                    session, binding, outDir, zoneHint, log, ct);
                totalBytes += bytes;
                foreach (var z in names)
                    zones.Add(z);
                if (IsHttp503Message(errNote))
                {
                    sawHttp503 = true;
                    // Calls: non martellare anche _defaultZone se default è già 503.
                    if (callsContainer)
                    {
                        log?.Report(
                            "  Calls: HTTP 503 su zone/retrieve — stop retrieve, " +
                            "attesa 10 s prima di zone/sync…");
                        Report("HTTP 503 — attesa…", 0.10, "backoff", phaseIndeterminate: true);
                        await Task.Delay(10_000, ct).ConfigureAwait(false);
                        break;
                    }
                }

                _ = ok;
            }

            // AppDefaultZone: getChanges / record/sync non supportati (ck1e0lk64, ck13ujr18).
            // Solo zone/retrieve sopra; i record vivono nelle custom zone.
            log?.Report(
                "  record/sync _defaultZone skip — AppDefaultZone non supporta getChanges " +
                "(Only custom zones / ck1e0lk64)");

            // Database changes → altre zone
            string? zoneSyncReason = null;
            try
            {
                Report("zone/sync (database changes)…", 0.15, "zone/sync", phaseIndeterminate: true);
                await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
                log?.Report("  zone/sync (database changes)…");
                var (zsyncBytes, zsyncErr, zsyncNames) = await ZoneSyncWithRateLimitRetryAsync(
                    session, binding, outDir, log, ct);
                totalBytes += zsyncBytes;
                zoneSyncReason = zsyncErr;
                if (IsHttp503Message(zsyncErr))
                    sawHttp503 = true;
                foreach (var z in zsyncNames)
                    zones.Add(z);
            }
            catch (Exception ex)
            {
                zoneSyncReason = ex.Message;
                log?.Report($"  zone/sync skip: {ex.Message}");
                if (IsHttp503Message(ex.Message))
                {
                    sawHttp503 = true;
                    Report("zone/sync HTTP 503 — attesa…", 0.16, "backoff", phaseIndeterminate: true);
                    await Task.Delay(callsContainer ? 12_000 : 8_000, ct).ConfigureAwait(false);
                }
            }

            // Default già syncata sopra; qui solo zone custom (no doppio passaggio).
            // metadata_zone = zona sistema CloudKit: spesso solo RetryAfter, zero record utili.
            // NON scartare com.apple.coredata.cloudkit.zone: è la zona dati di Voice Memos
            // (e altri Core Data CloudKit) — blacklistata per errore in fe63242.
            zones.RemoveWhere(IsDefaultZoneName);
            zones.RemoveWhere(IsCloudKitSystemZone);
            zones.RemoveWhere(static z => !IsPlausibleCustomZone(z));

            // Voice Memos: forza zona Core Data + tentativo controllato di metadata_zone
            // (advertised in zone/retrieve; può RetryAfter — RecordSync lo gestisce).
            if (binding.ContainerId.Equals(
                    VoiceMemosAudioDownloader.ContainerId, StringComparison.OrdinalIgnoreCase))
            {
                var before = zones.Count;
                zones.Add(VoiceMemosAudioDownloader.SyncZone);
                zones.Add(VoiceMemosAudioDownloader.MetadataZone);
                if (zones.Count > before)
                {
                    log?.Report(
                        $"  Voice Memos: seed zone " +
                        $"{VoiceMemosAudioDownloader.SyncZone}, " +
                        $"{VoiceMemosAudioDownloader.MetadataZone}");
                }
            }

            if (zones.Count == 0)
            {
                if (callsContainer && IsOptionalFeatureDisabled(zoneSyncReason))
                {
                    log?.Report(
                        "  Calls: CloudKit «optional feature disabled» (ckm4qn70) — " +
                        "questo container non espone Call History. " +
                        "Phone/FaceTime ON ≠ sync CK. Usa backup dispositivo iCloud " +
                        "(CallHistory.store / CallHistoryDB), non Sync Data.");
                    Report("optional feature disabled", 0.9, "Calls", 100);
                }
                else if (callsContainer && sawHttp503)
                {
                    log?.Report(
                        "  Calls: HTTP 503 su ckdatabase — rate-limit/partizione satura. " +
                        "Riprova tra qualche minuto; se poi compare ckm4qn70 il container " +
                        "è disabilitato lato server (nessuna zona da inventare).");
                    Report("HTTP 503 — nessuna zona", 0.9, "Calls", 100);
                }
                else
                {
                    log?.Report(
                        zoneSyncReason is not null
                            ? $"  nessuna custom zone per record/sync — motivo: {zoneSyncReason}"
                            : "  nessuna custom zone per record/sync (zone/retrieve e zone/sync senza zone utili)");
                    Report("nessuna custom zone", 0.85, "zone/sync", 100);
                }
            }
            else
            {
                var zoneList = zones.OrderBy(z => z, StringComparer.Ordinal).ToList();
                log?.Report($"  zone da sync: {string.Join(", ", zoneList)}");
                for (var zi = 0; zi < zoneList.Count; zi++)
                {
                    var zone = zoneList[zi];
                    ct.ThrowIfCancellationRequested();
                    var zoneFrac = 0.20 + 0.55 * (zi / (double)Math.Max(1, zoneList.Count));
                    var zonePhasePct = 100.0 * (zi + 1) / zoneList.Count;
                    Report(
                        $"zona {zi + 1}/{zoneList.Count}: {zone}",
                        zoneFrac, "zone", zonePhasePct);

                    await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
                    Report($"zone/retrieve {zone}…", zoneFrac + 0.02, "zone/retrieve", zonePhasePct);
                    var (_, zoneBytes, _, _) = await ZoneRetrieveAsync(
                        session, binding, outDir, zone, log, ct);
                    totalBytes += zoneBytes;

                    totalBytes += await SyncAndRetrieveZoneAsync(
                        session, binding, outDir, zone, log, anisetteRefresh, ct,
                        progress, Report, zoneFrac + 0.05, zonePhasePct);

                    await Task.Delay(150, ct);
                }
            }

            // PCS decrypt: Escrow KeySet e/o Manatee (CKKS OpenVault / disco).
            if (PcsSessionSeedKeys.HasAny(session))
            {
                Report("PCS decrypt…", 0.80, "PCS", phaseIndeterminate: true);
                try
                {
                    var dec = await Task.Run(
                        () => SyncDataPcsDecryptor.DecryptContainerDirectory(
                            session, outDir, binding.ContainerId, log),
                        ct);
                    if (dec.DecryptedCount > 0)
                        log?.Report($"  → crypto/: {dec.Message}");
                    else if (dec.FieldCount > 0)
                        log?.Report($"  → crypto pending: {dec.Message}");
                }
                catch (Exception ex)
                {
                    log?.Report($"  PCS decrypt skip: {ex.Message}");
                }
            }
            else
            {
                log?.Report(
                    "  PCS decrypt skip — né Escrow KeySet né Manatee " +
                    "(Unlock EscrowedKeys oppure Octagon/CKKS OpenVault)");
            }

            // Voice Memos / Messages: download CKAsset via content.icloud.com dopo PCS.
            var isVoiceMemos = binding.ContainerId.Equals(
                VoiceMemosAudioDownloader.ContainerId, StringComparison.OrdinalIgnoreCase);
            if (isVoiceMemos
                || binding.ContainerId.Equals(
                    VoiceMemosAudioDownloader.MessagesContainerId, StringComparison.OrdinalIgnoreCase))
            {
                var isMessages = binding.ContainerId.Equals(
                    VoiceMemosAudioDownloader.MessagesContainerId,
                    StringComparison.OrdinalIgnoreCase);
                try
                {
                    Report(isMessages ? "MMCS Messages…" : "MMCS Voice Memos…",
                        0.88, "MMCS", phaseIndeterminate: true);
                    await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
                    var dl = isMessages
                        ? VoiceMemosAudioDownloader.ForMessages(_http)
                        : new VoiceMemosAudioDownloader(_http);
                    var n = await dl.DownloadAsync(session, outDir, log, ct).ConfigureAwait(false);
                    if (isMessages && n == 0)
                    {
                        log?.Report(
                            "  Messages: nessun ckAsset MMCS in chiaro. Zone *ManateeZone sono PCS-Manatee — " +
                            "serve CKKS OpenVault (view Manatee) che riesca a unwrap PublicX nei record; " +
                            "poi allegati/blob possono comparire come Asset con auth.");
                    }
                }
                catch (Exception ex)
                {
                    log?.Report($"  MMCS asset download skip: {ex.Message}");
                }
            }

            if (isVoiceMemos)
            {
                try
                {
                    Report("Voice Memos inventory…", 0.94, "inventory", phaseIndeterminate: true);
                    _ = VoiceMemosInventoryBuilder.Build(outDir, log);
                }
                catch (Exception ex)
                {
                    log?.Report($"  Voice Memos inventory skip: {ex.Message}");
                }
            }

            var isMessagesContainer = binding.ContainerId.Equals(
                VoiceMemosAudioDownloader.MessagesContainerId,
                StringComparison.OrdinalIgnoreCase);
            if (isMessagesContainer)
            {
                try
                {
                    Report("Messages inventory…", 0.94, "inventory", phaseIndeterminate: true);
                    _ = MessagesInventoryBuilder.Build(outDir, log);
                    Report("Messages HTML viewer…", 0.96, "viewer", phaseIndeterminate: true);
                    await MessagesHtmlViewerPublisher.PublishAsync(
                        outDir, ownHandles: null, log, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    log?.Report($"  Messages inventory/viewer skip: {ex.Message}");
                }
            }

            Report("completato", 1.0, "done", 100);
            return new SyncDataContainerResult(binding.ContainerId, true, totalBytes, null);
        }
        catch (Exception ex)
        {
            log?.Report($"  ERRORE: {ex.Message}");
            Report($"ERRORE: {ex.Message}", 1.0, "error", 100);
            return new SyncDataContainerResult(binding.ContainerId, false, 0, ex.Message);
        }
    }

    private async Task<(bool Ok, long Bytes, List<string> Zones, string? ErrorNote)> ZoneRetrieveAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string zone,
        IProgress<string>? log,
        CancellationToken ct)
    {
        try
        {
            log?.Report($"  zone/retrieve → {zone}…");
            var body = CloudKitDelimitedRequest.BuildZoneRetrieve(
                session.CloudKitUserId, [zone], container: binding);
            var payload = await _gateway.ZoneRetrieveAsync(session, body, ct, container: binding);
            await SaveAsync(outDir, $"zones_{Sanitize(zone)}", payload, ct);

            var isErr = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err);
            var reason = CloudKitResponseParser.TryGetCloudKitReason(payload);
            var note = isErr
                ? (err ?? reason)
                : (reason ?? CloudKitResponseParser.DescribeCompactPayload(payload));
            log?.Report(
                $"    → {payload.Length:N0} B" +
                (note is null
                    ? ""
                    : isErr || reason is not null && IsLikelyErrorNote(note)
                        ? $" — errore: {note}"
                        : $" — {note}"));

            var zones = new List<string>();
            if (!isErr)
            {
                var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                foreach (var z in WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(strings))
                    zones.Add(z);
                // Se la risposta ha contenuto utile, includi la zona richiesta
                // (mai il solo containerId: non è un zone name).
                if (payload.Length > 160 && !IsDefaultZoneName(zone))
                {
                    var n = WhatsAppCloudKitProbeService.NormalizeZoneName(zone);
                    if (!n.Equals(binding.ContainerId, StringComparison.OrdinalIgnoreCase))
                        zones.Add(n);
                }
            }

            return (!isErr, payload.Length, zones, isErr ? note : null);
        }
        catch (Exception ex)
        {
            log?.Report($"    zone/retrieve {zone}: {ex.Message}");
            return (false, 0, [], ex.Message);
        }
    }

    private const int MaxRecordSyncPages = 24;

    private async Task<(long Bytes, string? Error, List<string> Zones)> ZoneSyncWithRateLimitRetryAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var zones = new List<string>();
        long total = 0;
        string? lastErr = null;

        for (var attempt = 1; attempt <= 2; attempt++)
        {
            var body = CloudKitDelimitedRequest.BuildZoneRetrieveChanges(
                session.CloudKitUserId, container: binding);
            var payload = await _gateway.ZoneChangesAsync(session, body, ct, binding);
            total += payload.Length;
            var tag = attempt == 1 ? "zone_changes" : "zone_changes_retry";
            await SaveAsync(outDir, tag, payload, ct);

            if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var zsyncErr))
            {
                lastErr = zsyncErr
                    ?? CloudKitResponseParser.TryGetCloudKitReason(payload)
                    ?? $"payload errore {payload.Length} B";
                log?.Report($"  zone/sync → {payload.Length:N0} B — errore: {lastErr}");
                if (IsRateLimitReason(lastErr) && attempt < 2)
                {
                    log?.Report("  zone/sync rate-limit (cknegrxn) → attesa 8 s, riprovo…");
                    await Task.Delay(8_000, ct).ConfigureAwait(false);
                    continue;
                }

                return (total, lastErr, zones);
            }

            var note = CloudKitResponseParser.TryGetCloudKitReason(payload)
                ?? CloudKitResponseParser.DescribeCompactPayload(payload);
            log?.Report(
                $"  zone/sync → {payload.Length:N0} B" +
                (note is null ? "" : $" — {note}"));

            var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
            foreach (var z in WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(strings))
                zones.Add(z);
            return (total, null, zones);
        }

        return (total, lastErr, zones);
    }

    private delegate void ContainerProgressReport(
        string detail, double frac, string phase, double? phasePct = null, bool phaseIndeterminate = false);

    /// <summary>
    /// <c>record/sync</c> sulla zona, poi <c>record/retrieve</c> batch sui name emersi.
    /// </summary>
    private async Task<long> SyncAndRetrieveZoneAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string zone,
        IProgress<string>? log,
        SyncDataAnisetteRefresh anisetteRefresh,
        CancellationToken ct,
        IProgress<SyncDataProgressReport>? progress = null,
        ContainerProgressReport? report = null,
        double progressFrac = 0.5,
        double zonePhasePct = 50)
    {
        report?.Invoke($"record/sync {zone}…", progressFrac, "record/sync", zonePhasePct, true);
        await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
        var (syncBytes, recordNames) = await RecordSyncAsync(
            session, binding, outDir, zone, log, ct, report, progressFrac, zonePhasePct);

        long total = syncBytes;
        if (recordNames.Count > 0)
        {
            report?.Invoke(
                $"record/retrieve {zone} ({recordNames.Count})…",
                progressFrac + 0.08, "record/retrieve", zonePhasePct);
            await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
            total += await RecordRetrieveBatchesAsync(
                session, binding, outDir, zone, recordNames, log, anisetteRefresh, ct,
                report, progressFrac + 0.08, zonePhasePct);
        }
        else
        {
            log?.Report($"  record/retrieve skip {zone} — nessun record name da sync");
        }

        return total;
    }

    private async Task<(long Bytes, List<string> RecordNames)> RecordSyncAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string zone,
        IProgress<string>? log,
        CancellationToken ct,
        ContainerProgressReport? report = null,
        double progressFrac = 0.5,
        double zonePhasePct = 50)
    {
        log?.Report($"  record/sync → {zone}…");
        long total = 0;
        byte[]? token = null;
        var retryAfterLeft = 2;
        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            for (var page = 1; page <= MaxRecordSyncPages; page++)
            {
                ct.ThrowIfCancellationRequested();
                report?.Invoke(
                    $"record/sync {zone} p{page}…",
                    progressFrac + 0.01 * Math.Min(page, 8),
                    "record/sync",
                    zonePhasePct);
                var body = CloudKitDelimitedRequest.BuildRecordRetrieveChanges(
                    session.CloudKitUserId, zone, syncContinuationToken: token, binding);
                var payload = await _gateway.RecordChangesAsync(session, body, ct, binding);
                total += payload.Length;
                await SaveAsync(outDir, $"record_sync_{Sanitize(zone)}_p{page}", payload, ct);

                var isErr = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err);
                var reason = CloudKitResponseParser.TryGetCloudKitReason(payload);
                var note = isErr
                    ? (err ?? reason)
                    : (reason ?? CloudKitResponseParser.DescribeCompactPayload(payload));
                log?.Report(
                    $"    → p{page} {payload.Length:N0} B" +
                    (note is null
                        ? ""
                        : isErr || reason is not null && IsLikelyErrorNote(note)
                            ? $" — errore: {note}"
                            : $" — {note}"));
                if (isErr)
                {
                    // RetryAfter / cknegrxn: backoff, poi skip zona.
                    if (IsRetryAfterNote(note) && retryAfterLeft > 0)
                    {
                        retryAfterLeft--;
                        var delayMs = IsRateLimitReason(note)
                            ? (retryAfterLeft == 1 ? 8_000 : 12_000)
                            : (retryAfterLeft == 1 ? 2_000 : 4_000);
                        log?.Report(
                            $"    {(IsRateLimitReason(note) ? "rate-limit" : "RetryAfter")} " +
                            $"→ attesa {delayMs} ms, riprovo…");
                        await Task.Delay(delayMs, ct);
                        page--;
                        continue;
                    }

                    if (IsRetryAfterNote(note))
                        log?.Report($"    rate-limit/RetryAfter persistente — skip {zone}");
                    break;
                }

                foreach (var n in ExtractRecordNamesFromSyncPayload(payload, zone))
                    names.Add(n);

                var cont = CloudKitResponseParser.TryExtractRecordSyncContinuation(payload);
                var stringMore = CloudKitResponseParser.ExtractDiagnosticStrings(payload)
                    .Any(static s => s.Contains("moreComing", StringComparison.OrdinalIgnoreCase));
                var shouldContinue = cont.MoreComing
                                     || (stringMore && cont.SyncContinuationToken is { Length: > 0 });
                if (!shouldContinue || cont.SyncContinuationToken is not { Length: > 0 })
                {
                    if ((cont.MoreComing || stringMore) && cont.SyncContinuationToken is null)
                        log?.Report("    moreComing senza token — stop");
                    break;
                }

                if (token is not null
                    && token.AsSpan().SequenceEqual(cont.SyncContinuationToken))
                {
                    log?.Report("    syncToken invariato — stop");
                    break;
                }

                token = cont.SyncContinuationToken;
                await Task.Delay(120, ct);
            }
        }
        catch (Exception ex)
        {
            log?.Report($"    record/sync {zone}: {ex.Message}");
        }

        var ordered = names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
        if (ordered.Count > 0)
            log?.Report($"    record name da sync: {ordered.Count}");
        return (total, ordered);
    }

    private async Task<long> RecordRetrieveBatchesAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string zone,
        IReadOnlyList<string> recordNames,
        IProgress<string>? log,
        SyncDataAnisetteRefresh anisetteRefresh,
        CancellationToken ct,
        ContainerProgressReport? report = null,
        double progressFrac = 0.6,
        double zonePhasePct = 50)
    {
        if (recordNames.Count == 0)
            return 0;

        var fetchDir = Path.Combine(outDir, $"record_retrieve_{Sanitize(zone)}");
        Directory.CreateDirectory(fetchDir);
        long total = 0;
        var batchCount = (recordNames.Count + RecordRetrieveBatchSize - 1) / RecordRetrieveBatchSize;

        log?.Report(
            $"  record/retrieve → {zone} ({recordNames.Count} record, " +
            $"batch={RecordRetrieveBatchSize})…");

        for (var offset = 0; offset < recordNames.Count; offset += RecordRetrieveBatchSize)
        {
            ct.ThrowIfCancellationRequested();
            var batch = recordNames.Skip(offset).Take(RecordRetrieveBatchSize).ToList();
            var batchIndex = offset / RecordRetrieveBatchSize + 1;
            var batchTag = $"batch{batchIndex:00}";
            var batchPct = 100.0 * batchIndex / Math.Max(1, batchCount);
            report?.Invoke(
                $"record/retrieve {zone} {batchIndex}/{batchCount}…",
                progressFrac + 0.05 * (batchIndex / (double)Math.Max(1, batchCount)),
                "record/retrieve",
                batchPct);

            try
            {
                if (batchIndex == 1 || batchIndex % 4 == 0)
                    await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);

                var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
                    session.CloudKitUserId, zone, batch, container: binding);
                var payload = await _gateway.RecordRetrieveAsync(
                    session, body, ct, container: binding);
                total += payload.Length;
                await File.WriteAllBytesAsync(
                    Path.Combine(fetchDir, $"{batchTag}.bin"), payload, ct);
                await File.WriteAllLinesAsync(
                    Path.Combine(fetchDir, $"{batchTag}_names.txt"), batch, ct);
                var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                await File.WriteAllLinesAsync(
                    Path.Combine(fetchDir, $"{batchTag}_strings.txt"), strings, ct);

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

            await Task.Delay(100, ct);
        }

        return total;
    }

    /// <summary>
    /// Record name tipici da payload record/sync: Core Data / Voice Memos,
    /// Notes, <c>metadata_device_*</c>, UUID standalone.
    /// </summary>
    private static IReadOnlyList<string> ExtractRecordNamesFromSyncPayload(
        byte[] payload, string zone)
    {
        if (payload is not { Length: > 32 })
            return [];

        var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        foreach (var rec in VoiceMemosSyncRecordParser.ParseRecords(payload))
        {
            if (!string.IsNullOrWhiteSpace(rec.RecordName))
                names.Add(rec.RecordName);
        }

        foreach (var dev in VoiceMemosSyncRecordParser.ParseMetadataDevices(payload))
        {
            if (!string.IsNullOrWhiteSpace(dev.RecordName))
                names.Add(dev.RecordName);
        }

        foreach (var rec in NotesSyncRecordParser.ParseRecords(payload))
        {
            if (!string.IsNullOrWhiteSpace(rec.RecordName))
                names.Add(rec.RecordName);
        }

        foreach (var s in CloudKitResponseParser.ExtractDiagnosticStrings(payload))
        {
            if (string.IsNullOrWhiteSpace(s) || s.Length > 200)
                continue;
            if (s.StartsWith('_') || s.StartsWith('$'))
                continue;
            if (s.StartsWith("metadata_device_", StringComparison.OrdinalIgnoreCase))
            {
                names.Add(s);
                continue;
            }

            if (s.Length == 36 && Guid.TryParse(s, out _))
                names.Add(s.ToUpperInvariant());
        }

        names.Remove(zone);
        if (names.Count > 8_000)
        {
            return names
                .OrderBy(n => n, StringComparer.OrdinalIgnoreCase)
                .Take(8_000)
                .ToList();
        }

        return names.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static async Task SaveAsync(string outDir, string tag, byte[] payload, CancellationToken ct)
    {
        await File.WriteAllBytesAsync(Path.Combine(outDir, $"{tag}.bin"), payload, ct);
        var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
        await File.WriteAllLinesAsync(Path.Combine(outDir, $"{tag}_strings.txt"), strings, ct);
    }

    private static bool IsCallHistoryContainer(string containerId) =>
        containerId.Contains("CallHistory", StringComparison.OrdinalIgnoreCase)
        || containerId.Contains("callhistory", StringComparison.OrdinalIgnoreCase);

    private static bool IsOptionalFeatureDisabled(string? note) =>
        note is not null
        && (note.Contains("Optional feature", StringComparison.OrdinalIgnoreCase)
            || note.Contains("ckm4qn70", StringComparison.OrdinalIgnoreCase));

    private static bool IsLikelyErrorNote(string note) =>
        note.Contains("disabled", StringComparison.OrdinalIgnoreCase)
        || note.Contains("not exist", StringComparison.OrdinalIgnoreCase)
        || note.Contains("not support", StringComparison.OrdinalIgnoreCase)
        || note.Contains("Only custom", StringComparison.OrdinalIgnoreCase)
        || note.Contains("Optional feature", StringComparison.OrdinalIgnoreCase)
        || note.Contains("error", StringComparison.OrdinalIgnoreCase)
        || note.Contains("fail", StringComparison.OrdinalIgnoreCase)
        || note.Contains("forbidden", StringComparison.OrdinalIgnoreCase)
        || note.Contains("unauthor", StringComparison.OrdinalIgnoreCase)
        || note.Contains("RetryAfter", StringComparison.OrdinalIgnoreCase)
        || note.Contains("throttl", StringComparison.OrdinalIgnoreCase);

    private static bool IsRetryAfterNote(string? note) =>
        note is not null
        && (note.Contains("RetryAfter", StringComparison.OrdinalIgnoreCase)
            || note.Contains("retry after", StringComparison.OrdinalIgnoreCase)
            || note.Contains("throttl", StringComparison.OrdinalIgnoreCase)
            || note.Equals("retry", StringComparison.OrdinalIgnoreCase)
            || IsRateLimitReason(note));

    /// <summary>
    /// Motivo CloudKit tipico di throttle (~102 B): <c>cknegrxn</c>, poi spesso HTTP 503.
    /// </summary>
    private static bool IsRateLimitReason(string? note) =>
        note is not null
        && (note.Contains("cknegrxn", StringComparison.OrdinalIgnoreCase)
            || note.Contains("RequestRateLimited", StringComparison.OrdinalIgnoreCase)
            || note.Contains("rate limit", StringComparison.OrdinalIgnoreCase)
            || note.Contains("ZoneBusy", StringComparison.OrdinalIgnoreCase)
            || note.Contains("ServiceUnavailable", StringComparison.OrdinalIgnoreCase));

    private static bool IsHttp503Message(string? message) =>
        message is not null
        && (message.Contains("HTTP 503", StringComparison.Ordinal)
            || message.Contains("HTTP 429", StringComparison.Ordinal)
            || message.Contains("HTTP 502", StringComparison.Ordinal));

    private static bool IsDefaultZoneName(string zone) =>
        string.Equals(zone, "_defaultZone", StringComparison.OrdinalIgnoreCase)
        || string.Equals(zone, "default", StringComparison.OrdinalIgnoreCase)
        || string.Equals(zone, "defaultZone", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Zone sistema CloudKit da non passare a record/sync
    /// (Messages <c>metadata_zone</c> → RetryAfter; metadata Core Data senza record app).
    /// <c>com.apple.coredata.cloudkit.zone</c> NON è qui: contiene i record Voice Memos.
    /// </summary>
    private static bool IsCloudKitSystemZone(string zone) =>
        zone.Equals("metadata_zone", StringComparison.OrdinalIgnoreCase)
        || zone.Equals("com.apple.coredata.cloudkit.metadata", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Zone custom su cui ha senso record/sync (no hex fingerprint, no rumore binario).
    /// Voice Memos può re-inserire <c>metadata_zone</c> dopo i filtri (seed dedicato).
    /// </summary>
    private static bool IsPlausibleCustomZone(string zone)
    {
        if (string.IsNullOrWhiteSpace(zone) || IsDefaultZoneName(zone) || IsCloudKitSystemZone(zone))
            return false;
        if (zone.Length >= 16 && zone.All(Uri.IsHexDigit))
            return false;
        return WhatsAppCloudKitProbeService.LooksLikeRealZoneName(zone);
    }

    private static string ShortContainerName(string containerId)
    {
        var parts = containerId.Split('.');
        return parts.Length >= 2 ? string.Join('.', parts.TakeLast(Math.Min(3, parts.Length))) : containerId;
    }

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_');
        return sb.ToString();
    }
}

public sealed record SyncDataProbeResult(
    string OutputDirectory,
    IReadOnlyList<SyncDataContainerResult> Containers,
    string? RunLogPath = null);

public sealed record SyncDataContainerResult(
    string ContainerId,
    bool Ok,
    long Bytes,
    string? Error);

/// <summary>Stato Sync Data per progress bar UI (overall + fase corrente download/decrypt).</summary>
public sealed record SyncDataProgressReport(
    string Status,
    double? Percent = null,
    bool IsIndeterminate = false,
    /// <summary>Etichetta fase corrente (es. Download, Decrypt, CPL PCS).</summary>
    string? PhaseLabel = null,
    /// <summary>Avanzamento 0–100 della fase corrente; null = non aggiornare la barra fase.</summary>
    double? PhasePercent = null,
    bool PhaseIndeterminate = false,
    /// <summary>Se true nasconde/azzera la barra di fase.</summary>
    bool ClearPhase = false);
