using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.WhatsApp;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Probe iCloud Sync Data (capture <c>capture_http_20260802_054842</c>):
/// Escrow KeySet già in sessione → per ogni container
/// ckAppInit → zone/retrieve → record/sync (download payload grezzi).
/// </summary>
public sealed class ICloudSyncDataProbeService
{
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


            for (var i = 0; i < containers.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var binding = containers[i];
                progress?.Report(new SyncDataProgressReport(
                    $"Container {i + 1}/{containers.Count}: {ShortContainerName(binding.ContainerId)}",
                    5 + 90.0 * i / Math.Max(1, containers.Count)));
                containerResults.Add(
                    await ProbeContainerAsync(
                        session, binding, outDir, teeLog, progress, anisetteRefresh, ct,
                        buildPhotosRecordMetadata));
                await Task.Delay(250, ct);
            }

            var ok = containerResults.Count(static r => r.Ok);
            WriteRunLog($"Sync Data completato: {ok}/{containerResults.Count} container OK → {outDir}");
            progress?.Report(new SyncDataProgressReport(
                $"Completato: {ok}/{containerResults.Count} container OK", 100));
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
        bool buildPhotosRecordMetadata = false)
    {
        var shortName = ShortContainerName(binding.ContainerId);
        var outDir = Path.Combine(rootOut, "ck", Sanitize(shortName));
        Directory.CreateDirectory(outDir);
        log?.Report($"—— {binding.ContainerId} ——");


        try
        {
            await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
            progress?.Report(new SyncDataProgressReport($"ckAppInit {shortName}…", IsIndeterminate: true));
            await _orchestrator.CkAppInitAsync(session, binding.ContainerId, log, ct);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
                || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            {
                log?.Report("  ckAppInit incompleto — skip");
                return new SyncDataContainerResult(binding.ContainerId, false, 0, "ckAppInit incompleto");
            }

            File.WriteAllText(
                Path.Combine(outDir, "session.txt"),
                $"container={binding.ContainerId}\r\n" +
                $"bundle={binding.BundleId}\r\n" +
                $"ckUserId={session.CloudKitUserId}\r\n");

            if (binding.ContainerId.Equals("com.apple.photos.cloud", StringComparison.OrdinalIgnoreCase))
            {
                var photos = new PhotosCloudSyncService(_http, _gateway);
                photos.SetAnisetteRefresh(anisetteRefresh);
                return await photos.RecoverAsync(
                    session, binding, outDir, log, progress, ct,
                    buildRecordMetadata: buildPhotosRecordMetadata);
            }

            if (binding.ContainerId.Equals("com.apple.notes", StringComparison.OrdinalIgnoreCase))
            {
                var notes = new NotesCloudSyncService(_gateway);
                notes.SetAnisetteRefresh(anisetteRefresh);
                return await notes.RecoverAsync(session, binding, outDir, log, progress, ct);
            }

            var zones = new HashSet<string>(StringComparer.Ordinal);
            long totalBytes = 0;

            // zone/retrieve su default + _defaultZone (come / CloudDocs).
            foreach (var zoneHint in new[] { "default", "_defaultZone", binding.ContainerId })
            {
                ct.ThrowIfCancellationRequested();
                await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
                var (ok, bytes, names) = await ZoneRetrieveAsync(
                    session, binding, outDir, zoneHint, log, ct);
                totalBytes += bytes;
                foreach (var z in names)
                    zones.Add(z);
                _ = ok;
            }

            // Database changes → altre zone
            try
            {
                await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
                log?.Report("  zone/sync (database changes)…");
                var body = CloudKitDelimitedRequest.BuildZoneRetrieveChanges(
                    session.CloudKitUserId, container: binding);
                var payload = await _gateway.ZoneChangesAsync(session, body, ct, binding);
                totalBytes += payload.Length;
                await SaveAsync(outDir, "zone_changes", payload, ct);
                log?.Report($"  zone/sync → {payload.Length:N0} B");
                if (!CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _))
                {
                    var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                    foreach (var z in WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(strings))
                        zones.Add(z);
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  zone/sync skip: {ex.Message}");
            }

            if (zones.Count == 0)
            {
                // Fallback: prova comunque _defaultZone per record/sync (alcuni store rispondono).
                zones.Add("_defaultZone");
            }

            log?.Report($"  zone da sync: {string.Join(", ", zones.OrderBy(z => z, StringComparer.Ordinal))}");
            foreach (var zone in zones.OrderBy(z => z, StringComparer.Ordinal))
            {
                ct.ThrowIfCancellationRequested();
                await anisetteRefresh.EnsureFreshAsync(session, log, ct).ConfigureAwait(false);
                totalBytes += await RecordSyncAsync(session, binding, outDir, zone, log, ct);
                await Task.Delay(150, ct);
            }

            // PCS decrypt: Escrow KeySet e/o Manatee (CKKS OpenVault / disco).
            if (PcsSessionSeedKeys.HasAny(session))
            {
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

            return new SyncDataContainerResult(binding.ContainerId, true, totalBytes, null);
        }
        catch (Exception ex)
        {
            log?.Report($"  ERRORE: {ex.Message}");
            return new SyncDataContainerResult(binding.ContainerId, false, 0, ex.Message);
        }
    }

    private async Task<(bool Ok, long Bytes, List<string> Zones)> ZoneRetrieveAsync(
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

            var note = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err)
                ? err
                : CloudKitResponseParser.DescribeCompactPayload(payload);
            log?.Report($"    → {payload.Length:N0} B" + (note is null ? "" : $" — {note}"));

            var zones = new List<string>();
            if (!CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _))
            {
                var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                foreach (var z in WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(strings))
                    zones.Add(z);
                // Se la risposta ha contenuto utile, includi anche la zona richiesta.
                if (payload.Length > 160 && !IsDefaultZoneName(zone))
                    zones.Add(WhatsAppCloudKitProbeService.NormalizeZoneName(zone));
                else if (payload.Length > 400)
                    zones.Add("_defaultZone");
            }

            return (!CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _), payload.Length, zones);
        }
        catch (Exception ex)
        {
            log?.Report($"    zone/retrieve {zone}: {ex.Message}");
            return (false, 0, []);
        }
    }

    private async Task<long> RecordSyncAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string zone,
        IProgress<string>? log,
        CancellationToken ct)
    {
        log?.Report($"  record/sync → {zone}…");
        long total = 0;
        try
        {
            var body = CloudKitDelimitedRequest.BuildRecordRetrieveChanges(
                session.CloudKitUserId, zone, syncContinuationToken: null, binding);
            var payload = await _gateway.RecordChangesAsync(session, body, ct, binding);
            total = payload.Length;
            await SaveAsync(outDir, $"record_sync_{Sanitize(zone)}_p1", payload, ct);

            var note = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err)
                ? err
                : CloudKitResponseParser.DescribeCompactPayload(payload);
            log?.Report($"    → {payload.Length:N0} B" + (note is null ? "" : $" — {note}"));
            if (!CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _)
                && CloudKitResponseParser.ResponseIndicatesMoreResults(payload))
            {
                log?.Report("    moreComing — stop (serve syncToken parser)");
            }
        }
        catch (Exception ex)
        {
            log?.Report($"    record/sync {zone}: {ex.Message}");
        }

        return total;
    }

    private static async Task SaveAsync(string outDir, string tag, byte[] payload, CancellationToken ct)
    {
        await File.WriteAllBytesAsync(Path.Combine(outDir, $"{tag}.bin"), payload, ct);
        var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
        await File.WriteAllLinesAsync(Path.Combine(outDir, $"{tag}_strings.txt"), strings, ct);
    }

    private static bool IsDefaultZoneName(string zone) =>
        string.Equals(zone, "_defaultZone", StringComparison.OrdinalIgnoreCase)
        || string.Equals(zone, "default", StringComparison.OrdinalIgnoreCase);

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
