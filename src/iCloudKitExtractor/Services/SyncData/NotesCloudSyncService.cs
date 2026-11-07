using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.WhatsApp;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Ramo Notes di iCloud Sync Data (<c>capture_syncdata_notes_20260827_125749</c>):
/// ckAppInit <c>com.apple.notes</c> (già fatto dal probe) →
/// <c>zone/retrieve</c> (<c>default</c>) → <c>zone/retrieve</c> (Notes) →
/// record/sync+retrieve (Notes) → PCS decrypt.
/// (AppDefaultZone: getChanges non supportato.)
/// </summary>
public sealed class NotesCloudSyncService
{
    public const string NotesZone = "Notes";
    private const int MaxSyncPages = 40;
    private const int RecordRetrieveBatchSize = 8;

    private readonly CloudKitGatewayClient _gateway;
    private SyncDataAnisetteRefresh? _anisetteRefresh;

    public NotesCloudSyncService(CloudKitGatewayClient gateway) =>
        _gateway = gateway;

    public void SetAnisetteRefresh(SyncDataAnisetteRefresh? refresh) =>
        _anisetteRefresh = refresh;

    private Task EnsureAnisetteFreshAsync(
        ICloudSession session,
        IProgress<string>? log,
        CancellationToken ct,
        bool force = false) =>
        _anisetteRefresh is null
            ? Task.CompletedTask
            : _anisetteRefresh.EnsureFreshAsync(session, log, ct, force);

    public async Task<SyncDataContainerResult> RecoverAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct)
    {
        Directory.CreateDirectory(outDir);
        long totalBytes = 0;

        try
        {
            log?.Report($"  Notes CK → zona {NotesZone}");
            progress?.Report(new SyncDataProgressReport(
                "Notes: zone/retrieve…", 10,
                PhaseLabel: "Notes",
                PhaseIndeterminate: true));


            await EnsureAnisetteFreshAsync(session, log, ct).ConfigureAwait(false);

            // wo 186: zone/retrieve su "default" → risposta include Notes / Metadata / _defaultZone.
            byte[]? zonePayload = null;
            try
            {
                var zoneBody = CloudKitDelimitedRequest.BuildZoneRetrieve(
                    session.CloudKitUserId, ["default"], container: binding);
                zonePayload = await _gateway.ZoneRetrieveAsync(session, zoneBody, ct, container: binding);
                totalBytes += zonePayload.Length;
                await File.WriteAllBytesAsync(
                    Path.Combine(outDir, "zones_default.bin"), zonePayload, ct);
                var strings = CloudKitResponseParser.ExtractDiagnosticStrings(zonePayload);
                await File.WriteAllLinesAsync(
                    Path.Combine(outDir, "zones_default_strings.txt"), strings, ct);

                var note = CloudKitResponseParser.IsCloudKitErrorPayload(zonePayload, out var zerr)
                    ? zerr
                    : CloudKitResponseParser.DescribeCompactPayload(zonePayload);
                log?.Report(
                    $"  zone/retrieve default → {zonePayload.Length:N0} B" +
                    (note is null ? "" : $" — {note}"));

            }
            catch (Exception ex)
            {
                log?.Report($"  zone/retrieve default skip: {ex.Message}");
            }

            log?.Report(
                "  record/sync _defaultZone skip — AppDefaultZone non supporta getChanges");

            var syncZone = ResolveNotesZone(zonePayload);

            // zone/retrieve sulla zona Notes prima di record/sync.
            try
            {
                await EnsureAnisetteFreshAsync(session, log, ct).ConfigureAwait(false);
                log?.Report($"  zone/retrieve → {syncZone}…");
                var namedBody = CloudKitDelimitedRequest.BuildZoneRetrieve(
                    session.CloudKitUserId, [syncZone], container: binding);
                var namedPayload = await _gateway.ZoneRetrieveAsync(
                    session, namedBody, ct, container: binding);
                totalBytes += namedPayload.Length;
                await File.WriteAllBytesAsync(
                    Path.Combine(outDir, $"zones_{Sanitize(syncZone)}.bin"), namedPayload, ct);
                var namedStrings = CloudKitResponseParser.ExtractDiagnosticStrings(namedPayload);
                await File.WriteAllLinesAsync(
                    Path.Combine(outDir, $"zones_{Sanitize(syncZone)}_strings.txt"),
                    namedStrings, ct);
                var namedNote = CloudKitResponseParser.IsCloudKitErrorPayload(namedPayload, out var nerr)
                    ? nerr
                    : CloudKitResponseParser.DescribeCompactPayload(namedPayload);
                log?.Report(
                    $"    → {namedPayload.Length:N0} B" +
                    (namedNote is null ? "" : $" — {namedNote}"));
            }
            catch (Exception ex)
            {
                log?.Report($"  zone/retrieve {syncZone} skip: {ex.Message}");
            }

            totalBytes += await SyncAndRetrieveNamedZoneAsync(
                session, binding, outDir, syncZone, log, progress, ct,
                progressLabel: "Notes");

            if (PcsSessionSeedKeys.HasAny(session))
            {
                progress?.Report(new SyncDataProgressReport(
                    "Notes: PCS decrypt…", 92,
                    PhaseLabel: "Notes PCS",
                    PhaseIndeterminate: true));
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
                    "  PCS decrypt skip — né Escrow KeySet né Manatee");
            }

            progress?.Report(new SyncDataProgressReport(
                "Notes: Notes.db…", 96,
                PhaseLabel: "Notes DB",
                PhaseIndeterminate: true));
            try
            {
                var cryptoRoot = Path.Combine(outDir, "crypto");
                if (Directory.Exists(cryptoRoot)
                    && Directory.EnumerateFileSystemEntries(cryptoRoot).Any())
                {
                    var built = await NotesLibraryBuilder.BuildAsync(outDir, log, ct);
                    progress?.Report(new SyncDataProgressReport(
                        "Notes: HTML viewer…", 97,
                        PhaseLabel: "Notes viewer",
                        PhaseIndeterminate: true));
                    await NotesHtmlViewerPublisher.PublishAsync(outDir, log, ct)
                        .ConfigureAwait(false);
                    _ = built;
                }
                else
                {
                    log?.Report("  Notes.db skip: crypto/ assente");
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  Notes.db/viewer skip: {ex.Message}");
            }

            progress?.Report(new SyncDataProgressReport(
                $"Notes: ok ({totalBytes:N0} B)", 98, ClearPhase: true));
            return new SyncDataContainerResult(binding.ContainerId, true, totalBytes, null);
        }
        catch (Exception ex)
        {
            log?.Report($"  Notes ERRORE: {ex.Message}");
                        return new SyncDataContainerResult(binding.ContainerId, false, totalBytes, ex.Message);
        }
    }

    private async Task<long> SyncAndRetrieveNamedZoneAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string zone,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct,
        string progressLabel)
    {
        log?.Report($"  record/sync → {zone}…");
        progress?.Report(new SyncDataProgressReport(
            $"{progressLabel}: record/sync…",
            PhaseLabel: progressLabel,
            PhaseIndeterminate: true));

        long total = 0;
        byte[]? token = null;
        var pages = 0;
        var recordNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var page = 1; page <= MaxSyncPages; page++)
        {
            ct.ThrowIfCancellationRequested();
            await EnsureAnisetteFreshAsync(session, log, ct).ConfigureAwait(false);

            var body = CloudKitDelimitedRequest.BuildNotesRecordRetrieveChanges(
                session.CloudKitUserId, zone, token, binding);

            byte[] payload;
            try
            {
                payload = await _gateway.RecordChangesAsync(session, body, ct, binding);
            }
            catch (Exception ex)
            {
                log?.Report($"    record/sync p{page}: {ex.Message}");
                break;
            }

            total += payload.Length;
            pages++;
            var tag = $"record_sync_{Sanitize(zone)}_p{page}";
            await File.WriteAllBytesAsync(Path.Combine(outDir, $"{tag}.bin"), payload, ct);
            var pageStrings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
            await File.WriteAllLinesAsync(
                Path.Combine(outDir, $"{tag}_strings.txt"), pageStrings, ct);

            var pageNote = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err)
                ? err
                : CloudKitResponseParser.DescribeCompactPayload(payload);
            log?.Report(
                $"    → p{page} {payload.Length:N0} B" +
                (pageNote is null ? "" : $" — {pageNote}"));

            if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _))
                break;

            // Solo UUID Note/Folder/… veri. I suffissi di Note_UserSpecific::…::UUID
            // non sono record name CloudKit → ck1onjkgg se richiesti da soli.
            foreach (var name in NotesSyncRecordParser.RetrieveRecordNames(payload))
                recordNames.Add(name);

            var cont = CloudKitResponseParser.TryExtractRecordSyncContinuation(payload);
            var stringMore = pageStrings.Any(static s =>
                s.Contains("moreComing", StringComparison.OrdinalIgnoreCase));
            var shouldContinue = cont.MoreComing
                                 || (stringMore && cont.SyncContinuationToken is { Length: > 0 });
            if (!shouldContinue || cont.SyncContinuationToken is not { Length: > 0 })
                break;

            if (token is not null
                && token.AsSpan().SequenceEqual(cont.SyncContinuationToken))
                break;

            token = cont.SyncContinuationToken;
            await Task.Delay(120, ct);
        }

        log?.Report(
            $"  {zone} record/sync: {pages} pagina/e, record name={recordNames.Count}");

        if (recordNames.Count == 0)
        {
            log?.Report($"  record/retrieve skip {zone} — nessun record name da sync");
            return total;
        }

        total += await RecordRetrieveBatchesAsync(
            session, binding, outDir, zone,
            recordNames.OrderBy(n => n, StringComparer.OrdinalIgnoreCase).ToList(),
            log, progress, ct, progressLabel);
        return total;
    }

    private async Task<long> RecordRetrieveBatchesAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string zone,
        IReadOnlyList<string> recordNames,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct,
        string progressLabel = "Notes retrieve")
    {
        var fetchDir = Path.Combine(outDir, $"record_retrieve_{Sanitize(zone)}");
        Directory.CreateDirectory(fetchDir);
        long total = 0;
        var batchCount = (recordNames.Count + RecordRetrieveBatchSize - 1) / RecordRetrieveBatchSize;

        log?.Report(
            $"  record/retrieve → {zone} ({recordNames.Count} record, " +
            $"batch={RecordRetrieveBatchSize})…");
        progress?.Report(new SyncDataProgressReport(
            $"{progressLabel}: record/retrieve ({recordNames.Count})…",
            84,
            PhaseLabel: progressLabel,
            PhasePercent: 0));

        for (var offset = 0; offset < recordNames.Count; offset += RecordRetrieveBatchSize)
        {
            ct.ThrowIfCancellationRequested();
            var batch = recordNames.Skip(offset).Take(RecordRetrieveBatchSize).ToList();
            var batchIndex = offset / RecordRetrieveBatchSize + 1;
            var batchTag = $"batch{batchIndex:00}";

            try
            {
                if (batchIndex == 1 || batchIndex % 4 == 0)
                    await EnsureAnisetteFreshAsync(session, log, ct).ConfigureAwait(false);

                progress?.Report(new SyncDataProgressReport(
                    $"{progressLabel}: record/retrieve {batchIndex}/{batchCount}…",
                    Math.Min(90, 84 + batchIndex),
                    PhaseLabel: progressLabel,
                    PhasePercent: 100.0 * batchIndex / Math.Max(1, batchCount)));

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

                // Batch misti: alcuni UUID ok, altri ck1onjkgg — non etichettare tutto come errore.
                var notFound = strings.Count(static s =>
                    s.Contains("Record not found", StringComparison.OrdinalIgnoreCase));
                var note = notFound > 0
                    ? $"Record not found×{notFound}" +
                      (strings.Any(static s =>
                          s.Contains("ck1onjkgg", StringComparison.OrdinalIgnoreCase))
                          ? " (ck1onjkgg)"
                          : "")
                    : CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err)
                        ? err
                        : CloudKitResponseParser.DescribeCompactPayload(payload);
                var hasEncrypted = strings.Any(static s =>
                    s.Contains("Encrypted", StringComparison.OrdinalIgnoreCase));
                log?.Report(
                    $"    {batchTag}: {batch.Count} record → {payload.Length:N0} B" +
                    (hasEncrypted ? " [cipher]" : "") +
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
    /// Preferisci zona <c>Notes</c> se presente nella zone/retrieve; altrimenti hardcode.
    /// </summary>
    private static string ResolveNotesZone(byte[]? zonePayload)
    {
        if (zonePayload is { Length: > 0 })
        {
            var names = CloudKitResponseParser.ExtractDiagnosticStrings(zonePayload)
                .Select(WhatsAppCloudKitProbeService.NormalizeZoneName)
                .Where(static s => !string.IsNullOrWhiteSpace(s))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();

            if (names.Any(static s => s.Equals(NotesZone, StringComparison.OrdinalIgnoreCase)))
                return NotesZone;

            // Evita Metadata / default come target sync (synca solo Notes).
            foreach (var z in WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(names))
            {
                if (z.Equals("Metadata", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (z.Equals("_defaultZone", StringComparison.OrdinalIgnoreCase)
                    || z.Equals("default", StringComparison.OrdinalIgnoreCase))
                    continue;
                return z;
            }
        }

        return NotesZone;
    }

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        return sb.ToString();
    }

}
