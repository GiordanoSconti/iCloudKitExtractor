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
/// <c>zone/retrieve</c> (<c>default</c>) → zona <c>Notes</c> →
/// <c>record/sync</c> paginato (<c>syncContinuationToken</c>) → PCS decrypt.
/// </summary>
public sealed class NotesCloudSyncService
{
    public const string NotesZone = "Notes";
    private const int MaxSyncPages = 40;

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

            var syncZone = ResolveNotesZone(zonePayload);
            log?.Report($"  record/sync → {syncZone}…");

            byte[]? token = null;
            var pages = 0;
            for (var page = 1; page <= MaxSyncPages; page++)
            {
                ct.ThrowIfCancellationRequested();
                await EnsureAnisetteFreshAsync(session, log, ct).ConfigureAwait(false);
                progress?.Report(new SyncDataProgressReport(
                    $"Notes: record/sync pagina {page}…",
                    Math.Min(88, 20 + page * 8),
                    PhaseLabel: "Notes sync",
                    PhasePercent: 100.0 * page / MaxSyncPages));

                var body = CloudKitDelimitedRequest.BuildNotesRecordRetrieveChanges(
                    session.CloudKitUserId, syncZone, token, binding);

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

                totalBytes += payload.Length;
                pages++;
                var tag = $"record_sync_{Sanitize(syncZone)}_p{page}";
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
                {
                                        break;
                }

                var cont = CloudKitResponseParser.TryExtractRecordSyncContinuation(payload);
                var stringMore = pageStrings.Any(static s =>
                    s.Contains("moreComing", StringComparison.OrdinalIgnoreCase));

                var shouldContinue = cont.MoreComing
                                     || (stringMore && cont.SyncContinuationToken is { Length: > 0 });
                if (!shouldContinue
                    || cont.SyncContinuationToken is not { Length: > 0 })
                {
                    if ((cont.MoreComing || stringMore) && cont.SyncContinuationToken is null)
                        log?.Report("    moreComing senza token — stop");
                    break;
                }

                // Evita loop se il server ripete lo stesso token.
                if (token is not null
                    && token.AsSpan().SequenceEqual(cont.SyncContinuationToken))
                {
                    log?.Report("    syncToken invariato — stop");
                    break;
                }

                token = cont.SyncContinuationToken;
                await Task.Delay(120, ct);
            }

            log?.Report($"  Notes record/sync: {pages} pagina/e");

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
                }
                else
                {
                    log?.Report("  Notes.db skip: crypto/ assente");
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  Notes.db skip: {ex.Message}");
                            }


            progress?.Report(new SyncDataProgressReport(
                $"Notes: ok pages={pages}", 98, ClearPhase: true));
            return new SyncDataContainerResult(binding.ContainerId, true, totalBytes, null);
        }
        catch (Exception ex)
        {
            log?.Report($"  Notes ERRORE: {ex.Message}");
                        return new SyncDataContainerResult(binding.ContainerId, false, totalBytes, ex.Message);
        }
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
