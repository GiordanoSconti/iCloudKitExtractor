using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.WhatsApp;

namespace iCloudKitExtractor.Services.CloudKit;

/// <summary>
/// Laboratory CloudKit experiments: share graph, change-token timeline,
/// third-party container atlas. Read-only; restores session tokens.
/// </summary>
public sealed class CloudKitLaboratoryService
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static readonly Regex IsoDate = new(
        @"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?",
        RegexOptions.Compiled);

    private readonly ICloudBackupOrchestrator _orchestrator;
    private readonly HttpClient _http;

    public CloudKitLaboratoryService(ICloudBackupOrchestrator orchestrator, HttpClient http)
    {
        _orchestrator = orchestrator;
        _http = http;
    }

    // ─── Share graph ─────────────────────────────────────────────────────────

    public sealed record ShareEdge(
        string ContainerId,
        string Label,
        string Zone,
        IReadOnlyList<string> Signals,
        int ZoneSyncBytes,
        bool RecordSyncOk,
        int RecordSyncBytes,
        IReadOnlyList<string> Participants);

    public sealed record ShareGraphResult(
        IReadOnlyList<ShareEdge> Edges,
        int ContainersOk,
        int ShareZones,
        string ReportText,
        string? OutputDirectory,
        string? JsonPath,
        string? CsvPath);

    public static IReadOnlyList<(string ContainerId, string Label, string BundleId)> ShareCandidates { get; } =
    [
        ("com.apple.notes", "Notes", "com.apple.Notes"),
        ("com.apple.clouddocs", "iCloud Drive", "com.apple.CloudDocs"),
        ("com.apple.photos.cloud", "Photos", "com.apple.Photos"),
        ("com.apple.Home", "Home", "com.apple.Home"),
        ("com.apple.HomeKit", "HomeKit", "com.apple.Home"),
        ("com.apple.reminders", "Reminders", "com.apple.reminders"),
        ("com.apple.Reminders", "Reminders (R)", "com.apple.reminders"),
        ("com.apple.freeform", "Freeform", "com.apple.freeform"),
        ("com.apple.mobilecal", "Calendar", "com.apple.mobilecal"),
        ("com.apple.SafariShared.WBSCloudBookmarksStore", "Safari Bookmarks", "com.apple.SafariBookmarksSyncAgent"),
        ("com.apple.messages.cloud", "Messages", "com.apple.imagent"),
    ];

    public async Task<ShareGraphResult> ProbeShareGraphAsync(
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        EnsureSession(session);
        var gateway = new CloudKitGatewayClient(_http);
        var edges = new List<ShareEdge>();
        var containersOk = 0;
        using var scope = new SessionCloudKitScope(session);

        log?.Report($"Share graph — {ShareCandidates.Count} containers…");
        foreach (var (containerId, label, bundleId) in ShareCandidates)
        {
            ct.ThrowIfCancellationRequested();
            log?.Report($"  {containerId}…");
            scope.Restore();
            var status = await TryInitAsync(session, containerId, ct).ConfigureAwait(false);
            if (status != 200)
            {
                log?.Report($"    HTTP {status}");
                await Task.Delay(100, ct).ConfigureAwait(false);
                continue;
            }

            containersOk++;
            var binding = new CloudKitContainerBinding(containerId, bundleId);
            var zone = await ZoneSyncAsync(gateway, session, binding, ct).ConfigureAwait(false);
            if (!zone.Ok)
            {
                log?.Report($"    zone/sync fail: {zone.Note}");
                await Task.Delay(120, ct).ConfigureAwait(false);
                continue;
            }

            var shareZones = zone.Zones.Where(LooksLikeShareZone).ToList();
            if (shareZones.Count == 0 && zone.ShareSignals.Count > 0)
                shareZones.Add("(signals-only)");

            if (shareZones.Count == 0)
            {
                log?.Report($"    no share-like zones ({zone.Zones.Count} zones)");
                await Task.Delay(120, ct).ConfigureAwait(false);
                continue;
            }

            foreach (var z in shareZones.Take(8))
            {
                IReadOnlyList<string> participants = [];
                var recOk = false;
                var recBytes = 0;
                if (z != "(signals-only)")
                {
                    var rec = await RecordSyncSampleAsync(
                            gateway, session, binding, z, newestFirst: true, ct)
                        .ConfigureAwait(false);
                    recOk = rec.Ok;
                    recBytes = rec.Bytes;
                    participants = ExtractParticipants(rec.Strings);
                }

                var signals = zone.ShareSignals
                    .Concat(participants.Select(p => "participant:" + Trunc(p, 40)))
                    .Distinct(StringComparer.OrdinalIgnoreCase)
                    .Take(16)
                    .ToList();

                edges.Add(new ShareEdge(
                    containerId, label, z, signals, zone.Bytes, recOk, recBytes, participants));
                log?.Report(
                    $"    ◈ {z} signals={signals.Count} participants={participants.Count}");
            }

            await Task.Delay(150, ct).ConfigureAwait(false);
        }

        scope.Restore();
        var report = FormatShareReport(edges, containersOk);
        var outDir = EnsureDir(outputDirectory);
        var json = Path.Combine(outDir, "share_graph.json");
        var csv = Path.Combine(outDir, "share_graph.csv");
        await File.WriteAllTextAsync(json, JsonSerializer.Serialize(new
        {
            generatedAt = DateTimeOffset.UtcNow,
            containersOk,
            shareZones = edges.Count,
            edges
        }, JsonOpts), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(csv, BuildShareCsv(edges), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(Path.Combine(outDir, "share_graph.txt"), report, ct)
            .ConfigureAwait(false);
        log?.Report($"  share graph → {outDir}");

        return new ShareGraphResult(
            edges, containersOk, edges.Count, report, outDir, json, csv);
    }

    // ─── Change timeline ─────────────────────────────────────────────────────

    public sealed record TimelineEvent(
        string ContainerId,
        string Zone,
        string? WhenIso,
        string Kind,
        string Detail);

    public sealed record TimelineToken(
        string ContainerId,
        string Zone,
        string TokenBase64,
        int SampleRecords,
        DateTimeOffset CapturedAt);

    public sealed record TimelineResult(
        IReadOnlyList<TimelineEvent> Events,
        IReadOnlyList<TimelineToken> Tokens,
        int ContainersOk,
        int ZonesSampled,
        int DaysWindow,
        string ReportText,
        string? OutputDirectory,
        string? JsonPath,
        string? CsvPath);

    public static IReadOnlyList<(string ContainerId, string Label, string BundleId)> TimelineCandidates { get; } =
    [
        ("com.apple.notes", "Notes", "com.apple.Notes"),
        ("com.apple.photos.cloud", "Photos", "com.apple.Photos"),
        ("com.apple.clouddocs", "iCloud Drive", "com.apple.CloudDocs"),
        ("com.apple.messages.cloud", "Messages", "com.apple.imagent"),
        ("com.apple.VoiceMemosContainer", "Voice Memos", "com.apple.voicememod"),
        ("com.apple.CallHistory", "Call History", "com.apple.callhistory.sync-helper"),
        ("com.apple.SafariShared.CloudTabs", "Safari Cloud Tabs", "com.apple.SafariBookmarksSyncAgent"),
        ("com.apple.reminders", "Reminders", "com.apple.reminders"),
    ];

    public async Task<TimelineResult> ProbeTimelineAsync(
        ICloudSession session,
        string outputDirectory,
        int days = 14,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        EnsureSession(session);
        if (days < 1)
            days = 1;
        if (days > 365)
            days = 365;

        var gateway = new CloudKitGatewayClient(_http);
        var events = new List<TimelineEvent>();
        var tokens = new List<TimelineToken>();
        var containersOk = 0;
        var zonesSampled = 0;
        var cutoff = DateTimeOffset.UtcNow.AddDays(-days);
        using var scope = new SessionCloudKitScope(session);

        log?.Report($"Change timeline — last {days} days, {TimelineCandidates.Count} containers…");
        foreach (var (containerId, label, bundleId) in TimelineCandidates)
        {
            ct.ThrowIfCancellationRequested();
            log?.Report($"  {containerId}…");
            scope.Restore();
            var status = await TryInitAsync(session, containerId, ct).ConfigureAwait(false);
            if (status != 200)
            {
                log?.Report($"    HTTP {status}");
                await Task.Delay(100, ct).ConfigureAwait(false);
                continue;
            }

            containersOk++;
            var binding = new CloudKitContainerBinding(containerId, bundleId);
            var zone = await ZoneSyncAsync(gateway, session, binding, ct).ConfigureAwait(false);
            if (!zone.Ok || zone.Zones.Count == 0)
            {
                // Still try _defaultZone / CoreData default.
                var fallback = new List<string> { "_defaultZone", CloudKitContainerProbeService.CoreDataCloudKitZone };
                foreach (var z in fallback.Distinct(StringComparer.OrdinalIgnoreCase).Take(2))
                {
                    var sample = await SampleZoneTimelineAsync(
                            gateway, session, binding, containerId, z, cutoff, events, tokens, log, ct)
                        .ConfigureAwait(false);
                    if (sample)
                        zonesSampled++;
                }

                await Task.Delay(120, ct).ConfigureAwait(false);
                continue;
            }

            var pick = PickTimelineZones(zone.Zones).Take(4).ToList();
            foreach (var z in pick)
            {
                var sample = await SampleZoneTimelineAsync(
                        gateway, session, binding, containerId, z, cutoff, events, tokens, log, ct)
                    .ConfigureAwait(false);
                if (sample)
                    zonesSampled++;
            }

            await Task.Delay(150, ct).ConfigureAwait(false);
        }

        scope.Restore();
        var report = FormatTimelineReport(events, tokens, containersOk, zonesSampled, days);
        var outDir = EnsureDir(outputDirectory);
        var json = Path.Combine(outDir, "change_timeline.json");
        var csv = Path.Combine(outDir, "change_timeline.csv");
        await File.WriteAllTextAsync(json, JsonSerializer.Serialize(new
        {
            generatedAt = DateTimeOffset.UtcNow,
            days,
            cutoff = cutoff.ToString("O"),
            containersOk,
            zonesSampled,
            events,
            tokens
        }, JsonOpts), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(csv, BuildTimelineCsv(events), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(
                Path.Combine(outDir, "change_tokens.json"),
                JsonSerializer.Serialize(tokens, JsonOpts), ct)
            .ConfigureAwait(false);
        await File.WriteAllTextAsync(Path.Combine(outDir, "change_timeline.txt"), report, ct)
            .ConfigureAwait(false);
        log?.Report($"  timeline → {outDir}");

        return new TimelineResult(
            events, tokens, containersOk, zonesSampled, days, report, outDir, json, csv);
    }

    // ─── Third-party ─────────────────────────────────────────────────────────

    public sealed record ThirdPartyHit(
        string ContainerId,
        string Label,
        string Source,
        int StatusCode,
        bool ZoneSyncOk,
        IReadOnlyList<string> Zones,
        bool PcsLikely,
        string? Note);

    public sealed record ThirdPartyResult(
        IReadOnlyList<ThirdPartyHit> Hits,
        int OkCount,
        string ReportText,
        string? OutputDirectory,
        string? JsonPath,
        string? CsvPath);

    /// <summary>Known / commonly seen non-Apple CloudKit containers.</summary>
    public static IReadOnlyList<(string ContainerId, string Label)> KnownThirdPartyCandidates { get; } =
    [
        (CloudKitContainerBinding.WhatsApp.ContainerId, "WhatsApp"),
        ("iCloud.com.agilebits.onepassword", "1Password (legacy iCloud)"),
        ("2BUA8C4S2C.com.1password.safari", "1Password Safari"),
        ("com.omnigroup.OmniFocus3.iCloud", "OmniFocus"),
        ("com.culturedcode.ThingsMac", "Things"),
        ("com.flexibits.fantastical2.mac", "Fantastical"),
        ("net.shinyfrog.bear-iCloud", "Bear"),
        ("com.apple.developer.icloud-container-identifiers", "(placeholder — replace)"),
    ];

    public async Task<ThirdPartyResult> ProbeThirdPartyAsync(
        ICloudSession session,
        string outputDirectory,
        IReadOnlyList<string>? extraContainers = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        EnsureSession(session);
        var candidates = BuildThirdPartyCandidates(session, extraContainers);
        var gateway = new CloudKitGatewayClient(_http);
        var hits = new List<ThirdPartyHit>();
        using var scope = new SessionCloudKitScope(session);

        log?.Report($"Third-party atlas — {candidates.Count} candidates…");
        foreach (var (containerId, label, source) in candidates)
        {
            ct.ThrowIfCancellationRequested();
            if (containerId.Contains("placeholder", StringComparison.OrdinalIgnoreCase))
                continue;

            log?.Report($"  [{source}] {containerId}…");
            scope.Restore();
            var status = await TryInitAsync(session, containerId, ct).ConfigureAwait(false);
            if (status != 200)
            {
                hits.Add(new ThirdPartyHit(
                    containerId, label, source, status, false, [], false, $"HTTP {status}"));
                log?.Report($"    HTTP {status}");
                await Task.Delay(100, ct).ConfigureAwait(false);
                continue;
            }

            var binding = new CloudKitContainerBinding(containerId, GuessBundle(containerId));
            var zone = await ZoneSyncAsync(gateway, session, binding, ct).ConfigureAwait(false);
            hits.Add(new ThirdPartyHit(
                containerId, label, source, 200, zone.Ok, zone.Zones, zone.PcsLikely, zone.Note));
            log?.Report(
                zone.Ok
                    ? $"    OK zones={zone.Zones.Count} pcs≈{zone.PcsLikely}"
                    : $"    OK ckAppInit, zone/sync: {zone.Note}");
            await Task.Delay(140, ct).ConfigureAwait(false);
        }

        scope.Restore();
        var ok = hits.Count(static h => h.StatusCode == 200);
        var report = FormatThirdPartyReport(hits);
        var outDir = EnsureDir(outputDirectory);
        var json = Path.Combine(outDir, "third_party_atlas.json");
        var csv = Path.Combine(outDir, "third_party_atlas.csv");
        await File.WriteAllTextAsync(json, JsonSerializer.Serialize(new
        {
            generatedAt = DateTimeOffset.UtcNow,
            ok,
            hits
        }, JsonOpts), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(csv, BuildThirdPartyCsv(hits), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(Path.Combine(outDir, "third_party_atlas.txt"), report, ct)
            .ConfigureAwait(false);
        log?.Report($"  third-party → {outDir}");

        return new ThirdPartyResult(hits, ok, report, outDir, json, csv);
    }

    // ─── Internals ───────────────────────────────────────────────────────────

    private async Task<bool> SampleZoneTimelineAsync(
        CloudKitGatewayClient gateway,
        ICloudSession session,
        CloudKitContainerBinding binding,
        string containerId,
        string zoneName,
        DateTimeOffset cutoff,
        List<TimelineEvent> events,
        List<TimelineToken> tokens,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var sample = await RecordSyncSampleAsync(
                gateway, session, binding, zoneName, newestFirst: true, ct)
            .ConfigureAwait(false);
        if (!sample.Ok)
        {
            log?.Report($"    {zoneName}: record/sync fail — {sample.Note}");
            return false;
        }

        if (sample.Token is { Length: > 0 })
        {
            tokens.Add(new TimelineToken(
                containerId,
                zoneName,
                Convert.ToBase64String(sample.Token),
                sample.RecordHints.Count,
                DateTimeOffset.UtcNow));
        }

        var dated = 0;
        foreach (var s in sample.Strings)
        {
            foreach (Match m in IsoDate.Matches(s))
            {
                if (!DateTimeOffset.TryParse(
                        m.Value, CultureInfo.InvariantCulture,
                        DateTimeStyles.RoundtripKind, out var when))
                    continue;
                if (when < cutoff)
                    continue;
                events.Add(new TimelineEvent(
                    containerId, zoneName, when.ToUniversalTime().ToString("O"),
                    "timestamp", Trunc(s, 120)));
                dated++;
            }
        }

        foreach (var hint in sample.RecordHints.Take(40))
        {
            events.Add(new TimelineEvent(
                containerId, zoneName, null, "record-hint", hint));
        }

        events.Add(new TimelineEvent(
            containerId, zoneName, DateTimeOffset.UtcNow.ToString("O"),
            "sync-sample",
            $"bytes={sample.Bytes} hints={sample.RecordHints.Count} datedInWindow={dated} moreComing={sample.MoreComing}"));

        log?.Report(
            $"    {zoneName}: {sample.Bytes:N0} B, hints={sample.RecordHints.Count}, dated={dated}, token={(sample.Token is null ? "no" : "yes")}");
        return true;
    }

    private static IEnumerable<string> PickTimelineZones(IReadOnlyList<string> zones)
    {
        // Prefer CoreData / share / named sync zones over opaque ids.
        foreach (var z in zones.Where(LooksLikeShareZone))
            yield return z;
        foreach (var z in zones.Where(static z =>
                     z.Equals(CloudKitContainerProbeService.CoreDataCloudKitZone,
                         StringComparison.OrdinalIgnoreCase)))
            yield return z;
        foreach (var z in zones.Where(static z =>
                     !LooksLikeShareZone(z)
                     && !z.Equals(CloudKitContainerProbeService.CoreDataCloudKitZone,
                         StringComparison.OrdinalIgnoreCase)))
            yield return z;
    }

    private async Task<(
        bool Ok,
        int Bytes,
        string? Note,
        IReadOnlyList<string> Zones,
        IReadOnlyList<string> ShareSignals,
        bool PcsLikely)> ZoneSyncAsync(
        CloudKitGatewayClient gateway,
        ICloudSession session,
        CloudKitContainerBinding binding,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
            || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            return (false, 0, "missing ck token", [], [], false);

        try
        {
            var body = CloudKitDelimitedRequest.BuildZoneRetrieveChanges(
                session.CloudKitUserId, container: binding);
            var payload = await gateway.ZoneChangesAsync(session, body, ct, binding)
                .ConfigureAwait(false);
            if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err))
                return (false, payload.Length, err ?? "ck error", [], [], false);

            var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
            var zones = WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(strings)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static z => z, StringComparer.OrdinalIgnoreCase)
                .ToList();
            var shareSignals = strings
                .Where(static s => ContainsAny(s,
                    "shareEtag", "CKShare", "shareID", "participant", "ownerName", "SharedDB"))
                .Select(static s => Trunc(s, 64))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(12)
                .ToList();
            var pcs = strings.Any(static s => ContainsAny(s,
                "protectionInfo", "ProtectedCloudStorage", "pcsKey", "Manatee", "encryptedFields"));
            return (true, payload.Length, null, zones, shareSignals, pcs);
        }
        catch (Exception ex)
        {
            return (false, 0, ex.Message, [], [], false);
        }
    }

    private async Task<(
        bool Ok,
        int Bytes,
        string? Note,
        byte[]? Token,
        bool MoreComing,
        IReadOnlyList<string> Strings,
        IReadOnlyList<string> RecordHints)> RecordSyncSampleAsync(
        CloudKitGatewayClient gateway,
        ICloudSession session,
        CloudKitContainerBinding binding,
        string zoneName,
        bool newestFirst,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
            || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            return (false, 0, "missing ck token", null, false, [], []);

        try
        {
            var body = CloudKitDelimitedRequest.BuildRecordRetrieveChanges(
                session.CloudKitUserId, zoneName, syncContinuationToken: null,
                container: binding, newestFirst: newestFirst);
            var payload = await gateway.RecordChangesAsync(session, body, ct, binding)
                .ConfigureAwait(false);
            if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err))
                return (false, payload.Length, err ?? "ck error", null, false, [], []);

            var cont = CloudKitResponseParser.TryExtractRecordSyncContinuation(payload);
            var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload, max: 300);
            var hints = strings
                .Where(LooksLikeRecordHint)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .Take(60)
                .ToList();
            return (true, payload.Length, null, cont.SyncContinuationToken, cont.MoreComing, strings, hints);
        }
        catch (Exception ex)
        {
            return (false, 0, ex.Message, null, false, [], []);
        }
    }

    private async Task<int> TryInitAsync(ICloudSession session, string containerId, CancellationToken ct)
    {
        try
        {
            return await _orchestrator
                .TryCkAppInitOnceAsync(session, containerId, log: null, ct)
                .ConfigureAwait(false);
        }
        catch
        {
            return -1;
        }
    }

    private static List<(string ContainerId, string Label, string Source)> BuildThirdPartyCandidates(
        ICloudSession session,
        IReadOnlyList<string>? extras)
    {
        var list = new List<(string, string, string)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void Add(string id, string label, string source)
        {
            if (string.IsNullOrWhiteSpace(id) || !seen.Add(id.Trim()))
                return;
            // Skip pure Apple system containers for this atlas.
            if (id.StartsWith("com.apple.", StringComparison.OrdinalIgnoreCase)
                && !id.Equals(CloudKitContainerBinding.WhatsApp.ContainerId, StringComparison.OrdinalIgnoreCase))
                return;
            list.Add((id.Trim(), label, source));
        }

        foreach (var (id, label) in KnownThirdPartyCandidates)
            Add(id, label, "known");

        // Dataclass hints that are not Apple system (rare, but harvest reverse-DNS).
        foreach (var dc in session.AvailableDataclasses ?? [])
        {
            if (dc.StartsWith("com.apple.", StringComparison.OrdinalIgnoreCase))
                continue;
            Add(dc, "dataclass", "account-settings");
        }

        if (extras is not null)
        {
            foreach (var raw in extras)
            {
                var id = raw.Trim();
                if (id.Length == 0 || id.StartsWith('#'))
                    continue;
                Add(id, "custom", "user");
            }
        }

        return list;
    }

    private static void EnsureSession(ICloudSession session)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Session has no dsid — sign in first.");
        if (string.IsNullOrWhiteSpace(session.MobileMeAuthToken)
            && string.IsNullOrWhiteSpace(session.CloudKitGsToken)
            && string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            throw new InvalidOperationException("Session missing CloudKit / mme tokens — sign in again.");
    }

    private static string EnsureDir(string path)
    {
        var full = Path.GetFullPath(path.Trim());
        Directory.CreateDirectory(full);
        return full;
    }

    private static bool LooksLikeShareZone(string zone) =>
        zone.Contains("Share", StringComparison.OrdinalIgnoreCase)
        || zone.Contains("Shared", StringComparison.OrdinalIgnoreCase)
        || zone.StartsWith("ckshare", StringComparison.OrdinalIgnoreCase)
        || zone.Contains(".share", StringComparison.OrdinalIgnoreCase)
        || zone.Contains("-share-", StringComparison.OrdinalIgnoreCase);

    private static bool LooksLikeRecordHint(string s)
    {
        if (s.Length is < 4 or > 128)
            return false;
        if (s.Contains(' ', StringComparison.Ordinal))
            return false;
        if (IsoDate.IsMatch(s))
            return false;
        if (s.StartsWith("CKD", StringComparison.Ordinal) || s is "SUCCESS" or "FAILURE" or "Production")
            return false;
        // UUID-like or reverse-DNS record types / names
        return s.Contains('.') || s.Contains('_') || s.Contains('-')
               || (s.Length >= 8 && s.All(char.IsLetterOrDigit));
    }

    private static IReadOnlyList<string> ExtractParticipants(IReadOnlyList<string> strings) =>
        strings
            .Where(static s =>
                s.Contains('@')
                || s.Contains("participant", StringComparison.OrdinalIgnoreCase)
                || s.Contains("ownerName", StringComparison.OrdinalIgnoreCase)
                || (s.StartsWith('_') && s.Length > 8))
            .Select(static s => Trunc(s, 80))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(20)
            .ToList();

    private static string GuessBundle(string containerId)
    {
        var parts = containerId.Split('.');
        if (parts.Length >= 3 && parts[0].Length is >= 8 and <= 12 && parts[0].All(char.IsLetterOrDigit))
            return string.Join('.', parts.Skip(1)); // TEAMID.bundle → bundle
        return containerId;
    }

    private static bool ContainsAny(string hay, params string[] needles)
    {
        foreach (var n in needles)
        {
            if (hay.Contains(n, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static string Trunc(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    private static string FormatShareReport(IReadOnlyList<ShareEdge> edges, int containersOk)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== CloudKit share graph ===");
        sb.AppendLine($"Containers OK: {containersOk}  |  share edges: {edges.Count}");
        sb.AppendLine();
        if (edges.Count == 0)
        {
            sb.AppendLine("(no share-like zones found on probed containers)");
            return sb.ToString().TrimEnd();
        }

        foreach (var g in edges.GroupBy(static e => e.ContainerId, StringComparer.OrdinalIgnoreCase)
                     .OrderBy(static g => g.Key, StringComparer.OrdinalIgnoreCase))
        {
            sb.AppendLine($"— {g.Key} ({g.First().Label}) —");
            foreach (var e in g)
            {
                sb.AppendLine($"  zone={e.Zone}  recSync={(e.RecordSyncOk ? "ok" : "skip")}  {e.RecordSyncBytes:N0} B");
                if (e.Participants.Count > 0)
                    sb.AppendLine($"    participants: {string.Join(" | ", e.Participants.Take(8))}");
                if (e.Signals.Count > 0)
                    sb.AppendLine($"    signals: {string.Join(" | ", e.Signals.Take(6))}");
            }
        }

        sb.AppendLine();
        sb.AppendLine("Heuristic: zone names / payload strings only — not a full CKShare decode.");
        return sb.ToString().TrimEnd();
    }

    private static string FormatTimelineReport(
        IReadOnlyList<TimelineEvent> events,
        IReadOnlyList<TimelineToken> tokens,
        int containersOk,
        int zonesSampled,
        int days)
    {
        var dated = events.Count(static e => e.WhenIso is not null && e.Kind == "timestamp");
        var sb = new StringBuilder();
        sb.AppendLine("=== CloudKit change timeline ===");
        sb.AppendLine(
            $"Window: last {days} days  |  containers OK: {containersOk}  |  zones sampled: {zonesSampled}");
        sb.AppendLine($"Events: {events.Count} (dated-in-window: {dated})  |  tokens saved: {tokens.Count}");
        sb.AppendLine();
        sb.AppendLine("--- Dated signals (in window) ---");
        var datedEvents = events
            .Where(static e => e.Kind == "timestamp" && e.WhenIso is not null)
            .OrderByDescending(static e => e.WhenIso)
            .Take(40)
            .ToList();
        if (datedEvents.Count == 0)
            sb.AppendLine("(none parsed from payload strings — tokens still useful as baselines)");
        else
        {
            foreach (var e in datedEvents)
                sb.AppendLine($"{e.WhenIso}  {e.ContainerId}/{e.Zone}  {e.Detail}");
        }

        sb.AppendLine();
        sb.AppendLine("--- Sync tokens (for incremental follow-up) ---");
        foreach (var t in tokens)
            sb.AppendLine(
                $"{t.ContainerId}/{t.Zone}  records≈{t.SampleRecords}  token={t.TokenBase64[..Math.Min(24, t.TokenBase64.Length)]}…");

        sb.AppendLine();
        sb.AppendLine("Newest-first record/sync sample; dates are string heuristics from the payload.");
        return sb.ToString().TrimEnd();
    }

    private static string FormatThirdPartyReport(IReadOnlyList<ThirdPartyHit> hits)
    {
        var ok = hits.Where(static h => h.StatusCode == 200).ToList();
        var sb = new StringBuilder();
        sb.AppendLine("=== Third-party CloudKit atlas ===");
        sb.AppendLine($"Candidates: {hits.Count}  |  OK: {ok.Count}");
        sb.AppendLine();
        sb.AppendLine("--- Available (HTTP 200) ---");
        if (ok.Count == 0)
            sb.AppendLine("(none)");
        else
        {
            foreach (var h in ok.OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
            {
                sb.AppendLine($"{h.ContainerId}  [{h.Source}]  {h.Label}");
                sb.AppendLine(
                    $"  zones=[{string.Join(", ", h.Zones)}]  pcs≈{h.PcsLikely}  note={h.Note ?? "ok"}");
            }
        }

        sb.AppendLine();
        sb.AppendLine("--- Not available ---");
        foreach (var h in hits.Where(static h => h.StatusCode != 200)
                     .OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
            sb.AppendLine($"  {h.ContainerId}  → {(h.StatusCode < 0 ? "EX" : "HTTP " + h.StatusCode)}");

        sb.AppendLine();
        sb.AppendLine("Paste extra container IDs (TEAMID.bundle / iCloud.com…) in the Laboratory extras box.");
        return sb.ToString().TrimEnd();
    }

    private static string BuildShareCsv(IReadOnlyList<ShareEdge> edges)
    {
        var sb = new StringBuilder();
        sb.AppendLine("containerId,label,zone,participants,signals,zoneSyncBytes,recordSyncOk,recordSyncBytes");
        foreach (var e in edges)
        {
            sb.Append(Csv(e.ContainerId)).Append(',')
                .Append(Csv(e.Label)).Append(',')
                .Append(Csv(e.Zone)).Append(',')
                .Append(Csv(string.Join('|', e.Participants))).Append(',')
                .Append(Csv(string.Join('|', e.Signals))).Append(',')
                .Append(e.ZoneSyncBytes).Append(',')
                .Append(e.RecordSyncOk ? "1" : "0").Append(',')
                .Append(e.RecordSyncBytes)
                .AppendLine();
        }

        return sb.ToString();
    }

    private static string BuildTimelineCsv(IReadOnlyList<TimelineEvent> events)
    {
        var sb = new StringBuilder();
        sb.AppendLine("whenIso,containerId,zone,kind,detail");
        foreach (var e in events)
        {
            sb.Append(Csv(e.WhenIso)).Append(',')
                .Append(Csv(e.ContainerId)).Append(',')
                .Append(Csv(e.Zone)).Append(',')
                .Append(Csv(e.Kind)).Append(',')
                .Append(Csv(e.Detail))
                .AppendLine();
        }

        return sb.ToString();
    }

    private static string BuildThirdPartyCsv(IReadOnlyList<ThirdPartyHit> hits)
    {
        var sb = new StringBuilder();
        sb.AppendLine("containerId,label,source,status,zoneSyncOk,pcsLikely,zones,note");
        foreach (var h in hits)
        {
            sb.Append(Csv(h.ContainerId)).Append(',')
                .Append(Csv(h.Label)).Append(',')
                .Append(Csv(h.Source)).Append(',')
                .Append(h.StatusCode).Append(',')
                .Append(h.ZoneSyncOk ? "1" : "0").Append(',')
                .Append(h.PcsLikely ? "1" : "0").Append(',')
                .Append(Csv(string.Join('|', h.Zones))).Append(',')
                .Append(Csv(h.Note))
                .AppendLine();
        }

        return sb.ToString();
    }

    private static string Csv(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        if (value.Contains('"') || value.Contains(',') || value.Contains('\n') || value.Contains('\r'))
            return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        return value;
    }

    private sealed class SessionCloudKitScope : IDisposable
    {
        private readonly ICloudSession _session;
        private readonly string? _userId;
        private readonly string? _token;
        private readonly string? _gateway;
        private readonly string? _partition;

        public SessionCloudKitScope(ICloudSession session)
        {
            _session = session;
            _userId = session.CloudKitUserId;
            _token = session.CloudKitAuthToken;
            _gateway = session.CloudKitGatewayUrl;
            _partition = session.Partition;
        }

        public void Restore()
        {
            _session.CloudKitUserId = _userId ?? "";
            _session.CloudKitAuthToken = _token ?? "";
            _session.CloudKitGatewayUrl = _gateway ?? "";
            _session.Partition = _partition ?? "";
        }

        public void Dispose() => Restore();
    }
}
