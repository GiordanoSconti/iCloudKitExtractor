using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.SyncData;
using iCloudKitExtractor.Services.WhatsApp;

namespace iCloudKitExtractor.Services.CloudKit;

/// <summary>
/// Probe read-only: <c>ckAppInit</c> sui container candidati, poi (se OK)
/// <c>zone/sync</c> per flaggare <c>com.apple.coredata.cloudkit.zone</c>.
/// Ripristina sempre i token CloudKit della sessione.
/// </summary>
public sealed class CloudKitContainerProbeService
{
    public const string CoreDataCloudKitZone = VoiceMemosAudioDownloader.SyncZone;

    private readonly ICloudBackupOrchestrator _orchestrator;
    private readonly HttpClient _http;

    public CloudKitContainerProbeService(ICloudBackupOrchestrator orchestrator, HttpClient http)
    {
        _orchestrator = orchestrator;
        _http = http;
    }

    public sealed record Candidate(string ContainerId, string Label, bool InCatalog);

    public sealed record Hit(
        string ContainerId,
        string Label,
        bool InCatalog,
        int StatusCode,
        string? CloudKitUserId,
        string? GatewayUrl,
        string? Partition,
        int TokenLength,
        bool ZoneSyncAttempted = false,
        bool ZoneSyncOk = false,
        int ZoneSyncBytes = 0,
        string? ZoneSyncNote = null,
        bool HasCoreDataCloudKitZone = false,
        IReadOnlyList<string>? Zones = null);

    /// <summary>
    /// Container già in catalogo + candidati tipici non ancora mappati
    /// (Calendar, Reminders, Wallet, Screen Time, …).
    /// </summary>
    public static IReadOnlyList<Candidate> DefaultCandidates { get; } = BuildDefaultCandidates();

    public async Task<string> ProbeAsync(
        ICloudSession session,
        IReadOnlyList<Candidate>? candidates = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Session has no dsid — sign in first.");
        if (string.IsNullOrWhiteSpace(session.MobileMeAuthToken)
            && string.IsNullOrWhiteSpace(session.CloudKitGsToken)
            && string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
        {
            throw new InvalidOperationException(
                "Session missing mmeAuthToken / CloudKit token — sign in again.");
        }

        var list = Deduplicate(candidates ?? DefaultCandidates);
        var hits = new List<Hit>(list.Count);
        var gateway = new CloudKitGatewayClient(_http);

        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;
        var savedPartition = session.Partition;

        log?.Report(
            $"CloudKit container probe — {list.Count} candidati " +
            $"(ckAppInit + zone/sync → {CoreDataCloudKitZone})…");

        try
        {
            for (var i = 0; i < list.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var c = list[i];
                log?.Report($"  [{i + 1}/{list.Count}] {c.ContainerId}…");

                // Ripristina baseline prima di ogni tentativo (ckAppInit sovrascrive).
                session.CloudKitUserId = savedUserId;
                session.CloudKitAuthToken = savedToken;
                session.CloudKitGatewayUrl = savedGateway;
                session.Partition = savedPartition;

                int status;
                try
                {
                    status = await _orchestrator
                        .TryCkAppInitOnceAsync(session, c.ContainerId, log: null, ct)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    hits.Add(new Hit(
                        c.ContainerId, c.Label, c.InCatalog,
                        StatusCode: -1,
                        CloudKitUserId: null,
                        GatewayUrl: null,
                        Partition: null,
                        TokenLength: 0));
                    log?.Report($"    EX: {ex.Message}");
                    continue;
                }

                if (status != 200)
                {
                    hits.Add(new Hit(
                        c.ContainerId, c.Label, c.InCatalog,
                        status,
                        CloudKitUserId: null,
                        GatewayUrl: null,
                        Partition: null,
                        TokenLength: 0));
                    log?.Report($"    HTTP {status}");
                    if (i + 1 < list.Count)
                        await Task.Delay(120, ct).ConfigureAwait(false);
                    continue;
                }

                log?.Report(
                    $"    OK  userId={(string.IsNullOrEmpty(session.CloudKitUserId) ? "(empty)" : "presente")} "
                    + $"gw={(string.IsNullOrEmpty(session.CloudKitGatewayUrl) ? "(empty)" : "presente")}");

                var binding = ResolveBinding(c);
                var (zoneOk, zoneBytes, zoneNote, zones, hasCoreData) =
                    await TryZoneSyncAsync(gateway, session, binding, log, ct)
                        .ConfigureAwait(false);

                hits.Add(new Hit(
                    c.ContainerId,
                    c.Label,
                    c.InCatalog,
                    status,
                    session.CloudKitUserId,
                    session.CloudKitGatewayUrl,
                    session.Partition,
                    session.CloudKitAuthToken?.Length ?? 0,
                    ZoneSyncAttempted: true,
                    ZoneSyncOk: zoneOk,
                    ZoneSyncBytes: zoneBytes,
                    ZoneSyncNote: zoneNote,
                    HasCoreDataCloudKitZone: hasCoreData,
                    Zones: zones));

                if (hasCoreData)
                    log?.Report($"    ★ Core Data CloudKit zone PRESENT");
                else if (zoneOk)
                    log?.Report(
                        zones.Count > 0
                            ? $"    zone/sync OK — {zones.Count} zone (no Core Data default)"
                            : "    zone/sync OK — nessuna zona custom");
                else
                    log?.Report($"    zone/sync: {zoneNote ?? "fail"}");

                if (i + 1 < list.Count)
                    await Task.Delay(180, ct).ConfigureAwait(false);
            }
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
            session.Partition = savedPartition;
        }

        return FormatReport(hits);
    }

    private static async Task<(
        bool Ok,
        int Bytes,
        string? Note,
        IReadOnlyList<string> Zones,
        bool HasCoreData)> TryZoneSyncAsync(
        CloudKitGatewayClient gateway,
        ICloudSession session,
        CloudKitContainerBinding binding,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
            || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
        {
            return (false, 0, "ck token/userId assenti dopo ckAppInit", [], false);
        }

        try
        {
            log?.Report("    zone/sync…");
            var body = CloudKitDelimitedRequest.BuildZoneRetrieveChanges(
                session.CloudKitUserId, container: binding);
            var payload = await gateway.ZoneChangesAsync(session, body, ct, binding)
                .ConfigureAwait(false);

            if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err))
            {
                var reason = err
                             ?? CloudKitResponseParser.TryGetCloudKitReason(payload)
                             ?? $"errore {payload.Length} B";
                return (false, payload.Length, reason, [], false);
            }

            var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
            var zones = WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(strings)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static z => z, StringComparer.OrdinalIgnoreCase)
                .ToList();

            // Also accept raw substring hits (zone name may appear with leading space).
            var hasCoreData = zones.Any(static z =>
                                    z.Equals(CoreDataCloudKitZone, StringComparison.OrdinalIgnoreCase))
                              || strings.Any(static s =>
                                    s.Contains(CoreDataCloudKitZone, StringComparison.OrdinalIgnoreCase));

            if (hasCoreData
                && !zones.Any(static z =>
                    z.Equals(CoreDataCloudKitZone, StringComparison.OrdinalIgnoreCase)))
            {
                zones.Add(CoreDataCloudKitZone);
                zones = zones.OrderBy(static z => z, StringComparer.OrdinalIgnoreCase).ToList();
            }

            var note = CloudKitResponseParser.DescribeCompactPayload(payload)
                       ?? $"{zones.Count} zone";
            return (true, payload.Length, note, zones, hasCoreData);
        }
        catch (Exception ex)
        {
            return (false, 0, ex.Message, [], false);
        }
    }

    private static CloudKitContainerBinding ResolveBinding(Candidate c)
    {
        foreach (var known in CloudKitContainerBinding.SyncDataContainers)
        {
            if (known.ContainerId.Equals(c.ContainerId, StringComparison.OrdinalIgnoreCase))
                return known;
        }

        // Explore candidates: bundle spesso coincide col container o col label corto.
        var bundle = GuessBundleId(c.ContainerId);
        return new CloudKitContainerBinding(c.ContainerId, bundle);
    }

    private static string GuessBundleId(string containerId)
    {
        // Heuristics for explore list — enough for zone/sync headers.
        if (containerId.Equals("com.apple.freeform", StringComparison.OrdinalIgnoreCase))
            return "com.apple.freeform";
        if (containerId.Equals("com.apple.journal", StringComparison.OrdinalIgnoreCase))
            return "com.apple.journal";
        if (containerId.Equals("com.apple.Home", StringComparison.OrdinalIgnoreCase)
            || containerId.Equals("com.apple.HomeKit", StringComparison.OrdinalIgnoreCase))
            return "com.apple.Home";
        if (containerId.Equals("com.apple.reminders", StringComparison.OrdinalIgnoreCase)
            || containerId.Equals("com.apple.Reminders", StringComparison.OrdinalIgnoreCase))
            return "com.apple.reminders";
        if (containerId.Equals("com.apple.mobilecal", StringComparison.OrdinalIgnoreCase)
            || containerId.Equals("com.apple.Calendar", StringComparison.OrdinalIgnoreCase))
            return "com.apple.mobilecal";
        if (containerId.Equals("com.apple.shortcuts", StringComparison.OrdinalIgnoreCase))
            return "com.apple.shortcuts";
        if (containerId.Contains("Safari", StringComparison.OrdinalIgnoreCase))
            return "com.apple.Safari";
        return containerId;
    }

    public static string FormatReport(IReadOnlyList<Hit> hits)
    {
        var ok = hits.Where(static h => h.StatusCode == 200).ToList();
        var coreData = hits.Where(static h => h.HasCoreDataCloudKitZone).ToList();
        var denied = hits.Where(static h => h.StatusCode is >= 400 and < 500).ToList();
        var other = hits.Where(static h => h.StatusCode != 200 && h.StatusCode is not (>= 400 and < 500))
            .ToList();

        var sb = new StringBuilder();
        sb.AppendLine("=== CloudKit container probe (ckAppInit) ===");
        sb.AppendLine(
            $"Candidati: {hits.Count}  |  OK: {ok.Count}  |  CoreData-zone: {coreData.Count}  |  4xx: {denied.Count}  |  altro: {other.Count}");
        sb.AppendLine($"Read-only: no Relogin; session CloudKit tokens restored.");
        sb.AppendLine("Read-only: no Relogin; session CloudKit tokens restored.");
        sb.AppendLine();

        sb.AppendLine($"--- Disponibili (HTTP 200) ---");
        if (coreData.Count == 0)
        {
            sb.AppendLine("(nessuno)");
        }
        else
        {
            foreach (var h in coreData.OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
            {
                var tag = h.InCatalog ? "catalogo" : "NUOVO?";
                sb.AppendLine($"{h.ContainerId}  [{tag}]  {h.Label}");
                sb.AppendLine(
                    $"  zones=[{string.Join(", ", h.Zones ?? [])}]  zone/sync={h.ZoneSyncBytes:N0} B");
            }
        }

        sb.AppendLine();
        sb.AppendLine("--- Disponibili (HTTP 200) ---");
        if (ok.Count == 0)
        {
            sb.AppendLine("(nessuno)");
        }
        else
        {
            foreach (var h in ok.OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
            {
                var tag = h.InCatalog ? "catalogo" : "NUOVO?";
                var cd = h.HasCoreDataCloudKitZone ? "  ★COREDATA" : "";
                sb.AppendLine($"{h.ContainerId}  [{tag}]  {h.Label}{cd}");
                sb.AppendLine(
                    $"  ckUserId={NullDash(h.CloudKitUserId)}  tokenLen={h.TokenLength}  partition={NullDash(h.Partition)}");
                sb.AppendLine($"  gateway={NullDash(h.GatewayUrl)}");
                if (h.ZoneSyncAttempted)
                {
                    if (h.ZoneSyncOk)
                    {
                        var z = h.Zones is { Count: > 0 }
                            ? string.Join(", ", h.Zones)
                            : "(nessuna custom)";
                        sb.AppendLine($"  zone/sync OK {h.ZoneSyncBytes:N0} B — {z}");
                    }
                    else
                    {
                        sb.AppendLine($"  zone/sync FAIL — {NullDash(h.ZoneSyncNote)}");
                    }
                }
            }
        }

        sb.AppendLine();
        sb.AppendLine("--- Rifiutati / assenti (4xx) ---");
        if (denied.Count == 0)
        {
            sb.AppendLine("(nessuno)");
        }
        else
        {
            foreach (var g in denied.GroupBy(static h => h.StatusCode).OrderBy(static g => g.Key))
            {
                sb.AppendLine($"HTTP {g.Key} ({g.Count()}):");
                foreach (var h in g.OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
                    sb.AppendLine($"  {h.ContainerId}  ({h.Label})");
            }
        }

        if (other.Count > 0)
        {
            sb.AppendLine();
            sb.AppendLine("--- Altro ---");
            foreach (var h in other.OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
            {
                var code = h.StatusCode < 0 ? "exception" : $"HTTP {h.StatusCode}";
                sb.AppendLine($"  {h.ContainerId}  → {code}");
            }
        }

        sb.AppendLine();
        sb.AppendLine("Nota: HTTP 200 conferma che il container accetta ckAppInit sul tuo account.");
        sb.AppendLine(
            $"★COREDATA = zone/sync ha elencato {CoreDataCloudKitZone} (pattern NSPersistentCloudKitContainer).");
        sb.AppendLine("Does not imply zone/record parsing is already implemented in the app.");
        return sb.ToString().TrimEnd();
    }

    private static string NullDash(string? s) =>
        string.IsNullOrWhiteSpace(s) ? "(empty)" : s;

    private static List<Candidate> Deduplicate(IReadOnlyList<Candidate> source)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<Candidate>();
        foreach (var c in source)
        {
            if (string.IsNullOrWhiteSpace(c.ContainerId))
                continue;
            if (!seen.Add(c.ContainerId.Trim()))
                continue;
            list.Add(c with { ContainerId = c.ContainerId.Trim() });
        }

        return list;
    }

    private static IReadOnlyList<Candidate> BuildDefaultCandidates()
    {
        var list = new List<Candidate>();

        void AddKnown(string containerId, string label) =>
            list.Add(new Candidate(containerId, label, InCatalog: true));

        void AddExplore(string containerId, string label) =>
            list.Add(new Candidate(containerId, label, InCatalog: false));

        // Catalogo esistente
        AddKnown(CloudKitContainerBinding.Backup.ContainerId, "Backup iOS");
        AddKnown(CloudKitContainerBinding.WhatsApp.ContainerId, "WhatsApp");
        AddKnown(CloudKitContainerBinding.CloudDocs.ContainerId, "iCloud Drive / CloudDocs");
        AddKnown(CloudKitContainerBinding.SearchParty.ContainerId, "Find My Items / SearchParty");
        AddKnown(CloudKitContainerBinding.Cuttlefish.ContainerId, "Octagon / Cuttlefish / Keychain");

        foreach (var c in CloudKitContainerBinding.SyncDataContainers)
            AddKnown(c.ContainerId, $"Sync Data · {c.BundleId}");

        // Candidati tipici ancora da verificare sul account
        AddExplore("com.apple.CloudDocs.container-metadata", "CloudDocs metadata");
        AddExplore("com.apple.reminders", "Reminders");
        AddExplore("com.apple.Reminders", "Reminders (capital R)");
        AddExplore("com.apple.mobilecal", "Calendar (mobilecal)");
        AddExplore("com.apple.Calendar", "Calendar");
        AddExplore("com.apple.contacts", "Contacts (CloudKit)");
        AddExplore("com.apple.AddressBook", "AddressBook");
        AddExplore("com.apple.Passbook", "Wallet / Passbook");
        AddExplore("com.apple.passd", "passd");
        AddExplore("com.apple.ScreenTimeAgent", "Screen Time Agent");
        AddExplore("com.apple.screentime.cloudkit", "Screen Time CloudKit");
        AddExplore("com.apple.wifi", "Wi-Fi sync");
        AddExplore("com.apple.wifid.sync", "wifid sync");
        AddExplore("com.apple.HomeKit", "HomeKit");
        AddExplore("com.apple.Home", "Home");
        AddExplore("com.apple.shortcuts", "Shortcuts");
        AddExplore("com.apple.news", "News");
        AddExplore("com.apple.stocks", "Stocks");
        AddExplore("com.apple.weather", "Weather");
        AddExplore("com.apple.podcasts", "Podcasts");
        AddExplore("com.apple.freeform", "Freeform");
        AddExplore("com.apple.journal", "Journal");
        AddExplore("com.apple.tips", "Tips");
        AddExplore("com.apple.FileProvider", "FileProvider");
        AddExplore("com.apple.SafariShared.CloudTabs", "Safari CloudTabs (alias)");
        AddExplore("com.apple.mobileslideshow.Photostream", "Photostream");
        AddExplore("com.apple.icloud.searchpartyuseragent", "SearchParty user agent");
        AddExplore("com.apple.private.alloy", "IDS Alloy container");

        return Deduplicate(list);
    }
}
