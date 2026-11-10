using System.Text;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.CloudKit;

/// <summary>
/// Probe read-only: prova <c>ckAppInit</c> su una lista di container CloudKit candidati
/// e ripristina sempre i token CloudKit della sessione.
/// </summary>
public sealed class CloudKitContainerProbeService
{
    private readonly ICloudBackupOrchestrator _orchestrator;

    public CloudKitContainerProbeService(ICloudBackupOrchestrator orchestrator)
    {
        _orchestrator = orchestrator;
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
        int TokenLength);

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

        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;
        var savedPartition = session.Partition;

        log?.Report($"CloudKit container probe — {list.Count} candidati…");

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

                if (status == 200)
                {
                    hits.Add(new Hit(
                        c.ContainerId,
                        c.Label,
                        c.InCatalog,
                        status,
                        session.CloudKitUserId,
                        session.CloudKitGatewayUrl,
                        session.Partition,
                        session.CloudKitAuthToken?.Length ?? 0));
                    log?.Report(
                        $"    OK  userId={(string.IsNullOrEmpty(session.CloudKitUserId) ? "(empty)" : "present")} "
                        + $"gw={(string.IsNullOrEmpty(session.CloudKitGatewayUrl) ? "(empty)" : "present")}");
                }
                else
                {
                    hits.Add(new Hit(
                        c.ContainerId, c.Label, c.InCatalog,
                        status,
                        CloudKitUserId: null,
                        GatewayUrl: null,
                        Partition: null,
                        TokenLength: 0));
                    log?.Report($"    HTTP {status}");
                }

                if (i + 1 < list.Count)
                    await Task.Delay(120, ct).ConfigureAwait(false);
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

    public static string FormatReport(IReadOnlyList<Hit> hits)
    {
        var ok = hits.Where(static h => h.StatusCode == 200).ToList();
        var denied = hits.Where(static h => h.StatusCode is >= 400 and < 500).ToList();
        var other = hits.Where(static h => h.StatusCode != 200 && h.StatusCode is not (>= 400 and < 500))
            .ToList();

        var sb = new StringBuilder();
        sb.AppendLine("=== CloudKit container probe (ckAppInit) ===");
        sb.AppendLine($"Candidati: {hits.Count}  |  OK: {ok.Count}  |  4xx: {denied.Count}  |  altro: {other.Count}");
        sb.AppendLine("Read-only: no Relogin; session CloudKit tokens restored.");
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
                sb.AppendLine($"{h.ContainerId}  [{tag}]  {h.Label}");
                sb.AppendLine($"  ckUserId={NullDash(h.CloudKitUserId)}  tokenLen={h.TokenLength}  partition={NullDash(h.Partition)}");
                sb.AppendLine($"  gateway={NullDash(h.GatewayUrl)}");
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
