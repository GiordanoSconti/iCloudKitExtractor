using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.SyncData;
using iCloudKitExtractor.Services.WhatsApp;

namespace iCloudKitExtractor.Services.CloudKit;

/// <summary>
/// Probe read-only: <c>ckAppInit</c> sui container candidati, poi (se OK)
/// <c>zone/sync</c> per flaggare CoreData zone, segnali PCS e zone share-like.
/// Ripristina sempre i token CloudKit della sessione.
/// </summary>
public sealed class CloudKitContainerProbeService
{
    public const string CoreDataCloudKitZone = VoiceMemosAudioDownloader.SyncZone;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

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
        IReadOnlyList<string>? Zones = null,
        bool PcsLikely = false,
        IReadOnlyList<string>? ShareZones = null,
        IReadOnlyList<string>? Signals = null,
        string Kind = "unknown");

    public sealed record AtlasResult(
        IReadOnlyList<Hit> Hits,
        int OkCount,
        int CoreDataCount,
        int PcsLikelyCount,
        int ShareZoneContainers,
        int ThirdPartyOk,
        string ReportText,
        string? OutputDirectory = null,
        string? JsonPath = null,
        string? CsvPath = null,
        string? ReportPath = null);

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
        var atlas = await ProbeAtlasAsync(session, candidates, outputDirectory: null, log, ct)
            .ConfigureAwait(false);
        return atlas.ReportText;
    }

    /// <summary>
    /// Container atlas: inventario strutturato + opzionale export sotto
    /// <c>laboratory/</c> (JSON / CSV / report).
    /// </summary>
    public async Task<AtlasResult> ProbeAtlasAsync(
        ICloudSession session,
        IReadOnlyList<Candidate>? candidates = null,
        string? outputDirectory = null,
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
            $"Container atlas — {list.Count} candidati " +
            $"(ckAppInit + zone/sync → CoreData / PCS / share)…");

        try
        {
            for (var i = 0; i < list.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var c = list[i];
                log?.Report($"  [{i + 1}/{list.Count}] {c.ContainerId}…");

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
                    hits.Add(MakeFailHit(c, -1));
                    log?.Report($"    EX: {ex.Message}");
                    continue;
                }

                if (status != 200)
                {
                    hits.Add(MakeFailHit(c, status));
                    log?.Report($"    HTTP {status}");
                    if (i + 1 < list.Count)
                        await Task.Delay(120, ct).ConfigureAwait(false);
                    continue;
                }

                log?.Report(
                    $"    OK  userId={(string.IsNullOrEmpty(session.CloudKitUserId) ? "(empty)" : "presente")} "
                    + $"gw={(string.IsNullOrEmpty(session.CloudKitGatewayUrl) ? "(empty)" : "presente")}");

                var binding = ResolveBinding(c);
                var zone = await TryZoneSyncAsync(gateway, session, binding, log, ct)
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
                    ZoneSyncOk: zone.Ok,
                    ZoneSyncBytes: zone.Bytes,
                    ZoneSyncNote: zone.Note,
                    HasCoreDataCloudKitZone: zone.HasCoreData,
                    Zones: zone.Zones,
                    PcsLikely: zone.PcsLikely,
                    ShareZones: zone.ShareZones,
                    Signals: zone.Signals,
                    Kind: ClassifyKind(c.ContainerId)));

                if (zone.HasCoreData)
                    log?.Report("    ★ Core Data CloudKit zone PRESENT");
                if (zone.PcsLikely)
                    log?.Report("    ◆ PCS signals in zone/sync payload");
                if (zone.ShareZones.Count > 0)
                    log?.Report($"    ◈ share-like zones: {string.Join(", ", zone.ShareZones)}");
                else if (zone.Ok)
                    log?.Report(
                        zone.Zones.Count > 0
                            ? $"    zone/sync OK — {zone.Zones.Count} zone"
                            : "    zone/sync OK — nessuna zona custom");
                else
                    log?.Report($"    zone/sync: {zone.Note ?? "fail"}");

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

        var report = FormatReport(hits);
        string? jsonPath = null, csvPath = null, reportPath = null, outDir = null;
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            outDir = Path.GetFullPath(outputDirectory.Trim());
            Directory.CreateDirectory(outDir);
            jsonPath = Path.Combine(outDir, "container_atlas.json");
            csvPath = Path.Combine(outDir, "container_atlas.csv");
            reportPath = Path.Combine(outDir, "container_atlas.txt");
            await File.WriteAllTextAsync(jsonPath, BuildAtlasJson(hits, session), ct)
                .ConfigureAwait(false);
            await File.WriteAllTextAsync(csvPath, BuildAtlasCsv(hits), ct).ConfigureAwait(false);
            await File.WriteAllTextAsync(reportPath, report, ct).ConfigureAwait(false);
            log?.Report($"  atlas → {outDir}");
        }

        var ok = hits.Count(static h => h.StatusCode == 200);
        return new AtlasResult(
            hits,
            OkCount: ok,
            CoreDataCount: hits.Count(static h => h.HasCoreDataCloudKitZone),
            PcsLikelyCount: hits.Count(static h => h.PcsLikely),
            ShareZoneContainers: hits.Count(static h => h.ShareZones is { Count: > 0 }),
            ThirdPartyOk: hits.Count(static h =>
                h.StatusCode == 200
                && h.Kind.Equals("third-party", StringComparison.OrdinalIgnoreCase)),
            ReportText: report,
            OutputDirectory: outDir,
            JsonPath: jsonPath,
            CsvPath: csvPath,
            ReportPath: reportPath);
    }

    private static Hit MakeFailHit(Candidate c, int status) => new(
        c.ContainerId, c.Label, c.InCatalog, status,
        CloudKitUserId: null, GatewayUrl: null, Partition: null, TokenLength: 0,
        Kind: ClassifyKind(c.ContainerId));

    private static string ClassifyKind(string containerId) =>
        containerId.StartsWith("com.apple.", StringComparison.OrdinalIgnoreCase)
        || containerId.StartsWith("iCloud.com.apple.", StringComparison.OrdinalIgnoreCase)
            ? "apple"
            : "third-party";

    private static async Task<(
        bool Ok,
        int Bytes,
        string? Note,
        IReadOnlyList<string> Zones,
        bool HasCoreData,
        bool PcsLikely,
        IReadOnlyList<string> ShareZones,
        IReadOnlyList<string> Signals)> TryZoneSyncAsync(
        CloudKitGatewayClient gateway,
        ICloudSession session,
        CloudKitContainerBinding binding,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
            || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
        {
            return (false, 0, "ck token/userId assenti dopo ckAppInit", [], false, false, [], []);
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
                return (false, payload.Length, reason, [], false, false, [], []);
            }

            var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
            var zones = WhatsAppCloudKitProbeService.ExtractLikelyZoneNames(strings)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .OrderBy(static z => z, StringComparer.OrdinalIgnoreCase)
                .ToList();

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

            var shareZones = zones.Where(LooksLikeShareZone).ToList();
            var signals = new List<string>();
            var pcsLikely = DetectPcsSignals(strings, zones, signals);
            if (hasCoreData)
                signals.Add("coredata-zone");
            if (shareZones.Count > 0)
                signals.Add($"share-zones:{shareZones.Count}");

            var note = CloudKitResponseParser.DescribeCompactPayload(payload)
                       ?? $"{zones.Count} zone";
            return (true, payload.Length, note, zones, hasCoreData, pcsLikely, shareZones, signals);
        }
        catch (Exception ex)
        {
            return (false, 0, ex.Message, [], false, false, [], []);
        }
    }

    private static bool DetectPcsSignals(
        IReadOnlyList<string> strings,
        IReadOnlyList<string> zones,
        List<string> signals)
    {
        var hits = 0;
        foreach (var s in strings)
        {
            if (ContainsAny(s,
                    "protectionInfo", "ProtectedCloudStorage", "pcsKey", "pcsservice",
                    "Manatee", "wrappingKey", "encryptedFields", "PCS"))
            {
                hits++;
                if (signals.Count < 8
                    && !signals.Any(x => x.StartsWith("pcs:", StringComparison.Ordinal)))
                    signals.Add("pcs:" + Trunc(s, 48));
            }

            if (ContainsAny(s, "shareEtag", "CKShare", "shareID", "participant", "ownerName"))
            {
                if (signals.Count < 12
                    && !signals.Any(x => x.StartsWith("share-sig:", StringComparison.Ordinal)))
                    signals.Add("share-sig:" + Trunc(s, 48));
            }
        }

        foreach (var z in zones)
        {
            if (ContainsAny(z, "PCS", "Manatee", "Protected"))
            {
                hits++;
                signals.Add("pcs-zone:" + z);
            }
        }

        return hits > 0;
    }

    private static bool LooksLikeShareZone(string zone)
    {
        if (string.IsNullOrWhiteSpace(zone))
            return false;
        return zone.Contains("Share", StringComparison.OrdinalIgnoreCase)
               || zone.Contains("Shared", StringComparison.OrdinalIgnoreCase)
               || zone.StartsWith("ckshare", StringComparison.OrdinalIgnoreCase)
               || zone.Contains(".share", StringComparison.OrdinalIgnoreCase)
               || zone.Contains("-share-", StringComparison.OrdinalIgnoreCase);
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

    private static CloudKitContainerBinding ResolveBinding(Candidate c)
    {
        foreach (var known in CloudKitContainerBinding.SyncDataContainers)
        {
            if (known.ContainerId.Equals(c.ContainerId, StringComparison.OrdinalIgnoreCase))
                return known;
        }

        var bundle = GuessBundleId(c.ContainerId);
        return new CloudKitContainerBinding(c.ContainerId, bundle);
    }

    private static string GuessBundleId(string containerId)
    {
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
        var pcs = hits.Where(static h => h.PcsLikely).ToList();
        var share = hits.Where(static h => h.ShareZones is { Count: > 0 }).ToList();
        var third = hits.Where(static h =>
            h.StatusCode == 200
            && h.Kind.Equals("third-party", StringComparison.OrdinalIgnoreCase)).ToList();
        var denied = hits.Where(static h => h.StatusCode is >= 400 and < 500).ToList();
        var other = hits.Where(static h => h.StatusCode != 200 && h.StatusCode is not (>= 400 and < 500))
            .ToList();

        var sb = new StringBuilder();
        sb.AppendLine("=== CloudKit container atlas ===");
        sb.AppendLine(
            $"Candidati: {hits.Count}  |  OK: {ok.Count}  |  CoreData: {coreData.Count}  |  PCS≈{pcs.Count}  |  share-zones: {share.Count}  |  3rd-party OK: {third.Count}  |  4xx: {denied.Count}");
        sb.AppendLine("Read-only: no Relogin; session CloudKit tokens restored.");
        sb.AppendLine();

        sb.AppendLine("--- ★ Core Data CloudKit zone ---");
        if (coreData.Count == 0)
            sb.AppendLine("(nessuno)");
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
        sb.AppendLine("--- ◆ PCS signals (heuristic) ---");
        if (pcs.Count == 0)
            sb.AppendLine("(nessuno)");
        else
        {
            foreach (var h in pcs.OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine(
                    $"{h.ContainerId}  signals=[{string.Join(", ", h.Signals ?? [])}]");
        }

        sb.AppendLine();
        sb.AppendLine("--- ◈ Share-like zones ---");
        if (share.Count == 0)
            sb.AppendLine("(nessuno)");
        else
        {
            foreach (var h in share.OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
                sb.AppendLine(
                    $"{h.ContainerId}  share=[{string.Join(", ", h.ShareZones!)}]");
        }

        sb.AppendLine();
        sb.AppendLine("--- Disponibili (HTTP 200) ---");
        if (ok.Count == 0)
            sb.AppendLine("(nessuno)");
        else
        {
            foreach (var h in ok.OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
            {
                var tag = h.InCatalog ? "catalogo" : "NUOVO?";
                var flags = new List<string>();
                if (h.HasCoreDataCloudKitZone)
                    flags.Add("COREDATA");
                if (h.PcsLikely)
                    flags.Add("PCS");
                if (h.ShareZones is { Count: > 0 })
                    flags.Add("SHARE");
                if (h.Kind == "third-party")
                    flags.Add("3P");
                var flagTxt = flags.Count == 0 ? "" : "  ★" + string.Join("+", flags);
                sb.AppendLine($"{h.ContainerId}  [{tag}/{h.Kind}]  {h.Label}{flagTxt}");
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
            sb.AppendLine("(nessuno)");
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
            $"★COREDATA = zone/sync ha elencato {CoreDataCloudKitZone} (NSPersistentCloudKitContainer).");
        sb.AppendLine("◆PCS / ◈SHARE = euristiche sul payload zone/sync — non equivalgono a unwrap completo.");
        sb.AppendLine("Does not imply zone/record parsing is already implemented in the app.");
        return sb.ToString().TrimEnd();
    }

    private static string BuildAtlasJson(IReadOnlyList<Hit> hits, ICloudSession session)
    {
        var doc = new
        {
            generatedAt = DateTimeOffset.UtcNow,
            dsid = session.Dsid,
            appleId = session.AppleId,
            summary = new
            {
                candidates = hits.Count,
                ok = hits.Count(static h => h.StatusCode == 200),
                coreData = hits.Count(static h => h.HasCoreDataCloudKitZone),
                pcsLikely = hits.Count(static h => h.PcsLikely),
                shareZoneContainers = hits.Count(static h => h.ShareZones is { Count: > 0 }),
                thirdPartyOk = hits.Count(static h =>
                    h.StatusCode == 200
                    && h.Kind.Equals("third-party", StringComparison.OrdinalIgnoreCase)),
            },
            containers = hits.Select(h => new
            {
                h.ContainerId,
                h.Label,
                h.Kind,
                h.InCatalog,
                h.StatusCode,
                available = h.StatusCode == 200,
                h.HasCoreDataCloudKitZone,
                h.PcsLikely,
                shareZones = h.ShareZones ?? [],
                zones = h.Zones ?? [],
                signals = h.Signals ?? [],
                h.ZoneSyncOk,
                h.ZoneSyncBytes,
                h.ZoneSyncNote,
                h.CloudKitUserId,
                h.GatewayUrl,
                h.Partition,
                h.TokenLength,
            }),
        };
        return JsonSerializer.Serialize(doc, JsonOpts);
    }

    private static string BuildAtlasCsv(IReadOnlyList<Hit> hits)
    {
        var sb = new StringBuilder();
        sb.AppendLine(
            "containerId,label,kind,inCatalog,status,available,coreData,pcsLikely,shareZones,zones,signals,zoneSyncOk,zoneSyncBytes");
        foreach (var h in hits.OrderBy(static x => x.ContainerId, StringComparer.OrdinalIgnoreCase))
        {
            sb.Append(Csv(h.ContainerId)).Append(',')
                .Append(Csv(h.Label)).Append(',')
                .Append(Csv(h.Kind)).Append(',')
                .Append(h.InCatalog ? "1" : "0").Append(',')
                .Append(h.StatusCode).Append(',')
                .Append(h.StatusCode == 200 ? "1" : "0").Append(',')
                .Append(h.HasCoreDataCloudKitZone ? "1" : "0").Append(',')
                .Append(h.PcsLikely ? "1" : "0").Append(',')
                .Append(Csv(string.Join('|', h.ShareZones ?? []))).Append(',')
                .Append(Csv(string.Join('|', h.Zones ?? []))).Append(',')
                .Append(Csv(string.Join('|', h.Signals ?? []))).Append(',')
                .Append(h.ZoneSyncOk ? "1" : "0").Append(',')
                .Append(h.ZoneSyncBytes)
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

        AddKnown(CloudKitContainerBinding.Backup.ContainerId, "Backup iOS");
        AddKnown(CloudKitContainerBinding.WhatsApp.ContainerId, "WhatsApp");
        AddKnown(CloudKitContainerBinding.CloudDocs.ContainerId, "iCloud Drive / CloudDocs");
        AddKnown(CloudKitContainerBinding.SearchParty.ContainerId, "Find My Items / SearchParty");
        AddKnown(CloudKitContainerBinding.Cuttlefish.ContainerId, "Octagon / Cuttlefish / Keychain");

        foreach (var c in CloudKitContainerBinding.SyncDataContainers)
            AddKnown(c.ContainerId, $"Sync Data · {c.BundleId}");

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
