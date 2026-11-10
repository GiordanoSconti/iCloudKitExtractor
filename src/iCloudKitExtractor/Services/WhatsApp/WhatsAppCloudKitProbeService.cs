using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;

namespace iCloudKitExtractor.Services.WhatsApp;

/// <summary>
/// Probe CloudKit private DB sul container WhatsApp:
/// ckAppInit → zone/retrieve(_defaultZone) → zone/sync →
/// record/sync sulle zone custom (mai su _defaultZone: getChanges non supportato).
/// </summary>
public sealed class WhatsAppCloudKitProbeService
{
    private static readonly Regex GuidLike = new(
        @"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        RegexOptions.Compiled);

    private readonly ICloudBackupOrchestrator _orchestrator;
    private readonly CloudKitGatewayClient _gateway;

    public WhatsAppCloudKitProbeService(HttpClient http, ICloudBackupOrchestrator orchestrator)
    {
        _orchestrator = orchestrator;
        _gateway = new CloudKitGatewayClient(http);
    }

    public async Task<WhatsAppProbeResult> ProbePrivateDatabaseAsync(
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Session has no dsid — sign in first.");
        if (string.IsNullOrWhiteSpace(session.CloudKitAuthToken)
            && string.IsNullOrWhiteSpace(session.MobileMeAuthToken)
            && string.IsNullOrWhiteSpace(session.CloudKitGsToken))
        {
            throw new InvalidOperationException("Session has no CloudKit/MME token.");
        }

        Directory.CreateDirectory(outputDirectory);
        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var outDir = Path.Combine(outputDirectory, $"whatsapp_ck_{stamp}");
        Directory.CreateDirectory(outDir);

        var binding = CloudKitContainerBinding.WhatsApp;
        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;
        var summaries = new List<WhatsAppZoneProbe>();

        try
        {
            log?.Report($"WhatsApp CloudKit probe → {outDir}");
            log?.Report($"  container={binding.ContainerId}");
            log?.Report($"  bundle={binding.BundleId}");

            log?.Report("ckAppInit (WhatsApp)…");
            await _orchestrator.CkAppInitAsync(session, binding.ContainerId, log, ct);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId))
                throw new InvalidOperationException("ckAppInit WhatsApp missing cloudKitUserId.");
            if (string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
                throw new InvalidOperationException("ckAppInit WhatsApp missing cloudKitToken.");

            log?.Report(
                $"  ckUserId={session.CloudKitUserId} tokenLen={session.CloudKitAuthToken.Length}");

            File.WriteAllText(
                Path.Combine(outDir, "session.txt"),
                $"container={binding.ContainerId}\r\n" +
                $"bundle={binding.BundleId}\r\n" +
                $"ckUserId={session.CloudKitUserId}\r\n" +
                $"tokenPrefix={session.CloudKitAuthToken[..Math.Min(8, session.CloudKitAuthToken.Length)]}…\r\n" +
                $"dsid={session.Dsid}\r\n");

            // 1) zone/retrieve: solo esistenza. getChanges NON supportato su _defaultZone.
            summaries.Add(await ProbeNamedZoneRetrieveAsync(
                session, binding, outDir, "_defaultZone", log, ct));
            log?.Report(
                "  note: _defaultZone does not support RecordRetrieveChanges (AppDefaultZone); " +
                "empty sync zone ⇒ no custom zones in native WA container.");

            // 2) Database changes → elenco zone custom
            log?.Report("ZoneRetrieveChanges (database)…");
            byte[] zoneChangesPayload;
            try
            {
                var body = CloudKitDelimitedRequest.BuildZoneRetrieveChanges(
                    session.CloudKitUserId, container: binding);
                zoneChangesPayload = await _gateway.ZoneChangesAsync(session, body, ct, binding);
            }
            catch (Exception ex)
            {
                log?.Report($"  ERROR ZoneRetrieveChanges: {ex.Message}");
                summaries.Add(new WhatsAppZoneProbe("zone/changes", false, 0, ex.Message, []));
                log?.Report("WhatsApp probe completed (backup tokens restored).");
                return new WhatsAppProbeResult(outDir, binding.ContainerId, summaries);
            }

            await SavePayloadAsync(
                outDir, "zone_changes", zoneChangesPayload, log, ct);
            var zoneChangeStrings = CloudKitResponseParser.ExtractDiagnosticStrings(zoneChangesPayload);
            summaries.Add(new WhatsAppZoneProbe(
                "zone/changes",
                !CloudKitResponseParser.IsCloudKitErrorPayload(zoneChangesPayload, out _),
                zoneChangesPayload.Length,
                CloudKitResponseParser.DescribeCompactPayload(zoneChangesPayload),
                zoneChangeStrings.Take(50).ToList()));

            var zonesToScan = new HashSet<string>(StringComparer.Ordinal);
            foreach (var z in ExtractLikelyZoneNames(zoneChangeStrings))
            {
                if (!IsDefaultZone(z))
                    zonesToScan.Add(z);
            }

            if (zonesToScan.Count == 0)
            {
                log?.Report(
                    "  no custom zone: WA files live in CloudDocs " +
                    "(zone 57T9237FN3.net.whatsapp.WhatsApp), not in this container.");
            }
            else
            {
                log?.Report($"  zone custom da scansionare ({zonesToScan.Count}): {string.Join(", ", zonesToScan)}");
                foreach (var zone in zonesToScan.OrderBy(static z => z, StringComparer.Ordinal))
                {
                    ct.ThrowIfCancellationRequested();
                    summaries.Add(await ProbeRecordChangesAsync(
                        session, binding, outDir, zone, log, ct));
                }
            }

            log?.Report("WhatsApp probe completed (backup tokens restored).");
            return new WhatsAppProbeResult(outDir, binding.ContainerId, summaries);
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    private async Task<WhatsAppZoneProbe> ProbeNamedZoneRetrieveAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string zone,
        IProgress<string>? log,
        CancellationToken ct)
    {
        log?.Report($"zone/retrieve → {zone}…");
        try
        {
            var body = CloudKitDelimitedRequest.BuildZoneRetrieve(
                session.CloudKitUserId, [zone], container: binding);
            var payload = await _gateway.ZoneRetrieveAsync(session, body, ct, container: binding);
            await SavePayloadAsync(outDir, $"zones_{Sanitize(zone)}", payload, log, ct);
            var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
            var err = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var errDesc)
                ? errDesc
                : CloudKitResponseParser.DescribeCompactPayload(payload);
            if (!string.IsNullOrWhiteSpace(err))
                log?.Report($"  nota: {err}");
            return new WhatsAppZoneProbe(zone, err is null || !err.Contains("not exist", StringComparison.OrdinalIgnoreCase),
                payload.Length, err, strings.Take(50).ToList());
        }
        catch (Exception ex)
        {
            log?.Report($"  ERROR: {ex.Message}");
            return new WhatsAppZoneProbe(zone, false, 0, ex.Message, []);
        }
    }

    private async Task<WhatsAppZoneProbe> ProbeRecordChangesAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string zone,
        IProgress<string>? log,
        CancellationToken ct)
    {
        log?.Report($"RecordRetrieveChanges → {zone}…");
        byte[]? syncToken = null;
        var page = 0;
        var totalBytes = 0;
        var allStrings = new List<string>();
        string? lastNote = null;
        var ok = false;

        try
        {
            while (page < 8)
            {
                page++;
                var body = CloudKitDelimitedRequest.BuildRecordRetrieveChanges(
                    session.CloudKitUserId, zone, syncToken, binding);
                var payload = await _gateway.RecordChangesAsync(session, body, ct, binding);
                totalBytes += payload.Length;
                var tag = $"record_changes_{Sanitize(zone)}_p{page}";
                await SavePayloadAsync(outDir, tag, payload, log, ct);

                var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                allStrings.AddRange(strings);
                lastNote = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var errDesc)
                    ? errDesc
                    : CloudKitResponseParser.DescribeCompactPayload(payload);
                if (!string.IsNullOrWhiteSpace(lastNote))
                    log?.Report($"  p{page} nota: {lastNote}");

                ok = !CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _);
                if (!ok)
                    break;

                if (!CloudKitResponseParser.ResponseIndicatesMoreResults(payload))
                    break;

                // Token grezzo: spesso compare come run binario; senza parser dedicato fermiamoci
                // dopo moreComing se non abbiamo un token esplicito.
                log?.Report($"  p{page} moreComing=true — stop (syncToken parser required to continue)");
                break;
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  ERROR: {ex.Message}");
            lastNote = ex.Message;
            ok = false;
        }

        return new WhatsAppZoneProbe(
            $"changes:{zone}",
            ok,
            totalBytes,
            lastNote,
            allStrings.Distinct(StringComparer.Ordinal).Take(80).ToList());
    }

    private static async Task SavePayloadAsync(
        string outDir,
        string tag,
        byte[] payload,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var bin = Path.Combine(outDir, $"{tag}.bin");
        await File.WriteAllBytesAsync(bin, payload, ct);
        var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
        File.WriteAllLines(Path.Combine(outDir, $"{tag}_strings.txt"), strings);
        log?.Report($"  risposta {payload.Length} B → {bin}");
        foreach (var s in strings.Take(25))
            log?.Report($"    «{s}»");
    }

    /// <summary>
    /// Euristica: stringhe che sembrano nomi zona (non UUID, non owner id, non messaggi errore).
    /// </summary>
    internal static IEnumerable<string> ExtractLikelyZoneNames(IEnumerable<string> strings)
    {
        foreach (var raw in strings)
        {
            var s = NormalizeZoneName(raw);
            if (!LooksLikeRealZoneName(s))
                continue;
            if (IsDefaultZone(s))
                continue;
            if (s.StartsWith('_') && s.Length == 33 && s.Skip(1).All(Uri.IsHexDigit))
                continue; // owner / ck user
            if (GuidLike.IsMatch(s))
                continue;
            if (s.Contains("error", StringComparison.OrdinalIgnoreCase)
                || s.Contains("not exist", StringComparison.OrdinalIgnoreCase)
                || s.Contains("notFound", StringComparison.OrdinalIgnoreCase)
                || s.Contains("not support", StringComparison.OrdinalIgnoreCase)
                || s.StartsWith("ck", StringComparison.OrdinalIgnoreCase) && s.Length < 16)
                continue;
            if (s is "SUCCESS" or "FAILURE" or "PARTIAL" or "Production")
                continue;
            if (s.StartsWith("CKD", StringComparison.Ordinal))
                continue;
            yield return s;
        }
    }

    /// <summary>
    /// Nome zona CloudKit plausibile (Messages/Drive/…). Scarta rumore binario
    /// tipo <c>.91qX&gt;</c>, <c>GE{'{'}.</c>, <c>3u.q</c>.
    /// </summary>
    internal static bool LooksLikeRealZoneName(string s)
    {
        if (string.IsNullOrWhiteSpace(s) || s.Length is < 3 or > 128)
            return false;
        if (s.Contains(' ', StringComparison.Ordinal) || s.Contains('\t'))
            return false;
        // Solo identifier-safe (niente { } < > # ecc.)
        if (!s.All(static c => char.IsLetterOrDigit(c) || c is '.' or '_' or '-' or '~'))
            return false;
        // Deve contenere almeno una lettera.
        if (!s.Any(char.IsLetter))
            return false;

        if (s.EndsWith("Zone", StringComparison.OrdinalIgnoreCase)
            || s.EndsWith("_zone", StringComparison.OrdinalIgnoreCase)
            || s.Equals("metadata_zone", StringComparison.OrdinalIgnoreCase)
            || s.StartsWith("CD_", StringComparison.OrdinalIgnoreCase)
            || s.Equals("PrimarySync", StringComparison.OrdinalIgnoreCase))
            return true;

        // reverse-DNS: com.apple.… / bundle-style — segmenti alfanumerici, ≥2 punti.
        if (s.Contains('.', StringComparison.Ordinal))
        {
            var parts = s.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                return false;
            if (!parts.All(static p => p.Length > 0 && p.All(char.IsLetterOrDigit)))
                return false;
            // Evita "3u.q" / "xO.Z": serve almeno un segmento ≥3 con lettere.
            return parts.Any(static p => p.Length >= 3 && p.Any(char.IsLetter))
                   && s.Length >= 8;
        }

        // Alfanumerico lungo senza punteggiatura (es. BeaconStore).
        return s.Length >= 10
               && s.All(static c => char.IsLetterOrDigit(c) || c is '-' or '_' or '~');
    }

    internal static string NormalizeZoneName(string raw)
    {
        var s = raw.Trim();
        // Prefissi wire tipici: !owner, $uuid, &zone, #deleted-marker, spazi spurii.
        while (s.Length > 0 && s[0] is '!' or '$' or '&' or '#' or ' ' or '\t')
            s = s[1..].TrimStart();
        return s;
    }

    internal static bool IsDefaultZone(string zone) =>
        string.Equals(zone, "_defaultZone", StringComparison.Ordinal)
        || string.Equals(zone, "defaultZone", StringComparison.OrdinalIgnoreCase)
        || string.Equals(zone, "AppDefaultZone", StringComparison.OrdinalIgnoreCase);

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        return sb.ToString();
    }
}

public sealed record WhatsAppProbeResult(
    string OutputDirectory,
    string ContainerId,
    IReadOnlyList<WhatsAppZoneProbe> Zones);

public sealed record WhatsAppZoneProbe(
    string ZoneName,
    bool LooksOk,
    int PayloadBytes,
    string? Note,
    IReadOnlyList<string> SampleStrings);
