using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>Risultato del catalogo file deterministico (classico M: o moderno :CN:).</summary>
public sealed class DeterministicFileCatalog
{
    /// <summary><c>classic-M</c> oppure <c>modern-CN</c>.</summary>
    public required string Source { get; init; }

    public required IReadOnlyList<string> ManifestIds { get; init; }
    public required IReadOnlyList<string> FileRecordNames { get; init; }
    public required IReadOnlyDictionary<string, int> FilesPerManifest { get; init; }
    public int CnEntryCount { get; init; }
    public byte[]? SnapshotPayload { get; init; }
}

/// <summary>
/// Risolve l'elenco file backup in modo deterministico (non per candidati MA:).
/// <list type="bullet">
/// <item>Classico: <c>S:</c> → <c>manifestIDs</c> → <c>M:…:0</c> → <c>files</c></item>
/// <item>Moderno : <c>S:</c> → <c>:CN:uuid:checksum</c> / <c>domainBaseRecordIDs</c></item>
/// </list>
/// </summary>
public sealed class BackupDeterministicCatalogService
{
    private readonly CloudKitGatewayClient _gateway;
    private readonly CloudKitQueryService _query;

    public BackupDeterministicCatalogService(HttpClient http)
    {
        _gateway = new CloudKitGatewayClient(http);
        _query = new CloudKitQueryService(_gateway);
    }

    public BackupDeterministicCatalogService(
        CloudKitGatewayClient gateway,
        CloudKitQueryService query)
    {
        _gateway = gateway;
        _query = query;
    }

    public async Task<DeterministicFileCatalog> ResolveAsync(
        ICloudSession session,
        BackupSnapshot snapshot,
        string outputDirectory,
        RestoreSessionState? restore = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);

        var sPayload = snapshot.CatalogPayload;
        if (sPayload is not { Length: > 256 })
        {
            log?.Report("CloudKit: fetch snapshot S: for file catalog…");
            sPayload = await FetchMbksyncRecordAsync(session, snapshot.RecordName, restore, log, ct);
        }
        else
        {
            log?.Report($"  snapshot S: from list cache ({sPayload.Length:N0} bytes)");
        }

        if (sPayload is not { Length: > 0 })
            throw new InvalidOperationException(
                "Snapshot S: payload missing — cannot build file catalog.");

        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "snapshot_S_payload.bin"), sPayload, ct);

        var manifestIds = CloudKitManifestCatalogParser.ExtractManifestIds(sPayload);
        var allCn = CloudKitManifestChecksumParser.ParseCatalogCnEntries(sPayload);
        // EN:/flist: UUID file (manifestChecksums), non domainBase (UUID = snapshot).
        var cnEntries = CloudKitManifestChecksumParser.ParseFileCnEntries(
            sPayload, snapshot.RecordName);

        log?.Report(
            $"  S: → manifestIDs(M:)={manifestIds.Count}, voci :CN:={allCn.Count}" +
            (cnEntries.Count != allCn.Count
                ? $" (file UUID={cnEntries.Count}, domainBase excluded)"
                : ""));

        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "manifest_ids.json"),
            JsonSerializer.Serialize(new
            {
                snapshot = snapshot.RecordName,
                classicManifestIds = manifestIds.Count,
                cnEntries = allCn.Count,
                fileCnEntries = cnEntries.Count,
                ids = manifestIds,
                cnSample = cnEntries.Take(32).Select(CloudKitManifestChecksumParser.ToCatalogRecordName)
            }, new JsonSerializerOptions { WriteIndented = true }),
            ct);

        // Preferisci classico solo se M: è davvero presente; altrimenti path moderno :CN:.
        if (manifestIds.Count > 0)
            return await ResolveClassicMAsync(
                session, snapshot, outputDirectory, sPayload, manifestIds, restore, log, ct);

        if (cnEntries.Count > 0)
            return await ResolveModernCnAsync(snapshot, outputDirectory, sPayload, cnEntries, log, ct);

        throw new InvalidOperationException(
            $"No file catalog in snapshot {snapshot.RecordName}: " +
            "manifestIDs(M:)=0 and :CN: entries=0.");
    }

    private static async Task<DeterministicFileCatalog> ResolveModernCnAsync(
        BackupSnapshot snapshot,
        string outputDirectory,
        byte[] sPayload,
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var fileList = cnEntries
            .Select(CloudKitManifestChecksumParser.ToCatalogRecordName)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static n => n, StringComparer.Ordinal)
            .ToList();

        log?.Report(
            $"  modern :CN: catalog → {fileList.Count:N0} ids " +
            $"(manifestChecksums file UUID → EN:/Manifest; MMCS download uses PreAuth/query)");

        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "cn_catalog.json"),
            JsonSerializer.Serialize(new
            {
                snapshot = snapshot.RecordName,
                source = "modern-CN",
                count = fileList.Count,
                uuidSample = cnEntries.Take(8).Select(static e => e.FileUuid).Distinct().ToList(),
                records = fileList
            }, new JsonSerializerOptions { WriteIndented = true }),
            ct);

        return new DeterministicFileCatalog
        {
            Source = "modern-CN",
            ManifestIds = [],
            FileRecordNames = fileList,
            FilesPerManifest = new Dictionary<string, int>(StringComparer.Ordinal)
            {
                [":CN:"] = fileList.Count
            },
            CnEntryCount = fileList.Count,
            SnapshotPayload = sPayload
        };
    }

    private async Task<DeterministicFileCatalog> ResolveClassicMAsync(
        ICloudSession session,
        BackupSnapshot snapshot,
        string outputDirectory,
        byte[] sPayload,
        IReadOnlyList<string> manifestIds,
        RestoreSessionState? restore,
        IProgress<string>? log,
        CancellationToken ct)
    {
        log?.Report($"  classic path: fetch {manifestIds.Count} M:…:0… records");

        var allFiles = new Dictionary<string, byte>(StringComparer.Ordinal);
        var perManifest = new Dictionary<string, int>(StringComparer.Ordinal);
        var mIndex = 0;

        foreach (var manifestId in manifestIds)
        {
            ct.ThrowIfCancellationRequested();
            mIndex++;
            var recordName = CloudKitManifestCatalogParser.ToManifestRecordName(manifestId);
            log?.Report($"CloudKit: fetch M: {mIndex}/{manifestIds.Count} → {recordName}");

            var mPayload = await FetchDefaultZoneRecordAsync(
                session, recordName, restore, log, ct);
            if (mPayload is not { Length: > 0 })
            {
                log?.Report($"  FAIL M: {recordName} — empty payload");
                perManifest[manifestId] = 0;
                continue;
            }

            var safe = Sanitize(recordName);
            if (safe.Length > 72)
                safe = safe[..72];
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, $"M_{mIndex:D2}_{safe}.bin"), mPayload, ct);

            var files = CloudKitManifestCatalogParser.ExtractFileRecordNames(mPayload);
            perManifest[manifestId] = files.Count;
            foreach (var f in files)
                allFiles.TryAdd(f, 0);

            log?.Report($"  M: OK ({mPayload.Length:N0} B) → {files.Count:N0} files in files field");
        }

        var fileList = allFiles.Keys
            .OrderBy(static n => n, StringComparer.Ordinal)
            .ToList();

        log?.Report($"  classic catalog → {fileList.Count:N0} unique files from {manifestIds.Count} M:");

        return new DeterministicFileCatalog
        {
            Source = "classic-M",
            ManifestIds = manifestIds,
            FileRecordNames = fileList,
            FilesPerManifest = perManifest,
            CnEntryCount = 0,
            SnapshotPayload = sPayload
        };
    }

    private async Task<byte[]?> FetchMbksyncRecordAsync(
        ICloudSession session,
        string recordName,
        RestoreSessionState? restore,
        IProgress<string>? log,
        CancellationToken ct)
    {
        try
        {
            var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
                session.CloudKitUserId,
                "mbksync",
                [CloudKitRecordNames.CanonicalSnapshotRecordName(recordName)],
                restore?.ToRequestContext());
            var payload = await _gateway.RecordRetrieveAsync(session, body, ct, restore);
            if (payload.Length > 0)
                log?.Report($"  fetch S: OK ({payload.Length:N0} byte)");
            return payload.Length > 0 ? payload : null;
        }
        catch (Exception ex)
        {
            log?.Report($"  fetch S: skip: {ex.Message}");
            return null;
        }
    }

    private async Task<byte[]?> FetchDefaultZoneRecordAsync(
        ICloudSession session,
        string recordName,
        RestoreSessionState? restore,
        IProgress<string>? log,
        CancellationToken ct)
    {
        try
        {
            var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
                session.CloudKitUserId,
                "_defaultZone",
                [recordName],
                restore?.ToRequestContext());
            var payload = await _gateway.RecordRetrieveAsync(session, body, ct, restore);
            if (payload.Length >= 64
                && !CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _))
                return payload;

            if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err))
                log?.Report($"  retrieve {recordName}: {err}");
        }
        catch (Exception ex)
        {
            log?.Report($"  retrieve {recordName} skip: {ex.Message}");
        }

        try
        {
            var payload = await _query.QueryFetchPayloadAsync(session, recordName, restore, ct);
            if (payload.Length >= 64
                && !CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _))
            {
                log?.Report($"  query M: OK ({payload.Length:N0} byte)");
                return payload;
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  query {recordName} skip: {ex.Message}");
        }

        return null;
    }

    private static string Sanitize(string name)
    {
        var chars = name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_').ToArray();
        return new string(chars);
    }
}
