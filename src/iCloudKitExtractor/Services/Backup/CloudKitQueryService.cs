using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

public sealed record QueryDiscoveryResult(
    IReadOnlyList<string> RecordNames,
    IReadOnlyList<BackupAsset> Assets);

/// <summary>
/// Discovery asset via CloudKit query/retrieve (PrivilegedBatchRecordFetch dinamico).
/// </summary>
public sealed class CloudKitQueryService
{
    private const int MaxBfsFetches = 512;

    private readonly CloudKitGatewayClient _gateway;

    public CloudKitQueryService(CloudKitGatewayClient gateway) => _gateway = gateway;

    public CloudKitQueryService(HttpClient http) : this(new CloudKitGatewayClient(http)) { }

    public async Task<QueryDiscoveryResult> DiscoverViaQueryAsync(
        ICloudSession session,
        IEnumerable<string> seedRecordNames,
        IProgress<string>? log = null,
        RestoreSessionState? restore = null,
        CancellationToken ct = default)
    {
        var seeds = seedRecordNames
            .Where(static s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        log?.Report($"CloudKit: discovery query da {seeds.Count} seed…");
        if (seeds.Count == 0)
            log?.Report("  nessun seed asset nel catalogo bootstrap");

        return await DiscoverViaBatchFetchBfsAsync(session, seeds, log, restore, ct);
    }

    public async Task<QueryDiscoveryResult> DiscoverViaBatchFetchBfsAsync(
        ICloudSession session,
        IEnumerable<string> seedRecordNames,
        IProgress<string>? log = null,
        RestoreSessionState? restore = null,
        CancellationToken ct = default,
        int? maxFetches = null)
    {
        var prioritizedSeeds = seedRecordNames
            .Where(IsBatchFetchCandidate)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(BatchFetchPriority)
            .ThenBy(static s => s, StringComparer.Ordinal)
            .ToList();

        var names = new HashSet<string>(StringComparer.Ordinal);
        var assets = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        var queue = new Queue<string>(prioritizedSeeds);
        var visited = new HashSet<string>(StringComparer.Ordinal);

        foreach (var seed in seedRecordNames)
        {
            if (!string.IsNullOrWhiteSpace(seed))
                names.Add(seed);
        }

        if (prioritizedSeeds.Count > 0)
        {
            var head = prioritizedSeeds[0];
            log?.Report(
                $"  BFS seed head → {head[..Math.Min(48, head.Length)]}… " +
                $"({prioritizedSeeds.Count} candidati, priorità KA>MA>LA>NA>JA)");
        }

        var fetched = 0;
        var fetchLimit = maxFetches ?? MaxBfsFetches;
        while (queue.Count > 0 && fetched < fetchLimit)
        {
            ct.ThrowIfCancellationRequested();
            var recordName = queue.Dequeue();
            if (!visited.Add(recordName))
                continue;

            fetched++;
            try
            {
                await PaceAsync(ct);
                var payload = await QueryFetchPayloadAsync(session, recordName, restore, ct);
                foreach (var found in CloudKitResponseParser.ExtractAssetRecordNames(payload))
                {
                    names.Add(found);
                    if (IsBatchFetchCandidate(found))
                        queue.Enqueue(found);
                }

                foreach (var asset in CloudKitAssetService.ParseAssetsFromPayload(payload))
                {
                    assets[asset.RecordName] = asset;
                    if (IsBatchFetchCandidate(asset.RecordName))
                        queue.Enqueue(asset.RecordName);
                }

                var single = CloudKitAssetService.ParseAssetRecord(payload, recordName);
                if (single is not null && !string.IsNullOrWhiteSpace(single.MmcsAuth))
                    assets[single.RecordName] = single;
            }
            catch (Exception ex)
            {
                log?.Report($"  query {recordName} skip: {ex.Message}");
            }
        }

        if (fetched > 0)
        {
            var phase = maxFetches is not null ? "parziale" : "BFS";
            log?.Report($"  query {phase}: {fetched} fetch, {names.Count} nomi, {assets.Count} con auth");
        }

        return new QueryDiscoveryResult(
            names.OrderBy(static n => n, StringComparer.Ordinal).ToList(),
            assets.Values.OrderBy(static a => a.RecordName, StringComparer.Ordinal).ToList());
    }

    public async Task<IReadOnlyList<string>> QueryFetchRecordAsync(
        ICloudSession session,
        string recordName,
        IProgress<string>? log,
        CancellationToken ct)
    {
        log?.Report($"CloudKit: query PrivilegedBatchFetch {recordName}…");
        var payload = await QueryFetchPayloadAsync(session, recordName, restore: null, ct);
        var found = CloudKitResponseParser.ExtractAssetRecordNames(payload);
        log?.Report($"  query → {found.Count} record");
        return found;
    }

    public async Task<byte[]> QueryFetchPayloadAsync(
        ICloudSession session,
        string recordName,
        RestoreSessionState? restore,
        CancellationToken ct) =>
        await QueryFetchPayloadAsync(session, [recordName], restore, ct);

    public async Task<byte[]> QueryFetchPayloadAsync(
        ICloudSession session,
        IReadOnlyList<string> recordNames,
        RestoreSessionState? restore,
        CancellationToken ct)
    {
        RestoreRequestContext? ctx = null;
        try
        {
            ctx = restore?.ToRequestContext();
        }
        catch (InvalidOperationException)
        {
            // query fuori fase restore senza foreground
        }

        var body = CloudKitDelimitedRequest.BuildPrivilegedBatchFetch(
            session.CloudKitUserId, "_defaultZone", recordNames, ctx);
        return await _gateway.QueryRetrieveAsync(session, body, ct, restore);
    }

    public async Task<BackupAsset?> FetchAssetViaQueryAsync(
        ICloudSession session,
        string recordName,
        RestoreSessionState? restore,
        CancellationToken ct)
    {
        var payload = await QueryFetchPayloadAsync(session, recordName, restore, ct);
        return CloudKitAssetService.ParseAssetRecord(payload, recordName);
    }

    public async Task<BackupAsset?> FetchAssetAsync(
        ICloudSession session,
        string recordName,
        CancellationToken ct)
    {
        var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
            session.CloudKitUserId, "_defaultZone", [recordName]);
        var payload = await _gateway.RecordRetrieveAsync(session, body, ct);
        return CloudKitAssetService.ParseAssetRecord(payload, recordName);
    }

    private static bool IsBatchFetchCandidate(string recordName) =>
        recordName.StartsWith("KA:", StringComparison.Ordinal)
        || recordName.StartsWith("MA:", StringComparison.Ordinal)
        || recordName.StartsWith("LA:", StringComparison.Ordinal)
        || recordName.StartsWith("NA:", StringComparison.Ordinal)
        || recordName.StartsWith("JA:", StringComparison.Ordinal);

    /// <summary>parte da KA:; JA: arriva dopo dalle risposte, non come seed alfabetico.</summary>
    private static int BatchFetchPriority(string recordName)
    {
        if (recordName.StartsWith("KA:", StringComparison.Ordinal)) return 0;
        if (recordName.StartsWith("MA:", StringComparison.Ordinal)) return 1;
        if (recordName.StartsWith("LA:", StringComparison.Ordinal)) return 2;
        if (recordName.StartsWith("NA:", StringComparison.Ordinal)) return 3;
        if (recordName.StartsWith("JA:", StringComparison.Ordinal)) return 4;
        return 5;
    }

    private static Task PaceAsync(CancellationToken ct) => Task.Delay(300, ct);
}
