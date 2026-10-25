using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Senza cache MMCS locale (tipico su Windows), il primo seed KA: non è nel bootstrap.
/// Prova PrivilegedBatchFetch con UUID/checksum da manifestChecksums (:CN:).
/// </summary>
public sealed class CloudKitColdStartSeedService
{
    private const int MaxCnEntries = 12;
    private const int MaxProbes = 48;

    private readonly CloudKitQueryService _query;

    public CloudKitColdStartSeedService(CloudKitQueryService query) => _query = query;

    public async Task<IReadOnlyList<string>> ProbeSeedsAsync(
        ICloudSession session,
        BackupDevice device,
        byte[]? devicePayload,
        byte[]? snapshotPayload,
        RestoreSessionState? restore,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var cnEntries = CloudKitManifestChecksumParser.ParseCnEntries(devicePayload, snapshotPayload);
        if (cnEntries.Count == 0)
        {
            log?.Report("  manifestChecksums (:CN:) assente nel bootstrap");
            return [];
        }

        var prefix = CloudKitRecordNames.DevicePrefix4(device.DeviceUuid);
        var candidates = CloudKitManifestChecksumParser
            .BuildProbeRecordNames(prefix, cnEntries.Take(MaxCnEntries), MaxProbes)
            .ToList();

        log?.Report(
            $"CloudKit: cold-start probe ({cnEntries.Count} :CN:, {candidates.Count} query)…");

        var found = new HashSet<string>(StringComparer.Ordinal);
        var probes = 0;

        foreach (var recordName in candidates)
        {
            ct.ThrowIfCancellationRequested();
            probes++;

            try
            {
                await Task.Delay(250, ct);
                var payload = await _query.QueryFetchPayloadAsync(session, recordName, restore, ct);
                var added = MergeProbeResult(found, payload);
                if (added > 0)
                {
                    log?.Report($"  probe hit {recordName} → +{added} nomi");
                    if (found.Any(IsBatchFetchCandidate))
                        break;
                }
            }
            catch
            {
                // nome candidato errato — atteso in cold start
            }
        }

        if (found.Count > 0)
            log?.Report($"  cold-start → {found.Count} seed da {probes} probe");
        else
            log?.Report($"  cold-start → 0 seed ({probes} probe, cache iOS/necessaria per il primo KA:)");

        return found.OrderBy(static n => n, StringComparer.Ordinal).ToList();
    }

    private static int MergeProbeResult(HashSet<string> found, byte[] payload)
    {
        var before = found.Count;

        foreach (var name in CloudKitResponseParser.ExtractAssetRecordNames(payload))
            found.Add(name);

        foreach (var asset in CloudKitAssetService.ParseAssetsFromPayload(payload))
        {
            if (!string.IsNullOrWhiteSpace(asset.RecordName))
                found.Add(asset.RecordName);
        }

        return found.Count - before;
    }

    private static bool IsBatchFetchCandidate(string recordName) =>
        recordName.StartsWith("KA:", StringComparison.Ordinal)
        || recordName.StartsWith("MA:", StringComparison.Ordinal)
        || recordName.StartsWith("LA:", StringComparison.Ordinal)
        || recordName.StartsWith("NA:", StringComparison.Ordinal)
        || recordName.StartsWith("JA:", StringComparison.Ordinal);
}
