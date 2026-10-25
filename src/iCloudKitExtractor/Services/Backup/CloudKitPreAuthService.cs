using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// PreAuth MMCS post-Lock allineato al flusso 
/// record/retrieve (ubchunk N:) → discovery parziale → query/retrieve → eventuali round aggiuntivi.
/// </summary>
public sealed class CloudKitPreAuthService
{
    /// <summary>Round iniziali su record/retrieve (201505: 2 richieste grandi prima delle query).</summary>
    private const int RecordRetrievePreAuthRounds = 2;

    private const int MaxPreAuthRounds = 8;

    private readonly CloudKitGatewayClient _gateway;

    public CloudKitPreAuthService(CloudKitGatewayClient gateway) => _gateway = gateway;

    public CloudKitPreAuthService(HttpClient http) : this(new CloudKitGatewayClient(http)) { }

    public async Task<CloudKitPreAuthResult> TryPreAuthRetrieveAsync(
        ICloudSession session,
        RestoreSessionState restore,
        BackupDevice device,
        byte[]? devicePayload,
        byte[]? snapshotPayload,
        byte[]? mbsPayload,
        byte[]? lockPayload,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var catalog = UbChunkCatalog.Empty;

        restore.TryAbsorbFromPayload(devicePayload);
        restore.TryAbsorbFromPayload(snapshotPayload);
        restore.TryAbsorbFromPayload(mbsPayload);
        restore.TryAbsorbFromPayload(lockPayload);

        var absorbed = ForegroundRestorePlistExtractor.Resolve(
            devicePayload, snapshotPayload, mbsPayload, lockPayload);
        if (absorbed is not null)
            log?.Report(
                $"  Foreground assorbito da risposta (hw={SafePrefix(absorbed.HardwareIdHex, 12)}…)");
        restore.EnsureForeground(session, device);

        var foreground = restore.Foreground!;
        log?.Report(
            $"  Foreground Restore (proto={foreground.ProtoVersion}, sha256={SafePrefix(foreground.PlistSha256Base64, 12)}…, hw={SafePrefix(foreground.HardwareIdHex, 12)}…)");

        var cnEntries = CloudKitManifestChecksumParser.ParseCnEntries(
            devicePayload, snapshotPayload, mbsPayload, lockPayload);
        if (cnEntries.Count == 0)
        {
            log?.Report("  manifestChecksums (:CN:) assente — PreAuth senza frame N:");
            return Finish(catalog, log);
        }

        log?.Report($"  manifestChecksums: {cnEntries.Count} voci :CN:");
        // 20260721: PreAuth record/retrieve = frame FG RequestOperation + N: (come round 2).
        // Il blob wSc sintetico (201505) produceva body senza CKDFetch/Foreground → HTTP 503.
        // Non generare materiale wSc finto: usare solo prefisso/blob estratti da risposte reali.
        if (restore.ResolvePreAuthWscPrefix() is { Length: > 0 } prefix)
            log?.Report($"  wSc prefix (da risposta) → {prefix.Length} byte");
        if (restore.PreAuthSessionBlob is { Length: >= 2800 } blob)
            log?.Report($"  session blob (da risposta) → {blob.Length} byte");

        var requestContext = restore.ToRequestContext();
        var skip = 0;

        skip = await RunRecordRetrievePreAuthRoundsAsync(
            session, restore, cnEntries, requestContext, catalog, skip, log, ct);
        catalog = restore.PreAuthCatalog;

        return new CloudKitPreAuthResult
        {
            Catalog = catalog,
            CnEntriesConsumed = skip,
            TotalCnEntries = cnEntries.Count
        };
    }

    /// <summary>
    /// Continua PreAuth su query/retrieve per le voci :CN: non ancora inviate (fase post-discovery parziale).
    /// </summary>
    public async Task<CloudKitPreAuthResult> TryPreAuthQueryRetrieveAsync(
        ICloudSession session,
        RestoreSessionState restore,
        BackupDevice device,
        byte[]? devicePayload,
        byte[]? snapshotPayload,
        byte[]? mbsPayload,
        byte[]? lockPayload,
        int cnSkip,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        restore.TryAbsorbFromPayload(devicePayload);
        restore.TryAbsorbFromPayload(snapshotPayload);
        restore.TryAbsorbFromPayload(mbsPayload);
        restore.TryAbsorbFromPayload(lockPayload);
        restore.EnsureForeground(session, device);

        var cnEntries = CloudKitManifestChecksumParser.ParseCnEntries(
            devicePayload, snapshotPayload, mbsPayload, lockPayload);
        if (cnSkip >= cnEntries.Count)
            return new CloudKitPreAuthResult { Catalog = restore.PreAuthCatalog, CnEntriesConsumed = cnSkip, TotalCnEntries = cnEntries.Count };

        var requestContext = restore.ToRequestContext();
        var catalog = restore.PreAuthCatalog;
        var skip = cnSkip;

        log?.Report($"CloudKit: PreAuth query/retrieve (da voce :CN: {skip + 1}/{cnEntries.Count})…");

        for (var round = 1; round <= MaxPreAuthRounds && skip < cnEntries.Count; round++)
        {
            ct.ThrowIfCancellationRequested();

            var body = UbChunkPreAuthRequestBuilder.BuildRound2(
                requestContext, session.CloudKitUserId, cnEntries, skipEntries: skip);

            log?.Report(
                $"  PreAuth query round {round} ({body.Length:N0} byte, {CountEnFrames(body)} N:)…");

            try
            {
                var payload = await _gateway.QueryRetrieveWscPreAuthAsync(session, body, ct, restore);
                restore.TryAbsorbFromPayload(payload);

                var parsed = UbChunkCatalogParser.Parse(payload);
                catalog = catalog.Merge(parsed);
                restore.MergePreAuthCatalog(parsed);

                var batchSize = Math.Min(UbChunkPreAuthRequestBuilder.MaxEnFramesPerRound, cnEntries.Count - skip);
                skip += batchSize;

                log?.Report(
                    $"  PreAuth query round {round} → {payload.Length:N0} byte, +{parsed.RecordNames.Count} nomi, " +
                    $"{parsed.SignedChunks.Count} chunk, {parsed.QuerySeeds.Count} seed");
            }
            catch (Exception ex)
            {
                log?.Report($"  PreAuth query round {round} skip: {ex.Message}");
                break;
            }
        }

        return FinishQuery(catalog, skip, cnEntries.Count, log);
    }

    private async Task<int> RunRecordRetrievePreAuthRoundsAsync(
        ICloudSession session,
        RestoreSessionState restore,
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries,
        RestoreRequestContext requestContext,
        UbChunkCatalog catalog,
        int skip,
        IProgress<string>? log,
        CancellationToken ct)
    {
        for (var round = 1; round <= RecordRetrievePreAuthRounds && skip < cnEntries.Count; round++)
        {
            ct.ThrowIfCancellationRequested();

            // 20260721: entrambi i round record/retrieve usano FG+N: (BuildRound2).
            // Round 1 in cattura ha anche un prefisso binario opaco ~1.1 KB; round 2 no.
            // Senza prefisso reale estratto, FG+N: è il wire accettato (PreAuth2).
            var maxEntries = round == 1
                ? UbChunkPreAuthRequestBuilder.MaxEnFramesFirstRound
                : UbChunkPreAuthRequestBuilder.MaxEnFramesPerRound;
            var body = UbChunkPreAuthRequestBuilder.BuildRound2(
                requestContext, session.CloudKitUserId, cnEntries, skipEntries: skip, maxEntries: maxEntries);

            if (round == 1)
                log?.Report("  PreAuth wire: FG RequestOperation + N: (20260721)");

            log?.Report(
                $"CloudKit: PreAuth record/retrieve round {round} ({body.Length:N0} byte, {CountEnFrames(body)} N:)…");

            try
            {
                var payload = await _gateway.RecordRetrieveWscPreAuthAsync(session, body, ct, restore);
                restore.TryAbsorbFromPayload(payload);

                var parsed = UbChunkCatalogParser.Parse(payload);
                catalog = catalog.Merge(parsed);
                restore.MergePreAuthCatalog(parsed);

                var batchSize = round == 1
                    ? Math.Min(UbChunkPreAuthRequestBuilder.MaxEnFramesFirstRound, cnEntries.Count - skip)
                    : Math.Min(UbChunkPreAuthRequestBuilder.MaxEnFramesPerRound, cnEntries.Count - skip);
                skip += batchSize;

                log?.Report(
                    $"  PreAuth record round {round} → {payload.Length:N0} byte, +{parsed.RecordNames.Count} nomi, " +
                    $"{parsed.SignedChunks.Count} chunk, {parsed.QuerySeeds.Count} seed");
            }
            catch (Exception ex)
            {
                log?.Report($"  PreAuth record round {round} skip: {ex.Message}");
                break;
            }
        }

        if (catalog.RecordNames.Count > 0 || catalog.SignedChunks.Count > 0)
        {
            var seed = UbChunkCatalogParser.SelectPrimaryQuerySeed(catalog);
            log?.Report(
                $"  PreAuth record → {catalog.RecordNames.Count} record, " +
                $"{catalog.SignedChunks.Count} path firmati" +
                (seed is null ? "" : $", seed {seed}"));
        }

        return skip;
    }

    private static CloudKitPreAuthResult Finish(UbChunkCatalog catalog, IProgress<string>? log)
    {
        if (catalog.RecordNames.Count == 0 && catalog.SignedChunks.Count == 0)
            log?.Report("  PreAuth → catalogo vuoto (verifica batch S: e Lock)");

        return new CloudKitPreAuthResult { Catalog = catalog };
    }

    private static CloudKitPreAuthResult FinishQuery(
        UbChunkCatalog catalog,
        int consumed,
        int total,
        IProgress<string>? log)
    {
        if (catalog.RecordNames.Count > 0 || catalog.SignedChunks.Count > 0)
        {
            var seed = UbChunkCatalogParser.SelectPrimaryQuerySeed(catalog);
            log?.Report(
                $"  PreAuth query → {catalog.RecordNames.Count} record, {catalog.SignedChunks.Count} path" +
                (seed is null ? "" : $", seed {seed}") +
                $" (:CN: {consumed}/{total})");
        }

        return new CloudKitPreAuthResult
        {
            Catalog = catalog,
            CnEntriesConsumed = consumed,
            TotalCnEntries = total
        };
    }

    private static bool HasPreAuthRound1Material(RestoreSessionState restore) =>
        restore.PreAuthSessionBlob is { Length: >= 2800 }
        || restore.ResolvePreAuthWscPrefix() is { Length: > 0 };

    private static string SafePrefix(string? value, int max)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        return value.Length <= max ? value : value[..max];
    }

    private static int CountEnFrames(byte[] body)
    {
        var count = 0;
        foreach (var frame in UbChunkDelimitedCodec.EnumerateFrames(body))
        {
            if (UbChunkCatalogParser.ContainsChunkRecordName(frame))
                count++;
        }

        return count;
    }
}
