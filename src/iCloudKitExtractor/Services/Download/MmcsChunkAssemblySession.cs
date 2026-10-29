using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using System.Threading;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.Download;

/// <summary>Metadati di un chunk scaricato ( slot + ChunkInfo + object-id).</summary>
public sealed record MmcsChunkRecord(
    string CacheKey,
    string ObjectId,
    long RangeStart,
    long RangeEnd,
    int ContainerIndex,
    byte[]? Signature21,
    int BodyLength);

/// <summary>File in attesa di chunk Ford/dati mancanti in cache.</summary>
public sealed record PendingFileAssembly(
    BackupAsset Asset,
    byte[] AuthSlice,
    IReadOnlyList<SignedUrlChunk> Chunks,
    IReadOnlyList<string> MissingKeys,
    DateTimeOffset RegisteredAt);

/// <summary>
/// Sessione download-style: scarica tutti i chunk del batch in cache per firma,
/// assembla i file via refs senza bloccare se manca il Ford.
/// </summary>
public sealed class MmcsChunkAssemblySession
{
    private readonly MmcsChunkStore _store;
    private readonly object _cacheGate = new();
    private readonly Dictionary<string, MmcsChunkRecord> _byCacheKey = new(StringComparer.Ordinal);
    private readonly List<PendingFileAssembly> _pending = [];
    /// <summary>
    /// Chunk edge falliti dopo retry (es. HTTP 500 server): chiave cache → motivo.
    /// I file che li referenziano diventano Falliti, non abort dello snapshot.
    /// </summary>
    private readonly ConcurrentDictionary<string, string> _chunkDownloadFailures =
        new(StringComparer.OrdinalIgnoreCase);
    // #region agent log
    private static int _unlockedRegisterLogN;
    private static int _pendingMutateLogN;
    // #endregion
    private byte[]? _batchAuthorizeGetBody;
    private AuthorizeGetDecryptPlan? _batchPlan;
    private IReadOnlyList<SignedUrlChunk>? _batchHosts;
    /// <summary>
    /// chunkMap per file (FillChunks Phase A/B): lookup/create nodi tra passate
    /// Ford→data sullo stesso asset. Chiave = recordName o relativePath.
    /// </summary>
    private readonly Dictionary<string, ChunkTree> _fileChunkTrees = new(StringComparer.Ordinal);
    private readonly object _treeGate = new();
    /// <summary>
    /// >0 mentre il batch sta ancora assemblando/coda-decrypt: non rilasciare chunk dati
    /// condivisi (altrimenti i file successivi del batch → PENDING sullo stesso OID).
    /// </summary>
    private int _dataReleaseSuppressDepth;
    /// <summary>Release richiesti durante retain → flush a EndDataChunkRetain(depth=0).</summary>
    private readonly List<(IReadOnlyList<SignedUrlChunk> Chunks, byte[] Auth)> _deferredReleases = [];
    private readonly object _deferredReleaseLock = new();
    /// <summary>
    /// Refcount cross-batch: +1 per file-part che usa la chiave (dopo prefetch completo).
    /// ReleaseDataChunksForAsset decrementa; rimozione store solo a 0 (e senza pending hold).
    /// </summary>
    private readonly ConcurrentDictionary<string, int> _chunkLeases =
        new(StringComparer.Ordinal);

    public MmcsChunkAssemblySession(string cacheRoot)
    {
        _store = new MmcsChunkStore(cacheRoot);
        var parent = Path.GetDirectoryName(Path.GetFullPath(cacheRoot));
        ChunkFileCache.Bind(Path.Combine(
            string.IsNullOrEmpty(parent) ? cacheRoot : parent,
            "CChunkCache"));
    }

    public MmcsChunkStore Store => _store;
    public IReadOnlyList<PendingFileAssembly> Pending => _pending;
    public int PendingCount => _pending.Count;

    /// <summary>Registra fallimento GET edge (dopo retry) senza abortire il batch parallelo.</summary>
    public void RecordChunkDownloadFailure(IReadOnlyList<string> keys, string reason)
    {
        if (keys is null || keys.Count == 0 || string.IsNullOrWhiteSpace(reason))
            return;
        foreach (var key in keys)
        {
            if (string.IsNullOrEmpty(key))
                continue;
            _chunkDownloadFailures[key] = reason;
        }
    }

    /// <summary>
    /// Se uno dei chunk ordinati ha fallito il GET edge (es. HTTP 500), restituisce il motivo.
    /// </summary>
    public bool TryGetChunkDownloadFailure(
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        AuthorizeGetDecryptPlan plan,
        out string reason)
    {
        reason = "";
        if (orderedChunks is null || orderedChunks.Count == 0 || plan is null)
            return false;
        foreach (var chunk in orderedChunks)
        {
            foreach (var key in ResolveCacheKeysForChunk(chunk, plan))
            {
                if (_chunkDownloadFailures.TryGetValue(key, out var hit)
                    && !string.IsNullOrWhiteSpace(hit))
                {
                    reason = hit;
                    return true;
                }
            }
        }

        return false;
    }

    public int ClearChunkDownloadFailures()
    {
        var n = _chunkDownloadFailures.Count;
        _chunkDownloadFailures.Clear();
        return n;
    }

    /// <summary>
    /// FillChunks chunkMap per file: Phase A lookup/create tra passate Ford→data.
    /// </summary>
    public ChunkTree GetOrCreateFileChunkTree(string fileKey)
    {
        if (string.IsNullOrEmpty(fileKey))
            fileKey = "_";
        lock (_treeGate)
        {
            if (!_fileChunkTrees.TryGetValue(fileKey, out var tree))
            {
                tree = new ChunkTree();
                _fileChunkTrees[fileKey] = tree;
            }

            return tree;
        }
    }

    public void ClearFileChunkTree(string fileKey)
    {
        if (string.IsNullOrEmpty(fileKey))
            return;
        lock (_treeGate)
        {
            if (_fileChunkTrees.Remove(fileKey, out var tree))
                tree.Clear();
        }
    }

    public int ClearAllFileChunkTrees()
    {
        lock (_treeGate)
        {
            var n = _fileChunkTrees.Count;
            foreach (var t in _fileChunkTrees.Values)
                t.Clear();
            _fileChunkTrees.Clear();
            return n;
        }
    }

    /// <summary>
    /// Cap pending in RAM. Oltre la soglia i più vecchi escono dalla coda pending e
    /// vanno in <see cref="DrainEvictedPendingForRetry"/> (re-AG), non vengono persi.
    /// </summary>
    public const int MaxPendingFiles = 48;

    /// <summary>
    /// Asset tolti da pending per cap RAM — devono essere ripresi con authorizeGet
    /// (non leave-silent). Drain dal caller dopo ogni batch / fine domain.
    /// </summary>
    private readonly ConcurrentQueue<BackupAsset> _evictedPendingForRetry = new();

    /// <summary>Blocca ReleaseDataChunksForAsset (batch in corso / drain decrypt).</summary>
    public void BeginDataChunkRetain() => Interlocked.Increment(ref _dataReleaseSuppressDepth);

    public void EndDataChunkRetain()
    {
        if (Interlocked.Decrement(ref _dataReleaseSuppressDepth) < 0)
            Interlocked.Exchange(ref _dataReleaseSuppressDepth, 0);
        if (Volatile.Read(ref _dataReleaseSuppressDepth) == 0)
            FlushDeferredDataChunkReleases();
    }

    /// <summary>
    /// Dopo fine retain: rilascia i chunk dei file già decifrati, tenendo quelli
    /// ancora referenziati dai pending.
    /// </summary>
    public int FlushDeferredDataChunkReleases()
    {
        if (Volatile.Read(ref _dataReleaseSuppressDepth) > 0)
            return 0;

        List<(IReadOnlyList<SignedUrlChunk> Chunks, byte[] Auth)> queued;
        lock (_deferredReleaseLock)
        {
            if (_deferredReleases.Count == 0)
                return 0;
            queued = new List<(IReadOnlyList<SignedUrlChunk>, byte[])>(_deferredReleases);
            _deferredReleases.Clear();
        }

        var total = 0;
        foreach (var (chunks, auth) in queued)
            total += ReleaseDataChunksForAsset(chunks, auth);

        // #region agent log
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.FlushDeferredDataChunkReleases",
                ["message"] = "flush_deferred_releases",
                ["hypothesisId"] = "H-RAM-REL",
                ["runId"] = "ram-release-v2",
                ["data"] = new
                {
                    queued = queued.Count,
                    removed = total,
                    pendingFiles = _pending.Count,
                    storeApproxMb = _store.ApproximateBytes / (1024 * 1024),
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        return total;
    }

    /// <summary>
    /// Svuota cache disco + indici in memoria. Solo a fine snapshot (o esplicito):
    /// a metà download il wipe con pending=0 toglie host ancora utili al prossimo AG.
    /// Durante i batch usare <see cref="ReleaseDataChunksForAsset"/> sui soli Ok.
    /// </summary>
    public int ClearCacheIfIdle(IProgress<string>? log = null, bool force = false)
    {
        if (_pending.Count > 0 && !force)
        {
            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "MmcsChunkAssemblySession.ClearCacheIfIdle",
                    ["message"] = "clear_skipped_pending",
                    ["hypothesisId"] = "H-RAM-REL",
                    ["runId"] = "ram-release-v1",
                    ["data"] = new
                    {
                        pendingFiles = _pending.Count,
                        storeEntries = _store.EntryCount,
                        storeApproxMb = _store.ApproximateBytes / (1024 * 1024),
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion
            return 0;
        }

        if (!force)
        {
            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "b3df71",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "MmcsChunkAssemblySession.ClearCacheIfIdle",
                    ["message"] = "clear_skipped_no_force",
                    ["hypothesisId"] = "H-CACHE-OKONLY",
                    ["runId"] = "clear-okonly-v1",
                    ["data"] = new
                    {
                        pendingFiles = 0,
                        storeEntries = _store.EntryCount,
                        storeApproxMb = _store.ApproximateBytes / (1024 * 1024),
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion
            return 0;
        }

        var mode = _store.PersistToDisk ? "disk+ram" : "ram";
        var beforeMb = _store.ApproximateBytes / (1024 * 1024);
        lock (_cacheGate)
            _pending.Clear();
        var removed = _store.Clear();
        _byCacheKey.Clear();
        _chunkLeases.Clear();
        while (_evictedPendingForRetry.TryDequeue(out _)) { /* drop */ }
        _chunkDownloadFailures.Clear();
        _batchAuthorizeGetBody = null;
        _batchPlan = null;
        _batchHosts = null;
        var treesCleared = ClearAllFileChunkTrees();
        // #region agent log
        try
        {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "b3df71",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "MmcsChunkAssemblySession.ClearCacheIfIdle",
                    ["message"] = "clear_ok",
                    ["hypothesisId"] = "H-RAM-REL",
                    ["runId"] = "clear-okonly-v1",
                    ["data"] = new
                    {
                        removed,
                        treesCleared,
                        beforeMb,
                        afterMb = _store.ApproximateBytes / (1024 * 1024),
                        gcMb = GC.GetTotalMemory(false) / (1024 * 1024),
                        wsMb = Environment.WorkingSet / (1024 * 1024),
                        force,
                    },
                });
            IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                    line);
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
        }
        catch { /* ignore */ }
        // #endregion
        if (removed > 0)
            log?.Report($"  mmcs_cache({mode}): rimossi {removed:N0} chunk (FL completato)");
        return removed;
    }

    /// <summary>Indice host del authorizeGet batch intero (per Ford slice su range sovrapposti).</summary>
    public void IndexBatchAuthorizeGetHosts(byte[] authorizeGetBody)
    {
        _batchAuthorizeGetBody = authorizeGetBody;
        _batchPlan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
        _batchHosts = UbChunkBuilder.ParseAuthorizeGetResponse(authorizeGetBody);
    }

    /// <summary>
    /// Body authorizeGet del batch FileGroup intero (Auth→storage). Null se monofile
    /// o non ancora indicizzato. Serve quando AuthSlice per-file è mute ma il FG ha nested gate45.
    /// </summary>
    public byte[]? TryGetBatchAuthorizeGetBody() => _batchAuthorizeGetBody;

    /// <summary>
    /// Disabilitato: slice dataStart−N da host overlapping = inventiva non-IKE.
    /// Ford arriva solo da Auth FileGroup GET con body.Length == ctLen.
    /// </summary>
    public async Task<ReadOnlyMemory<byte>> TrySliceFordFromOverlappingHostAsync(
        string objectId,
        long fordAbsStart,
        int fordLen,
        ReadOnlyMemory<byte> fordIkm,
        HttpClient http,
        IProgress<string>? log,
        CancellationToken ct)
    {
        _ = objectId;
        _ = fordAbsStart;
        _ = fordLen;
        _ = fordIkm;
        _ = http;
        _ = log;
        _ = ct;
        await Task.CompletedTask.ConfigureAwait(false);
        return ReadOnlyMemory<byte>.Empty;
    }

    /// <summary>
    /// Scarica in cache i chunk citati dai file-part (header edge per-chunk corretti).
    /// Non usare il parse del authorizeGet intero: in batch grandi eredita signature sbagliate.
    /// </summary>
    public async Task<long> EnsureFilePartsChunksCachedAsync(
        IReadOnlyList<AuthorizeGetFilePart> fileParts,
        HttpClient http,
        IProgress<string>? log,
        CancellationToken ct,
        EdgeDownloadAuthState? edgeAuth = null)
    {
        var unique = new Dictionary<string, (SignedUrlChunk Chunk, byte[] AuthSlice, IReadOnlyList<SignedUrlChunk> Hosts)>(StringComparer.Ordinal);
        foreach (var part in fileParts)
        {
            foreach (var chunk in part.Chunks)
            {
                if (string.IsNullOrEmpty(chunk.Url) || chunk.ByteRange is not { } range)
                    continue;
                var oid = chunk.EdgeHeaders?.ObjectId ?? string.Empty;
                var dedupe = $"{oid}:{range.Start}:{range.End}";
                unique.TryAdd(dedupe, (chunk, part.AuthSlice, part.Chunks));
            }
        }

        var pending = new List<(SignedUrlChunk Chunk, AuthorizeGetDecryptPlan Plan, IReadOnlyList<SignedUrlChunk> Hosts, IReadOnlyList<string> Keys)>();
        var skipped = 0;
        foreach (var (_, entry) in unique)
        {
            var get = entry.Chunk;
            var plan = UbChunkBuilder.BuildDecryptPlan(entry.AuthSlice);
            var hosts = entry.Hosts;
            var keys = ResolveCacheKeysForChunk(get, plan);
            if (keys.Count == 0)
                continue;

            lock (_cacheGate)
            {
                if (keys.All(_store.Has))
                {
                    skipped++;
                    RegisterRecordIfMissing(get, plan, keys, _store.TryGet(keys[0])?.Length ?? 0);
                    continue;
                }
            }

            pending.Add((get, plan, hosts, keys));
        }

        var sw = Environment.TickCount64;
        var (downloaded, totalBytes) = await DownloadAndStoreChunksParallelAsync(
            pending, http, log, ct, edgeAuth).ConfigureAwait(false);

        // #region agent log
        BackupDownloadService.AgentFlEdgeDebugLog(
            "MmcsChunkAssemblySession.EnsureFilePartsChunksCachedAsync",
            "mmcs_cache batch prefetch done",
            new
            {
                unique = unique.Count,
                downloaded,
                skipped,
                pending = pending.Count,
                parallelism = BackupDownloadService.BackupEdgeDownloadParallelism,
                elapsedMs = Environment.TickCount64 - sw,
                totalBytes,
            },
            "H-P0-PARALLEL",
            "post-fix");
        // #endregion

        log?.Report(
            $"  mmcs_cache batch: {downloaded} downloaded, {skipped} cache hit, " +
            $"unique={unique.Count}, dir={_store.RootDirectory}");
        return totalBytes;
    }

    /// <summary>
    /// +1 lease per ogni cache-key usata da ciascun file-part (chunk condivisi → N).
    /// Da chiamare solo dopo prefetch completo del batch, prima di qualsiasi assemble.
    /// </summary>
    public int AcquireLeasesForFileParts(IReadOnlyList<AuthorizeGetFilePart> fileParts)
    {
        if (fileParts is null || fileParts.Count == 0)
            return 0;

        var acquired = 0;
        var uniqueKeys = 0;
        foreach (var part in fileParts)
        {
            var plan = part.AuthSlice.Length > 0
                ? UbChunkBuilder.BuildDecryptPlan(part.AuthSlice)
                : null;
            if (plan is null)
                continue;
            foreach (var chunk in part.Chunks)
            {
                foreach (var key in ResolveCacheKeysForChunk(chunk, plan))
                {
                    var next = _chunkLeases.AddOrUpdate(key, 1, static (_, c) => c + 1);
                    if (next == 1)
                        uniqueKeys++;
                    acquired++;
                }
            }
        }

        // #region agent log
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "9a5651",
                    ["runId"] = "chunk-pipeline-v1",
                    ["hypothesisId"] = "H-P3",
                    ["location"] = "MmcsChunkAssemblySession.AcquireLeasesForFileParts",
                    ["message"] = "chunk_leases_acquired",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["fileParts"] = fileParts.Count,
                        ["acquired"] = acquired,
                        ["uniqueKeysNew"] = uniqueKeys,
                        ["leaseEntries"] = _chunkLeases.Count,
                        ["storeApproxMb"] = _store.ApproximateBytes / (1024 * 1024),
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        return acquired;
    }

    /// <summary>
    /// Ri-scarica i chunk ancora mancanti per un file ordinato (second chance prima di Pending).
    /// </summary>
    public async Task<(int Downloaded, int StillMissing)> EnsureOrderedChunksCachedAsync(
        IReadOnlyList<SignedUrlChunk> ordered,
        byte[] authSlice,
        IReadOnlyList<SignedUrlChunk> hosts,
        HttpClient http,
        IProgress<string>? log,
        CancellationToken ct,
        EdgeDownloadAuthState? edgeAuth = null)
    {
        if (ordered is null || ordered.Count == 0)
            return (0, 0);

        var plan = UbChunkBuilder.BuildDecryptPlan(authSlice);
        var pending = new List<(SignedUrlChunk Chunk, AuthorizeGetDecryptPlan Plan, IReadOnlyList<SignedUrlChunk> Hosts, IReadOnlyList<string> Keys)>();
        var stillMissing = 0;
        foreach (var chunk in ordered)
        {
            if (TryGetChunkBody(chunk) is not null)
                continue;
            stillMissing++;
            if (string.IsNullOrEmpty(chunk.Url) || chunk.ByteRange is null)
                continue;
            var keys = ResolveCacheKeysForChunk(chunk, plan);
            if (keys.Count == 0)
                continue;
            pending.Add((chunk, plan, hosts, keys));
        }

        if (pending.Count == 0)
            return (0, stillMissing);

        var (downloaded, _) = await DownloadAndStoreChunksParallelAsync(
            pending, http, log, ct, edgeAuth).ConfigureAwait(false);

        stillMissing = 0;
        foreach (var chunk in ordered)
        {
            if (TryGetChunkBody(chunk) is null)
                stillMissing++;
        }

        // #region agent log
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "9a5651",
                    ["runId"] = "chunk-pipeline-v1",
                    ["hypothesisId"] = "H-P1",
                    ["location"] = "MmcsChunkAssemblySession.EnsureOrderedChunksCachedAsync",
                    ["message"] = "ordered_chunk_refetch",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["toFetch"] = pending.Count,
                        ["downloaded"] = downloaded,
                        ["stillMissing"] = stillMissing,
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        return (downloaded, stillMissing);
    }

    /// <summary>
    /// Prefetch unificato: empty Ford hosts + file-part chunks in <b>un solo</b>
    /// <see cref="DownloadAndStoreChunksParallelAsync"/>. Prima erano sequenziali →
    /// le 8 slot del GlobalEdgeDownloadGate restavano mezze vuote tra le due fasi.
    /// Stesse regole cache (length check, signature solo Length esatta) — niente alias.
    /// </summary>
    public async Task<(long EmptyBytes, long PartsBytes, int EmptyPending, int PartsPending)> EnsureAuthorizeGetBatchPrefetchCachedAsync(
        byte[] authorizeGetBody,
        IReadOnlyList<AuthorizeGetFilePart> fileParts,
        HttpClient http,
        IProgress<string>? log,
        CancellationToken ct,
        EdgeDownloadAuthState? edgeAuth = null)
    {
        var pending = new List<(SignedUrlChunk Chunk, AuthorizeGetDecryptPlan Plan, IReadOnlyList<SignedUrlChunk> Hosts, IReadOnlyList<string> Keys)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var emptyPending = 0;
        var partsPending = 0;
        var skipped = 0;
        var authDescPending = 0;
        var fordSizedPending = 0;
        var size0Pending = 0;
        var fillContainersHosts = 0;

        if (authorizeGetBody.Length > 0)
        {
            var allChunks = UbChunkBuilder.ParseAuthorizeGetResponse(authorizeGetBody);
            var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
            var authDescs = UbChunkBuilder.CollectAuthFordDescriptors(
                authorizeGetBody, plan, allChunks);

            // FillContainers @ +0xa29720 (live): pusha OGNI host del FG
            // (anche ci==0 → entry.size=0). Nessun filtro Ford-only / hostLen.
            // Diff #4: cache hit → skip GET (equivalente bypass FillContainers su path
            // MUT quando body è già in CChunkCache).
            for (var i = 0; i < allChunks.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var get = allChunks[i];
                if (string.IsNullOrEmpty(get.Url) || get.ByteRange is not { } range)
                    continue;

                var oid = get.EdgeHeaders?.ObjectId ?? "";
                var dedupe = $"{oid}:{range.Start}:{range.End}";
                if (!seen.Add(dedupe))
                    continue;

                var keys = ResolveCacheKeysForChunk(get, plan);
                if (keys.Count == 0)
                    continue;

                var why = ClassifyFordPrefetchHost(plan, i, get, authDescs);
                lock (_cacheGate)
                {
                    if (keys.All(_store.Has))
                    {
                        skipped++;
                        RegisterRecordIfMissing(get, plan, keys, _store.TryGet(keys[0])?.Length ?? 0);
                        continue;
                    }
                }

                pending.Add((get, plan, allChunks, keys));
                fillContainersHosts++;
                if (why is not null)
                {
                    emptyPending++;
                    switch (why)
                    {
                        case "authDesc":
                            authDescPending++;
                            break;
                        case "fordSized":
                            fordSizedPending++;
                            break;
                        case "size0":
                            size0Pending++;
                            break;
                    }
                }
                else
                    partsPending++;
            }
        }

        // File-part residue (AuthSlice demux / host non nel body AG grezzo).
        foreach (var part in fileParts)
        {
            var partPlan = part.AuthSlice.Length > 0
                ? UbChunkBuilder.BuildDecryptPlan(part.AuthSlice)
                : null;
            foreach (var chunk in part.Chunks)
            {
                if (string.IsNullOrEmpty(chunk.Url) || chunk.ByteRange is not { } range)
                    continue;
                var oid = chunk.EdgeHeaders?.ObjectId ?? string.Empty;
                var dedupe = $"{oid}:{range.Start}:{range.End}";
                if (!seen.Add(dedupe))
                    continue;
                var plan = partPlan ?? UbChunkBuilder.BuildDecryptPlan(part.AuthSlice);
                var keys = ResolveCacheKeysForChunk(chunk, plan);
                if (keys.Count == 0)
                    continue;
                lock (_cacheGate)
                {
                    if (keys.All(_store.Has))
                    {
                        skipped++;
                        RegisterRecordIfMissing(chunk, plan, keys, _store.TryGet(keys[0])?.Length ?? 0);
                        continue;
                    }
                }

                pending.Add((chunk, plan, part.Chunks, keys));
                partsPending++;
            }

            //  nessun GET inventato da Auth descriptor.
            // FillContainers (sopra) + host dei file-part = tutti i ByteRange FileGroup.
            // Read(ctLen) è solo L2 su body già scaricato (LiveFillPipeline).
            _ = partPlan;
        }

        var sw = Environment.TickCount64;
        var (downloaded, totalBytes) = await DownloadAndStoreChunksParallelAsync(
            pending, http, log, ct, edgeAuth).ConfigureAwait(false);

        // #region agent log
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["runId"] = LiveFillPipeline.RunId,
                ["hypothesisId"] = "H-DL1",
                ["location"] = "MmcsChunkAssemblySession.EnsureAuthorizeGetBatchPrefetchCachedAsync",
                ["message"] = "prefetch_fillcontainers_all_hosts",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new Dictionary<string, object?>
                {
                    ["fillContainersHosts"] = fillContainersHosts,
                    ["emptyPending"] = emptyPending,
                    ["partsPending"] = partsPending,
                    ["authDescPending"] = authDescPending,
                    ["fordSizedPending"] = fordSizedPending,
                    ["size0Pending"] = size0Pending,
                    ["pending"] = pending.Count,
                    ["downloaded"] = downloaded,
                    ["skippedHit"] = skipped,
                    ["elapsedMs"] = Environment.TickCount64 - sw,
                    ["totalBytes"] = totalBytes,
                    ["edgeParallel"] = BackupDownloadService.BackupEdgeDownloadParallelism,
                    ["unified"] = true,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        if (pending.Count > 0)
        {
            log?.Report(
                $"  mmcs_cache FillContainers: {downloaded} dl, {skipped} hit, " +
                $"hosts={fillContainersHosts} ford={emptyPending} parts={partsPending} " +
                $"unique={pending.Count}");
        }

        // Bytes non splittati per fase (un solo download pool); attributi proporzionali ai pending.
        var emptyBytes = 0L;
        var partsBytes = totalBytes;
        if (emptyPending + partsPending > 0 && totalBytes > 0)
        {
            emptyBytes = totalBytes * emptyPending / (emptyPending + partsPending);
            partsBytes = totalBytes - emptyBytes;
        }

        return (emptyBytes, partsBytes, emptyPending, partsPending);
    }

    /// <summary>
    /// Prefetch una tantum degli host senza ChunkInfo (Ford empty) dal authorizeGet batch.
    /// Non vanno nei file-part (anti-storm); restano in cache per sibling Ford select.
    /// </summary>
    public async Task<long> EnsureAuthorizeGetEmptyHostsCachedAsync(
        byte[] authorizeGetBody,
        HttpClient http,
        IProgress<string>? log,
        CancellationToken ct,
        EdgeDownloadAuthState? edgeAuth = null)
    {
        if (authorizeGetBody.Length == 0)
            return 0;

        var allChunks = UbChunkBuilder.ParseAuthorizeGetResponse(authorizeGetBody);
        var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
        var authDescs = UbChunkBuilder.CollectAuthFordDescriptors(
            authorizeGetBody, plan, allChunks);
        var pending = new List<(SignedUrlChunk Chunk, AuthorizeGetDecryptPlan Plan, IReadOnlyList<SignedUrlChunk> Hosts, IReadOnlyList<string> Keys)>();
        var skipped = 0;
        var considered = 0;
        var sizeSkipped = 0;
        var noUrlRange = 0;
        var noKeys = 0;
        var emptyHostTotal = 0;
        var expectedSiblingKeys = new List<string>(32);
        var sizeSkippedSample = new List<object>(8);

        for (var i = 0; i < allChunks.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var get = allChunks[i];
            var why = ClassifyFordPrefetchHost(plan, i, get, authDescs);
            if (why is null)
                continue;
            emptyHostTotal++;
            if (string.IsNullOrEmpty(get.Url) || get.ByteRange is not { } range)
            {
                noUrlRange++;
                continue;
            }

            var hostLen = range.End - range.Start + 1;
            // GET = ByteRange Auth intero (anche ≫65KiB, es. HTTPCache2 ≈172KiB).
            if (hostLen < 112)
            {
                sizeSkipped++;
                if (sizeSkippedSample.Count < 8)
                {
                    sizeSkippedSample.Add(new
                    {
                        oid = get.EdgeHeaders?.ObjectId ?? "",
                        start = range.Start,
                        len = hostLen,
                    });
                }

                continue;
            }

            if (why == "fordSized"
                && plan.Containers[i].Count == 1
                && plan.Containers[i][0].Length >= 112
                && hostLen > plan.Containers[i][0].Length + 256
                && hostLen > 4096
                && hostLen <= 65_536)
            {
                // Solo su host “piccoli” ambigui: i pack Auth grandi restano (Read(ctLen)@0).
                sizeSkipped++;
                continue;
            }

            considered++;
            var oid = get.EdgeHeaders?.ObjectId ?? "";
            expectedSiblingKeys.Add($"{oid}@{range.Start}");
            var keys = ResolveCacheKeysForChunk(get, plan);
            if (keys.Count == 0)
            {
                noKeys++;
                continue;
            }

            lock (_cacheGate)
            {
                if (keys.All(_store.Has))
                {
                    skipped++;
                    RegisterRecordIfMissing(get, plan, keys, _store.TryGet(keys[0])?.Length ?? 0);
                    continue;
                }
            }

            pending.Add((get, plan, allChunks, keys));
        }

        var sw = Environment.TickCount64;
        var (downloaded, totalBytes) = await DownloadAndStoreChunksParallelAsync(
            pending, http, log, ct, edgeAuth).ConfigureAwait(false);

        var missingInStore = 0;
        foreach (var (_, _, _, keys) in pending)
        {
            if (keys.Count == 0 || !keys.All(_store.Has))
                missingInStore++;
        }

        // #region agent log
        BackupDownloadService.AgentFlEdgeDebugLog(
            "MmcsChunkAssemblySession.EnsureAuthorizeGetEmptyHostsCachedAsync",
            "mmcs_cache empty-host prefetch done",
            new
            {
                emptyHostTotal,
                considered,
                downloaded,
                skipped,
                sizeSkipped,
                noUrlRange,
                noKeys,
                missingInStoreAfterDl = missingInStore,
                pending = pending.Count,
                expectedSiblingKeys = expectedSiblingKeys.Count,
                sizeSkippedSample,
                parallelism = BackupDownloadService.BackupEdgeDownloadParallelism,
                elapsedMs = Environment.TickCount64 - sw,
                totalBytes,
            },
            "H-FP1",
            "fordpool-v1");
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.EnsureAuthorizeGetEmptyHostsCachedAsync",
                ["message"] = "empty_prefetch_coverage",
                ["hypothesisId"] = "H-FP1",
                ["runId"] = "fordpool-v1",
                ["data"] = new Dictionary<string, object?>
                {
                    ["emptyHostTotal"] = emptyHostTotal,
                    ["considered"] = considered,
                    ["downloaded"] = downloaded,
                    ["skippedHit"] = skipped,
                    ["sizeSkipped"] = sizeSkipped,
                    ["noUrlRange"] = noUrlRange,
                    ["noKeys"] = noKeys,
                    ["missingInStoreAfterDl"] = missingInStore,
                    ["expectedSiblingKeySample"] = expectedSiblingKeys.Take(12).ToArray(),
                    ["sizeSkippedSample"] = sizeSkippedSample,
                },
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch
        {
            // ignore
        }
        // #endregion

        if (considered > 0)
        {
            log?.Report(
                $"  mmcs_cache empty-hosts: {downloaded} downloaded, {skipped} hit, " +
                $"candidates={considered} sizeSkip={sizeSkipped}");
        }

        return totalBytes;
    }

    private async Task<(int Downloaded, long TotalBytes)> DownloadAndStoreChunksParallelAsync(
        IReadOnlyList<(SignedUrlChunk Chunk, AuthorizeGetDecryptPlan Plan, IReadOnlyList<SignedUrlChunk> Hosts, IReadOnlyList<string> Keys)> pending,
        HttpClient http,
        IProgress<string>? log,
        CancellationToken ct,
        EdgeDownloadAuthState? edgeAuth = null)
    {
        if (pending.Count == 0)
            return (0, 0);

        var downloaded = 0;
        long totalBytes = 0;
        using var gate = new SemaphoreSlim(
            BackupDownloadService.BackupEdgeDownloadParallelism,
            BackupDownloadService.BackupEdgeDownloadParallelism);
        var tasks = pending.Select(WorkerAsync).ToArray();
        await Task.WhenAll(tasks).ConfigureAwait(false);
        return (downloaded, totalBytes);

        async Task WorkerAsync((SignedUrlChunk Chunk, AuthorizeGetDecryptPlan Plan, IReadOnlyList<SignedUrlChunk> Hosts, IReadOnlyList<string> Keys) item)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ct.ThrowIfCancellationRequested();
                var (get, plan, hosts, keys) = item;
                // RAM ConcurrentDictionary: Has/Put thread-safe — no disk I/O under gate.
                if (keys.All(_store.Has))
                {
                    // Rifiuta cache hit se la lunghezza non combacia col Range (contaminazione).
                    if (get.ByteRange is { } brHit
                        && _store.TryGet(keys[0]) is { } cached
                        && cached.Length != brHit.End - brHit.Start + 1)
                    {
                        foreach (var k in keys)
                            _store.Remove(k);
                    }
                    else
                        return;
                }

                try
                {
                    var body = await BackupDownloadService.DownloadSingleEdgeChunkWithRefreshAsync(
                            get, http, edgeAuth, ct)
                        .ConfigureAwait(false);
                    if (keys.All(_store.Has))
                    {
                        if (get.ByteRange is { } br2
                            && _store.TryGet(keys[0]) is { } cached2
                            && cached2.Length == br2.End - br2.Start + 1)
                            return;
                        foreach (var k in keys)
                            _store.Remove(k);
                    }

                    if (get.ByteRange is { } br)
                    {
                        var expect = br.End - br.Start + 1;
                        if (body.Length != expect)
                        {
                            // #region agent log
                            try
                            {
                                var line = System.Text.Json.JsonSerializer.Serialize(
                                    new Dictionary<string, object?>
                                    {
                                        ["sessionId"] = "7dabb5",
                                        ["runId"] = "range-len-v1",
                                        ["hypothesisId"] = "H-RANGE-LEN",
                                        ["location"] = "MmcsChunkAssemblySession.DownloadAndStoreChunksParallelAsync",
                                        ["message"] = "edge_body_len_mismatch",
                                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                        ["data"] = new
                                        {
                                            objectId = get.EdgeHeaders?.ObjectId,
                                            range = $"{br.Start}-{br.End}",
                                            expect,
                                            actual = body.Length,
                                        },
                                    });
                                // Quiet-safe: sempre su disco (diagnostica contaminazione).
                                File.AppendAllText(
                                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                                    line + Environment.NewLine);
                            }
                            catch { /* ignore */ }
                            // #endregion
                            throw new InvalidOperationException(
                                $"edge GET body len {body.Length} ≠ range {expect} " +
                                $"oid={get.EdgeHeaders?.ObjectId} {br.Start}-{br.End}");
                        }
                    }

                    _store.PutShared(keys, body);
                    PutAuthLayoutChecksumSlices(plan, get, body, hosts);

                    lock (_cacheGate)
                        RegisterRecord(get, plan, keys, body.Length);

                    var n = Interlocked.Increment(ref downloaded);
                    Interlocked.Add(ref totalBytes, body.Length);

                    // Evita flood UI: un log ogni 64 chunk (+ ultimo gestito dal chiamante).
                    if (n == 1 || (n & 63) == 0)
                    {
                        var sigHint = keys[0].Length == 42
                            ? keys[0][..Math.Min(16, keys[0].Length)]
                            : keys[0];
                        var mode = _store.PersistToDisk ? "disk" : "ram";
                        log?.Report(
                            $"  mmcs_cache({mode}): #{n} {body.Length:N0} B key={sigHint}… " +
                            $"oid={get.EdgeHeaders?.ObjectId} " +
                            $"entries={_store.EntryCount}");
                    }
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    // Un chunk 500/403 esaurito non deve abortire WhenAll → MessageBox fatale.
                    // I file che lo usano → Falliti in UI; il resto dello snapshot continua.
                    var reason = ex is EdgeUrlExpiredException edgeEx
                        && EdgeChunkRemap.IsServerSideEdgeStatus(edgeEx.StatusCode)
                            ? ex.Message
                            : ex.Message.Contains("edge GET HTTP", StringComparison.Ordinal)
                                ? ex.Message
                                : $"edge GET fallito: {ex.Message}";
                    RecordChunkDownloadFailure(keys, reason);
                    log?.Report(
                        $"  WARN edge chunk skip (continua): oid={get.EdgeHeaders?.ObjectId} " +
                        $"range={get.ByteRange?.Start}-{get.ByteRange?.End} — {reason}");
                    // #region agent log
                    try
                    {
                        var line = System.Text.Json.JsonSerializer.Serialize(
                            new Dictionary<string, object?>
                            {
                                ["sessionId"] = "b3df71",
                                ["runId"] = "edge-500-continue-v1",
                                ["hypothesisId"] = "H-EDGE-500",
                                ["location"] =
                                    "MmcsChunkAssemblySession.DownloadAndStoreChunksParallelAsync",
                                ["message"] = "edge_chunk_fail_continue",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new
                                {
                                    objectId = get.EdgeHeaders?.ObjectId,
                                    range = get.ByteRange is { } r
                                        ? $"{r.Start}-{r.End}"
                                        : null,
                                    keys = keys.Take(3).ToArray(),
                                    errType = ex.GetType().Name,
                                    reason,
                                    status = ex is EdgeUrlExpiredException eue
                                        ? (int)eue.StatusCode
                                        : -1,
                                },
                            });
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                            line + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion
                }
            }
            finally
            {
                gate.Release();
            }
        }
    }

    /// <summary>
    /// Limite sotto MemoryStream (~2 GiB). Sopra: <see cref="TryAssembleCompactToFile"/>.
    /// </summary>
    public const long MaxInMemoryCompactBytes = FordMmcsDecryptor.MaxInMemoryPlaintextBytes;

    /// <summary>Concatena i body in cache nell'ordine Ford/dati del file.</summary>
    public (byte[]? Compact, List<string> Missing) TryAssembleCompact(
        IReadOnlyList<SignedUrlChunk> orderedChunks)
    {
        var missing = new List<string>();
        if (orderedChunks.Count == 0)
            return (null, ["no-chunks"]);

        long estimate = 0;
        var bodies = new List<byte[]>(orderedChunks.Count);
        foreach (var chunk in orderedChunks)
        {
            var body = TryGetChunkBody(chunk);
            if (body is null)
            {
                missing.Add(DescribeMissingChunk(chunk));
                continue;
            }

            bodies.Add(body);
            estimate += body.Length;
        }

        if (missing.Count > 0)
            return (null, missing);

        if (estimate > MaxInMemoryCompactBytes)
        {
            // Non throw: il batch catch marcava ERROR ogni asset dell'AG (plist + Gemma).
            // Il caller usa SizeBytes / estimate → FinishLargeAssetFromMmcsCacheAsync.
            return (null, [$"compact-too-large:{estimate}"]);
        }

        using var ms = new MemoryStream(estimate > int.MaxValue ? 0 : (int)estimate);
        foreach (var body in bodies)
            ms.Write(body);

        return (ms.ToArray(), missing);
    }

    /// <summary>Stima ByteRange (senza leggere la cache) per gate large-asset.</summary>
    public static long EstimateOrderedBytes(IReadOnlyList<SignedUrlChunk> orderedChunks)
    {
        long sum = 0;
        foreach (var chunk in orderedChunks)
        {
            if (chunk.ByteRange is { } br)
                sum += br.End - br.Start + 1;
        }

        return sum;
    }

    /// <summary>Come TryAssembleCompact ma scrive su file (asset multi-GB).</summary>
    public (bool Ok, List<string> Missing, long BytesWritten) TryAssembleCompactToFile(
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        string outputPath)
    {
        var missing = new List<string>();
        if (orderedChunks.Count == 0)
            return (false, ["no-chunks"], 0);

        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        using var fs = new FileStream(
            outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024);
        foreach (var chunk in orderedChunks)
        {
            var body = TryGetChunkBody(chunk);
            if (body is null)
            {
                missing.Add(DescribeMissingChunk(chunk));
                continue;
            }

            fs.Write(body);
        }

        if (missing.Count > 0)
        {
            try { File.Delete(outputPath); } catch { /* ignore */ }
            return (false, missing, 0);
        }

        return (true, missing, fs.Length);
    }

    public void RegisterPending(
        BackupAsset asset,
        byte[] authSlice,
        IReadOnlyList<SignedUrlChunk> chunks,
        IReadOnlyList<string> missingKeys)
    {
        // #region agent log
        // H-CM2: List _pending mutated without gate while PendingNeedsHostRange/Purge enumerate.
        {
            var n = Interlocked.Increment(ref _pendingMutateLogN);
            if (n <= 20 || (n & 31) == 0)
            {
                AgentCollectionRaceLog(
                    "H-CM2",
                    "pending_mutate",
                    new
                    {
                        n,
                        op = "RegisterPending",
                        path = asset.RelativePath ?? asset.RecordName,
                        pendingBefore = _pending.Count,
                        gateHeld = Monitor.IsEntered(_cacheGate),
                        stack = Environment.StackTrace,
                    });
            }
        }
        // #endregion

        int removedDup;
        // H-NRE: RemoveAll/Add devono essere sotto _cacheGate — decrypt workers
        // enumerano _pending in PendingNeedsHostRange (ReleaseDataChunksForAsset).
        lock (_cacheGate)
        {
            var wantSig = asset.AssetSignature ?? [];
            removedDup = _pending.RemoveAll(p =>
                p.Asset is not null
                && string.Equals(p.Asset.RecordName, asset.RecordName, StringComparison.Ordinal)
                && (p.Asset.AssetSignature ?? []).AsSpan().SequenceEqual(wantSig));

            _pending.Add(new PendingFileAssembly(
                asset,
                authSlice,
                chunks,
                missingKeys,
                DateTimeOffset.UtcNow));
        }

        // Cap: evict oldest prima che la cache resti pinned da centinaia di pending.
        var evicted = EvictExcessPending(MaxPendingFiles, log: null);

        // #region agent log
        AgentPendingLifecycleLog(
            "pending_register",
            new
            {
                path = asset.RelativePath ?? asset.RecordName,
                missingN = missingKeys.Count,
                missingSample = missingKeys.Take(3).ToArray(),
                removedDup,
                evicted,
                pendingFiles = PendingCount,
                authSliceMb = authSlice.Length / (1024.0 * 1024.0),
                storeApproxMb = _store.ApproximateBytes / (1024 * 1024),
                locked = true,
                hypothesis = "H-NRE",
                runId = "nre-fix-v1",
            });
        // #endregion
    }

    /// <summary>
    /// Stima RAM agganciata ai pending (AuthSlice + riferimenti; i body sono nello store).
    /// </summary>
    public (int Count, long AuthSliceBytes, long UniqueAuthBytes) EstimatePendingRam()
    {
        long auth = 0;
        var seen = new HashSet<object>(ReferenceEqualityComparer.Instance);
        long uniqueAuth = 0;
        lock (_cacheGate)
        {
            foreach (var p in _pending)
            {
                auth += p.AuthSlice.LongLength;
                if (seen.Add(p.AuthSlice))
                    uniqueAuth += p.AuthSlice.LongLength;
            }

            return (_pending.Count, auth, uniqueAuth);
        }
    }

    /// <summary>
    /// Toglie i pending più vecchi oltre <paramref name="maxPending"/>, rilascia i loro
    /// data-chunk e li accoda per re-authorizeGet (<see cref="DrainEvictedPendingForRetry"/>).
    /// Non abbandona il lavoro in silenzio.
    /// </summary>
    public int EvictExcessPending(int maxPending, IProgress<string>? log)
    {
        if (maxPending < 0)
            maxPending = 0;

        List<PendingFileAssembly> victims;
        lock (_cacheGate)
        {
            if (_pending.Count <= maxPending)
                return 0;

            var drop = _pending.Count - maxPending;
            victims = _pending
                .OrderBy(static p => p.RegisteredAt)
                .Take(drop)
                .ToList();

            foreach (var v in victims)
                _pending.Remove(v);
        }

        var removed = 0;
        long freedAuth = 0;
        foreach (var v in victims)
        {
            removed++;
            freedAuth += v.AuthSlice.LongLength;
            if (v.Asset is not null)
            {
                v.Asset.ContentFromExistingSignature = false;
                _evictedPendingForRetry.Enqueue(v.Asset);
            }

            // Release fuori dal gate pending-mutate: re-entra su _cacheGate in modo sicuro.
            _ = ReleaseDataChunksForAsset(v.Chunks, v.AuthSlice);
        }

        // #region agent log
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.EvictExcessPending",
                ["message"] = "pending_evict",
                ["hypothesisId"] = "H-RAM-PEND",
                ["runId"] = "ram-cap-retry-v1",
                ["data"] = new
                {
                    removed,
                    maxPending,
                    pendingAfter = PendingCount,
                    retryQueued = _evictedPendingForRetry.Count,
                    freedAuthMb = freedAuth / (1024 * 1024),
                    storeApproxMb = _store.ApproximateBytes / (1024 * 1024),
                    gcMb = GC.GetTotalMemory(false) / (1024 * 1024),
                    wsMb = Environment.WorkingSet / (1024 * 1024),
                    requeue = true,
                },
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "9a5651",
                    ["runId"] = "pending-fix-v1",
                    ["hypothesisId"] = "H-EVICT-RETRY",
                    ["location"] = "MmcsChunkAssemblySession.EvictExcessPending",
                    ["message"] = "pending_evict_requeue",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        removed,
                        maxPending,
                        pendingAfter = PendingCount,
                        retryQueued = _evictedPendingForRetry.Count,
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        if (removed > 0)
        {
            log?.Report(
                $"  mmcs_cache: evict→retry {removed} pending oltre cap={maxPending} " +
                $"(restano {PendingCount}; coda retry={_evictedPendingForRetry.Count}; " +
                $"−auth ~{freedAuth / (1024 * 1024.0):0.#} MB)");
        }

        return removed;
    }

    /// <summary>Svuota la coda degli asset evicted da riprendere con authorizeGet.</summary>
    public List<BackupAsset> DrainEvictedPendingForRetry()
    {
        var list = new List<BackupAsset>();
        while (_evictedPendingForRetry.TryDequeue(out var a))
        {
            if (a is not null)
                list.Add(a);
        }

        return list;
    }

    public int EvictedPendingForRetryCount => _evictedPendingForRetry.Count;

    /// <summary>Riprova i file pending dopo batch successivi (Ford da altro host).</summary>
    public IReadOnlyList<(PendingFileAssembly Pending, byte[] Compact)> TryCollectReadyPending()
    {
        var ready = new List<(PendingFileAssembly, byte[])>();
        var stillMissing = 0;
        var refreshed = 0;
        int before;
        lock (_cacheGate)
        {
            before = _pending.Count;
            for (var i = _pending.Count - 1; i >= 0; i--)
            {
                var p = _pending[i];
                var ordered = UbChunkBuilder.OrderChunksForFordFile(p.Chunks, p.AuthSlice);
                long present = 0;
                var missDescs = new List<string>();
                foreach (var ch in ordered)
                {
                    var body = TryGetChunkBody(ch);
                    if (body is null)
                    {
                        missDescs.Add(DescribeMissingChunk(ch));
                        continue;
                    }

                    present += body.Length;
                }

                // Aggiorna MissingKeys così UI/journal non restano sullo snapshot iniziale.
                if (missDescs.Count != p.MissingKeys.Count
                    || !missDescs.SequenceEqual(p.MissingKeys))
                {
                    _pending[i] = p with { MissingKeys = missDescs };
                    p = _pending[i];
                    refreshed++;
                }

                if (missDescs.Count > 0)
                {
                    stillMissing++;
                    continue;
                }

                // Multi-GB: niente compact in RAM — sentinel Length=0 per Finalize large-path.
                if (present > MaxInMemoryCompactBytes
                    || p.Asset.SizeBytes is long sz && sz > MaxInMemoryCompactBytes)
                {
                    _pending.RemoveAt(i);
                    ready.Add((p, []));
                    continue;
                }

                var (compact, missing) = TryAssembleCompact(ordered);
                if (compact is null || missing.Count > 0)
                {
                    stillMissing++;
                    if (missing.Count > 0)
                        _pending[i] = p with { MissingKeys = missing };
                    continue;
                }

                _pending.RemoveAt(i);
                ready.Add((p, compact));
            }
        }

        // #region agent log
        AgentPendingLifecycleLog(
            "pending_collect_ready",
            new
            {
                before,
                ready = ready.Count,
                stillMissing,
                refreshed,
                after = PendingCount,
                storeApproxMb = _store.ApproximateBytes / (1024 * 1024),
            });
        // #endregion

        return ready;
    }

    /// <summary>
    /// Dopo decrypt riuscito: decrementa lease e rimuove dalla cache i chunk dati
    /// (non empty-host Ford condivisi). Non rilascia se: retain batch attivo, lease&gt;0
    /// (altri file/batch ancora sharer), o un pending ha ancora bisogno dello stesso OID/range.
    /// </summary>
    public int ReleaseDataChunksForAsset(
        IReadOnlyList<SignedUrlChunk> chunks,
        ReadOnlySpan<byte> authSlice)
    {
        if (chunks.Count == 0)
            return 0;

        // H-EVICT: release anticipato → altri file dello stesso batch / pending condividono
        // lo stesso data:OID e finiscono in "mancano 1 chunk" (28× stesso OID in journal).
        if (Volatile.Read(ref _dataReleaseSuppressDepth) > 0)
        {
            // Accoda: EndDataChunkRetain farà il vero release (prima era released≡0 forever).
            var authCopy = authSlice.ToArray();
            lock (_deferredReleaseLock)
                _deferredReleases.Add((chunks, authCopy));
            // #region agent log
            AgentReleaseDiag(
                "release_deferred_batch_retain",
                chunks.Count,
                pendingHold: 0,
                emptySkip: 0,
                removeMiss: 0,
                removed: 0,
                bytesBefore: _store.ApproximateBytes,
                bytesAfter: _store.ApproximateBytes);
            // #endregion
            return 0;
        }

        var plan = UbChunkBuilder.BuildDecryptPlan(authSlice.ToArray());
        var removed = 0;
        var pendingHold = 0;
        var leaseHold = 0;
        var emptySkip = 0;
        var removeMiss = 0;
        var bytesBefore = _store.ApproximateBytes;
        lock (_cacheGate)
        {
            var n = Math.Min(chunks.Count, plan.Containers.Count);
            for (var i = 0; i < n; i++)
            {
                if (plan.Containers[i].Count == 0)
                {
                    emptySkip++;
                    continue;
                }

                var chunk = chunks[i];
                if (chunk.ByteRange is { } br
                    && PendingNeedsHostRange(chunk.EdgeHeaders?.ObjectId, br.Start, br.End))
                {
                    // Pending tiene il body: consuma comunque 1 lease di questo file Ok
                    // altrimenti i lease restano gonfi e i chunk non escono mai.
                    foreach (var key in ResolveCacheKeysForChunk(chunk, plan))
                        DecrementChunkLease(key);
                    pendingHold++;
                    continue;
                }

                var keys = ResolveCacheKeysForChunk(chunk, plan);
                if (keys.Count == 0)
                {
                    removeMiss++;
                    continue;
                }

                foreach (var key in keys)
                {
                    var remaining = DecrementChunkLease(key);
                    if (remaining > 0)
                    {
                        leaseHold++;
                        continue;
                    }

                    if (!_store.Remove(key))
                    {
                        removeMiss++;
                        continue;
                    }
                    removed++;
                    _byCacheKey.Remove(key);
                }
            }
        }

        // #region agent log
        AgentReleaseDiag(
            "release_data_chunks",
            chunks.Count,
            pendingHold,
            emptySkip,
            removeMiss,
            removed,
            bytesBefore,
            _store.ApproximateBytes);
        try
        {
            if (leaseHold > 0 || pendingHold > 0)
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "9a5651",
                        ["runId"] = "chunk-pipeline-v1",
                        ["hypothesisId"] = "H-P3",
                        ["location"] = "MmcsChunkAssemblySession.ReleaseDataChunksForAsset",
                        ["message"] = "release_lease_or_pending_hold",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["chunkN"] = chunks.Count,
                            ["leaseHold"] = leaseHold,
                            ["pendingHold"] = pendingHold,
                            ["removed"] = removed,
                            ["leaseEntries"] = _chunkLeases.Count,
                        },
                    }) + Environment.NewLine);
            }
        }
        catch { /* ignore */ }
        // #endregion

        return removed;
    }

    /// <summary>Decrementa 1 lease; 0 = libero di rimuovere (o mai acquisito).</summary>
    private int DecrementChunkLease(string key)
    {
        while (true)
        {
            if (!_chunkLeases.TryGetValue(key, out var cur))
                return 0;
            if (cur <= 1)
            {
                if (_chunkLeases.TryRemove(key, out var removed) && removed <= 1)
                    return 0;
                continue;
            }

            if (_chunkLeases.TryUpdate(key, cur - 1, cur))
                return cur - 1;
        }
    }

    private bool PendingNeedsHostRange(string? objectId, long rangeStart, long rangeEnd)
    {
        if (string.IsNullOrEmpty(objectId))
            return false;

        // Snapshot sotto gate: evita NRE/InvalidOperation se RegisterPending muta in parallelo.
        PendingFileAssembly[] snap;
        lock (_cacheGate)
        {
            if (_pending.Count == 0)
                return false;
            snap = _pending.ToArray();
        }

        try
        {
            foreach (var p in snap)
            {
                if (p.Chunks is null)
                    continue;
                foreach (var ch in p.Chunks)
                {
                    if (ch.ByteRange is not { } br)
                        continue;
                    if (!string.Equals(ch.EdgeHeaders?.ObjectId, objectId, StringComparison.Ordinal))
                        continue;
                    if (br.Start == rangeStart && br.End == rangeEnd)
                        return true;
                }
            }
        }
        catch (InvalidOperationException ex)
        {
            // #region agent log
            AgentCollectionRaceLog(
                "H-CM2",
                "pending_enum_fault",
                new
                {
                    where = "PendingNeedsHostRange",
                    err = ex.Message,
                    pending = snap.Length,
                    stack = ex.StackTrace,
                });
            // #endregion
            throw;
        }

        return false;
    }

    /// <summary>
    /// Ri-scarica in cache i chunk ancora mancanti per i file in <see cref="_pending"/>.
    /// Necessario perché FinalizePending prima faceva solo TryCollectReady senza edge GET.
    /// </summary>
    public async Task<long> EnsurePendingChunksCachedAsync(
        HttpClient http,
        IProgress<string>? log,
        CancellationToken ct,
        EdgeDownloadAuthState? edgeAuth = null)
    {
        if (_pending.Count == 0)
            return 0;

        var unique = new Dictionary<string, (SignedUrlChunk Chunk, AuthorizeGetDecryptPlan Plan, IReadOnlyList<SignedUrlChunk> Hosts, IReadOnlyList<string> Keys)>(
            StringComparer.Ordinal);
        var missingBefore = 0;
        PendingFileAssembly[] pendingSnap;
        lock (_cacheGate)
            pendingSnap = _pending.ToArray();

        foreach (var p in pendingSnap)
        {
            var plan = UbChunkBuilder.BuildDecryptPlan(p.AuthSlice);
            var ordered = UbChunkBuilder.OrderChunksForFordFile(p.Chunks, p.AuthSlice);
            foreach (var chunk in ordered)
            {
                if (TryGetChunkBody(chunk) is not null)
                    continue;
                missingBefore++;
                if (string.IsNullOrEmpty(chunk.Url) || chunk.ByteRange is not { } range)
                    continue;
                var oid = chunk.EdgeHeaders?.ObjectId ?? string.Empty;
                var dedupe = $"{oid}:{range.Start}:{range.End}";
                if (unique.ContainsKey(dedupe))
                    continue;
                var keys = ResolveCacheKeysForChunk(chunk, plan);
                if (keys.Count == 0)
                    continue;
                unique[dedupe] = (chunk, plan, p.Chunks, keys);
            }
        }

        if (unique.Count == 0)
        {
            log?.Report(
                $"  mmcs_cache pending-refetch: 0 URL scaricabili " +
                $"(pendingFiles={_pending.Count}, missingSlots={missingBefore})");
            return 0;
        }

        var list = unique.Values.ToList();
        var (downloaded, totalBytes) = await DownloadAndStoreChunksParallelAsync(
            list, http, log, ct, edgeAuth).ConfigureAwait(false);

        // #region agent log
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.EnsurePendingChunksCachedAsync",
                ["message"] = "pending_chunk_refetch",
                ["hypothesisId"] = "H-EVICT",
                ["runId"] = "pending-fix-v1",
                ["data"] = new
                {
                    pendingFiles = _pending.Count,
                    missingSlots = missingBefore,
                    uniqueToFetch = unique.Count,
                    downloaded,
                    totalBytes,
                },
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch { /* ignore */ }
        // #endregion

        log?.Report(
            $"  mmcs_cache pending-refetch: {downloaded} downloaded " +
            $"(unique={unique.Count}, pendingFiles={_pending.Count}, +{totalBytes:N0} B)");
        return totalBytes;
    }

    public IReadOnlyList<string> DescribeStillPending(IProgress<string>? log)
    {
        var lines = new List<string>();
        foreach (var p in _pending)
        {
            var ordered = UbChunkBuilder.OrderChunksForFordFile(p.Chunks, p.AuthSlice);
            var (_, missing) = TryAssembleCompact(ordered);
            var msg =
                $"  PENDING {p.Asset.RelativePath ?? p.Asset.RecordName}: " +
                $"missing {missing.Count} chunk(s) — {string.Join("; ", missing.Take(3))}";
            lines.Add(msg);
            log?.Report(msg);
        }

        return lines;
    }

    /// <summary>
    /// Popola sibling con host Ford del <b>authorizeGet batch corrente</b> (modello):
    /// empty-host <c>ChunkInfo.count==0</c> <b>oppure</b> host con un solo ChunkInfo
    /// di taglia Ford (112/…/≤4KiB) — oracle: CT AesSiv è un GET separato anche
    /// quando Auth espone gate 45B e il plan non marca emptyHosts.
    /// Non re-idrata tutta la cache storica (siblingCount→5000+ / multi-GB RAM).
    /// </summary>
    public int SeedSiblingCompactsFromAuthorizeGet(
        IDictionary<string, (byte[] Compact, long MmcsStart)> map,
        byte[] authorizeGetBody)
    {
        var added = 0;
        long addedBytes = 0;
        var fordSizedChunkInfo = 0;
        var authDescSeeded = 0;
        try
        {
            var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
            var gets = UbChunkBuilder.ParseAuthorizeGetResponse(authorizeGetBody);
            var n = Math.Min(plan.Containers.Count, gets.Count);
            for (var i = 0; i < n; i++)
            {
                var group = plan.Containers[i];
                var empty = group.Count == 0;
                var size0 = string.Equals(
                    gets[i].EdgeHeaders?.MmcsContainerSize, "0", StringComparison.Ordinal);
                var fordChunk = !empty && !size0
                                && FordMmcsDecryptor.IsFordSizedPlanContainer(plan, i);
                var hasFordDesc = !empty && group.Any(UbChunkBuilder.IsAuthFordDescriptorChunk);
                //  TUTTI gli host Auth del FG (Ford + data) sotto oid@{Start}.
                if (fordChunk || hasFordDesc)
                    fordSizedChunkInfo++;
                if (gets[i].ByteRange is not { } br)
                    continue;
                var hostLen = br.End - br.Start + 1;
                // FillContainers: ogni FileGroup con range valido (Ford 112+ e data).
                if (hostLen < 0x12)
                    continue;

                var oid = gets[i].EdgeHeaders?.ObjectId ?? "";
                //  OID può essere vuoto — seed comunque sotto host:i@{Start}.
                var key = !string.IsNullOrEmpty(oid)
                    ? $"{oid}@{br.Start}"
                    : $"host:{i}@{br.Start}";
                var hostKeyAlt = $"host:{i}@{br.Start}";
                if (map.ContainsKey(key) && map.ContainsKey(hostKeyAlt))
                    continue;
                var body = TryGetChunkBody(gets[i]);
                // Class B ike-no-data: data host già scaricato sotto sig:/altro range ma
                // TryGetChunkBody miss su oid@{Start} Auth → PlantAuth non crea sig: in map.
                // Solo data-only (no Ford CI45): non tocca path Ford/spill.
                if (body is not { Length: > 0 })
                {
                    var hasDataCi = group.Any(UbChunkBuilder.IsAuthDataChunk);
                    var hasFordCi = group.Any(UbChunkBuilder.IsAuthFordDescriptorChunk);
                    if (hasDataCi && !hasFordCi)
                    {
                        if (TryRecoverDataHostBody(
                                oid, br.Start, br.End, hostLen, group, out var recovered, out var sigOnly)
                            && recovered is { Length: > 0 })
                        {
                            if (sigOnly)
                            {
                                // Slice CI: pianta solo sig: (Extract), non fingere host pack.
                                foreach (var c in group)
                                {
                                    if (!UbChunkBuilder.IsAuthDataChunk(c)
                                        || c.Checksum21 is not { Length: 21 }
                                        || recovered.Length != c.Length)
                                        continue;
                                    map.TryAdd(
                                        "sig:" + Convert.ToHexString(c.Checksum21).ToLowerInvariant(),
                                        (recovered, 0L));
                                }

                                // #region agent log
                                try
                                {
                                    var ok = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                                    {
                                        ["sessionId"] = "03cce7",
                                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                        ["hypothesisId"] = "H-SEED-DATA-RECOVER",
                                        ["runId"] = "data-seed-recover-v1",
                                        ["location"] = "MmcsChunkAssemblySession.SeedSiblingCompactsFromAuthorizeGet",
                                        ["message"] = "seed_data_sig_only_recovered",
                                        ["data"] = new Dictionary<string, object?>
                                        {
                                            ["h"] = i,
                                            ["oid"] = oid.Length > 16 ? oid[..16] : oid,
                                            ["start"] = br.Start,
                                            ["hostLen"] = hostLen,
                                            ["bodyLen"] = recovered.Length,
                                        },
                                    });
                                    File.AppendAllText(
                                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                                        ok + Environment.NewLine);
                                }
                                catch { /* ignore */ }
                                // #endregion
                                continue;
                            }

                            body = recovered;
                            // #region agent log
                            try
                            {
                                var ok = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "03cce7",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["hypothesisId"] = "H-SEED-DATA-RECOVER",
                                    ["runId"] = "data-seed-recover-v1",
                                    ["location"] = "MmcsChunkAssemblySession.SeedSiblingCompactsFromAuthorizeGet",
                                    ["message"] = "seed_data_host_recovered",
                                    ["data"] = new Dictionary<string, object?>
                                    {
                                        ["h"] = i,
                                        ["oid"] = oid.Length > 16 ? oid[..16] : oid,
                                        ["start"] = br.Start,
                                        ["hostLen"] = hostLen,
                                        ["bodyLen"] = body.Length,
                                    },
                                });
                                File.AppendAllText(
                                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                                    ok + Environment.NewLine);
                            }
                            catch { /* ignore */ }
                            // #endregion
                        }
                    }
                }

                if (body is not { Length: > 0 })
                {
                    // #region agent log
                    try
                    {
                        var hostKey = MmcsChunkStore.HostRangeKey(-1, oid, br.Start, br.End);
                        byte[]? dataCs = null;
                        foreach (var c in group)
                        {
                            if (UbChunkBuilder.IsAuthDataChunk(c) && c.Checksum21 is { Length: 21 })
                            {
                                dataCs = c.Checksum21;
                                break;
                            }
                        }
                        var sigHas = dataCs is not null
                            && _store.Has(MmcsChunkStore.SignatureToKey(dataCs));
                        // Live 3052: prefetch dl=24/10MB ma seed added=19 — gap sui REF data.
                        var byOidStart = 0;
                        var byOidStartLen = 0;
                        lock (_cacheGate)
                        {
                            foreach (var rec in _byCacheKey.Values)
                            {
                                if (!string.Equals(rec.ObjectId, oid, StringComparison.Ordinal))
                                    continue;
                                if (rec.RangeStart != br.Start)
                                    continue;
                                byOidStart++;
                                byOidStartLen = rec.BodyLength;
                            }
                        }

                        var miss = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "03cce7",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["hypothesisId"] = "H-SEED-GAP",
                            ["runId"] = LiveFillPipeline.RunId,
                            ["location"] = "MmcsChunkAssemblySession.SeedSiblingCompactsFromAuthorizeGet",
                            ["message"] = "seed_host_body_miss",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["h"] = i,
                                ["oid"] = oid.Length > 16 ? oid[..16] : oid,
                                ["start"] = br.Start,
                                ["end"] = br.End,
                                ["hostLen"] = hostLen,
                                ["size0"] = size0,
                                ["dataCi"] = group.Count(UbChunkBuilder.IsAuthDataChunk),
                                ["fordCi"] = group.Count(UbChunkBuilder.IsAuthFordDescriptorChunk),
                                ["storeHostHas"] = _store.Has(hostKey),
                                ["storeSigHas"] = sigHas,
                                ["hostKey12"] = hostKey.Length > 48 ? hostKey[..48] : hostKey,
                                ["byOidStartN"] = byOidStart,
                                ["byOidStartLen"] = byOidStartLen,
                                ["storeEntries"] = _store.EntryCount,
                            },
                        });
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                            miss + Environment.NewLine);
                        IkeLogOptions.AppendAgentNdjson(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                            miss);
                    }
                    catch { /* ignore */ }
                    // #endregion
                    continue;
                }
                map[key] = (body, br.Start);
                map[hostKeyAlt] = (body, br.Start);
                // H-ORDER: alimenta cache di processo così pending per-gate si recuperano
                // anche quando il seed arriva dopo TraceDecrypt di un sibling sullo stesso OID.
                if (!string.IsNullOrEmpty(oid))
                    OidHostBodyCache.Put(oid, br.Start, body);
                // #region agent log
                if (body.Length > 65_536 || empty || size0 || fordChunk || hasFordDesc)
                {
                    try
                    {
                        var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "03cce7",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["hypothesisId"] = "H-COMPACT",
                            ["runId"] = "per-host-v1",
                            ["location"] = "MmcsChunkAssemblySession.SeedSiblingCompactsFromAuthorizeGet",
                            ["message"] = "seed_host_body_oid_at",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["oid"] = oid.Length > 16 ? oid[..16] : oid,
                                ["start"] = br.Start,
                                ["bodyLen"] = body.Length,
                                ["hostLen"] = hostLen,
                                ["hasFordDesc"] = hasFordDesc,
                                ["empty"] = empty,
                                ["size0"] = size0,
                                ["dataHost"] = !empty && !size0 && !fordChunk && !hasFordDesc,
                            },
                        });
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                            line + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                }
                // #endregion
                // oid@0 solo CT Ford esatto — mai pack data.
                if (body.Length is >= 0x12 and <= 4096
                    && (empty || size0 || fordChunk || hasFordDesc))
                {
                    var exactCt = false;
                    if (group.Count == 0 || fordChunk || hasFordDesc)
                    {
                        if (group.Count == 1 && group[0].Length == body.Length)
                            exactCt = true;
                        else if (empty || size0)
                            //  empty GET body == Auth ctLen (112/155/224/234/…).
                            exactCt = body.Length is >= 0x12 and <= 4096 && body[0] == 0x04;
                    }
                    // Solo ByteRange.Start==0 → oid@0 (mai alias da @highOffset).
                    if (exactCt && br.Start == 0)
                        map.TryAdd(oid + "@0", (body, 0L));
                }
                // Solo bag large (ctLen>64KiB): CI gate45, body==Length≤ByteRange.
                else if (hasFordDesc
                         && br.Start == 0
                         && group.Count == 1
                         && UbChunkBuilder.IsAuthFordDescriptorChunk(group[0])
                         && UbChunkBuilder.IsLargeAuthFordCtLen(group[0].Length)
                         && group[0].Length == body.Length
                         && UbChunkBuilder.IsPlausibleAuthFordCtLen(body.Length, hostLen))
                {
                    map.TryAdd(oid + "@0", (body, 0L));
                }
                added++;
                addedBytes += body.Length;
            }

            // H-AUTH-FORD: seed GETs matched by Auth descriptor OID+ctLen/hostHint
            // Exact Range==ctLen, oppure empty/size0 con hostLen>=ctLen (Read(ctLen)).
            var descs = UbChunkBuilder.CollectAuthFordDescriptors(authorizeGetBody, plan, gets);
            if (descs.Count > 0)
            {
                for (var i = 0; i < gets.Count; i++)
                {
                    var oid = gets[i].EdgeHeaders?.ObjectId ?? "";
                    if (string.IsNullOrEmpty(oid) || gets[i].ByteRange is not { } br)
                        continue;
                    var hostLen = br.End - br.Start + 1;
                    if (hostLen < 112)
                        continue;
                    var sizeMatch = false;
                    foreach (var d in descs)
                    {
                        if (!string.Equals(d.ObjectId, oid, StringComparison.Ordinal))
                            continue;
                        //  1 FileGroup GET = body len == Auth nested ctLen (live 234).
                        if (hostLen == d.CtLen
                            || (d.HostSizeHint > 0 && hostLen == d.HostSizeHint))
                        {
                            sizeMatch = true;
                            break;
                        }
                    }

                    if (!sizeMatch)
                        continue;
                    var key = $"{oid}@{br.Start}";
                    if (map.ContainsKey(key))
                        continue;
                    var body = TryGetChunkBody(gets[i]);
                    if (body is not { Length: > 0 })
                        continue;
                    map[key] = (body, br.Start);
                    OidHostBodyCache.Put(oid, br.Start, body);
                    // #region agent log
                    if (body.Length > 65_536)
                    {
                        try
                        {
                            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "03cce7",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["hypothesisId"] = "H-65K",
                                ["runId"] = "post-fix",
                                ["location"] = "MmcsChunkAssemblySession.SeedSiblingCompactsFromAuthorizeGet",
                                ["message"] = "seed_large_auth_desc",
                                ["data"] = new Dictionary<string, object?>
                                {
                                    ["oid"] = oid.Length > 16 ? oid[..16] : oid,
                                    ["start"] = br.Start,
                                    ["bodyLen"] = body.Length,
                                    ["hostLen"] = hostLen,
                                },
                            });
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                                line + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                    }
                    // #endregion
                    // oid@0 solo CT esatto da HostInfo Start==0 — mai overwrite da altro range.
                    if (br.Start == 0)
                    {
                        foreach (var d in descs)
                        {
                            if (!string.Equals(d.ObjectId, oid, StringComparison.Ordinal))
                                continue;
                            if (body.Length == d.CtLen)
                            {
                                map[oid + "@0"] = (body, 0L);
                                break;
                            }
                        }
                    }
                    added++;
                    addedBytes += body.Length;
                    authDescSeeded++;
                }
            }
        }
        catch
        {
            // fallback sotto
        }

        // #region agent log
        try
        {
            var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
            var emptyHosts = plan.Containers.Count(static c => c.Count == 0);
            var dataHosts = plan.Containers.Count(static c => c.Count != 0);
            var macs = FordMmcsDecryptor.ExtractChunkHeaderMacs(authorizeGetBody);
            var getsLog = UbChunkBuilder.ParseAuthorizeGetResponse(authorizeGetBody);
            var descs = UbChunkBuilder.CollectAuthFordDescriptors(authorizeGetBody, plan, getsLog);
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.SeedSiblingCompactsFromAuthorizeGet",
                ["message"] = "auth_edge_provenance",
                ["hypothesisId"] = "H-P0",
                ["runId"] = "auth-edge-v2",
                ["data"] = new Dictionary<string, object?>
                {
                    // L0 Auth → ingredients for FillChunks
                    ["authBytes"] = authorizeGetBody.Length,
                    ["hosts"] = plan.Containers.Count,
                    ["emptyHosts"] = emptyHosts,
                    ["dataHosts"] = dataHosts,
                    ["refs"] = plan.References.Count,
                    ["macN"] = macs.Count,
                    ["macLead"] = macs.Count > 0 ? Convert.ToHexString(macs[0].AsSpan(0, Math.Min(4, macs[0].Length))) : null,
                    ["authDescN"] = descs.Count,
                    ["authCtLens"] = descs.Select(static d => d.CtLen).Take(8).ToArray(),
                    ["authOids"] = descs.Select(static d => d.ObjectId).Where(static s => s.Length > 0)
                        .Distinct().Take(6).ToArray(),
                    // L1 seed into sibling/cache (edge bodies available for DecryptFord)
                    ["added"] = added,
                    ["addedBytes"] = addedBytes,
                    ["fordSizedChunkInfo"] = fordSizedChunkInfo,
                    ["authDescSeeded"] = authDescSeeded,
                    ["mapCount"] = map.Count,
                },
            });
            // Always-on: provenance is the L0/L1 map for Pipe A/B.
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line + Environment.NewLine);
            // Keep prior seed summary for H-AUTH-FORD filters.
            var seedLine = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.SeedSiblingCompactsFromAuthorizeGet",
                ["message"] = "sibling_seed_batch",
                ["hypothesisId"] = "H-AUTH-FORD",
                ["runId"] = "auth-edge-v2",
                ["data"] = new Dictionary<string, object?>
                {
                    ["added"] = added,
                    ["addedBytes"] = addedBytes,
                    ["fordSizedChunkInfo"] = fordSizedChunkInfo,
                    ["authDescSeeded"] = authDescSeeded,
                    ["mapCount"] = map.Count,
                    ["cacheRecords"] = _byCacheKey.Count,
                    ["storeEntries"] = _store.EntryCount,
                    ["storeApproxMb"] = _store.ApproximateBytes / (1024 * 1024),
                    ["gcMb"] = GC.GetTotalMemory(false) / (1024 * 1024),
                    ["wsMb"] = Environment.WorkingSet / (1024 * 1024),
                },
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                seedLine);
        }
        catch { /* ignore */ }
        // #endregion

        return added;
    }

    /// <summary>
    /// Dopo FillChunks: libera chunk dati grandi. Con pending&gt;0 tiene solo OID+range
    /// ancora referenziati; con pending=0 purge completo dei data-chunk.
    /// </summary>
    public int PurgeDataChunksAfterBatch(IProgress<string>? log = null)
    {
        // Prima sblocca i pin dei pending eccessivi, poi flush release + purge dati.
        EvictExcessPending(MaxPendingFiles, log);
        FlushDeferredDataChunkReleases();

        var removed = 0;
        long freed = 0;
        var before = _store.ApproximateBytes;
        List<(string Key, int Len)> toRemove;
        lock (_cacheGate)
        {
            if (_pending.Count == 0)
            {
                // Nessun pending: NON wipe dei data-chunk — il prossimo AG può
                // condividere gli stessi OID. I file già decifrati sono già stati
                // rilasciati da ReleaseDataChunksForAsset (solo Ok).
                toRemove = [];
            }
            else
            {
                var needed = new HashSet<string>(StringComparer.Ordinal);
                foreach (var p in _pending)
                {
                    foreach (var ch in p.Chunks)
                    {
                        if (ch.ByteRange is not { } br)
                            continue;
                        var oid = ch.EdgeHeaders?.ObjectId;
                        if (string.IsNullOrEmpty(oid))
                            continue;
                        needed.Add($"{oid}:{br.Start}-{br.End}");
                    }

                    foreach (var mk in p.MissingKeys)
                        needed.Add("miss:" + mk);
                }

                toRemove = [];
                foreach (var kv in _byCacheKey)
                {
                    if (kv.Value.BodyLength <= 65_536)
                        continue;
                    var tag = $"{kv.Value.ObjectId}:{kv.Value.RangeStart}-{kv.Value.RangeEnd}";
                    if (needed.Contains(tag) || needed.Contains("miss:" + kv.Key))
                        continue;
                    toRemove.Add((kv.Key, kv.Value.BodyLength));
                }
            }
        }

        foreach (var (key, len) in toRemove)
        {
            if (!_store.Remove(key))
                continue;
            removed++;
            freed += len;
            lock (_cacheGate)
                _byCacheKey.Remove(key);
        }

        // #region agent log
        try
        {
            var (pendN, authBytes, uniqueAuth) = EstimatePendingRam();
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.PurgeDataChunksAfterBatch",
                ["message"] = "purge_data_chunks",
                ["hypothesisId"] = "H-RAM-REL",
                ["runId"] = "ram-cap-v2",
                ["data"] = new
                {
                    removed,
                    freedMb = freed / (1024 * 1024),
                    mbBefore = before / (1024 * 1024),
                    mbAfter = _store.ApproximateBytes / (1024 * 1024),
                    pendingFiles = pendN,
                    pendingAuthMb = authBytes / (1024 * 1024),
                    pendingUniqueAuthMb = uniqueAuth / (1024 * 1024),
                    storeEntries = _store.EntryCount,
                    gcMb = GC.GetTotalMemory(false) / (1024 * 1024),
                    wsMb = Environment.WorkingSet / (1024 * 1024),
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        if (removed > 0)
        {
            log?.Report(
                $"  mmcs_cache: purge {removed} chunk dati " +
                $"(−{freed / (1024 * 1024.0):0.#} MB; pending={_pending.Count})");
        }

        return removed;
    }

    /// <summary>
    /// OID@start ancora referenziati da file pending — non trim/purge (H-EVICT / PENDING).
    /// </summary>
    public HashSet<string> CollectPendingKeepOidAtStartKeys()
    {
        var keep = new HashSet<string>(StringComparer.Ordinal);
        PendingFileAssembly[] snap;
        lock (_cacheGate)
            snap = _pending.ToArray();
        foreach (var p in snap)
        {
            if (p.Chunks is null)
                continue;
            foreach (var ch in p.Chunks)
            {
                if (ch.ByteRange is not { } br)
                    continue;
                var oid = ch.EdgeHeaders?.ObjectId;
                if (string.IsNullOrEmpty(oid))
                    continue;
                keep.Add($"{oid}@{br.Start}");
            }
        }

        return keep;
    }

    /// <summary>
    /// Dopo un AG-batch: rilascia empty-host Ford non più nel keep-set (cap RAM stile iTunes ~centinaia MB).
    /// </summary>
    public int TrimEmptyHostCache(
        IReadOnlyCollection<string>? keepOidAtStartKeys,
        int maxEmptyEntries = 256,
        long maxEmptyBytes = 32L * 1024 * 1024)
    {
        var removed = 0;
        long emptyBytes = 0;
        var emptyKeys = new List<(string CacheKey, string MapKey, int Len)>();
        lock (_cacheGate)
        {
            foreach (var rec in _byCacheKey.Values)
            {
                if (rec.BodyLength > 65_536)
                    continue;
                var mapKey = $"{rec.ObjectId}@{rec.RangeStart}";
                emptyKeys.Add((rec.CacheKey, mapKey, rec.BodyLength));
                emptyBytes += rec.BodyLength;
            }
        }

        if (emptyKeys.Count == 0)
            return 0;

        // Sempre unisci i pending: body ≤65KiB possono essere DATA (es. 656B) non solo Ford.
        var keep = new HashSet<string>(StringComparer.Ordinal);
        foreach (var k in CollectPendingKeepOidAtStartKeys())
            keep.Add(k);
        if (keepOidAtStartKeys is { Count: > 0 })
        {
            foreach (var k in keepOidAtStartKeys)
                keep.Add(k);
        }

        // Evict: non in keep, oppure overflow oltre max entries/bytes (i più vecchi in lista).
        long keptBytes = 0;
        var kept = 0;
        foreach (var (cacheKey, mapKey, len) in emptyKeys)
        {
            var mustKeep = keep.Contains(mapKey);
            if (mustKeep)
            {
                kept++;
                keptBytes += len;
                continue;
            }

            if (kept < maxEmptyEntries && keptBytes + len <= maxEmptyBytes)
            {
                kept++;
                keptBytes += len;
                continue;
            }

            if (_store.Remove(cacheKey))
            {
                lock (_cacheGate)
                    _byCacheKey.Remove(cacheKey);
                removed++;
            }
        }

        // #region agent log
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.TrimEmptyHostCache",
                ["message"] = "mmcs_trim_empty",
                ["hypothesisId"] = "H-EVICT",
                ["runId"] = "pending-keep-v1",
                ["data"] = new Dictionary<string, object?>
                {
                    ["removed"] = removed,
                    ["emptyBefore"] = emptyKeys.Count,
                    ["kept"] = kept,
                    ["keptBytes"] = keptBytes,
                    ["pendingKeep"] = keep.Count,
                    ["storeEntries"] = _store.EntryCount,
                    ["storeApproxMb"] = _store.ApproximateBytes / (1024 * 1024),
                    ["gcMb"] = GC.GetTotalMemory(false) / (1024 * 1024),
                    ["wsMb"] = Environment.WorkingSet / (1024 * 1024),
                },
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch { /* ignore */ }
        // #endregion

        return removed;
    }

    /// <summary>
    /// CChunkCache Ford feed: pianta in sibling solo host Auth Ford-material
    /// (empty / gate45 / ford-sized). I data host restano nello store + <c>sig:</c>
    /// (non sotto <c>oid@*</c> — altrimenti Read(ctLen) prende data[:ctLen]).
    /// </summary>
    public void SeedSiblingCompacts(IDictionary<string, (byte[] Compact, long MmcsStart)> map)
    {
        const int maxEntries = 256;
        const long maxBytes = 32L * 1024 * 1024;
        var added = 0;
        var skippedLarge = 0;
        var skippedData = 0;
        long addedBytes = 0;
        long skippedBytes = 0;
        MmcsChunkRecord[] snapshot;
        lock (_cacheGate)
            snapshot = _byCacheKey.Values.ToArray();
        foreach (var rec in snapshot)
        {
            if (added >= maxEntries || addedBytes >= maxBytes)
                break;

            var body = _store.TryGet(rec.CacheKey);
            if (body is null || body.Length == 0)
                continue;

            //  ogni host Auth ha il proprio body sotto oid@{Start} (Ford E data).
            // Compact concatenato non sostituisce questa mappa.
            // Data CI → anche sig:checksum21 (CChunkCache twin).
            if (rec.Signature21 is { Length: 21 })
            {
                var sigKey = "sig:" + Convert.ToHexString(rec.Signature21).ToLowerInvariant();
                map.TryAdd(sigKey, (body, 0L));
            }
            else if (_batchPlan is not null && !IsFordMaterialCacheRecord(rec, body.Length))
            {
                // Pack data: slice CI sotto sig: + body intero sotto oid@ sotto.
                SeedSigIdentitySlicesIntoMap(
                    map, _batchPlan, body,
                    rec.ObjectId, rec.RangeStart, rec.RangeEnd, _batchHosts);
            }

            // Solo host del batch corrente (range Auth) — non spill alieni.
            if (_batchPlan is not null && _batchHosts is not null
                && !IsBatchHostRange(rec))
            {
                skippedData++;
                continue;
            }

            var key = $"{rec.ObjectId}@{rec.RangeStart}";
            if (map.ContainsKey(key))
                continue;
            map[key] = (body, rec.RangeStart);
            if (!string.IsNullOrEmpty(rec.ObjectId))
                OidHostBodyCache.Put(rec.ObjectId, rec.RangeStart, body);
            added++;
            addedBytes += body.Length;
            // #region agent log
            if (body.Length > 65_536)
            {
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-COMPACT",
                        ["runId"] = "per-host-v1",
                        ["location"] = "MmcsChunkAssemblySession.SeedSiblingCompacts",
                        ["message"] = "seed_host_body_oid_at",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["oid"] = rec.ObjectId.Length > 16 ? rec.ObjectId[..16] : rec.ObjectId,
                            ["start"] = rec.RangeStart,
                            ["bodyLen"] = body.Length,
                            ["fordMaterial"] = IsFordMaterialCacheRecord(rec, body.Length),
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
            }
            // #endregion
        }

        // Pack Auth grandi fuori batch match: comunque sig: slices.
        if (_batchPlan is not null)
        {
            foreach (var rec in snapshot)
            {
                if (rec.BodyLength <= 65_536)
                    continue;
                var pack = _store.TryGet(rec.CacheKey);
                if (pack is null || pack.Length != rec.BodyLength)
                    continue;
                SeedSigIdentitySlicesIntoMap(
                    map, _batchPlan, pack,
                    rec.ObjectId, rec.RangeStart, rec.RangeEnd, _batchHosts);
            }
        }

        // #region agent log
        try
        {
            var keySample = map.Keys.Take(16).ToArray();
            var sigN = map.Keys.Count(static k => k.StartsWith("sig:", StringComparison.Ordinal));
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.SeedSiblingCompacts",
                ["message"] = "sibling_seed_ford_only",
                ["hypothesisId"] = "H-DL3",
                ["runId"] = "download-ike-v1",
                ["data"] = new Dictionary<string, object?>
                {
                    ["cacheRecords"] = _byCacheKey.Count,
                    ["added"] = added,
                    ["addedBytes"] = addedBytes,
                    ["skippedLarge"] = skippedLarge,
                    ["skippedData"] = skippedData,
                    ["skippedBytes"] = skippedBytes,
                    ["mapCount"] = map.Count,
                    ["sigKeys"] = sigN,
                    ["keySample"] = keySample,
                    ["gcMb"] = GC.GetTotalMemory(false) / (1024 * 1024),
                    ["wsMb"] = Environment.WorkingSet / (1024 * 1024),
                    ["downloadIke"] = true,
                },
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line);
        }
        catch
        {
            // ignore
        }
        // #endregion
    }

    private static void SeedSigIdentitySlicesIntoMap(
        IDictionary<string, (byte[] Compact, long MmcsStart)> map,
        AuthorizeGetDecryptPlan plan,
        byte[] pack,
        string? objectId = null,
        long rangeStart = -1,
        long rangeEnd = -1,
        IReadOnlyList<SignedUrlChunk>? alignedHosts = null)
    {
        IReadOnlyList<AuthorizeGetCryptoChunk> match;
        long layoutSum;
        long hostStart = 0;
        if (objectId is not null
            && rangeStart >= 0
            && rangeEnd >= rangeStart
            && alignedHosts is not null)
        {
            var fakeGet = new SignedUrlChunk
            {
                ByteRange = (rangeStart, rangeEnd),
                EdgeHeaders = new EdgeDownloadHeaders { ObjectId = objectId },
            };
            if (!TryResolveHostContainerGroup(plan, fakeGet, alignedHosts, out match, out layoutSum))
                return;
            hostStart = rangeStart;
        }
        else if (!TryPickAuthLayoutGroup(plan, pack.Length, out match, out layoutSum))
        {
            return;
        }

        var fordOnly = match.Count > 0 && match.All(UbChunkBuilder.IsAuthFordDescriptorChunk);
        var hostLen = pack.Length;
        var layoutOff = 0;
        for (var i = 0; i < match.Count; i++)
        {
            var ch = match[i];
            var wireOff = UbChunkBuilder.ResolveCiWireInHostBody(
                ch.Offset, ch.Length, hostStart, hostLen,
                layoutOff, i, match.Count, layoutSum, fordOnly);
            if (ch.Length <= 0
                || wireOff < 0
                || wireOff + ch.Length > pack.Length)
            {
                layoutOff += ch.Length;
                continue;
            }

            // ChunkStream key = hex(checksum): data sig21 + Ford gate45.
            if (ch.Checksum21 is { Length: 21 })
            {
                var sigKey = "sig:" + Convert.ToHexString(ch.Checksum21).ToLowerInvariant();
                map[sigKey] = (pack.AsSpan((int)wireOff, ch.Length).ToArray(), 0L);
            }
            else if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch))
            {
                // Vietato: slice gate da pack via CI.Offset. Spill = body exact ctLen
                // solo in LiveFillPipeline (1 GET → 1 file).
            }

            layoutOff += ch.Length;
        }
    }

    /// <summary>
    /// Come <see cref="TryGetChunkBody"/>; se miss e <paramref name="dataGroup"/> è data-only,
    /// prova recovery store (sig: / OID+len) senza toccare Ford.
    /// </summary>
    public byte[]? TryGetChunkBodyOrRecoverData(
        SignedUrlChunk chunk,
        IReadOnlyList<AuthorizeGetCryptoChunk>? dataGroup)
    {
        var body = TryGetChunkBody(chunk);
        if (body is { Length: > 0 })
            return body;
        if (dataGroup is null || chunk.ByteRange is not { } br)
            return null;
        if (!dataGroup.Any(UbChunkBuilder.IsAuthDataChunk)
            || dataGroup.Any(UbChunkBuilder.IsAuthFordDescriptorChunk))
            return null;
        var oid = chunk.EdgeHeaders?.ObjectId ?? "";
        var hostLen = br.End - br.Start + 1;
        if (!TryRecoverDataHostBody(oid, br.Start, br.End, hostLen, dataGroup, out var recovered, out var sigOnly)
            || recovered is not { Length: > 0 }
            || sigOnly)
            return null;
        return recovered;
    }

    public byte[]? TryGetChunkBody(SignedUrlChunk chunk)
    {
        if (chunk.ByteRange is not { } range)
            return null;

        var oid = chunk.EdgeHeaders?.ObjectId ?? string.Empty;
        MmcsChunkRecord[] snapshot;
        try
        {
            lock (_cacheGate)
                snapshot = _byCacheKey.Values.ToArray();
        }
        catch (InvalidOperationException ex)
        {
            // #region agent log
            AgentCollectionRaceLog(
                "H-CM1",
                "byCacheKey_enum_fault",
                new
                {
                    where = "TryGetChunkBody",
                    err = ex.Message,
                    count = _byCacheKey.Count,
                    stack = ex.StackTrace,
                });
            // #endregion
            throw;
        }
        foreach (var rec in snapshot)
        {
            if (!string.Equals(rec.ObjectId, oid, StringComparison.Ordinal))
                continue;
            if (rec.RangeStart == range.Start && rec.RangeEnd == range.End)
                return _store.TryGet(rec.CacheKey);
        }

        // RAM / keyed lookup without _byCacheKey (race / host-range put).
        var hostKey = MmcsChunkStore.HostRangeKey(-1, oid, range.Start, range.End);
        var fromStore = _store.TryGet(hostKey);
        if (fromStore is { Length: > 0 })
            return fromStore;

        // Fallback disco solo se spill abilitato e la cartella esiste.
        if (!_store.PersistToDisk || !Directory.Exists(_store.RootDirectory))
            return null;

        foreach (var key in Directory.EnumerateFiles(_store.RootDirectory))
        {
            var name = Path.GetFileName(key);
            if (name.StartsWith("host_", StringComparison.Ordinal)
                && name.Contains($"_{range.Start}_{range.End}", StringComparison.Ordinal)
                && name.Contains(SanitizeOidToken(oid), StringComparison.Ordinal))
            {
                return File.ReadAllBytes(key);
            }
        }

        return null;
    }

    /// <summary>
    /// Recupera body data già in store quando la chiave Auth <c>oid@{Start}</c> manca
    /// (range-key drift / release anticipato). Solo host data-only — mai Ford.
    /// Re-indexa sotto HostRangeKey Auth così i seed successivi trovano il body.
    /// </summary>
    private bool TryRecoverDataHostBody(
        string oid,
        long rangeStart,
        long rangeEnd,
        long hostLen,
        IReadOnlyList<AuthorizeGetCryptoChunk> group,
        out byte[]? body,
        out bool sigOnly)
    {
        body = null;
        sigOnly = false;
        if (hostLen < 0x12 || string.IsNullOrEmpty(oid))
            return false;

        // 1) SignatureToKey del CI data (PutAuthLayout / PutShared).
        foreach (var c in group)
        {
            if (!UbChunkBuilder.IsAuthDataChunk(c)
                || c.Checksum21 is not { Length: 21 }
                || c.Length <= 0)
                continue;
            var fromSig = _store.TryGet(MmcsChunkStore.SignatureToKey(c.Checksum21));
            if (fromSig is not { Length: > 0 })
                continue;
            if (fromSig.Length == hostLen)
            {
                body = fromSig;
                ReindexDataHostBody(oid, rangeStart, rangeEnd, body, c.Checksum21);
                return true;
            }

            if (fromSig.Length == c.Length)
            {
                body = fromSig;
                sigOnly = true;
                return true;
            }
        }

        // 2) Stesso OID con BodyLength == hostLen (Start diverso dall'Auth range).
        MmcsChunkRecord[] snapshot;
        lock (_cacheGate)
            snapshot = _byCacheKey.Values.ToArray();
        foreach (var rec in snapshot)
        {
            if (!string.Equals(rec.ObjectId, oid, StringComparison.Ordinal))
                continue;
            if (rec.BodyLength != hostLen)
                continue;
            var cand = _store.TryGet(rec.CacheKey);
            if (cand is not { Length: > 0 } || cand.Length != hostLen)
                continue;
            body = cand;
            byte[]? dataCs = null;
            foreach (var c in group)
            {
                if (UbChunkBuilder.IsAuthDataChunk(c) && c.Checksum21 is { Length: 21 })
                {
                    dataCs = c.Checksum21;
                    break;
                }
            }

            ReindexDataHostBody(oid, rangeStart, rangeEnd, body, dataCs);
            return true;
        }

        return false;
    }

    private void ReindexDataHostBody(
        string oid,
        long rangeStart,
        long rangeEnd,
        byte[] body,
        byte[]? dataChecksum21)
    {
        var hostKey = MmcsChunkStore.HostRangeKey(-1, oid, rangeStart, rangeEnd);
        var keys = new List<string>(2) { hostKey };
        if (dataChecksum21 is { Length: 21 })
            keys.Add(MmcsChunkStore.SignatureToKey(dataChecksum21));
        _store.PutShared(keys, body);
        lock (_cacheGate)
        {
            if (_byCacheKey.ContainsKey(hostKey))
                return;
            _byCacheKey[hostKey] = new MmcsChunkRecord(
                hostKey, oid, rangeStart, rangeEnd, -1, dataChecksum21, body.Length);
        }
    }

    private void RegisterRecordIfMissing(
        SignedUrlChunk get,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<string> keys,
        int bodyLength)
    {
        if (keys.Count == 0 || _byCacheKey.ContainsKey(keys[0]))
            return;
        RegisterRecord(get, plan, keys, bodyLength);
    }

    private void RegisterRecord(
        SignedUrlChunk get,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<string> keys,
        int bodyLength)
    {
        if (keys.Count == 0 || get.ByteRange is not { } range)
            return;

        // #region agent log
        // H-CM1: Dictionary _byCacheKey must only mutate under _cacheGate; unlocked writes
        // race Values.ToArray()/foreach → "Collection was modified".
        if (!Monitor.IsEntered(_cacheGate))
        {
            var n = Interlocked.Increment(ref _unlockedRegisterLogN);
            if (n <= 30 || (n & 63) == 0)
            {
                AgentCollectionRaceLog(
                    "H-CM1",
                    "byCacheKey_mutate_unlocked",
                    new
                    {
                        n,
                        oid = get.EdgeHeaders?.ObjectId,
                        keysN = keys.Count,
                        bodyLength,
                        stack = Environment.StackTrace,
                    });
            }
        }
        // #endregion

        byte[]? sig = FindChecksumForChunk(get, plan);

        var rec = new MmcsChunkRecord(
            keys[0],
            get.EdgeHeaders?.ObjectId ?? string.Empty,
            range.Start,
            range.End,
            -1,
            sig,
            bodyLength);

        foreach (var key in keys)
            _byCacheKey[key] = rec;
    }

    // #region agent log
    private static void AgentCollectionRaceLog(string hypothesisId, string message, object data)
    {
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession",
                ["message"] = message,
                ["hypothesisId"] = hypothesisId,
                ["runId"] = "coll-mod-v1",
                ["data"] = data,
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    /// <summary>
    /// True se il record cache è un host Auth Ford (empty/gate/ford-sized), non data CI.
    /// </summary>
    private bool IsFordMaterialCacheRecord(MmcsChunkRecord rec, int bodyLen)
    {
        if (_batchPlan is not null && _batchHosts is not null)
        {
            var n = Math.Min(_batchPlan.Containers.Count, _batchHosts.Count);
            for (var i = 0; i < n; i++)
            {
                var host = _batchHosts[i];
                if (!string.Equals(host.EdgeHeaders?.ObjectId, rec.ObjectId, StringComparison.Ordinal))
                    continue;
                if (host.ByteRange is not { } br
                    || br.Start != rec.RangeStart
                    || br.End != rec.RangeEnd)
                    continue;

                var g = _batchPlan.Containers[i];
                if (g.Count == 0
                    || UbChunkBuilder.IsAuthFordMaterialHost(g)
                    || g.Any(UbChunkBuilder.IsAuthFordDescriptorChunk)
                    || UbChunkBuilder.IsFordSizedHostLengths(g)
                    || string.Equals(
                        host.EdgeHeaders?.MmcsContainerSize, "0", StringComparison.Ordinal))
                    return true;

                // Host Auth data del batch (ora anche in sibling oid@ — body separato).
                return false;
            }
        }

        // Fuori batch: solo CT Ford classici (mai data CI mid-size tipo 256/512/3072).
        return bodyLen is 112 or 155 or 224 or 310 or 464 or 480
               || (bodyLen >= 224 && bodyLen <= 4096 && bodyLen % 112 == 0);
    }

    /// <summary>Record corrisponde a un host del batch AG corrente (OID+ByteRange).</summary>
    private bool IsBatchHostRange(MmcsChunkRecord rec)
    {
        if (_batchHosts is null)
            return false;
        foreach (var host in _batchHosts)
        {
            if (!string.Equals(host.EdgeHeaders?.ObjectId, rec.ObjectId, StringComparison.Ordinal))
                continue;
            if (host.ByteRange is not { } br)
                continue;
            if (br.Start == rec.RangeStart && br.End == rec.RangeEnd)
                return true;
        }

        return false;
    }

    // #region agent log
    private static void AgentLogDownloadEnqueue(
        string kind, string oid, long start, long end, int ctLen, long authLen)
    {
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-DL1",
                ["runId"] = "download-ike-v1",
                ["location"] = "MmcsChunkAssemblySession.EnsureAuthorizeGetBatchPrefetchCachedAsync",
                ["message"] = "download_enqueue",
                ["data"] = new Dictionary<string, object?>
                {
                    ["kind"] = kind,
                    ["oid"] = oid.Length > 16 ? oid[..16] : oid,
                    ["start"] = start,
                    ["end"] = end,
                    ["ctLen"] = ctLen,
                    ["authLen"] = authLen,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
    }
    // #endregion

    private static byte[]? FindChecksumForChunk(SignedUrlChunk get, AuthorizeGetDecryptPlan plan)
    {
        if (get.ByteRange is not { } range)
            return null;

        var len = range.End - range.Start + 1;
        byte[]? unique = null;
        var n = 0;
        foreach (var group in plan.Containers)
        {
            foreach (var ch in group)
            {
                if (ch.Length != len || ch.Checksum21 is not { Length: 21 })
                    continue;
                n++;
                unique = ch.Checksum21;
            }
        }

        // Identità: solo se UN CI nel plan ha questa Length (no alias 2×D3072).
        return n == 1 ? unique : null;
    }

    private static List<string> ResolveCacheKeysForChunk(
        SignedUrlChunk get,
        AuthorizeGetDecryptPlan plan)
    {
        var keys = new List<string>(2);
        if (get.ByteRange is not { } range)
            return keys;

        var oid = get.EdgeHeaders?.ObjectId ?? string.Empty;
        keys.Add(MmcsChunkStore.HostRangeKey(-1, oid, range.Start, range.End));

        // Signature solo se Length unica nel plan — mai PutShared su entrambi i D3072.
        var sig = FindChecksumForChunk(get, plan);
        if (sig is { Length: 21 })
            keys.Add(MmcsChunkStore.SignatureToKey(sig));

        // #region agent log
        try
        {
            var sameLen = 0;
            var len = range.End - range.Start + 1;
            foreach (var g in plan.Containers)
            foreach (var ch in g)
                if (ch.Length == len && ch.Checksum21 is { Length: 21 })
                    sameLen++;
            if (sameLen > 1 || sig is not null)
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-ID2",
                    ["runId"] = "identity-v1",
                    ["location"] = "MmcsChunkAssemblySession.ResolveCacheKeysForChunk",
                    ["message"] = "cache_keys_identity",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["oid"] = oid.Length > 12 ? oid[..12] : oid,
                        ["len"] = len,
                        ["sameLenCi"] = sameLen,
                        ["boundSig"] = sig is not null,
                        ["keysN"] = keys.Count,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
        }
        catch { /* ignore */ }
        // #endregion

        return keys.Distinct(StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// CChunkCache: dopo GET del pack Auth, mette ogni CI sotto SignatureToKey(checksum21).
    /// Container = host OID+ByteRange allineato al plan (mai demux per sola length:
    /// N×112 Ford → AMB e Put saltato).
    /// </summary>
    private void PutAuthLayoutChecksumSlices(
        AuthorizeGetDecryptPlan plan,
        SignedUrlChunk get,
        byte[] body,
        IReadOnlyList<SignedUrlChunk>? alignedHosts = null)
    {
        if (get.ByteRange is not { } br || body.Length == 0)
            return;
        var hostLen = br.End - br.Start + 1;
        if (body.Length != hostLen)
            return;

        if (!TryResolveHostContainerGroup(plan, get, alignedHosts, out var match, out var layoutSum))
            return;

        var fordOnly = match.Count > 0 && match.All(UbChunkBuilder.IsAuthFordDescriptorChunk);
        var hasData = match.Any(UbChunkBuilder.IsAuthDataChunk);
        // Host locale: data+ford sullo stesso pack (log/spill).
        var mixedDataFord = hasData && match.Any(UbChunkBuilder.IsAuthFordDescriptorChunk);
        // Plan-wide: FileBus/PaperBoard = Ford su host A, data su host B → mixedDataFord=false
        // ma SIV richiede lead-0x04 comunque (altrimenti MAC20 staging).
        var planHasFord = false;
        foreach (var g in plan.Containers)
        {
            if (g.Any(UbChunkBuilder.IsAuthFordDescriptorChunk))
            {
                planHasFord = true;
                break;
            }
        }

        var layoutOff = 0;
        var putN = 0;
        var hostStart = br.Start;
        var resolveHow = alignedHosts is not null ? "host-id" : "fallback";
        for (var i = 0; i < match.Count; i++)
        {
            var ch = match[i];
            // Data: ChunkInfo.Offset  poi gap layout.
            if (ch.Checksum21 is { Length: 21 } && ch.Length > 0)
            {
                var wireOff = UbChunkBuilder.ResolveCiWireInHostBody(
                    ch.Offset, ch.Length, hostStart, hostLen,
                    layoutOff, i, match.Count, layoutSum, fordOnlyHost: false);
                if (wireOff >= 0 && wireOff + ch.Length <= body.Length)
                {
                    var slice = body.AsSpan((int)wireOff, ch.Length);
                    //  data CI keyed checksum21 indipendentemente dal lead
                    // (live packed host: CI head C4… sotto 42-hex; Ford head 04 sotto 90-hex).
                    // Non richiedere 0x04 quando planHasFord — altrimenti Class B ike-no-data.
                    _ = planHasFord;
                    if (slice.Length > 0)
                    {
                        var key = MmcsChunkStore.SignatureToKey(ch.Checksum21);
                        _store.Put(key, slice);
                        // Persist beyond ReleaseDataChunks / siblingCompacts.Clear (Class B).
                        ChunkFileCache.Put(ch.Checksum21, slice);
                        putN++;
                        // #region agent log
                        try
                        {
                            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "b3df71",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["hypothesisId"] = "H-IKE1",
                                ["runId"] = "data-plant-non04-v1",
                                ["location"] = "MmcsChunkAssemblySession.PutAuthLayoutChecksumSlices",
                                ["message"] = "put_data_ci_any_lead",
                                ["data"] = new Dictionary<string, object?>
                                {
                                    ["len"] = slice.Length,
                                    ["head"] = slice.Length > 0 ? slice[0] : -1,
                                    ["planHasFord"] = planHasFord,
                                    ["wireOff"] = wireOff,
                                },
                            });
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                                line + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                        // #endregion
                    }
                }
            }
            // Ford: NON spillare qui in ChunkFileCache / sig-key.
            // Questo path gira al GET Auth spesso SENZA IKM → body head-04 che non apre
            // avvelena .chunks (Books: 043A2AC4… sotto gate 01C0FE09 → no-ford).
            // Spill Ford solo da PutChunksFromHostBodies / BindOwnedFordStorages con IKM.
            else if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                     && ch.Length > 0
                     && !mixedDataFord)
            {
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-NO-EARLY-FORD-SPILL",
                        ["runId"] = "no-early-ford-spill-v1",
                        ["location"] = "MmcsChunkAssemblySession.PutAuthLayoutChecksumSlices",
                        ["message"] = "skip_ford_spill_no_ikm",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["ctLen"] = ch.Length,
                            ["bodyLen"] = body.Length,
                            ["gate8"] = ch.Checksum21.Length >= 8
                                ? Convert.ToHexString(ch.Checksum21.AsSpan(0, 8))
                                : "",
                            ["resolve"] = resolveHow,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
            }

            layoutOff += ch.Length;
        }

        // #region agent log
        if (putN > 0)
        {
            try
            {
                var fordGap = UbChunkBuilder.AuthInterCiFordGap(hostLen, layoutSum, match.Count);
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-FORD-GAP",
                    ["runId"] = "host-id-put-v1",
                    ["location"] = "MmcsChunkAssemblySession.PutAuthLayoutChecksumSlices",
                    ["message"] = "sig_slices_put",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["hostLen"] = hostLen,
                        ["layoutSum"] = layoutSum,
                        ["pad"] = hostLen - layoutSum,
                        ["fordGap"] = fordGap,
                        ["fordOnly"] = fordOnly,
                        ["ciN"] = match.Count,
                        ["putN"] = putN,
                        ["how"] = resolveHow,
                        ["oid"] = (get.EdgeHeaders?.ObjectId ?? "").Length > 12
                            ? (get.EdgeHeaders?.ObjectId ?? "")[..12]
                            : get.EdgeHeaders?.ObjectId ?? "",
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
        }
        // #endregion
    }

    /// <summary>
    ///  container = host Auth allineato (OID+ByteRange → Containers[i]).
    /// Fallback length-unique solo se un solo gruppo layoutta hostLen.
    /// </summary>
    private static bool TryResolveHostContainerGroup(
        AuthorizeGetDecryptPlan plan,
        SignedUrlChunk get,
        IReadOnlyList<SignedUrlChunk>? alignedHosts,
        out IReadOnlyList<AuthorizeGetCryptoChunk> match,
        out long layoutSum)
    {
        match = Array.Empty<AuthorizeGetCryptoChunk>();
        layoutSum = 0;
        if (get.ByteRange is not { } br)
            return false;

        var oid = get.EdgeHeaders?.ObjectId ?? "";
        // Solo hosts 1:1 con Containers (AuthSlice / AG completo). Liste filtrate → fallback.
        if (alignedHosts is { Count: > 0 }
            && alignedHosts.Count == plan.Containers.Count)
        {
            for (var i = 0; i < alignedHosts.Count; i++)
            {
                var h = alignedHosts[i];
                if (h.ByteRange is not { } hbr)
                    continue;
                if (!string.Equals(h.EdgeHeaders?.ObjectId ?? "", oid, StringComparison.Ordinal))
                    continue;
                if (hbr.Start != br.Start || hbr.End != br.End)
                    continue;
                match = plan.Containers[i];
                foreach (var ch in match)
                    layoutSum += ch.Length;
                return true;
            }
        }

        var hostLen = br.End - br.Start + 1;
        return TryPickAuthLayoutGroup(plan, hostLen, out match, out layoutSum);
    }

    /// <summary>
    /// Gruppo CI che layoutta il pack Auth: max Σlen ≤ hostLen con padding ≤ 8KiB.
    /// Esclude AuthSlice demux (un solo CI su pack multi-MB).
    /// </summary>
    private static bool TryPickAuthLayoutGroup(
        AuthorizeGetDecryptPlan plan,
        long hostLen,
        out IReadOnlyList<AuthorizeGetCryptoChunk> match,
        out long layoutSum)
    {
        match = Array.Empty<AuthorizeGetCryptoChunk>();
        layoutSum = 0;
        const long maxPad = 8192;
        IReadOnlyList<AuthorizeGetCryptoChunk>? best = null;
        long bestSum = -1;
        var nBest = 0;
        foreach (var group in plan.Containers)
        {
            long sum = 0;
            foreach (var ch in group)
                sum += ch.Length;
            if (sum <= 0 || sum > hostLen || hostLen - sum > maxPad)
                continue;
            if (sum > bestSum)
            {
                bestSum = sum;
                best = group;
                nBest = 1;
            }
            else if (sum == bestSum)
            {
                nBest++;
            }
        }

        if (best is null || nBest != 1)
            return false;
        match = best;
        layoutSum = bestSum;
        return true;
    }

    /// <summary>
    /// ChunkStream: pianta in sibling <c>sig:hex</c> / <c>gate:hex</c> ogni CI
    /// già in store (checksum21 data o gate45 Ford).
    /// </summary>
    public void SeedChecksum21FromStoreIntoMap(
        IDictionary<string, (byte[] Compact, long MmcsStart)> map,
        AuthorizeGetDecryptPlan plan)
    {
        var addedSig = 0;
        var addedGate = 0;
        foreach (var group in plan.Containers)
        {
            foreach (var ch in group)
            {
                if (ch.Length <= 0 || ch.Checksum21 is not { Length: > 0 })
                    continue;
                var isData = ch.Checksum21.Length == 21;
                var isGate = UbChunkBuilder.IsAuthFordDescriptorChunk(ch);
                if (!isData && !isGate)
                    continue;
                var storeKey = MmcsChunkStore.SignatureToKey(ch.Checksum21);
                var body = _store.TryGet(storeKey);
                if (body is null || body.Length != ch.Length)
                    continue;
                var hex = Convert.ToHexString(ch.Checksum21).ToLowerInvariant();
                if (isData)
                {
                    if (map.TryAdd("sig:" + hex, (body, 0L)))
                        addedSig++;
                    ChunkFileCache.Put(ch.Checksum21, body);
                }
                else if (map.TryAdd("gate:" + hex, (body, 0L)))
                {
                    addedGate++;
                }
            }
        }

        // #region agent log
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-FEED-SIG",
                ["runId"] = "gate-cache-v1",
                ["location"] = "MmcsChunkAssemblySession.SeedChecksum21FromStoreIntoMap",
                ["message"] = "sig_gate_seed_from_store",
                ["data"] = new Dictionary<string, object?>
                {
                    ["addedSig"] = addedSig,
                    ["addedGate"] = addedGate,
                    ["mapCount"] = map.Count,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
    }

    /// <summary>
    /// Auth→edge Ford host (live 2026-09-23 CallParseAuth dump):
    /// empty CI, <c>X-Apple-MMCS-Container-Size:0</c>, ford-sized CI, oppure
    /// Auth gate45+ctLen+OID con range=ctLen (es. bytes=0-604 → 605).
    /// </summary>
    private static string? ClassifyFordPrefetchHost(
        AuthorizeGetDecryptPlan plan,
        int containerIndex,
        SignedUrlChunk get,
        IReadOnlyList<UbChunkBuilder.AuthFordDescriptor> descs)
    {
        var empty = (uint)containerIndex >= (uint)plan.Containers.Count
                    || plan.Containers[containerIndex].Count == 0;
        if (empty)
            return "empty";

        if (string.Equals(get.EdgeHeaders?.MmcsContainerSize, "0", StringComparison.Ordinal))
            return "size0";

        if (FordMmcsDecryptor.IsFordSizedPlanContainer(plan, containerIndex))
            return "fordSized";

        if (descs.Count == 0 || get.ByteRange is not { } br)
            return null;

        var oid = get.EdgeHeaders?.ObjectId ?? "";
        if (string.IsNullOrEmpty(oid))
            return null;

        var hostLen = br.End - br.Start + 1;
        foreach (var d in descs)
        {
            if (!string.Equals(d.ObjectId, oid, StringComparison.Ordinal))
                continue;
            // Exact ctLen / hostHint only (Read(ctLen)). No ≤4096 blanket.
            if (hostLen == d.CtLen)
                return "authDesc";
            if (d.HostSizeHint > 0 && hostLen == d.HostSizeHint)
                return "authDesc";
        }

        return null;
    }

    public static string DescribeMissingChunk(SignedUrlChunk chunk)
    {
        var oid = chunk.EdgeHeaders?.ObjectId ?? "?";
        var range = chunk.ByteRange is { } r ? $"{r.Start}-{r.End}" : "?";
        var len = chunk.ByteRange is { } br ? br.End - br.Start + 1 : -1;
        var kind = len is 112 or 155 or 224 or 310 or 464 or 480 ? "ford?" : "data";
        return $"{kind}:{oid}:{range}({len}B)";
    }

    private static string SanitizeOidToken(string oid)
    {
        if (string.IsNullOrEmpty(oid))
            return "unknown";
        return oid.Replace('-', '_').Replace('/', '_');
    }

    // #region agent log
    private static int _pendingLifecycleLogCount;
    private static int _releaseDiagCount;

    private void AgentPendingLifecycleLog(string message, object data)
    {
        try
        {
            var n = Interlocked.Increment(ref _pendingLifecycleLogCount);
            if (n > 80 && n % 15 != 0)
                return;
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession",
                ["message"] = message,
                ["hypothesisId"] = "H-PENDING",
                ["runId"] = "pending-lifecycle-v1",
                ["data"] = data,
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch { /* ignore */ }
    }

    private void AgentReleaseDiag(
        string message,
        int chunkN,
        int pendingHold,
        int emptySkip,
        int removeMiss,
        int removed,
        long bytesBefore,
        long bytesAfter)
    {
        try
        {
            var n = Interlocked.Increment(ref _releaseDiagCount);
            // Sempre i primi 60 + ogni 20 + quando pending blocca o 0 remove con chunk dati.
            if (n > 60 && n % 20 != 0 && pendingHold == 0 && !(removed == 0 && chunkN > 0))
                return;
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "MmcsChunkAssemblySession.ReleaseDataChunksForAsset",
                ["message"] = message,
                ["hypothesisId"] = "H-RAM-REL",
                ["runId"] = "ram-release-v1",
                ["data"] = new
                {
                    n,
                    chunkN,
                    pendingHold,
                    emptySkip,
                    removeMiss,
                    removed,
                    pendingFiles = _pending.Count,
                    retainDepth = Volatile.Read(ref _dataReleaseSuppressDepth),
                    storeEntries = _store.EntryCount,
                    mbBefore = bytesBefore / (1024 * 1024),
                    mbAfter = bytesAfter / (1024 * 1024),
                    mbFreed = (bytesBefore - bytesAfter) / (1024 * 1024),
                    gcMb = GC.GetTotalMemory(false) / (1024 * 1024),
                    wsMb = Environment.WorkingSet / (1024 * 1024),
                },
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch { /* ignore */ }
    }
    // #endregion
}
