using System.Collections.Concurrent;
using System.IO;
using System.Threading.Channels;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.Download;

/// <summary>
/// Job decrypt MMCS/Ford post-download — eseguito da worker pool in parallelo al download.
/// <see cref="PrebuiltCompact"/> è mutabile: dopo FillChunks lo azzera (cipher transient).
/// </summary>
public sealed class BackupDecryptJob
{
    public BackupDecryptJob(
        BackupAsset asset,
        byte[] authResponseBody,
        IReadOnlyList<SignedUrlChunk> chunks,
        int assetIndex,
        int assetTotal,
        byte[]? prebuiltCompact,
        BackupDecryptJobContext context)
    {
        Asset = asset;
        AuthResponseBody = authResponseBody;
        Chunks = chunks;
        AssetIndex = assetIndex;
        AssetTotal = assetTotal;
        PrebuiltCompact = prebuiltCompact;
        Context = context;
    }

    public BackupAsset Asset { get; }
    public byte[] AuthResponseBody { get; }
    public IReadOnlyList<SignedUrlChunk> Chunks { get; }
    public int AssetIndex { get; }
    public int AssetTotal { get; }
    /// <summary>Cipher assemblato — null dopo decrypt ( body non pinned).</summary>
    public byte[]? PrebuiltCompact { get; set; }
    public BackupDecryptJobContext Context { get; }
}

/// <summary>Contesto condiviso (thread-safe dove indicato) tra job decrypt.</summary>
public sealed class BackupDecryptJobContext
{
    public required ICloudSession Session { get; init; }
    public required string SnapshotDirectory { get; init; }
    public required string OutputRoot { get; init; }
    public required BackupFilesystemWriter FsWriter { get; init; }
    public required BackupFileKeyContext FileKeyCtx { get; init; }
    public required ConcurrentDictionary<string, (byte[] Compact, long MmcsStart)> SiblingCompacts { get; init; }
    public MmcsChunkAssemblySession? MmcsSession { get; init; }
    public IProgress<DownloadProgressReport>? Progress { get; init; }
    public IProgress<string>? Log { get; init; }
    public required BackupDownloadService Service { get; init; }
}

/// <summary>
/// Producer/consumer stile iTunes FillChunks: con FillAwait il GET AG attende il decrypt
/// del batch (unità = file/storage). Coda corta ≈ worker pool — no multi-AG compact backlog.
/// </summary>
public sealed class BackupDecryptWorkerQueue : IAsyncDisposable
{
    /// <summary>QThread FillChunks ≈ 8. Env <c>IKE_DECRYPT_WORKERS</c> 4–32.</summary>
    public const int DefaultParallelism = 8;

    /// <summary>
    /// ≈ parallelism (picco concurrent compact). Evidence: 96–240 + overlap → WS multi-GB.
    /// Env <c>IKE_DECRYPT_CAPACITY</c> 8–96.
    /// </summary>
    public const int DefaultCapacity = 24;

    /// <summary>Oltre questa soglia il compact non entra in coda: decrypt sync (PDF/app grandi).</summary>
    public const int LargeCompactSyncBytes = 2 * 1024 * 1024;

    private readonly Channel<QueuedWork> _channel;
    private readonly Task[] _workers;
    private readonly CancellationToken _shutdown;
    private int _inFlight;

    private sealed record QueuedWork(
        BackupDecryptJob Job,
        TaskCompletionSource<AssetDownloadOutcome> Completion);

    public BackupDecryptWorkerQueue(
        Func<BackupDecryptJob, CancellationToken, Task<AssetDownloadOutcome>> worker,
        CancellationToken shutdown,
        int parallelism = DefaultParallelism,
        int capacity = DefaultCapacity)
    {
        _shutdown = shutdown;
        _channel = Channel.CreateBounded<QueuedWork>(new BoundedChannelOptions(
            Math.Max(parallelism, capacity))
        {
            SingleReader = false,
            SingleWriter = false,
            FullMode = BoundedChannelFullMode.Wait,
        });

        _workers = new Task[Math.Max(1, parallelism)];
        for (var i = 0; i < _workers.Length; i++)
            _workers[i] = RunWorkerAsync(worker, i);
    }

    public int InFlight => Volatile.Read(ref _inFlight);
    public int QueuedCount => _channel.Reader.Count;

    // #region agent log
    private static int _schedSampleN;
    private static int _jobSampleN;
    // #endregion

    /// <summary>
    /// Attende uno slot in coda (backpressure), poi restituisce il task del decrypt.
    /// </summary>
    public async Task<Task<AssetDownloadOutcome>> ScheduleAsync(
        BackupDecryptJob job,
        CancellationToken ct = default)
    {
        var tcs = new TaskCompletionSource<AssetDownloadOutcome>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        using (ct.Register(() => tcs.TrySetCanceled(ct)))
        {
            // #region agent log
            var qBefore = _channel.Reader.Count;
            var inflBefore = Volatile.Read(ref _inFlight);
            var sw = Environment.TickCount64;
            // #endregion
            await _channel.Writer.WriteAsync(new QueuedWork(job, tcs), ct).ConfigureAwait(false);
            // #region agent log
            var waitMs = Environment.TickCount64 - sw;
            var n = Interlocked.Increment(ref _schedSampleN);
            if (waitMs >= 50 || n <= 8 || n % 25 == 0)
            {
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "BackupDecryptWorkerQueue.ScheduleAsync",
                        ["message"] = "decrypt_schedule_wait",
                        ["hypothesisId"] = "H-Q1",
                        ["runId"] = "queue-opt-v1",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["waitMs"] = waitMs,
                            ["qBefore"] = qBefore,
                            ["inFlightBefore"] = inflBefore,
                            ["qAfter"] = _channel.Reader.Count,
                            ["inFlightAfter"] = Volatile.Read(ref _inFlight),
                            ["capacity"] = DefaultCapacity,
                            ["workers"] = _workers.Length,
                            ["compact"] = job.PrebuiltCompact?.Length ?? 0,
                            ["saturated"] = waitMs >= 50 || qBefore >= DefaultCapacity - 2,
                        },
                    });
                    File.AppendAllText(
                        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                        line + Environment.NewLine);
                }
                catch
                {
                    // ignore
                }
            }
            // #endregion
        }

        return tcs.Task;
    }

    public async Task WhenIdleAsync(CancellationToken ct = default)
    {
        while (InFlight > 0 || _channel.Reader.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(50, ct).ConfigureAwait(false);
        }
    }

    public async ValueTask DisposeAsync()
    {
        _channel.Writer.TryComplete();
        try
        {
            await Task.WhenAll(_workers).ConfigureAwait(false);
        }
        catch
        {
            // shutdown
        }
    }

    private async Task RunWorkerAsync(
        Func<BackupDecryptJob, CancellationToken, Task<AssetDownloadOutcome>> worker,
        int workerId)
    {
        await foreach (var item in _channel.Reader.ReadAllAsync(_shutdown).ConfigureAwait(false))
        {
            Interlocked.Increment(ref _inFlight);
            try
            {
                // #region agent log
                var jobSw = Environment.TickCount64;
                var qAtStart = _channel.Reader.Count;
                // #endregion
                var outcome = await worker(item.Job, _shutdown).ConfigureAwait(false);
                // #region agent log
                var jobMs = Environment.TickCount64 - jobSw;
                var compactWas = item.Job.PrebuiltCompact?.Length ?? 0;
                var jn = Interlocked.Increment(ref _jobSampleN);
                if (jobMs >= 500 || jn <= 8 || jn % 20 == 0
                    || compactWas >= 1_000_000)
                {
                    try
                    {
                        var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "7dabb5",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["location"] = "BackupDecryptWorkerQueue.RunWorkerAsync",
                            ["message"] = "decrypt_job_done",
                            ["hypothesisId"] = "H-RAM-IKE4",
                            ["runId"] = "ike-ram-4pt-v1",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["workerId"] = workerId,
                                ["jobMs"] = jobMs,
                                ["ok"] = outcome.Ok,
                                ["compactWas"] = compactWas,
                                ["qAtStart"] = qAtStart,
                                ["qAfter"] = _channel.Reader.Count,
                                ["inFlight"] = Volatile.Read(ref _inFlight),
                                ["sizeBytes"] = item.Job.Asset.SizeBytes ?? 0,
                                ["wsMb"] = Environment.WorkingSet / (1024 * 1024),
                            },
                        });
                        File.AppendAllText(
                            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                            line + Environment.NewLine);
                    }
                    catch
                    {
                        // ignore
                    }
                }
                // #endregion
                item.Completion.TrySetResult(outcome);
            }
            catch (OperationCanceledException)
            {
                item.Completion.TrySetCanceled(_shutdown);
            }
            catch (OutOfMemoryException ex)
            {
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "BackupDecryptWorkerQueue",
                        ["message"] = "worker_oom",
                        ["hypothesisId"] = "H-OOM2",
                        ["runId"] = "oom-v2",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["workerId"] = workerId,
                            ["path"] = item.Job.Asset.RelativePath ?? item.Job.Asset.RecordName,
                            ["compact"] = item.Job.PrebuiltCompact?.Length ?? 0,
                            ["queued"] = _channel.Reader.Count,
                            ["inFlight"] = Volatile.Read(ref _inFlight),
                            ["gcMb"] = GC.GetTotalMemory(false) / (1024 * 1024),
                            ["wsMb"] = Environment.WorkingSet / (1024 * 1024),
                            ["err"] = ex.Message,
                        },
                    });
                    File.AppendAllText(
                        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                        line + Environment.NewLine);
                }
                catch
                {
                    // ignore
                }
                // #endregion
                item.Completion.TrySetException(ex);
                // Liberare LOH: dopo OOM il processo è instabile; forzare raccolta.
                try { GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true); }
                catch { /* ignore */ }
            }
            catch (Exception ex)
            {
                item.Completion.TrySetException(ex);
            }
            finally
            {
                // point 4: cipher transient — sempre drop pin (ok / fail / OOM).
                item.Job.PrebuiltCompact = null;
                Interlocked.Decrement(ref _inFlight);
            }
        }
    }
}

/// <summary>Risultato batch flist: outcome immediati + task decrypt async.</summary>
public sealed record FlistBatchRunResult(
    IReadOnlyList<AssetDownloadOutcome> Outcomes,
    IReadOnlyList<Task<AssetDownloadOutcome>> DecryptTasks,
    /// <summary>Fasi ms del batch AG (auth→edge→assemble→fill). Null se fallback.</summary>
    AgBatchPhaseTiming? Phases = null);

/// <summary>Breakdown timing di un authorizeGet×N + edge + FillChunks.</summary>
public sealed record AgBatchPhaseTiming(
    long AuthMs,
    long EmptyHostMs,
    long PartsMs,
    long AssembleMs,
    long FillMs,
    int DecryptN,
    int BatchFiles);

/// <summary>Esito singolo asset (download/decrypt pipeline).</summary>
public readonly record struct AssetDownloadOutcome(
    bool Ok,
    long DownloadedBytes,
    bool WrittenSharded,
    bool StagedChunks,
    bool MmcsDecrypted,
    bool FileDecrypted,
    bool PendingChunks = false,
    bool QueuedDecrypt = false,
    /// <summary>
    /// True se Scaricati/Decifrati/Falliti sono già stati aggiornati da
    /// <c>RunDecryptJobAsync</c> (evita doppio <c>batch_fail</c> dopo FillChunks).
    /// </summary>
    bool CountersApplied = false)
{
    public static AssetDownloadOutcome Failed { get; } = new(false, 0, false, false, false, false);
    public static AssetDownloadOutcome Pending { get; } = new(false, 0, false, true, false, false, true);
    public static AssetDownloadOutcome Queued { get; } = new(false, 0, false, false, false, false, false, true);
}
