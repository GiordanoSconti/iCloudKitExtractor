using System.Buffers.Binary;
using System.Collections.Concurrent;
using System.IO;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Download;

public sealed class BackupDownloadService
{
    /// <summary>LaunchThreads = 8 workers (cmp ebp, 8). Override via edge only.</summary>
    internal const int BackupEdgeDownloadParallelism = 8;

    /// <summary>
    /// Cap globale sui GET edge (tutti i domain). Senza questo, domainParallel×edgeParallel
    /// arriva a 64 GET concorrenti → URL scaduti (403) e compact sbagliati.
    /// </summary>
    private static readonly SemaphoreSlim GlobalEdgeDownloadGate =
        new(BackupEdgeDownloadParallelism, BackupEdgeDownloadParallelism);

    private static int _edgeInFlight;

    /// <summary>
    /// Pipeline authorizeGet→edge concorrenti. Slot detenuto solo per AG+prefetch
    /// (URL consumate subito; GlobalEdgeDownloadGate resta 8). tiene i worker
    /// download saturi mentre FillChunks gira altrove — default 1 serializzava i domain.
    /// Override: <c>IKE_EDGE_AUTH_PIPELINE</c> (1–8). Default 4.
    /// </summary>
    internal const int DefaultEdgeAuthPipelineSlots = 4;

    private static SemaphoreSlim? _edgeAuthDownloadPipeline;

    private static SemaphoreSlim GetEdgeAuthDownloadPipeline()
    {
        if (_edgeAuthDownloadPipeline is not null)
            return _edgeAuthDownloadPipeline;
        var slots = ResolveEdgeAuthPipelineSlots();
        var created = new SemaphoreSlim(slots, slots);
        if (Interlocked.CompareExchange(ref _edgeAuthDownloadPipeline, created, null) is not null)
            created.Dispose();
        return _edgeAuthDownloadPipeline!;
    }

    /// <summary>
    /// authorizeGet wire batch = 12 files (mitm 00262/00264).
    /// Mega-AG sull'intero FL-slice (fino a migliaia) collassa il throughput edge.
    /// </summary>
    internal const int AuthorizeGetBatchSize = 12;

    /// <summary>
    /// Domain in parallelo stile LaunchThreads=8.
    /// Override: <c>IKE_DOMAIN_PARALLELISM</c> (1–8).
    /// </summary>
    internal const int DefaultDomainParallelism = 8;

    /// <summary>
    /// Copie da snapshot/cache precedenti in parallelo (File.Copy).
    /// Override: <c>IKE_CLONE_PARALLELISM</c> (1–16). Default 8.
    /// </summary>
    internal const int DefaultCloneParallelism = 8;

    private readonly HttpClient _http;
    private readonly CloudKitAssetService _assets;
    private readonly CloudKitAssetService.SessionRefreshDelegate? _refreshSession;
    /// <summary>pref4 device corrente — seed owned BA <c>A:pref4:rid</c> (UUID → NOT_FOUND).</summary>
    private string? _activeDevicePrefix4;
    private List<(byte[] Master, string Source)>? _cachedMmcsMasters;
    /// <summary>Pool seed+nested dopo la prima harvest zone (riuso per asset successivi).</summary>
    private List<PcsCompactPrivateKey>? _cachedMmcsBootPool;
    /// <summary>Zone bootstrap già unwrapped per ViaShare (niente re-Absorb × asset).</summary>
    private List<ProtectionZoneKeys>? _cachedShareBootstrapZones;
    private readonly object _mmcsMastersGate = new();
    private int _mmcsKekOkLog;
    private int _mmcsKekFailLog;
    /// <summary>
    /// Scope per-FL: ogni ProcessOneDomainAsync crea la propria sessione MMCS.
    /// AsyncLocal evita race con domainParallelism&gt;1 sul campo globale.
    /// </summary>
    private static readonly AsyncLocal<MmcsChunkAssemblySession?> _mmcsSessionLocal = new();
    private MmcsChunkAssemblySession? _mmcsChunkSessionStore;

    /// <summary>Sessione attiva (per-FL se in scope, altrimenti store di chiusura snapshot).</summary>
    private MmcsChunkAssemblySession? _mmcsChunkSession
    {
        get => _mmcsSessionLocal.Value ?? _mmcsChunkSessionStore;
        set
        {
            if (_mmcsSessionLocal.Value is not null)
                _mmcsSessionLocal.Value = value;
            else
                _mmcsChunkSessionStore = value;
        }
    }

    private BackupDecryptWorkerQueue? _decryptQueue;
    private readonly object _pendingDecryptLock = new();
    private readonly List<(BackupAsset Asset, Task<AssetDownloadOutcome> Task)> _pendingDecryptTasks = [];
    private int _uiFilesDownloaded;
    private int _uiFilesDecrypted;
    private int _uiFilesDecryptFailed;
    /// <summary>
    /// File materializzati in Backup/ ancora ciphertext (no file-AES) — sottoinsieme di
    /// Decifrati (parity incompleta) oppure Falliti con body CIFRATO salvato.
    /// </summary>
    private int _uiFilesCiphertextSaved;
    private int _uiFilesDuplicated;
    /// <summary>Job decrypt schedulati non ancora terminati (coda UI live).</summary>
    private int _uiDecryptPending;
    private int _uiFilesTotal;
    /// <summary>Etichetta snapshot corrente (catena UI).</summary>
    private string? _uiSnapshotLabel;
    /// <summary>Byte materializzati per progress Dati (MMCS/edge + copie cloni accreditate).</summary>
    private long _uiBytesDownloaded;
    /// <summary>Stima byte totali Dati (già include la dimensione snapshot / needDownload).</summary>
    private long _uiBytesTotal;
    /// <summary>
    /// Cap opzionale barra Dati. Tenuto a 0: il totale non va gonfiato con i cloni
    /// (SizeBytes cloni già contati nel totale dichiarato).
    /// </summary>
    private long _uiBytesSnapshotDeclared;
    // #region agent log
    private static int _bytesCreditSampleN;
    private int _bytesDownloadPlanLogN;
    private int _bytesProgressUiLogN;
    // #endregion
    /// <summary>Seq monotona per ReportFilesDoneProgress (anti-stale UI).</summary>
    private long _progressReportSeq;
    /// <summary>Log download corrente (per ERROR su Falliti anche da worker async).</summary>
    private IProgress<string>? _downloadLog;

    /// <summary>
    /// Ford host bodies scaricati da fresh authorizeGet (anche se IKM iniziale non apre).
    /// Sopravvive al purge MMCS store — riusati se lo stesso wrap ricompare in payload.
    /// Key = assetSignature hex (o path).
    /// </summary>
    private readonly ConcurrentDictionary<string, List<(string Oid, long Start, byte[] Body)>> _freshAgFordBodies =
        new(StringComparer.Ordinal);

    /// <summary>
    /// H-ORDER: asset no-ford in attesa di pack OID successivi (retry assemble).
    /// </summary>
    private readonly ConcurrentDictionary<string, OidOrderRetry> _oidOrderRetries =
        new(StringComparer.OrdinalIgnoreCase);

    private sealed record OidOrderRetry(
        ICloudSession Session,
        BackupAsset Asset,
        string OutputFile,
        byte[] AuthBody,
        IReadOnlyList<SignedUrlChunk> Chunks,
        string? WorkDirectory,
        int AssetIndex,
        int AssetTotal,
        IProgress<DownloadProgressReport>? Progress,
        int Attempts);

    internal static int ResolveDomainParallelism()
    {
        var env = Environment.GetEnvironmentVariable("IKE_DOMAIN_PARALLELISM");
        if (int.TryParse(env, out var n) && n >= 1 && n <= 8)
            return n;
        return DefaultDomainParallelism;
    }

    internal static int ResolveEdgeAuthPipelineSlots()
    {
        var env = Environment.GetEnvironmentVariable("IKE_EDGE_AUTH_PIPELINE");
        if (int.TryParse(env, out var n) && n >= 1 && n <= 8)
            return n;
        return DefaultEdgeAuthPipelineSlots;
    }

    /// <summary>
    /// Worker Ford/chunk decrypt (non GET edge). Default 8 (pool); env <c>IKE_DECRYPT_WORKERS</c> 4–32.
    /// </summary>
    internal static int ResolveDecryptWorkerParallelism()
    {
        var env = Environment.GetEnvironmentVariable("IKE_DECRYPT_WORKERS");
        if (int.TryParse(env, out var n) && n is >= 4 and <= 32)
            return n;
        return BackupDecryptWorkerQueue.DefaultParallelism;
    }

    /// <summary>
    /// Coda decrypt (compact pinned). Default 24; env <c>IKE_DECRYPT_CAPACITY</c> 8–96.
    /// Con FillAwait ≈ worker×3 — no multi-AG backlog.
    /// </summary>
    internal static int ResolveDecryptQueueCapacity()
    {
        var env = Environment.GetEnvironmentVariable("IKE_DECRYPT_CAPACITY");
        if (int.TryParse(env, out var n) && n is >= 8 and <= 96)
            return n;
        return BackupDecryptWorkerQueue.DefaultCapacity;
    }

    /// <summary>
    ///  FillChunks completa il batch AG prima del prossimo (await decrypt).
    /// Disattiva overlap anti-overlap con <c>IKE_FILL_AWAIT=0</c>.
    /// </summary>
    internal static bool ResolveFillAwait()
    {
        var env = Environment.GetEnvironmentVariable("IKE_FILL_AWAIT");
        if (string.IsNullOrWhiteSpace(env))
            return true;
        return env is not ("0" or "false" or "False" or "FALSE" or "off" or "OFF" or "no" or "NO");
    }

    internal static int ResolveCloneParallelism()
    {
        var env = Environment.GetEnvironmentVariable("IKE_CLONE_PARALLELISM");
        if (int.TryParse(env, out var n) && n >= 1 && n <= 16)
            return n;
        return DefaultCloneParallelism;
    }

    public BackupDownloadService(HttpClient http)
        : this(http, null)
    {
    }

    public BackupDownloadService(
        HttpClient http,
        CloudKitAssetService.SessionRefreshDelegate? refreshSession)
    {
        _http = http;
        _assets = new CloudKitAssetService(http);
        _refreshSession = refreshSession;
        _assets.SetSessionRefresh(refreshSession);
    }

    public async Task DownloadSnapshotAsync(
        ICloudSession session,
        DownloadJob job,
        IProgress<DownloadProgressReport>? progress = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(job.OutputDirectory);
        var snapshotRoot = job.OutputDirectory;
        var workDir = IkeBackupOutputPaths.ResolveTmpDirectory(snapshotRoot);
        Directory.CreateDirectory(workDir);
        // #region agent log
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "BackupDownloadService.DownloadSnapshotAsync",
                ["message"] = "snapshot_tmp_created",
                ["hypothesisId"] = "H-TMP-LAYOUT",
                ["runId"] = "tmp-layout-v1",
                ["data"] = new
                {
                    snapshotRoot,
                    workDir,
                    backupDir = IkeBackupOutputPaths.ResolveCleanBackupDirectory(snapshotRoot),
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
        var contentHost = $"https://{session.Partition}-content.icloud.com";
        _downloadLog = log;
        _cachedMmcsMasters = null;
        _cachedMmcsBootPool = null;
        _cachedShareBootstrapZones = null;
        _mmcsKekOkLog = 0;
        _mmcsKekFailLog = 0;
        _pendingDecryptTasks.Clear();
        _uiFilesDownloaded = 0;
        _uiFilesDecrypted = 0;
        _uiFilesDecryptFailed = 0;
        _uiFilesCiphertextSaved = 0;
        _uiFilesDuplicated = 0;
        _uiDecryptPending = 0;
        _progressReportSeq = 0;
        _bytesDownloadPlanLogN = 0;
        _bytesProgressUiLogN = 0;
        _cloneCountUiLogN = 0;
        _uiFilesTotal = 0;
        _uiBytesDownloaded = 0;
        // Barra Dati: totale già dichiarato (no doppio conteggio cloni); i cloni
        // accreditano solo i byte fatti. Catalog Snapshot.SizeBytes = diagnostica.
        var catalogSnapBytes = job.Snapshot.SizeBytes is > 0 ? job.Snapshot.SizeBytes.Value : 0L;
        _uiBytesSnapshotDeclared = 0;
        _uiBytesTotal = 0;
        _uiSnapshotLabel = string.IsNullOrWhiteSpace(job.ChainLabel)
            ? $"{job.Snapshot.DateLabel} · {job.Snapshot.ShortUuid}"
            : job.ChainLabel;
        // #region agent log
        AgentCountAlways("bytes_total_init", new
        {
            catalogSnapBytes,
            snapshotSize = _uiBytesSnapshotDeclared,
            snapshotId = job.Snapshot.BackupUuid ?? job.Snapshot.RecordName,
            snapshotLabel = _uiSnapshotLabel,
            hypothesis = "H-BYTES-SNAP",
            runId = "bytes-clone-excl-v1",
        });
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "b3df71",
                ["runId"] = "bytes-clone-excl-v1",
                ["hypothesisId"] = "H2",
                ["location"] = "BackupDownloadService.DownloadSnapshotAsync:init",
                ["message"] = "bytes_total_init_download_only",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new
                {
                    catalogSnapBytes,
                    uiBytesTotal = _uiBytesTotal,
                    snapshotCap = _uiBytesSnapshotDeclared,
                    snapshotLabel = _uiSnapshotLabel,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
        _assets.ResetAnisetteRefreshCircuit();
        if (_decryptQueue is not null)
            await _decryptQueue.DisposeAsync().ConfigureAwait(false);
        _decryptQueue = new BackupDecryptWorkerQueue(
            RunDecryptJobAsync,
            ct,
            parallelism: ResolveDecryptWorkerParallelism(),
            //  coda corta = capacity env/default (24). NON domain×AG12 (quello era
            // overlap multi-AG → WS multi-GB).
            capacity: ResolveDecryptQueueCapacity());

        try
        {
        // ASSET_DECRYPT §1: escrow → PCS KeySet PRIMA di CloudKit Lock/N:/MMCS.
        progress?.Report(new DownloadProgressReport { Status = "Escrow / PCS KeySet…" });
        await EnsureEscrowKeySetBeforeRestoreAsync(session, job, log, ct);
        log?.Report(
            PcsSessionSeedKeys.HasAny(session)
                ? $"PCS seed: escrow={session.PcsEscrowedKeySet?.Length ?? 0} B, " +
                  $"manatee={session.PcsManateeCompactKeys?.Count ?? 0} — prima del restore CloudKit"
                : "PCS seed: assente — zone masters / keybag / MMCS KEK limitati");

        // Wire: zones → D:/S: → K: unlock → Lock → N: (niente authorizeGet anticipato).
        progress?.Report(new DownloadProgressReport { Status = "Preparazione restore…" });
        await _assets.PrepareDownloadAsync(
            session,
            job.Device,
            job.Snapshot,
            log,
            _refreshSession,
            ct,
            workDir).ConfigureAwait(false);

        // Unlock già tentato in Prepare se KeySet+K: presenti; ripeti solo se keybag arrivati dopo.
        if (PcsSessionSeedKeys.HasAny(session)
            && (job.Device.KeybagRawPayloads.Count > 0 || job.Device.KeybagDataBlobs.Count > 0)
            && !Directory.EnumerateFiles(workDir, "keybag_tlv_*.bin").Any()
            && !Directory.EnumerateFiles(workDir, "keybag_key_*.bin").Any()
            && !File.Exists(Path.Combine(workDir, BackupKeybagPcsUnlock.DecryptedFileName)))
        {
            progress?.Report(new DownloadProgressReport { Status = "Unlock Keybag PCS…" });
            var kbUnlock = await _assets.UnlockKeybagsWithPcsAsync(
                session, job.Device, workDir, log, ct);
            await _assets.EnsureZoneMastersCachedAsync(
                session, workDir, session.PcsKeysDirectory, log, ct);
            log?.Report(
                kbUnlock.Success
                    ? $"Keybag PCS: {kbUnlock.Message}"
                    : $"Keybag PCS: {kbUnlock.Message}");
        }

        await _assets.SaveKeybagsAsync(job.Device, workDir, ct);
        log?.Report(
            $"Keybags salvati → {Path.Combine(workDir, "keybags.json")}");

        // Catalogo deterministico: moderno S:→:CN: oppure classico S:→M:→files.
        progress?.Report(new DownloadProgressReport { Status = "Catalogo S:→:CN:/M:…" });
        log?.Report("Catalogo deterministico: S: → :CN: (moderno) oppure M:→files (classico)…");
        var catalogService = new BackupDeterministicCatalogService(_http);
        var catalog = await catalogService.ResolveAsync(
            session,
            job.Snapshot,
            workDir,
            _assets.CurrentRestoreState,
            log,
            ct);

        await LocalBackupManifestWriter.WriteAsync(
            workDir, job.Device, job.Snapshot, catalog, ct);
        log?.Report(
            $"Catalogo {catalog.FileRecordNames.Count:N0} " +
            $"(source={catalog.Source}, M:={catalog.ManifestIds.Count}, :CN:={catalog.CnEntryCount}) " +
            $"→ tmp={workDir}; skeleton Manifest.db → Backup/");

        EnFetchResult? enFetch = _assets.LastEnFetch;
        if (enFetch is null
            && catalog.Source.StartsWith("modern", StringComparison.OrdinalIgnoreCase)
            && catalog.CnEntryCount > 0)
        {
            progress?.Report(new DownloadProgressReport { Status = "EN: file list post-Lock…" });
            var enNames = BackupEnRecordService.BuildEnRecordNamesFromCatalogNames(
                catalog.FileRecordNames);
            // Limite test: MaxAssets sul numero di EN richiesti.
            if (job.MaxAssets is int maxEn and > 0 && enNames.Count > maxEn)
                enNames = enNames.Take(maxEn).ToList();

            var enService = new BackupEnRecordService(_http);
            enFetch = await enService.FetchAsync(
                session,
                enNames,
                workDir,
                _assets.CurrentRestoreState,
                BackupEnRecordService.FirstBatchSize,
                BackupEnRecordService.SubsequentBatchSize,
                log,
                ct,
                _assets.BootstrapZonesPayload).ConfigureAwait(false);
        }
        else if (enFetch is not null)
        {
            log?.Report(
                $"N: riusato da PrepareDownload (auth={enFetch.MmcsAuthHeaders.Count}, " +
                $"signed={enFetch.SignedChunks.Count}, flist={enFetch.FlistEntries.Count})");
        }

        if (enFetch is { FlistEntries.Count: > 0 })
        {
            await File.WriteAllTextAsync(
                Path.Combine(workDir, "flist_entries.json"),
                JsonSerializer.Serialize(
                    enFetch.FlistEntries.Select(static e => new
                    {
                        e.Domain,
                        e.RelativePath,
                        e.AssetRecordName,
                        e.RecordIdSuffix,
                        e.AssetSize,
                        e.ProtectionClass
                    }),
                    new JsonSerializerOptions { WriteIndented = true }),
                ct);
        }

        if (job.ManifestOnly)
        {
            await WriteItunesSidecarsAtEndOfSnapshotAsync(
                session, job, log, ct).ConfigureAwait(false);
            progress?.Report(new DownloadProgressReport
            {
                Status = $"Catalogo Manifest OK ({catalog.FileRecordNames.Count:N0} file, {catalog.Source}" +
                         (enFetch is null ? "" : $", EN auth={enFetch.MmcsAuthHeaders.Count}") + ")",
                AssetsCompleted = 1,
                AssetsTotal = 1
            });
            return;
        }

        // Auth MMCS: preferisci EN: (flusso post-Lock); fallback PreAuth/query KA:MA.
        //  niente PrivilegedBatch di massa prima del download — FL poi KA/LA/MA interleaved.
        progress?.Report(new DownloadProgressReport { Status = "Risoluzione auth MMCS…" });
        var assets = await ResolveAssetsForCatalogAsync(
            session, job, catalog, log, ct, enFetch);

        var isModernCn = string.Equals(
            catalog.Source, "modern-CN", StringComparison.OrdinalIgnoreCase);
        var kalamaSeeds = enFetch is not null
            ? CollectKaLaMaSeeds(enFetch, job.Device)
            : [];

        if (assets.Count == 0 && kalamaSeeds.Count == 0)
        {
            throw new InvalidOperationException(
                $"Catalogo OK ({catalog.FileRecordNames.Count:N0} file, {catalog.Source}), " +
                "ma nessun MMCS auth risolto (PreAuth / query KA:MA / fetch contents).");
        }

        await WriteManifestAsync(job, assets, ct);

        var flAssets = assets
            .Where(static a => a.RecordName.StartsWith("FL:", StringComparison.Ordinal))
            .ToList();
        var readyAssets = assets
            .Where(static a => !a.RecordName.StartsWith("FL:", StringComparison.Ordinal))
            .ToList();

        // Totale barre UI = solo file destinati a Backup/ (path regolari con contenuto).
        // Mai i fileList (FL:), né il conteggio grezzo di tutti gli asset CK.
        var estimatedTotal = isModernCn
            ? 0
            : readyAssets.Count(static a => a.HasFilesystemIdentity);
        if (job.MaxAssets is int maxEst and > 0 && !isModernCn)
            estimatedTotal = Math.Min(estimatedTotal, maxEst);
        var catalogAssets = 0;
        var backupBoundPlanned = 0;

        log?.Report(
            isModernCn
                ? $"Download: FL={flAssets.Count}, EN-auth={readyAssets.Count}, " +
                  $"KA/LA/MA seed={kalamaSeeds.Count} (catalogo {catalog.Source}; " +
                  "download solo asset in fileList)"
                : $"Download: {assets.Count} asset con auth (catalogo {catalog.Source})");

        var cleanDir = IkeBackupOutputPaths.ResolveCleanBackupDirectory(snapshotRoot);
        Directory.CreateDirectory(cleanDir);
        if (FordOfflineDumpWriter.Enabled)
            Directory.CreateDirectory(FordOfflineDumpWriter.ResolveRoot(workDir));
        if (IkeOraclePairDumpWriter.Enabled)
        {
            var oracleRoot = Path.Combine(workDir, IkeOraclePairDumpWriter.FolderName);
            IkeOraclePairDumpWriter.SetRoot(oracleRoot);
            Directory.CreateDirectory(oracleRoot);
        }

        log?.Report(
            $"Layout: root={snapshotRoot} | tmp={workDir} | Backup={cleanDir}" +
            (FordOfflineDumpWriter.Enabled
                ? $" | Ford offline={FordOfflineDumpWriter.ResolveRoot(workDir)}"
                : " | Ford offline=off") +
            (IkeOraclePairDumpWriter.Enabled
                ? $" | oracle dump={IkeOraclePairDumpWriter.ResolveRoot()}"
                : " | oracle dump=off"));
        log?.Report(
            $"Perf: decryptWorkers={ResolveDecryptWorkerParallelism()} " +
            $"capacity={ResolveDecryptQueueCapacity()} " +
            $"fillAwait={(ResolveFillAwait() ? "on" : "off")} " +
            $"edgeParallel={BackupEdgeDownloadParallelism} " +
            $"domainParallel={ResolveDomainParallelism()} " +
            $"authPipeline={ResolveEdgeAuthPipelineSlots()} " +
            $"cloneParallel={ResolveCloneParallelism()} " +
            $"fordShapeFallback={((string.Equals(Environment.GetEnvironmentVariable("IKE_FORD_SHAPE_FALLBACK"), "1", StringComparison.Ordinal) || string.Equals(Environment.GetEnvironmentVariable("IKE_FORD_SHAPE_FALLBACK"), "true", StringComparison.OrdinalIgnoreCase) || string.Equals(Environment.GetEnvironmentVariable("IKE_FORD_SHAPE_FALLBACK"), "on", StringComparison.OrdinalIgnoreCase)) ? "on" : "off")} " +
            $"agentDiag={(string.Equals(Environment.GetEnvironmentVariable("IKE_AGENT_DIAG"), "1", StringComparison.Ordinal) ? "on" : "off")}");
        // #region agent log
        AgentFlEdgeDebugLog(
            "BackupDownloadService.DownloadSnapshotAsync",
            "perf_settings",
            new
            {
                decryptWorkers = ResolveDecryptWorkerParallelism(),
                decryptCapacity = ResolveDecryptQueueCapacity(),
                edgeParallel = BackupEdgeDownloadParallelism,
                domainParallel = ResolveDomainParallelism(),
                fordOfflineDump = FordOfflineDumpWriter.Enabled,
                fordShapeFallback = string.Equals(
                                         Environment.GetEnvironmentVariable("IKE_FORD_SHAPE_FALLBACK"),
                                         "1",
                                         StringComparison.Ordinal)
                                     || string.Equals(
                                         Environment.GetEnvironmentVariable("IKE_FORD_SHAPE_FALLBACK"),
                                         "true",
                                         StringComparison.OrdinalIgnoreCase)
                                     || string.Equals(
                                         Environment.GetEnvironmentVariable("IKE_FORD_SHAPE_FALLBACK"),
                                         "on",
                                         StringComparison.OrdinalIgnoreCase),
                ikmGate = "asset-unwrapped-only",
                aesSkip = "modern-bag-or-asset-uw",
                privilegedBatchPaceDefault = 0,
                privilegedBatchChunkSize = 12,
                authorizeGetBatchSize = AuthorizeGetBatchSize,
                waveSeedCap = 144,
                midFlFinalize = "coalesced-nonblocking",
            },
            "H-PERF");
        // #endregion
        // #region agent log
        AgentCountAlways("perf_settings_always", new
        {
            edgeParallel = BackupEdgeDownloadParallelism,
            domainParallel = ResolveDomainParallelism(),
            launchThreads = 8,
            domainVsParallel = $"{ResolveDomainParallelism()}vs8",
            authorizeGetBatchSize = AuthorizeGetBatchSize,
            decryptWorkers = ResolveDecryptWorkerParallelism(),
            decryptCapacity = ResolveDecryptQueueCapacity(),
            privilegedBatchChunkSize = 12,
            waveSeedCap = 144,
            pipeline = "ike-ram-4pt-v1",
            edgeGlobalCap = BackupEdgeDownloadParallelism,
            edgeAuthPipeline = ResolveEdgeAuthPipelineSlots(),
            decryptOverlap = !ResolveFillAwait(),
            fillAwait = ResolveFillAwait(),
            hypothesis = "H-RAM-IKE4",
            runId = "ike-ram-4pt-v1",
        });
        // #endregion
        await using var fsWriter = await BackupFilesystemWriter.OpenAsync(cleanDir, ct);
        BackupFileKeyContext fileKeyCtx = BackupFileKeyContext.Load(workDir, log);

        var downloaded = new ConcurrentDictionary<string, byte>(StringComparer.Ordinal);
        var assetIndex = 0;
        long totalBytes = 0;
        var writtenSharded = 0;
        var stagedChunks = 0;
        var mmcsOk = 0;
        var fileDecryptOk = 0;

        async Task<bool> ProcessOneAsync(
            BackupAsset asset,
            string phase,
            int phaseIndex,
            int phaseTotal,
            int? overallCompleted = null,
            int? overallTotal = null)
        {
            if (!downloaded.TryAdd(AssetDownloadKey(asset), 0))
                return false;

            // Cede il thread (UI pump / thread-pool) prima di I/O+crypto pesanti del primo FL.
            await Task.Yield();

            Interlocked.Increment(ref assetIndex);
            log?.Report($"{phase} {phaseIndex}/{phaseTotal}: {asset.RecordName}");

            // assetTotal UI = file Backup/ dello snapshot quando noto; altrimenti phaseTotal (classico).
            var uiAssetTotal = Math.Max(overallTotal ?? phaseTotal, 1);
            var one = await DownloadAndDecryptAssetAsync(
                session,
                contentHost,
                asset,
                workDir,
                workDir,
                fsWriter,
                fileKeyCtx,
                phaseIndex,
                uiAssetTotal,
                progress,
                log,
                ct).ConfigureAwait(false);

            if (!one.Ok && !one.QueuedDecrypt)
            {
                if (!one.PendingChunks)
                {
                    NoteSyncOrQueuedOutcome(one, "fl_asset");
                    if (overallTotal is int otFail && otFail > 0)
                        ReportFilesDoneProgress(progress, overallCompleted ?? Volatile.Read(ref writtenSharded), otFail, Volatile.Read(ref totalBytes));
                }
                return false;
            }

            if (one.QueuedDecrypt)
            {
                NoteSyncOrQueuedOutcome(one, "fl_asset");
                if (overallTotal is int otQ && otQ > 0)
                    ReportFilesDoneProgress(progress, overallCompleted ?? Volatile.Read(ref writtenSharded), otQ, Volatile.Read(ref totalBytes));
                return true;
            }

            Interlocked.Add(ref totalBytes, one.DownloadedBytes);
            if (one.WrittenSharded) Interlocked.Increment(ref writtenSharded);
            if (one.StagedChunks) Interlocked.Increment(ref stagedChunks);
            if (one.MmcsDecrypted) Interlocked.Increment(ref mmcsOk);
            if (one.FileDecrypted) Interlocked.Increment(ref fileDecryptOk);
            NoteSyncOrQueuedOutcome(one, "fl_asset");
            if (overallTotal is int ot && ot > 0)
                ReportFilesDoneProgress(progress, overallCompleted ?? Volatile.Read(ref writtenSharded), ot, Volatile.Read(ref totalBytes));
            return true;
        }

        if (isModernCn)
        {
            // interleaved: per ogni Domain → FL download/decrypt/parse → Asset del fileList
            // → Domain successivo (non tutti i FL prima, poi tutti gli Asset).
            var flTotal = flAssets.Count;
            var maxFiles = job.MaxAssets is int m and > 0 ? m : int.MaxValue;
            var filesDone = 0;
            var fileIndex = 0;
            //  cloni solo intra-FL. shardBySig globale resta vuoto (niente seed
            // device/sibling); ogni ProcessOneDomainAsync usa flShardBySig locale.
            var shardBySig = new ConcurrentDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            var deferredClones = new List<BackupAsset>();
            // root = …/{udid}/[{snap}][{stamp}]/; device = parent (path resolve only).
            var deviceDir = Path.GetDirectoryName(
                snapshotRoot.TrimEnd(
                    Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar))
                ?? snapshotRoot;
            // #region agent log
            AgentCountAlways("copy_snapshot_seed", new
            {
                deviceDir,
                snapshotRoot,
                workDir,
                seededFromCache = 0,
                shardMap = 0,
                intraFlClonesOnly = true,
                siblings = IkeBackupOutputPaths
                    .EnumerateSiblingSnapshotWorkDirs(deviceDir, snapshotRoot).Count,
                hypothesis = "H-COPY-SNAP",
            });
            // #endregion
            var pref4 = CloudKitRecordNames.DevicePrefix4(job.Device.DeviceUuid);
            _activeDevicePrefix4 = pref4;
            var domainBySig = BuildDomainByFileListSignature(enFetch);
            var sessionRefreshedForAssets = 0;
            //  loop per-Domain/manifest (FL→PB→AG→edge×8), overlap Domain leggero.
            var domainParallelism = ResolveDomainParallelism();
            var planLock = new object();
            var stateLock = new object();
            var mmcsInitLock = new object();
            using var domainGate = new SemaphoreSlim(domainParallelism, domainParallelism);
            using var finalizeGate = new SemaphoreSlim(1, 1);
            var domainsActive = 0;

            var declared = SumDomainInventory(enFetch);
            // Denominatore UI = MMCS Asset dello snapshot (Domain inventory), non n° di FL.
            // Cresce solo se i flist pianificano più path di quanto dichiarato.
            catalogAssets = declared.Assets > 0 ? declared.Assets : 0;
            if (maxFiles < int.MaxValue && catalogAssets > 0)
                catalogAssets = Math.Min(catalogAssets, maxFiles);
            estimatedTotal = catalogAssets;
            backupBoundPlanned = 0;

            log?.Report(
                $"Download interleaved: {flTotal} fileList → " +
                $"{declared.Files:N0} file, {declared.Directories:N0} cartelle (escluse), " +
                $"{declared.EmptyFiles:N0} empty, {declared.Symlinks:N0} symlink; " +
                $"MMCS assets snapshot={catalogAssets:N0}" +
                $" (cap={maxFiles}, domainParallel={domainParallelism}, " +
                $"edgeParallel={BackupEdgeDownloadParallelism})");
            // #region agent log
            AgentCountAlways("backup_total_init", new
            {
                flTotal,
                files = declared.Files,
                directories = declared.Directories,
                empty = declared.EmptyFiles,
                symlinks = declared.Symlinks,
                assets = declared.Assets,
                catalogAssets,
                estimatedTotal,
                seededFromInventory = catalogAssets > 0,
                maxFiles = maxFiles < int.MaxValue ? maxFiles : -1,
                domainParallelism,
                edgeParallel = BackupEdgeDownloadParallelism,
                orchestrator = "per-domain",
                hypothesis = "H-TOTAL-SNAP",
            });
            // #endregion
            if (estimatedTotal > 0)
                ReportFilesDoneProgress(progress, 0, estimatedTotal);
            else
                progress?.Report(new DownloadProgressReport
                {
                    Status = FormatSnapshotStatus($" preparazione fileList 0/{flTotal}…"),
                    SnapshotLabel = _uiSnapshotLabel,
                    AppendToLog = false,
                });
            if (_uiBytesTotal > 0)
                log?.Report($"  stima dimensione snapshot: {_uiBytesTotal:N0} B (ETA su byte)");

            var flIndex = 0;
            var domainTasks = new List<Task>(flTotal);

            /// <summary>
            /// Attende il finalize pending (non fire-and-forget) e applica gli outcome.
            /// Evita domain_end con PendingChunks ancora aperti / evicted persi.
            /// </summary>
            async Task DrainMmcsPendingOnceAsync(
                string reason,
                ConcurrentDictionary<string, string>? shardMap = null)
            {
                if (_mmcsChunkSession is not { PendingCount: > 0 })
                    return;

                var map = shardMap ?? shardBySig;
                await finalizeGate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    var midFinal = await FinalizePendingChunkFilesAsync(
                        session,
                        workDir,
                        workDir,
                        fsWriter,
                        fileKeyCtx,
                        Math.Max(estimatedTotal, 1),
                        progress,
                        log,
                        ct,
                        map,
                        cleanDir).ConfigureAwait(false);
                    foreach (var fin in midFinal)
                    {
                        if (fin.CountersApplied)
                        {
                            if (!fin.Ok || fin.QueuedDecrypt || fin.PendingChunks)
                                continue;
                            Interlocked.Increment(ref filesDone);
                            Interlocked.Add(ref totalBytes, fin.DownloadedBytes);
                            if (fin.WrittenSharded) Interlocked.Increment(ref writtenSharded);
                            if (fin.StagedChunks) Interlocked.Increment(ref stagedChunks);
                            if (fin.MmcsDecrypted) Interlocked.Increment(ref mmcsOk);
                            if (fin.FileDecrypted) Interlocked.Increment(ref fileDecryptOk);
                            continue;
                        }

                        NoteSyncOrQueuedOutcome(fin, "pending_drain");
                        if (fin.QueuedDecrypt || fin.PendingChunks || !fin.Ok)
                            continue;
                        Interlocked.Increment(ref filesDone);
                        Interlocked.Add(ref totalBytes, fin.DownloadedBytes);
                        if (fin.WrittenSharded) Interlocked.Increment(ref writtenSharded);
                        if (fin.StagedChunks) Interlocked.Increment(ref stagedChunks);
                        if (fin.MmcsDecrypted) Interlocked.Increment(ref mmcsOk);
                        if (fin.FileDecrypted) Interlocked.Increment(ref fileDecryptOk);
                    }

                    ReportFilesDoneProgress(
                        progress, Volatile.Read(ref writtenSharded),
                        Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                        Volatile.Read(ref totalBytes));
                }
                finally
                {
                    finalizeGate.Release();
                }

                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                        JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "9a5651",
                            ["runId"] = "pending-fix-v1",
                            ["hypothesisId"] = "H-DRAIN",
                            ["location"] = "BackupDownloadService.DrainMmcsPendingOnceAsync",
                            ["message"] = "pending_drain_once",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new
                            {
                                reason,
                                pendingAfter = _mmcsChunkSession?.PendingCount ?? 0,
                                evictedRetry = _mmcsChunkSession?.EvictedPendingForRetryCount ?? 0,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
            }

            async Task DrainMmcsPendingUntilIdleAsync(
                string reason,
                int maxRounds = 8,
                ConcurrentDictionary<string, string>? shardMap = null)
            {
                var map = shardMap ?? shardBySig;
                for (var round = 0; round < maxRounds; round++)
                {
                    if (_mmcsChunkSession is not { PendingCount: > 0 })
                        break;
                    await DrainMmcsPendingOnceAsync($"{reason}#{round}", map)
                        .ConfigureAwait(false);
                    if (_pendingDecryptTasks.Count > 0)
                    {
                        var drain = await DrainPendingDecryptTasksAsync(
                            map, cleanDir, progress, log, ct).ConfigureAwait(false);
                        filesDone += drain.Completed;
                        totalBytes += drain.TotalBytes;
                        writtenSharded += drain.WrittenSharded;
                        stagedChunks += drain.StagedChunks;
                        mmcsOk += drain.MmcsOk;
                        fileDecryptOk += drain.FileDecryptOk;
                    }
                }
            }

            /// <summary>
            /// Re-AG degli asset evicted dal cap pending (e eventuali liste passate).
            /// Stesso schema del clone-demote: batch AG → drain pending → monofile fallback.
            /// </summary>
            async Task ProcessEvictedPendingRetriesAsync(
                string reason,
                List<BackupAsset>? extra = null,
                int depth = 0,
                ConcurrentDictionary<string, string>? shardMap = null)
            {
                if (depth > 3)
                    return;

                var map = shardMap ?? shardBySig;
                var retry = _mmcsChunkSession?.DrainEvictedPendingForRetry() ?? [];
                if (extra is { Count: > 0 })
                    retry.AddRange(extra);
                if (retry.Count == 0)
                    return;

                // Dedup per record/path.
                var seen = new HashSet<string>(StringComparer.Ordinal);
                var unique = new List<BackupAsset>(retry.Count);
                foreach (var a in retry)
                {
                    var key = AssetDownloadKey(a);
                    if (!seen.Add(key))
                        continue;
                    a.ContentFromExistingSignature = false;
                    unique.Add(a);
                }

                log?.Report(
                    $"  pending-evict→re-AG: {unique.Count} file ({reason})");
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                        JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "9a5651",
                            ["runId"] = "pending-fix-v1",
                            ["hypothesisId"] = "H-EVICT-RETRY",
                            ["location"] = "BackupDownloadService.ProcessEvictedPendingRetriesAsync",
                            ["message"] = "evicted_retry_start",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new { reason, count = unique.Count },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion

                var retryTotalUi = Math.Max(
                    estimatedTotal > 0 ? estimatedTotal : fileIndex + unique.Count, 1);
                for (var off = 0; off < unique.Count; off += AuthorizeGetBatchSize)
                {
                    ct.ThrowIfCancellationRequested();
                    var chunk = unique.GetRange(
                        off, Math.Min(AuthorizeGetBatchSize, unique.Count - off));
                    FlistBatchRunResult? batchResult = null;
                    try
                    {
                        batchResult = await TryProcessFlistAuthorizeBatchAsync(
                            session, contentHost, chunk, workDir, workDir,
                            fsWriter, fileKeyCtx, fileIndex, retryTotalUi,
                            progress, log, ct).ConfigureAwait(false);
                    }
                    catch (OperationCanceledException) { throw; }
                    catch (Exception ex)
                    {
                        log?.Report(
                            $"  ERROR evict-retry AG ({chunk.Count}): {ex.Message}");
                        foreach (var planned in chunk)
                        {
                            fileIndex++;
                            downloaded.TryAdd(AssetDownloadKey(planned), 0);
                            var failPath = planned.RelativePath ?? planned.RecordName;
                            NoteFileDownloaded("evict_retry_ag_ex", failPath);
                            NoteDecryptFailed(
                                "edge_server", failPath, emitUiError: true, detail: ex.Message);
                        }

                        continue;
                    }

                    var pendingInBatch = 0;
                    if (batchResult is not null)
                    {
                        for (var i = 0; i < chunk.Count; i++)
                        {
                            fileIndex++;
                            downloaded.TryAdd(AssetDownloadKey(chunk[i]), 0);
                            var one = batchResult.Outcomes[i];
                            if (one.QueuedDecrypt)
                            {
                                NoteSyncOrQueuedOutcome(one, "evict_retry");
                                continue;
                            }

                            if (one.PendingChunks)
                            {
                                pendingInBatch++;
                                stagedChunks++;
                                continue;
                            }

                            if (!one.Ok)
                            {
                                NoteSyncOrQueuedOutcome(one, "evict_retry");
                                continue;
                            }

                            NoteSyncOrQueuedOutcome(one, "evict_retry");
                            filesDone++;
                            totalBytes += one.DownloadedBytes;
                            if (one.WrittenSharded)
                            {
                                writtenSharded++;
                                RememberShardPath(chunk[i], map, cleanDir);
                            }

                            if (one.StagedChunks) stagedChunks++;
                            if (one.MmcsDecrypted) mmcsOk++;
                            if (one.FileDecrypted) fileDecryptOk++;
                        }
                    }
                    else
                    {
                        foreach (var planned in chunk)
                        {
                            ct.ThrowIfCancellationRequested();
                            fileIndex++;
                            if (!downloaded.TryAdd(AssetDownloadKey(planned), 0))
                                continue;
                            var one = await DownloadAndDecryptAssetAsync(
                                session, contentHost, planned, workDir, workDir,
                                fsWriter, fileKeyCtx, fileIndex, retryTotalUi,
                                progress, log, ct).ConfigureAwait(false);
                            if (one.PendingChunks)
                            {
                                pendingInBatch++;
                                stagedChunks++;
                                NoteSyncOrQueuedOutcome(one, "evict_retry_single");
                                continue;
                            }

                            if (one.QueuedDecrypt || !one.Ok)
                            {
                                NoteSyncOrQueuedOutcome(one, "evict_retry_single");
                                continue;
                            }

                            NoteSyncOrQueuedOutcome(one, "evict_retry_single");
                            filesDone++;
                            totalBytes += one.DownloadedBytes;
                            if (one.WrittenSharded)
                            {
                                writtenSharded++;
                                RememberShardPath(planned, map, cleanDir);
                            }

                            if (one.StagedChunks) stagedChunks++;
                            if (one.MmcsDecrypted) mmcsOk++;
                            if (one.FileDecrypted) fileDecryptOk++;
                        }
                    }

                    if (pendingInBatch > 0)
                    {
                        await DrainMmcsPendingUntilIdleAsync(
                            $"evict_retry_{reason}", maxRounds: 6, map)
                            .ConfigureAwait(false);
                    }
                }

                if (_pendingDecryptTasks.Count > 0)
                {
                    var drain = await DrainPendingDecryptTasksAsync(
                        map, cleanDir, progress, log, ct).ConfigureAwait(false);
                    filesDone += drain.Completed;
                    totalBytes += drain.TotalBytes;
                    writtenSharded += drain.WrittenSharded;
                    stagedChunks += drain.StagedChunks;
                    mmcsOk += drain.MmcsOk;
                    fileDecryptOk += drain.FileDecryptOk;
                }

                await DrainMmcsPendingUntilIdleAsync(
                    $"evict_retry_end_{reason}", maxRounds: 8, map)
                    .ConfigureAwait(false);

                // Evict durante il retry → altro giro (bound).
                var again = _mmcsChunkSession?.EvictedPendingForRetryCount ?? 0;
                if (again > 0)
                {
                    await ProcessEvictedPendingRetriesAsync(
                        reason + "+again", depth: depth + 1, shardMap: map)
                        .ConfigureAwait(false);
                }
            }

            // CopySnapshot/cloni: coda dedicata così i domain worker non restano
            // bloccati su File.Copy (UI e MMCS restano responsivi).
            // Job porta la mappa shard del FL ( niente lookup cross-FL).
            var cloneCopyChannel = Channel.CreateUnbounded<(
                List<BackupAsset> Batch,
                ConcurrentDictionary<string, string> ShardMap,
                List<BackupAsset> DeferSink)>(
                new UnboundedChannelOptions
                {
                    SingleReader = true,
                    SingleWriter = false,
                    AllowSynchronousContinuations = false,
                });
            var cloneCopyQueued = 0;
            var cloneCopyPump = Task.Run(async () =>
            {
                await foreach (var job in cloneCopyChannel.Reader.ReadAllAsync(ct)
                    .ConfigureAwait(false))
                {
                    // #region agent log
                    try
                    {
                        var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "b3df71",
                            ["runId"] = "clone-async-v1",
                            ["hypothesisId"] = "H-CLONE-ASYNC",
                            ["location"] = "BackupDownloadService.cloneCopyPump",
                            ["message"] = "clone_copy_pump_batch",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new
                            {
                                batch = job.Batch.Count,
                                shardMap = job.ShardMap.Count,
                                queuedLeft = Volatile.Read(ref cloneCopyQueued),
                            },
                        });
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                            line + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion
                    await FlushReadyClonesAsync(job.Batch, job.ShardMap, job.DeferSink)
                        .ConfigureAwait(false);
                    Interlocked.Add(ref cloneCopyQueued, -job.Batch.Count);
                }
            }, ct);

            async Task EnqueueCloneCopiesAsync(
                List<BackupAsset> batch,
                ConcurrentDictionary<string, string> flShardMap,
                List<BackupAsset> deferSink)
            {
                if (batch.Count == 0)
                    return;
                Interlocked.Add(ref cloneCopyQueued, batch.Count);
                // #region agent log
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "b3df71",
                        ["runId"] = "clone-async-v1",
                        ["hypothesisId"] = "H-CLONE-ASYNC",
                        ["location"] = "BackupDownloadService.EnqueueCloneCopiesAsync",
                        ["message"] = "clone_copy_enqueued",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            batch = batch.Count,
                            shardMap = flShardMap.Count,
                            queued = Volatile.Read(ref cloneCopyQueued),
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                await cloneCopyChannel.Writer.WriteAsync(
                    (batch, flShardMap, deferSink), ct).ConfigureAwait(false);
            }

            foreach (var flAsset in flAssets)
            {
                ct.ThrowIfCancellationRequested();
                if (Volatile.Read(ref filesDone) >= maxFiles)
                    break;

                var flAssetLocal = flAsset;
                var myFlIndex = Interlocked.Increment(ref flIndex);
                domainTasks.Add(ProcessOneDomainAsync(flAssetLocal, myFlIndex));
            }

            await Task.WhenAll(domainTasks).ConfigureAwait(false);
            cloneCopyChannel.Writer.TryComplete();
            await cloneCopyPump.ConfigureAwait(false);
            await DrainMmcsPendingUntilIdleAsync("post_domains", maxRounds: 12)
                .ConfigureAwait(false);
            await ProcessEvictedPendingRetriesAsync("post_domains").ConfigureAwait(false);

            // Prior-ready: copia subito e ++ Scaricati/Decifrati; resto → deferSink (per-FL).
            //  lookup solo su flShardMap — mai device cache / altri FL.
            async Task FlushReadyClonesAsync(
                List<BackupAsset> batch,
                ConcurrentDictionary<string, string> flShardMap,
                List<BackupAsset> deferSink)
            {
                if (batch.Count == 0)
                    return;

                var readyNow = new List<BackupAsset>();
                var defer = new List<BackupAsset>();
                foreach (var a in batch)
                {
                    if (a.AssetSignature is { Length: 21 } sig)
                    {
                        var hex = Convert.ToHexString(sig).ToLowerInvariant();
                        if (flShardMap.TryGetValue(hex, out var src) && File.Exists(src))
                        {
                            readyNow.Add(a);
                            continue;
                        }
                    }

                    defer.Add(a);
                }

                if (readyNow.Count > 0)
                {
                    var copiedInFlush = 0;
                    var r = await CopyCloneAssetsAsync(
                        readyNow, flShardMap, fsWriter, cleanDir, log, ct, deviceDir,
                        onCopied: (a, bytes) =>
                        {
                            // Cloni: Scaricati/Decifrati/Duplicati + byte Dati (SizeBytes clone).
                            NoteCloneFileCopied(a.RelativePath ?? a.RecordName, bytes);
                            if (bytes > 0)
                                Interlocked.Add(ref totalBytes, bytes);
                            Interlocked.Increment(ref filesDone);
                            Interlocked.Increment(ref writtenSharded);
                            var n = Interlocked.Increment(ref copiedInFlush);
                            // UI: non refresh ad ogni file (I/O UI + progress flood).
                            if (n == 1 || n == readyNow.Count || n % 25 == 0)
                            {
                                ReportFilesDoneProgress(
                                    progress,
                                    Volatile.Read(ref writtenSharded),
                                    Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                    Volatile.Read(ref totalBytes));
                            }
                        },
                        allowCrossFlOrPrior: false).ConfigureAwait(false);
                    ReportFilesDoneProgress(
                        progress,
                        Volatile.Read(ref writtenSharded),
                        Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                        Volatile.Read(ref totalBytes));
                    if (r.Missing.Count > 0)
                        defer.AddRange(r.Missing);
                    // #region agent log
                    AgentCountAlways("clone_flush_ready", new
                    {
                        ready = readyNow.Count,
                        copied = r.Copied,
                        defer = defer.Count,
                        flShardMap = flShardMap.Count,
                        intraFlOnly = true,
                        hypothesis = "H-CLONE-COUNT",
                    });
                    // #endregion
                }

                if (defer.Count > 0)
                {
                    lock (deferSink)
                        deferSink.AddRange(defer);
                }
            }

            async Task ProcessOneDomainAsync(BackupAsset flAsset, int flIndex)
            {
                if (Volatile.Read(ref filesDone) >= maxFiles)
                    return;

                await domainGate.WaitAsync(ct).ConfigureAwait(false);
                Interlocked.Increment(ref domainsActive);
                var domainSw = System.Diagnostics.Stopwatch.StartNew();
                // #region agent log
                var domainSliceN = 0;
                var domainClonesN = 0;
                var domainNeedN = 0;
                var domainSkipAuthN = 0;
                var domainExitReason = "running";
                string? domainName = null;
                // #endregion
                // #region agent log
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "ike-orch",
                        ["hypothesisId"] = "H-ORCH",
                        ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                        ["message"] = "domain_start",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            flIndex,
                            flTotal,
                            active = Volatile.Read(ref domainsActive),
                            domainParallelism,
                            edgeParallel = BackupEdgeDownloadParallelism,
                            record = flAsset.RecordName,
                        },
                    });
                    IkeLogOptions.AppendAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
                }
                catch { /* ignore */ }
                // #endregion
                try
                {
                    ct.ThrowIfCancellationRequested();
                    if (Volatile.Read(ref filesDone) >= maxFiles)
                    {
                        log?.Report($"  cap MaxAssets={maxFiles} raggiunto — stop fileList rimanenti");
                        return;
                    }

                    log?.Report($"FL {flIndex}/{flTotal}: {flAsset.RecordName}");
                    // Mai passare flTotal come FilesTotal: è il n° di Domain/fileList, non i file Backup/.
                    var filesDenom = Math.Max(Volatile.Read(ref estimatedTotal), Volatile.Read(ref backupBoundPlanned));
                    if (filesDenom > 0)
                        ReportFilesDoneProgress(progress, writtenSharded, filesDenom, totalBytes);
                    else
                        progress?.Report(new DownloadProgressReport
                        {
                            Status = FormatSnapshotStatus($" fileList {flIndex}/{flTotal}…"),
                            SnapshotLabel = _uiSnapshotLabel,
                            AppendToLog = false,
                        });

                    var flOk = await ProcessOneAsync(
                        flAsset, "FL", flIndex, flTotal, filesDone,
                        Math.Max(Math.Max(filesDenom, catalogAssets), 1))
                        .ConfigureAwait(false);
                    if (!flOk)
                    {
                        // #region agent log
                        domainExitReason = "fl_download_failed";
                        try
                        {
                            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "9a5651",
                                ["runId"] = "fl-incomplete-v1",
                                ["hypothesisId"] = "H1",
                                ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                ["message"] = "domain_early_exit",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new
                                {
                                    reason = "fl_download_failed",
                                    flIndex,
                                    flTotal,
                                    record = flAsset.RecordName,
                                    filesDone = Volatile.Read(ref filesDone),
                                },
                            });
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                                line + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                        // #endregion
                        return;
                    }

                    var dbPath = ResolveFlistDbPath(workDir, flAsset);
                    if (!File.Exists(dbPath))
                    {
                        log?.Report($"  {flAsset.RecordName}: flist DB assente dopo download — skip Asset");
                        // #region agent log
                        domainExitReason = "flist_db_missing";
                        try
                        {
                            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "9a5651",
                                ["runId"] = "fl-incomplete-v1",
                                ["hypothesisId"] = "H2",
                                ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                ["message"] = "domain_early_exit",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new
                                {
                                    reason = "flist_db_missing",
                                    flIndex,
                                    flTotal,
                                    record = flAsset.RecordName,
                                    dbPath,
                                    filesDone = Volatile.Read(ref filesDone),
                                },
                            });
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                                line + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                        // #endregion
                        return;
                    }

                    //  dedup signature solo dentro questo FL (non cross-FL).
                    var flSeenSig = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                    var flShardBySig = new ConcurrentDictionary<string, string>(
                        StringComparer.OrdinalIgnoreCase);
                    var flDeferredClones = new List<BackupAsset>();
                    List<BackupAsset> slice;
                    lock (planLock)
                    {
                        slice = FlistDownloadPlanBuilder.BuildBatchFromDb(
                            dbPath, workDir, enFetch, flSeenSig, log,
                            _activeDevicePrefix4).ToList();
                    }
                    if (slice.Count == 0)
                    {
                        // #region agent log
                        domainExitReason = "slice_empty";
                        try
                        {
                            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "9a5651",
                                ["runId"] = "fl-incomplete-v1",
                                ["hypothesisId"] = "H3",
                                ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                ["message"] = "domain_early_exit",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new
                                {
                                    reason = "slice_empty",
                                    flIndex,
                                    flTotal,
                                    record = flAsset.RecordName,
                                    dbPath,
                                    filesDone = Volatile.Read(ref filesDone),
                                },
                            });
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                                line + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                        // #endregion
                        return;
                    }

                    // #region agent log
                    try
                    {
                        var sample = slice
                            .Where(static a =>
                                (a.RelativePath ?? "").Contains("RemoteStrings", StringComparison.OrdinalIgnoreCase)
                                || (a.RelativePath ?? "").Contains("Numbers.plist", StringComparison.OrdinalIgnoreCase)
                                || (a.RecordIdSuffix ?? "").Contains("023F34AE", StringComparison.OrdinalIgnoreCase))
                            .Take(6)
                            .Select(static a => new Dictionary<string, object?>
                            {
                                ["path"] = a.RelativePath,
                                ["record"] = a.RecordName,
                                ["isA"] = CloudKitMmcsIds.IsAssetRecordName(a.RecordName),
                                ["isUuid"] = CloudKitMmcsIds.IsUuidRecordName(a.RecordName),
                                ["ridTok8"] = a.RecordIdSuffix is { } r && r.Contains(':')
                                    ? r.Split(':').ElementAtOrDefault(1) is { Length: >= 8 } t
                                        ? t[..Math.Min(12, t.Length)]
                                        : ""
                                    : "",
                            })
                            .ToList();
                        if (sample.Count > 0)
                        {
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                                JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "03cce7",
                                    ["runId"] = "recordkey-a-v1",
                                    ["hypothesisId"] = "H-RECORDKEY-A",
                                    ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                    ["message"] = "flist_batch_recordname_form",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["data"] = new Dictionary<string, object?>
                                    {
                                        ["pref4"] = _activeDevicePrefix4 ?? "",
                                        ["batchN"] = slice.Count,
                                        ["aFormN"] = slice.Count(static a =>
                                            CloudKitMmcsIds.IsAssetRecordName(a.RecordName)),
                                        ["uuidOnlyN"] = slice.Count(static a =>
                                            CloudKitMmcsIds.IsUuidRecordName(a.RecordName)),
                                        ["sample"] = sample,
                                    },
                                }) + Environment.NewLine);
                        }
                    }
                    catch { /* ignore */ }
                    // #endregion

                    var doneNow = Volatile.Read(ref filesDone);
                    if (doneNow + slice.Count > maxFiles)
                        slice = slice.Take(Math.Max(0, maxFiles - doneNow)).ToList();

                    var plannedNow = Interlocked.Add(ref backupBoundPlanned, slice.Count);
                    if (plannedNow > Volatile.Read(ref estimatedTotal))
                    {
                        estimatedTotal = maxFiles < int.MaxValue
                            ? Math.Min(plannedNow, maxFiles)
                            : plannedNow;
                    }

                    log?.Report(
                        $"  → {slice.Count} file Backup/ da fileList {flIndex}/{flTotal} " +
                        $"({slice[0].Domain ?? "?"}; totale Backup/={estimatedTotal:N0}, " +
                        $"pianificati={backupBoundPlanned:N0})");
                    AgentCountAlways("backup_total_grow", new
                    {
                        flIndex,
                        flTotal,
                        slice = slice.Count,
                        clones = slice.Count(static a => a.ContentFromExistingSignature),
                        backupBoundPlanned,
                        estimatedTotal,
                    });
                    // #region agent log
                    try
                    {
                        var cloneN = slice.Count(static a => a.ContentFromExistingSignature);
                        var originN = slice.Count - cloneN;
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                            JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "9a5651",
                                ["runId"] = "clone-gap-v1",
                                ["hypothesisId"] = "H-SEEN-SCOPE",
                                ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                ["message"] = "fl_seen_sig_scope",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new
                                {
                                    flIndex,
                                    domain = slice[0].Domain,
                                    slice = slice.Count,
                                    origins = originN,
                                    clones = cloneN,
                                    flSeenSig = flSeenSig.Count,
                                    intraFlOnly = true,
                                },
                            }) + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion

                    // Prima i cloni (stessa signature nello stesso FL): niente AG/edge —
                    // solo File.Copy dall'originale già scaricato in questo FL.
                    //  niente TryBindPriorShardSource (device cache / altri FL / sibling).
                    var cloneBatch = new List<BackupAsset>();
                    var needDownload = new List<BackupAsset>();
                    var priorHits = 0; // legacy counter (sempre 0 con intra-FL only)
                    foreach (var a in slice)
                    {
                        if (a.ContentFromExistingSignature)
                            cloneBatch.Add(a);
                        else
                            needDownload.Add(a);
                    }

                    // Denominatore Dati: SizeBytes needDownload (i cloni non si sommano — già nel totale).
                    {
                        var downloadDeclared = 0L;
                        var cloneDeclared = 0L;
                        foreach (var a in needDownload)
                        {
                            if (a.SizeBytes is > 0)
                                downloadDeclared += a.SizeBytes.Value;
                        }
                        foreach (var a in cloneBatch)
                        {
                            if (a.SizeBytes is > 0)
                                cloneDeclared += a.SizeBytes.Value;
                        }
                        if (downloadDeclared > 0)
                            Interlocked.Add(ref _uiBytesTotal, downloadDeclared);
                        // #region agent log
                        var nPlan = Interlocked.Increment(ref _bytesDownloadPlanLogN);
                        if (nPlan <= 12 || nPlan % 50 == 0 || cloneDeclared > 0)
                        {
                            try
                            {
                                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "b3df71",
                                    ["runId"] = "bytes-clone-incl-v1",
                                    ["hypothesisId"] = "H-CLONE-BYTES",
                                    ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                    ["message"] = "bytes_download_planned",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["data"] = new
                                    {
                                        flIndex,
                                        domain = slice[0].Domain,
                                        slice = slice.Count,
                                        clones = cloneBatch.Count,
                                        needDownload = needDownload.Count,
                                        downloadDeclared,
                                        cloneDeclaredNotAddedToTotal = cloneDeclared,
                                        uiBytesTotal = Volatile.Read(ref _uiBytesTotal),
                                        priorHits,
                                    },
                                });
                                File.AppendAllText(
                                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                                    line + Environment.NewLine);
                            }
                            catch { /* ignore */ }
                        }
                        // #endregion
                    }

                    if (priorHits > 0 || cloneBatch.Count > 0)
                    {
                        log?.Report(
                            $"  CopySnapshot: {cloneBatch.Count} file da snapshot/cache " +
                            $"(priorBind={priorHits}, no PB/MMCS; download={needDownload.Count})");
                        // #region agent log
                        AgentCountAlways("copy_snapshot_prior_hits", new
                        {
                            priorHits,
                            clones = cloneBatch.Count,
                            download = needDownload.Count,
                            shardMap = shardBySig.Count,
                            hypothesis = "H-COPY-SNAP",
                        });
                        try
                        {
                            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "b3df71",
                                ["runId"] = "clone-before-auth-v1",
                                ["hypothesisId"] = "H-CLONE-SKIP-AUTH",
                                ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                ["message"] = "clone_split_before_auth",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new
                                {
                                    flIndex,
                                    domain = slice[0].Domain,
                                    slice = slice.Count,
                                    clones = cloneBatch.Count,
                                    needDownload = needDownload.Count,
                                    priorHits,
                                },
                            });
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                                line + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                        // #endregion
                    }

                    // #region agent log
                    domainSliceN = slice.Count;
                    domainClonesN = cloneBatch.Count;
                    domainNeedN = needDownload.Count;
                    domainName = slice[0].Domain;
                    // #endregion

                    if (cloneBatch.Count > 0)
                    {
                        await EnqueueCloneCopiesAsync(
                            cloneBatch, flShardBySig, flDeferredClones).ConfigureAwait(false);
                    }

                    // Con flSeenSig per-FL non dovremmo mai avere need=0 e slice>0
                    // (ogni signature unica ha un originale). Se succede (o cloni senza
                    // shard), demote→download invece di uscire lasciando gap su Backup/.
                    if (needDownload.Count == 0 && cloneBatch.Count > 0)
                    {
                        log?.Report(
                            $"  WARN FL{flIndex}: {cloneBatch.Count} cloni senza originale " +
                            "nel FL → demote download");
                        // #region agent log
                        domainExitReason = "clones_only_demoted";
                        try
                        {
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                                JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "9a5651",
                                    ["runId"] = "clone-gap-v1",
                                    ["hypothesisId"] = "H-CLONE-DEMOTE",
                                    ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                    ["message"] = "clones_only_demoted_to_download",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["data"] = new
                                    {
                                        flIndex,
                                        domain = slice[0].Domain,
                                        demoted = cloneBatch.Count,
                                        flShardMap = flShardBySig.Count,
                                    },
                                }) + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                        // #endregion
                        foreach (var a in cloneBatch)
                            a.ContentFromExistingSignature = false;
                        needDownload = cloneBatch;
                        cloneBatch = [];
                        domainNeedN = needDownload.Count;
                        domainClonesN = 0;
                    }
                    else if (needDownload.Count == 0)
                    {
                        // #region agent log
                        domainExitReason = "clones_only_enqueued";
                        // #endregion
                        return;
                    }

                    if (Interlocked.CompareExchange(ref sessionRefreshedForAssets, 1, 0) == 0)
                    {
                        await RefreshAnisetteBeforeFlistAssetsAsync(session, log, ct)
                            .ConfigureAwait(false);
                    }

                    await AttachFlistAuthFromCachesAsync(needDownload, readyAssets, log)
                        .ConfigureAwait(false);
                    await ResolveFlistBatchAuthAsync(
                        session, needDownload, pref4, workDir, enFetch, log, ct)
                        .ConfigureAwait(false);

                    var readyBatch = new List<BackupAsset>();
                    var skipAuthAssets = new List<BackupAsset>();
                    foreach (var a in needDownload)
                    {
                        if (a.AssetSignature is { Length: 21 }
                            && MmcsAuthBuilder.TryBuildFlistAuthorizeEntry(a.AssetSignature, a.MmcsAuth)
                                is not null)
                        {
                            readyBatch.Add(a);
                        }
                        else
                        {
                            Interlocked.Increment(ref fileIndex);
                            skipAuthAssets.Add(a);
                        }
                    }

                    // #region agent log
                    // Always-on: recovery summary after PB/cache attach (H-FL1).
                    try
                    {
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                            JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "7dabb5",
                                ["runId"] = "fl-authget-v1",
                                ["hypothesisId"] = "H-FL1",
                                ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                ["message"] = "flist_auth_recovery_summary",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new
                                {
                                    flIndex,
                                    flRecord = flAsset.RecordName,
                                    slice = slice.Count,
                                    ready = readyBatch.Count,
                                    clones = cloneBatch.Count,
                                    skipAuth = skipAuthAssets.Count,
                                    priorHits,
                                    authOnly = needDownload.Count,
                                    domain = slice[0].Domain,
                                    anisetteBlocked = _assets.AnisetteRefreshBlocked,
                                },
                            }) + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion
                    // #region agent log
                    domainSkipAuthN = skipAuthAssets.Count;
                    // #endregion

                    if (skipAuthAssets.Count > 0)
                    {
                        // Dopo PB completo: se Anisette era il blocco, non contare Falliti —
                        // è lavoro incompleto. Solo gap auth reale → ERROR+Falliti.
                        var anisetteBlocked = _assets.AnisetteRefreshBlocked;
                        var skipAuthPaths = skipAuthAssets
                            .Select(static a => a.RelativePath ?? a.RecordName)
                            .ToList();
                        var preAuthN = _assets.GetPreAuthMmcsAuthHeaders().Count;
                        var enAuthN = enFetch?.MmcsAuthHeaders.Count ?? 0;

                        // #region agent log
                        // Always-on: Quiet salta AppendAgentNdjson — serve causa per-file.
                        try
                        {
                            var reasons = skipAuthAssets.Take(24).Select(static a =>
                            {
                                var hasAuth = HasUsableMmcsAuth(a.MmcsAuth);
                                var hasSig = a.AssetSignature is { Length: 21 };
                                var buildOk = hasSig
                                    && MmcsAuthBuilder.TryBuildFlistAuthorizeEntry(
                                        a.AssetSignature!, a.MmcsAuth) is not null;
                                string why;
                                if (!hasSig)
                                    why = "no_asset_signature";
                                else if (!hasAuth)
                                    why = "no_mmcs_auth_after_pb";
                                else if (!buildOk)
                                    why = "auth_present_but_build_entry_fail";
                                else
                                    why = "unexpected_skip";
                                return new
                                {
                                    path = a.RelativePath ?? a.RecordName,
                                    why,
                                    hasAuth,
                                    hasSig,
                                    authParts = string.IsNullOrWhiteSpace(a.MmcsAuth)
                                        ? 0
                                        : a.MmcsAuth!.Split(
                                            ' ', StringSplitOptions.RemoveEmptyEntries).Length,
                                    rid = a.RecordIdSuffix,
                                    size = a.SizeBytes,
                                    pc = a.ProtectionClass,
                                };
                            }).ToArray();
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                                JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "7dabb5",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                    ["message"] = "mmcs_auth_skip_detail",
                                    ["hypothesisId"] = "H-AUTH-GAP",
                                    ["runId"] = "auth-gap-v2",
                                    ["data"] = new
                                    {
                                        skipCount = skipAuthPaths.Count,
                                        readyCount = readyBatch.Count,
                                        cloneCount = cloneBatch.Count,
                                        preAuthInRam = preAuthN,
                                        enAuthInRam = enAuthN,
                                        anisetteBlocked,
                                        terminalFail = !anisetteBlocked,
                                        reasons,
                                    },
                                }) + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                        // #endregion

                        if (anisetteBlocked)
                        {
                            log?.Report(
                                $"  ERROR MmcsAuth: PrivilegedBatch incompleto (Anisette) per " +
                                $"{skipAuthPaths.Count} file — non marcati Falliti; " +
                                "ripari Anisette e riprendi lo snapshot.");
                        }
                        else
                        {
                            foreach (var skipped in skipAuthAssets)
                            {
                                NoteFileDownloaded(
                                    "mmcs_auth_skip", skipped.RelativePath ?? skipped.RecordName);
                                NoteDecryptFailed(
                                    "mmcs_auth_skip",
                                    skipped.RelativePath ?? skipped.RecordName,
                                    emitUiError: true,
                                    detail: "MmcsAuth/authorizeGet skip");
                            }

                            ReportMmcsAuthSkipSummary(skipAuthPaths, readyBatch.Count, log);
                        }

                        // #region agent log
                        AgentCountAlways("mmcs_auth_skip_summary", new
                        {
                            skipCount = skipAuthPaths.Count,
                            readyCount = readyBatch.Count,
                            cloneCount = cloneBatch.Count,
                            preAuthInRam = preAuthN,
                            enAuthInRam = enAuthN,
                            anisetteBlocked,
                            terminalFail = !anisetteBlocked,
                            sample = skipAuthPaths.Take(3).ToArray(),
                            hypothesis = "H-AUTH-JOIN",
                        });
                        // #endregion

                        if (readyBatch.Count == 0
                            && cloneBatch.Count == 0
                            && anisetteBlocked)
                        {
                            throw new InvalidOperationException(
                                $"MmcsAuth assente per {skipAuthPaths.Count} file: Anisette non disponibile " +
                                "dopo 401 (GET http://127.0.0.1:6971/). Avvia/ripara AnisetteServer e riprendi — " +
                                "niente mass-skip silenzioso.");
                        }
                    }

                    // Cloni già in coda copia (prima dell'auth); qui resta solo MMCS.
                    if (readyBatch.Count == 0)
                        return;

                    //  cache MMCS isolata per FL — wipe a domain_end.
                    var flCacheSafe = SanitizeFlCacheFolderName(
                        flAsset.RecordName, flIndex);
                    var flCacheDir = Path.Combine(workDir, "mmcs_cache", flCacheSafe);
                    Directory.CreateDirectory(flCacheDir);
                    var flMmcsSession = new MmcsChunkAssemblySession(flCacheDir);
                    _mmcsSessionLocal.Value = flMmcsSession;
                    {
                        var mode = flMmcsSession.Store.PersistToDisk ? "disk+ram" : "ram";
                        log?.Report(
                            $"  mmcs_cache FL{flIndex}: {mode} dir={flCacheSafe} " +
                            $"(IKE_MMCS_CACHE_DISK=1 per spill disco)");
                        flMmcsSession.Store.AgentRamCachePerfLog("session_start_fl");
                        // #region agent log
                        try
                        {
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                                JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "9a5651",
                                    ["runId"] = "fl-cache-v1",
                                    ["hypothesisId"] = "H-FL-ISO",
                                    ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                    ["message"] = "fl_mmcs_session_start",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["data"] = new
                                    {
                                        flIndex,
                                        record = flAsset.RecordName,
                                        flCacheDir,
                                        ready = readyBatch.Count,
                                        clones = cloneBatch.Count,
                                    },
                                }) + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                        // #endregion
                    }

                    // PrepareFiles: ck::Record BackupAsset già owned prima di AG/FillFord.
                    // Prefetch solo se PrepareFiles-bind non ha già parent+wrap dal PB.
                    await PrefetchOwnedBackupAssetPayloadsAsync(
                        session, readyBatch, workDir, log, ct)
                        .ConfigureAwait(false);

                    //  authorizeGet ×12, poi edge×8 — non un mega-AG sull'intero FL-slice.
                    var fileTotalUi = Math.Max(
                        estimatedTotal > 0 ? estimatedTotal : fileIndex + readyBatch.Count, 1);
                    for (var agOff = 0; agOff < readyBatch.Count; agOff += AuthorizeGetBatchSize)
                    {
                        ct.ThrowIfCancellationRequested();
                        var agChunk = readyBatch.GetRange(
                            agOff,
                            Math.Min(AuthorizeGetBatchSize, readyBatch.Count - agOff));
                        // #region agent log
                        AgentCountAlways("ag_chunk_start", new
                        {
                            flIndex,
                            readyTotal = readyBatch.Count,
                            agOff,
                            agChunk = agChunk.Count,
                            agCap = AuthorizeGetBatchSize,
                            edgeParallel = BackupEdgeDownloadParallelism,
                        });
                        // #endregion
                        var agSw = Environment.TickCount64;
                        FlistBatchRunResult? batchResult;
                        try
                        {
                            batchResult = await TryProcessFlistAuthorizeBatchAsync(
                                session,
                                contentHost,
                                agChunk,
                                workDir,
                                workDir,
                                fsWriter,
                                fileKeyCtx,
                                fileIndex,
                                fileTotalUi,
                                progress,
                                log,
                                ct).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch (Exception batchEx)
                        {
                            // Edge 500 / AG batch: non abortire lo snapshot — Falliti per i file del batch.
                            var isEdge = batchEx.Message.Contains("edge GET", StringComparison.Ordinal)
                                || batchEx is EdgeUrlExpiredException
                                || batchEx is AggregateException;
                            log?.Report(
                                $"  ERROR batch AG ({agChunk.Count} file): {batchEx.Message}" +
                                (isEdge ? " — continuo lo snapshot" : ""));
                            // #region agent log
                            try
                            {
                                File.AppendAllText(
                                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                                    JsonSerializer.Serialize(new Dictionary<string, object?>
                                    {
                                        ["sessionId"] = "b3df71",
                                        ["runId"] = "edge-500-continue-v1",
                                        ["hypothesisId"] = "H-EDGE-500",
                                        ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                        ["message"] = "ag_batch_exception_continue",
                                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                        ["data"] = new
                                        {
                                            flIndex,
                                            agChunk = agChunk.Count,
                                            errType = batchEx.GetType().Name,
                                            msg = batchEx.Message,
                                            isEdge,
                                        },
                                    }) + Environment.NewLine);
                            }
                            catch { /* ignore */ }
                            // #endregion
                            foreach (var planned in agChunk)
                            {
                                Interlocked.Increment(ref fileIndex);
                                downloaded.TryAdd(AssetDownloadKey(planned), 0);
                                var failPath = planned.RelativePath ?? planned.RecordName;
                                NoteFileDownloaded("ag_batch_ex", failPath);
                                NoteDecryptFailed(
                                    "edge_server",
                                    failPath,
                                    emitUiError: true,
                                    detail: batchEx.Message);
                                DecryptFailureJournal.Record(
                                    workDir,
                                    planned,
                                    "edge_server_error",
                                    batchEx.Message);
                            }
                            ReportFilesDoneProgress(
                                progress, Volatile.Read(ref writtenSharded),
                                Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                Volatile.Read(ref totalBytes));
                            continue;
                        }
                        var agMs = Environment.TickCount64 - agSw;

                        if (batchResult is not null)
                        {
                            // #region agent log
                            var ph = batchResult.Phases;
                            var pendingN = batchResult.Outcomes.Count(static o => o.PendingChunks);
                            AgentCountAlways("ag_chunk_ok", new
                            {
                                flIndex,
                                agChunk = agChunk.Count,
                                outcomes = batchResult.Outcomes.Count,
                                agMs,
                                authMs = ph?.AuthMs,
                                emptyHostMs = ph?.EmptyHostMs,
                                partsMs = ph?.PartsMs,
                                assembleMs = ph?.AssembleMs,
                                fillMs = ph?.FillMs,
                                decryptN = ph?.DecryptN,
                                domainParallel = ResolveDomainParallelism(),
                                edgeParallel = BackupEdgeDownloadParallelism,
                                decryptWorkers = ResolveDecryptWorkerParallelism(),
                                queued = batchResult.Outcomes.Count(static o => o.QueuedDecrypt),
                                pending = pendingN,
                                syncDone = batchResult.Outcomes.Count(static o =>
                                    !o.QueuedDecrypt && !o.PendingChunks),
                                hypothesis = "H-PHASE",
                            });
                            // #endregion
                            for (var i = 0; i < agChunk.Count; i++)
                            {
                                Interlocked.Increment(ref fileIndex);
                                downloaded.TryAdd(AssetDownloadKey(agChunk[i]), 0);
                                var one = batchResult.Outcomes[i];
                                if (one.QueuedDecrypt)
                                {
                                    // Scaricati già a schedule; Decifrati/Falliti a fine job.
                                    ReportFilesDoneProgress(
                                        progress, Volatile.Read(ref writtenSharded),
                                        Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                        Volatile.Read(ref totalBytes));
                                    continue;
                                }
                                if (one.PendingChunks)
                                {
                                    Interlocked.Increment(ref stagedChunks);
                                    ReportFilesDoneProgress(
                                        progress, Volatile.Read(ref writtenSharded),
                                        Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                        Volatile.Read(ref totalBytes));
                                    continue;
                                }

                                // FillChunks: contatori già applicati in RunDecryptJobAsync.
                                if (one.CountersApplied)
                                {
                                    if (one.Ok)
                                    {
                                        Interlocked.Increment(ref filesDone);
                                        Interlocked.Add(ref totalBytes, one.DownloadedBytes);
                                        if (one.WrittenSharded)
                                        {
                                            Interlocked.Increment(ref writtenSharded);
                                            RememberShardPath(agChunk[i], flShardBySig, cleanDir);
                                        }
                                        if (one.StagedChunks) Interlocked.Increment(ref stagedChunks);
                                        if (one.MmcsDecrypted) Interlocked.Increment(ref mmcsOk);
                                        if (one.FileDecrypted) Interlocked.Increment(ref fileDecryptOk);
                                    }
                                    ReportFilesDoneProgress(
                                        progress, Volatile.Read(ref writtenSharded),
                                        Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                        Volatile.Read(ref totalBytes));
                                    continue;
                                }

                                if (!one.Ok)
                                {
                                    var failPath = agChunk[i].RelativePath ?? agChunk[i].RecordName;
                                    NoteFileDownloaded("batch_fail", failPath);
                                    // Dettaglio già in ERROR size≠ / no-resolve — niente "batch_fail: ?".
                                    NoteDecryptFailed(
                                        "batch_fail",
                                        failPath,
                                        emitUiError: true,
                                        detail: "AG batch decrypt failed");
                                    ReportFilesDoneProgress(
                                        progress, Volatile.Read(ref writtenSharded),
                                        Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                        Volatile.Read(ref totalBytes));
                                    continue;
                                }

                                NoteSyncOrQueuedOutcome(one, "batch");
                                Interlocked.Increment(ref filesDone);
                                Interlocked.Add(ref totalBytes, one.DownloadedBytes);
                                if (one.WrittenSharded)
                                {
                                    Interlocked.Increment(ref writtenSharded);
                                    RememberShardPath(agChunk[i], flShardBySig, cleanDir);
                                }
                                if (one.StagedChunks) Interlocked.Increment(ref stagedChunks);
                                if (one.MmcsDecrypted) Interlocked.Increment(ref mmcsOk);
                                if (one.FileDecrypted) Interlocked.Increment(ref fileDecryptOk);
                                ReportFilesDoneProgress(
                                    progress, Volatile.Read(ref writtenSharded),
                                    Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                    Volatile.Read(ref totalBytes));
                            }

                            // PendingChunks: drain subito (niente solo Schedule) così non
                            // saturiamo MaxPendingFiles → evict di lavoro ancora aperto.
                            if (pendingN > 0)
                            {
                                await DrainMmcsPendingUntilIdleAsync(
                                    $"pending_batch_fl{flIndex}", maxRounds: 4,
                                    flShardBySig).ConfigureAwait(false);
                            }
                        }
                        else
                        {
                            // #region agent log
                            AgentCountAlways("ag_chunk_fallback", new
                            {
                                flIndex,
                                agChunk = agChunk.Count,
                                agMs,
                            });
                            // #endregion
                            foreach (var planned in agChunk)
                            {
                                ct.ThrowIfCancellationRequested();
                                Interlocked.Increment(ref fileIndex);
                                if (!downloaded.TryAdd(AssetDownloadKey(planned), 0))
                                    continue;

                                log?.Report(
                                    $"File {fileIndex}/{Math.Max(estimatedTotal, 1)}: {planned.RelativePath ?? planned.RecordName}");
                                ReportFilesDoneProgress(
                                    progress, writtenSharded,
                                    Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                    totalBytes);

                                var one = await DownloadAndDecryptAssetAsync(
                                    session,
                                    contentHost,
                                    planned,
                                    workDir,
                                    workDir,
                                    fsWriter,
                                    fileKeyCtx,
                                    fileIndex,
                                    Math.Max(estimatedTotal, 1),
                                    progress,
                                    log,
                                    ct).ConfigureAwait(false);

                                if (!one.Ok && !one.QueuedDecrypt)
                                {
                                    if (!one.PendingChunks)
                                    {
                                        NoteSyncOrQueuedOutcome(one, "single");
                                        ReportFilesDoneProgress(
                                            progress, writtenSharded,
                                            Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                            totalBytes);
                                    }
                                    continue;
                                }
                                if (one.QueuedDecrypt)
                                {
                                    NoteSyncOrQueuedOutcome(one, "single");
                                    ReportFilesDoneProgress(
                                        progress, writtenSharded,
                                        Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                        totalBytes);
                                    continue;
                                }

                                NoteSyncOrQueuedOutcome(one, "single");
                                Interlocked.Increment(ref filesDone);
                                Interlocked.Add(ref totalBytes, one.DownloadedBytes);
                                if (one.WrittenSharded)
                                {
                                    Interlocked.Increment(ref writtenSharded);
                                    RememberShardPath(planned, flShardBySig, cleanDir);
                                }
                                if (one.StagedChunks) Interlocked.Increment(ref stagedChunks);
                                if (one.FileDecrypted) Interlocked.Increment(ref fileDecryptOk);
                                if (one.MmcsDecrypted) Interlocked.Increment(ref mmcsOk);
                                ReportFilesDoneProgress(
                                    progress, Volatile.Read(ref writtenSharded),
                                    Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                    Volatile.Read(ref totalBytes));
                            }
                        }
                    }

                    // Chiudi i pending di questo domain prima di domain_end.
                    await DrainMmcsPendingUntilIdleAsync(
                        $"after_domain_fl{flIndex}", maxRounds: 8, flShardBySig)
                        .ConfigureAwait(false);
                    await ProcessEvictedPendingRetriesAsync(
                        $"after_domain_fl{flIndex}", shardMap: flShardBySig)
                        .ConfigureAwait(false);

                    //  cloni dopo che gli originali dello stesso FL sono su disco.
                    List<BackupAsset> clonesToFlush;
                    lock (flDeferredClones)
                    {
                        clonesToFlush = flDeferredClones.ToList();
                        flDeferredClones.Clear();
                    }
                    // Anche i cloni già "pronti" ma ancora in coda pump: riflush sync.
                    if (cloneBatch.Count > 0 && clonesToFlush.Count == 0)
                        clonesToFlush = cloneBatch.ToList();
                    else if (cloneBatch.Count > 0)
                    {
                        // Unisci senza dup.
                        var seenClone = new HashSet<string>(StringComparer.Ordinal);
                        foreach (var c in clonesToFlush)
                            seenClone.Add(AssetDownloadKey(c));
                        foreach (var c in cloneBatch)
                        {
                            if (seenClone.Add(AssetDownloadKey(c)))
                                clonesToFlush.Add(c);
                        }
                    }

                    if (clonesToFlush.Count > 0)
                    {
                        var stillMissing = new List<BackupAsset>();
                        await FlushReadyClonesAsync(
                            clonesToFlush, flShardBySig, stillMissing).ConfigureAwait(false);
                        if (stillMissing.Count > 0)
                        {
                            log?.Report(
                                $"  WARN FL{flIndex}: {stillMissing.Count} cloni senza " +
                                "originale nello stesso FL → coda demote download");
                            foreach (var a in stillMissing)
                                a.ContentFromExistingSignature = false;
                            // Post-domains: CopyClone (fallisce) → demote→AG (vedi sotto).
                            lock (deferredClones)
                                deferredClones.AddRange(stillMissing);
                            // #region agent log
                            try
                            {
                                File.AppendAllText(
                                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                                    JsonSerializer.Serialize(new Dictionary<string, object?>
                                    {
                                        ["sessionId"] = "9a5651",
                                        ["runId"] = "clone-gap-v1",
                                        ["hypothesisId"] = "H-CLONE-DEMOTE",
                                        ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                        ["message"] = "fl_clones_missing_queued_demote",
                                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                        ["data"] = new
                                        {
                                            flIndex,
                                            domain = domainName,
                                            missing = stillMissing.Count,
                                            flShardMap = flShardBySig.Count,
                                            sample = stillMissing.Take(5)
                                                .Select(static a => a.RelativePath ?? a.RecordName)
                                                .ToArray(),
                                        },
                                    }) + Environment.NewLine);
                            }
                            catch { /* ignore */ }
                            // #endregion
                        }
                    }

                    // #region agent log
                    domainExitReason = "completed_drained";
                    // #endregion

                    if (estimatedTotal > 0)
                        ReportFilesDoneProgress(
                            progress, Volatile.Read(ref writtenSharded), estimatedTotal,
                            Volatile.Read(ref totalBytes));
                }
                finally
                {
                    // Wipe cache per-FL (anche su early-exit dopo session start).
                    if (_mmcsSessionLocal.Value is { } flSess)
                    {
                        try
                        {
                            var pendingLeft = flSess.PendingCount;
                            // Fine FL: drop cache anche se restano pending (lavoro incompleto).
                            var cleared = flSess.ClearCacheIfIdle(log, force: true);
                            // #region agent log
                            try
                            {
                                File.AppendAllText(
                                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                                    JsonSerializer.Serialize(new Dictionary<string, object?>
                                    {
                                        ["sessionId"] = "9a5651",
                                        ["runId"] = "fl-cache-v1",
                                        ["hypothesisId"] = "H-FL-ISO",
                                        ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                                        ["message"] = "fl_mmcs_session_end",
                                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                        ["data"] = new
                                        {
                                            flIndex,
                                            pendingLeft,
                                            cleared,
                                            exitReason = domainExitReason,
                                        },
                                    }) + Environment.NewLine);
                            }
                            catch { /* ignore */ }
                            // #endregion
                            try
                            {
                                var dir = flSess.Store.RootDirectory;
                                if (Directory.Exists(dir)
                                    && dir.IndexOf(
                                        $"{Path.DirectorySeparatorChar}mmcs_cache{Path.DirectorySeparatorChar}",
                                        StringComparison.OrdinalIgnoreCase) >= 0)
                                {
                                    Directory.Delete(dir, recursive: true);
                                }
                            }
                            catch { /* best-effort */ }
                        }
                        catch { /* ignore wipe errors */ }
                        finally
                        {
                            _mmcsSessionLocal.Value = null;
                        }
                    }

                    domainSw.Stop();
                    var left = Interlocked.Decrement(ref domainsActive);
                    // #region agent log
                    if (domainExitReason == "running")
                        domainExitReason = "completed_try";
                    try
                    {
                        var payload = new Dictionary<string, object?>
                        {
                            ["flIndex"] = flIndex,
                            ["flTotal"] = flTotal,
                            ["activeLeft"] = left,
                            ["elapsedMs"] = domainSw.ElapsedMilliseconds,
                            ["filesDone"] = Volatile.Read(ref filesDone),
                            ["writtenSharded"] = Volatile.Read(ref writtenSharded),
                            ["domain"] = domainName,
                            ["slice"] = domainSliceN,
                            ["clones"] = domainClonesN,
                            ["needDownload"] = domainNeedN,
                            ["skipAuth"] = domainSkipAuthN,
                            ["exitReason"] = domainExitReason,
                            ["record"] = flAsset.RecordName,
                        };
                        var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "7dabb5",
                            ["runId"] = "ike-orch",
                            ["hypothesisId"] = "H-ORCH",
                            ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                            ["message"] = "domain_end",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = payload,
                        });
                        IkeLogOptions.AppendAgentNdjson(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                            line);
                        var line2 = JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "9a5651",
                            ["runId"] = "fl-incomplete-v1",
                            ["hypothesisId"] = "H5",
                            ["location"] = "BackupDownloadService.ProcessOneDomainAsync",
                            ["message"] = "domain_end",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = payload,
                        });
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                            line2 + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion
                    domainGate.Release();
                }
            }

            // Totale definitivo ≥ inventario snapshot e ≥ pianificati flist (mai solo flTotal).
            {
                var finalDenom = Math.Max(catalogAssets, backupBoundPlanned);
                if (finalDenom > 0)
                {
                    estimatedTotal = maxFiles < int.MaxValue
                        ? Math.Min(finalDenom, maxFiles)
                        : finalDenom;
                }
                // #region agent log
                AgentCountAlways("backup_total_final", new
                {
                    backupBoundPlanned,
                    catalogAssets,
                    estimatedTotal,
                    declaredAssets = declared.Assets,
                    directories = declared.Directories,
                    empty = declared.EmptyFiles,
                    hypothesis = "H-TOTAL-SNAP",
                });
                // #endregion
            }

            // Prima il drain decrypt (ReleaseDataChunks con pending-guard), poi refetch+finalize.
            var flDrain = await DrainPendingDecryptTasksAsync(
                shardBySig, cleanDir, progress, log, ct).ConfigureAwait(false);
            filesDone += flDrain.Completed;
            totalBytes += flDrain.TotalBytes;
            writtenSharded += flDrain.WrittenSharded;
            stagedChunks += flDrain.StagedChunks;
            mmcsOk += flDrain.MmcsOk;
            fileDecryptOk += flDrain.FileDecryptOk;
            if (estimatedTotal > 0)
                ReportFilesDoneProgress(progress, writtenSharded, estimatedTotal, totalBytes);

            if (_mmcsChunkSession is { PendingCount: > 0 })
            {
                log?.Report(
                    $"mmcs_cache: {_mmcsChunkSession.PendingCount} file in attesa — refetch+finalizzazione…");
                var finalized = await FinalizePendingChunkFilesAsync(
                    session,
                    workDir,
                    workDir,
                    fsWriter,
                    fileKeyCtx,
                    Math.Max(estimatedTotal, 1),
                    progress,
                    log,
                    ct,
                    shardBySig,
                    cleanDir).ConfigureAwait(false);
                foreach (var one in finalized)
                {
                    NoteSyncOrQueuedOutcome(one, "fl_finalize");
                    if (one.QueuedDecrypt)
                        continue;
                    if (!one.Ok)
                        continue;
                    filesDone++;
                    totalBytes += one.DownloadedBytes;
                    if (one.WrittenSharded) writtenSharded++;
                    if (one.StagedChunks) stagedChunks++;
                    if (one.MmcsDecrypted) mmcsOk++;
                    if (one.FileDecrypted) fileDecryptOk++;
                }

                if (estimatedTotal > 0)
                    ReportFilesDoneProgress(progress, writtenSharded, estimatedTotal, totalBytes);

                // Finalize può aver messo altri job in coda decrypt → drain prima dei clone.
                if (_pendingDecryptTasks.Count > 0)
                {
                    var flDrain2 = await DrainPendingDecryptTasksAsync(
                        shardBySig, cleanDir, progress, log, ct).ConfigureAwait(false);
                    filesDone += flDrain2.Completed;
                    totalBytes += flDrain2.TotalBytes;
                    writtenSharded += flDrain2.WrittenSharded;
                    stagedChunks += flDrain2.StagedChunks;
                    mmcsOk += flDrain2.MmcsOk;
                    fileDecryptOk += flDrain2.FileDecryptOk;
                }

                if (_mmcsChunkSession.PendingCount > 0)
                    _mmcsChunkSession.DescribeStillPending(log);
                else
                    _mmcsChunkSession.ClearCacheIfIdle(log);
            }
            else
            {
                _mmcsChunkSession?.ClearCacheIfIdle(log);
            }

            // H-DUP: cloni dopo che shardBySig è popolato (drain + finalize).
            if (deferredClones.Count > 0)
            {
                var cloneBatchNow = deferredClones;
                deferredClones = [];
                var cloneCopied = 0;
                var cloneResult = await CopyCloneAssetsAsync(
                    cloneBatchNow, shardBySig, fsWriter, cleanDir, log, ct, deviceDir,
                    onCopied: (a, bytes) =>
                    {
                        // Cloni: Scaricati/Decifrati/Duplicati + byte Dati (SizeBytes clone).
                        NoteCloneFileCopied(a.RelativePath ?? a.RecordName, bytes);
                        if (bytes > 0)
                            Interlocked.Add(ref totalBytes, bytes);
                        Interlocked.Increment(ref filesDone);
                        Interlocked.Increment(ref writtenSharded);
                        var n = Interlocked.Increment(ref cloneCopied);
                        if (n == 1 || n % 25 == 0)
                        {
                            ReportFilesDoneProgress(
                                progress,
                                Volatile.Read(ref writtenSharded),
                                Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                                Volatile.Read(ref totalBytes));
                        }
                    },
                    allowCrossFlOrPrior: false)
                    .ConfigureAwait(false);
                ReportFilesDoneProgress(
                    progress,
                    Volatile.Read(ref writtenSharded),
                    Math.Max(estimatedTotal > 0 ? estimatedTotal : 1, 1),
                    Volatile.Read(ref totalBytes));

                if (cloneResult.Missing.Count > 0)
                {
                    log?.Report(
                        $"  clone demote→download: {cloneResult.Missing.Count} path " +
                        "(sorgente assente dopo drain)");
                    // #region agent log
                    AgentDebugLog(
                        "H-DUP",
                        "BackupDownloadService.DownloadSnapshotAsync",
                        "clone_demote_download",
                        new { demoted = cloneResult.Missing.Count, copied = cloneResult.Copied },
                        runId: "clone-fix-v1");
                    // #endregion

                    foreach (var a in cloneResult.Missing)
                        a.ContentFromExistingSignature = false;

                    // Stesso cap ×12 del path FL principale: un mega-AG (es. 14k)
                    // fa OOM in ParseAuthorizeGetFiles (host×file concat) → fallback monofile.
                    var demoteMissing = cloneResult.Missing;
                    var demoteTotalUi = Math.Max(
                        estimatedTotal > 0 ? estimatedTotal : fileIndex + demoteMissing.Count, 1);
                    for (var demoteOff = 0;
                         demoteOff < demoteMissing.Count;
                         demoteOff += AuthorizeGetBatchSize)
                    {
                        ct.ThrowIfCancellationRequested();
                        var demoteChunk = demoteMissing.GetRange(
                            demoteOff,
                            Math.Min(AuthorizeGetBatchSize, demoteMissing.Count - demoteOff));

                            FlistBatchRunResult? demoteResult;
                        try
                        {
                            demoteResult = await TryProcessFlistAuthorizeBatchAsync(
                                session,
                                contentHost,
                                demoteChunk,
                                workDir,
                                workDir,
                                fsWriter,
                                fileKeyCtx,
                                fileIndex,
                                demoteTotalUi,
                                progress,
                                log,
                                ct).ConfigureAwait(false);
                        }
                        catch (OperationCanceledException)
                        {
                            throw;
                        }
                        catch (Exception demoteEx)
                        {
                            log?.Report(
                                $"  ERROR demote AG ({demoteChunk.Count} file): {demoteEx.Message} — continuo");
                            foreach (var planned in demoteChunk)
                            {
                                fileIndex++;
                                downloaded.TryAdd(AssetDownloadKey(planned), 0);
                                var failPath = planned.RelativePath ?? planned.RecordName;
                                NoteFileDownloaded("demote_ag_ex", failPath);
                                log?.Report(
                                    $"  ERROR {failPath}: demote batch — {demoteEx.Message}");
                                NoteDecryptFailed(
                                    "edge_server",
                                    failPath,
                                    emitUiError: true,
                                    detail: demoteEx.Message);
                                DecryptFailureJournal.Record(
                                    workDir, planned, "edge_server_error", demoteEx.Message);
                            }

                            continue;
                        }

                        if (demoteResult is not null)
                        {
                            var demotePendingN = 0;
                            for (var i = 0; i < demoteChunk.Count; i++)
                            {
                                fileIndex++;
                                downloaded.TryAdd(AssetDownloadKey(demoteChunk[i]), 0);
                                var one = demoteResult.Outcomes[i];
                                if (one.QueuedDecrypt)
                                {
                                    NoteSyncOrQueuedOutcome(one, "clone_demote");
                                    continue;
                                }

                                if (one.PendingChunks)
                                {
                                    demotePendingN++;
                                    stagedChunks++;
                                    continue;
                                }

                                if (!one.Ok)
                                {
                                    NoteSyncOrQueuedOutcome(one, "clone_demote");
                                    continue;
                                }

                                NoteSyncOrQueuedOutcome(one, "clone_demote");
                                filesDone++;
                                totalBytes += one.DownloadedBytes;
                                if (one.WrittenSharded)
                                {
                                    writtenSharded++;
                                    RememberShardPath(demoteChunk[i], shardBySig, cleanDir);
                                }

                                if (one.StagedChunks) stagedChunks++;
                                if (one.MmcsDecrypted) mmcsOk++;
                                if (one.FileDecrypted) fileDecryptOk++;
                            }

                            if (demotePendingN > 0)
                            {
                                await DrainMmcsPendingUntilIdleAsync(
                                    "clone_demote_pending", maxRounds: 6)
                                    .ConfigureAwait(false);
                            }

                            continue;
                        }

                        // Chunk AG fallito → monofile (niente skip silenzioso dei demote).
                        foreach (var planned in demoteChunk)
                        {
                            ct.ThrowIfCancellationRequested();
                            fileIndex++;
                            if (!downloaded.TryAdd(AssetDownloadKey(planned), 0))
                                continue;

                            var one = await DownloadAndDecryptAssetAsync(
                                session,
                                contentHost,
                                planned,
                                workDir,
                                workDir,
                                fsWriter,
                                fileKeyCtx,
                                fileIndex,
                                demoteTotalUi,
                                progress,
                                log,
                                ct).ConfigureAwait(false);

                            if (one.QueuedDecrypt || one.PendingChunks)
                            {
                                NoteSyncOrQueuedOutcome(one, "clone_demote_single");
                                if (one.PendingChunks)
                                {
                                    stagedChunks++;
                                    await DrainMmcsPendingUntilIdleAsync(
                                        "clone_demote_single_pending", maxRounds: 4)
                                        .ConfigureAwait(false);
                                }

                                continue;
                            }

                            if (!one.Ok)
                            {
                                NoteSyncOrQueuedOutcome(one, "clone_demote_single");
                                continue;
                            }

                            NoteSyncOrQueuedOutcome(one, "clone_demote_single");
                            filesDone++;
                            totalBytes += one.DownloadedBytes;
                            if (one.WrittenSharded)
                            {
                                writtenSharded++;
                                RememberShardPath(planned, shardBySig, cleanDir);
                            }

                            if (one.StagedChunks) stagedChunks++;
                            if (one.MmcsDecrypted) mmcsOk++;
                            if (one.FileDecrypted) fileDecryptOk++;
                        }
                    }

                    if (_pendingDecryptTasks.Count > 0)
                    {
                        var demoteDrain = await DrainPendingDecryptTasksAsync(
                            shardBySig, cleanDir, progress, log, ct).ConfigureAwait(false);
                        filesDone += demoteDrain.Completed;
                        totalBytes += demoteDrain.TotalBytes;
                        writtenSharded += demoteDrain.WrittenSharded;
                        stagedChunks += demoteDrain.StagedChunks;
                        mmcsOk += demoteDrain.MmcsOk;
                        fileDecryptOk += demoteDrain.FileDecryptOk;
                    }

                    await DrainMmcsPendingUntilIdleAsync("clone_demote_end", maxRounds: 8)
                        .ConfigureAwait(false);
                    await ProcessEvictedPendingRetriesAsync("clone_demote").ConfigureAwait(false);

                    if (_mmcsChunkSession is { PendingCount: > 0 })
                    {
                        var demoteFinal = await FinalizePendingChunkFilesAsync(
                            session, workDir, workDir, fsWriter, fileKeyCtx,
                            Math.Max(estimatedTotal, 1), progress, log, ct,
                            shardBySig, cleanDir).ConfigureAwait(false);
                        foreach (var one in demoteFinal)
                        {
                            NoteSyncOrQueuedOutcome(one, "clone_demote_finalize");
                            if (one.QueuedDecrypt || !one.Ok)
                                continue;
                            filesDone++;
                            totalBytes += one.DownloadedBytes;
                            if (one.WrittenSharded) writtenSharded++;
                            if (one.StagedChunks) stagedChunks++;
                            if (one.MmcsDecrypted) mmcsOk++;
                            if (one.FileDecrypted) fileDecryptOk++;
                        }

                        if (_pendingDecryptTasks.Count > 0)
                        {
                            var demoteDrain2 = await DrainPendingDecryptTasksAsync(
                                shardBySig, cleanDir, progress, log, ct).ConfigureAwait(false);
                            filesDone += demoteDrain2.Completed;
                            totalBytes += demoteDrain2.TotalBytes;
                            writtenSharded += demoteDrain2.WrittenSharded;
                            stagedChunks += demoteDrain2.StagedChunks;
                            mmcsOk += demoteDrain2.MmcsOk;
                            fileDecryptOk += demoteDrain2.FileDecryptOk;
                        }
                    }
                }

                if (estimatedTotal > 0)
                    ReportFilesDoneProgress(progress, writtenSharded, estimatedTotal, totalBytes);
            }

            var manifestRebuild = await ManifestFromFileListBuilder.RebuildAsync(
                workDir, domainBySig, log, ct, cleanDir).ConfigureAwait(false);
            // #region agent log
            AgentCountAlways("manifest_rebuild_done", new
            {
                rowsUpserted = manifestRebuild.RowsUpserted,
                fileListDatabases = manifestRebuild.FileListDatabases,
                domainsResolved = manifestRebuild.DomainsResolved,
                skippedNoDomain = manifestRebuild.SkippedNoDomain,
                catalogAssets,
                backupBoundPlanned,
                writtenSharded,
                hypothesis = "H-GAP-MANIFEST",
            });
            // #endregion

            log?.Report(
                $"interleaved: FL={flIndex}/{flTotal}, asset={filesDone} " +
                "(query/retrieve→MmcsAuth, authorizeGet f1=assetSignature→edge)");
        }
        else
        {
            // Path classico M:/KA:: stesso per-asset decrypt, senza fasi FL.
            var classicTotal = assets.Count;
            log?.Report(
                $"Download per-asset: payload→meta→authorizeGet→edge→MMCS→class-key ×{classicTotal}");
            var classicIndex = 0;
            foreach (var asset in assets)
            {
                ct.ThrowIfCancellationRequested();
                classicIndex++;
                await ProcessOneAsync(
                    asset, "Asset", classicIndex, classicTotal,
                    writtenSharded, classicTotal);
                ReportFilesDoneProgress(progress, writtenSharded, classicTotal, totalBytes);
            }
        }

        // Fine snapshot: attendi decrypt async residui, poi sidecar iTunes.
        var endDrain = await DrainPendingDecryptTasksAsync(
            null, cleanDir, progress, log, ct).ConfigureAwait(false);
        totalBytes += endDrain.TotalBytes;
        writtenSharded += endDrain.WrittenSharded;
        stagedChunks += endDrain.StagedChunks;
        mmcsOk += endDrain.MmcsOk;
        fileDecryptOk += endDrain.FileDecryptOk;

        if (_decryptQueue is not null)
            await _decryptQueue.DisposeAsync().ConfigureAwait(false);
        _decryptQueue = null;

        await WriteItunesSidecarsAtEndOfSnapshotAsync(
            session, job, log, ct).ConfigureAwait(false);

        log?.Report(
            $"layout: sharded={writtenSharded}, staged=.chunks/{stagedChunks}, " +
            $"mmcsDecrypt={mmcsOk}, fileDecrypt={fileDecryptOk}, " +
            $"processati={downloaded.Count} | pulito={cleanDir}");

        DecryptFailureJournal.WriteSummary(workDir, log);

        var doneTotal = Math.Max(estimatedTotal > 0 ? estimatedTotal : writtenSharded, 1);
        var uiDecrypted = Volatile.Read(ref _uiFilesDecrypted);
        var uiDownloaded = Volatile.Read(ref _uiFilesDownloaded);
        var uiFailed = Volatile.Read(ref _uiFilesDecryptFailed);
        var uiCipher = Volatile.Read(ref _uiFilesCiphertextSaved);
        // #region agent log
        try
        {
            var manifestPath = Path.Combine(cleanDir, "Manifest.db");
            var manifestFiles = 0;
            var manifestDirs = 0;
            var diskPayload = 0;
            var ghostFiles = 0;
            if (File.Exists(manifestPath))
            {
                await using var mcon = new Microsoft.Data.Sqlite.SqliteConnection(
                    $"Data Source={manifestPath};Mode=ReadOnly");
                await mcon.OpenAsync(ct).ConfigureAwait(false);
                await using (var cmd = mcon.CreateCommand())
                {
                    cmd.CommandText = "SELECT flags, COUNT(*) FROM Files GROUP BY flags;";
                    await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                    while (await r.ReadAsync(ct).ConfigureAwait(false))
                    {
                        var flags = r.GetInt32(0);
                        var n = r.GetInt32(1);
                        if (flags == 1) manifestFiles = n;
                        else if (flags == 2) manifestDirs = n;
                    }
                }

                await using (var cmd = mcon.CreateCommand())
                {
                    cmd.CommandText = "SELECT fileID FROM Files WHERE flags = 1;";
                    await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
                    while (await r.ReadAsync(ct).ConfigureAwait(false))
                    {
                        var fid = r.GetString(0);
                        if (fid.Length < 2) { ghostFiles++; continue; }
                        var p = Path.Combine(cleanDir, fid[..2], fid);
                        if (File.Exists(p)) diskPayload++;
                        else ghostFiles++;
                    }
                }
            }

            var gapPayload = new
            {
                catalogAssets = doneTotal,
                backupBoundPlanned,
                writtenSharded,
                uiDownloaded,
                uiDecrypted,
                uiFailed,
                uiCipher,
                manifestFiles,
                manifestDirs,
                manifestTotal = manifestFiles + manifestDirs,
                diskPayload,
                ghostFiles,
                mmcsOk,
                fileDecryptOk,
                bytesDownloaded = totalBytes,
                bytesTotalUi = Volatile.Read(ref _uiBytesTotal),
                missingAssets = Math.Max(0, doneTotal - uiDecrypted),
                hypothesis = "H-GAP-1GB",
            };
            AgentCountAlways("snapshot_gap_summary", gapPayload);
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "b3df71",
                    ["runId"] = "gap-49k-32k",
                    ["hypothesisId"] = "H-GAP-49K-32K",
                    ["location"] = "BackupDownloadService.DownloadSnapshotAsync",
                    ["message"] = "snapshot_gap_summary",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = gapPayload,
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #region agent log
            try
            {
                var line4 = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "4ff690",
                    ["runId"] = "gap-1gb-v1",
                    ["hypothesisId"] = "H-GAP-1GB",
                    ["location"] = "BackupDownloadService.DownloadSnapshotAsync",
                    ["message"] = "snapshot_gap_summary",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = gapPayload,
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\AIAgent\debug-4ff690.log",
                    line4 + Environment.NewLine);
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-4ff690.log",
                    line4 + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion

            log?.Report(
                $"  gap check: UI {uiDecrypted:N0}/{doneTotal:N0} decifrati; " +
                $"Manifest rows={manifestFiles + manifestDirs:N0} (file={manifestFiles:N0}, dir={manifestDirs:N0}); " +
                $"payload su disco={diskPayload:N0}, ghost Manifest senza file={ghostFiles:N0}");
            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "9a5651",
                    ["runId"] = "fl-incomplete-v1",
                    ["hypothesisId"] = "H4",
                    ["location"] = "BackupDownloadService.DownloadSnapshotAsync",
                    ["message"] = "snapshot_gap_summary",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = gapPayload,
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
        }
        catch { /* ignore gap probe */ }
        // #endregion
        ReportFilesDoneProgress(progress, uiDecrypted, doneTotal, totalBytes);
        progress?.Report(new DownloadProgressReport
        {
            // Completato = solo successi decrypt (= Decifrati), non writtenSharded grezzo.
            AssetsCompleted = uiDecrypted,
            AssetsTotal = doneTotal,
            FilesDownloaded = uiDownloaded,
            FilesDecrypted = uiDecrypted,
            FilesDecryptFailed = uiFailed,
            FilesCiphertextSaved = uiCipher,
            FilesTotal = doneTotal,
            DecryptQueued = CurrentDecryptQueueDepth(),
            BytesDownloaded = totalBytes,
            TotalBytes = Math.Max(_uiBytesTotal, totalBytes),
            ReportSequence = Interlocked.Increment(ref _progressReportSeq),
            AppendToLog = true,
            Status =
                $"Completato: {uiDecrypted:N0}/{doneTotal:N0} file scaricati e decifrati " +
                $"(falliti={uiFailed:N0}, cifrati={uiCipher:N0}, staged={stagedChunks}, " +
                $"MMCS={mmcsOk}, AES={fileDecryptOk}) → Backup/"
        });
        }
        finally
        {
            // Fine snapshot: wipe forzato (durante i batch solo release dei file Ok).
            try { _mmcsChunkSession?.ClearCacheIfIdle(log, force: true); }
            catch { /* ignore */ }
            _mmcsChunkSession = null;
            var deleted = IkeBackupOutputPaths.TryDeleteTmpDirectory(snapshotRoot, log);
            // #region agent log
            try
            {
                var tmpPath = IkeBackupOutputPaths.ResolveTmpDirectory(snapshotRoot);
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "BackupDownloadService.DownloadSnapshotAsync",
                    ["message"] = "snapshot_tmp_deleted",
                    ["hypothesisId"] = "H-TMP-LAYOUT",
                    ["runId"] = "tmp-layout-v1",
                    ["data"] = new
                    {
                        snapshotRoot,
                        tmpPath,
                        deleted,
                        tmpStillExists = Directory.Exists(tmpPath),
                        backupExists = Directory.Exists(
                            IkeBackupOutputPaths.ResolveCleanBackupDirectory(snapshotRoot)),
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
        }
    }

    private void NoteFileDownloaded(string? where = null, string? path = null)
    {
        var n = Interlocked.Increment(ref _uiFilesDownloaded);
        // #region agent log
        AgentCountAlways("count_downloaded", new
        {
            where,
            path,
            n,
            decrypted = Volatile.Read(ref _uiFilesDecrypted),
            failed = Volatile.Read(ref _uiFilesDecryptFailed),
            queue = CurrentDecryptQueueDepth(),
        });
        // #endregion
    }

    /// <summary>
    /// Annulla uno <see cref="NoteFileDownloaded"/> quando un job già schedulato
    /// torna Pending / ok-meta (niente Decifrati né Falliti) — altrimenti
    /// Scaricati &gt; Decifrati con Coda=0 e zero errori.
    /// </summary>
    private void UndoFileDownloaded(string? where = null, string? path = null)
    {
        while (true)
        {
            var dl = Volatile.Read(ref _uiFilesDownloaded);
            var dec = Volatile.Read(ref _uiFilesDecrypted);
            var fail = Volatile.Read(ref _uiFilesDecryptFailed);
            if (dl <= 0)
                return;
            // Non scendere sotto gli esiti già chiusi.
            if (dl - 1 < dec + fail)
                return;
            if (Interlocked.CompareExchange(ref _uiFilesDownloaded, dl - 1, dl) == dl)
            {
                // #region agent log
                AgentCountAlways("count_downloaded_undo", new
                {
                    where,
                    path,
                    n = dl - 1,
                    decrypted = dec,
                    failed = fail,
                    queue = CurrentDecryptQueueDepth(),
                    pendingMmcs = CurrentPendingChunkFiles(),
                    hypothesis = "H-PENDING-GAP",
                });
                // #endregion
                return;
            }
        }
    }

    private void NoteFileDecrypted(string? where = null, string? path = null)
    {
        // Scaricati è la base indipendente. Decifrati+Falliti non possono superarla.
        // La coda NON entra nel guard: tra NoteDecryptJobFinished e qui un nuovo
        // schedule alza q e rifiuterebbe un esito legittimo (race H-COUNT-RACE).
        while (true)
        {
            var dl = Volatile.Read(ref _uiFilesDownloaded);
            var dec = Volatile.Read(ref _uiFilesDecrypted);
            var fail = Volatile.Read(ref _uiFilesDecryptFailed);
            var q = CurrentDecryptQueueDepth();
            if (dec + fail >= dl)
            {
                // #region agent log
                AgentCountAlways("count_decrypted_rejected", new
                {
                    where,
                    path,
                    dl,
                    dec,
                    fail,
                    q,
                    hypothesis = "H-COUNT-BASE",
                });
                // #endregion
                return;
            }

            if (Interlocked.CompareExchange(ref _uiFilesDecrypted, dec + 1, dec) == dec)
            {
                // #region agent log
                AgentCountAlways("count_decrypted", new
                {
                    where,
                    path,
                    n = dec + 1,
                    downloaded = dl,
                    failed = fail,
                    queue = q,
                    sumOutcomes = dec + 1 + fail,
                    hypothesis = "H-COUNT-BASE",
                });
                // #endregion
                return;
            }
        }
    }

    /// <summary>
    /// Body in Backup/ ancora ciphertext MMCS/Ford (Ford/MMCS non riuscito).
    /// Non usare <c>!FileDecrypted</c>: su bag moderni FileDecrypted=false è normale
    /// (class-key AES saltato) mentre il body è già plaintext post-Ford — altrimenti
    /// il contatore «Cifrati» gonfia a ~tutti i file (scan: ~1–2% reali).
    /// </summary>
    private void NoteCiphertextSaved(string? where = null, string? path = null)
    {
        var n = Interlocked.Increment(ref _uiFilesCiphertextSaved);
        // #region agent log
        AgentCountAlways("count_ciphertext", new
        {
            where,
            path,
            n,
            downloaded = Volatile.Read(ref _uiFilesDownloaded),
            decrypted = Volatile.Read(ref _uiFilesDecrypted),
            failed = Volatile.Read(ref _uiFilesDecryptFailed),
            hypothesis = "H-CIPHER-SEM",
            runId = "cipher-count-mmcs-v1",
        });
        // #endregion
    }

    /// <summary>
    /// Conta come «Cifrati» solo se scritto in Backup/ e MMCS/Ford non ha prodotto plaintext.
    /// </summary>
    private static bool CountsAsCiphertextOnDisk(in AssetDownloadOutcome one) =>
        one.WrittenSharded && !one.MmcsDecrypted;

    private void NoteDecryptFailed(
        string? where = null,
        string? path = null,
        bool emitUiError = true,
        string? detail = null)
    {
        // Ogni errore DEVE incrementare Falliti e comparire nel tab Errori.
        // Se Scaricati è già bilanciato (dec+fail >= dl), alza Scaricati — non scartare il fail.
        var ensuredDl = false;
        while (true)
        {
            var dl = Volatile.Read(ref _uiFilesDownloaded);
            var dec = Volatile.Read(ref _uiFilesDecrypted);
            var fail = Volatile.Read(ref _uiFilesDecryptFailed);
            var q = CurrentDecryptQueueDepth();
            if (dec + fail >= dl)
            {
                if (!ensuredDl)
                {
                    NoteFileDownloaded(
                        string.IsNullOrWhiteSpace(where) ? "fail_ensure_dl" : where + "_ensure_dl",
                        path);
                    ensuredDl = true;
                    // #region agent log
                    try
                    {
                        var rej = JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "4ff690",
                            ["runId"] = "fail-count-v2",
                            ["hypothesisId"] = "H-FAIL-UI",
                            ["location"] = "BackupDownloadService.NoteDecryptFailed",
                            ["message"] = "count_failed_ensure_downloaded",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new { where, path, dl, dec, fail, q },
                        });
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\AIAgent\debug-4ff690.log",
                            rej + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion
                    continue;
                }

                // #region agent log
                AgentCountAlways("count_failed_rejected", new
                {
                    where,
                    path,
                    dl,
                    dec,
                    fail,
                    q,
                    hypothesis = "H-COUNT-BASE",
                });
                // #endregion
                // Ultimo fallback: forza ++Falliti comunque (UI non deve mentire).
                Interlocked.Increment(ref _uiFilesDecryptFailed);
                EmitDecryptFailedUi(where, path, detail, emitUiError: true);
                return;
            }

            if (Interlocked.CompareExchange(ref _uiFilesDecryptFailed, fail + 1, fail) == fail)
            {
                EmitDecryptFailedUi(where, path, detail, emitUiError: true);
                // #region agent log
                AgentCountAlways("count_failed", new
                {
                    where,
                    path,
                    n = fail + 1,
                    downloaded = Volatile.Read(ref _uiFilesDownloaded),
                    decrypted = dec,
                    queue = q,
                    sumOutcomes = dec + fail + 1,
                    detail,
                    hypothesis = "H-FAIL-UI",
                });
                try
                {
                    var ok = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "4ff690",
                        ["runId"] = "fail-count-v2",
                        ["hypothesisId"] = "H-FAIL-UI",
                        ["location"] = "BackupDownloadService.NoteDecryptFailed",
                        ["message"] = "count_failed",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            where,
                            path,
                            n = fail + 1,
                            dl = Volatile.Read(ref _uiFilesDownloaded),
                            dec,
                            detail,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\AIAgent\debug-4ff690.log",
                        ok + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                return;
            }
        }
    }

    private void EmitDecryptFailedUi(
        string? where,
        string? path,
        string? detail,
        bool emitUiError)
    {
        if (!emitUiError)
            return;
        var reason = string.IsNullOrWhiteSpace(where) ? "decrypt" : where;
        var label = string.IsNullOrWhiteSpace(path) ? "?" : path;
        var msg = string.IsNullOrWhiteSpace(detail)
            ? $"  ERROR decrypt fallito ({reason}): {label}"
            : $"  ERROR decrypt fallito ({reason}): {label} — {detail}";
        _downloadLog?.Report(msg);
    }

    private void NoteFileDuplicated() =>
        Interlocked.Increment(ref _uiFilesDuplicated);

    /// <summary>
    /// Contatori UI — Scaricati è la base (primo, indipendente):
    /// - QueuedDecrypt → Scaricati già ++ a <see cref="NoteDecryptJobScheduled"/>;
    ///   poi Decifrati o Falliti a fine job (mai entrambi; mai oltre Scaricati)
    /// - Terminal sync con <see cref="AssetDownloadOutcome.WrittenSharded"/> → Scaricati+Decifrati
    /// - Ok senza shard (FL: flist DB, staging) → fuori dalle barre Backup/ (non Falliti)
    /// </summary>
    private void NoteSyncOrQueuedOutcome(AssetDownloadOutcome one, string where)
    {
        // Contatori già applicati dal decrypt worker — non ricontare (batch/wave_finalize).
        if (one.CountersApplied)
        {
            // #region agent log
            AgentCountAlways("sync_skip_counters_applied", new
            {
                where,
                ok = one.Ok,
                written = one.WrittenSharded,
                hypothesis = "H-DOUBLE-COUNT",
            });
            // #endregion
            AgentDlCountLog(where + "_counters_already_applied", one);
            return;
        }

        if (one.QueuedDecrypt)
        {
            // #region agent log
            AgentDlCountLog(where + "_queued", one);
            // #endregion
            return;
        }

        if (one.PendingChunks)
            return;

        if (!one.Ok)
        {
            NoteFileDownloaded(where + "_terminal", null);
            NoteDecryptFailed(
                where + "_fail",
                null,
                emitUiError: true,
                detail: "terminal sync fail");
            if (CountsAsCiphertextOnDisk(one))
                NoteCiphertextSaved(where + "_fail_cipher", null);
            // #region agent log
            AgentDlCountLog(where + "_fail", one);
            // #endregion
            return;
        }

        if (one.WrittenSharded)
        {
            NoteFileDownloaded(where + "_terminal", null);
            NoteFileDecrypted(where + "_sync_written", null);
            if (CountsAsCiphertextOnDisk(one))
                NoteCiphertextSaved(where + "_sync_cipher", null);
            // #region agent log
            AgentDlCountLog(where + "_sync_written", one);
            // #endregion
            return;
        }

        // Ok ma non in Backup/: tipicamente download FL: (materializza flist_*.db)
        // o .chunks staging — NON è decrypt fallito. Non gonfiare Scaricati/Falliti.
        // #region agent log
        AgentCountAlways("ok_not_sharded_ignored", new
        {
            where,
            staged = one.StagedChunks,
            mmcs = one.MmcsDecrypted,
            fileAes = one.FileDecrypted,
            downloaded = Volatile.Read(ref _uiFilesDownloaded),
            failed = Volatile.Read(ref _uiFilesDecryptFailed),
            hypothesis = "H-FL-NOT-FAIL",
        });
        // #endregion
        AgentDlCountLog(where + "_ok_meta_or_flist", one);
    }

    // #region agent log
    private void AgentDlCountLog(string where, AssetDownloadOutcome one)
    {
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "pipeline-bars-v3",
                ["hypothesisId"] = "H-DL-SEMANTICS",
                ["location"] = "BackupDownloadService." + where,
                ["message"] = "pipeline_count",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new
                {
                    downloaded = Volatile.Read(ref _uiFilesDownloaded),
                    decrypted = Volatile.Read(ref _uiFilesDecrypted),
                    decryptFailed = Volatile.Read(ref _uiFilesDecryptFailed),
                    queue = CurrentDecryptQueueDepth(),
                    queuedDecrypt = one.QueuedDecrypt,
                    ok = one.Ok,
                    written = one.WrittenSharded,
                    staged = one.StagedChunks,
                    pending = one.PendingChunks,
                },
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch { /* ignore */ }
    }
    // #endregion

    private void AgentCountAlways(string message, object data)
    {
        // #region agent log
        // Hot path: non scrivere sempre su disco (1.7GB+ log = collo di bottiglia I/O).
        // Timing AG resta campionato sotto; resto solo con IKE_AGENT_DIAG=1 + quiet off.
        try
        {
            var isPerf = message is "ag_chunk_ok" or "ag_prefetch_done" or "ag_chunk_start"
                         or "ag_phase_profile" or "ag_batch_fillchunks_done"
                         or "clone_flush_ready" or "clone_copy_parallel" or "perf_settings_always"
                         or "backup_total_init" or "backup_total_final"
                         or "bytes_total_init" or "count_ciphertext"
                         or "mmcs_ram_after_assemble" or "mmcs_ram_after_fillchunks"
                         or "mmcs_ram_before_retain_end"
                         or "ag_batch_fillchunks_overlap" or "ag_assemble_split"
                         or "ag_phase_profile";
            if (!isPerf && !IkeLogOptions.ShouldWriteAgentDiag)
                return;

            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "perf-phase-v1",
                ["hypothesisId"] = isPerf ? "H-PHASE" : "H-COUNT-SEM",
                ["location"] = "BackupDownloadService",
                ["message"] = message,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = data,
            });
            if (isPerf)
            {
                // Perf: append diretto ma raro (pochi eventi/batch).
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line + Environment.NewLine);
            }
            else
            {
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
        }
        catch { /* ignore */ }
        // #endregion
    }

    // #region agent log
    private static void AgentCollectionModifiedCatch(
        string location,
        string path,
        Exception ex)
    {
        var msg = ex.Message ?? "";
        var isCollMod = msg.Contains("Collection was modified", StringComparison.OrdinalIgnoreCase)
                        || msg.Contains("enumeration operation", StringComparison.OrdinalIgnoreCase);
        var isNre = ex is NullReferenceException
                    || msg.Contains("Object reference not set", StringComparison.OrdinalIgnoreCase);
        if (!isCollMod && !isNre)
            return;
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = location,
                ["message"] = isNre ? "nullref_catch" : "collection_modified_catch",
                ["hypothesisId"] = isNre ? "H-NRE" : "H-CM0",
                ["runId"] = isNre ? "nre-v1" : "coll-mod-v1",
                ["data"] = new Dictionary<string, object?>
                {
                    ["path"] = path,
                    ["type"] = ex.GetType().FullName,
                    ["msg"] = msg,
                    ["stack"] = ex.StackTrace,
                    ["inner"] = ex.InnerException?.GetType().FullName,
                    ["innerMsg"] = ex.InnerException?.Message,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    private void NoteDecryptJobScheduled()
    {
        Interlocked.Increment(ref _uiDecryptPending);
        // Scaricati = contenuto pronto (in coda). Decifrati solo a successo in RunDecryptJobAsync.
        NoteFileDownloaded("decrypt_scheduled", null);
        // #region agent log
        AgentCountAlways("decrypt_scheduled", new
        {
            queue = CurrentDecryptQueueDepth(),
            downloaded = Volatile.Read(ref _uiFilesDownloaded),
            decrypted = Volatile.Read(ref _uiFilesDecrypted),
            failed = Volatile.Read(ref _uiFilesDecryptFailed),
            hypothesis = "H-DEC-QUEUE",
        });
        // #endregion
    }

    /// <summary>Fine job async (ok o fail) — prima del Report UI così la coda non resta a 1.</summary>
    private int NoteDecryptJobFinished()
    {
        var left = Interlocked.Decrement(ref _uiDecryptPending);
        if (left < 0)
        {
            Interlocked.Exchange(ref _uiDecryptPending, 0);
            return 0;
        }
        return left;
    }

    /// <summary>
    /// Coda UI: job ancora da completare (<see cref="_uiDecryptPending"/>).
    /// Non usare InFlight del channel qui: il report parte ancora dentro il worker
    /// (InFlight include il job corrente → coda resta ≥1 finché non arriva un report dopo).
    /// </summary>
    private int CurrentDecryptQueueDepth() =>
        Math.Max(0, Volatile.Read(ref _uiDecryptPending));

    /// <summary>
    /// Pending visibile in UI: file in attesa chunk MMCS + file in defer Ford
    /// H-ORDER (<see cref="_oidOrderRetries"/>). Non usare
    /// <see cref="OidHostBodyCache.PendingCount"/> (è per-gate, non per-file).
    /// </summary>
    private int CurrentPendingChunkFiles() =>
        Math.Max(0, _mmcsChunkSession?.PendingCount ?? 0)
        + Math.Max(0, _oidOrderRetries.Count);

    private void ReportFilesDoneProgress(
        IProgress<DownloadProgressReport>? progress,
        int filesDone,
        int filesTotal,
        long bytesDownloaded = 0,
        int? decryptQueuedOverride = null)
    {
        if (progress is null)
            return;
        var total = Math.Max(filesTotal, 1);
        if (filesTotal > 0)
            _uiFilesTotal = Math.Max(_uiFilesTotal, filesTotal);
        // Denominatore live ≥ Scaricati e ≥ Decifrati+Falliti (mai 134k catalogo stale).
        total = Math.Max(
            Math.Max(_uiFilesTotal, Volatile.Read(ref _uiFilesDownloaded)),
            Volatile.Read(ref _uiFilesDecrypted) + Volatile.Read(ref _uiFilesDecryptFailed));
        if (total < 1)
            total = 1;
        // Solo contatori live — niente Math.Max(filesDone/writtenSharded) che gonfiava Decifrati
        // oltre Scaricati (es. 999 dl / 1044 dec).
        var downloaded = Math.Max(0, Volatile.Read(ref _uiFilesDownloaded));
        var decrypted = Math.Max(0, Volatile.Read(ref _uiFilesDecrypted));
        var decryptQueued = decryptQueuedOverride ?? CurrentDecryptQueueDepth();
        var decryptFailed = Volatile.Read(ref _uiFilesDecryptFailed);
        var ciphertextSaved = Volatile.Read(ref _uiFilesCiphertextSaved);
        var duplicated = Math.Max(0, Volatile.Read(ref _uiFilesDuplicated));
        var pendingChunks = CurrentPendingChunkFiles();
        var channelLive = _decryptQueue is null
            ? -1
            : _decryptQueue.QueuedCount + _decryptQueue.InFlight;

        // Byte: il caller passa il cumulativo (MMCS + cloni accreditati su totalBytes);
        // i job decrypt passano delta piccoli → non regredire.
        if (bytesDownloaded > Volatile.Read(ref _uiBytesDownloaded))
            Volatile.Write(ref _uiBytesDownloaded, bytesDownloaded);
        var bytesDl = Volatile.Read(ref _uiBytesDownloaded);
        var snapshotCap = Volatile.Read(ref _uiBytesSnapshotDeclared);
        var bytesTotal = Volatile.Read(ref _uiBytesTotal);

        // Totale Dati = _uiBytesTotal (cloni non raddoppiano il denominatore).
        // Cap catalogo disabilitato (snapshotCap=0). Estrapolazione solo se manca stima.
        if (snapshotCap > 0)
        {
            bytesTotal = snapshotCap;
        }
        else
        {
            var filesRemaining = total > decrypted + Math.Max(0, decryptFailed);
            // Non estrapolare sul conteggio file (gonfia con cloni): solo se manca stima byte.
            if (bytesTotal <= 0 && bytesDl > 0 && decrypted > 0 && total > decrypted)
            {
                bytesTotal = (long)(bytesDl * (double)total / decrypted);
            }

            if (!filesRemaining && bytesTotal < bytesDl)
                bytesTotal = bytesDl;
        }

        if (bytesTotal > Volatile.Read(ref _uiBytesTotal) && snapshotCap <= 0)
            Volatile.Write(ref _uiBytesTotal, bytesTotal);
        else if (snapshotCap > 0)
            Volatile.Write(ref _uiBytesTotal, snapshotCap);
        // #region agent log
        {
            var nBp = Interlocked.Increment(ref _bytesProgressUiLogN);
            if (nBp <= 20 || nBp % 40 == 0)
            {
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "b3df71",
                        ["runId"] = "bytes-clone-excl-v1",
                        ["hypothesisId"] = "H1-H2",
                        ["location"] = "BackupDownloadService.ReportFilesDoneProgress",
                        ["message"] = "bytes_progress_ui",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            n = nBp,
                            bytesDl,
                            bytesTotal,
                            snapshotCap,
                            snapshotLabel = _uiSnapshotLabel,
                            filesDownloaded = downloaded,
                            filesDecrypted = decrypted,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
            }
        }
        // #endregion
        // #region agent log
        try
        {
            var filesRemainingLog = total > decrypted + Math.Max(0, decryptFailed);
            var etaStuck = filesRemainingLog && bytesTotal > 0 && bytesDl >= bytesTotal;
            var n = Interlocked.Increment(ref _filesDoneProgressLogCount);
            var equalStuck = downloaded == decrypted && decryptQueued > 0;
            if (n <= 40 || n % 25 == 0 || decryptQueued == 0 || pendingChunks == 0
                || decryptFailed > 0
                || equalStuck
                || downloaded != decrypted
                || etaStuck
                || snapshotCap > 0 && bytesTotal > snapshotCap * 2)
            {
                if (IkeLogOptions.ShouldWriteAgentDiag)
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "BackupDownloadService.ReportFilesDoneProgress",
                        ["message"] = "files_done_progress",
                        ["hypothesisId"] = "H-TOTAL-SNAP",
                        ["runId"] = "total-snap-v2",
                        ["data"] = new
                        {
                            n,
                            filesDoneIgnored = filesDone,
                            filesTotal = total,
                            filesDownloaded = downloaded,
                            filesDecrypted = decrypted,
                            filesDecryptFailed = decryptFailed,
                            filesCiphertextSaved = ciphertextSaved,
                            decryptQueued,
                            outcomesSum = decrypted + decryptFailed,
                            invariantOk = decrypted + decryptFailed <= downloaded,
                            bytesDownloaded = bytesDl,
                            bytesTotal,
                            snapshotCap,
                            trustedSnapshot = snapshotCap > 0,
                            filesRemaining = filesRemainingLog,
                            statusNumerator = decrypted,
                            snapshotLabel = _uiSnapshotLabel,
                            hypothesis = "H-CIPHER-UI",
                        },
                    });
                    IkeLogOptions.AppendAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
                }
            }
        }
        catch { /* ignore */ }
        // #endregion
        var seq = Interlocked.Increment(ref _progressReportSeq);
        progress.Report(new DownloadProgressReport
        {
            // Numeratore stato = solo successi decrypt (= Decifrati). Denominatore = pianificati live.
            Status = FormatSnapshotStatus($"Decifrati: {decrypted:N0}/{total:N0}"),
            SnapshotLabel = _uiSnapshotLabel,
            AssetsCompleted = decrypted,
            AssetsTotal = total,
            FilesDownloaded = downloaded,
            FilesDecrypted = decrypted,
            FilesDecryptFailed = Math.Max(decryptFailed, 0),
            FilesCiphertextSaved = Math.Max(ciphertextSaved, 0),
            FilesTotal = total,
            DecryptQueued = decryptQueued,
            FilesDuplicated = duplicated,
            FilesPendingChunks = pendingChunks,
            BytesDownloaded = bytesDl,
            TotalBytes = bytesTotal,
            ReportSequence = seq,
            AppendToLog = false,
        });
    }

    private string FormatSnapshotStatus(string body)
    {
        var label = _uiSnapshotLabel;
        return string.IsNullOrWhiteSpace(label) ? body : $"[{label}] {body}";
    }

    /// <summary>Un solo messaggio ERROR: MmcsAuth assente = fail terminale (niente decrypt dopo).</summary>
    private static void ReportMmcsAuthSkipSummary(
        IReadOnlyList<string> paths,
        int readyCount,
        IProgress<string>? log)
    {
        if (paths.Count == 0 || log is null)
            return;
        if (paths.Count <= 3)
        {
            foreach (var p in paths)
            {
                log.Report(
                    $"  ERROR MmcsAuth assente — decrypt impossibile (nessun retry): {p}");
            }
        }
        else
        {
            log.Report(
                $"  ERROR MmcsAuth assente per {paths.Count} file — decrypt impossibile " +
                $"(ready={readyCount}; es. {paths[0]}, {paths[1]}, …)");
        }

        // #region agent log
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "auth-gap-v2",
                    ["hypothesisId"] = "H-AUTH-GAP",
                    ["location"] = "ReportMmcsAuthSkipSummary",
                    ["message"] = "mmcs_auth_skip_summary",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        skipCount = paths.Count,
                        readyCount,
                        sample = paths.Take(5).ToArray(),
                        terminal = true,
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
    }

    private static int _filesDoneProgressLogCount;

    internal readonly record struct DecryptDrainStats(
        int Completed,
        long TotalBytes,
        int WrittenSharded,
        int StagedChunks,
        int MmcsOk,
        int FileDecryptOk);

    /// <summary>
    /// Scarica candidati MA: e materializza Manifest.db (+ .encrypted).
    /// </summary>
    private async Task<bool> TryDownloadManifestDbCandidatesAsync(
        ICloudSession session,
        string contentHost,
        DownloadJob job,
        IReadOnlyList<BackupAsset> candidates,
        IProgress<DownloadProgressReport>? progress,
        IProgress<string>? log,
        CancellationToken ct)
    {
        const int MinManifestBytes = 400_000;
        var workDir = IkeBackupOutputPaths.ResolveTmpDirectory(job.OutputDirectory);
        Directory.CreateDirectory(workDir);
        var top = candidates
            .Where(static a => a.RecordName.StartsWith("MA:", StringComparison.Ordinal))
            .Where(static a => !string.IsNullOrWhiteSpace(a.MmcsAuth))
            .OrderByDescending(static a => a.SizeBytes ?? 0)
            .ToList();
        if (top.Count == 0)
        {
            log?.Report("  nessun candidato MA: con MmcsAuth per Manifest.db");
            return false;
        }

        var maDownloaded = new List<(BackupAsset Asset, string ObjectFile, long Bytes, bool MmcsDecrypted)>();
        for (var idx = 1; idx <= top.Count; idx++)
        {
            var asset = top[idx - 1];
            log?.Report($"Manifest candidate {idx}/{top.Count}: {asset.RecordName}");

            byte[] authBody;
            long declared;
            try
            {
                authBody = await AuthorizeGetAsync(session, contentHost, asset, ct)
                    .ConfigureAwait(false);
                declared = UbChunkBuilder.BuildDecryptPlan(authBody).TotalCryptoBytes;
            }
            catch (Exception ex)
            {
                log?.Report($"  authorizeGet Manifest skip {asset.RecordName}: {ex.Message}");
                continue;
            }

            var authTag = "MANIFEST_" + SanitizeFileName(asset.RecordName);
            if (authTag.Length > 72)
                authTag = authTag[..72];
            await File.WriteAllBytesAsync(
                Path.Combine(workDir, authTag + "_authorizeGet.bin"),
                authBody,
                ct);

            var filePart = UbChunkBuilder.SelectFilePartAligned(
                UbChunkBuilder.ParseAuthorizeGetFiles(authBody),
                authBody,
                asset.AssetSignature ?? [],
                fallbackIndex: 0);
            var chunks = filePart.Chunks.Count > 0
                ? filePart.Chunks
                : UbChunkBuilder.ParseAuthorizeGetResponse(authBody);
            if (chunks.Count == 0)
                continue;

            var objectId = ResolveObjectId(chunks[0]);
            var outputFile = Path.Combine(
                workDir,
                "MANIFEST_OBJ_" + SanitizeFileName(objectId) + ".bin");

            try
            {
                var result = await DownloadAssembleAssetAsync(
                    session,
                    asset,
                    outputFile,
                    filePart.AuthSlice.Length > 0 ? filePart.AuthSlice : authBody,
                    chunks,
                    idx,
                    top.Count,
                    progress,
                    log,
                    ct,
                    tryMmcsDecrypt: true,
                    workDirectory: workDir);

                var len = new FileInfo(outputFile).Length;
                if (len < MinManifestBytes)
                {
                    log?.Report(
                        $"  scarto stub {Path.GetFileName(outputFile)} ({len:N0} B < {MinManifestBytes:N0})");
                    continue;
                }

                maDownloaded.Add((asset, outputFile, len, result.MmcsDecrypted));
                log?.Report(
                    $"  Manifest object {Path.GetFileName(outputFile)} ← {len:N0} byte " +
                    $"(authSum={declared:N0}, +{result.DownloadedBytes:N0} scaricati, {result.AssemblyMode}" +
                    (result.MmcsDecrypted ? ", mmcsDecrypted" : "") + ")");
            }
            catch (Exception ex)
            {
                log?.Report($"  download Manifest skip {asset.RecordName}: {ex.Message}");
            }
        }

        if (maDownloaded.Count == 0)
        {
            log?.Report($"FAIL: nessun oggetto Manifest ≥ {MinManifestBytes:N0} B scaricato");
            return false;
        }

        await MaterializeManifestDbAsync(job.OutputDirectory, maDownloaded, log, ct);
        var enc = Path.Combine(
            IkeBackupOutputPaths.ResolveTmpDirectory(job.OutputDirectory),
            "Manifest.db.encrypted");
        var ok = File.Exists(enc) && new FileInfo(enc).Length >= MinManifestBytes;
        if (ok)
            log?.Report($"OK Manifest.db.encrypted → {enc} ({new FileInfo(enc).Length:N0} byte)");
        else
            log?.Report(
                $"FAIL: Manifest.db.encrypted assente o stub (< {MinManifestBytes:N0} B)");
        return ok;
    }

    private static async Task WriteItunesSidecarsAtEndOfSnapshotAsync(
        ICloudSession session,
        DownloadJob job,
        IProgress<string>? log,
        CancellationToken ct)
    {
        SnapshotBackupPropertiesDecryptor.ApplyHardwareIdentityToDevices([job.Device]);
        var cleanDir = IkeBackupOutputPaths.ResolveCleanBackupDirectory(job.OutputDirectory);
        Directory.CreateDirectory(cleanDir);
        log?.Report(
            "Sidecar iTunes a fine snapshot: Info.plist + Status.plist + Manifest.plist " +
            $"(device/snapshot/Lockdown → {cleanDir})");
        await ItunesBackupSidecarWriter.WriteAsync(
            cleanDir, job.Device, job.Snapshot, session, log, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Sequenza per un asset: payload CloudKit → decrypt metadata → authorizeGet →
    /// edge → MMCS KEK → class-key AES → write filesystem.
    /// </summary>

    /// <summary>
    /// Sequenza per un asset: payload CloudKit → decrypt metadata → authorizeGet →
    /// edge → MMCS KEK → class-key AES → write filesystem.
    /// </summary>
    private async Task<AssetDownloadOutcome> DownloadAndDecryptAssetAsync(
        ICloudSession session,
        string contentHost,
        BackupAsset asset,
        string snapshotDirectory,
        string outputRoot,
        BackupFilesystemWriter fsWriter,
        BackupFileKeyContext fileKeyCtx,
        int assetIndex,
        int assetTotal,
        IProgress<DownloadProgressReport>? progress,
        IProgress<string>? log,
        CancellationToken ct)
    {
        await EnsureAssetRecordPayloadAsync(session, asset, log, ct).ConfigureAwait(false);

        await Task.Run(() =>
        {
            var meta = BackupAssetMetadataDecryptor.TryDecrypt(
                asset, asset.RecordPayload, session, fileKeyCtx.ClassicKeybag, log);
            BackupAssetMetadataDecryptor.Apply(asset, meta);
            if (!meta.Success)
            {
                if (assetIndex <= 5 || assetIndex == assetTotal
                    || meta.Message.Contains("OK", StringComparison.Ordinal))
                    log?.Report($"  {meta.Message}");
                else if (assetIndex == 6)
                    log?.Report("  … metadata pending (log ridotto)");
            }
        }, ct).ConfigureAwait(false);

        await EnsureAssetWrapAndIkmAsync(session, asset, snapshotDirectory, log, ct)
            .ConfigureAwait(false);

        if (asset.RecordPayload is { Length: > 32 })
        {
            await FordOfflineDumpWriter.DumpCloudKitQueryAsync(
                snapshotDirectory,
                asset.RecordPayload,
                [asset.RecordName],
                "mem_" + SanitizeFileName(asset.RecordName),
                ct).ConfigureAwait(false);
        }

        if (!await EnsureMmcsAuthForAuthorizeGetAsync(session, asset, snapshotDirectory, log, ct)
                .ConfigureAwait(false))
        {
            log?.Report(
                $"  ERROR {asset.RecordName}: authorizeGet senza x-apple-mmcs-auth " +
                "(PrivilegedBatch/PreAuth non hanno restituito auth)");
            return AssetDownloadOutcome.Failed;
        }

        byte[] authResponseBody;
        try
        {
            authResponseBody = await AuthorizeGetAsync(session, contentHost, asset, ct)
                .ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log?.Report($"  ERROR {asset.RecordName}: authorizeGet {ex.Message}");
            return AssetDownloadOutcome.Failed;
        }

        var authTag = "AUTH_" + SanitizeFileName(asset.RecordName);
        if (authTag.Length > 72)
            authTag = authTag[..72];
        byte[]? authRequest = null;
        if (asset.AssetSignature is { Length: 21 } reqSig
            && MmcsAuthBuilder.TryBuildFlistAuthorizeEntry(reqSig, asset.MmcsAuth) is { } reqEntry)
        {
            authRequest = UbChunkBuilder.BuildAuthorizeGetRequest([reqEntry]);
            await File.WriteAllBytesAsync(
                Path.Combine(snapshotDirectory, authTag + "_request.bin"),
                authRequest,
                ct).ConfigureAwait(false);
        }

        await File.WriteAllBytesAsync(
            Path.Combine(snapshotDirectory, authTag + "_authorizeGet.bin"),
            authResponseBody,
            ct).ConfigureAwait(false);

        var filePart = UbChunkBuilder.SelectFilePartAligned(
            UbChunkBuilder.ParseAuthorizeGetFiles(authResponseBody),
            authResponseBody,
            asset.AssetSignature ?? [],
            fallbackIndex: 0);
        var chunks = filePart.Chunks.Count > 0
            ? filePart.Chunks
            : UbChunkBuilder.ParseAuthorizeGetResponse(authResponseBody);
        if (chunks.Count == 0)
        {
            log?.Report($"  ERROR {asset.RecordName}: authorizeGet senza chunk");
            return AssetDownloadOutcome.Failed;
        }

        var authSlice = filePart.AuthSlice.Length > 0 ? filePart.AuthSlice : authResponseBody;

        //  dopo AG, materiali FileGroup sullo stesso CKFile (già FillFord pre-AG).
        try
        {
            var planFg = UbChunkBuilder.BuildDecryptPlan(authSlice);
            AssetMaterialPipeline.AttachFileGroupMaterials(asset, authSlice, planFg, chunks);
        }
        catch { /* best-effort */ }

        try
        {
            return await FinishFlistAssetAfterAuthorizeAsync(
                session,
                asset,
                snapshotDirectory,
                outputRoot,
                fsWriter,
                fileKeyCtx,
                authSlice,
                chunks,
                assetIndex,
                assetTotal,
                progress,
                log,
                ct).ConfigureAwait(false);
        }
        catch (BackupCryptoAbortException)
        {
            throw;
        }
        catch (Exception ex)
        {
            log?.Report($"  ERROR {asset.RecordName}: download {ex.Message}");
            return AssetDownloadOutcome.Failed;
        }
    }

    /// <summary>
    /// IKM per DecryptFordKeys — allineato a <c>FillFordIkmFromContents</c>:
    /// solo unwrap(wrap40 contents × zoneMaster) → <see cref="BackupAsset.AssetUnwrappedKey"/>.
    /// Con align ON non usa mai flist <c>EncryptionKey</c> (CKFile+0x1a0 / InitEK),
    /// path vuoto sul Ford live (<c>ford_ikm_who_writes.md</c>).
    /// </summary>
    private static byte[]? TryResolveFordIkm(BackupAsset asset, out string source)
    {
        if (asset.AssetUnwrappedKey is { Length: 16 or 32 } unwrapped)
        {
            source = "protectionInfo-unwrap";
            // #region agent log
            try
            {
                var path = asset.RelativePath ?? asset.RecordName ?? "";
                if (path.Contains("AuthKit", StringComparison.OrdinalIgnoreCase)
                    || path.Contains("Preferences/com.apple.", StringComparison.OrdinalIgnoreCase)
                    || IkeLogOptions.ShouldWriteAgentDiag)
                {
                    AgentNdjsonAlways(JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = "post-fix-no-batch-rp",
                        ["hypothesisId"] = "H-ALIEN-IKM",
                        ["location"] = "BackupDownloadService.TryResolveFordIkm",
                        ["message"] = "ikm_from_contents_unwrap",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            path,
                            ikmLen = unwrapped.Length,
                            ikmHead8 = Convert.ToHexString(unwrapped.AsSpan(0, Math.Min(8, unwrapped.Length))),
                            ikmSha16 = Convert.ToHexString(
                                System.Security.Cryptography.SHA256.HashData(unwrapped).AsSpan(0, 8)),
                            wrapLen = string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                                ? 0
                                : asset.AssetProtectionInfoHex!.Length / 2,
                            rpLen = asset.RecordPayload?.Length ?? 0,
                            wrapMatchesIkm = string.Equals(
                                asset.AssetUnwrappedKeyWrapHex,
                                asset.AssetProtectionInfoHex,
                                StringComparison.OrdinalIgnoreCase),
                        },
                    }));
                    try
                    {
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                            JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "03cce7",
                                ["runId"] = "post-fix-no-batch-rp",
                                ["hypothesisId"] = "H-ALIEN-IKM",
                                ["location"] = "BackupDownloadService.TryResolveFordIkm",
                                ["message"] = "ikm_from_contents_unwrap",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new Dictionary<string, object?>
                                {
                                    ["path"] = path,
                                    ["ikmHead8"] = Convert.ToHexString(
                                        unwrapped.AsSpan(0, Math.Min(8, unwrapped.Length))),
                                    ["rpLen"] = asset.RecordPayload?.Length ?? 0,
                                    ["wrapLen"] = string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                                        ? 0
                                        : asset.AssetProtectionInfoHex!.Length / 2,
                                },
                            }) + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                }
            }
            catch { /* ignore */ }
            // #endregion
            return unwrapped;
        }

        // FillFordIkm: IKM solo da contents wrap — mai InitFileEncryptionKey / flist EK.
        source = "ike-no-unwrapped-key";
        // #region agent log
        try
        {
            AgentNdjsonAlways(JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "ike-ikm-align",
                ["hypothesisId"] = "H-WRITE",
                ["location"] = "BackupDownloadService.TryResolveFordIkm",
                ["message"] = "ikm_missing_skip_flist_ek",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new
                {
                    path = asset.RelativePath ?? asset.RecordName,
                    hasWrap = !string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex),
                    ekLen = asset.EncryptionKey?.Length ?? 0,
                },
            }));
        }
        catch { /* ignore */ }
        // #endregion
        return null;
    }

    /// <summary>
    /// Speculare <c>FillFordIkmFromContents</c>:
    /// wrap40 = Asset.protectionInfo da contents (stesso signature) →
    /// IKM32 = AES-KW(NISTKDF(zoneMaster, "wrapping key wrap me"), wrap40).
    /// Scrive <see cref="BackupAsset.AssetUnwrappedKey"/> (= CKFile+0x160).
    /// </summary>
    private void EnsureAssetWrapAndIkm(
        ICloudSession session,
        BackupAsset asset,
        string? workDirectory,
        IProgress<string>? log)
    {
        // Solo UUID/KA/MA/…: FL: non compare nel RP (RP ha UUID CK) — 14:06 cleared=976
        // tutti FL → ikmLen=0 / KEY@+0x38 miss. Ownership FL = wrap×AssetSignature.
        if (asset.RecordPayload is { Length: > 32 }
            && IsCloudKitAssetRecordName(asset.RecordName)
            && !AssetRecordWindowBelongsTo(asset, asset.RecordPayload))
        {
            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-SAME-RP",
                    ["runId"] = "sanitize-alien-rp-v2",
                    ["location"] = "BackupDownloadService.EnsureAssetWrapAndIkm",
                    ["message"] = "cleared_alien_record_payload",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["path"] = asset.RelativePath ?? asset.RecordName,
                        ["recordName"] = asset.RecordName,
                        ["rpLen"] = asset.RecordPayload.Length,
                        ["hadWrap"] = !string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex),
                        ["ckName"] = true,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            asset.RecordPayload = null;
            asset.AssetProtectionInfoHex = null;
            asset.AssetUnwrappedKey = null;
            asset.AssetUnwrappedKeyWrapHex = null;
        }

        InvalidateStaleAssetUnwrappedKey(asset, "pre-bind");
        BindWrapToAssetSignature(asset, workDirectory, log);
        InvalidateStaleAssetUnwrappedKey(asset, "post-bind");

        // map["contents"]: wrap dal field contents (sig04≠sig01 OK), poi f2/f17.
        if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
            && asset.RecordPayload is { Length: > 32 } window
            && asset.AssetSignature is { Length: >= 4 } sig)
        {
            var wrap = CloudKitAssetProto.TryResolveOwnedWrap(window, sig, out var ownedSrc);
            if (wrap is { Length: 24 or 40 })
            {
                asset.AssetProtectionInfoHex = Convert.ToHexString(wrap);
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-CONTENTS-BIND",
                        ["runId"] = "map-contents-first-v2",
                        ["location"] = "BackupDownloadService.EnsureAssetWrapAndIkm",
                        ["message"] = "bound_map_contents_wrap",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["source"] = ownedSrc,
                            ["wrapLen"] = wrap.Length,
                            ["sigLead"] = sig[0],
                            ["sig8"] = Convert.ToHexString(sig.AsSpan(0, Math.Min(8, sig.Length))),
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
            }
        }

        // Enforce: clear solo se wrap non è owned né su RP né su CK (RP spesso incompleto).
        if (!string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
            && asset.AssetSignature is { Length: >= 4 } sigOwn)
        {
            try
            {
                var cur = Convert.FromHexString(asset.AssetProtectionInfoHex);
                if (cur.Length is 24 or 40)
                {
                    var ownedOnRp = asset.RecordPayload is { Length: > 32 } winOwn
                        && CloudKitAssetProto.IsOwnedWrap(winOwn, sigOwn, cur);
                    var ownedOnCk = false;
                    if (!ownedOnRp && !string.IsNullOrWhiteSpace(workDirectory))
                    {
                        var ckOwned = FordOfflineDumpWriter.TryFindOwnedWrapInCk(
                            workDirectory, sigOwn, out _);
                        ownedOnCk = ckOwned is { Length: 24 or 40 }
                            && ckOwned.AsSpan().SequenceEqual(cur);
                    }

                    if (!ownedOnRp && !ownedOnCk)
                    {
                        if (FordOfflineDumpWriter.ShouldKeepFlMmcsPreboundWrap(asset, out var keepWhy))
                        {
                            // #region agent log
                            try
                            {
                                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "b3df71",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["hypothesisId"] = "H-FL-KEK",
                                    ["runId"] = "fl-keep-wrap24-v1",
                                    ["location"] = "BackupDownloadService.EnsureAssetWrapAndIkm",
                                    ["message"] = "keep_non_owned_fl_mmcs_wrap24",
                                    ["data"] = new Dictionary<string, object?>
                                    {
                                        ["path"] = asset.RelativePath ?? asset.RecordName,
                                        ["wrapLen"] = cur.Length,
                                        ["why"] = keepWhy,
                                    },
                                });
                                File.AppendAllText(
                                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                                    line + Environment.NewLine);
                            }
                            catch { /* ignore */ }
                            // #endregion
                        }
                        else
                        {
                            // #region agent log
                            try
                            {
                                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "03cce7",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["hypothesisId"] = "H-WRAP-ENFORCE",
                                    ["runId"] = "ck-owned-noveto-v1",
                                    ["location"] = "BackupDownloadService.EnsureAssetWrapAndIkm",
                                    ["message"] = "cleared_non_owned_wrap_post_bind",
                                    ["data"] = new Dictionary<string, object?>
                                    {
                                        ["path"] = asset.RelativePath ?? asset.RecordName,
                                        ["wrapLen"] = cur.Length,
                                        ["hadPayload"] = asset.RecordPayload is { Length: > 32 },
                                    },
                                });
                                File.AppendAllText(
                                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                                    line + Environment.NewLine);
                            }
                            catch { /* ignore */ }
                            // #endregion
                            asset.AssetProtectionInfoHex = null;
                            asset.AssetUnwrappedKey = null;
                            asset.AssetUnwrappedKeyWrapHex = null;
                        }
                    }
                }
            }
            catch { /* ignore bad hex */ }
        }

        // #region agent log
        LogWrapIkmProvenance(asset, "after-bind");
        // #endregion

        // FillFordIkmFromContents: Record → wrap → IKM@CKFile+0x160 (unica strada).
        AssetMaterialPipeline.FillFordIkmFromContents(
            asset,
            (a, wrap) =>
            {
                if (wrap is not { Length: 24 or 40 })
                    return null;
                // Force unwrap path via TryResolveMmcsKek (sets AssetUnwrappedKey).
                a.AssetProtectionInfoHex = Convert.ToHexString(wrap);
                a.AssetUnwrappedKey = null;
                a.AssetUnwrappedKeyWrapHex = null;
                _ = TryResolveMmcsKek(session, a, log);
                if (a.AssetUnwrappedKey is { Length: 16 or 32 } live)
                    return live;
                if (!string.IsNullOrWhiteSpace(workDirectory)
                    && FordOfflineDumpWriter.TryUnwrapWithSavedMasters(
                        workDirectory, a.AssetProtectionInfoHex) is { Length: 16 or 32 } disk)
                {
                    AcceptAssetUnwrappedKey(a, disk, "disk-zone-master", wrap.Length, log);
                    return disk;
                }

                return null;
            });

        if (asset.AssetUnwrappedKey is { Length: 16 or 32 })
            return;

        // Ultimo tentativo offline: wrap owned per signature nei dump CK del workdir.
        if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
            && !string.IsNullOrWhiteSpace(workDirectory)
            && asset.AssetSignature is { Length: >= 4 } sigDump
            && FordOfflineDumpWriter.TryFindOwnedWrapInCk(workDirectory, sigDump, out _)
                is { Length: 24 or 40 } dumpWrap)
        {
            asset.AssetProtectionInfoHex = Convert.ToHexString(dumpWrap);
            AssetMaterialPipeline.FillFordIkmFromContents(
                asset,
                (a, wrap) =>
                {
                    if (wrap is not { Length: 24 or 40 })
                        return null;
                    a.AssetProtectionInfoHex = Convert.ToHexString(wrap);
                    a.AssetUnwrappedKey = null;
                    a.AssetUnwrappedKeyWrapHex = null;
                    _ = TryResolveMmcsKek(session, a, log);
                    return a.AssetUnwrappedKey is { Length: 16 or 32 } live ? live : null;
                });
            if (asset.AssetUnwrappedKey is { Length: 16 or 32 })
                return;
        }

        if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
            return;

        int wrapLenFail = 0;
        try
        {
            wrapLenFail = Convert.FromHexString(asset.AssetProtectionInfoHex).Length;
        }
        catch
        {
            return;
        }

        if (wrapLenFail is not (24 or 40))
            return;

        // FL wrap24: non abortire l'intero backup se lo ZM non unwrap-a ancora —
        // Pipe C type02 riproverà con KEK; meglio fallire un FL che killare la sessione.
        if (FordOfflineDumpWriter.ShouldKeepFlMmcsPreboundWrap(asset, out var flWhy))
        {
            log?.Report(
                $"  {asset.RecordName}: unwrap wrap{wrapLenFail} fallito ({flWhy}) — continuo (Pipe C)");
            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "b3df71",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-FL-KEK",
                    ["runId"] = "fl-keep-wrap24-v1",
                    ["location"] = "BackupDownloadService.EnsureAssetWrapAndIkm",
                    ["message"] = "fl_unwrap_soft_fail_no_abort",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["path"] = asset.RelativePath ?? asset.RecordName,
                        ["wrapLen"] = wrapLenFail,
                        ["why"] = flWhy,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            return;
        }

        throw AbortCrypto(
            asset,
            $"Unwrap wrap{wrapLenFail} fallito (IKM assente). " +
            "Il download backup è stato interrotto.");
    }

    /// <summary>
    /// Strategia  wrap = <c>Asset.protectionInfo</c> dello stesso messaggio
    /// la cui <c>Asset.signature</c> (f2) == <see cref="BackupAsset.AssetSignature"/>.
    /// </summary>
    private static void BindWrapToAssetSignature(
        BackupAsset asset,
        string? workDirectory,
        IProgress<string>? log)
    {
        if (asset.AssetSignature is not { Length: >= 4 })
            return;

        var previous = asset.AssetProtectionInfoHex;
        var source = FordOfflineDumpWriter.BindWrapToSignature(workDirectory ?? "", asset);
        if (source is "keep-prebound-fl-mmcs")
        {
            log?.Report(
                $"  {asset.RecordName}: wrap24 FL/MMCS KEK conservato (Pipe C type02)");
            return;
        }

        if (source is "cleared-prebound" or "cleared-not-owned")
        {
            log?.Report(
                $"  {asset.RecordName}: wrap prebound alieno rimosso (no-owned match)");
            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-WRAP-CLEAR",
                    ["runId"] = "ike-owned-wrap-v1",
                    ["location"] = "BackupDownloadService.BindWrapToAssetSignature",
                    ["message"] = "cleared_prebound",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["path"] = asset.RelativePath ?? asset.RecordName,
                        ["hadPrev"] = !string.IsNullOrWhiteSpace(previous),
                        ["source"] = source,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            return;
        }

        if (string.Equals(previous, asset.AssetProtectionInfoHex, StringComparison.OrdinalIgnoreCase))
            return;
        if (source is "missing" or "prebound" or "no-signature")
            return;

        log?.Report($"  {asset.RecordName}: wrap-owned ({source})");
    }

    /// <summary>H-WRAP:-owned wrap vs alien prebound (AuthKit multi-asset).</summary>
    private static void LogWrapIkmProvenance(BackupAsset asset, string phase)
    {
        try
        {
            var path = asset.RelativePath ?? asset.RecordName ?? "";
            byte[]? sigWrap = null;
            byte[]? ownedWrap = null;
            var ownedSrc = "missing";
            var payloadAssetN = 0;
            var payloadWrapN = 0;
            if (asset.RecordPayload is { Length: > 32 } pl
                && asset.AssetSignature is { Length: >= 4 } sig)
            {
                sigWrap = CloudKitAssetProto.TryGetWrapForSignature(pl, sig);
                ownedWrap = CloudKitAssetProto.TryResolveOwnedWrap(pl, sig, out ownedSrc);
                foreach (var a in CloudKitAssetProto.EnumerateAssets(pl))
                {
                    payloadAssetN++;
                    if (a.ProtectionWrap is { Length: 24 or 40 })
                        payloadWrapN++;
                }
            }

            byte[]? curWrap = null;
            if (!string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
            {
                try { curWrap = Convert.FromHexString(asset.AssetProtectionInfoHex); }
                catch { /* ignore */ }
            }

            var curMatchesSigWrap = curWrap is not null
                && sigWrap is not null
                && curWrap.AsSpan().SequenceEqual(sigWrap);
            var curIsOwned = curWrap is not null
                && ownedWrap is not null
                && curWrap.AsSpan().SequenceEqual(ownedWrap);
            // Log Preferences / mismatch / dual-asset / rid-token siblings (Class A).
            var interesting = path.Contains("AuthKit", StringComparison.OrdinalIgnoreCase)
                || path.Contains("RemoteStrings", StringComparison.OrdinalIgnoreCase)
                || path.Contains("Numbers.plist", StringComparison.OrdinalIgnoreCase)
                || path.Contains("Preferences/com.apple.", StringComparison.OrdinalIgnoreCase)
                || (curWrap is not null && !curIsOwned)
                || (payloadAssetN >= 2 && payloadWrapN == 1);
            if (!interesting)
                return;

            var ikm = asset.AssetUnwrappedKey;
            // #region agent log
            try
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = "rid-token-v1",
                        ["hypothesisId"] = "H-UUID-COLLISION",
                        ["location"] = "BackupDownloadService.LogWrapIkmProvenance",
                        ["message"] = "wrap_bind_rid_identity",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["phase"] = phase,
                            ["path"] = path,
                            ["record"] = asset.RecordName,
                            ["recordIsA"] = CloudKitMmcsIds.IsAssetRecordName(asset.RecordName),
                            ["recordIsUuid"] = CloudKitMmcsIds.IsUuidRecordName(asset.RecordName),
                            ["rid"] = asset.RecordIdSuffix is { Length: > 72 } r
                                ? r[..72]
                                : asset.RecordIdSuffix,
                            ["ridTok8"] = TryExtractRidToken(asset.RecordIdSuffix) is { } t
                                ? (t.Length > 12 ? t[..12] : t)
                                : "",
                            ["rpBelongs"] = AssetRecordWindowBelongsTo(asset, asset.RecordPayload),
                            ["hasIkm"] = ikm is { Length: 16 or 32 },
                            ["ikmSha16"] = ikm is { Length: > 0 }
                                ? Convert.ToHexString(
                                    System.Security.Cryptography.SHA256.HashData(ikm))[..16]
                                : null,
                            ["sig8"] = asset.AssetSignature is { Length: >= 4 } sg
                                ? Convert.ToHexString(sg.AsSpan(0, Math.Min(8, sg.Length)))
                                : null,
                            ["curIsOwned"] = curIsOwned,
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            AgentNdjsonAlways(JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "ike-owned-wrap-v1",
                ["hypothesisId"] = "H-WRAP",
                ["location"] = "BackupDownloadService.LogWrapIkmProvenance",
                ["message"] = "wrap_bind_provenance",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new
                {
                    phase,
                    path,
                    record = asset.RecordName,
                    ridTok8 = TryExtractRidToken(asset.RecordIdSuffix) is { } tok
                        ? (tok.Length > 12 ? tok[..12] : tok)
                        : "",
                    hasIkm = ikm is { Length: 16 or 32 },
                    ikmSha16 = ikm is { Length: > 0 }
                        ? Convert.ToHexString(
                            System.Security.Cryptography.SHA256.HashData(ikm).AsSpan(0, 8))
                        : null,
                    wrapLen = curWrap?.Length ?? 0,
                    wrapSha16 = curWrap is { Length: > 0 }
                        ? Convert.ToHexString(
                            System.Security.Cryptography.SHA256.HashData(curWrap).AsSpan(0, 8))
                        : null,
                    sigWrapLen = sigWrap?.Length ?? 0,
                    ownedSrc,
                    ownedWrapLen = ownedWrap?.Length ?? 0,
                    curMatchesSigWrap,
                    curIsOwned,
                    payloadAssetN,
                    payloadWrapN,
                    sig8 = asset.AssetSignature is { Length: >= 4 } s
                        ? Convert.ToHexString(s.AsSpan(0, Math.Min(8, s.Length)))
                        : null,
                },
            }));
        }
        catch { /* ignore */ }
    }



    private static void InvalidateStaleAssetUnwrappedKey(BackupAsset asset, string phase)
    {
        if (asset.AssetUnwrappedKey is null)
            return;

        var wrapHex = asset.AssetProtectionInfoHex;
        if (!string.IsNullOrWhiteSpace(wrapHex)
            && !string.IsNullOrWhiteSpace(asset.AssetUnwrappedKeyWrapHex)
            && string.Equals(asset.AssetUnwrappedKeyWrapHex, wrapHex, StringComparison.OrdinalIgnoreCase))
            return;

        // #region agent log
        AgentDebugLog(
            "H-IKM",
            "BackupDownloadService.InvalidateStaleAssetUnwrappedKey",
            "invalidate_ikm",
            new
            {
                phase,
                record = asset.RecordName,
                path = asset.RelativePath,
                wrapHex = wrapHex?[..Math.Min(16, wrapHex.Length)],
                ikmWrapHex = asset.AssetUnwrappedKeyWrapHex?[
                    ..Math.Min(16, asset.AssetUnwrappedKeyWrapHex?.Length ?? 0)],
                ikmLen = asset.AssetUnwrappedKey?.Length ?? 0,
            });
        // #endregion

        asset.AssetUnwrappedKey = null;
        asset.AssetUnwrappedKeyWrapHex = null;
    }

    private static byte[]? TryFindWrapInFordOfflineCk(
        string workDirectory,
        BackupAsset asset,
        ReadOnlySpan<byte> assetSignature,
        out string? source)
    {
        source = null;
        try
        {
            var ckDir = Path.Combine(workDirectory, FordOfflineDumpWriter.FolderName, "ck");
            if (!Directory.Exists(ckDir))
                return null;

            var preferred = new List<string>();
            foreach (var hint in BuildCkFileMatchHints(asset))
            {
                foreach (var file in Directory.EnumerateFiles(ckDir, "*.contents.bin"))
                {
                    if (Path.GetFileName(file).Contains(hint, StringComparison.OrdinalIgnoreCase))
                        preferred.Add(file);
                }
            }

            foreach (var file in preferred.Distinct(StringComparer.OrdinalIgnoreCase))
            {
                var wrap = CloudKitAssetProto.TryResolveOwnedWrap(
                    File.ReadAllBytes(file), assetSignature, out var src);
                if (wrap is { Length: 24 or 40 })
                {
                    source = src + "/ck-pref:" + Path.GetFileName(file);
                    return wrap;
                }
            }

            foreach (var file in Directory.EnumerateFiles(ckDir, "*.contents.bin"))
            {
                if (preferred.Contains(file, StringComparer.OrdinalIgnoreCase))
                    continue;
                var wrap = CloudKitAssetProto.TryResolveOwnedWrap(
                    File.ReadAllBytes(file), assetSignature, out var src);
                if (wrap is { Length: 24 or 40 })
                {
                    source = src + "/ck:" + Path.GetFileName(file);
                    return wrap;
                }
            }

            var safe = SanitizeRecordNameForCk(asset.RecordName);
            if (!string.IsNullOrEmpty(safe))
            {
                var recordFile = Path.Combine(ckDir, $"record_{safe}.bin");
                if (File.Exists(recordFile))
                {
                    var wrap = CloudKitAssetProto.TryResolveOwnedWrap(
                        File.ReadAllBytes(recordFile), assetSignature, out var src);
                    if (wrap is { Length: 24 or 40 })
                    {
                        source = src + "/ck-record:" + Path.GetFileName(recordFile);
                        return wrap;
                    }
                }
            }
        }
        catch
        {
            // ignore offline scan failures
        }

        return null;
    }

    /// <summary>
    /// Un solo wrap nei dump CK preferiti per il record (candidato CT-trial).
    /// </summary>
    private static byte[]? TryFindSoleWrapInFordOfflineCk(
        string workDirectory,
        BackupAsset asset,
        out string? source)
    {
        source = null;
        try
        {
            var ckDir = Path.Combine(workDirectory, FordOfflineDumpWriter.FolderName, "ck");
            if (!Directory.Exists(ckDir))
                return null;

            foreach (var hint in BuildCkFileMatchHints(asset))
            {
                foreach (var file in Directory.EnumerateFiles(ckDir, "*.contents.bin"))
                {
                    if (!Path.GetFileName(file).Contains(hint, StringComparison.OrdinalIgnoreCase))
                        continue;
                    var sole = CloudKitAssetProto.TryResolveContentsSoleWrap(
                        File.ReadAllBytes(file), out var src);
                    if (sole is { Length: 24 or 40 })
                    {
                        source = src + "/ck-pref:" + Path.GetFileName(file);
                        return sole;
                    }
                }
            }

            var safe = SanitizeRecordNameForCk(asset.RecordName);
            if (!string.IsNullOrEmpty(safe))
            {
                var recordFile = Path.Combine(ckDir, $"record_{safe}.bin");
                if (File.Exists(recordFile))
                {
                    var sole = CloudKitAssetProto.TryResolveContentsSoleWrap(
                        File.ReadAllBytes(recordFile), out var src);
                    if (sole is { Length: 24 or 40 })
                    {
                        source = src + "/ck-record:" + Path.GetFileName(recordFile);
                        return sole;
                    }
                }
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static IEnumerable<string> BuildCkFileMatchHints(BackupAsset asset)
    {
        var guid = ExtractRecordGuid(asset.RecordName);
        if (!string.IsNullOrWhiteSpace(guid))
            yield return guid;

        if (!string.IsNullOrWhiteSpace(asset.MmcsAuth))
        {
            var tok = asset.MmcsAuth.Split([' ', '|'], StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();
            if (!string.IsNullOrEmpty(tok) && tok.Length >= 16)
                yield return tok[..Math.Min(40, tok.Length)];
        }
    }

    private static string? ExtractRecordGuid(string? recordName)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            return null;

        foreach (var part in recordName.Split(':', StringSplitOptions.RemoveEmptyEntries))
        {
            if (Guid.TryParse(part, out var g))
                return g.ToString();
        }

        var head = recordName.Split('=', 2)[0];
        return Guid.TryParse(head, out var direct) ? direct.ToString() : null;
    }

    private static string SanitizeRecordNameForCk(string recordName)
    {
        var chars = recordName.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_').ToArray();
        var s = new string(chars);
        return s.Length <= 72 ? s : s[..72];
    }

    private static void AgentNdjsonGated(string jsonLine)
    {
        if (!IkeLogOptions.ShouldWriteAgentDiag)
            return;
        IkeLogOptions.AppendAgentNdjson(
            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
            jsonLine);
    }

    /// <summary>
    /// NDJSON size0 / rebind: bypass Quiet (altrimenti zero evidenza su no-resolve).
    /// </summary>
    private static void AgentNdjsonAlways(string jsonLine)
    {
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                jsonLine + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }

    // #region agent log
    private static void AgentDebugLog(string hypothesisId, string location, string message, object data, string runId = "wrap-bind-fix")
    {
        if (!IkeLogOptions.ShouldWriteAgentDiag)
            return;
        try
        {
            var logPath = Path.Combine(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log");
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "ab5168",
                ["runId"] = runId,
                ["hypothesisId"] = hypothesisId,
                ["location"] = location,
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            File.AppendAllText(logPath, line + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    private static BackupCryptoAbortException AbortCrypto(
        BackupAsset asset,
        string reason,
        Exception? inner = null)
    {
        var name = string.IsNullOrWhiteSpace(asset.RelativePath)
            ? asset.RecordName
            : asset.RelativePath;
        var msg = $"{name}: {reason}";
        // #region agent log
        AgentDebugLog(
            "H-ABORT",
            "BackupDownloadService.AbortCrypto",
            "crypto_abort",
            new
            {
                path = name,
                record = asset.RecordName,
                reason,
                inner = inner?.GetType().Name
            },
            runId: "abort-crypto");
        // #endregion
        return inner is null
            ? new BackupCryptoAbortException(msg)
            : new BackupCryptoAbortException(msg, inner);
    }

    private static string SanitizeFlCacheFolderName(string? recordName, int flIndex)
    {
        var raw = string.IsNullOrWhiteSpace(recordName) ? $"FL_{flIndex}" : recordName;
        var invalid = Path.GetInvalidFileNameChars();
        var chars = raw.Select(c => invalid.Contains(c) ? '_' : c).ToArray();
        var safe = new string(chars);
        if (safe.Length > 80)
            safe = safe[..80];
        return $"FL_{flIndex}_{safe}";
    }

    private static void RememberShardPath(
        BackupAsset asset,
        ConcurrentDictionary<string, string> shardBySig,
        string cleanDir,
        string? deviceDirectory = null)
    {
        if (asset.AssetSignature is not { Length: 21 } sig)
            return;
        var fid = asset.EnsureFileId();
        if (string.IsNullOrWhiteSpace(fid))
            return;
        var path = IkeBackupOutputPaths.ToShardedFilePath(cleanDir, fid);
        if (!File.Exists(path))
            return;
        var hex = Convert.ToHexString(sig).ToLowerInvariant();
        shardBySig[hex] = path;
        deviceDirectory ??= InferDeviceDirectoryFromCleanBackup(cleanDir);
        PersistDeviceSigCacheEntry(deviceDirectory, hex, path);
    }

    private static string? InferDeviceDirectoryFromCleanBackup(string cleanDir)
    {
        try
        {
            var trimmed = cleanDir.TrimEnd(
                Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
            var name = Path.GetFileName(trimmed);
            var work = string.Equals(
                name, IkeBackupOutputPaths.CleanBackupFolderName, StringComparison.OrdinalIgnoreCase)
                ? Path.GetDirectoryName(trimmed)
                : trimmed;
            return string.IsNullOrWhiteSpace(work) ? null : Path.GetDirectoryName(work);
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Carica indice signature→path da run precedenti (device <c>.ike_sig_cache</c>).
    /// </summary>
    private static int SeedShardIndexFromPriorSnapshots(
        string deviceDirectory,
        string currentWorkDirectory,
        ConcurrentDictionary<string, string> shardBySig,
        IProgress<string>? log)
    {
        var added = 0;
        try
        {
            var cacheDir = IkeBackupOutputPaths.ResolveDeviceSigCacheDirectory(deviceDirectory);
            if (Directory.Exists(cacheDir))
            {
                foreach (var entry in Directory.EnumerateFiles(cacheDir))
                {
                    try
                    {
                        var hex = Path.GetFileName(entry);
                        if (hex.Length != 42) // 21 bytes hex
                            continue;
                        var target = File.ReadAllText(entry).Trim();
                        if (string.IsNullOrWhiteSpace(target) || !File.Exists(target))
                            continue;
                        if (shardBySig.TryAdd(hex, target))
                            added++;
                    }
                    catch
                    {
                        // next entry
                    }
                }
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  CopySnapshot seed skip: {ex.Message}");
        }

        if (added > 0)
            log?.Report(
                $"  CopySnapshot: indice device {added:N0} signature riusabili " +
                $"(sibling snapshot sotto {deviceDirectory})");
        return added;
    }

    /// <summary>
    /// Se la signature (o lo stesso fileID iTunes) esiste già su disco da uno snapshot
    /// precedente, collega la sorgente in <paramref name="shardBySig"/> per la copia.
    /// </summary>
    private static bool TryBindPriorShardSource(
        BackupAsset asset,
        ConcurrentDictionary<string, string> shardBySig,
        string deviceDirectory,
        string currentWorkDirectory)
    {
        if (asset.AssetSignature is { Length: 21 } sig)
        {
            var hex = Convert.ToHexString(sig).ToLowerInvariant();
            if (shardBySig.TryGetValue(hex, out var mapped)
                && IsUsablePriorShardFile(mapped, asset.SizeBytes))
                return true;

            // Indice device lazy (entry scritta da run precedenti).
            try
            {
                var entry = IkeBackupOutputPaths.ResolveDeviceSigCacheEntryPath(deviceDirectory, hex);
                if (File.Exists(entry))
                {
                    var target = File.ReadAllText(entry).Trim();
                    if (IsUsablePriorShardFile(target, asset.SizeBytes))
                    {
                        shardBySig[hex] = target;
                        return true;
                    }
                }
            }
            catch
            {
                // fall through fileId
            }
        }

        // Stesso fileID in Backup/ di uno sibling = contenuto invariato (incrementale).
        var fid = asset.EnsureFileId();
        if (string.IsNullOrWhiteSpace(fid))
            return false;
        var prior = IkeBackupOutputPaths.TryFindPriorBackupShard(
            deviceDirectory, fid, currentWorkDirectory);
        if (prior is null || !IsUsablePriorShardFile(prior, asset.SizeBytes))
            return false;

        if (asset.AssetSignature is { Length: 21 } sig2)
        {
            var hex2 = Convert.ToHexString(sig2).ToLowerInvariant();
            shardBySig[hex2] = prior;
            PersistDeviceSigCacheEntry(deviceDirectory, hex2, prior);
        }

        return true;
    }

    private static bool IsUsablePriorShardFile(string? path, long? expectedSizeBytes)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return false;
        long len;
        try
        {
            len = new FileInfo(path).Length;
        }
        catch
        {
            return false;
        }

        if (len <= 0)
            return false;
        if (expectedSizeBytes is > 0 && len != expectedSizeBytes.Value)
            return false;
        return true;
    }

    private static void PersistDeviceSigCacheEntry(
        string? deviceDirectory,
        string sigHex,
        string absolutePath)
    {
        if (string.IsNullOrWhiteSpace(deviceDirectory) || string.IsNullOrWhiteSpace(sigHex))
            return;
        try
        {
            var dir = IkeBackupOutputPaths.ResolveDeviceSigCacheDirectory(deviceDirectory);
            Directory.CreateDirectory(dir);
            var entry = IkeBackupOutputPaths.ResolveDeviceSigCacheEntryPath(deviceDirectory, sigHex);
            File.WriteAllText(entry, absolutePath);
        }
        catch
        {
            // Non bloccare il download se l'indice non è scrivibile.
        }
    }

    private readonly record struct CloneCopyResult(int Copied, List<BackupAsset> Missing);

    /// <summary>
    /// Scaricati + Decifrati + Duplicati per un path copiato (stessa AssetSignature).
    /// I byte Dati si accreditano sul cumulativo <c>totalBytes</c> del caller.
    /// </summary>
    private int _cloneCountUiLogN;

    private void NoteCloneFileCopied(string? path = null, long bytes = 0)
    {
        NoteFileDownloaded("clone_copy", path);
        NoteFileDecrypted("clone_copy", path);
        NoteFileDuplicated();
        // #region agent log
        // Evita flood NDJSON su decine di migliaia di copie (congela I/O + UI).
        var n = Interlocked.Increment(ref _cloneCountUiLogN);
        if (n <= 8 || n % 100 == 0)
        {
            var bytesDl = Volatile.Read(ref _uiBytesDownloaded);
            var duplicated = Volatile.Read(ref _uiFilesDuplicated);
            AgentCountAlways("clone_count_ui", new
            {
                path,
                bytes,
                n,
                downloaded = Volatile.Read(ref _uiFilesDownloaded),
                decrypted = Volatile.Read(ref _uiFilesDecrypted),
                duplicated,
                bytesDl,
                hypothesis = "H-CLONE-BYTES",
            });
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "9a5651",
                    ["runId"] = "bytes-clone-incl-v1",
                    ["hypothesisId"] = "H-CLONE-BYTES",
                    ["location"] = "BackupDownloadService.NoteCloneFileCopied",
                    ["message"] = "clone_count_and_bytes",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        n,
                        cloneFileBytes = bytes,
                        duplicated,
                        bytesDl,
                        uiBytesTotal = Volatile.Read(ref _uiBytesTotal),
                    },
                });
                // Mai Append sync sul hot-path clone (log multi-100MB → I/O stall worker).
                _ = Task.Run(() =>
                {
                    try
                    {
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                            line + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                });
            }
            catch { /* ignore */ }
        }
        // #endregion
    }

    /// <summary>Byte da accreditare sulla barra Dati: SizeBytes asset, altrimenti len file sorgente.</summary>
    private static long ResolveCloneCreditBytes(BackupAsset clone, string srcPath)
    {
        if (clone.SizeBytes is > 0)
            return clone.SizeBytes.Value;
        try
        {
            var len = new FileInfo(srcPath).Length;
            return len > 0 ? len : 0;
        }
        catch
        {
            return 0;
        }
    }

    /// <summary>
    /// Credito barra «Dati»: byte dei <b>chunk data</b> (ChunkInfo referenziati / host dati),
    /// non SizeBytes plaintext e non la lunghezza del compact (Ford‖data + host condivisi
    /// sommati N volte → UI gonfiata vs disco).
    /// </summary>
    private static long ResolveUiProgressCreditBytes(
        BackupAsset asset,
        byte[]? authSlice,
        IReadOnlyList<SignedUrlChunk>? chunks,
        long mmcsCompactOrEdgeBytes,
        int plaintextOrBodyLen = 0)
    {
        var dataChunkBytes = SumAssetDataChunkBytes(authSlice, chunks);
        if (dataChunkBytes > 0)
            return dataChunkBytes;
        // Fallback: body scritto (cipher o plain); mai SizeBytes (gonfia vs edge data).
        if (plaintextOrBodyLen > 0)
            return plaintextOrBodyLen;
        return mmcsCompactOrEdgeBytes > 0 ? mmcsCompactOrEdgeBytes : 0;
    }

    /// <summary>
    /// Somma Length dei ChunkInfo referenziati (payload data MMCS). Esclude host Ford
    /// empty (Containers[i].Count==0) che non entrano in TotalCryptoBytes via refs.
    /// </summary>
    private static long SumAssetDataChunkBytes(
        byte[]? authSlice,
        IReadOnlyList<SignedUrlChunk>? chunks)
    {
        if (authSlice is { Length: > 0 })
        {
            var plan = UbChunkBuilder.BuildDecryptPlan(authSlice);
            long sum = 0;
            if (plan.References.Count > 0)
            {
                foreach (var r in plan.References)
                {
                    if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                        continue;
                    var group = plan.Containers[r.ContainerIndex];
                    if ((uint)r.ChunkIndex >= (uint)group.Count)
                        continue;
                    sum += group[r.ChunkIndex].Length;
                }

                if (sum > 0)
                    return sum;
            }

            // Plan senza refs utili: crypto sum dei soli container non-vuoti.
            if (plan.TotalCryptoBytes > 0)
                return plan.TotalCryptoBytes;
        }

        if (chunks is not { Count: > 0 })
            return 0;

        // Senza auth: somma range host che non sembrano Ford empty (≤65 KiB tipici).
        long rangeSum = 0;
        foreach (var ch in chunks)
        {
            if (ch.ByteRange is not { } br)
                continue;
            var len = br.End - br.Start + 1;
            if (len <= 0)
                continue;
            if (len <= 65_536 && FordMmcsDecryptor.CanContainStandardFordWindow((int)len))
                continue;
            rangeSum += len;
        }

        return rangeSum;
    }

    /// <summary>
    /// Copia path con stessa assetSignature da uno shard già scritto
    /// (stesso run o snapshot precedente — CopySnapshotFiles).
    /// I missing vanno demote → download MMCS (non silenziosi).
    /// Per ogni copia ok: Scaricati+Decifrati + byte size via <paramref name="onCopied"/>.
    /// Copie <see cref="File.Copy"/> in parallelo (<c>IKE_CLONE_PARALLELISM</c>, default 8);
    /// upsert Manifest resta serializzato in <see cref="BackupFilesystemWriter"/>.
    /// </summary>
    private async Task<CloneCopyResult> CopyCloneAssetsAsync(
        List<BackupAsset> clones,
        ConcurrentDictionary<string, string> shardBySig,
        BackupFilesystemWriter fsWriter,
        string cleanDir,
        IProgress<string>? log,
        CancellationToken ct,
        string? deviceDirectory = null,
        Action<BackupAsset, long>? onCopied = null,
        bool allowCrossFlOrPrior = false)
    {
        if (clones.Count == 0)
            return new CloneCopyResult(0, []);

        var work = new List<(BackupAsset Clone, string Src)>(clones.Count);
        var missing = new ConcurrentBag<BackupAsset>();
        foreach (var clone in clones)
        {
            if (clone.AssetSignature is not { Length: 21 } sig)
            {
                missing.Add(clone);
                continue;
            }

            var hex = Convert.ToHexString(sig).ToLowerInvariant();
            if (!shardBySig.TryGetValue(hex, out var src) || !File.Exists(src))
            {
                //  cloni solo da mappa dello stesso FL — niente device cache / sibling.
                if (!allowCrossFlOrPrior)
                {
                    missing.Add(clone);
                    continue;
                }

                string? currentWork = null;
                try
                {
                    var trimmed = cleanDir.TrimEnd(
                        Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
                    currentWork = string.Equals(
                        Path.GetFileName(trimmed),
                        IkeBackupOutputPaths.CleanBackupFolderName,
                        StringComparison.OrdinalIgnoreCase)
                        ? Path.GetDirectoryName(trimmed)
                        : trimmed;
                }
                catch { /* ignore */ }

                if (deviceDirectory is not null
                    && TryBindPriorShardSource(
                        clone, shardBySig, deviceDirectory, currentWork ?? cleanDir)
                    && shardBySig.TryGetValue(hex, out src)
                    && File.Exists(src))
                {
                    // bound from prior snapshot (legacy path only)
                }
                else
                {
                    missing.Add(clone);
                    continue;
                }
            }

            work.Add((clone, src));
        }

        var copied = 0;
        var logOk = 0;
        var parallelism = Math.Min(ResolveCloneParallelism(), Math.Max(1, work.Count));
        var sw = Environment.TickCount64;
        if (work.Count > 0)
        {
            await Parallel.ForEachAsync(
                work,
                new ParallelOptions
                {
                    MaxDegreeOfParallelism = parallelism,
                    CancellationToken = ct,
                },
                async (item, token) =>
                {
                    try
                    {
                        var dest = await fsWriter.CopyExistingAsync(item.Clone, item.Src, token)
                            .ConfigureAwait(false);
                        RememberShardPath(item.Clone, shardBySig, cleanDir, deviceDirectory);

                        var bytes = ResolveCloneCreditBytes(item.Clone, item.Src);
                        var n = Interlocked.Increment(ref copied);
                        onCopied?.Invoke(item.Clone, bytes);
                        // #region agent log
                        if (Interlocked.Increment(ref logOk) <= 8)
                        {
                            AgentDebugLog("H-DUP", "BackupDownloadService.CopyCloneAssetsAsync",
                                "clone_ok", new
                                {
                                    path = item.Clone.RelativePath,
                                    dest = Path.GetFileName(dest),
                                    bytes,
                                    srcExists = true,
                                    fromPrior = !item.Src.StartsWith(
                                        cleanDir, StringComparison.OrdinalIgnoreCase),
                                    parallelism,
                                },
                                runId: "clone-par-v1");
                        }
                        // #endregion
                        _ = n;
                    }
                    catch (Exception ex)
                    {
                        missing.Add(item.Clone);
                        log?.Report(
                            $"  clone skip {item.Clone.RelativePath ?? item.Clone.RecordName}: {ex.Message}");
                    }
                }).ConfigureAwait(false);
        }

        var elapsedMs = Environment.TickCount64 - sw;
        var missingList = missing.ToList();
        if (copied > 0 || missingList.Count > 0)
        {
            log?.Report(
                $"  copie path duplicati: ok={copied}, srcAssente={missingList.Count} " +
                $"(parallel={parallelism}, {elapsedMs} ms)");
            // #region agent log
            AgentCountAlways("clone_copy_parallel", new
            {
                copied,
                missing = missingList.Count,
                clones = clones.Count,
                work = work.Count,
                parallelism,
                elapsedMs,
                hypothesis = "H-CLONE-PAR",
            });
            AgentDebugLog("H-DUP", "BackupDownloadService.CopyCloneAssetsAsync",
                "clone_summary", new
                {
                    copied,
                    missing = missingList.Count,
                    clones = clones.Count,
                    parallelism,
                    elapsedMs,
                },
                runId: "clone-par-v1");
            // #endregion
        }

        return new CloneCopyResult(copied, missingList);
    }


    private static byte[] TryDecryptBackupFileBody(
        BackupAsset asset,
        byte[] body,
        BackupFileKeyContext fileKeyCtx,
        IProgress<string>? log,
        out bool decrypted)
    {
        decrypted = false;
        if (fileKeyCtx.IsEmpty
            || asset.EncryptionKey is not { Length: > 0 } encKey
            || asset.ProtectionClass is not int pc)
            return body;

        if (!fileKeyCtx.TryUnwrapFileKey(encKey, pc, out var fileKey, out var err, out var source)
            || fileKey is null)
        {
            if (!string.IsNullOrWhiteSpace(err))
                log?.Report($"  file decrypt skip: {err}");
            return body;
        }

        try
        {
            using var aes = System.Security.Cryptography.Aes.Create();
            aes.Key = fileKey.Length >= 16 ? fileKey.AsSpan(0, 16).ToArray() : fileKey;
            aes.Mode = System.Security.Cryptography.CipherMode.CBC;
            aes.Padding = System.Security.Cryptography.PaddingMode.None;
            var iv = new byte[16];
            var truncated = body.Length - (body.Length % 16);
            if (truncated <= 0)
                return body;
            using var dec = aes.CreateDecryptor(aes.Key, iv);
            var plain = dec.TransformFinalBlock(body, 0, truncated);
            var size = plain.Length;
            if (asset.SizeBytes is > 0 and <= int.MaxValue)
                size = Math.Min(size, (int)asset.SizeBytes.Value);
            log?.Report($"  file AES-CBC OK (class={pc}, {source}, {size:N0} B)");
            decrypted = true;
            return plain.AsSpan(0, size).ToArray();
        }
        catch (Exception ex)
        {
            log?.Report($"  file AES-CBC fail: {ex.Message}");
            return body;
        }
    }

    private async Task<List<BackupAsset>> ResolveAssetsForCatalogAsync(
        ICloudSession session,
        DownloadJob job,
        DeterministicFileCatalog catalog,
        IProgress<string>? log,
        CancellationToken ct,
        EnFetchResult? enFetch = null)
    {
        var fileRecordNames = catalog.FileRecordNames;
        var preAuth = _assets.GetPreAuthMmcsAuthHeaders();
        var byF2 = MmcsAuthBuilder.IndexAuthsByChecksum(preAuth);
        log?.Report($"  PreAuth auth disponibili: {preAuth.Count} (indice f2={byF2.Count})");

        // Path moderno: :CN: → EN: (capture); fallback discovery/PreAuth.
        if (string.Equals(catalog.Source, "modern-CN", StringComparison.OrdinalIgnoreCase))
        {
            log?.Report(
                "  catalogo modern-CN — auth MMCS da EN: (preferito) / PreAuth / query KA:MA");
            return await ResolveModernCnDownloadAssetsAsync(
                session, job, byF2, log, ct, enFetch);
        }

        var names = fileRecordNames.AsEnumerable();
        if (job.MaxAssets is > 0)
            names = names.Take(job.MaxAssets.Value);

        var ready = new List<BackupAsset>();
        var checksumHits = 0;
        var fetchHits = 0;
        var missing = 0;

        foreach (var name in names)
        {
            ct.ThrowIfCancellationRequested();
            var isCn = name.StartsWith(":CN:", StringComparison.OrdinalIgnoreCase)
                       || name.StartsWith("CN:", StringComparison.OrdinalIgnoreCase);

            var asset = new BackupAsset
            {
                RecordName = name,
                ZoneName = "_defaultZone",
                SizeBytes = UbChunkBuilder.ExtractDeclaredSize(name)
            };

            var hex = MmcsAuthBuilder.TryExtractAssetChecksumHex(name);
            if (hex is not null && byF2.TryGetValue(hex, out var auth))
            {
                asset.MmcsAuth = auth;
                ready.Add(asset);
                checksumHits++;
                continue;
            }

            // :CN: non è un record retrieveable — senza match f2 resta missing.
            if (isCn)
            {
                missing++;
                continue;
            }

            // Fetch record → ParseAssetRecord (campo contents / mmcs auth).
            try
            {
                var fetched = await _assets.TryResolveAssetAuthAsync(session, name, log, ct);
                if (fetched is not null && !string.IsNullOrWhiteSpace(fetched.MmcsAuth))
                {
                    ready.Add(fetched);
                    fetchHits++;
                    continue;
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  auth skip {name}: {ex.Message}");
            }

            missing++;
        }

        log?.Report(
            $"  auth risolti: checksum={checksumHits}, fetch={fetchHits}, missing={missing}, ready={ready.Count}");

        if (ready.Count == 0 && preAuth.Count > 0)
        {
            log?.Report("  join catalogo↔f2 vuoto — fallback auth PreAuth diretti (authorizeGet)");
            return TakeMax(BuildAssetsFromPreAuthAuths(preAuth), job.MaxAssets);
        }

        return ready;
    }

    /// <summary>
    /// §6–7: catalogo N: post-Lock → asset con auth MMCS;
    /// fallback discovery/PreAuth solo se il catalogo N: non ha auth.
    /// </summary>
    private async Task<List<BackupAsset>> ResolveModernCnDownloadAssetsAsync(
        ICloudSession session,
        DownloadJob job,
        IReadOnlyDictionary<string, string> byF2,
        IProgress<string>? log,
        CancellationToken ct,
        EnFetchResult? enFetch = null)
    {
        if (enFetch is { HasAuth: true })
        {
            var fromEn = BackupEnRecordService.BuildAssetsFromEn(enFetch);
            var fileListCount = fromEn.Count(static a =>
                a.RecordName.StartsWith("FL:", StringComparison.Ordinal));
            var kalamaSeeds = CollectKaLaMaSeeds(enFetch, job.Device);
            log?.Report(
                $"  N: catalogo → {fromEn.Count:N0} asset con auth " +
                $"(fileList={fileListCount}, flistHints={enFetch.FlistEntries.Count}, " +
                $"signed={enFetch.SignedChunks.Count}, seeds KA/LA/MA={kalamaSeeds.Count})");
            log?.Report(
                "  PrivilegedBatch KA/LA/MA deferred — interleaved in download " +
                "(payload→auth→edge→decrypt per file, come)");

            // Solo FL + auth EN: niente fetch di massa. I seed restano per la fase 3.
            if (fromEn.Count > 0)
                return fromEn;
        }
        else if (enFetch is { HasDownloadMaterial: true })
        {
            log?.Report(
                $"  N: signed={enFetch.SignedChunks.Count} path={enFetch.SignedPaths.Count} " +
                "senza auth f2/f5/f17 — discovery con seed, no stub PreAuth di massa");
        }
        else if (enFetch is not null)
        {
            log?.Report(
                $"  N: senza materiale (resp={enFetch.TotalResponseBytes:N0} B) — fallback discovery/PreAuth");
        }

        if (enFetch is { QuerySeeds.Count: > 0 })
        {
            foreach (var seed in enFetch.QuerySeeds)
                job.Device.AssetHints.Add(seed);
        }

        var discovered = await _assets.DiscoverAssetsAsync(
            session, job.Device, job.Snapshot, job.MaxAssets, log, ct);

        var withAuth = discovered
            .Where(static a => !string.IsNullOrWhiteSpace(a.MmcsAuth))
            .ToList();

        var joined = 0;
        foreach (var asset in discovered)
        {
            if (!string.IsNullOrWhiteSpace(asset.MmcsAuth))
                continue;
            var hex = MmcsAuthBuilder.TryExtractAssetChecksumHex(asset.RecordName);
            if (hex is null || !byF2.TryGetValue(hex, out var auth))
                continue;
            asset.MmcsAuth = auth;
            withAuth.Add(asset);
            joined++;
        }

        log?.Report(
            $"  discovery → {discovered.Count:N0} asset, con auth={withAuth.Count:N0} " +
            $"(+join f2={joined})");

        if (withAuth.Count > 0)
            return TakeMax(withAuth, job.MaxAssets);

        if (enFetch is { HasAuth: true })
        {
            log?.Report("  N: aveva auth ma join KA/MA vuoto — skip stub PreAuth");
            return [];
        }

        var preAuth = _assets.GetPreAuthMmcsAuthHeaders();
        if (preAuth.Count == 0)
            return [];

        log?.Report(
            $"  fallback {preAuth.Count} auth PreAuth (join checksum↔discovery se possibile)");
        return TakeMax(BuildAssetsFromPreAuthAuths(preAuth, discovered), job.MaxAssets);
    }

    /// <summary>
    /// Seed PrivilegedBatch: QuerySeeds / AssetRecordNames / flist (con <c>=:size</c>).
    /// Esclude <c>newAssets</c>/<c>deletedAssets</c> (ref spesso stale → NOT_FOUND).
    /// </summary>
    private static List<string> CollectKaLaMaSeeds(EnFetchResult en, BackupDevice device)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in en.QuerySeeds)
            set.Add(s);
        foreach (var s in en.AssetRecordNames)
            set.Add(s);
        foreach (var e in en.FlistEntries)
        {
            if (!string.IsNullOrWhiteSpace(e.AssetRecordName))
                set.Add(e.AssetRecordName);
        }

        foreach (var h in device.AssetHints)
            set.Add(h);

        return CloudKitAssetService.NormalizeKaLaMaSeeds(set);
    }

    private static List<BackupAsset> BuildAssetsFromPreAuthAuths(
        IReadOnlyList<string> preAuthHeaders,
        IReadOnlyList<BackupAsset>? discovered = null)
    {
        // Indice discovery per checksum nome record (KA:/MA:…:base64:size).
        var byChecksum = new Dictionary<string, BackupAsset>(StringComparer.OrdinalIgnoreCase);
        if (discovered is { Count: > 0 })
        {
            foreach (var asset in discovered)
            {
                var hex = MmcsAuthBuilder.TryExtractAssetChecksumHex(asset.RecordName);
                if (hex is null || byChecksum.ContainsKey(hex))
                    continue;
                byChecksum[hex] = asset;
            }
        }

        var ready = new List<BackupAsset>(preAuthHeaders.Count);
        var i = 0;
        var matched = 0;
        foreach (var auth in preAuthHeaders)
        {
            if (auth.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length < 3)
                continue;

            var f2 = MmcsAuthBuilder.TryExtractFileChecksumHex(auth) ?? $"idx{i}";
            if (byChecksum.TryGetValue(f2, out var known))
            {
                known.MmcsAuth = auth;
                ready.Add(known);
                matched++;
            }
            else
            {
                ready.Add(new BackupAsset
                {
                    RecordName = $"MMCS:{f2}",
                    ZoneName = "_defaultZone",
                    MmcsAuth = auth
                });
            }

            i++;
        }

        _ = matched; // log dal caller se serve
        return ready;
    }

    private static List<BackupAsset> TakeMax(List<BackupAsset> assets, int? maxAssets)
    {
        if (maxAssets is > 0 && assets.Count > maxAssets.Value)
            return assets.Take(maxAssets.Value).ToList();
        return assets;
    }

    /// <summary>
    /// post-flist / pre-AG: materializza i Record BackupAsset owned sul batch
    /// pronto per authorizeGet (live: FillFord legge già <c>map["contents"]</c>).
    /// PrivilegedBatch resta solo MmcsAuth — qui è il fetch #2
    /// (<c>A:pref4:rid</c> → contents wrap; UUID nudo → NOT_FOUND).
    /// </summary>
    private async Task PrefetchOwnedBackupAssetPayloadsAsync(
        ICloudSession session,
        IReadOnlyList<BackupAsset> readyBatch,
        string? workDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (readyBatch.Count == 0)
            return;

        var dop = Math.Clamp(AuthorizeGetBatchSize, 2, 8);
        var ok = 0;
        var miss = 0;
        await Parallel.ForEachAsync(
            readyBatch,
            new ParallelOptions
            {
                MaxDegreeOfParallelism = dop,
                CancellationToken = ct,
            },
            async (asset, token) =>
            {
                await EnsureAssetRecordPayloadAsync(session, asset, log, token)
                    .ConfigureAwait(false);
                if (!string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                    || (asset.RecordPayload is { Length: > 32 }
                        && AssetRecordWindowBelongsTo(asset, asset.RecordPayload)))
                    Interlocked.Increment(ref ok);
                else
                    Interlocked.Increment(ref miss);
            }).ConfigureAwait(false);

        // #region agent log
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-PREFETCH",
                ["runId"] = "owned-ba-seed-v2",
                ["location"] = "BackupDownloadService.PrefetchOwnedBackupAssetPayloadsAsync",
                ["message"] = "owned_ba_prefetch_batch",
                ["data"] = new Dictionary<string, object?>
                {
                    ["batch"] = readyBatch.Count,
                    ["ok"] = ok,
                    ["miss"] = miss,
                    ["dop"] = dop,
                    ["domain"] = readyBatch[0].Domain,
                    ["pref4"] = _activeDevicePrefix4 ?? "",
                    ["workDir"] = workDirectory is null ? "" : Path.GetFileName(workDirectory),
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        if (miss > 0 && ok == 0)
            log?.Report(
                $"  owned BackupAsset prefetch: 0/{readyBatch.Count} con RP/wrap " +
                "(FillFord-equiv verrà ritentato per-file)");
        else if (readyBatch.Count >= 4)
            log?.Report(
                $"  owned BackupAsset prefetch: {ok}/{readyBatch.Count} pronti " +
                $"(wrap/RP; miss={miss})");
    }

    /// <summary>
    /// PrepareFiles: parent Record già sulla query PrivilegedBatch del rid
    /// (<see cref="AttachFetchedAuthToFlistAssets"/>). Qui si fa fetch solo se
    /// manca ancora la finestra owned (contents/extension/version) per FillFord.
    /// Mai riusare il payload batch intero né RP di un altro rid.
    /// </summary>
    private async Task EnsureAssetRecordPayloadAsync(
        ICloudSession session,
        BackupAsset asset,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (!IsCloudKitAssetRecordName(asset.RecordName))
            return;

        // Alien RP (batch sibling) → drop; usa solo il Record del file.
        if (asset.RecordPayload is { Length: > 32 }
            && !AssetRecordWindowBelongsTo(asset, asset.RecordPayload))
        {
            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-BA2",
                    ["runId"] = "owned-backupasset-v1",
                    ["location"] = "BackupDownloadService.EnsureAssetRecordPayloadAsync",
                    ["message"] = "cleared_alien_rp_before_fetch",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["path"] = asset.RelativePath ?? asset.RecordName,
                        ["recordName"] = asset.RecordName,
                        ["rpLen"] = asset.RecordPayload.Length,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            asset.RecordPayload = null;
            asset.AssetProtectionInfoHex = null;
            asset.AssetUnwrappedKey = null;
            asset.AssetUnwrappedKeyWrapHex = null;
        }

        var haveOwnedRp = asset.RecordPayload is { Length: > 32 }
            && AssetRecordWindowBelongsTo(asset, asset.RecordPayload);
        // Fetch solo se manca RP owned o manca wrap contents (IKM lo fa EnsureAssetWrapAndIkm).
        var needContentsWrap = string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex);
        if (haveOwnedRp && !needContentsWrap)
        {
            // Wrap già bound: allinea comunque MmcsAuth al RP (Books flist↔rpF17 desync).
            TryBindMmcsAuthFromOwnedRecord(asset);
            return;
        }

        // Owned RP c’è ma manca wrap: prova contents sul window prima di HTTP.
        if (haveOwnedRp
            && needContentsWrap
            && asset.AssetSignature is { Length: >= 4 } sigLocal
            && asset.RecordPayload is { Length: > 32 } winLocal)
        {
            var localWrap = CloudKitAssetProto.TryResolveOwnedWrap(winLocal, sigLocal, out var localSrc);
            if (localWrap is { Length: 24 or 40 })
            {
                asset.AssetProtectionInfoHex = Convert.ToHexString(localWrap);
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-BA3",
                        ["runId"] = "owned-backupasset-v1",
                        ["location"] = "BackupDownloadService.EnsureAssetRecordPayloadAsync",
                        ["message"] = "bound_contents_from_owned_rp",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["source"] = localSrc,
                            ["wrapLen"] = localWrap.Length,
                            ["fetched"] = false,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                TryBindMmcsAuthFromOwnedRecord(asset);
                return;
            }
        }

        // Seed wire PrivilegedBatch/retrieve: A:pref4:rid. UUID nudo → NOT_FOUND
        // e ParseAssetRecord (pre-fix) saltava i candidati non-KA/MA.
        // Size flist ≠ size nel recordName (=:10676 vs sum 11264) → prova varianti.
        var fetchNames = ResolveOwnedBackupAssetFetchNames(asset);
        var fetchName = fetchNames.Count > 0 ? fetchNames[0] : asset.RecordName;
        // #region agent log
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-SEED",
                ["runId"] = "owned-ba-seed-v3",
                ["location"] = "BackupDownloadService.EnsureAssetRecordPayloadAsync",
                ["message"] = "owned_ba_fetch_name",
                ["data"] = new Dictionary<string, object?>
                {
                    ["path"] = asset.RelativePath ?? asset.RecordName,
                    ["recordName"] = asset.RecordName,
                    ["fetchName"] = fetchName.Length > 96 ? fetchName[..96] : fetchName,
                    ["fetchVariants"] = fetchNames.Count,
                    ["fetchIsUuid"] = CloudKitMmcsIds.IsUuidRecordName(fetchName),
                    ["hasRid"] = !string.IsNullOrWhiteSpace(asset.RecordIdSuffix),
                    ["hasPref4"] = !string.IsNullOrWhiteSpace(_activeDevicePrefix4),
                    ["hadOwnedRp"] = haveOwnedRp,
                    ["size"] = asset.SizeBytes,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        try
        {
            BackupAsset? fetched = null;
            foreach (var tryName in fetchNames)
            {
                fetched = await _assets.TryResolveAssetAuthAsync(session, tryName, log, ct)
                    .ConfigureAwait(false);
                if (fetched is null)
                    continue;
                // Preferisci hit con wrap/RP contents.
                if (!string.IsNullOrWhiteSpace(fetched.AssetProtectionInfoHex)
                    || fetched.RecordPayload is { Length: > 32 })
                {
                    fetchName = tryName;
                    break;
                }
            }

            if (fetched is null)
            {
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-BA1",
                        ["runId"] = "owned-ba-seed-v3",
                        ["location"] = "BackupDownloadService.EnsureAssetRecordPayloadAsync",
                        ["message"] = "owned_backupasset_fetch_miss",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["recordName"] = asset.RecordName,
                            ["fetchName"] = fetchName.Length > 96 ? fetchName[..96] : fetchName,
                            ["fetchVariants"] = fetchNames.Count,
                            ["hadOwnedRp"] = haveOwnedRp,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                return;
            }

            if (fetched.RecordPayload is { Length: > 32 } fp
                && AssetRecordWindowBelongsTo(asset, fp))
            {
                asset.RecordPayload = fp;
                haveOwnedRp = true;
            }

            if (string.IsNullOrWhiteSpace(asset.MmcsAuth) && !string.IsNullOrWhiteSpace(fetched.MmcsAuth))
                asset.MmcsAuth = fetched.MmcsAuth;
            if (string.IsNullOrWhiteSpace(asset.RecordProtectionInfoDerHex)
                && !string.IsNullOrWhiteSpace(fetched.RecordProtectionInfoDerHex))
                asset.RecordProtectionInfoDerHex = fetched.RecordProtectionInfoDerHex;
            if (string.IsNullOrWhiteSpace(asset.Extension) && !string.IsNullOrWhiteSpace(fetched.Extension))
                asset.Extension = fetched.Extension;

            // map["contents"]: wrap dal field contents del Record owned — non first-wrap batch.
            byte[]? wrap = null;
            var src = "missing";
            if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                && asset.AssetSignature is { Length: >= 4 } sig
                && asset.RecordPayload is { Length: > 32 } win)
            {
                wrap = CloudKitAssetProto.TryResolveOwnedWrap(win, sig, out src);
                if (wrap is { Length: 24 or 40 })
                    asset.AssetProtectionInfoHex = Convert.ToHexString(wrap);
                else if (!string.IsNullOrWhiteSpace(fetched.AssetProtectionInfoHex)
                         && fetched.RecordPayload is { Length: > 32 } fWin
                         && AssetRecordWindowBelongsTo(asset, fWin))
                {
                    try
                    {
                        var hw = Convert.FromHexString(fetched.AssetProtectionInfoHex);
                        if (CloudKitAssetProto.IsOwnedWrap(fWin, sig, hw))
                        {
                            asset.AssetProtectionInfoHex = fetched.AssetProtectionInfoHex;
                            src = "fetched-protectionInfo-owned";
                            wrap = hw;
                        }
                    }
                    catch { /* ignore */ }
                }
            }

            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-BA3",
                    ["runId"] = "owned-ba-seed-v2",
                    ["location"] = "BackupDownloadService.EnsureAssetRecordPayloadAsync",
                    ["message"] = !string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                        ? "owned_backupasset_fetch_wrap_ok"
                        : "owned_backupasset_fetch_wrap_miss",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["path"] = asset.RelativePath ?? asset.RecordName,
                        ["recordName"] = asset.RecordName,
                        ["fetchName"] = fetchName.Length > 96 ? fetchName[..96] : fetchName,
                        ["rpLen"] = asset.RecordPayload?.Length ?? 0,
                        ["wrapLen"] = wrap?.Length
                            ?? (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                                ? 0
                                : asset.AssetProtectionInfoHex.Length / 2),
                        ["source"] = src,
                        ["fetched"] = true,
                        ["haveOwnedRp"] = haveOwnedRp,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion

            TryBindMmcsAuthFromOwnedRecord(asset);
        }
        catch (Exception ex)
        {
            log?.Report($"  payload fetch skip {fetchName}: {ex.Message}");
        }
    }

    /// <summary>
    /// Nome CK per retrieve owned BackupAsset: <c>A:{pref4}:{rid}</c>.
    /// UUID flist da solo → PrivilegedBatch NOT_FOUND.
    /// </summary>
    private string ResolveOwnedBackupAssetFetchName(BackupAsset asset) =>
        ResolveOwnedBackupAssetFetchNames(asset)[0];

    /// <summary>
    /// Candidati fetch: recordName, size flist, varianti base64.
    /// Evita UUID nudo (Domain Authy multi-asset → no-ikm).
    /// </summary>
    private List<string> ResolveOwnedBackupAssetFetchNames(BackupAsset asset)
    {
        var list = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void Add(string? name)
        {
            if (string.IsNullOrWhiteSpace(name) || CloudKitMmcsIds.IsUuidRecordName(name))
                return;
            if (!seen.Add(name))
                return;
            list.Add(name);
        }

        if (!CloudKitMmcsIds.IsUuidRecordName(asset.RecordName)
            && CloudKitMmcsIds.IsAssetRecordName(asset.RecordName))
        {
            foreach (var v in CloudKitMmcsIds.EnumerateAssetRecordNameVariants(
                         asset.RecordName, asset.SizeBytes))
                Add(v);
        }

        var rid = asset.RecordIdSuffix;
        if (string.IsNullOrWhiteSpace(rid)
            && !string.IsNullOrWhiteSpace(asset.RecordName)
            && CloudKitMmcsIds.IsUuidRecordName(asset.RecordName))
            rid = asset.RecordName;

        if (!string.IsNullOrWhiteSpace(rid)
            && !string.IsNullOrWhiteSpace(_activeDevicePrefix4)
            && CloudKitMmcsIds.ToPrivilegedBatchSeed(_activeDevicePrefix4, rid) is { } seed)
        {
            foreach (var v in CloudKitMmcsIds.EnumerateAssetRecordNameVariants(seed, asset.SizeBytes))
                Add(v);
        }

        if (list.Count == 0)
            Add(asset.RecordName);
        if (list.Count == 0)
            list.Add(asset.RecordName);
        return list;
    }

    /// <summary>
    /// FillFord prep: owned BackupAsset Record → contents wrap → IKM@+0x160.
    /// </summary>
    private async Task EnsureAssetWrapAndIkmAsync(
        ICloudSession session,
        BackupAsset asset,
        string? workDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        await EnsureAssetRecordPayloadAsync(session, asset, log, ct).ConfigureAwait(false);
        await Task.Run(() => EnsureAssetWrapAndIkm(session, asset, workDirectory, log), ct)
            .ConfigureAwait(false);

        // Query aveva restituito batch/RP senza wrap owned → clear e re-fetch varianti size.
        if (asset.AssetUnwrappedKey is { Length: 16 or 32 }
            || !string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
            return;
        if (!IsCloudKitAssetRecordName(asset.RecordName)
            && string.IsNullOrWhiteSpace(asset.RecordIdSuffix))
            return;

        asset.RecordPayload = null;
        asset.AssetProtectionInfoHex = null;
        asset.AssetUnwrappedKey = null;
        asset.AssetUnwrappedKeyWrapHex = null;
        asset.CkFileAsset = null;
        // #region agent log
        try
        {
            AgentNdjsonAlways(JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "wrap-refetch-v1",
                ["hypothesisId"] = "H-NO-WRAP",
                ["location"] = "BackupDownloadService.EnsureAssetWrapAndIkmAsync",
                ["message"] = "force_refetch_after_no_wrap",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new
                {
                    path = asset.RelativePath ?? asset.RecordName,
                    record = asset.RecordName,
                    size = asset.SizeBytes,
                },
            }));
        }
        catch { /* ignore */ }
        // #endregion
        await EnsureAssetRecordPayloadAsync(session, asset, log, ct).ConfigureAwait(false);
        await Task.Run(() => EnsureAssetWrapAndIkm(session, asset, workDirectory, log), ct)
            .ConfigureAwait(false);
    }

    private static bool IsCloudKitAssetRecordName(string recordName) =>
        CloudKitMmcsIds.IsUuidRecordName(recordName)
        || CloudKitMmcsIds.IsAssetRecordName(recordName)
        || recordName.StartsWith("KA:", StringComparison.Ordinal)
        || recordName.StartsWith("MA:", StringComparison.Ordinal)
        || recordName.StartsWith("LA:", StringComparison.Ordinal)
        || recordName.StartsWith("NA:", StringComparison.Ordinal)
        || recordName.StartsWith("JA:", StringComparison.Ordinal);

    private sealed record AssembleResult(
        long DownloadedBytes,
        string AssemblyMode,
        string PlanSummary,
        bool MmcsDecrypted,
        /// <summary>Body in RAM (MMCS plain o cipher) — evita staging OBJ_* su path flist.</summary>
        byte[]? Body = null);

    /// <summary>
    /// Compact edge download + BuildDecryptPlan assembly (refs). Opzionale DecryptAndAssemble.
    /// Fallback seek-by-Start solo se plan vuoto.
    /// </summary>
    private async Task<AssembleResult> DownloadAssembleAssetAsync(
        ICloudSession session,
        BackupAsset asset,
        string outputFile,
        byte[] authBody,
        IReadOnlyList<SignedUrlChunk> chunks,
        int assetIndex,
        int assetTotal,
        IProgress<DownloadProgressReport>? progress,
        IProgress<string>? log,
        CancellationToken ct,
        bool tryMmcsDecrypt,
        string? workDirectory = null,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts = null,
        byte[]? prebuiltCompact = null,
        bool deferDecrypt = false)
    {
        var plan = UbChunkBuilder.BuildDecryptPlan(authBody);
        var planSummary =
            $"crypto={plan.TotalCryptoChunks} refs={plan.References.Count} sum={plan.TotalCryptoBytes:N0}";

        //  FileGroup materials sullo stesso CKFile (gate/ctLen/refs/companion).
        AssetMaterialPipeline.AttachFileGroupMaterials(asset, authBody, plan, chunks);

        // Sempre compact-concat: content-byte-range è offset nell'oggetto MMCS, NON nel file
        // di output. Seek su Start lascia NULL in testa (bug osservato su Backup/OBJ).
        var orderedChunks = UbChunkBuilder.OrderChunksForFordFile(chunks, authBody);

        var compactPath = outputFile + ".compact.tmp";
        long downloadedBytes;
        try
        {
            byte[] compact;
            ConcurrentDictionary<string, (byte[] Compact, long MmcsStart)> sibMap;
            if (siblingCompacts is ConcurrentDictionary<string, (byte[] Compact, long MmcsStart)> existing)
                sibMap = existing;
            else
            {
                sibMap = new ConcurrentDictionary<string, (byte[] Compact, long MmcsStart)>(
                    StringComparer.Ordinal);
                if (siblingCompacts is { Count: > 0 })
                {
                    foreach (var kv in siblingCompacts)
                        sibMap[kv.Key] = kv.Value;
                }
            }

            if (prebuiltCompact is { Length: > 0 })
            {
                // #region agent log
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.DownloadAssembleAssetAsync",
                    "edge compact from cache",
                    new
                    {
                        record = asset.RecordName,
                        bytes = prebuiltCompact.Length,
                        chunks = orderedChunks.Count,
                    },
                    "H-P0-CACHE",
                    "post-fix");
                // #endregion
                //  non usare la concat per decrypt — body già in MMCS/siblings (SeedSiblingCompactsFromPart).
                compact = Array.Empty<byte>();
                downloadedBytes = prebuiltCompact.Length;
            }
            else
            {
                // #region agent log
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.DownloadAssembleAssetAsync",
                    "edge per-host GET",
                    new
                    {
                        record = asset.RecordName,
                        chunks = orderedChunks.Count,
                        parallelism = BackupEdgeDownloadParallelism,
                    },
                    "H-P0-DOWNLOAD",
                    "post-fix");
                // #endregion
                var edgeAuth = CreateAssetEdgeAuthState(
                    session,
                    asset,
                    authBody,
                    chunks,
                    workDirectory,
                    log);
                var (downloaded, bodies) = await DownloadChunksPerHostAsync(
                    orderedChunks,
                    assetIndex,
                    assetTotal,
                    progress,
                    ct,
                    _http,
                    edgeAuth).ConfigureAwait(false);
                authBody = edgeAuth.AuthBody;
                orderedChunks = UbChunkBuilder.OrderChunksForFordFile(edgeAuth.Chunks, authBody);
                chunks = edgeAuth.Chunks;
                downloadedBytes = downloaded;
                SeedOidHostsFromBodies(orderedChunks, bodies, sibMap);
                compact = Array.Empty<byte>();
            }

            siblingCompacts = sibMap;

            // Compact grezzo edge: deprecato (= GET per-host). Sidecar solo se ancora pieno.
            if (IkeDiskDumpOptions.DumpEdgeSidecars && compact.Length > 0)
            {
                await File.WriteAllBytesAsync(outputFile + ".edge_compact.bin", compact, ct)
                    .ConfigureAwait(false);
            }

            if (deferDecrypt)
            {
                return new AssembleResult(
                    downloadedBytes,
                    "deferred",
                    planSummary,
                    false);
            }

            var ranges = orderedChunks
                .Where(static c => c.ByteRange is not null)
                .Select(static c => c.ByteRange!.Value)
                .ToList();

            //  owned BackupAsset Record → contents wrap → IKM prima di SpillOpen/Fill.
            await EnsureAssetWrapAndIkmAsync(session, asset, workDirectory, log, ct)
                .ConfigureAwait(false);

            var canMmcs = tryMmcsDecrypt
                          || asset.AssetUnwrappedKey is { Length: > 0 }
                          || !string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                          // FL / Pipe C: chunkEncryptionKey nei refs anche senza wrap Asset.
                          || FileGroupFillDecrypt.PlanHasChunkEncryptionKeys(plan);
            if (UbChunkBuilder.IsFordFamilySingleGet(plan)
                || UbChunkBuilder.IsFordFamilyZeroKeyPlan(plan))
                canMmcs = false;

            var usePlan = plan.References.Count > 0 && plan.TotalCryptoChunks > 0;
            //  IKM già sul CKFile (FillFord). Riusa CkFileAsset.Ikm se presente.
            var fordIkm = asset.CkFileAsset?.Ikm is { Length: 16 or 32 } ckIkm
                ? ckIkm
                : TryResolveFordIkm(asset, out _);
            if (fordIkm is { Length: 16 or 32 }
                && asset.CkFileAsset is { } ckRefresh)
            {
                ckRefresh.Ikm = fordIkm;
                ckRefresh.IkmSource = asset.CkFileAsset.IkmSource is "missing" or "unwrap-failed"
                    ? "TryResolveFordIkm"
                    : asset.CkFileAsset.IkmSource;
            }

            // SpillOpen con IKM: reject poison cache + packScan lead-0x04 (ike_run).
            LiveFillPipeline.PutChunksFromHostBodies(
                sibMap, plan, chunks, authBody, fordIkm ?? []);
            FileGroupFillDecrypt.PlantAuthChecksumSlicesIntoMap(
                sibMap, plan, chunks, sibMap, fordIkm: fordIkm ?? []);
            // #region agent log
            AgentD3IkmLog(
                "AssembleChunks.TryResolveFordIkm",
                fordIkm is { Length: > 0 } ? "ike_ford_ikm_ok" : "ike_ford_ikm_miss",
                asset,
                fordIkm,
                asset.CkFileAsset?.IkmSource ?? "TryResolveFordIkm",
                TryWrapLen(asset.AssetProtectionInfoHex));
            // #endregion

            // H-ORDER readiness: non TraceDecrypt se il CT Ford owned non è ancora
            // materializzabile (body OID in arrivo da altro host/AG). Defer + pending
            // per-gate; retry quando OidHostBodyCache.Put recupera il CT.
            if (fordIkm is { Length: 16 or 32 }
                && !OidHostBodyCache.TryOwnedFordCtAvailable(
                    authBody, plan, chunks, sibMap, fordIkm))
            {
                var deferPath = asset.RelativePath ?? asset.RecordName ?? outputFile;
                OidHostBodyCache.RegisterOwnedPendings(
                    authBody, plan, chunks, fordIkm, deferPath);
                _oidOrderRetries[deferPath] = new OidOrderRetry(
                    session, asset, outputFile, authBody, chunks, workDirectory,
                    assetIndex, assetTotal, progress, Attempts: 0);
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "03cce7",
                            ["runId"] = "oid-order-v2",
                            ["hypothesisId"] = "H-ORDER",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["location"] = "BackupDownloadService.DownloadAssembleAssetAsync",
                            ["message"] = "ford_decrypt_deferred",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["path"] = deferPath,
                                ["sib"] = sibMap.Count,
                                ["ikmLen"] = fordIkm.Length,
                                ["pendingGates"] = OidHostBodyCache.PendingCount,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                log?.Report(
                    $"  {asset.RecordName}: Ford CT owned non pronto — defer (H-ORDER)");
                return new AssembleResult(
                    compact.LongLength,
                    "ike-ford-deferred",
                    planSummary,
                    false,
                    Body: null);
            }

            log?.Report($"  {asset.RecordName}: FileGroup FillDecrypt (unica strada)");
            byte[]? mmcsKek = null;
            if (canMmcs)
                mmcsKek = TryResolveMmcsKek(session, asset, log);

            // FillChunks(CKFile, fordStorages) — IKM = CKFile+0x160.
            var trace = await Task.Run(
                () => FileGroupFillDecrypt.TraceDecrypt(
                    asset,
                    compact,
                    authBody,
                    plan,
                    orderedChunks,
                    chunks,
                    fordIkm ?? [],
                    siblingCompacts,
                    canMmcs,
                    mmcsKek),
                ct).ConfigureAwait(false);

            var pipe = FileGroupFillDecrypt.ToResult(
                string.IsNullOrEmpty(trace.FailReason) && trace.Plaintext is { Length: > 0 } pt
                    ? new FileGroupFillDecrypt.Outcome(pt, trace.Note, "")
                    : new FileGroupFillDecrypt.Outcome(
                        [],
                        string.IsNullOrEmpty(trace.Note) ? trace.FailReason : trace.Note,
                        trace.FailReason));

            // Fallimento = Auth→storage/FillChunks miss.
            if (!pipe.Decrypted
                && ((pipe.Mode?.Contains("no-resolve", StringComparison.OrdinalIgnoreCase) ?? false)
                    || (pipe.Mode?.Contains("no-ikm", StringComparison.OrdinalIgnoreCase) ?? false)
                    || (pipe.Mode?.Contains("ike-no-", StringComparison.OrdinalIgnoreCase) ?? false)
                    || (pipe.FailReason?.Contains("no-resolve", StringComparison.OrdinalIgnoreCase) ?? false)
                    || (pipe.FailReason?.Length > 0)))
            {
                // #region agent log
                try
                {
                    AgentNdjsonAlways(JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = "ford-rebind-v1",
                        ["hypothesisId"] = "H-FORD-OFF",
                        ["location"] = "BackupDownloadService.DownloadAssembleAssetAsync",
                        ["message"] = "no_resolve_gate",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            path = asset.RelativePath ?? asset.RecordName,
                            record = asset.RecordName,
                            recordIsA = CloudKitMmcsIds.IsAssetRecordName(asset.RecordName),
                            mode = pipe.Mode,
                            canMmcs,
                            fail = pipe.FailReason,
                            compactLen = compact.Length,
                            compactLead = compact.Length > 0 ? compact[0] : -1,
                            hasWrap = !string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex),
                            hasIkm = asset.AssetUnwrappedKey is { Length: > 0 },
                            ikmHead8 = asset.AssetUnwrappedKey is { Length: >= 8 } ik
                                ? Convert.ToHexString(ik.AsSpan(0, 8))
                                : "",
                            fordOpen = trace.FordOpen,
                            fordN = trace.FordN,
                            fordSkip = trace.FordSkip,
                            note = trace.Note,
                        },
                    }));

                    // Books / fordSkip: dump which RP asset owns the wrap vs flist sig.
                    var failPath = asset.RelativePath ?? asset.RecordName ?? "";
                    if (failPath.Contains("Backup-Books", StringComparison.OrdinalIgnoreCase)
                        || (trace.FordSkip > 0 && trace.FordOpen == 0))
                    {
                        var assetRows = new List<Dictionary<string, object?>>();
                        string? ownedSrc = null;
                        byte[]? ownedWrap = null;
                        var fordCt = trace.Storages
                            .Select(static s => s.FordCt)
                            .FirstOrDefault(static ct => ct is { Length: > 0 });
                        var unwrapWorkDir = workDirectory
                            ?? Path.GetDirectoryName(outputFile)
                            ?? ".";
                        if (asset.RecordPayload is { Length: > 32 } rp
                            && asset.AssetSignature is { Length: >= 4 } wantSig)
                        {
                            ownedWrap = CloudKitAssetProto.TryResolveOwnedWrap(
                                rp, wantSig, out ownedSrc);
                            var i = 0;
                            foreach (var a in CloudKitAssetProto.EnumerateAssets(rp))
                            {
                                var w = a.ProtectionWrap;
                                var sigMatch = a.Signature is { Length: >= 4 } asg
                                    && (asg.AsSpan().SequenceEqual(wantSig)
                                        || (wantSig.Length == 21 && asg.Length == 21
                                            && asg.AsSpan(1).SequenceEqual(wantSig[1..])));
                                string? candIkmHead = null;
                                var candOpensFord = false;
                                if (w is { Length: 24 or 40 })
                                {
                                    var unwrapped = FordOfflineDumpWriter.TryUnwrapWithSavedMasters(
                                        unwrapWorkDir, Convert.ToHexString(w));
                                    if (unwrapped is { Length: >= 8 })
                                    {
                                        candIkmHead = Convert.ToHexString(unwrapped.AsSpan(0, 8));
                                        if (fordCt is { Length: > 0 })
                                        {
                                            candOpensFord = FordMmcsDecryptor.BlobOpensExactWithIkm(
                                                unwrapped, fordCt);
                                        }
                                    }
                                }

                                assetRows.Add(new Dictionary<string, object?>
                                {
                                    ["i"] = i++,
                                    ["sig8"] = a.Signature is { Length: >= 4 } s
                                        ? Convert.ToHexString(s.AsSpan(0, Math.Min(8, s.Length)))
                                        : "",
                                    ["sigLead"] = a.Signature is { Length: >= 1 } sl ? sl[0] : -1,
                                    ["wrapLen"] = w?.Length ?? 0,
                                    ["wrapHead8"] = w is { Length: >= 8 }
                                        ? Convert.ToHexString(w.AsSpan(0, 8))
                                        : "",
                                    ["matchesWant"] = sigMatch,
                                    ["wrapEqOwned"] = w is not null && ownedWrap is not null
                                        && w.AsSpan().SequenceEqual(ownedWrap),
                                    ["unwrapIkmHead8"] = candIkmHead,
                                    ["unwrapOpensFord"] = candOpensFord,
                                });
                            }
                        }

                        byte[]? curWrap = null;
                        try
                        {
                            if (!string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
                                curWrap = Convert.FromHexString(asset.AssetProtectionInfoHex);
                        }
                        catch { /* ignore */ }

                        var auditLine = JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "03cce7",
                            ["runId"] = "books-wrap-audit-v1",
                            ["hypothesisId"] = "H-BOOKS-WRAP",
                            ["location"] = "BackupDownloadService.DownloadAssembleAssetAsync",
                            ["message"] = "books_or_fordskip_wrap_audit",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["path"] = failPath,
                                ["record"] = asset.RecordName,
                                ["fail"] = pipe.FailReason,
                                ["fordOpen"] = trace.FordOpen,
                                ["fordN"] = trace.FordN,
                                ["fordSkip"] = trace.FordSkip,
                                ["fordHead8"] = fordCt is { Length: >= 8 }
                                    ? Convert.ToHexString(fordCt.AsSpan(0, 8))
                                    : "",
                                ["fordSha8"] = fordCt is { Length: > 0 }
                                    ? Convert.ToHexString(
                                        System.Security.Cryptography.SHA256.HashData(fordCt).AsSpan(0, 8))
                                    : "",
                                ["ikmHead8"] = asset.AssetUnwrappedKey is { Length: >= 8 } ikm
                                    ? Convert.ToHexString(ikm.AsSpan(0, 8))
                                    : "",
                                ["wrapHead8"] = curWrap is { Length: >= 8 }
                                    ? Convert.ToHexString(curWrap.AsSpan(0, 8))
                                    : "",
                                ["ownedSrc"] = ownedSrc,
                                ["ownedWrapHead8"] = ownedWrap is { Length: >= 8 }
                                    ? Convert.ToHexString(ownedWrap.AsSpan(0, 8))
                                    : "",
                                ["curEqOwned"] = curWrap is not null && ownedWrap is not null
                                    && curWrap.AsSpan().SequenceEqual(ownedWrap),
                                ["wantSig8"] = asset.AssetSignature is { Length: >= 4 } ws
                                    ? Convert.ToHexString(ws.AsSpan(0, Math.Min(8, ws.Length)))
                                    : "",
                                ["rpLen"] = asset.RecordPayload?.Length ?? 0,
                                ["rpBelongs"] = AssetRecordWindowBelongsTo(
                                    asset, asset.RecordPayload),
                                ["assets"] = assetRows,
                            },
                        });
                        AgentNdjsonAlways(auditLine);
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                            auditLine + Environment.NewLine);
                    }
                }
                catch { /* ignore */ }
                // #endregion
            }

            if (pipe.FailReason is { Length: > 0 } && !pipe.Decrypted)
            {
                DecryptFailureJournal.Record(
                    workDirectory ?? Path.GetDirectoryName(outputFile) ?? ".",
                    asset,
                    "ford_fallback",
                    pipe.FailReason,
                    new DecryptFailureDetails
                    {
                        AuthSlice = authBody,
                        Chunks = chunks,
                        ObjectId = orderedChunks.Count > 0
                            ? ResolveObjectId(orderedChunks[0])
                            : null,
                        CompactLength = compact.Length,
                        AssemblyMode = pipe.Mode,
                    });

                // H-ORDER: coda retry se pack OID arriva dopo (Books @112 → pack MB).
                if (pipe.FailReason.Contains("no-ford", StringComparison.OrdinalIgnoreCase)
                    || (pipe.Mode?.Contains("no-ford", StringComparison.OrdinalIgnoreCase) ?? false))
                {
                    var retryPath = asset.RelativePath ?? asset.RecordName ?? outputFile;
                    _oidOrderRetries[retryPath] = new OidOrderRetry(
                        session, asset, outputFile, authBody, chunks, workDirectory,
                        assetIndex, assetTotal, progress, Attempts: 0);
                }
            }

            log?.Report(
                $"  {asset.RecordName}: pipeline stage={pipe.Stage} mode={pipe.Mode}" +
                (pipe.Decrypted ? " OK" : " (ciphertext/fallback)") +
                (pipe.Note is { Length: > 0 } ? $" ({pipe.Note})" : ""));

            //  materializza solo plaintext decryptato — mai compact come asset.
            var writeObjStaging = IkeDiskDumpOptions.DumpEdgeSidecars;
            if (writeObjStaging)
            {
                if (pipe.Decrypted && pipe.Body is { Length: > 0 })
                {
                    await File.WriteAllBytesAsync(outputFile, pipe.Body, ct).ConfigureAwait(false);
                }
                else if (IkeDiskDumpOptions.DumpEdgeSidecars && compact.Length > 0)
                {
                    await File.WriteAllBytesAsync(outputFile + ".ciphertext", compact, ct)
                        .ConfigureAwait(false);
                }
            }
            else
            {
                // #region agent log
                AgentCountAlways("obj_staging_skipped", new
                {
                    path = asset.RelativePath ?? asset.RecordName,
                    bodyLen = pipe.Body?.Length ?? 0,
                    compactLen = compact.Length,
                    mmcs = pipe.Decrypted,
                    mode = pipe.Mode,
                    hypothesis = "H-OBJ-RAM",
                });
                // #endregion
            }

            if (pipe.Decrypted && IkeDiskDumpOptions.DumpEdgeSidecars && compact.Length > 0)
            {
                await File.WriteAllBytesAsync(outputFile + ".ciphertext", compact, ct)
                    .ConfigureAwait(false);
            }

            //  Body solo se MMCS decrypt OK — nessuno fallback compact → size≠.
            byte[]? bodyOut = pipe.Decrypted && pipe.Body is { Length: > 0 }
                ? pipe.Body
                : null;
            // #region agent log
            if (!pipe.Decrypted)
            {
                AgentCountAlways("no_compact_body", new
                {
                    path = asset.RelativePath ?? asset.RecordName,
                    mode = pipe.Mode,
                    fail = pipe.FailReason,
                    compactLen = compact.Length,
                    runId = "ike-faithful-v1",
                    hypothesis = "H-IKE-NO-CT-AS-FILE",
                });
            }
            // #endregion
            return new AssembleResult(
                downloadedBytes,
                pipe.Mode ?? "unknown",
                pipe.Decrypted
                    ? (pipe.Note ?? planSummary)
                    : (pipe.FailReason is { Length: > 0 } fr
                        ? $"{planSummary}; {fr}"
                        : (pipe.Note ?? planSummary)),
                pipe.Decrypted,
                bodyOut);
        }
        finally
        {
            try
            {
                if (File.Exists(compactPath))
                    File.Delete(compactPath);
            }
            catch
            {
                // ignore
            }
        }
    }

    private byte[]? TryResolveMmcsKek(
        ICloudSession session,
        BackupAsset asset,
        IProgress<string>? log)
    {
        if (asset.AssetUnwrappedKey is { Length: > 0 } cached)
            return cached;

        if (asset.AssetProtectionInfoHex is not { Length: > 0 })
            return null;
        // Escrow classico: gate + seed identici a HEAD. Manatee ADP: ramo separato.
        if (!PcsSessionSeedKeys.HasAny(session))
        {
            if (_mmcsKekFailLog++ < 3)
                log?.Report($"  {asset.RecordName}: KeySet PCS assente — skip MMCS KEK");
            return null;
        }

        byte[] wrap;
        try
        {
            wrap = Convert.FromHexString(asset.AssetProtectionInfoHex);
        }
        catch
        {
            return null;
        }

        if (wrap.Length is not (24 or 40))
        {
            if (_mmcsKekFailLog++ < 3)
                log?.Report(
                    $"  {asset.RecordName}: wrap Asset.protectionInfo len={wrap.Length} " +
                    "(atteso 24 o 40)");
            return null;
        }

        List<PcsCompactPrivateKey> seeds;
        try
        {
            if (PcsSessionSeedKeys.HasEscrowKeySet(session))
                seeds = PcsDer.ParseKeySetPrivateKeys(session.PcsEscrowedKeySet!);
            else
                seeds = PcsSessionSeedKeys.Collect(session, log);
        }
        catch (Exception ex)
        {
            if (_mmcsKekFailLog++ < 3)
                log?.Report($"  {asset.RecordName}: parse KeySet fallito — {ex.Message}");
            return null;
        }

        if (seeds.Count == 0)
            return null;

        // Pool espanso (seed+nested) riempito sotto lock alla prima harvest.
        var pool = new List<PcsCompactPrivateKey>(seeds);
        var masters = new List<(byte[] Master, string Source)>();
        var seenMaster = new HashSet<string>(StringComparer.Ordinal);

        void ConsiderZone(ProtectionZoneKeys zone, string source)
        {
            var id = Convert.ToHexString(zone.MasterKey);
            if (!seenMaster.Add(id))
                return;
            masters.Add((zone.MasterKey, source));
            if (zone.NestedPrivateKeys.Count > 0)
                pool = PcsProtectionZone.MergeKeys(pool, [zone]);
        }

        void ConsiderPayload(byte[]? payload, string source)
        {
            if (payload is not { Length: > 64 })
                return;
            foreach (var zone in PcsProtectionZone.TryUnwrapAll(payload, pool))
                ConsiderZone(zone, source);
        }

        // Master di zona bootstrap: una sola volta (lock: decryptWorkers paralleli).
        lock (_mmcsMastersGate)
        {
            if (_cachedMmcsMasters is null)
            {
                var boot = new List<(byte[] Master, string Source)>();
                var bootZones = new List<ProtectionZoneKeys>();
                var bootSeen = new HashSet<string>(StringComparer.Ordinal);
                pool = new List<PcsCompactPrivateKey>(seeds);
                void BootMaster(byte[] master, string source)
                {
                    var id = Convert.ToHexString(master);
                    if (!bootSeen.Add(id))
                        return;
                    boot.Add((master, source));
                }

                void BootZone(ProtectionZoneKeys zone, string source)
                {
                    BootMaster(zone.MasterKey, source);
                    bootZones.Add(zone);
                    if (zone.NestedPrivateKeys.Count > 0)
                        pool = PcsProtectionZone.MergeKeys(pool, [zone]);
                }

                // Preferisci master già unwrapped/persistiti, filtrati per zona asset (_defaultZone).
                _assets.EnsureZoneMastersCached(session, null, session.PcsKeysDirectory, log);
                var assetZone = string.IsNullOrWhiteSpace(asset.ZoneName) ? "_defaultZone" : asset.ZoneName;
                foreach (var (master, source) in _assets.MastersForMmcsZone(assetZone))
                    BootMaster(master, source);

                // Re-unwrap payload etichettato (HEAD: light default ON) — una tantum.
                if (_assets.BootstrapZonesPayload is { Length: > 64 })
                {
                    foreach (var z in PcsProtectionZone.TryUnwrapAllIterative(
                                 _assets.BootstrapZonesPayload, seeds))
                        BootZone(z, "zones-iter");
                }

                foreach (var z in PcsProtectionZone.TryUnwrapAllIterative(
                             _assets.BootstrapSnapshotPayload ?? [], pool))
                    BootZone(z, "snapshot-S");

                _cachedMmcsMasters = boot
                    .OrderBy(m => m.Source.Contains("default", StringComparison.OrdinalIgnoreCase)
                                  || m.Source.Contains("_defaultZone", StringComparison.OrdinalIgnoreCase)
                        ? 0
                        : m.Source.Contains("mbksync", StringComparison.OrdinalIgnoreCase) ? 2 : 1)
                    .ToList();
                _cachedMmcsBootPool = new List<PcsCompactPrivateKey>(pool);
                _cachedShareBootstrapZones = bootZones;
                if (PcsSessionSeedKeys.IsManateePrimary(session) && bootZones.Count > 0)
                    PcsSessionSeedKeys.RememberFromZones(session, bootZones, seeds);
                log?.Report(
                    $"  MMCS KEK: cache master zona = {_cachedMmcsMasters.Count} " +
                    $"(prefer={assetZone}, zones={_assets.BootstrapZonesPayload?.Length ?? 0} B, " +
                    $"S:={_assets.BootstrapSnapshotPayload?.Length ?? 0} B, " +
                    $"diskLabeled={_assets.CachedZoneMasters.Count}, seeds={seeds.Count}, " +
                    $"pool={pool.Count}, shareZones={bootZones.Count})");
            }
            else if (_cachedMmcsBootPool is { Count: > 0 })
            {
                pool = new List<PcsCompactPrivateKey>(_cachedMmcsBootPool);
            }
        }

        foreach (var m in _cachedMmcsMasters!)
        {
            if (seenMaster.Add(Convert.ToHexString(m.Master)))
                masters.Add(m);
        }

        // ProtectionInfo DER del record (Domain / BackupAsset).
        if (asset.RecordProtectionInfoDerHex is { Length: > 0 })
        {
            try
            {
                var der = Convert.FromHexString(asset.RecordProtectionInfoDerHex);
                var zone = PcsProtectionZone.TryUnwrap(der, pool);
                if (zone is not null)
                    ConsiderZone(zone, "record-PI");
                else
                {
                    foreach (var z in PcsProtectionZone.TryUnwrapAll(der, pool))
                        ConsiderZone(z, "record-PI-scan");
                }
            }
            catch (Exception ex)
            {
                if (_mmcsKekFailLog++ < 3)
                    log?.Report($"  {asset.RecordName}: record PI unwrap — {ex.Message}");
            }
        }

        // Finestra record N:/KA:.
        ConsiderPayload(asset.RecordPayload, "record-window");

        foreach (var (master, source) in masters)
        {
            var plain = PcsProtectionZone.TryUnwrapWrappingKey(master, wrap);
            if (plain is null)
                continue;

            return AcceptAssetUnwrappedKey(asset, plain, source, wrap.Length, log);
        }

        // CreatePcsShareProtection + CUWK (HEAD: absorb completo zones/snapshot/record).
        var sharePlain = TryResolveMmcsKekViaShare(session, asset, wrap, masters, pool, log);
        if (sharePlain is { Length: > 0 })
            return AcceptAssetUnwrappedKey(asset, sharePlain, "share/CUWK", wrap.Length, log);

        if (_mmcsKekFailLog++ < 5)
        {
            log?.Report(
                $"  {asset.RecordName}: wrap{wrap.Length} presente ma master/KEK non risolto " +
                $"(masters={masters.Count}, poolKeys={pool.Count}, " +
                $"pi={(asset.RecordProtectionInfoDerHex is null ? "no" : "yes")}, " +
                $"win={asset.RecordPayload?.Length ?? 0})");
        }
        else if (_mmcsKekFailLog == 6)
        {
            log?.Report("  … KEK MMCS fail (log ridotto)");
        }

        // #region agent log
        AgentBkFailLog(
            "H-BK1",
            "BackupDownloadService.TryResolveMmcsKek",
            "kek_unresolved",
            new
            {
                record = asset.RecordName,
                path = asset.RelativePath,
                wrapLen = wrap.Length,
                masters = masters.Count,
                poolKeys = pool.Count,
                hasRecordPi = asset.RecordProtectionInfoDerHex is { Length: > 0 },
                winLen = asset.RecordPayload?.Length ?? 0,
                bootZones = _assets.BootstrapZonesPayload?.Length ?? 0,
                cachedMasters = _cachedMmcsMasters?.Count ?? 0,
                failN = _mmcsKekFailLog,
            });
        // #endregion

        return null;
    }


    private byte[] AcceptAssetUnwrappedKey(
        BackupAsset asset,
        byte[] plain,
        string source,
        int wrapLen,
        IProgress<string>? log)
    {
        asset.AssetUnwrappedKey = plain;
        asset.AssetUnwrappedKeyWrapHex = asset.AssetProtectionInfoHex;
        if (_mmcsKekOkLog++ < 8)
        {
            log?.Report(
                $"  {asset.RecordName}: Asset wrap{wrapLen} → key{plain.Length} OK ({source}) " +
                $"{Convert.ToHexString(plain.AsSpan(0, Math.Min(8, plain.Length)))}…");
        }
        else if (_mmcsKekOkLog == 9)
        {
            log?.Report("  … Asset wrap unwrap OK (log ridotto)");
        }

        // #region agent log
        if (wrapLen == 40 || IkeLogOptions.ShouldWriteAgentDiag)
        {
            try
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = "wrap40-ikm-v1",
                        ["hypothesisId"] = "H-WRAP40-IKM",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "BackupDownloadService.AcceptAssetUnwrappedKey",
                        ["message"] = "wrap_ikm_accepted",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["source"] = source,
                            ["wrapLen"] = wrapLen,
                            ["ikmLen"] = plain.Length,
                            ["ikmHead8"] = Convert.ToHexString(
                                plain.AsSpan(0, Math.Min(8, plain.Length))),
                            ["domain"] = asset.Domain,
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
        }
        // #endregion

        // #region agent log
        AgentD3IkmLog(
            "AcceptAssetUnwrappedKey",
            "ike_ikm_accept",
            asset,
            plain,
            source,
            wrapLen);
        // #endregion

        return plain;
    }

    /// <summary>
    /// CreateWithExported → ShareProtection → CUWK / brute key map → AES-KW wrap 24/40.
    /// </summary>
    private byte[]? TryResolveMmcsKekViaShare(
        ICloudSession session,
        BackupAsset asset,
        byte[] wrap,
        List<(byte[] Master, string Source)> masters,
        List<PcsCompactPrivateKey> pool,
        IProgress<string>? log)
    {
        try
        {
            // Bootstrap zones/S: già harvestati una volta in TryResolveMmcsKek (cache).
            // Per-asset: solo record window / PI — niente re-Absorb del payload zone.
            var zones = new List<ProtectionZoneKeys>();
            if (_cachedShareBootstrapZones is { Count: > 0 })
                zones.AddRange(_cachedShareBootstrapZones);
            else
            {
                void AbsorbBoot(byte[]? payload)
                {
                    if (payload is not { Length: > 64 })
                        return;
                    zones.AddRange(PcsProtectionZone.TryUnwrapAllIterative(payload, pool));
                }

                AbsorbBoot(_assets.BootstrapZonesPayload);
                AbsorbBoot(_assets.BootstrapSnapshotPayload);
            }

            void AbsorbRecord(byte[]? payload)
            {
                if (payload is not { Length: > 64 })
                    return;
                zones.AddRange(PcsProtectionZone.TryUnwrapAllIterative(payload, pool));
            }

            AbsorbRecord(asset.RecordPayload);
            if (asset.RecordProtectionInfoDerHex is { Length: > 0 })
            {
                try
                {
                    AbsorbRecord(Convert.FromHexString(asset.RecordProtectionInfoDerHex));
                }
                catch
                {
                    // ignore
                }
            }

            // Zone keys già in masters → ProtectionZoneKeys light per fill share.
            foreach (var (master, source) in masters)
            {
                zones.Add(new ProtectionZoneKeys(
                    master,
                    PcsNistKdf.CtrHmacSha256(
                        master, Encoding.ASCII.GetBytes("encryption key key m"), 16),
                    source,
                    null,
                    [],
                    Convert.ToHexString(SHA256.HashData(master)[..20])));
            }

            if (zones.Count == 0)
                return null;

            var share = PcsShareProtection.FromZoneKeys(zones);
            if (share.KeyCount == 0)
                return null;

            // CUWK: se il wrap/PI ha KeyID esplicito, seleziona; altrimenti prova tutte.
            byte[]? selected = null;
            if (asset.RecordProtectionInfoDerHex is { Length: > 0 })
            {
                // KeyID spesso = master key id 20 B nello stesso DER; prova default CUWK.
                selected = share.CreateUnwrappingKeyHex(share.DefaultKeyIdHex);
            }

            selected ??= share.DefaultKey;
            var brute = share.TryUnwrapAssetWrap(wrap);
            if (brute is { Length: > 0 })
                return brute;
        }
        catch (Exception ex)
        {
            if (_mmcsKekFailLog++ < 3)
                log?.Report($"  {asset.RecordName}: share/CUWK — {ex.Message}");
        }

        return null;
    }


    /// <summary>
    /// Salva il DB fileList (encoding=2) e logga conteggi schema.
    /// Ritorna il path del <c>flist_*.db</c> se materializzato.
    /// </summary>
    private static async Task<string?> MaterializeFileListDbAsync(
        string snapshotDirectory,
        BackupAsset asset,
        byte[] sqliteDb,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var dbPath = ResolveFlistDbPath(snapshotDirectory, asset);
        await File.WriteAllBytesAsync(dbPath, sqliteDb, ct).ConfigureAwait(false);

        var parsed = await Task.Run(
            () => FileListSqliteParser.ParseFile(dbPath, sampleLimit: 3), ct)
            .ConfigureAwait(false);
        if (!parsed.Ok)
        {
            log?.Report(
                $"  {asset.RecordName}: flist SQLite salvato ({sqliteDb.Length:N0} B) " +
                $"ma parse FAIL: {parsed.Error}");
            return dbPath;
        }

        log?.Report(
            $"  {asset.RecordName}: flist SQLite OK → {Path.GetFileName(dbPath)} " +
            $"({sqliteDb.Length:N0} B, Assets={parsed.AssetRows}, " +
            $"FileMetadata={parsed.FileMetadataRows}, join={parsed.Entries.Count}+)");

        var meta = JsonSerializer.Serialize(new
        {
            record = asset.RecordName,
            domain = asset.Domain,
            bytes = sqliteDb.Length,
            tables = parsed.Tables,
            assets = parsed.AssetRows,
            fileMetadata = parsed.FileMetadataRows,
            sample = parsed.Entries.Select(e => new
            {
                rid = e.RecordIdSuffix,
                path = e.RelativePath,
                size = e.Size,
                pc = e.ProtectionClass,
                ekLen = e.EncryptionKey?.Length ?? 0
            })
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(
            Path.Combine(snapshotDirectory, Path.GetFileNameWithoutExtension(dbPath) + "_meta.json"),
            meta,
            ct).ConfigureAwait(false);
        return dbPath;
    }

    private static string ResolveFlistDbPath(string snapshotDirectory, BackupAsset flAsset)
    {
        var sig = flAsset.RecordName;
        if (sig.StartsWith("FL:", StringComparison.Ordinal))
            sig = sig["FL:".Length..];
        sig = SanitizeFileName(sig);
        if (sig.Length > 64)
            sig = sig[..64];
        return Path.Combine(snapshotDirectory, $"flist_{sig}.db");
    }

    /// <summary>
    /// Copia il MA: più grande come <c>Manifest.db</c> + alias <c>Manifest.db.encrypted</c>.
    /// </summary>
    private static async Task MaterializeManifestDbAsync(
        string outputDirectory,
        List<(BackupAsset Asset, string ObjectFile, long Bytes, bool MmcsDecrypted)> maDownloaded,
        IProgress<string>? log,
        CancellationToken ct)
    {
        Directory.CreateDirectory(outputDirectory);
        var workDir = IkeBackupOutputPaths.ResolveTmpDirectory(outputDirectory);
        var cleanDir = IkeBackupOutputPaths.ResolveCleanBackupDirectory(outputDirectory);
        Directory.CreateDirectory(workDir);
        Directory.CreateDirectory(cleanDir);

        if (maDownloaded.Count == 0)
        {
            log?.Report("  nessun MA: scaricato — Manifest.db non creato");
            return;
        }

        var byFile = maDownloaded
            .GroupBy(x => x.ObjectFile, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderByDescending(x => x.Bytes).First())
            .OrderByDescending(x => x.MmcsDecrypted)
            .ThenByDescending(x => x.Bytes)
            .ThenByDescending(x => x.Asset.SizeBytes ?? UbChunkBuilder.ExtractDeclaredSize(x.Asset.RecordName) ?? 0)
            .ToList();

        string? manifestPath = null;
        string? encryptedAlias = null;
        var looksSqlite = false;
        var mmcsDecrypted = false;
        foreach (var item in byFile)
        {
            var safe = SanitizeFileName(item.Asset.RecordName);
            if (safe.Length > 80)
                safe = safe[..80];
            var maCopy = Path.Combine(workDir, "MA_" + safe + ".bin");
            if (!string.Equals(item.ObjectFile, maCopy, StringComparison.OrdinalIgnoreCase))
                File.Copy(item.ObjectFile, maCopy, overwrite: true);

            if (manifestPath is null)
            {
                manifestPath = Path.Combine(cleanDir, "Manifest.db");
                encryptedAlias = Path.Combine(workDir, "Manifest.db.encrypted");

                var cipherSource = item.ObjectFile + ".ciphertext";
                if (item.MmcsDecrypted && File.Exists(cipherSource))
                {
                    File.Copy(cipherSource, encryptedAlias, overwrite: true);
                    File.Copy(item.ObjectFile, manifestPath, overwrite: true);
                    mmcsDecrypted = true;
                }
                else
                {
                    File.Copy(item.ObjectFile, encryptedAlias, overwrite: true);
                    File.Copy(item.ObjectFile, manifestPath, overwrite: true);
                    mmcsDecrypted = item.MmcsDecrypted;
                }

                looksSqlite = LooksLikeSqlite(manifestPath);
                var kind = mmcsDecrypted
                    ? (looksSqlite ? "mmcsDecrypted + SQLite" : "mmcsDecrypted (non-SQLite)")
                    : looksSqlite
                        ? "già SQLite"
                        : "ciphertext MMCS (non PCS class-key)";
                log?.Report(
                    $"  Manifest.db (+ .encrypted in tmp) ← {Path.GetFileName(item.ObjectFile)} " +
                    $"({item.Bytes:N0} byte, record={item.Asset.RecordName}, {kind})");
            }
            else
            {
                log?.Report($"  MA_*.bin ← {Path.GetFileName(maCopy)} ({item.Bytes:N0} byte)");
            }
        }

        var meta = JsonSerializer.Serialize(new
        {
            manifestDb = manifestPath is null ? null : Path.Combine(IkeBackupOutputPaths.CleanBackupFolderName, "Manifest.db"),
            manifestDbEncrypted = encryptedAlias is null ? null : Path.GetFileName(encryptedAlias),
            mmcsDecrypted,
            encrypted = !looksSqlite && !mmcsDecrypted,
            looksLikeSqlite = looksSqlite,
            note = mmcsDecrypted
                ? (looksSqlite
                    ? "Manifest.db = plaintext MMCS (AES-CFB); magic SQLite OK."
                    : "Manifest.db = output MMCS decrypt; non è ancora SQLite — può servire keybag/PIN.")
                : looksSqlite
                    ? "Manifest.db ha magic SQLite (già in chiaro)."
                    : "Manifest.db / Manifest.db.encrypted = blob MMCS assemblato (refs); " +
                      "wrap assente o KEK non risolto. Keybag+PIN resta fuori scope.",
            candidates = byFile.Select(x => new
            {
                record = x.Asset.RecordName,
                objectFile = Path.GetFileName(x.ObjectFile),
                bytes = x.Bytes,
                mmcsDecrypted = x.MmcsDecrypted,
                assetWrap = !string.IsNullOrWhiteSpace(x.Asset.AssetProtectionInfoHex),
                declaredSize = x.Asset.SizeBytes ?? UbChunkBuilder.ExtractDeclaredSize(x.Asset.RecordName),
                role = x.ObjectFile.Equals(byFile[0].ObjectFile, StringComparison.OrdinalIgnoreCase)
                    ? "manifest"
                    : "ma-other"
            })
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(
            Path.Combine(workDir, "manifest_db_meta.json"), meta, ct);
    }

    private static bool LooksLikeSqlite(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> head = stackalloc byte[16];
            var n = fs.Read(head);
            return n >= 16 && head.StartsWith("SQLite format 3\0"u8);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// ASSET_DECRYPT §1: material PCS disponibile prima di Lock / N: / authorizeGet.
    /// Riusa KeySet in sessione o cartella Escrow; opzionale recover iCSC.
    /// </summary>
    private async Task EnsureEscrowKeySetBeforeRestoreAsync(
        ICloudSession session,
        DownloadJob job,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var escrowWork = IkeBackupOutputPaths.ResolveTmpDirectory(job.OutputDirectory);
        Directory.CreateDirectory(escrowWork);

        // ADP/Manatee: seed già in sessione, o Manatee Octagon/CKKS già su disco.
        if (!PcsSessionSeedKeys.HasAny(session))
            _ = EscrowPcsSession.TryLoadManateeFromDisk(
                session,
                session.OctagonKeysDirectory ?? session.PcsKeysDirectory ?? escrowWork,
                log);

        if (PcsSessionSeedKeys.HasAny(session))
        {
            log?.Report(
                session.PcsEscrowedKeySet is { Length: > 32 }
                    ? "  PCS KeySet già in sessione — skip get_records/recover"
                    : $"  PCS Manatee già pronto ({session.PcsManateeCompactKeys!.Count}) — skip get_records/recover");
            return;
        }

        await TryEscrowGetRecordsProbeAsync(session, escrowWork, log, ct);

        // Prova unlock da cartella PCS / Octagon senza nuovo SRP.
        try
        {
            var pcsDir = EscrowPcsSession.ResolvePcsKeysDirectory(
                session.PcsKeysDirectory,
                session.OctagonKeysDirectory,
                escrowWork);
            var ensured = await EscrowPcsSession.EnsureKeySetAsync(
                session,
                _http,
                pcsDir,
                job.IcscSecurityCode,
                sms: null,
                log,
                ct);
            if (ensured.Success && PcsSessionSeedKeys.HasAny(session))
            {
                log?.Report(
                    $"  PCS seed ← EnsureKeySet ({ensured.Source ?? ensured.Message ?? "ok"})");
                return;
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  EnsureKeySet skip: {ex.Message}");
        }

        if (!job.EnableEscrowRecover)
        {
            log?.Report("  Escrow recover non richiesto (EnableEscrowRecover=false)");
            return;
        }

        if (string.IsNullOrWhiteSpace(job.IcscSecurityCode))
        {
            log?.Report("Escrow recover richiesto ma iCSC vuoto — skip srp_init/recover");
            return;
        }

        try
        {
            var recovery = new EscrowRecoveryService(_http);
            var recovered = await recovery.RecoverWithIcscAsync(
                session, job.IcscSecurityCode, escrowWork, log, ct);
            log?.Report(recovered.Success
                ? $"Escrow recover: {recovered.Message}"
                : $"Escrow recover FAIL: {recovered.Message}");
        }
        catch (Exception ex)
        {
            log?.Report($"Escrow recover skip: {ex.Message}");
        }
    }

    private async Task TryEscrowGetRecordsProbeAsync(
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        try
        {
            var pcsDir = EscrowPcsSession.ResolvePcsKeysDirectory(
                session.PcsKeysDirectory, outputDirectory);

            // Già recuperati (scheda Escrow / EnsureKeySet): niente seconda get_records nello snapshot.
            if (HasEscrowGetRecordsArtifacts(pcsDir))
            {
                log?.Report(
                    $"  escrow get_records skip — artifact già in {pcsDir}");
                await CopyEscrowProbeArtifactsIfMissingAsync(pcsDir, outputDirectory, ct);
                if (File.Exists(Path.Combine(outputDirectory, "escrow_bottles.json"))
                    || File.Exists(Path.Combine(pcsDir, "escrow_bottles.json")))
                    log?.Report("  escrow_bottles.json → metadata ICDP/PCS (cached)");
                return;
            }

            var escrow = new EscrowProxyClient(_http);
            var result = await escrow.GetRecordsAsync(session, log, ct);
            // Salva nel PCS store (run root), non solo nella cartella snapshot.
            await EscrowProxyClient.SaveProbeArtifactsAsync(pcsDir, result, ct);
            await EscrowBottlesParser.SaveBottlesJsonAsync(pcsDir, result.RawBody, ct);
            await CopyEscrowProbeArtifactsIfMissingAsync(pcsDir, outputDirectory, ct);
            log?.Report(
                $"  escrow artifacts → {Path.Combine(pcsDir, "escrow_get_records_response.bin")} " +
                $"(HTTP {result.HttpStatus}, {result.RawBody.Length:N0} byte, " +
                $"ok={EscrowProxyClient.IsEscrowSuccess(result)}, " +
                $"labels={result.RecordLabels.Count})");
            if (File.Exists(Path.Combine(pcsDir, "escrow_bottles.json")))
                log?.Report($"  escrow_bottles.json → metadata ICDP/PCS");
        }
        catch (Exception ex)
        {
            log?.Report($"EscrowProxy get_records skip: {ex.Message}");
        }
    }

    private static bool HasEscrowGetRecordsArtifacts(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            return false;

        return File.Exists(Path.Combine(directory, "escrow_get_records_response.bin"))
               || File.Exists(Path.Combine(directory, "escrow_get_records_response.xml"))
               || File.Exists(Path.Combine(directory, "escrow_bottles.json"))
               || File.Exists(Path.Combine(directory, EscrowPcsKeyUnwrap.BackupBagPasswordFileName));
    }

    private static async Task CopyEscrowProbeArtifactsIfMissingAsync(
        string sourceDir,
        string destDir,
        CancellationToken ct)
    {
        if (string.Equals(
                Path.GetFullPath(sourceDir),
                Path.GetFullPath(destDir),
                StringComparison.OrdinalIgnoreCase))
            return;

        Directory.CreateDirectory(destDir);
        string[] names =
        [
            "escrow_get_records_response.bin",
            "escrow_get_records_response.xml",
            "escrow_get_records_meta.json",
            "escrow_bottles.json",
            "pcs_metadata_summary.json"
        ];
        foreach (var name in names)
        {
            var src = Path.Combine(sourceDir, name);
            var dst = Path.Combine(destDir, name);
            if (!File.Exists(src) || File.Exists(dst))
                continue;
            await using var input = File.OpenRead(src);
            await using var output = File.Create(dst);
            await input.CopyToAsync(output, ct);
        }
    }

    private static async Task WriteManifestAsync(
        DownloadJob job,
        IReadOnlyList<BackupAsset> assets,
        CancellationToken ct)
    {
        var workDir = IkeBackupOutputPaths.ResolveTmpDirectory(job.OutputDirectory);
        Directory.CreateDirectory(workDir);
        var manifestPath = Path.Combine(workDir, "download_manifest.json");
        var manifest = new
        {
            snapshot = job.Snapshot.RecordName,
            device = job.Device.DeviceUuid,
            keybagCount = job.Device.Keybags.Count,
            assets = assets.Select(a => new
            {
                a.RecordName,
                a.SizeBytes,
                encrypted = true,
                assetWrap = !string.IsNullOrWhiteSpace(a.AssetProtectionInfoHex),
                role = a.RecordName.StartsWith("MA:", StringComparison.Ordinal)
                    ? "manifest-asset"
                    : "file-asset"
            })
        };
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(manifestPath, json, ct);
    }

    /// <summary>
    /// Scarica i chunk in file contiguo (ordine authorizeGet; niente OrderBy Start).
    /// </summary>
    /// <summary>
    ///  scarica ogni GET host in parallelo e restituisce i body separati
    /// (niente concat compact).
    /// </summary>
    internal static async Task<(long Downloaded, byte[][] Bodies)> DownloadChunksPerHostAsync(
        IReadOnlyList<SignedUrlChunk> chunks,
        int assetIndex,
        int assetTotal,
        IProgress<DownloadProgressReport>? progress,
        CancellationToken ct,
        HttpClient? http = null,
        EdgeDownloadAuthState? edgeAuth = null)
    {
        _ = assetIndex;
        _ = assetTotal;
        _ = progress;
        http ??= new HttpClient();
        var ordered = chunks
            .Where(static c => !string.IsNullOrEmpty(c.Url))
            .ToList();

        var sw = Environment.TickCount64;
        var bodies = await DownloadEdgeChunkBodiesParallelAsync(ordered, http, ct, edgeAuth)
            .ConfigureAwait(false);
        // #region agent log
        AgentFlEdgeDebugLog(
            "BackupDownloadService.DownloadChunksPerHostAsync",
            "edge per-host batch done",
            new
            {
                chunkTotal = ordered.Count,
                parallelism = BackupEdgeDownloadParallelism,
                elapsedMs = Environment.TickCount64 - sw,
                totalBytes = bodies.Sum(static b => b.Length),
            },
            "H-P0-PARALLEL",
            "post-fix");
        // #endregion

        return (bodies.Sum(static b => (long)b.Length), bodies);
    }

    /// <summary>
    /// Pianta ogni body GET sotto <c>oid@{Start}</c> e, se OID vuoto (Ford),
    /// sotto <c>host:{i}@{Start}</c> — demux poi via gate → Read(ctLen).
    /// </summary>
    private static void SeedOidHostsFromBodies(
        IReadOnlyList<SignedUrlChunk> ordered,
        byte[][] bodies,
        ConcurrentDictionary<string, (byte[] Compact, long MmcsStart)> sibMap)
    {
        var n = Math.Min(ordered.Count, bodies.Length);
        for (var i = 0; i < n; i++)
        {
            if (ordered[i].ByteRange is not { } br)
                continue;
            if (bodies[i] is not { Length: > 0 } body)
                continue;
            var oid = ordered[i].EdgeHeaders?.ObjectId ?? "";
            if (!string.IsNullOrEmpty(oid))
                sibMap[$"{oid}@{br.Start}"] = (body, br.Start);
            else
                sibMap[$"host:{i}@{br.Start}"] = (body, br.Start);
        }
        // #region agent log
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-PER-HOST",
                ["runId"] = "get-host-v1",
                ["location"] = "BackupDownloadService.SeedOidHostsFromBodies",
                ["message"] = "seed_oid_hosts",
                ["data"] = new Dictionary<string, object?>
                {
                    ["n"] = n,
                    ["oidN"] = sibMap.Keys.Count(static k =>
                        k.Contains('@', StringComparison.Ordinal)
                        && !k.StartsWith("sig:", StringComparison.Ordinal)
                        && !k.StartsWith("gate:", StringComparison.Ordinal)),
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
    }

    internal static async Task<long> DownloadChunksCompactAsync(
        string outputFile,
        IReadOnlyList<SignedUrlChunk> chunks,
        int assetIndex,
        int assetTotal,
        IProgress<DownloadProgressReport>? progress,
        CancellationToken ct,
        HttpClient? http = null,
        EdgeDownloadAuthState? edgeAuth = null)
    {
        http ??= new HttpClient();
        var ordered = chunks
            .Where(static c => !string.IsNullOrEmpty(c.Url))
            .ToList();

        var sw = Environment.TickCount64;
        var bodies = await DownloadEdgeChunkBodiesParallelAsync(ordered, http, ct, edgeAuth)
            .ConfigureAwait(false);
        // #region agent log
        AgentFlEdgeDebugLog(
            "BackupDownloadService.DownloadChunksCompactAsync",
            "edge parallel batch done",
            new
            {
                chunkTotal = ordered.Count,
                parallelism = BackupEdgeDownloadParallelism,
                elapsedMs = Environment.TickCount64 - sw,
                totalBytes = bodies.Sum(static b => b.Length),
            },
            "H-P0-PARALLEL",
            "post-fix");
        // #endregion

        await using var output = new FileStream(
            outputFile, FileMode.Create, FileAccess.Write, FileShare.None);
        long downloaded = 0;
        for (var chunkIndex = 0; chunkIndex < bodies.Length; chunkIndex++)
        {
            ct.ThrowIfCancellationRequested();
            var body = bodies[chunkIndex];
            await output.WriteAsync(body, ct).ConfigureAwait(false);
            downloaded += body.Length;

            // #region agent log
            AgentFlEdgeDebugLog(
                "BackupDownloadService.cs:DownloadChunksCompactAsync",
                "edge GET ok",
                new
                {
                    chunkIndex = chunkIndex + 1,
                    chunkTotal = ordered.Count,
                    includeTryCache = false,
                    downloaded,
                    objectId = ordered[chunkIndex].EdgeHeaders?.ObjectId,
                },
                "H12",
                "post-fix");
            // #endregion

            // compact progress: solo log esterno / niente bar

        }

        return downloaded;
    }

    /// <summary>
    /// H-R5: Ford lives in same-OID prefix before mid-range data GET.
    /// Tries overlap slice, geometric dataStart−len, then full prefix GET when Start&lt;8KiB.
    /// </summary>

    // #region agent log
    private static void AgentLogImpliedDisabled(string where)
    {
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = "ike-no-invent-ford-v2",
                    ["hypothesisId"] = "H-NO-IMPLIED",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "BackupDownloadService." + where,
                    ["message"] = "implied_ford_disabled",
                    ["data"] = new Dictionary<string, object?> { ["where"] = where },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
    }
    // #endregion

    private async Task<ReadOnlyMemory<byte>> TryResolveHr5PrefixFordAsync(
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        ReadOnlyMemory<byte> fordIkm,
        string? snapshotDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        //-strict: no dataStart−N invent. Ford = Auth FileGroup GET exact ctLen only.
        _ = orderedChunks; _ = fordIkm; _ = snapshotDirectory; _ = log; _ = ct;
        AgentLogImpliedDisabled("TryResolveHr5PrefixFordAsync");
        await Task.CompletedTask.ConfigureAwait(false);
        return ReadOnlyMemory<byte>.Empty;
    }

    /// <summary>
    /// H-R5: Ford nello stesso OID prima del data GET mid-range.
    /// Solo overlap su host <b>già autorizzati</b> in cache/batch.
    /// Vietato inventare Range su URL firmate per un altro byte-range → 403 storm.
    /// Se vuoto: il chiamante deve fare fresh authorizeGet (empty hosts).
    /// </summary>
    private async Task<ReadOnlyMemory<byte>> TryResolveHr5PrefixFordCoreAsync(
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        ReadOnlyMemory<byte> fordIkm,
        string? snapshotDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        _ = orderedChunks; _ = fordIkm; _ = snapshotDirectory; _ = log; _ = ct;
        await Task.CompletedTask.ConfigureAwait(false);
        return ReadOnlyMemory<byte>.Empty;
    }

    private async Task<ReadOnlyMemory<byte>> TryResolveImpliedFordHeuristicAsync(
        ICloudSession session,
        BackupAsset asset,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        IReadOnlyList<SignedUrlChunk> originalChunks,
        ReadOnlyMemory<byte> fordIkm,
        string? snapshotDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        //-strict: vietato dataStart−112 / overlap invent. Solo spill Auth FileGroup.
        _ = session; _ = asset; _ = plan; _ = orderedChunks; _ = originalChunks;
        _ = fordIkm; _ = snapshotDirectory; _ = log; _ = ct;
        AgentLogImpliedDisabled("TryResolveImpliedFordHeuristicAsync");
        await Task.CompletedTask.ConfigureAwait(false);
        return ReadOnlyMemory<byte>.Empty;
    }

    /// <summary>
    /// Scarica host Ford del plan: empty <b>oppure</b> ChunkInfo singolo di taglia Ford
    /// (oracle  CT 112 lead-0x04 è un GET separato, spesso con ChunkInfo e non empty).
    /// </summary>
    private async Task<ReadOnlyMemory<byte>> TryDownloadFordSizedPlanHostsAndPickAsync(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> originalChunks,
        ReadOnlyMemory<byte> fordIkm,
        long dataStart,
        string? snapshotDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        ReadOnlyMemory<byte> best = default;
        var downloaded = 0;
        var openN = 0;
        var n = Math.Min(originalChunks.Count, plan.Containers.Count);
        for (var i = 0; i < n; i++)
        {
            var group = plan.Containers[i];
            var empty = group.Count == 0;
            var fordChunk = !empty && FordMmcsDecryptor.IsFordSizedPlanContainer(plan, i);
            if (!empty && !fordChunk)
                continue;

            var host = originalChunks[i];
            if (host.ByteRange is not { } br)
                continue;

            var hostLen = br.End - br.Start + 1;
            if (hostLen < 112 || hostLen > 65_536)
                continue;

            var hostOid = host.EdgeHeaders?.ObjectId ?? "";
            byte[] body;
            try
            {
                var cacheKey = MmcsChunkStore.HostRangeKey(-1, hostOid, br.Start, br.End);
                var cached = _mmcsChunkSession?.Store.TryGet(cacheKey);
                if (cached is { Length: >= 0x12 })
                    body = cached;
                else
                {
                    body = await DownloadSingleEdgeChunkAsync(host, _http, ct).ConfigureAwait(false);
                    _mmcsChunkSession?.Store.Put(cacheKey, body);
                    downloaded++;
                }

                if (!string.IsNullOrEmpty(snapshotDirectory))
                {
                    try
                    {
                        var tag = empty ? "EMPTY" : "FORD_CHUNK";
                        var dumpName =
                            $"PLAN_{tag}_HOST_{SanitizeFileName(hostOid)}_{br.Start}_{br.End}.bin";
                        await File.WriteAllBytesAsync(
                            Path.Combine(snapshotDirectory, dumpName), body, ct)
                            .ConfigureAwait(false);
                    }
                    catch { /* best-effort */ }
                }
            }
            catch (Exception)
            {
                continue;
            }

            if (!TryPickFordFromHostBody(body, fordIkm, dataStart, br.Start, out var ford))
                continue;

            openN++;
            log?.Report(
                $"  plan ford-host {br.Start}-{br.End} oid={hostOid} ({ford.Length} B " +
                $"{(empty ? "empty" : "chunkInfo")})");
            if (best.IsEmpty || ford.Length < best.Length)
                best = ford;
        }

        // #region agent log
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = "BackupDownloadService.TryDownloadFordSizedPlanHosts",
                ["message"] = "ford_sized_plan_hosts",
                ["hypothesisId"] = "H-FORD-CT-GET",
                ["runId"] = "post-fix",
                ["data"] = new Dictionary<string, object?>
                {
                    ["downloaded"] = downloaded,
                    ["openN"] = openN,
                    ["bestLen"] = best.Length,
                    ["bestLead"] = best.Length > 0 ? best.Span[0] : -1,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        return best;
    }

    /// <summary>
    /// Scarica <b>tutti</b> gli empty host del plan (cache/disk), poi restituisce il primo IKM-open.
    /// Non si ferma al primo download riuscito senza aver scaricato i restanti.
    /// </summary>
    private async Task<ReadOnlyMemory<byte>> TryDownloadAllPlanEmptyHostsAndPickAsync(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> originalChunks,
        ReadOnlyMemory<byte> fordIkm,
        long dataStart,
        string? snapshotDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        ReadOnlyMemory<byte> best = default;
        var downloaded = 0;
        var openN = 0;
        var n = Math.Min(originalChunks.Count, plan.Containers.Count);
        for (var i = 0; i < n; i++)
        {
            if (plan.Containers[i].Count != 0)
                continue;
            var host = originalChunks[i];
            if (host.ByteRange is not { } br)
                continue;

            var hostLen = br.End - br.Start + 1;
            if (hostLen < 112 || hostLen > 65_536)
                continue;

            var hostOid = host.EdgeHeaders?.ObjectId ?? "";
            byte[] body;
            try
            {
                var cacheKey = MmcsChunkStore.HostRangeKey(-1, hostOid, br.Start, br.End);
                var cached = _mmcsChunkSession?.Store.TryGet(cacheKey);
                if (cached is { Length: >= 0x12 })
                    body = cached;
                else
                {
                    body = await DownloadSingleEdgeChunkAsync(host, _http, ct).ConfigureAwait(false);
                    _mmcsChunkSession?.Store.Put(cacheKey, body);
                    downloaded++;
                }

                if (!string.IsNullOrEmpty(snapshotDirectory))
                {
                    try
                    {
                        var dumpName =
                            $"PLAN_EMPTY_HOST_{SanitizeFileName(hostOid)}_{br.Start}_{br.End}.bin";
                        await File.WriteAllBytesAsync(
                            Path.Combine(snapshotDirectory, dumpName), body, ct)
                            .ConfigureAwait(false);
                    }
                    catch { /* best-effort */ }
                }
            }
            catch (Exception)
            {
                continue;
            }

            if (!TryPickFordFromHostBody(body, fordIkm, dataStart, br.Start, out var ford))
            {
                continue;
            }

            openN++;
            log?.Report(
                $"  plan empty-host Ford {br.Start}-{br.End} oid={hostOid} ({ford.Length} B)");
            if (best.IsEmpty)
                best = ford;
            // Continua il loop: scarica/verifica anche gli altri empty host.
        }

        return best;
    }

    /// <summary>
    /// authorizeGet monofile per asset: scarica <b>tutti</b> gli empty host, cache/dump,
    /// poi restituisce solo un Ford IKM-open (preferenza same-OID adiacente).
    /// </summary>
    private async Task<ReadOnlyMemory<byte>> TryResolveFordViaFreshAuthorizeGetAsync(
        ICloudSession session,
        BackupAsset asset,
        string objectId,
        long dataStart,
        ReadOnlyMemory<byte> fordIkm,
        string? snapshotDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        //-strict: no adjacent dataStart−112 from fresh AG invent.
        _ = session; _ = asset; _ = objectId; _ = dataStart; _ = fordIkm;
        _ = snapshotDirectory; _ = log; _ = ct;
        AgentLogImpliedDisabled("TryResolveFordViaFreshAuthorizeGetAsync");
        await Task.CompletedTask.ConfigureAwait(false);
        return ReadOnlyMemory<byte>.Empty;
    }


    private static string FreshAgAssetKey(BackupAsset asset)
    {
        if (asset.AssetSignature is { Length: > 0 } sig)
            return Convert.ToHexString(sig);
        return asset.RelativePath ?? asset.RecordName ?? "";
    }

    private void RememberFreshAgFordBody(
        BackupAsset asset,
        string hostOid,
        long hostStart,
        byte[] body)
    {
        if (body.Length < 0x12 || body.Length > 65_536 || string.IsNullOrEmpty(hostOid))
            return;
        var key = FreshAgAssetKey(asset);
        if (string.IsNullOrEmpty(key))
            return;
        var list = _freshAgFordBodies.GetOrAdd(key, static _ => []);
        lock (list)
        {
            foreach (var existing in list)
            {
                if (existing.Start == hostStart
                    && existing.Body.Length == body.Length
                    && string.Equals(existing.Oid, hostOid, StringComparison.Ordinal))
                    return;
            }

            if (list.Count >= 12)
                list.RemoveAt(0);
            list.Add((hostOid, hostStart, body));
        }
    }

    /// <summary>
    /// Dopo fresh AG: Ford bodies in MMCS store / sibling / remembered fresh-AG list /
    /// disk AUTH_FRESH dumps — riprovati con IKM candidato (force-wrap).
    /// </summary>
    private ReadOnlyMemory<byte> TryOpenImpliedFordFromCachedHosts(
        BackupAsset asset,
        string? workDirectory,
        IReadOnlyList<SignedUrlChunk>? chunks,
        ReadOnlySpan<byte> fordIkm,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts)
    {
        _ = asset; _ = workDirectory; _ = chunks; _ = fordIkm; _ = siblingCompacts;
        AgentLogImpliedDisabled("TryOpenImpliedFordFromCachedHosts");
        return ReadOnlyMemory<byte>.Empty;
    }

    /// <summary>
    /// Sceglie un Ford da un body host: prova geometria, blob intero, finestre lead-0x04.
    /// Con IKM presente: accetta <b>solo</b> candidati che aprono (mai tenant altrui).
    /// </summary>
    private static bool TryPickFordFromHostBody(
        byte[] body,
        ReadOnlyMemory<byte> fordIkm,
        long dataStart,
        long hostStart,
        out ReadOnlyMemory<byte> ford)
    {
        ford = ReadOnlyMemory<byte>.Empty;
        _ = dataStart;
        _ = hostStart;
        if (body.Length < 0x12)
            return false;

        //-strict: body GET intero == ctLen. Niente geometric dataStart−N / scan finestre.
        if (!fordIkm.IsEmpty)
        {
            if (!FordMmcsDecryptor.TryExtractIkmOpenFord(fordIkm.Span, body, out var open))
                return false;
            ford = open;
            return true;
        }

        if (FordMmcsDecryptor.IsExactStandardFordHostLength(body.Length) && body[0] == 0x04)
        {
            ford = body;
            return true;
        }

        return false;
    }

    internal static async Task<byte[]> DownloadSingleEdgeChunkAsync(
        SignedUrlChunk chunk,
        HttpClient? http,
        CancellationToken ct,
        int chunkIndex = 0,
        int chunkTotal = 0)
    {
        // Cap globale su TUTTI i path edge (batch AG × domainParallel altrimenti → 64 GET → 403).
        var gateWaitSw = Environment.TickCount64;
        await GlobalEdgeDownloadGate.WaitAsync(ct).ConfigureAwait(false);
        var gateWaitMs = Environment.TickCount64 - gateWaitSw;
        var inFlight = Interlocked.Increment(ref _edgeInFlight);
        // #region agent log
        if (gateWaitMs >= 100 || (inFlight >= BackupEdgeDownloadParallelism && (inFlight & 7) == 0))
        {
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "edge-gate-v1",
                    ["hypothesisId"] = "H-EDGE-GATE",
                    ["location"] = "BackupDownloadService.DownloadSingleEdgeChunkAsync",
                    ["message"] = "edge_gate_enter",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        gateWaitMs,
                        inFlight,
                        cap = BackupEdgeDownloadParallelism,
                        domainParallel = ResolveDomainParallelism(),
                        objectId = chunk.EdgeHeaders?.ObjectId,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
        }
        // #endregion
        try
        {
            return await DownloadSingleEdgeChunkCoreAsync(
                    chunk, http, ct, chunkIndex, chunkTotal)
                .ConfigureAwait(false);
        }
        finally
        {
            Interlocked.Decrement(ref _edgeInFlight);
            GlobalEdgeDownloadGate.Release();
        }
    }

    /// <summary>HTTP GET edge senza gate (il chiamante deve già detenere <see cref="GlobalEdgeDownloadGate"/>).</summary>
    private static async Task<byte[]> DownloadSingleEdgeChunkCoreAsync(
        SignedUrlChunk chunk,
        HttpClient? http,
        CancellationToken ct,
        int chunkIndex = 0,
        int chunkTotal = 0)
    {
        http ??= new HttpClient();
        using var request = BuildBackupEdgeGetRequest(chunk);
        using var response = await http.SendAsync(
            request, HttpCompletionOption.ResponseHeadersRead, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            // #region agent log
            AgentFlEdgeDebugLog(
                "BackupDownloadService.DownloadSingleEdgeChunkAsync",
                "edge GET failed",
                new
                {
                    status = (int)response.StatusCode,
                    chunkIndex,
                    chunkTotal,
                    includeTryCache = false,
                    httpRange = chunk.ByteRange is { } r ? $"{r.Start}-{r.End}" : null,
                    objectId = chunk.EdgeHeaders?.ObjectId,
                    clientNowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    expired = EdgeChunkRemap.IsExpiredEdgeStatus(response.StatusCode),
                    edgeInFlight = Volatile.Read(ref _edgeInFlight),
                    authAgeHint = "core",
                },
                EdgeChunkRemap.IsExpiredEdgeStatus(response.StatusCode)
                    ? "H-EDGE-REFRESH"
                    : response.StatusCode == System.Net.HttpStatusCode.Forbidden ? "H12" : "H4");
            // #endregion
            var statusCode = (int)response.StatusCode;
            var msg = EdgeChunkRemap.IsServerSideEdgeStatus(response.StatusCode)
                ? $"edge GET HTTP {statusCode} (errore lato server Apple) " +
                  $"range={chunk.ByteRange?.Start}-{chunk.ByteRange?.End}"
                : $"edge GET HTTP {statusCode} " +
                  $"range={chunk.ByteRange?.Start}-{chunk.ByteRange?.End}";
            if (EdgeChunkRemap.IsExpiredEdgeStatus(response.StatusCode))
                throw new EdgeUrlExpiredException(response.StatusCode, msg);
            throw new InvalidOperationException(msg);
        }

        var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        if (chunk.ByteRange is { } brExpect)
        {
            var expect = brExpect.End - brExpect.Start + 1;
            if (body.Length != expect)
            {
                // #region agent log
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "range-len-v1",
                        ["hypothesisId"] = "H-RANGE-LEN",
                        ["location"] = "BackupDownloadService.DownloadSingleEdgeChunkCoreAsync",
                        ["message"] = "edge_body_len_mismatch",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            status = (int)response.StatusCode,
                            objectId = chunk.EdgeHeaders?.ObjectId,
                            range = $"{brExpect.Start}-{brExpect.End}",
                            expect,
                            actual = body.Length,
                            contentRange = response.Content.Headers.ContentRange?.ToString(),
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                throw new EdgeUrlExpiredException(
                    response.StatusCode,
                    $"edge GET body len {body.Length} ≠ range {expect} " +
                    $"oid={chunk.EdgeHeaders?.ObjectId} {brExpect.Start}-{brExpect.End}");
            }
        }

        return body;
    }

    /// <summary>Scarica N chunk edge in parallelo (ordine output = ordine input).</summary>
    internal static async Task<byte[][]> DownloadEdgeChunkBodiesParallelAsync(
        IReadOnlyList<SignedUrlChunk> ordered,
        HttpClient http,
        CancellationToken ct,
        EdgeDownloadAuthState? edgeAuth = null,
        int parallelism = BackupEdgeDownloadParallelism)
    {
        if (ordered.Count == 0)
            return [];

        var bodies = new byte[ordered.Count][];
        using var gate = new SemaphoreSlim(parallelism, parallelism);
        var tasks = new Task[ordered.Count];
        for (var i = 0; i < ordered.Count; i++)
        {
            var idx = i;
            tasks[i] = WorkerAsync(idx);
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        return bodies;

        async Task WorkerAsync(int idx)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                bodies[idx] = await DownloadSingleEdgeChunkWithRefreshAsync(
                        ordered[idx], http, edgeAuth, ct, idx + 1, ordered.Count)
                    .ConfigureAwait(false);
            }
            finally
            {
                gate.Release();
            }
        }
    }

    /// <summary>
    /// CDN/edge chiude a metà stream (Gemma multi-GB): HttpRequestException /
    /// HttpIOException ResponseEnded — ritentabile, non fatale per lo snapshot.
    /// </summary>
    internal static bool IsTransientEdgeTransport(Exception ex)
    {
        for (Exception? e = ex; e is not null; e = e.InnerException)
        {
            if (e is OperationCanceledException)
                return false;
            if (e is TimeoutException)
                return true;
            if (e is IOException)
                return true;
            if (e is HttpRequestException)
            {
                var m = e.Message;
                if (m.Contains("ResponseEnded", StringComparison.OrdinalIgnoreCase)
                    || m.Contains("ended prematurely", StringComparison.OrdinalIgnoreCase)
                    || m.Contains("copying content", StringComparison.OrdinalIgnoreCase)
                    || m.Contains("Unable to read data", StringComparison.OrdinalIgnoreCase)
                    || m.Contains("connection", StringComparison.OrdinalIgnoreCase)
                    || e.InnerException is IOException)
                    return true;
                // Altri HttpRequestException edge: un retry breve di solito basta.
                return true;
            }
        }

        return false;
    }

    internal static async Task<byte[]> DownloadSingleEdgeChunkWithRefreshAsync(
        SignedUrlChunk chunk,
        HttpClient http,
        EdgeDownloadAuthState? edgeAuth,
        CancellationToken ct,
        int chunkIndex = 0,
        int chunkTotal = 0,
        int maxAttempts = 5)
    {
        // Refresh SEMPRE fuori dal gate edge (CloudKit AG non deve bloccare gli altri GET).
        var current = chunk;
        Exception? lastIo = null;
        for (var attempt = 0; attempt < maxAttempts; attempt++)
        {
            var didPostGateRefresh = false;
            // Dopo ResponseEnded / 403: rinnova URL se possibile (range grandi).
            if (edgeAuth is not null
                && (attempt > 0 || edgeAuth.AuthAgeMs >= EdgeDownloadAuthState.MaxAuthAgeMsBeforeRefresh))
            {
                var ageBefore = edgeAuth.AuthAgeMs;
                await edgeAuth.RefreshAsync(ct, force: true).ConfigureAwait(false);
                current = edgeAuth.RemapChunk(chunk);
                // #region agent log
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "edge-io-retry-v1",
                        ["hypothesisId"] = "H-EDGE-IO",
                        ["location"] =
                            "BackupDownloadService.DownloadSingleEdgeChunkWithRefreshAsync",
                        ["message"] = "edge_jit_refresh",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            reason = attempt > 0
                                ? (lastIo is not null ? "after_io" : "after_403")
                                : "auth_age",
                            attempt,
                            ageBeforeMs = ageBefore,
                            ageAfterMs = edgeAuth.AuthAgeMs,
                            refreshN = edgeAuth.RefreshCount,
                            objectId = chunk.EdgeHeaders?.ObjectId,
                            lastIo = lastIo?.GetType().Name,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
            }

            var gateWaitSw = Environment.TickCount64;
            await GlobalEdgeDownloadGate.WaitAsync(ct).ConfigureAwait(false);
            var gateWaitMs = Environment.TickCount64 - gateWaitSw;

            // Bug 403: refresh solo PRIMA del gate → URL scadono in coda (log: expired=true,
            // edgeInFlight=8). Se abbiamo aspettato o l'auth è vecchia: rilascia, rinnova,
            // ri-prendi il gate UNA volta (niente loop).
            if (edgeAuth is not null
                && !didPostGateRefresh
                && edgeAuth.ShouldRefreshProactively(gateWaitMs))
            {
                GlobalEdgeDownloadGate.Release();
                didPostGateRefresh = true;
                // #region agent log
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "edge-io-retry-v1",
                        ["hypothesisId"] = "H-EDGE-IO",
                        ["location"] =
                            "BackupDownloadService.DownloadSingleEdgeChunkWithRefreshAsync",
                        ["message"] = "edge_jit_refresh_after_gate_wait",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            gateWaitMs,
                            authAgeMs = edgeAuth.AuthAgeMs,
                            attempt,
                            objectId = chunk.EdgeHeaders?.ObjectId,
                            range = chunk.ByteRange is { } br0 ? $"{br0.Start}-{br0.End}" : null,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                await edgeAuth.RefreshAsync(ct, force: true).ConfigureAwait(false);
                current = edgeAuth.RemapChunk(chunk);
                await GlobalEdgeDownloadGate.WaitAsync(ct).ConfigureAwait(false);
            }

            Interlocked.Increment(ref _edgeInFlight);
            try
            {
                return await DownloadSingleEdgeChunkCoreAsync(
                        current, http, ct, chunkIndex, chunkTotal)
                    .ConfigureAwait(false);
            }
            catch (EdgeUrlExpiredException) when (edgeAuth is not null && attempt < maxAttempts - 1)
            {
                lastIo = null;
                // #region agent log
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.DownloadSingleEdgeChunkWithRefreshAsync",
                    "edge_chunk_refresh",
                    new
                    {
                        attempt = attempt + 1,
                        chunkIndex,
                        chunkTotal,
                        objectId = current.EdgeHeaders?.ObjectId,
                        range = current.ByteRange is { } r ? $"{r.Start}-{r.End}" : null,
                        authAgeMs = edgeAuth.AuthAgeMs,
                        gateWaitMs,
                    },
                    "H-EDGE-REFRESH",
                    "post-fix");
                // #endregion
            }
            catch (Exception ex) when (IsTransientEdgeTransport(ex) && attempt < maxAttempts - 1)
            {
                lastIo = ex;
                // #region agent log
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "edge-io-retry-v1",
                        ["hypothesisId"] = "H-EDGE-IO",
                        ["location"] =
                            "BackupDownloadService.DownloadSingleEdgeChunkWithRefreshAsync",
                        ["message"] = "edge_io_retry",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            attempt = attempt + 1,
                            chunkIndex,
                            chunkTotal,
                            objectId = current.EdgeHeaders?.ObjectId,
                            range = current.ByteRange is { } r2 ? $"{r2.Start}-{r2.End}" : null,
                            expect = current.ByteRange is { } brE
                                ? brE.End - brE.Start + 1
                                : -1,
                            err = ex.GetType().Name,
                            msg = ex.Message,
                            inner = ex.InnerException?.GetType().Name,
                            innerMsg = ex.InnerException?.Message,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
            }
            finally
            {
                Interlocked.Decrement(ref _edgeInFlight);
                GlobalEdgeDownloadGate.Release();
            }

            // ResponseEnded su range grandi: backoff più lungo.
            var delayMs = lastIo is not null
                ? Math.Min(8_000, 400 * (1 << attempt))
                : 200 * (attempt + 1);
            await Task.Delay(delayMs, ct).ConfigureAwait(false);
        }

        if (lastIo is not null)
            throw new HttpRequestException(
                $"edge GET: transport retry esaurito ({maxAttempts}×) — {lastIo.Message}",
                lastIo);
        throw new InvalidOperationException(
            $"edge GET: retry esaurito ({maxAttempts}×) — ultimo status tipicamente 403/5xx lato server");
    }

    /// <summary>
    /// Edge GET backup iOS (capture): Range + header firmati, <b>senza</b> x-apple-try-cache.
    /// Photos/CloudDocs usano <see cref="ApplyEdgeHeaders"/> con try-cache (default).
    /// </summary>
    private static HttpRequestMessage BuildBackupEdgeGetRequest(SignedUrlChunk chunk)
    {
        var request = new HttpRequestMessage(HttpMethod.Get, chunk.Url);
        // RangeHeaderValue throws ArgumentOutOfRangeException if from>to or negative.
        if (chunk.ByteRange is { } range
            && range.Start >= 0
            && range.End >= range.Start)
            request.Headers.Range = new RangeHeaderValue(range.Start, range.End);
        ApplyEdgeHeaders(request, chunk.EdgeHeaders, includeTryCache: false);
        // #region agent log
        try
        {
            var url = chunk.Url ?? "";
            var cbr = "";
            var m = System.Text.RegularExpressions.Regex.Match(
                url, @"content-byte-range=(\d+)-(\d+)",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase);
            if (m.Success)
                cbr = m.Groups[1].Value + "-" + m.Groups[2].Value;
            var br = chunk.ByteRange;
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "b3df71",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-P4",
                ["runId"] = "get-align-v1",
                ["location"] = "BackupDownloadService.BuildBackupEdgeGetRequest",
                ["message"] = "edge_get_exact_auth_range",
                ["data"] = new Dictionary<string, object?>
                {
                    ["oid"] = chunk.EdgeHeaders?.ObjectId is { Length: > 16 } o
                        ? o[..16]
                        : chunk.EdgeHeaders?.ObjectId,
                    ["br"] = br is { } r ? $"{r.Start}-{r.End}" : null,
                    ["urlCbr"] = string.IsNullOrEmpty(cbr) ? null : cbr,
                    ["match"] = br is { } r2 && cbr == $"{r2.Start}-{r2.End}",
                    ["len"] = br is { } r3 ? r3.End - r3.Start + 1 : 0,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
        return request;
    }

    /// <summary>
    /// Download edge chunks. <c>content-byte-range</c> è offset nell'oggetto MMCS:
    /// i body vanno concatenati (compact), mai scritti con seek su Start — altrimenti
    /// il file di output ha NULL in testa fino al primo range.
    /// </summary>
    internal static async Task<long> DownloadChunksAsync(
        string outputFile,
        IReadOnlyList<SignedUrlChunk> chunks,
        int assetIndex,
        int assetTotal,
        IProgress<DownloadProgressReport>? progress,
        CancellationToken ct,
        HttpClient? http = null,
        bool mergeIntoExisting = false)
    {
        // mergeIntoExisting non ha senso con concat: il file deve essere ricreato.
        _ = mergeIntoExisting;
        var ordered = chunks
            .Where(static c => !string.IsNullOrEmpty(c.Url))
            .ToList();
        return await DownloadChunksCompactAsync(
            outputFile, ordered, assetIndex, assetTotal, progress, ct, http)
            .ConfigureAwait(false);
    }

    /// <summary>Object-ID MMCS (path o header): chiave di assemblaggio file.</summary>
    private static string ResolveObjectId(SignedUrlChunk chunk)
    {
        if (!string.IsNullOrWhiteSpace(chunk.EdgeHeaders?.ObjectId))
            return chunk.EdgeHeaders.ObjectId;

        try
        {
            var uri = new Uri(chunk.Url);
            var seg = uri.AbsolutePath.Trim('/');
            if (!string.IsNullOrEmpty(seg))
                return seg;
        }
        catch
        {
            // ignore
        }

        return "unknown";
    }

    /// <summary>
    /// Indice container Auth per un host ordered (OID + ByteRange), altrimenti -1.
    /// </summary>
    private static int IndexOfAuthorizeHost(
        IReadOnlyList<SignedUrlChunk> hosts,
        SignedUrlChunk needle)
    {
        var oid = ResolveObjectId(needle);
        var range = needle.ByteRange;
        for (var i = 0; i < hosts.Count; i++)
        {
            var h = hosts[i];
            if (!string.Equals(ResolveObjectId(h), oid, StringComparison.Ordinal))
                continue;
            if (range is { } nr && h.ByteRange is { } hr
                && nr.Start == hr.Start && nr.End == hr.End)
                return i;
            if (range is null && h.ByteRange is null
                && string.Equals(h.Url, needle.Url, StringComparison.Ordinal))
                return i;
        }

        // Fallback: stessa URL.
        for (var i = 0; i < hosts.Count; i++)
        {
            if (string.Equals(hosts[i].Url, needle.Url, StringComparison.Ordinal))
                return i;
        }

        return -1;
    }

    internal static void ApplyEdgeHeaders(
        HttpRequestMessage request,
        EdgeDownloadHeaders? headers,
        string? cloudKitContainer = null,
        string? cloudKitZone = null,
        bool includeTryCache = true)
    {
        if (headers is null)
            return;

        if (!string.IsNullOrEmpty(headers.ObjectId))
            request.Headers.TryAddWithoutValidation("X-Apple-Object-ID", headers.ObjectId);
        if (!string.IsNullOrEmpty(headers.Destination))
            request.Headers.TryAddWithoutValidation("x-apple-destination", headers.Destination);
        if (!string.IsNullOrEmpty(headers.MmeOwner))
            request.Headers.TryAddWithoutValidation("x-apple-mme-owner", headers.MmeOwner);
        if (!string.IsNullOrEmpty(headers.OpaqueOwnerId))
            request.Headers.TryAddWithoutValidation("x-apple-opaque-ownerid", headers.OpaqueOwnerId);
        if (!string.IsNullOrEmpty(headers.Partition))
            request.Headers.TryAddWithoutValidation("x-apple-content-partition", headers.Partition);
        if (!string.IsNullOrEmpty(headers.Uuid))
            request.Headers.TryAddWithoutValidation("x-apple-uuid", headers.Uuid);
        if (!string.IsNullOrEmpty(headers.Date))
            request.Headers.TryAddWithoutValidation("x-apple-date", headers.Date);
        if (!string.IsNullOrEmpty(headers.Expires))
            request.Headers.TryAddWithoutValidation("x-apple-expires", headers.Expires);
        if (!string.IsNullOrEmpty(headers.Signature))
            request.Headers.TryAddWithoutValidation("x-apple-signature", headers.Signature);

        if (!string.IsNullOrEmpty(headers.HttpDate))
            request.Headers.TryAddWithoutValidation("Date", headers.HttpDate);
        if (!string.IsNullOrEmpty(headers.BossRecommendationUsed))
            request.Headers.TryAddWithoutValidation("x-apple-boss-recommendation-used", headers.BossRecommendationUsed);
        if (!string.IsNullOrEmpty(headers.IncomingEdgePop))
            request.Headers.TryAddWithoutValidation("x-apple-incoming-icloud-edge-pop", headers.IncomingEdgePop);

        request.Headers.TryAddWithoutValidation("x-apple-mmcs-dataclass", "8");
        request.Headers.TryAddWithoutValidation("X-Apple-MMCS-Container-Size", "0");
        if (includeTryCache)
            request.Headers.TryAddWithoutValidation("x-apple-try-cache", "true");
        request.Headers.TryAddWithoutValidation(
            "x-cloudkit-container",
            string.IsNullOrWhiteSpace(cloudKitContainer) ? "com.apple.backup.ios" : cloudKitContainer);
        request.Headers.TryAddWithoutValidation(
            "x-cloudkit-zones",
            string.IsNullOrWhiteSpace(cloudKitZone) ? "_defaultZone" : cloudKitZone);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", AppleClientInfo.CloudKitDaemonClientInfo);
    }

    /// <summary>
    /// Risolve <see cref="BackupAsset.MmcsAuth"/> prima di authorizeGet.
    /// I seed flist (KA/LA/MA) arrivano senza auth: serve query/PreAuth/f2.
    /// </summary>
    private async Task<bool> EnsureMmcsAuthForAuthorizeGetAsync(
        ICloudSession session,
        BackupAsset asset,
        string snapshotDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (HasUsableMmcsAuth(asset.MmcsAuth))
            return true;

        // PreAuth: match checksum nel nome record (KA:…:token=:size → f2).
        var hex = MmcsAuthBuilder.TryExtractAssetChecksumHex(asset.RecordName);
        if (hex is not null)
        {
            var byF2 = MmcsAuthBuilder.IndexAuthsByChecksum(_assets.GetPreAuthMmcsAuthHeaders());
            if (byF2.TryGetValue(hex, out var preAuth))
            {
                asset.MmcsAuth = preAuth;
                return true;
            }
        }

        // PrivilegedBatch: flist → A:pref4:rid pieno (token); UUID nudo collide.
        if (IsCloudKitAssetRecordName(asset.RecordName)
            || !string.IsNullOrWhiteSpace(asset.RecordIdSuffix))
        {
            try
            {
                var fetchName = ResolveOwnedBackupAssetFetchName(asset);
                var fetched = await _assets.FetchKaLaMaRecordsAsync(
                    session,
                    [fetchName],
                    snapshotDirectory,
                    log,
                    ct,
                    maxFetches: 1);
                // Match per rid/token pieno — MAI solo UUID (12× 023F34AE sibling).
                // MAI "primo auth qualsiasi" / signature/WindowContains (AuthKit 09:16).
                var wantTok = TryExtractRidToken(asset.RecordIdSuffix);
                var hit = fetched.FirstOrDefault(a =>
                {
                    if (!string.IsNullOrWhiteSpace(asset.RecordIdSuffix))
                    {
                        if (string.Equals(
                                a.RecordIdSuffix, asset.RecordIdSuffix, StringComparison.Ordinal))
                            return true;
                        var fr = CloudKitMmcsIds.ToRecordIdSuffix(a.RecordName);
                        if (string.Equals(fr, asset.RecordIdSuffix, StringComparison.Ordinal))
                            return true;
                        if (wantTok is { Length: >= 8 }
                            && a.RecordName.Contains(wantTok, StringComparison.Ordinal))
                            return true;
                        // Full rid known: refuse UUID-only match.
                        return false;
                    }

                    return RecordNamesMatch(a.RecordName, asset.RecordName)
                        || (!string.IsNullOrWhiteSpace(asset.MmcsFileId)
                            && a.RecordName.Contains(
                                asset.RecordName, StringComparison.OrdinalIgnoreCase))
                        || a.RecordName.StartsWith(
                            asset.RecordName.Split('=', 2)[0], StringComparison.Ordinal);
                });
                if (hit is not null)
                {
                    // CKFile+0x08 = A:zone:uuid:token:size — mai collassare a UUID.
                    if (CloudKitMmcsIds.IsAssetRecordName(asset.RecordName))
                    {
                        // keep recordKey
                    }
                    else if (CloudKitMmcsIds.IsAssetRecordName(hit.RecordName))
                    {
                        asset.RecordName = hit.RecordName;
                    }
                    else if (!CloudKitMmcsIds.IsUuidRecordName(asset.RecordName)
                        && !string.Equals(hit.RecordName, asset.RecordName, StringComparison.Ordinal)
                        && !string.IsNullOrWhiteSpace(hit.RecordName)
                        && !CloudKitMmcsIds.IsUuidRecordName(hit.RecordName))
                    {
                        asset.RecordName = hit.RecordName;
                    }
                    if (HasUsableMmcsAuth(hit.MmcsAuth))
                        asset.MmcsAuth = hit.MmcsAuth;
                    if (hit.RecordPayload is { Length: > 32 } hp
                        && AssetRecordWindowBelongsTo(asset, hp))
                    {
                        if (asset.RecordPayload is not { Length: > 0 }
                            || (AssetRecordWindowBelongsTo(asset, asset.RecordPayload)
                                && hp.Length > asset.RecordPayload.Length)
                            || !AssetRecordWindowBelongsTo(asset, asset.RecordPayload))
                            asset.RecordPayload = hp;

                        // Always bind wrap to OUR AssetSignature —-owned only.
                        if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                            && asset.AssetSignature is { Length: >= 4 } wantSig)
                        {
                            var wrap = CloudKitAssetProto.TryResolveOwnedWrap(hp, wantSig, out _);
                            if (wrap is { Length: 24 or 40 })
                                asset.AssetProtectionInfoHex = Convert.ToHexString(wrap);
                            // #region agent log
                            AgentWrapBindLog(
                                wrap is { Length: 24 or 40 } ? "H-WRAP4" : "H-WRAP4",
                                "BackupDownloadService.EnsureMmcsAuthForAuthorizeGetAsync",
                                wrap is { Length: 24 or 40 } ? "fetch_wrap_ok" : "fetch_wrap_miss",
                                new
                                {
                                    record = asset.RecordName,
                                    winLen = hp.Length,
                                    assetCount = CloudKitAssetProto.EnumerateAssets(hp).Count,
                                    wrapLen = wrap?.Length ?? 0,
                                    sigLead = wantSig[0],
                                });
                            // #endregion
                        }
                    }
                    else if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                        && !string.IsNullOrWhiteSpace(hit.AssetProtectionInfoHex)
                        && asset.AssetSignature is { Length: >= 4 } wantSigHit
                        && hit.RecordPayload is { Length: > 32 } hitPl)
                    {
                        try
                        {
                            var hw = Convert.FromHexString(hit.AssetProtectionInfoHex);
                            if (CloudKitAssetProto.IsOwnedWrap(hitPl, wantSigHit, hw))
                                asset.AssetProtectionInfoHex = hit.AssetProtectionInfoHex;
                        }
                        catch { /* ignore */ }
                    }
                    if (string.IsNullOrWhiteSpace(asset.MmcsFileId)
                        && !string.IsNullOrWhiteSpace(hit.MmcsFileId))
                        asset.MmcsFileId = hit.MmcsFileId;
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  mmcs-auth fetch {asset.RecordName}: {ex.Message}");
            }
        }

        // Ultimo tentativo: ricostruisci da payload (UUID e/o F: fileID).
        if (!HasUsableMmcsAuth(asset.MmcsAuth)
            && asset.RecordPayload is { Length: > 32 } payload)
        {
            var built = MmcsAuthBuilder.BuildFromRecordPayload(payload, asset.RecordName);
            if (!HasUsableMmcsAuth(built) && !string.IsNullOrWhiteSpace(asset.MmcsFileId))
                built = MmcsAuthBuilder.BuildFromRecordPayload(payload, asset.MmcsFileId);
            if (HasUsableMmcsAuth(built))
                asset.MmcsAuth = built;
        }

        // Books desync: flist companion può ≠ rpF17 (stesso wrap contents). Preferisci RP.
        TryBindMmcsAuthFromOwnedRecord(asset);

        // Post-flist: header part0 = Assets.assetSignature (0x04…), non CK 0x01.
        // Companion/token restano quelli di MmcsAuth (ora allineati al RP se divergevano).
        if (HasUsableMmcsAuth(asset.MmcsAuth) && asset.AssetSignature is { Length: 21 })
            ApplyFlistSignatureOverrideToAuthHeaders([asset]);

        return HasUsableMmcsAuth(asset.MmcsAuth);
    }

    private static string AssetDownloadKey(BackupAsset asset)
    {
        if (asset.AssetSignature is { Length: 21 } sig)
            return "sig:" + Convert.ToHexString(sig).ToLowerInvariant();
        return asset.RecordName;
    }

    /// <summary>
    /// Conteggi Domain.fileList: gli Asset MMCS sono i file da scaricare;
    /// cartelle/symlink/empty restano solo in FileMetadata.
    /// </summary>
    private readonly record struct DomainInventoryTotals(
        int Files, int Directories, int Assets, int EmptyFiles, int Symlinks);

    private static DomainInventoryTotals SumDomainInventory(EnFetchResult? enFetch)
    {
        if (enFetch?.DomainRecords is not { Count: > 0 } domains)
            return default;
        long files = 0, dirs = 0, assets = 0, empty = 0, links = 0;
        foreach (var d in domains)
        {
            files += d.CumulativeFileCount;
            dirs += d.CumulativeDirectoryCount;
            assets += d.CumulativeAssetCount;
            empty += d.CumulativeEmptyFileCount;
            links += d.CumulativeSymLinkCount;
        }

        static int Cap(long n) => n > int.MaxValue ? int.MaxValue : (int)n;
        return new DomainInventoryTotals(Cap(files), Cap(dirs), Cap(assets), Cap(empty), Cap(links));
    }

    private static Dictionary<string, string> BuildDomainByFileListSignature(EnFetchResult? enFetch)
    {
        var domainBySig = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (enFetch is null)
            return domainBySig;

        foreach (var d in enFetch.DomainRecords)
        {
            if (d.FileList is null || string.IsNullOrWhiteSpace(d.DomainName))
                continue;
            domainBySig[d.FileList.SignatureHex] = d.DomainName;
        }

        if (domainBySig.Count == 0 && enFetch.FileListAssets is { Count: > 0 })
        {
            foreach (var fl in enFetch.FileListAssets)
                domainBySig[fl.SignatureHex] = fl.DomainName;
        }

        return domainBySig;
    }

    /// <summary>
    /// Rinnova Anisette prima del primo PrivilegedBatch Asset ( no Re-Lock, no ckAppInit).
    /// </summary>
    private async Task RefreshAnisetteBeforeFlistAssetsAsync(
        ICloudSession session,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (_refreshSession is null)
            return;

        log?.Report("Refresh Anisette prima di query/retrieve Asset (no ckAppInit / no Re-Lock)…");
        try
        {
            // Soft: riusa sessione + Client-Time (no mint anisette).
            await _refreshSession(session, log, ct, forceRemint: false).ConfigureAwait(false);
            _assets.ClearGatewayUnauthorized();
        }
        catch (Exception ex)
        {
            log?.Report($"  refresh pre-Asset skip: {ex.Message}");
        }
    }

    /// <summary>
    /// Attende la fine del cooldown Anisette (stesso circuito 401) senza abortire il PB.
    /// </summary>
    private async Task PauseForAnisetteCooldownAsync(IProgress<string>? log, CancellationToken ct)
    {
        const int sliceMs = 2_000;
        const int maxWaitMs = 90_000;
        var waited = 0;
        while (_assets.AnisetteRefreshBlocked && waited < maxWaitMs)
        {
            log?.Report($"  attendo Anisette… ({waited / 1000}s)");
            await Task.Delay(sliceMs, ct).ConfigureAwait(false);
            waited += sliceMs;
        }

        if (!_assets.AnisetteRefreshBlocked)
            _assets.ResetAnisetteRefreshCircuit();
    }

    /// <summary>
    /// Aggancia auth già noti (EN/PreAuth in RAM) per <b>signature digest</b>
    /// (type-byte 0x01/0x04 agnostico) — stesso join di PrivilegedBatch.
    /// </summary>
    private Task AttachFlistAuthFromCachesAsync(
        IReadOnlyList<BackupAsset> assets,
        IReadOnlyList<BackupAsset> readyAssets,
        IProgress<string>? log)
    {
        var preAuthHeaders = _assets.GetPreAuthMmcsAuthHeaders();
        // IndexAuthsBySignatureHex: full 42-char + digest 40-char (01↔04).
        var preBySig = MmcsAuthBuilder.IndexAuthsBySignatureHex(preAuthHeaders);

        var attached = 0;
        var byDigest = 0;
        var byReady = 0;
        foreach (var asset in assets)
        {
            if (HasUsableMmcsAuth(asset.MmcsAuth))
            {
                attached++;
                continue;
            }

            if (asset.AssetSignature is { Length: 21 })
            {
                var fullHex = Convert.ToHexString(asset.AssetSignature).ToLowerInvariant();
                string? hitAuth = null;
                if (preBySig.TryGetValue(fullHex, out var byFull) && HasUsableMmcsAuth(byFull))
                    hitAuth = byFull;
                else if (MmcsAuthBuilder.SignatureDigestHex(asset.AssetSignature) is { } dig
                         && preBySig.TryGetValue(dig, out var byDig)
                         && HasUsableMmcsAuth(byDig))
                {
                    hitAuth = byDig;
                    byDigest++;
                }

                if (hitAuth is not null)
                {
                    asset.MmcsAuth = hitAuth;
                    attached++;
                    continue;
                }
            }

            if (!string.IsNullOrWhiteSpace(asset.RecordIdSuffix))
            {
                // Solo RecordIdSuffix esatto — MAI RecordNamesMatch su UUID
                // (flist: molti Assets con stesso UUID, token:size diversi → RP/wrap alieni).
                // MAI SameSignatureDigest (AuthKit 12:23: RP 716E70BF… wrap BDA84A86×9).
                var hit = readyAssets.FirstOrDefault(a =>
                    HasUsableMmcsAuth(a.MmcsAuth)
                    && string.Equals(
                        a.RecordIdSuffix,
                        asset.RecordIdSuffix,
                        StringComparison.Ordinal));
                if (hit is not null)
                {
                    asset.MmcsAuth = hit.MmcsAuth;
                    if (hit.RecordPayload is { Length: > 32 } hp
                        && AssetRecordWindowBelongsTo(asset, hp)
                        && (asset.RecordPayload is not { Length: > 0 }
                            || !AssetRecordWindowBelongsTo(asset, asset.RecordPayload)
                            || hp.Length > asset.RecordPayload.Length))
                        asset.RecordPayload = hp;
                    if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                        && asset.RecordPayload is { Length: > 32 } win
                        && AssetRecordWindowBelongsTo(asset, win)
                        && asset.AssetSignature is { Length: >= 4 } wantSig)
                    {
                        var wrap = CloudKitAssetProto.TryResolveOwnedWrap(win, wantSig, out _);
                        if (wrap is { Length: 24 or 40 })
                            asset.AssetProtectionInfoHex = Convert.ToHexString(wrap);
                    }
                    else if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
                        && !string.IsNullOrWhiteSpace(hit.AssetProtectionInfoHex)
                        && asset.AssetSignature is { Length: >= 4 } wantSigHit
                        && hit.RecordPayload is { Length: > 32 } hitPl
                        && AssetRecordWindowBelongsTo(asset, hitPl))
                    {
                        try
                        {
                            var hw = Convert.FromHexString(hit.AssetProtectionInfoHex);
                            if (CloudKitAssetProto.IsOwnedWrap(hitPl, wantSigHit, hw))
                                asset.AssetProtectionInfoHex = hit.AssetProtectionInfoHex;
                        }
                        catch { /* ignore */ }
                    }

                    attached++;
                    byReady++;
                }
            }
        }

        ApplyFlistSignatureOverrideToAuthHeaders(assets);
        var preN = preAuthHeaders.Count;
        log?.Report(
            $"  auth flist da EN/PreAuth in RAM: {attached}/{assets.Count} " +
            $"(header={preN}, digestJoin={byDigest}, readyJoin={byReady}; " +
            "resto → PrivilegedBatch)");
        // #region agent log
        AgentCountAlways("auth_flist_cache_attach", new
        {
            attached,
            assets = assets.Count,
            preAuthInRam = preN,
            byDigest,
            byReady,
            stillNeed = assets.Count - attached,
            hypothesis = "H-AUTH-JOIN",
        });
        // #endregion
        return Task.CompletedTask;
    }

    /// <summary>
    /// Per un fileList: <c>query/retrieve</c> (00253) con seed
    /// <c>TYPE:pref4:rid</c> da Domain.newAssets, harvest CAog, join per
    /// <c>assetSignature</c>. Poi authorizeGet → edge.
    /// </summary>
    private async Task ResolveFlistBatchAuthAsync(
        ICloudSession session,
        IReadOnlyList<BackupAsset> batch,
        string devicePrefix4,
        string snapshotDirectory,
        EnFetchResult? enFetch,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var need = batch.Where(static a =>
            !HasUsableMmcsAuth(a.MmcsAuth)
            && !string.IsNullOrWhiteSpace(a.RecordIdSuffix)
            && a.AssetSignature is { Length: 21 }).ToList();
        if (need.Count == 0)
        {
            ApplyFlistSignatureOverrideToAuthHeaders(batch);
            return;
        }

        var enBySuffix = IndexEnNamesByRidSuffix(snapshotDirectory, enFetch);
        var seeds = new List<string>(need.Count);
        var seedTypes = new Dictionary<string, string>(StringComparer.Ordinal);
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var fromEn = 0;
        var synthesized = 0;
        foreach (var asset in need)
        {
            var rid = asset.RecordIdSuffix!;
            string? seed = null;
            string? enName = null;
            if (enBySuffix.TryGetValue(rid, out enName)
                && !CloudKitMmcsIds.IsUuidRecordName(enName))
            {
                seed = enName;
                fromEn++;
            }
            else if (TryExtractRidToken(rid) is { } tok
                     && enBySuffix.TryGetValue("tok:" + tok, out enName)
                     && !CloudKitMmcsIds.IsUuidRecordName(enName))
            {
                seed = enName;
                fromEn++;
            }

            var type = CloudKitMmcsIds.ResolveAssetType(enName, asset.SizeBytes, rid);
            if (seed is null)
            {
                seed = CloudKitMmcsIds.ToPrivilegedBatchSeed(devicePrefix4, rid, type);
                if (seed is not null)
                    synthesized++;
            }

            if (seed is null || CloudKitMmcsIds.IsUuidRecordName(seed))
                continue;
            seed = HardenPrivilegedBatchSeed(seed, devicePrefix4, asset.SizeBytes);
            seedTypes[rid] = type;
            if (!seen.Add(seed))
                continue;
            seeds.Add(seed);
        }

        if (seeds.Count == 0)
            return;

        // Domini grandi: wave di seed (PB chunk=12). Cap più alto → meno refresh Anisette.
        const int waveSeedCap = 144; // 12 chunk × 12 (ex 96 con PB×24)
        const int maxWaves = 64;
        var pendingSeeds = seeds;
        var fetched = new List<BackupAsset>();
        byte[]? payload = null;
        var wave = 0;
        var attachedBefore = 0;

        while (pendingSeeds.Count > 0 && wave < maxWaves)
        {
            wave++;
            var waveSeeds = pendingSeeds.Count <= waveSeedCap
                ? pendingSeeds
                : pendingSeeds.Take(waveSeedCap).ToList();
            pendingSeeds = pendingSeeds.Skip(waveSeeds.Count).ToList();

            log?.Report(
                $"  query/retrieve seeds wave {wave}: ×{waveSeeds.Count} " +
                $"(restano {pendingSeeds.Count}; EN={fromEn}, size-class={synthesized}), " +
                string.Join(", ", seedTypes.Values.GroupBy(static x => x)
                    .OrderBy(static g => g.Key)
                    .Select(static g => $"{g.Key}×{g.Count()}")));

            // Refresh sessione all'inizio di ogni wave grande (oltre la 1ª).
            if (wave > 1 && waveSeeds.Count >= 48 && _refreshSession is not null)
            {
                try
                {
                    log?.Report($"  refresh Anisette prima wave {wave}…");
                    await _refreshSession(session, log, ct, forceRemint: false).ConfigureAwait(false);
                    _assets.ClearGatewayUnauthorized();
                    await Task.Delay(800, ct).ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    log?.Report($"  refresh wave skip: {ex.Message}");
                }
            }

            var (more, morePayload) = await _assets.FetchPrivilegedBatchMultiAsync(
                session, waveSeeds, snapshotDirectory, log, ct).ConfigureAwait(false);
            if (more.Count > 0)
                fetched.AddRange(more);
            if (morePayload is { Length: > 0 })
                payload = morePayload;

            // Attach incrementale: se la wave ha coperto abbastanza, ferma le seed residue.
            AttachFetchedAuthToFlistAssets(need, fetched, payload, out var attachedNow);
            var gained = attachedNow - attachedBefore;
            attachedBefore = attachedNow;
            var stillNeed = need.Count(static a => !HasUsableMmcsAuth(a.MmcsAuth));
            log?.Report(
                $"  wave {wave} → +{gained} auth (totale {attachedNow}/{need.Count}, " +
                $"mancano {stillNeed})");
            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "auth-gap",
                    ["hypothesisId"] = "H-AUTH-WAVE",
                    ["location"] = "ResolveFlistBatchAuthAsync",
                    ["message"] = "pb_wave",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        wave,
                        waveSeeds = waveSeeds.Count,
                        pendingLeft = pendingSeeds.Count,
                        gained,
                        attachedNow,
                        need = need.Count,
                        stillNeed,
                        anisetteBlocked = _assets.AnisetteRefreshBlocked,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion

            if (stillNeed == 0)
                break;

            // NON svuotare pendingSeeds su Anisette blocked: è lavoro incompleto, non
            // "MmcsAuth assente". Il gateway già fa 401→refresh→stessa request; qui
            // aspettiamo il cooldown e continuiamo le seed residue (flusso PB unico).
            if (gained == 0 && _assets.AnisetteRefreshBlocked)
            {
                log?.Report(
                    $"  PrivilegedBatch: Anisette in cooldown — attendo, poi continuo " +
                    $"({stillNeed} senza auth, {pendingSeeds.Count} seed in coda)…");
                // #region agent log
                AgentCountAlways("pb_wave_anisette_pause", new
                {
                    wave,
                    stillNeed,
                    pendingLeft = pendingSeeds.Count,
                    hypothesis = "H-AUTH-JOIN",
                });
                // #endregion
                await PauseForAnisetteCooldownAsync(log, ct).ConfigureAwait(false);
                if (_refreshSession is not null)
                {
                    try
                    {
                        // Dopo cooldown 401: remint (OTP era il problema).
                        await _refreshSession(session, log, ct, forceRemint: true).ConfigureAwait(false);
                        _assets.ClearGatewayUnauthorized();
                        _assets.ResetAnisetteRefreshCircuit();
                    }
                    catch (Exception ex)
                    {
                        log?.Report($"  refresh dopo cooldown: {ex.Message}");
                    }
                }

                // Rimetti in coda anche la wave appena fallita (stesso lavoro, non un retry a valle).
                pendingSeeds = waveSeeds
                    .Concat(pendingSeeds)
                    .Distinct(StringComparer.Ordinal)
                    .ToList();
            }

            // H-AUTH-GAP: NON abbandonare seed residue su gained==0 — Domain grandi
            // (es. 900+ ready / 200+ skip) restavano senza MmcsAuth. Continua le wave.
        }

        // Retry dedicato: solo seed degli asset ancora senza auth (dopo wave + remount).
        for (var retry = 0; retry < 4; retry++)
        {
            var missing = need.Where(static a => !HasUsableMmcsAuth(a.MmcsAuth)).ToList();
            if (missing.Count == 0 || _assets.AnisetteRefreshBlocked)
                break;

            var retrySeeds = new List<string>();
            var retrySeen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var asset in missing)
            {
                var rid = asset.RecordIdSuffix;
                if (string.IsNullOrWhiteSpace(rid))
                    continue;
                string? seed = null;
                if (enBySuffix.TryGetValue(rid, out var enName)
                    && !CloudKitMmcsIds.IsUuidRecordName(enName))
                    seed = enName;
                else if (TryExtractRidToken(rid) is { } tok
                         && enBySuffix.TryGetValue("tok:" + tok, out enName)
                         && !CloudKitMmcsIds.IsUuidRecordName(enName))
                    seed = enName;
                else
                {
                    var type = seedTypes.TryGetValue(rid, out var t) ? t : "A";
                    seed = CloudKitMmcsIds.ToPrivilegedBatchSeed(devicePrefix4, rid, type);
                }

                if (seed is null || CloudKitMmcsIds.IsUuidRecordName(seed))
                    continue;
                seed = HardenPrivilegedBatchSeed(seed, devicePrefix4, asset.SizeBytes);
                if (!retrySeen.Add(seed))
                    continue;
                retrySeeds.Add(seed);
            }

            if (retrySeeds.Count == 0)
                break;

            log?.Report(
                $"  query/retrieve retry missing ×{retrySeeds.Count} " +
                $"(pass {retry + 1}, ancora senza auth={missing.Count})…");
            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "auth-gap",
                    ["hypothesisId"] = "H-AUTH-RETRY",
                    ["location"] = "ResolveFlistBatchAuthAsync",
                    ["message"] = "pb_retry_missing",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        pass = retry + 1,
                        missing = missing.Count,
                        retrySeeds = retrySeeds.Count,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion

            if (retry > 0 && _refreshSession is not null)
            {
                try
                {
                    await _refreshSession(session, log, ct, forceRemint: false).ConfigureAwait(false);
                    _assets.ClearGatewayUnauthorized();
                    await Task.Delay(800, ct).ConfigureAwait(false);
                }
                catch { /* ignore */ }
            }

            var (moreRetry, morePayloadRetry) = await _assets.FetchPrivilegedBatchMultiAsync(
                session, retrySeeds, snapshotDirectory, log, ct).ConfigureAwait(false);
            if (moreRetry.Count > 0)
                fetched.AddRange(moreRetry);
            if (morePayloadRetry is { Length: > 0 })
                payload = morePayloadRetry;
            AttachFetchedAuthToFlistAssets(need, fetched, payload, out _);
        }

        // Solo per i mancanti: TYPE alternate (no-op sul wire A:; tenuto per seed sintetici).
        // Criterio = MmcsAuth già sull'asset (rid-only), non join per signature.
        if (need.Count(static a => !HasUsableMmcsAuth(a.MmcsAuth)) > 0
            && !_assets.AnisetteRefreshBlocked)
        {
            var stillNeed = need
                .Where(static a => !HasUsableMmcsAuth(a.MmcsAuth)
                    && !string.IsNullOrWhiteSpace(a.RecordIdSuffix))
                .ToList();
            var altSeeds = new List<string>();
            var altSeen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var asset in stillNeed)
            {
                var rid = asset.RecordIdSuffix!;
                if (enBySuffix.ContainsKey(rid)
                    || (TryExtractRidToken(rid) is { } tok && enBySuffix.ContainsKey("tok:" + tok)))
                    continue;
                var primary = seedTypes.TryGetValue(rid, out var t) ? t : "A";
                foreach (var alt in CloudKitMmcsIds.EnumerateAlternateTypes(primary).Take(3))
                {
                    var s = CloudKitMmcsIds.ToPrivilegedBatchSeed(devicePrefix4, rid, alt);
                    if (s is null)
                        continue;
                    s = HardenPrivilegedBatchSeed(s, devicePrefix4, asset.SizeBytes);
                    if (!altSeen.Add(s) || seeds.Contains(s, StringComparer.Ordinal))
                        continue;
                    altSeeds.Add(s);
                }
            }

            if (altSeeds.Count > 0)
            {
                log?.Report($"  query/retrieve retry TYPE alternate ×{altSeeds.Count}…");
                var (more, morePayload) = await _assets.FetchPrivilegedBatchMultiAsync(
                    session, altSeeds, snapshotDirectory, log, ct).ConfigureAwait(false);
                fetched = fetched.Concat(more).ToList();
                if (morePayload is { Length: > 0 })
                    payload = morePayload;
            }
        }

        AttachFetchedAuthToFlistAssets(need, fetched, payload, out var attached);
        log?.Report($"  query/retrieve rid→MmcsAuth: {attached}/{need.Count}");
        // #region agent log
        try
        {
            var gap = need.Where(static a => !HasUsableMmcsAuth(a.MmcsAuth)).Take(12).Select(asset =>
            {
                var rid = asset.RecordIdSuffix ?? "";
                string? seed = null;
                var fromEn = false;
                if (enBySuffix.TryGetValue(rid, out var enName)
                    && !CloudKitMmcsIds.IsUuidRecordName(enName))
                {
                    seed = enName;
                    fromEn = true;
                }
                else if (TryExtractRidToken(rid) is { } tok
                         && enBySuffix.TryGetValue("tok:" + tok, out enName)
                         && !CloudKitMmcsIds.IsUuidRecordName(enName))
                {
                    seed = enName;
                    fromEn = true;
                }
                else
                {
                    var type = seedTypes.TryGetValue(rid, out var t) ? t : "A";
                    seed = CloudKitMmcsIds.ToPrivilegedBatchSeed(devicePrefix4, rid, type);
                }

                var seedShort = seed is null ? null : (seed.Length > 96 ? seed[..96] : seed);
                var hasSize = seed is not null
                    && CloudKitMmcsIds.TryExtractSizeFromRid(seed) is not null;
                var sigHex = asset.AssetSignature is { Length: 21 } sig
                    ? Convert.ToHexString(sig).ToLowerInvariant()
                    : null;
                return new Dictionary<string, object?>
                {
                    ["path"] = asset.RelativePath ?? asset.RecordName,
                    ["ridTail"] = rid.Length > 48 ? rid[^48..] : rid,
                    ["seed"] = seedShort,
                    ["fromEn"] = fromEn,
                    ["seedHasSize"] = hasSize,
                    ["size"] = asset.SizeBytes,
                    ["sig8"] = sigHex is { Length: >= 8 } ? sigHex[..8] : sigHex,
                    ["inSeedsList"] = seed is not null
                        && seeds.Contains(seed, StringComparer.Ordinal),
                };
            }).ToList();
            if (gap.Count > 0)
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "9a5651",
                    ["runId"] = "pb-gap-seed",
                    ["hypothesisId"] = "H1-H4",
                    ["location"] = "ResolveFlistBatchAuthAsync",
                    ["message"] = "pb_sticky_gap_seeds",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        need = need.Count,
                        attached,
                        gap = need.Count - attached,
                        fetched = fetched.Count,
                        sample = gap,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                    line + Environment.NewLine);
            }
        }
        catch { /* ignore */ }
        // #endregion
        ApplyFlistSignatureOverrideToAuthHeaders(batch);
    }

    /// <summary>
    /// <c>PrepareFilesToDownload</c>: un job = recordKey <c>A:…:rid</c> + parent
    /// <c>ck::Record</c> (stessa query) + assetSignature. Auth e wrap non si
    /// riassociano dopo per solo digest.
    /// </summary>
    private static void AttachFetchedAuthToFlistAssets(
        IReadOnlyList<BackupAsset> need,
        IReadOnlyList<BackupAsset> fetched,
        byte[]? payload,
        out int attached)
    {
        // Auth MMCS: rid-first, poi signature (PB harvest spesso RecordName=sig:…).
        // Parent Record/wrap: SOLO rid — mai dal BA matched per digest.
        var bySig = MmcsAuthBuilder.IndexAuthsBySignatureHex(
            fetched.Select(static a => a.MmcsAuth!).Where(HasUsableMmcsAuth));
        if (payload is { Length: > 0 })
        {
            foreach (var (hex, auth) in MmcsAuthBuilder.IndexAuthsBySignatureHex(
                         MmcsAuthBuilder.ExtractAllReadyMadeAuths(payload)))
                bySig.TryAdd(hex, auth);
        }

        var byRid = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        var byToken = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        foreach (var a in fetched)
        {
            if (string.IsNullOrWhiteSpace(a.RecordIdSuffix)
                && !a.RecordName.StartsWith("sig:", StringComparison.OrdinalIgnoreCase)
                && CloudKitMmcsIds.ToRecordIdSuffix(a.RecordName) is { } derived)
                a.RecordIdSuffix = derived;

            // Parent wrap: solo record con rid reale (non orphan sig: senza bind).
            var isSigOrphan = a.RecordName.StartsWith("sig:", StringComparison.OrdinalIgnoreCase)
                && string.IsNullOrWhiteSpace(a.RecordIdSuffix);
            if (!isSigOrphan)
            {
                if (!string.IsNullOrWhiteSpace(a.RecordIdSuffix))
                    byRid.TryAdd(a.RecordIdSuffix, a);
                var ridFromName = CloudKitMmcsIds.ToRecordIdSuffix(a.RecordName);
                if (ridFromName is not null)
                    byRid.TryAdd(ridFromName, a);
            }

            // Join token (size mismatch / EN vs flist): come EnsureMmcsAuth.
            var tok = TryExtractRidToken(a.RecordIdSuffix)
                ?? (!a.RecordName.StartsWith("sig:", StringComparison.OrdinalIgnoreCase)
                    ? TryExtractRidToken(CloudKitMmcsIds.ToRecordIdSuffix(a.RecordName) ?? a.RecordName)
                    : null);
            if (tok is { Length: >= 8 } && HasUsableMmcsAuth(a.MmcsAuth))
                byToken.TryAdd(tok, a);
        }

        attached = 0;
        var parentBound = 0;
        var authFromRid = 0;
        var authFromTok = 0;
        var authFromSig = 0;
        var ridMiss = 0;
        foreach (var asset in need)
        {
            BackupAsset? ck = null;
            if (!string.IsNullOrWhiteSpace(asset.RecordIdSuffix))
                byRid.TryGetValue(asset.RecordIdSuffix, out ck);
            if (ck is null
                && CloudKitMmcsIds.ToRecordIdSuffix(asset.RecordName) is { } assetRid)
                byRid.TryGetValue(assetRid, out ck);

            var wantTok = TryExtractRidToken(asset.RecordIdSuffix)
                ?? TryExtractRidToken(CloudKitMmcsIds.ToRecordIdSuffix(asset.RecordName));
            BackupAsset? tokHit = null;
            if (wantTok is { Length: >= 8 })
                byToken.TryGetValue(wantTok, out tokHit);

            if (ck is null && tokHit is not null)
                ck = tokHit;

            if (ck is null)
                ridMiss++;

            if (!HasUsableMmcsAuth(asset.MmcsAuth))
            {
                string? auth = null;
                if (ck is not null && HasUsableMmcsAuth(ck.MmcsAuth))
                {
                    auth = ck.MmcsAuth;
                    if (tokHit is not null && ReferenceEquals(ck, tokHit)
                        && (string.IsNullOrWhiteSpace(asset.RecordIdSuffix)
                            || !byRid.ContainsKey(asset.RecordIdSuffix)))
                        authFromTok++;
                    else
                        authFromRid++;
                }
                else if (tokHit is not null && HasUsableMmcsAuth(tokHit.MmcsAuth))
                {
                    auth = tokHit.MmcsAuth;
                    authFromTok++;
                }
                else if (!string.IsNullOrWhiteSpace(asset.RecordIdSuffix)
                         && TryMatchAuthByRecordEmbed(asset.RecordIdSuffix, fetched) is { } embedAuth)
                {
                    auth = embedAuth;
                    authFromTok++;
                }
                else if (asset.AssetSignature is { Length: 21 })
                {
                    // Fallback MMCS: token keyed by signature (PB orphan sig:… / CAog).
                    // Non usiamo quel BA come parent Record.
                    var fullHex = Convert.ToHexString(asset.AssetSignature).ToLowerInvariant();
                    if (bySig.TryGetValue(fullHex, out var byHex))
                        auth = byHex;
                    else if (MmcsAuthBuilder.SignatureDigestHex(asset.AssetSignature) is { } dig
                             && bySig.TryGetValue(dig, out var byDig))
                        auth = byDig;
                    else
                        auth = TryFindAuthForFlistAsset(asset, fetched, payload);
                    if (HasUsableMmcsAuth(auth))
                        authFromSig++;
                }

                if (HasUsableMmcsAuth(auth))
                    asset.MmcsAuth = auth;
            }

            // Parent Record+wrap solo da rid (mai da orphan sig:).
            if (ck is not null
                && !ck.RecordName.StartsWith("sig:", StringComparison.OrdinalIgnoreCase)
                && BindPrepareFilesParentRecord(asset, ck))
                parentBound++;

            if (HasUsableMmcsAuth(asset.MmcsAuth))
                attached++;
        }

        // #region agent log
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = "preparefiles-auth-v3",
                    ["hypothesisId"] = "H-AUTH-REGRESS",
                    ["location"] = "BackupDownloadService.AttachFetchedAuthToFlistAssets",
                    ["message"] = "preparefiles_atomic_bind",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["need"] = need.Count,
                        ["fetched"] = fetched.Count,
                        ["authAttached"] = attached,
                        ["authFromRid"] = authFromRid,
                        ["authFromTok"] = authFromTok,
                        ["authFromSig"] = authFromSig,
                        ["parentBound"] = parentBound,
                        ["ridMiss"] = ridMiss,
                        ["byRidN"] = byRid.Count,
                        ["byTokenN"] = byToken.Count,
                    },
                }) + Environment.NewLine);

            // Case2: per-asset join miss taxonomy (only when gap remains).
            if (attached < need.Count)
            {
                var missSample = need
                    .Where(static a => !HasUsableMmcsAuth(a.MmcsAuth))
                    .Take(20)
                    .Select(asset =>
                    {
                        string? rid = !string.IsNullOrWhiteSpace(asset.RecordIdSuffix)
                            ? asset.RecordIdSuffix
                            : CloudKitMmcsIds.ToRecordIdSuffix(asset.RecordName);
                        BackupAsset? ck = null;
                        var ridHit = false;
                        if (!string.IsNullOrWhiteSpace(rid)
                            && byRid.TryGetValue(rid, out ck))
                            ridHit = true;
                        var tok = TryExtractRidToken(rid);
                        var tokHit = tok is { Length: >= 8 } && byToken.ContainsKey(tok);
                        var ckHasAuth = ck is not null && HasUsableMmcsAuth(ck.MmcsAuth);
                        var sigInMap = false;
                        string? sig4 = null;
                        string? dig4 = null;
                        if (asset.AssetSignature is { Length: 21 } sig)
                        {
                            sig4 = Convert.ToHexString(sig.AsSpan(0, 4));
                            var fullHex = Convert.ToHexString(sig).ToLowerInvariant();
                            if (bySig.ContainsKey(fullHex))
                                sigInMap = true;
                            if (MmcsAuthBuilder.SignatureDigestHex(sig) is { } dig)
                            {
                                dig4 = dig.Length >= 8 ? dig[..8] : dig;
                                if (bySig.ContainsKey(dig))
                                    sigInMap = true;
                            }
                        }

                        string why;
                        if (!ridHit && !tokHit && !sigInMap)
                            why = "not_in_fetched_rid_or_sig";
                        else if (ridHit && !ckHasAuth && !sigInMap)
                            why = "rid_hit_empty_auth";
                        else if (!ridHit && !tokHit && sigInMap)
                            why = "sig_map_hit_attach_failed";
                        else if (ridHit && ckHasAuth)
                            why = "rid_had_auth_not_copied";
                        else if (tokHit)
                            why = "tok_hit_attach_failed";
                        else
                            why = "join_miss_other";

                        return new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["why"] = why,
                            ["ridHit"] = ridHit,
                            ["tokHit"] = tokHit,
                            ["ckHasAuth"] = ckHasAuth,
                            ["sigInMap"] = sigInMap,
                            ["sig4"] = sig4,
                            ["dig4"] = dig4,
                            ["size"] = asset.SizeBytes,
                            ["domain"] = asset.Domain,
                        };
                    }).ToList();

                var whyCounts = missSample
                    .GroupBy(static m => (string)(m["why"] ?? "?"))
                    .ToDictionary(static g => g.Key, static g => g.Count());
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "b3df71",
                        ["runId"] = "case2-mmcsauth-v1",
                        ["hypothesisId"] = "H-A-E-AUTHJOIN",
                        ["location"] = "BackupDownloadService.AttachFetchedAuthToFlistAssets",
                        ["message"] = "mmcs_auth_join_miss",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["need"] = need.Count,
                            ["fetched"] = fetched.Count,
                            ["authAttached"] = attached,
                            ["gap"] = need.Count - attached,
                            ["authFromRid"] = authFromRid,
                            ["authFromTok"] = authFromTok,
                            ["authFromSig"] = authFromSig,
                            ["ridMiss"] = ridMiss,
                            ["byRidN"] = byRid.Count,
                            ["byTokenN"] = byToken.Count,
                            ["bySigN"] = bySig.Count,
                            ["whyCounts"] = whyCounts,
                            ["sample"] = missSample,
                        },
                    }) + Environment.NewLine);
            }
        }
        catch { /* ignore */ }
        // #endregion
    }

    /// <summary>
    /// Pref4 dispositivo + <c>=:size</c> (EN stale / rid senza size → CK NOT_FOUND).
    /// </summary>
    private static string HardenPrivilegedBatchSeed(
        string seed,
        string devicePrefix4,
        long? sizeBytes)
    {
        var s = CloudKitMmcsIds.RewritePrivilegedBatchPref4(seed, devicePrefix4);
        if (sizeBytes is long sz and >= 0)
            s = CloudKitMmcsIds.EnsurePrivilegedBatchSeedSize(s, sz);
        return s;
    }

    /// <summary>
    /// CAog embed del rid/token (PB orphan <c>sig:</c> senza RecordName A:).
    /// </summary>
    private static string? TryMatchAuthByRecordEmbed(
        string ridOrName,
        IReadOnlyList<BackupAsset> fetched)
    {
        if (string.IsNullOrWhiteSpace(ridOrName))
            return null;
        var rid = CloudKitMmcsIds.ToRecordIdSuffix(ridOrName) ?? ridOrName.Trim();
        foreach (var a in fetched)
        {
            if (!HasUsableMmcsAuth(a.MmcsAuth))
                continue;
            if (MmcsAuthBuilder.AuthMatchesRecord(a.MmcsAuth!, rid)
                || MmcsAuthBuilder.AuthMatchesRecord(a.MmcsAuth!, ridOrName))
                return a.MmcsAuth;
            if (!a.RecordName.StartsWith("sig:", StringComparison.OrdinalIgnoreCase)
                && MmcsAuthBuilder.AuthMatchesRecord(a.MmcsAuth!, a.RecordName)
                && TryExtractRidToken(rid) is { Length: >= 8 } tok
                && a.RecordName.Contains(tok, StringComparison.Ordinal))
                return a.MmcsAuth;
        }

        return null;
    }

    /// <summary>
    /// Join auth per assetSignature (21B) — MMCS token, non parent Record.
    /// Match anche sul solo digest 20B (CK part0 può essere 0x01 mentre flist è 0x04).
    /// </summary>
    private static string? TryFindAuthForFlistAsset(
        BackupAsset asset,
        IReadOnlyList<BackupAsset> fetched,
        byte[]? payload)
    {
        if (asset.AssetSignature is not { Length: 21 } sig)
            return null;
        var hex = Convert.ToHexString(sig).ToLowerInvariant();
        var digest = MmcsAuthBuilder.SignatureDigestHex(sig);

        foreach (var a in fetched)
        {
            if (!HasUsableMmcsAuth(a.MmcsAuth))
                continue;
            if (a.AssetSignature is { Length: 21 } aSig
                && (aSig.AsSpan().SequenceEqual(sig)
                    || MmcsAuthBuilder.SameSignatureDigest(aSig, sig)))
                return a.MmcsAuth;
            if (MmcsAuthBuilder.TrySplitMmcsAuth(a.MmcsAuth, out var part0, out _, out _)
                && (part0.AsSpan().SequenceEqual(sig)
                    || MmcsAuthBuilder.SameSignatureDigest(part0, sig)))
                return a.MmcsAuth;
        }

        if (payload is { Length: > 0 })
        {
            var map = MmcsAuthBuilder.IndexAuthsBySignatureHex(
                MmcsAuthBuilder.ExtractAllReadyMadeAuths(payload));
            if (map.TryGetValue(hex, out var auth))
                return auth;
            if (digest is not null && map.TryGetValue(digest, out auth))
                return auth;
        }

        return null;
    }

    /// <summary>
    /// CKFile[+0x28]=parent Record della stessa query PrivilegedBatch/retrieve.
    /// </summary>
    private static bool BindPrepareFilesParentRecord(BackupAsset asset, BackupAsset ck)
    {
        var changed = false;
        if (ck.RecordPayload is { Length: > 32 } ckWin
            && AssetRecordWindowBelongsTo(asset, ckWin)
            && (asset.RecordPayload is not { Length: > 0 }
                || !AssetRecordWindowBelongsTo(asset, asset.RecordPayload)
                || ckWin.Length > asset.RecordPayload.Length))
        {
            asset.RecordPayload = ckWin;
            changed = true;
        }

        if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
            && asset.RecordPayload is { Length: > 32 } win
            && AssetRecordWindowBelongsTo(asset, win)
            && asset.AssetSignature is { Length: >= 4 } wantSig)
        {
            var wrap = CloudKitAssetProto.TryResolveOwnedWrap(win, wantSig, out _);
            if (wrap is { Length: 24 or 40 })
            {
                asset.AssetProtectionInfoHex = Convert.ToHexString(wrap);
                changed = true;
            }
        }
        else if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex)
            && !string.IsNullOrWhiteSpace(ck.AssetProtectionInfoHex)
            && asset.AssetSignature is { Length: >= 4 } wantSigCk
            && ck.RecordPayload is { Length: > 32 } ckPl
            && AssetRecordWindowBelongsTo(asset, ckPl))
        {
            try
            {
                var cw = Convert.FromHexString(ck.AssetProtectionInfoHex);
                if (CloudKitAssetProto.IsOwnedWrap(ckPl, wantSigCk, cw))
                {
                    asset.AssetProtectionInfoHex = ck.AssetProtectionInfoHex;
                    changed = true;
                }
            }
            catch { /* ignore */ }
        }

        // Keep recordKey A:… if CK brought it and flist already has A: or UUID.
        if (!string.IsNullOrWhiteSpace(ck.RecordName)
            && CloudKitMmcsIds.IsAssetRecordName(ck.RecordName)
            && (string.IsNullOrWhiteSpace(asset.RecordName)
                || CloudKitMmcsIds.IsUuidRecordName(asset.RecordName)))
        {
            asset.RecordName = ck.RecordName;
            changed = true;
        }

        if (string.IsNullOrWhiteSpace(asset.RecordIdSuffix)
            && !string.IsNullOrWhiteSpace(ck.RecordIdSuffix))
        {
            asset.RecordIdSuffix = ck.RecordIdSuffix;
            changed = true;
        }

        return changed;
    }

    private static Dictionary<string, string> IndexEnNamesByRidSuffix(
        string snapshotDirectory,
        EnFetchResult? enFetch)
    {
        var map = new Dictionary<string, string>(StringComparer.Ordinal);

        void Add(string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return;
            var wire = CloudKitMmcsIds.ToPrivilegedBatchWireName(name);
            if (wire is null)
                return;
            var rid = CloudKitMmcsIds.ToRecordIdSuffix(wire);
            if (rid is null)
                return;
            if (!map.TryGetValue(rid, out var existing) || wire.Length > existing.Length)
                map[rid] = wire;

            // Token-join: uuid flist e newAssets possono differire; il token base64 no.
            var token = TryExtractRidToken(rid);
            if (token is null)
                return;
            var tokKey = "tok:" + token;
            if (!map.TryGetValue(tokKey, out var byTok) || wire.Length > byTok.Length)
                map[tokKey] = wire;
        }

        if (enFetch is not null)
        {
            foreach (var n in enFetch.QuerySeeds)
                Add(n);
            foreach (var n in enFetch.AssetRecordNames)
                Add(n);
            // Fonte primaria  Domain.newAssets (TYPE:pref4:rid) — offline 100% match flist.
            foreach (var domain in enFetch.DomainRecords)
            {
                foreach (var n in domain.NewAssetRecordNames)
                    Add(n);
                foreach (var n in domain.DeletedAssetRecordNames)
                    Add(n);
            }

            foreach (var e in enFetch.FlistEntries)
            {
                if (!string.IsNullOrWhiteSpace(e.AssetRecordName))
                    Add(e.AssetRecordName);
            }

            foreach (var payload in enFetch.ResponsePayloads)
            {
                foreach (var s in ProtobufStringScanner.ExtractUtf8Strings(payload))
                    Add(s);
            }
        }

        foreach (var batchFile in Directory.EnumerateFiles(snapshotDirectory, "en_batch_*records.bin"))
        {
            try
            {
                foreach (var s in ProtobufStringScanner.ExtractUtf8Strings(File.ReadAllBytes(batchFile)))
                    Add(s);
            }
            catch
            {
                // ignore
            }
        }

        // Indice persistito al fetch EN (offline / rerun senza riscan 6+ MB).
        var indexPath = Path.Combine(snapshotDirectory, "en_newassets_rid_index.tsv");
        if (File.Exists(indexPath))
        {
            try
            {
                foreach (var line in File.ReadLines(indexPath))
                {
                    if (line.StartsWith("recordIDSuffix", StringComparison.Ordinal)
                        || string.IsNullOrWhiteSpace(line))
                        continue;
                    var parts = line.Split('\t');
                    if (parts.Length >= 2)
                        Add(parts[1].Trim());
                }
            }
            catch
            {
                // ignore
            }
        }

        return map;
    }

    /// <summary>
    /// Ricostruisce <see cref="BackupAsset.MmcsAuth"/> con f1 = assetSignature flist
    /// (header = hex(sig) hex(companion) CAog) — ground truth capture 00262.
    /// </summary>
    private static void ApplyFlistSignatureOverrideToAuthHeaders(IReadOnlyList<BackupAsset> assets)
    {
        foreach (var asset in assets)
        {
            // Prima allinea companion al RP (se diverge), poi f1 = flist AssetSignature.
            TryBindMmcsAuthFromOwnedRecord(asset);
            if (asset.AssetSignature is not { Length: 21 })
                continue;
            var entry = MmcsAuthBuilder.TryBuildFlistAuthorizeEntry(
                asset.AssetSignature, asset.MmcsAuth);
            if (entry is null)
                continue;
            asset.MmcsAuth = UbChunkBuilder.BuildMmcsAuthHeader(entry);
            asset.MmcsAuthToken = entry.AuthToken;
            asset.MmcsCompanionSignature = entry.Companion21;
        }
    }

    /// <summary>
    /// Allinea <see cref="BackupAsset.MmcsAuth"/> al RecordPayload owned quando il
    /// companion flist (f17) diverge da quello del contents/RP. usa wrap + Ford
    /// dalla stessa contents (<c>companionSrc=rpF17</c>); IKE altrimenti tiene il
    /// MmcsAuth flist e chiede un Ford incompatibile con l'IKM del wrap.
    /// </summary>
    /// <returns>True se MmcsAuth è stato sostituito con quello del Record.</returns>
    private static bool TryBindMmcsAuthFromOwnedRecord(BackupAsset asset)
    {
        if (asset.RecordPayload is not { Length: > 32 } payload)
            return false;
        if (!AssetRecordWindowBelongsTo(asset, payload))
            return false;

        string? rpAuth = null;
        var authSrc = "missing";
        if (asset.AssetSignature is { Length: >= 4 } sig)
        {
            var parsed = CloudKitAssetProto.TryFindBySignature(payload, sig);
            // Solo se splittabile in sig/companion/CAog — altrimenti fallback BuildFromRP.
            if (MmcsAuthBuilder.TrySplitMmcsAuth(parsed?.DownloadAuth, out _, out _, out _))
            {
                rpAuth = parsed!.DownloadAuth;
                authSrc = "contents-DownloadAuth";
            }
        }

        if (rpAuth is null
            || !MmcsAuthBuilder.TrySplitMmcsAuth(rpAuth, out _, out _, out _))
        {
            rpAuth = MmcsAuthBuilder.BuildFromRecordPayload(payload, asset.RecordName);
            if (!MmcsAuthBuilder.TrySplitMmcsAuth(rpAuth, out _, out _, out _)
                && !string.IsNullOrWhiteSpace(asset.MmcsFileId))
                rpAuth = MmcsAuthBuilder.BuildFromRecordPayload(payload, asset.MmcsFileId!);
            if (MmcsAuthBuilder.TrySplitMmcsAuth(rpAuth, out _, out _, out _))
                authSrc = "BuildFromRecordPayload";
        }

        if (!MmcsAuthBuilder.TrySplitMmcsAuth(rpAuth, out _, out var rpCompanion, out var rpToken))
            return false;

        if (MmcsAuthBuilder.TrySplitMmcsAuth(asset.MmcsAuth, out _, out var flistCompanion, out _)
            && flistCompanion.AsSpan().SequenceEqual(rpCompanion))
        {
            if (asset.MmcsCompanionSignature is not { Length: 21 })
                asset.MmcsCompanionSignature = rpCompanion;
            return false;
        }

        var prevCompanion = MmcsAuthBuilder.TrySplitMmcsAuth(
            asset.MmcsAuth, out _, out var prevComp, out _)
            ? Convert.ToHexString(prevComp).ToLowerInvariant()
            : null;

        asset.MmcsAuth = rpAuth;
        asset.MmcsAuthToken = rpToken;
        asset.MmcsCompanionSignature = rpCompanion;

        // #region agent log
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-AUTH-DESYNC",
                ["runId"] = "rp-auth-bind-v1",
                ["location"] = "BackupDownloadService.TryBindMmcsAuthFromOwnedRecord",
                ["message"] = "bound_mmcs_auth_from_owned_rp",
                ["data"] = new Dictionary<string, object?>
                {
                    ["path"] = asset.RelativePath ?? asset.RecordName,
                    ["prevCompanion"] = prevCompanion,
                    ["rpCompanion"] = Convert.ToHexString(rpCompanion).ToLowerInvariant(),
                    ["authSrc"] = authSrc,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        return true;
    }

    /// <summary>Finalizza file rimasti in coda pending quando la cache MMCS è completa.</summary>
    private async Task<IReadOnlyList<AssetDownloadOutcome>> FinalizePendingChunkFilesAsync(
        ICloudSession session,
        string snapshotDirectory,
        string outputRoot,
        BackupFilesystemWriter fsWriter,
        BackupFileKeyContext fileKeyCtx,
        int fileTotal,
        IProgress<DownloadProgressReport>? progress,
        IProgress<string>? log,
        CancellationToken ct,
        ConcurrentDictionary<string, string>? shardBySig = null,
        string? cleanDirForShards = null)
    {
        if (_mmcsChunkSession is null)
            return [];

        // Ri-scarica chunk dati mancanti (spesso evicted da ReleaseDataChunks o mai arrivati).
        //  finalize = FillChunks sul pending set, non enqueue infinito.
        var decryptTasks = new List<Task<AssetDownloadOutcome>>();
        var queuedAssets = new List<BackupAsset>();
        await _mmcsChunkSession.EnsurePendingChunksCachedAsync(
            _http, log, ct).ConfigureAwait(false);

        var ready = _mmcsChunkSession.TryCollectReadyPending();
        if (ready.Count == 0)
            return [];

        var outcomes = new List<AssetDownloadOutcome>(ready.Count);
        var idx = 0;
        var siblingCompacts = new ConcurrentDictionary<string, (byte[] Compact, long MmcsStart)>(
            StringComparer.Ordinal);
        _mmcsChunkSession?.SeedSiblingCompacts(siblingCompacts);
        foreach (var (pending, compact) in ready)
        {
            ct.ThrowIfCancellationRequested();
            idx++;
            log?.Report(
                $"  mmcs_cache finalize {idx}/{ready.Count}: " +
                $"{pending.Asset.RelativePath ?? pending.Asset.RecordName} " +
                $"({compact.Length:N0} B compact)");
            try
            {
                SeedSiblingCompactsFromPart(_mmcsChunkSession!, pending.Chunks, siblingCompacts, pending.AuthSlice);
                if (pending.AuthSlice.Length > 0)
                {
                    try
                    {
                        _mmcsChunkSession!.SeedChecksum21FromStoreIntoMap(
                            siblingCompacts,
                            UbChunkBuilder.BuildDecryptPlan(pending.AuthSlice));
                    }
                    catch { /* best-effort */ }
                }

                await FlushOidOrderRetriesAsync(
                    siblingCompacts, snapshotDirectory, outputRoot, fsWriter, fileKeyCtx,
                    progress, log, ct).ConfigureAwait(false);

                var ordered = UbChunkBuilder.OrderChunksForFordFile(pending.Chunks, pending.AuthSlice);
                if (compact.Length == 0
                    || pending.Asset.SizeBytes is long pSz
                       && pSz > MmcsChunkAssemblySession.MaxInMemoryCompactBytes)
                {
                    var largeOne = await FinishLargeAssetFromMmcsCacheAsync(
                        session,
                        pending.Asset,
                        snapshotDirectory,
                        outputRoot,
                        fsWriter,
                        fileKeyCtx,
                        pending.AuthSlice,
                        pending.Chunks,
                        ordered,
                        _mmcsChunkSession!,
                        siblingCompacts,
                        log,
                        ct).ConfigureAwait(false);
                    if (largeOne.WrittenSharded
                        && shardBySig is not null
                        && !string.IsNullOrWhiteSpace(cleanDirForShards))
                    {
                        RememberShardPath(pending.Asset, shardBySig, cleanDirForShards);
                    }

                    outcomes.Add(largeOne);
                    continue;
                }

                // H-BOTTLE-AG: niente decrypt sync ≥2MB qui — stessa coda del batch AG.
                if (_decryptQueue is null)
                {
                    var one = await FinishFlistAssetAfterAuthorizeAsync(
                        session,
                        pending.Asset,
                        snapshotDirectory,
                        outputRoot,
                        fsWriter,
                        fileKeyCtx,
                        pending.AuthSlice,
                        pending.Chunks,
                        idx,
                        fileTotal,
                        progress,
                        log,
                        ct,
                        prebuiltCompact: compact).ConfigureAwait(false);
                    if (one.WrittenSharded
                        && shardBySig is not null
                        && !string.IsNullOrWhiteSpace(cleanDirForShards))
                    {
                        RememberShardPath(pending.Asset, shardBySig, cleanDirForShards);
                    }

                    outcomes.Add(one);
                    continue;
                }

                var ctx = new BackupDecryptJobContext
                {
                    Session = session,
                    SnapshotDirectory = snapshotDirectory,
                    OutputRoot = outputRoot,
                    FsWriter = fsWriter,
                    FileKeyCtx = fileKeyCtx,
                    SiblingCompacts = siblingCompacts,
                    MmcsSession = _mmcsChunkSession,
                    Progress = progress,
                    Log = log,
                    Service = this,
                };
                var job = new BackupDecryptJob(
                    pending.Asset,
                    pending.AuthSlice,
                    pending.Chunks,
                    idx,
                    fileTotal,
                    compact,
                    ctx);
                var task = await _decryptQueue.ScheduleAsync(job, ct).ConfigureAwait(false);
                NoteDecryptJobScheduled();
                decryptTasks.Add(task);
                queuedAssets.Add(pending.Asset);
                lock (_pendingDecryptLock)
                    _pendingDecryptTasks.Add((pending.Asset, task));
                outcomes.Add(AssetDownloadOutcome.Queued);
            }
            catch (BackupCryptoAbortException)
            {
                throw;
            }
            catch (Exception ex)
            {
                // #region agent log
                AgentCollectionModifiedCatch(
                    "BackupDownloadService.pending_finalize",
                    pending.Asset.RelativePath ?? pending.Asset.RecordName,
                    ex);
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                        JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "b3df71",
                            ["runId"] = "finalize-nre-v1",
                            ["hypothesisId"] = "H-FINALIZE-NRE",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["location"] = "BackupDownloadService.FinalizePendingChunkFilesAsync",
                            ["message"] = "pending_finalize_exception",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["path"] = pending.Asset?.RelativePath ?? pending.Asset?.RecordName,
                                ["exType"] = ex.GetType().FullName,
                                ["exMsg"] = ex.Message,
                                ["stack"] = ex.StackTrace,
                                ["chunksNull"] = pending.Chunks is null,
                                ["chunkN"] = pending.Chunks?.Count,
                                ["authLen"] = pending.AuthSlice?.Length ?? -1,
                                ["compactLen"] = compact.Length,
                                ["sizeBytes"] = pending.Asset?.SizeBytes,
                                ["sessionNull"] = _mmcsChunkSession is null,
                                ["queueNull"] = _decryptQueue is null,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                var failPath = pending.Asset?.RelativePath ?? pending.Asset?.RecordName ?? "?";
                log?.Report($"  mmcs_cache finalize FAIL {failPath}: {ex.Message}");
                // Già rimosso da TryCollectReadyPending: rimetti in coda altrimenti
                // Pending MMCS cala senza esito e i chunk restano "held" da nessun entry.
                if (pending.Asset is null
                    || pending.Chunks is null
                    || pending.AuthSlice is null)
                {
                    outcomes.Add(AssetDownloadOutcome.Failed);
                    continue;
                }

                _mmcsChunkSession?.RegisterPending(
                    pending.Asset,
                    pending.AuthSlice,
                    pending.Chunks,
                    [ex.Message]);
                DecryptFailureJournal.Record(
                    snapshotDirectory,
                    pending.Asset,
                    "pending_finalize_error",
                    ex.Message,
                    new DecryptFailureDetails
                    {
                        AuthSlice = pending.AuthSlice,
                        Chunks = pending.Chunks,
                        ObjectId = pending.Chunks.Count > 0
                            ? ResolveObjectId(pending.Chunks[0])
                            : null,
                        CompactLength = compact.Length,
                    });
                outcomes.Add(AssetDownloadOutcome.Failed);
            }
        }

        //  finalize pending = FillChunks sul set ready, await, poi release.
        // #region agent log
        if (decryptTasks.Count > 0)
        {
            AgentCountAlways("finalize_fillchunks_overlap", new
            {
                ready = ready.Count,
                decryptN = decryptTasks.Count,
                overlap = !ResolveFillAwait(),
                fillAwait = ResolveFillAwait(),
                pendingAll = _pendingDecryptTasks.Count,
                hypothesis = "H-IKE-FILL",
                runId = "ike-fill-await-v1",
            });
        }
        // #endregion

        if (ResolveFillAwait() && decryptTasks.Count > 0)
        {
            var finished = new AssetDownloadOutcome[decryptTasks.Count];
            for (var ti = 0; ti < decryptTasks.Count; ti++)
            {
                try
                {
                    finished[ti] = await decryptTasks[ti].ConfigureAwait(false);
                }
                catch
                {
                    finished[ti] = AssetDownloadOutcome.Failed with { CountersApplied = true };
                }
            }

            lock (_pendingDecryptLock)
            {
                var doneSet = new HashSet<Task<AssetDownloadOutcome>>(decryptTasks);
                _pendingDecryptTasks.RemoveAll(p => doneSet.Contains(p.Task));
            }

            var fi = 0;
            for (var oi = 0; oi < outcomes.Count; oi++)
            {
                if (!outcomes[oi].QueuedDecrypt)
                    continue;
                if (fi >= finished.Length)
                    break;
                var r = finished[fi++];
                outcomes[oi] = r with
                {
                    QueuedDecrypt = false,
                    PendingChunks = false,
                    CountersApplied = true,
                };
            }

            siblingCompacts.Clear();
        }

        return outcomes;
    }

    /// <summary>
    /// authorizeGet batch  un fileList intero (N = Asset count). Ritorna outcomes
    /// per-file se demux OK; altrimenti null (fallback monofile).
    /// </summary>
    private async Task<FlistBatchRunResult?> TryProcessFlistAuthorizeBatchAsync(
        ICloudSession session,
        string contentHost,
        IReadOnlyList<BackupAsset> batch,
        string snapshotDirectory,
        string outputRoot,
        BackupFilesystemWriter fsWriter,
        BackupFileKeyContext fileKeyCtx,
        int fileIndexBase,
        int fileTotal,
        IProgress<DownloadProgressReport>? progress,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var entries = new List<UbChunkBuilder.AuthorizeGetFileEntry>(batch.Count);
        foreach (var a in batch)
        {
            var e = MmcsAuthBuilder.TryBuildFlistAuthorizeEntry(a.AssetSignature!, a.MmcsAuth);
            if (e is null)
                return null;
            entries.Add(e);
        }

        // Aspetta slot pipeline PRIMA di authorizeGet: l'auth non resta in coda dietro
        // altri domain (URL firmate → GET immediato). Decrypt/assemble fuori dallo slot.
        var pipeline = GetEdgeAuthDownloadPipeline();
        var pipeWaitSw = Environment.TickCount64;
        await pipeline.WaitAsync(ct).ConfigureAwait(false);
        var pipeWaitMs = Environment.TickCount64 - pipeWaitSw;
        // #region agent log
        // Always-on: FL AuthGet recovery (Quiet/IKE_AGENT_DIAG non devono nasconderlo).
        try
        {
            var f1Leads = entries.Take(12).Select(static e => e.Signature21[0]).ToArray();
            var f1Is04 = entries.Count(static e => e.Signature21[0] == 0x04);
            var f1Is01 = entries.Count(static e => e.Signature21[0] == 0x01);
            var sigMatch = 0;
            for (var i = 0; i < entries.Count; i++)
            {
                if (batch[i].AssetSignature is { Length: 21 } want
                    && want.AsSpan().SequenceEqual(entries[i].Signature21))
                    sigMatch++;
            }
            var ckPart0Lead = 0;
            var ckPart0Mismatch = 0;
            foreach (var a in batch.Take(24))
            {
                if (!MmcsAuthBuilder.TrySplitMmcsAuth(a.MmcsAuth, out var ckSig, out _, out _))
                    continue;
                if (ckSig.Length == 21)
                {
                    ckPart0Lead = ckSig[0];
                    if (a.AssetSignature is { Length: 21 } asSig
                        && !asSig.AsSpan().SequenceEqual(ckSig))
                        ckPart0Mismatch++;
                }
            }
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "fl-authget-v1",
                    ["hypothesisId"] = "H-FL2",
                    ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                    ["message"] = "flist_authget_request",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        batchFiles = batch.Count,
                        entries = entries.Count,
                        f1Is04,
                        f1Is01,
                        f1Leads,
                        assetSigMatchEntries = sigMatch,
                        ckPart0LeadSample = ckPart0Lead,
                        ckPart0MismatchVsAssetSig = ckPart0Mismatch,
                        domain = batch[0].Domain,
                        firstPath = batch[0].RelativePath ?? batch[0].RecordName,
                        pipeWaitMs,
                        slots = ResolveEdgeAuthPipelineSlots(),
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        byte[] authBody;
        long authMs;
        long emptyHostMs;
        long partsMs;
        IReadOnlyList<AuthorizeGetFilePart> files;
        MmcsChunkAssemblySession mmcsSession;
        EdgeDownloadAuthState batchEdgeAuth;
        try
        {
            var authSw = Environment.TickCount64;
            try
            {
                // Flist-sourced batch: RecordName è rid UUID, non "FL:" — flag sempre true.
                authBody = await AuthorizeGetBatchAsync(
                    session, contentHost, entries, batch[0].ZoneName, ct,
                    debugRecord: $"BATCH×{batch.Count}:{batch[0].RecordName}",
                    debugIsFileList: true)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "7dabb5",
                            ["runId"] = "fl-authget-v1",
                            ["hypothesisId"] = ex.Message.Contains("401", StringComparison.Ordinal)
                                ? "H-FL1" : "H-FL3",
                            ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                            ["message"] = "flist_authget_http_fail",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new
                            {
                                batchFiles = batch.Count,
                                err = ex.Message,
                                domain = batch[0].Domain,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.AuthorizeGetBatchAsync",
                    "authorize_get_batch_exception",
                    new
                    {
                        record = $"BATCH×{batch.Count}:{batch[0].RecordName}",
                        isFileList = true,
                        err = ex.Message,
                    },
                    ex.Message.Contains("503", StringComparison.Ordinal) ? "H-AUTH-503"
                        : ex.Message.Contains("401", StringComparison.Ordinal) ? "H-AUTH-401"
                        : "H-AUTH-ERR");
                // #endregion
                log?.Report($"  authorizeGet batch×{batch.Count}: {ex.Message}");
                return null;
            }

            authMs = Environment.TickCount64 - authSw;

            var dumpName = $"AUTH_BATCH_{fileIndexBase + 1}_{batch.Count}_authorizeGet.bin";
            if (IkeDiskDumpOptions.DumpAuthBatch)
            {
                await File.WriteAllBytesAsync(
                    Path.Combine(snapshotDirectory, dumpName), authBody, ct).ConfigureAwait(false);

                var reqBody = UbChunkBuilder.BuildAuthorizeGetRequest(entries);
                await File.WriteAllBytesAsync(
                    Path.Combine(snapshotDirectory, $"AUTH_BATCH_{fileIndexBase + 1}_{batch.Count}_request.bin"),
                    reqBody,
                    ct).ConfigureAwait(false);
            }

            try
            {
                files = UbChunkBuilder.ParseAuthorizeGetFiles(authBody);
            }
            catch (Exception ex)
            {
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "7dabb5",
                            ["runId"] = "fl-authget-v1",
                            ["hypothesisId"] = "H-FL3",
                            ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                            ["message"] = "flist_authget_parse_fail",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new
                            {
                                batch = batch.Count,
                                bodyLen = authBody.Length,
                                err = ex.Message,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                    "parse_authorize_files_exception",
                    new { batch = batch.Count, bodyLen = authBody.Length, err = ex.GetType().Name, msg = ex.Message },
                    "H-AOR2",
                    "post-fix");
                // #endregion
                log?.Report($"  authorizeGet batch×{batch.Count}: parse fail ({ex.Message}) → fallback monofile");
                return null;
            }

            if (files.Count != batch.Count)
            {
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "7dabb5",
                            ["runId"] = "fl-authget-v1",
                            ["hypothesisId"] = "H-FL3",
                            ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                            ["message"] = "flist_authget_demux_mismatch",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new
                            {
                                batch = batch.Count,
                                fileParts = files.Count,
                                bodyLen = authBody.Length,
                                authMs,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                log?.Report(
                    $"  authorizeGet batch×{batch.Count}: file_parts={files.Count} " +
                    "≠ file → fallback monofile");
                return null;
            }

            mmcsSession = _mmcsChunkSession ??= new MmcsChunkAssemblySession(
                Path.Combine(snapshotDirectory, "mmcs_cache"));
            // Retain PRIMA del prefetch: altrimenti un altro batch può ReleaseDataChunks
            // sullo stesso OID:range tra Put e SeedSibling/SeedChecksum21 → Class B
            // ike-no-data (sig: assente) anche se GET+Put erano riusciti (Radocea 2.2MB).
            mmcsSession.BeginDataChunkRetain();
            // #region agent log
            try
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = "retain-before-prefetch-v1",
                        ["hypothesisId"] = "H-B1-RETAIN",
                        ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                        ["message"] = "retain_before_prefetch",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            batchFiles = batch.Count,
                            authBodyLen = authBody.Length,
                            storeMb = mmcsSession.Store.ApproximateBytes / (1024 * 1024),
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            mmcsSession.IndexBatchAuthorizeGetHosts(authBody);
            var batchHosts = UbChunkBuilder.ParseAuthorizeGetResponse(authBody);
            batchEdgeAuth = CreateBatchEdgeAuthState(
                session,
                contentHost,
                batch,
                entries,
                authBody,
                batchHosts,
                snapshotDirectory,
                mmcsSession,
                log);
            var prefetchSw = Environment.TickCount64;
            // Empty Ford + file-parts in un solo pool GET (riempie GlobalEdgeDownloadGate=8).
            // Prima: due await sequenziali → gate idle tra le fasi. Stesse regole cache/length.
            int emptyPend;
            int partsPend;
            try
            {
                (_, _, emptyPend, partsPend) = await mmcsSession
                    .EnsureAuthorizeGetBatchPrefetchCachedAsync(
                        authBody, files, _http, log, ct, batchEdgeAuth)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                mmcsSession.EndDataChunkRetain();
                throw;
            }
            catch (Exception prefetchEx)
            {
                // Prefetch non dovrebbe più lanciare (chunk fail → RecordChunkDownloadFailure).
                // Se arriva qui: log + continua assemble (file → Falliti); retain resta attivo.
                log?.Report(
                    $"  WARN prefetch edge (continua assemble): {prefetchEx.Message}");
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                        JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "b3df71",
                            ["runId"] = "edge-500-continue-v1",
                            ["hypothesisId"] = "H-EDGE-500",
                            ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                            ["message"] = "prefetch_exception_continue_assemble",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new
                            {
                                batchFiles = batch.Count,
                                errType = prefetchEx.GetType().Name,
                                msg = prefetchEx.Message,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                emptyPend = 0;
                partsPend = 0;
            }
            var prefetchMs = Environment.TickCount64 - prefetchSw;
            // Gap-fill: riesamina i file-part (demux) e scarica ciò che il pass unificato
            // non ha messo in cache — assemble solo dopo prefetch 100% per questo batch.
            long gapFillBytes = 0;
            try
            {
                gapFillBytes = await mmcsSession
                    .EnsureFilePartsChunksCachedAsync(
                        files, _http, log, ct, batchEdgeAuth)
                    .ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                mmcsSession.EndDataChunkRetain();
                throw;
            }
            catch (Exception gapEx)
            {
                log?.Report($"  WARN prefetch gap-fill (continua assemble): {gapEx.Message}");
            }

            var leases = mmcsSession.AcquireLeasesForFileParts(files);
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
                        ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                        ["message"] = "prefetch_complete_before_assemble",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            batchFiles = batch.Count,
                            fileParts = files.Count,
                            emptyPend,
                            partsPend,
                            prefetchMs,
                            gapFillBytes,
                            leases,
                            storeMb = mmcsSession.Store.ApproximateBytes / (1024 * 1024),
                            domain = batch[0].Domain,
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion

            // Attribuisci wall-clock al breakdown: empty/parts proporzionali ai pending.
            if (emptyPend + partsPend > 0)
            {
                emptyHostMs = prefetchMs * emptyPend / (emptyPend + partsPend);
                partsMs = prefetchMs - emptyHostMs;
            }
            else
            {
                emptyHostMs = 0;
                partsMs = prefetchMs;
            }
            // #region agent log
            AgentCountAlways("ag_prefetch_done", new
            {
                batchFiles = batch.Count,
                fileParts = files.Count,
                emptyHostMs,
                partsMs,
                prefetchMs,
                emptyPend,
                partsPend,
                gapFillBytes,
                leases,
                merged = true,
                authBodyLen = authBody.Length,
                edgeParallel = BackupEdgeDownloadParallelism,
                pipeWaitMs,
                authPipelineSlots = ResolveEdgeAuthPipelineSlots(),
                flistAuthGet = true,
            });
            // #region agent log
            // Always-on: FL AuthGet response + edge prefetch shape (H-FL3/H-FL5).
            try
            {
                var plan = UbChunkBuilder.BuildDecryptPlan(authBody);
                var emptyHosts = plan.Containers.Count(static c => c.Count == 0);
                var dataHosts = plan.Containers.Count(static c => c.Count != 0);
                var descs = UbChunkBuilder.ExtractAuthFordDescriptors(authBody);
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "fl-authget-v1",
                        ["hypothesisId"] = "H-FL5",
                        ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                        ["message"] = "flist_authget_ok",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            batchFiles = batch.Count,
                            fileParts = files.Count,
                            authMs,
                            authBodyLen = authBody.Length,
                            emptyHosts,
                            dataHosts,
                            refs = plan.References.Count,
                            authDescN = descs.Count,
                            authCtLens = descs.Select(static d => d.CtLen).Take(8).ToArray(),
                            emptyPend,
                            partsPend,
                            prefetchMs,
                            domain = batch[0].Domain,
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
        }
        finally
        {
            pipeline.Release();
        }

        // Da qui auth già consumata dai GET — assemble/decrypt fuori dallo slot pipeline.
        // Retain già attivo da prima del prefetch (H-B1); End dopo assemble → decrypt su
        // siblingCompacts (sig:/gate:/oid@) in RAM — store può essere rilasciato.
        var retainHeld = true;
        var releaseTargets = new List<(IReadOnlyList<SignedUrlChunk> Chunks, byte[] AuthSlice, BackupAsset Asset)>();
        // Sibling Ford = solo empty del batch AG corrente (non tutta la cache storica).
        var siblingCompacts = new ConcurrentDictionary<string, (byte[] Compact, long MmcsStart)>(
            StringComparer.Ordinal);
        try
        {
        mmcsSession.SeedSiblingCompactsFromAuthorizeGet(siblingCompacts, authBody);
        try
        {
            mmcsSession.SeedChecksum21FromStoreIntoMap(
                siblingCompacts,
                UbChunkBuilder.BuildDecryptPlan(authBody));
        }
        catch { /* best-effort */ }

        // H-ORDER: body seedati ora possono sbloccare defer di AG precedenti.
        await FlushOidOrderRetriesAsync(
            siblingCompacts, snapshotDirectory, outputRoot, fsWriter, fileKeyCtx,
            progress, log, ct).ConfigureAwait(false);

        // #region agent log
        try
        {
            var seedPlan = UbChunkBuilder.BuildDecryptPlan(authBody);
            var seedGets = UbChunkBuilder.ParseAuthorizeGetResponse(authBody);
            var dataRefMiss = 0;
            var dataRefOk = 0;
            var dataRefStoreHas = 0;
            var dataRefOidAt = 0;
            foreach (var r in seedPlan.References)
            {
                if ((uint)r.ContainerIndex >= (uint)seedPlan.Containers.Count)
                    continue;
                var g = seedPlan.Containers[r.ContainerIndex];
                if ((uint)r.ChunkIndex >= (uint)g.Count)
                    continue;
                var ch = g[r.ChunkIndex];
                if (ch.Checksum21 is not { Length: 21 } || ch.Length <= 0)
                    continue;
                var sk = "sig:" + Convert.ToHexString(ch.Checksum21).ToLowerInvariant();
                if (siblingCompacts.TryGetValue(sk, out var sv) && sv.Compact.Length == ch.Length)
                {
                    dataRefOk++;
                    continue;
                }

                dataRefMiss++;
                var storeKey = MmcsChunkStore.SignatureToKey(ch.Checksum21);
                if (mmcsSession.Store.Has(storeKey))
                    dataRefStoreHas++;
                if ((uint)r.ContainerIndex < (uint)seedGets.Count
                    && seedGets[r.ContainerIndex].ByteRange is { } dbr)
                {
                    var oid = seedGets[r.ContainerIndex].EdgeHeaders?.ObjectId ?? "";
                    if (siblingCompacts.ContainsKey($"{oid}@{dbr.Start}"))
                        dataRefOidAt++;
                }
            }

            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = "retain-before-prefetch-v1",
                    ["hypothesisId"] = "H-B1-SEED",
                    ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                    ["message"] = "post_seed_data_ref_coverage",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        batchFiles = batch.Count,
                        refs = seedPlan.References.Count,
                        dataRefOk,
                        dataRefMiss,
                        dataRefStoreHas,
                        dataRefOidAt,
                        mapCount = siblingCompacts.Count,
                        storeMb = mmcsSession.Store.ApproximateBytes / (1024 * 1024),
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        // #region agent log
        try
        {
            var batchPlan = UbChunkBuilder.BuildDecryptPlan(authBody);
            var batchGets = UbChunkBuilder.ParseAuthorizeGetResponse(authBody);
            var expectedEmptyKeys = new List<string>();
            var sizeOut = 0;
            for (var ei = 0; ei < batchGets.Count; ei++)
            {
                if ((uint)ei < (uint)batchPlan.Containers.Count && batchPlan.Containers[ei].Count != 0)
                    continue;
                if (batchGets[ei].ByteRange is not { } br)
                    continue;
                var len = br.End - br.Start + 1;
                if (len < 112 || len > 65_536)
                {
                    sizeOut++;
                    continue;
                }

                var oid = batchGets[ei].EdgeHeaders?.ObjectId ?? "";
                expectedEmptyKeys.Add($"{oid}@{br.Start}");
            }

            var missingSib = expectedEmptyKeys.Where(k => !siblingCompacts.ContainsKey(k)).Take(20).ToArray();
            AgentCountAlways("batch_empty_vs_sibling", new Dictionary<string, object?>
            {
                ["batchFiles"] = batch.Count,
                ["expectedEmptyInWindow"] = expectedEmptyKeys.Count,
                ["siblingCount"] = siblingCompacts.Count,
                ["missingInSibling"] = missingSib.Length,
                ["sizeOutOfWindow"] = sizeOut,
                ["coveragePct"] = expectedEmptyKeys.Count == 0
                    ? 100
                    : (int)(100.0 * (expectedEmptyKeys.Count - missingSib.Length) / expectedEmptyKeys.Count),
                ["storeEntries"] = mmcsSession.Store.EntryCount,
                ["storeApproxMb"] = mmcsSession.Store.ApproximateBytes / (1024 * 1024),
                ["gcMb"] = GC.GetTotalMemory(false) / (1024 * 1024),
                ["wsMb"] = Environment.WorkingSet / (1024 * 1024),
            });
        }
        catch
        {
            // ignore
        }
        // #endregion

        var outcomes = new List<AssetDownloadOutcome>(batch.Count);
        var decryptTasks = new List<Task<AssetDownloadOutcome>>();
        var assembleSw = Environment.TickCount64;
        // #region agent log
        long assemblePureMs = 0;
        long scheduleWaitMs = 0;
        var scheduleN = 0;
        var pendingN = 0;
        // #endregion
        var jobContext = new BackupDecryptJobContext
        {
            Session = session,
            SnapshotDirectory = snapshotDirectory,
            OutputRoot = outputRoot,
            FsWriter = fsWriter,
            FileKeyCtx = fileKeyCtx,
            SiblingCompacts = siblingCompacts,
            MmcsSession = mmcsSession,
            Progress = progress,
            Log = log,
            Service = this,
        };

        for (var i = 0; i < batch.Count; i++)
        {
            var asset = batch[i];
            var idx = fileIndexBase + i + 1;
            // Progress label: indice monotono (fileIndex), non filesDone (solo OK sync).
            // #region agent log
            if (i == 0 || idx is 401 or 403 or 404)
            {
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "file-index-v1",
                        ["hypothesisId"] = "H-FILE-IDX",
                        ["location"] = "BackupDownloadService.batch_file_label",
                        ["message"] = "file_progress_label",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            idx,
                            fileIndexBase,
                            i,
                            fileTotal,
                            path = asset.RelativePath ?? asset.RecordName,
                        },
                    });
                    AgentNdjsonGated(line);
                }
                catch { /* ignore */ }
            }
            // #endregion
            log?.Report($"File {idx}/{fileTotal}: {asset.RelativePath ?? asset.RecordName}");
            AuthorizeGetFilePart? part = null;
            try
            {
                // Probe DiagC4: part = GateOwnsPlan(gate⊃AssetSignature), non solo batch index.
                part = UbChunkBuilder.SelectFilePartAligned(
                    files,
                    authBody,
                    asset.AssetSignature ?? [],
                    fallbackIndex: i);
                // #region agent log
                // H-DEMUX: stesso compact/bodyLen su path diversi = FilePart sbagliato.
                try
                {
                    var sig = asset.AssetSignature ?? [];
                    var refsHit = 0;
                    var rawHit = 0;
                    foreach (var p in files)
                    {
                        if (sig.Length >= 16
                            && UbChunkBuilder.AuthSliceContainsAssetSignatureForDebug(
                                p.AuthSlice, sig))
                            refsHit++;
                        if (sig.Length >= 16
                            && p.AuthSlice.AsSpan().IndexOf(sig) >= 0)
                            rawHit++;
                    }
                    var pick = refsHit == 1 ? "refs"
                        : rawHit == 1 ? "raw"
                        : files.Count == 1 ? "mono"
                        : (uint)i < (uint)files.Count ? "fallbackIndex" : "fallback0";
                    var partHasSig = sig.Length >= 16
                        && (UbChunkBuilder.AuthSliceContainsAssetSignatureForDebug(
                                part.AuthSlice, sig)
                            || part.AuthSlice.AsSpan().IndexOf(sig) >= 0);
                    if (pick is "fallbackIndex" or "fallback0" || !partHasSig || files.Count != batch.Count)
                    {
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                            JsonSerializer.Serialize(new Dictionary<string, object?>
                            {
                                ["sessionId"] = "7dabb5",
                                ["runId"] = "demux-fail-v1",
                                ["hypothesisId"] = "H-DEMUX",
                                ["location"] = "TryProcessFlistAuthorizeBatchAsync",
                                ["message"] = "filepart_pick",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new
                                {
                                    path = asset.RelativePath ?? asset.RecordName,
                                    record = asset.RecordName,
                                    pick,
                                    partHasSig,
                                    partsN = files.Count,
                                    batchN = batch.Count,
                                    batchIdx = i,
                                    refsHit,
                                    rawHit,
                                    authSliceLen = part.AuthSlice.Length,
                                    chunkN = part.Chunks.Count,
                                    expectSize = asset.SizeBytes,
                                    sig8 = sig.Length >= 4
                                        ? Convert.ToHexString(sig.AsSpan(0, Math.Min(8, sig.Length)))
                                        : null,
                                },
                            }) + Environment.NewLine);
                    }
                }
                catch { /* ignore */ }
                // #endregion

                var ordered = UbChunkBuilder.OrderChunksForFordFile(part.Chunks, part.AuthSlice);
                var orderedBytes = MmcsChunkAssemblySession.EstimateOrderedBytes(ordered);

                // Compact/host-sum >~1.8GB (o SizeBytes): niente MemoryStream — path file.
                var needsLarge = orderedBytes > MmcsChunkAssemblySession.MaxInMemoryCompactBytes
                    || (asset.SizeBytes is long hugeSz
                        && hugeSz > MmcsChunkAssemblySession.MaxInMemoryCompactBytes);
                if (needsLarge)
                {
                    var largeOne = await FinishLargeAssetFromMmcsCacheAsync(
                        session,
                        asset,
                        snapshotDirectory,
                        outputRoot,
                        fsWriter,
                        fileKeyCtx,
                        part.AuthSlice,
                        part.Chunks,
                        ordered,
                        mmcsSession,
                        siblingCompacts,
                        log,
                        ct).ConfigureAwait(false);
                    outcomes.Add(largeOne);
                    releaseTargets.Add((part.Chunks, part.AuthSlice, asset));
                    continue;
                }

                var (cachedCompact, missing) = mmcsSession.TryAssembleCompact(ordered);

                if (cachedCompact is null || missing.Count > 0)
                {
                    // compact-too-large non dovrebbe arrivare qui (gate sopra); resta pending.
                    if (missing.Count > 0
                        && missing[0].StartsWith("compact-too-large:", StringComparison.Ordinal))
                    {
                        var largeFallback = await FinishLargeAssetFromMmcsCacheAsync(
                            session,
                            asset,
                            snapshotDirectory,
                            outputRoot,
                            fsWriter,
                            fileKeyCtx,
                            part.AuthSlice,
                            part.Chunks,
                            ordered,
                            mmcsSession,
                            siblingCompacts,
                            log,
                            ct).ConfigureAwait(false);
                        outcomes.Add(largeFallback);
                        releaseTargets.Add((part.Chunks, part.AuthSlice, asset));
                        continue;
                    }

                    // GET edge esaurito (es. HTTP 500 server) → Falliti UI, non PENDING né abort.
                    var partPlan = part.AuthSlice.Length > 0
                        ? UbChunkBuilder.BuildDecryptPlan(part.AuthSlice)
                        : UbChunkBuilder.BuildDecryptPlan(authBody);
                    if (mmcsSession.TryGetChunkDownloadFailure(ordered, partPlan, out var edgeFail))
                    {
                        var failPath = asset.RelativePath ?? asset.RecordName;
                        log?.Report(
                            $"  ERROR {failPath}: edge server — {edgeFail}");
                        DecryptFailureJournal.Record(
                            snapshotDirectory,
                            asset,
                            "edge_server_error",
                            edgeFail,
                            new DecryptFailureDetails
                            {
                                AuthSlice = part.AuthSlice,
                                Chunks = part.Chunks,
                                ObjectId = part.Chunks.Count > 0
                                    ? ResolveObjectId(part.Chunks[0])
                                    : null,
                            });
                        // #region agent log
                        try
                        {
                            File.AppendAllText(
                                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                                JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "b3df71",
                                    ["runId"] = "edge-500-continue-v1",
                                    ["hypothesisId"] = "H-EDGE-500",
                                    ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                                    ["message"] = "edge_server_file_failed_continue",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["data"] = new
                                    {
                                        path = failPath,
                                        edgeFail,
                                        missingN = missing.Count,
                                    },
                                }) + Environment.NewLine);
                        }
                        catch { /* ignore */ }
                        // #endregion
                        // Lease acquisito al prefetch: senza Ok/Finish va rilasciato.
                        mmcsSession.ReleaseDataChunksForAsset(part.Chunks, part.AuthSlice);
                        outcomes.Add(AssetDownloadOutcome.Failed);
                        continue;
                    }

                    // Second chance: ri-GET dei missing prima di Pending (prefetch gap / race).
                    var missingBefore = missing.Count;
                    try
                    {
                        await mmcsSession.EnsureOrderedChunksCachedAsync(
                            ordered, part.AuthSlice, part.Chunks, _http, log, ct, batchEdgeAuth)
                            .ConfigureAwait(false);
                        (cachedCompact, missing) = mmcsSession.TryAssembleCompact(ordered);
                    }
                    catch (Exception refetchEx)
                    {
                        log?.Report(
                            $"  WARN ordered-refetch {asset.RelativePath ?? asset.RecordName}: " +
                            refetchEx.Message);
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
                                ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                                ["message"] = "assemble_after_ordered_refetch",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["data"] = new
                                {
                                    path = asset.RelativePath ?? asset.RecordName,
                                    missingBefore,
                                    missingAfter = missing.Count,
                                    recovered = cachedCompact is not null && missing.Count == 0,
                                },
                            }) + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion

                    if (cachedCompact is not null && missing.Count == 0)
                    {
                        // Recuperato: continua sul path assemble OK sotto (non Pending).
                        goto AssembledFromCache;
                    }

                    // #region agent log
                    pendingN++;
                    // #endregion
                    mmcsSession.RegisterPending(
                        asset, part.AuthSlice, part.Chunks, missing);
                    DecryptFailureJournal.Record(
                        snapshotDirectory,
                        asset,
                        "pending_chunks",
                        $"mancano {missing.Count} chunk: {string.Join(", ", missing.Take(3))}",
                        new DecryptFailureDetails
                        {
                            AuthSlice = part.AuthSlice,
                            Chunks = part.Chunks,
                            ObjectId = part.Chunks.Count > 0
                                ? ResolveObjectId(part.Chunks[0])
                                : null,
                        });
                    log?.Report(
                        $"  PENDING {asset.RelativePath ?? asset.RecordName}: " +
                        $"mancano {missing.Count} chunk in cache " +
                        $"({string.Join(", ", missing.Take(3))}) — download continua");
                    outcomes.Add(AssetDownloadOutcome.Pending);
                    continue;
                }

                AssembledFromCache:
                // Chunk in cache: decrypt via edge diretto (header per-chunk del file-part).
                // L'assemblaggio da cache resta solo per i pending cross-batch.
                SeedSiblingCompactsFromPart(mmcsSession, part.Chunks, siblingCompacts, part.AuthSlice);
                //  solo FileGroup di questo file (authSlice), mai plant dall'AG intero.
                try
                {
                    var slice = part.AuthSlice.Length > 0 ? part.AuthSlice : authBody;
                    mmcsSession.SeedChecksum21FromStoreIntoMap(
                        siblingCompacts,
                        UbChunkBuilder.BuildDecryptPlan(slice));
                }
                catch { /* best-effort */ }

                await FlushOidOrderRetriesAsync(
                    siblingCompacts, snapshotDirectory, outputRoot, fsWriter, fileKeyCtx,
                    progress, log, ct).ConfigureAwait(false);

                releaseTargets.Add((part.Chunks, part.AuthSlice, asset));
                // H-BOTTLE-AG: non fare decrypt sync ≥2MB nel loop AG — blocca edge/AG
                // per minuti (agMs p90≈43s, max≈568s). Coda decrypt (8 worker) +
                // backpressure channel; streaming large resta sync sotto.
                if (_decryptQueue is null)
                {
                    log?.Report(
                        $"  mmcs_cache: chunk OK per {asset.RelativePath ?? asset.RecordName}, decrypt sync");
                    var one = await FinishFlistAssetAfterAuthorizeAsync(
                        session,
                        asset,
                        snapshotDirectory,
                        outputRoot,
                        fsWriter,
                        fileKeyCtx,
                        part.AuthSlice,
                        part.Chunks,
                        idx,
                        fileTotal,
                        progress,
                        log,
                        ct,
                        siblingCompacts: siblingCompacts,
                        prebuiltCompact: cachedCompact).ConfigureAwait(false);
                    outcomes.Add(one);
                    continue;
                }

                log?.Report(
                    $"  mmcs_cache: chunk OK per {asset.RelativePath ?? asset.RecordName}, " +
                    "FillChunks (decrypt batch)");

                var job = new BackupDecryptJob(
                    asset,
                    part.AuthSlice,
                    part.Chunks,
                    idx,
                    fileTotal,
                    cachedCompact,
                    jobContext);
                // #region agent log
                var schedSw = Environment.TickCount64;
                // #endregion
                var task = await _decryptQueue.ScheduleAsync(job, ct).ConfigureAwait(false);
                // #region agent log
                scheduleWaitMs += Environment.TickCount64 - schedSw;
                scheduleN++;
                // #endregion
                NoteDecryptJobScheduled();
                decryptTasks.Add(task);
                lock (_pendingDecryptLock)
                    _pendingDecryptTasks.Add((asset, task));
                outcomes.Add(AssetDownloadOutcome.Queued);

                // #region agent log
                if (decryptTasks.Count == 1 || decryptTasks.Count % 25 == 0)
                {
                    try
                    {
                        long sibBytes = 0;
                        foreach (var kv in siblingCompacts)
                            sibBytes += kv.Value.Compact.Length;
                        var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "7dabb5",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["location"] = "BackupDownloadService.batch_enqueue",
                            ["message"] = "decrypt_queue_pressure",
                            ["hypothesisId"] = "H-OOM2",
                            ["runId"] = "oom-v2",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["queuedBatch"] = decryptTasks.Count,
                                ["pendingAll"] = _pendingDecryptTasks.Count,
                                ["channelQueued"] = _decryptQueue.QueuedCount,
                                ["inFlight"] = _decryptQueue.InFlight,
                                ["sibCount"] = siblingCompacts.Count,
                                ["sibBytes"] = sibBytes,
                                ["compact"] = cachedCompact.Length,
                                ["gcMb"] = GC.GetTotalMemory(false) / (1024 * 1024),
                                ["wsMb"] = Environment.WorkingSet / (1024 * 1024),
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
                }

                AgentFlEdgeDebugLog(
                    "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                    "decrypt_enqueued",
                    new
                    {
                        path = asset.RelativePath ?? asset.RecordName,
                        compact = cachedCompact.Length,
                        queueDepth = decryptTasks.Count,
                        inFlight = _decryptQueue.InFlight,
                        channelQueued = _decryptQueue.QueuedCount,
                    },
                    "H-PIPE",
                    "post-fix");
                // #endregion
            }
            catch (BackupCryptoAbortException ex)
            {
                var detail = ex.Message;
                var colon = detail.IndexOf(": ", StringComparison.Ordinal);
                if (colon >= 0 && colon + 2 < detail.Length)
                    detail = detail[(colon + 2)..];
                detail = detail.Replace(
                    " Il download backup è stato interrotto.",
                    "",
                    StringComparison.Ordinal);
                await RecordSkippedCryptoAsync(
                    session,
                    asset,
                    snapshotDirectory,
                    part?.AuthSlice ?? [],
                    part?.Chunks ?? [],
                    "skip_crypto",
                    detail,
                    log,
                    ct).ConfigureAwait(false);
                log?.Report(
                    $"  ERROR SKIP crypto {asset.RelativePath ?? asset.RecordName}: {detail}");
                outcomes.Add(AssetDownloadOutcome.Failed);
            }
            catch (Exception ex)
            {
                // Prefisso ERROR: in Quiet la scheda Errori filtra solo token errore
                // (altrimenti Falliti++ ma la riga «skip …» non compare — H-FAIL-UI).
                // #region agent log
                AgentCollectionModifiedCatch(
                    "BackupDownloadService.batch_fail",
                    asset.RelativePath ?? asset.RecordName,
                    ex);
                // #endregion
                log?.Report(
                    $"  ERROR {asset.RelativePath ?? asset.RecordName}: batch fail — {ex.Message}");
                DecryptFailureJournal.Record(
                    snapshotDirectory,
                    asset,
                    "batch_error",
                    ex.Message,
                    new DecryptFailureDetails
                    {
                        AuthSlice = part?.AuthSlice,
                        Chunks = part?.Chunks,
                        ObjectId = part is { Chunks.Count: > 0 }
                            ? ResolveObjectId(part.Chunks[0])
                            : null,
                    });
                outcomes.Add(AssetDownloadOutcome.Failed);
            }
        }

        // H-ORDER: fine batch — ritenta defer Ford se Put/seed hanno recuperato CT.
        await FlushOidOrderRetriesAsync(
            siblingCompacts, snapshotDirectory, outputRoot, fsWriter, fileKeyCtx,
            progress, log, ct).ConfigureAwait(false);

        var assembleMs = Environment.TickCount64 - assembleSw;
        // #region agent log
        assemblePureMs = Math.Max(0, assembleMs - scheduleWaitMs);
        AgentCountAlways("ag_assemble_split", new
        {
            batchFiles = batch.Count,
            assembleMs,
            assemblePureMs,
            scheduleWaitMs,
            scheduleN,
            pendingN,
            decryptN = decryptTasks.Count,
            channelQueued = _decryptQueue?.QueuedCount ?? 0,
            inFlight = _decryptQueue?.InFlight ?? 0,
            hypothesis = "H-Q1",
            runId = "queue-opt-v1",
        });
        // #endregion

        // Class B ike-no-data: NON rilasciare data-chunk prima di FillChunks.
        // Prima: EndRetain+Release qui → store vuoto mentre i job decrypt leggono
        // ancora siblingCompacts; se sig: non era stato copiato al seed → refs data miss.
        // Ford/PutChunks/Bind invariati: solo lifetime della cache data.
        var storeMbBeforeRelease = mmcsSession.Store.ApproximateBytes / (1024 * 1024);
        long siblingCompactBytes = 0;
        foreach (var kv in siblingCompacts)
            siblingCompactBytes += kv.Value.Compact.Length;
        // #region agent log
        AgentCountAlways("mmcs_ram_after_assemble", new
        {
            batchFiles = batch.Count,
            releaseTargets = releaseTargets.Count,
            releasedChunks = 0,
            trimmedEmpty = 0,
            siblingCount = siblingCompacts.Count,
            siblingMb = siblingCompactBytes / (1024 * 1024),
            pendingFiles = mmcsSession.PendingCount,
            storeMbBeforeRelease,
            storeEntries = mmcsSession.Store.EntryCount,
            storeApproxMb = mmcsSession.Store.ApproximateBytes / (1024 * 1024),
            gcMb = GC.GetTotalMemory(false) / (1024 * 1024),
            wsMb = Environment.WorkingSet / (1024 * 1024),
            hypothesis = "H-RAM-REL",
            retainUntilFill = true,
        });
        // #endregion

        // FillChunks: await decrypt del batch AG prima del prossimo AG
        // (no cross-AG backlog di compact → schedule_wait + multi-GB RAM).
        // Override legacy overlap: IKE_FILL_AWAIT=0.
        long fillMs = 0;
        var fillAwait = ResolveFillAwait();
        if (fillAwait && decryptTasks.Count > 0)
        {
            var fillSw = Environment.TickCount64;
            var finished = new AssetDownloadOutcome[decryptTasks.Count];
            for (var ti = 0; ti < decryptTasks.Count; ti++)
            {
                try
                {
                    finished[ti] = await decryptTasks[ti].ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    // #region agent log
                    AgentCollectionModifiedCatch(
                        "BackupDownloadService.fill_await",
                        $"decrypt_job[{ti}]",
                        ex);
                    // #endregion
                    finished[ti] = AssetDownloadOutcome.Failed with { CountersApplied = true };
                }
            }

            fillMs = Environment.TickCount64 - fillSw;

            lock (_pendingDecryptLock)
            {
                var doneSet = new HashSet<Task<AssetDownloadOutcome>>(decryptTasks);
                _pendingDecryptTasks.RemoveAll(p => doneSet.Contains(p.Task));
            }

            var fi = 0;
            for (var oi = 0; oi < outcomes.Count; oi++)
            {
                if (!outcomes[oi].QueuedDecrypt)
                    continue;
                if (fi >= finished.Length)
                    break;
                var r = finished[fi++];
                outcomes[oi] = r with
                {
                    QueuedDecrypt = false,
                    PendingChunks = false,
                    CountersApplied = true,
                };
            }

            //  Ford sibling del batch non servono oltre FillChunks.
            siblingCompacts.Clear();
        }

        // Ora sì: release data dopo FillChunks — solo file già decifrati (Ok).
        // Evict di host condivisi su fail → ike-no-data intermittente (stesso AG).
        var releasedChunks = 0;
        if (retainHeld)
        {
            mmcsSession.EndDataChunkRetain();
            retainHeld = false;
        }

        // Chunk-pipeline v1: FinishFlist/Large già chiamano ReleaseDataChunksForAsset
        // (anche via coda decrypt). Un secondo pass su releaseTargets decrementava i
        // lease due volte e poteva evictare chunk ancora referenziati da altri file/batch.
        // releaseTargets resta solo per tracciare quali asset erano candidati al release.
        _ = releaseTargets;
        var okReleased = 0;
        for (var oi = 0; oi < outcomes.Count && oi < batch.Count; oi++)
        {
            var o = outcomes[oi];
            if (o.Ok || o.FileDecrypted || o.MmcsDecrypted)
                okReleased++;
        }

        var keepEmpty = siblingCompacts.Keys.ToList();
        var trimmedEmpty = mmcsSession.TrimEmptyHostCache(keepEmpty);
        // #region agent log
        AgentCountAlways("mmcs_ram_after_fill_release", new
        {
            batchFiles = batch.Count,
            releaseTargets = releaseTargets.Count,
            releasedChunks,
            okReleased,
            skipDuplicateRelease = true,
            trimmedEmpty,
            fillAwait,
            decryptN = decryptTasks.Count,
            storeApproxMb = mmcsSession.Store.ApproximateBytes / (1024 * 1024),
            hypothesis = "H-RAM-REL-POSTFILL",
        });
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "9a5651",
                    ["runId"] = "chunk-pipeline-v1",
                    ["hypothesisId"] = "H-P3",
                    ["location"] = "BackupDownloadService.TryProcessFlistAuthorizeBatchAsync",
                    ["message"] = "post_fill_skip_duplicate_release",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        batchFiles = batch.Count,
                        releaseTargets = releaseTargets.Count,
                        okReleased,
                        trimmedEmpty,
                        storeMb = mmcsSession.Store.ApproximateBytes / (1024 * 1024),
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        // #region agent log
        AgentCountAlways("ag_batch_fillchunks_overlap", new
        {
            batchFiles = batch.Count,
            decryptN = decryptTasks.Count,
            fillMs,
            overlap = !fillAwait,
            fillAwait,
            pendingAll = _pendingDecryptTasks.Count,
            channelQueued = _decryptQueue?.QueuedCount ?? 0,
            inFlight = _decryptQueue?.InFlight ?? 0,
            authPipelineSlots = ResolveEdgeAuthPipelineSlots(),
            hypothesis = "H-IKE-FILL",
            runId = "ike-fill-await-v1",
            gcMb = GC.GetTotalMemory(false) / (1024 * 1024),
            wsMb = Environment.WorkingSet / (1024 * 1024),
        });
        // #endregion

        var phases = new AgBatchPhaseTiming(
            authMs, emptyHostMs, partsMs, assembleMs, fillMs,
            decryptTasks.Count, batch.Count);
        // #region agent log
        var accounted = authMs + emptyHostMs + partsMs + assembleMs + fillMs;
        AgentCountAlways("ag_phase_profile", new
        {
            batchFiles = batch.Count,
            authMs,
            emptyHostMs,
            partsMs,
            assembleMs,
            assemblePureMs,
            scheduleWaitMs,
            scheduleN,
            pendingN,
            fillMs,
            accountedMs = accounted,
            authPct = accounted > 0 ? (int)(100.0 * authMs / accounted) : 0,
            emptyPct = accounted > 0 ? (int)(100.0 * emptyHostMs / accounted) : 0,
            partsPct = accounted > 0 ? (int)(100.0 * partsMs / accounted) : 0,
            assemblePct = accounted > 0 ? (int)(100.0 * assembleMs / accounted) : 0,
            scheduleWaitPct = accounted > 0 ? (int)(100.0 * scheduleWaitMs / accounted) : 0,
            fillPct = accounted > 0 ? (int)(100.0 * fillMs / accounted) : 0,
            decryptN = decryptTasks.Count,
            domainParallel = ResolveDomainParallelism(),
            edgeParallel = BackupEdgeDownloadParallelism,
            decryptWorkers = ResolveDecryptWorkerParallelism(),
            dominant =
                fillMs > 0
                && fillMs >= partsMs && fillMs >= emptyHostMs && fillMs >= authMs && fillMs >= assembleMs
                    ? "fill_decrypt"
                    : scheduleWaitMs >= assemblePureMs
                      && scheduleWaitMs >= emptyHostMs
                      && scheduleWaitMs >= authMs
                      && scheduleWaitMs >= partsMs
                        ? "schedule_wait"
                        : partsMs >= emptyHostMs && partsMs >= authMs && partsMs >= assembleMs
                            ? "edge_parts"
                            : emptyHostMs >= authMs && emptyHostMs >= assembleMs
                                ? "empty_host"
                                : authMs >= assembleMs
                                    ? "authorize_get"
                                    : "assemble",
            decryptOverlap = !ResolveFillAwait(),
            fillAwait = ResolveFillAwait(),
            hypothesis = "H-PHASE",
            runId = "ike-fill-await-v1",
        });
        // #endregion

        // Store MMCS: purge reale nel finally (dopo EndDataChunkRetain / flush deferred).
        // #region agent log
        AgentCountAlways("mmcs_ram_before_retain_end", new
        {
            pendingFiles = mmcsSession.PendingCount,
            storeApproxMb = mmcsSession.Store.ApproximateBytes / (1024 * 1024),
            storeEntries = mmcsSession.Store.EntryCount,
            gcMb = GC.GetTotalMemory(false) / (1024 * 1024),
            wsMb = Environment.WorkingSet / (1024 * 1024),
            hypothesis = "H-RAM-REL",
        });
        // #endregion

        return new FlistBatchRunResult(outcomes, DecryptTasks: [], Phases: phases);
        }
        finally
        {
            if (retainHeld)
                mmcsSession.EndDataChunkRetain();
            // Retain off → flush deferred (solo Ok già rilasciati) + cap pending.
            // Niente ClearCacheIfIdle qui: wipe globale con pending=0 toglie host
            // ancora utili al prossimo AG → ike-no-data intermittente.
            var purged = mmcsSession.PurgeDataChunksAfterBatch(log);
            var clearedIdle = 0;
            var keepPending = mmcsSession.CollectPendingKeepOidAtStartKeys();
            var trimmedAfter = mmcsSession.TrimEmptyHostCache(keepPending);
            // FillAwait: sibling già Clear dopo WhenAll. Overlap legacy: worker ancora vivi.
            if (ResolveFillAwait())
                siblingCompacts.Clear();
            var (pendN, authBytes, uniqueAuth) = mmcsSession.EstimatePendingRam();
            var gcBefore = GC.GetTotalMemory(false) / (1024 * 1024);
            var wsBefore = Environment.WorkingSet / (1024 * 1024);
            var forcedGc = false;
            long gcAfter = gcBefore;
            long wsAfter = wsBefore;
            // ~300MB: Gen2 se supera ~512MB (prima 768/1536 lasciava crescere troppo).
            if (gcBefore >= 512 || wsBefore >= 768)
            {
                GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
                GC.WaitForPendingFinalizers();
                GC.Collect(2, GCCollectionMode.Aggressive, blocking: true, compacting: true);
                forcedGc = true;
                gcAfter = GC.GetTotalMemory(true) / (1024 * 1024);
                wsAfter = Environment.WorkingSet / (1024 * 1024);
            }

            // #region agent log
            AgentCountAlways("mmcs_ram_after_fillchunks", new
            {
                purged,
                clearedIdle,
                trimmedAfter,
                pendingFiles = pendN,
                pendingAuthMb = authBytes / (1024 * 1024),
                pendingUniqueAuthMb = uniqueAuth / (1024 * 1024),
                storeApproxMb = mmcsSession.Store.ApproximateBytes / (1024 * 1024),
                storeEntries = mmcsSession.Store.EntryCount,
                gcMb = gcAfter,
                wsMb = wsAfter,
                gcBeforeMb = gcBefore,
                wsBeforeMb = wsBefore,
                forcedGc,
                fillAwait = ResolveFillAwait(),
                decryptWorkers = ResolveDecryptWorkerParallelism(),
                decryptCapacity = ResolveDecryptQueueCapacity(),
                hypothesis = "H-RAM",
            });
            // #endregion
        }
    }

    internal async Task<AssetDownloadOutcome> RunDecryptJobAsync(
        BackupDecryptJob job,
        CancellationToken ct)
    {
        var ctx = job.Context;
        try
        {
            var outcome = await FinishFlistAssetAfterAuthorizeAsync(
                ctx.Session,
                job.Asset,
                ctx.SnapshotDirectory,
                ctx.OutputRoot,
                ctx.FsWriter,
                ctx.FileKeyCtx,
                job.AuthResponseBody,
                job.Chunks,
                job.AssetIndex,
                job.AssetTotal,
                ctx.Progress,
                ctx.Log,
                ct,
                siblingCompacts: ctx.SiblingCompacts,
                prebuiltCompact: job.PrebuiltCompact,
                mmcsSession: ctx.MmcsSession).ConfigureAwait(false);

            // Decrementa coda PRIMA del Report (InFlight channel include ancora questo job).
            var queueLeft = NoteDecryptJobFinished();
            var totalForUi = Math.Max(_uiFilesTotal > 0 ? _uiFilesTotal : job.AssetTotal, 1);

            if (outcome.Ok && outcome.WrittenSharded)
            {
                var pathOk = job.Asset.RelativePath ?? job.Asset.RecordName;
                // Scaricati già ++ a schedule; qui solo Decifrati (successo fuori coda).
                var before = Volatile.Read(ref _uiFilesDecrypted);
                NoteFileDecrypted("decrypt_job_ok", pathOk);
                // Cifrati = ancora MMCS/Ford cipher su disco (!MmcsDecrypted).
                // !FileDecrypted = solo “no class-key AES” (normale post-Ford) → non contare.
                if (CountsAsCiphertextOnDisk(outcome))
                    NoteCiphertextSaved("decrypt_job_ok_cipher", pathOk);
                var live = Volatile.Read(ref _uiFilesDecrypted);
                // #region agent log
                AgentCountAlways("decrypt_job_ok_count", new
                {
                    path = pathOk,
                    before,
                    after = live,
                    downloaded = Volatile.Read(ref _uiFilesDownloaded),
                    failed = Volatile.Read(ref _uiFilesDecryptFailed),
                    ciphertext = Volatile.Read(ref _uiFilesCiphertextSaved),
                    mmcs = outcome.MmcsDecrypted,
                    fileAes = outcome.FileDecrypted,
                    countedCipher = CountsAsCiphertextOnDisk(outcome),
                    queueLeft,
                    hypothesis = "H-CIPHER-SEM",
                    runId = "cipher-count-mmcs-v1",
                });
                // #endregion
                ReportFilesDoneProgress(
                    ctx.Progress,
                    live,
                    totalForUi,
                    outcome.DownloadedBytes,
                    decryptQueuedOverride: queueLeft);
                return outcome with { CountersApplied = true };
            }
            else if (outcome.Ok)
            {
                // Ok senza shard (FL/meta): non è un file Backup in attesa —
                // annulla Scaricati dello schedule altrimenti gap permanente.
                var pathMeta = job.Asset.RelativePath ?? job.Asset.RecordName;
                UndoFileDownloaded("decrypt_ok_not_written", pathMeta);
                // #region agent log
                AgentCountAlways("decrypt_ok_not_written", new
                {
                    path = pathMeta,
                    queueLeft,
                    writtenSharded = outcome.WrittenSharded,
                    staged = outcome.StagedChunks,
                    downloaded = Volatile.Read(ref _uiFilesDownloaded),
                    decrypted = Volatile.Read(ref _uiFilesDecrypted),
                    hypothesis = "H-PENDING-GAP",
                });
                // #endregion
                ReportFilesDoneProgress(
                    ctx.Progress,
                    Volatile.Read(ref _uiFilesDecrypted),
                    totalForUi,
                    decryptQueuedOverride: queueLeft);
                // Ok senza shard (raro in coda): non Falliti; caller non riconta.
                return outcome with { CountersApplied = true };
            }
            else if (!outcome.PendingChunks && !outcome.QueuedDecrypt)
            {
                var pathFail = job.Asset.RelativePath ?? job.Asset.RecordName;
                var beforeFail = Volatile.Read(ref _uiFilesDecrypted);
                var failDetail =
                    !outcome.MmcsDecrypted ? "mmcs_not_decrypted"
                    : outcome.WrittenSharded ? "written_but_failed"
                    : "decrypt_job_failed";
                NoteDecryptFailed(
                    "decrypt_job_fail",
                    pathFail,
                    emitUiError: true,
                    detail: failDetail);
                if (CountsAsCiphertextOnDisk(outcome))
                    NoteCiphertextSaved("decrypt_job_fail_cipher", pathFail);
                var afterFail = Volatile.Read(ref _uiFilesDecrypted);
                // #region agent log
                AgentCountAlways("decrypt_job_fail_count", new
                {
                    path = pathFail,
                    before = beforeFail,
                    after = afterFail,
                    downloaded = Volatile.Read(ref _uiFilesDownloaded),
                    failed = Volatile.Read(ref _uiFilesDecryptFailed),
                    ciphertext = Volatile.Read(ref _uiFilesCiphertextSaved),
                    mmcs = outcome.MmcsDecrypted,
                    fileAes = outcome.FileDecrypted,
                    written = outcome.WrittenSharded,
                    countedCipher = CountsAsCiphertextOnDisk(outcome),
                    queueLeft,
                    decryptedUnchanged = beforeFail == afterFail,
                    hypothesis = "H-CIPHER-SEM",
                    runId = "cipher-count-mmcs-v1",
                });
                // #endregion
                ReportFilesDoneProgress(
                    ctx.Progress,
                    Volatile.Read(ref _uiFilesDecrypted),
                    totalForUi,
                    decryptQueuedOverride: queueLeft);
                return outcome with { CountersApplied = true };
            }
            else
            {
                // PendingChunks / QueuedDecrypt: job esce dalla coda decrypt ma
                // non ha esito — annulla Scaricati dello schedule; il file resta
                // in Pending MMCS / H-ORDER fino al finalize/retry.
                var pathPend = job.Asset.RelativePath ?? job.Asset.RecordName;
                UndoFileDownloaded("decrypt_job_pending", pathPend);
                // #region agent log
                AgentCountAlways("decrypt_job_pending_undo", new
                {
                    path = pathPend,
                    queueLeft,
                    pendingChunks = outcome.PendingChunks,
                    queuedDecrypt = outcome.QueuedDecrypt,
                    downloaded = Volatile.Read(ref _uiFilesDownloaded),
                    decrypted = Volatile.Read(ref _uiFilesDecrypted),
                    pendingUi = CurrentPendingChunkFiles(),
                    hypothesis = "H-PENDING-GAP",
                });
                // #endregion
                ReportFilesDoneProgress(
                    ctx.Progress,
                    Volatile.Read(ref _uiFilesDecrypted),
                    totalForUi,
                    decryptQueuedOverride: queueLeft);
                return outcome with { CountersApplied = true };
            }
        }
        catch (BackupCryptoAbortException)
        {
            NoteDecryptJobFinished();
            throw;
        }
        catch (Exception ex)
        {
            var queueLeftEx = NoteDecryptJobFinished();
            // #region agent log
            AgentCollectionModifiedCatch(
                "BackupDownloadService.decrypt_job",
                job.Asset.RelativePath ?? job.Asset.RecordName,
                ex);
            // #endregion
            NoteDecryptFailed(
                "decrypt_job_exception",
                job.Asset.RelativePath ?? job.Asset.RecordName,
                emitUiError: true,
                detail: ex.Message);
            ReportFilesDoneProgress(
                ctx.Progress,
                Volatile.Read(ref _uiFilesDecrypted),
                Math.Max(_uiFilesTotal > 0 ? _uiFilesTotal : job.AssetTotal, 1),
                decryptQueuedOverride: queueLeftEx);
            return AssetDownloadOutcome.Failed with { CountersApplied = true };
        }
    }

    private async Task<DecryptDrainStats> DrainPendingDecryptTasksAsync(
        ConcurrentDictionary<string, string>? shardBySig,
        string cleanDir,
        IProgress<DownloadProgressReport>? progress,
        IProgress<string>? log,
        CancellationToken ct)
    {
        List<(BackupAsset Asset, Task<AssetDownloadOutcome> Task)> remaining;
        lock (_pendingDecryptLock)
        {
            if (_pendingDecryptTasks.Count == 0)
                return default;

            log?.Report(
                $"decrypt pipeline: attendo {_pendingDecryptTasks.Count} job " +
                $"(inFlight={_decryptQueue?.InFlight ?? 0})…");

            remaining = new List<(BackupAsset Asset, Task<AssetDownloadOutcome> Task)>(_pendingDecryptTasks);
            _pendingDecryptTasks.Clear();
        }
        var done = 0;
        long addBytes = 0;
        var addWritten = 0;
        var addStaged = 0;
        var addMmcs = 0;
        var addFile = 0;
        while (remaining.Count > 0)
        {
            ct.ThrowIfCancellationRequested();
            var finished = await Task.WhenAny(remaining.Select(static x => x.Task)).ConfigureAwait(false);
            var idx = remaining.FindIndex(x => x.Task == finished);
            if (idx < 0)
                continue;
            var (asset, _) = remaining[idx];
            remaining.RemoveAt(idx);
            AssetDownloadOutcome one;
            try
            {
                one = await finished.ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // #region agent log
                AgentBkFailLog(
                    "H-DRAIN",
                    "BackupDownloadService.DrainPendingDecryptTasksAsync",
                    "decrypt_task_fault",
                    new
                    {
                        path = asset.RelativePath ?? asset.RecordName,
                        type = ex.GetType().FullName,
                        msg = ex.Message,
                        stack = ex.StackTrace?.Split('\n').Take(8).ToArray(),
                    });
                // #endregion
                log?.Report(
                    $"  ERROR decrypt job {asset.RelativePath ?? asset.RecordName}: " +
                    $"{ex.GetType().Name}: {ex.Message}");
                done++;
                continue;
            }
            done++;
            if (!one.Ok)
                continue;
            addBytes += one.DownloadedBytes;
            if (one.WrittenSharded)
            {
                addWritten++;
                if (shardBySig is not null)
                    RememberShardPath(asset, shardBySig, cleanDir);
                // Progress già aggiornato in RunDecryptJobAsync — qui solo stats.
            }
            if (one.StagedChunks) addStaged++;
            if (one.MmcsDecrypted) addMmcs++;
            if (one.FileDecrypted) addFile++;
            // Niente AssetsTotal qui: la bar la aggiorna il caller con writtenSharded.
            log?.Report($"  decrypt async ok {done}: {asset.RelativePath ?? asset.RecordName}");
        }

        if (_decryptQueue is not null)
            await _decryptQueue.WhenIdleAsync(ct).ConfigureAwait(false);

        // Forza coda UI a 0 (ultimo job poteva aver riportato depth con race).
        if (Volatile.Read(ref _uiDecryptPending) != 0)
            Volatile.Write(ref _uiDecryptPending, 0);
        ReportFilesDoneProgress(progress, Volatile.Read(ref _uiFilesDecrypted), Math.Max(_uiFilesTotal, 1));

        log?.Report($"decrypt pipeline: {done} job completati");
        return new DecryptDrainStats(done, addBytes, addWritten, addStaged, addMmcs, addFile);
    }

    /// <summary>
    /// H-ORDER: dopo seed di nuovi body OID, ritenta asset no-ford recuperati via packScan.
    /// </summary>
    private async Task FlushOidOrderRetriesAsync(
        ConcurrentDictionary<string, (byte[] Compact, long MmcsStart)> siblingCompacts,
        string snapshotDirectory,
        string outputRoot,
        BackupFilesystemWriter fsWriter,
        BackupFileKeyContext fileKeyCtx,
        IProgress<DownloadProgressReport>? progress,
        IProgress<string>? log,
        CancellationToken ct)
    {
        _ = snapshotDirectory;
        _ = outputRoot;
        _ = fsWriter;
        _ = fileKeyCtx;
        while (OidHostBodyCache.TryDequeueRecovered(out var path))
        {
            if (!_oidOrderRetries.TryRemove(path, out var r) || r.Attempts >= 3)
                continue;
            log?.Report($"  retry oid_pack_recover: {path}");
            // #region agent log
            try
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = "oid-order-v2",
                        ["hypothesisId"] = "H-ORDER",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "BackupDownloadService.FlushOidOrderRetriesAsync",
                        ["message"] = "oid_order_retry",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = path,
                            ["attempts"] = r.Attempts,
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            try
            {
                // Finish completo (assemble + write shard), non solo TraceDecrypt.
                var outcome = await FinishFlistAssetAfterAuthorizeAsync(
                    r.Session,
                    r.Asset,
                    snapshotDirectory,
                    outputRoot,
                    fsWriter,
                    fileKeyCtx,
                    r.AuthBody,
                    r.Chunks,
                    r.AssetIndex,
                    r.AssetTotal,
                    r.Progress ?? progress,
                    log,
                    ct,
                    siblingCompacts: siblingCompacts).ConfigureAwait(false);
                if (outcome.PendingChunks
                    || (!outcome.Ok && !outcome.MmcsDecrypted))
                {
                    // Ancora deferred / miss → rimetti in coda (max Attempts).
                    _oidOrderRetries[path] = r with
                    {
                        Attempts = outcome.PendingChunks ? r.Attempts : r.Attempts + 1,
                    };
                    log?.Report(
                        $"  retry oid_pack_recover FAIL: {path} " +
                        $"(pending={outcome.PendingChunks} ok={outcome.Ok})");
                    ReportFilesDoneProgress(
                        r.Progress ?? progress,
                        Volatile.Read(ref _uiFilesDecrypted),
                        Math.Max(_uiFilesTotal, 1));
                }
                else if (outcome.Ok && outcome.WrittenSharded)
                {
                    // Retry sync: non passa da Schedule → applica Scaricati+Decifrati.
                    NoteSyncOrQueuedOutcome(outcome, "oid_order_retry_ok");
                    log?.Report($"  retry oid_pack_recover OK: {path}");
                    ReportFilesDoneProgress(
                        r.Progress ?? progress,
                        Volatile.Read(ref _uiFilesDecrypted),
                        Math.Max(_uiFilesTotal, 1),
                        outcome.DownloadedBytes);
                }
                else if (outcome.Ok && outcome.MmcsDecrypted)
                {
                    log?.Report($"  retry oid_pack_recover OK: {path}");
                    ReportFilesDoneProgress(
                        r.Progress ?? progress,
                        Volatile.Read(ref _uiFilesDecrypted),
                        Math.Max(_uiFilesTotal, 1));
                }
                else
                {
                    _oidOrderRetries[path] = r with { Attempts = r.Attempts + 1 };
                    log?.Report($"  retry oid_pack_recover FAIL: {path}");
                    ReportFilesDoneProgress(
                        r.Progress ?? progress,
                        Volatile.Read(ref _uiFilesDecrypted),
                        Math.Max(_uiFilesTotal, 1));
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  retry oid_pack_recover ERR: {path}: {ex.Message}");
            }
        }
    }

    private static void SeedSiblingCompactsFromPart(
        MmcsChunkAssemblySession mmcsSession,
        IReadOnlyList<SignedUrlChunk> chunks,
        ConcurrentDictionary<string, (byte[] Compact, long MmcsStart)> siblingCompacts,
        byte[]? authSlice = null,
        ReadOnlySpan<byte> fordIkm = default)
    {
        // FillContainers twin: solo host Ford (empty/CI45) + Read(ctLen) identity.
        // MAI alias oid@0 su data host / (0,hint) — contaminava Ford → fordOpen=0
        // (oracle SeedLive OK vs oid0ctLen FAIL).
        AuthorizeGetDecryptPlan? plan = null;
        IReadOnlyList<UbChunkBuilder.AuthFordDescriptor> descs =
            Array.Empty<UbChunkBuilder.AuthFordDescriptor>();
        byte[]? fileId = null;
        HashSet<string> ownedOids = new(StringComparer.Ordinal);
        if (authSlice is { Length: > 0 })
        {
            try
            {
                plan = UbChunkBuilder.BuildDecryptPlan(authSlice);
                descs = UbChunkBuilder.CollectAuthFordDescriptors(authSlice, plan, chunks);
                fileId = plan.FileChecksum is { Length: 21 } fc ? fc : null;
                foreach (var d in UbChunkBuilder.ExtractAuthFordDescriptors(authSlice))
                {
                    if (d.Gate45.Length != 45 || string.IsNullOrEmpty(d.ObjectId))
                        continue;
                    if (fileId is { Length: 21 }
                        && UbChunkBuilder.GateEmbedsFileChecksum(d.Gate45, fileId))
                        ownedOids.Add(d.ObjectId);
                }
            }
            catch { /* seed best-effort */ }
        }

        var fordSeeded = 0;
        var oid0Aliased = 0;
        var skippedData = 0;

        void SeedFordBody(
            SignedUrlChunk ch,
            bool allowOid0,
            int preferredCtLen,
            bool plantOwnedGate,
            IReadOnlyList<AuthorizeGetCryptoChunk>? hostGroup)
        {
            if (ch.ByteRange is not { } br)
                return;
            var hostLen = br.End - br.Start + 1;
            // GET = ByteRange Auth intero; minimo = Auth ctLen tipico (≥0x12), non 112.
            if (hostLen < 0x12)
                return;
            var oid = ch.EdgeHeaders?.ObjectId ?? "";
            if (string.IsNullOrEmpty(oid))
                return;
            var key = $"{oid}@{br.Start}";
            var body = mmcsSession.TryGetChunkBody(ch);
            // Data-only: recovery store se oid@{Start} manca (Class B ike-no-data).
            if (body is not { Length: > 0 }
                && hostGroup is not null
                && hostGroup.Any(UbChunkBuilder.IsAuthDataChunk)
                && !hostGroup.Any(UbChunkBuilder.IsAuthFordDescriptorChunk))
            {
                body = mmcsSession.TryGetChunkBodyOrRecoverData(ch, hostGroup);
            }

            if (body is not { Length: > 0 })
                return;
            if (!siblingCompacts.ContainsKey(key))
            {
                siblingCompacts[key] = (body, br.Start);
                fordSeeded++;
                // H-ORDER: tutti i range OID in cache di processo (Books@112 → pack MB dopo).
                OidHostBodyCache.Put(oid, br.Start, body);
                // Seed body only — spill Ford in PutChunksFromHostBodies (exact|wireOff).
                _ = plantOwnedGate;
                _ = preferredCtLen;
                _ = hostGroup;
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "03cce7",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["hypothesisId"] = "H-NO-SEED-PLANT",
                            ["runId"] = LiveFillPipeline.RunId,
                            ["location"] = "BackupDownloadService.SeedFordBody",
                            ["message"] = "seed_body_only_no_putchunk",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["oid8"] = oid.Length >= 8 ? oid[..8] : oid,
                                ["bodyLen"] = body.Length,
                                ["hostStart"] = br.Start,
                                ["hostGates"] = hostGroup?.Count ?? 0,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
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
                            ["location"] = "BackupDownloadService.SeedSiblingCompactsFromPart",
                            ["message"] = "seed_large_ford_part",
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
            }

            if (!allowOid0)
                return;
            // Solo il HostInfo con ByteRange.Start==0 può vivere come oid@0.
            // Alias da @2851040 (altro gate sullo stesso OID) sovrascriveva il Ford owned
            // → dump ike_run: waSy@0 == waSy@2851040, IKM ok ma fordOpen=0 (cross IE=True).
            if (br.Start != 0)
            {
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-OID0-ALIAS",
                        ["runId"] = "oid0-guard-v1",
                        ["location"] = "BackupDownloadService.SeedFordBody",
                        ["message"] = "skip_oid0_alias_nonzero_start",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["oid"] = oid.Length > 16 ? oid[..16] : oid,
                            ["start"] = br.Start,
                            ["bodyLen"] = body.Length,
                            ["preferredCtLen"] = preferredCtLen,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                return;
            }

            // Read(ctLen) identity: SOLO body == ctLen. MAI pack[0..ctLen) —
            // su host N×112 il gate owned è a off>0 (oracle oid0ctLen → fordOpen=0 / MAC/SIV).
            if (preferredCtLen is >= 0x12 and <= 65_536 && body.Length == preferredCtLen)
            {
                siblingCompacts[oid + "@0"] = (body, 0L);
                oid0Aliased++;
            }
            else if (preferredCtLen <= 0 && body.Length is >= 0x12 and <= 4096
                     && body[0] == 0x04)
            {
                // empty Ford CT: qualsiasi ctLen Auth (112/155/224/234/…), non solo 112.
                siblingCompacts[oid + "@0"] = (body, 0L);
                oid0Aliased++;
            }
        }

        for (var i = 0; i < chunks.Count; i++)
        {
            var ch = chunks[i];
            var group = plan is not null && (uint)i < (uint)plan.Containers.Count
                ? plan.Containers[i]
                : null;
            var isFordHost = group is null
                ? false
                : group.Count == 0
                  || group.Any(UbChunkBuilder.IsAuthFordDescriptorChunk)
                  || UbChunkBuilder.IsAuthFordMaterialHost(group);
            //  plant TUTTI gli host (Ford + data) sotto oid@{Start}.
            // oid@0 / .chunks gate: solo CI45 del container host (mai empty-OID broadcast).
            if (!isFordHost)
            {
                SeedFordBody(ch, allowOid0: false, preferredCtLen: 0, plantOwnedGate: false, hostGroup: group);
                skippedData++; // counted as data host seeded without oid@0
                continue;
            }

            var oidHost = ch.EdgeHeaders?.ObjectId ?? "";
            var ownedHost = ownedOids.Contains(oidHost)
                            || descs.Any(d =>
                                string.Equals(d.ObjectId, oidHost, StringComparison.Ordinal));
            // Gate Put = FillContainers: host Ford-only con ≥1 CI45 → PutChunk tutti i gate.
            // Empty/size0 senza CI45: SpillOpen exact via PutChunksFromHostBodies.
            var fordOnlyHost = group is not null
                               && group.Count > 0
                               && group.All(UbChunkBuilder.IsAuthFordDescriptorChunk);
            var plantGate = fordOnlyHost
                            && group!.Any(c =>
                                UbChunkBuilder.IsAuthFordDescriptorChunk(c)
                                && c.Checksum21.Length == 45);
            var ctPrefer = descs
                .Where(d => string.Equals(d.ObjectId, oidHost, StringComparison.Ordinal))
                .Select(d => d.CtLen)
                .FirstOrDefault(l => l is >= 0x12 and <= 65_536);
            if (ctPrefer == 0 && group is not null)
            {
                foreach (var c in group)
                {
                    if (UbChunkBuilder.IsAuthFordDescriptorChunk(c)
                        && c.Length is >= 0x12 and <= 65_536)
                    {
                        ctPrefer = c.Length;
                        break;
                    }
                }
            }

            SeedFordBody(
                ch,
                allowOid0: ownedHost,
                preferredCtLen: ctPrefer,
                plantOwnedGate: plantGate,
                hostGroup: group);
        }

        // Nested gate-oid senza host CI45: plant CT owned sotto oid@0 da cache Auth range.
        foreach (var d in descs)
        {
            if (string.IsNullOrEmpty(d.ObjectId) || d.CtLen is < 0x12 or > 65_536)
                continue;
            if (fileId is { Length: 21 }
                && d.Gate45.Length == 45
                && !UbChunkBuilder.GateEmbedsFileChecksum(d.Gate45, fileId)
                && !ownedOids.Contains(d.ObjectId))
                continue;
            if (siblingCompacts.ContainsKey(d.ObjectId + "@0"))
                continue;
            foreach (var ch in chunks)
            {
                if (!string.Equals(ch.EdgeHeaders?.ObjectId, d.ObjectId, StringComparison.Ordinal)
                    || ch.ByteRange is not { } br
                    || br.Start != 0)
                    continue;
                var hostLen = br.End - br.Start + 1;
                if (hostLen < d.CtLen)
                    continue;
                var body = mmcsSession.TryGetChunkBody(ch);
                if (body is null || body.Length < d.CtLen)
                    continue;
                // demux: solo body exact ctLen @Start=0 (gate → Read(ctLen) altrove).
                if (body.Length == d.CtLen)
                {
                    siblingCompacts[d.ObjectId + "@0"] = (body, 0L);
                    oid0Aliased++;
                }
                break;
            }
        }

        // L1 PutChunk finale: SpillOpen exact/wire/packScan(IKM) → .chunks/hex(gate).
        if (plan is not null)
            LiveFillPipeline.PutChunksFromHostBodies(
                siblingCompacts, plan, chunks, authSlice, fordIkm);

        // #region agent log
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-DL2",
                ["runId"] = LiveFillPipeline.RunId,
                ["location"] = "BackupDownloadService.SeedSiblingCompactsFromPart",
                ["message"] = "sibling_ford_auth_only",
                ["data"] = new Dictionary<string, object?>
                {
                    ["chunks"] = chunks.Count,
                    ["descs"] = descs.Count,
                    ["ownedOids"] = ownedOids.Count,
                    ["fordSeeded"] = fordSeeded,
                    ["oid0Aliased"] = oid0Aliased,
                    ["skippedData"] = skippedData,
                    ["mapCount"] = siblingCompacts.Count,
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
    /// Asset &gt;~1.8 GB: assembla chunk da cache senza MemoryStream, Ford decrypt su FileStream.
    /// </summary>
    private async Task<AssetDownloadOutcome> FinishLargeAssetFromMmcsCacheAsync(
        ICloudSession session,
        BackupAsset asset,
        string snapshotDirectory,
        string outputRoot,
        BackupFilesystemWriter fsWriter,
        BackupFileKeyContext fileKeyCtx,
        byte[] authSlice,
        IReadOnlyList<SignedUrlChunk> chunks,
        IReadOnlyList<SignedUrlChunk> ordered,
        MmcsChunkAssemblySession mmcsSession,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var pathLabel = asset.RelativePath ?? asset.RecordName;
        var plan = UbChunkBuilder.BuildDecryptPlan(authSlice);
        var missing = new List<string>();
        // ordered ⊆ chunks: allinea body → container index (non bodies[i]==Containers[i]).
        var orderedBodies = new List<(int ContainerIndex, byte[] Body)>(ordered.Count);
        long downloaded = 0;
        foreach (var ch in ordered)
        {
            var body = mmcsSession.TryGetChunkBody(ch);
            if (body is null)
            {
                missing.Add(MmcsChunkAssemblySession.DescribeMissingChunk(ch));
                continue;
            }

            var ci = IndexOfAuthorizeHost(chunks, ch);
            if (ci < 0)
                ci = IndexOfAuthorizeHost(ordered, ch);
            orderedBodies.Add((ci, body));
            downloaded += body.Length;
        }

        if (missing.Count > 0)
        {
            mmcsSession.RegisterPending(asset, authSlice, chunks, missing);
            DecryptFailureJournal.Record(
                snapshotDirectory,
                asset,
                "pending_chunks",
                $"large-asset mancano {missing.Count}: {string.Join(", ", missing.Take(3))}",
                new DecryptFailureDetails { AuthSlice = authSlice, Chunks = chunks });
            log?.Report(
                $"  PENDING large {pathLabel}: mancano {missing.Count} chunk");
            return AssetDownloadOutcome.Pending;
        }

        await EnsureAssetWrapAndIkmAsync(session, asset, snapshotDirectory, log, ct)
            .ConfigureAwait(false);
        var fordIkm = TryResolveFordIkm(asset, out var ikmSrc);
        if (fordIkm is not { Length: > 0 })
        {
            log?.Report($"  ERROR large {pathLabel}: manca IKM Ford ({ikmSrc})");
            DecryptFailureJournal.Record(
                snapshotDirectory, asset, "mmcs_not_decrypted", "large-asset no IKM",
                new DecryptFailureDetails { AuthSlice = authSlice, Chunks = chunks });
            return AssetDownloadOutcome.Failed;
        }

        var fordCiphers = new List<byte[]>();
        var dataByContainer = new Dictionary<int, byte[]>();
        foreach (var (ci, body) in orderedBodies)
        {
            if ((uint)ci < (uint)plan.Containers.Count
                && (UbChunkBuilder.IsAuthFordMaterialHost(plan.Containers[ci])
                    || UbChunkBuilder.IsFordSizedHostLengths(plan.Containers[ci])))
            {
                fordCiphers.Add(body);
                continue;
            }

            if (ci >= 0)
                dataByContainer[ci] = body;
        }

        // dataChunks nell'ordine first-seen dei refs (perHostOwned).
        var dataChunks = new List<byte[]>();
        var seenData = new HashSet<int>();
        foreach (var r in plan.References)
        {
            if (!seenData.Add(r.ContainerIndex))
                continue;
            if (dataByContainer.TryGetValue(r.ContainerIndex, out var db))
                dataChunks.Add(db);
        }

        // data_only: Ford da sibling empty-host pool.
        if (fordCiphers.Count == 0
            && dataChunks.Count > 0
            && siblingCompacts is { Count: > 0 }
            && FordMmcsDecryptor.TryCollectIkmOpenFordPool(fordIkm, siblingCompacts, out var pool)
            && FordMmcsDecryptor.TrySelectFordStoragesForRefCount(
                fordIkm, pool, plan.References.Count, out var selected))
        {
            fordCiphers = selected.ToList();
        }

        if (fordCiphers.Count == 0 || dataChunks.Count == 0)
        {
            log?.Report(
                $"  ERROR large {pathLabel}: ford={fordCiphers.Count} dataHosts={dataChunks.Count} " +
                $"(refs={plan.References.Count} dataMap={dataByContainer.Count}) — impossibile decrypt streaming");
            DecryptFailureJournal.Record(
                snapshotDirectory, asset, "mmcs_not_decrypted",
                $"large-asset resolve ford={fordCiphers.Count} data={dataChunks.Count}",
                new DecryptFailureDetails
                {
                    AuthSlice = authSlice,
                    Chunks = chunks,
                    AssemblyMode = "large-file-stream",
                });
            return AssetDownloadOutcome.Failed;
        }

        long? dataObjectStart = null;
        if (plan.References.Count > 0)
        {
            var ci = plan.References[0].ContainerIndex;
            if ((uint)ci < (uint)chunks.Count && chunks[ci].ByteRange is { } br)
                dataObjectStart = br.Start;
        }

        var objectId = chunks.Count > 0 ? ResolveObjectId(chunks[0]) : "large";
        var stagingPt = ResolveAssetStagingObjectPath(snapshotDirectory, asset, objectId)
                        + ".large_pt.bin";
        try
        {
            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "huge-stream-v1",
                    ["hypothesisId"] = "H-HUGE",
                    ["location"] = "BackupDownloadService.FinishLargeAssetFromMmcsCacheAsync",
                    ["message"] = "large_decrypt_begin",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        path = pathLabel,
                        sizeBytes = asset.SizeBytes,
                        downloaded,
                        fordN = fordCiphers.Count,
                        dataN = dataChunks.Count,
                        refs = plan.References.Count,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion

            log?.Report(
                $"  large-asset decrypt→file ({asset.SizeBytes:N0} B) {pathLabel}");
            await Task.Run(
                    () => FordMmcsDecryptor.DecryptAssetAlignedToFile(
                        fordIkm,
                        fordCiphers,
                        dataChunks,
                        authSlice,
                        stagingPt,
                        asset.SizeBytes,
                        dataObjectStart),
                    ct)
                .ConfigureAwait(false);

            var ptLen = new FileInfo(stagingPt).Length;
            var fileDecrypted = false;
            var outPath = stagingPt;

            // File-AES streaming se serve (CBC, IV zero — stesso di TryDecryptBackupFileBody).
            if (!fileKeyCtx.IsEmpty
                && asset.EncryptionKey is { Length: > 0 } encKey
                && asset.ProtectionClass is int pc
                && fileKeyCtx.TryUnwrapFileKey(encKey, pc, out var fileKey, out _, out _)
                && fileKey is { Length: > 0 })
            {
                var aesOut = stagingPt + ".aes";
                await Task.Run(() => DecryptBackupFileBodyToFile(stagingPt, aesOut, fileKey, asset.SizeBytes), ct)
                    .ConfigureAwait(false);
                try { File.Delete(stagingPt); } catch { /* ignore */ }
                outPath = aesOut;
                fileDecrypted = true;
                ptLen = new FileInfo(outPath).Length;
            }

            if (asset.SizeBytes is long expect && expect > 0 && ptLen != expect)
            {
                var delta = ptLen - expect;
                //  pad-trim 1..15 su body post-Ford, salva ciphertext — non ERROR.
                if (!fileDecrypted && delta is >= 1 and <= 15 && expect <= int.MaxValue)
                {
                    // Truncate file to assetSize (pad trim).
                    await Task.Run(() =>
                    {
                        using var fs = new FileStream(outPath, FileMode.Open, FileAccess.ReadWrite, FileShare.None);
                        fs.SetLength(expect);
                    }, ct).ConfigureAwait(false);
                    ptLen = expect;
                    // #region agent log
                    AgentFlEdgeDebugLog(
                        "BackupDownloadService.FinishLargeFlistAsset",
                        "parity_pad_trim_large",
                        new { path = pathLabel, fromDelta = delta, toLen = expect },
                        "H-IKE-TRIM");
                    // #endregion
                }
                else
                {
                log?.Report(
                    $"  ERROR {pathLabel}: size {ptLen} ≠ assetSize {expect} " +
                    "(large-asset post-edge)");
                DecryptFailureJournal.Record(
                    snapshotDirectory, asset, "size_mismatch",
                    $"body={ptLen} expected={expect}",
                    new DecryptFailureDetails
                    {
                        AuthSlice = authSlice,
                        Chunks = chunks,
                        AssemblyMode = "large-file-stream",
                        MmcsDecrypted = true,
                        FileDecrypted = fileDecrypted,
                        BodyLength = ptLen > int.MaxValue ? int.MaxValue : (int)ptLen,
                    });

                // Salva comunque il body (cifrato/incompleto) in Backup/ per retry PIN/keybag.
                var largeCipherWritten = false;
                var largeCipherStaged = false;
                try
                {
                    if (asset.HasFilesystemIdentity && File.Exists(outPath))
                    {
                        await fsWriter.WriteFileFromPathAsync(asset, outPath, ct).ConfigureAwait(false);
                        largeCipherWritten = true;
                        log?.Report(
                            $"  {pathLabel} → Backup/ CIFRATO/incompleto {ptLen:N0} B " +
                            $"(atteso {expect:N0}; salvato per retry PIN/keybag)");
                    }
                    else if (File.Exists(outPath))
                    {
                        var chunksDir = IkeBackupOutputPaths.ChunksStagingDirectory(outputRoot);
                        Directory.CreateDirectory(chunksDir);
                        var dest = Path.Combine(chunksDir, Path.GetFileName(outPath));
                        await Task.Run(() => File.Copy(outPath, dest, overwrite: true), ct)
                            .ConfigureAwait(false);
                        largeCipherStaged = true;
                    }
                }
                catch (Exception ex)
                {
                    log?.Report($"  WARN {pathLabel}: salva cifrato large fallito — {ex.Message}");
                }

                try { File.Delete(outPath); } catch { /* ignore */ }

                // #region agent log
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "cipher-save-v1",
                        ["hypothesisId"] = "H-CIPHER-SAVE",
                        ["location"] = "BackupDownloadService.FinishLargeAssetFromMmcsCacheAsync",
                        ["message"] = "cipher_saved_on_fail",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            path = pathLabel,
                            bodyLen = ptLen,
                            expect,
                            cipherWritten = largeCipherWritten,
                            cipherStaged = largeCipherStaged,
                        },
                    });
                    IkeLogOptions.AppendAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
                }
                catch { /* ignore */ }
                // #endregion

                return new AssetDownloadOutcome(
                    false, downloaded, largeCipherWritten, largeCipherStaged, true, fileDecrypted);
                } // else size_mismatch hard
            } // if ptLen != expect

            var writtenSharded = false;
            var staged = false;
            if (asset.HasFilesystemIdentity)
            {
                await fsWriter.WriteFileFromPathAsync(asset, outPath, ct).ConfigureAwait(false);
                writtenSharded = true;
                log?.Report(
                    $"  {pathLabel} → Backup/ (large-file-stream, {ptLen:N0} B)" +
                    (fileDecrypted ? " AES" : ""));
            }
            else
            {
                var chunksDir = IkeBackupOutputPaths.ChunksStagingDirectory(outputRoot);
                Directory.CreateDirectory(chunksDir);
                var dest = Path.Combine(chunksDir, Path.GetFileName(outPath));
                await Task.Run(() => File.Copy(outPath, dest, overwrite: true), ct)
                    .ConfigureAwait(false);
                staged = true;
                log?.Report($"  {asset.RecordName} → .chunks/ (large {ptLen:N0} B)");
            }

            try { File.Delete(outPath); } catch { /* ignore */ }

            mmcsSession.ReleaseDataChunksForAsset(chunks, authSlice);
            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "huge-stream-v1",
                    ["hypothesisId"] = "H-HUGE",
                    ["location"] = "BackupDownloadService.FinishLargeAssetFromMmcsCacheAsync",
                    ["message"] = "large_decrypt_ok",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        path = pathLabel,
                        ptLen,
                        writtenSharded,
                        fileDecrypted,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion

            return new AssetDownloadOutcome(
                true, downloaded, writtenSharded, staged, true, fileDecrypted);
        }
        catch (Exception ex)
        {
            log?.Report($"  ERROR large {pathLabel}: {ex.Message}");
            DecryptFailureJournal.Record(
                snapshotDirectory, asset, "batch_error", ex.Message,
                new DecryptFailureDetails
                {
                    AuthSlice = authSlice,
                    Chunks = chunks,
                    AssemblyMode = "large-file-stream",
                });
            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "huge-stream-v1",
                    ["hypothesisId"] = "H-HUGE",
                    ["location"] = "BackupDownloadService.FinishLargeAssetFromMmcsCacheAsync",
                    ["message"] = "large_decrypt_fail",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        path = pathLabel,
                        err = ex.Message.Length <= 200 ? ex.Message : ex.Message[..200],
                        type = ex.GetType().Name,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion
            return AssetDownloadOutcome.Failed;
        }
    }

    private static void DecryptBackupFileBodyToFile(
        string inputPath,
        string outputPath,
        byte[] fileKey,
        long? sizeBytes)
    {
        using var aes = System.Security.Cryptography.Aes.Create();
        aes.Key = fileKey.Length >= 16 ? fileKey.AsSpan(0, 16).ToArray() : fileKey;
        aes.Mode = System.Security.Cryptography.CipherMode.CBC;
        aes.Padding = System.Security.Cryptography.PaddingMode.None;
        aes.IV = new byte[16];
        using var input = new FileStream(inputPath, FileMode.Open, FileAccess.Read, FileShare.Read);
        using var output = new FileStream(outputPath, FileMode.Create, FileAccess.Write, FileShare.None);
        using var dec = aes.CreateDecryptor();
        using var crypto = new System.Security.Cryptography.CryptoStream(
            input, dec, System.Security.Cryptography.CryptoStreamMode.Read);
        var buf = new byte[1024 * 1024];
        long written = 0;
        var limit = sizeBytes is > 0 ? sizeBytes.Value : long.MaxValue;
        while (written < limit)
        {
            var toRead = (int)Math.Min(buf.Length, limit - written);
            var n = crypto.Read(buf, 0, toRead);
            if (n <= 0)
                break;
            output.Write(buf, 0, n);
            written += n;
        }
    }

    private async Task<AssetDownloadOutcome> FinishFlistAssetAfterAuthorizeAsync(
        ICloudSession session,
        BackupAsset asset,
        string snapshotDirectory,
        string outputRoot,
        BackupFilesystemWriter fsWriter,
        BackupFileKeyContext fileKeyCtx,
        byte[] authResponseBody,
        IReadOnlyList<SignedUrlChunk> chunks,
        int assetIndex,
        int assetTotal,
        IProgress<DownloadProgressReport>? progress,
        IProgress<string>? log,
        CancellationToken ct,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts = null,
        byte[]? prebuiltCompact = null,
        MmcsChunkAssemblySession? mmcsSession = null)
    {
        if (chunks.Count == 0)
            return AssetDownloadOutcome.Failed;

        // siblingCompacts = CChunkCache batch (globale). Materialize fa Read(ctLen) per host.

        var objectId = ResolveObjectId(chunks[0]);
        var stagingObj = ResolveAssetStagingObjectPath(snapshotDirectory, asset, objectId);

        // #region agent log
        AgentFlEdgeDebugLog(
            "BackupDownloadService.FinishFlistAssetAfterAuthorizeAsync",
            "staging_path",
            new
            {
                path = asset.RelativePath ?? asset.RecordName,
                stagingObj = Path.GetFileName(stagingObj),
                objectId,
                prebuilt = prebuiltCompact?.Length ?? 0,
            },
            "H-PIPE-LOCK",
            "post-fix");
        // #endregion

        // FillFord prep sul path flist: owned BackupAsset → contents wrap → IKM
        // PRIMA di decidere tryMmcs (altrimenti wrap/IKM post-fetch restano ignorati).
        await EnsureAssetWrapAndIkmAsync(session, asset, snapshotDirectory, log, ct)
            .ConfigureAwait(false);
        // Pipe C (FL): prova sempre MMCS/FillDecrypt. Senza wrap, type 0x01 non serve KEK;
        // ford-family spegne canMmcs in Assemble. type 0x02 richiede wrap/KEK risolto dopo.
        var tryMmcs = true;

        var result = await DownloadAssembleAssetAsync(
            session,
            asset,
            stagingObj,
            authResponseBody,
            chunks,
            assetIndex,
            assetTotal,
            progress,
            log,
            ct,
            tryMmcsDecrypt: tryMmcs,
            workDirectory: snapshotDirectory,
            siblingCompacts: siblingCompacts,
            prebuiltCompact: prebuiltCompact)
            .ConfigureAwait(false);

        // Solo plaintext MMCS decryptato . Mai prebuiltCompact come “body” asset.
        byte[]? ramBytes = result.MmcsDecrypted && result.Body is { Length: > 0 }
            ? result.Body
            : null;
        if (ramBytes is not { Length: > 0 })
        {
            // H-ORDER: Ford CT not ready yet — not a hard fail; retry on Put recover.
            if (result.AssemblyMode is "ike-ford-deferred")
            {
                log?.Report(
                    $"  PENDING Ford {asset.RelativePath ?? asset.RecordName}: " +
                    "CT owned deferred (H-ORDER)");
                return AssetDownloadOutcome.Pending;
            }

            var why = !result.MmcsDecrypted
                ? (result.AssemblyMode ?? "ike-decrypt-fail")
                : "body assente dopo decrypt";
            log?.Report(
                $"  ERROR {asset.RelativePath ?? asset.RecordName}: {why}" +
                (result.PlanSummary is { Length: > 0 } ? $" ({result.PlanSummary})" : ""));
            // #region agent log
            AgentCountAlways("finish_no_plaintext", new
            {
                path = asset.RelativePath ?? asset.RecordName,
                mmcs = result.MmcsDecrypted,
                mode = result.AssemblyMode,
                bodyLen = result.Body?.Length ?? 0,
                prebuilt = prebuiltCompact?.Length ?? 0,
                runId = "ike-faithful-v1",
                hypothesis = "H-IKE-NO-CT-AS-FILE",
            });
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "4ff690",
                    ["runId"] = "fail-count-v1",
                    ["hypothesisId"] = "H-FAIL-UI",
                    ["location"] = "BackupDownloadService.FinishFlistAssetAfterAuthorizeAsync",
                    ["message"] = "finish_no_plaintext",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        path = asset.RelativePath ?? asset.RecordName,
                        mode = result.AssemblyMode,
                        plan = result.PlanSummary,
                        downloaded = Volatile.Read(ref _uiFilesDownloaded),
                        decrypted = Volatile.Read(ref _uiFilesDecrypted),
                        failed = Volatile.Read(ref _uiFilesDecryptFailed),
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\AIAgent\debug-4ff690.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            DecryptFailureJournal.Record(
                snapshotDirectory,
                asset,
                "mmcs_not_decrypted",
                $"{result.AssemblyMode}; {result.PlanSummary}",
                new DecryptFailureDetails
                {
                    AuthSlice = authResponseBody,
                    Chunks = chunks,
                    ObjectId = objectId,
                    CompactLength = prebuiltCompact?.Length ?? 0,
                    AssemblyMode = result.AssemblyMode,
                    MmcsDecrypted = false,
                });
            return AssetDownloadOutcome.Failed;
        }

        var edgeCipher = ramBytes;
        // #region agent log
        AgentCountAlways("finish_ram_body", new
        {
            path = asset.RelativePath ?? asset.RecordName,
            fromBody = result.Body?.Length ?? 0,
            fromPrebuilt = prebuiltCompact?.Length ?? 0,
            used = edgeCipher.Length,
            hypothesis = "H-OBJ-RAM",
        });
        // #endregion

        byte[]? authRequest = null;
        if (asset.AssetSignature is { Length: 21 } sig
            && MmcsAuthBuilder.TryBuildFlistAuthorizeEntry(sig, asset.MmcsAuth) is { } entry)
            authRequest = UbChunkBuilder.BuildAuthorizeGetRequest([entry]);

        EnsureAssetWrapAndIkm(session, asset, snapshotDirectory, log);

        await FordOfflineDumpWriter.DumpEdgePackageAsync(
            snapshotDirectory,
            asset,
            authRequest,
            authResponseBody,
            objectId,
            edgeCipher,
            ct).ConfigureAwait(false);

        var cipherBody = edgeCipher;
        var (body, fileDecrypted, lzfseExpanded, preLzfseLen) = await Task.Run(() =>
        {
            var plain = TryDecryptBackupFileBody(
                asset, cipherBody, fileKeyCtx, log, out var fd);
            var (expanded, lzfse, preLen) = BackupAssetDecryptPipeline.ApplyLzfse(plain);
            return (expanded, fd, lzfse, preLen);
        }, ct).ConfigureAwait(false);

        // DA CONFERMARE A RUNTIME: compressionMethod != 0 → decompress post-decrypt.
        if (asset.CompressionMethod is > 0 and not 2 /* LZFSE already tried */)
        {
            log?.Report(
                $"  {asset.RelativePath}: compressionMethod={asset.CompressionMethod} " +
                "(DA CONFERMARE decompress)");
        }

        // sizeBytes CloudKit = spesso post-Ford pre-LZFSE (bvx*); dopo LZFSE il body è più grande.
        // (live x64dbg + output): su Backup moderno NON applica file-AES class-key;
        // dopo Ford trimma solo body→assetSize (pad δ 1..15) e salva ancora ciphertext.
        var sizeMismatchHardFail = false;
        var mmcsHardFail = !result.MmcsDecrypted;
        if (asset.SizeBytes is long expect
            && body.Length != expect
            && !(lzfseExpanded && preLzfseLen == expect))
        {
            var pendingFileAes = !fileDecrypted
                                 && asset.EncryptionKey is { Length: > 0 }
                                 && asset.ProtectionClass is not null;
            var delta = body.Length - expect;
            // Solo post-Ford (MmcsDecrypted): stesso caso Cat.B pad-trim.
            var padTrim = result.MmcsDecrypted
                             && !fileDecrypted
                             && expect > 0
                             && expect <= int.MaxValue
                             && delta is >= 1 and <= 15;
            // #region agent log
            AgentFlEdgeDebugLog(
                "BackupDownloadService.FinishFlistAssetAfterAuthorizeAsync",
                padTrim ? "parity_pad_trim" : "size_mismatch",
                new
                {
                    path = asset.RelativePath ?? asset.RecordName,
                    bodyLen = body.Length,
                    expect,
                    delta,
                    mmcsDecrypted = result.MmcsDecrypted,
                    assemblyMode = result.AssemblyMode,
                    fileDecrypted,
                    pendingFileAes,
                    padTrim,
                    lzfseExpanded,
                    preLzfseLen,
                    protectionClass = asset.ProtectionClass,
                    ekLen = asset.EncryptionKey?.Length ?? 0,
                    planSummary = result.PlanSummary,
                    dataChunkCredit = SumAssetDataChunkBytes(authResponseBody, chunks),
                },
                padTrim ? "H-IKE-TRIM"
                    : result.MmcsDecrypted && !fileDecrypted && asset.EncryptionKey is { Length: > 0 }
                        ? "H2"
                        : !result.MmcsDecrypted ? "H1" : "H3");
            // #endregion
            if (padTrim)
            {
                body = body.AsSpan(0, (int)expect).ToArray();
                // #region agent log
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "BackupDownloadService.FinishFlistAssetAfterAuthorizeAsync",
                        ["message"] = "parity_pad_trim_applied",
                        ["hypothesisId"] = "H-IKE-TRIM",
                        ["runId"] = "ike-pad-trim-v2",
                        ["data"] = new
                        {
                            path = asset.RelativePath ?? asset.RecordName,
                            fromLen = (int)expect + (int)delta,
                            toLen = (int)expect,
                            delta,
                            protectionClass = asset.ProtectionClass,
                            stillCipher = true,
                        },
                    });
                    IkeLogOptions.AppendAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
                }
                catch { /* ignore */ }
                // #endregion
            }
            else if (pendingFileAes && delta is >= 1 and <= 15 && expect <= int.MaxValue)
            {
                //  stesso pad — trim + save cipher, no ERROR.
                body = body.AsSpan(0, (int)expect).ToArray();
            }
            else if (pendingFileAes)
            {
                // non fa file-AES: non WARN come se fosse un buco Ford.
                // #region agent log
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.FinishFlistAssetAfterAuthorizeAsync",
                    "skip_file_aes_keep_cipher",
                    new
                    {
                        path = asset.RelativePath ?? asset.RecordName,
                        bodyLen = body.Length,
                        expect,
                        delta,
                    },
                    "H-IKE-TRIM");
                // #endregion
            }
            else
            {
                // #region agent log
                AgentCountAlways("size_mismatch_hard", new
                {
                    path = asset.RelativePath ?? asset.RecordName,
                    record = asset.RecordName,
                    bodyLen = body.Length,
                    bodySha16 = body.Length > 0
                        ? Convert.ToHexString(
                            System.Security.Cryptography.SHA256.HashData(body).AsSpan(0, 8))
                        : null,
                    expect,
                    delta,
                    mmcs = result.MmcsDecrypted,
                    fileAes = fileDecrypted,
                    assembly = result.AssemblyMode,
                    mode = result.AssemblyMode,
                    plan = result.PlanSummary,
                    protectionClass = asset.ProtectionClass,
                    ratio = expect > 0 ? Math.Round(body.Length / (double)expect, 2) : 0,
                    hypothesis = "H-SIZE-IKE",
                    runId = "demux-fail-v1",
                });
                // #endregion
                log?.Report(
                    $"  ERROR {asset.RelativePath}: size {body.Length} ≠ assetSize {expect} " +
                    "(post-edge; decrypt/compress incompleto)");
                sizeMismatchHardFail = true;
            }
        }

        // mmcs_not_decrypted / size 0 (o mismatch) → Falliti, non Decifrati.
        // Se c'è body (cipher MMCS/edge o plain incompleto), materializza comunque in Backup/
        // per retry offline (PIN/keybag/Ford) — non lasciare il download perso.
        if (mmcsHardFail || sizeMismatchHardFail || (asset.SizeBytes is > 0 && body.Length == 0))
        {
            LogDecryptOutcomeIfNeeded(
                snapshotDirectory,
                asset,
                authResponseBody,
                chunks,
                objectId,
                stagingObj,
                result,
                body,
                fileDecrypted,
                asset.SizeBytes,
                lzfseExpanded,
                preLzfseLen);

            var cipherWritten = false;
            var cipherStaged = false;
            if (body.Length > 0)
            {
                try
                {
                    if (asset.HasFilesystemIdentity)
                    {
                        var path = await fsWriter.WriteFileAsync(asset, body, ct).ConfigureAwait(false);
                        cipherWritten = true;
                        log?.Report(
                            $"  {asset.RelativePath ?? asset.RecordName} → " +
                            $"{Path.GetRelativePath(snapshotDirectory, path)} " +
                            $"CIFRATO/incompleto {body.Length:N0} B " +
                            $"(atteso {asset.SizeBytes?.ToString("N0") ?? "?"}; " +
                            $"pc={asset.ProtectionClass?.ToString() ?? "?"}; " +
                            "salvato per retry PIN/keybag)");
                    }
                    else
                    {
                        var stagedPath = await BackupFilesystemWriter.WriteChunkStagingAsync(
                            outputRoot, asset, body, ct).ConfigureAwait(false);
                        cipherStaged = true;
                        log?.Report(
                            $"  {asset.RecordName} → .chunks/{Path.GetFileName(stagedPath)} " +
                            $"CIFRATO/incompleto {body.Length:N0} B " +
                            $"(pc={asset.ProtectionClass?.ToString() ?? "?"})");
                    }
                }
                catch (Exception ex)
                {
                    log?.Report(
                        $"  WARN {asset.RelativePath ?? asset.RecordName}: " +
                        $"salva cifrato fallito — {ex.Message}");
                }
            }

            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "cipher-pc-measure-v1",
                    ["hypothesisId"] = "H-PC-CLAIM",
                    ["location"] = "BackupDownloadService.FinishFlistAssetAfterAuthorizeAsync",
                    ["message"] = "cipher_saved_on_fail",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        path = asset.RelativePath ?? asset.RecordName,
                        bodyLen = body.Length,
                        expect = asset.SizeBytes,
                        mmcs = result.MmcsDecrypted,
                        mode = result.AssemblyMode,
                        mmcsHardFail,
                        sizeMismatchHardFail,
                        protectionClass = asset.ProtectionClass,
                        ekLen = asset.EncryptionKey?.Length ?? 0,
                        cipherWritten,
                        cipherStaged,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion

            return new AssetDownloadOutcome(
                Ok: false,
                DownloadedBytes: ResolveUiProgressCreditBytes(
                    asset, authResponseBody, chunks, result.DownloadedBytes, body.Length),
                WrittenSharded: cipherWritten,
                StagedChunks: cipherStaged,
                MmcsDecrypted: result.MmcsDecrypted,
                FileDecrypted: fileDecrypted);
        }

        // OBJ_* plaintext: solo con dump edge (IKE_DUMP_EDGE). Pipeline normale → Backup/ da RAM.
        if (IkeDiskDumpOptions.DumpEdgeSidecars && (fileDecrypted || lzfseExpanded))
            await File.WriteAllBytesAsync(stagingObj, body, ct).ConfigureAwait(false);

        // FL: materializza flist_*.db (SQLite) — richiesto dal loop interleaved
        // (ResolveFlistDbPath → BuildBatchFromDb). Senza questo → "flist DB assente".
        var isFileList = asset.RecordName.StartsWith("FL:", StringComparison.Ordinal);
        var looksSqlite = isFileList && FileListSqliteParser.LooksLikeSqlite(body);
        // #region agent log
        if (isFileList)
        {
            try
            {
                var head = Convert.ToHexString(body.AsSpan(0, Math.Min(16, body.Length)));
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "BackupDownloadService.FinishFlistAssetAfterAuthorizeAsync",
                    ["message"] = "fl_materialize_check",
                    ["hypothesisId"] = "H-FLDB",
                    ["runId"] = "post-fix",
                    ["data"] = new
                    {
                        record = asset.RecordName,
                        bodyLen = body.Length,
                        looksSqlite,
                        mmcs = result.MmcsDecrypted,
                        fileAes = fileDecrypted,
                        lzfse = lzfseExpanded,
                        head16 = head,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
        }
        // #endregion
        if (looksSqlite)
        {
            await MaterializeFileListDbAsync(snapshotDirectory, asset, body, log, ct)
                .ConfigureAwait(false);
        }
        else if (isFileList)
        {
            log?.Report(
                $"  {asset.RecordName}: MMCS={(result.MmcsDecrypted ? "OK" : "no")} " +
                $"ma body non SQLite dopo decrypt " +
                $"(lzfse={lzfseExpanded}, len={body.Length:N0}, " +
                $"head={Convert.ToHexString(body.AsSpan(0, Math.Min(8, body.Length)))})");
        }

        var writtenSharded = false;
        var staged = false;
        if (asset.HasFilesystemIdentity)
        {
            var path = await fsWriter.WriteFileAsync(asset, body, ct).ConfigureAwait(false);
            writtenSharded = true;
            log?.Report(
                $"  {asset.RelativePath ?? asset.RecordName} → " +
                $"{Path.GetRelativePath(snapshotDirectory, path)} " +
                $"edge={chunks.Count} {result.PlanSummary}" +
                (result.MmcsDecrypted ? " MMCS" : "") +
                (fileDecrypted ? " AES" : "") +
                (lzfseExpanded ? " LZFSE" : "") +
                $" (+{result.DownloadedBytes:N0} B)");
        }
        else
        {
            var stagedPath = await BackupFilesystemWriter.WriteChunkStagingAsync(
                outputRoot, asset, body, ct).ConfigureAwait(false);
            staged = true;
                log?.Report(
                $"  {asset.RecordName} → .chunks/{Path.GetFileName(stagedPath)} " +
                $"(+{result.DownloadedBytes:N0} B)");
        }

        LogDecryptOutcomeIfNeeded(
            snapshotDirectory,
            asset,
            authResponseBody,
            chunks,
            objectId,
            stagingObj,
            result,
            body,
            fileDecrypted,
            asset.SizeBytes,
            lzfseExpanded,
            preLzfseLen);

        mmcsSession ??= _mmcsChunkSession;
        if (result.MmcsDecrypted || fileDecrypted || lzfseExpanded)
        {
            var released = mmcsSession?.ReleaseDataChunksForAsset(chunks, authResponseBody) ?? 0;
            // #region agent log
            AgentCountAlways("post_write_release", new
            {
                path = asset.RelativePath ?? asset.RecordName,
                released,
                writtenSharded,
                bodyMb = body.Length / (1024 * 1024),
                prebuiltMb = (prebuiltCompact?.Length ?? 0) / (1024 * 1024),
                storeApproxMb = mmcsSession?.Store.ApproximateBytes / (1024 * 1024) ?? -1,
                pendingFiles = mmcsSession?.PendingCount ?? -1,
                hypothesis = "H-RAM-POST",
            });
            // #endregion
            if (released > 0)
            {
                log?.Report(
                    $"  mmcs_cache: rilasciati {released} chunk dati dopo decrypt " +
                    $"{asset.RelativePath ?? asset.RecordName}");
            }
        }

        // #region agent log
        try
        {
            var credit = ResolveUiProgressCreditBytes(
                asset, authResponseBody, chunks, result.DownloadedBytes, body.Length);
            var dataChunks = SumAssetDataChunkBytes(authResponseBody, chunks);
            // Log quando compact/SizeBytes divergono dal credito data-chunk (diagnostica UI).
            if ((result.DownloadedBytes > 0 && credit > 0
                 && (result.DownloadedBytes > credit * 2
                     || (asset.SizeBytes is long sz && sz > 0
                         && Math.Abs(sz - credit) > Math.Max(4096, credit / 10))))
                || (dataChunks > 0 && Interlocked.Increment(ref _bytesCreditSampleN) <= 40))
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "bytes-data-v1",
                    ["hypothesisId"] = "H-BYTES-DATA",
                    ["location"] = "BackupDownloadService.FinishFlistAssetAfterAuthorizeAsync",
                    ["message"] = "progress_credit_data_chunks",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        path = asset.RelativePath ?? asset.RecordName,
                        mmcsCompact = result.DownloadedBytes,
                        bodyLen = body.Length,
                        sizeBytes = asset.SizeBytes,
                        dataChunkBytes = dataChunks,
                        credit,
                        writtenSharded,
                        mmcsOk = result.MmcsDecrypted,
                        protectionClass = asset.ProtectionClass,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line + Environment.NewLine);
            }
        }
        catch { /* ignore */ }
        // #endregion

        return new AssetDownloadOutcome(
            true,
            ResolveUiProgressCreditBytes(
                asset, authResponseBody, chunks, result.DownloadedBytes, body.Length),
            writtenSharded,
            staged,
            result.MmcsDecrypted,
            fileDecrypted);
    }

    private static void LogDecryptOutcomeIfNeeded(
        string snapshotDirectory,
        BackupAsset asset,
        byte[] authSlice,
        IReadOnlyList<SignedUrlChunk> chunks,
        string objectId,
        string stagingObj,
        AssembleResult result,
        byte[] body,
        bool fileDecrypted,
        long? expectedSize,
        bool lzfseExpanded = false,
        int preLzfseLength = -1)
    {
        if (string.IsNullOrWhiteSpace(snapshotDirectory))
            return;

        var details = new DecryptFailureDetails
        {
            ObjectId = objectId,
            StagingObjectPath = stagingObj,
            AuthSlice = authSlice,
            Chunks = chunks,
            AssemblyMode = result.AssemblyMode,
            MmcsDecrypted = result.MmcsDecrypted,
            FileDecrypted = fileDecrypted,
            BodyLength = body.Length,
        };

        if (!result.MmcsDecrypted)
        {
            DecryptFailureJournal.Record(
                snapshotDirectory,
                asset,
                "mmcs_not_decrypted",
                $"{result.AssemblyMode}; {result.PlanSummary}",
                details);
            // #region agent log
            AgentBkFailLog(
                "H-PC-CLAIM",
                "BackupDownloadService.LogDecryptOutcomeIfNeeded",
                "mmcs_not_decrypted",
                new
                {
                    record = asset.RecordName,
                    path = asset.RelativePath,
                    mode = result.AssemblyMode,
                    plan = ClipBk(result.PlanSummary, 120),
                    hasWrap = !string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex),
                    hasIkm = asset.AssetUnwrappedKey is { Length: 16 or 32 },
                    wrapLen = TryWrapLen(asset.AssetProtectionInfoHex),
                    bodyLen = body.Length,
                    sizeBytes = asset.SizeBytes,
                    protectionClass = asset.ProtectionClass,
                    ekLen = asset.EncryptionKey?.Length ?? 0,
                });
            // #endregion
        }

        // Non duplicare size_mismatch se MMCS è già fallito (stesso file → 2 righe journal,
        // 1 Falliti UI: sembra «manca un errore» in Errori).
        if (result.MmcsDecrypted
            && expectedSize is long expect && expect > 0 && body.Length != expect)
        {
            // sizeBytes CK è spesso la lunghezza post-Ford / pre-LZFSE (magic bvx*).
            // Dopo LZFSE il file in Backup è il cleartext espanso — non è un decrypt fallito.
            var lzfseExplains =
                lzfseExpanded && preLzfseLength == expect;
            if (!lzfseExplains)
            {
                DecryptFailureJournal.Record(
                    snapshotDirectory,
                    asset,
                    "size_mismatch",
                    $"body={body.Length} expected={expect}",
                    details);
                // #region agent log
                AgentBkFailLog(
                    "H-BK5",
                    "BackupDownloadService.LogDecryptOutcomeIfNeeded",
                    "size_mismatch",
                    new
                    {
                        record = asset.RecordName,
                        path = asset.RelativePath,
                        bodyLen = body.Length,
                        expected = expect,
                        lzfseExpanded,
                        preLzfseLength,
                        mmcsOk = result.MmcsDecrypted,
                        fileOk = fileDecrypted,
                    });
                // #endregion
            }
        }

        // modern Backup: class-key file-AES = dead (GCUK/PrepDecryptV4 = 0 hits).
        // Post-Ford body resta ciphertext; pad-trim δ1..15 = successo, non "file_aes fail".
        if (result.MmcsDecrypted
            && !fileDecrypted && asset.EncryptionKey is { Length: > 0 })
        {
            // #region agent log
            AgentBkFailLog(
                "H-IKE-TRIM",
                "BackupDownloadService.LogDecryptOutcomeIfNeeded",
                "skip_file_aes_no_journal",
                new
                {
                    record = asset.RecordName,
                    path = asset.RelativePath,
                    protectionClass = asset.ProtectionClass,
                    ekLen = asset.EncryptionKey.Length,
                    bodyLen = body.Length,
                    sizeBytes = expectedSize,
                    runId = "ike-pad-trim-v2",
                });
            // #endregion
            // Non DecryptFailureJournal — allineati a (salva cipher, no class-key AES).
        }
    }

    private async Task RecordSkippedCryptoAsync(
        ICloudSession session,
        BackupAsset asset,
        string snapshotDirectory,
        byte[] authSlice,
        IReadOnlyList<SignedUrlChunk> chunks,
        string stage,
        string reason,
        IProgress<string>? log,
        CancellationToken ct)
    {
        await TryDumpFailureOfflinePackageAsync(
            session, asset, snapshotDirectory, authSlice, chunks, log, ct).ConfigureAwait(false);

        var oid = chunks.Count > 0 ? ResolveObjectId(chunks[0]) : string.Empty;
        var stagingObj = string.IsNullOrEmpty(oid)
            ? null
            : Path.Combine(snapshotDirectory, "OBJ_" + SanitizeFileName(oid) + ".bin");

        DecryptFailureJournal.Record(
            snapshotDirectory,
            asset,
            stage,
            reason,
            new DecryptFailureDetails
            {
                ObjectId = oid,
                StagingObjectPath = stagingObj,
                AuthSlice = authSlice,
                Chunks = chunks,
            });

        log?.Report(
            $"  ERROR decrypt_failures +1 ({stage}) {asset.RelativePath ?? asset.RecordName} — {reason}");
    }

    private async Task TryDumpFailureOfflinePackageAsync(
        ICloudSession session,
        BackupAsset asset,
        string snapshotDirectory,
        byte[] authSlice,
        IReadOnlyList<SignedUrlChunk> chunks,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (chunks.Count == 0 || string.IsNullOrWhiteSpace(snapshotDirectory))
            return;

        try
        {
            var objectId = ResolveObjectId(chunks[0]);
            var stagingObj = ResolveAssetStagingObjectPath(snapshotDirectory, asset, objectId);
            byte[]? edgeCipher = null;
            var compactSide = stagingObj + ".edge_compact.bin";
            if (File.Exists(compactSide))
                edgeCipher = await File.ReadAllBytesAsync(compactSide, ct).ConfigureAwait(false);
            else if (File.Exists(stagingObj))
                edgeCipher = await File.ReadAllBytesAsync(stagingObj, ct).ConfigureAwait(false);

            if (edgeCipher is not { Length: > 0 })
                return;

            await Task.Run(
                    () => EnsureAssetWrapAndIkm(session, asset, snapshotDirectory, log),
                    ct)
                .ConfigureAwait(false);

            byte[]? authRequest = null;
            if (asset.AssetSignature is { Length: 21 } sig
                && MmcsAuthBuilder.TryBuildFlistAuthorizeEntry(sig, asset.MmcsAuth) is { } entry)
                authRequest = UbChunkBuilder.BuildAuthorizeGetRequest([entry]);

            await FordOfflineDumpWriter.DumpEdgePackageAsync(
                snapshotDirectory,
                asset,
                authRequest,
                authSlice,
                objectId,
                edgeCipher,
                ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log?.Report($"  decrypt_failures: dump offline skip — {ex.Message}");
        }
    }

    private async Task<byte[]> AuthorizeGetBatchAsync(
        ICloudSession session,
        string contentHost,
        IReadOnlyList<UbChunkBuilder.AuthorizeGetFileEntry> entries,
        string? zoneName,
        CancellationToken ct,
        string? debugRecord = null,
        bool debugIsFileList = false)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("authorizeGet: manca session.Dsid.");
        if (entries.Count == 0)
            throw new ArgumentException("Batch authorizeGet vuoto.", nameof(entries));

        var mmcsAuth = UbChunkBuilder.BuildMmcsAuthHeader(entries[0]);
        var body = UbChunkBuilder.BuildAuthorizeGetRequest(entries);
        var url = $"{contentHost}/{session.Dsid}/authorizeGet";

        Exception? last401 = null;
        for (var attempt = 0; attempt < 4; attempt++)
        {
            using var request = new HttpRequestMessage(HttpMethod.Post, url);
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType =
                new MediaTypeHeaderValue("application/vnd.com.apple.me.ubchunk+protobuf");
            request.Headers.TryAddWithoutValidation(
                "Accept", "application/vnd.com.apple.me.ubchunk+protobuf");
            request.Headers.TryAddWithoutValidation("x-apple-mme-dsid", session.Dsid);
            request.Headers.TryAddWithoutValidation("x-apple-mmcs-proto-version", "4.0");
            request.Headers.TryAddWithoutValidation(
                "x-apple-mmcs-dataclass", "com.apple.Dataclass.CloudKit");
            request.Headers.TryAddWithoutValidation("X-CloudKit-Container", "com.apple.backup.ios");
            request.Headers.TryAddWithoutValidation(
                "X-CloudKit-Zones",
                string.IsNullOrWhiteSpace(zoneName) ? "_defaultZone" : zoneName);
            request.Headers.TryAddWithoutValidation("x-apple-mmcs-auth", mmcsAuth);
            request.Headers.TryAddWithoutValidation(
                "X-MMe-Client-Info", AppleClientInfo.CloudKitDaemonClientInfo);
            request.Headers.TryAddWithoutValidation(
                "User-Agent", AppleClientInfo.MmcsUserAgent);
            session.Anisette.TouchClientTimeUtc();
            request.Headers.TryAddWithoutValidation("X-Apple-I-Client-Time", session.Anisette.ClientTimeUtc);

            HttpResponseMessage response;
            byte[] responseBody;
            try
            {
                response = await _http.SendAsync(
                        request, HttpCompletionOption.ResponseHeadersRead, ct)
                    .ConfigureAwait(false);
                responseBody = await response.Content.ReadAsByteArrayAsync(ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex) when (IsTransientEdgeTransport(ex) && attempt < 3)
            {
                // #region agent log
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.AuthorizeGetBatchAsync",
                    "authorize_get_io_retry",
                    new
                    {
                        record = debugRecord,
                        isFileList = debugIsFileList,
                        attempt = attempt + 1,
                        entryCount = entries.Count,
                        zone = zoneName,
                        err = ex.GetType().Name,
                        msg = ex.Message,
                        inner = ex.InnerException?.Message,
                    },
                    "H-EDGE-IO");
                // #endregion
                await Task.Delay(Math.Min(8_000, 500 * (1 << attempt)), ct).ConfigureAwait(false);
                continue;
            }

            using (response)
            {
                if (response.IsSuccessStatusCode)
                {
                    // #region agent log
                    if (debugIsFileList)
                    {
                        AgentFlEdgeDebugLog(
                            "BackupDownloadService.AuthorizeGetBatchAsync",
                            "authorize_get_ok",
                            new
                            {
                                record = debugRecord,
                                isFileList = true,
                                status = (int)response.StatusCode,
                                bodyLen = responseBody.Length,
                                attempt = attempt + 1,
                                entryCount = entries.Count,
                                zone = zoneName,
                            },
                            "H-AUTH-OK");
                    }
                    // #endregion
                    return responseBody;
                }

                var status = (int)response.StatusCode;
                if (status == 401 && _refreshSession is not null && attempt < 3)
                {
                    last401 = new InvalidOperationException(
                        $"authorizeGet HTTP 401 ({responseBody.Length} B)");
                    // #region agent log
                    AgentFlEdgeDebugLog(
                        "BackupDownloadService.AuthorizeGetBatchAsync",
                        "authorize_get_401_retry",
                        new
                        {
                            record = debugRecord,
                            isFileList = debugIsFileList,
                            status,
                            bodyLen = responseBody.Length,
                            attempt = attempt + 1,
                            entryCount = entries.Count,
                            zone = zoneName,
                            host = contentHost,
                        },
                        "H-AUTH-401");
                    // #endregion
                    await _refreshSession(session, null, ct, forceRemint: true).ConfigureAwait(false);
                    _assets.ClearGatewayUnauthorized();
                    await Task.Delay(1500 * (attempt + 1), ct).ConfigureAwait(false);
                    continue;
                }

                if (status is 503 or 502 or 429 && attempt < 3)
                {
                    // #region agent log
                    AgentFlEdgeDebugLog(
                        "BackupDownloadService.AuthorizeGetBatchAsync",
                        "authorize_get_503_retry",
                        new
                        {
                            record = debugRecord,
                            isFileList = debugIsFileList,
                            status,
                            bodyLen = responseBody.Length,
                            attempt = attempt + 1,
                            entryCount = entries.Count,
                            zone = zoneName,
                            host = contentHost,
                        },
                        "H-AUTH-503");
                    // #endregion
                    await Task.Delay(2000 * (attempt + 1), ct).ConfigureAwait(false);
                    continue;
                }

                // #region agent log
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.AuthorizeGetBatchAsync",
                    "authorize_get_fail",
                    new
                    {
                        record = debugRecord,
                        isFileList = debugIsFileList,
                        status,
                        bodyLen = responseBody.Length,
                        attempt = attempt + 1,
                        entryCount = entries.Count,
                        zone = zoneName,
                        host = contentHost,
                        bodyHead = responseBody.Length > 0
                            ? Convert.ToHexString(responseBody.AsSpan(0, Math.Min(32, responseBody.Length)))
                            : null,
                    },
                    status == 503 ? "H-AUTH-503" : status == 401 ? "H-AUTH-401" : "H-AUTH-ERR");
                // #endregion
                throw new InvalidOperationException(
                    $"authorizeGet HTTP {status} ({responseBody.Length} B)");
            }
        }

        // #region agent log
        AgentFlEdgeDebugLog(
            "BackupDownloadService.AuthorizeGetBatchAsync",
            "authorize_get_401_exhausted",
            new
            {
                record = debugRecord,
                isFileList = debugIsFileList,
                attempts = 4,
                entryCount = entries.Count,
                zone = zoneName,
                host = contentHost,
            },
            "H-AUTH-401");
        // #endregion
        throw last401 ?? new InvalidOperationException("authorizeGet HTTP 401");
    }

    /// <summary>
    /// Token base64 in <c>uuid:token=:size</c> (tra il primo <c>:</c> dopo l'UUID e <c>=:</c>).
    /// </summary>
    private static string? TryExtractRidToken(string? rid) =>
        CloudKitMmcsIds.TryExtractRidToken(rid);

    private static bool HasUsableMmcsAuth(string? mmcsAuth) =>
        !string.IsNullOrWhiteSpace(mmcsAuth)
        && mmcsAuth.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length >= 3;

    private static bool RecordNamesMatch(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b))
            return false;
        if (string.Equals(a, b, StringComparison.OrdinalIgnoreCase))
            return true;
        foreach (var ca in MmcsAuthBuilder.RecordNameLookupCandidates(a))
        {
            foreach (var cb in MmcsAuthBuilder.RecordNameLookupCandidates(b))
            {
                if (string.Equals(ca, cb, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        var sa = CloudKitMmcsIds.ToRecordIdSuffix(a);
        var sb = CloudKitMmcsIds.ToRecordIdSuffix(b);
        return sa is { Length: >= 32 } && sb is { Length: >= 32 }
               && string.Equals(sa, sb, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// True se la finestra CK appartiene a questo asset.
    /// Con rid flist <c>uuid:token=:size</c> richiede token/rid pieno — UUID solo
    /// collide (flist Numbers: 12 Assets con stesso UUID 023F34AE, token diversi;
    /// recordKey = <c>A:zone:uuid:token:size</c>).
    /// </summary>
    private static bool AssetRecordWindowBelongsTo(BackupAsset asset, byte[]? window)
        => RecordWindowBelongsTo(window, asset.RecordName, asset.RecordIdSuffix);

    /// <summary>
    /// True se la finestra CK contiene il recordName / rid. Evita RP alieni
    /// tipo AuthKit←3924430F (ike_run rp_4506/4507 identici).
    /// </summary>
    private static bool RecordWindowBelongsTo(
        byte[]? window,
        string? recordName,
        string? recordIdSuffix = null)
    {
        if (window is not { Length: > 32 })
            return false;

        // Full rid (uuid:token=:size): match token/rid — never UUID-only.
        var fullRid = !string.IsNullOrWhiteSpace(recordIdSuffix)
            ? recordIdSuffix.Trim()
            : null;
        if (fullRid is null
            && !string.IsNullOrWhiteSpace(recordName)
            && CloudKitMmcsIds.ToRecordIdSuffix(recordName) is { } fromName
            && TryExtractRidToken(fromName) is not null)
            fullRid = fromName;

        if (fullRid is not null && TryExtractRidToken(fullRid) is { Length: > 0 } token)
        {
            var fullBytes = Encoding.UTF8.GetBytes(fullRid);
            if (window.AsSpan().IndexOf(fullBytes) >= 0)
                return true;
            if (token.Length >= 8)
            {
                var tokenBytes = Encoding.UTF8.GetBytes(token);
                if (window.AsSpan().IndexOf(tokenBytes) >= 0)
                    return true;
            }

            return false;
        }

        if (string.IsNullOrWhiteSpace(recordName))
            return false;

        foreach (var cand in MmcsAuthBuilder.RecordNameLookupCandidates(recordName))
        {
            if (cand.Length < 8)
                continue;
            var nb = Encoding.UTF8.GetBytes(cand);
            if (window.AsSpan().IndexOf(nb) >= 0)
                return true;
        }

        var rid = CloudKitMmcsIds.ToRecordIdSuffix(recordName);
        if (rid is { Length: >= 32 })
        {
            var rb = Encoding.UTF8.GetBytes(rid);
            if (window.AsSpan().IndexOf(rb) >= 0)
                return true;
        }

        return false;
    }

    private async Task<byte[]> AuthorizeGetAsync(
        ICloudSession session,
        string contentHost,
        BackupAsset asset,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("authorizeGet: manca session.Dsid.");

        // Post-fileList  f1 = Assets.assetSignature verbatim (0x04‖20B).
        // Mai usare CK mmcs-auth part0 (0x01) come f1 quando la signature flist c'è.
        if (asset.AssetSignature is { Length: 21 } flSig)
        {
            if (MmcsAuthBuilder.TryBuildFlistAuthorizeEntry(flSig, asset.MmcsAuth)
                is not { } flistEntry)
            {
                throw new InvalidOperationException(
                    "authorizeGet flist: MmcsAuth assente/incompleto con AssetSignature presente " +
                    $"(prefisso=0x{flSig[0]:X2}, serve CAog+companion da PrivilegedBatch).");
            }

            // #region agent log
            try
            {
                var isFlRecord = asset.RecordName.StartsWith("FL:", StringComparison.Ordinal);
                MmcsAuthBuilder.TrySplitMmcsAuth(asset.MmcsAuth, out var ckSig, out _, out _);
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "fl-authget-v1",
                        ["hypothesisId"] = isFlRecord ? "H-FL4" : "H-FL2",
                        ["location"] = "BackupDownloadService.AuthorizeGetAsync",
                        ["message"] = "mono_authget_flist_f1",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            record = asset.RecordName,
                            isFlRecord,
                            f1Lead = flistEntry.Signature21[0],
                            assetSigLead = flSig[0],
                            ckPart0Lead = ckSig is { Length: 21 } ? ckSig[0] : -1,
                            path = asset.RelativePath,
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion

            return await AuthorizeGetBatchAsync(
                session, contentHost, [flistEntry], asset.ZoneName, ct,
                debugRecord: asset.RecordName,
                debugIsFileList: asset.RecordName.StartsWith("FL:", StringComparison.Ordinal)
                    || asset.AssetSignature is { Length: 21 })
                .ConfigureAwait(false);
        }

        // FL / CKAsset legacy: f1 = mmcs-auth part0 (tipicamente 0x01‖20B).
        var mmcsAuth = asset.MmcsAuth;
        if (!MmcsAuthBuilder.TrySplitMmcsAuth(mmcsAuth, out var sig, out var companion, out var token))
        {
            throw new InvalidOperationException(
                "authorizeGet: MmcsAuth assente o incompleto (attesi 3 token x-apple-mmcs-auth).");
        }

        // #region agent log
        try
        {
            var isFlRecord = asset.RecordName.StartsWith("FL:", StringComparison.Ordinal);
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "fl-authget-v1",
                    ["hypothesisId"] = "H-FL4",
                    ["location"] = "BackupDownloadService.AuthorizeGetAsync",
                    ["message"] = "mono_authget_ck_legacy_f1",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        record = asset.RecordName,
                        isFlRecord,
                        f1Lead = sig.Length > 0 ? sig[0] : -1,
                        hasAssetSig = false,
                        path = asset.RelativePath,
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        return await AuthorizeGetBatchAsync(
            session,
            contentHost,
            [new UbChunkBuilder.AuthorizeGetFileEntry(sig, token, companion)],
            asset.ZoneName,
            ct,
            debugRecord: asset.RecordName,
            debugIsFileList: asset.RecordName.StartsWith("FL:", StringComparison.Ordinal))
            .ConfigureAwait(false);
    }

    private EdgeDownloadAuthState CreateAssetEdgeAuthState(
        ICloudSession session,
        BackupAsset asset,
        byte[] authBody,
        IReadOnlyList<SignedUrlChunk> chunks,
        string? workDirectory,
        IProgress<string>? log)
    {
        var contentHost = $"https://{session.Partition}-content.icloud.com";
        return EdgeDownloadAuthState.ForAsset(
            authBody,
            chunks,
            async ct =>
            {
                if (!await EnsureMmcsAuthForAuthorizeGetAsync(
                        session, asset, workDirectory ?? ".", log, ct)
                        .ConfigureAwait(false))
                {
                    throw new InvalidOperationException(
                        $"edge refresh: MmcsAuth assente per {asset.RecordName}");
                }

                var freshAuth = await AuthorizeGetAsync(session, contentHost, asset, ct)
                    .ConfigureAwait(false);
                var (authSlice, freshChunks) = ResolveAuthorizeGetPart(asset, freshAuth);
                if (!string.IsNullOrEmpty(workDirectory))
                {
                    var tag = SanitizeFileName(asset.RecordName ?? "asset");
                    if (tag.Length > 48)
                        tag = tag[..48];
                    await File.WriteAllBytesAsync(
                        Path.Combine(workDirectory, $"AUTH_EDGE_REFRESH_{tag}_authorizeGet.bin"),
                        freshAuth,
                        ct).ConfigureAwait(false);
                }

                log?.Report(
                    $"  edge refresh: nuovo authorizeGet per {asset.RelativePath ?? asset.RecordName}");
                // #region agent log
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.CreateAssetEdgeAuthState",
                    "edge_authorize_refresh_ok",
                    new
                    {
                        record = asset.RecordName,
                        relativePath = asset.RelativePath,
                        chunkCount = freshChunks.Count,
                        authLen = authSlice.Length,
                    },
                    "H-EDGE-REFRESH",
                    "post-fix");
                // #endregion
                return (authSlice, freshChunks);
            });
    }

    private EdgeDownloadAuthState CreateBatchEdgeAuthState(
        ICloudSession session,
        string contentHost,
        IReadOnlyList<BackupAsset> batch,
        IReadOnlyList<UbChunkBuilder.AuthorizeGetFileEntry> entries,
        byte[] authBody,
        IReadOnlyList<SignedUrlChunk> batchHosts,
        string snapshotDirectory,
        MmcsChunkAssemblySession mmcsSession,
        IProgress<string>? log)
    {
        return EdgeDownloadAuthState.ForAsset(
            authBody,
            batchHosts,
            async ct =>
            {
                var freshAuth = await AuthorizeGetBatchAsync(
                    session,
                    contentHost,
                    entries,
                    batch[0].ZoneName,
                    ct,
                    debugRecord: $"BATCH_REFRESH×{batch.Count}:{batch[0].RecordName}",
                    debugIsFileList: true)
                    .ConfigureAwait(false);

                if (IkeDiskDumpOptions.DumpAuthBatch)
                {
                    await File.WriteAllBytesAsync(
                        Path.Combine(
                            snapshotDirectory,
                            $"AUTH_BATCH_REFRESH_{DateTimeOffset.UtcNow:yyyyMMdd_HHmmss}_authorizeGet.bin"),
                        freshAuth,
                        ct).ConfigureAwait(false);
                }

                mmcsSession.IndexBatchAuthorizeGetHosts(freshAuth);
                var freshHosts = UbChunkBuilder.ParseAuthorizeGetResponse(freshAuth);
                log?.Report(
                    $"  edge refresh batch×{batch.Count}: nuovo authorizeGet ({freshHosts.Count} host)");
                // #region agent log
                AgentFlEdgeDebugLog(
                    "BackupDownloadService.CreateBatchEdgeAuthState",
                    "edge_batch_authorize_refresh_ok",
                    new
                    {
                        batchCount = batch.Count,
                        hostCount = freshHosts.Count,
                        authLen = freshAuth.Length,
                    },
                    "H-EDGE-REFRESH",
                    "post-fix");
                // #endregion
                return (freshAuth, freshHosts);
            });
    }

    private static (byte[] AuthSlice, IReadOnlyList<SignedUrlChunk> Chunks) ResolveAuthorizeGetPart(
        BackupAsset asset,
        byte[] authorizeGetBody)
    {
        if (asset.AssetSignature is { Length: 21 } sig)
        {
            var part = UbChunkBuilder.SelectFilePartAligned(
                UbChunkBuilder.ParseAuthorizeGetFiles(authorizeGetBody),
                authorizeGetBody,
                sig,
                fallbackIndex: 0);
            return (part.AuthSlice, part.Chunks);
        }

        return (authorizeGetBody, UbChunkBuilder.ParseAuthorizeGetResponse(authorizeGetBody));
    }

    private static string SanitizeFileName(string name)
    {
        var chars = name.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_').ToArray();
        return new string(chars);
    }

    /// <summary>
    /// Staging per-asset: in batch più file condividono lo stesso object-id MMCS
    /// ma file-part/auth diversi — path unico evita lock con decrypt parallelo.
    /// </summary>
    private static string ResolveAssetStagingObjectPath(
        string snapshotDirectory,
        BackupAsset asset,
        string objectId)
    {
        var oid = SanitizeFileName(objectId);
        if (asset.AssetSignature is { Length: 21 } sig)
        {
            var tag = Convert.ToHexString(sig).ToLowerInvariant();
            if (tag.Length > 24)
                tag = tag[..24];
            return Path.Combine(snapshotDirectory, $"OBJ_{oid}_{tag}.bin");
        }

        var record = SanitizeFileName(asset.RecordName);
        if (record.Length > 36)
            record = record[..36];
        return Path.Combine(snapshotDirectory, $"OBJ_{oid}_{record}.bin");
    }

    // #region agent log
    internal static void AgentFlEdgeDebugLog(
        string location,
        string message,
        object data,
        string hypothesisId,
        string runId = "pre-fix")
    {
        // 401/403/edge refresh: sempre su disco (Quiet nascondeva il 403 in sessione).
        var critical = hypothesisId is "H12" or "H-EDGE-REFRESH" or "H4"
                       || message.Contains("edge GET failed", StringComparison.Ordinal)
                       || message.Contains("edge_chunk_refresh", StringComparison.Ordinal);
        if (!critical)
        {
            if (IkeLogOptions.Quiet && message != "perf_settings")
                return;
            var diagOn = string.Equals(
                Environment.GetEnvironmentVariable("IKE_AGENT_DIAG"),
                "1",
                StringComparison.Ordinal);
            // Always emit perf_settings to session log; other messages only with IKE_AGENT_DIAG=1.
            if (!diagOn && message != "perf_settings")
                return;
        }

        try
        {
            var payload = new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = location,
                ["message"] = message,
                ["data"] = data,
                ["hypothesisId"] = hypothesisId,
                ["runId"] = runId,
            };
            var line = JsonSerializer.Serialize(payload);
            if (critical)
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line + Environment.NewLine);
            }
            else
            {
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
                var diagOn = string.Equals(
                    Environment.GetEnvironmentVariable("IKE_AGENT_DIAG"),
                    "1",
                    StringComparison.Ordinal);
                if (diagOn)
                {
                    payload["sessionId"] = "ab5168";
                    IkeLogOptions.AppendAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-ab5168.log",
                        JsonSerializer.Serialize(payload));
                }
            }
        }
        catch
        {
            // ignore debug log failures
        }
    }

    private static int _bkFailLogCount;
    private static int _d3IkmLogCount;
    private static int _wrapBindLogCount;

    private static void AgentWrapBindLog(
        string hypothesisId,
        string location,
        string message,
        object data)
    {
        var n = Interlocked.Increment(ref _wrapBindLogCount);
        if (n > 120 && n % 20 != 0)
            return;
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = location,
                ["message"] = message,
                ["data"] = data,
                ["hypothesisId"] = hypothesisId,
                ["runId"] = "wrap-bind-v1",
                ["wrapN"] = n,
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

    // #region agent log
    /// <summary>D3: fingerprint IKM32 (sha16 + head8 + CSB/sig) per confronto DecryptFordKeys.</summary>
    private static void AgentD3IkmLog(
        string location,
        string message,
        BackupAsset asset,
        byte[]? ikm,
        string source,
        int wrapLen)
    {
        var n = Interlocked.Increment(ref _d3IkmLogCount);
        if (n > 40 && n % 10 != 0)
            return;
        try
        {
            string? ikmSha16 = null;
            string? ikmHead8 = null;
            if (ikm is { Length: > 0 })
            {
                ikmSha16 = Convert.ToHexString(SHA256.HashData(ikm).AsSpan(0, 8));
                ikmHead8 = Convert.ToHexString(ikm.AsSpan(0, Math.Min(8, ikm.Length)));
            }

            string? sigHex = null;
            if (asset.AssetSignature is { Length: > 0 } sig)
                sigHex = Convert.ToHexString(sig.AsSpan(0, Math.Min(21, sig.Length)));

            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = location,
                ["message"] = message,
                ["hypothesisId"] = "H-D3",
                ["runId"] = "d3-ikm-vs-live",
                ["data"] = new Dictionary<string, object?>
                {
                    ["n"] = n,
                    ["record"] = ClipBk(asset.RecordName, 64),
                    ["source"] = source,
                    ["wrapLen"] = wrapLen,
                    ["ikmLen"] = ikm?.Length ?? 0,
                    ["ikmSha16"] = ikmSha16,
                    ["ikmHead8"] = ikmHead8,
                    ["sigHex"] = sigHex,
                    ["wrapHead8"] = ClipBk(asset.AssetProtectionInfoHex, 16),
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
    }
    // #endregion

    private static void AgentBkFailLog(
        string hypothesisId,
        string location,
        string message,
        object data)
    {
        // Cap volume: first 80 fails fully, then every 25th.
        var n = Interlocked.Increment(ref _bkFailLogCount);
        if (n > 80 && n % 25 != 0)
            return;
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = location,
                ["message"] = message,
                ["data"] = data,
                ["hypothesisId"] = hypothesisId,
                ["runId"] = "bk-decrypt-v1",
                ["failN"] = n,
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

    private static string? ClipBk(string? s, int max)
        => string.IsNullOrEmpty(s) ? s : (s.Length <= max ? s : s[..max]);

    private static int TryWrapLen(string? hex)
    {
        if (string.IsNullOrWhiteSpace(hex))
            return 0;
        try
        {
            return Convert.FromHexString(hex).Length;
        }
        catch
        {
            return -1;
        }
    }
    // #endregion
}
