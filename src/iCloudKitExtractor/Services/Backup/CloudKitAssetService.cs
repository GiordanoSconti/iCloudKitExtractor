using System.Collections.Concurrent;
using System.IO;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Backup;

public sealed class CloudKitAssetService
{
    private const string DefaultZone = "_defaultZone";
    private const string MbksyncZone = "mbksync";

    private static readonly Regex AssetRecordRegex = new(
        @"^(?:KA|MA|LA|NA|JA):",
        RegexOptions.Compiled);

    /// <summary>
    /// Candidati accettati da <see cref="ParseAssetRecord"/>: TYPE illusione,
    /// wire <c>A:pref4:…</c>, oppure UUID nudo (owned BackupAsset).
    /// </summary>
    private static bool IsAssetRecordParseCandidate(string candidate) =>
        AssetRecordRegex.IsMatch(candidate)
        || CloudKitMmcsIds.IsUuidRecordName(candidate)
        || CloudKitMmcsIds.IsAssetRecordName(candidate);

    private readonly HttpClient _http;
    private readonly CloudKitGatewayClient _gateway;
    private readonly MobileBackupService _mbs;
    private readonly CloudKitPreAuthService _preAuth;
    private readonly CloudKitQueryService _query;
    private RestoreSessionState? _restoreState;

    /// <summary>Stato restore dopo <see cref="PrepareDownloadAsync"/> (Lock/PreAuth).</summary>
    public RestoreSessionState? CurrentRestoreState => _restoreState;

    /// <summary>
    /// Payload S: del bootstrap (batch gateway, preferito alla cache lista domainBase).
    /// Usato dal catalogo deterministico / EN: post-Lock.
    /// </summary>
    public byte[]? BootstrapSnapshotPayload => _bootstrapSnapshotPayload;

    /// <summary>Payload grezzo FetchRecordZones mbksync (cache offline KEK/fileList).</summary>
    public const string MbksyncZonesFileName = "mbksync_zones_retrieve.bin";

    /// <summary>Directory con master di zona già unwrapped (32 B ciascuno) + meta.</summary>
    public const string ZoneMastersDirectoryName = "mbksync_zone_masters";

    public byte[]? BootstrapZonesPayload => _bootstrapZonesPayload;

    /// <summary>Master zona in memoria (da payload o da cache su disco).</summary>
    public IReadOnlyList<(byte[] Master, string Source, string KeyIdHex, string ZoneName)> CachedZoneMasters =>
        _cachedZoneMasters;

    private UbChunkCatalog _preAuthCatalog = UbChunkCatalog.Empty;
    private byte[]? _bootstrapDevicePayload;
    private byte[]? _bootstrapSnapshotPayload;
    private byte[]? _bootstrapMbsPayload;
    private byte[]? _bootstrapZonesPayload;
    private byte[]? _lockSaveBody;
    private EnFetchResult? _lastEnFetch;
    private readonly List<(byte[] Master, string Source, string KeyIdHex, string ZoneName)> _cachedZoneMasters = [];
    private readonly object _zoneMastersGate = new();
    private bool _zoneMastersHarvestDone;
    private bool _zoneMastersPersisted;

    /// <summary>Catalogo N: post-Lock (§6: due record/retrieve grandi dopo Lock).</summary>
    public EnFetchResult? LastEnFetch => _lastEnFetch;

    public CloudKitAssetService(HttpClient http)
    {
        _http = http;
        _gateway = new CloudKitGatewayClient(http);
        _mbs = new MobileBackupService(http);
        _query = new CloudKitQueryService(_gateway);
        _preAuth = new CloudKitPreAuthService(_gateway);
    }

    /// <param name="forceRemint">
    /// true = nuovo mint Anisette (401 OTP); false = riusa sessione + Client-Time.
    /// </param>
    public delegate Task SessionRefreshDelegate(
        ICloudSession session,
        IProgress<string>? log,
        CancellationToken ct,
        bool forceRemint);

    private SessionRefreshDelegate? _sessionRefresh;

    /// <summary>Azzera il circuit breaker HTTP 401 del gateway (dopo refresh sessione).</summary>
    public void ClearGatewayUnauthorized()
    {
        _gateway.ClearUnauthorized();
        Volatile.Write(ref _gatewayPaceMs, 0);
    }

    /// <summary>True se l'ultimo refresh Anisette è fallito e siamo ancora in cooldown.</summary>
    public bool AnisetteRefreshBlocked
    {
        get
        {
            if (Volatile.Read(ref _anisetteRefreshFailed) == 0)
                return false;
            var at = Volatile.Read(ref _anisetteRefreshFailedAtMs);
            if (at == 0)
                return true;
            return Environment.TickCount64 - at < AnisetteRefreshCooldownMs;
        }
    }

    /// <summary>Riabilita i refresh Anisette dopo un fallimento (nuovo download / login).</summary>
    public void ResetAnisetteRefreshCircuit()
    {
        Volatile.Write(ref _anisetteRefreshFailed, 0);
        Volatile.Write(ref _anisetteRefreshFailedAtMs, 0);
    }

    public void SetSessionRefresh(SessionRefreshDelegate? refresh)
    {
        _sessionRefresh = refresh;
        _gateway.SetUnauthorizedRefresh(refresh is null
            ? null
            : (s, ct) => refresh(s, null, ct, forceRemint: true));
    }

    public async Task AcquireRestoreLockAsync(
        ICloudSession session,
        BackupDevice device,
        RestoreSessionState restore,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        log?.Report("CloudKit: record/save Lock (Foreground Restore)…");
        restore.TryAbsorbFromPayload(_bootstrapDevicePayload);
        restore.TryAbsorbFromPayload(_bootstrapSnapshotPayload);
        restore.TryAbsorbFromPayload(_bootstrapMbsPayload);
        restore.EnsureForeground(session, device);
        var lockOperationId = Guid.NewGuid().ToString().ToUpperInvariant();
        _lockSaveBody = CloudKitLockRequestBuilder.BuildLockSave(
            restore.ToRequestContext(),
            session.CloudKitUserId,
            device.DeviceUuid,
            lockOperationId);
        var payload = await _gateway.RecordSaveAsync(session, _lockSaveBody, ct, restore);
        restore.TryAbsorbFromPayload(payload);
        CapturePreAuthSessionFromBatch(payload, restore);

        var lockText = payload is { Length: > 0 }
            ? System.Text.Encoding.Latin1.GetString(payload)
            : string.Empty;
        if (lockText.Contains("Invalid lock id", StringComparison.OrdinalIgnoreCase))
        {
            log?.Report("  Lock RIFIUTATO: Invalid lock id (MobileBackupServerExtension)");
            throw new InvalidOperationException(
                "CloudKit Lock rifiutato (Invalid lock id). Verifica Foreground hw/sha e record {device}:Lock.");
        }

        if (lockText.Contains("owners", StringComparison.Ordinal)
            || lockText.Contains(":Lock", StringComparison.Ordinal))
            log?.Report($"  Lock OK → {payload.Length:N0} byte");
        else
            log?.Report($"  Lock risposta → {payload.Length:N0} byte (verifica owners/expiration)");
    }

    public async Task PrepareDownloadAsync(
        ICloudSession session,
        BackupDevice device,
        BackupSnapshot snapshot,
        IProgress<string>? log = null,
        SessionRefreshDelegate? refreshSession = null,
        CancellationToken ct = default,
        string? outputDirectory = null)
    {
        _sessionRefresh = refreshSession ?? _sessionRefresh;
        _bootstrapDevicePayload = null;
        _bootstrapSnapshotPayload = null;
        _bootstrapMbsPayload = null;
        _bootstrapZonesPayload = null;
        _cachedZoneMasters.Clear();
        _zoneMastersHarvestDone = false;
        _zoneMastersPersisted = false;
        _lockSaveBody = null;
        _lastEnFetch = null;
        // Stesso Foreground assorbito da mbs/batch; fallback sintetico solo se assente.
        _restoreState = RestoreSessionState.CreateForCatalog(session);

        // Wire: zones → Account → D: → S: → (mbs) → Lock → N:
        // Crypto locale (KeySet già in sessione): zone masters + K: subito dopo D:/S:,
        // prima di Lock/N: e prima di qualsiasi authorizeGet.
        await BootstrapRestoreCatalogAsync(session, device, snapshot, log, ct).ConfigureAwait(false);
        await PersistOrLoadMbksyncZonesAsync(outputDirectory, session.PcsKeysDirectory, log, ct)
            .ConfigureAwait(false);
        await EnsureZoneMastersCachedAsync(session, outputDirectory, session.PcsKeysDirectory, log, ct)
            .ConfigureAwait(false);
        if (_restoreState.Foreground is null)
            _restoreState.EnsureForeground(session, device);
        await PaceGatewayAsync(ct).ConfigureAwait(false);

        if (device.Keybags.Count == 0)
            await EnrichDeviceKeybagsAsync(session, device, log, ct).ConfigureAwait(false);
        await DownloadKeybagBlobsAsync(session, device, log, ct).ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(outputDirectory)
            && PcsSessionSeedKeys.HasAny(session)
            && (device.KeybagRawPayloads.Count > 0 || device.KeybagDataBlobs.Count > 0))
        {
            log?.Report("CloudKit: unlock Keybag PCS ( prima di Lock / authorizeGet)…");
            var kbUnlock = await UnlockKeybagsWithPcsAsync(
                session, device, outputDirectory, log, ct).ConfigureAwait(false);
            await EnsureZoneMastersCachedAsync(
                session, outputDirectory, session.PcsKeysDirectory, log, ct)
                .ConfigureAwait(false);
            log?.Report(
                kbUnlock.Success
                    ? $"  Keybag PCS: {kbUnlock.Message}"
                    : $"  Keybag PCS: {kbUnlock.Message}");
        }
        else if (!PcsSessionSeedKeys.HasAny(session))
        {
            log?.Report(
                "  Keybag unlock defer: PCS assente — Escrow e/o CKKS OpenVault prima del restore");
        }

        await PaceGatewayAsync(ct).ConfigureAwait(false);
        await AcquireRestoreLockAsync(session, device, _restoreState, log, ct).ConfigureAwait(false);
        await PaceGatewayAsync(ct).ConfigureAwait(false);

        // §6: dopo Lock → catalogo N: (due retrieve grandi), non flood query.
        var enDir = string.IsNullOrWhiteSpace(outputDirectory)
            ? Path.Combine(Path.GetTempPath(), "iCloudKitExtractor-en")
            : outputDirectory;
        _lastEnFetch = await TryFetchEnAfterLockAsync(
            session, snapshot, enDir, log, ct).ConfigureAwait(false);

        var catalogOk = _lastEnFetch is { HasAuth: true }
            || _lastEnFetch is { TotalResponseBytes: > 100_000, SignedChunks.Count: > 0 }
            || _lastEnFetch is { TotalResponseBytes: > 100_000, QuerySeeds.Count: > 0 };

        if (_lastEnFetch is { } enAny
            && (enAny.HasAuth || enAny.SignedChunks.Count > 0 || enAny.TotalResponseBytes > 1024))
        {
            MergeEnIntoPreAuthCatalog(enAny);
            foreach (var hint in enAny.QuerySeeds.Concat(enAny.AssetRecordNames).Take(64))
                device.AssetHints.Add(hint);
        }

        if (catalogOk)
        {
            //  niente authorizeGet qui — prima PrivilegedBatch + decrypt metadata locale.
            log?.Report(
                "  N: catalogo post-Lock OK — defer authorizeGet a dopo PrivBatch/metadata " +
                "(ordine ASSET_DECRYPT)");
        }
        else
        {
            if (_lastEnFetch is not null)
            {
                log?.Report(
                    $"  N: catalogo debole (resp={_lastEnFetch.TotalResponseBytes:N0} B, " +
                    $"auth={_lastEnFetch.MmcsAuthHeaders.Count}, signed={_lastEnFetch.SignedChunks.Count}) " +
                    "— PreAuth ubchunk fallback (solo catalogo, no authorizeGet)");
            }

            log?.Report("CloudKit: PreAuth record/retrieve (ubchunk fallback)…");
            var preAuthRecord = await _preAuth.TryPreAuthRetrieveAsync(
                session,
                _restoreState,
                device,
                _bootstrapDevicePayload,
                _bootstrapSnapshotPayload,
                _bootstrapMbsPayload,
                _lockSaveBody,
                log,
                ct);

            foreach (var hint in preAuthRecord.RecordNames)
                device.AssetHints.Add(hint);
            foreach (var path in preAuthRecord.Catalog.SignedPaths)
                device.AssetHints.Add(path);

            _preAuthCatalog = _preAuthCatalog.Merge(preAuthRecord.Catalog);
            if (preAuthRecord.Catalog.SignedChunks.Count > 0)
            {
                log?.Report(
                    $"  PreAuth path firmati → {preAuthRecord.Catalog.SignedChunks.Count}");
            }

            // Nessun TryAuthorizeGetFromPreAuthAsync: MMCS solo nel loop download post-metadata.
        }
    }

    /// <summary>
    /// post-Lock §6: <c>:CN:</c> → <c>N:uuid:checksum=:0</c> in <c>_defaultZone</c>.
    /// </summary>
    private async Task<EnFetchResult?> TryFetchEnAfterLockAsync(
        ICloudSession session,
        BackupSnapshot snapshot,
        string outputDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var cnEntries = CloudKitManifestChecksumParser.ParseFileCnEntries(
            _bootstrapSnapshotPayload ?? snapshot.CatalogPayload,
            snapshot.RecordName);
        if (cnEntries.Count == 0)
        {
            log?.Report("  EN post-Lock skip: nessun :CN: file nel bootstrap S:");
            return null;
        }

        var enNames = BackupEnRecordService.BuildEnRecordNames(cnEntries);
        log?.Report(
            $"CloudKit: N: file list post-Lock (order, {enNames.Count:N0} da {cnEntries.Count:N0} :CN:; " +
            "nome N:…=:0, non EN:)…");

        try
        {
            var enService = new BackupEnRecordService(_gateway);
            return await enService.FetchAsync(
                session,
                enNames,
                outputDirectory,
                _restoreState,
                BackupEnRecordService.FirstBatchSize,
                BackupEnRecordService.SubsequentBatchSize,
                log,
                ct,
                _bootstrapZonesPayload).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log?.Report($"  EN post-Lock FAIL: {ex.Message}");
            return null;
        }
    }

    private void MergeEnIntoPreAuthCatalog(EnFetchResult en)
    {
        var auths = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var existing in _preAuthCatalog.MmcsAuths)
            auths[existing.Key] = existing.Value;

        var i = 0;
        foreach (var auth in en.MmcsAuthHeaders)
        {
            var key = MmcsAuthBuilder.TryExtractFileChecksumHex(auth) ?? $"en-auth:{i}";
            auths[key] = auth;
            i++;
        }

        var names = new HashSet<string>(_preAuthCatalog.RecordNames, StringComparer.Ordinal);
        foreach (var n in en.AssetRecordNames.Concat(en.QuerySeeds))
            names.Add(n);

        var chunks = _preAuthCatalog.SignedChunks.ToList();
        var seenUrl = new HashSet<string>(chunks.Select(static c => c.Url), StringComparer.OrdinalIgnoreCase);
        foreach (var chunk in en.SignedChunks)
        {
            if (seenUrl.Add(chunk.Url))
                chunks.Add(chunk);
        }

        var paths = new HashSet<string>(_preAuthCatalog.SignedPaths, StringComparer.Ordinal);
        foreach (var p in en.SignedPaths)
            paths.Add(p);

        _preAuthCatalog = new UbChunkCatalog
        {
            RecordNames = names.OrderBy(static n => n, StringComparer.Ordinal).ToList(),
            QuerySeeds = en.QuerySeeds.Count > 0
                ? en.QuerySeeds.ToList()
                : _preAuthCatalog.QuerySeeds,
            SignedChunks = chunks,
            SignedPaths = paths.OrderBy(static p => p, StringComparer.Ordinal).ToList(),
            MmcsAuths = auths
        };
    }

    private async Task TryAuthorizeGetFromEnAsync(
        ICloudSession session,
        BackupDevice device,
        EnFetchResult en,
        IProgress<string>? log,
        CancellationToken ct)
    {
        log?.Report(
            $"  EN download hints → {en.SignedChunks.Count} chunk, {en.MmcsAuthHeaders.Count} auth");

        var auth = en.MmcsAuthHeaders.FirstOrDefault(static a =>
            a.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length >= 3);
        if (string.IsNullOrWhiteSpace(auth))
        {
            log?.Report("  authorizeGet da EN skip: nessun auth f2/f5/f17 strutturato");
            return;
        }

        var synthetic = new CloudKitPreAuthResult
        {
            Catalog = new UbChunkCatalog
            {
                MmcsAuths = new Dictionary<string, string>(StringComparer.Ordinal)
                {
                    ["en"] = auth
                },
                SignedChunks = en.SignedChunks.ToList(),
                SignedPaths = en.SignedPaths.ToList(),
                RecordNames = en.AssetRecordNames.ToList(),
                QuerySeeds = en.QuerySeeds.ToList()
            }
        };
        await TryAuthorizeGetFromPreAuthAsync(session, device, synthetic, log, ct);
    }

    /// <summary>
    /// Usa KeySet Escrow (già in sessione) + zone mbksync per decifrare keybagData/secret.
    /// </summary>
    public BackupKeybagPcsUnlockResult UnlockKeybagsWithPcs(
        ICloudSession session,
        BackupDevice device,
        string outputDirectory,
        IProgress<string>? log = null)
    {
        TryLoadMbksyncZonesFromDisk(outputDirectory, session.PcsKeysDirectory, log);
        TryPersistMbksyncZones(outputDirectory, session.PcsKeysDirectory, log);
        EnsureZoneMastersCached(session, outputDirectory, session.PcsKeysDirectory, log);
        return BackupKeybagPcsUnlock.Unlock(
            session, device, _bootstrapZonesPayload, outputDirectory, log);
    }

    /// <summary>Versione async: crypto PCS/keybag su thread pool (non blocca la UI).</summary>
    public Task<BackupKeybagPcsUnlockResult> UnlockKeybagsWithPcsAsync(
        ICloudSession session,
        BackupDevice device,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default) =>
        Task.Run(() => UnlockKeybagsWithPcs(session, device, outputDirectory, log), ct);

    /// <summary>Unwrap zone masters su thread pool.</summary>
    public Task EnsureZoneMastersCachedAsync(
        ICloudSession session,
        string? outputDirectory,
        string? pcsKeysDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default) =>
        Task.Run(() => EnsureZoneMastersCached(session, outputDirectory, pcsKeysDirectory, log), ct);

    /// <summary>
    /// Unwrap PI da payload zone (+ cache disco) → master in memoria e su
    /// <see cref="ZoneMastersDirectoryName"/>. Etichetta <c>_defaultZone</c> vs <c>mbksync</c>
    /// (MMCS asset → default; keybag K: → mbksync).
    /// </summary>
    public void EnsureZoneMastersCached(
        ICloudSession session,
        string? outputDirectory,
        string? pcsKeysDirectory,
        IProgress<string>? log = null)
    {
        // domainParallel × decryptWorkers chiamano questo in parallelo: un solo harvest.
        lock (_zoneMastersGate)
        {
            if (_zoneMastersHarvestDone && _cachedZoneMasters.Count > 0)
            {
                PcsSessionSeedKeys.RememberKeyIdHexes(
                    session,
                    _cachedZoneMasters
                        .Select(static m => m.KeyIdHex)
                        .Where(static id => !string.IsNullOrWhiteSpace(id)));
                return;
            }

            if (_cachedZoneMasters.Count == 0)
                TryLoadZoneMastersFromDisk(outputDirectory, pcsKeysDirectory, log);

            if (_cachedZoneMasters.Count > 0)
            {
                PcsSessionSeedKeys.RememberKeyIdHexes(
                    session,
                    _cachedZoneMasters
                        .Select(static m => m.KeyIdHex)
                        .Where(static id => !string.IsNullOrWhiteSpace(id)));
            }

            // Unwrap zone UNA volta: nested master aprono wrap FL.
            // Escrow: seed = ParseKeySet (HEAD). Manatee: Collect. Light ON (una tantum).
            if (PcsSessionSeedKeys.HasAny(session)
                && _bootstrapZonesPayload is { Length: > 64 })
            {
                try
                {
                    var manateeFast = PcsSessionSeedKeys.IsManateePrimary(session);
                    var seeds = PcsSessionSeedKeys.HasEscrowKeySet(session)
                        ? PcsDer.ParseKeySetPrivateKeys(session.PcsEscrowedKeySet!)
                        : PcsSessionSeedKeys.Collect(session, log);
                    if (seeds.Count > 0)
                    {
                        var before = _cachedZoneMasters.Count;
                        var labeled = UnwrapZonesLabeled(
                            _bootstrapZonesPayload, seeds, includeLight: true);
                        foreach (var (zone, zoneName) in labeled)
                            ConsiderCachedMaster(
                                zone.MasterKey, $"zones:{zoneName}", zone.MasterKeyIdHex, zoneName);
                        if (labeled.Count > 0 && manateeFast)
                            PcsSessionSeedKeys.RememberFromZones(
                                session, labeled.Select(static t => t.Zone), seeds);
                        if (_cachedZoneMasters.Count > before)
                        {
                            var def = _cachedZoneMasters.Count(static m =>
                                m.ZoneName.Equals(DefaultZone, StringComparison.OrdinalIgnoreCase));
                            var mbk = _cachedZoneMasters.Count(static m =>
                                m.ZoneName.Equals(MbksyncZone, StringComparison.OrdinalIgnoreCase));
                            log?.Report(
                                $"  zone masters unwrap → {_cachedZoneMasters.Count} " +
                                $"(default={def}, mbksync={mbk}, +{_cachedZoneMasters.Count - before}, " +
                                "nested/FL+light once)");
                        }
                    }
                }
                catch (Exception ex)
                {
                    log?.Report($"  zone masters unwrap skip: {ex.Message}");
                }
            }

            _zoneMastersHarvestDone = true;

            if (_cachedZoneMasters.Count == 0)
                return;

            if (!_zoneMastersPersisted)
            {
                TryPersistZoneMasters(outputDirectory, pcsKeysDirectory, log);
                _zoneMastersPersisted = true;
            }
        }
    }

    /// <summary>
    /// Master preferiti per KEK MMCS: zona dell'asset (default <c>_defaultZone</c>).
    /// </summary>
    public IEnumerable<(byte[] Master, string Source)> MastersForMmcsZone(string? zoneName)
    {
        var want = string.IsNullOrWhiteSpace(zoneName) ? DefaultZone : zoneName;
        foreach (var m in _cachedZoneMasters)
        {
            if (m.ZoneName.Equals(want, StringComparison.OrdinalIgnoreCase))
                yield return (m.Master, m.Source);
        }

        // Fallback: se etichetta assente, prova comunque i master default-labelled.
        if (!want.Equals(DefaultZone, StringComparison.OrdinalIgnoreCase))
            yield break;

        foreach (var m in _cachedZoneMasters)
        {
            if (m.ZoneName is "" or "unknown")
                yield return (m.Master, m.Source + ":unlabeled");
        }
    }

    /// <summary>Master mbksync (keybag / record K:).</summary>
    public IEnumerable<(byte[] Master, string Source)> MastersForMbksync()
    {
        foreach (var m in _cachedZoneMasters)
        {
            if (m.ZoneName.Equals(MbksyncZone, StringComparison.OrdinalIgnoreCase))
                yield return (m.Master, m.Source);
        }
    }

    /// <summary>
    ///  <c>query/retrieve</c> PrivilegedBatchRecordFetch per <c>A:pref4:…</c> in <c>_defaultZone</c>.
    /// Salva i payload e restituisce gli asset con auth MMCS.
    /// </summary>
    public async Task<IReadOnlyList<BackupAsset>> FetchKaLaMaRecordsAsync(
        ICloudSession session,
        IEnumerable<string> seedRecordNames,
        string? outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        int maxFetches = 96)
    {
        //  A:…:token=:size — senza =:N → NOT_FOUND tipico. Dedupe per base name.
        var seeds = NormalizeKaLaMaSeeds(seedRecordNames).Take(maxFetches).ToList();

        if (seeds.Count == 0)
        {
            log?.Report("CloudKit: nessun seed A:pref4:… valido da PrivilegedBatch");
            return [];
        }

        log?.Report(
            $"CloudKit: PrivilegedBatch ×{seeds.Count} (_defaultZone; A:pref4:rid)…");
        var dir = IkeDiskDumpOptions.DumpKalamaRecords
                  && !string.IsNullOrWhiteSpace(outputDirectory)
            ? Path.Combine(outputDirectory, "kalama_records")
            : null;
        if (dir is not null)
            Directory.CreateDirectory(dir);

        var assets = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        var ok = 0;
        var notFound = 0;
        var errors = 0;
        var remountHits = 0;
        var refreshedOnce = false;
        foreach (var name in seeds)
        {
            ct.ThrowIfCancellationRequested();
            BackupAsset? got = null;
            string? gotName = null;
            var triedNotFound = 0;
            foreach (var tryName in EnumerateTypeAlternates(name))
            {
                await PaceGatewayAsync(ct);
                try
                {
                    var payload = await _query.QueryFetchPayloadAsync(
                        session, tryName, _restoreState, ct);
                    if (dir is not null && payload.Length > 0)
                    {
                        var safe = SanitizeKeybagFileStem(tryName);
                        if (safe.Length > 80) safe = safe[..80];
                        await File.WriteAllBytesAsync(
                            Path.Combine(dir, $"query_{safe}.bin"), payload, ct);
                        // Replay Ford offline: CK BackupAsset (contents) separato da kalama auth-like.
                        var work = Directory.GetParent(dir)?.FullName;
                        if (!string.IsNullOrWhiteSpace(work))
                        {
                            await FordOfflineDumpWriter.DumpCloudKitQueryAsync(
                                work, payload, [tryName], safe, ct).ConfigureAwait(false);
                        }
                    }

                    if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err))
                    {
                        var msg = err ?? "errore";
                        var isNf = msg.Contains("NOT_FOUND", StringComparison.OrdinalIgnoreCase);
                        if (isNf)
                        {
                            triedNotFound++;
                            // Prova TYPE alternativo (JA->KA...) sullo stesso uuid:token=:size.
                            continue;
                        }

                        errors++;
                        if (errors <= 5)
                            log?.Report($"  {tryName}: errore {msg}");
                        break;
                    }

                    var parsed = ParseAssetRecord(payload, tryName);
                    // Sempre harvest sibling dalla stessa risposta ( 5 seed → 12+ CAog).
                    foreach (var a in ParseAssetsFromPayload(payload))
                    {
                        a.ZoneName = DefaultZone;
                        a.RecordPayload ??= payload;
                        assets[a.RecordName] = a;
                        ok++;
                    }

                    if (parsed is not null)
                    {
                        parsed.ZoneName = DefaultZone;
                        parsed.RecordPayload ??= payload;
                        assets[parsed.RecordName] = parsed;
                        got = parsed;
                        gotName = tryName;
                        break;
                    }

                    BackupAsset? fromPayload = assets.Values.FirstOrDefault(a =>
                        string.Equals(a.RecordName, tryName, StringComparison.Ordinal)
                        || a.RecordName.Contains(
                            tryName.Split(':', 3).ElementAtOrDefault(2) ?? "\0",
                            StringComparison.Ordinal));
                    if (fromPayload is not null)
                    {
                        got = fromPayload;
                        gotName = tryName;
                        break;
                    }

                    errors++;
                    if (errors <= 5)
                        log?.Report($"  {tryName}: risposta senza BackupAsset/auth");
                    break;
                }
                catch (Exception ex) when (IsUnauthorizedCloudKit(ex) && !refreshedOnce)
                {
                    refreshedOnce = true;
                    log?.Report($"  PrivilegedBatch 401 su {tryName} — refresh Anisette e retry…");
                    if (await TryRefreshSessionAfterUnauthorizedAsync(session, log, ct))
                    {
                        try
                        {
                            await PaceGatewayAsync(ct);
                            var payload = await _query.QueryFetchPayloadAsync(
                                session, tryName, _restoreState, ct);
                            var parsed = ParseAssetRecord(payload, tryName);
                            if (parsed is not null)
                            {
                                parsed.ZoneName = DefaultZone;
                                parsed.RecordPayload ??= payload;
                                got = parsed;
                                gotName = tryName;
                                break;
                            }
                        }
                        catch (Exception retryEx)
                        {
                            errors++;
                            if (errors <= 5)
                                log?.Report($"  PrivilegedBatch retry {tryName}: {retryEx.Message}");
                        }
                    }
                    else
                    {
                        errors++;
                        if (errors <= 5)
                            log?.Report($"  PrivilegedBatch {tryName}: {ex.Message}");
                    }

                    break;
                }
                catch (Exception ex)
                {
                    errors++;
                    if (errors <= 5)
                        log?.Report($"  PrivilegedBatch {tryName}: {ex.Message}");
                    if (ex.Message.Contains("CloudKit bloccato", StringComparison.OrdinalIgnoreCase)
                        && !refreshedOnce)
                    {
                        refreshedOnce = true;
                        await TryRefreshSessionAfterUnauthorizedAsync(session, log, ct);
                    }

                    break;
                }
            }

            if (got is not null)
            {
                assets[got.RecordName] = got;
                ok++;
                if (gotName is not null
                    && !string.Equals(gotName, name, StringComparison.Ordinal))
                {
                    remountHits++;
                    if (remountHits <= 8)
                        log?.Report($"  remount TYPE {name} → {gotName}");
                }
            }
            else if (triedNotFound > 0)
            {
                notFound++;
                if (notFound <= 5)
                    log?.Report($"  {name}: errore Error code: NOT_FOUND (TYPE alternati esauriti)");
            }
        }

        if (notFound > 5 || errors > 5 || remountHits > 8)
        {
            log?.Report(
                $"  PrivilegedBatch: NOT_FOUND={notFound}, remount={remountHits}, " +
                $"altri err={errors} (log ridotto)");
        }

        log?.Report($"  PrivilegedBatch A: → {ok} ok, {assets.Count} asset con auth/payload");
        return assets.Values.OrderBy(static a => a.RecordName, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// 00253: <c>query/retrieve</c> PrivilegedBatchRecordFetch con seed
    /// <c>A:pref4:rid</c>, raggruppati per UUID dominio (come  un Domain per query).
    /// Domini grandi: pacing adattivo, refresh token periodico, niente flood per-seed.
    /// </summary>
    public async Task<(IReadOnlyList<BackupAsset> Assets, byte[]? Payload)> FetchPrivilegedBatchMultiAsync(
        ICloudSession session,
        IReadOnlyList<string> seedRecordNames,
        string? outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var rawIn = seedRecordNames.Count;
        var seeds = NormalizeKaLaMaSeeds(seedRecordNames)
            .Where(static n => !CloudKitMmcsIds.IsUuidRecordName(n))
            .Where(IsTypePrefixedAssetName)
            .Where(HasAssetSizeSuffix)
            .ToList();
        // #region agent log
        try
        {
            var droppedNoSize = seedRecordNames
                .Where(static n => !string.IsNullOrWhiteSpace(n) && !HasAssetSizeSuffix(n))
                .Take(8)
                .Select(static n => n.Length > 96 ? n[..96] : n)
                .ToArray();
            var lineDrop = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "9a5651",
                ["runId"] = "pb-size-filter",
                ["hypothesisId"] = "H1",
                ["location"] = "FetchPrivilegedBatchMultiAsync",
                ["message"] = "pb_seed_filter",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new
                {
                    rawIn,
                    afterNorm = seeds.Count,
                    dropped = Math.Max(0, rawIn - seeds.Count),
                    droppedNoSizeSample = droppedNoSize,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                lineDrop + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
        if (seeds.Count == 0)
            return ([], null);

        //  tutti i seed di un Domain condividono l'UUID; batch ~6–12.
        var groups = GroupSeedsByDomainUuid(seeds);
        var chunkCount = groups.Sum(static g => (g.Count + PrivilegedBatchChunkSize - 1) / PrivilegedBatchChunkSize);
        log?.Report(
            $"CloudKit: query/retrieve PrivilegedBatch ×{seeds.Count} seed " +
            $"in {groups.Count} gruppi Domain (~{chunkCount} chunk×{PrivilegedBatchChunkSize}, " +
            $"parallel={PrivilegedBatchParallelism}, _defaultZone)…");

        // #region agent log
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "pb-fast",
                ["hypothesisId"] = "H-PB-FAST",
                ["location"] = "FetchPrivilegedBatchMultiAsync",
                ["message"] = "privileged_batch_start",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new
                {
                    seeds = seeds.Count,
                    groups = groups.Count,
                    chunkCount,
                    chunkSize = PrivilegedBatchChunkSize,
                    parallel = PrivilegedBatchParallelism,
                    gatewayPaceMs = Volatile.Read(ref _gatewayPaceMs),
                },
            });
            if (IkeLogOptions.ShouldWriteAgentDiag)
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
        }
        catch { /* ignore */ }
        // #endregion

        var assets = new ConcurrentDictionary<string, BackupAsset>(StringComparer.Ordinal);
        byte[]? lastPayload = null;
        var lastPayloadLock = new object();
        var dir = IkeDiskDumpOptions.DumpKalamaRecords
                  && !string.IsNullOrWhiteSpace(outputDirectory)
            ? Path.Combine(outputDirectory, "kalama_records")
            : null;
        if (dir is not null)
            Directory.CreateDirectory(dir);

        // Domini grandi: evita fallback 1×seed (4117 → migliaia di query → 401).
        var allowPerSeedFallback = seeds.Count <= PrivilegedBatchPerSeedMaxTotal;
        var chunksDone = 0;
        var chunksSinceRefresh = 0;
        var unauthorizedRefreshes = 0;
        var lastProgressLog = 0;
        var refreshGate = new SemaphoreSlim(1, 1);
        using var parallelGate = new SemaphoreSlim(PrivilegedBatchParallelism);
        var tasks = new List<Task>();

        async Task<bool> RefreshAnisetteAsync(string reason)
        {
            if (Volatile.Read(ref _anisetteRefreshFailed) != 0)
                return false;

            await refreshGate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                if (Volatile.Read(ref _anisetteRefreshFailed) != 0)
                    return false;

                log?.Report($"  PrivilegedBatch: refresh Anisette ({reason})…");
                if (await TryRefreshSessionAfterUnauthorizedAsync(session, log, ct)
                        .ConfigureAwait(false))
                {
                    Interlocked.Exchange(ref chunksSinceRefresh, 0);
                    await Task.Delay(PrivilegedBatchPostRefreshDelayMs, ct).ConfigureAwait(false);
                    return true;
                }

                return false;
            }
            finally
            {
                refreshGate.Release();
            }
        }

        foreach (var group in groups)
        {
            foreach (var chunk in ChunkList(group, PrivilegedBatchChunkSize))
            {
                var chunkLocal = chunk;
                tasks.Add(Task.Run(async () =>
                {
                    await parallelGate.WaitAsync(ct).ConfigureAwait(false);
                    try
                    {
                        ct.ThrowIfCancellationRequested();

                        // Refresh proattivo Anisette (serializzato).
                        if (Volatile.Read(ref chunksSinceRefresh) >= PrivilegedBatchRefreshEveryChunks)
                        {
                            await RefreshAnisetteAsync(
                                    $"periodico chunk≈{Volatile.Read(ref chunksDone)}/{chunkCount}")
                                .ConfigureAwait(false);
                        }

                        var paceMs = Volatile.Read(ref _gatewayPaceMs);
                        var (chunkAssets, payload, hardFail) = await QueryPrivilegedBatchChunkAsync(
                            session,
                            chunkLocal,
                            dir,
                            log,
                            ct,
                            paceMs,
                            allowPerSeedFallback).ConfigureAwait(false);

                        var done = Interlocked.Increment(ref chunksDone);
                        Interlocked.Increment(ref chunksSinceRefresh);

                        if (hardFail)
                        {
                            // Bump solo su 401 persistente (non su ogni transient).
                            NoteGatewayUnauthorized();
                            var n401 = Interlocked.Increment(ref unauthorizedRefreshes);
                            log?.Report(
                                $"  PrivilegedBatch: 401 sul chunk {done}/{chunkCount} — " +
                                $"refresh Anisette e ritento (paceMs={Volatile.Read(ref _gatewayPaceMs)})…");
                            var refreshed = await RefreshAnisetteAsync($"401 chunk {done}")
                                .ConfigureAwait(false);
                            if (!refreshed)
                            {
                                log?.Report(
                                    $"  ERROR PrivilegedBatch: skip chunk ({chunkLocal.Count} seed) — " +
                                    "refresh Anisette non disponibile (niente loop 401).");
                                return;
                            }

                            await Task.Delay(
                                    PrivilegedBatchPostRefreshDelayMs * Math.Min(n401, 4),
                                    ct)
                                .ConfigureAwait(false);

                            try
                            {
                                (chunkAssets, payload, hardFail) = await QueryPrivilegedBatchChunkAsync(
                                    session,
                                    chunkLocal,
                                    dir,
                                    log,
                                    ct,
                                    Volatile.Read(ref _gatewayPaceMs),
                                    allowPerSeedFallback).ConfigureAwait(false);
                            }
                            catch (Exception retryEx)
                            {
                                log?.Report(
                                    $"  PrivilegedBatch chunk retry: {retryEx.Message}");
                                return;
                            }

                            if (hardFail)
                            {
                                NoteGatewayUnauthorized();
                                log?.Report(
                                    $"  PrivilegedBatch: 401 persistente dopo refresh — skip chunk ({chunkLocal.Count} seed)");
                                return;
                            }
                        }

                        // H-PB-PACE: dopo chunk ok (anche post-401) azzera pace — altrimenti resta a 800.
                        NoteGatewayOk();

                        if (payload is { Length: > 0 })
                        {
                            lock (lastPayloadLock)
                                lastPayload = payload;
                        }
                        foreach (var a in chunkAssets)
                            assets[a.RecordName] = a;

                        var prevLog = Volatile.Read(ref lastProgressLog);
                        if (done - prevLog >= 10 || done == chunkCount)
                        {
                            if (Interlocked.CompareExchange(ref lastProgressLog, done, prevLog) == prevLog
                                || done == chunkCount)
                            {
                                log?.Report(
                                    $"  PrivilegedBatch progresso {done}/{chunkCount} " +
                                    $"auth={assets.Count} pace={Volatile.Read(ref _gatewayPaceMs)}ms " +
                                    $"parallel={PrivilegedBatchParallelism}");
                            }
                        }

                        // #region agent log
                        if (done == 1 || done % 25 == 0 || hardFail)
                        {
                            try
                            {
                                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "7dabb5",
                                    ["runId"] = "pb-fast",
                                    ["hypothesisId"] = "H-PB-FAST",
                                    ["location"] = "FetchPrivilegedBatchMultiAsync.chunk",
                                    ["message"] = "privileged_batch_chunk",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["data"] = new
                                    {
                                        n = done,
                                        chunkCount,
                                        harvested = chunkAssets.Count,
                                        hardFail,
                                        paceMs = Volatile.Read(ref _gatewayPaceMs),
                                        bagCount = assets.Count,
                                        parallel = PrivilegedBatchParallelism,
                                        chunkSize = PrivilegedBatchChunkSize,
                                    },
                                });
                                if (IkeLogOptions.ShouldWriteAgentDiag)
                                    IkeLogOptions.AppendAgentNdjson(
                                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                                        line);
                            }
                            catch { /* ignore */ }
                        }
                        // #endregion
                    }
                    catch (OperationCanceledException)
                    {
                        throw;
                    }
                    catch (Exception ex) when (IsUnauthorizedCloudKit(ex))
                    {
                        Interlocked.Increment(ref chunksDone);
                        NoteGatewayUnauthorized();
                        log?.Report(
                            $"  PrivilegedBatch chunk 401 ({chunkLocal.Count} seed) — " +
                            "refresh Anisette e ritento la stessa richiesta…");
                        if (!await RefreshAnisetteAsync("401 exception").ConfigureAwait(false))
                        {
                            log?.Report(
                                $"  ERROR PrivilegedBatch: skip chunk ({chunkLocal.Count} seed) — " +
                                "refresh Anisette non disponibile.");
                            return;
                        }

                        try
                        {
                            var (retryAssets, retryPayload, retryFail) = await QueryPrivilegedBatchChunkAsync(
                                session,
                                chunkLocal,
                                dir,
                                log,
                                ct,
                                Volatile.Read(ref _gatewayPaceMs),
                                allowPerSeedFallback).ConfigureAwait(false);
                            if (retryFail)
                            {
                                NoteGatewayUnauthorized();
                                log?.Report(
                                    $"  PrivilegedBatch chunk ancora 401 dopo refresh — skip ({chunkLocal.Count} seed)");
                                return;
                            }

                            NoteGatewayOk();
                            if (retryPayload is { Length: > 0 })
                            {
                                lock (lastPayloadLock)
                                    lastPayload = retryPayload;
                            }
                            foreach (var a in retryAssets)
                                assets[a.RecordName] = a;
                        }
                        catch (Exception retryEx)
                        {
                            log?.Report($"  PrivilegedBatch chunk retry: {retryEx.Message}");
                        }
                    }
                    catch (Exception ex)
                    {
                        Interlocked.Increment(ref chunksDone);
                        log?.Report(
                            $"  PrivilegedBatch chunk skip ({chunkLocal.Count} seed): " +
                            $"{ex.GetType().Name}: {ex.Message}");
                    }
                    finally
                    {
                        parallelGate.Release();
                    }
                }, ct));
            }
        }

        await Task.WhenAll(tasks).ConfigureAwait(false);
        refreshGate.Dispose();

        log?.Report($"  PrivilegedBatch harvest → {assets.Count} auth/asset");
        return (
            assets.Values.OrderBy(static a => a.RecordName, StringComparer.Ordinal).ToList(),
            lastPayload);
    }

    /// <summary>capture ~6–12 seed/query; 12 bilancia RTT vs 401.</summary>
    private const int PrivilegedBatchChunkSize = 12;
    /// <summary>Chunk PrivilegedBatch in parallelo per Domain (solo se pace=0).</summary>
    private const int PrivilegedBatchParallelism = 2;
    /// <summary>Soglia oltre la quale il fallback per-seed è troppo costoso (401).</summary>
    private const int PrivilegedBatchPerSeedMaxTotal = 48;
    /// <summary>Pace di base (Anisette ok): 0 — solo back-off dopo 401.</summary>
    private const int PrivilegedBatchPaceMs = 0;
    private const int PrivilegedBatchPaceLargeMs = 50;
    private const int PrivilegedBatchPaceMaxMs = 800;
    private const int PrivilegedBatchRefreshEveryChunks = 60;
    private const int PrivilegedBatchPostRefreshDelayMs = 300;
    /// <summary>Retry su IO/HttpRequest (connessione reset) — prima solo 401 aveva retry.</summary>
    private const int PrivilegedBatchTransportMaxAttempts = 3;
    private const int PrivilegedBatchTransportRetryBaseMs = 400;

    private async Task<(IReadOnlyList<BackupAsset> Assets, byte[]? Payload, bool HitUnauthorized)>
        QueryPrivilegedBatchChunkAsync(
        ICloudSession session,
        IReadOnlyList<string> chunk,
        string? dumpDir,
        IProgress<string>? log,
        CancellationToken ct,
        int paceMs,
        bool allowPerSeedFallback)
    {
        if (paceMs > 0)
            await Task.Delay(paceMs, ct).ConfigureAwait(false);
        byte[] payload;
        var hit401 = false;
        try
        {
            payload = await QueryFetchPayloadWithTransportRetryAsync(
                session, chunk, log, ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsUnauthorizedCloudKit(ex))
        {
            hit401 = true;
            // Non bumpare qui: un 401 recuperato dal retry non deve lasciare pace=800 globale.
            log?.Report($"  PrivilegedBatch ×{chunk.Count}: {ex.Message} — refresh e retry…");
            if (!await TryRefreshSessionAfterUnauthorizedAsync(session, log, ct)
                    .ConfigureAwait(false))
            {
                NoteGatewayUnauthorized();
                return ([], null, true);
            }

            try
            {
                await Task.Delay(PrivilegedBatchPostRefreshDelayMs, ct).ConfigureAwait(false);
                payload = await QueryFetchPayloadWithTransportRetryAsync(
                    session, chunk, log, ct).ConfigureAwait(false);
                hit401 = false; // retry ok
            }
            catch (Exception retryEx)
            {
                NoteGatewayUnauthorized();
                log?.Report($"  PrivilegedBatch ×{chunk.Count} retry: {retryEx.Message}");
                return ([], null, true);
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  PrivilegedBatch ×{chunk.Count}: {ex.Message}");
            return ([], null, false);
        }

        if (dumpDir is not null && payload.Length > 0)
        {
            try
            {
                var tag = $"multi_{chunk.Count}_{DateTime.UtcNow:HHmmssfff}";
                await File.WriteAllBytesAsync(
                    Path.Combine(dumpDir, $"query_{tag}.bin"), payload, ct).ConfigureAwait(false);
                var work = Directory.GetParent(dumpDir)?.FullName;
                if (!string.IsNullOrWhiteSpace(work))
                {
                    await FordOfflineDumpWriter.DumpCloudKitQueryAsync(
                        work, payload, chunk, tag, ct).ConfigureAwait(false);
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  PrivilegedBatch dump skip: {ex.GetType().Name}: {ex.Message}");
            }
        }

        List<BackupAsset> harvested;
        try
        {
            harvested = HarvestAssetsFromQueryPayload(payload, chunk);
            // H-WRAP5: wrap40 vive nei record A:/F: del batch, non nella finestra UUID.
            // Indicizza sempre (anche senza IKE_FORD_OFFLINE_DUMP).
            FordOfflineDumpWriter.AbsorbWrapsFromPayload(payload);
        }
        catch (Exception ex)
        {
            log?.Report($"  PrivilegedBatch harvest skip: {ex.GetType().Name}: {ex.Message}");
            return ([], payload, hit401);
        }
        if (harvested.Count > 0)
            return (harvested, payload, hit401);

        if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err))
        {
            if (!allowPerSeedFallback)
            {
                log?.Report(
                    $"  PrivilegedBatch ×{chunk.Count}: {err ?? "errore"} — " +
                    "skip per-seed (batch grande)");
                return ([], payload, hit401);
            }

            log?.Report(
                $"  PrivilegedBatch ×{chunk.Count}: {err ?? "errore"} — fallback per-seed");
            var (one, onePayload) = await QueryPrivilegedBatchPerSeedAsync(
                session, chunk, dumpDir, log, ct).ConfigureAwait(false);
            return (one, onePayload, hit401);
        }

        log?.Report($"  PrivilegedBatch ×{chunk.Count}: risposta senza CAog ({payload.Length} B)");
        return ([], payload, hit401);
    }

    private async Task<(IReadOnlyList<BackupAsset> Assets, byte[]? Payload)> QueryPrivilegedBatchPerSeedAsync(
        ICloudSession session,
        IReadOnlyList<string> seeds,
        string? dumpDir,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var assets = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        byte[]? lastOk = null;
        var hits = 0;
        var misses = 0;
        var refreshedOnce = false;

        foreach (var seed in seeds)
        {
            ct.ThrowIfCancellationRequested();
            await PaceGatewayAsync(ct).ConfigureAwait(false);
            byte[] payload;
            try
            {
                payload = await QueryFetchPayloadWithTransportRetryAsync(
                    session, [seed], log, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsUnauthorizedCloudKit(ex) && !refreshedOnce)
            {
                refreshedOnce = true;
                log?.Report($"  PrivilegedBatch per-seed 401 — refresh e retry…");
                if (!await TryRefreshSessionAfterUnauthorizedAsync(session, log, ct)
                        .ConfigureAwait(false))
                {
                    misses++;
                    continue;
                }

                try
                {
                    await PaceGatewayAsync(ct).ConfigureAwait(false);
                    payload = await QueryFetchPayloadWithTransportRetryAsync(
                        session, [seed], log, ct).ConfigureAwait(false);
                }
                catch
                {
                    misses++;
                    continue;
                }
            }
            catch
            {
                misses++;
                continue;
            }

            if (dumpDir is not null && payload.Length > 0)
            {
                var safe = SanitizeKeybagFileStem(seed);
                if (safe.Length > 80) safe = safe[..80];
                await File.WriteAllBytesAsync(
                    Path.Combine(dumpDir, $"query_one_{safe}.bin"), payload, ct)
                    .ConfigureAwait(false);
                var work = Directory.GetParent(dumpDir)?.FullName;
                if (!string.IsNullOrWhiteSpace(work))
                {
                    await FordOfflineDumpWriter.DumpCloudKitQueryAsync(
                        work, payload, [seed], $"one_{safe}", ct).ConfigureAwait(false);
                }
            }

            var got = HarvestAssetsFromQueryPayload(payload, [seed]);
            FordOfflineDumpWriter.AbsorbWrapsFromPayload(payload);
            if (got.Count == 0)
            {
                misses++;
                continue;
            }

            hits++;
            lastOk = payload;
            foreach (var a in got)
                assets[a.RecordName] = a;
        }

        if (hits > 0 || misses > 0)
            log?.Report($"  PrivilegedBatch per-seed: hit={hits} miss={misses} auth={assets.Count}");

        return (
            assets.Values.OrderBy(static a => a.RecordName, StringComparer.Ordinal).ToList(),
            lastOk);
    }

    private List<BackupAsset> HarvestAssetsFromQueryPayload(
        byte[] payload,
        IReadOnlyList<string>? queriedSeeds = null)
    {
        var assets = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        if (payload.Length == 0
            || CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _))
            return [];

        foreach (var a in ParseAssetsFromPayload(payload))
        {
            a.ZoneName = DefaultZone;
            a.RecordPayload ??= payload;
            if (string.IsNullOrWhiteSpace(a.RecordIdSuffix))
                a.RecordIdSuffix = CloudKitMmcsIds.ToRecordIdSuffix(a.RecordName);
            assets[a.RecordName] = a;
        }

        foreach (var auth in MmcsAuthBuilder.ExtractAllReadyMadeAuths(payload))
        {
            if (!MmcsAuthBuilder.TrySplitMmcsAuth(auth, out var sig, out _, out _))
                continue;
            var key = "sig:" + Convert.ToHexString(sig).ToLowerInvariant();
            if (assets.ContainsKey(key))
                continue;
            assets[key] = new BackupAsset
            {
                RecordName = key,
                ZoneName = DefaultZone,
                MmcsAuth = auth,
                AssetSignature = sig,
                RecordPayload = payload
            };
        }

        // Gap join: PB harvest spesso lascia CAog come sig:… senza rid.
        // Rilegga i seed interrogati e promuovi RecordName/RecordIdSuffix.
        if (queriedSeeds is { Count: > 0 })
            BindQueriedSeedsOntoHarvest(assets, queriedSeeds);

        return assets.Values.ToList();
    }

    /// <summary>
    /// Associa CAog orphan (<c>sig:…</c>) / record incompleti ai seed
    /// <c>A:pref4:rid</c> della query, così <c>AttachFetchedAuthToFlistAssets</c>
    /// può fare join rid-first (non solo signature).
    /// </summary>
    private static void BindQueriedSeedsOntoHarvest(
        Dictionary<string, BackupAsset> assets,
        IReadOnlyList<string> seeds)
    {
        if (assets.Count == 0 || seeds.Count == 0)
            return;

        var usableAuths = assets.Values
            .Where(static a =>
                !string.IsNullOrWhiteSpace(a.MmcsAuth)
                && a.MmcsAuth!.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length >= 3)
            .ToList();

        foreach (var seed in seeds)
        {
            if (string.IsNullOrWhiteSpace(seed)
                || CloudKitMmcsIds.IsUuidRecordName(seed))
                continue;

            var seedRid = CloudKitMmcsIds.ToRecordIdSuffix(seed);
            if (string.IsNullOrWhiteSpace(seedRid))
                continue;

            if (assets.TryGetValue(seed, out var already))
            {
                already.RecordIdSuffix ??= seedRid;
                // Seed già in harvest ma senza CAog: non skippare — bind orphan sotto.
                if (already.MmcsAuth is { Length: > 0 }
                    && already.MmcsAuth.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length >= 3)
                    continue;
            }

            BackupAsset? match = null;
            var seedTok = CloudKitMmcsIds.TryExtractRidToken(seedRid);
            var seedUuid = CloudKitMmcsIds.CkRecordNameFromRid(seedRid);
            foreach (var a in usableAuths)
            {
                var matchedEmbed = false;
                foreach (var variant in CloudKitMmcsIds.EnumerateAssetRecordNameVariants(seed))
                {
                    if (MmcsAuthBuilder.AuthMatchesRecord(a.MmcsAuth!, variant))
                    {
                        matchedEmbed = true;
                        break;
                    }
                }

                if (!matchedEmbed
                    && (MmcsAuthBuilder.AuthMatchesRecord(a.MmcsAuth!, seedRid)
                        || MmcsAuthBuilder.AuthMatchesRecord(a.MmcsAuth!, seed)))
                    matchedEmbed = true;

                if (matchedEmbed)
                {
                    match = a;
                    break;
                }

                var aRid = a.RecordIdSuffix ?? CloudKitMmcsIds.ToRecordIdSuffix(a.RecordName);
                if (aRid is not null
                    && string.Equals(aRid, seedRid, StringComparison.Ordinal))
                {
                    match = a;
                    break;
                }

                // Token match solo se stesso Domain UUID (niente cross-UUID EN collision).
                if (seedTok is { Length: >= 8 }
                    && !a.RecordName.StartsWith("sig:", StringComparison.OrdinalIgnoreCase)
                    && a.RecordName.Contains(seedTok, StringComparison.Ordinal))
                {
                    var aUuid = CloudKitMmcsIds.CkRecordNameFromRid(a.RecordName)
                        ?? CloudKitMmcsIds.CkRecordNameFromRid(aRid);
                    if (seedUuid is null
                        || aUuid is null
                        || string.Equals(seedUuid, aUuid, StringComparison.OrdinalIgnoreCase))
                    {
                        match = a;
                        break;
                    }
                }
            }

            // Chunk a un solo seed: se resta un solo CAog orphan, bind diretto.
            if (match is null
                && seeds.Count == 1
                && usableAuths.Count == 1
                && usableAuths[0].RecordName.StartsWith("sig:", StringComparison.OrdinalIgnoreCase))
            {
                match = usableAuths[0];
            }

            if (match is null)
                continue;

            match.RecordIdSuffix = seedRid;
            if (assets.TryGetValue(seed, out var existingSeed))
            {
                // Promuovi CAog sull'entry seed già presente (spesso senza auth).
                if (string.IsNullOrWhiteSpace(existingSeed.MmcsAuth)
                    && !string.IsNullOrWhiteSpace(match.MmcsAuth))
                    existingSeed.MmcsAuth = match.MmcsAuth;
                existingSeed.RecordIdSuffix ??= seedRid;
                if (existingSeed.AssetSignature is not { Length: 21 }
                    && match.AssetSignature is { Length: 21 })
                    existingSeed.AssetSignature = match.AssetSignature;
                if (existingSeed.RecordPayload is not { Length: > 32 }
                    && match.RecordPayload is { Length: > 32 })
                    existingSeed.RecordPayload = match.RecordPayload;
                continue;
            }

            if (match.RecordName.StartsWith("sig:", StringComparison.OrdinalIgnoreCase))
            {
                assets[seed] = new BackupAsset
                {
                    RecordName = seed,
                    RecordIdSuffix = seedRid,
                    ZoneName = match.ZoneName,
                    MmcsAuth = match.MmcsAuth,
                    AssetSignature = match.AssetSignature,
                    RecordPayload = match.RecordPayload,
                    SizeBytes = match.SizeBytes,
                    ProtectionClass = match.ProtectionClass,
                };
            }
            else
            {
                assets[seed] = match;
            }
        }
    }

    /// <summary> seed dello stesso Domain condividono l'UUID dopo <c>TYPE:pref4:</c>.</summary>
    private static List<List<string>> GroupSeedsByDomainUuid(IReadOnlyList<string> seeds)
    {
        var map = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        var orphan = new List<string>();
        foreach (var seed in seeds)
        {
            var uuid = CloudKitMmcsIds.CkRecordNameFromRid(seed);
            if (uuid is null)
            {
                orphan.Add(seed);
                continue;
            }

            if (!map.TryGetValue(uuid, out var list))
            {
                list = [];
                map[uuid] = list;
            }

            list.Add(seed);
        }

        var groups = map.Values
            .OrderByDescending(static g => g.Count)
            .ToList();
        if (orphan.Count > 0)
            groups.Add(orphan);
        return groups;
    }

    private static IEnumerable<List<T>> ChunkList<T>(IReadOnlyList<T> items, int size)
    {
        if (size <= 0) size = 8;
        for (var i = 0; i < items.Count; i += size)
        {
            var n = Math.Min(size, items.Count - i);
            var chunk = new List<T>(n);
            for (var j = 0; j < n; j++)
                chunk.Add(items[i + j]);
            yield return chunk;
        }
    }

    /// <summary>
    /// Ordine remount: nome originale, poi MA→KA→LA→NA→JA (size-class; MA prima di KA).
    /// </summary>
    public static IEnumerable<string> EnumerateTypeAlternates(string recordName)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            yield break;

        var name = recordName.Trim();
        yield return name;

        var colon = name.IndexOf(':');
        if (colon <= 0 || colon >= name.Length - 1)
            yield break;

        var current = name[..colon];
        var rest = name[(colon + 1)..];
        foreach (var t in CloudKitMmcsIds.EnumerateAlternateTypes(current))
            yield return t + ":" + rest;
    }

    /// <summary>
    /// Seed PrivilegedBatch: UUID flist (<c>rid.Split(':')[0]</c>) oppure
    /// nomi TYPE con suffisso <c>=:size</c>. Unifica duplicati preferendo la forma completa.
    /// </summary>
    public static List<string> NormalizeKaLaMaSeeds(IEnumerable<string> seedRecordNames)
    {
        var uuids = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var byBase = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var raw in seedRecordNames)
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;

            var name = raw.Trim();
            if (CloudKitMmcsIds.ToPrivilegedBatchWireName(name) is { } wire)
                name = wire;

            // FileID F:uuid:token:size: → CK recordName = uuid.
            if (name.StartsWith("F:", StringComparison.Ordinal))
            {
                var uuid = CloudKitMmcsIds.CkRecordNameFromRid(name);
                if (uuid is not null)
                    uuids.Add(uuid);
                continue;
            }

            if (CloudKitMmcsIds.IsUuidRecordName(name))
            {
                uuids.Add(name);
                continue;
            }

            // rid flist uuid:token=:size (senza A:) → CK uuid.
            if (!IsTypePrefixedAssetName(name))
            {
                var fromRid = CloudKitMmcsIds.CkRecordNameFromRid(name);
                if (fromRid is not null
                    && (CloudKitMmcsIds.IsUuidRecordName(name) || name.Contains(':', StringComparison.Ordinal)))
                {
                    uuids.Add(fromRid);
                    continue;
                }
            }

            if (!IsTypePrefixedAssetName(name))
                continue;

            var hasSize = HasAssetSizeSuffix(name);
            var bas = StripAssetSizeSuffix(name);
            if (!byBase.TryGetValue(bas, out var existing))
            {
                byBase[bas] = name;
                continue;
            }

            // Preferisci sempre la forma con =:N.
            if (!HasAssetSizeSuffix(existing) && hasSize)
                byBase[bas] = name;
        }

        var typed = byBase.Values
            .Where(HasAssetSizeSuffix)
            .OrderBy(static n => n, StringComparer.Ordinal);

        return uuids
            .OrderBy(static u => u, StringComparer.OrdinalIgnoreCase)
            .Concat(typed)
            .ToList();
    }

    private static bool IsTypePrefixedAssetName(string name) =>
        CloudKitMmcsIds.IsAssetRecordName(name);

    private static bool HasAssetSizeSuffix(string recordName)
    {
        var lastColon = recordName.LastIndexOf(':');
        if (lastColon <= 0 || lastColon >= recordName.Length - 1)
            return false;
        for (var j = lastColon + 1; j < recordName.Length; j++)
        {
            if (!char.IsAsciiDigit(recordName[j]))
                return false;
        }

        // Evita di scambiare il segmento dsid (fd77) per una size.
        return lastColon > 8 && recordName.AsSpan(lastColon + 1).Length > 0;
    }

    private static string StripAssetSizeSuffix(string recordName)
    {
        if (!HasAssetSizeSuffix(recordName))
            return recordName;
        return recordName[..recordName.LastIndexOf(':')];
    }

    private static List<(ProtectionZoneKeys Zone, string ZoneName)> UnwrapZonesLabeled(
        byte[] zonesPayload,
        IReadOnlyList<PcsCompactPrivateKey> seeds,
        bool includeLight = true)
    {
        var results = new List<(ProtectionZoneKeys, string)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var text = Encoding.Latin1.GetString(zonesPayload);

        foreach (var zoneName in new[] { DefaultZone, MbksyncZone })
        {
            var start = 0;
            while (true)
            {
                var idx = text.IndexOf(zoneName, start, StringComparison.Ordinal);
                if (idx < 0)
                    break;

                // Finestra dopo il nome zona: PI tipicamente subito dopo (~200–900 B).
                var from = Math.Max(0, idx - 32);
                var len = Math.Min(zonesPayload.Length - from, 1200);
                var window = zonesPayload.AsSpan(from, len).ToArray();
                foreach (var z in PcsProtectionZone.TryUnwrapAll(
                             window, seeds, includeLight: includeLight))
                {
                    var id = Convert.ToHexString(z.MasterKey);
                    if (!seen.Add(id))
                        continue;
                    results.Add((z, zoneName));
                }

                start = idx + zoneName.Length;
            }
        }

        // Catch-all iterativo sul payload intero: nested keys aprono PI secondari (fileList).
        foreach (var z in PcsProtectionZone.TryUnwrapAllIterative(
                     zonesPayload, seeds, includeLight: includeLight))
        {
            var id = Convert.ToHexString(z.MasterKey);
            if (!seen.Add(id))
                continue;
            var label = InferZoneNameNearPublic(zonesPayload, text, z.MasterPublicMatched);
            // Master da nested su PI senza nome zona vicino: tipicamente content _defaultZone.
            if (label == "unknown")
                label = DefaultZone;
            results.Add((z, label));
        }

        return results;
    }

    private static string InferZoneNameNearPublic(
        byte[] payload,
        string text,
        byte[] publicX)
    {
        var pubIdx = IndexOfBytes(payload, publicX);
        if (pubIdx < 0)
            return "unknown";
        var def = text.LastIndexOf(DefaultZone, pubIdx, StringComparison.Ordinal);
        var mbk = text.LastIndexOf(MbksyncZone, pubIdx, StringComparison.Ordinal);
        if (def < 0 && mbk < 0)
            return "unknown";
        return def >= mbk ? DefaultZone : MbksyncZone;
    }

    private static int IndexOfBytes(byte[] hay, byte[] needle)
    {
        if (needle.Length == 0 || hay.Length < needle.Length)
            return -1;
        for (var i = 0; i <= hay.Length - needle.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (hay[i + j] != needle[j])
                {
                    ok = false;
                    break;
                }
            }

            if (ok)
                return i;
        }

        return -1;
    }

    private void ConsiderCachedMaster(byte[] master, string source, string keyIdHex, string zoneName)
    {
        if (master.Length is not (16 or 32))
            return;
        var id = Convert.ToHexString(master);
        if (_cachedZoneMasters.Any(m => Convert.ToHexString(m.Master) == id))
            return;
        _cachedZoneMasters.Add((master, source, keyIdHex, zoneName));
    }

    private void TryPersistZoneMasters(
        string? outputDirectory,
        string? pcsKeysDirectory,
        IProgress<string>? log)
    {
        if (_cachedZoneMasters.Count == 0)
            return;

        var saved = false;
        foreach (var dir in DistinctExistingDirs(outputDirectory, pcsKeysDirectory))
        {
            try
            {
                var mastersDir = Path.Combine(dir, ZoneMastersDirectoryName);
                Directory.CreateDirectory(mastersDir);
                // Non cancellare mentre altri worker leggono: overwrite per nome stabile.
                var meta = new List<object>();
                for (var i = 0; i < _cachedZoneMasters.Count; i++)
                {
                    var (master, source, keyId, zoneName) = _cachedZoneMasters[i];
                    var shortId = keyId.Length >= 8 ? keyId[..8] : keyId;
                    var zoneTag = zoneName.Equals(DefaultZone, StringComparison.OrdinalIgnoreCase)
                        ? "default"
                        : zoneName.Equals(MbksyncZone, StringComparison.OrdinalIgnoreCase)
                            ? "mbksync"
                            : "unknown";
                    var name = $"master_{i:D2}_{zoneTag}_{shortId}.bin";
                    var path = Path.Combine(mastersDir, name);
                    using (var fs = new FileStream(
                               path, FileMode.Create, FileAccess.Write, FileShare.Read))
                        fs.Write(master, 0, master.Length);
                    meta.Add(new
                    {
                        index = i,
                        file = name,
                        keyId,
                        source,
                        zone = zoneName,
                        bytes = master.Length
                    });
                }

                File.WriteAllText(
                    Path.Combine(mastersDir, "masters_meta.json"),
                    JsonSerializer.Serialize(
                        new { count = meta.Count, masters = meta },
                        new JsonSerializerOptions { WriteIndented = true }));
                saved = true;
            }
            catch (Exception ex)
            {
                log?.Report($"  zone masters cache skip: {ex.Message}");
            }
        }

        if (saved)
            log?.Report($"  zone masters cache → {ZoneMastersDirectoryName}/ ({_cachedZoneMasters.Count})");
    }

    private void TryLoadZoneMastersFromDisk(
        string? outputDirectory,
        string? pcsKeysDirectory,
        IProgress<string>? log)
    {
        foreach (var dir in DistinctExistingDirs(outputDirectory, pcsKeysDirectory))
        {
            var mastersDir = Path.Combine(dir, ZoneMastersDirectoryName);
            if (!Directory.Exists(mastersDir))
                continue;

            try
            {
                var files = Directory.GetFiles(mastersDir, "master_*.bin").OrderBy(f => f).ToArray();
                if (files.Length == 0)
                    continue;

                // masters_meta.json ha KeyId completi (il filename ne tiene solo 8 hex).
                var fullKeyIds = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                var metaPath = Path.Combine(mastersDir, "masters_meta.json");
                if (File.Exists(metaPath))
                {
                    try
                    {
                        using var doc = JsonDocument.Parse(File.ReadAllText(metaPath));
                        if (doc.RootElement.TryGetProperty("masters", out var arr)
                            && arr.ValueKind == JsonValueKind.Array)
                        {
                            foreach (var m in arr.EnumerateArray())
                            {
                                var fileName = m.TryGetProperty("file", out var f)
                                    ? f.GetString()
                                    : null;
                                var keyId = m.TryGetProperty("keyId", out var k)
                                    ? k.GetString()
                                    : null;
                                if (!string.IsNullOrEmpty(fileName) && !string.IsNullOrEmpty(keyId))
                                    fullKeyIds[fileName] = keyId;
                            }
                        }
                    }
                    catch
                    {
                        // filename fallback sotto
                    }
                }

                var loaded = 0;
                foreach (var file in files)
                {
                    byte[] bytes;
                    try
                    {
                        using var fs = new FileStream(
                            file, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
                        bytes = new byte[fs.Length];
                        _ = fs.Read(bytes, 0, bytes.Length);
                    }
                    catch (IOException)
                    {
                        continue;
                    }

                    if (bytes.Length is not (16 or 32))
                        continue;
                    var stem = Path.GetFileNameWithoutExtension(file);
                    var fileName = Path.GetFileName(file);
                    // master_00_default_EF9ED308  |  master_00_EF9ED308 (legacy)
                    var parts = stem.Split('_');
                    var zoneName = "unknown";
                    var keyIdHint = "";
                    if (parts.Length >= 4)
                    {
                        zoneName = parts[2] switch
                        {
                            "default" => DefaultZone,
                            "mbksync" => MbksyncZone,
                            _ => parts[2]
                        };
                        keyIdHint = parts[^1];
                    }
                    else if (parts.Length >= 3)
                    {
                        keyIdHint = parts[^1];
                    }

                    if (fullKeyIds.TryGetValue(fileName, out var fullId))
                        keyIdHint = fullId;

                    ConsiderCachedMaster(bytes, "disk-cache", keyIdHint, zoneName);
                    loaded++;
                }

                if (loaded > 0)
                {
                    log?.Report(
                        $"  zone masters da cache locale → {_cachedZoneMasters.Count} ({ZoneMastersDirectoryName}/)");
                    return;
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  zone masters read skip: {ex.Message}");
            }
        }
    }

    private async Task PersistOrLoadMbksyncZonesAsync(
        string? outputDirectory,
        string? pcsKeysDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        TryLoadMbksyncZonesFromDisk(outputDirectory, pcsKeysDirectory, log);
        if (_bootstrapZonesPayload is not { Length: > 64 })
            return;

        var saved = false;
        foreach (var dir in DistinctExistingDirs(outputDirectory, pcsKeysDirectory))
        {
            var path = Path.Combine(dir, MbksyncZonesFileName);
            try
            {
                await File.WriteAllBytesAsync(path, _bootstrapZonesPayload, ct);
                saved = true;
            }
            catch (Exception ex)
            {
                log?.Report($"  zone/retrieve cache skip: {ex.Message}");
            }
        }

        if (saved)
        {
            log?.Report(
                $"  zone/retrieve cache → {MbksyncZonesFileName} ({_bootstrapZonesPayload.Length:N0} B)");
        }
    }

    private void TryPersistMbksyncZones(
        string? outputDirectory,
        string? pcsKeysDirectory,
        IProgress<string>? log)
    {
        if (_bootstrapZonesPayload is not { Length: > 64 })
            return;

        foreach (var dir in DistinctExistingDirs(outputDirectory, pcsKeysDirectory))
        {
            var path = Path.Combine(dir, MbksyncZonesFileName);
            try
            {
                File.WriteAllBytes(path, _bootstrapZonesPayload);
            }
            catch (Exception ex)
            {
                log?.Report($"  zone cache write skip: {ex.Message}");
            }
        }
    }

    private void TryLoadMbksyncZonesFromDisk(
        string? outputDirectory,
        string? pcsKeysDirectory,
        IProgress<string>? log)
    {
        if (_bootstrapZonesPayload is { Length: > 64 })
            return;

        foreach (var dir in DistinctExistingDirs(outputDirectory, pcsKeysDirectory))
        {
            var path = Path.Combine(dir, MbksyncZonesFileName);
            if (!File.Exists(path))
                continue;
            try
            {
                var bytes = File.ReadAllBytes(path);
                if (bytes.Length < 64)
                    continue;
                _bootstrapZonesPayload = bytes;
                log?.Report($"  zone/retrieve da cache locale → {bytes.Length:N0} B ({MbksyncZonesFileName})");
                return;
            }
            catch (Exception ex)
            {
                log?.Report($"  zone cache read skip: {ex.Message}");
            }
        }
    }

    private static IEnumerable<string> DistinctExistingDirs(params string?[] dirs)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var d in dirs)
        {
            if (string.IsNullOrWhiteSpace(d))
                continue;
            try
            {
                Directory.CreateDirectory(d);
            }
            catch
            {
                continue;
            }

            if (seen.Add(d))
                yield return d;
        }
    }

    /// <summary>
    /// Fase pre-Lock (20260721): zone → BackupAccount → D: → S:×N → mbs stub → Lock.
    /// </summary>
    private async Task BootstrapRestoreCatalogAsync(
        ICloudSession session,
        BackupDevice device,
        BackupSnapshot snapshot,
        IProgress<string>? log,
        CancellationToken ct)
    {
        log?.Report("CloudKit: bootstrap restore (pre-Lock)…");
        var restore = _restoreState ?? throw new InvalidOperationException("RestoreSessionState non inizializzato.");
        // Header Foreground+f30 richiesti da gateway; sostituiti se assorbiti da mbs/batch.
        restore.EnsureForeground(session, device);
        var ctx = restore.ToRequestContext();

        if (snapshot.CatalogPayload is { Length: > 256 } cachedSnapshot)
        {
            _bootstrapSnapshotPayload = cachedSnapshot;
            restore.TryAbsorbFromPayload(cachedSnapshot);
            CapturePreAuthSessionFromBatch(cachedSnapshot, restore);
            MergeCatalogPayload(device, cachedSnapshot);
            var listCn = CloudKitManifestChecksumParser.ParseCnEntries(cachedSnapshot).Count;
            log?.Report(
                $"  snapshot cached da lista → {cachedSnapshot.Length:N0} byte, {listCn} voci :CN:");
        }

        try
        {
            var zonesBody = CloudKitDelimitedRequest.BuildZoneRetrieve(
                session.CloudKitUserId, CloudKitDelimitedRequest.BackupZones, ctx);
            // recovery: FetchRecordZones su record/retrieve (non /zone/retrieve).
            byte[] zonesPayload;
            try
            {
                zonesPayload = await _gateway.RecordRetrieveZonesAsync(
                    session, zonesBody, ct, restore);
                log?.Report(
                    $"  record/retrieve FetchRecordZones OK ({zonesPayload.Length:N0} byte)");
            }
            catch (Exception exRecord)
            {
                log?.Report(
                    $"  record/retrieve FetchRecordZones skip: {exRecord.Message} — fallback zone/retrieve");
                zonesPayload = await _gateway.ZoneRetrieveAsync(session, zonesBody, ct, restore);
                log?.Report($"  zone/retrieve OK ({zonesPayload.Length:N0} byte)");
            }

            _bootstrapZonesPayload = zonesPayload;
            restore.TryAbsorbFromPayload(zonesPayload);
        }
        catch (Exception ex)
        {
            log?.Report($"  FetchRecordZones skip: {ex.Message}");
        }

        await PaceGatewayAsync(ct);

        var accountPayload = await TryFetchMbksyncRecordAsync(
            session, "BackupAccount", log, ct);
        if (accountPayload is { Length: > 0 })
        {
            restore.TryAbsorbFromPayload(accountPayload);
            log?.Report($"  BackupAccount → {accountPayload.Length:N0} byte");
        }

        await PaceGatewayAsync(ct);

        var deviceRecord = CloudKitRecordNames.DeviceRecord(device.DeviceUuid);
        _bootstrapDevicePayload = await TryFetchMbksyncRecordAsync(
            session, deviceRecord, log, ct, restorePhase: true);
        if (_bootstrapDevicePayload is { Length: > 0 })
        {
            MergeCatalogPayload(device, _bootstrapDevicePayload);
            log?.Report(
                $"  {deviceRecord} → {_bootstrapDevicePayload.Length:N0} byte, " +
                $"{device.Keybags.Count} keybag, {device.AssetHints.Count} hint");
        }
        else
        {
            log?.Report($"  {deviceRecord} non recuperato");
        }

        await PaceGatewayAsync(ct);

        // Conta solo :CN: file (non domainBase con UUID=snapshot) per decidere se bastano.
        var snapUuidForCn = CloudKitManifestChecksumParser.NormalizeSnapshotUuid(snapshot.RecordName);
        var cnReady = _bootstrapSnapshotPayload is { Length: > 0 }
            ? CloudKitManifestChecksumParser.ParseFileCnEntries(
                _bootstrapSnapshotPayload, snapUuidForCn).Count
            : 0;
        const int EnoughCnForPreAuth = 500;

        //  un solo batch S:×N. Se la lista ha già i file UUID, non rifetchare.
        if (cnReady >= EnoughCnForPreAuth)
        {
            log?.Report(
                $"  batch S: skip (già {cnReady} :CN: file UUID — non ridondante)");
        }
        else
        {
            log?.Report("CloudKit: batch S: (pre-Lock)…");
            await TryFetchSnapshotBatchAsync(session, device, snapshot, log, ct);
        }

        //  mbs stub opzionale; basta se abbiamo abbastanza :CN: file UUID.
        cnReady = CloudKitManifestChecksumParser.ParseFileCnEntries(
            _bootstrapSnapshotPayload, snapUuidForCn).Count;
        if (cnReady >= EnoughCnForPreAuth)
        {
            log?.Report("  mbs skip (manifest :CN: file già da gateway S:)");
        }
        else
        {
            _bootstrapMbsPayload = await FetchMbsManifestBestAsync(session, log, ct);
            if (_bootstrapMbsPayload is { Length: > 256 })
            {
                restore.TryAbsorbFromPayload(_bootstrapMbsPayload);
                CapturePreAuthSessionFromBatch(_bootstrapMbsPayload, restore);
                log?.Report($"  mbs → {_bootstrapMbsPayload.Length:N0} byte");
            }
            else
            {
                log?.Report(
                    _bootstrapMbsPayload is { Length: > 0 }
                        ? $"  mbs stub ({_bootstrapMbsPayload.Length} B)"
                        : "  mbs assente");
            }
        }

        var cnAfterBatch = CloudKitManifestChecksumParser.ParseCnEntries(
            _bootstrapDevicePayload, _bootstrapSnapshotPayload, _bootstrapMbsPayload).Count;
        // Non rifetchare S: uno-a-uno: 110 KB con ~800 :CN: basta per PreAuth .
        if (cnAfterBatch < EnoughCnForPreAuth)
            await EnrichSnapshotPayloadForManifestAsync(session, device, snapshot, log, ct);

        var cnEntries = CloudKitManifestChecksumParser.ParseCnEntries(
            _bootstrapDevicePayload, _bootstrapSnapshotPayload, _bootstrapMbsPayload);
        var snapUuid = CloudKitManifestChecksumParser.NormalizeSnapshotUuid(snapshot.RecordName);
        var fileCn = CloudKitManifestChecksumParser.ParseFileCnEntries(
            _bootstrapSnapshotPayload, snapUuid);
        if (cnEntries.Count > 0)
            log?.Report(
                $"  manifestChecksums → {cnEntries.Count} voci :CN:" +
                (fileCn.Count != cnEntries.Count
                    ? $" ({fileCn.Count} file UUID per EN:, escluso domainBase)"
                    : ""));
        else
            log?.Report("  manifestChecksums (:CN:) assente — verifica fetch S: batch");

        // Catalogo deterministico / EN: devono usare il batch S: (file UUID), non la cache lista.
        SyncSnapshotCatalogPayload(snapshot, log);

        await PaceGatewayAsync(ct);

        if (_bootstrapSnapshotPayload is { Length: > 256 })
        {
            foreach (var name in MbsManifestParser.ExtractAssetRecordNames(_bootstrapSnapshotPayload))
                device.AssetHints.Add(name);
            log?.Report($"  batch hint → {device.AssetHints.Count} totali");
        }
    }

    private void SyncSnapshotCatalogPayload(BackupSnapshot snapshot, IProgress<string>? log)
    {
        if (_bootstrapSnapshotPayload is not { Length: > 256 })
            return;

        var current = snapshot.CatalogPayload;
        if (current is { Length: > 0 } && current.Length >= _bootstrapSnapshotPayload.Length)
        {
            // Preferisci comunque il bootstrap se ha più :CN: file (batch vs domainBase lista).
            var snapUuid = CloudKitManifestChecksumParser.NormalizeSnapshotUuid(snapshot.RecordName);
            var currentFile = CloudKitManifestChecksumParser.ParseFileCnEntries(current, snapUuid).Count;
            var bootFile = CloudKitManifestChecksumParser.ParseFileCnEntries(
                _bootstrapSnapshotPayload, snapUuid).Count;
            if (bootFile <= currentFile)
                return;
        }

        snapshot.CatalogPayload = _bootstrapSnapshotPayload;
        log?.Report(
            $"  CatalogPayload ← bootstrap S: ({_bootstrapSnapshotPayload.Length:N0} byte) " +
            "per catalogo/EN:");
    }

    private async Task<byte[]?> FetchMbsManifestBestAsync(
        ICloudSession session,
        IProgress<string>? log,
        CancellationToken ct)
    {
        try
        {
            return await _mbs.GetAccountManifestBestAsync(session, ct, log);
        }
        catch (Exception ex)
        {
            log?.Report($"  mbs skip: {ex.Message}");
            return null;
        }
    }

    private async Task TryFetchSnapshotBatchAsync(
        ICloudSession session,
        BackupDevice device,
        BackupSnapshot snapshot,
        IProgress<string>? log,
        CancellationToken ct)
    {
        const int MinBatchBytes = 400_000;

        var canonicalNames = new List<string>();
        foreach (var snap in device.Snapshots)
        {
            if (string.IsNullOrWhiteSpace(snap.RecordName))
                continue;

            var canonical = CloudKitRecordNames.CanonicalSnapshotRecordName(snap.RecordName);
            if (!canonicalNames.Contains(canonical, StringComparer.Ordinal))
                canonicalNames.Add(canonical);
        }

        if (!string.IsNullOrWhiteSpace(snapshot.RecordName))
        {
            var target = CloudKitRecordNames.CanonicalSnapshotRecordName(snapshot.RecordName);
            if (!canonicalNames.Contains(target, StringComparer.Ordinal))
                canonicalNames.Add(target);
        }

        if (canonicalNames.Count == 0)
            return;

        var restore = _restoreState ?? throw new InvalidOperationException("RestoreSessionState non inizializzato.");
        restore.TryAbsorbFromPayload(_bootstrapDevicePayload);

        // retrieve batch usa S:uuid (Canonical). &S: in Device response è solo riferimento.
        byte[]? best = null;
        string? bestLabel = null;

        log?.Report($"CloudKit: batch fetch S:×{canonicalNames.Count} (pre-Lock)…");
        var sPayload = await TryFetchMbksyncRecordsBatchAsync(session, canonicalNames, restore, log, ct);
        AbsorbSnapshotBatchPayload(sPayload, restore, log, "S:");
        if (IsBetterSnapshotBatch(sPayload, best))
        {
            best = sPayload;
            bestLabel = "S:";
        }

        if (best is not { Length: > 256 })
        {
            log?.Report("  batch snapshot risposta troppo piccola");
            return;
        }

        log?.Report(
            best.Length >= MinBatchBytes
                ? $"  batch {bestLabel} → {best.Length:N0} byte (manifest completo)"
                : $"  batch {bestLabel} → {best.Length:N0} byte (< {MinBatchBytes:N0}, manifest ridotto)");

        if (_bootstrapSnapshotPayload is null || best.Length > _bootstrapSnapshotPayload.Length)
        {
            _bootstrapSnapshotPayload = best;
            MergeCatalogPayload(device, best);
            snapshot.CatalogPayload = best;
            log?.Report($"  batch snapshot → {best.Length:N0} byte");
        }
        else if (snapshot.CatalogPayload is not { Length: > 256 }
                 || snapshot.CatalogPayload.Length < best.Length)
        {
            // Batch non batte bootstrap già tenuto, ma aggiorna comunque la cache lista corta.
            snapshot.CatalogPayload = _bootstrapSnapshotPayload;
        }
    }

    private static bool IsBetterSnapshotBatch(byte[]? candidate, byte[]? current)
    {
        if (candidate is not { Length: > 256 })
            return false;

        return current is null || candidate.Length > current.Length;
    }

    private static void AbsorbSnapshotBatchPayload(
        byte[]? payload,
        RestoreSessionState restore,
        IProgress<string>? log,
        string label)
    {
        if (payload is null)
            return;

        restore.TryAbsorbFromPayload(payload);
        CapturePreAuthSessionFromBatch(payload, restore);

        var foreground = ForegroundRestorePlistExtractor.Extract(payload);
        if (foreground is null)
            return;

        var synth = restore.ForegroundIsSynthetic ? "sintetico" : "ike-static";
        log?.Report(
            $"  Foreground da batch {label} (hw={foreground.HardwareIdHex[..Math.Min(12, foreground.HardwareIdHex.Length)]}…, {synth})");
    }

    private async Task TryAbsorbForegroundFromSnapshotsAsync(
        ICloudSession session,
        IReadOnlyList<string> canonicalNames,
        RestoreSessionState restore,
        IProgress<string>? log,
        CancellationToken ct)
    {
        foreach (var name in canonicalNames.Take(2))
        {
            var payload = await TryFetchMbksyncRecordAsync(session, name, log, ct, restorePhase: true);
            if (payload is not { Length: > 256 })
                continue;

            restore.TryAbsorbFromPayload(payload);
            if (!restore.ForegroundIsSynthetic)
            {
                log?.Report($"  Foreground assorbito da {name}");
                return;
            }
        }
    }

    private static void CapturePreAuthSessionFromBatch(byte[] payload, RestoreSessionState restore)
    {
        var wscPrefix = UbChunkCatalogParser.TryExtractWscSessionPrefix(payload);
        if (wscPrefix is not null)
            restore.CapturePreAuthWscPrefix(wscPrefix);

        var sessionBlob = UbChunkCatalogParser.TryExtractPreAuthSessionBlob(payload);
        if (sessionBlob is not null)
            restore.CapturePreAuthSessionBlob(sessionBlob);

        var sessionFrame = UbChunkCatalogParser.TryExtractForegroundSessionFrame(payload);
        if (sessionFrame is not null)
            restore.CapturePreAuthHeader(sessionFrame);
    }

    private async Task EnrichSnapshotPayloadForManifestAsync(
        ICloudSession session,
        BackupDevice device,
        BackupSnapshot snapshot,
        IProgress<string>? log,
        CancellationToken ct)
    {
        const int MinManifestBytes = 400_000;
        if (_bootstrapSnapshotPayload is { Length: >= MinManifestBytes })
            return;

        byte[]? best = _bootstrapSnapshotPayload;
        foreach (var snap in device.Snapshots)
        {
            if (string.IsNullOrWhiteSpace(snap.RecordName))
                continue;

            var canonical = CloudKitRecordNames.CanonicalSnapshotRecordName(snap.RecordName);
            byte[]? snapPayload = null;
            foreach (var candidate in CloudKitRecordNames.ListFetchCandidates(canonical))
            {
                var payload = await TryFetchMbksyncRecordAsync(session, candidate, log, ct, restorePhase: true);
                if (payload is not { Length: > 256 })
                    continue;

                if (snapPayload is null || payload.Length > snapPayload.Length)
                    snapPayload = payload;

                if (payload.Length >= 400_000)
                    break;
            }

            if (snapPayload is not { Length: > 256 })
                continue;

            if (best is null || snapPayload.Length > best.Length)
                best = snapPayload;
        }

        if (best is not null
            && (_bootstrapSnapshotPayload is null || best.Length > _bootstrapSnapshotPayload.Length))
        {
            _bootstrapSnapshotPayload = best;
            snapshot.CatalogPayload = best;
            log?.Report($"  snapshot manifest arricchito → {best.Length:N0} byte");
        }
    }

    private static List<string> BuildManifestDPathBatch(
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries,
        IReadOnlyList<string> discoveredNames)
    {
        const int MaxBatchPaths = 320;
        var batch = new List<string>(Math.Min(cnEntries.Count, MaxBatchPaths));
        foreach (var entry in cnEntries)
        {
            var checksum = CloudKitManifestChecksumParser.CleanCnChecksum(entry.ChecksumBase64);
            if (string.IsNullOrWhiteSpace(checksum))
                continue;

            batch.Add($"D:{checksum}:0");
            if (batch.Count >= MaxBatchPaths)
                break;
        }

        if (batch.Count >= 8)
            return batch;

        foreach (var name in discoveredNames)
        {
            if (!name.StartsWith("D:", StringComparison.Ordinal))
                continue;
            if (batch.Contains(name, StringComparer.Ordinal))
                continue;
            batch.Add(name);
            if (batch.Count >= MaxBatchPaths)
                break;
        }

        return batch;
    }

    private static QueryDiscoveryResult MergeDiscoveryResults(
        QueryDiscoveryResult? existing,
        QueryDiscoveryResult incoming)
    {
        if (existing is null)
            return incoming;

        var names = new HashSet<string>(existing.RecordNames, StringComparer.Ordinal);
        foreach (var name in incoming.RecordNames)
            names.Add(name);

        var assets = existing.Assets.ToDictionary(static a => a.RecordName, StringComparer.Ordinal);
        foreach (var asset in incoming.Assets)
            assets[asset.RecordName] = asset;

        return new QueryDiscoveryResult(
            names.OrderBy(static n => n, StringComparer.Ordinal).ToList(),
            assets.Values.OrderBy(static a => a.RecordName, StringComparer.Ordinal).ToList());
    }

    private static void MergeCatalogPayload(BackupDevice device, byte[] payload)
    {
        foreach (var bag in CloudKitResponseParser.ExtractKeybags(payload))
        {
            if (!device.Keybags.Contains(bag, StringComparer.Ordinal))
                device.Keybags.Add(bag);
        }

        foreach (var name in CloudKitResponseParser.ExtractAssetRecordNames(payload))
            device.AssetHints.Add(name);

        foreach (var path in CloudKitMmcsBatchBuilder.ExtractSignedPaths(payload))
            device.AssetHints.Add(path);
    }

    private async Task<byte[]?> TryFetchMbksyncRecordAsync(
        ICloudSession session,
        string recordName,
        IProgress<string>? log,
        CancellationToken ct,
        bool restorePhase = false)
    {
        const int MinFullRecordBytes = 256;
        byte[]? best = null;
        string? bestCandidate = null;
        RestoreRequestContext? ctx = null;
        if (restorePhase && _restoreState is not null)
            ctx = _restoreState.ToRequestContext();

        var candidates = CloudKitRecordNames.ListFetchCandidates(recordName);

        foreach (var candidate in candidates)
        {
            try
            {
                var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
                    session.CloudKitUserId, MbksyncZone, [candidate], ctx);
                var payload = await _gateway.RecordRetrieveAsync(
                    session, body, ct, restorePhase ? _restoreState : null);
                if (restorePhase)
                    _restoreState?.TryAbsorbFromPayload(payload);
                if (payload.Length == 0)
                    continue;

                if (payload.Length < MinFullRecordBytes)
                {
                    var hint = CloudKitResponseParser.DescribeCompactPayload(payload);
                    log?.Report($"  fetch {candidate} → {payload.Length} byte (stub?{ (hint is null ? "" : $" {hint}") })");
                }

                if (best is null || payload.Length > best.Length)
                {
                    best = payload;
                    bestCandidate = candidate;
                }

                if (payload.Length >= MinFullRecordBytes)
                    break;
            }
            catch (Exception ex)
            {
                log?.Report($"  fetch {candidate} skip: {ex.Message}");
            }
        }

        if (best is not null && bestCandidate is not null && best.Length >= MinFullRecordBytes)
            log?.Report($"  fetch ok {bestCandidate} ({best.Length:N0} byte)");

        return best;
    }

    private async Task<byte[]?> TryFetchMbksyncRecordsBatchAsync(
        ICloudSession session,
        IReadOnlyList<string> recordNames,
        RestoreSessionState restore,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (recordNames.Count == 0)
            return null;

        try
        {
            var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
                session.CloudKitUserId, MbksyncZone, recordNames, restore.ToRequestContext());
            var payload = await _gateway.RecordRetrieveAsync(session, body, ct, restore);
            if (payload.Length < 256)
            {
                var hint = CloudKitResponseParser.DescribeCompactPayload(payload);
                log?.Report($"  batch fetch → {payload.Length} byte (stub?{ (hint is null ? "" : $" {hint}") })");
            }
            else
            {
                log?.Report($"  batch fetch ok ({payload.Length:N0} byte, {recordNames.Count} record)");
            }

            return payload;
        }
        catch (Exception ex)
        {
            log?.Report($"  batch fetch skip: {ex.Message}");
            return null;
        }
    }

    /// <summary>
    /// Pace CloudKit: default 0. Solo dopo 401 sale (max <see cref="PrivilegedBatchPaceMaxMs"/>).
    /// Prima era Delay(500) fisso → FL grandi lentissimi.
    /// </summary>
    private int _gatewayPaceMs;
    /// <summary>1 = refresh Anisette fallito; ritenta dopo <see cref="AnisetteRefreshCooldownMs"/>.</summary>
    private int _anisetteRefreshFailed;
    private long _anisetteRefreshFailedAtMs;
    private const int AnisetteRefreshCooldownMs = 60_000;

    private Task PaceGatewayAsync(CancellationToken ct)
    {
        var ms = Volatile.Read(ref _gatewayPaceMs);
        return ms > 0 ? Task.Delay(ms, ct) : Task.CompletedTask;
    }

    private void NoteGatewayUnauthorized()
    {
        while (true)
        {
            var cur = Volatile.Read(ref _gatewayPaceMs);
            var next = Math.Min(Math.Max(cur, 250) + 250, PrivilegedBatchPaceMaxMs);
            if (Interlocked.CompareExchange(ref _gatewayPaceMs, next, cur) == cur)
            {
                // #region agent log
                try
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "pb-pace-fix",
                        ["hypothesisId"] = "H-PB-PACE",
                        ["location"] = "NoteGatewayUnauthorized",
                        ["message"] = "pace_bump",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new { cur, next },
                    });
                    if (IkeLogOptions.ShouldWriteAgentDiag)
                        IkeLogOptions.AppendAgentNdjson(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                            line);
                }
                catch { /* ignore */ }
                // #endregion
                return;
            }
        }
    }

    private void NoteGatewayOk()
    {
        var cur = Volatile.Read(ref _gatewayPaceMs);
        if (cur == 0)
            return;
        // Dopo successo torniamo a 0 (non pacea a vuoto).
        Volatile.Write(ref _gatewayPaceMs, 0);
        // #region agent log
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "pb-pace-fix",
                ["hypothesisId"] = "H-PB-PACE",
                ["location"] = "NoteGatewayOk",
                ["message"] = "pace_clear",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new { clearedFrom = cur },
            });
            if (IkeLogOptions.ShouldWriteAgentDiag)
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
        }
        catch { /* ignore */ }
        // #endregion
    }

    /// <summary>
    /// query/retrieve iniziale usa seed KA: (poi MA:). JA: non è seed di partenza.
    /// </summary>
    private static List<string> SelectQuerySeeds(CloudKitPreAuthResult preAuth)
    {
        var pool = preAuth.QuerySeeds.Count > 0
            ? preAuth.QuerySeeds
            : preAuth.RecordNames;
        return SelectQuerySeedsFromNames(pool);
    }

    private static List<string> SelectQuerySeedsFromNames(IEnumerable<string> names)
    {
        const int MaxKaSeeds = 8;

        static IEnumerable<string> OfPrefix(IEnumerable<string> pool, string prefix) =>
            pool.Where(n => n.StartsWith(prefix, StringComparison.Ordinal))
                .OrderBy(static n => n, StringComparer.Ordinal);

        var list = names
            .Where(static n => !string.IsNullOrWhiteSpace(n))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var ka = OfPrefix(list, "KA:").Take(MaxKaSeeds).ToList();
        if (ka.Count > 0)
            return ka;

        var ma = OfPrefix(list, "MA:").Take(MaxKaSeeds).ToList();
        if (ma.Count > 0)
            return ma;

        // Ultimo fallback: priorità parser, mai JA: come unico head se esiste KA altrove.
        return list
            .Where(static n =>
                n.StartsWith("KA:", StringComparison.Ordinal)
                || n.StartsWith("MA:", StringComparison.Ordinal)
                || n.StartsWith("LA:", StringComparison.Ordinal)
                || n.StartsWith("NA:", StringComparison.Ordinal))
            .OrderBy(static n => n.StartsWith("KA:", StringComparison.Ordinal) ? 0
                : n.StartsWith("MA:", StringComparison.Ordinal) ? 1
                : n.StartsWith("LA:", StringComparison.Ordinal) ? 2 : 3)
            .ThenBy(static n => n, StringComparer.Ordinal)
            .Take(MaxKaSeeds)
            .ToList();
    }

    /// <summary>
    ///  POST …/authorizeGet subito dopo PreAuth2, prima delle query.
    /// Gli header x-apple-mmcs-auth (f2/f5/f17) arrivano già dalla PreAuth.
    /// </summary>
    private async Task TryAuthorizeGetFromPreAuthAsync(
        ICloudSession session,
        BackupDevice device,
        CloudKitPreAuthResult preAuth,
        IProgress<string>? log,
        CancellationToken ct)
    {
        log?.Report(
            $"  PreAuth download hints → {preAuth.Catalog.SignedChunks.Count} chunk, " +
            $"{preAuth.Catalog.MmcsAuths.Count} auth strutturati f2/f5/f17");

        var auth = preAuth.Catalog.MmcsAuths.Values.FirstOrDefault(static a =>
            a.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length >= 3);
        if (string.IsNullOrWhiteSpace(auth))
        {
            log?.Report(
                "  authorizeGet skip: manca x-apple-mmcs-auth firmato (f2/f5/f17) in PreAuth.");
            return;
        }

        try
        {
            var contentHost = $"https://{session.Partition}-content.icloud.com";
            var authBody = await AuthorizeGetRawAsync(session, contentHost, auth, DefaultZone, ct);
            if (authBody is not { Length: > 0 })
            {
                log?.Report("  authorizeGet HTTP non-OK o body vuoto");
                return;
            }

            var chunks = UbChunkBuilder.ParseAuthorizeGetResponse(authBody);
            log?.Report(
                $"  authorizeGet OK → {authBody.Length:N0} byte, {chunks.Count} chunk edge");

            if (chunks.Count == 0)
                return;

            try
            {
                var probe = await DownloadProbeChunksAsync(chunks, log, ct);
                if (probe.ByteLength > 0)
                {
                    log?.Report(
                        $"  edge probe OK → {probe.ByteLength:N0} byte, " +
                        $"{probe.RecordNames.Count} nomi, {probe.Keybags.Count} keybag");
                    foreach (var name in probe.RecordNames)
                        device.AssetHints.Add(name);
                    foreach (var bag in probe.Keybags)
                    {
                        if (!device.Keybags.Contains(bag, StringComparer.Ordinal))
                            device.Keybags.Add(bag);
                    }
                }
            }
            catch (Exception edgeEx)
            {
                // Auth è comunque valido: non bloccare il restore per un edge header malformato.
                log?.Report($"  edge probe skip (auth tenuto): {edgeEx.Message}");
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  authorizeGet skip: {ex.Message}");
        }
    }

    private async Task<byte[]?> AuthorizeGetRawAsync(
        ICloudSession session,
        string contentHost,
        string mmcsAuth,
        string zoneName,
        CancellationToken ct)
    {
        var url = $"{contentHost}/{session.Dsid}/authorizeGet";
        var body = UbChunkBuilder.BuildAuthorizeGetRequest(mmcsAuth);

        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType =
            new MediaTypeHeaderValue("application/vnd.com.apple.me.ubchunk+protobuf");
        request.Headers.TryAddWithoutValidation("Accept", "application/vnd.com.apple.me.ubchunk+protobuf");
        request.Headers.TryAddWithoutValidation("x-apple-mme-dsid", session.Dsid);
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-proto-version", "4.0");
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-dataclass", "com.apple.Dataclass.CloudKit");
        request.Headers.TryAddWithoutValidation("X-CloudKit-Container", "com.apple.backup.ios");
        request.Headers.TryAddWithoutValidation("X-CloudKit-Zones", zoneName == MbksyncZone ? MbksyncZone : DefaultZone);
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-auth", mmcsAuth);
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.MmcsUserAgent);
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", AppleClientInfo.CloudKitDaemonClientInfo);

        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
            return null;
        return await response.Content.ReadAsByteArrayAsync(ct);
    }

    private async Task<ManifestProbeResult> DownloadProbeChunksAsync(
        IReadOnlyList<SignedUrlChunk> chunks,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var tempFile = Path.Combine(Path.GetTempPath(), $"ick_manifest_{Guid.NewGuid():N}.bin");
        try
        {
            await Services.Download.BackupDownloadService.DownloadChunksAsync(
                tempFile, chunks, 1, 1, null, ct, _http);
            var data = await File.ReadAllBytesAsync(tempFile, ct);
            var found = CloudKitResponseParser.ExtractAssetRecordNames(data);
            var keybags = CloudKitResponseParser.ExtractKeybags(data);
            return new ManifestProbeResult(found, keybags, data.Length);
        }
        finally
        {
            if (File.Exists(tempFile))
                File.Delete(tempFile);
        }
    }

    public async Task<IReadOnlyList<BackupAsset>> DiscoverAssetsAsync(
        ICloudSession session,
        BackupDevice device,
        BackupSnapshot snapshot,
        int? maxAssets = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var recordNames = new HashSet<string>(StringComparer.Ordinal);

        foreach (var hint in device.AssetHints)
            recordNames.Add(hint);

        var catalogAssets = BackupManifestBuilder.FromRecordNames(recordNames);
        log?.Report(
            $"catalogo PreAuth/hint → {catalogAssets.Count:N0} record asset " +
            $"(KA/MA/LA/NA/JA) — base del Manifest");

        log?.Report("mbs: probe account (spesso stub, non il file list)…");
        try
        {
            var manifest = await _mbs.GetAccountManifestAsync(session, ct);
            var before = recordNames.Count;
            if (manifest.Length < 64)
            {
                log?.Report($"  mbs stub → {manifest.Length} byte (nessuna lista file)");
            }
            else
            {
                foreach (var name in MbsManifestParser.ExtractAssetRecordNames(manifest))
                    recordNames.Add(name);
                log?.Report(
                    $"  mbs → {manifest.Length:N0} byte, +{recordNames.Count - before} nomi " +
                    $"(totale {recordNames.Count:N0})");
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  mbs skip: {ex.Message}");
        }

        //  query BFS parte da pochi seed KA:, non da tutto il catalogo PreAuth (~20k).
        var bfsSeeds = SelectQuerySeedsFromNames(recordNames);
        log?.Report($"CloudKit: query BFS da {bfsSeeds.Count} seed KA: (non {recordNames.Count:N0} candidati)…");
        await PaceGatewayAsync(ct);
        QueryDiscoveryResult bfs;
        try
        {
            bfs = await _query.DiscoverViaBatchFetchBfsAsync(
                session, bfsSeeds, log, _restoreState, ct, maxFetches: 8);
        }
        catch (Exception ex) when (ex.Message.Contains("401", StringComparison.Ordinal))
        {
            log?.Report($"  query BFS abort (401): {ex.Message}");
            bfs = new QueryDiscoveryResult([], []);
        }

        foreach (var name in bfs.RecordNames)
            recordNames.Add(name);

        // Con catalogo PreAuth ricco non serve scan D:/S: né espansione LA/NA (erano il flood 401).
        var catalogRich = BackupManifestBuilder.FromRecordNames(recordNames).Count >= 500;
        if (!catalogRich)
        {
            try
            {
                await PaceGatewayAsync(ct);
                await ScanCloudKitRecordAsync(session,
                    CloudKitRecordNames.DeviceRecord(device.DeviceUuid),
                    MbksyncZone, recordNames, device, log, ct);

                if (!string.IsNullOrWhiteSpace(snapshot.RecordName))
                {
                    await ScanCloudKitRecordAsync(session,
                        CloudKitRecordNames.CanonicalSnapshotRecordName(snapshot.RecordName),
                        MbksyncZone, recordNames, device, log, ct);
                }

                await ExpandListingAssetsRecursiveAsync(session, recordNames, log, ct);
            }
            catch (Exception ex) when (ex.Message.Contains("401", StringComparison.Ordinal))
            {
                log?.Report($"  scan/listing abort (401): {ex.Message}");
            }
        }
        else
        {
            log?.Report("  scan D:/S: + listing LA/NA skip (catalogo PreAuth già sufficiente)");
        }

        if (!catalogRich)
        {
            // Vecchio probe via snapshot.MmcsAuth rimosso: S: non espone auth MMCS;
            // Manifest è locale (:CN:) e gli auth arrivano da PreAuth f2.
            await ProbeDiscoveredAssetManifestsAsync(session, device, recordNames, bfs.Assets, log, ct);
        }

        PruneShadowAssetNames(recordNames);

        var assetsByName = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);

        // Manifest: tutti i record catalogo (anche senza auth) — base scaricabile appena arriva MMCS.
        foreach (var catalogAsset in BackupManifestBuilder.FromRecordNames(recordNames))
            assetsByName[catalogAsset.RecordName] = catalogAsset;

        foreach (var asset in bfs.Assets)
            assetsByName[asset.RecordName] = asset;

        // Gli x-apple-mmcs-auth sono già in PreAuth (f2/f5/f17): agganciarli agli asset.
        var preAuthAttached = 0;
        var orphanAuths = new List<string>();
        var catalogHasNamedAssets = assetsByName.Keys.Any(static k =>
            k.StartsWith("MA:", StringComparison.Ordinal)
            || k.StartsWith("KA:", StringComparison.Ordinal));

        foreach (var (key, header) in _preAuthCatalog.MmcsAuths)
        {
            if (header.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length < 3)
                continue;

            if (assetsByName.TryGetValue(key, out var existing))
            {
                if (string.IsNullOrWhiteSpace(existing.MmcsAuth))
                {
                    existing.MmcsAuth = header;
                    preAuthAttached++;
                }
            }
            else if (key.StartsWith("MA:", StringComparison.Ordinal)
                     || key.StartsWith("KA:", StringComparison.Ordinal)
                     || key.StartsWith("LA:", StringComparison.Ordinal)
                     || key.StartsWith("NA:", StringComparison.Ordinal))
            {
                assetsByName[key] = new BackupAsset
                {
                    RecordName = key,
                    ZoneName = DefaultZone,
                    SizeBytes = UbChunkBuilder.ExtractDeclaredSize(key),
                    MmcsAuth = header
                };
                preAuthAttached++;
            }
            else if (!catalogHasNamedAssets)
            {
                // Solo se non abbiamo KA:/MA: in catalogo: altrimenti i MMCS: orfani
                // monopolizzano MaxAssets e Manifest.db non viene mai scaricato.
                var name = key.Contains(':', StringComparison.Ordinal) ? key : $"MMCS:{key}";
                assetsByName[name] = new BackupAsset
                {
                    RecordName = name,
                    ZoneName = DefaultZone,
                    MmcsAuth = header
                };
                preAuthAttached++;
            }
            else
            {
                orphanAuths.Add(header);
            }
        }

        if (preAuthAttached > 0)
            log?.Report($"  PreAuth → {preAuthAttached} x-apple-mmcs-auth agganciati agli asset");
        if (orphanAuths.Count > 0)
            log?.Report(
                $"  PreAuth → {orphanAuths.Count} auth senza nome KA/MA");

        // Join orfani ↔ MA:/KA: per checksum (f2/f17 = SHA1 del segmento base64 nel nome).
        var checksumAttached = AttachOrphanAuthsByChecksum(assetsByName, orphanAuths, log);
        if (checksumAttached > 0)
            log?.Report($"  PreAuth → {checksumAttached} auth agganciati per checksum f2/f17↔MA/KA");

        // PreAuth tipicamente non associa MA:. Probe CloudKit solo se pochi match checksum.
        const int MaxMaAuthProbes = 24;
        var maMissingAuth = checksumAttached >= 8
            ? []
            : assetsByName.Values
                .Where(static a =>
                    a.RecordName.StartsWith("MA:", StringComparison.Ordinal)
                    && string.IsNullOrWhiteSpace(a.MmcsAuth))
                .OrderByDescending(static a => a.SizeBytes ?? ExtractSizeSuffix(a.RecordName) ?? 0)
                .ThenBy(static a => a.RecordName, StringComparer.Ordinal)
                .Take(MaxMaAuthProbes)
                .ToList();

        // Se non c'è alcun auth PreAuth, probe anche pochi seed KA:.
        var kaMissingAuth = preAuthAttached + checksumAttached == 0
            ? assetsByName.Values
                .Where(static a =>
                    a.RecordName.StartsWith("KA:", StringComparison.Ordinal)
                    && string.IsNullOrWhiteSpace(a.MmcsAuth))
                .OrderBy(static a => a.RecordName, StringComparer.Ordinal)
                .Take(maxAssets is > 0 ? Math.Min(maxAssets.Value, 8) : 8)
                .ToList()
            : [];

        var authProbes = maMissingAuth.Concat(kaMissingAuth).ToList();
        var maAuthOk = assetsByName.Values.Count(static a =>
            a.RecordName.StartsWith("MA:", StringComparison.Ordinal)
            && !string.IsNullOrWhiteSpace(a.MmcsAuth));
        if (authProbes.Count > 0)
        {
            log?.Report(
                $"CloudKit: probe auth → {maMissingAuth.Count} MA: + {kaMissingAuth.Count} KA: " +
                $"(catalogo {assetsByName.Count:N0}, MA già con auth={maAuthOk})…");
            foreach (var candidate in authProbes)
            {
                ct.ThrowIfCancellationRequested();
                try
                {
                    await PaceGatewayAsync(ct);
                    var asset = await FetchAssetWithQueryFallbackAsync(session, candidate.RecordName, log, ct);
                    if (asset is not null && !string.IsNullOrWhiteSpace(asset.MmcsAuth))
                    {
                        assetsByName[asset.RecordName] = asset;
                        if (asset.RecordName.StartsWith("MA:", StringComparison.Ordinal))
                            maAuthOk++;
                    }
                    else if (candidate.RecordName.StartsWith("MA:", StringComparison.Ordinal)
                             && assetsByName.TryGetValue(candidate.RecordName, out var maAsset)
                             && string.IsNullOrWhiteSpace(maAsset.MmcsAuth))
                    {
                        var matched = MmcsAuthBuilder.TryFindAuthForRecord(orphanAuths, candidate.RecordName);
                        if (matched is not null)
                        {
                            maAsset.MmcsAuth = matched;
                            maAuthOk++;
                            log?.Report($"  MA: {candidate.RecordName} ← auth PreAuth (checksum f2)");
                        }
                    }
                }
                catch (Exception ex)
                {
                    log?.Report($"  skip {candidate.RecordName}: {ex.Message}");
                }
            }
        }

        if (maAuthOk == 0)
        {
            log?.Report(
                "  nessun MA: con auth f2-matched — Manifest userà scoring authorizeGet " +
                "sugli auth PreAuth (niente bind cieco al nome)");
        }

        var withAuth = assetsByName.Values.Count(static a => !string.IsNullOrWhiteSpace(a.MmcsAuth));
        var maTotal = assetsByName.Values.Count(static a => a.RecordName.StartsWith("MA:", StringComparison.Ordinal));
        var maWrap = assetsByName.Values.Count(static a =>
            a.RecordName.StartsWith("MA:", StringComparison.Ordinal)
            && !string.IsNullOrWhiteSpace(a.AssetProtectionInfoHex));
        var otherWrap = assetsByName.Values.Count(static a =>
            !a.RecordName.StartsWith("MA:", StringComparison.Ordinal)
            && !string.IsNullOrWhiteSpace(a.AssetProtectionInfoHex));
        log?.Report(
            $"  discovery → {assetsByName.Count:N0} nel Manifest, {withAuth} con MMCS auth " +
            $"(MA con auth={maAuthOk})");
        log?.Report(
            $"  Asset.protectionInfo wrap: MA: {maWrap}/{maTotal}, altri {otherWrap}");

        if (withAuth == 0)
            log?.Report("  nessun x-apple-mmcs-auth utilizzabile — catalogo comunque scritto");

        //  MA: (Manifest.db) prima dei KA:; auth prima dei senza auth.
        var ordered = assetsByName.Values
            .OrderBy(static a => AssetDownloadPriority(a))
            .ThenByDescending(static a => a.SizeBytes ?? ExtractSizeSuffix(a.RecordName) ?? 0)
            .ThenBy(static a => a.RecordName, StringComparer.Ordinal)
            .ToList();
        if (maxAssets is > 0)
        {
            // Non tagliare mai i MA: con auth — Manifest.db deve entrare sempre.
            var maKeep = ordered
                .Where(static a =>
                    a.RecordName.StartsWith("MA:", StringComparison.Ordinal)
                    && !string.IsNullOrWhiteSpace(a.MmcsAuth))
                .ToList();
            var maNames = maKeep.Select(static a => a.RecordName).ToHashSet(StringComparer.Ordinal);
            var rest = ordered
                .Where(a => !maNames.Contains(a.RecordName))
                .Take(Math.Max(0, maxAssets.Value - maKeep.Count))
                .ToList();
            ordered = maKeep.Concat(rest).ToList();
        }

        var maCount = ordered.Count(static a => a.RecordName.StartsWith("MA:", StringComparison.Ordinal));
        if (maCount > 0)
            log?.Report($"  priorità MA: → {maCount} candidati Manifest (download prima dei KA:)");

        return ordered;
    }

    /// <summary>
    /// Aggancia auth PreAuth orfani agli asset MA:/KA: il cui checksum nome = f2/f17.
    /// </summary>
    private static int AttachOrphanAuthsByChecksum(
        Dictionary<string, BackupAsset> assetsByName,
        IReadOnlyList<string> orphanAuths,
        IProgress<string>? log)
    {
        if (orphanAuths.Count == 0 || assetsByName.Count == 0)
            return 0;

        var byChecksum = MmcsAuthBuilder.IndexAuthsByChecksum(orphanAuths);
        if (byChecksum.Count == 0)
            return 0;

        var attached = 0;
        foreach (var asset in assetsByName.Values)
        {
            if (!string.IsNullOrWhiteSpace(asset.MmcsAuth))
                continue;
            if (!asset.RecordName.StartsWith("MA:", StringComparison.Ordinal)
                && !asset.RecordName.StartsWith("KA:", StringComparison.Ordinal)
                && !asset.RecordName.StartsWith("LA:", StringComparison.Ordinal)
                && !asset.RecordName.StartsWith("NA:", StringComparison.Ordinal))
                continue;

            var hex = MmcsAuthBuilder.TryExtractAssetChecksumHex(asset.RecordName);
            if (hex is null)
                continue;
            if (!byChecksum.TryGetValue(hex, out var auth))
                continue;

            asset.MmcsAuth = auth;
            attached++;
        }

        return attached;
    }

    private static int AssetDownloadPriority(BackupAsset a)
    {
        var hasAuth = !string.IsNullOrWhiteSpace(a.MmcsAuth);
        if (a.RecordName.StartsWith("MA:", StringComparison.Ordinal))
            return hasAuth ? 0 : 3;
        if (a.RecordName.StartsWith("KA:", StringComparison.Ordinal))
            return hasAuth ? 1 : 4;
        return hasAuth ? 2 : 5;
    }

    private static long? ExtractSizeSuffix(string recordName) =>
        UbChunkBuilder.ExtractDeclaredSize(recordName);

    /// <summary>Header x-apple-mmcs-auth già estratti dalla PreAuth (anche senza nome KA/MA).</summary>
    public IReadOnlyList<string> GetPreAuthMmcsAuthHeaders() =>
        _preAuthCatalog.MmcsAuths.Values
            .Where(static a => a.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length >= 3)
            .Distinct(StringComparer.Ordinal)
            .ToList();

    /// <summary>
    /// Risolve candidati MA: con auth per Manifest.db.
    /// Pool = tutti i MA: con match f2↔checksum (+ probe PreAuth residui), senza taglio per size suffix.
    /// </summary>
    public async Task<IReadOnlyList<BackupAsset>> ResolveManifestMaCandidatesAsync(
        ICloudSession session,
        BackupDevice device,
        IReadOnlyList<BackupAsset> discovered,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        _ = session;
        _ = ct;

        var byName = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        foreach (var a in discovered.Where(static x => x.RecordName.StartsWith("MA:", StringComparison.Ordinal)))
            byName[a.RecordName] = a;

        foreach (var hint in device.AssetHints.Where(static h => h.StartsWith("MA:", StringComparison.Ordinal)))
        {
            if (!byName.ContainsKey(hint))
            {
                byName[hint] = new BackupAsset
                {
                    RecordName = hint,
                    ZoneName = DefaultZone,
                    SizeBytes = UbChunkBuilder.ExtractDeclaredSize(hint)
                };
            }
        }

        var allPreAuth = GetPreAuthMmcsAuthHeaders();
        var byF2 = MmcsAuthBuilder.IndexAuthsByChecksum(allPreAuth);

        var matched = new List<BackupAsset>();
        var usedAuths = new HashSet<string>(StringComparer.Ordinal);
        var checksumHits = 0;

        // Match su TUTTI i MA: del catalogo (niente Take(64) per size suffix).
        foreach (var asset in byName.Values)
        {
            if (!string.IsNullOrWhiteSpace(asset.MmcsAuth))
            {
                if (usedAuths.Add(asset.MmcsAuth!))
                    matched.Add(asset);
                continue;
            }

            var hex = MmcsAuthBuilder.TryExtractAssetChecksumHex(asset.RecordName);
            if (hex is null || !byF2.TryGetValue(hex, out var auth))
                continue;

            asset.MmcsAuth = auth;
            if (!usedAuths.Add(auth))
                continue;
            matched.Add(asset);
            checksumHits++;
        }

        if (checksumHits > 0)
            log?.Report($"  Manifest MA: ← {checksumHits} auth PreAuth per checksum f2 (catalogo {byName.Count:N0})");

        // Cap authorizeGet: max 96 MA matched unici + 48 PreAuth senza nome.
        const int MaxMatched = 96;
        const int MaxUnmatchedProbes = 48;
        if (matched.Count > MaxMatched)
        {
            log?.Report($"  Manifest MA matched {matched.Count} → cap {MaxMatched} (scoring authorizeGet)");
            matched = matched.Take(MaxMatched).ToList();
        }

        var ready = new List<BackupAsset>(matched);
        var unmatched = allPreAuth.Where(h => !usedAuths.Contains(h)).Take(MaxUnmatchedProbes).ToList();
        if (unmatched.Count > 0)
        {
            var i = 0;
            foreach (var auth in unmatched)
            {
                i++;
                ready.Add(new BackupAsset
                {
                    RecordName = $"MA:__preauth_{i}",
                    ZoneName = DefaultZone,
                    MmcsAuth = auth
                });
            }

            log?.Report(
                $"  + {unmatched.Count} auth PreAuth senza match nome " +
                "(authorizeGet per size reale Manifest)");
        }

        // Niente ordinamento per size suffix: BackupDownloadService sceglie per cryptoSum.
        log?.Report($"  candidati Manifest.db → {ready.Count} con auth (matched={matched.Count})");
        return ready;
    }

    /// <summary>
    /// Scarica i record <c>K:</c> (mbksync) e sostituisce gli id UUID con i blob TLV se presenti.
    /// </summary>
    public async Task DownloadKeybagBlobsAsync(
        ICloudSession session,
        BackupDevice device,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var recordIds = device.Keybags
            .Where(CloudKitResponseParser.IsKeybagRecordId)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        var fullBlobs = device.Keybags
            .Where(CloudKitResponseParser.IsFullKeybagBlob)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (recordIds.Count == 0)
        {
            if (fullBlobs.Count > 0)
                log?.Report($"CloudKit: {fullBlobs.Count} keybag blob già completi");
            else
                log?.Report("CloudKit: nessun id K: da scaricare");
            return;
        }

        log?.Report($"CloudKit: download {recordIds.Count} record keybag…");
        var rawById = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        device.KeybagDataBlobs.Clear();

        foreach (var id in recordIds)
        {
            ct.ThrowIfCancellationRequested();
            await PaceGatewayAsync(ct);

            // record/retrieve su K: spesso stub; usa PrivilegedBatch (query). Retrieve solo se serve.
            byte[]? payload = null;
            try
            {
                var body = CloudKitDelimitedRequest.BuildPrivilegedBatchFetch(
                    session.CloudKitUserId, MbksyncZone, id,
                    _restoreState?.ToRequestContext());
                var queried = await _gateway.QueryRetrieveAsync(session, body, ct, _restoreState);
                if (CloudKitResponseParser.IsCloudKitErrorPayload(queried, out var queryErr))
                {
                    log?.Report($"  query Keybag {id} → errore: {queryErr}");
                }
                else if (queried.Length > 0)
                {
                    payload = queried;
                    log?.Report($"  query Keybag {id} → {queried.Length:N0} byte");
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  query Keybag {id} skip: {ex.Message}");
            }

            var queryHasKeybagData = payload is { Length: >= 64 }
                                     && !CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _)
                                     && payload.AsSpan().IndexOf("keybagData"u8) >= 0;
            if (queryHasKeybagData)
            {
                log?.Report(
                    $"  retrieve Keybag {id} skip (query PrivilegedBatch già contiene keybagData)");
            }
            else
            {
                try
                {
                    var retrieved = await TryFetchMbksyncRecordAsync(
                        session, id, log, ct, restorePhase: true);
                    if (retrieved is not null
                        && !CloudKitResponseParser.IsCloudKitErrorPayload(retrieved, out _)
                        && retrieved.Length >= 64)
                    {
                        var preferRetrieve = payload is null
                            || retrieved.Length > payload.Length
                            || (retrieved.AsSpan().IndexOf("keybagData"u8) >= 0
                                && payload.AsSpan().IndexOf("keybagData"u8) < 0);
                        if (preferRetrieve)
                        {
                            payload = retrieved;
                            log?.Report($"  retrieve Keybag {id} → {retrieved.Length:N0} byte");
                        }
                        else
                        {
                            log?.Report(
                                $"  retrieve Keybag {id} → {retrieved.Length:N0} byte (tenuto query {payload!.Length:N0} B)");
                        }
                    }
                }
                catch (Exception ex)
                {
                    log?.Report($"  retrieve Keybag {id} skip: {ex.Message}");
                }
            }

            if (payload is null or { Length: 0 })
            {
                log?.Report($"  FAIL Keybag {id}: nessun payload");
                continue;
            }

            if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err))
            {
                log?.Report($"  FAIL Keybag {id}: {err}");
                continue;
            }

            rawById[id] = payload;

            var isKeybagType = payload.AsSpan().IndexOf("Keybag"u8) >= 0;
            if (isKeybagType)
                log?.Report($"  {id}: record type=Keybag");

            foreach (var blob in CloudKitResponseParser.ExtractEmbeddedKeybagBlobs(payload))
            {
                var record = "K:" + Convert.ToBase64String(blob);
                if (!fullBlobs.Contains(record, StringComparer.Ordinal))
                    fullBlobs.Add(record);
            }

            // Campi tipici: keybagData (+ secret). Di solito ancora protetti da PCS.
            var fields = CloudKitResponseParser.ExtractNamedByteFields(
                payload, "keybagData", "secret");
            if (fields.TryGetValue("keybagData", out var keybagData))
            {
                device.KeybagDataBlobs[id] = keybagData;
                if (IosKeybag.TryParse(keybagData, out _, out _))
                {
                    var record = "K:" + Convert.ToBase64String(keybagData);
                    if (!fullBlobs.Contains(record, StringComparer.Ordinal))
                        fullBlobs.Add(record);
                    log?.Report($"  {id}: keybagData {keybagData.Length:N0} byte (TLV chiaro)");
                }
                else
                {
                    log?.Report(
                        $"  {id}: keybagData {keybagData.Length:N0} byte " +
                        "(cifrato PCS — serve KeyBagKey escrow)");
                }
            }
            else if (!isKeybagType)
            {
                log?.Report($"  {id}: payload senza type Keybag / keybagData");
            }

            if (fields.TryGetValue("secret", out var secret))
                log?.Report($"  {id}: secret {secret.Length} byte");
        }

        device.KeybagRecordIds = recordIds;
        device.KeybagRawPayloads = rawById;

        if (fullBlobs.Count > 0)
        {
            device.Keybags.Clear();
            device.Keybags.AddRange(fullBlobs);
            log?.Report($"  keybag blob completi → {fullBlobs.Count}");
        }
        else
        {
            log?.Report(
                "  nessun blob TLV chiaro nei record K: — salvati payload grezzi " +
                "(serve unlock PCS/keybagData)");
        }
    }

    public async Task SaveKeybagsAsync(BackupDevice device, string outputDirectory, CancellationToken ct = default)
    {
        var recordIds = device.KeybagRecordIds.Count > 0
            ? device.KeybagRecordIds
            : device.Keybags.Where(CloudKitResponseParser.IsKeybagRecordId).ToList();
        var fullBlobs = device.Keybags.Where(CloudKitResponseParser.IsFullKeybagBlob).ToList();

        if (recordIds.Count == 0 && fullBlobs.Count == 0 && device.KeybagRawPayloads.Count == 0)
            return;

        Directory.CreateDirectory(outputDirectory);
        var rawFiles = new List<string>();

        foreach (var (id, payload) in device.KeybagRawPayloads)
        {
            var safe = SanitizeKeybagFileStem(id);
            var fileName = $"keybag_{safe}.pb";
            var filePath = Path.Combine(outputDirectory, fileName);
            await File.WriteAllBytesAsync(filePath, payload, ct);
            rawFiles.Add(fileName);
        }

        var keybagDataFiles = new List<string>();
        foreach (var (id, keybagData) in device.KeybagDataBlobs)
        {
            var safe = SanitizeKeybagFileStem(id);
            var fileName = $"keybag_data_{safe}.bin";
            await File.WriteAllBytesAsync(Path.Combine(outputDirectory, fileName), keybagData, ct);
            keybagDataFiles.Add(fileName);
            rawFiles.Add(fileName);
        }

        string? decryptedKeybagFile = null;
        var decryptedPath = Path.Combine(outputDirectory, BackupKeybagPcsUnlock.DecryptedFileName);
        if (File.Exists(decryptedPath))
        {
            decryptedKeybagFile = BackupKeybagPcsUnlock.DecryptedFileName;
            if (!rawFiles.Contains(decryptedKeybagFile, StringComparer.Ordinal))
                rawFiles.Add(decryptedKeybagFile);
        }

        for (var i = 0; i < fullBlobs.Count; i++)
        {
            if (!IosKeybag.TryParse(fullBlobs[i], out _, out _))
                continue;
            var b64 = fullBlobs[i].StartsWith("K:", StringComparison.Ordinal)
                ? fullBlobs[i][2..]
                : fullBlobs[i];
            try
            {
                var bytes = Convert.FromBase64String(b64);
                var fileName = $"keybag_blob_{i}.bin";
                await File.WriteAllBytesAsync(Path.Combine(outputDirectory, fileName), bytes, ct);
                rawFiles.Add(fileName);
                if (decryptedKeybagFile is null)
                {
                    decryptedKeybagFile = BackupKeybagPcsUnlock.DecryptedFileName;
                    await File.WriteAllBytesAsync(
                        Path.Combine(outputDirectory, decryptedKeybagFile), bytes, ct);
                    rawFiles.Add(decryptedKeybagFile);
                }
            }
            catch
            {
                // ignore bad b64
            }
        }

        var path = Path.Combine(outputDirectory, "keybags.json");
        var pcsMetaExists = File.Exists(
            Path.Combine(outputDirectory, BackupKeybagPcsUnlock.UnlockMetaFileName));
        var json = JsonSerializer.Serialize(new
        {
            deviceUuid = device.DeviceUuid,
            recordIds,
            keybags = fullBlobs.Count > 0 ? fullBlobs : device.Keybags,
            keybagDataFiles,
            keybagDecrypted = decryptedKeybagFile,
            rawFiles,
            note = decryptedKeybagFile is not null
                ? "keybag_decrypted.bin = TLV chiaro (PCS unwrap da Escrow KeySet). " +
                  "Class keys richiedono secret decifrato (vedi keybag_pcs_unlock_meta.json)."
                : pcsMetaExists
                    ? "PCS unlock tentato ma senza TLV — vedi keybag_pcs_unlock_meta.json."
                    : "Solo id/payload grezzi: keybagData ancora cifrato PCS. " +
                      "Serve KeySet Escrow in sessione (scheda Escrow → Unlock EscrowedKeys)."
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(path, json, ct);
    }

    private static string SanitizeKeybagFileStem(string recordId)
    {
        var s = recordId.StartsWith("K:", StringComparison.Ordinal) ? recordId[2..] : recordId;
        var chars = s.Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray();
        var stem = new string(chars);
        return stem.Length > 48 ? stem[..48] : stem;
    }

    /// <summary>
    /// Risolve MMCS auth per un record asset (query/retrieve _defaultZone).
    /// Trasporto transient: retry con backoff. HTTP 401: remint Anisette, un retry — poi skip.
    /// </summary>
    public async Task<BackupAsset?> TryResolveAssetAuthAsync(
        ICloudSession session,
        string recordName,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var refreshed = false;
        for (var attempt = 0; attempt < 2; attempt++)
        {
            BackupAsset? viaQuery = null;
            try
            {
                viaQuery = await FetchAssetViaQueryWithTransportRetryAsync(
                    session, recordName, log, ct).ConfigureAwait(false);
                // Query spesso dà solo CAog (auth) senza contents wrap → no-ikm.
                // Se manca RP/wrap, continua con retrieve e merge.
                if (viaQuery is not null && HasUsableRecordMaterials(viaQuery))
                    return viaQuery;
            }
            catch (Exception ex) when (IsUnauthorizedCloudKit(ex) && !refreshed)
            {
                refreshed = true;
                log?.Report($"  query auth 401 {recordName} — refresh Anisette e retry…");
                if (!await TryRefreshSessionAfterUnauthorizedAsync(session, log, ct))
                    log?.Report($"  query auth {recordName}: {FormatExceptionChain(ex)}");
                continue;
            }
            catch (Exception ex)
            {
                log?.Report($"  query auth {recordName}: {FormatExceptionChain(ex)}");
            }

            try
            {
                var viaRetrieve = await FetchAssetRetrieveWithTransportRetryAsync(
                    session, recordName, log, ct).ConfigureAwait(false);
                if (viaRetrieve is not null)
                    return MergeResolvedAsset(viaQuery, viaRetrieve);
                if (viaQuery is not null)
                    return viaQuery;
            }
            catch (Exception ex) when (IsUnauthorizedCloudKit(ex) && !refreshed)
            {
                refreshed = true;
                log?.Report($"  retrieve auth 401 {recordName} — refresh Anisette e retry…");
                if (!await TryRefreshSessionAfterUnauthorizedAsync(session, log, ct))
                    log?.Report($"  retrieve auth {recordName}: {FormatExceptionChain(ex)}");
                continue;
            }
            catch (Exception ex)
            {
                log?.Report($"  retrieve auth {recordName}: {FormatExceptionChain(ex)}");
                if (viaQuery is not null)
                    return viaQuery;
            }

            break;
        }

        return null;
    }

    /// <summary>Wrap contents (FillFord) — non basta RP/batch con un "contents" alieno.</summary>
    private static bool HasUsableRecordMaterials(BackupAsset a) =>
        !string.IsNullOrWhiteSpace(a.AssetProtectionInfoHex)
        || (a.RecordPayload is { Length: > 32 } rp
            && a.AssetSignature is { Length: >= 4 } sig
            && CloudKitAssetProto.TryResolveOwnedWrap(rp, sig, out _) is { Length: 24 or 40 });

    private static BackupAsset MergeResolvedAsset(BackupAsset? query, BackupAsset retrieve)
    {
        if (query is null)
            return retrieve;

        if (string.IsNullOrWhiteSpace(retrieve.MmcsAuth)
            && !string.IsNullOrWhiteSpace(query.MmcsAuth))
            retrieve.MmcsAuth = query.MmcsAuth;
        if (retrieve.RecordPayload is not { Length: > 32 }
            && query.RecordPayload is { Length: > 32 })
            retrieve.RecordPayload = query.RecordPayload;
        if (string.IsNullOrWhiteSpace(retrieve.AssetProtectionInfoHex)
            && !string.IsNullOrWhiteSpace(query.AssetProtectionInfoHex))
            retrieve.AssetProtectionInfoHex = query.AssetProtectionInfoHex;
        if (retrieve.AssetSignature is not { Length: 21 }
            && query.AssetSignature is { Length: 21 })
            retrieve.AssetSignature = query.AssetSignature;
        return retrieve;
    }

    private async Task<BackupAsset?> FetchAssetViaQueryWithTransportRetryAsync(
        ICloudSession session,
        string recordName,
        IProgress<string>? log,
        CancellationToken ct)
    {
        Exception? last = null;
        for (var attempt = 0; attempt < PrivilegedBatchTransportMaxAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return await _query.FetchAssetViaQueryAsync(
                    session, recordName, _restoreState, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsUnauthorizedCloudKit(ex))
            {
                throw;
            }
            catch (Exception ex) when (
                IsTransientCloudKitTransport(ex)
                && attempt < PrivilegedBatchTransportMaxAttempts - 1)
            {
                last = ex;
                var delayMs = PrivilegedBatchTransportRetryBaseMs * (attempt + 1);
                log?.Report(
                    $"  query auth {recordName}: {FormatExceptionChain(ex)} — " +
                    $"retry trasporto {attempt + 1}/{PrivilegedBatchTransportMaxAttempts - 1} (+{delayMs} ms)");
                await Task.Delay(delayMs, ct).ConfigureAwait(false);
            }
        }

        if (last is not null)
            throw last;
        return null;
    }

    private async Task<BackupAsset?> FetchAssetRetrieveWithTransportRetryAsync(
        ICloudSession session,
        string recordName,
        IProgress<string>? log,
        CancellationToken ct)
    {
        Exception? last = null;
        for (var attempt = 0; attempt < PrivilegedBatchTransportMaxAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return await _query.FetchAssetAsync(session, recordName, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsUnauthorizedCloudKit(ex))
            {
                throw;
            }
            catch (Exception ex) when (
                IsTransientCloudKitTransport(ex)
                && attempt < PrivilegedBatchTransportMaxAttempts - 1)
            {
                last = ex;
                var delayMs = PrivilegedBatchTransportRetryBaseMs * (attempt + 1);
                log?.Report(
                    $"  retrieve auth {recordName}: {FormatExceptionChain(ex)} — " +
                    $"retry trasporto {attempt + 1}/{PrivilegedBatchTransportMaxAttempts - 1} (+{delayMs} ms)");
                await Task.Delay(delayMs, ct).ConfigureAwait(false);
            }
        }

        if (last is not null)
            throw last;
        return null;
    }

    private static string FormatExceptionChain(Exception ex)
    {
        var parts = new List<string>(3);
        for (Exception? e = ex; e is not null && parts.Count < 4; e = e.InnerException)
            parts.Add($"{e.GetType().Name}: {e.Message}");
        return string.Join(" → ", parts);
    }

    private readonly SemaphoreSlim _sessionRefreshGate = new(1, 1);

    private async Task<bool> TryRefreshSessionAfterUnauthorizedAsync(
        ICloudSession session,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (Volatile.Read(ref _anisetteRefreshFailed) != 0)
        {
            var at = Volatile.Read(ref _anisetteRefreshFailedAtMs);
            var age = at == 0 ? AnisetteRefreshCooldownMs : Environment.TickCount64 - at;
            if (age < AnisetteRefreshCooldownMs)
                return false;
            Volatile.Write(ref _anisetteRefreshFailed, 0);
            log?.Report(
                $"  retry refresh Anisette dopo cooldown {AnisetteRefreshCooldownMs / 1000}s…");
        }

        _gateway.ClearUnauthorized();
        if (_sessionRefresh is null)
            return false;

        await _sessionRefreshGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // Double-check dopo il gate (altro chunk può aver già refreshato).
            if (Volatile.Read(ref _anisetteRefreshFailed) != 0)
            {
                var at = Volatile.Read(ref _anisetteRefreshFailedAtMs);
                var age = at == 0 ? AnisetteRefreshCooldownMs : Environment.TickCount64 - at;
                if (age < AnisetteRefreshCooldownMs)
                    return false;
                Volatile.Write(ref _anisetteRefreshFailed, 0);
            }

            // #region agent log
            var workerHealth = await ProbeAdiWorkerHealthAsync(ct).ConfigureAwait(false);
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "anisette-401",
                    ["hypothesisId"] = "H-401-ADI",
                    ["location"] = "TryRefreshSessionAfterUnauthorizedAsync",
                    ["message"] = "refresh_after_401_begin",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        workerHealth,
                        paceMs = Volatile.Read(ref _gatewayPaceMs),
                    },
                });
                if (IkeLogOptions.ShouldWriteAgentDiag)
                    IkeLogOptions.AppendAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
            }
            catch { /* ignore */ }
            // #endregion

            // 401 → OTP morto: remint obbligatorio (non solo Client-Time).
            await _sessionRefresh(session, log, ct, forceRemint: true);
            _gateway.ClearUnauthorized();
            Volatile.Write(ref _anisetteRefreshFailed, 0);
            Volatile.Write(ref _anisetteRefreshFailedAtMs, 0);
            Volatile.Write(ref _gatewayPaceMs, 0);

            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "anisette-401",
                    ["hypothesisId"] = "H-401-ADI",
                    ["location"] = "TryRefreshSessionAfterUnauthorizedAsync",
                    ["message"] = "refresh_after_401_ok",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new { workerHealthBefore = workerHealth },
                });
                if (IkeLogOptions.ShouldWriteAgentDiag)
                    IkeLogOptions.AppendAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
            }
            catch { /* ignore */ }
            // #endregion
            return true;
        }
        catch (Exception ex)
        {
            Volatile.Write(ref _anisetteRefreshFailed, 1);
            Volatile.Write(ref _anisetteRefreshFailedAtMs, Environment.TickCount64);
            var workerAfter = await ProbeAdiWorkerHealthAsync(ct).ConfigureAwait(false);
            log?.Report($"  refresh sessione fallito: {ex.Message}");
            log?.Report(
                $"  ERROR Anisette offline (ADI worker={workerAfter}) — " +
                $"niente PrivilegedBatch auth per ~{AnisetteRefreshCooldownMs / 1000}s. " +
                "Verifica python akd_adi_worker.py :6973 e GET http://127.0.0.1:6971/.");
            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "anisette-401",
                    ["hypothesisId"] = "H-401-ADI",
                    ["location"] = "TryRefreshSessionAfterUnauthorizedAsync",
                    ["message"] = "refresh_after_401_fail",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["data"] = new
                    {
                        error = ex.Message,
                        errorType = ex.GetType().FullName,
                        inner = ex.InnerException?.Message,
                        workerAfter,
                        cooldownMs = AnisetteRefreshCooldownMs,
                    },
                });
                if (IkeLogOptions.ShouldWriteAgentDiag)
                    IkeLogOptions.AppendAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
            }
            catch { /* ignore */ }
            // #endregion
            return false;
        }
        finally
        {
            _sessionRefreshGate.Release();
        }
    }

    private static async Task<string> ProbeAdiWorkerHealthAsync(CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(2) };
            using var resp = await http.GetAsync("http://127.0.0.1:6973/health", ct)
                .ConfigureAwait(false);
            return resp.IsSuccessStatusCode
                ? $"ok:{(int)resp.StatusCode}"
                : $"http:{(int)resp.StatusCode}";
        }
        catch (Exception ex)
        {
            return $"down:{ex.GetType().Name}:{ex.Message}";
        }
    }

    private static bool IsUnauthorizedCloudKit(Exception ex) =>
        ex.Message.Contains("401", StringComparison.Ordinal)
        || ex.Message.Contains("HTTP 401", StringComparison.Ordinal)
        || ex.Message.Contains("CloudKit bloccato", StringComparison.OrdinalIgnoreCase);

    /// <summary>
    /// Errori di trasporto ritentabili (stesso criterio edge): HttpRequestException /
    /// IOException / Timeout — es. "An error occurred while sending the request."
    /// </summary>
    private static bool IsTransientCloudKitTransport(Exception ex)
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
                return true;
        }

        return false;
    }

    /// <summary>
    /// QueryFetch con fino a <see cref="PrivilegedBatchTransportMaxAttempts"/> tentativi
    /// su errori di trasporto. I 401 restano al caller (refresh Anisette).
    /// </summary>
    private async Task<byte[]> QueryFetchPayloadWithTransportRetryAsync(
        ICloudSession session,
        IReadOnlyList<string> chunk,
        IProgress<string>? log,
        CancellationToken ct)
    {
        Exception? last = null;
        for (var attempt = 0; attempt < PrivilegedBatchTransportMaxAttempts; attempt++)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                return await _query.QueryFetchPayloadAsync(
                    session, chunk, _restoreState, ct).ConfigureAwait(false);
            }
            catch (Exception ex) when (IsUnauthorizedCloudKit(ex))
            {
                throw; // 401 → refresh path del caller
            }
            catch (Exception ex) when (
                IsTransientCloudKitTransport(ex)
                && attempt < PrivilegedBatchTransportMaxAttempts - 1)
            {
                last = ex;
                var delayMs = PrivilegedBatchTransportRetryBaseMs * (attempt + 1);
                log?.Report(
                    $"  PrivilegedBatch ×{chunk.Count}: {ex.Message} — " +
                    $"retry trasporto {attempt + 1}/{PrivilegedBatchTransportMaxAttempts - 1} " +
                    $"(+{delayMs} ms)");
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                        JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "9a5651",
                            ["runId"] = "pb-transport-retry-v1",
                            ["hypothesisId"] = "H-PB-IO",
                            ["location"] = "CloudKitAssetService.QueryFetchPayloadWithTransportRetryAsync",
                            ["message"] = "pb_transport_retry",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["chunk"] = chunk.Count,
                                ["attempt"] = attempt + 1,
                                ["maxAttempts"] = PrivilegedBatchTransportMaxAttempts,
                                ["delayMs"] = delayMs,
                                ["errType"] = ex.GetType().Name,
                                ["msg"] = ex.Message,
                                ["inner"] = ex.InnerException?.GetType().Name,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                await Task.Delay(delayMs, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                last = ex;
                throw;
            }
        }

        throw last ?? new InvalidOperationException("PrivilegedBatch transport retry exhausted");
    }

    public static BackupAsset? ParseAssetRecord(byte[] payload, string recordName)
    {
        foreach (var candidate in MmcsAuthBuilder.RecordNameLookupCandidates(recordName))
        {
            // Prima: solo KA|MA|… → UUID / A:pref4:rid sempre null → fetch_miss / no-ikm.
            if (!IsAssetRecordParseCandidate(candidate))
                continue;

            var window = ExtractRecordWindow(payload, candidate);
            if (window is not { Length: > 32 }
                && payload.AsSpan().IndexOf(Encoding.UTF8.GetBytes(candidate)) < 0)
                continue;

            // Mai il PrivilegedBatch intero come “window” se c’è un token rid:
            // IndexOf("contents") sul batch → HasUsableRecordMaterials true senza wrap owned
            // (Authy watch/tumblr, Microsoft GraphicsCache → no-ikm).
            if (window is null
                && CloudKitMmcsIds.TryExtractRidToken(candidate) is { Length: >= 8 })
                continue;

            window ??= payload.Length <= 2_000_000 ? payload : null;
            if (window is not { Length: > 32 })
                continue;

            EnrichProtectionInfo(ref window, out var wrapHex, out var recordPiHex);
            //  signature+wrap dallo stesso messaggio Asset (contents).
            var contents = BackupAssetContentsParser.Parse(window);
            var mmcsAuth = !string.IsNullOrWhiteSpace(contents.MmcsAuth)
                ? contents.MmcsAuth
                : MmcsAuthBuilder.BuildFromRecordPayload(payload, candidate);

            // Anche senza auth: il payload serve per encryptedAttributes / protectionClass.
            if (string.IsNullOrWhiteSpace(mmcsAuth)
                && window.AsSpan().IndexOf("BackupAsset"u8) < 0
                && window.AsSpan().IndexOf("contents"u8) < 0
                && window.AsSpan().IndexOf("encryptedAttributes"u8) < 0)
                continue;

            if (contents.AssetProtectionWrap is { Length: > 0 } w)
                wrapHex = Convert.ToHexString(w);

            return new BackupAsset
            {
                RecordName = candidate,
                ZoneName = DefaultZone,
                RecordIdSuffix = CloudKitMmcsIds.ToRecordIdSuffix(candidate),
                SizeBytes = UbChunkBuilder.ExtractDeclaredSize(candidate),
                MmcsAuth = mmcsAuth,
                AssetSignature = contents.AssetSignature is { Length: 21 } sig
                    ? sig
                    : null,
                AssetProtectionInfoHex = wrapHex,
                RecordProtectionInfoDerHex = recordPiHex,
                Extension = contents.Extension,
                RecordPayload = window
            };
        }

        return null;
    }

    public static IReadOnlyList<BackupAsset> ParseAssetsFromPayload(byte[]? payload)
    {
        if (payload is not { Length: > 0 })
            return [];

        var assets = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        var recordNames = CloudKitResponseParser.ExtractAssetRecordNames(payload);
        var structured = MmcsAuthBuilder.ExtractStructuredAuths(payload);

        // 1) Auth strutturati con nome record associato (accoppiamento certo).
        foreach (var auth in structured)
        {
            if (auth.RecordName is null)
                continue;
            var name = recordNames.FirstOrDefault(r =>
                r == auth.RecordName
                || MmcsAuthBuilder.RecordNameLookupCandidates(r).Contains(auth.RecordName, StringComparer.Ordinal))
                ?? auth.RecordName;
            assets[name] = CreateAsset(name, auth.Header, payload);
        }

        // 2) Un solo record + un solo auth strutturato senza nome → associazione univoca.
        if (assets.Count == 0 && recordNames.Count == 1 && structured.Count == 1)
            assets[recordNames[0]] = CreateAsset(recordNames[0], structured[0].Header, payload);

        // 3) Fallback: match per contenuto del proto.
        foreach (var auth in MmcsAuthBuilder.ExtractAllReadyMadeAuths(payload))
        {
            foreach (var recordName in recordNames)
            {
                if (assets.ContainsKey(recordName))
                    continue;
                if (MmcsAuthBuilder.AuthMatchesRecord(auth, recordName)
                    || auth.Contains(recordName, StringComparison.Ordinal))
                {
                    assets[recordName] = CreateAsset(recordName, auth, payload);
                }
            }
        }

        return assets.Values.OrderBy(static a => a.RecordName, StringComparer.Ordinal).ToList();
    }

    private static BackupAsset CreateAsset(string recordName, string mmcsAuth, byte[]? payload = null)
    {
        byte[]? window = payload is null ? null : ExtractRecordWindow(payload, recordName);
        EnrichProtectionInfo(ref window, out var wrapHex, out var recordPiHex);
        var contents = window is { Length: > 0 }
            ? BackupAssetContentsParser.Parse(window)
            : null;
        if (contents?.AssetProtectionWrap is { Length: > 0 } w)
            wrapHex = Convert.ToHexString(w);
        var auth = !string.IsNullOrWhiteSpace(mmcsAuth)
            ? mmcsAuth
            : contents?.MmcsAuth;

        return new BackupAsset
        {
            RecordName = recordName,
            ZoneName = DefaultZone,
            RecordIdSuffix = CloudKitMmcsIds.ToRecordIdSuffix(recordName),
            SizeBytes = UbChunkBuilder.ExtractDeclaredSize(recordName),
            MmcsAuth = auth,
            AssetSignature = contents?.AssetSignature is { Length: 21 } sig ? sig : null,
            AssetProtectionInfoHex = wrapHex,
            RecordProtectionInfoDerHex = recordPiHex,
            Extension = contents?.Extension,
            //  un CKFile = finestra del singolo record. Mai il PrivilegedBatch intero:
            // altrimenti map-contents/lead04 e TryExtract legano lo stesso wrap → IKM alien
            // condiviso su AuthKit/AMS/PersistedBags (ike_run 3026–3035, ikm=57bca31a).
            RecordPayload = window is { Length: > 32 } ? window : null
        };
    }

    private static void EnrichProtectionInfo(
        ref byte[]? window,
        out string? wrapHex,
        out string? recordPiHex)
    {
        wrapHex = null;
        recordPiHex = null;
        if (window is not { Length: > 0 })
            return;

        var wrap = MmcsAssetProtection.TryExtract(window);
        if (wrap is { Length: > 0 })
            wrapHex = Convert.ToHexString(wrap);

        var recordPi = PcsProtectionZone.TryExtractRecordProtectionInfoDer(window);
        if (recordPi is { Length: > 0 })
            recordPiHex = Convert.ToHexString(recordPi);
    }

    /// <summary>
    /// Finestra record: dal nome fino a contents completo (o max 2 MiB).
    /// Cap 16 KiB troncava package multi-Asset (Office/…) → wrap miss / no-ikm.
    /// Preferisce il match più lungo (A:pref:rid); mai UUID nudo con token noto.
    /// </summary>
    private static byte[]? ExtractRecordWindow(byte[] payload, string recordName)
    {
        if (payload.Length == 0 || string.IsNullOrEmpty(recordName))
            return null;

        const int MaxWindow = 2_000_000;
        var idx = -1;
        byte[]? nameBytes = null;
        var bestLen = -1;
        var ridTok = CloudKitMmcsIds.TryExtractRidToken(recordName);
        foreach (var cand in MmcsAuthBuilder.RecordNameLookupCandidates(recordName))
        {
            // UUID nudo in Domain multi-asset → finestra sibling / wrap alieno.
            if (ridTok is { Length: >= 8 }
                && CloudKitMmcsIds.IsUuidRecordName(cand))
                continue;

            var nb = Encoding.UTF8.GetBytes(cand);
            var at = IndexOfBytes(payload, nb);
            if (at < 0)
                continue;
            if (nb.Length < bestLen)
                continue;
            bestLen = nb.Length;
            idx = at;
            nameBytes = nb;
        }

        // Fallback: token rid (univoco) se il wire A:… non è letterale nel payload.
        if ((idx < 0 || nameBytes is null)
            && ridTok is { Length: >= 8 })
        {
            var tb = Encoding.UTF8.GetBytes(ridTok);
            var at = IndexOfBytes(payload, tb);
            if (at >= 0)
            {
                // Allinea indietro a inizio record se possibile (max 256 B).
                var start = Math.Max(0, at - 256);
                idx = start;
                nameBytes = tb;
                // Preferisci start sull'occorrenza del token.
                idx = at;
            }
        }

        if (idx < 0 || nameBytes is null)
        {
            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-SAME-RP",
                    ["runId"] = "extract-window-null-on-miss",
                    ["location"] = "CloudKitAssetService.ExtractRecordWindow",
                    ["message"] = "record_name_not_in_payload",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["recordName"] = recordName.Length > 64 ? recordName[..64] : recordName,
                        ["payloadLen"] = payload.Length,
                        ["hasTok"] = ridTok is { Length: >= 8 },
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            return null;
        }

        // Finestra del SINGOLO record: da name fino al prossimo name-like UUID
        // record o al cap contents-slice (non coda multi-record).
        var end = Math.Min(payload.Length, idx + nameBytes.Length + 16_384);
        var contentsAt = IndexOfAscii(payload, idx, Math.Min(payload.Length, idx + MaxWindow), "contents"u8);
        if (contentsAt >= 0)
        {
            var afterContents = contentsAt + "contents".Length;
            var sliceEnd = Math.Min(payload.Length, afterContents + 8_192);
            sliceEnd = CutAsciiBefore(payload, afterContents, sliceEnd, "extension"u8);
            sliceEnd = CutAsciiBefore(payload, afterContents, sliceEnd, "relativePath"u8);
            sliceEnd = CutAsciiBefore(payload, afterContents, sliceEnd, "domain"u8);
            sliceEnd = CutAsciiBefore(payload, afterContents, sliceEnd, "encryptionKey"u8);
            end = Math.Max(end, sliceEnd);
        }

        end = Math.Min(end, payload.Length);
        if (end - idx < 32)
            return null;
        return payload.AsSpan(idx, end - idx).ToArray();
    }

    private static int CutAsciiBefore(byte[] hay, int start, int end, ReadOnlySpan<byte> name)
    {
        var i = IndexOfAscii(hay, start, end, name);
        if (i >= start + 64 && i < end)
            return i;
        return end;
    }

    private static int IndexOfAscii(byte[] hay, int start, int end, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || end - start < needle.Length)
            return -1;
        var last = end - needle.Length;
        for (var i = start; i <= last; i++)
        {
            if (hay.AsSpan(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }

    private async Task<BackupAsset?> FetchAssetWithQueryFallbackAsync(
        ICloudSession session,
        string recordName,
        IProgress<string>? log,
        CancellationToken ct)
    {
        foreach (var candidate in MmcsAuthBuilder.RecordNameLookupCandidates(recordName))
        {
            var viaQuery = await _query.FetchAssetViaQueryAsync(session, candidate, _restoreState, ct);
            if (viaQuery is not null)
                return viaQuery;

            var viaRetrieve = await _query.FetchAssetAsync(session, candidate, ct);
            if (viaRetrieve is not null)
                return viaRetrieve;
        }

        return null;
    }

    private static void PruneShadowAssetNames(HashSet<string> names)
    {
        foreach (var name in names.Where(static n => n.StartsWith("A:", StringComparison.Ordinal)).ToList())
        {
            if (names.Contains("K" + name, StringComparer.Ordinal))
                names.Remove(name);
        }
    }

    private async Task ProbeDiscoveredAssetManifestsAsync(
        ICloudSession session,
        BackupDevice device,
        HashSet<string> recordNames,
        IReadOnlyList<BackupAsset> extraAssets,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var assets = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        foreach (var asset in extraAssets)
            assets[asset.RecordName] = asset;

        foreach (var asset in assets.Values)
        {
            if (string.IsNullOrWhiteSpace(asset.MmcsAuth))
                continue;

            log?.Report($"CloudKit: probe manifest asset {asset.RecordName}…");
            var probe = await ProbeManifestByAuthAsync(
                session, asset.MmcsAuth, asset.ZoneName ?? DefaultZone, log, ct);
            var added = 0;
            foreach (var name in probe.RecordNames)
            {
                if (recordNames.Add(name))
                    added++;
            }

            foreach (var bag in probe.Keybags)
            {
                if (!device.Keybags.Contains(bag, StringComparer.Ordinal))
                    device.Keybags.Add(bag);
            }

            if (probe.RecordNames.Count > 0 || probe.Keybags.Count > 0)
            {
                log?.Report($"  probe {asset.RecordName} → {probe.RecordNames.Count} nomi (+{added}), " +
                            $"{probe.Keybags.Count} keybag, {probe.ByteLength:N0} byte");
            }
            else
            {
                log?.Report($"  probe {asset.RecordName} → 0 nomi ({probe.ByteLength:N0} byte, blob cifrato?)");
            }
        }
    }

    private sealed record ManifestProbeResult(
        IReadOnlyList<string> RecordNames,
        IReadOnlyList<string> Keybags,
        int ByteLength);

    private async Task<ManifestProbeResult> ProbeManifestByAuthAsync(
        ICloudSession session,
        string mmcsAuth,
        string zoneName,
        IProgress<string>? log,
        CancellationToken ct)
    {
        try
        {
            var contentHost = $"https://{session.Partition}-content.icloud.com";
            var authBody = await AuthorizeGetRawAsync(session, contentHost, mmcsAuth, zoneName, ct);
            if (authBody is not { Length: > 0 })
            {
                log?.Report("  authorizeGet HTTP non-OK o body vuoto");
                return new ManifestProbeResult([], [], 0);
            }

            var chunks = UbChunkBuilder.ParseAuthorizeGetResponse(authBody);
            if (chunks.Count == 0)
            {
                log?.Report("  authorizeGet senza chunk");
                return new ManifestProbeResult([], [], 0);
            }

            return await DownloadProbeChunksAsync(chunks, log, ct);
        }
        catch (Exception ex)
        {
            log?.Report($"  probe manifest skip: {ex.Message}");
            return new ManifestProbeResult([], [], 0);
        }
    }

    private async Task EnrichDeviceKeybagsAsync(
        ICloudSession session,
        BackupDevice device,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (device.Keybags.Count > 0)
            return;

        log?.Report($"CloudKit: keybag da {CloudKitRecordNames.DeviceRecord(device.DeviceUuid)}…");
        try
        {
            var payload = await TryFetchMbksyncRecordAsync(
                session,
                CloudKitRecordNames.DeviceRecord(device.DeviceUuid),
                log,
                ct);

            if (payload is null or { Length: 0 })
                return;

            foreach (var bag in CloudKitResponseParser.ExtractKeybags(payload))
                device.Keybags.Add(bag);
            foreach (var asset in CloudKitResponseParser.ExtractAssetRecordNames(payload))
                device.AssetHints.Add(asset);
            log?.Report($"  {device.Keybags.Count} keybag, {device.AssetHints.Count} hint asset");
        }
        catch (Exception ex)
        {
            log?.Report($"  keybag skip: {ex.Message}");
        }

        if (device.Keybags.Count == 0)
            await EnrichKeybagsFromSnapshotRecordsAsync(session, device, log, ct);
    }

    private async Task EnrichKeybagsFromSnapshotRecordsAsync(
        ICloudSession session,
        BackupDevice device,
        IProgress<string>? log,
        CancellationToken ct)
    {
        foreach (var snapshot in device.Snapshots)
        {
            if (string.IsNullOrWhiteSpace(snapshot.RecordName))
                continue;

            try
            {
                var payload = await TryFetchMbksyncRecordAsync(
                    session,
                    CloudKitRecordNames.CanonicalSnapshotRecordName(snapshot.RecordName),
                    log,
                    ct);
                if (payload is null)
                    continue;

                foreach (var bag in CloudKitResponseParser.ExtractKeybags(payload))
                {
                    if (!device.Keybags.Contains(bag, StringComparer.Ordinal))
                        device.Keybags.Add(bag);
                }
            }
            catch
            {
                // best-effort
            }
        }

        if (device.Keybags.Count > 0)
            log?.Report($"  keybag da snapshot → {device.Keybags.Count} totali");
    }

    private async Task ScanCloudKitRecordAsync(
        ICloudSession session,
        string recordName,
        string zoneName,
        HashSet<string> sink,
        BackupDevice? device,
        IProgress<string>? log,
        CancellationToken ct)
    {
        log?.Report($"CloudKit: scan {recordName}…");
        var payload = await TryFetchMbksyncRecordAsync(session, recordName, log, ct);
        if (payload is not { Length: > 0 })
            return;

        foreach (var asset in CloudKitResponseParser.ExtractAssetRecordNames(payload))
            sink.Add(asset);
        if (device is not null)
        {
            foreach (var bag in CloudKitResponseParser.ExtractKeybags(payload))
            {
                if (!device.Keybags.Contains(bag, StringComparer.Ordinal))
                    device.Keybags.Add(bag);
            }
        }
    }

    private async Task ExpandListingAssetsRecursiveAsync(
        ICloudSession session,
        HashSet<string> recordNames,
        IProgress<string>? log,
        CancellationToken ct)
    {
        const int maxListings = 256;
        var expanded = new HashSet<string>(StringComparer.Ordinal);
        var queue = new Queue<string>(recordNames.Where(static n =>
            n.StartsWith("LA:", StringComparison.Ordinal)
            || n.StartsWith("NA:", StringComparison.Ordinal)));

        while (queue.Count > 0 && expanded.Count < maxListings)
        {
            ct.ThrowIfCancellationRequested();
            var listRecord = queue.Dequeue();
            if (!expanded.Add(listRecord))
                continue;

            log?.Report($"CloudKit: espansione listing {listRecord}…");
            try
            {
                await PaceGatewayAsync(ct);
                foreach (var name in await _query.QueryFetchRecordAsync(session, listRecord, log, ct))
                {
                    if (recordNames.Add(name)
                        && (name.StartsWith("LA:", StringComparison.Ordinal)
                            || name.StartsWith("NA:", StringComparison.Ordinal)))
                    {
                        queue.Enqueue(name);
                    }
                }

                var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
                    session.CloudKitUserId, DefaultZone, [listRecord]);
                var payload = await _gateway.RecordRetrieveAsync(session, body, ct);
                foreach (var asset in CloudKitResponseParser.ExtractAssetRecordNames(payload))
                {
                    if (recordNames.Add(asset)
                        && (asset.StartsWith("LA:", StringComparison.Ordinal)
                            || asset.StartsWith("NA:", StringComparison.Ordinal)))
                    {
                        queue.Enqueue(asset);
                    }
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  listing skip: {ex.Message}");
            }
        }

        if (expanded.Count > 0)
            log?.Report($"  listing: espansi {expanded.Count} record LA/NA → {recordNames.Count} nomi totali");
    }
}
