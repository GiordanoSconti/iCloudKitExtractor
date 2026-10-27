using System.IO;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Ramo Photos di iCloud Sync Data: ckAppInit <c>com.apple.photos.cloud</c> →
/// query/retrieve zona <c>PrimarySync</c> (CPLAlbum, CPLContainerRelation,
/// CPLAssetAndMasterByAssetDate + continuation) → download MMCS originali.
/// Flusso <c>capture_http_20260802_054842</c> wo 735/755/765/775/778.
/// </summary>
public sealed class PhotosCloudSyncService
{
    public const string PhotosZone = CplPhotosRecordParser.PhotosZone;
    private const int MaxAssetPages = 40;
    /// <summary>MMCS edge GET in parallelo (1 file bloccava tutto su video ~GB).</summary>
    private const int DownloadParallelism = 4;
    private static readonly TimeSpan AuthorizeGetTimeout = TimeSpan.FromSeconds(45);

    private readonly HttpClient _http;
    private readonly CloudKitGatewayClient _gateway;
    private SyncDataAnisetteRefresh? _anisetteRefresh;

    public PhotosCloudSyncService(HttpClient http, CloudKitGatewayClient gateway)
    {
        _http = http;
        _gateway = gateway;
    }

    public void SetAnisetteRefresh(SyncDataAnisetteRefresh? refresh) =>
        _anisetteRefresh = refresh;

    private Task EnsureAnisetteFreshAsync(
        ICloudSession session,
        IProgress<string>? log,
        CancellationToken ct,
        bool force = false) =>
        _anisetteRefresh is null
            ? Task.CompletedTask
            : _anisetteRefresh.EnsureFreshAsync(session, log, ct, force);

    public async Task<SyncDataContainerResult> RecoverAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct,
        bool buildRecordMetadata = false)
    {
        Directory.CreateDirectory(outDir);
        var photosDir = Path.Combine(outDir, "photos");
        Directory.CreateDirectory(photosDir);
        long totalBytes = 0;

        try
        {
            // Resume dinamico: se questa cartella ha già ciphertext + KEK ma manca
            // crypto/Album, salta rete e completa decrypt+organize sulla stessa outDir.
            if (LooksLikeIncompletePhotosCloudDir(outDir))
            {
                log?.Report("  Photos: ripresa sessione incompleta (skip download/query)…");
                                var resumed = await DecryptAndOrganizeExistingAsync(
                    session, outDir, httpRunDir: null, log, progress, ct,
                    buildRecordMetadata: buildRecordMetadata);
                return new SyncDataContainerResult(
                    binding.ContainerId, true, totalBytes,
                    $"resume decrypt={resumed.Ok}/{resumed.Total}");
            }

            log?.Report($"  Photos CPL → zona {PhotosZone}");
            progress?.Report(new SyncDataProgressReport("Photos: zone/retrieve…", 8));

            byte[]? zonePayload = null;
            try
            {
                var zoneBody = CloudKitDelimitedRequest.BuildZoneRetrieve(
                    session.CloudKitUserId, [PhotosZone], container: binding);
                zonePayload = await _gateway.ZoneRetrieveAsync(session, zoneBody, ct, container: binding);
                zonePayload = CplPhotosRecordParser.MaybeDecompress(zonePayload);
                totalBytes += zonePayload.Length;
                await File.WriteAllBytesAsync(Path.Combine(outDir, "zones_PrimarySync.bin"), zonePayload, ct);
                var zoneNote = CloudKitResponseParser.IsCloudKitErrorPayload(zonePayload, out var zerr)
                    ? zerr
                    : CloudKitResponseParser.DescribeCompactPayload(zonePayload);
                log?.Report($"  zone/retrieve {PhotosZone} → {zonePayload.Length:N0} B" +
                            (zoneNote is null ? "" : $" — {zoneNote}"));
            }
            catch (Exception ex)
            {
                log?.Report($"  zone/retrieve {PhotosZone} skip: {ex.Message}");
            }

            progress?.Report(new SyncDataProgressReport("Photos: query album…", 12));
            var albumsPayload = await QueryAsync(
                session, binding, outDir, "query_cplalbum",
                "CPLRecordByType", "type", "CPLAlbum",
                continuationRecord: null, continuationMarker: null, log, ct);
            totalBytes += albumsPayload.Length;

            progress?.Report(new SyncDataProgressReport("Photos: query relazioni…", 16));
            var relationsPayload = await QueryAsync(
                session, binding, outDir, "query_cplcontainerrelation",
                "CPLRecordByType", "type", "CPLContainerRelation",
                continuationRecord: null, continuationMarker: null, log, ct);
            totalBytes += relationsPayload.Length;

            var assetPages = new List<byte[]>();
            string? contRecord = null;
            byte[]? contMarker = null;
            for (var page = 1; page <= MaxAssetPages; page++)
            {
                ct.ThrowIfCancellationRequested();
                await EnsureAnisetteFreshAsync(session, log, ct).ConfigureAwait(false);
                progress?.Report(new SyncDataProgressReport(
                    $"Photos: query asset pagina {page}…",
                    Math.Min(34, 18 + page * 3)));
                var tag = $"query_cplasset_p{page}";
                byte[] pagePayload;
                try
                {
                    pagePayload = await QueryAsync(
                        session, binding, outDir, tag,
                        "CPLAssetAndMasterByAssetDate",
                        filterFieldName: null, filterEqualsValue: null,
                        contRecord, contMarker, log, ct);
                }
                catch (Exception ex) when (page > 1)
                {
                    log?.Report(
                        $"    → page {page} skip: {ex.Message} — continuo con {assetPages.Count} pagina/e già scaricate");
                    break;
                }

                totalBytes += pagePayload.Length;
                assetPages.Add(pagePayload);

                var cont = CplPhotosRecordParser.ExtractContinuation(pagePayload);

                if (!cont.MoreComing
                    || string.IsNullOrWhiteSpace(cont.LastRecordName)
                    || cont.Marker is not { Length: > 0 })
                    break;
                if (string.Equals(cont.LastRecordName, contRecord, StringComparison.OrdinalIgnoreCase)
                    && pagePayload.Length < 8_000)
                    break;
                contRecord = cont.LastRecordName;
                contMarker = cont.Marker;
            }

            progress?.Report(new SyncDataProgressReport("Photos: parsing CPL…", 36));
            var albums = CplPhotosRecordParser.ParseAlbums(albumsPayload);
            var relations = CplPhotosRecordParser.ParseRelations(relationsPayload);
            var media = assetPages.SelectMany(CplPhotosRecordParser.ParseMedia).ToList();
            var withAuth = media.Count(static m => !string.IsNullOrWhiteSpace(m.MmcsAuth));
            var hidden = media.Count(static m => m.Hidden);
            var trashed = media.Count(static m => m.Trashed);

            log?.Report(
                $"  CPL: album={albums.Count} relazioni={relations.Count} " +
                $"media={media.Count} (mmcs={withAuth} hidden={hidden} trashed={trashed})");

            var albumNames = DecryptAlbumNames(session, zonePayload, albumsPayload, albums, log);
            WriteInventory(photosDir, albums, relations, media, albumNames);

            var cache = new PhotosMediaMetaCache(photosDir);
            cache.SaveAlbumNames(albumNames);

            // Download MMCS (I/O) ∥ unwrap PCS pagine (CPU, pool crescente sequenziale).
            // I ciphertext non servono il KEK; il decrypt parte dopo WhenAll.
            log?.Report(
                $"  Photos: download MMCS ∥ PCS unwrap ({withAuth} auth, {assetPages.Count} pagine)…");
            progress?.Report(new SyncDataProgressReport(
                $"Photos: download ∥ unwrap PCS ({withAuth} auth)…", 38,
                PhaseLabel: "Download∥PCS",
                PhasePercent: 0));

            var swOverlap = System.Diagnostics.Stopwatch.StartNew();
            // BuildPcsZonesAndKekAsync è quasi tutto sync CPU fino agli await finali:
            // Task.Run così il download parte davvero in parallelo.
            var unwrapTask = Task.Run(
                async () => await BuildPcsZonesAndKekAsync(
                    session, zonePayload, assetPages, photosDir, media, log, progress, ct,
                    reportOverallPercent: false).ConfigureAwait(false),
                ct);
            var downloadTask = DownloadMediaAsync(
                session, media, relations, cache,
                photosDir, log, progress, ct);

            await Task.WhenAll(downloadTask, unwrapTask).ConfigureAwait(false);
            var downloaded = await downloadTask.ConfigureAwait(false);
            var (zones, kekPool) = await unwrapTask.ConfigureAwait(false);
            swOverlap.Stop();
            log?.Report(
                $"  Photos: download∥unwrap wall={swOverlap.ElapsedMilliseconds} ms " +
                $"(dl={downloaded}/{withAuth}, zones={zones.Count}, kek={kekPool.Count})");

            // Coda post-download: crypto/ PRIMA (nomi album), poi MMCS, poi organize.
            // Non lasciare che BuildRecordMetadata blocchi crypto + Album/.
            var decrypted = await FinalizePhotosLibraryAsync(
                session,
                binding.ContainerId,
                outDir,
                photosDir,
                zonePayload,
                assetPages,
                albums,
                relations,
                media,
                cache,
                zones,
                kekPool,
                log,
                progress,
                ct,
                buildRecordMetadata: buildRecordMetadata);

            log?.Report(
                $"  Photos: scaricati {downloaded}/{withAuth}, decifrati {decrypted.Ok}/{decrypted.Total} → {photosDir}");
            progress?.Report(new SyncDataProgressReport(
                $"Photos: ok download={downloaded} decrypt={decrypted.Ok}", 98,
                ClearPhase: true));
            return new SyncDataContainerResult(binding.ContainerId, true, totalBytes, null);
        }
        catch (Exception ex)
        {
            var root = ex is AggregateException agg
                ? agg.Flatten().InnerExceptions.FirstOrDefault() ?? ex
                : ex;
            while (root.InnerException is not null
                   && root is not ArgumentOutOfRangeException)
                root = root.InnerException;

            var param = (root as ArgumentOutOfRangeException)?.ParamName;
            var marks = (root.StackTrace ?? ex.StackTrace ?? "")
                .Split('\n')
                .Select(static l => l.Trim())
                .Where(static l => l.Contains("iCloudKitExtractor", StringComparison.Ordinal))
                .Take(6)
                .ToList();
            log?.Report(
                $"  Photos ERRORE: {root.GetType().Name}: {root.Message}" +
                (string.IsNullOrEmpty(param) ? "" : $" (param={param})"));
            foreach (var mark in marks)
                log?.Report($"    at {mark}");
            // #region agent log
            AgentLogPhotos(
                "H-AOR-PHOTOS",
                "PhotosCloudSyncService.RecoverAsync",
                "photos_fatal",
                new
                {
                    type = root.GetType().FullName,
                    msg = root.Message,
                    param,
                    marks,
                    outer = ex.GetType().FullName,
                });
            // #endregion
            return new SyncDataContainerResult(binding.ContainerId, false, totalBytes, root.Message);
        }
    }

    /// <summary>
    /// Se l'<b>ultima</b> cartella <c>sync_data_*</c> sotto <paramref name="backupsRoot"/>
    /// è incompleta (ha materiale Photos ma manca crypto/Album), restituisce quel path.
    /// Nessun stamp hardcodato: solo LastWriteTime della sessione più recente.
    /// </summary>
    public static string? TryGetLatestIncompletePhotosSession(string backupsRoot)
    {
        if (string.IsNullOrWhiteSpace(backupsRoot) || !Directory.Exists(backupsRoot))
            return null;

        var latest = Directory.GetDirectories(backupsRoot, "sync_data_*")
            .Select(static d => new DirectoryInfo(d))
            .OrderByDescending(static d => d.LastWriteTimeUtc)
            .ThenByDescending(static d => d.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault();
        if (latest is null)
            return null;

        var cloud = Path.Combine(latest.FullName, "ck", "apple.photos.cloud");
        if (!LooksLikeIncompletePhotosCloudDir(cloud))
            return null;

        return latest.FullName;
    }

    /// <summary>Compat: alias di <see cref="TryGetLatestIncompletePhotosSession"/>.</summary>
    public static string? TryFindIncompletePhotosSession(string backupsRoot) =>
        TryGetLatestIncompletePhotosSession(backupsRoot);

    public static bool LooksLikeIncompletePhotosCloudDir(string photosCloudDir)
    {
        if (string.IsNullOrWhiteSpace(photosCloudDir) || !Directory.Exists(photosCloudDir))
            return false;

        var photosDir = Path.Combine(photosCloudDir, "photos");
        var sfoglia = Path.Combine(photosDir, "Sfoglia");
        var hasQueries = File.Exists(Path.Combine(photosCloudDir, "query_cplalbum.bin"))
                         || Directory.EnumerateFiles(photosCloudDir, "query_cplasset_p*.bin").Any();
        // Solo ciphertext reale: .ct a 0 B (edge 403) non contano — altrimenti la ripresa
        // resta agganciata a una sessione fallita e salta il re-download.
        var hasCipher = HasSubstantialCiphertext(sfoglia);

        // Deve esserci progresso locale (query e/o ciphertext), altrimenti è una cartella vuota.
        if (!hasQueries && !hasCipher)
            return false;

        // Query CPL ok ma zero body scaricati → NON riprendere: rifai download MMCS.
        if (hasQueries && !hasCipher)
            return false;

        var crypto = Path.Combine(photosCloudDir, "crypto");
        var album = Path.Combine(photosDir, "Album");
        var hasCrypto = Directory.Exists(crypto)
                        && Directory.EnumerateFileSystemEntries(crypto).Any();
        var hasAlbum = Directory.Exists(album)
                       && Directory.EnumerateFileSystemEntries(album).Any();

        // Completa solo se ci sono sia crypto/ sia Album/.
        return !hasCrypto || !hasAlbum;
    }

    /// <summary>True se Sfoglia ha almeno un .ct/.bin con payload (non stub da 403).</summary>
    public static bool HasSubstantialCiphertext(string sfogliaDir)
    {
        if (string.IsNullOrWhiteSpace(sfogliaDir) || !Directory.Exists(sfogliaDir))
            return false;

        const long minBytes = 64_000;
        foreach (var f in Directory.EnumerateFiles(sfogliaDir, "*.ct"))
        {
            try
            {
                if (new FileInfo(f).Length > minBytes)
                    return true;
            }
            catch
            {
                // ignore
            }
        }

        foreach (var f in Directory.EnumerateFiles(sfogliaDir, "*.bin"))
        {
            if (f.EndsWith(".ag.bin", StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                if (new FileInfo(f).Length > minBytes)
                    return true;
            }
            catch
            {
                // ignore
            }
        }

        return false;
    }

    /// <summary>
    /// crypto/ dump → (opz.) metadati per-record → MMCS decrypt → Album/Nascoste/Eliminate/Preferiti.
    /// Ogni fase è isolata: un fallimento non salta organize se crypto è disponibile.
    /// </summary>
    private async Task<(int Ok, int Fail, int Total)> FinalizePhotosLibraryAsync(
        ICloudSession session,
        string containerId,
        string outDir,
        string photosDir,
        byte[]? zonePayload,
        List<byte[]> assetPages,
        IReadOnlyList<CplPhotosRecordParser.CplAlbum> albums,
        IReadOnlyList<CplPhotosRecordParser.CplRelation> relations,
        IReadOnlyList<CplPhotosRecordParser.CplMedia> media,
        PhotosMediaMetaCache cache,
        IReadOnlyList<ProtectionZoneKeys>? zones,
        List<byte[]>? kekPool,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct,
        bool buildRecordMetadata = false)
    {
        // 1) PCS dump → crypto/ (fonte nomi album/file per OrganizeAsync)
        TryDumpPhotosCrypto(session, outDir, containerId, log, progress);

        // 2) Decrypt MMCS ciphertext → immagini in Sfoglia
        //    (prima di BuildRecordMetadata: run 134146 restava bloccata sui metadati
        //    con zones=[] e non raggiungeva mai MMCS).
        var decrypted = (Ok: 0, Fail: 0, Total: 0, KekCount: 0);
        try
        {
            decrypted = await DecryptDownloadedMediaAsync(
                session, zonePayload, assetPages, photosDir, media,
                agByCipherSize: null, log, progress, ct, cache, kekPool);
            log?.Report($"  Photos MMCS decrypt: {decrypted.Ok}/{decrypted.Total} (fail={decrypted.Fail})");
                    }
        catch (Exception ex)
        {
            log?.Report($"  Photos MMCS decrypt skip: {ex.Message}");
                    }

        // 3) Sempre: catalogo crypto + cartelle Album/Nascoste/Eliminate/Preferiti + Photos.db
        progress?.Report(new SyncDataProgressReport(
            "Photos: organizza libreria…", 96,
            PhaseLabel: "Organizza",
            PhaseIndeterminate: true));
        try
        {
            var catalog = PhotosCryptoPlaintextCatalog.LoadInto(outDir, cache, albums, log);
            // #region agent log
            AgentLogPhotos(
                "H-P1",
                "PhotosCloudSyncService.cs:organize",
                "organize_start",
                new
                {
                    entries = cache.Entries.Count,
                    slashNames = cache.Entries.Count(e => (e.RecordName ?? "").Contains('/')),
                    albums = albums.Count,
                });
            // #endregion
            await PhotosLibraryOrganizer.OrganizeAsync(
                photosDir, cache, albums, relations, catalog.AlbumNames, log, ct);
            // #region agent log
            AgentLogPhotos(
                "H-P1",
                "PhotosCloudSyncService.cs:organize",
                "organize_ok",
                new { entries = cache.Entries.Count });
            // #endregion
            WriteInventory(photosDir, albums, relations, media, catalog.AlbumNames);
            PhotosViewerPublisher.Publish(photosDir, log);
            log?.Report(
                $"  inventory.json: nomi album aggiornati " +
                $"({CountNamedAlbums(albums, catalog.AlbumNames)}/{albums.Count(a => !a.IsRootFolder)})");
                    }
        catch (Exception ex)
        {
            log?.Report($"  Photos organize ERRORE: {ex.Message}");
            // Non abortire Sync Photos: crypto/MMCS possono essere ok; l'utente può
            // rieseguire organize. Prima: EnumerateFiles su RecordName con '/' crashava.
        }

        // 4) Metadati PCS per-record — opzionale (checkbox UI Sync Data).
        if (!buildRecordMetadata)
        {
            log?.Report("  Photos: BuildRecordMetadata skip (opzione OFF)");
                        return (decrypted.Ok, decrypted.Fail, decrypted.Total);
        }

        try
        {
            progress?.Report(new SyncDataProgressReport(
                "Photos: cache metadati PCS…", 97,
                PhaseLabel: "Metadati",
                PhaseIndeterminate: true));
            log?.Report("  Photos: BuildRecordMetadata…");
            var swMeta = System.Diagnostics.Stopwatch.StartNew();
            var metaOk = cache.BuildRecordMetadata(
                session, zonePayload, assetPages, log, zones,
                pageProgress: (pageIdx, pageTotal) =>
                {
                    progress?.Report(new SyncDataProgressReport(
                        $"Metadati PCS pagina {pageIdx}/{pageTotal}…",
                        97,
                        PhaseLabel: "Metadati",
                        PhasePercent: 100.0 * pageIdx / Math.Max(1, pageTotal)));
                });
            swMeta.Stop();
            log?.Report($"  BuildRecordMetadata: ok≈{metaOk} in {swMeta.ElapsedMilliseconds} ms");
        }
        catch (Exception ex)
        {
            log?.Report($"  BuildRecordMetadata skip: {ex.Message}");
                    }

        return (decrypted.Ok, decrypted.Fail, decrypted.Total);
    }

    private static void TryDumpPhotosCrypto(
        ICloudSession session,
        string outDir,
        string containerId,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress)
    {
        if (!PcsSessionSeedKeys.HasAny(session))
        {
            log?.Report("  PCS decrypt skip: né Escrow KeySet né Manatee in sessione");
            return;
        }

        try
        {
            log?.Report("  PCS decrypt metadati (crypto/ dump)…");
            progress?.Report(new SyncDataProgressReport(
                "PCS decrypt metadati…", 82, IsIndeterminate: true));
            var dec = SyncDataPcsDecryptor.DecryptContainerDirectory(
                session, outDir, containerId, log);
            if (dec.DecryptedCount > 0)
                log?.Report($"  → crypto/: {dec.Message}");
                    }
        catch (Exception ex)
        {
            log?.Report($"  PCS decrypt skip: {ex.Message}");
                    }
    }


    private async Task<byte[]> QueryAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string outDir,
        string tag,
        string queryRecordType,
        string? filterFieldName,
        string? filterEqualsValue,
        string? continuationRecord,
        byte[]? continuationMarker,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var body = CloudKitDelimitedRequest.BuildCplQueryRetrieve(
            session.CloudKitUserId,
            PhotosZone,
            queryRecordType,
            binding,
            filterFieldName,
            filterEqualsValue,
            continuationRecord,
            continuationMarker);
        log?.Report(
            $"  query/retrieve {queryRecordType}" +
            (filterEqualsValue is null ? "" : $" type={filterEqualsValue}") +
            (continuationRecord is null ? "" : " [page+]") + "…");

        var payload = await _gateway.QueryRetrieveAsync(session, body, ct, container: binding);
        payload = CplPhotosRecordParser.MaybeDecompress(payload);
        await File.WriteAllBytesAsync(Path.Combine(outDir, tag + ".bin"), payload, ct);
        var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
        await File.WriteAllLinesAsync(Path.Combine(outDir, tag + "_strings.txt"), strings, ct);

        var note = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err)
            ? err
            : CloudKitResponseParser.DescribeCompactPayload(payload);
        log?.Report($"    → {payload.Length:N0} B" + (note is null ? "" : $" — {note}"));

        return payload;
    }

    private static Dictionary<string, string> DecryptAlbumNames(
        ICloudSession session,
        byte[]? zonePayload,
        byte[] albumsPayload,
        IReadOnlyList<CplPhotosRecordParser.CplAlbum> albums,
        IProgress<string>? log)
    {
        var names = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var album in albums.Where(static a => a.IsRootFolder))
            names[album.RecordName] = "Root";

        if (!PcsSessionSeedKeys.HasAny(session))
            return names;

        try
        {
            var seedKeys = PcsSessionSeedKeys.CollectForSyncData(session, log);
            var pool = new List<PcsCompactPrivateKey>(seedKeys);
            var zones = new List<ProtectionZoneKeys>();
            if (zonePayload is { Length: > 32 })
                zones.AddRange(PcsProtectionZone.TryUnwrapAll(zonePayload, seedKeys));
            zones.AddRange(PcsProtectionZone.TryUnwrapAll(albumsPayload, pool));
            pool = PcsProtectionZone.MergeKeys(pool, zones);

            var fields = CloudKitEncryptedFieldScanner.Scan(albumsPayload, ["albumNameEnc"]);
            var named = fields.Where(static f => f.FieldName == "albumNameEnc").ToList();
            var albumSet = albums.Select(static a => a.RecordName)
                .ToHashSet(StringComparer.OrdinalIgnoreCase);
            var ok = 0;
            var fallbackIdx = 0;
            var namedAlbums = albums.Where(static a => a.HasEncryptedName).ToList();

            foreach (var field in named)
            {
                var plain = TryDecryptField(field.Ciphertext, "albumNameEnc", zones, seedKeys);
                if (plain is not { Length: > 0 })
                    continue;
                var text = Encoding.UTF8.GetString(plain).Trim().Trim('\0');
                if (string.IsNullOrWhiteSpace(text))
                    continue;

                var recordName = CplPhotosRecordParser.TryFindUuidForEncryptedField(
                    albumsPayload, field.Offset, "albumNameEnc");
                if (recordName is not null && albumSet.Contains(recordName))
                {
                    names[recordName] = text;
                    ok++;
                    continue;
                }

                // Fallback zip-order se UUID non legibile.
                if (fallbackIdx < namedAlbums.Count)
                {
                    names[namedAlbums[fallbackIdx].RecordName] = text;
                    fallbackIdx++;
                    ok++;
                }
            }

            if (ok > 0)
                log?.Report($"  albumNameEnc decrypt {ok}/{named.Count}");
        }
        catch (Exception ex)
        {
            log?.Report($"  albumNameEnc skip: {ex.Message}");
        }

        return names;
    }

    private static byte[]? TryDecryptField(
        byte[] ciphertext,
        string fieldName,
        List<ProtectionZoneKeys> zones,
        List<PcsCompactPrivateKey> seedKeys)
    {
        var aad = new[] { fieldName, "albumName" };
        foreach (var zone in zones)
        {
            var plain = PcsProtectionZone.TryDecryptField(zone, ciphertext, aad);
            if (plain is { Length: > 0 })
                return plain;
        }

        foreach (var zone in PcsProtectionZone.TryUnwrapAll(ciphertext, seedKeys))
        {
            var plain = PcsProtectionZone.TryDecryptField(zone, ciphertext, aad);
            if (plain is { Length: > 0 })
                return plain;
        }

        return null;
    }

    private static int CountNamedAlbums(
        IReadOnlyList<CplPhotosRecordParser.CplAlbum> albums,
        IReadOnlyDictionary<string, string> albumNames) =>
        albums.Count(a =>
            !a.IsRootFolder
            && !string.IsNullOrWhiteSpace(albumNames.GetValueOrDefault(a.RecordName)));

    private static void WriteInventory(
        string photosDir,
        IReadOnlyList<CplPhotosRecordParser.CplAlbum> albums,
        IReadOnlyList<CplPhotosRecordParser.CplRelation> relations,
        IReadOnlyList<CplPhotosRecordParser.CplMedia> media,
        IReadOnlyDictionary<string, string> albumNames)
    {
        var json = JsonSerializer.Serialize(new
        {
            zone = PhotosZone,
            albums = albums.Select(a => new
            {
                a.RecordName,
                a.AlbumType,
                a.IsRootFolder,
                name = albumNames.GetValueOrDefault(a.RecordName),
                folder = CplPhotosRecordParser.ClassifyAlbumFolder(
                    a, albumNames.GetValueOrDefault(a.RecordName))
            }),
            relationCount = relations.Count,
            mediaCount = media.Count,
            hidden = media.Count(m => m.Hidden),
            trashed = media.Count(m => m.Trashed),
            favorites = media.Count(m => m.Favorite),
            withMmcs = media.Count(m => !string.IsNullOrWhiteSpace(m.MmcsAuth)),
        }, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path.Combine(photosDir, "inventory.json"), json);

        var relLines = new List<string> { "itemId\tcontainerId" };
        relLines.AddRange(relations.Select(r => $"{r.ItemId}\t{r.ContainerId}"));
        File.WriteAllLines(Path.Combine(photosDir, "relations.tsv"), relLines);
    }

    private async Task<int> DownloadMediaAsync(
        ICloudSession session,
        List<CplPhotosRecordParser.CplMedia> media,
        IReadOnlyList<CplPhotosRecordParser.CplRelation> relations,
        PhotosMediaMetaCache cache,
        string photosDir,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct)
    {
        var allPhotos = Path.Combine(photosDir, "Sfoglia");
        Directory.CreateDirectory(allPhotos);
        // Album/Nascoste/Eliminate/Preferiti si riempiono dopo decrypt (nomi originali).

        var containersByItem = relations
            .GroupBy(r => r.ItemId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Select(x => x.ContainerId).ToList(), StringComparer.OrdinalIgnoreCase);

        var downloadables = media
            .Where(static m => !string.IsNullOrWhiteSpace(m.MmcsAuth))
            .GroupBy(static m => m.MmcsAuth!, StringComparer.Ordinal)
            .Select(ChoosePreferred)
            .ToList();


        if (downloadables.Count == 0)
        {
            log?.Report("  Photos: nessun MMCS auth nelle query asset — skip download");
            progress?.Report(new SyncDataProgressReport("Photos: nessun MMCS auth", 90));
            return 0;
        }

        log?.Report($"  Photos download plan: {downloadables.Count} file unici (da {media.Count} media)");
        progress?.Report(new SyncDataProgressReport(
            $"Photos download 0/{downloadables.Count}", 40));
        log?.Report(
            $"  Photos: download ciphertext MMCS ×{DownloadParallelism} paralleli (+ cache sidecars)…");

        var downloaded = 0;
        var skipped = 0;
        var n = 0;
        var fail403 = 0;
        var gate = new SemaphoreSlim(DownloadParallelism, DownloadParallelism);
        var progressLock = new object();
        var lastProgressLog = DateTime.UtcNow;

        async Task WorkerAsync(CplPhotosRecordParser.CplMedia item)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ct.ThrowIfCancellationRequested();
                await EnsureAnisetteFreshAsync(session, log, ct).ConfigureAwait(false);

                // Skip se .ct già presente (ripresa / retry) — evita rifare video da 900 MB.
                var tokenHint = SanitizeFileToken(item.RecordName);
                var existing = Path.Combine(allPhotos, tokenHint + ".ct");
                if (File.Exists(existing) && new FileInfo(existing).Length > 64_000)
                {
                    Interlocked.Increment(ref skipped);
                    var doneSkip = Interlocked.Increment(ref n);
                    ReportDownloadProgress(
                        doneSkip, downloadables.Count, downloaded, skipped,
                        progress, log, progressLock, ref lastProgressLog, force: false);
                    return;
                }

                var sizeHint = item.SizeBytes ?? 0;
                if (sizeHint >= 40_000_000)
                {
                    log?.Report(
                        $"  Photos DL grande ~{sizeHint / 1_000_000.0:0} MB {item.RecordName}…");
                }

                var sw = System.Diagnostics.Stopwatch.StartNew();
                var ok = await TryDownloadOneAsync(
                    session, item, allPhotos, containersByItem, cache, log, ct)
                    .ConfigureAwait(false);
                sw.Stop();

                if (ok)
                    Interlocked.Increment(ref downloaded);
                var done = Interlocked.Increment(ref n);
                if (sizeHint >= 40_000_000 || sw.ElapsedMilliseconds >= 20_000)
                {
                    log?.Report(
                        $"  Photos DL {(ok ? "ok" : "fail")} {item.RecordName} " +
                        $"in {sw.Elapsed.TotalSeconds:0.0}s");
                }

                ReportDownloadProgress(
                    done, downloadables.Count, downloaded, skipped,
                    progress, log, progressLock, ref lastProgressLog,
                    force: done == downloadables.Count);
            }
            catch (Exception ex)
            {
                Interlocked.Increment(ref n);
                if (ex.Message.Contains("403", StringComparison.Ordinal))
                    Interlocked.Increment(ref fail403);
                log?.Report($"  Photos skip {item.RecordName}: {ex.Message}");
            }
            finally
            {
                gate.Release();
            }
        }

        await Task.WhenAll(downloadables.Select(WorkerAsync)).ConfigureAwait(false);

        cache.SaveIndex();
        log?.Report(
            $"  decrypt_cache: {cache.Entries.Count} entry → {cache.CacheDirectory} " +
            $"(downloaded={downloaded} skipped={skipped})");
                return downloaded;
    }

    private static void ReportDownloadProgress(
        int done,
        int total,
        int downloaded,
        int skipped,
        IProgress<SyncDataProgressReport>? progress,
        IProgress<string>? log,
        object progressLock,
        ref DateTime lastProgressLogUtc,
        bool force)
    {
        var pct = 40 + 40.0 * done / Math.Max(1, total);
        var phasePct = 100.0 * done / Math.Max(1, total);
        if (done == 1 || done % 5 == 0 || force)
        {
            progress?.Report(new SyncDataProgressReport(
                $"Download {done}/{total} (ok={downloaded} skip={skipped})",
                pct,
                PhaseLabel: "Download",
                PhasePercent: phasePct));
        }

        lock (progressLock)
        {
            var due = force
                       || done % 10 == 0
                       || DateTime.UtcNow - lastProgressLogUtc >= TimeSpan.FromSeconds(15);
            if (!due)
                return;
            lastProgressLogUtc = DateTime.UtcNow;
            log?.Report(
                $"  Photos download {done}/{total} (ok={downloaded} skip={skipped})");
        }
    }

    /// <summary>
    /// Decifra una cartella Photos già scaricata (es. sync_data_*/ck/apple.photos.cloud):
    /// ciphertext .bin/.ct + query CPL su disco + KeySet sessione.
    /// Gli authorizeGet mancanti si recuperano dai log HTTP della run
    /// (<c>%AppData%/iCloudKitExtractor/logs/run_*</c>), non dalla rete.
    /// </summary>
    public async Task<(int Ok, int Fail, int Total, int KekCount)> DecryptExistingPhotosFolderAsync(
        ICloudSession session,
        string photosCloudDir,
        string? httpRunDir,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct)
    {
        var photosDir = Path.Combine(photosCloudDir, "photos");
        var allPhotos = Path.Combine(photosDir, "Sfoglia");
        if (!Directory.Exists(allPhotos))
            throw new DirectoryNotFoundException($"Sfoglia assente: {allPhotos}");

        byte[]? zonePayload = null;
        var zonePath = Path.Combine(photosCloudDir, "zones_PrimarySync.bin");
        if (File.Exists(zonePath))
            zonePayload = await File.ReadAllBytesAsync(zonePath, ct);

        var assetPages = new List<byte[]>();
        foreach (var pagePath in Directory.GetFiles(photosCloudDir, "query_cplasset_p*.bin")
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            assetPages.Add(await File.ReadAllBytesAsync(pagePath, ct));
        }

        if (assetPages.Count == 0)
            throw new InvalidOperationException("Nessuna query_cplasset_p*.bin nella cartella");

        var media = new List<CplPhotosRecordParser.CplMedia>();
        foreach (var page in assetPages)
            media.AddRange(CplPhotosRecordParser.ParseMedia(page));

        httpRunDir ??= TryFindHttpRunWithAuthorizeGet();
        var agBySize = string.IsNullOrWhiteSpace(httpRunDir)
            ? new Dictionary<long, HttpAgEntry>()
            : LoadAuthorizeGetByCipherSize(httpRunDir!);

        log?.Report(
            $"  Photos offline decrypt: dir={photosCloudDir} pages={assetPages.Count} " +
            $"media={media.Count} httpAg={agBySize.Count} run={httpRunDir}");

        return await DecryptDownloadedMediaAsync(
            session, zonePayload, assetPages, photosDir, media, agBySize, log, progress, ct);
    }

    /// <summary>
    /// Offline: decrypt MMCS + metadati PCS + riorganizza Album/ + Photos.db.
    /// </summary>
    public async Task<(int Ok, int Fail, int Total)> DecryptAndOrganizeExistingAsync(
        ICloudSession session,
        string photosCloudDir,
        string? httpRunDir,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct,
        bool buildRecordMetadata = false)
    {
        var photosDir = Path.Combine(photosCloudDir, "photos");
        var albumsPayloadPath = Path.Combine(photosCloudDir, "query_cplalbum.bin");
        var relationsPath = Path.Combine(photosCloudDir, "query_cplcontainerrelation.bin");

        // Sessione già completa (es. 134146 dopo Organize): non rientrare in BRM/organize.
        var albumDir = Path.Combine(photosDir, "Album");
        var photosDb = Path.Combine(photosDir, "Photos.db");
        if (Directory.Exists(albumDir)
            && Directory.EnumerateFileSystemEntries(albumDir).Any()
            && File.Exists(photosDb))
        {
            log?.Report(
                "  Photos: libreria già completa (Album/ + Photos.db) — skip decrypt/organize/BRM");
            return (0, 0, 0);
        }

        byte[]? zonePayload = null;
        var zonePath = Path.Combine(photosCloudDir, "zones_PrimarySync.bin");
        if (File.Exists(zonePath))
            zonePayload = await File.ReadAllBytesAsync(zonePath, ct);

        var albumsPayload = File.Exists(albumsPayloadPath)
            ? await File.ReadAllBytesAsync(albumsPayloadPath, ct)
            : [];
        var relationsPayload = File.Exists(relationsPath)
            ? await File.ReadAllBytesAsync(relationsPath, ct)
            : [];

        var albums = albumsPayload.Length > 0
            ? CplPhotosRecordParser.ParseAlbums(albumsPayload)
            : [];
        var relations = relationsPayload.Length > 0
            ? CplPhotosRecordParser.ParseRelations(relationsPayload)
            : [];

        var assetPages = new List<byte[]>();
        foreach (var pagePath in Directory.GetFiles(photosCloudDir, "query_cplasset_p*.bin")
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
            assetPages.Add(await File.ReadAllBytesAsync(pagePath, ct));

        var media = new List<CplPhotosRecordParser.CplMedia>();
        foreach (var page in assetPages)
            media.AddRange(CplPhotosRecordParser.ParseMedia(page));

        var albumNames = DecryptAlbumNames(session, zonePayload, albumsPayload, albums, log);
        var cache = new PhotosMediaMetaCache(photosDir);
        cache.LoadIfPresent();
        cache.SaveAlbumNames(albumNames);

        // Se manca media_index, ricostruisci dalle sidecars in Sfoglia.
        if (cache.Entries.Count == 0)
            RebuildCacheFromSfoglia(photosDir, media, relations, cache);

        var dec = await DecryptExistingPhotosFolderAsync(
            session, photosCloudDir, httpRunDir, log, progress, ct);


        // crypto/ serve ai nomi album; se già c'è (run precedente) non rifare il dump PCS.
        var cryptoDir = Path.Combine(photosCloudDir, "crypto");
        if (!Directory.Exists(cryptoDir)
            || !Directory.EnumerateFileSystemEntries(cryptoDir).Any())
        {
            TryDumpPhotosCrypto(session, photosCloudDir, "com.apple.photos.cloud", log, progress);
        }
        else
        {
            log?.Report("  crypto/ già presente — skip dump PCS");
        }

        // Organize SUBITO dopo MMCS (prima di BuildRecordMetadata, che su 4 pagine
        // multi-MB può restare silenzioso per decine di minuti e sembrare "bloccato").
        progress?.Report(new SyncDataProgressReport(
            "Photos: organizza libreria…", 96,
            PhaseLabel: "Organizza",
            PhaseIndeterminate: true));
        log?.Report("  Photos: OrganizeAsync (Album / rename / Photos.db)…");
        try
        {
            var catalog = PhotosCryptoPlaintextCatalog.LoadInto(photosCloudDir, cache, albums, log);
            await PhotosLibraryOrganizer.OrganizeAsync(
                photosDir, cache, albums, relations, catalog.AlbumNames, log, ct);
            WriteInventory(photosDir, albums, relations, media, catalog.AlbumNames);
            PhotosViewerPublisher.Publish(photosDir, log);
            log?.Report(
                $"  inventory.json: nomi album aggiornati " +
                $"({CountNamedAlbums(albums, catalog.AlbumNames)}/{albums.Count(a => !a.IsRootFolder)})");
        }
        catch (Exception ex)
        {
            log?.Report($"  Photos organize ERRORE: {ex.Message}");
        }

        // Offline: i nomi file/album arrivano già da crypto/ (Organize). BRM senza zone
        // precomputate rifà unwrap+localTryUnwrap silenzioso per decine di minuti
        // (sessione 134146: post-organize bloccato, zoneOnly=1, ok≈0). Non rieseguire.
        if (buildRecordMetadata)
        {
            log?.Report(
                "  Photos: BuildRecordMetadata skip (offline — libreria già da crypto/; " +
                "usa Sync Data live + checkbox solo se servono nomi PCS extra)");
        }
        else
        {
            log?.Report("  Photos: BuildRecordMetadata skip (opzione OFF)");
        }

        return (dec.Ok, dec.Fail, dec.Total);
    }

    /// <summary>
    /// Solo riorganizzazione finale da crypto/ già presente (nomi album/file + Photos.db).
    /// </summary>
    public async Task<int> ReorganizeFromCryptoAsync(
        string photosCloudDir,
        IProgress<string>? log,
        CancellationToken ct = default)
    {
        var photosDir = Path.Combine(photosCloudDir, "photos");
        var cryptoRoot = Path.Combine(photosCloudDir, "crypto");
        var albumsPayloadPath = Path.Combine(photosCloudDir, "query_cplalbum.bin");
        var relationsPath = Path.Combine(photosCloudDir, "query_cplcontainerrelation.bin");
        var assetPages = Directory.Exists(photosCloudDir)
            ? Directory.GetFiles(photosCloudDir, "query_cplasset_p*.bin")
            : [];


        // Non toccare Album/DB/inventory se manca il materiale crypto/wire: altrimenti
        // un REORG a vuoto azzera metadati su una libreria già scaricata.
        if (!Directory.Exists(cryptoRoot)
            || (!File.Exists(albumsPayloadPath) && assetPages.Length == 0))
        {
            log?.Report("  REORG abortito: manca crypto/ o query_*.bin nella cartella indicata.");
            return 0;
        }

        var albumsPayload = File.Exists(albumsPayloadPath)
            ? await File.ReadAllBytesAsync(albumsPayloadPath, ct)
            : [];
        var relationsPayload = File.Exists(relationsPath)
            ? await File.ReadAllBytesAsync(relationsPath, ct)
            : [];

        var albums = albumsPayload.Length > 0
            ? CplPhotosRecordParser.ParseAlbums(albumsPayload)
            : [];
        var relations = relationsPayload.Length > 0
            ? CplPhotosRecordParser.ParseRelations(relationsPayload)
            : [];

        var cache = new PhotosMediaMetaCache(photosDir);
        cache.LoadIfPresent();

        var media = new List<CplPhotosRecordParser.CplMedia>();
        foreach (var pagePath in assetPages.OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
            media.AddRange(CplPhotosRecordParser.ParseMedia(File.ReadAllBytes(pagePath)));

        var catalog = PhotosCryptoPlaintextCatalog.LoadInto(photosCloudDir, cache, albums, log);

        if (catalog.AlbumMapped == 0
            && catalog.AlbumNames.Count == 0
            && cache.Entries.Count == 0
            && media.Count == 0)
        {
            log?.Report(
                "  REORG abortito: crypto/ presente ma catalogo vuoto (nessun album/media). " +
                "Nessuna modifica a Photos.db / inventory.");
            return 0;
        }

        var renamed = await PhotosLibraryOrganizer.OrganizeAsync(
            photosDir, cache, albums, relations, catalog.AlbumNames, log, ct);

        WriteInventory(photosDir, albums, relations, media, catalog.AlbumNames);
        PhotosViewerPublisher.Publish(photosDir, log);
        log?.Report(
            $"  inventory.json: nomi album aggiornati " +
            $"({CountNamedAlbums(albums, catalog.AlbumNames)}/{albums.Count(a => !a.IsRootFolder)})");

        return renamed;
    }

    private static void RebuildCacheFromSfoglia(
        string photosDir,
        IReadOnlyList<CplPhotosRecordParser.CplMedia> media,
        IReadOnlyList<CplPhotosRecordParser.CplRelation> relations,
        PhotosMediaMetaCache cache)
    {
        var sfoglia = Path.Combine(photosDir, "Sfoglia");
        if (!Directory.Exists(sfoglia))
            return;

        var byAuth = media
            .Where(static m => !string.IsNullOrWhiteSpace(m.MmcsAuth))
            .GroupBy(static m => m.MmcsAuth!, StringComparer.Ordinal)
            .ToDictionary(static g => g.Key, ChoosePreferred, StringComparer.Ordinal);

        var containersByItem = relations
            .GroupBy(r => r.ItemId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                g => g.Key,
                g => g.Select(x => x.ContainerId).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                StringComparer.OrdinalIgnoreCase);

        foreach (var authPath in Directory.EnumerateFiles(sfoglia, "*.mmcsauth.txt"))
        {
            var fileName = Path.GetFileName(authPath);
            if (!fileName.EndsWith(".mmcsauth.txt", StringComparison.OrdinalIgnoreCase))
                continue;
            var token = fileName[..^".mmcsauth.txt".Length];

            var auth = File.ReadAllText(authPath).Trim();
            byAuth.TryGetValue(auth, out var item);
            var wrapPath = Path.Combine(sfoglia, token + ".wrap.hex");
            var wrapHex = File.Exists(wrapPath) ? File.ReadAllText(wrapPath).Trim() : item?.AssetProtectionInfoHex;
            var recordName = item?.RecordName ?? token;
            var relationKey = recordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase)
                ? recordName[..^5]
                : recordName;
            containersByItem.TryGetValue(relationKey, out var albumIds);
            albumIds ??= [];

            cache.AddDownload(new PhotosMediaMetaCache.MediaEntry
            {
                Token = token,
                RecordName = recordName,
                MmcsAuth = auth,
                WrapHex = wrapHex,
                Hidden = item?.Hidden ?? false,
                Trashed = item?.Trashed ?? false,
                Favorite = item?.Favorite ?? false,
                IsLive = recordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase),
                AlbumIds = albumIds.ToList(),
                CipherRelativePath = Path.Combine("Sfoglia", token + ".ct")
            });
        }

        // Fallback: plaintext già decifrati (token = Sanitize(RecordName) o RecordName_SIG8).
        if (cache.Entries.Count == 0)
        {
            var byToken = media
                .GroupBy(m => SanitizeFileToken(m.RecordName), StringComparer.OrdinalIgnoreCase)
                .ToDictionary(g => g.Key, ChoosePreferred, StringComparer.OrdinalIgnoreCase);

            foreach (var path in Directory.EnumerateFiles(sfoglia))
            {
                var ext = Path.GetExtension(path);
                if (ext is ".ct" or ".bin" or ".txt" or ".hex")
                    continue;
                if (path.EndsWith(".ag.bin", StringComparison.OrdinalIgnoreCase))
                    continue;
                var token = Path.GetFileNameWithoutExtension(path);
                // COLLISION_* / SIG8: prova prefisso UUID
                CplPhotosRecordParser.CplMedia? item = null;
                if (byToken.TryGetValue(token, out var exact))
                    item = exact;
                else
                {
                    var underscore = token.LastIndexOf('_');
                    if (underscore > 8)
                    {
                        var baseTok = token[..underscore];
                        byToken.TryGetValue(baseTok, out item);
                    }
                }

                if (item is null)
                    continue;

                var relationKey = item.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase)
                    ? item.RecordName[..^5]
                    : item.RecordName;
                containersByItem.TryGetValue(relationKey, out var albumIds);
                albumIds ??= [];

                cache.AddDownload(new PhotosMediaMetaCache.MediaEntry
                {
                    Token = token,
                    RecordName = item.RecordName,
                    MmcsAuth = item.MmcsAuth,
                    WrapHex = item.AssetProtectionInfoHex,
                    Hidden = item.Hidden,
                    Trashed = item.Trashed,
                    Favorite = item.Favorite,
                    IsLive = item.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase),
                    AlbumIds = albumIds.ToList(),
                    PlainRelativePath = Path.Combine("Sfoglia", Path.GetFileName(path))
                });
            }
        }

        cache.SaveIndex();
    }

    public readonly record struct HttpAgEntry(string AgBodyPath, string? MmcsAuth);

    /// <summary>
    /// Indice authorizeGet dai log HTTP: somma bodyLen edge GET → response authorizeGet (.pb).
    /// </summary>
    public static Dictionary<long, HttpAgEntry> LoadAuthorizeGetByCipherSize(string httpRunDir)
    {
        var exchangePath = Path.Combine(httpRunDir, "http_exchange.jsonl");
        if (!File.Exists(exchangePath))
            return new Dictionary<long, HttpAgEntry>();

        var rows = new List<JsonElement>();
        foreach (var line in File.ReadLines(exchangePath))
        {
            var trimmed = line.Trim().TrimStart('\uFEFF');
            if (trimmed.Length == 0)
                continue;
            rows.Add(JsonSerializer.Deserialize<JsonElement>(trimmed));
        }

        var bySize = new Dictionary<long, HttpAgEntry>();
        var ambiguous = new HashSet<long>();
        for (var i = 0; i < rows.Count; i++)
        {
            if (!rows[i].TryGetProperty("request", out var req))
                continue;
            var url = req.TryGetProperty("url", out var u) ? u.GetString() ?? "" : "";
            if (!url.Contains("authorizeGet", StringComparison.OrdinalIgnoreCase))
                continue;

            string? mmcsAuth = null;
            if (req.TryGetProperty("headers", out var hdrs)
                && hdrs.TryGetProperty("x-apple-mmcs-auth", out var authEl))
            {
                mmcsAuth = authEl.ValueKind == JsonValueKind.Array
                    ? authEl[0].GetString()
                    : authEl.GetString();
            }

            if (!rows[i].TryGetProperty("response", out var resp))
                continue;
            var agRel = resp.TryGetProperty("bodyFile", out var bf) ? bf.GetString() : null;
            if (string.IsNullOrWhiteSpace(agRel))
                continue;
            var agPath = Path.GetFullPath(Path.Combine(httpRunDir, agRel.Replace('/', Path.DirectorySeparatorChar)));
            if (!File.Exists(agPath))
                continue;

            long edgeSum = 0;
            for (var j = i + 1; j < rows.Count; j++)
            {
                if (!rows[j].TryGetProperty("request", out var rq))
                    break;
                var nextUrl = rq.TryGetProperty("url", out var nu) ? nu.GetString() ?? "" : "";
                if (nextUrl.Contains("authorizeGet", StringComparison.OrdinalIgnoreCase))
                    break;
                if (!nextUrl.Contains("icloud-content.com", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!rows[j].TryGetProperty("response", out var er))
                    continue;
                var status = er.TryGetProperty("status", out var st) ? st.GetInt32() : 0;
                var bodyLen = er.TryGetProperty("bodyLen", out var bl) ? bl.GetInt64() : 0;
                if (status is 200 or 206 && bodyLen > 0)
                    edgeSum += bodyLen;
            }

            if (edgeSum <= 0)
                continue;
            if (ambiguous.Contains(edgeSum))
                continue;
            if (bySize.ContainsKey(edgeSum))
            {
                bySize.Remove(edgeSum);
                ambiguous.Add(edgeSum);
                continue;
            }

            bySize[edgeSum] = new HttpAgEntry(agPath, mmcsAuth);
        }

        return bySize;
    }

    public static string? TryFindHttpRunWithAuthorizeGet()
    {
        var root = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "iCloudKitExtractor",
            "logs");
        if (!Directory.Exists(root))
            return null;

        foreach (var dir in Directory.GetDirectories(root, "run_*")
                     .OrderByDescending(static d => d, StringComparer.OrdinalIgnoreCase))
        {
            var bodies = Path.Combine(dir, "http_bodies");
            if (!Directory.Exists(bodies))
                continue;
            if (Directory.EnumerateFiles(bodies, "*authorizeGet_body.pb").Any())
                return dir;
        }

        return null;
    }

    /// <summary>Parallelismo full-scan PCS sulle pagine CPL (DER+light).</summary>
    private static readonly int PcsPageUnwrapParallelism = Math.Clamp(Environment.ProcessorCount, 2, 8);

    /// <summary>
    /// Unwrap zone + pagine CPL → KEK MMCS. Un solo path: full-scan DER+light
    /// (Escrow e Manatee uguali). Pagine in parallelo; 2ª passata sulle pagine a 0
    /// con pool allargato (nested keys).
    /// </summary>
    private async Task<(List<ProtectionZoneKeys> Zones, List<byte[]> KekPool)> BuildPcsZonesAndKekAsync(
        ICloudSession session,
        byte[]? zonePayload,
        List<byte[]> assetPages,
        string photosDir,
        IReadOnlyList<CplPhotosRecordParser.CplMedia>? media,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct,
        bool reportOverallPercent = true)
    {
        _ = media;
        var kekCachePath = Path.Combine(photosDir, "decrypt_cache", "mmcs_kek_pool.hexl");
        Directory.CreateDirectory(Path.GetDirectoryName(kekCachePath)!);
        var legacyKek = Path.Combine(photosDir, "mmcs_kek_pool.hexl");
        if (!File.Exists(kekCachePath) && File.Exists(legacyKek))
            File.Copy(legacyKek, kekCachePath);

        if (session.PcsManateeCompactKeys is not { Count: > 0 })
            _ = EscrowPcsSession.TryLoadManateeFromDisk(
                session,
                session.OctagonKeysDirectory ?? session.PcsKeysDirectory,
                log);

        var seedKeys = PcsSessionSeedKeys.HasAny(session)
            ? PcsSessionSeedKeys.CollectForSyncData(session, log)
            : [];
        if (seedKeys.Count == 0)
        {
            log?.Report(
                "  Photos PCS unwrap: seed vuoto — Unlock EscrowedKeys oppure " +
                "Octagon/CKKS OpenVault (Manatee) prima di Sync Data Photos.");
        }
        else
        {
            log?.Report(
                $"  Photos PCS seed: {PcsSessionSeedKeys.DescribeSeed(session)}" +
                $" → CollectForSyncData={seedKeys.Count}");
        }

        var zones = new List<ProtectionZoneKeys>();
        var pool = new List<PcsCompactPrivateKey>(seedKeys);
        var swAll = System.Diagnostics.Stopwatch.StartNew();
        var fromZoneCount = 0;

        if (seedKeys.Count > 0 && zonePayload is { Length: > 32 })
        {
            var fromZone = await Task.Run(
                    () => PcsProtectionZone.TryUnwrapAll(
                        zonePayload, seedKeys, lightKeys: seedKeys),
                    ct)
                .ConfigureAwait(false);
            if (fromZone.Count > 0)
            {
                zones.AddRange(fromZone);
                pool = PcsProtectionZone.MergeKeys(seedKeys, fromZone);
                fromZoneCount = fromZone.Count;
                PcsSessionSeedKeys.RememberFromZones(session, fromZone, seedKeys);
                log?.Report(
                    $"  PCS unwrap zone PrimarySync: +{fromZone.Count} (pool={pool.Count})");
            }
        }

        if (seedKeys.Count > 0 && assetPages.Count > 0)
        {
            // lightKeys = pool (seed ∪ nested zona): i light 0xFF CPL usano spesso
            // la pub delle nested MasterKeySet, non solo il KeyId zona/seed.
            var dop = Math.Min(PcsPageUnwrapParallelism, Math.Max(1, assetPages.Count));
            log?.Report(
                $"  PCS unwrap: full-scan {assetPages.Count} pagine CPL " +
                $"(DER+light iter ×{dop}; seedKeys={seedKeys.Count}, pool={pool.Count}" +
                (reportOverallPercent ? ")" : "; ∥download)"));

            var poolBeforePages = pool.Count;
            var pass1 = await UnwrapCplPagesParallelAsync(
                    assetPages, pool, log, progress, ct, reportOverallPercent,
                    passLabel: "full")
                .ConfigureAwait(false);

            foreach (var pageZones in pass1)
            {
                if (pageZones.Count == 0)
                    continue;
                zones.AddRange(pageZones);
                pool = PcsProtectionZone.MergeKeys(pool, pageZones);
                PcsSessionSeedKeys.RememberFromZones(session, pageZones, seedKeys);
            }

            // 2ª passata su TUTTE le pagine se il pool EC è cresciuto (nested cross-page).
            if (pool.Count > poolBeforePages)
            {
                log?.Report(
                    $"  PCS unwrap: rescan {assetPages.Count} pagine con pool={pool.Count} " +
                    $"(+{pool.Count - poolBeforePages} nested)…");
                var pass2 = await UnwrapCplPagesParallelAsync(
                        assetPages, pool, log, progress, ct, reportOverallPercent,
                        passLabel: "rescan")
                    .ConfigureAwait(false);
                var seen = new HashSet<string>(
                    zones.Select(static z => Convert.ToHexString(z.MasterKey)),
                    StringComparer.Ordinal);
                foreach (var pageZones in pass2)
                {
                    foreach (var z in pageZones)
                    {
                        if (!seen.Add(Convert.ToHexString(z.MasterKey)))
                            continue;
                        zones.Add(z);
                    }

                    if (pageZones.Count > 0)
                    {
                        pool = PcsProtectionZone.MergeKeys(pool, pageZones);
                        PcsSessionSeedKeys.RememberFromZones(session, pageZones, seedKeys);
                    }
                }
            }
        }

        // Master da recordProtectionInfo media (PI ~400 → MasterKey; ~535 → nested 16 B).
        if (media is { Count: > 0 } && pool.Count > 0)
        {
            var fromRecordPi = 0;
            var seen = new HashSet<string>(
                zones.Select(static z => Convert.ToHexString(z.MasterKey)),
                StringComparer.Ordinal);
            foreach (var m in media)
            {
                if (m.RecordProtectionInfoDerHex is not { Length: > 0 })
                    continue;
                byte[] der;
                try { der = Convert.FromHexString(m.RecordProtectionInfoDerHex); }
                catch { continue; }
                foreach (var z in PcsProtectionZone.TryUnwrapAll(
                             der, pool, includeLight: false, includeDer: true))
                {
                    if (!seen.Add(Convert.ToHexString(z.MasterKey)))
                        continue;
                    zones.Add(z);
                    fromRecordPi++;
                }
            }

            if (fromRecordPi > 0)
            {
                pool = PcsProtectionZone.MergeKeys(pool, zones);
                log?.Report($"  PCS unwrap: +{fromRecordPi} master da recordProtectionInfo media");
            }
        }

        // MasterKey + DecryptKey + nested wrap-ref 16 B (PI ~535 Photos/ADP).
        var kekPool = zones
            .SelectMany(PcsProtectionZone.EnumerateMmcsKekCandidates)
            .Where(static k => k is { Length: >= 16 })
            .Distinct(ByteArrayComparer.Instance)
            .ToList();

        if (kekPool.Count == 0 && File.Exists(kekCachePath))
        {
            kekPool = await LoadKekCacheAsync(kekCachePath, ct).ConfigureAwait(false);
            log?.Report($"  PCS unwrap: pool vuoto → riuso cache kek={kekPool.Count}");
        }
        else if (kekPool.Count > 0)
        {
            await File.WriteAllLinesAsync(
                kekCachePath,
                kekPool.Select(static k => Convert.ToHexString(k)),
                ct).ConfigureAwait(false);
        }

        swAll.Stop();
        log?.Report(
            $"  Photos PCS unwrap: zones={zones.Count} kek={kekPool.Count} " +
            $"in {swAll.ElapsedMilliseconds} ms (full-scan ∥{PcsPageUnwrapParallelism}" +
            (fromZoneCount > 0 ? $", zonePI={fromZoneCount}" : "") + ")");
        if (kekPool.Count == 0 && seedKeys.Count > 0)
        {
            log?.Report(
                "  Photos PCS: nessun KEK da unwrap — le compact Manatee/Escrow " +
                "non aprono ProtectionInfo CPL. Rilancia CKKS OpenVault (view Photos/PCS) " +
                "oppure Unlock EscrowedKeys per questo account.");
        }

        return (zones, kekPool);
    }

    private static async Task<List<ProtectionZoneKeys>[]> UnwrapCplPagesParallelAsync(
        IReadOnlyList<byte[]> pages,
        IReadOnlyList<PcsCompactPrivateKey> pool,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct,
        bool reportOverallPercent,
        string passLabel)
    {
        var results = new List<ProtectionZoneKeys>[pages.Count];
        for (var i = 0; i < pages.Count; i++)
            results[i] = [];

        if (pages.Count == 0)
            return results;

        var done = 0;
        var dop = Math.Min(PcsPageUnwrapParallelism, pages.Count);
        // pool = seed ∪ nested: serve sia a DER sia a light (pub nested nei 0xFF CPL).
        var poolSnapshot = pool.ToList();

        await Parallel.ForEachAsync(
            Enumerable.Range(0, pages.Count),
            new ParallelOptions
            {
                MaxDegreeOfParallelism = dop,
                CancellationToken = ct,
            },
            async (i, token) =>
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                List<ProtectionZoneKeys> fromPage;
                try
                {
                    fromPage = await Task.Run(
                            () => UnwrapOneCplPage(pages[i], poolSnapshot),
                            token)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    fromPage = [];
                    log?.Report(
                        $"  PCS unwrap page {i + 1}/{pages.Count} {passLabel} skip: " +
                        $"{ex.GetType().Name}: {ex.Message}");
                }

                results[i] = fromPage;
                var n = Interlocked.Increment(ref done);
                progress?.Report(new SyncDataProgressReport(
                    $"Chiavi PCS pagina {n}/{pages.Count}…",
                    reportOverallPercent
                        ? 78 + 4.0 * n / Math.Max(1, pages.Count)
                        : null,
                    PhaseLabel: reportOverallPercent ? "CPL PCS" : "CPL PCS∥DL",
                    PhasePercent: 100.0 * n / Math.Max(1, pages.Count)));
                log?.Report(
                    $"  PCS unwrap page {i + 1}/{pages.Count} {passLabel}: +{fromPage.Count} " +
                    $"in {sw.ElapsedMilliseconds} ms");
            }).ConfigureAwait(false);

        return results;
    }

    /// <summary>
    /// Una pagina CPL: DER (tutti i candidati) + light indexed-only (niente ECDH×N
    /// su ogni 0xFF falso positivo). I master MMCS utili sono i PI ~400 B.
    /// </summary>
    private static List<ProtectionZoneKeys> UnwrapOneCplPage(
        byte[] page,
        IReadOnlyList<PcsCompactPrivateKey> pool)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<ProtectionZoneKeys>();

        void AddRange(IEnumerable<ProtectionZoneKeys> zones)
        {
            foreach (var z in zones)
            {
                if (!seen.Add(Convert.ToHexString(z.MasterKey)))
                    continue;
                list.Add(z);
            }
        }

        AddRange(PcsProtectionZone.TryUnwrapAll(
            page, pool, lightKeys: pool, includeLight: false, includeDer: true));
        AddRange(PcsProtectionLight.TryUnwrapAll(page, pool, bruteForceUnknownPub: false));

        // Harvest esplicito PI 380–430 B (wrapping master Photos): la full DER
        // a volte AOR-skippa pezzi di pagina; qui filtriamo per lunghezza.
        foreach (var der in PcsProtectionZone.TryExtractAllRecordProtectionInfoDer(page))
        {
            if (der.Length is < 380 or > 430)
                continue;
            AddRange(PcsProtectionZone.TryUnwrapAll(
                der, pool, includeLight: false, includeDer: true));
        }

        return list;
    }

    private static async Task<List<byte[]>> LoadKekCacheAsync(string path, CancellationToken ct)
    {
        try
        {
            return (await File.ReadAllLinesAsync(path, ct).ConfigureAwait(false))
                .Where(static l => !string.IsNullOrWhiteSpace(l))
                .Select(static l => Convert.FromHexString(l.Trim()))
                .Where(static k => k.Length >= 16)
                .Distinct(ByteArrayComparer.Instance)
                .ToList();
        }
        catch
        {
            return [];
        }
    }

    private async Task<(int Ok, int Fail, int Total, int KekCount)> DecryptDownloadedMediaAsync(
        ICloudSession session,
        byte[]? zonePayload,
        List<byte[]> assetPages,
        string photosDir,
        IReadOnlyList<CplPhotosRecordParser.CplMedia> media,
        IReadOnlyDictionary<long, HttpAgEntry>? agByCipherSize,
        IProgress<string>? log,
        IProgress<SyncDataProgressReport>? progress,
        CancellationToken ct,
        PhotosMediaMetaCache? cache = null,
        List<byte[]>? precomputedKek = null)
    {
        var allPhotos = Path.Combine(photosDir, "Sfoglia");
        if (!Directory.Exists(allPhotos))
            return (0, 0, 0, 0);

        // Run nuove: .ct + sidecar; run legacy: .bin (+ .ag.bin dai log HTTP).
        var cipherFiles = Directory.GetFiles(allPhotos, "*.ct")
            .Concat(Directory.GetFiles(allPhotos, "*.bin")
                .Where(static f => !f.EndsWith(".ag.bin", StringComparison.OrdinalIgnoreCase)))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static f => f, StringComparer.OrdinalIgnoreCase)
            .ToArray();
        if (cipherFiles.Length == 0)
        {
            log?.Report("  Photos MMCS decrypt: nessun .ct/.bin da decifrare");
            return (0, 0, 0, 0);
        }

        var byToken = media
            .Where(static m => !string.IsNullOrWhiteSpace(m.MmcsAuth))
            .GroupBy(m => SanitizeFileToken(m.RecordName), StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                static g => g.Key,
                static g => ChoosePreferred(g),
                StringComparer.OrdinalIgnoreCase);

        var byAuth = media
            .Where(static m => !string.IsNullOrWhiteSpace(m.MmcsAuth))
            .GroupBy(static m => m.MmcsAuth!, StringComparer.Ordinal)
            .ToDictionary(
                static g => g.Key,
                static g => ChoosePreferred(g),
                StringComparer.Ordinal);

        // Wrap: usa quelli già estratti in ParseMedia / cache (niente O(media×pagine) su blob multi-MB).
        var swWrap = System.Diagnostics.Stopwatch.StartNew();
        var wrapBySig = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var m in media)
        {
            if (m.MmcsAuth is null || m.AssetProtectionInfoHex is not { Length: > 0 })
                continue;
            if (!MmcsAuthBuilder.TrySplitMmcsAuth(m.MmcsAuth, out var sig21, out _, out _))
                continue;
            wrapBySig.TryAdd(Convert.ToHexString(sig21), m.AssetProtectionInfoHex);
        }

        if (cache is not null)
        {
            foreach (var e in cache.Entries)
            {
                if (e.MmcsAuth is null || e.WrapHex is not { Length: > 0 })
                    continue;
                if (!MmcsAuthBuilder.TrySplitMmcsAuth(e.MmcsAuth, out var sig21, out _, out _))
                    continue;
                wrapBySig.TryAdd(Convert.ToHexString(sig21), e.WrapHex);
            }
        }

        // Solo per signature ancora senza wrap: una passata EnumerateAssets per pagina.
        if (wrapBySig.Count < media.Count(static m => m.MmcsAuth is not null))
        {
            foreach (var page in assetPages)
            {
                foreach (var asset in CloudKitAssetProto.EnumerateAssets(page))
                {
                    if (asset.Signature is not { Length: > 0 } || asset.ProtectionWrap is not { Length: 24 or 40 })
                        continue;
                    wrapBySig.TryAdd(
                        Convert.ToHexString(asset.Signature),
                        Convert.ToHexString(asset.ProtectionWrap));
                }
            }
        }

        swWrap.Stop();

        progress?.Report(new SyncDataProgressReport(
            "Photos: decrypt MMCS…", 86, IsIndeterminate: true));
        log?.Report(
            $"  Photos MMCS decrypt: {cipherFiles.Length} ciphertext, wrapBySig={wrapBySig.Count}…");

        List<byte[]> kekPool;
        if (precomputedKek is { Count: > 0 })
        {
            kekPool = precomputedKek;
            log?.Report($"  Photos MMCS decrypt: kek precomputati {kekPool.Count}");
        }
        else
        {
            // Percorso originale offline: scan pagine CPL (niente unwrap zone).
            var built = await BuildPcsZonesAndKekAsync(
                session, zonePayload, assetPages, photosDir, media, log, progress, ct);
            kekPool = built.KekPool;
        }

        log?.Report(
            $"  Photos MMCS decrypt: kek={kekPool.Count} " +
            $"httpAg={(agByCipherSize?.Count ?? 0)}");

        if (kekPool.Count == 0)
        {
            log?.Report("  Photos MMCS decrypt: nessun KEK — abort");
            return (0, cipherFiles.Length, cipherFiles.Length, 0);
        }

        const int decryptParallelism = 4;
        var ok = 0;
        var fail = 0;
        var agFromHttp = 0;
        var missingMeta = 0;
        var done = 0;
        long ticksMeta = 0;
        long ticksIo = 0;
        long ticksCrypto = 0;
        long ticksReplace = 0;
        long sumKekTried = 0;
        var gate = new SemaphoreSlim(decryptParallelism, decryptParallelism);
        var swDec = System.Diagnostics.Stopwatch.StartNew();

        async Task DecryptOneAsync(string cipherPath)
        {
            await gate.WaitAsync(ct).ConfigureAwait(false);
            try
            {
                ct.ThrowIfCancellationRequested();
                var token = Path.GetFileNameWithoutExtension(cipherPath);
                var dir = Path.GetDirectoryName(cipherPath)!;
                var stem = Path.Combine(dir, token);
                var sidecarRoot = Path.Combine(photosDir, "decrypt_cache", "sidecars");
                var agPath = stem + ".ag.bin";
                var wrapPath = stem + ".wrap.hex";
                var authPath = stem + ".mmcsauth.txt";
                var agCache = Path.Combine(sidecarRoot, token + ".ag.bin");
                var wrapCache = Path.Combine(sidecarRoot, token + ".wrap.hex");
                var authCache = Path.Combine(sidecarRoot, token + ".mmcsauth.txt");
                byToken.TryGetValue(token, out var meta);
                var swPart = System.Diagnostics.Stopwatch.StartNew();

                try
                {
                    var cipherLen = new FileInfo(cipherPath).Length;
                    string? mmcsAuth = File.Exists(authPath)
                        ? (await File.ReadAllTextAsync(authPath, ct)).Trim()
                        : File.Exists(authCache)
                            ? (await File.ReadAllTextAsync(authCache, ct)).Trim()
                            : null;

                    byte[]? ag = File.Exists(agPath)
                        ? await File.ReadAllBytesAsync(agPath, ct)
                        : File.Exists(agCache)
                            ? await File.ReadAllBytesAsync(agCache, ct)
                            : null;

                    if ((ag is null || ag.Length == 0)
                        && agByCipherSize is not null
                        && agByCipherSize.TryGetValue(cipherLen, out var httpAg)
                        && File.Exists(httpAg.AgBodyPath))
                    {
                        ag = await File.ReadAllBytesAsync(httpAg.AgBodyPath, ct);
                        mmcsAuth ??= httpAg.MmcsAuth;
                        Interlocked.Increment(ref agFromHttp);
                        await File.WriteAllBytesAsync(agPath, ag, ct);
                    }

                    if (meta is null && mmcsAuth is not null)
                        byAuth.TryGetValue(mmcsAuth, out meta);

                    string? wrapHex = null;
                    if (mmcsAuth is not null
                        && MmcsAuthBuilder.TrySplitMmcsAuth(mmcsAuth, out var sig21, out _, out _))
                    {
                        var sigHex = Convert.ToHexString(sig21);
                        if (wrapBySig.TryGetValue(sigHex, out var sigWrap))
                            wrapHex = sigWrap;
                    }
                    if (string.IsNullOrWhiteSpace(wrapHex) && File.Exists(wrapPath))
                        wrapHex = (await File.ReadAllTextAsync(wrapPath, ct)).Trim();
                    if (string.IsNullOrWhiteSpace(wrapHex) && File.Exists(wrapCache))
                        wrapHex = (await File.ReadAllTextAsync(wrapCache, ct)).Trim();
                    if (string.IsNullOrWhiteSpace(wrapHex) && cache is not null)
                    {
                        var cached = cache.Entries.FirstOrDefault(e =>
                            string.Equals(e.Token, token, StringComparison.OrdinalIgnoreCase));
                        if (cached?.WrapHex is { Length: > 0 })
                            wrapHex = cached.WrapHex;
                    }
                    if (string.IsNullOrWhiteSpace(wrapHex))
                        wrapHex = meta?.AssetProtectionInfoHex;
                    if (string.IsNullOrWhiteSpace(wrapHex) && mmcsAuth is not null
                        && byAuth.TryGetValue(mmcsAuth, out var viaAuth))
                        wrapHex = viaAuth.AssetProtectionInfoHex;

                    Interlocked.Add(ref ticksMeta, swPart.ElapsedTicks);
                    swPart.Restart();

                    if (string.IsNullOrWhiteSpace(wrapHex))
                    {
                        Interlocked.Increment(ref fail);
                        var mm = Interlocked.Increment(ref missingMeta);
                        if (mm <= 5)
                            log?.Report($"  Photos decrypt skip (no wrap): {Path.GetFileName(cipherPath)}");
                        return;
                    }

                    if (ag is null || ag.Length == 0)
                    {
                        Interlocked.Increment(ref fail);
                        var mm = Interlocked.Increment(ref missingMeta);
                        if (mm <= 5)
                            log?.Report($"  Photos decrypt skip (no AG): {Path.GetFileName(cipherPath)}");
                        return;
                    }

                    if (!File.Exists(wrapPath))
                        await File.WriteAllTextAsync(wrapPath, wrapHex, ct);

                    var cipher = await File.ReadAllBytesAsync(cipherPath, ct);
                    Interlocked.Add(ref ticksIo, swPart.ElapsedTicks);
                    swPart.Restart();

                    var plain = TryDecryptCipher(
                        wrapHex, cipher, ag, kekPool, out var failReason, out var kekTried);
                    Interlocked.Add(ref ticksCrypto, swPart.ElapsedTicks);
                    Interlocked.Add(ref sumKekTried, kekTried);
                    swPart.Restart();

                    // assemble_fail: AG stale. unwrap_miss: wrap sbagliato o master assente.
                    // In entrambi i casi prova AG fresco (solo assemble) + wrap alternativi dal wire.
                    if (plain is null
                        && !string.IsNullOrWhiteSpace(mmcsAuth)
                        && (failReason.StartsWith("assemble_fail", StringComparison.Ordinal)
                            || failReason.StartsWith("unwrap_miss", StringComparison.Ordinal)))
                    {
                        // #region agent log
                        AgentLogPhotos(
                            "H-P2",
                            "PhotosCloudSyncService.cs:decrypt-retry",
                            "decrypt_retry",
                            new
                            {
                                token,
                                failReason,
                                wrapLen = wrapHex.Length / 2,
                                agLen = ag.Length,
                                cipherLen = cipher.Length,
                            });
                        // #endregion

                        if (failReason.StartsWith("assemble_fail", StringComparison.Ordinal))
                        {
                            var refreshed = await TryRefreshAuthorizeGetAsync(
                                session, mmcsAuth, ct).ConfigureAwait(false);
                            if (refreshed is { Length: > 0 })
                            {
                                ag = refreshed;
                                await File.WriteAllBytesAsync(agPath, ag, ct);
                                await File.WriteAllBytesAsync(agCache, ag, ct);
                                plain = TryDecryptCipher(
                                    wrapHex, cipher, ag, kekPool, out failReason, out var kekTried2);
                                Interlocked.Add(ref sumKekTried, kekTried2);
                                if (plain is not null)
                                {
                                    // #region agent log
                                    AgentLogPhotos(
                                        "H-P2",
                                        "PhotosCloudSyncService.cs:decrypt-retry",
                                        "reauth_ag_ok",
                                        new { token, agLen = ag.Length });
                                    // #endregion
                                }
                            }
                        }

                        if (plain is null
                            && MmcsAuthBuilder.TrySplitMmcsAuth(mmcsAuth, out var sigRetry, out _, out _))
                        {
                            foreach (var page in assetPages)
                            {
                                var alt = CloudKitAssetProto.TryGetWrapForReferenceSignature(
                                              page, sigRetry)
                                          ?? CloudKitAssetProto.TryGetWrapForSignature(
                                              page, sigRetry);
                                if (alt is not { Length: 24 or 40 })
                                    continue;
                                var altHex = Convert.ToHexString(alt);
                                if (altHex.Equals(wrapHex, StringComparison.OrdinalIgnoreCase))
                                    continue;
                                plain = TryDecryptCipher(
                                    altHex, cipher, ag, kekPool, out failReason, out var kekTried3);
                                Interlocked.Add(ref sumKekTried, kekTried3);
                                if (plain is null)
                                    continue;
                                wrapHex = altHex;
                                await File.WriteAllTextAsync(wrapPath, wrapHex, ct);
                                // #region agent log
                                AgentLogPhotos(
                                    "H-P3",
                                    "PhotosCloudSyncService.cs:decrypt-retry",
                                    "alt_wrap_ok",
                                    new { token, wrapLen = alt.Length });
                                // #endregion
                                break;
                            }
                        }
                    }

                    if (plain is null)
                    {
                        var f = Interlocked.Increment(ref fail);
                        if (f <= 12)
                            log?.Report($"  Photos decrypt fail: {Path.GetFileName(cipherPath)} ({failReason})");
                        // #region agent log
                        if (f <= 20)
                        {
                            AgentLogPhotos(
                                "H-P2",
                                "PhotosCloudSyncService.cs:decrypt-fail",
                                "decrypt_fail",
                                new { token, failReason });
                        }
                        // #endregion
                        return;
                    }

                    var ext = CplPhotosRecordParser.GuessExtension(plain);
                    if (ext.Equals(".bin", StringComparison.OrdinalIgnoreCase)
                        || string.Equals(stem + ext, cipherPath, StringComparison.OrdinalIgnoreCase))
                        ext = ".dec.bin";

                    var outPath = stem + ext;
                    await File.WriteAllBytesAsync(outPath, plain, ct);
                    if (!string.Equals(cipherPath, outPath, StringComparison.OrdinalIgnoreCase))
                        TryDelete(cipherPath);
                    TryDelete(agPath);
                    TryDelete(wrapPath);
                    TryDelete(authPath);
                    Interlocked.Add(ref ticksIo, swPart.ElapsedTicks);
                    swPart.Restart();

                    await ReplaceCiphertextCopiesAsync(photosDir, Path.GetFileName(cipherPath), outPath, plain, ct);
                    Interlocked.Add(ref ticksReplace, swPart.ElapsedTicks);
                    Interlocked.Increment(ref ok);
                }
                catch (Exception ex)
                {
                    var f = Interlocked.Increment(ref fail);
                    if (f <= 5)
                        log?.Report($"  Photos decrypt err {Path.GetFileName(cipherPath)}: {ex.Message}");
                }
            }
            finally
            {
                gate.Release();
                var d = Interlocked.Increment(ref done);
                if (d == 1 || d % 5 == 0 || d == cipherFiles.Length)
                {
                    progress?.Report(new SyncDataProgressReport(
                        $"Decrypt {d}/{cipherFiles.Length} (ok={Volatile.Read(ref ok)} fail={Volatile.Read(ref fail)})",
                        86 + 6.0 * d / Math.Max(1, cipherFiles.Length),
                        PhaseLabel: "Decrypt",
                        PhasePercent: 100.0 * d / Math.Max(1, cipherFiles.Length)));
                }
            }
        }

        await Task.WhenAll(cipherFiles.Select(DecryptOneAsync)).ConfigureAwait(false);
        swDec.Stop();
        var msMeta = (long)(ticksMeta * 1000.0 / System.Diagnostics.Stopwatch.Frequency);
        var msIo = (long)(ticksIo * 1000.0 / System.Diagnostics.Stopwatch.Frequency);
        var msCrypto = (long)(ticksCrypto * 1000.0 / System.Diagnostics.Stopwatch.Frequency);
        var msReplace = (long)(ticksReplace * 1000.0 / System.Diagnostics.Stopwatch.Frequency);
        var avgKekTried = ok + fail > 0 ? (double)sumKekTried / (ok + fail) : 0;
        log?.Report(
            $"  Photos MMCS decrypt done: ok={ok} fail={fail}/{cipherFiles.Length} " +
            $"in {swDec.ElapsedMilliseconds} ms (×{decryptParallelism}) " +
            $"meta={msMeta}ms io={msIo}ms crypto={msCrypto}ms replace={msReplace}ms " +
            $"avgKekTried={avgKekTried:F1}");

        return (ok, fail, cipherFiles.Length, kekPool.Count);
    }

    private static async Task ReplaceCiphertextCopiesAsync(
        string photosDir,
        string ctFileName,
        string plainPath,
        byte[] plain,
        CancellationToken ct)
    {
        var plainName = Path.GetFileName(plainPath);
        foreach (var sub in new[] { "Nascoste", "Eliminate", "Preferiti", "Album" })
        {
            var root = Path.Combine(photosDir, sub);
            if (!Directory.Exists(root))
                continue;
            foreach (var old in Directory.EnumerateFiles(root, ctFileName, SearchOption.AllDirectories))
            {
                var dest = Path.Combine(Path.GetDirectoryName(old)!, plainName);
                await File.WriteAllBytesAsync(dest, plain, ct);
                TryDelete(old);
            }
        }
    }

    private static void TryDelete(string path)
    {
        try { File.Delete(path); }
        catch { /* ignore */ }
    }

    private sealed class ByteArrayComparer : IEqualityComparer<byte[]>
    {
        public static readonly ByteArrayComparer Instance = new();
        public bool Equals(byte[]? x, byte[]? y)
        {
            if (ReferenceEquals(x, y)) return true;
            if (x is null || y is null || x.Length != y.Length) return false;
            return x.AsSpan().SequenceEqual(y);
        }
        public int GetHashCode(byte[] obj)
        {
            var h = new HashCode();
            foreach (var b in obj.AsSpan(0, Math.Min(32, obj.Length)))
                h.Add(b);
            return h.ToHashCode();
        }
    }

    private static CplPhotosRecordParser.CplMedia ChoosePreferred(
        IGrouping<string, CplPhotosRecordParser.CplMedia> group)
    {
        return group
            .OrderByDescending(static m => m.LooksOriginal)
            .ThenByDescending(static m => m.RecordType == "CPLMaster")
            .ThenByDescending(static m => m.SizeBytes ?? 0)
            .First();
    }

    private async Task<bool> TryDownloadOneAsync(
        ICloudSession session,
        CplPhotosRecordParser.CplMedia item,
        string allPhotos,
        Dictionary<string, List<string>> containersByItem,
        PhotosMediaMetaCache cache,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(item.MmcsAuth) || string.IsNullOrWhiteSpace(session.Dsid))
            return false;

        //  p178-content.icloud.com (partition) — non gateway.
        var hosts = new List<string>();
        if (!string.IsNullOrWhiteSpace(session.Partition))
            hosts.Add($"https://{session.Partition}-content.icloud.com");
        if (!string.IsNullOrWhiteSpace(item.ContentBaseUrl))
            hosts.Add(item.ContentBaseUrl.TrimEnd('/'));

        byte[]? authBody = null;
        string? usedHost = null;
        IReadOnlyList<SignedUrlChunk> chunks = [];
        var authStatuses = new List<string>();
        foreach (var host in hosts.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var (body, status) = await AuthorizeGetAsync(session, host, item.MmcsAuth!, ct);
                authStatuses.Add($"{host}→{status}");
                if (body is not { Length: > 0 })
                    continue;
                chunks = UbChunkBuilder.ParseAuthorizeGetResponse(body);
                if (chunks.Count == 0)
                    continue;
                authBody = body;
                usedHost = host;
                break;
            }
            catch (Exception ex)
            {
                authStatuses.Add($"{host}→ex:{ex.GetType().Name}");
            }
        }

        if (authBody is null || chunks.Count == 0 || usedHost is null)
        {
            return false;
        }

        var token = SanitizeFileToken(item.RecordName);
        var ctPath = Path.Combine(allPhotos, token + ".ct");
        // Evita overwrite su collisioni UUID (stesso record name, auth diversi).
        if (File.Exists(ctPath)
            && MmcsAuthBuilder.TrySplitMmcsAuth(item.MmcsAuth, out var sig21, out _, out _))
        {
            var sigHex = Convert.ToHexString(sig21);
            var sigTag = sigHex.Length >= 8 ? sigHex[..8] : sigHex;
            token = SanitizeFileToken(item.RecordName) + "_" + sigTag;
            ctPath = Path.Combine(allPhotos, token + ".ct");
        }

        try
        {
            await DownloadChunksAsync(ctPath, chunks, ct, omitHttpRange: false);
        }
        catch (Exception ex) when (
            ex is ArgumentOutOfRangeException
            || (ex is HttpRequestException http
                && (http.StatusCode == System.Net.HttpStatusCode.Forbidden
                    || http.Message.Contains("403", StringComparison.Ordinal))))
        {
            await DownloadChunksAsync(ctPath, chunks, ct, omitHttpRange: true);
        }

        // Sidecar cache per decrypt MMCS post-download (Sfoglia + decrypt_cache/sidecars).
        var sidecarDir = Path.Combine(Path.GetDirectoryName(allPhotos)!, "decrypt_cache", "sidecars");
        Directory.CreateDirectory(sidecarDir);
        await File.WriteAllBytesAsync(Path.Combine(allPhotos, token + ".ag.bin"), authBody, ct);
        await File.WriteAllBytesAsync(Path.Combine(sidecarDir, token + ".ag.bin"), authBody, ct);
        var wrapHex = item.AssetProtectionInfoHex;
        if (wrapHex is { Length: > 0 })
        {
            await File.WriteAllTextAsync(Path.Combine(allPhotos, token + ".wrap.hex"), wrapHex, ct);
            await File.WriteAllTextAsync(Path.Combine(sidecarDir, token + ".wrap.hex"), wrapHex, ct);
        }

        await File.WriteAllTextAsync(Path.Combine(allPhotos, token + ".mmcsauth.txt"), item.MmcsAuth!, ct);
        await File.WriteAllTextAsync(Path.Combine(sidecarDir, token + ".mmcsauth.txt"), item.MmcsAuth!, ct);

        var relationKey = item.AssetRecordName
                          ?? (item.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase)
                              ? item.RecordName[..^5]
                              : item.RecordName);
        containersByItem.TryGetValue(relationKey, out var albumIds);
        albumIds ??= [];

        cache.AddDownload(new PhotosMediaMetaCache.MediaEntry
        {
            Token = token,
            RecordName = item.RecordName,
            AssetRecordName = item.AssetRecordName,
            MmcsAuth = item.MmcsAuth,
            WrapHex = wrapHex,
            SizeBytes = new FileInfo(ctPath).Length,
            Hidden = item.Hidden,
            Trashed = item.Trashed,
            Favorite = item.Favorite,
            IsLive = item.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase),
            AlbumIds = albumIds.ToList(),
            CipherRelativePath = Path.Combine("Sfoglia", token + ".ct")
        });

        return true;
    }

    private static byte[]? TryDecryptCipher(
        string? wrapHex,
        byte[] ciphertext,
        byte[] authorizeGetBody,
        List<byte[]> kekPool,
        out string failReason,
        out int kekTried)
    {
        failReason = "ok";
        kekTried = 0;
        if (ciphertext.Length == 0 || kekPool.Count == 0)
        {
            failReason = "empty_ct_or_kek";
            return null;
        }

        if (string.IsNullOrWhiteSpace(wrapHex))
        {
            failReason = "no_wrap";
            return null;
        }

        byte[] wrap;
        try
        {
            wrap = Convert.FromHexString(wrapHex.Trim());
        }
        catch
        {
            failReason = "wrap_hex";
            return null;
        }

        if (wrap.Length is not (24 or 40))
        {
            failReason = $"wrap_len_{wrap.Length}";
            return null;
        }

        var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
        if (plan.TotalCryptoChunks == 0)
        {
            failReason = "plan_empty";
            return null;
        }

        if (plan.TotalCryptoBytes != ciphertext.Length)
        {
            failReason = $"size_mismatch_plan{plan.TotalCryptoBytes}_ct{ciphertext.Length}";
            return null;
        }

        var unwrapOk = 0;
        string? lastAssemble = null;
        foreach (var master in kekPool)
        {
            kekTried++;
            var kek = PcsProtectionZone.TryUnwrapWrappingKey(master, wrap);
            if (kek is null)
                continue;
            unwrapOk++;
            foreach (var tryKek in KekCandidates(kek))
            {
                try
                {
                    return MmcsChunkCrypto.DecryptAndAssemble(ciphertext, plan, tryKek);
                }
                catch (Exception ex)
                {
                    lastAssemble = ex.GetType().Name + ":" + ex.Message;
                }
            }
        }

        failReason = unwrapOk == 0
            ? $"unwrap_miss_wrap{wrap.Length}_kek{kekPool.Count}"
            : $"assemble_fail_n{unwrapOk}_{lastAssemble}";
        return null;
    }

    private static IEnumerable<byte[]> KekCandidates(byte[] kek)
    {
        yield return kek;
        if (kek.Length == 32)
            yield return kek.AsSpan(0, 16).ToArray();
        if (kek.Length == 32)
            yield return kek.AsSpan(16, 16).ToArray();
    }

    private static string SanitizeFileToken(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        return sb.ToString();
    }

    private async Task<(byte[]? Body, int Status)> AuthorizeGetAsync(
        ICloudSession session,
        string contentHost,
        string mmcsAuth,
        CancellationToken ct)
    {
        var url = $"{contentHost.TrimEnd('/')}/{session.Dsid}/authorizeGet";
        var body = UbChunkBuilder.BuildAuthorizeGetRequest(mmcsAuth);
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType =
            new MediaTypeHeaderValue("application/vnd.com.apple.me.ubchunk+protobuf");
        request.Headers.TryAddWithoutValidation("Accept", "application/vnd.com.apple.me.ubchunk+protobuf");
        request.Headers.TryAddWithoutValidation("x-apple-mme-dsid", session.Dsid);
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-proto-version", "4.0");
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-dataclass", "com.apple.Dataclass.CloudKit");
        request.Headers.TryAddWithoutValidation("X-CloudKit-Container", "com.apple.photos.cloud");
        request.Headers.TryAddWithoutValidation("X-CloudKit-Zones", PhotosZone);
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-auth", mmcsAuth);
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.PhotosMmcsUserAgent);
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", AppleClientInfo.PhotosMmcsClientInfo);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(AuthorizeGetTimeout);
        using var response = await _http.SendAsync(request, timeoutCts.Token).ConfigureAwait(false);
        var status = (int)response.StatusCode;
        if (!response.IsSuccessStatusCode)
            return (null, status);
        var bytes = await response.Content.ReadAsByteArrayAsync(timeoutCts.Token).ConfigureAwait(false);
        return (bytes, status);
    }

    private async Task<byte[]?> TryRefreshAuthorizeGetAsync(
        ICloudSession session,
        string mmcsAuth,
        CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid) || string.IsNullOrWhiteSpace(mmcsAuth))
            return null;

        var hosts = new List<string>();
        if (!string.IsNullOrWhiteSpace(session.Partition))
            hosts.Add($"https://{session.Partition}-content.icloud.com");
        foreach (var host in hosts)
        {
            try
            {
                var (body, status) = await AuthorizeGetAsync(session, host, mmcsAuth, ct)
                    .ConfigureAwait(false);
                if (status is >= 200 and < 300 && body is { Length: > 0 })
                    return body;
            }
            catch
            {
                // ignore host
            }
        }

        return null;
    }

    // #region agent log
    private static void AgentLogPhotos(string hypothesisId, string location, string message, object data)
    {
        try
        {
            var payload = JsonSerializer.Serialize(new
            {
                sessionId = "7dabb5",
                hypothesisId,
                location,
                message,
                data,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                runId = "photos-mmcs-organize",
            });
            var path = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.Desktop),
                "PROGRAMMAZIONE", "Projects", "iCloudDownloader", "debug-7dabb5.log");
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            File.AppendAllText(path, payload + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    private async Task DownloadChunksAsync(
        string outputFile,
        IReadOnlyList<SignedUrlChunk> chunks,
        CancellationToken ct,
        bool omitHttpRange = false)
    {
        var tmp = outputFile + ".partial";
        try
        {
            await using (var output = new FileStream(tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                foreach (var chunk in chunks.Where(static c => !string.IsNullOrEmpty(c.Url)))
                {
                    ct.ThrowIfCancellationRequested();
                    var expectedBytes = chunk.ByteRange is { } br
                        ? Math.Max(1, br.End - br.Start + 1)
                        : 32_000_000L;
                    // ~0.5 MB/s floor, min 90s, max 8 min per chunk (evita stall da Timeout=30min del HttpClient).
                    var timeoutSec = Math.Clamp(90 + (int)(expectedBytes / 500_000), 90, 480);
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromSeconds(timeoutSec));

                    using var request = new HttpRequestMessage(HttpMethod.Get, chunk.Url);
                    // Photos: URL ha content-byte-range E Range HTTP allineato.
                    // RangeHeaderValue throws ArgumentOutOfRangeException se from>to o negativi
                    // (stesso guard di BackupDownloadService.BuildBackupEdgeGetRequest).
                    if (!omitHttpRange && chunk.ByteRange is { } range
                        && range.Start >= 0
                        && range.End >= range.Start)
                        request.Headers.Range = new RangeHeaderValue(range.Start, range.End);
                    Download.BackupDownloadService.ApplyEdgeHeaders(
                        request,
                        chunk.EdgeHeaders,
                        cloudKitContainer: "com.apple.photos.cloud",
                        cloudKitZone: PhotosZone,
                        includeTryCache: true);
                    // Sovrascrivi Client-Info backup→Photos (ApplyEdgeHeaders usa CloudKitDaemon).
                    request.Headers.Remove("X-MMe-Client-Info");
                    request.Headers.TryAddWithoutValidation(
                        "X-MMe-Client-Info", AppleClientInfo.PhotosMmcsClientInfo);
                    request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.PhotosMmcsUserAgent);

                    using var response = await _http
                        .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token)
                        .ConfigureAwait(false);
                    if (!response.IsSuccessStatusCode)
                    {
                        // #region agent log
                        PhotosEdgeDebugLog(
                            "edge_get_fail",
                            new
                            {
                                status = (int)response.StatusCode,
                                omitHttpRange,
                                hasSig = !string.IsNullOrEmpty(chunk.EdgeHeaders?.Signature),
                                hasDate = !string.IsNullOrEmpty(chunk.EdgeHeaders?.Date),
                                hasHttpDate = !string.IsNullOrEmpty(chunk.EdgeHeaders?.HttpDate),
                                oid = chunk.EdgeHeaders?.ObjectId,
                                range = chunk.ByteRange is { } r2 ? $"{r2.Start}-{r2.End}" : null,
                                host = TryHost(chunk.Url),
                            });
                        // #endregion
                    }

                    response.EnsureSuccessStatusCode();
                    await using var stream = await response.Content.ReadAsStreamAsync(timeoutCts.Token)
                        .ConfigureAwait(false);
                    await stream.CopyToAsync(output, timeoutCts.Token).ConfigureAwait(false);
                }
            }

            File.Copy(tmp, outputFile, overwrite: true);
        }
        finally
        {
            try
            {
                if (File.Exists(tmp))
                    File.Delete(tmp);
            }
            catch
            {
                // ignore
            }

            // Non lasciare stub 0 B che bloccano la ripresa incomplete.
            try
            {
                if (File.Exists(outputFile) && new FileInfo(outputFile).Length == 0)
                    File.Delete(outputFile);
            }
            catch
            {
                // ignore
            }
        }
    }

    private static string? TryHost(string? url)
    {
        try
        {
            return string.IsNullOrEmpty(url) ? null : new Uri(url).Host;
        }
        catch
        {
            return null;
        }
    }

    private static int _photosEdgeDebugCount;

    private static void PhotosEdgeDebugLog(string message, object data)
    {
        // #region agent log
        if (Interlocked.Increment(ref _photosEdgeDebugCount) > 12)
            return;
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "photos-edge-403",
                ["hypothesisId"] = "H-P403",
                ["location"] = "PhotosCloudSyncService.DownloadChunksAsync",
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
        // #endregion
    }

    private static async Task WriteCopyAsync(string path, byte[] data, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllBytesAsync(path, data, ct);
    }

    private static int CountAscii(byte[] data, ReadOnlySpan<byte> needle)
    {
        var n = 0;
        var span = data.AsSpan();
        while (true)
        {
            var i = span.IndexOf(needle);
            if (i < 0)
                return n;
            n++;
            span = span[(i + needle.Length)..];
        }
    }

}
