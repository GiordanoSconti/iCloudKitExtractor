using System.IO;
using System.Net.Http.Headers;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Download;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Download audio Voice Memos: Asset <c>CD_versionedAudioFuture_ckAsset</c>
/// → authorizeGet MMCS → edge GET → unwrap wrap24 + KEK zone PCS → file audio.
/// </summary>
public sealed class VoiceMemosAudioDownloader
{
    public const string ContainerId = "com.apple.VoiceMemosContainer";
    public const string SyncZone = "com.apple.coredata.cloudkit.zone";

    private readonly HttpClient _http;

    public VoiceMemosAudioDownloader(HttpClient http) => _http = http;

    public async Task<int> DownloadAsync(
        ICloudSession session,
        string containerDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
        {
            log?.Report("  VoiceMemos MMCS: DSID assente");
            return 0;
        }

        var syncFiles = Directory.GetFiles(containerDirectory, "record_sync_*.bin");
        if (syncFiles.Length == 0)
        {
            log?.Report("  VoiceMemos MMCS: nessun record_sync");
            return 0;
        }

        var titles = LoadTitles(containerDirectory);
        var assets = new List<(CloudKitAssetProto.ParsedAsset Asset, string? Title)>();
        foreach (var sf in syncFiles)
        {
            var data = await File.ReadAllBytesAsync(sf, ct).ConfigureAwait(false);
            foreach (var a in CloudKitAssetProto.EnumerateAssets(data))
            {
                if (a.Signature is not { Length: 21 }
                    || string.IsNullOrWhiteSpace(a.DownloadAuth)
                    || a.ReferenceSignature is not { Length: 21 })
                    continue;
                // Dedup by signature
                if (assets.Any(x => x.Asset.Signature.AsSpan().SequenceEqual(a.Signature)))
                    continue;
                var title = titles.Count > 0 ? GuessTitleNearAsset(data, a.Offset, titles) : null;
                assets.Add((a, title));
            }
        }

        if (assets.Count == 0)
        {
            log?.Report("  VoiceMemos MMCS: nessun ckAsset con auth/signature");
            return 0;
        }

        log?.Report($"  VoiceMemos MMCS: {assets.Count} audio asset…");

        var kekPool = BuildKekPool(session, containerDirectory, log);
        if (kekPool.Count == 0)
            log?.Report("  VoiceMemos MMCS: KEK pool vuoto — scarico ciphertext, decrypt forse fallisce");

        var audioDir = Path.Combine(containerDirectory, "audio");
        Directory.CreateDirectory(audioDir);
        var ok = 0;
        var i = 0;
        foreach (var (asset, title) in assets)
        {
            i++;
            ct.ThrowIfCancellationRequested();
            var label = string.IsNullOrWhiteSpace(title)
                ? $"asset{i}"
                : title.Trim();
            log?.Report(
                $"  VoiceMemos MMCS {i}/{assets.Count}: «{label}» " +
                $"({asset.SizeBytes?.ToString("N0") ?? "?"} B)…");

            try
            {
                if (await TryDownloadOneAsync(
                        session, asset, label, audioDir, kekPool, log, ct)
                    .ConfigureAwait(false))
                    ok++;
            }
            catch (Exception ex)
            {
                log?.Report($"    FAIL: {ex.Message}");
            }
        }

        log?.Report($"  VoiceMemos MMCS: {ok}/{assets.Count} → {audioDir}");
        return ok;
    }

    private async Task<bool> TryDownloadOneAsync(
        ICloudSession session,
        CloudKitAssetProto.ParsedAsset asset,
        string label,
        string audioDir,
        List<byte[]> kekPool,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var mmcsAuth =
            $"{Convert.ToHexString(asset.Signature).ToLowerInvariant()} " +
            $"{Convert.ToHexString(asset.ReferenceSignature!).ToLowerInvariant()} " +
            asset.DownloadAuth!.Trim();

        var hosts = new List<string>();
        if (!string.IsNullOrWhiteSpace(session.Partition))
            hosts.Add($"https://{session.Partition}-content.icloud.com");
        if (!string.IsNullOrWhiteSpace(asset.DownloadUrl))
            hosts.Add(asset.DownloadUrl.TrimEnd('/'));
        hosts.Add("https://gateway.icloud.com:443/content");
        hosts.Add("https://gateway.icloud.com/content");

        byte[]? authBody = null;
        string? usedHost = null;
        IReadOnlyList<SignedUrlChunk> chunks = [];
        var statuses = new List<string>();
        foreach (var host in hosts.Distinct(StringComparer.OrdinalIgnoreCase))
        {
            try
            {
                var (body, status) = await AuthorizeGetAsync(session, host, mmcsAuth, ct)
                    .ConfigureAwait(false);
                statuses.Add($"{TryHost(host)}→{status}");
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
                statuses.Add($"{TryHost(host)}→{ex.GetType().Name}");
            }
        }

        if (authBody is null || chunks.Count == 0 || usedHost is null)
        {
            log?.Report($"    authorizeGet fail ({string.Join(", ", statuses)})");
            return false;
        }

        var incomplete = MmcsContentEndpoints.IsAuthorizeGetIncomplete(chunks, asset.SizeBytes);
        var c0 = chunks[0];
        log?.Report(
            $"    authorizeGet OK @ {TryHost(usedHost)} " +
            $"({chunks.Count} chunk, {string.Join(", ", statuses)}; " +
            $"edge={TryHost(c0.Url)} sig={(c0.EdgeHeaders?.Signature is { Length: > 0 } ? "ok" : "MISSING")} " +
            $"range={(c0.ByteRange is { } r ? $"{r.Start}-{r.End}" : "-")} " +
            $"incomplete={incomplete})");

        var token = Sanitize(label);
        var ctPath = Path.Combine(audioDir, token + ".ct");
        if (File.Exists(ctPath))
            ctPath = Path.Combine(
                audioDir,
                token + "_" + Convert.ToHexString(asset.Signature.AsSpan(1, 4)) + ".ct");

        // Dump subito: se edge 403 non perdiamo authorizeGet per analisi offline.
        await File.WriteAllBytesAsync(ctPath + ".ag.bin", authBody, ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(ctPath + ".mmcsauth.txt", mmcsAuth, ct).ConfigureAwait(false);
        if (asset.ProtectionWrap is { Length: > 0 } wrap)
            await File.WriteAllTextAsync(
                    ctPath + ".wrap.hex", Convert.ToHexString(wrap), ct)
                .ConfigureAwait(false);
        await File.WriteAllTextAsync(
                ctPath + ".edge.url.txt",
                string.Join("\n", chunks.Select(c => c.Url)),
                ct)
            .ConfigureAwait(false);

        var edgeErr = await TryDownloadWithEdgeVariantsAsync(ctPath, chunks, log, ct)
            .ConfigureAwait(false);
        if (edgeErr is not null)
        {
            log?.Report($"    edge GET FAIL: {edgeErr}");
            return false;
        }

        var cipher = await File.ReadAllBytesAsync(ctPath, ct).ConfigureAwait(false);
        var plain = TryDecrypt(cipher, authBody, asset.ProtectionWrap, kekPool, out var reason);
        if (plain is null)
        {
            log?.Report($"    scaricato {cipher.Length:N0} B ciphertext — decrypt: {reason}");
            return false;
        }

        var ext = GuessAudioExtension(plain);
        var outPath = Path.Combine(audioDir, token + ext);
        if (File.Exists(outPath))
            outPath = Path.Combine(
                audioDir,
                token + "_" + Convert.ToHexString(asset.Signature.AsSpan(1, 4)) + ext);
        await File.WriteAllBytesAsync(outPath, plain, ct).ConfigureAwait(false);
        try
        {
            File.Delete(ctPath);
        }
        catch
        {
            // keep ciphertext if delete fails
        }

        log?.Report($"    OK → {Path.GetFileName(outPath)} ({plain.Length:N0} B)");
        return true;
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
        request.Headers.TryAddWithoutValidation("X-CloudKit-Container", ContainerId);
        request.Headers.TryAddWithoutValidation("X-CloudKit-Zones", SyncZone);
        request.Headers.TryAddWithoutValidation("x-apple-mmcs-auth", mmcsAuth);
        // Come Photos: CloudKitDaemon su content edge → 403. Serve icloud.content.
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.PhotosMmcsUserAgent);
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", AppleClientInfo.PhotosMmcsClientInfo);

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(TimeSpan.FromSeconds(90));
        using var response = await _http.SendAsync(request, timeoutCts.Token).ConfigureAwait(false);
        var status = (int)response.StatusCode;
        if (!response.IsSuccessStatusCode)
            return (null, status);
        var bytes = await response.Content.ReadAsByteArrayAsync(timeoutCts.Token).ConfigureAwait(false);
        return (bytes, status);
    }

    private enum EdgeHeaderMode
    {
        /// <summary>Solo header firmati del template + icloud.content (niente CK/dataclass/try-cache).</summary>
        MinimalSigned,

        /// <summary>Come Photos: ApplyEdgeHeaders + override Client-Info.</summary>
        PhotosStyle,

        /// <summary>Come backup iOS: ApplyEdgeHeaders senza try-cache, Client-Info CloudKitDaemon.</summary>
        BackupStyle,
    }

    private readonly record struct EdgeAttempt(
        string Name,
        EdgeHeaderMode Mode,
        bool OmitHttpRange,
        bool StripPort443);

    private async Task<string?> TryDownloadWithEdgeVariantsAsync(
        string outputFile,
        IReadOnlyList<SignedUrlChunk> chunks,
        IProgress<string>? log,
        CancellationToken ct)
    {
        EdgeAttempt[] attempts =
        [
            new("minimal+range", EdgeHeaderMode.MinimalSigned, OmitHttpRange: false, StripPort443: false),
            new("minimal", EdgeHeaderMode.MinimalSigned, OmitHttpRange: true, StripPort443: false),
            new("minimal-noport", EdgeHeaderMode.MinimalSigned, OmitHttpRange: true, StripPort443: true),
            new("photos+range", EdgeHeaderMode.PhotosStyle, OmitHttpRange: false, StripPort443: false),
            new("photos", EdgeHeaderMode.PhotosStyle, OmitHttpRange: true, StripPort443: false),
            new("photos-nocache", EdgeHeaderMode.PhotosStyle, OmitHttpRange: true, StripPort443: false),
            new("backup", EdgeHeaderMode.BackupStyle, OmitHttpRange: false, StripPort443: false),
            new("backup-noport", EdgeHeaderMode.BackupStyle, OmitHttpRange: true, StripPort443: true),
        ];

        string? lastErr = null;
        foreach (var attempt in attempts)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var includeTryCache = attempt.Mode == EdgeHeaderMode.PhotosStyle
                    && attempt.Name is not "photos-nocache";
                await DownloadChunksAsync(
                        outputFile,
                        chunks,
                        ct,
                        attempt,
                        includeTryCache)
                    .ConfigureAwait(false);
                if (attempt.Name is not "minimal+range" and not "photos+range")
                    log?.Report($"    edge GET OK via {attempt.Name}");
                return null;
            }
            catch (Exception ex) when (
                ex is ArgumentOutOfRangeException
                || ex is HttpRequestException
                || ex is InvalidOperationException)
            {
                lastErr = $"{attempt.Name}: {ex.Message}";
                log?.Report($"    edge GET {attempt.Name} → {ShortErr(ex)}");
            }
        }

        return lastErr ?? "edge GET fallito";
    }

    private async Task DownloadChunksAsync(
        string outputFile,
        IReadOnlyList<SignedUrlChunk> chunks,
        CancellationToken ct,
        EdgeAttempt attempt,
        bool includeTryCache)
    {
        var tmp = outputFile + ".partial";
        try
        {
            await using (var output = new FileStream(
                             tmp, FileMode.Create, FileAccess.Write, FileShare.None))
            {
                foreach (var chunk in chunks.Where(static c => !string.IsNullOrEmpty(c.Url)))
                {
                    ct.ThrowIfCancellationRequested();
                    using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                    timeoutCts.CancelAfter(TimeSpan.FromMinutes(5));

                    var url = attempt.StripPort443
                        ? chunk.Url.Replace(":443/", "/", StringComparison.Ordinal)
                            .Replace(":443?", "?", StringComparison.Ordinal)
                        : chunk.Url;

                    using var request = new HttpRequestMessage(HttpMethod.Get, url);
                    if (!attempt.OmitHttpRange && chunk.ByteRange is { } range
                        && range.Start >= 0
                        && range.End >= range.Start)
                        request.Headers.Range = new RangeHeaderValue(range.Start, range.End);

                    ApplyVmEdgeHeaders(request, chunk.EdgeHeaders, attempt.Mode, includeTryCache);

                    using var response = await _http
                        .SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeoutCts.Token)
                        .ConfigureAwait(false);
                    if (!response.IsSuccessStatusCode)
                    {
                        var body = "";
                        try
                        {
                            body = await response.Content
                                .ReadAsStringAsync(timeoutCts.Token).ConfigureAwait(false);
                            if (body.Length > 180)
                                body = body[..180];
                        }
                        catch
                        {
                            // ignore
                        }

                        throw new HttpRequestException(
                            $"HTTP {(int)response.StatusCode} {(string.IsNullOrWhiteSpace(body) ? response.ReasonPhrase : body)}",
                            null,
                            response.StatusCode);
                    }

                    await using var stream = await response.Content
                        .ReadAsStreamAsync(timeoutCts.Token).ConfigureAwait(false);
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
        }
    }

    private static void ApplyVmEdgeHeaders(
        HttpRequestMessage request,
        EdgeDownloadHeaders? headers,
        EdgeHeaderMode mode,
        bool includeTryCache)
    {
        if (mode == EdgeHeaderMode.MinimalSigned)
        {
            ApplySignedTemplateHeaders(request, headers);
            request.Headers.TryAddWithoutValidation("Accept", "*/*");
            request.Headers.TryAddWithoutValidation(
                "X-MMe-Client-Info", AppleClientInfo.PhotosMmcsClientInfo);
            request.Headers.TryAddWithoutValidation(
                "User-Agent", AppleClientInfo.PhotosMmcsUserAgent);
            return;
        }

        BackupDownloadService.ApplyEdgeHeaders(
            request,
            headers,
            cloudKitContainer: ContainerId,
            cloudKitZone: SyncZone,
            includeTryCache: includeTryCache);

        request.Headers.Remove("X-MMe-Client-Info");
        request.Headers.Remove("User-Agent");
        if (mode == EdgeHeaderMode.BackupStyle)
        {
            request.Headers.TryAddWithoutValidation(
                "X-MMe-Client-Info", AppleClientInfo.CloudKitDaemonClientInfo);
            request.Headers.TryAddWithoutValidation(
                "User-Agent", AppleClientInfo.CloudKitDaemonUserAgent);
        }
        else
        {
            request.Headers.TryAddWithoutValidation(
                "X-MMe-Client-Info", AppleClientInfo.PhotosMmcsClientInfo);
            request.Headers.TryAddWithoutValidation(
                "User-Agent", AppleClientInfo.PhotosMmcsUserAgent);
        }

        // Usa Container-Size dal template se presente (ApplyEdgeHeaders forza "0").
        if (headers?.MmcsContainerSize is { Length: > 0 } size)
        {
            request.Headers.Remove("X-Apple-MMCS-Container-Size");
            request.Headers.TryAddWithoutValidation("X-Apple-MMCS-Container-Size", size);
        }
    }

    private static void ApplySignedTemplateHeaders(
        HttpRequestMessage request,
        EdgeDownloadHeaders? headers)
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
            request.Headers.TryAddWithoutValidation(
                "x-apple-boss-recommendation-used", headers.BossRecommendationUsed);
        if (!string.IsNullOrEmpty(headers.IncomingEdgePop))
            request.Headers.TryAddWithoutValidation(
                "x-apple-incoming-icloud-edge-pop", headers.IncomingEdgePop);
        if (!string.IsNullOrEmpty(headers.MmcsContainerSize))
            request.Headers.TryAddWithoutValidation(
                "X-Apple-MMCS-Container-Size", headers.MmcsContainerSize);
    }

    private static string ShortErr(Exception ex)
    {
        var msg = ex.Message;
        if (msg.Length > 120)
            msg = msg[..120];
        return msg.Replace('\r', ' ').Replace('\n', ' ');
    }

    private static byte[]? TryDecrypt(
        byte[] ciphertext,
        byte[] authorizeGetBody,
        byte[]? wrap,
        List<byte[]> kekPool,
        out string reason)
    {
        reason = "ok";
        if (ciphertext.Length == 0)
        {
            reason = "empty_ct";
            return null;
        }

        if (wrap is not { Length: 24 or 40 })
        {
            reason = $"wrap_len_{wrap?.Length ?? 0}";
            return null;
        }

        if (kekPool.Count == 0)
        {
            reason = "no_kek";
            return null;
        }

        var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
        if (plan.TotalCryptoChunks == 0)
        {
            reason = "plan_empty";
            return null;
        }

        var unwrapOk = 0;
        string? last = null;
        foreach (var master in kekPool)
        {
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
                    last = ex.GetType().Name;
                }
            }
        }

        reason = unwrapOk == 0
            ? $"unwrap_miss_kek{kekPool.Count}"
            : $"assemble_fail_{last}";
        return null;
    }

    private static IEnumerable<byte[]> KekCandidates(byte[] kek)
    {
        yield return kek;
        if (kek.Length == 32)
        {
            yield return kek.AsSpan(0, 16).ToArray();
            yield return kek.AsSpan(16, 16).ToArray();
        }
    }

    private static List<byte[]> BuildKekPool(
        ICloudSession session,
        string containerDirectory,
        IProgress<string>? log)
    {
        var pool = new List<byte[]>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void Add(byte[]? key)
        {
            if (key is not { Length: > 0 })
                return;
            if (!seen.Add(Convert.ToHexString(key)))
                return;
            pool.Add(key);
        }

        var seed = PcsSessionSeedKeys.CollectForSyncData(session, log: null);
        byte[]? richestZones = null;
        foreach (var zf in Directory.GetFiles(containerDirectory, "zones_*.bin"))
        {
            var data = File.ReadAllBytes(zf);
            if (richestZones is null || data.Length > richestZones.Length)
                richestZones = data;
        }

        var zones = new List<ProtectionZoneKeys>();
        if (richestZones is { Length: > 32 })
            zones.AddRange(PcsProtectionZone.TryUnwrapAll(richestZones, seed));

        foreach (var sf in Directory.GetFiles(containerDirectory, "record_sync_*.bin"))
        {
            var data = File.ReadAllBytes(sf);
            if (data.Length < 64)
                continue;
            var fromRec = data.Length >= 200_000
                ? PcsProtectionZone.TryUnwrapAll(data, seed)
                : PcsProtectionZone.TryUnwrapAllIterative(data, seed);
            zones.AddRange(fromRec);
        }

        foreach (var z in zones)
        {
            Add(z.DecryptKey);
            Add(z.MasterKey);
        }

        // Blob CD_versionedAudioFuture plaintext (spesso wrapping key locale)
        var futureDir = Path.Combine(
            containerDirectory, "crypto");
        if (Directory.Exists(futureDir))
        {
            foreach (var f in Directory.GetFiles(
                         futureDir, "*.bin", SearchOption.AllDirectories))
            {
                if (!f.Contains("CD_versionedAudioFuture", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (f.Contains("ckAsset", StringComparison.OrdinalIgnoreCase))
                    continue;
                var blob = File.ReadAllBytes(f);
                if (blob.Length is >= 16 and <= 128)
                    Add(blob);
                if (blob.Length >= 32)
                    Add(blob.AsSpan(0, 16).ToArray());
                if (blob.Length >= 48)
                    Add(blob.AsSpan(blob.Length - 16, 16).ToArray());
            }
        }

        log?.Report($"  VoiceMemos MMCS: KEK candidates={pool.Count} (zones={zones.Count})");
        return pool;
    }

    private static Dictionary<string, string> LoadTitles(string containerDirectory)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var tsv in Directory.GetFiles(
                     Path.Combine(containerDirectory, "crypto"),
                     "field_records.tsv",
                     SearchOption.AllDirectories))
        {
            foreach (var line in File.ReadLines(tsv).Skip(1))
            {
                var parts = line.Split('\t');
                if (parts.Length < 6)
                    continue;
                if (!parts[0].Contains("encryptedTitle", StringComparison.OrdinalIgnoreCase))
                    continue;
                var record = parts[2].Trim();
                var text = parts[5].Trim();
                if (record.Length > 0 && text.Length > 0)
                    map[record] = text;
            }
        }

        return map;
    }

    private static string? GuessTitleNearAsset(
        byte[] payload,
        int assetOffset,
        Dictionary<string, string> titles)
    {
        // Cerca UUID record entro ~2 KB intorno all'asset (prima, poi dopo)
        var start = Math.Max(0, assetOffset - 2048);
        var end = Math.Min(payload.Length, assetOffset + 256);
        var window = payload.AsSpan(start, end - start);
        string? best = null;
        var bestDist = int.MaxValue;
        foreach (var (uuid, title) in titles)
        {
            var needle = Encoding.ASCII.GetBytes(uuid);
            var at = IndexOf(window, needle);
            if (at < 0)
                continue;
            var abs = start + at;
            var dist = Math.Abs(assetOffset - abs);
            if (dist < bestDist)
            {
                bestDist = dist;
                best = title;
            }
        }

        return best;
    }

    private static int IndexOf(ReadOnlySpan<byte> hay, ReadOnlySpan<byte> needle)
    {
        for (var i = 0; i <= hay.Length - needle.Length; i++)
        {
            if (hay[i..].StartsWith(needle))
                return i;
        }

        return -1;
    }

    private static string GuessAudioExtension(byte[] plain)
    {
        if (plain.Length >= 12
            && plain[4] == (byte)'f'
            && plain[5] == (byte)'t'
            && plain[6] == (byte)'y'
            && plain[7] == (byte)'p')
            return ".m4a";
        if (plain.Length >= 4
            && plain[0] == (byte)'c'
            && plain[1] == (byte)'a'
            && plain[2] == (byte)'f'
            && plain[3] == (byte)'f')
            return ".caf";
        if (plain.Length >= 4
            && plain[0] == (byte)'R'
            && plain[1] == (byte)'I'
            && plain[2] == (byte)'F'
            && plain[3] == (byte)'F')
            return ".wav";
        return ".bin";
    }

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name.Trim())
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' or ' ' ? c : '_');
        var s = sb.ToString().Trim();
        if (s.Length == 0)
            return "memo";
        return s.Length > 60 ? s[..60].Trim() : s;
    }

    private static string TryHost(string url)
    {
        try
        {
            return new Uri(url).Host;
        }
        catch
        {
            return url;
        }
    }
}
