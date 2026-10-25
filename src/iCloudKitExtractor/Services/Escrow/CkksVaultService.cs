using System.IO;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;

namespace iCloudKitExtractor.Services.Escrow;

public sealed record CkksVaultItem(
    string View,
    string Name,
    string? Etag,
    string? Class,
    string? Agrp,
    string? Srvr,
    string? Acct,
    string? Labl,
    byte[]? Data,
    Dictionary<string, object?> Attrs,
    long? PcsService = null,
    byte[]? PcsPublicKey = null);

public sealed record CkksVaultOpenResult(
    bool Success,
    string Message,
    string? View = null,
    int RecordCount = 0,
    int TlkShares = 0,
    int ClassKeys = 0,
    int ItemsDecrypted = 0,
    int PcsKeysFound = 0,
    string? TlkPath = null,
    string? ItemsJsonPath = null);

/// <summary>
/// Apre vault CKKS (appleservices <c>ckks.OpenVault</c>):
/// record/sync view → TLKShare ECIES(peer enc) → classA/C → decrypt items.
/// View tipiche: <c>Manatee</c> / PCS, <c>Passwords</c> (Safari / Password app).
/// </summary>
public sealed class CkksVaultService
{
    /// <summary>
    /// Manatee + PCS → chiavi account-wide; <c>Passwords</c> → login web (srvr/acct/v_Data);
    /// LimitedPeersAllowed → altri vault.
    /// </summary>
    public static readonly string[] DefaultViews =
        ["Manatee", "ProtectedCloudStorage", "LimitedPeersAllowed", "Passwords"];

    private const int MaxSyncPages = 100;

    private readonly HttpClient _http;
    private readonly ICloudBackupOrchestrator _orchestrator;
    private readonly CloudKitGatewayClient _gateway;

    public CkksVaultService(HttpClient http, ICloudBackupOrchestrator orchestrator)
    {
        _http = http;
        _orchestrator = orchestrator;
        _gateway = new CloudKitGatewayClient(http);
    }

    /// <param name="prefetchRecoverableTlks">
    /// false se i TLK sono già in <paramref name="preloadedTlks"/> (path RK): evita un secondo
    /// <c>fetchRecoverableTLKShares</c> (e le varianti legacy che fanno 500).
    /// </param>
    public async Task<CkksVaultOpenResult> OpenViewsAsync(
        ICloudSession session,
        string outputDirectory,
        IEnumerable<string>? views = null,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        IReadOnlyDictionary<string, byte[]>? preloadedTlks = null,
        bool prefetchRecoverableTlks = true)
    {
        Directory.CreateDirectory(outputDirectory);
        var viewList = (views ?? DefaultViews).Where(v => !string.IsNullOrWhiteSpace(v)).ToList();
        if (viewList.Count == 0)
            return new CkksVaultOpenResult(false, "Nessuna view CKKS richiesta.");

        if (preloadedTlks is { Count: > 0 })
        {
            session.CkksTlkByView ??= new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            foreach (var (view, tlk) in preloadedTlks)
            {
                if (tlk is { Length: > 0 })
                    session.CkksTlkByView[view] = tlk;
            }

            log?.Report($"  preloaded TLK views: {string.Join(", ", preloadedTlks.Keys)}");
        }

        var hasPeer = session.OctagonPeerEncryptionPkcs8 is { Length: > 0 }
                      && !string.IsNullOrWhiteSpace(session.OctagonPeerId);
        var hasPreloaded = session.CkksTlkByView is { Count: > 0 };
        if (!hasPeer && !hasPreloaded)
        {
            return new CkksVaultOpenResult(
                false,
                "Serve peer encryption PKCS#8 (OTBottle/RK) oppure TLK preloaded (CkksTlkByView).");
        }

        // Ricarica peer keys da disco se sessione parziale.
        if (hasPeer)
            TryReloadPeerFromDisk(session, outputDirectory, log);

        var binding = CloudKitContainerBinding.Cuttlefish;
        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;

        var allItems = new List<CkksVaultItem>();
        var pcsKeys = new List<PcsCompactPrivateKey>();
        var totalRecords = 0;
        var totalShares = 0;
        var totalClass = 0;
        string? lastTlkPath = null;
        var errors = new List<string>();

        try
        {
            log?.Report($"CKKS vault: ckAppInit → {binding.ContainerId}…");
            await _orchestrator.CkAppInitAsync(session, binding.ContainerId, log, ct);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
                || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            {
                return new CkksVaultOpenResult(false, "ckAppInit keychain senza cloudKitUserId/token.");
            }

            if (hasPeer)
            {
                log?.Report(
                    $"  sponsor peer={TrimId(session.OctagonPeerId!)} " +
                    $"encPkcs8={session.OctagonPeerEncryptionPkcs8!.Length} B");
            }

            // TLK per view user-controllable (Passwords/…) se manca tlkshare in zone.
            IReadOnlyDictionary<string, byte[]> recoverableTlks =
                session.CkksTlkByView is { Count: > 0 } existing
                    ? new Dictionary<string, byte[]>(existing, StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            IReadOnlyList<CkksRecord> recoverableSyncKeys = [];
            var alreadyHaveTlks = preloadedTlks is { Count: > 0 } || recoverableTlks.Count > 0;
            if (hasPeer && prefetchRecoverableTlks && !alreadyHaveTlks)
            {
                try
                {
                    var cuttlefish = new OctagonCuttlefishService(_http, _orchestrator);
                    var recov = await cuttlefish.FetchRecoverableTlkSharesAsync(
                            session, outputDirectory, session.OctagonPeerId!, log, ct,
                            tryLegacyFieldVariants: false)
                        .ConfigureAwait(false);
                    if (recov.Success)
                    {
                        var merged = new Dictionary<string, byte[]>(
                            recoverableTlks, StringComparer.OrdinalIgnoreCase);
                        foreach (var (k, v) in recov.TlkByView)
                            merged[k] = v;
                        recoverableTlks = merged;
                        recoverableSyncKeys = recov.SyncKeyRecords;
                        log?.Report(
                            $"  recoverable TLK views: {string.Join(", ", recoverableTlks.Keys)}");
                    }
                    else
                    {
                        log?.Report($"  recoverable TLK: {recov.Message}");
                    }
                }
                catch (Exception ex)
                {
                    log?.Report($"  recoverable TLK skip: {ex.Message}");
                }
            }
            else if (alreadyHaveTlks && !prefetchRecoverableTlks)
            {
                log?.Report(
                    $"  skip fetchRecoverable (TLK già preloaded: {string.Join(", ", recoverableTlks.Keys)})");
            }

            foreach (var view in viewList)
            {
                ct.ThrowIfCancellationRequested();
                log?.Report($"CKKS view «{view}»…");
                try
                {
                    var result = await OpenOneViewAsync(
                            session, binding, view, outputDirectory, log, ct,
                            recoverableTlks, recoverableSyncKeys)
                        .ConfigureAwait(false);
                    if (!result.Success)
                    {
                        errors.Add($"{view}: {result.Message}");
                        log?.Report($"  FAIL {view}: {result.Message}");
                        continue;
                    }

                    totalRecords += result.RecordCount;
                    totalShares += result.TlkShares;
                    totalClass += result.ClassKeys;
                    lastTlkPath ??= result.TlkPath;
                    allItems.AddRange(result.Items);
                    pcsKeys.AddRange(result.PcsKeys);
                    log?.Report(
                        $"  OK {view}: records={result.RecordCount} tlkshares={result.TlkShares} " +
                        $"classKeys={result.ClassKeys} items={result.Items.Count} " +
                        $"pcsKeys={result.PcsKeys.Count}");
                }
                catch (Exception ex)
                {
                    errors.Add($"{view}: {ex.Message}");
                    log?.Report($"  ERR {view}: {ex.Message}");
                }
            }

            // Dedup PCS keys by PublicX.
            pcsKeys = DedupPcs(pcsKeys);
            if (pcsKeys.Count > 0)
            {
                // Backup/PCS: SearchParty (82) in coda — altrimenti ogni unwrap prova 82 per primo.
                pcsKeys = pcsKeys
                    .OrderBy(k => k.Service == PcsPrivateKeyDer.SearchPartyServiceType ? 1 : 0)
                    .ThenBy(k => k.Service ?? int.MaxValue)
                    .ToList();
                session.PcsManateeCompactKeys = pcsKeys;
                var keysDir = Path.Combine(outputDirectory, "manatee_pcs_keys");
                Directory.CreateDirectory(keysDir);
                var svc82 = 0;
                for (var i = 0; i < pcsKeys.Count; i++)
                {
                    var k = pcsKeys[i];
                    if (k.Service == PcsPrivateKeyDer.SearchPartyServiceType)
                        svc82++;
                    var tag = k.Service?.ToString() ?? "na";
                    await File.WriteAllBytesAsync(
                        Path.Combine(keysDir, $"pcs_{i:D3}_svc{tag}_x.bin"), k.PublicX, ct);
                    await File.WriteAllBytesAsync(
                        Path.Combine(keysDir, $"pcs_{i:D3}_svc{tag}_d.bin"), k.PrivateD, ct);
                }

                log?.Report(
                    $"  Manatee PCS keys → sessione ({pcsKeys.Count}, searchparty/82={svc82})");
            }

            var itemsPath = Path.Combine(outputDirectory, "ckks_items.json");
            var itemsJson = JsonSerializer.Serialize(
                allItems.Select(i => new
                {
                    i.View,
                    i.Name,
                    i.Class,
                    i.Agrp,
                    i.Srvr,
                    i.Acct,
                    i.Labl,
                    dataLen = i.Data?.Length ?? 0,
                    dataB64 = i.Data is { Length: > 0 and <= 4096 }
                        ? Convert.ToBase64String(i.Data)
                        : null
                }),
                new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(itemsPath, itemsJson, ct);

            var passwordRows = 0;
            try
            {
                passwordRows = await CkksPasswordExport
                    .WriteAsync(allItems, outputDirectory, log, ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                log?.Report($"  Passwords export skip: {ex.Message}");
                errors.Add("passwords-export: " + ex.Message);
            }

            var meta = JsonSerializer.Serialize(new
            {
                success = totalClass > 0 || allItems.Count > 0,
                peerId = session.OctagonPeerId,
                views = viewList,
                records = totalRecords,
                tlkSharesMatched = totalShares,
                classKeys = totalClass,
                items = allItems.Count,
                pcsKeys = pcsKeys.Count,
                passwordItems = passwordRows,
                errors,
                refImpl = "Laky-64/appleservices ckks OpenVault"
            }, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(
                Path.Combine(outputDirectory, "ckks_vault_meta.json"), meta, ct);

            var ok = totalClass > 0 || allItems.Count > 0 || pcsKeys.Count > 0;
            var msg = ok
                ? $"OK — items={allItems.Count} classKeys={totalClass} pcsKeys={pcsKeys.Count}"
                  + $" passwords={passwordRows}"
                  + (errors.Count > 0 ? $" (warn: {errors.Count})" : "")
                : errors.Count > 0
                    ? string.Join("; ", errors.Take(3))
                    : "Nessuna chiave/item CKKS recuperata.";

            return new CkksVaultOpenResult(
                ok, msg,
                View: string.Join(",", viewList),
                RecordCount: totalRecords,
                TlkShares: totalShares,
                ClassKeys: totalClass,
                ItemsDecrypted: allItems.Count,
                PcsKeysFound: pcsKeys.Count,
                TlkPath: lastTlkPath,
                ItemsJsonPath: itemsPath);
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    private sealed record ViewOpenResult(
        bool Success,
        string Message,
        int RecordCount,
        int TlkShares,
        int ClassKeys,
        List<CkksVaultItem> Items,
        List<PcsCompactPrivateKey> PcsKeys,
        string? TlkPath);

    private async Task<ViewOpenResult> OpenOneViewAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string view,
        string outputDirectory,
        IProgress<string>? log,
        CancellationToken ct,
        IReadOnlyDictionary<string, byte[]>? recoverableTlks = null,
        IReadOnlyList<CkksRecord>? recoverableSyncKeys = null)
    {
        var records = await FetchZoneRecordsAsync(session, binding, view, outputDirectory, log, ct)
            .ConfigureAwait(false);

        // Merge solo synckey recoverable il cui nome/zone punta a questa view.
        if (recoverableSyncKeys is { Count: > 0 })
        {
            var byName = new HashSet<string>(
                records.Where(r => !string.IsNullOrEmpty(r.Name)).Select(r => r.Name),
                StringComparer.Ordinal);
            foreach (var sk in recoverableSyncKeys)
            {
                if (!sk.Type.Equals("synckey", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!SyncKeyBelongsToView(sk, view))
                    continue;
                if (!string.IsNullOrEmpty(sk.Name) && !byName.Add(sk.Name))
                    continue;
                records.Add(sk);
            }
        }

        if (records.Count == 0)
            return new ViewOpenResult(false, "nessun record in zone", 0, 0, 0, [], [], null);

        var tlkShares = records.Count(r => r.Type.Equals("tlkshare", StringComparison.OrdinalIgnoreCase));
        log?.Report($"  records={records.Count} (tlkshare={tlkShares})");

        byte[] tlk;
        if (session.CkksTlkByView is not null
            && session.CkksTlkByView.TryGetValue(view, out var seeded)
            && seeded is { Length: > 0 })
        {
            tlk = seeded;
            log?.Report($"  TLK da sessione/preload ({tlk.Length} B)");
        }
        else if (!TryUnwrapTlk(session, records, out tlk, out var tlkErr))
        {
            if (recoverableTlks is not null
                && recoverableTlks.TryGetValue(view, out var recovTlk)
                && recovTlk is { Length: > 0 })
            {
                tlk = recovTlk;
                log?.Report($"  TLK da fetchRecoverableTLKShares ({tlk.Length} B)");
            }
            else
            {
                return new ViewOpenResult(
                    false, tlkErr ?? "TLK unwrap fallito", records.Count, 0, 0, [], [], null);
            }
        }

        var tlkPath = Path.Combine(outputDirectory, $"ckks_{Sanitize(view)}_tlk.bin");
        await File.WriteAllBytesAsync(tlkPath, tlk, ct);
        session.CkksTlkByView ??= new Dictionary<string, byte[]>(StringComparer.Ordinal);
        session.CkksTlkByView[view] = tlk;

        var (classKeys, classMap) = DeriveClassKeys(records, tlk);
        if (classKeys.Count == 0)
            return new ViewOpenResult(
                false, "nessuna classA/classC synckey", records.Count, 1, 0, [], [], tlkPath);

        log?.Report($"  TLK OK ({tlk.Length} B), classKeys={classKeys.Count}");

        var items = new List<CkksVaultItem>();
        var pcs = new List<PcsCompactPrivateKey>();
        foreach (var rec in records)
        {
            if (!rec.Type.Equals("item", StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                var item = DecryptItemRecord(view, rec, classKeys);
                items.Add(item);
                pcs.AddRange(ExtractPcsFromItem(item));
            }
            catch (Exception ex)
            {
                log?.Report($"    item {TrimId(rec.Name)}: {ex.Message}");
            }
        }

        // Persist decrypted item payloads.
        var itemsDir = Path.Combine(outputDirectory, $"ckks_{Sanitize(view)}_items");
        Directory.CreateDirectory(itemsDir);
        foreach (var item in items)
        {
            if (item.Data is not { Length: > 0 })
                continue;
            var safe = Sanitize(item.Name);
            if (safe.Length > 80)
                safe = safe[..80];
            await File.WriteAllBytesAsync(
                Path.Combine(itemsDir, $"{safe}.bin"), item.Data, ct);
        }

        return new ViewOpenResult(
            true, "ok", records.Count, 1, classKeys.Count, items, pcs, tlkPath);
    }

    /// <summary>
    /// Lab: record/sync di una view CKKS senza richiedere peer PKCS#8.
    /// Utile per vedere se la zona espone tlkshare/item a sessione non-peer.
    /// </summary>
    public async Task<(bool Ok, int Records, int TlkShares, int Items, string Message)> ProbeFetchZoneAsync(
        ICloudSession session,
        string view,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var binding = CloudKitContainerBinding.Cuttlefish;
        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;
        try
        {
            await _orchestrator.CkAppInitAsync(session, binding.ContainerId, log, ct)
                .ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
                || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            {
                return (false, 0, 0, 0, "ckAppInit senza token");
            }

            var records = await FetchZoneRecordsAsync(
                    session, binding, view, outputDirectory, log, ct)
                .ConfigureAwait(false);
            var tlk = records.Count(r => r.Type.Equals("tlkshare", StringComparison.OrdinalIgnoreCase));
            var items = records.Count(r => r.Type.Equals("item", StringComparison.OrdinalIgnoreCase));
            return (true, records.Count, tlk, items,
                $"records={records.Count} tlkshare={tlk} item={items}");
        }
        catch (Exception ex)
        {
            return (false, 0, 0, 0, ex.Message);
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    private async Task<List<CkksRecord>> FetchZoneRecordsAsync(
        ICloudSession session,
        CloudKitContainerBinding binding,
        string view,
        string outputDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var byName = new Dictionary<string, CkksRecord>(StringComparer.Ordinal);
        var ordered = new List<CkksRecord>();
        byte[]? token = null;

        for (var page = 0; page < MaxSyncPages; page++)
        {
            ct.ThrowIfCancellationRequested();
            var body = CloudKitDelimitedRequest.BuildCkksRecordSync(
                session.CloudKitUserId!, view, token, binding);
            byte[] payload;
            try
            {
                payload = await _gateway.RecordChangesAsync(session, body, ct, binding)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                log?.Report($"  record/sync p{page + 1}: {ex.Message}");
                break;
            }

            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, $"ckks_{Sanitize(view)}_sync_p{page + 1}.bin"),
                payload, ct);

            if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err))
            {
                log?.Report($"  record/sync p{page + 1} error: {err}");
                break;
            }

            var pageRecords = CkksZoneParser.ParseZone(payload);
            var added = 0;
            foreach (var rec in pageRecords)
            {
                if (!string.IsNullOrEmpty(rec.Name) && byName.TryGetValue(rec.Name, out var idx))
                {
                    var i = ordered.IndexOf(idx);
                    if (i >= 0)
                        ordered[i] = rec;
                    byName[rec.Name] = rec;
                    continue;
                }

                if (!string.IsNullOrEmpty(rec.Name))
                    byName[rec.Name] = rec;
                ordered.Add(rec);
                added++;
            }

            log?.Report($"  sync p{page + 1}: {payload.Length:N0} B, +{added} records");

            var cont = CloudKitResponseParser.TryExtractRecordSyncContinuation(payload);
            if (!cont.MoreComing || cont.SyncContinuationToken is not { Length: > 0 })
                break;
            if (token is not null && token.AsSpan().SequenceEqual(cont.SyncContinuationToken))
                break;
            if (page > 0 && added == 0)
                break;
            token = cont.SyncContinuationToken;
        }

        return ordered;
    }

    private static bool SyncKeyBelongsToView(CkksRecord sk, string view)
    {
        foreach (var key in new[] { "view", "zone", "zonename" })
        {
            var v = sk.FieldString(key);
            if (!string.IsNullOrEmpty(v)
                && v.Equals(view, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        if (!string.IsNullOrEmpty(sk.Name)
            && sk.Name.StartsWith(view + ":", StringComparison.OrdinalIgnoreCase))
            return true;

        // Senza tag zona: includi (viewkeys RPC è già scoped al peer; DeriveClassKeys
        // scarta wrap che non aprono con il TLK di questa view).
        return string.IsNullOrEmpty(sk.FieldString("view"))
               && string.IsNullOrEmpty(sk.FieldString("zone"))
               && (string.IsNullOrEmpty(sk.Name) || !sk.Name.Contains(':'));
    }

    private static bool TryUnwrapTlk(
        ICloudSession session,
        IReadOnlyList<CkksRecord> records,
        out byte[] tlk,
        out string? error)
    {
        tlk = [];
        error = null;
        var peerId = session.OctagonPeerId!;
        var pkcs8 = session.OctagonPeerEncryptionPkcs8!;
        var tried = 0;

        foreach (var rec in records)
        {
            if (!rec.Type.Equals("tlkshare", StringComparison.OrdinalIgnoreCase))
                continue;
            var receiver = rec.FieldString("receiver");
            if (!string.Equals(receiver, peerId, StringComparison.Ordinal))
                continue;

            tried++;
            var wrapped = rec.FieldString("wrappedkey");
            if (string.IsNullOrEmpty(wrapped))
            {
                error = "tlkshare senza wrappedkey";
                continue;
            }

            if (!CkksTlkShare.TryExtractEciesBlob(wrapped, out var ecies, out var extractErr))
            {
                error = extractErr;
                continue;
            }

            try
            {
                var ckksKeyPt = CkksEcies.Unwrap(pkcs8, ecies);
                tlk = CkksKeys.TlkFromCkksKeyPlaintext(ckksKeyPt);
                return true;
            }
            catch (Exception ex)
            {
                error = $"ECIES unwrap: {ex.Message}";
            }
        }

        if (tried == 0)
        {
            // Fallback: prova ogni tlkshare (peer id mismatch formati SHA256:…).
            foreach (var rec in records)
            {
                if (!rec.Type.Equals("tlkshare", StringComparison.OrdinalIgnoreCase))
                    continue;
                var wrapped = rec.FieldString("wrappedkey");
                if (string.IsNullOrEmpty(wrapped))
                    continue;
                if (!CkksTlkShare.TryExtractEciesBlob(wrapped, out var ecies, out _))
                    continue;
                try
                {
                    var ckksKeyPt = CkksEcies.Unwrap(pkcs8, ecies);
                    tlk = CkksKeys.TlkFromCkksKeyPlaintext(ckksKeyPt);
                    return true;
                }
                catch
                {
                    // next share
                }
            }

            error = $"nessun TLKShare per peer {TrimId(peerId)}";
            return false;
        }

        error ??= "TLKShare unwrap fallito";
        return false;
    }

    private static (List<byte[]> Keys, Dictionary<string, byte[]> ByClass) DeriveClassKeys(
        IReadOnlyList<CkksRecord> records, byte[] tlk)
    {
        var keys = new List<byte[]>();
        var byClass = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var rec in records)
        {
            if (!rec.Type.Equals("synckey", StringComparison.OrdinalIgnoreCase))
                continue;
            var cls = rec.FieldString("class");
            if (cls is not ("classA" or "classC"))
                continue;
            var wrappedB64 = rec.FieldString("wrappedkey");
            if (string.IsNullOrEmpty(wrappedB64))
                continue;
            byte[] wrapped;
            try
            {
                wrapped = Convert.FromBase64String(wrappedB64);
            }
            catch
            {
                continue;
            }

            try
            {
                var key = CkksKeys.UnwrapKey(tlk, wrapped);
                keys.Add(key);
                byClass.TryAdd(cls, key);
            }
            catch
            {
                // skip
            }
        }

        return (keys, byClass);
    }

    private static CkksVaultItem DecryptItemRecord(
        string view, CkksRecord rec, IReadOnlyList<byte[]> classKeys)
    {
        var wrappedB64 = rec.FieldString("wrappedkey")
                         ?? throw new InvalidDataException("item senza wrappedkey");
        var wrapped = Convert.FromBase64String(wrappedB64);
        byte[]? itemKey = null;
        foreach (var ck in classKeys)
        {
            try
            {
                itemKey = CkksKeys.UnwrapKey(ck, wrapped);
                break;
            }
            catch
            {
                // next class key
            }
        }

        if (itemKey is null)
            throw new InvalidDataException("nessuna class key unwrapa la per-item key");

        var data = rec.FieldBytes("data")
                   ?? throw new InvalidDataException("item senza data");
        var aad = BuildItemAad(rec);
        var padded = CkksKeys.DecryptItem(itemKey, data, aad);
        var plain = CkksKeys.TrimPkcs7StylePadding(padded);
        var attrs = ParseItemPlist(plain);

        return new CkksVaultItem(
            view,
            rec.Name,
            rec.Etag,
            AsString(attrs, "class"),
            AsString(attrs, "agrp"),
            AsString(attrs, "srvr"),
            AsString(attrs, "acct"),
            AsString(attrs, "labl"),
            AsBytes(attrs, "v_Data"),
            attrs,
            PcsService: rec.FieldInt("pcsservice"),
            PcsPublicKey: rec.FieldBytes("pcspublickey"));
    }

    private static List<byte[]> BuildItemAad(CkksRecord item)
    {
        var aad = new List<byte[]> { Encoding.UTF8.GetBytes(item.Name) };
        if (item.FieldInt("encver") is { } encver)
            aad.Add(CkksKeys.LeInt64(encver));
        if (item.FieldInt("gen") is { } gen)
            aad.Add(CkksKeys.LeInt64(gen));
        if (item.FieldBytes("pcspublicidentity") is { Length: > 0 } pcsId)
            aad.Add(pcsId);
        if (item.FieldBytes("pcspublickey") is { Length: > 0 } pcsPub)
            aad.Add(pcsPub);
        if (item.FieldInt("pcsservice") is { } pcsSvc)
            aad.Add(CkksKeys.LeInt64(pcsSvc));
        if (item.FieldBytes("parentkeyref") is { Length: > 0 } pref)
        {
            var parent = CkksZoneParser.RefTargetName(pref);
            if (!string.IsNullOrEmpty(parent))
                aad.Add(Encoding.UTF8.GetBytes(parent));
        }

        return aad;
    }

    private static Dictionary<string, object?> ParseItemPlist(byte[] data)
    {
        if (data.Length >= 6 && data.AsSpan(0, 6).SequenceEqual("bplist"u8))
        {
            if (AppleBinaryPlist.TryParseDict(data, out var dict, out _) && dict is not null)
                return dict;
        }

        // XML plist minimale (string / data base64).
        try
        {
            var text = Encoding.UTF8.GetString(data);
            if (text.Contains("<plist", StringComparison.OrdinalIgnoreCase))
                return ParseXmlPlistDict(text);
        }
        catch
        {
            // ignore
        }

        return new Dictionary<string, object?>(StringComparer.Ordinal);
    }

    private static Dictionary<string, object?> ParseXmlPlistDict(string xml)
    {
        var d = new Dictionary<string, object?>(StringComparer.Ordinal);
        var doc = XDocument.Parse(xml);
        var dict = doc.Descendants("dict").FirstOrDefault();
        if (dict is null)
            return d;
        string? pendingKey = null;
        foreach (var el in dict.Elements())
        {
            if (el.Name.LocalName == "key")
            {
                pendingKey = el.Value;
                continue;
            }

            if (pendingKey is null)
                continue;
            d[pendingKey] = el.Name.LocalName switch
            {
                "string" => el.Value,
                "data" => Convert.FromBase64String(
                    string.Concat(el.Value.Where(c => !char.IsWhiteSpace(c)))),
                "integer" => long.TryParse(el.Value, out var n) ? n : el.Value,
                "true" => true,
                "false" => false,
                _ => el.Value
            };
            pendingKey = null;
        }

        return d;
    }

    private static string? AsString(Dictionary<string, object?> attrs, string key) =>
        attrs.TryGetValue(key, out var v) ? v?.ToString() : null;

    private static byte[]? AsBytes(Dictionary<string, object?> attrs, string key) =>
        attrs.TryGetValue(key, out var v) ? v as byte[] : null;

    /// <summary>
    /// Estrae PCS private keys reali (DER PCSPrivateKey / KeySet) da item
    /// <c>com.apple.ProtectedCloudStorage</c> nelle view Manatee/PCS.
    /// Niente sliding-window: produceva centinaia di falsi positivi.
    /// </summary>
    private static List<PcsCompactPrivateKey> ExtractPcsFromItem(CkksVaultItem item)
    {
        if (item.Data is not { Length: > 0 } data)
            return [];

        var agrp = item.Agrp ?? "";
        var sdmn = AsString(item.Attrs, "sdmn") ?? "";
        var vwht = AsString(item.Attrs, "vwht") ?? "";
        var interesting =
            item.View.Equals("Manatee", StringComparison.OrdinalIgnoreCase)
            || item.View.Equals("ProtectedCloudStorage", StringComparison.OrdinalIgnoreCase)
            || agrp.Equals("com.apple.ProtectedCloudStorage", StringComparison.OrdinalIgnoreCase)
            || sdmn.Equals("ProtectedCloudStorage", StringComparison.OrdinalIgnoreCase)
            || vwht.Equals("Manatee", StringComparison.OrdinalIgnoreCase)
            || vwht.Equals("PCS-MasterKey", StringComparison.OrdinalIgnoreCase)
            || item.PcsService is not null
            || item.PcsPublicKey is { Length: > 0 };

        if (!interesting)
            return [];

        int? serviceHint = item.PcsService is { } s ? (int)s : null;
        // keychain "type" field = keychain_type (82 per searchparty)
        if (serviceHint is null && item.Attrs.TryGetValue("type", out var typeObj))
        {
            if (typeObj is long tl && tl is > 0 and < 1_000_000)
                serviceHint = (int)tl;
            else if (typeObj is int ti && ti is > 0 and < 1_000_000)
                serviceHint = ti;
        }

        var found = PcsPrivateKeyDer.TryParseAll(data, serviceHint);

        // Se acct è base64 della PublicX, allinea la chiave estratta.
        if (found.Count == 0
            && !string.IsNullOrEmpty(item.Acct)
            && data.Length >= 64)
        {
            try
            {
                var acctPub = Convert.FromBase64String(item.Acct);
                if (acctPub.Length >= 32)
                {
                    var x = acctPub.AsSpan(0, 32).ToArray();
                    // cerca x‖d nel blob
                    var idx = IndexOf(data, x);
                    if (idx >= 0 && idx + 64 <= data.Length)
                    {
                        var d = data.AsSpan(idx + 32, 32).ToArray();
                        found.Add(new PcsCompactPrivateKey(x, d, PcsDer.KeyIdOf(x), serviceHint));
                    }
                }
            }
            catch
            {
                // acct non base64
            }
        }

        return DedupPcs(found);
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        if (needle.Length == 0 || hay.Length < needle.Length)
            return -1;
        var span = hay.AsSpan();
        for (var i = 0; i <= span.Length - needle.Length; i++)
        {
            if (span.Slice(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }

    private static List<PcsCompactPrivateKey> DedupPcs(List<PcsCompactPrivateKey> keys)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var outList = new List<PcsCompactPrivateKey>();
        foreach (var k in keys)
        {
            var id = Convert.ToHexString(k.KeyId);
            if (!seen.Add(id))
                continue;
            outList.Add(k);
        }

        return outList;
    }

    private static void TryReloadPeerFromDisk(
        ICloudSession session, string outputDirectory, IProgress<string>? log)
    {
        if (session.OctagonPeerEncryptionPkcs8 is { Length: > 0 }
            && !string.IsNullOrWhiteSpace(session.OctagonPeerId))
            return;

        var dirs = new[]
        {
            outputDirectory,
            session.OctagonKeysDirectory ?? ""
        };
        foreach (var dir in dirs.Where(d => !string.IsNullOrWhiteSpace(d) && Directory.Exists(d)))
        {
            var enc = Path.Combine(dir, "octagon_peer_encryption.pkcs8");
            var meta = Path.Combine(dir, "octagon_peer_unlock_meta.json");
            if (File.Exists(enc) && session.OctagonPeerEncryptionPkcs8 is not { Length: > 0 })
            {
                session.OctagonPeerEncryptionPkcs8 = File.ReadAllBytes(enc);
                log?.Report($"  peer enc ricaricata da {enc}");
            }

            if (File.Exists(meta) && string.IsNullOrWhiteSpace(session.OctagonPeerId))
            {
                try
                {
                    using var doc = JsonDocument.Parse(File.ReadAllText(meta));
                    if (doc.RootElement.TryGetProperty("peerId", out var p))
                        session.OctagonPeerId = p.GetString();
                }
                catch
                {
                    // ignore
                }
            }
        }
    }

    private static string Sanitize(string s)
    {
        var sb = new StringBuilder(s.Length);
        foreach (var c in s)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        return sb.ToString();
    }

    private static string TrimId(string? id)
    {
        if (string.IsNullOrWhiteSpace(id))
            return "?";
        return id.Length <= 24 ? id : id[..12] + "…" + id[^8..];
    }
}
