using System.IO;
using System.Linq;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Http;
using iCloudKitExtractor.Services;

namespace iCloudKitExtractor.Services.Escrow;

public sealed record OctagonViableBottle(
    string PeerId,
    string BottleId,
    string EscrowRecordLabel,
    string Serial,
    string Model,
    byte[] Contents);

public sealed record OctagonPeerRecoveryResult(
    bool Success,
    string Message,
    string? PeerId = null,
    string? BottleId = null,
    string? EscrowLabel = null,
    string? PeerEncryptionPkcs8Path = null,
    string? PeerSigningPkcs8Path = null,
    int ViableCount = 0,
    int PartialCount = 0);

/// <summary>
/// Risultato di <c>fetchRecoverableTLKShares</c>: TLK per zona + synckey viewkeys.
/// </summary>
public sealed record RecoverableTlkSharesResult(
    bool Success,
    string Message,
    IReadOnlyDictionary<string, byte[]> TlkByView,
    IReadOnlyList<CkksRecord> SyncKeyRecords,
    int ShareRecords = 0);

public sealed record OctagonViableBottlesFetchResult(
    bool Success,
    string Message,
    byte[] Raw,
    IReadOnlyList<OctagonViableBottle> Viable,
    IReadOnlyList<OctagonViableBottle> Partial);

/// <summary>
/// Post-escrow Octagon: CloudKit <c>code/invoke</c> Cuttlefish
/// <c>fetchViableBottles</c> → AES-GCM OTBottle con BottledPeerEntropy
/// (Laky-64/appleservices).
/// </summary>
public sealed class OctagonCuttlefishService
{
    public const string ContainerId = "com.apple.security.keychain";
    public const string BundleId = "com.apple.security.cuttlefish";
    public const string ServiceName = "Cuttlefish";
    public const int FunctionInvokeType = 1101;

    private readonly HttpClient _http;
    private readonly ICloudBackupOrchestrator _orchestrator;

    public OctagonCuttlefishService(HttpClient http, ICloudBackupOrchestrator orchestrator)
    {
        _http = http;
        _orchestrator = orchestrator;
    }

    /// <summary>
    /// Session-only: <c>fetchViableBottles</c> senza entropy/PIN/RK.
    /// Restituisce Contents (ciphertext atteso) per audit overshare.
    /// </summary>
    public async Task<OctagonViableBottlesFetchResult> FetchViableBottlesOnlyAsync(
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;
        try
        {
            log?.Report($"Octagon Cuttlefish: ckAppInit → {ContainerId} (enum bottles, no decrypt)…");
            await _orchestrator.CkAppInitAsync(session, ContainerId, log, ct);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
                || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            {
                return new OctagonViableBottlesFetchResult(
                    false, "ckAppInit keychain senza cloudKitUserId/token.", [], [], []);
            }

            var dbUrl = ResolveDatabaseUrl(session);
            if (string.IsNullOrWhiteSpace(dbUrl))
            {
                return new OctagonViableBottlesFetchResult(
                    false, "CloudKit database URL assente dopo ckAppInit.", [], [], []);
            }

            var codeBase = dbUrl.Replace("-ckdatabase.", "-ckcoderouter.", StringComparison.Ordinal);
            log?.Report($"  code/invoke → {codeBase}  fetchViableBottles…");
            var raw = await InvokeAsync(
                session, codeBase, "fetchViableBottles", [], log, ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "octagon_fetchViableBottles.bin"), raw, ct);

            var (viable, partial) = ParseViableBottles(raw);
            log?.Report($"  bottles: viable={viable.Count} partial={partial.Count} " +
                        $"withContents={viable.Concat(partial).Count(b => b.Contents.Length > 0)}");
            return new OctagonViableBottlesFetchResult(
                true, $"OK viable={viable.Count} partial={partial.Count}", raw, viable, partial);
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    public async Task<OctagonPeerRecoveryResult> FetchAndDecryptPeerAsync(
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (session.OctagonBottledPeerEntropy is not { Length: > 0 })
        {
            return new OctagonPeerRecoveryResult(
                false, "BottledPeerEntropy assente — fai prima Unlock Octagon bottle.");
        }

        if (string.IsNullOrWhiteSpace(session.Adsid))
            return new OctagonPeerRecoveryResult(false, "Adsid assente (serve come salt HKDF).");

        Directory.CreateDirectory(outputDirectory);

        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;

        try
        {
            log?.Report($"Octagon Cuttlefish: ckAppInit → {ContainerId}…");
            await _orchestrator.CkAppInitAsync(session, ContainerId, log, ct);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
                || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            {
                return new OctagonPeerRecoveryResult(
                    false, "ckAppInit keychain senza cloudKitUserId/token.");
            }

            var dbUrl = ResolveDatabaseUrl(session);
            if (string.IsNullOrWhiteSpace(dbUrl))
            {
                return new OctagonPeerRecoveryResult(
                    false, "CloudKit database URL assente dopo ckAppInit.");
            }

            var codeBase = dbUrl.Replace("-ckdatabase.", "-ckcoderouter.", StringComparison.Ordinal);
            log?.Report($"  code/invoke → {codeBase}  fetchViableBottles…");

            var raw = await InvokeAsync(
                session, codeBase, "fetchViableBottles", [], log, ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "octagon_fetchViableBottles.bin"), raw, ct);

            var (viable, partial) = ParseViableBottles(raw);
            log?.Report($"  bottles: viable={viable.Count} partial={partial.Count}");

            var all = viable.Concat(partial).ToList();
            foreach (var b in all.Take(12))
            {
                log?.Report(
                    $"    · peer={TrimId(b.PeerId)} bottle={TrimId(b.BottleId)} " +
                    $"serial={b.Serial} label={TrimLabel(b.EscrowRecordLabel)} " +
                    $"contents={b.Contents.Length} B");
            }

            var preferLabel = session.OctagonBottleLabel ?? "";
            var preferSerial = session.OctagonBottleSerial ?? "";
            var withContents = all.Where(b => b.Contents.Length > 0).ToList();
            if (withContents.Count == 0)
            {
                return new OctagonPeerRecoveryResult(
                    false,
                    "Nessuna OTBottle con Contents (fetchViableBottles vuoto o solo metadati).",
                    ViableCount: viable.Count,
                    PartialCount: partial.Count);
            }

            var ordered = OrderBottlesForDecrypt(withContents, preferLabel, preferSerial);
            if (!string.IsNullOrWhiteSpace(preferLabel)
                && !withContents.Any(b =>
                    string.Equals(b.EscrowRecordLabel, preferLabel, StringComparison.Ordinal)))
            {
                log?.Report(
                    $"  WARN: bottle Escrow sbloccata ({TrimLabel(preferLabel)}" +
                    (string.IsNullOrWhiteSpace(preferSerial) ? "" : $", serial={preferSerial}") +
                    ") non ha Contents in fetchViableBottles. " +
                    "Provo tutte le OTBottle (GCM fallirà se l'entropy non matcha).");
            }

            OctagonViableBottle? match = null;
            byte[]? peerSigning = null;
            byte[]? peerEncryption = null;
            string? peerIdFromBottle = null;
            string? bottleIdFromBottle = null;
            string? lastErr = null;

            foreach (var candidate in ordered)
            {
                log?.Report(
                    $"  decrypt OTBottle ← label={TrimLabel(candidate.EscrowRecordLabel)} " +
                    $"serial={candidate.Serial} peer={TrimId(candidate.PeerId)} " +
                    $"contents={candidate.Contents.Length} B…");
                await File.WriteAllBytesAsync(
                    Path.Combine(outputDirectory, "octagon_otbottle_contents.bin"),
                    candidate.Contents, ct);

                if (OctagonBottleCrypto.TryDecryptOtBottle(
                        session.OctagonBottledPeerEntropy,
                        session.Adsid,
                        candidate.Contents,
                        out peerSigning,
                        out peerEncryption,
                        out peerIdFromBottle,
                        out bottleIdFromBottle,
                        out var err))
                {
                    match = candidate;
                    break;
                }

                lastErr = err;
                log?.Report($"    GCM fail ({err}) — prossima bottle…");
            }

            if (match is null
                || peerSigning is null
                || peerEncryption is null)
            {
                return new OctagonPeerRecoveryResult(
                    false,
                    $"Decrypt OTBottle fallito su {ordered.Count} candidate(s): {lastErr}. " +
                    "L'entropy Escrow deve provenire dalla stessa bottle/device delle Contents " +
                    "in fetchViableBottles (sblocca una bottle SHA256:… presente nella lista viable).",
                    EscrowLabel: preferLabel,
                    ViableCount: viable.Count,
                    PartialCount: partial.Count);
            }

            var peerId = !string.IsNullOrWhiteSpace(match.PeerId)
                ? match.PeerId
                : peerIdFromBottle ?? "";
            var bottleId = !string.IsNullOrWhiteSpace(match.BottleId)
                ? match.BottleId
                : bottleIdFromBottle ?? "";

            var encPath = Path.Combine(outputDirectory, "octagon_peer_encryption.pkcs8");
            var sigPath = Path.Combine(outputDirectory, "octagon_peer_signing.pkcs8");
            await File.WriteAllBytesAsync(encPath, peerEncryption, ct);
            await File.WriteAllBytesAsync(sigPath, peerSigning, ct);

            session.OctagonPeerId = peerId;
            session.OctagonPeerEncryptionPkcs8 = peerEncryption;
            session.OctagonPeerSigningPkcs8 = peerSigning;

            var meta = JsonSerializer.Serialize(new
            {
                success = true,
                peerId,
                bottleId,
                escrowLabel = match.EscrowRecordLabel,
                serial = match.Serial,
                model = match.Model,
                viable = viable.Count,
                partial = partial.Count,
                contentsBytes = match.Contents.Length,
                peerEncryptionPkcs8 = Path.GetFileName(encPath),
                peerSigningPkcs8 = Path.GetFileName(sigPath),
                refImpl = "Laky-64/appleservices octagon DecryptBottle + fetchViableBottles"
            }, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(
                Path.Combine(outputDirectory, "octagon_peer_unlock_meta.json"), meta, ct);

            log?.Report($"  peer encryption PKCS8 → {Path.GetFileName(encPath)} ({peerEncryption.Length} B)");
            log?.Report($"  peer signing PKCS8 → {Path.GetFileName(sigPath)} ({peerSigning.Length} B)");

            return new OctagonPeerRecoveryResult(
                true,
                $"OK — sponsor peer {TrimId(peerId)} (enc={peerEncryption.Length} B).",
                peerId,
                bottleId,
                match.EscrowRecordLabel,
                encPath,
                sigPath,
                viable.Count,
                partial.Count);
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    /// <summary>
    /// Cuttlefish <c>fetchRecoverableTLKShares(forPeer)</c> — TLK per view user-controllable
    /// (Passwords/Manatee) quando i <c>tlkshare</c> in zone non sono indirizzati al peer.
    /// Con ghost Trust il peer bottled è lo sponsor: <paramref name="forPeerId"/> = OctagonPeerId.
    /// </summary>
    /// <param name="tryLegacyFieldVariants">
    /// false (path RK/prod): solo <c>fetchRecoverableTLKShares</c> f1 poi f2
    /// (niente casing <c>Tlkshares</c> → HTTP 500).
    /// true (lab/authz): prova anche casing legacy.
    /// </param>
    public async Task<RecoverableTlkSharesResult> FetchRecoverableTlkSharesAsync(
        ICloudSession session,
        string outputDirectory,
        string? forPeerId = null,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        bool tryLegacyFieldVariants = true)
    {
        // allowEmptyForPeer: probe authz with explicit empty string (IKE_AUTHZ_PROBES).
        var allowEmpty = string.Equals(
            Environment.GetEnvironmentVariable("IKE_AUTHZ_ALLOW_EMPTY_FORPEER"),
            "1",
            StringComparison.Ordinal);
        var peerId = forPeerId ?? session.OctagonPeerId;
        if (string.IsNullOrWhiteSpace(peerId) && !(allowEmpty && forPeerId is not null))
        {
            return new RecoverableTlkSharesResult(
                false, "OctagonPeerId assente.",
                new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase),
                []);
        }

        peerId ??= "";

        if (session.OctagonPeerEncryptionPkcs8 is not { Length: > 0 })
        {
            return new RecoverableTlkSharesResult(
                false, "Peer encryption PKCS#8 assente.",
                new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase),
                []);
        }

        Directory.CreateDirectory(outputDirectory);

        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;

        try
        {
            // OpenVault ha già fatto ckAppInit sulla stessa container; se manca, rifallo.
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId)
                || string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
            {
                log?.Report($"Octagon Cuttlefish: ckAppInit → {ContainerId}…");
                await _orchestrator.CkAppInitAsync(session, ContainerId, log, ct);
            }

            var dbUrl = ResolveDatabaseUrl(session);
            if (string.IsNullOrWhiteSpace(dbUrl))
            {
                return new RecoverableTlkSharesResult(
                    false, "CloudKit database URL assente.",
                    new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase),
                    []);
            }

            var codeBase = dbUrl.Replace("-ckdatabase.", "-ckcoderouter.", StringComparison.Ordinal);
            log?.Report(
                $"  fetchRecoverableTLKShares forPeer={TrimId(peerId)}…");

            // Prod: camelCase, forPeer f1 prima (Lab live unwrap OK), poi f2.
            // Authz-only: anche casing Tlkshares → spesso HTTP 500.
            byte[]? raw = null;
            List<CkksRecord> shareRecs = [];
            List<CkksRecord> syncRecs = [];
            string? lastErr = null;
            var attempts = tryLegacyFieldVariants
                ? new (string Fn, int Field)[]
                {
                    ("fetchRecoverableTLKShares", 1),
                    ("fetchRecoverableTLKShares", 2),
                    ("fetchRecoverableTlkshares", 1),
                    ("fetchRecoverableTlkshares", 2),
                }
                : new (string Fn, int Field)[]
                {
                    ("fetchRecoverableTLKShares", 1),
                    ("fetchRecoverableTLKShares", 2),
                };
            foreach (var (fn, field) in attempts)
            {
                ct.ThrowIfCancellationRequested();
                var req = new ProtobufWriter();
                req.WriteString(field, peerId);
                try
                {
                    var attempt = await InvokeAsync(session, codeBase, fn, req.ToArray(), log, ct)
                        .ConfigureAwait(false);
                    var tag = $"{fn}_f{field}";
                    await File.WriteAllBytesAsync(
                        Path.Combine(outputDirectory, $"octagon_{tag}.bin"), attempt, ct);
                    var (sh, sk) = ParseRecoverableTlkSharesResponse(attempt);
                    log?.Report(
                        $"  {fn} f{field}: {attempt.Length:N0} B → " +
                        $"tlkshare={sh.Count} synckey={sk.Count}");
                    raw = attempt;
                    shareRecs = sh;
                    syncRecs = sk;
                    if (sh.Count > 0)
                        break;
                }
                catch (Exception ex)
                {
                    lastErr = ex.Message;
                    log?.Report($"  {fn} field {field}: {ex.Message}");
                }
            }

            if (raw is null)
            {
                return new RecoverableTlkSharesResult(
                    false, lastErr ?? "fetchRecoverableTLKShares fallito.",
                    new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase),
                    []);
            }

            log?.Report(
                $"  recoverable: tlkshare={shareRecs.Count} synckey={syncRecs.Count}");

            var tlkByView = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            var pkcs8 = session.OctagonPeerEncryptionPkcs8!;
            var unwrapped = 0;
            foreach (var rec in shareRecs)
            {
                var wrapped = rec.FieldString("wrappedkey");
                if (string.IsNullOrEmpty(wrapped))
                    continue;
                if (!CkksTlkShare.TryExtractEciesBlob(wrapped, out var ecies, out _))
                    continue;
                try
                {
                    var pt = CkksEcies.Unwrap(pkcs8, ecies);
                    var tlk = CkksKeys.TlkFromCkksKeyPlaintext(pt);
                    var zone = CkksKeys.ZoneNameFromCkksKeyPlaintext(pt)
                               ?? GuessZoneFromShare(rec);
                    if (string.IsNullOrWhiteSpace(zone))
                        continue;
                    if (tlkByView.TryAdd(zone, tlk))
                    {
                        unwrapped++;
                        log?.Report($"    TLK «{zone}» ({tlk.Length} B)");
                    }
                }
                catch (Exception ex)
                {
                    log?.Report($"    share {TrimId(rec.Name)}: {ex.Message}");
                }
            }

            // Live f1 body spesso non passa dal parser CuttlefishRecord (0 share) ma
            // contiene tlkshare-…::RK-… + wrappedkey bplist — stesso path offline di Lab.
            if (tlkByView.Count == 0 && raw.Length > 0)
            {
                log?.Report(
                    "  recoverable: parser 0 share strutturati — unwrap wire (tlkshare::RK)…");
                var added = OctagonRecoveryKeyVerifier.TryUnwrapBin(
                    raw, pkcs8, tlkByView, peerId);
                unwrapped = added;
                foreach (var view in tlkByView.Keys.OrderBy(k => k, StringComparer.OrdinalIgnoreCase))
                    log?.Report($"    TLK «{view}» ({tlkByView[view].Length} B)");
            }

            // Persist TLK bins per view.
            foreach (var (view, tlk) in tlkByView)
            {
                var safe = SanitizeFile(view);
                await File.WriteAllBytesAsync(
                    Path.Combine(outputDirectory, $"ckks_{safe}_tlk_recoverable.bin"),
                    tlk, ct);
            }

            var shareHint = Math.Max(shareRecs.Count, tlkByView.Count);
            return new RecoverableTlkSharesResult(
                tlkByView.Count > 0,
                tlkByView.Count > 0
                    ? $"OK — {unwrapped} TLK da recoverable shares."
                    : "Nessun TLK unwrapped dal recoverable body.",
                tlkByView,
                syncRecs,
                shareHint);
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    /// <summary>Public wrapper for offline RK verifier / dump re-parse.</summary>
    public static (List<CkksRecord> Shares, List<CkksRecord> SyncKeys)
        ParseRecoverableResponse(byte[] raw) =>
        ParseRecoverableTlkSharesResponse(raw);

    /// <summary>
    /// Response: repeated RecoverableTlkShare groups (field 1 and/or 2).
    /// Group: service/view name + viewkeys + share wrap (field numbers variano 1–4
    /// tra protodoc / Sank6 / cephalochromoscope).
    /// </summary>
    private static (List<CkksRecord> Shares, List<CkksRecord> SyncKeys)
        ParseRecoverableTlkSharesResponse(byte[] raw)
    {
        var shares = new List<CkksRecord>();
        var syncKeys = new List<CkksRecord>();
        var r = new ProtobufReader(raw);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var grp = r.ReadLengthDelimited();
            // Field 1 e 2 sono entrambi usati come repeated share-groups sul wire.
            if (field is 1 or 2)
                ParseRecoverableGroup(grp, shares, syncKeys);
            else
                CollectCkksRecordsDeep(grp, shares, syncKeys);
        }

        if (shares.Count == 0 && syncKeys.Count == 0)
            CollectCkksRecordsDeep(raw, shares, syncKeys);

        return (shares, syncKeys);
    }

    private static void ParseRecoverableGroup(
        byte[] grp, List<CkksRecord> shares, List<CkksRecord> syncKeys)
    {
        var viewkeysBlobs = new List<byte[]>();
        var shareWraps = new List<byte[]>();
        var r = new ProtobufReader(grp);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            switch (field)
            {
                case 1:
                    // service name (string) OPPURE viewkeys wrap — prova entrambi.
                    if (LooksLikeUtf8Name(payload))
                        break;
                    viewkeysBlobs.Add(payload);
                    shareWraps.Add(payload);
                    break;
                case 2:
                    viewkeysBlobs.Add(payload);
                    break;
                case 3:
                case 4:
                    shareWraps.Add(payload);
                    break;
            }
        }

        foreach (var shareWrap in shareWraps)
        {
            foreach (var rec in TryRecordsFromCuttlefishWrap(shareWrap))
            {
                if (rec.Type.Equals("tlkshare", StringComparison.OrdinalIgnoreCase))
                    shares.Add(rec);
                else if (rec.Type.Equals("synckey", StringComparison.OrdinalIgnoreCase))
                    syncKeys.Add(rec);
            }
        }

        foreach (var viewkeys in viewkeysBlobs)
        {
            var vk = new ProtobufReader(viewkeys);
            while (vk.HasMore)
            {
                var (field, wire) = vk.ReadTag();
                if (wire != 2)
                {
                    vk.SkipField(wire);
                    continue;
                }

                var payload = vk.ReadLengthDelimited();
                // tlk=1, classA=2, classB/C=3
                if (field is < 1 or > 4)
                    continue;
                foreach (var rec in TryRecordsFromCuttlefishWrap(payload))
                {
                    if (rec.Type.Equals("synckey", StringComparison.OrdinalIgnoreCase)
                        || rec.Type.Equals("tlkshare", StringComparison.OrdinalIgnoreCase))
                    {
                        if (rec.Type.Equals("tlkshare", StringComparison.OrdinalIgnoreCase))
                            shares.Add(rec);
                        else
                            syncKeys.Add(rec);
                    }
                }
            }

            // Fallback: l'intero blob viewkeys può essere un CuttlefishRecord wrap.
            foreach (var rec in TryRecordsFromCuttlefishWrap(viewkeys))
            {
                if (rec.Type.Equals("tlkshare", StringComparison.OrdinalIgnoreCase))
                    shares.Add(rec);
                else if (rec.Type.Equals("synckey", StringComparison.OrdinalIgnoreCase))
                    syncKeys.Add(rec);
            }
        }

        // Ultima rete: deep-scan del gruppo intero (schema sconosciuto).
        if (shares.Count == 0 && syncKeys.Count == 0)
            CollectCkksRecordsDeep(grp, shares, syncKeys);
    }

    private static bool LooksLikeUtf8Name(byte[] payload)
    {
        if (payload.Length is 0 or > 128)
            return false;
        try
        {
            var s = Encoding.UTF8.GetString(payload);
            return s.All(c => c is >= ' ' and < '\x7f' or >= '\u00a0');
        }
        catch
        {
            return false;
        }
    }

    private static IEnumerable<CkksRecord> TryRecordsFromCuttlefishWrap(byte[] wrap)
    {
        // CuttlefishRecord: CloudKit Record tipicamente in field 1 o 3.
        var candidates = new List<byte[]> { wrap };
        try
        {
            var r = new ProtobufReader(wrap);
            while (r.HasMore)
            {
                var (field, wire) = r.ReadTag();
                if (wire != 2)
                {
                    r.SkipField(wire);
                    continue;
                }

                var payload = r.ReadLengthDelimited();
                if (field is 1 or 2 or 3)
                    candidates.Add(payload);
            }
        }
        catch
        {
            // use wrap only
        }

        foreach (var c in candidates)
        {
            CkksRecord rec;
            try
            {
                rec = CkksZoneParser.ParseRecordBytes(c);
            }
            catch
            {
                continue;
            }

            if (!string.IsNullOrEmpty(rec.Type))
                yield return rec;
        }
    }

    private static void CollectCkksRecordsDeep(
        byte[] data, List<CkksRecord> shares, List<CkksRecord> syncKeys)
    {
        void Visit(byte[] blob, int depth)
        {
            if (depth > 8 || blob.Length < 8)
                return;
            try
            {
                var rec = CkksZoneParser.ParseRecordBytes(blob);
                if (rec.Type.Equals("tlkshare", StringComparison.OrdinalIgnoreCase))
                {
                    shares.Add(rec);
                    return;
                }

                if (rec.Type.Equals("synckey", StringComparison.OrdinalIgnoreCase))
                {
                    syncKeys.Add(rec);
                    return;
                }
            }
            catch
            {
                // not a record
            }

            try
            {
                var r = new ProtobufReader(blob);
                while (r.HasMore)
                {
                    var (field, wire) = r.ReadTag();
                    if (wire != 2)
                    {
                        r.SkipField(wire);
                        continue;
                    }

                    Visit(r.ReadLengthDelimited(), depth + 1);
                }
            }
            catch
            {
                // stop
            }
        }

        Visit(data, 0);
    }

    private static string? GuessZoneFromShare(CkksRecord rec)
    {
        // Alcuni share hanno view/zone come stringa; altrimenti dal record name.
        foreach (var key in new[] { "view", "zone", "zonename", "ckzone" })
        {
            var v = rec.FieldString(key);
            if (!string.IsNullOrWhiteSpace(v))
                return v;
        }

        if (!string.IsNullOrWhiteSpace(rec.Name) && rec.Name.Contains(':'))
        {
            // es. "Passwords:tlkshare:…"
            var head = rec.Name.Split(':')[0];
            if (head.Length is > 0 and < 64)
                return head;
        }

        return null;
    }

    private static string SanitizeFile(string name)
    {
        var chars = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(Array.IndexOf(chars, c) >= 0 ? '_' : c);
        return sb.ToString();
    }

    /// <summary>
    /// Lab: invoca una funzione Cuttlefish arbitraria (authz probe).
    /// Esegue ckAppInit se mancano token CK.
    /// </summary>
    public async Task<(bool Ok, int HttpHint, byte[] Body, string Message)> ProbeInvokeAsync(
        ICloudSession session,
        string functionName,
        byte[]? parameters = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        try
        {
            // Sempre ckAppInit fresco: fetchChanges/join spesso 401 su token stantii.
            log?.Report($"  probe ckAppInit → {ContainerId}…");
            await _orchestrator.CkAppInitAsync(session, ContainerId, log, ct)
                .ConfigureAwait(false);

            var dbUrl = ResolveDatabaseUrl(session);
            if (string.IsNullOrWhiteSpace(dbUrl))
                return (false, 0, [], "CloudKit database URL assente.");

            var codeBase = dbUrl.Replace("-ckdatabase.", "-ckcoderouter.", StringComparison.Ordinal);
            log?.Report($"  probe invoke {functionName}…");
            var (http, wire, decoded, decodeErr) = await InvokeRawAsync(
                    session, codeBase, functionName, parameters ?? [], log, ct)
                .ConfigureAwait(false);
            if (http is < 200 or >= 300)
            {
                var snip = Encoding.UTF8.GetString(wire.AsSpan(0, Math.Min(wire.Length, 200)));
                return (false, http, wire, $"HTTP {http}: {snip}");
            }

            if (decoded is { Length: > 0 })
                return (true, http, decoded, $"OK {decoded.Length} B");

            // HTTP 200 ma senza functionInvokeResponse 1101 = tipicamente errore CK/reject,
            // non join accettata. Conserva wire per triage.
            return (false, http, wire,
                string.IsNullOrWhiteSpace(decodeErr)
                    ? $"decode-empty ({wire.Length} B wire)"
                    : $"{decodeErr} (wire {wire.Length} B)");
        }
        catch (Exception ex)
        {
            var http = 0;
            var msg = ex.Message;
            var m = System.Text.RegularExpressions.Regex.Match(msg, @"HTTP (\d+)");
            if (m.Success)
                int.TryParse(m.Groups[1].Value, out http);
            return (false, http, [], msg);
        }
    }

    private async Task<byte[]> InvokeAsync(
        ICloudSession session,
        string codeBase,
        string functionName,
        byte[] serializedParameters,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var (http, wire, decoded, decodeErr) = await InvokeRawAsync(
            session, codeBase, functionName, serializedParameters, log, ct);
        if (http is < 200 or >= 300)
        {
            var snip = Encoding.UTF8.GetString(wire.AsSpan(0, Math.Min(wire.Length, 200)));
            throw new InvalidOperationException(
                $"code/invoke {functionName} HTTP {http}: {snip}");
        }

        if (decoded is { Length: > 0 })
            return decoded;

        throw new InvalidDataException(
            string.IsNullOrWhiteSpace(decodeErr)
                ? "code/invoke: missing functionInvokeResponse 1101"
                : decodeErr);
    }

    /// <summary>
    /// Come <see cref="InvokeAsync"/> ma non butta il body se il decode 1101 fallisce
    /// (serve ai probe join/establish).
    /// </summary>
    private async Task<(int Http, byte[] Wire, byte[]? Decoded, string? DecodeError)> InvokeRawAsync(
        ICloudSession session,
        string codeBase,
        string functionName,
        byte[] serializedParameters,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var header = BuildCodeInvokeHeader(session);
        var opUuid = Guid.NewGuid().ToString("D").ToUpperInvariant();
        var reqOp = EncodeCodeInvokeRequest(
            ServiceName, functionName, opUuid, serializedParameters, header);
        var body = FrameCodeInvoke(reqOp);

        var url = $"{codeBase.TrimEnd('/')}/api/client/code/invoke";
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-protobuf");

        ApplyCloudKitHeaders(request, session, functionName);
        session.Anisette.TouchClientTimeUtc();
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: false);

        log?.Report($"  POST code/invoke ({body.Length} B)…");
        using var response = await _http.SendAsync(request, ct);
        var raw = await response.Content.ReadAsByteArrayAsync(ct);
        var http = (int)response.StatusCode;
        log?.Report($"    → HTTP {http}, {raw.Length:N0} B");
        if (http is < 200 or >= 300)
            return (http, raw, null, null);

        try
        {
            var framed = UnframeCodeInvoke(raw);
            var decoded = DecodeCodeInvokeResponse(framed);
            return (http, raw, decoded, null);
        }
        catch (Exception ex)
        {
            return (http, raw, null, ex.Message);
        }
    }
    private static void ApplyCloudKitHeaders(
        HttpRequestMessage request,
        ICloudSession session,
        string? functionName = null)
    {
        var mme = session.MobileMeAuthToken
                  ?? throw new InvalidOperationException("mmeAuthToken assente.");
        var ckTok = session.CloudKitAuthToken
                    ?? throw new InvalidOperationException("CloudKitAuthToken assente.");

        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation(
            "Authorization",
            "Basic " + AppleHttpExtensions.BasicAuth(session.Dsid, mme));
        request.Headers.TryAddWithoutValidation("X-CloudKit-AuthToken", ckTok);
        request.Headers.TryAddWithoutValidation("X-CloudKit-DSID", session.Dsid);
        request.Headers.TryAddWithoutValidation("X-CloudKit-ContainerId", ContainerId);
        request.Headers.TryAddWithoutValidation("X-CloudKit-BundleId", BundleId);
        request.Headers.TryAddWithoutValidation("X-CloudKit-Environment", "production");
        request.Headers.TryAddWithoutValidation("X-CloudKit-DatabaseScope", "Private");
        request.Headers.TryAddWithoutValidation(
            "X-Apple-Request-UUID", Guid.NewGuid().ToString("D"));
        // Sank6 / rustpush: obbligatorio su alcuni op (fetchChanges, joinWithVoucher).
        if (!string.IsNullOrWhiteSpace(functionName))
        {
            request.Headers.TryAddWithoutValidation(
                "X-CloudKit-FunctionRoutingHint",
                $"{ServiceName}/{functionName}");
        }

        if (!string.IsNullOrWhiteSpace(session.CloudKitUserId))
            request.Headers.TryAddWithoutValidation("X-CloudKit-UserId", session.CloudKitUserId);
    }

    private static string? ResolveDatabaseUrl(ICloudSession session)
    {
        if (!string.IsNullOrWhiteSpace(session.CloudKitGatewayUrl))
            return session.CloudKitGatewayUrl.Trim().TrimEnd('/');
        if (!string.IsNullOrWhiteSpace(session.Partition))
            return $"https://{session.Partition}-ckdatabase.icloud.com";
        return null;
    }

    private static byte[] BuildCodeInvokeHeader(ICloudSession session)
    {
        var w = new ProtobufWriter();
        void Str(int f, string? v)
        {
            if (!string.IsNullOrWhiteSpace(v))
                w.WriteString(f, v);
        }

        var deviceId = Convert.ToHexString(
            SHA256.HashData(Encoding.UTF8.GetBytes(
                (session.Anisette.MmeDeviceId ?? "") + (session.Dsid ?? "")))).ToLowerInvariant();

        Str(2, ContainerId);
        Str(3, BundleId);
        Str(4, "15.8.0.127");
        Str(8, "Windows; 10.0.26200.8875; Win11 Professional; x64");
        Str(9, "PC");
        Str(10, "CloudKitWin");
        Str(11, "168.1.0.0");
        w.WriteVarint(16, 1);
        Str(18, "5.0");
        w.WriteVarint(19, 1);
        Str(21, Environment.MachineName);
        Str(22, deviceId);
        w.WriteVarint(23, 1);
        w.WriteVarint(25, 2);
        Str(26, "EphemeralGroup");

        var kv = new ProtobufWriter();
        void AddKv(string key, string? val)
        {
            if (string.IsNullOrWhiteSpace(val))
                return;
            var e = new ProtobufWriter();
            e.WriteString(1, key);
            e.WriteString(2, val);
            kv.WriteBytes(1, e.ToArray());
        }

        AddKv("x-mme-client-info", AkdHttpHeaders.ResolveAkdClientInfo(session.Anisette));
        kv.WriteVarint(2, 0);
        w.WriteBytes(30, kv.ToArray());
        return w.ToArray();
    }

    private static byte[] EncodeCodeInvokeRequest(
        string serviceName,
        string functionName,
        string operationUuid,
        byte[] serializedParameters,
        byte[] header)
    {
        var op = new ProtobufWriter();
        op.WriteString(1, operationUuid);
        op.WriteVarint(2, FunctionInvokeType);

        var fi = new ProtobufWriter();
        fi.WriteString(1, serviceName);
        fi.WriteString(2, functionName);
        fi.WriteBytes(3, serializedParameters);

        var req = new ProtobufWriter();
        if (header.Length > 0)
            req.WriteBytes(1, header);
        req.WriteBytes(2, op.ToArray());
        req.WriteBytes(FunctionInvokeType, fi.ToArray());
        return req.ToArray();
    }

    private static byte[] FrameCodeInvoke(byte[] message)
    {
        var len = EncodeUvarint((ulong)message.Length);
        var framed = new byte[len.Length + message.Length];
        Buffer.BlockCopy(len, 0, framed, 0, len.Length);
        Buffer.BlockCopy(message, 0, framed, len.Length, message.Length);
        return framed;
    }

    private static byte[] UnframeCodeInvoke(byte[] body)
    {
        var (n, off) = ConsumeUvarint(body);
        var rest = body.AsSpan(off);
        if ((ulong)rest.Length != n)
            throw new InvalidDataException(
                $"code/invoke framing: prefix {n} != body {rest.Length}");
        return rest.ToArray();
    }

    private static byte[] DecodeCodeInvokeResponse(byte[] responseOperation)
    {
        byte[]? fiBytes = null;
        var reader = new ProtobufReader(responseOperation);
        while (reader.HasMore)
        {
            var (field, wire) = reader.ReadTag();
            if (wire != 2)
            {
                reader.SkipField(wire);
                continue;
            }

            var payload = reader.ReadLengthDelimited();
            if (field == FunctionInvokeType)
                fiBytes = payload;
        }

        if (fiBytes is null)
            throw new InvalidDataException("code/invoke: missing functionInvokeResponse 1101");

        var inner = new ProtobufReader(fiBytes);
        while (inner.HasMore)
        {
            var (field, wire) = inner.ReadTag();
            if (wire != 2)
            {
                inner.SkipField(wire);
                continue;
            }

            var payload = inner.ReadLengthDelimited();
            if (field == 1)
                return payload;
        }

        throw new InvalidDataException("code/invoke: missing serializedResult field 1");
    }

    private static (List<OctagonViableBottle> Viable, List<OctagonViableBottle> Partial)
        ParseViableBottles(byte[] data)
    {
        var viable = new List<OctagonViableBottle>();
        var partial = new List<OctagonViableBottle>();
        var reader = new ProtobufReader(data);
        while (reader.HasMore)
        {
            var (field, wire) = reader.ReadTag();
            if (wire != 2)
            {
                reader.SkipField(wire);
                continue;
            }

            var blob = reader.ReadLengthDelimited();
            var bottle = ExtractBottle(blob);
            if (field == 1)
                viable.Add(bottle);
            else if (field == 2)
                partial.Add(bottle);
        }

        return (viable, partial);
    }

    private static OctagonViableBottle ExtractBottle(byte[] blob)
    {
        string? label = null;
        byte[]? inner = null;
        var hasBottleId = false;
        var r = new ProtobufReader(blob);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                if (field == 7 && wire == 0)
                {
                    r.ReadVarint();
                    hasBottleId = true;
                }
                else
                {
                    r.SkipField(wire);
                }

                continue;
            }

            var payload = r.ReadLengthDelimited();
            switch (field)
            {
                case 1:
                    label = Encoding.UTF8.GetString(payload);
                    break;
                case 2:
                    inner = payload;
                    break;
                case 7:
                    hasBottleId = true;
                    break;
            }
        }

        if (hasBottleId || inner is null)
        {
            var direct = UnmarshalBottle(blob);
            return direct with { EscrowRecordLabel = label ?? direct.EscrowRecordLabel };
        }

        var nested = UnmarshalBottle(inner);
        var device = ParseDevice(blob);
        return nested with
        {
            EscrowRecordLabel = label ?? "",
            Serial = device.Serial,
            Model = device.Model
        };
    }

    private static OctagonViableBottle UnmarshalBottle(byte[] data)
    {
        byte[] contents = [];
        var peerId = "";
        var bottleId = "";
        var r = new ProtobufReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            switch (field)
            {
                case 2:
                    contents = payload;
                    break;
                case 6:
                    peerId = Encoding.UTF8.GetString(payload);
                    break;
                case 7:
                    bottleId = Encoding.UTF8.GetString(payload);
                    break;
            }
        }

        return new OctagonViableBottle(peerId, bottleId, "", "", "", contents);
    }

    private static (string Serial, string Model) ParseDevice(byte[] wrapper)
    {
        var meta = SubField(SubField(wrapper, 4), 3);
        if (meta is null)
            return ("", "");
        var serial = Encoding.UTF8.GetString(SubField(meta, 8) ?? []);
        var client = SubField(meta, 2);
        var model = client is null
            ? ""
            : Encoding.UTF8.GetString(SubField(client, 8) ?? []);
        return (serial, model);
    }

    private static byte[]? SubField(byte[]? data, int num)
    {
        if (data is null)
            return null;
        var r = new ProtobufReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field == num)
                return payload;
        }

        return null;
    }

    private static byte[] EncodeUvarint(ulong v)
    {
        var ms = new MemoryStream();
        while (v >= 0x80)
        {
            ms.WriteByte((byte)(v | 0x80));
            v >>= 7;
        }

        ms.WriteByte((byte)v);
        return ms.ToArray();
    }

    private static (ulong Value, int Offset) ConsumeUvarint(byte[] b)
    {
        ulong v = 0;
        var shift = 0;
        for (var i = 0; i < b.Length; i++)
        {
            if (shift >= 64)
                throw new InvalidDataException("varint overflow");
            var c = b[i];
            v |= (ulong)(c & 0x7f) << shift;
            if ((c & 0x80) == 0)
                return (v, i + 1);
            shift += 7;
        }

        throw new InvalidDataException("truncated varint");
    }

    /// <summary>
    /// Ordine: label Escrow esatta → serial device → resto con Contents.
    /// </summary>
    private static List<OctagonViableBottle> OrderBottlesForDecrypt(
        IReadOnlyList<OctagonViableBottle> withContents,
        string preferLabel,
        string preferSerial)
    {
        int Rank(OctagonViableBottle b)
        {
            if (!string.IsNullOrWhiteSpace(preferLabel)
                && string.Equals(b.EscrowRecordLabel, preferLabel, StringComparison.Ordinal))
                return 0;
            if (!string.IsNullOrWhiteSpace(preferSerial)
                && string.Equals(b.Serial, preferSerial, StringComparison.OrdinalIgnoreCase))
                return 1;
            return 2;
        }

        return withContents
            .OrderBy(Rank)
            .ThenByDescending(b => b.Contents.Length)
            .ToList();
    }

    private static string TrimId(string? s) =>
        string.IsNullOrWhiteSpace(s) ? "?" : (s.Length > 12 ? s[..12] + "…" : s);

    private static string TrimLabel(string? s) =>
        string.IsNullOrWhiteSpace(s) ? "?" : (s.Length > 40 ? s[..40] + "…" : s);
}
