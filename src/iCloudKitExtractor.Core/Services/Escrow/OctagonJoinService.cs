using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Join di un **nuovo** peer nel circle Octagon via sponsor voucher +
/// Cuttlefish <c>joinWithVoucher</c>. Non fa OpenVault / password export.
/// </summary>
public sealed class OctagonJoinService
{
    private readonly OctagonCuttlefishService _cuttlefish;

    public OctagonJoinService(HttpClient http, ICloudBackupOrchestrator orchestrator)
        => _cuttlefish = new OctagonCuttlefishService(http, orchestrator);

    public OctagonJoinService(OctagonCuttlefishService cuttlefish)
        => _cuttlefish = cuttlefish;

    public sealed record JoinResult(
        bool Success,
        string Message,
        string? NewPeerId = null,
        string? BottleId = null,
        string? OutputDirectory = null,
        int HttpHint = 0);

    public sealed record JoinOptions(
        string MachineId,
        string ModelId = "MacBookPro18,1",
        string SerialNumber = "IKEJOIN000000",
        string DeviceName = "IKE OctagonJoin",
        string OsVersion = "macOS 15.0 (24A335)",
        bool IncludeSponsorInDynamic = true,
        bool SkipBottle = false);

    public async Task<JoinResult> JoinNewDeviceAsync(
        ICloudSession session,
        string outputDirectory,
        JoinOptions options,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);

        if (session.OctagonPeerSigningPkcs8 is not { Length: > 0 }
            || string.IsNullOrWhiteSpace(session.OctagonPeerId))
        {
            return new JoinResult(
                false,
                "Sponsor peer missing — load octagon_peer_signing.pkcs8 + peerId "
                + "(OTBottle / Peer unlock in IKE first).");
        }

        if (string.IsNullOrWhiteSpace(session.Adsid))
            return new JoinResult(false, "Session Adsid/altDSID missing (needed for bottle HKDF).");

        var sponsorId = session.OctagonPeerId!;
        log?.Report($"OctagonJoin: sponsor={TrimId(sponsorId)}");

        // fetchChanges → restorePoint + included peers (best-effort).
        string? restorePoint = null;
        var included = new List<string> { sponsorId };
        try
        {
            log?.Report("  fetchChanges (trust graph)…");
            var fcReq = new ProtobufWriter();
            // empty syncToken = full
            var (fcOk, _, fcBody, fcMsg) = await _cuttlefish
                .ProbeInvokeAsync(session, "fetchChanges", fcReq.ToArray(), log, ct)
                .ConfigureAwait(false);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "join_fetchChanges.bin"),
                fcBody, ct).ConfigureAwait(false);
            log?.Report($"  fetchChanges: {(fcOk ? "OK" : "warn")} {fcMsg}");
            if (fcOk && fcBody.Length > 0)
                TryParseFetchChanges(fcBody, out restorePoint, included);
        }
        catch (Exception ex)
        {
            log?.Report($"  fetchChanges skip: {ex.Message}");
        }

        if (options.IncludeSponsorInDynamic
            && !included.Contains(sponsorId, StringComparer.Ordinal))
            included.Add(sponsorId);

        log?.Report(
            $"  generate new peer (model={options.ModelId}, included={included.Count})…");
        var peer = OctagonPeerIdentity.Create(
            options.MachineId,
            options.ModelId,
            options.SerialNumber,
            options.DeviceName,
            options.OsVersion,
            included);

        var voucher = OctagonPeerIdentity.CreateVoucher(
            session.OctagonPeerSigningPkcs8!,
            sponsorId,
            peer.PeerId);
        log?.Report($"  new peer={TrimId(peer.PeerId)}");
        log?.Report("  voucher signed by sponsor");

        OctagonJoinBottleFactory.BuiltBottle? bottle = null;
        if (!options.SkipBottle)
        {
            bottle = OctagonJoinBottleFactory.Build(peer, session.Adsid!);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "join_bottle_entropy.bin"),
                bottle.Entropy, ct).ConfigureAwait(false);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "join_bottle.message.bin"),
                bottle.BottleMessage, ct).ConfigureAwait(false);
            log?.Report($"  bottle={bottle.BottleId} (entropy saved; escrow enroll NOT done)");
        }

        var peerMsg = OctagonPeerIdentity.EncodeCuttlefishPeer(peer, voucher);
        var joinReq = new ProtobufWriter();
        if (!string.IsNullOrEmpty(restorePoint))
            joinReq.WriteString(1, restorePoint);
        joinReq.WriteBytes(2, peerMsg);
        if (bottle is not null)
            joinReq.WriteBytes(3, bottle.BottleMessage);
        // shares=4 / keys=5 left empty — post-join fetchRecoverableTLKShares(forPeer=new)

        var reqBytes = joinReq.ToArray();
        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "joinWithVoucher.request.bin"),
            reqBytes, ct).ConfigureAwait(false);

        log?.Report($"  joinWithVoucher ({reqBytes.Length} B)…");
        var (ok, http, body, message) = await _cuttlefish
            .ProbeInvokeAsync(session, "joinWithVoucher", reqBytes, log, ct)
            .ConfigureAwait(false);

        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "joinWithVoucher.response.bin"),
            body, ct).ConfigureAwait(false);

        var encPath = Path.Combine(outputDirectory, "joined_peer_encryption.pkcs8");
        var sigPath = Path.Combine(outputDirectory, "joined_peer_signing.pkcs8");
        await File.WriteAllBytesAsync(encPath, peer.EncryptionPkcs8, ct).ConfigureAwait(false);
        await File.WriteAllBytesAsync(sigPath, peer.SigningPkcs8, ct).ConfigureAwait(false);

        var meta = new
        {
            success = ok,
            http,
            message,
            sponsorPeerId = sponsorId,
            newPeerId = peer.PeerId,
            bottleId = bottle?.BottleId,
            restorePoint,
            includedPeers = included,
            skipBottle = options.SkipBottle,
            machineId = options.MachineId,
            modelId = options.ModelId,
            serialNumber = options.SerialNumber,
            peerEncryptionPkcs8 = Path.GetFileName(encPath),
            peerSigningPkcs8 = Path.GetFileName(sigPath),
            note =
                "Join mutates Octagon trust. Escrow ENROLL of the new bottle is NOT performed — "
                + "peer is for vault access with joined keys; PIN-recover of this peer needs enroll.",
            refImpl = "OpenBubbles/rustpush join_clique_from_escrow / joinWithVoucher"
        };
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "octagon_join_meta.json"),
            JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }),
            ct).ConfigureAwait(false);

        if (ok)
        {
            session.OctagonPeerId = peer.PeerId;
            session.OctagonPeerEncryptionPkcs8 = peer.EncryptionPkcs8;
            session.OctagonPeerSigningPkcs8 = peer.SigningPkcs8;
            session.OctagonKeysDirectory = outputDirectory;
        }

        return new JoinResult(
            ok,
            ok
                ? $"OK — joined peer {TrimId(peer.PeerId)} (HTTP {http}). Keys → {outputDirectory}"
                : $"joinWithVoucher failed: {message}",
            peer.PeerId,
            bottle?.BottleId,
            outputDirectory,
            http);
    }

    private static void TryParseFetchChanges(
        byte[] body,
        out string? syncToken,
        List<string> includedAccum)
    {
        syncToken = null;
        // Response: FetchChangesResponse { changes = 1 { syncToken=1, changes=2 { add=3 peer } } }
        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (field, wire) = r.ReadTag();
                if (wire != 2)
                {
                    r.SkipField(wire);
                    continue;
                }

                var payload = r.ReadLengthDelimited();
                if (field == 1)
                    WalkChanges(payload, ref syncToken, includedAccum);
            }
        }
        catch
        {
            // best-effort
        }
    }

    private static void WalkChanges(
        byte[] changesMsg,
        ref string? syncToken,
        List<string> includedAccum)
    {
        var r = new ProtobufReader(changesMsg);
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
                    syncToken = Encoding.UTF8.GetString(payload);
                    break;
                case 2:
                    // CuttlefishChange { add = 3 }
                    var cr = new ProtobufReader(payload);
                    while (cr.HasMore)
                    {
                        var (cf, cw) = cr.ReadTag();
                        if (cw != 2)
                        {
                            cr.SkipField(cw);
                            continue;
                        }

                        var cp = cr.ReadLengthDelimited();
                        if (cf == 3)
                            TryAddPeerHash(cp, includedAccum);
                    }

                    break;
            }
        }
    }

    private static void TryAddPeerHash(byte[] peerMsg, List<string> includedAccum)
    {
        var r = new ProtobufReader(peerMsg);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field == 1)
            {
                var id = Encoding.UTF8.GetString(payload);
                if (!string.IsNullOrWhiteSpace(id)
                    && !includedAccum.Contains(id, StringComparer.Ordinal))
                    includedAccum.Add(id);
            }
        }
    }

    private static string TrimId(string id) =>
        id.Length <= 28 ? id : id[..12] + "…" + id[^8..];
}
