using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace iCloudKitExtractor.Services.Escrow;

public sealed record OctagonBottleRecoveryResult(
    bool Success,
    string Message,
    string? Label = null,
    string? BottleId = null,
    byte[]? BottledPeerEntropy = null,
    string? EntropyPath = null,
    string? BottlePlistPath = null,
    int? Pbkdf2Rounds = null);

public sealed record OctagonBottleListItem(
    string Label,
    string Display,
    string? Serial,
    string? Build,
    string? BottleId,
    string? Timestamp,
    int? RemainingAttempts,
    string? RecordStatus);

/// <summary>
/// Unlock bottle iCDP/Octagon via escrowproxy:
/// <c>get_records</c> → <c>SRP_INIT</c>/<c>RECOVER</c> con label <c>com.apple.icdp.record.*</c>
/// e passcode dispositivo → EscrowBottle plist → <c>BottledPeerEntropy</c> (72 B).
/// IRREVERSIBILE: max ~10 tentativi per record (HSM).
/// </summary>
public sealed class OctagonBottleRecoveryService
{
    public const string EntropyFileName = "octagon_bottled_peer_entropy.bin";
    public const string BottlePlistFileName = "octagon_escrow_bottle.plist";
    public const string MetaFileName = "octagon_bottle_unlock_meta.json";

    private readonly EscrowProxyClient _client;

    public OctagonBottleRecoveryService(HttpClient http) =>
        _client = new EscrowProxyClient(http);

    public OctagonBottleRecoveryService(EscrowProxyClient client) =>
        _client = client;

    public static bool IsIcdpLabel(string? label) =>
        !string.IsNullOrWhiteSpace(label)
        && label.StartsWith("com.apple.icdp.record.", StringComparison.Ordinal);

    public static IReadOnlyList<OctagonBottleListItem> ListIcdpBottles(byte[] getRecordsBody)
    {
        var bottles = EscrowBottlesParser.Parse(getRecordsBody);
        return bottles
            .Where(b => IsIcdpLabel(b.Label))
            .OrderByDescending(b => b.Timestamp ?? "")
            .Select(b => new OctagonBottleListItem(
                b.Label,
                FormatDisplay(b),
                b.Serial,
                b.Build,
                b.BottleId,
                b.Timestamp,
                b.RemainingAttempts,
                b.RecordStatus))
            .ToList();
    }

    public async Task<(IReadOnlyList<OctagonBottleListItem> Bottles, string? Error)> ListBottlesLiveAsync(
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        log?.Report("Octagon: get_records (lista bottle iCDP, non distruttivo)…");
        var records = await _client.GetRecordsAsync(session, log, ct);
        await EscrowProxyClient.SaveProbeArtifactsAsync(outputDirectory, records, ct);
        try
        {
            await EscrowBottlesParser.SaveBottlesJsonAsync(outputDirectory, records.RawBody, ct);
        }
        catch (Exception ex)
        {
            log?.Report($"  parse bottles: {ex.Message}");
        }

        if (!EscrowProxyClient.IsEscrowSuccess(records))
        {
            var err = AppleXmlPlist.GetString(records.Parsed!, "message")
                      ?? $"HTTP {records.HttpStatus}";
            return ([], $"get_records fallito: {err}");
        }

        var list = ListIcdpBottles(records.RawBody);
        log?.Report($"  iCDP bottles: {list.Count}");
        foreach (var b in list.Take(12))
            log?.Report($"    · {b.Display}");
        return (list, null);
    }

    /// <summary>
    /// Recover irreversibile: passcode dispositivo (o iCSC) della bottle scelta.
    /// </summary>
    public async Task<OctagonBottleRecoveryResult> RecoverBottleAsync(
        ICloudSession session,
        string bottleLabel,
        string devicePasscode,
        string outputDirectory,
        bool confirmIrreversible,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (!confirmIrreversible)
        {
            return new OctagonBottleRecoveryResult(
                false,
                "REFUSED: recover iCDP consuma 1 tentativo irreversibile (max ~10). "
                + "Conferma esplicitamente prima di procedere.");
        }

        if (string.IsNullOrWhiteSpace(session.Dsid))
            return new OctagonBottleRecoveryResult(false, "Sessione senza dsid.");
        if (!IsIcdpLabel(bottleLabel))
            return new OctagonBottleRecoveryResult(false, "Label non iCDP: " + bottleLabel);
        if (string.IsNullOrWhiteSpace(devicePasscode))
            return new OctagonBottleRecoveryResult(false, "Serve il passcode del dispositivo della bottle.");

        Directory.CreateDirectory(outputDirectory);
        var passcode = EscrowSrpClient.NormalizeIcsc(devicePasscode);
        var label = bottleLabel.Trim();

        log?.Report($"Octagon Unlock → label={label}");
        log?.Report("  ATTENZIONE: recover fallito consuma 1 tentativo HSM (limite ~10).");
        // iCDP ≠ PCS: SRP P = passcode device (dsid:passcode). PCS usa dsid:dsid.
        // Passcode serve anche al PBKDF2 post-recover → EscrowBottle.
        // -6015 "Credential is not verified" = M1 sbagliato (secret SRP errato).
        log?.Report(
            $"  SRP iCDP (appleservices): x=H(salt‖H(dsid:passcode)) K=H(PAD(S))  dsid={session.Dsid}");
        log?.Report("  passcode → SRP M1 + layer-2 PBKDF2 bottle");
        // Auth HTTP: Basic(email, PET) + userActionLabel/transactionUUID (rustpush/Sank6).
        var pet = EscrowProxyClient.ResolveRawPetToken(session);
        if (string.IsNullOrWhiteSpace(session.AppleId) || string.IsNullOrWhiteSpace(pet))
        {
            return new OctagonBottleRecoveryResult(
                false,
                "PET/AppleId assenti — rifai login GSA (serve com.apple.gs.idms.pet per iCDP).",
                label);
        }

        log?.Report($"  auth iCDP: Basic email+PET (petLen={pet.Length}) + sbd action fields");

        var srp = new EscrowSrpClient(session.Dsid);
        var publicA = srp.PublicA;
        log?.Report($"  srp_init (A padded={publicA.Length} B)…");

        var init = await _client.SrpInitAsync(
            session,
            publicA,
            label,
            log: log,
            ct: ct,
            auth: EscrowProxyClient.AuthStyle.PetBasic,
            includeSbdActionFields: true);
        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "octagon_srp_init_request.xml"),
            init.RequestBody ?? [], ct);
        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "octagon_srp_init_response.xml"),
            init.RawBody, ct);

        if (!EscrowProxyClient.IsEscrowSuccess(init))
        {
            var err = AppleXmlPlist.GetString(init.Parsed!, "message") ?? $"HTTP {init.HttpStatus}";
            var hint = init.HttpStatus == 401
                ? " — auth iCDP (Basic email+PET). Rifai login GSA se PET scaduto."
                : "";
            return new OctagonBottleRecoveryResult(false, $"srp_init fallito: {err}{hint}", label);
        }

        var respBlob = AppleXmlPlist.GetEscrowRespBlob(init.Parsed!);
        if (respBlob is not { Length: > 0 })
            return new OctagonBottleRecoveryResult(false, "srp_init senza respBlob", label);

        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "octagon_srp_init_respBlob.bin"), respBlob, ct);

        if (!EscrowSecureBackupBlob.TryParseSrpInitResponse(
                respBlob, out var sessionId, out var recordId, out var salt, out var serverB))
        {
            return new OctagonBottleRecoveryResult(
                false, "Impossibile parsare salt/B da srp_init respBlob", label);
        }

        var correlationId = EscrowSecureBackupBlob.FormatRecordId(recordId);
        var srpDsid = AppleXmlPlist.GetString(init.Parsed!, "dsid") ?? session.Dsid;
        var clubTypeId = init.Parsed is null
            ? null
            : AppleXmlPlist.GetInt(init.Parsed, "clubTypeID")
              ?? AppleXmlPlist.GetInt(init.Parsed, "clubTypeId");
        // clubTypeID=1 → AES-GCM sulla *risposta* recover; header recover resta ver=0
        // (come srp_init). Non mettere ver=2 nel request — causa CLUBH -6122.
        log?.Report(
            $"  srp_init OK — record_id={correlationId} ({recordId.Length} B), salt={salt.Length} B, " +
            $"B={serverB.Length} B, clubTypeID={clubTypeId?.ToString() ?? "?"}");

        try
        {
            // appleservices computeEscrowM: I=dsid, P=passcode, K=H(PAD(S)).
            srp.Complete(
                passcode, salt, serverB, identityOverride: srpDsid, padSessionKey: true);
        }
        catch (Exception ex)
        {
            return new OctagonBottleRecoveryResult(false, $"Calcolo SRP fallito: {ex.Message}", label);
        }

        const uint recoverVersion = 0;
        // appleservices buildRecoverBlob: clubID senza pad a 20 (diverso da PCS).
        var recoverBlob = EscrowSecureBackupBlob.BuildRecoverBlob(
            sessionId, recordId, srp.M1, recoverVersion, padRecordIdTo20: false);
        log?.Report(
            $"  recover (blob={recoverBlob.Length} B, hdrVer={recoverVersion}, " +
            "clubID no-pad, K=H(PAD(S)))…");

        var recover = await _client.RecoverAsync(
            session,
            recoverBlob,
            label,
            log: log,
            ct: ct,
            auth: EscrowProxyClient.AuthStyle.PetBasic,
            includeSbdActionFields: true);
        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "octagon_recover_request.xml"),
            recover.RequestBody ?? [], ct);
        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "octagon_recover_response.xml"),
            recover.RawBody, ct);

        if (!EscrowProxyClient.IsEscrowSuccess(recover))
        {
            var err = AppleXmlPlist.GetString(recover.Parsed!, "message")
                      ?? $"HTTP {recover.HttpStatus}";
            var status = AppleXmlPlist.GetString(recover.Parsed!, "status");
            return new OctagonBottleRecoveryResult(
                false,
                $"recover FALLITO: {err}" + (status is null ? "" : $" (status={status})")
                + " — tentativo consumato.",
                label);
        }

        var recoverResp = AppleXmlPlist.GetEscrowRespBlob(recover.Parsed!);
        if (recoverResp is not { Length: > 0 })
            return new OctagonBottleRecoveryResult(false, "recover senza respBlob", label);

        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "octagon_recover_respBlob.bin"), recoverResp, ct);

        // appleservices decodeRecoverPayload: sezioni IV|CT → AES-256-CBC(K=H(PAD(S))).
        string? aesMethod = null;
        byte[]? inner = null;
        if (EscrowSecureBackupBlob.TryUnpack(recoverResp, headerLen: 24, sectionCount: 3,
                out _, out var clubhSecs)
            && clubhSecs.Length >= 3
            && clubhSecs[1].Length >= 16
            && clubhSecs[2].Length >= 16)
        {
            inner = OctagonEscrowSrp.TryDecryptRecoverInner(
                srp.SessionKey, version: 0, clubhSecs[1], clubhSecs[2], out aesMethod);
        }

        if (inner is not { Length: > 0 })
            inner = srp.TryDecryptEscrowPayload(recoverResp, out aesMethod);

        if (inner is not { Length: > 0 }
            && EscrowSecureBackupBlob.TryParseRecoverResponse(
                recoverResp, out _, out var m2, out var encPayload)
            && encPayload.Length > 32)
        {
            if (m2.Length > 0 && srp.VerifyServerM2(m2))
                log?.Report("  M2 OK");
            inner = srp.TryDecryptEscrowPayload(encPayload, out aesMethod);
        }

        if (inner is not { Length: > 0 }
            && EscrowSecureBackupBlob.TryUnpack(recoverResp, headerLen: 40, sectionCount: 3,
                out var hdr40, out var payloads40)
            && payloads40.Length >= 3)
        {
            var wireVersion = BinaryPrimitives.ReadUInt32BigEndian(hdr40.AsSpan(4, 4));
            inner = OctagonEscrowSrp.TryDecryptRecoverInner(
                srp.SessionKey, wireVersion, payloads40[1], payloads40[2], out aesMethod);
        }

        if (inner is not { Length: > 0 })
        {
            return new OctagonBottleRecoveryResult(
                false, "Decrypt AES(K_SRP) fallito sul recover respBlob", label);
        }

        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "octagon_recover_inner.bin"), inner, ct);
        log?.Report($"  AES(K) OK ← {aesMethod} ({inner.Length:N0} B)");

        if (!OctagonEscrowSrp.TryUnwrapEscrowBottlePlist(
                inner, passcode, out var bottlePlist, out var rounds, out var unwrapErr))
        {
            return new OctagonBottleRecoveryResult(
                false,
                $"Unwrap EscrowBottle fallito (passcode device?): {unwrapErr}",
                label);
        }

        var bottlePath = Path.Combine(outputDirectory, BottlePlistFileName);
        await File.WriteAllBytesAsync(bottlePath, bottlePlist, ct);
        log?.Report($"  EscrowBottle plist ← PBKDF2 rounds={rounds} ({bottlePlist.Length:N0} B)");

        if (!TryExtractBottledPeerEntropy(bottlePlist, out var entropy, out var entErr))
        {
            return new OctagonBottleRecoveryResult(
                false, $"BottledPeerEntropy assente: {entErr}", label,
                BottlePlistPath: bottlePath, Pbkdf2Rounds: rounds);
        }

        var entropyPath = Path.Combine(outputDirectory, EntropyFileName);
        await File.WriteAllBytesAsync(entropyPath, entropy, ct);
        log?.Report($"  BottledPeerEntropy → {EntropyFileName} ({entropy.Length} B)");

        if (session.Adsid is { Length: > 0 })
        {
            var sym = OctagonBottleCrypto.DeriveSymmetricKey(entropy, session.Adsid);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "octagon_escrow_symmetric_key.bin"), sym, ct);
            log?.Report($"  HKDF Escrow Symmetric Key (adsid) → 32 B");
        }
        else
        {
            log?.Report("  WARN: Adsid assente — skip derive HKDF (serve per OTBottle AES-GCM).");
        }

        session.OctagonBottledPeerEntropy = entropy;
        session.OctagonBottleLabel = label;
        session.OctagonKeysDirectory = outputDirectory;
        // Serial da get_records (se disponibile) — OTBottle match preferisce stessa device.
        try
        {
            var cached = Path.Combine(outputDirectory, "escrow_get_records_response.bin");
            if (!File.Exists(cached))
                cached = Path.Combine(outputDirectory, "escrow_get_records_response.xml");
            if (File.Exists(cached))
            {
                var bottles = EscrowBottlesParser.Parse(await File.ReadAllBytesAsync(cached, ct));
                var hit = bottles.FirstOrDefault(b =>
                    string.Equals(b.Label, label, StringComparison.Ordinal));
                if (!string.IsNullOrWhiteSpace(hit?.Serial))
                    session.OctagonBottleSerial = hit!.Serial;
            }
        }
        catch
        {
            /* best-effort */
        }

        var meta = JsonSerializer.Serialize(new
        {
            success = true,
            label,
            bottleId = correlationId,
            recordIdHex = Convert.ToHexString(recordId),
            srpDsid,
            clubTypeId,
            recoverHeaderVersion = recoverVersion,
            srpSecret = "dsid:passcode",
            sessionKey = "H(PAD(S))",
            recoverClubIdPadded = false,
            refImpl = "Laky-64/appleservices escrow",
            aesMethod,
            pbkdf2Rounds = rounds,
            entropyBytes = entropy.Length,
            entropyFile = EntropyFileName,
            bottlePlistFile = BottlePlistFileName,
            adsidPresent = !string.IsNullOrWhiteSpace(session.Adsid),
            note =
                "Allineato a appleservices: P=passcode, K=H(PAD(S)), clubID no-pad. " +
                "Poi fetchViableBottles → OTBottle AES-GCM(entropy)."
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(Path.Combine(outputDirectory, MetaFileName), meta, ct);

        return new OctagonBottleRecoveryResult(
            true,
            $"OK — BottledPeerEntropy {entropy.Length} B (rounds={rounds}). " +
            "Prossimo: fetchViableBottles/CKCode per OTBottle.",
            label,
            correlationId,
            entropy,
            entropyPath,
            bottlePath,
            rounds);
    }

    private static bool TryExtractBottledPeerEntropy(
        byte[] bottlePlist, out byte[] entropy, out string? error)
    {
        entropy = [];
        error = null;
        try
        {
            if (!AppleBinaryPlist.TryParseDict(bottlePlist, out var dict, out _)
                || dict is null)
            {
                // xml plist?
                if (LooksLikeXml(bottlePlist))
                {
                    var parsed = AppleXmlPlist.Parse(bottlePlist);
                    return TryEntropyFromDict(parsed, out entropy, out error);
                }

                error = "plist non parsabile";
                return false;
            }

            return TryEntropyFromDict(dict, out entropy, out error);
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryEntropyFromDict(
        Dictionary<string, object?> dict, out byte[] entropy, out string? error)
    {
        entropy = [];
        error = null;
        foreach (var key in new[] { "BottledPeerEntropy", "bottledPeerEntropy", "bottled_peer_entropy" })
        {
            if (!dict.TryGetValue(key, out var v) || v is null)
                continue;
            if (v is byte[] raw && raw.Length is >= 32 and <= 128)
            {
                entropy = raw;
                return true;
            }

            if (v is string s && s.Length > 0)
            {
                try
                {
                    var b = Convert.FromBase64String(s);
                    if (b.Length is >= 32 and <= 128)
                    {
                        entropy = b;
                        return true;
                    }
                }
                catch
                {
                    // next
                }
            }
        }

        error = "chiave BottledPeerEntropy non trovata nel plist";
        return false;
    }

    private static bool LooksLikeXml(byte[] data) =>
        data.Length > 5 && data[0] == (byte)'<' ;

    private static string FormatDisplay(EscrowBottleInfo b)
    {
        var serial = string.IsNullOrWhiteSpace(b.Serial) ? "?" : b.Serial;
        var build = string.IsNullOrWhiteSpace(b.Build) ? "?" : b.Build;
        var ts = string.IsNullOrWhiteSpace(b.Timestamp) ? "?" : b.Timestamp;
        var attempts = b.RemainingAttempts?.ToString() ?? "?";
        var shortLabel = b.Label.Length > 48 ? b.Label[..48] + "…" : b.Label;
        return $"{serial} / {build} / {ts} (tentativi={attempts}) — {shortLabel}";
    }
}

/// <summary>
/// HKDF + OTBottle AES-GCM (appleservices <c>octagon.DecryptBottle</c>).
/// </summary>
public static class OctagonBottleCrypto
{
    private static readonly byte[] InfoSym = "Escrow Symmetric Key"u8.ToArray();
    private const int P384KeyDataLen = 1 + 48 * 3;

    public static byte[] DeriveSymmetricKey(byte[] entropy, string adsid)
    {
        // HKDF-SHA384(salt=adsid, ikm=entropy, info, 32)
        var hashLen = 48; // SHA384
        var prk = HkdfExtract(Encoding.UTF8.GetBytes(adsid), entropy, hashLen);
        return HkdfExpand(prk, InfoSym, 32, hashLen);
    }

    /// <summary>
    /// Ispeziona Contents senza entropy: ciphertext atteso vs plaintext / GCM banale.
    /// Critico solo se peer keys in chiaro o unwrap con entropy triviale.
    /// </summary>
    public static OtBottleOvershareInspect InspectOvershare(
        byte[] bottleContents,
        string? adsid)
    {
        string? peerId = null;
        string? bottleId = null;
        byte[] iv = [];
        byte[] ct = [];
        byte[] tag = [];
        string? parseErr = null;
        var hasAuth = false;
        var clearKeys = false;
        var trivialHits = new List<string>();

        try
        {
            hasAuth = TryParseOtBottle(
                bottleContents, out peerId, out bottleId,
                out iv, out ct, out tag, out parseErr);
            if (!hasAuth)
            {
                // A volte Contents è già AuthenticatedCiphertext (f1/f2/f3) senza wrapper OTBottle.
                hasAuth = TryParseAuthCiphertext(
                    bottleContents, out iv, out ct, out tag, out parseErr);
            }
        }
        catch (Exception ex)
        {
            parseErr = "auth-parse: " + ex.Message;
            hasAuth = false;
        }

        // Non far esplodere il probe: Contents cifrati non sono protobuf BottleContents validi
        // (ProtobufReader può vedere wire type 6/7 su byte casuali).
        try
        {
            clearKeys = TryParseBottleContents(bottleContents, out _, out _, out _);
        }
        catch
        {
            clearKeys = false;
        }

        if (!clearKeys && hasAuth && ct.Length > 0)
        {
            try
            {
                clearKeys = TryParseBottleContents(ct, out _, out _, out _);
            }
            catch
            {
                // ciphertext ≠ contents in chiaro
            }
        }

        if (hasAuth && !string.IsNullOrWhiteSpace(adsid)
            && iv.Length is >= 8 and <= 64
            && tag.Length is >= 12 and <= 16
            && ct.Length > 0)
        {
            foreach (var (name, ikm) in TrivialEntropies())
            {
                try
                {
                    var sym = DeriveSymmetricKey(ikm, adsid!);
                    var plain = AesGcmOpen(sym, iv, ct, tag);
                    if (TryParseBottleContents(plain, out _, out _, out _))
                        trivialHits.Add(name);
                }
                catch
                {
                    // GCM fail atteso
                }
            }
        }

        var pkcs8Prefix = CountOccurrences(
            bottleContents, Convert.FromHexString("308187020100301306072a8648ce3d0201"));
        var critical = clearKeys || trivialHits.Count > 0;

        return new OtBottleOvershareInspect(
            hasAuth,
            peerId,
            bottleId,
            iv.Length,
            ct.Length,
            tag.Length,
            parseErr,
            clearKeys,
            trivialHits,
            pkcs8Prefix,
            critical);
    }
    public readonly record struct OtBottleOvershareInspect(
        bool HasAuthenticatedCiphertext,
        string? PeerId,
        string? BottleId,
        int IvLen,
        int CiphertextLen,
        int TagLen,
        string? ParseError,
        bool ClearPeerKeysWithoutDecrypt,
        IReadOnlyList<string> TrivialGcmHits,
        int Pkcs8P384PrefixHits,
        bool Critical);

    private static IEnumerable<(string Name, byte[] Ikm)> TrivialEntropies()
    {
        yield return ("zeros-72", new byte[72]);
        yield return ("zeros-32", new byte[32]);
        yield return ("ones-72", Enumerable.Repeat((byte)0xFF, 72).ToArray());
        var empty = Array.Empty<byte>();
        yield return ("empty-ikm", empty);
    }

    private static int CountOccurrences(byte[] hay, byte[] needle)
    {
        if (needle.Length == 0 || hay.Length < needle.Length)
            return 0;
        var n = 0;
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
                n++;
        }

        return n;
    }

    private static bool TryParseAuthCiphertext(
        byte[] data,
        out byte[] iv,
        out byte[] ciphertext,
        out byte[] tag,
        out string? error)
    {
        iv = [];
        ciphertext = [];
        tag = [];
        error = null;
        var ar = new ProtobufReader(data);
        while (ar.HasMore)
        {
            var (field, wire) = ar.ReadTag();
            if (wire != 2)
            {
                ar.SkipField(wire);
                continue;
            }

            var payload = ar.ReadLengthDelimited();
            switch (field)
            {
                case 1:
                    ciphertext = payload;
                    break;
                case 2:
                    tag = payload;
                    break;
                case 3:
                    iv = payload;
                    break;
            }
        }

        if (ciphertext.Length == 0 || tag.Length == 0 || iv.Length == 0)
        {
            error = "AuthenticatedCiphertext incompleto";
            return false;
        }

        return true;
    }

    /// <summary>
    /// Decrypt OTBottle Contents → peer signing/encryption PKCS#8 (P-384).
    /// </summary>
    public static bool TryDecryptOtBottle(
        byte[] entropy,
        string adsid,
        byte[] bottleContents,
        out byte[] peerSigningPkcs8,
        out byte[] peerEncryptionPkcs8,
        out string? peerId,
        out string? bottleId,
        out string? error)
    {
        peerSigningPkcs8 = [];
        peerEncryptionPkcs8 = [];
        peerId = null;
        bottleId = null;
        error = null;

        try
        {
            if (!TryParseOtBottle(
                    bottleContents, out peerId, out bottleId,
                    out var iv, out var ciphertext, out var tag, out var parseErr))
            {
                error = parseErr;
                return false;
            }

            // appleservices: NewGCMWithNonceSize(block, len(iv)) — IV può essere 12 o 32 B.
            if (iv.Length is < 8 or > 64 || ciphertext.Length == 0 || tag.Length is < 12 or > 16)
            {
                error = $"auth ciphertext irregolare (iv={iv.Length}, ct={ciphertext.Length}, tag={tag.Length})";
                return false;
            }

            var sym = DeriveSymmetricKey(entropy, adsid);
            var plain = AesGcmOpen(sym, iv, ciphertext, tag);
            if (!TryParseBottleContents(plain, out var sigKeyData, out var encKeyData, out var contentsErr))
            {
                error = contentsErr;
                return false;
            }

            peerSigningPkcs8 = P384KeyDataToPkcs8(sigKeyData);
            peerEncryptionPkcs8 = P384KeyDataToPkcs8(encKeyData);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    private static bool TryParseOtBottle(
        byte[] data,
        out string? peerId,
        out string? bottleId,
        out byte[] iv,
        out byte[] ciphertext,
        out byte[] tag,
        out string? error)
    {
        peerId = null;
        bottleId = null;
        iv = [];
        ciphertext = [];
        tag = [];
        error = null;

        byte[]? authBlob = null;
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
                case 1:
                    peerId = Encoding.UTF8.GetString(payload);
                    break;
                case 2:
                    bottleId = Encoding.UTF8.GetString(payload);
                    break;
                case 12:
                    authBlob = payload;
                    break;
            }
        }

        if (authBlob is null)
        {
            error = "OTBottle senza Contents (field 12)";
            return false;
        }

        var ar = new ProtobufReader(authBlob);
        while (ar.HasMore)
        {
            var (field, wire) = ar.ReadTag();
            if (wire != 2)
            {
                ar.SkipField(wire);
                continue;
            }

            var payload = ar.ReadLengthDelimited();
            switch (field)
            {
                case 1:
                    ciphertext = payload;
                    break;
                case 2:
                    tag = payload;
                    break;
                case 3:
                    iv = payload;
                    break;
            }
        }

        if (ciphertext.Length == 0 || tag.Length == 0 || iv.Length == 0)
        {
            error = "AuthenticatedCiphertext incompleto";
            return false;
        }

        return true;
    }

    private static bool TryParseBottleContents(
        byte[] plain, out byte[] signingKeyData, out byte[] encryptionKeyData, out string? error)
    {
        signingKeyData = [];
        encryptionKeyData = [];
        error = null;
        byte[]? sigPk = null;
        byte[]? encPk = null;
        var r = new ProtobufReader(plain);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field == 3)
                sigPk = OtPrivateKeyData(payload);
            else if (field == 4)
                encPk = OtPrivateKeyData(payload);
        }

        if (sigPk is null || encPk is null)
        {
            error = "bottle contents senza peer signing/encryption keys";
            return false;
        }

        signingKeyData = sigPk;
        encryptionKeyData = encPk;
        return true;
    }

    private static byte[]? OtPrivateKeyData(byte[] otPrivateKey)
    {
        var r = new ProtobufReader(otPrivateKey);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field == 2)
                return payload;
        }

        return null;
    }

    /// <summary>
    /// AES-GCM con nonce arbitrario (Go <c>cipher.NewGCMWithNonceSize</c> /
    /// appleservices OTBottle IV spesso 32 B — .NET <see cref="AesGcm"/> no).
    /// </summary>
    private static byte[] AesGcmOpen(byte[] key, byte[] iv, byte[] ciphertext, byte[] tag)
    {
        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(false, new AeadParameters(new KeyParameter(key), tag.Length * 8, iv));
        var input = new byte[ciphertext.Length + tag.Length];
        Buffer.BlockCopy(ciphertext, 0, input, 0, ciphertext.Length);
        Buffer.BlockCopy(tag, 0, input, ciphertext.Length, tag.Length);
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var len = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        len += cipher.DoFinal(output, len);
        return output[..len];
    }

    private static byte[] P384KeyDataToPkcs8(byte[] keyData)
    {
        if (keyData.Length != P384KeyDataLen || keyData[0] != 0x04)
            throw new CryptographicException($"P-384 keyData len={keyData.Length}");

        var ec = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP384,
            Q = new ECPoint
            {
                X = keyData[1..49],
                Y = keyData[49..97]
            },
            D = keyData[97..145]
        };
        using var ecdsa = ECDsa.Create(ec);
        return ecdsa.ExportPkcs8PrivateKey();
    }

    private static byte[] HkdfExtract(byte[] salt, byte[] ikm, int hashLen)
    {
        if (salt.Length == 0)
            salt = new byte[hashLen];
        return HMACSHA384.HashData(salt, ikm);
    }

    private static byte[] HkdfExpand(byte[] prk, byte[] info, int length, int hashLen)
    {
        var n = (length + hashLen - 1) / hashLen;
        var okm = new byte[n * hashLen];
        var t = Array.Empty<byte>();
        var offset = 0;
        for (var i = 1; i <= n; i++)
        {
            var input = new byte[t.Length + info.Length + 1];
            Buffer.BlockCopy(t, 0, input, 0, t.Length);
            Buffer.BlockCopy(info, 0, input, t.Length, info.Length);
            input[^1] = (byte)i;
            t = HMACSHA384.HashData(prk, input);
            Buffer.BlockCopy(t, 0, okm, offset, t.Length);
            offset += t.Length;
        }

        return okm[..length];
    }
}
