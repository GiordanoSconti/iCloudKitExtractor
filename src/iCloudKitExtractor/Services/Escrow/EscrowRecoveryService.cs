using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

public sealed record EscrowRecoveryResult(
    bool Success,
    string Message,
    string? CorrelationId = null,
    byte[]? RecoverRespBlob = null,
    byte[]? EncryptedKeyBagKey = null,
    string? EncryptedKeyBagKeyPath = null,
    byte[]? DecryptedEscrow = null,
    bool PcsUnwrapPending = true,
    string? KeybagDecryptedPath = null,
    string? KeybagKeyPath = null,
    string? PcsUnwrapMethod = null);

/// <summary>
/// Opzioni variante SMS (secondaria; PCS non le usa).
/// Se <see cref="Enabled"/>: label securebackup + get_sms_targets / generate_sms_challenge
/// + campi SMS su srp_init/recover.
/// </summary>
public sealed record EscrowSmsOptions(
    bool Enabled = false,
    string? SmsChallengeCode = null,
    string? PhoneNumberToken = null,
    bool RequestSmsChallenge = false);

/// <summary>
/// Flusso Escrow (default, no SMS): <c>get_records</c> → <c>srp_init</c> → <c>recover</c>.
/// Label PCS (MME); <c>x = SHA(salt ‖ SHA(dsid ":" secret))</c> (HITCON 2017 p.33);
/// u/k OpenSSL PAD; M1 Belenko (salt/A/B/K grezzi).
/// Variante opzionale SMS: label securebackup + codice SMS.
/// </summary>
public sealed class EscrowRecoveryService
{
    public const string EncryptedKeyBagKeyFileName = "keybag_key_encrypted.bin";
    public const string EncryptedKeyBagKeyWrappedFileName = "escrow_pcs_wrapped.bin";

    private readonly EscrowProxyClient _client;

    public EscrowRecoveryService(HttpClient http) =>
        _client = new EscrowProxyClient(http);

    public EscrowRecoveryService(EscrowProxyClient client) =>
        _client = client;

    /// <summary>
    /// Esegue escrow recover e salva il KeyBagKey cifrato in
    /// <paramref name="outputDirectory"/>/<see cref="EncryptedKeyBagKeyFileName"/>.
    /// </summary>
    /// <param name="escrowPassword">
    /// Legacy/ignorato. Unwrap PCS usa il dsid (PBKDF2), non iCSC.
    /// </param>
    /// <param name="twoFactorCode">Ignorato (legacy).</param>
    public async Task<EscrowRecoveryResult> FetchEncryptedKeyBagKeyAsync(
        ICloudSession session,
        string escrowPassword,
        string outputDirectory,
        IProgress<string>? log = null,
        EscrowSmsOptions? sms = null,
        string? twoFactorCode = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Sessione senza dsid.");

        Directory.CreateDirectory(outputDirectory);
        var useSms = sms?.Enabled == true;
        var label = useSms
            ? EscrowProxyClient.LabelSecureBackupRecord
            : EscrowProxyClient.LabelProtectedCloudStorageRecord;

        // Secret = dsid: x = SHA256(salt || SHA256(dsid ":" dsid))
        var passcodeCandidates = BuildDsidPasscodeCandidates(session.Dsid);
        log?.Report(
            useSms
                ? $"Escrow: securebackup + SMS (label={label})"
                : $"Escrow: label={label}");
        log?.Report(
            $"  SRP x = SHA256(salt || SHA256(dsid:dsid))  dsid={session.Dsid}");
        log?.Report(
            $"  candidati ({passcodeCandidates.Count}): " +
            string.Join(", ", passcodeCandidates.Select(c => c.Name)));

        log?.Report("Escrow: get_records…");
        var records = await _client.GetRecordsAsync(session, log, ct);
        await EscrowProxyClient.SaveProbeArtifactsAsync(outputDirectory, records, ct);
        try
        {
            await EscrowBottlesParser.SaveBottlesJsonAsync(outputDirectory, records.RawBody, ct);
            log?.Report("  escrow_bottles.json / pcs_* salvati da metadata");
        }
        catch (Exception ex)
        {
            log?.Report($"  parse bottles: {ex.Message}");
        }

        if (!EscrowProxyClient.IsEscrowSuccess(records))
        {
            var err = ExtractMessage(records.Parsed) ?? $"HTTP {records.HttpStatus}";
            return new EscrowRecoveryResult(false, $"get_records fallito: {err}");
        }

        string? phoneToken = sms?.PhoneNumberToken?.Trim();
        string? smsCode = sms?.SmsChallengeCode?.Trim();

        if (useSms)
        {
            log?.Report("Escrow SMS: get_sms_targets…");
            var targets = await _client.GetSmsTargetsAsync(session, log, ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "escrow_get_sms_targets_response.xml"),
                targets.RawBody,
                ct);
            if (!EscrowProxyClient.IsEscrowSuccess(targets))
            {
                var err = ExtractMessage(targets.Parsed) ?? $"HTTP {targets.HttpStatus}";
                return new EscrowRecoveryResult(false, $"get_sms_targets fallito: {err}");
            }

            phoneToken ??= EscrowProxyClient.ExtractPhoneNumberToken(targets.Parsed);
            if (string.IsNullOrWhiteSpace(phoneToken))
            {
                return new EscrowRecoveryResult(
                    false,
                    "get_sms_targets OK ma phoneNumberToken assente — inseriscilo manualmente.");
            }

            log?.Report($"  phoneNumberToken OK ({phoneToken.Length} char)");

            if (sms?.RequestSmsChallenge == true || string.IsNullOrWhiteSpace(smsCode))
            {
                log?.Report("Escrow SMS: generate_sms_challenge…");
                var challenge = await _client.GenerateSmsChallengeAsync(session, label, log, ct);
                await File.WriteAllBytesAsync(
                    Path.Combine(outputDirectory, "escrow_generate_sms_challenge_response.xml"),
                    challenge.RawBody,
                    ct);
                if (!EscrowProxyClient.IsEscrowSuccess(challenge))
                {
                    var err = ExtractMessage(challenge.Parsed) ?? $"HTTP {challenge.HttpStatus}";
                    return new EscrowRecoveryResult(false, $"generate_sms_challenge fallito: {err}");
                }

                if (string.IsNullOrWhiteSpace(smsCode))
                {
                    return new EscrowRecoveryResult(
                        false,
                        "SMS inviato. Inserisci il codice ricevuto e ripeti con variante SMS attiva.");
                }
            }

            if (string.IsNullOrWhiteSpace(smsCode))
            {
                return new EscrowRecoveryResult(
                    false, "Variante SMS attiva: serve il codice SMS (smsChallengeCode).");
            }
        }

        log?.Report($"Escrow: srp_init / recover (identity=dsid={session.Dsid})…");
        log?.Report(
            "  ATTENZIONE: ogni recover fallito consuma 1 tentativo escrow (limite duro ~10).");

        EscrowSrpClient? srp = null;
        byte[]? recordId = null;
        string? correlationId = null;
        byte[]? salt = null;
        EscrowCommandResult? recover = null;
        string? winningPasscodeName = null;
        var attemptErrors = new List<string>();

        for (var i = 0; i < passcodeCandidates.Count; i++)
        {
            var candidate = passcodeCandidates[i];
            log?.Report(
                $"  [{i + 1}/{passcodeCandidates.Count}] passcode={candidate.Name}…");

            srp = new EscrowSrpClient(session.Dsid);
            var publicA = srp.PublicA;
            log?.Report(
                useSms
                    ? $"  srp_init SMS (A={publicA.Length} B)…"
                    : $"  srp_init (A={publicA.Length} B)…");

            var init = await _client.SrpInitAsync(
                session,
                publicA,
                label,
                smsChallengeCode: useSms ? smsCode : null,
                phoneNumberToken: useSms ? phoneToken : null,
                log: log,
                ct: ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, $"escrow_srp_init_request_{candidate.Name}.xml"),
                init.RequestBody ?? [],
                ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, $"escrow_srp_init_response_{candidate.Name}.xml"),
                init.RawBody,
                ct);
            // Ultimo anche senza suffix (compat artefatti).
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "escrow_srp_init_request.xml"),
                init.RequestBody ?? [],
                ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "escrow_srp_init_response.xml"),
                init.RawBody,
                ct);

            if (!EscrowProxyClient.IsEscrowSuccess(init))
            {
                var err = ExtractMessage(init.Parsed) ?? $"HTTP {init.HttpStatus}";
                return new EscrowRecoveryResult(false, $"srp_init fallito: {err}");
            }

            var respBlob = AppleXmlPlist.GetEscrowRespBlob(init.Parsed!);
            if (respBlob is null || respBlob.Length == 0)
                return new EscrowRecoveryResult(false, "srp_init senza respBlob");

            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "escrow_srp_init_respBlob.bin"),
                respBlob,
                ct);

            if (!EscrowSecureBackupBlob.TryParseSrpInitResponse(
                    respBlob, out var sessionId, out recordId, out salt, out var serverB))
            {
                return new EscrowRecoveryResult(
                    false,
                    "Impossibile parsare salt/B dal respBlob srp_init — artefatti salvati.");
            }

            correlationId = EscrowSecureBackupBlob.FormatRecordId(recordId);
            log?.Report(
                $"  srp_init OK — record_id={correlationId}, salt={salt.Length} B, B={serverB.Length} B");

            var srpDsid = AppleXmlPlist.GetString(init.Parsed!, "dsid") ?? session.Dsid;
            if (!string.Equals(srpDsid, session.Dsid, StringComparison.Ordinal))
                log?.Report($"  dsid srp_init={srpDsid} (login={session.Dsid}) — uso quello di srp_init");

            // Se srp_init restituisce un dsid diverso, ricalcola col dsid corretto.
            var secret = srpDsid;
            try
            {
                srp.Complete(secret, salt, serverB, identityOverride: srpDsid);
            }
            catch (Exception ex)
            {
                return new EscrowRecoveryResult(false, $"Calcolo SRP fallito: {ex.Message}");
            }

            var recoverBlob = EscrowSecureBackupBlob.BuildRecoverBlob(
                sessionId, recordId, srp.M1);
            log?.Report($"  recover (blob={recoverBlob.Length} B, passcode={candidate.Name})…");

            recover = await _client.RecoverAsync(
                session,
                recoverBlob,
                label,
                smsChallengeCode: useSms ? smsCode : null,
                log: log,
                ct: ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, $"escrow_recover_request_{candidate.Name}.xml"),
                recover.RequestBody ?? [],
                ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, $"escrow_recover_response_{candidate.Name}.xml"),
                recover.RawBody,
                ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "escrow_recover_request.xml"),
                recover.RequestBody ?? [],
                ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "escrow_recover_response.xml"),
                recover.RawBody,
                ct);

            if (EscrowProxyClient.IsEscrowSuccess(recover))
            {
                winningPasscodeName = candidate.Name;
                log?.Report($"  recover OK con passcode={candidate.Name}");
                break;
            }

            var errMsg = ExtractMessage(recover.Parsed) ?? $"HTTP {recover.HttpStatus}";
            var status = AppleXmlPlist.GetString(recover.Parsed!, "status");
            var detail = $"{candidate.Name}: {errMsg}"
                         + (status is null ? "" : $" (status={status})");
            attemptErrors.Add(detail);
            log?.Report($"  recover FAIL — {detail}");

            if (IsEscrowAttemptLimit(status, errMsg))
            {
                return new EscrowRecoveryResult(
                    false,
                    "recover bloccato dal limite tentativi escrow — stop candidati. " +
                    string.Join(" | ", attemptErrors));
            }
        }

        if (winningPasscodeName is null || recover is null || srp is null
            || correlationId is null || salt is null)
        {
            return new EscrowRecoveryResult(
                false,
                "recover fallito per tutti i candidati passcode: "
                + string.Join(" | ", attemptErrors)
                + (useSms
                    ? " (M1/SMS rifiutati)"
                    : " (M1 rifiutato: nessun passcode accettato)"));
        }

        var recoverResp = AppleXmlPlist.GetEscrowRespBlob(recover.Parsed!);
        if (recoverResp is null || recoverResp.Length == 0)
            return new EscrowRecoveryResult(false, "recover senza respBlob");

        var wrappedPath = Path.Combine(outputDirectory, EncryptedKeyBagKeyWrappedFileName);
        await File.WriteAllBytesAsync(wrappedPath, recoverResp, ct);
        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, "escrow_recover_respBlob.bin"),
            recoverResp,
            ct);
        log?.Report($"  recover respBlob → {EncryptedKeyBagKeyWrappedFileName} ({recoverResp.Length:N0} B)");

        byte[] encryptedKeyBagKey;
        if (EscrowSecureBackupBlob.TryParseRecoverResponse(
                recoverResp, out _, out var m2, out var inner)
            && inner.Length > 32)
        {
            encryptedKeyBagKey = inner;
            if (m2.Length > 0)
            {
                await File.WriteAllBytesAsync(
                    Path.Combine(outputDirectory, "escrow_recover_m2.bin"), m2, ct);
                log?.Report($"  recover M2 tag=0x24 ({m2.Length} B)");
                if (srp.VerifyServerM2(m2))
                    log?.Report("  M2 OK (prova server verificata)");
                else
                    log?.Report("  WARN: M2 non verifica — K/encoding potrebbero non coincidere");
            }

            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "escrow_pcs_ciphertext.bin"),
                inner,
                ct);
        }
        else if (EscrowSecureBackupBlob.TryExtractLargestTaggedPayload(recoverResp, out inner)
                 && inner.Length > 32)
        {
            encryptedKeyBagKey = inner;
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "escrow_pcs_ciphertext.bin"),
                inner,
                ct);
        }
        else
        {
            encryptedKeyBagKey = recoverResp;
            log?.Report("  nessun TLV interno — uso respBlob intero come blob cifrato");
        }

        var keyPath = Path.Combine(outputDirectory, EncryptedKeyBagKeyFileName);
        await File.WriteAllBytesAsync(keyPath, encryptedKeyBagKey, ct);
        log?.Report(
            $"  KeyBagKey cifrato → {EncryptedKeyBagKeyFileName} ({encryptedKeyBagKey.Length:N0} B)");

        byte[]? decrypted = srp.TryDecryptEscrowPayload(encryptedKeyBagKey, out var mutAMethod)
                            ?? srp.TryDecryptEscrowPayload(recoverResp, out mutAMethod);
        string? keybagPath = null;
        string? keybagKeyPath = null;
        string? pcsMethod = null;
        var pcsPending = true;

        if (decrypted is { Length: > 0 })
        {
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, EscrowPcsKeyUnwrap.UnwrappedFileName),
                decrypted,
                ct);
            log?.Report(
                $"  unwrap {(mutAMethod ?? "K_SRP")} OK → {EscrowPcsKeyUnwrap.UnwrappedFileName} ({decrypted.Length:N0} B)");

            keybagPath = await TryPersistDecryptedKeybagAsync(outputDirectory, decrypted, log, ct);

            // PCS unwrap: type2 PBKDF2(dsid,salt64)+AesSiv  / CBC legacy.
            log?.Report("Escrow: unwrap PCS sec3 (PBKDF2(dsid)+AesSiv/CBC)…");
            var unwrap = await EscrowPcsKeyUnwrap.UnwrapAsync(decrypted, outputDirectory, log, ct);
            if (unwrap.Success)
            {
                pcsPending = false;
                keybagKeyPath = unwrap.OutputPath;
                pcsMethod = unwrap.Method;

                log?.Report("Escrow: unlock kPCSMetadataEscrowedKeys (RFC6637+GCM)…");
                var unlock = await EscrowPcsUnlock.UnlockFromDirectoryAsync(outputDirectory, log, ct);
                if (!unlock.Success)
                    log?.Report($"  {unlock.Message}");
            }
            else
            {
                log?.Report($"  {unwrap.Message}");
            }
        }
        else
        {
            log?.Report("  unwrap recover fallito — blob cifrato salvato comunque.");
        }

        if (keybagPath is not null)
            pcsPending = false;

        var meta = JsonSerializer.Serialize(new
        {
            success = true,
            correlationId,
            recordId = correlationId,
            srpIdentity = session.Dsid,
            smsVariant = useSms,
            label,
            passcodeUsed = winningPasscodeName,
            saltBytes = salt.Length,
            encryptedKeyBagKeyFile = EncryptedKeyBagKeyFileName,
            encryptedKeyBagKeyBytes = encryptedKeyBagKey.Length,
            wrappedFile = EncryptedKeyBagKeyWrappedFileName,
            wrappedBytes = recoverResp.Length,
            decryptedBytes = decrypted?.Length ?? 0,
            keybagDecrypted = keybagPath is null ? null : Path.GetFileName(keybagPath),
            keybagKey = keybagKeyPath is null ? null : Path.GetFileName(keybagKeyPath),
            pcsUnwrapMethod = pcsMethod,
            pcsUnwrapPending = pcsPending,
            note =
                "SRP P=dsid → AES(K_SRP) → KeyVault 0x0A → PBKDF2(dsid)+AES(sec3) → BackupBagPassword. " +
                "Poi unlock kPCSMetadataEscrowedKeys (RFC6637+GCM)."
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "escrow_keybag_key_meta.json"), meta, ct);

        var msg = pcsPending
            ? $"OK — AES(K_SRP) fatto; PCS sec3 unwrap pending. " +
              $"{EncryptedKeyBagKeyFileName} ({encryptedKeyBagKey.Length:N0} B)"
            : $"OK — PCS unwrap → BackupBagPassword ({pcsMethod}). " +
              $"{(keybagKeyPath is null ? EncryptedKeyBagKeyFileName : Path.GetFileName(keybagKeyPath))}";

        return new EscrowRecoveryResult(
            true,
            msg + $" [{(useSms ? "SMS" : "PCS")}, srp={winningPasscodeName}]",
            correlationId,
            recoverResp,
            encryptedKeyBagKey,
            keyPath,
            decrypted,
            PcsUnwrapPending: pcsPending,
            KeybagDecryptedPath: keybagPath,
            KeybagKeyPath: keybagKeyPath,
            PcsUnwrapMethod: pcsMethod);
    }

    /// <summary>
    /// Solo unwrap PCS su <c>escrow_pcs_unwrapped.bin</c> (PBKDF2(dsid)+AES) — zero recover.
    /// </summary>
    public Task<EscrowPcsUnwrapResult> CompletePcsUnwrapOfflineAsync(
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default) =>
        EscrowPcsKeyUnwrap.UnwrapFromDirectoryAsync(outputDirectory, log, ct);

    /// <summary>
    /// Solo unlock offline <c>kPCSMetadataEscrowedKeys</c> con <c>BackupBagPassword</c> — zero recover.
    /// </summary>
    public Task<EscrowPcsUnlockResult> CompletePcsUnlockOfflineAsync(
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default) =>
        EscrowPcsUnlock.UnlockFromDirectoryAsync(outputDirectory, log, ct);

    /// <summary>
    /// Riusa <c>escrow_get_records_response</c> già salvato dal recover (niente seconda get_records).
    /// </summary>
    public async Task<bool> ReparseEscrowedKeysFromCachedGetRecordsAsync(
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        if (EscrowPcsUnlock.ResolveEscrowedKeysPath(outputDirectory) is not null)
            return true;

        var cached = Path.Combine(outputDirectory, "escrow_get_records_response.bin");
        if (!File.Exists(cached) || new FileInfo(cached).Length < 1024)
            cached = Path.Combine(outputDirectory, "escrow_get_records_response.xml");
        if (!File.Exists(cached) || new FileInfo(cached).Length < 1024)
        {
            log?.Report(
                "  pcs_escrowed_keys assente e nessuna get_records cached — " +
                "serve Unlock EscrowedKeys completo (recover include get_records).");
            return false;
        }

        log?.Report(
            $"  PCS: re-parse get_records cached ({new FileInfo(cached).Length:N0} B) → pcs_escrowed_keys…");
        try
        {
            await EscrowBottlesParser.SaveBottlesJsonAsync(
                outputDirectory, await File.ReadAllBytesAsync(cached, ct), ct);
        }
        catch (Exception ex)
        {
            log?.Report($"  parse bottles (cached): {ex.Message}");
            return false;
        }

        var path = EscrowPcsUnlock.ResolveEscrowedKeysPath(outputDirectory);
        if (path is null)
        {
            log?.Report(
                "  re-parse OK ma pcs_escrowed_keys.bin ancora assente — " +
                "metadata PCS senza kPCSMetadataEscrowedKeys estraibile.");
            return false;
        }

        log?.Report($"  pcs_escrowed_keys ← {Path.GetFileName(path)} ({new FileInfo(path).Length:N0} B)");
        return true;
    }

    /// <summary>Alias legacy — stesso flusso di <see cref="FetchEncryptedKeyBagKeyAsync"/>.</summary>
    public Task<EscrowRecoveryResult> RecoverWithIcscAsync(
        ICloudSession session,
        string iCloudSecurityCode,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default) =>
        FetchEncryptedKeyBagKeyAsync(session, iCloudSecurityCode, outputDirectory, log, sms: null, ct: ct);

    private static async Task<string?> TryPersistDecryptedKeybagAsync(
        string outputDirectory,
        byte[]? decryptedEscrow,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (decryptedEscrow is not { Length: > 0 })
            return null;

        var candidates = new List<(string Source, byte[] Data)>
        {
            ("escrow_pcs_unwrapped", decryptedEscrow)
        };
        foreach (var slice in EnumerateKeybagSlices(decryptedEscrow))
            candidates.Add(("escrow_slice", slice));

        foreach (var (source, data) in candidates)
        {
            if (!IosKeybag.TryParse(data, out var kb, out _) || kb is null)
                continue;

            var outPath = Path.Combine(outputDirectory, "keybag_decrypted.bin");
            await File.WriteAllBytesAsync(outPath, data, ct);
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "keybag_blob_tlv.bin"), data, ct);
            log?.Report(
                $"  keybag TLV ← {source} → keybag_decrypted.bin " +
                $"(type={kb.KeybagType}, {data.Length:N0} B)");
            return outPath;
        }

        return null;
    }

    private static IEnumerable<byte[]> EnumerateKeybagSlices(byte[] data)
    {
        for (var i = 0; i <= data.Length - 12; i++)
        {
            if (data[i] != (byte)'T'
                || data[i + 1] != (byte)'Y'
                || data[i + 2] != (byte)'P'
                || data[i + 3] != (byte)'E')
                continue;

            yield return data[i..];
        }
    }

    private static string? ExtractMessage(Dictionary<string, object?>? parsed) =>
        parsed is null ? null : AppleXmlPlist.GetString(parsed, "message");

    private readonly record struct PasscodeCandidate(string Name, string Secret);

    /// <summary>Secret SRP = dsid (P = I): <c>H(dsid ":" dsid)</c>.</summary>
    private static List<PasscodeCandidate> BuildDsidPasscodeCandidates(string dsid)
    {
        var list = new List<PasscodeCandidate>();
        if (!string.IsNullOrWhiteSpace(dsid))
            list.Add(new PasscodeCandidate("dsid", dsid.Trim()));
        return list;
    }

    private static bool IsEscrowAttemptLimit(string? status, string message)
    {
        if (status is "-6012" or "-6014" or "-6016")
            return true;
        var m = message.ToLowerInvariant();
        return m.Contains("soft limit", StringComparison.Ordinal)
               || m.Contains("hard limit", StringComparison.Ordinal)
               || m.Contains("too many", StringComparison.Ordinal)
               || m.Contains("attempt", StringComparison.Ordinal)
                  && m.Contains("limit", StringComparison.Ordinal);
    }
}
