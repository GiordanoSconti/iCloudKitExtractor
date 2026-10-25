using System.IO;
using System.Net.Http.Headers;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Client escrowproxy (PCS) + variante SMS opzionale (securebackup).
/// Default: <c>get_records</c> → <c>srp_init</c> → <c>recover</c> senza SMS
/// (label <c>com.apple.protectedcloudstorage.record</c>).
/// Opzionale: <c>get_sms_targets</c> → <c>generate_sms_challenge</c> → srp_init/recover
/// con <c>smsChallengeCode</c> + <c>phoneNumberToken</c>
/// (label <c>com.apple.securebackup.record</c>).
/// </summary>
public sealed class EscrowProxyClient
{
    /// <summary> <c>command=GETRECORDS</c> (no underscore) — <c>GET_RECORDS</c> → -5001.</summary>
    public const string CommandGetRecords = "GETRECORDS";
    public const string CommandSrpInit = "SRP_INIT";
    public const string CommandRecover = "RECOVER";
    /// <summary>Secure Backup / iCDP: scrive un nuovo record escrow (HSM). Mutante.</summary>
    public const string CommandEnroll = "ENROLL";
    /// <summary>Belenko / CloudServices: certificato club (HSM federation) per wrap enroll.</summary>
    public const string CommandGetClub = "GETCLUB";
    public const string CommandGetClubCert = "GET_CLUB_CERT";
    /// <summary>Variante underscore (diverso da GETRECORDS).</summary>
    public const string CommandGetSmsTargets = "GET_SMS_TARGETS";
    public const string CommandGenerateSmsChallenge = "GENERATE_SMS_CHALLENGE";

    /// <summary>Label PCS usata live (MME, no SMS).</summary>
    public const string LabelProtectedCloudStorageRecord =
        "com.apple.protectedcloudstorage.record";

    /// <summary>Label Keychain escrow classico (MME + SMS).</summary>
    public const string LabelSecureBackupRecord =
        "com.apple.securebackup.record";

    /// <summary>rustpush / Sank6: label azione recover iCDP/Octagon.</summary>
    public const string UserActionEscrowRecovery = "com.apple.sbd: escrow recovery";

    /// <summary>UA escrowproxy stile sbd (Sank6).</summary>
    public const string SbdUserAgent =
        "com.apple.sbd/638.100.48 com.apple.iCloudHelper/282";

    public const string SbdMmeClientInfo =
        "<iPhone14,2> <iPhone OS;16.6;20G75> <com.apple.AuthKit/1 (com.apple.sbd/638.100.48)>";

    private readonly HttpClient _http;

    public EscrowProxyClient(HttpClient http) => _http = http;

    /// <summary>
    /// Auth escrowproxy: PCS usa MME; iCDP/Octagon (rustpush) usa Basic email+PET.
    /// </summary>
    public enum AuthStyle
    {
        MobileMeToken = 0,
        PetBasic = 1,
    }

    /// <summary>
    /// POST …/escrowproxy/api/get_records — lista metadata escrow (PCS + icdp).
    /// Body allineato a <c>capture_http_20260722_170044</c>.
    /// </summary>
    public async Task<EscrowGetRecordsResult> GetRecordsAsync(
        ICloudSession session,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var baseUrl = RequireBaseUrl(session);
        RequireAuth(session);

        log?.Report($"EscrowProxy: get_records → {baseUrl}");
        log?.Report($"  cmd={CommandGetRecords} label={LabelProtectedCloudStorageRecord}");

        var fields = new Dictionary<string, object?>
        {
            ["command"] = CommandGetRecords,
            ["label"] = LabelProtectedCloudStorageRecord,
            ["version"] = 1
        };

        var result = await SendAsync(
            session,
            baseUrl,
            pathSegment: "get_records",
            fields,
            log,
            ct);

        var attempts = new List<EscrowAttemptInfo>
        {
            new(
                $"/{result.PathSegment} cmd={CommandGetRecords} v=1 label={LabelProtectedCloudStorageRecord}",
                result.HttpStatus,
                result.RawBody.Length,
                ExtractErrorMessage(result.Parsed),
                result.RecordLabels.Count)
        };

        var wrapped = new EscrowGetRecordsResult(
            result.HttpStatus,
            result.RawBody,
            result.Parsed,
            result.RecordLabels,
            result.ParseError,
            attempts,
            result.RequestBody,
            result.PathSegment,
            result.Records);

        if (IsEscrowSuccess(wrapped))
            log?.Report($"  OK — {wrapped.RecordLabels.Count} label, {wrapped.MetadataRecords.Count} metadata");
        else
            log?.Report($"  FAIL — {ExtractErrorMessage(wrapped.Parsed) ?? $"HTTP {wrapped.HttpStatus}"}");

        return wrapped;
    }

    /// <summary>
    /// POST …/srp_init —  <c>blob=A[256]</c>, <c>command</c>, <c>label</c>, <c>version</c>.
    /// Variante SMS: aggiunge <c>smsChallengeCode</c> + <c>phoneNumberToken</c>.
    /// </summary>
    public async Task<EscrowCommandResult> SrpInitAsync(
        ICloudSession session,
        byte[] publicA,
        string label = LabelProtectedCloudStorageRecord,
        string? smsChallengeCode = null,
        string? phoneNumberToken = null,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        AuthStyle auth = AuthStyle.MobileMeToken,
        bool includeSbdActionFields = false)
    {
        // PCS  A paddato 256 B. Octagon/iCDP (Sank6): A trimmed 1–256 B.
        if (publicA.Length is < 1 or > 256)
            throw new ArgumentException("blob SRP-A deve essere 1..256 byte.", nameof(publicA));

        var fields = new Dictionary<string, object?>
        {
            ["blob"] = publicA,
            ["command"] = CommandSrpInit,
            ["label"] = label,
            ["version"] = 1
        };
        if (!string.IsNullOrWhiteSpace(smsChallengeCode))
            fields["smsChallengeCode"] = smsChallengeCode.Trim();
        if (!string.IsNullOrWhiteSpace(phoneNumberToken))
            fields["phoneNumberToken"] = phoneNumberToken.Trim();
        if (includeSbdActionFields)
            AddSbdActionFields(fields);

        return await SendAsync(session, RequireBaseUrl(session), "srp_init", fields, log, ct, auth);
    }

    /// <summary>
    /// POST …/recover —  <c>blob</c> = session + M1, <c>command</c>, <c>label</c>, <c>version</c>.
    /// Variante SMS: opzionale <c>smsChallengeCode</c>.
    /// </summary>
    public async Task<EscrowCommandResult> RecoverAsync(
        ICloudSession session,
        byte[] recoverBlob,
        string label = LabelProtectedCloudStorageRecord,
        string? smsChallengeCode = null,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        AuthStyle auth = AuthStyle.MobileMeToken,
        bool includeSbdActionFields = false)
    {
        var fields = new Dictionary<string, object?>
        {
            ["blob"] = recoverBlob,
            ["command"] = CommandRecover,
            ["label"] = label,
            ["version"] = 1
        };
        if (!string.IsNullOrWhiteSpace(smsChallengeCode))
            fields["smsChallengeCode"] = smsChallengeCode.Trim();
        if (includeSbdActionFields)
            AddSbdActionFields(fields);

        return await SendAsync(session, RequireBaseUrl(session), "recover", fields, log, ct, auth);
    }

    private static void AddSbdActionFields(Dictionary<string, object?> fields)
    {
        fields["userActionLabel"] = UserActionEscrowRecovery;
        fields["transactionUUID"] = Guid.NewGuid().ToString("D").ToUpperInvariant();
    }

    /// <summary>
    /// POST …/enroll — tenta creazione record escrow.
    /// Auth tipica iCDP: <see cref="AuthStyle.PetBasic"/>. Body minimo = command/label/version;
    /// enroll reale Apple include anche <c>blob</c> (verifier SRP + payload cifrato).
    /// B20: formato KeyVault 0xa1 salt@68 ver@260 payloadWire=1000 → poi -3001 Auth failed
    /// (serve club cert / metadata / wrap federation, non solo PET).
    /// </summary>
    public async Task<EscrowCommandResult> EnrollAsync(
        ICloudSession session,
        string label,
        byte[]? blob = null,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        AuthStyle auth = AuthStyle.PetBasic,
        int version = 1,
        bool includeSbdActionFields = false,
        int? clubTypeId = null,
        byte[]? metadata = null,
        string? federation = null)
    {
        if (string.IsNullOrWhiteSpace(label))
            throw new ArgumentException("label enroll richiesta.", nameof(label));

        var fields = new Dictionary<string, object?>
        {
            ["command"] = CommandEnroll,
            ["label"] = label.Trim(),
            ["version"] = version,
            ["transactionUUID"] = Guid.NewGuid().ToString("D").ToUpperInvariant(),
        };
        if (blob is { Length: > 0 })
            fields["blob"] = blob;
        if (clubTypeId is int ctId)
            fields["clubTypeID"] = ctId;
        if (metadata is { Length: > 0 })
            fields["metadata"] = metadata;
        if (!string.IsNullOrWhiteSpace(federation))
            fields["federation"] = federation.Trim();
        if (includeSbdActionFields)
        {
            fields["userActionLabel"] = "com.apple.sbd: escrow enroll";
        }

        log?.Report(
            $"EscrowProxy: ENROLL label={label.Trim()} blob={(blob?.Length ?? 0)} B " +
            $"auth={auth} clubTypeID={clubTypeId?.ToString() ?? "—"} " +
            $"meta={(metadata?.Length ?? 0)}B fed={federation ?? "—"}");
        return await SendAsync(session, RequireBaseUrl(session), "enroll", fields, log, ct, auth);
    }

    /// <summary>
    /// Ottiene il certificato club / federation (HSM) usato da <c>wrapDataToFedKey</c> pre-ENROLL.
    /// Prova combinazioni command/path storiche (Belenko <c>get_club_cert</c>, Sank6 <c>GETCLUB</c>).
    /// </summary>
    public async Task<EscrowCommandResult> GetClubCertAsync(
        ICloudSession session,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        AuthStyle auth = AuthStyle.PetBasic)
    {
        var attempts = new (string Cmd, string Path)[]
        {
            (CommandGetClub, "getclub"),
            (CommandGetClub, "get_club"),
            (CommandGetClubCert, "get_club_cert"),
            (CommandGetClubCert, "getclubcert"),
        };

        EscrowCommandResult? last = null;
        foreach (var (cmd, path) in attempts)
        {
            var fields = new Dictionary<string, object?>
            {
                ["command"] = cmd,
                ["version"] = 1,
            };
            log?.Report($"EscrowProxy: {cmd} → /{path} auth={auth}");
            last = await SendAsync(session, RequireBaseUrl(session), path, fields, log, ct, auth)
                .ConfigureAwait(false);
            var err = ExtractErrorMessage(last.Parsed) ?? "";
            // Wrong command → -5001; keep trying. Success or other err → stop.
            if (IsEscrowSuccess(last))
                return last;
            if (!err.Contains("Wrong command", StringComparison.OrdinalIgnoreCase)
                && last.HttpStatus is >= 200 and < 500
                && last.RawBody.Length > 64)
                return last;
        }

        return last ?? new EscrowCommandResult(
            0, [], null, [], "get_club: nessun tentativo", null, null, "get_club", null);
    }

    /// <summary>POST …/get_sms_targets — lista numeri / token (variante SMS).</summary>
    public async Task<EscrowCommandResult> GetSmsTargetsAsync(
        ICloudSession session,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var fields = new Dictionary<string, object?>
        {
            ["command"] = CommandGetSmsTargets,
            ["version"] = 1
        };
        return await SendAsync(session, RequireBaseUrl(session), "get_sms_targets", fields, log, ct);
    }

    /// <summary>POST …/generate_sms_challenge — invia codice SMS (variante SMS).</summary>
    public async Task<EscrowCommandResult> GenerateSmsChallengeAsync(
        ICloudSession session,
        string label = LabelSecureBackupRecord,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        string? phoneNumber = null,
        string? countryDialCode = null,
        string? areaDialCode = null,
        int? deviceId = null,
        string? phoneNumberToken = null)
    {
        var fields = new Dictionary<string, object?>
        {
            ["command"] = CommandGenerateSmsChallenge,
            ["label"] = label,
            ["version"] = 1
        };
        // Slot challengeDevices di GET_SMS_TARGETS: numero Apple ID può riempire i campi vuoti.
        if (!string.IsNullOrWhiteSpace(phoneNumber))
            fields["phoneNumber"] = phoneNumber.Trim();
        if (!string.IsNullOrWhiteSpace(countryDialCode))
            fields["countryDialCode"] = countryDialCode.Trim();
        if (!string.IsNullOrWhiteSpace(areaDialCode))
            fields["areaDialCode"] = areaDialCode.Trim();
        if (deviceId is int id)
            fields["deviceId"] = id;
        if (!string.IsNullOrWhiteSpace(phoneNumberToken))
            fields["phoneNumberToken"] = phoneNumberToken.Trim();

        return await SendAsync(
            session, RequireBaseUrl(session), "generate_sms_challenge", fields, log, ct);
    }

    /// <summary>Estrae il primo <c>phoneNumberToken</c> dalla risposta get_sms_targets.</summary>
    public static string? ExtractPhoneNumberToken(Dictionary<string, object?>? parsed) =>
        FindStringByKey(parsed, "phoneNumberToken");

    /// <summary>Snapshot campi utili da GET_SMS_TARGETS (HSA vs escrow SMS).</summary>
    public static EscrowSmsTargetsSummary SummarizeSmsTargets(Dictionary<string, object?>? parsed)
    {
        if (parsed is null)
            return new EscrowSmsTargetsSummary(false, null, null, null, []);

        var enroll = parsed.TryGetValue("enrollRequiresPhoneNumber", out var er) && er is true;
        var hsa = parsed.TryGetValue("isHSAEnabled", out var h) ? h as bool? : null;
        var needsCode = parsed.TryGetValue("recoveryRequiresChallengeCode", out var rc)
            ? rc as bool?
            : null;
        var token = ExtractPhoneNumberToken(parsed);
        var devices = new List<EscrowSmsChallengeDevice>();
        if (parsed.TryGetValue("challengeDevices", out var arr) && arr is IList<object?> list)
        {
            foreach (var item in list)
            {
                if (item is not Dictionary<string, object?> d)
                    continue;
                devices.Add(new EscrowSmsChallengeDevice(
                    AppleXmlPlist.GetString(d, "deviceType"),
                    d.TryGetValue("deviceId", out var did) && did is int i ? i
                        : did is long l ? (int)l : null,
                    AppleXmlPlist.GetString(d, "countryDialCode"),
                    AppleXmlPlist.GetString(d, "areaDialCode"),
                    AppleXmlPlist.GetString(d, "phoneNumber"),
                    AppleXmlPlist.GetString(d, "phoneNumberToken")));
            }
        }

        return new EscrowSmsTargetsSummary(enroll, hsa, needsCode, token, devices);
    }

    public readonly record struct EscrowSmsChallengeDevice(
        string? DeviceType,
        int? DeviceId,
        string? CountryDialCode,
        string? AreaDialCode,
        string? PhoneNumber,
        string? PhoneNumberToken);

    public readonly record struct EscrowSmsTargetsSummary(
        bool EnrollRequiresPhoneNumber,
        bool? IsHsaEnabled,
        bool? RecoveryRequiresChallengeCode,
        string? PhoneNumberToken,
        IReadOnlyList<EscrowSmsChallengeDevice> ChallengeDevices);

    private static string? FindStringByKey(object? node, string key)
    {
        switch (node)
        {
            case Dictionary<string, object?> dict:
                if (dict.TryGetValue(key, out var direct) && direct is string s && !string.IsNullOrWhiteSpace(s))
                    return s;
                foreach (var value in dict.Values)
                {
                    var found = FindStringByKey(value, key);
                    if (found is not null)
                        return found;
                }

                break;
            case IList<object?> list:
                foreach (var item in list)
                {
                    var found = FindStringByKey(item, key);
                    if (found is not null)
                        return found;
                }

                break;
        }

        return null;
    }

    private async Task<EscrowCommandResult> SendAsync(
        ICloudSession session,
        string baseUrl,
        string pathSegment,
        Dictionary<string, object?> fields,
        IProgress<string>? log,
        CancellationToken ct,
        AuthStyle auth = AuthStyle.MobileMeToken)
    {
        if (auth == AuthStyle.PetBasic)
            RequirePetAuth(session);
        else
            RequireAuth(session);

        var url = $"{baseUrl.TrimEnd('/')}/escrowproxy/api/{pathSegment}";
        var requestBody = AppleXmlPlist.ToEscrowProxyXmlBytes(fields);
        log?.Report(
            $"  POST /escrowproxy/api/{pathSegment} ({requestBody.Length} B, auth={auth})…");

        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new ByteArrayContent(requestBody);
        // PCS  text/x-xml-plist. iCDP (appleservices): application/x-apple-plist.
        request.Content.Headers.ContentType = new MediaTypeHeaderValue(
            auth == AuthStyle.PetBasic ? "application/x-apple-plist" : "text/x-xml-plist");

        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        request.Headers.TryAddWithoutValidation("Accept-Encoding", "deflate, gzip");
        request.Headers.TryAddWithoutValidation("Accept-Language", "en-US");

        if (auth == AuthStyle.PetBasic)
        {
            var email = session.AppleId.Trim();
            var pet = ResolveRawPetToken(session)!;
            // appleservices: User-Agent com.apple.cloudservices 1.0
            request.Headers.TryAddWithoutValidation("User-Agent", "com.apple.cloudservices 1.0");
            request.Headers.TryAddWithoutValidation(
                "X-MMe-Client-Info",
                AkdHttpHeaders.ResolveAkdClientInfo(session.Anisette));
            request.Headers.TryAddWithoutValidation(
                "Authorization",
                "Basic " + AppleHttpExtensions.BasicAuth(email, pet));
            log?.Report($"  auth Basic email+PET ({email}, petLen={pet.Length})");
        }
        else
        {
            // Header escrow (CloudKit/829 + AuthKit iPhone, non lakitu).
            request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.AuthKitAkdUserAgent);
            request.Headers.TryAddWithoutValidation(
                "X-MMe-Client-Info",
                AkdHttpHeaders.ResolveAkdClientInfo(session.Anisette));
            request.Headers.TryAddWithoutValidation(
                "Authorization",
                $"X-MobileMe-AuthToken {AppleHttpExtensions.BasicAuth(session.Dsid, session.MobileMeAuthToken)}");
        }

        session.Anisette.TouchClientTimeUtc();
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);

        using var response = await _http.SendAsync(request, ct);
        var responseBody = await response.Content.ReadAsByteArrayAsync(ct);
        var status = (int)response.StatusCode;

        Dictionary<string, object?>? parsed = null;
        string? parseError = null;
        if (responseBody.Length > 0)
        {
            try
            {
                if (LooksLikeXml(responseBody))
                    parsed = AppleXmlPlist.Parse(responseBody);
                else
                    parseError =
                        $"body non-XML (magic={BitConverter.ToString(responseBody.AsSpan(0, Math.Min(8, responseBody.Length)).ToArray())})";
            }
            catch (Exception ex)
            {
                parseError = ex.Message;
            }
        }

        var labels = ExtractRecordLabels(parsed);
        var records = ExtractMetadataRecords(parsed);
        var errMsg = ExtractErrorMessage(parsed);
        log?.Report(
            $"    → HTTP {status}, {responseBody.Length:N0} B"
            + (errMsg is null ? "" : $", err={errMsg}")
            + (labels.Count == 0 ? "" : $", labels={labels.Count}"));

        return new EscrowCommandResult(
            status,
            responseBody,
            parsed,
            labels,
            parseError,
            Attempts: null,
            RequestBody: requestBody,
            PathSegment: pathSegment,
            Records: records);
    }

    /// <summary>Salva request/response grezzi per analisi.</summary>
    public static async Task SaveProbeArtifactsAsync(
        string outputDirectory,
        EscrowGetRecordsResult result,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);

        var responseBin = Path.Combine(outputDirectory, "escrow_get_records_response.bin");
        var existingLen = File.Exists(responseBin) ? new FileInfo(responseBin).Length : 0;
        var isSuccess = IsEscrowSuccess(result);
        // Non sovrascrivere una get_records buona (es. 35 KiB) con un 401 da 358 B.
        var shouldWriteBody = isSuccess
                              || result.RawBody.Length >= existingLen
                              || existingLen < 1024;

        if (result.RequestBody is { Length: > 0 })
        {
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "escrow_get_records_request.xml"),
                result.RequestBody,
                ct);
        }

        if (shouldWriteBody)
        {
            await File.WriteAllBytesAsync(responseBin, result.RawBody, ct);

            if (LooksLikeXml(result.RawBody))
            {
                await File.WriteAllBytesAsync(
                    Path.Combine(outputDirectory, "escrow_get_records_response.xml"),
                    result.RawBody,
                    ct);
            }
        }

        var metaPath = Path.Combine(outputDirectory, "escrow_get_records_meta.json");
        var meta = System.Text.Json.JsonSerializer.Serialize(new
        {
            httpStatus = result.HttpStatus,
            byteLength = result.RawBody.Length,
            success = isSuccess,
            labels = result.RecordLabels,
            preservedPreviousResponse = !shouldWriteBody,
            previousResponseBytes = existingLen,
            records = result.MetadataRecords.Select(r => new
            {
                r.Label,
                r.RecordStatus,
                r.SilentAttemptAllowed,
                r.RemainingAttempts
            }),
            parseError = result.ParseError,
            errorMessage = ExtractErrorMessage(result.Parsed),
            attempts = result.Attempts?.Select(a => new
            {
                a.Variant,
                a.HttpStatus,
                a.ByteLength,
                a.ErrorMessage,
                a.LabelCount
            }),
            note =
                "Wire: command=GETRECORDS + label=com.apple.protectedcloudstorage.record. " +
                "Poi srp_init → recover (senza SMS)."
        }, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(metaPath, meta, ct);
    }

    public static string? ResolveBaseUrl(ICloudSession session)
    {
        if (!string.IsNullOrWhiteSpace(session.EscrowProxyUrl))
            return session.EscrowProxyUrl.TrimEnd('/');

        if (!string.IsNullOrWhiteSpace(session.Partition))
            return $"https://{session.Partition}-escrowproxy.icloud.com";

        return null;
    }

    private static string RequireBaseUrl(ICloudSession session) =>
        ResolveBaseUrl(session)
        ?? throw new InvalidOperationException(
            "EscrowProxyUrl assente — manca com.apple.Dataclass.KeychainSync in get_account_settings.");

    private static void RequireAuth(ICloudSession session)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid)
            || string.IsNullOrWhiteSpace(session.MobileMeAuthToken))
        {
            throw new InvalidOperationException(
                "Serve dsid + mmeAuthToken per escrowproxy (stesso token MME del backup).");
        }
    }

    private static void RequirePetAuth(ICloudSession session)
    {
        if (string.IsNullOrWhiteSpace(session.AppleId))
            throw new InvalidOperationException("Serve Apple ID (email) per auth PET escrow iCDP.");
        if (ResolveRawPetToken(session) is null)
        {
            throw new InvalidOperationException(
                "Serve PET (com.apple.gs.idms.pet) in sessione — rifai login GSA.");
        }
    }

    /// <summary>PET grezzo da <c>spd.t</c> o decodifica di <see cref="ICloudSession.PeToken"/>.</summary>
    public static string? ResolveRawPetToken(ICloudSession session)
    {
        if (session.GsServiceTokens.TryGetValue("com.apple.gs.idms.pet", out var pet)
            && !string.IsNullOrWhiteSpace(pet))
        {
            return pet.Trim();
        }

        if (string.IsNullOrWhiteSpace(session.PeToken))
            return null;

        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(session.PeToken.Trim()));
            // "com.apple.gs.idms.pet:<token>" oppure già solo token
            const string prefix = "com.apple.gs.idms.pet:";
            if (decoded.StartsWith(prefix, StringComparison.Ordinal))
                return decoded[prefix.Length..];
            var colon = decoded.IndexOf(':');
            if (colon > 0
                && decoded.Contains("idms.pet", StringComparison.OrdinalIgnoreCase))
            {
                return decoded[(colon + 1)..];
            }

            return decoded;
        }
        catch
        {
            return null;
        }
    }

    public static bool IsEscrowSuccess(EscrowCommandResult result)
    {
        if (result.HttpStatus is < 200 or >= 300)
            return false;
        if (result.Parsed is null)
            return false;
        return !IsEscrowFailure(result.Parsed);
    }

    private static bool IsEscrowFailure(Dictionary<string, object?>? parsed)
    {
        if (parsed is null)
            return true;

        // Success: status="0" / message="Success" (no boolean "success").
        if (TryGetStatusCode(parsed, out var statusCode))
            return statusCode != 0;

        if (parsed.TryGetValue("success", out var success) && success is false)
            return true;
        if (parsed.TryGetValue("errorCode", out var code) && code is int n && n != 0)
            return true;
        if (parsed.TryGetValue("errorCode", out var codeL) && codeL is long nl && nl != 0)
            return true;

        var msg = ExtractErrorMessage(parsed);
        if (msg is null)
            return false;
        if (msg.Equals("Success", StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    private static bool TryGetStatusCode(Dictionary<string, object?> parsed, out int statusCode)
    {
        statusCode = 0;
        if (!parsed.TryGetValue("status", out var status) || status is null)
            return false;

        switch (status)
        {
            case int i:
                statusCode = i;
                return true;
            case long l:
                statusCode = (int)l;
                return true;
            case string s when int.TryParse(s, out var parsedInt):
                statusCode = parsedInt;
                return true;
            default:
                return false;
        }
    }

    public static string? ExtractErrorMessage(Dictionary<string, object?>? parsed)
    {
        if (parsed is null)
            return null;
        if (parsed.TryGetValue("errorMessage", out var msg) && msg is string s && !string.IsNullOrWhiteSpace(s))
            return s;
        if (parsed.TryGetValue("message", out var msg2) && msg2 is string s2 && !string.IsNullOrWhiteSpace(s2))
        {
            if (s2.Equals("Success", StringComparison.OrdinalIgnoreCase))
                return null;
            return s2;
        }

        if (TryGetStatusCode(parsed, out var statusCode) && statusCode != 0)
            return $"status={statusCode}";
        if (parsed.TryGetValue("errorCode", out var code) && code is int n && n != 0)
            return $"errorCode={n}";
        return null;
    }

    private static List<string> ExtractRecordLabels(Dictionary<string, object?>? root)
    {
        var labels = new List<string>();
        if (root is null)
            return labels;

        CollectLabels(root, labels);
        return labels.Distinct(StringComparer.Ordinal).OrderBy(s => s, StringComparer.Ordinal).ToList();
    }

    private static List<EscrowMetadataRecord> ExtractMetadataRecords(Dictionary<string, object?>? root)
    {
        var list = new List<EscrowMetadataRecord>();
        if (root is null)
            return list;

        if (!root.TryGetValue("metadataList", out var metaList) || metaList is not IList<object?> items)
            return list;

        foreach (var item in items)
        {
            if (item is not Dictionary<string, object?> dict)
                continue;

            var label = AppleXmlPlist.GetString(dict, "label") ?? "";
            var recordStatus = AppleXmlPlist.GetString(dict, "recordStatus");
            var silent = dict.TryGetValue("silentAttemptAllowed", out var sa) && sa is true;
            var remaining = AppleXmlPlist.GetInt(dict, "remainingAttempts");
            list.Add(new EscrowMetadataRecord(label, recordStatus, silent, remaining));
        }

        return list;
    }

    private static void CollectLabels(object? node, List<string> sink)
    {
        switch (node)
        {
            case Dictionary<string, object?> dict:
                foreach (var (key, value) in dict)
                {
                    if (key is "label" or "Label" or "name" or "recordType"
                        && value is string s
                        && s.StartsWith("com.apple.", StringComparison.Ordinal))
                    {
                        sink.Add(s);
                    }

                    CollectLabels(value, sink);
                }

                break;
            case IList<object?> list:
                foreach (var item in list)
                    CollectLabels(item, sink);
                break;
            case string text
                when text.StartsWith("com.apple.securebackup", StringComparison.Ordinal)
                     || text.StartsWith("com.apple.protectedcloudstorage", StringComparison.Ordinal)
                     || text.StartsWith("com.apple.icdp", StringComparison.Ordinal):
                sink.Add(text);
                break;
        }
    }

    private static bool LooksLikeXml(ReadOnlySpan<byte> body)
    {
        if (body.IsEmpty)
            return false;
        var text = Encoding.UTF8.GetString(body).TrimStart();
        // BOM / replacement char da capture gzip a volte in testa.
        text = text.TrimStart('\uFEFF', '\uFFFD', '\0');
        return text.StartsWith("<?xml", StringComparison.Ordinal)
               || text.StartsWith("<plist", StringComparison.Ordinal)
               || text.StartsWith("<dict", StringComparison.Ordinal);
    }
}

public sealed record EscrowAttemptInfo(
    string Variant,
    int HttpStatus,
    int ByteLength,
    string? ErrorMessage,
    int LabelCount);

public sealed record EscrowMetadataRecord(
    string Label,
    string? RecordStatus,
    bool SilentAttemptAllowed,
    int? RemainingAttempts);

public record EscrowCommandResult(
    int HttpStatus,
    byte[] RawBody,
    Dictionary<string, object?>? Parsed,
    IReadOnlyList<string> RecordLabels,
    string? ParseError,
    IReadOnlyList<EscrowAttemptInfo>? Attempts = null,
    byte[]? RequestBody = null,
    string PathSegment = "",
    IReadOnlyList<EscrowMetadataRecord>? Records = null)
{
    public IReadOnlyList<EscrowMetadataRecord> MetadataRecords =>
        Records ?? Array.Empty<EscrowMetadataRecord>();
}

public sealed record EscrowGetRecordsResult(
    int HttpStatus,
    byte[] RawBody,
    Dictionary<string, object?>? Parsed,
    IReadOnlyList<string> RecordLabels,
    string? ParseError,
    IReadOnlyList<EscrowAttemptInfo>? Attempts = null,
    byte[]? RequestBody = null,
    string PathSegment = "",
    IReadOnlyList<EscrowMetadataRecord>? Records = null)
    : EscrowCommandResult(
        HttpStatus,
        RawBody,
        Parsed,
        RecordLabels,
        ParseError,
        Attempts,
        RequestBody,
        PathSegment,
        Records);
