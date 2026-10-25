using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// iphone: AuthKit iPhone end-to-end con worker ADI Android (akd emulato).
/// hybrid: legacy AuthKitWin SRP — solo se authMode esplicito in config.
/// </summary>
public sealed class GsaGrandSlamAuthService
{
    private readonly HttpClient _http;
    private readonly IAnisetteProvider _windowsAnisette;
    private readonly IAnisetteProvider _iosAnisette;
    private readonly bool _useFullIphoneAuth;
    private readonly string _windowsDeviceUuid;
    private GsaSrpClient? _srp;
    private string? _identityToken;

    public event Action<AuthProgress>? Progress;

    public GsaGrandSlamAuthService(HttpClient http, AuthAnisetteProviders anisette, bool useFullIphoneAuth = false)
    {
        _http = http;
        _windowsAnisette = anisette.Windows;
        _iosAnisette = anisette.Ios;
        _useFullIphoneAuth = useFullIphoneAuth;
        _windowsDeviceUuid = new AnisetteDeviceStore(AdiDeviceProfile.Windows).GetOrCreateDeviceUuid();
    }

    private IAnisetteProvider SrpAnisette => _useFullIphoneAuth ? _iosAnisette : _windowsAnisette;

    private AdiDeviceProfile SrpProfile => _useFullIphoneAuth ? AdiDeviceProfile.Ios : AdiDeviceProfile.Windows;

    public async Task<AuthResult> SignInAsync(string appleId, string password, CancellationToken ct = default)
    {
        try
        {
            if (_useFullIphoneAuth)
                await EnsureGenuineIosAnisetteAsync(appleId, ct).ConfigureAwait(false);

            var session = new ICloudSession { AppleId = appleId };
            Report(AuthStep.Lookup,
                $"Identità CPD: {AdiDeviceProfile.ResolveIdentityMode()} ({SrpProfile.Name})");

            Report(AuthStep.Lookup, "Lookup GrandSlam…");
            await SendSetupAsync(HttpMethod.Get, "https://gsa.apple.com/grandslam/GsService2/lookup", ct);
            // ForceFresh: mint OTP nuovo. Cache Frida + TouchClientTime sul re-login → ec=-22410.
            var anisette = await FetchSrpAnisetteAsync(appleId, ct, forceFresh: true)
                .ConfigureAwait(false);

            await SendSetupAsync(HttpMethod.Get, "https://setup.icloud.com/configurations/init", ct);

            _srp = new GsaSrpClient(appleId);

            Task<Dictionary<string, object?>>? accountSettingsTask = null;
            if (!_useFullIphoneAuth)
            {
                Report(AuthStep.SrpExchange, "get_account_settings…");
                accountSettingsTask = GetAccountSettingsAsync(appleId, password, ct);
            }

            session.Anisette = anisette;
            var initCpd = GrandSlamCpdBuilder.Build(anisette, SrpProfile);
            LogCpd("init", initCpd);

            Report(AuthStep.Init, _useFullIphoneAuth
                ? "GsService2 init (A2k, AuthKit iPhone)…"
                : "GsService2 init (A2k)…");
            var initRequest = AppleXmlPlist.BuildGsService2Request("init", new Dictionary<string, object?>
            {
                ["A2k"] = _srp.PublicA,
                ["u"] = appleId,
                ["cpd"] = initCpd,
                ["ps"] = new List<object?> { "s2k", "s2k_fo" }
            });
            var initResponse = await PostGsService2Async(initRequest, session, ct);
            EnsureStatusOk(initResponse, "GsService2 init");

            var iterations = AppleXmlPlist.GetInt(initResponse, "i") ?? 20016;
            var salt = AppleXmlPlist.GetData(initResponse, "s")
                       ?? throw new InvalidOperationException(DescribeSrpFailure(initResponse, "Salt SRP"));
            var serverB = AppleXmlPlist.GetData(initResponse, "B")
                          ?? throw new InvalidOperationException(DescribeSrpFailure(initResponse, "Chiave B"));
            var protocol = AppleXmlPlist.GetString(initResponse, "sp") ?? "s2k";
            var challenge = AppleXmlPlist.GetString(initResponse, "c")
                            ?? throw new InvalidOperationException(DescribeSrpFailure(initResponse, "Challenge c"));

            if (accountSettingsTask is not null)
            {
                var accountSettings = await accountSettingsTask.ConfigureAwait(false);
                ApplyAccountSettingsHints(session, accountSettings);
            }

            var derived = _srp.DerivePassword(protocol, password, salt, iterations);
            _srp.Generate(derived, salt, serverB);

            // Complete: SEMPRE stesso cpd/anisette di init (MD + Client-Time). Un secondo Fetch
            // (cache Frida TouchClientTime / ADI) → stesso MD con clock avanzato → ec=-22410.
            var completeCpd = initCpd;
            Report(AuthStep.SrpExchange,
                "cpd[complete] riusa snapshot init (stesso MD + Client-Time)");

            session.Anisette = anisette;

            Report(AuthStep.SrpExchange, "GsService2 complete (M1)…");
            // I client GSA reali inviano solo c/M1/u nel complete. M2 è la prova del server
            // (verificata dalla risposta), NON va spedita: un campo M2 estraneo → -22410.
            var completeRequest = AppleXmlPlist.BuildGsService2Request("complete", new Dictionary<string, object?>
            {
                ["u"] = appleId,
                ["c"] = challenge,
                ["M1"] = _srp.M1,
                ["cpd"] = completeCpd
            });
            var completeResponse = await PostGsService2Async(completeRequest, session, ct);
            EnsureStatusOk(completeResponse, "GsService2 complete");

            var completeStatus = completeResponse.GetValueOrDefault("Status") as Dictionary<string, object?>;
            var authType = AppleXmlPlist.GetString(completeResponse, "au")
                           ?? (completeStatus is null ? null : AppleXmlPlist.GetString(completeStatus, "au"));

            var serverM2 = AppleXmlPlist.GetData(completeResponse, "M2");
            if (serverM2 is not null && !_srp.VerifyServerM2(serverM2))
                throw new InvalidOperationException("Verifica M2 server fallita.");

            ApplySpdCredentials(session, completeResponse);

            if (authType == "trustedDeviceSecondaryAuth" || string.IsNullOrEmpty(session.PeToken))
            {
                if (string.IsNullOrEmpty(session.IdentityToken))
                    throw new InvalidOperationException("Manca identity token dopo GsService2 complete (spd).");

                Report(AuthStep.TrustedDevicePrompt, "Recupero opzioni 2FA (dispositivi / SMS)…");
                // Riusa anisette di init/complete (stessa sessione MD).
                anisette = await FetchSrpAnisetteAsync(appleId, ct, reuseIfPresent: anisette);
                session.Anisette = anisette;
                var verification = await FetchVerificationOptionsAsync(session, ct);

                var smsOnly = verification.TrustedPhoneNumbers.Count > 0
                    && verification.TrustedDeviceCount <= 0;
                session.TwoFactorMethod = smsOnly ? TwoFactorMethod.Sms : TwoFactorMethod.TrustedDevice;
                return new AuthResult
                {
                    Success = false,
                    Requires2Fa = true,
                    Session = session,
                    VerificationOptions = verification,
                    Error = smsOnly
                        ? "Account senza dispositivo attendibile — richiedi SMS e inserisci il codice a 6 cifre."
                        : verification.TrustedPhoneNumbers.Count > 0
                            ? "Inserisci il codice dal dispositivo attendibile oppure richiedi SMS."
                            : "Inserisci il codice a 6 cifre del dispositivo attendibile."
                };
            }

            // setup/authenticate deve usare la stessa anisette del GsService2 complete
            // (PE/icloud.auth legati a quel MD). Un mint nuovo → spesso HTTP 401.
            session.Anisette = await FetchSrpAnisetteAsync(
                appleId, ct, reuseIfPresent: session.Anisette ?? anisette);
            Report(AuthStep.Authenticate, _useFullIphoneAuth
                ? "Autenticazione setup.icloud.com (AuthKit iPhone)…"
                : "Autenticazione setup.icloud.com (AuthKitWin, stessa sessione validate)…");
            var authenticated = await AuthenticateSetupAsync(appleId, session, ct);
            Report(AuthStep.Complete, "Login completato.");
            return new AuthResult { Success = true, Session = authenticated };
        }
        catch (Exception ex)
        {
            // Non Report(Failed) qui: CompleteSignInAsync rilancia e la UI logga già "Errore: …".
            return new AuthResult { Success = false, Error = ex.Message };
        }
    }

    public async Task<AuthResult> SubmitSmsCodeAsync(
        string appleId,
        string password,
        string code,
        ICloudSession partialSession,
        CancellationToken ct = default)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(password))
                return new AuthResult { Success = false, Error = "Password richiesta per completare il login post-SMS." };

            partialSession.TwoFactorMethod = TwoFactorMethod.Sms;
            var identity = ResolveIdentityToken(partialSession);
            if (string.IsNullOrEmpty(identity))
                return new AuthResult { Success = false, Error = "Manca identity token dalla fase SRP (spd)." };

            if (!partialSession.SmsCodeRequested)
            {
                return new AuthResult
                {
                    Success = false,
                    Error = "Prima clicca «Invia SMS», poi inserisci il codice ricevuto."
                };
            }

            var trimmed = code.Trim();
            var phone = partialSession.TrustedPhoneNumbers
                .FirstOrDefault(p => p.Id == partialSession.SelectedPhoneId)
                ?? partialSession.TrustedPhoneNumbers.FirstOrDefault();

            // Stessa anisette del PUT verify/phone (Invia SMS). Non rimintare:
            // un MD/OTP diverso da quello della richiesta SMS → Apple -21669.
            if (!HasUsableAnisette(partialSession.Anisette))
            {
                return new AuthResult
                {
                    Success = false,
                    Error = "Anisette assente dopo Invia SMS — richiedi di nuovo l'SMS."
                };
            }

            Report(AuthStep.ValidateCode, "POST gsa.apple.com/auth/verify/phone/securitycode…");
            await PostPhoneSecurityCodeAsync(identity, partialSession, partialSession.Anisette, trimmed, phone, ct);

            // securitycode soddisfa la 2FA (X-Apple-DSID). Se arrivano PE/GS → authenticate diretto.
            // Altrimenti (macless): nuovo GrandSlam SRP a 2FA già soddisfatta.
            if (string.IsNullOrEmpty(partialSession.Dsid))
            {
                return new AuthResult
                {
                    Success = false,
                    Error = "securitycode senza X-Apple-DSID — codice errato, scaduto o già usato."
                };
            }

            if (!string.IsNullOrEmpty(partialSession.PeToken)
                || !string.IsNullOrEmpty(partialSession.GsICloudAuthToken))
            {
                Report(AuthStep.ValidateCode,
                    "2FA SMS accettata — setup/authenticate con token da securitycode…");
                return await CompleteTwoFactorAuthenticateAsync(appleId, partialSession, ct);
            }

            Report(AuthStep.ValidateCode,
                "2FA SMS accettata (solo DSID) — nuovo GrandSlam SRP…");
            return await SignInAsync(appleId, password, ct);
        }
        catch (Exception ex)
        {
            return new AuthResult { Success = false, Error = ex.Message };
        }
    }

    public async Task RequestSmsCodeAsync(
        ICloudSession partialSession,
        int phoneId,
        CancellationToken ct = default)
    {
        partialSession.TwoFactorMethod = TwoFactorMethod.Sms;
        partialSession.SelectedPhoneId = phoneId;

        var phone = partialSession.TrustedPhoneNumbers
            .FirstOrDefault(p => p.Id == phoneId)
            ?? partialSession.TrustedPhoneNumbers.FirstOrDefault();

        var identity = ResolveIdentityToken(partialSession);
        if (string.IsNullOrEmpty(identity))
            throw new InvalidOperationException("Manca identity token GSA dalla fase SRP (spd).");

        if (partialSession.SmsCodeRequested)
        {
            Report(AuthStep.SmsCodeRequest,
                "Nuova richiesta SMS: il codice precedente non è più valido — usa solo l'ultimo.");
        }

        // Mint fresco qui (non riusare login): OTP MD deve essere recente per SMS + securitycode.
        // Il submit riusa questa stessa anisette — non rimintare tra Invia SMS e codice.
        Report(AuthStep.SmsCodeRequest, "Anisette fresca per richiesta SMS…");
        partialSession.Anisette = await FetchSrpAnisetteAsync(
            partialSession.AppleId, ct, reuseIfPresent: null, forceFresh: true);

        // Phone id già noto da verify/trusteddevice (412): salta GET /auth
        // (può far partire un SMS extra / confondere la sessione).
        if (phone is null || phoneId <= 0)
        {
            Report(AuthStep.SmsCodeRequest, "GET gsa.apple.com/auth (boot_args)…");
            var bootPhoneId = await FetchGsaAuthPageAsync(partialSession, identity, ct);
            if (bootPhoneId is not null)
            {
                partialSession.SelectedPhoneId = bootPhoneId.Value;
                phone = partialSession.TrustedPhoneNumbers
                    .FirstOrDefault(p => p.Id == bootPhoneId.Value)
                    ?? phone;
                phoneId = bootPhoneId.Value;
                Report(AuthStep.SmsCodeRequest, $"boot_args: phone id={phoneId}.");
            }
        }

        Report(AuthStep.SmsCodeRequest,
            $"PUT gsa verify/phone (numero id {phoneId}{(phone is not null ? $" — {phone.DisplayLabel}" : "")})…");
        await SendGsaSmsAsync(partialSession, identity, phoneId, phone, ct);

        partialSession.SmsSendChannel = SmsSendChannel.IdmsaPut; // canale GSA piggybacking (stesso payload)
        partialSession.SmsCodeRequested = true;
        Report(AuthStep.SmsCodeRequest, "SMS richiesto — usa solo questo codice (non quelli precedenti).");
    }

    public async Task<AuthResult> SubmitTrustedDeviceCodeAsync(
        string appleId,
        string code,
        ICloudSession partialSession,
        CancellationToken ct = default)
    {
        try
        {
            var identity = ResolveIdentityToken(partialSession);
            if (string.IsNullOrEmpty(identity))
                return new AuthResult { Success = false, Error = "Manca identity token dalla fase SRP (spd)." };

            partialSession.TwoFactorMethod = TwoFactorMethod.TrustedDevice;
            var validateAnisette = await FetchSrpAnisetteAsync(
                appleId, ct, reuseIfPresent: partialSession.Anisette);

            // validate + authenticate stesso profilo AuthKit; in hybrid entrambi AuthKitWin (PE legato alla sessione GSA).
            partialSession.Anisette = validateAnisette;

            Report(AuthStep.ValidateCode, "Validazione codice 2FA…");
            return await CompleteTwoFactorValidateAsync(appleId, partialSession, validateAnisette, code.Trim(), ct);
        }
        catch (Exception ex)
        {
            Report(AuthStep.Failed, ex.Message);
            return new AuthResult { Success = false, Error = ex.Message };
        }
    }

    private async Task<AuthResult> CompleteTwoFactorValidateAsync(
        string appleId,
        ICloudSession partialSession,
        AnisetteHeaders validateAnisette,
        string? securityCode,
        CancellationToken ct)
    {
        var identity = ResolveIdentityToken(partialSession);
        if (string.IsNullOrEmpty(identity))
            return new AuthResult { Success = false, Error = "Manca identity token dalla fase SRP (spd)." };

        using var validate = new HttpRequestMessage(HttpMethod.Get,
            "https://gsa.apple.com/grandslam/GsService2/validate");
        if (_useFullIphoneAuth)
            validate.ApplyGsValidateHeaders(validateAnisette);
        else
            validate.ApplyGsValidateWindowsHeaders(validateAnisette, _windowsDeviceUuid);
        if (!string.IsNullOrWhiteSpace(securityCode))
            validate.Headers.TryAddWithoutValidation("security-code", securityCode.Trim());
        validate.Headers.TryAddWithoutValidation("X-Apple-Identity-Token", identity);

        using var validateResponse = await _http.SendAsync(validate, ct);
        await EnsureValidateOkAsync(validateResponse, ct);

        ApplyGsHeaders(partialSession, validateResponse.Headers);
        EnsureValidateTokens(partialSession);

        var gsCount = validateResponse.Headers.TryGetValues("X-Apple-GS-Token", out var gsHdrs)
            ? gsHdrs.Count()
            : 0;
        Report(AuthStep.ValidateCode, gsCount > 0
            ? $"validate OK (ec=0) — {gsCount} X-Apple-GS-Token + PE."
            : "validate OK (ec=0) — X-Apple-PE-Token ricevuto.");

        return await CompleteTwoFactorAuthenticateAsync(appleId, partialSession, ct);
    }

    /// <summary>
    /// setup/authenticate dopo validate dispositivo attendibile (PE token).
    /// </summary>
    private async Task<AuthResult> CompleteTwoFactorAuthenticateAsync(
        string appleId,
        ICloudSession partialSession,
        CancellationToken ct)
    {
        EnsureAuthenticateTokens(partialSession);

        // Stessa anisette di validate/securitycode — non rimintare (401 su authenticate).
        partialSession.Anisette = await FetchSrpAnisetteAsync(
            appleId, ct, reuseIfPresent: partialSession.Anisette);

        Report(AuthStep.Authenticate, _useFullIphoneAuth
            ? "Autenticazione setup.icloud.com (AuthKit iPhone)…"
            : "Autenticazione setup.icloud.com (AuthKitWin)…");
        var session = await AuthenticateSetupAsync(appleId, partialSession, ct);
        Report(AuthStep.Complete, "Login completato.");
        return new AuthResult { Success = true, Session = session };
    }

    /// <summary>Estrae la password usabile per setup (get_account_settings / ckAppInit) da gs.icloud.auth.</summary>
    internal static string? ExtractGsICloudAuthPasswordForBootstrap(string encoded) =>
        ExtractGsICloudAuthPassword(encoded);

    private static string? ExtractGsICloudAuthPassword(string encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            return null;

        try
        {
            var rawBytes = Convert.FromBase64String(encoded);
            if (rawBytes.Length > 0 && rawBytes[0] < 0x20)
            {
                // Formato binario akd: ckAppInit usa il valore grezzo dell'header.
                return encoded;
            }

            var decoded = Encoding.UTF8.GetString(rawBytes);
            var firstColon = decoded.IndexOf(':');
            if (firstColon < 0)
                return decoded;

            var tokenPart = decoded[(firstColon + 1)..];
            var lastColon = tokenPart.LastIndexOf(':');
            if (lastColon > 0 && int.TryParse(tokenPart[(lastColon + 1)..], out _))
                tokenPart = tokenPart[..lastColon];
            return tokenPart;
        }
        catch
        {
            return encoded;
        }
    }

    private async Task<PhoneVerificationOptions> FetchVerificationOptionsAsync(
        ICloudSession session,
        CancellationToken ct)
    {
        var identity = ResolveIdentityToken(session);
        if (string.IsNullOrEmpty(identity))
            throw new InvalidOperationException("Manca identity token per verify/trusteddevice.");

        using var request = new HttpRequestMessage(HttpMethod.Get,
            "https://gsa.apple.com/auth/verify/trusteddevice");
        ApplyVerifyDeviceHeaders(request, session.Anisette);
        request.Headers.TryAddWithoutValidation("X-Apple-Identity-Token", identity);

        using var response = await _http.SendAsync(request, ct);
        var body = await response.Content.ReadAsByteArrayAsync(ct);
        var options = GsaPhoneVerificationParser.Parse(body);
        // Apple spesso risponde 412 (Precondition Failed) con body pieno di
        // phoneNumberVerification / trustedPhoneNumbers — è la challenge 2FA, non un errore.
        var usable = options.TrustedPhoneNumbers.Count > 0 || options.TrustedDeviceCount > 0;
        if (!response.IsSuccessStatusCode && !usable)
        {
            var text = Encoding.UTF8.GetString(body);
            throw new InvalidOperationException(
                $"verify/trusteddevice HTTP {(int)response.StatusCode}:{(string.IsNullOrWhiteSpace(text) ? "" : $" {text}")}");
        }

        if (!response.IsSuccessStatusCode)
        {
            Report(AuthStep.TrustedDevicePrompt,
                $"verify/trusteddevice HTTP {(int)response.StatusCode} → challenge 2FA " +
                $"(SMS={options.TrustedPhoneNumbers.Count}, device={options.TrustedDeviceCount})");
        }

        session.TrustedPhoneNumbers = options.TrustedPhoneNumbers;
        if (options.TrustedPhoneNumbers.Count > 0)
            session.SelectedPhoneId = options.TrustedPhoneNumbers[0].Id;

        if (options.TrustedPhoneNumbers.Count > 0)
        {
            Report(AuthStep.TrustedDevicePrompt,
                $"Dispositivi attendibili: {options.TrustedDeviceCount}; " +
                $"SMS: {string.Join(", ", options.TrustedPhoneNumbers.Select(p => p.DisplayLabel))}");
        }
        else
        {
            Report(AuthStep.TrustedDevicePrompt,
                $"Prompt dispositivo attendibile inviato ({options.TrustedDeviceCount} device).");
        }

        return options;
    }

    /// <summary>
    /// GET gsa.apple.com/auth — boot_args con phone id (macless-haystack sms_second_factor).
    /// </summary>
    private async Task<int?> FetchGsaAuthPageAsync(
        ICloudSession session,
        string identityToken,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://gsa.apple.com/auth");
        ApplyPhoneVerifyHeaders(request, session.Anisette);
        request.Headers.TryAddWithoutValidation("X-Apple-Identity-Token", identityToken);

        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
            return null;

        var html = await response.Content.ReadAsStringAsync(ct);
        return GsaAuthBootArgsParser.TryParsePhoneId(html);
    }

    /// <summary>
    /// PUT gsa.apple.com/auth/verify/phone — stesso host del POST securitycode (sessione coerente).
    /// </summary>
    private async Task SendGsaSmsAsync(
        ICloudSession session,
        string identityToken,
        int phoneId,
        TrustedPhoneNumber? phone,
        CancellationToken ct)
    {
        var mode = string.IsNullOrWhiteSpace(phone?.PushMode) ? "sms" : phone.PushMode;
        object phoneObj = phone?.NonFteu == true
            ? new { id = phoneId, nonFTEU = true }
            : new { id = phoneId };

        var payload = JsonSerializer.Serialize(new
        {
            phoneNumber = phoneObj,
            mode
        });

        using var request = new HttpRequestMessage(HttpMethod.Put,
            "https://gsa.apple.com/auth/verify/phone");
        ApplyPhoneVerifyHeaders(request, session.Anisette);
        request.Headers.TryAddWithoutValidation("X-Apple-Identity-Token", identityToken);
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await _http.SendAsync(request, ct);
        if (response.IsSuccessStatusCode)
            return;

        var body = await response.Content.ReadAsStringAsync(ct);
        throw new InvalidOperationException(
            $"gsa PUT verify/phone HTTP {(int)response.StatusCode}:{(string.IsNullOrWhiteSpace(body) ? "" : $" {body}")}");
    }

    private async Task PostPhoneSecurityCodeAsync(
        string identityToken,
        ICloudSession session,
        AnisetteHeaders anisette,
        string code,
        TrustedPhoneNumber? phone,
        CancellationToken ct)
    {
        var phoneObj = phone is null
            ? new { id = 1 }
            : phone.NonFteu
                ? (object)new { id = phone.Id, nonFTEU = true }
                : new { id = phone.Id };

        var mode = string.IsNullOrWhiteSpace(phone?.PushMode) ? "sms" : phone.PushMode;
        var payload = JsonSerializer.Serialize(new
        {
            phoneNumber = phoneObj,
            securityCode = new { code },
            mode
        });

        using var request = new HttpRequestMessage(HttpMethod.Post,
            "https://gsa.apple.com/auth/verify/phone/securitycode");
        ApplyPhoneVerifyHeaders(request, anisette);
        request.Headers.TryAddWithoutValidation("X-Apple-Identity-Token", identityToken);
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await _http.SendAsync(request, ct);
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            var serviceError = TryExtractGsaServiceError(body);
            var hint = (serviceError ?? body).Contains("-21669", StringComparison.Ordinal)
                ? " — codice errato/scaduto, oppure anisette diversa da Invia SMS: richiedi un nuovo SMS e riprova subito."
                : "";
            throw new InvalidOperationException(
                string.IsNullOrWhiteSpace(serviceError)
                    ? $"verify/phone/securitycode HTTP {(int)response.StatusCode}:{(string.IsNullOrWhiteSpace(body) ? "" : $" {body}")}{hint}"
                    : $"verify/phone/securitycode: {serviceError}{hint}");
        }

        ApplyGsHeaders(session, response.Headers);
        var dsid = GetHeader(response.Headers, "X-Apple-DSID");
        if (!string.IsNullOrEmpty(dsid))
            session.Dsid = dsid;

        var gsCount = response.Headers.TryGetValues("X-Apple-GS-Token", out var gsHdrs)
            ? gsHdrs.Count()
            : 0;
        var hasPe = !string.IsNullOrEmpty(GetHeader(response.Headers, "X-Apple-PE-Token"));
        var hasDsid = !string.IsNullOrEmpty(dsid);
        Report(AuthStep.ValidateCode, gsCount > 0
            ? $"securitycode OK — {gsCount} X-Apple-GS-Token{(hasPe ? " + PE" : "")}{(hasDsid ? ", DSID" : "")}."
            : hasDsid
                ? "securitycode OK — X-Apple-DSID ricevuto."
                : "securitycode HTTP 2xx.");
    }

    private static string? TryExtractGsaServiceError(string body)
    {
        if (string.IsNullOrWhiteSpace(body) || !body.Contains("serviceErrors", StringComparison.Ordinal))
            return null;

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("serviceErrors", out var errors)
                || errors.ValueKind != JsonValueKind.Array)
            {
                return null;
            }

            foreach (var err in errors.EnumerateArray())
            {
                var code = err.TryGetProperty("code", out var c) ? c.GetString() : null;
                var message = err.TryGetProperty("message", out var m) ? m.GetString() : null;
                if (!string.IsNullOrWhiteSpace(message))
                    return string.IsNullOrWhiteSpace(code) ? message : $"{message} (code {code})";
            }
        }
        catch (JsonException)
        {
            // body non JSON
        }

        return null;
    }

    private void ApplyVerifyDeviceHeaders(HttpRequestMessage request, AnisetteHeaders anisette)
    {
        if (_useFullIphoneAuth)
            request.ApplyTrustedDeviceHeaders(anisette);
        else
            request.ApplyTrustedDeviceWindowsHeaders(anisette, _windowsDeviceUuid);
    }

    private void ApplyPhoneVerifyHeaders(HttpRequestMessage request, AnisetteHeaders anisette) =>
        request.ApplyPhoneVerifyHeaders(anisette, _useFullIphoneAuth, _windowsDeviceUuid);

    private static void EnsureValidateTokens(ICloudSession session)
    {
        if (!string.IsNullOrEmpty(session.PeToken))
            return;

        throw new InvalidOperationException(
            "GsService2/validate senza X-Apple-PE-Token. " +
            "La sessione validate deve usare lo stesso profilo AuthKit del SRP init.");
    }

    private static void EnsureAuthenticateTokens(ICloudSession session)
    {
        if (!string.IsNullOrEmpty(session.PeToken)
            || !string.IsNullOrEmpty(session.GsICloudAuthToken)
            || !string.IsNullOrEmpty(session.GsToken))
        {
            return;
        }

        throw new InvalidOperationException(
            "2FA completata ma mancano token GS/PE per setup/authenticate " +
            "(attesi da validate o da POST verify/phone/securitycode).");
    }

    private async Task EnsureGenuineIosAnisetteAsync(string appleId, CancellationToken ct)
    {
        // Test diagnostico: identità coerente stile Provision (Xcode) → salta i controlli akd.
        if (AdiDeviceProfile.ResolveIdentityMode() == "provision")
            return;

        // Frida: non mintare qui — SignIn forceFresh minta una volta sola.
        // Un fetch pre-login popola la cache Frida; il login successivo TouchClientTime → -22410.
        if (_iosAnisette is RemoteAnisetteProvider remoteProv)
        {
            var backend = await remoteProv.TryGetBackendAsync(ct).ConfigureAwait(false);
            if (AnisetteCapability.IsFridaIphoneBackend(backend))
                return;
        }

        if (_iosAnisette is FridaIphoneAnisetteProvider)
            return;

        var opts = AnisetteFetchOptions.ForAppleId(appleId);
        var remote = await _iosAnisette.FetchAsync(opts, ct).ConfigureAwait(false);
        if (AnisetteCapability.IsEmulatedAkdAnisette(remote))
            return;

        var windows = await _windowsAnisette.FetchAsync(ct).ConfigureAwait(false);
        if (AnisetteCapability.IsLocalCoreAdiSpoof(windows, remote))
        {
            throw new InvalidOperationException(
                AnisetteCapability.DescribeForLogin(AnisetteProviderFactory.ResolveServerUrl(), localSpoof: true));
        }

        if (AnisetteCapability.IsDockerMacAnisette(remote))
        {
            throw new InvalidOperationException(
                AnisetteCapability.DescribeForLogin(
                    AnisetteProviderFactory.ResolveServerUrl(), localSpoof: false, remote));
        }
    }

    private static bool HasUsableAnisette(AnisetteHeaders? h) =>
        h is not null
        && !string.IsNullOrEmpty(h.Md)
        && !string.IsNullOrEmpty(h.MdM);

    private async Task<AnisetteHeaders> FetchSrpAnisetteAsync(
        string? appleId,
        CancellationToken ct,
        AnisetteHeaders? reuseIfPresent = null,
        bool forceFresh = false)
    {
        if (!forceFresh && HasUsableAnisette(reuseIfPresent))
            return reuseIfPresent!;
        var opts = forceFresh
            ? AnisetteFetchOptions.ForGrandSlamLogin(appleId)
            : AnisetteFetchOptions.ForAppleId(appleId);
        return await SrpAnisette.FetchAsync(opts, ct).ConfigureAwait(false);
    }

    private static async Task EnsureValidateOkAsync(HttpResponseMessage response, CancellationToken ct)
    {
        var body = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"GsService2 validate fallito (HTTP {(int)response.StatusCode}): {body}");
        }

        if (!body.Contains("\"ec\"", StringComparison.Ordinal))
            return;

        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("ec", out var ecEl) || !ecEl.TryGetInt32(out var ec) || ec == 0)
                return;

            var em = doc.RootElement.TryGetProperty("em", out var emEl) ? emEl.GetString() : null;
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(em)
                ? $"GsService2 validate fallito (ec={ec})."
                : $"GsService2 validate fallito (ec={ec}): {em}");
        }
        catch (JsonException)
        {
            // body non JSON
        }
    }

    private static string ResolveAuthenticatePassword(ICloudSession session)
    {
        if (!string.IsNullOrEmpty(session.PeToken))
            return DecodePeToken(session.PeToken);
        if (!string.IsNullOrEmpty(session.GsICloudAuthToken))
            return session.GsICloudAuthToken;
        return DecodePeToken(session.MobileMeAuthToken);
    }

    private static string? ResolveIdentityToken(ICloudSession session)
    {
        if (!string.IsNullOrEmpty(session.Adsid) && !string.IsNullOrEmpty(session.GsIdmsToken))
            return GsaSpdDecoder.BuildIdentityToken(session.Adsid, session.GsIdmsToken);
        return session.IdentityToken;
    }

    private async Task<AnisetteHeaders> FetchAuthenticateAnisetteAsync(string? appleId, CancellationToken ct)
    {
        var opts = AnisetteFetchOptions.ForAppleId(appleId);
        return _useFullIphoneAuth
            ? await _iosAnisette.FetchAsync(opts, ct).ConfigureAwait(false)
            : await _windowsAnisette.FetchAsync(opts, ct).ConfigureAwait(false);
    }

    private async Task<ICloudSession> AuthenticateSetupAsync(string appleId, ICloudSession session, CancellationToken ct)
    {
        var authPassword = ResolveAuthenticatePassword(session);
        if (string.IsNullOrEmpty(authPassword))
            throw new InvalidOperationException("Manca PE token da GsService2/validate per setup/authenticate.");

        using var request = new HttpRequestMessage(HttpMethod.Get,
            $"https://setup.icloud.com/setup/authenticate/{Uri.EscapeDataString(appleId)}");
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            AppleHttpExtensions.BasicAuth(appleId, authPassword));
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        if (_useFullIphoneAuth)
            request.ApplyAuthKitIphoneGsHeaders(session.Anisette);
        else
            request.ApplyWindowsAuthKitHeaders(session.Anisette, _windowsDeviceUuid);

        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync(ct);
            var hint = !_useFullIphoneAuth && response.StatusCode == System.Net.HttpStatusCode.Unauthorized
                ? " Il PE token da validate AuthKitWin richiede authenticate AuthKitWin (non iPhone)."
                : string.Empty;
            throw new InvalidOperationException(
                $"setup/authenticate HTTP {(int)response.StatusCode}:{hint}{(string.IsNullOrWhiteSpace(errorBody) ? "" : $" {errorBody}")}");
        }

        if (response.Headers.TryGetValues("x-apple-user-partition", out var partitionValues))
        {
            var partition = partitionValues.First();
            session.Partition = partition.StartsWith('p') ? partition : $"p{partition}";
        }

        var body = await response.Content.ReadAsByteArrayAsync(ct);
        ParseAuthenticateBody(session, body);
        return session;
    }

    private static void ParseAuthenticateBody(ICloudSession session, byte[] body)
    {
        if (body.Length == 0)
            return;

        if (LooksLikeXml(body))
        {
            ParseAuthenticateXmlPlist(session, body);
            return;
        }

        foreach (var text in ProtobufStringScanner.ExtractUtf8Strings(body))
            ApplyAuthenticateString(session, text);
    }

    private static bool LooksLikeXml(ReadOnlySpan<byte> body)
    {
        var text = Encoding.UTF8.GetString(body).TrimStart();
        return text.StartsWith("<?xml", StringComparison.Ordinal)
               || text.StartsWith("<plist", StringComparison.Ordinal)
               || text.StartsWith("<dict", StringComparison.Ordinal);
    }

    private static void ParseAuthenticateXmlPlist(ICloudSession session, byte[] body)
    {
        var root = AppleXmlPlist.Parse(body);

        if (root.TryGetValue("appleAccountInfo", out var accountInfo)
            && accountInfo is Dictionary<string, object?> accountDict
            && accountDict.TryGetValue("dsid", out var dsid)
            && dsid is string dsidText
            && !string.IsNullOrEmpty(dsidText))
        {
            session.Dsid = dsidText;
        }

        if (root.TryGetValue("tokens", out var tokens)
            && tokens is Dictionary<string, object?> tokenDict)
        {
            ApplyTokenDict(session, tokenDict);
        }

        if (root.TryGetValue("com.apple.mobileme", out var mobileMe)
            && mobileMe is Dictionary<string, object?> mobileMeDict
            && mobileMeDict.TryGetValue("tokens", out var mmeTokens)
            && mmeTokens is Dictionary<string, object?> mmeTokenDict)
        {
            ApplyTokenDict(session, mmeTokenDict);
        }
    }

    private static void ApplyTokenDict(ICloudSession session, Dictionary<string, object?> tokenDict)
    {
        if (tokenDict.TryGetValue("mmeAuthToken", out var mme)
            && mme is string mmeToken
            && !string.IsNullOrEmpty(mmeToken))
        {
            session.MobileMeAuthToken = mmeToken;
        }

        if (tokenDict.TryGetValue("cloudKitToken", out var ck)
            && ck is string ckToken
            && !string.IsNullOrEmpty(ckToken))
        {
            session.CloudKitAuthToken = ckToken;
        }

        if (tokenDict.TryGetValue("mmeFMFAppToken", out var fmfApp)
            && fmfApp is string fmfAppTok
            && !string.IsNullOrEmpty(fmfAppTok))
        {
            session.MmeFmfAppToken = fmfAppTok;
        }

        if (tokenDict.TryGetValue("mmeFMFToken", out var fmf)
            && fmf is string fmfTok
            && !string.IsNullOrEmpty(fmfTok))
        {
            session.MmeFmfToken = fmfTok;
        }

        if (tokenDict.TryGetValue("mmeFMIPToken", out var fmip)
            && fmip is string fmipTok
            && !string.IsNullOrEmpty(fmipTok))
        {
            session.MmeFmipToken = fmipTok;
        }

        if (tokenDict.TryGetValue("searchPartyToken", out var searchParty)
            && searchParty is string searchPartyTok
            && !string.IsNullOrEmpty(searchPartyTok))
        {
            session.SearchPartyToken = searchPartyTok;
        }
    }

    private static void ApplyAuthenticateString(ICloudSession session, string text)
    {
        if (string.IsNullOrEmpty(session.Dsid) && Regex.IsMatch(text, @"^\d{8,}$"))
            session.Dsid = text;
        if (text.StartsWith("EAA", StringComparison.Ordinal) && string.IsNullOrEmpty(session.MobileMeAuthToken))
            session.MobileMeAuthToken = text;
        if (text.StartsWith("EAM", StringComparison.Ordinal) && string.IsNullOrEmpty(session.CloudKitAuthToken))
            session.CloudKitAuthToken = text;
        if (text.StartsWith("_", StringComparison.Ordinal) && text.Length == 33 && string.IsNullOrEmpty(session.CloudKitUserId))
            session.CloudKitUserId = text;
    }

    private async Task<Dictionary<string, object?>> GetAccountSettingsAsync(
        string appleId,
        string password,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, "https://setup.icloud.com/setup/get_account_settings");
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            AppleHttpExtensions.BasicAuth(appleId, password));
        request.ApplySetupICloudHeaders();
        using var response = await _http.SendAsync(request, ct);
        var body = await response.Content.ReadAsByteArrayAsync(ct);

        if ((int)response.StatusCode == 409)
        {
            try
            {
                return AppleXmlPlist.Parse(body);
            }
            catch
            {
                return new Dictionary<string, object?>();
            }
        }

        response.EnsureSuccessStatusCode();
        return AppleXmlPlist.GetResponseDict(body) ?? new Dictionary<string, object?>();
    }

    private static void ApplyAccountSettingsHints(ICloudSession session, Dictionary<string, object?> accountSettings)
    {
        if (accountSettings.TryGetValue("appleAccountInfo", out var info)
            && info is Dictionary<string, object?> accountInfo
            && accountInfo.TryGetValue("dsid", out var dsid)
            && dsid is string dsidText
            && !string.IsNullOrEmpty(dsidText))
        {
            session.Dsid = dsidText;
        }

        if (accountSettings.TryGetValue("com.apple.mobileme", out var mobileMe)
            && mobileMe is Dictionary<string, object?> mobileMeDict)
        {
            AccountSettingsApply.ApplyMobileMeDict(session, mobileMeDict);
        }
    }

    private async Task<Dictionary<string, object?>> PostGsService2Async(
        byte[] body,
        ICloudSession session,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, "https://gsa.apple.com/grandslam/GsService2");
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("text/x-xml-plist");
        if (_useFullIphoneAuth)
            request.ApplyGsService2Headers(session.Anisette);
        else
            request.ApplyGsService2WindowsHeaders(session.Anisette, _windowsDeviceUuid);
        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
        ApplyGsHeaders(session, response.Headers);
        var responseBody = await response.Content.ReadAsByteArrayAsync(ct);
        if (responseBody.Length == 0)
            return new Dictionary<string, object?>();

        try
        {
            return AppleXmlPlist.GetResponseDict(responseBody) ?? new Dictionary<string, object?>();
        }
        catch
        {
            return new Dictionary<string, object?>();
        }
    }

    private async Task SendSetupAsync(HttpMethod method, string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, url);
        request.ApplySetupICloudHeaders();
        using var response = await _http.SendAsync(request, ct);
        response.EnsureSuccessStatusCode();
    }

    private static void EnsureStatusOk(Dictionary<string, object?> response, string step)
    {
        var status = response.GetValueOrDefault("Status") as Dictionary<string, object?>;
        var ec = status is null ? null : AppleXmlPlist.GetInt(status, "ec");
        if (ec is not null and not 0)
        {
            var em = AppleXmlPlist.GetString(status!, "em");
            throw new InvalidOperationException(string.IsNullOrWhiteSpace(em)
                ? $"{step} fallito (ec={ec})."
                : $"{step} fallito (ec={ec}): {em}");
        }
    }

    private static string DescribeSrpFailure(Dictionary<string, object?> response, string field)
    {
        var status = response.GetValueOrDefault("Status") as Dictionary<string, object?>;
        var ec = status is null ? null : AppleXmlPlist.GetInt(status, "ec");
        var em = status is null ? null : AppleXmlPlist.GetString(status, "em");
        var keys = string.Join(", ", response.Keys);
        if (ec is not null and not 0 && !string.IsNullOrWhiteSpace(em))
            return $"{field} mancante (ec={ec}): {em}";
        return ec is null
            ? $"{field} mancante nella risposta GsService2 init (chiavi: {keys})."
            : $"{field} mancante (ec={ec}, chiavi: {keys}).";
    }

    private void ApplySpdCredentials(ICloudSession session, Dictionary<string, object?> completeResponse)
    {
        var spd = AppleXmlPlist.GetData(completeResponse, "spd");
        if (spd is null || _srp is null)
            return;

        try
        {
            var decrypted = _srp.DecryptSpd(spd);
            var credentials = GsaSpdDecoder.TryParseCredentials(decrypted);
            if (credentials is null)
                throw new InvalidOperationException("spd decifrato ma senza adsid/GsIdmsToken.");

            session.Adsid = credentials.Value.Adsid;
            session.GsIdmsToken = credentials.Value.GsIdmsToken;
            var identity = GsaSpdDecoder.BuildIdentityToken(credentials.Value.Adsid, credentials.Value.GsIdmsToken);
            session.IdentityToken = identity;
            _identityToken = identity;

            var serviceTokens = GsaSpdDecoder.TryParseServiceTokens(decrypted);
            session.GsServiceTokens = new Dictionary<string, string>(
                serviceTokens, StringComparer.Ordinal);
            if (serviceTokens.TryGetValue("com.apple.gs.idms.pet", out var pet)
                && !string.IsNullOrEmpty(pet))
            {
                session.PeToken = GsaSpdDecoder.EncodeIdmsPetHeader(pet);
            }

            // Account Info usa t/com.apple.gs.appleid.auth (runtime 133259).
            // Non sovrascrivere IdentityToken SPD (adsid:GsIdmsToken) usato da validate/2FA.
            if (serviceTokens.TryGetValue("com.apple.gs.icloud.auth", out var icloudAuth)
                && !string.IsNullOrEmpty(icloudAuth))
            {
                session.GsICloudAuthToken = icloudAuth;
            }


            Report(AuthStep.SrpExchange,
                $"spd OK adsid + GsIdmsToken len={credentials.Value.GsIdmsToken.Length} " +
                $"t=[{string.Join(",", serviceTokens.Select(kv => $"{kv.Key.Split('.').LastOrDefault()}={kv.Value.Length}"))}]");
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException($"Impossibile decifrare spd da GsService2 complete: {ex.Message}", ex);
        }
    }

    private void ApplyGsHeaders(ICloudSession session, HttpResponseHeaders headers)
    {
        session.PeToken = GetHeader(headers, "X-Apple-PE-Token") ?? session.PeToken;
        session.GsToken = GetHeader(headers, "X-Apple-GS-Token") ?? session.GsToken;

        // validate: X-Apple-Identity-Token = com.apple.gs.idms.auth — non sovrascrivere
        // l'IdentityToken SPD (adsid:GsIdmsToken) usato da appleid/settings Account Info.
        var hdrIdentity = GetHeader(headers, "X-Apple-Identity-Token");
        if (!string.IsNullOrWhiteSpace(hdrIdentity) && !IsGsServiceIdentityHeader(hdrIdentity))
        {
            session.IdentityToken = hdrIdentity;
            _identityToken = hdrIdentity;
        }
        else if (string.IsNullOrWhiteSpace(session.IdentityToken)
                 && !string.IsNullOrWhiteSpace(session.Adsid)
                 && !string.IsNullOrWhiteSpace(session.GsIdmsToken))
        {
            session.IdentityToken = GsaSpdDecoder.BuildIdentityToken(session.Adsid, session.GsIdmsToken);
            _identityToken = session.IdentityToken;
        }

        session.AppleCloudKitContext = GetHeader(headers, "X-Apple-I-CK") ?? session.AppleCloudKitContext;
        if (!string.IsNullOrWhiteSpace(session.IdentityToken))
            _identityToken = session.IdentityToken;

        if (headers.TryGetValues("X-Apple-GS-Token", out var gsTokens))
        {
            foreach (var gsToken in gsTokens)
            {
                LogGsToken(gsToken);
                TryApplyGsServiceToken(session, gsToken);
            }
        }

        var sessionKey = GetHeader(headers, "X-Apple-Session-Key");
        if (!string.IsNullOrEmpty(sessionKey) && string.IsNullOrEmpty(session.MobileMeAuthToken))
            session.MobileMeAuthToken = DecodePeToken(session.PeToken);
    }

    /// <summary>True se token validate/service (<c>com.apple.gs.*</c>), non SPD adsid.</summary>
    private static bool IsGsServiceIdentityHeader(string token)
    {
        try
        {
            var text = Encoding.UTF8.GetString(Convert.FromBase64String(token));
            return text.StartsWith("com.apple.gs.", StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }

    private void LogGsToken(string encoded)
    {
        try
        {
            var raw = Convert.FromBase64String(encoded);
            var ascii = Encoding.ASCII.GetString(raw);
            // Estrae il primo run stampabile lungo (>=6) come nome servizio.
            var svc = Regex.Match(ascii, @"[\x20-\x7e]{6,}");
            var hex = BitConverter.ToString(raw, 0, Math.Min(4, raw.Length));
            Report(AuthStep.ValidateCode,
                $"GS-Token svc={(svc.Success ? svc.Value : "?")} b64pfx={encoded[..Math.Min(6, encoded.Length)]} bytes={hex} rawlen={raw.Length}");
        }
        catch
        {
            // ignora token non decodificabili
        }
    }

    private static void TryApplyGsServiceToken(ICloudSession session, string encoded)
    {
        try
        {
            var rawBytes = Convert.FromBase64String(encoded);

            // Formato binario akd (es. "EAAr…"): [header][nome-servizio ascii][token].
            // ckAppInit usa il VALORE GREZZO dell'header X-Apple-GS-Token gs.icloud.auth.
            if (rawBytes.Length > 0 && rawBytes[0] < 0x20)
            {
                var ascii = Encoding.ASCII.GetString(rawBytes);
                if (ascii.Contains("gs.icloud.auth", StringComparison.Ordinal))
                    session.GsICloudAuthToken = encoded;
                return;
            }

            var decoded = Encoding.UTF8.GetString(rawBytes);
            var firstColon = decoded.IndexOf(':');
            if (firstColon < 0)
                return;

            var service = decoded[..firstColon];
            var tokenPart = decoded[(firstColon + 1)..];
            var lastColon = tokenPart.LastIndexOf(':');
            if (lastColon > 0 && int.TryParse(tokenPart[(lastColon + 1)..], out _))
                tokenPart = tokenPart[..lastColon];

            if (!string.IsNullOrEmpty(service) && !string.IsNullOrEmpty(tokenPart))
                session.GsServiceTokens[service] = tokenPart;

            if (service.Equals("com.apple.gs.icloud.auth", StringComparison.Ordinal)
                && !string.IsNullOrEmpty(tokenPart)
                && string.IsNullOrEmpty(session.GsICloudAuthToken))
            {
                session.GsICloudAuthToken = tokenPart;
            }

            if (tokenPart.StartsWith("EAM", StringComparison.Ordinal)
                && service.Contains("cloudkit", StringComparison.OrdinalIgnoreCase)
                && string.IsNullOrEmpty(session.CloudKitAuthToken))
            {
                session.CloudKitAuthToken = tokenPart;
                return;
            }

            if (service.Contains("cloudkit", StringComparison.OrdinalIgnoreCase)
                && tokenPart.StartsWith("eyJ", StringComparison.Ordinal))
            {
                // ckAppInit (moderno): password = campo "token" interno del JWT cloudkit.auth
                // (blob strutturato AAAABLwI…, equivalente al gs.icloud.auth iOS12).
                var inner = ExtractJwtTokenField(tokenPart);
                if (!string.IsNullOrEmpty(inner))
                    session.CloudKitGsToken = inner;

                if (string.IsNullOrEmpty(session.CloudKitAuthToken))
                    TryExtractEamFromJwtPayload(session, tokenPart);
            }
        }
        catch
        {
            // token GS opzionale / formato sconosciuto
        }
    }

    private static string? ExtractJwtTokenField(string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
            return null;

        var payload = parts[1];
        var pad = payload.Length % 4;
        if (pad > 0)
            payload += new string('=', 4 - pad);

        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
            var match = Regex.Match(json, "\"token\"\\s*:\\s*\"([^\"]+)\"");
            return match.Success ? match.Groups[1].Value : null;
        }
        catch
        {
            return null;
        }
    }

    private static void TryExtractEamFromJwtPayload(ICloudSession session, string jwt)
    {
        var parts = jwt.Split('.');
        if (parts.Length < 2)
            return;

        var payload = parts[1];
        var pad = payload.Length % 4;
        if (pad > 0)
            payload += new string('=', 4 - pad);

        try
        {
            var json = Encoding.UTF8.GetString(Convert.FromBase64String(payload));
            var match = Regex.Match(json, @"EAM[A-Za-z0-9_~\-]+");
            if (match.Success)
                session.CloudKitAuthToken = match.Value;
        }
        catch
        {
            // JWT non decodificabile
        }
    }

    private static string? GetHeader(HttpResponseHeaders headers, string name) =>
        headers.TryGetValues(name, out var values) ? values.FirstOrDefault() : null;

    private static string DecodePeToken(string? encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            return string.Empty;
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var colon = decoded.IndexOf(':');
            return colon >= 0 ? decoded[(colon + 1)..] : decoded;
        }
        catch
        {
            return encoded;
        }
    }

    private void Report(AuthStep step, string message) =>
        Progress?.Invoke(new AuthProgress { Step = step, Message = message });

    private void LogCpd(string phase, Dictionary<string, object?> cpd)
    {
        string[] keys =
        {
            "capp", "prtn", "ptkn", "X-Apple-I-MD-RINFO", "X-Apple-I-Client-Time",
            "X-Apple-I-MD", "X-Apple-I-MD-M", "X-Apple-I-MD-LU", "X-Apple-I-SRL-NO"
        };

        foreach (var key in keys)
        {
            var val = cpd.GetValueOrDefault(key);
            if (key == "ptkn" && val is string s && s.Length > 12 && s != "0")
                val = s[..8] + "…" + s[^4..] + $" (len={s.Length})";
            Report(AuthStep.SrpExchange, $"cpd[{phase}] {key}={val}");
        }
    }

}
