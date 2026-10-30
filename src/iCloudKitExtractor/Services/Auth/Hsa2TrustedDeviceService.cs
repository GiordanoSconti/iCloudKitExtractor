using System.Linq;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Http;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Registra questo client nella lista HSA2 (dispositivi 2FA Apple ID) via GSA nativo.
/// Diverso da idmsa TrustToken web e da enroll IDS.
/// </summary>
public sealed class Hsa2TrustedDeviceService
{
    private readonly HttpClient _http;
    private readonly AuthAnisetteProviders _anisette;
    private readonly bool _useIphone;

    public Hsa2TrustedDeviceService(HttpClient http, AuthAnisetteProviders anisette, bool useIphoneAuth)
    {
        _http = http;
        _anisette = anisette;
        _useIphone = useIphoneAuth;
    }

    public async Task<Hsa2BeginResult> BeginAsync(
        string appleId,
        string password,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("Serve la password Apple ID (campo Accesso).");

        if (LooksLikePet(password))
            throw new InvalidOperationException(
                "Serve la password, non il PET — altrimenti Apple salta il challenge HSA2.");

        if (string.IsNullOrWhiteSpace(ApsSessionService.TryGetPushTokenHex()))
            throw new InvalidOperationException("Connetti APS prima (serve ptkn nel CPD GSA).");

                // Solo verifica OTP — NON soft-repair/wipe e NON newIdentity automatico:
        // wipe MidService su Android ADI → spesso 'ptm'/433 e rompe anche il login.
        await EnsureAnisetteHealthyAsync(log, ct).ConfigureAwait(false);

        var result = await SignInForHsa2Async(appleId, password, log, ct).ConfigureAwait(false);
        if (result.Requires2Fa && result.Session is not null)
            return NeedsOtp(result, log);

        if (result.Success && result.Session is not null)
        {
            log?.Invoke(
                "Login GSA senza challenge 2FA (au=trustedDeviceSecondaryAuth assente). " +
                "Questa ADI è già trusted per Apple. In UI: «Nuova identità ADI» poi riprova Registra. " +
                "Verifica anche ptkn APS.");
            var list = await TryListDevicesAsync(result.Session, log, ct).ConfigureAwait(false);
            return new Hsa2BeginResult
            {
                NeedsOtp = false,
                CompletedSession = result.Session,
                DeviceSummary = list,
                LogText = "Nessun challenge 2FA",
            };
        }

        throw new InvalidOperationException(result.Error ?? "GSA SignIn fallito.");

    }

    private static Hsa2BeginResult NeedsOtp(AuthResult result, Action<string>? log)
    {
        log?.Invoke(
            $"Challenge HSA2 OK — dispositivi noti≈{result.VerificationOptions?.TrustedDeviceCount ?? 0}. " +
            "Inserisci il codice dal tuo iPhone/iPad e conferma.");
        return new Hsa2BeginResult
        {
            NeedsOtp = true,
            PartialSession = result.Session,
            Verification = result.VerificationOptions,
            LogText = result.Error ?? "2FA richiesto",
        };
    }

    private async Task EnsureAnisetteHealthyAsync(Action<string>? log, CancellationToken ct)
    {
        if (!_useIphone)
            return;

        try
        {
            // Apple ID non noto qui: GET / senza apple_id può fallire a seconda del backend.
            _ = await _anisette.Ios.FetchAsync(ct).ConfigureAwait(false);
            log?.Invoke("HSA2: anisette OK.");
            return;
        }
        catch (Exception ex)
        {
            // Non fare soft-repair distruttivo (wipe ADI + MidService): se OTP è morta
            // l'utente ripara a mano. Qui solo messaggio chiaro.
            throw new InvalidOperationException(
                "Anisette :6971 non sana — " + TrimBody(ex.Message) +
                " Non eseguo wipe/newIdentity automatico (rompe MidService). " +
                "Se GET / fallisce con 'ptm', l'ADI locale è ok ma MidService riprovato: " +
                "riavvia AnisetteServer/worker senza POST /provision.",
                ex);
        }
    }

    private async Task<string> RotateAdiIdentityAsync(
        bool newIdentity,
        Action<string>? log,
        CancellationToken ct)
    {
        if (_useIphone)
        {
            var baseUrl = AnisetteProviderFactory.ResolveServerUrl().TrimEnd('/');
            var qs = newIdentity ? "?newIdentity=1" : "";
            log?.Invoke($"HSA2: POST {baseUrl}/provision{qs}…");
            using var provisionReq = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/provision{qs}");
            RemoteAnisetteProvider.ApplyLicenseHeader(provisionReq);
            using var response = await _http
                .SendAsync(provisionReq, ct)
                .ConfigureAwait(false);
            var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"AnisetteServer POST /provision HTTP {(int)response.StatusCode}: {TrimBody(body)}");
            }

            var store = new AnisetteDeviceStore(AdiDeviceProfile.Ios);
            store.InvalidateCache();
            var uuid = store.GetOrCreateDeviceUuid();
            var adi = store.GetOrCreateAdiIdentifier();
            return $"anisette={baseUrl} newIdentity={newIdentity} " +
                   $"uuid={uuid[..Math.Min(8, uuid.Length)]}… adi={adi[..Math.Min(8, adi.Length)]}…";
        }

        var svc = new AdiProvisioningService(_http, AdiDeviceProfile.Windows);
        return newIdentity
            ? await svc.ForceNewIdentityAndProvisionAsync(ct).ConfigureAwait(false)
            : await svc.RepairProvisioningAsync(ct).ConfigureAwait(false);
    }

    private async Task<AuthResult> SignInForHsa2Async(
        string appleId,
        string password,
        Action<string>? log,
        CancellationToken ct)
    {
        var gsa = new GsaGrandSlamAuthService(_http, _anisette, _useIphone);
        gsa.Progress += p => log?.Invoke($"[{p.Step}] {p.Message}");

        log?.Invoke("GSA SignIn (password + ptkn) per entrare in lista 2FA HSA2…");
        return await gsa.SignInAsync(appleId, password, ct).ConfigureAwait(false);
    }

    private static string TrimBody(string body)
    {
        var t = body.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return t.Length <= 300 ? t : t[..300] + "…";
    }

    public async Task<Hsa2CompleteResult> CompleteWithOtpAsync(
        string appleId,
        string code,
        ICloudSession partialSession,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(code) || code.Trim().Length < 4)
            throw new InvalidOperationException("Codice OTP non valido.");

        var gsa = new GsaGrandSlamAuthService(_http, _anisette, _useIphone);
        gsa.Progress += p => log?.Invoke($"[{p.Step}] {p.Message}");

        log?.Invoke("GSA: invio OTP trusted device + validate + authenticate…");
        var result = await gsa
            .SubmitTrustedDeviceCodeAsync(appleId, code.Trim(), partialSession, ct)
            .ConfigureAwait(false);

        if (!result.Success || result.Session is null)
            throw new InvalidOperationException(result.Error ?? "OTP GSA rifiutato.");

        log?.Invoke("Login GSA post-2FA OK — leggo security/devices…");
        var summary = await TryListDevicesAsync(result.Session, log, ct).ConfigureAwait(false);
        return new Hsa2CompleteResult
        {
            Session = result.Session,
            DeviceSummary = summary,
        };
    }

    public async Task<string> TryListDevicesAsync(
        ICloudSession session,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var identity = ResolveAppleIdIdentity(session);
        if (identity is null)
        {
            log?.Invoke(
                "security/devices: skip — manca com.apple.gs.appleid.auth " +
                "(serve dopo challenge HSA2 / Account Info, non GsIdms/PET).");
            return "(lista device non leggibile — manca appleid.auth)";
        }

        var (status, body) = await GetAppleIdJsonAsync(
                session,
                identity,
                "https://gsa.apple.com/appleid/account/manage/security/devices",
                ct)
            .ConfigureAwait(false);
        if (status is null || body is null)
            return "security/devices: request failed";
        if (status is not (>= 200 and < 300))
        {
            var preview = Encoding.UTF8.GetString(body);
            if (preview.Length > 200)
                preview = preview[..200] + "…";
            log?.Invoke($"security/devices HTTP {status}: {preview}");
            return $"security/devices HTTP {status}";
        }

        session.IdentityToken = identity;
        var summary = FormatDeviceList(body);
        log?.Invoke(summary);
        return summary;
    }

    /// <summary>
    /// Numeri associati all’Apple ID da manage/security/devices (+ dettaglio device).
    /// Diversi da <c>phoneNumberToken</c> escrow — ma riempiono challengeDevices vuoti.
    /// </summary>
    public async Task<IReadOnlyList<AssociatedAppleIdPhone>> FetchAssociatedPhonesAsync(
        ICloudSession session,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var identity = ResolveAppleIdIdentity(session);
        if (identity is null)
        {
            log?.Invoke("associated phones: skip — manca appleid.auth");
            return [];
        }

        session.IdentityToken = identity;
        var phones = new List<AssociatedAppleIdPhone>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        var (listStatus, listBody) = await GetAppleIdJsonAsync(
                session,
                identity,
                "https://gsa.apple.com/appleid/account/manage/security/devices",
                ct)
            .ConfigureAwait(false);
        if (listStatus is not (>= 200 and < 300) || listBody is null)
        {
            log?.Invoke($"associated phones: devices list HTTP {listStatus?.ToString() ?? "?"}");
            return [];
        }

        CollectPhonesFromJson(listBody, "devices-list", phones, seen);

        foreach (var deviceId in ExtractDeviceIds(listBody).Take(4))
        {
            ct.ThrowIfCancellationRequested();
            await Task.Delay(300, ct).ConfigureAwait(false);
            var (st, detail) = await GetAppleIdJsonAsync(
                    session,
                    identity,
                    "https://gsa.apple.com/appleid/account/manage/security/devices/" +
                    Uri.EscapeDataString(deviceId),
                    ct)
                .ConfigureAwait(false);
            if (st is (>= 200 and < 300) && detail is not null)
                CollectPhonesFromJson(detail, "device:" + TrimId(deviceId), phones, seen);
        }

        try
        {
            log?.Invoke(
                phones.Count == 0
                    ? "associated phones: nessuno in security/devices"
                    : $"associated phones: {phones.Count} — " +
                      string.Join(", ", phones.Select(p => p.Obfuscated ?? p.RawWithDialCode ?? "?")));
        }
        catch
        {
            // UI thread affinity del caller: non far fallire l’estrazione numeri.
        }

        return phones;
    }

    public readonly record struct AssociatedAppleIdPhone(
        string Source,
        string? CountryDialCode,
        string? Number,
        string? RawWithDialCode,
        string? Obfuscated,
        string? LastTwoDigits,
        bool? Verified);

    private async Task<(int? Status, byte[]? Body)> GetAppleIdJsonAsync(
        ICloudSession session,
        string identity,
        string url,
        CancellationToken ct)
    {
        // Come AccountInfoSyncClient: Basic + X-Apple-GS-Token (stesso Identity adsid:secret).
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Authorization", "Basic " + identity);
        request.Headers.TryAddWithoutValidation("X-Apple-GS-Token", identity);
        session.Anisette.TouchClientTimeUtc();
        request.Headers.Remove("User-Agent");
        request.Headers.TryAddWithoutValidation("User-Agent", "CloudKit/829 (17A577)");
        request.Headers.Remove("X-MMe-Client-Info");
        request.Headers.TryAddWithoutValidation(
            "X-MMe-Client-Info",
            AkdHttpHeaders.ResolveAkdClientInfo(session.Anisette));
        request.Headers.Remove("Accept-Language");
        request.Headers.TryAddWithoutValidation("Accept-Language", "en-US");
        request.Headers.Remove("X-Apple-I-MD-LU");
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);
        request.Headers.Accept.Clear();
        request.Headers.TryAddWithoutValidation("Accept", "application/json; q=0.01");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static List<string> ExtractDeviceIds(byte[] json)
    {
        var ids = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("devices", out var devices)
                || devices.ValueKind != JsonValueKind.Array)
                return ids;
            foreach (var d in devices.EnumerateArray())
            {
                if (d.TryGetProperty("id", out var id) && id.ValueKind == JsonValueKind.String)
                {
                    var s = id.GetString();
                    if (!string.IsNullOrWhiteSpace(s))
                        ids.Add(s!);
                }
            }
        }
        catch
        {
            // ignore
        }

        return ids;
    }

    private static void CollectPhonesFromJson(
        byte[] json,
        string source,
        List<AssociatedAppleIdPhone> phones,
        HashSet<string> seen)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            WalkPhones(doc.RootElement, source, phones, seen);
        }
        catch
        {
            // ignore
        }
    }

    private static void WalkPhones(
        JsonElement el,
        string source,
        List<AssociatedAppleIdPhone> phones,
        HashSet<string> seen)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                if (LooksLikePhoneObject(el))
                {
                    var raw = GetStr(el, "rawNumberWithDialCode")
                              ?? GetStr(el, "numberWithDialCode")
                              ?? GetStr(el, "fullNumberWithCountryPrefix");
                    var number = GetStr(el, "number") ?? GetStr(el, "rawNumber");
                    var dial = GetStr(el, "countryDialCode");
                    var key = (raw ?? "") + "|" + (number ?? "") + "|" + (dial ?? "");
                    if (!string.IsNullOrWhiteSpace(key) && seen.Add(key))
                    {
                        phones.Add(new AssociatedAppleIdPhone(
                            source,
                            dial,
                            number,
                            raw,
                            GetStr(el, "obfuscatedNumber"),
                            GetStr(el, "lastTwoDigits"),
                            el.TryGetProperty("verified", out var v) && v.ValueKind is JsonValueKind.True
                                ? true
                                : v.ValueKind is JsonValueKind.False ? false : null));
                    }
                }

                foreach (var p in el.EnumerateObject())
                    WalkPhones(p.Value, source, phones, seen);
                break;
            case JsonValueKind.Array:
                foreach (var item in el.EnumerateArray())
                    WalkPhones(item, source, phones, seen);
                break;
        }
    }

    private static bool LooksLikePhoneObject(JsonElement el) =>
        el.ValueKind == JsonValueKind.Object
        && (el.TryGetProperty("rawNumberWithDialCode", out _)
            || el.TryGetProperty("numberWithDialCode", out _)
            || (el.TryGetProperty("number", out _) && el.TryGetProperty("countryDialCode", out _)));

    private static string? GetStr(JsonElement el, string name) =>
        el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    private static string? ResolveAppleIdIdentity(ICloudSession session)
    {
        if (string.IsNullOrWhiteSpace(session.Adsid))
            return null;

        if (session.GsServiceTokens.TryGetValue("com.apple.gs.appleid.auth", out var auth)
            && !string.IsNullOrWhiteSpace(auth))
        {
            var secret = NormalizeAppleIdSecret(auth);
            if (secret.Length is >= 450 and <= 520)
            {
                return Convert.ToBase64String(
                    Encoding.UTF8.GetBytes($"{session.Adsid}:{secret}"));
            }
        }

        if (!string.IsNullOrWhiteSpace(session.IdentityToken)
            && LooksLikeAppleIdAuthIdentity(session.IdentityToken))
        {
            return session.IdentityToken;
        }

        return null;
    }

    private static bool LooksLikeAppleIdAuthIdentity(string identityToken)
    {
        try
        {
            var text = Encoding.UTF8.GetString(Convert.FromBase64String(identityToken));
            var colon = text.IndexOf(':');
            var secLen = colon >= 0 ? text.Length - colon - 1 : text.Length;
            return secLen is >= 450 and <= 520;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Toglie prefisso servizio e TTL (:3600) dal secret appleid.auth.</summary>
    private static string NormalizeAppleIdSecret(string secret)
    {
        var body = secret.Trim();
        if (body.StartsWith("com.apple.gs.", StringComparison.Ordinal))
        {
            var c = body.IndexOf(':');
            if (c > 0)
                body = body[(c + 1)..];
        }

        var lastColon = body.LastIndexOf(':');
        if (lastColon > 0 && int.TryParse(body[(lastColon + 1)..], out _))
            body = body[..lastColon];

        return body;
    }

    private static string FormatDeviceList(byte[] json)
    {
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("devices", out var devices)
                || devices.ValueKind != JsonValueKind.Array)
                return "security/devices: nessun array devices";

            var lines = new List<string> { $"Dispositivi HSA2 in lista: {devices.GetArrayLength()}" };
            var n = 0;
            foreach (var d in devices.EnumerateArray())
            {
                n++;
                var name = d.TryGetProperty("name", out var ne) ? ne.GetString() : null;
                var model = d.TryGetProperty("modelName", out var me) ? me.GetString()
                    : d.TryGetProperty("deviceClass", out var dc) ? dc.GetString() : null;
                var id = d.TryGetProperty("id", out var ie) ? ie.GetString() : null;
                lines.Add($"  {n}. {name ?? "(senza nome)"} — {model ?? "?"} id={TrimId(id)}");
                // Flag utili: Apple distingue "in lista" vs "può ricevere codici 2FA".
                foreach (var key in new[]
                         {
                             "deviceClass", "osVersion", "model", "currentDevice",
                             "hasMultipleAccounts", "locationAuth", "httpProtocolVersion",
                             "supportsVerificationCodes", "verificationCodeEligible",
                             "isHsaTrusted", "hsa2Eligible", "trusted", "bypass2fa"
                         })
                {
                    if (!d.TryGetProperty(key, out var v))
                        continue;
                    lines.Add($"      {key}={FormatJsonScalar(v)}");
                }
            }

            return string.Join(Environment.NewLine, lines);
        }
        catch (Exception ex)
        {
            return "security/devices parse: " + ex.Message;
        }
    }

    private static string TrimId(string? id) =>
        string.IsNullOrEmpty(id) ? "?"
        : id.Length <= 12 ? id
        : id[..6] + "…" + id[^4..];

    private static string FormatJsonScalar(JsonElement v) => v.ValueKind switch
    {
        JsonValueKind.String => v.GetString() ?? "",
        JsonValueKind.True => "true",
        JsonValueKind.False => "false",
        JsonValueKind.Number => v.ToString(),
        JsonValueKind.Null => "null",
        _ => v.GetRawText(),
    };

    private static bool LooksLikePet(string secret)
    {
        if (secret.Contains("com.apple.gs.idms.pet", StringComparison.Ordinal))
            return true;
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(secret.Trim()));
            return decoded.Contains("com.apple.gs.idms.pet", StringComparison.Ordinal);
        }
        catch
        {
            return false;
        }
    }
}

public sealed class Hsa2BeginResult
{
    public bool NeedsOtp { get; init; }
    public ICloudSession? PartialSession { get; init; }
    public ICloudSession? CompletedSession { get; init; }
    public PhoneVerificationOptions? Verification { get; init; }
    public string? DeviceSummary { get; init; }
    public string LogText { get; init; } = "";
}

public sealed class Hsa2CompleteResult
{
    public required ICloudSession Session { get; init; }
    public string DeviceSummary { get; init; } = "";
}
