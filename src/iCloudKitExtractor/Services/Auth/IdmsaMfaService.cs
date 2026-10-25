using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Sessione idmsa web: signin SRP, challenge 2FA (device/SMS), 2sv/trust.
/// Usa un <see cref="HttpClient"/> con <c>UseCookies=false</c> (vedi
/// <c>AppleHttpClientFactory.CreateManualCookies</c>) altrimenti i Set-Cookie DES*
/// spariscono nel CookieContainer .NET e 2sv/trust sembra “OK senza TrustToken”.
/// </summary>
public sealed class IdmsaMfaService
{
    private const string ClientId =
        "d39ba9916b7251055b22c7f910e2ea796ee65e98b2ddecea8f5dde8d9d1a815d";

    private const string AuthEndpoint = "https://idmsa.apple.com/appleauth/auth/";
    private const string IcloudOrigin = "https://www.icloud.com";

    private static readonly string FdClientInfo = JsonSerializer.Serialize(new
    {
        U = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0",
        L = "en-GB",
        Z = "GMT+01:00",
        V = "1.1",
        F = ""
    });

    private readonly HttpClient _http;
    private readonly CookieContainer? _sharedJar;
    private readonly string _oauthState = "auth-" + Guid.NewGuid().ToString("D").ToLowerInvariant();

    /// <param name="http">Preferibilmente client con UseCookies=false.</param>
    /// <param name="sharedJar">
    /// CookieContainer del client condiviso (UseCookies=true): usato solo come harvest
    /// di emergenza se DES* fossero finiti lì da richieste precedenti.
    /// </param>
    public IdmsaMfaService(HttpClient http, CookieContainer? sharedJar = null)
    {
        _http = http;
        _sharedJar = sharedJar;
    }

    /// <param name="passwordOrPet">
    /// Password Apple ID oppure PET (<c>com.apple.gs.idms.pet</c>) — password-equivalent per SRP idmsa.
    /// </param>
    /// <param name="trustTokens">
    /// Token <c>X-Apple-TwoSV-Trust-Token</c> già noti (es. da ~/.icloud) per evitare 2FA web.
    /// </param>
    public async Task<IdmsaMfaState> EstablishMfaSessionAsync(
        string appleId,
        string passwordOrPet,
        IReadOnlyList<string>? trustTokens = null,
        CancellationToken ct = default)
    {
        var srp = new GsaSrpClient(appleId);

        using var initRequest = BuildAuthRequest(HttpMethod.Post, "signin/init");
        var initPayload = JsonSerializer.Serialize(new
        {
            a = Convert.ToBase64String(srp.PublicA),
            protocols = new[] { "s2k", "s2k_fo" },
            accountName = appleId
        });
        initRequest.Content = new StringContent(initPayload, Encoding.UTF8, "application/json");

        using var initResponse = await _http.SendAsync(initRequest, ct);
        var initBody = await initResponse.Content.ReadAsStringAsync(ct);
        if (!initResponse.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"idmsa signin/init HTTP {(int)initResponse.StatusCode}:{initBody}");

        using var initDoc = JsonDocument.Parse(initBody);
        var initRoot = initDoc.RootElement;
        var protocol = initRoot.GetProperty("protocol").GetString()
                       ?? throw new InvalidOperationException("idmsa signin/init: protocol mancante.");
        var salt = Convert.FromBase64String(initRoot.GetProperty("salt").GetString()!);
        var serverB = Convert.FromBase64String(initRoot.GetProperty("b").GetString()!);
        var iterations = initRoot.GetProperty("iteration").GetInt32();
        var challenge = initRoot.GetProperty("c").GetString()
                        ?? throw new InvalidOperationException("idmsa signin/init: challenge c mancante.");

        var derived = srp.DerivePassword(protocol, passwordOrPet, salt, iterations);
        srp.Generate(derived, salt, serverB);
        var m1 = Convert.ToBase64String(srp.M1);
        var m2 = Convert.ToBase64String(srp.GenerateM2());

        var cookies = ParseSetCookies(initResponse.Headers);
        var scnt = FirstHeader(initResponse.Headers, "scnt");
        var sessionId = FirstHeader(initResponse.Headers, "X-Apple-ID-Session-Id");
        var tokens = trustTokens?
                         .Where(t => !string.IsNullOrWhiteSpace(t))
                         .Select(t => t.Trim())
                         .Distinct(StringComparer.Ordinal)
                         .ToArray()
                     ?? Array.Empty<string>();

        using var completeRequest = BuildAuthRequest(
            HttpMethod.Post,
            "signin/complete?isRememberMeEnabled=true",
            cookies,
            scnt,
            sessionId);
        var completePayload = JsonSerializer.Serialize(new
        {
            accountName = appleId,
            trustTokens = tokens,
            rememberMe = true,
            m1,
            m2,
            c = challenge
        });
        completeRequest.Content = new StringContent(completePayload, Encoding.UTF8, "application/json");

        using var completeResponse = await _http.SendAsync(completeRequest, ct);
        var completeBody = await completeResponse.Content.ReadAsStringAsync(ct);
        var status = (int)completeResponse.StatusCode;
        // 200/204 = sessione pronta; 409 = HSA2/2FA web ancora richiesto (ma session headers utili).
        if (status is not (200 or 204 or 409))
            throw new InvalidOperationException(
                $"idmsa signin/complete HTTP {status}:{completeBody}");

        cookies = MergeCookies(cookies, ParseSetCookies(completeResponse.Headers));
        var state = new IdmsaMfaState
        {
            Cookies = cookies,
            Scnt = FirstHeader(completeResponse.Headers, "scnt") ?? scnt,
            SessionId = FirstHeader(completeResponse.Headers, "X-Apple-ID-Session-Id") ?? sessionId,
            AuthAttributes = FirstHeader(completeResponse.Headers, "X-Apple-Auth-Attributes"),
            AccountCountryCode = FirstHeader(completeResponse.Headers, "X-Apple-ID-Account-Country") ?? "ITA",
            SessionToken = FirstHeader(completeResponse.Headers, "X-Apple-Session-Token"),
            TrustToken = FirstHeader(completeResponse.Headers, "X-Apple-TwoSV-Trust-Token"),
            LastSignInCompleteStatus = status,
        };
        HarvestTrustArtifacts(state, completeResponse);
        return state;
    }

    /// <summary>
    /// GET <c>/appleauth/auth</c> — aggiorna cookie/header e legge telefoni 2FA dalla challenge HSA2.
    /// </summary>
    public async Task<PhoneVerificationOptions> FetchAuthChallengeAsync(
        IdmsaMfaState state,
        CancellationToken ct = default)
    {
        using var request = BuildAuthRequest(HttpMethod.Get, "", state);
        request.Headers.Remove("Accept");
        request.Headers.TryAddWithoutValidation("Accept", "application/json, text/html, */*");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        ApplyResponseHeaders(state, response);
        HarvestTrustArtifacts(state, response);

        var status = (int)response.StatusCode;
        if (status is not (200 or 204 or 409))
            throw new InvalidOperationException($"idmsa GET auth HTTP {status}:{Trim(body, 300)}");

        return IdmsaAuthChallengeParser.Parse(body);
    }

    /// <summary>
    /// Trigger push codice su dispositivo fidato (GET verify/trusteddevice + PUT securitycode senza body).
    /// </summary>
    public async Task RequestTrustedDevicePushAsync(
        IdmsaMfaState state,
        CancellationToken ct = default)
    {
        string? getErr = null;
        using (var getReq = BuildAuthRequest(HttpMethod.Get, "verify/trusteddevice", state))
        {
            using var getResp = await _http.SendAsync(getReq, ct).ConfigureAwait(false);
            ApplyResponseHeaders(state, getResp);
            HarvestTrustArtifacts(state, getResp);
            var getStatus = (int)getResp.StatusCode;
            if (getStatus is not (200 or 202 or 204))
            {
                var getBody = await getResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                getErr = $"GET verify/trusteddevice HTTP {getStatus}:{Trim(getBody, 200)}";
            }
        }

        using var putReq = BuildAuthRequest(HttpMethod.Put, "verify/trusteddevice/securitycode", state);
        using var putResp = await _http.SendAsync(putReq, ct).ConfigureAwait(false);
        ApplyResponseHeaders(state, putResp);
        HarvestTrustArtifacts(state, putResp);
        var putStatus = (int)putResp.StatusCode;
        if (putStatus is 200 or 202 or 204)
            return;

        var putBody = await putResp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        throw new InvalidOperationException(
            $"idmsa PUT verify/trusteddevice/securitycode HTTP {putStatus}:{Trim(putBody, 300)}"
            + (getErr is null ? "" : $" | {getErr}"));
    }

    /// <summary>Verifica OTP dispositivo fidato su idmsa, poi GET 2sv/trust.</summary>
    public async Task SubmitTrustedDeviceCodeAsync(
        IdmsaMfaState state,
        string code,
        CancellationToken ct = default)
    {
        var payload = JsonSerializer.Serialize(new { securityCode = new { code = code.Trim() } });
        using var verifyRequest = BuildAuthRequest(
            HttpMethod.Post,
            "verify/trusteddevice/securitycode",
            state,
            mfaStyleCookies: true);
        verifyRequest.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var verifyResponse = await _http.SendAsync(verifyRequest, ct).ConfigureAwait(false);
        var verifyBody = await verifyResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        EnsureSecurityCodeAccepted(verifyResponse, verifyBody, "verify/trusteddevice/securitycode");
        ApplyResponseHeaders(state, verifyResponse);
        HarvestTrustArtifacts(state, verifyResponse);

        await CompleteTrustAsync(state, ct).ConfigureAwait(false);
    }

    /// <summary>Verifica OTP SMS su idmsa, poi GET 2sv/trust.</summary>
    public async Task SubmitSmsCodeAsync(
        IdmsaMfaState state,
        string code,
        int phoneId,
        TrustedPhoneNumber? phone,
        CancellationToken ct = default)
    {
        var trimmed = code.Trim();
        object phoneObj = phone?.NonFteu == true
            ? new { id = phoneId, nonFTEU = true }
            : new { id = phoneId };

        var payload = JsonSerializer.Serialize(new
        {
            phoneNumber = phoneObj,
            securityCode = new { code = trimmed },
            mode = "sms"
        });

        using var verifyRequest = BuildAuthRequest(
            HttpMethod.Post,
            "verify/phone/securitycode",
            state,
            mfaStyleCookies: true);
        verifyRequest.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var verifyResponse = await _http.SendAsync(verifyRequest, ct).ConfigureAwait(false);
        var verifyBody = await verifyResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        EnsureSecurityCodeAccepted(verifyResponse, verifyBody, "verify/phone/securitycode");
        ApplyResponseHeaders(state, verifyResponse);
        HarvestTrustArtifacts(state, verifyResponse);

        await CompleteTrustAsync(state, ct).ConfigureAwait(false);
    }

    public async Task RequestSmsAsync(
        IdmsaMfaState state,
        int phoneId,
        TrustedPhoneNumber? phone,
        CancellationToken ct = default)
    {
        object phoneObj = phone?.NonFteu == true
            ? new { id = phoneId, nonFTEU = true }
            : new { id = phoneId };

        var payload = JsonSerializer.Serialize(new
        {
            mode = "sms",
            phoneNumber = phoneObj
        });

        using var request = BuildAuthRequest(HttpMethod.Put, "verify/phone", state, mfaStyleCookies: true);
        request.Content = new StringContent(payload, Encoding.UTF8, "application/json");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var status = (int)response.StatusCode;
        if (status is not (200 or 204))
            throw new InvalidOperationException($"idmsa verify/phone HTTP {status}:{body}");

        ApplyResponseHeaders(state, response);
        HarvestTrustArtifacts(state, response);
        state.SmsRequested = true;
    }

    public async Task CompleteTrustAsync(IdmsaMfaState state, CancellationToken ct = default)
    {
        // 1) GET tipico (pyicloud / icloudjs): cookie MFA (aasp) + session id + scnt
        await SendTrustOnceAsync(state, mfaStyleCookies: true, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(state.TrustToken))
            return;

        // 2) Retry con cookie jar completo (fastlane DES quote)
        await SendTrustOnceAsync(state, mfaStyleCookies: false, ct).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(state.TrustToken))
            return;

        TryAssignTrustFromCookies(state);
        if (!string.IsNullOrWhiteSpace(state.TrustToken))
            return;

        throw new InvalidOperationException(
            "idmsa 2sv/trust HTTP OK ma TrustToken assente " +
            "(né X-Apple-TwoSV-Trust-Token né cookie DES/HSA). " +
            $"SessionToken={(string.IsNullOrWhiteSpace(state.SessionToken) ? "no" : "sì")}; " +
            $"cookies=[{string.Join(", ", state.Cookies.Keys)}]; " +
            $"jarShared={DescribeSharedJar()}");
    }

    private async Task SendTrustOnceAsync(IdmsaMfaState state, bool mfaStyleCookies, CancellationToken ct)
    {
        using var trustRequest = BuildAuthRequest(
            HttpMethod.Get,
            "2sv/trust",
            state,
            mfaStyleCookies: mfaStyleCookies,
            includeSessionToken: false);
        using var trustResponse = await _http.SendAsync(trustRequest, ct).ConfigureAwait(false);
        var trustBody = await trustResponse.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var trustStatus = (int)trustResponse.StatusCode;
        ApplyResponseHeaders(state, trustResponse);
        HarvestTrustArtifacts(state, trustResponse);
        TryAssignTrustFromCookies(state);

        if (trustStatus is not (200 or 204))
        {
            throw new InvalidOperationException(
                $"idmsa 2sv/trust HTTP {trustStatus}:{Trim(trustBody, 300)}");
        }
    }

    private void HarvestTrustArtifacts(IdmsaMfaState state, HttpResponseMessage response)
    {
        state.TrustToken ??= FindHeaderAny(response, "X-Apple-TwoSV-Trust-Token");
        state.SessionToken ??= FindHeaderAny(response, "X-Apple-Session-Token")
                              ?? state.SessionToken;
        var scnt = FindHeaderAny(response, "scnt");
        if (!string.IsNullOrWhiteSpace(scnt))
            state.Scnt = scnt;
        var sid = FindHeaderAny(response, "X-Apple-ID-Session-Id");
        if (!string.IsNullOrWhiteSpace(sid))
            state.SessionId = sid;
        var attrs = FindHeaderAny(response, "X-Apple-Auth-Attributes");
        if (!string.IsNullOrWhiteSpace(attrs))
            state.AuthAttributes = attrs;

        state.Cookies = MergeCookies(state.Cookies, ParseSetCookies(response.Headers));
        // Content-Headers a volte contengono Set-Cookie su alcuni proxy
        state.Cookies = MergeCookies(state.Cookies, ParseSetCookies(response.Content.Headers));
        MergeSharedJarInto(state);
        TryAssignTrustFromCookies(state);
    }

    private void MergeSharedJarInto(IdmsaMfaState state)
    {
        if (_sharedJar is null)
            return;

        foreach (var uri in new[]
                 {
                     "https://idmsa.apple.com/",
                     "https://idmsa.apple.com/appleauth/auth/",
                     "https://idmsa.apple.com/appleauth/auth/2sv/trust",
                     "https://appleid.apple.com/",
                     "https://www.icloud.com/",
                 })
        {
            CookieCollection jarCookies;
            try
            {
                jarCookies = _sharedJar.GetCookies(new Uri(uri));
            }
            catch
            {
                continue;
            }

            foreach (Cookie c in jarCookies)
            {
                if (string.IsNullOrEmpty(c.Name) || string.IsNullOrEmpty(c.Value))
                    continue;
                state.Cookies[c.Name] = c.Value.Trim().Trim('"');
            }
        }
    }

    private string DescribeSharedJar()
    {
        if (_sharedJar is null)
            return "n/a";
        try
        {
            var names = _sharedJar.GetCookies(new Uri("https://idmsa.apple.com/"))
                .Cast<Cookie>()
                .Select(c => c.Name)
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToArray();
            return names.Length == 0 ? "vuoto" : string.Join(",", names);
        }
        catch
        {
            return "?";
        }
    }

    private static void TryAssignTrustFromCookies(IdmsaMfaState state)
    {
        if (!string.IsNullOrWhiteSpace(state.TrustToken))
            return;

        var des = state.Cookies
            .Where(kv => kv.Key.StartsWith("DES", StringComparison.OrdinalIgnoreCase)
                         && !string.IsNullOrWhiteSpace(kv.Value)
                         && kv.Value.Length >= 16)
            .Select(kv => kv.Value.Trim().Trim('"'))
            .FirstOrDefault();
        if (!string.IsNullOrWhiteSpace(des))
        {
            state.TrustToken = des;
            return;
        }

        var hsa = state.Cookies
            .FirstOrDefault(kv =>
                kv.Key.Contains("HSA-TRUST", StringComparison.OrdinalIgnoreCase)
                || kv.Key.Contains("WEBAUTH-HSA", StringComparison.OrdinalIgnoreCase)).Value;
        if (!string.IsNullOrWhiteSpace(hsa))
            state.TrustToken = hsa.Trim().Trim('"');
    }

    private static string? FindHeaderAny(HttpResponseMessage response, string name)
    {
        foreach (var h in response.Headers.NonValidated)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
                return h.Value.FirstOrDefault();
        }

        foreach (var h in response.Content.Headers.NonValidated)
        {
            if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
                return h.Value.FirstOrDefault();
        }

        try
        {
            foreach (var h in response.TrailingHeaders.NonValidated)
            {
                if (string.Equals(h.Key, name, StringComparison.OrdinalIgnoreCase))
                    return h.Value.FirstOrDefault();
            }
        }
        catch
        {
            // TrailingHeaders non sempre disponibile
        }

        return null;
    }

    private HttpRequestMessage BuildAuthRequest(
        HttpMethod method,
        string relativePath,
        IdmsaMfaState state,
        bool mfaStyleCookies = false,
        bool includeSessionToken = true) =>
        BuildAuthRequest(
            method,
            relativePath,
            state.Cookies,
            state.Scnt,
            state.SessionId,
            state.AuthAttributes,
            includeSessionToken ? state.SessionToken : null,
            mfaStyleCookies);

    private HttpRequestMessage BuildAuthRequest(
        HttpMethod method,
        string relativePath,
        Dictionary<string, string>? cookies = null,
        string? scnt = null,
        string? sessionId = null,
        string? authAttributes = null,
        string? sessionToken = null,
        bool mfaStyleCookies = false)
    {
        var request = new HttpRequestMessage(method, AuthEndpoint + relativePath);
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        // pyicloud: Origin/Referer iCloud (non idmsa) — senza questo Apple spesso non emette TwoSV/DES.
        request.Headers.TryAddWithoutValidation("Origin", IcloudOrigin);
        request.Headers.TryAddWithoutValidation("Referer", IcloudOrigin + "/");
        request.Headers.TryAddWithoutValidation("User-Agent",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:103.0) Gecko/20100101 Firefox/103.0");
        request.Headers.TryAddWithoutValidation("X-Requested-With", "XMLHttpRequest");
        request.Headers.TryAddWithoutValidation("X-Apple-Widget-Key", ClientId);
        request.Headers.TryAddWithoutValidation("X-Apple-OAuth-Client-Id", ClientId);
        request.Headers.TryAddWithoutValidation("X-Apple-OAuth-Client-Type", "firstPartyAuth");
        request.Headers.TryAddWithoutValidation("X-Apple-OAuth-Redirect-URI", IcloudOrigin);
        request.Headers.TryAddWithoutValidation("X-Apple-OAuth-Require-Grant-Code", "true");
        request.Headers.TryAddWithoutValidation("X-Apple-OAuth-Response-Type", "code");
        request.Headers.TryAddWithoutValidation("X-Apple-OAuth-Response-Mode", "web_message");
        request.Headers.TryAddWithoutValidation("X-Apple-OAuth-State", _oauthState);
        request.Headers.TryAddWithoutValidation("X-Apple-I-FD-Client-Info", FdClientInfo);

        if (!string.IsNullOrEmpty(scnt))
            request.Headers.TryAddWithoutValidation("scnt", scnt);
        if (!string.IsNullOrEmpty(sessionId))
            request.Headers.TryAddWithoutValidation("X-Apple-ID-Session-Id", sessionId);
        if (!string.IsNullOrEmpty(authAttributes))
            request.Headers.TryAddWithoutValidation("X-Apple-Auth-Attributes", authAttributes);
        if (!string.IsNullOrEmpty(sessionToken))
            request.Headers.TryAddWithoutValidation("X-Apple-Session-Token", sessionToken);

        var cookieHeader = mfaStyleCookies
            ? ToMfaCookieHeader(cookies)
            : ToCookieHeader(cookies);
        if (!string.IsNullOrEmpty(cookieHeader))
            request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);

        return request;
    }

    private void ApplyResponseHeaders(IdmsaMfaState state, HttpResponseMessage response)
    {
        var headers = response.Headers;
        state.Cookies = MergeCookies(state.Cookies, ParseSetCookies(headers));
        state.Scnt = FirstHeader(headers, "scnt") ?? state.Scnt;
        state.SessionId = FirstHeader(headers, "X-Apple-ID-Session-Id") ?? state.SessionId;
        state.AuthAttributes = FirstHeader(headers, "X-Apple-Auth-Attributes") ?? state.AuthAttributes;
        state.SessionToken = FirstHeader(headers, "X-Apple-Session-Token") ?? state.SessionToken;
        state.TrustToken = FirstHeader(headers, "X-Apple-TwoSV-Trust-Token") ?? state.TrustToken;
        var country = FirstHeader(headers, "X-Apple-ID-Account-Country");
        if (!string.IsNullOrWhiteSpace(country))
            state.AccountCountryCode = country;
    }

    /// <summary>
    /// Accetta 200/204, oppure 409 con <c>securityCode.valid=true</c> e/o Session-Token
    /// (comportamento idmsa ~2026).
    /// </summary>
    private static void EnsureSecurityCodeAccepted(
        HttpResponseMessage response,
        string body,
        string endpoint)
    {
        var status = (int)response.StatusCode;
        if (status is 200 or 204)
            return;

        var hasSessionToken = response.Headers.Contains("X-Apple-Session-Token");
        var valid = false;
        try
        {
            using var doc = JsonDocument.Parse(string.IsNullOrWhiteSpace(body) ? "{}" : body);
            if (doc.RootElement.TryGetProperty("securityCode", out var sc)
                && sc.TryGetProperty("valid", out var v)
                && v.ValueKind == JsonValueKind.True)
            {
                valid = true;
            }
        }
        catch (JsonException)
        {
            // ignore
        }

        if (status == 409 && (valid || hasSessionToken))
            return;

        throw new InvalidOperationException($"idmsa {endpoint} HTTP {status}:{body}");
    }

    private static string Trim(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";

    private static string? FirstHeader(HttpHeaders headers, string name)
    {
        if (!headers.TryGetValues(name, out var values))
            return null;
        return values.FirstOrDefault();
    }

    private static Dictionary<string, string> ParseSetCookies(HttpHeaders headers)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in headers.NonValidated)
        {
            if (!string.Equals(header.Key, "Set-Cookie", StringComparison.OrdinalIgnoreCase))
                continue;
            foreach (var value in header.Value)
                MergeCookiePair(map, value);
        }
        return map;
    }

    private static void MergeCookiePair(Dictionary<string, string> map, string setCookie)
    {
        var pair = setCookie.Split(';')[0];
        var idx = pair.IndexOf('=');
        if (idx <= 0)
            return;
        var key = pair[..idx].Trim();
        var val = pair[(idx + 1)..].Trim().Trim('"');
        if (!string.IsNullOrEmpty(key))
            map[key] = val;
    }

    private static Dictionary<string, string> MergeCookies(
        Dictionary<string, string> existing,
        Dictionary<string, string> incoming)
    {
        var merged = new Dictionary<string, string>(existing, StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in incoming)
            merged[k] = v;
        return merged;
    }

    /// <summary>icloudjs MFA: solo <c>aasp</c> (+ DES se già presenti).</summary>
    private static string ToMfaCookieHeader(Dictionary<string, string>? cookies)
    {
        if (cookies is null || cookies.Count == 0)
            return string.Empty;

        var parts = new List<string>();
        if (cookies.TryGetValue("aasp", out var aasp) && !string.IsNullOrWhiteSpace(aasp))
            parts.Add($"aasp={aasp}");

        foreach (var (k, v) in cookies)
        {
            if (!k.StartsWith("DES", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(v))
                continue;
            parts.Add(FormatCookiePair(k, v));
        }

        return string.Join("; ", parts);
    }

    private static string ToCookieHeader(Dictionary<string, string>? cookies) =>
        cookies is null || cookies.Count == 0
            ? string.Empty
            : string.Join("; ", cookies.Select(kv => FormatCookiePair(kv.Key, kv.Value)));

    /// <summary>fastlane: i cookie DES vanno quotati nel header Cookie.</summary>
    private static string FormatCookiePair(string key, string value)
    {
        var v = value.Trim().Trim('"');
        if (key.Contains("DES", StringComparison.OrdinalIgnoreCase))
            return $"{key}=\"{v}\"";
        return $"{key}={v}";
    }
}
