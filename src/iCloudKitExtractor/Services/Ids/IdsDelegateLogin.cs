using System.Net.Http.Headers;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Auth;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// GrandSlam PET → <c>signin/v2</c> (o <c>loginDelegates</c>) per token IDS.
/// </summary>
public sealed class IdsDelegateLogin
{
    private readonly HttpClient _http;
    private readonly IAnisetteProvider _anisette;

    public IdsDelegateLogin(HttpClient http, IAnisetteProvider anisette)
    {
        _http = http;
        _anisette = anisette;
    }

    public async Task<IdsDelegateResult> ObtainAsync(
        ICloudSession session,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var pet = DecodePeToken(session.PeToken);
        if (string.IsNullOrEmpty(pet) && !string.IsNullOrEmpty(session.MobileMeAuthToken))
            pet = DecodePeToken(session.MobileMeAuthToken);
        if (string.IsNullOrEmpty(pet))
            throw new InvalidOperationException("Serve PET (com.apple.gs.idms.pet) in sessione — rifai login GSA.");

        if (string.IsNullOrWhiteSpace(session.AppleId))
            throw new InvalidOperationException("Apple ID assente in sessione.");

        var anisette = await _anisette.FetchAsync(ct).ConfigureAwait(false);
        anisette.TouchClientTimeUtc();

        string? nasQualify = null;
        try
        {
            log?.Invoke("NAC: X-Mme-Nas-Qualify…");
            nasQualify = await new NacValidationService()
                .GenerateNasQualifyBase64Async(log, ct)
                .ConfigureAwait(false);
        }
        catch (Exception nacEx)
        {
            log?.Invoke("NAC Nas-Qualify non disponibile: " + nacEx.Message);
        }

        log?.Invoke("IDS delegate: POST signin/v2/login (com.apple.private.ids)…");
        try
        {
            return await SigninV2Async(session, pet, anisette, nasQualify, log, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log?.Invoke("signin/v2 fallito: " + ex.Message + " — provo loginDelegates…");
            return await LoginDelegatesAsync(session, pet, anisette, nasQualify, log, ct).ConfigureAwait(false);
        }
    }

    private async Task<IdsDelegateResult> SigninV2Async(
        ICloudSession session,
        string pet,
        AnisetteHeaders anisette,
        string? nasQualifyB64,
        Action<string>? log,
        CancellationToken ct)
    {
        var bodyDict = new Dictionary<string, object?>
        {
            ["delegates"] = new Dictionary<string, object?>
            {
                [IdsConstants.DelegateService] = new Dictionary<string, object?>
                {
                    ["protocol-version"] = "4",
                },
            },
        };
        var body = AppleXmlPlist.ToXmlBytes(bodyDict);

        using var request = new HttpRequestMessage(HttpMethod.Post, IdsConstants.SigninV2Url);
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", AppleHttpExtensions.BasicAuth(session.AppleId, pet));
        if (!string.IsNullOrEmpty(session.Adsid))
            request.Headers.TryAddWithoutValidation("X-Apple-ADSID", session.Adsid);
        request.ApplyAuthKitIphoneGsHeaders(anisette);
        if (!string.IsNullOrEmpty(anisette.MmeDeviceId))
            request.Headers.TryAddWithoutValidation("X-Mme-Device-Id", anisette.MmeDeviceId);
        if (!string.IsNullOrEmpty(nasQualifyB64))
            request.Headers.TryAddWithoutValidation("X-Mme-Nas-Qualify", nasQualifyB64);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-apple-plist");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        var unzipped = IdsSigning.TryGunzip(bytes) ?? bytes;
        log?.Invoke($"signin/v2 HTTP {(int)response.StatusCode}, body={unzipped.Length} B");

        return ParseDelegateResponse(unzipped, "signin/v2");
    }

    private async Task<IdsDelegateResult> LoginDelegatesAsync(
        ICloudSession session,
        string pet,
        AnisetteHeaders anisette,
        string? nasQualifyB64,
        Action<string>? log,
        CancellationToken ct)
    {
        var bodyDict = new Dictionary<string, object?>
        {
            ["apple-id"] = session.AppleId,
            ["client-id"] = Guid.NewGuid().ToString().ToUpperInvariant(),
            ["delegates"] = new Dictionary<string, object?>
            {
                [IdsConstants.DelegateService] = new Dictionary<string, object?>
                {
                    ["protocol-version"] = "4",
                },
            },
            ["password"] = pet,
        };
        var body = AppleXmlPlist.ToXmlBytes(bodyDict);

        using var request = new HttpRequestMessage(HttpMethod.Post, IdsConstants.LoginDelegatesUrl);
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", AppleHttpExtensions.BasicAuth(session.AppleId, pet));
        request.ApplyAuthKitIphoneGsHeaders(anisette);
        if (!string.IsNullOrEmpty(anisette.MmeDeviceId))
            request.Headers.TryAddWithoutValidation("X-Mme-Device-Id", anisette.MmeDeviceId);
        if (!string.IsNullOrEmpty(nasQualifyB64))
            request.Headers.TryAddWithoutValidation("X-Mme-Nas-Qualify", nasQualifyB64);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-apple-plist");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        var unzipped = IdsSigning.TryGunzip(bytes) ?? bytes;
        log?.Invoke($"loginDelegates HTTP {(int)response.StatusCode}, body={unzipped.Length} B");

        return ParseDelegateResponse(unzipped, "loginDelegates");
    }

    private static IdsDelegateResult ParseDelegateResponse(byte[] plistBytes, string source)
    {
        Dictionary<string, object?> root;
        try
        {
            root = AppleXmlPlist.Parse(plistBytes);
        }
        catch (Exception ex)
        {
            var preview = Encoding.UTF8.GetString(plistBytes);
            if (preview.Length > 240)
                preview = preview[..240] + "…";
            throw new InvalidOperationException($"{source}: plist non valido ({ex.Message}): {preview}");
        }

        var outerStatus = AppleXmlPlist.GetInt(root, "status");
        if (outerStatus is not null and not 0)
            throw new InvalidOperationException($"{source}: status={outerStatus}");

        if (!root.TryGetValue("delegates", out var delegatesObj)
            || delegatesObj is not Dictionary<string, object?> delegates)
        {
            throw new InvalidOperationException($"{source}: manca delegates. Chiavi: {string.Join(", ", root.Keys)}");
        }

        if (!delegates.TryGetValue(IdsConstants.DelegateService, out var idsObj)
            || idsObj is not Dictionary<string, object?> idsDelegate)
        {
            throw new InvalidOperationException($"{source}: manca {IdsConstants.DelegateService}");
        }

        var idsStatus = AppleXmlPlist.GetInt(idsDelegate, "status");
        if (idsStatus is not null and not 0)
            throw new InvalidOperationException($"{source}: IDS delegate status={idsStatus}");

        Dictionary<string, object?> serviceData;
        if (idsDelegate.TryGetValue("service-data", out var sd) && sd is Dictionary<string, object?> sdDict)
            serviceData = sdDict;
        else
            serviceData = idsDelegate;

        var profileId =
            AppleXmlPlist.GetString(serviceData, "realm-user-id")
            ?? AppleXmlPlist.GetString(serviceData, "profile-id")
            ?? AppleXmlPlist.GetString(idsDelegate, "realm-user-id")
            ?? AppleXmlPlist.GetString(idsDelegate, "profile-id");

        var authToken =
            AppleXmlPlist.GetString(serviceData, "auth-token")
            ?? AppleXmlPlist.GetString(idsDelegate, "auth-token");

        if (string.IsNullOrWhiteSpace(profileId) || string.IsNullOrWhiteSpace(authToken))
        {
            throw new InvalidOperationException(
                $"{source}: profile-id/auth-token assenti. Chiavi service-data: "
                + string.Join(", ", serviceData.Keys));
        }

        return new IdsDelegateResult(profileId!, authToken!, source);
    }

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
}

public sealed record IdsDelegateResult(string ProfileId, string AuthToken, string Source);
