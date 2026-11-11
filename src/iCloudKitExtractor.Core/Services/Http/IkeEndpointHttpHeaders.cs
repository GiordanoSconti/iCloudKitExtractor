using System.Net.Http;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Auth;

namespace iCloudKitExtractor.Services.Http;

/// <summary>
/// Header HTTP per endpoint (User-Agent + X-MMe-Client-Info).
/// Riferimento capture capture_http_* / flusso akd iPhone.
/// </summary>
public static class IkeEndpointHttpHeaders
{
    /// <summary>
    /// CloudKit daemon (482.30): GsService2/lookup, configurations/init,
    /// get_account_settings, mobileme/content-1.0.plist.
    /// </summary>
    public static void ApplyCloudKitDaemon(this HttpRequestMessage request, bool acceptStar = false)
    {
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.CloudKitDaemonUserAgent);
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", AppleClientInfo.CloudKitDaemonClientInfo);
        request.Headers.TryAddWithoutValidation("Accept-Language", "en-US");
        if (acceptStar)
            request.Headers.TryAddWithoutValidation("Accept", "*/*");
    }

    /// <summary>
    /// AuthKit/akd (829): identità sessione senza X-Apple-I-MD* su HTTP (GsService2 init/complete POST).
    /// </summary>
    public static void ApplyAuthKitAkdIdentity(this HttpRequestMessage request, AnisetteHeaders? anisette = null)
    {
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.AuthKitAkdUserAgent);
        request.Headers.TryAddWithoutValidation(
            "X-MMe-Client-Info",
            anisette is null
                ? AppleClientInfo.AuthKitIphoneClientInfo
                : AkdHttpHeaders.ResolveAkdClientInfo(anisette));
        request.Headers.TryAddWithoutValidation("Accept-Language", "en-US");
    }

    /// <summary>
    /// AuthKit/akd (829) + anisette su HTTP: trusteddevice, GsService2/validate,
    /// security/devices, setup/authenticate, getQuotaInfo.
    /// </summary>
    public static void ApplyAuthKitAkdAnisette(this HttpRequestMessage request, AnisetteHeaders anisette)
    {
        request.ApplyAuthKitAkdIdentity(anisette);
        if (!string.IsNullOrEmpty(anisette.MdLu))
            request.Headers.TryAddWithoutValidation("X-Apple-I-MD-LU", anisette.MdLu);
        request.ApplyAnisetteHeaders(anisette, iosRouting: true);
    }
}
