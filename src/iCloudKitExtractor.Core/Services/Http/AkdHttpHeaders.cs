using System.Net.Http;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Http;

public static class AkdHttpHeaders
{
    public static string ResolveAkdClientInfo(AnisetteHeaders anisette) =>
        !string.IsNullOrEmpty(anisette.ClientMmeInfo)
            ? anisette.ClientMmeInfo
            : AppleClientInfo.AuthKitIphoneClientInfo;

    /// <summary>
    /// MidService provisioning — akd headers, no X-Apple-I-MD* su HTTP.
    /// (GsService2/lookup login usa CloudKit daemon: ApplySetupICloudHeaders.)
    /// </summary>
    public static void ApplyAkdProvisioningHeaders(this HttpRequestMessage request, AnisetteHeaders anisette)
    {
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.AkdUserAgent);
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", ResolveAkdClientInfo(anisette));
        if (!string.IsNullOrEmpty(anisette.MmeDeviceId))
            request.Headers.TryAddWithoutValidation("X-Mme-Device-Id", anisette.MmeDeviceId);
        if (!string.IsNullOrEmpty(anisette.MdLu))
            request.Headers.TryAddWithoutValidation("X-Apple-I-MD-LU", anisette.MdLu);
        request.Headers.TryAddWithoutValidation("X-Apple-Client-App-Name", "Setup");
        request.Headers.TryAddWithoutValidation("X-Apple-I-Client-Time", anisette.ClientTimeUtc);
        if (!string.IsNullOrEmpty(anisette.SerialNumber))
            request.Headers.TryAddWithoutValidation("X-Apple-I-SRL-NO", anisette.SerialNumber);
    }
}
