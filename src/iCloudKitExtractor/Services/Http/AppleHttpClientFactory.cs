using System.Net;
using System.Net.Http;
using System.Net.Security;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Auth;

namespace iCloudKitExtractor.Services.Http;

public sealed class AppleHttpClientFactory
{
    public HttpSessionCapture? Capture { get; set; }
    public Action<string>? HttpLogLine { get; set; }
    public CookieContainer Cookies { get; } = new();

    public HttpClient Create() => Create(useCookies: true);

    /// <summary>
    /// Client per idmsa: <c>UseCookies=false</c> così i <c>Set-Cookie</c> DES*/HSA
    /// restano leggibili negli header (il CookieContainer .NET li mangia altrimenti).
    /// </summary>
    public HttpClient CreateManualCookies() => Create(useCookies: false);

    public HttpClient Create(bool useCookies)
    {
        var handler = new SocketsHttpHandler
        {
            CookieContainer = Cookies,
            UseCookies = useCookies,
            MaxConnectionsPerServer = 32,
            AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
            SslOptions = new SslClientAuthenticationOptions
            {
                RemoteCertificateValidationCallback = AppleCertificateTrust.ValidateServerCertificate
            }
        };

        HttpMessageHandler pipeline = handler;
        if (Capture is not null || HttpLogLine is not null)
        {
            HttpTrafficLogger? legacy = HttpLogLine is not null
                ? new HttpTrafficLogger(null, HttpLogLine)
                : null;
            pipeline = Capture is not null
                ? legacy is not null
                    ? new HttpLoggingHandler(Capture, legacy, handler)
                    : new HttpLoggingHandler(Capture, handler)
                : new HttpLoggingHandler(legacy!, handler);
        }

        return new HttpClient(pipeline)
        {
            Timeout = TimeSpan.FromMinutes(30)
        };
    }
}

public static class AppleHttpExtensions
{
    public static void ApplySetupICloudHeaders(this HttpRequestMessage request) =>
        request.ApplyCloudKitDaemon(acceptStar: true);

    public static void ApplyWindowsGsaHeaders(this HttpRequestMessage request, string deviceUuid)
    {
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.CloudKitUserAgent);
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", AppleClientInfo.GetWindowsAuthKitClientInfo());
        request.Headers.TryAddWithoutValidation("X-Mme-Device-Id", deviceUuid);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        request.Headers.TryAddWithoutValidation("Accept-Language", "en-US");
    }

    public static void ApplyWindowsAuthKitHeaders(this HttpRequestMessage request, AnisetteHeaders anisette, string deviceUuid)
    {
        request.ApplyWindowsGsaHeaders(deviceUuid);
        request.ApplyAnisetteHeaders(anisette);
    }

    public static void ApplyAnisetteHeaders(this HttpRequestMessage request, AnisetteHeaders anisette, bool iosRouting = false)
    {
        request.Headers.TryAddWithoutValidation("X-Apple-I-Client-Time", anisette.ClientTimeUtc);
        request.Headers.TryAddWithoutValidation("X-Apple-I-Locale", anisette.Locale);
        request.Headers.TryAddWithoutValidation("X-Apple-I-MD-M", anisette.MdM);
        request.Headers.TryAddWithoutValidation("X-Apple-I-MD", anisette.Md);
        var rinfo = iosRouting
            ? GrandSlamCpdBuilder.IosMdRinfo.ToString(System.Globalization.CultureInfo.InvariantCulture)
            : GrandSlamCpdBuilder.FormatMdRinfo(anisette.MdRinfo);
        request.Headers.TryAddWithoutValidation("X-Apple-I-MD-RINFO", rinfo);
    }

    /// <summary>post-validate: AuthKit/akd iPhone, no X-Mme-Device-Id.</summary>
    public static void ApplyAuthKitIphoneGsHeaders(this HttpRequestMessage request, AnisetteHeaders anisette) =>
        request.ApplyAuthKitAkdAnisette(anisette);

    /// <summary>GsService2 init/complete — solo sessione Windows CoreADI (evita -22410).</summary>
    public static void ApplyGsService2WindowsHeaders(
        this HttpRequestMessage request,
        AnisetteHeaders anisette,
        string deviceUuid)
    {
        request.ApplyWindowsAuthKitHeaders(anisette, deviceUuid);
    }

    /// <summary>
    /// GsService2 init/complete POST — AuthKit/akd iPhone.
    /// Anisette solo nel cpd plist, non su HTTP (capture 0008/0011).
    /// </summary>
    public static void ApplyGsService2Headers(this HttpRequestMessage request, AnisetteHeaders anisette)
    {
        request.ApplyAuthKitAkdIdentity(anisette);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
    }

    public static void ApplyTrustedDeviceHeaders(this HttpRequestMessage request, AnisetteHeaders anisette)
    {
        request.ApplyAuthKitIphoneGsHeaders(anisette);
        request.Headers.TryAddWithoutValidation("Accept", "application/json; q=0.01");
    }

    public static void ApplyTrustedDeviceWindowsHeaders(
        this HttpRequestMessage request,
        AnisetteHeaders anisette,
        string deviceUuid)
    {
        request.ApplyWindowsAuthKitHeaders(anisette, deviceUuid);
        request.Headers.TryAddWithoutValidation("Accept", "application/json; q=0.01");
    }

    public static void ApplyGsValidateWindowsHeaders(
        this HttpRequestMessage request,
        AnisetteHeaders anisette,
        string deviceUuid)
    {
        request.ApplyWindowsAuthKitHeaders(anisette, deviceUuid);
        request.Headers.TryAddWithoutValidation("Accept", "application/json, text/javascript, */*; q=0.01");
    }

    public static void ApplyGsValidateHeaders(this HttpRequestMessage request, AnisetteHeaders anisette)
    {
        request.ApplyAuthKitIphoneGsHeaders(anisette);
        request.Headers.TryAddWithoutValidation("Accept", "application/json, text/javascript, */*; q=0.01");
    }

    /// <summary>GSA verify/phone — piggybacking + JSON (POST/PUT, capture 140406).</summary>
    public static void ApplyPhoneVerifyHeaders(
        this HttpRequestMessage request,
        AnisetteHeaders anisette,
        bool iphoneAuth,
        string? windowsDeviceUuid = null)
    {
        if (iphoneAuth)
            request.ApplyAuthKitIphoneGsHeaders(anisette);
        else if (!string.IsNullOrWhiteSpace(windowsDeviceUuid))
            request.ApplyWindowsAuthKitHeaders(anisette, windowsDeviceUuid);
        else
            request.ApplyAnisetteHeaders(anisette);

        request.Headers.TryAddWithoutValidation("Accept", "application/json, text/javascript, */*; q=0.01");
        request.Headers.TryAddWithoutValidation("X-Apple-AK-Context-Type", "piggybacking");
    }

    public static void ApplyCloudKitHeaders(
        this HttpRequestMessage request,
        ICloudSession session,
        string operationId,
        string? requestUuid = null,
        CloudKitContainerBinding? container = null)
    {
        // Evita Client-Time congelato al login (run 173715: 3 valori su 936 req → 401 a raffica).
        session.Anisette.TouchClientTimeUtc();
        var binding = container ?? CloudKitContainerBinding.Backup;

        request.ApplyAuthKitAkdIdentity(session.Anisette);
        request.Headers.TryAddWithoutValidation("X-CloudKit-DatabaseScope", "Private");
        request.Headers.TryAddWithoutValidation("X-CloudKit-BundleId", binding.BundleId);
        request.Headers.TryAddWithoutValidation("X-CloudKit-ContainerId", binding.ContainerId);
        request.Headers.TryAddWithoutValidation("X-CloudKit-UserId", session.CloudKitUserId);
        request.Headers.TryAddWithoutValidation("X-CloudKit-AuthToken", session.CloudKitAuthToken);
        request.Headers.TryAddWithoutValidation("x-apple-environment", "Production");
        request.Headers.TryAddWithoutValidation("x-apple-c2-metric-triggers", "0");
        request.Headers.TryAddWithoutValidation("cache-control", "no-transform");
        request.Headers.TryAddWithoutValidation("accept-language", "en-us");
        request.Headers.TryAddWithoutValidation("x-apple-operation-group-id", Guid.NewGuid().ToString("N")[..16].ToUpperInvariant());
        request.Headers.TryAddWithoutValidation("x-apple-operation-id", operationId);
        request.Headers.TryAddWithoutValidation("X-Apple-Request-UUID", requestUuid ?? Guid.NewGuid().ToString());
        request.Headers.Accept.Add(new System.Net.Http.Headers.MediaTypeWithQualityHeaderValue("application/x-protobuf"));
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);
    }

    public static string BasicAuth(string user, string token) =>
        Convert.ToBase64String(System.Text.Encoding.UTF8.GetBytes($"{user}:{token}"));
}
