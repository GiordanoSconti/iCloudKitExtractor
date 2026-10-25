using System.Globalization;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Provider Anisette tramite CoreADI / worker ADI + provisioning GSA.
/// </summary>
public sealed class CoreAdiAnisetteProvider : IAnisetteProvider
{
    private readonly AdiProvisioningService _provisioning;
    private readonly AnisetteDeviceStore _deviceStore;

    public CoreAdiAnisetteProvider(HttpClient http, AdiDeviceProfile? profile = null, IAdiCryptoClient? crypto = null)
    {
        var resolved = profile ?? AdiDeviceProfile.Windows;
        _provisioning = new AdiProvisioningService(http, resolved, crypto);
        // Stesso store del provisioning — evita adi_id stale dopo POST /provision.
        _deviceStore = _provisioning.DeviceStore;
    }

    public AdiProvisioningService Provisioning => _provisioning;

    public async Task<AnisetteHeaders> FetchAsync(CancellationToken ct = default)
    {
        _deviceStore.InvalidateCache();
        AdiOtpHeaderResult otp;
        try
        {
            // ADI già provisionata → solo ADIOTPRequest (OTP fresco, stesso MD-M).
            // Se non provisionata, RequestOtpHeadersAsync fa MidService prima.
            otp = await _provisioning.RequestOtpHeadersAsync(ct).ConfigureAwait(false);
        }
        catch (Exception first) when (IsRecoverableOtpFailure(first))
        {
            // Sessione ADI morta ma device identity ok → soft MidService forzato, poi OTP.
            await _provisioning.RepairProvisioningAsync(ct, forceMidService: true)
                .ConfigureAwait(false);
            otp = await _provisioning.RequestOtpHeadersAsync(ct).ConfigureAwait(false);
        }

        if (string.IsNullOrEmpty(otp.Md) || string.IsNullOrEmpty(otp.MdM) || string.IsNullOrEmpty(otp.MdRinfo))
            throw new InvalidOperationException("CoreADI non ha restituito header Anisette completi.");

        var culture = _deviceStore.Profile.IsIosClass
            ? CultureInfo.GetCultureInfo("en-US")
            : CultureInfo.CurrentUICulture;
        RegionInfo region;
        try
        {
            region = new RegionInfo(culture.Name);
        }
        catch
        {
            region = new RegionInfo("US");
        }

        return new AnisetteHeaders
        {
            Md = otp.Md,
            MdM = otp.MdM,
            MdLu = _deviceStore.GetOrCreateLocalUserUuid(),
            MdRinfo = _provisioning.Profile.IsIosClass
                ? GrandSlamCpdBuilder.IosMdRinfo.ToString(CultureInfo.InvariantCulture)
                : otp.MdRinfo,
            ClientMmeInfo = _deviceStore.GetProvisioningClientInfo(),
            MmeDeviceId = _deviceStore.GetOrCreateDeviceUuid(),
            ClientTimeUtc = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
            SerialNumber = _deviceStore.GetOrCreateSerialNumber(),
            ClientProductType = _deviceStore.GetOrCreateClientProductType(),
            Locale = culture.Name.Replace('-', '_'),
            TimeZone = TimeZoneInfo.Local.Id,
            CountryCode = region.TwoLetterISORegionName
        };
    }

    private static bool IsRecoverableOtpFailure(Exception ex)
    {
        var msg = ex.Message ?? "";
        // Worker down / ADI session rotta / not provisioned race — soft MidService può riparare.
        return msg.Contains("request-otp", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("not provisioned", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("ADI worker", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("Connection refused", StringComparison.OrdinalIgnoreCase)
               || ex.InnerException is not null && IsRecoverableOtpFailure(ex.InnerException);
    }
}
