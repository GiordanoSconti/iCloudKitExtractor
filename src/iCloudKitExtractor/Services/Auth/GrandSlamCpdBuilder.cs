using System.Globalization;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

public static class GrandSlamCpdBuilder
{
    /// <summary>Routing info for Windows native AuthKit (AltServer 1.7.3 / -22410 fix).</summary>
    public const ulong WindowsMdRinfo = 84215040UL;

    /// <summary>iOS AuthKit / akd .</summary>
    public const ulong IosMdRinfo = 17106176UL;

    public static Dictionary<string, object?> Build(AnisetteHeaders anisette) =>
        Build(anisette, AdiDeviceProfile.Windows, pushTokenHex: null);

    public static Dictionary<string, object?> Build(AnisetteHeaders anisette, AdiDeviceProfile profile) =>
        Build(anisette, profile, pushTokenHex: null);

    /// <param name="pushTokenHex">
    /// APS push token (uppercase hex) for GSA <c>ptkn</c>. When null/empty, uses "0"
    /// (legacy). HSA2 push OTP requires a real connected APS token.
    /// </param>
    public static Dictionary<string, object?> Build(
        AnisetteHeaders anisette,
        AdiDeviceProfile profile,
        string? pushTokenHex)
    {
        var deviceStore = new AnisetteDeviceStore(profile);
        var style = profile.IdentityStyle;
        var rinfo = profile.IsIosClass ? IosMdRinfo : ResolveWindowsMdRinfo(anisette.MdRinfo);
        var mdLu = !string.IsNullOrEmpty(anisette.MdLu)
            ? anisette.MdLu
            : deviceStore.GetOrCreateLocalUserUuid();
        var ptkn = NormalizePushTokenHex(pushTokenHex);

        // Minimal "winning" cpd style (dadoum/Provision). IphoneCoherent = same shape, iPhone client-info.
        if (style is AdiIdentityStyle.ProvisionCompat or AdiIdentityStyle.IphoneCoherent)
        {
            return new Dictionary<string, object?>
            {
                ["X-Apple-I-Client-Time"] = anisette.ClientTimeUtc,
                ["X-Apple-I-TimeZone"] = anisette.TimeZone,
                ["X-Apple-Locale"] = anisette.Locale,
                ["loc"] = anisette.Locale,
                ["X-Apple-I-MD"] = anisette.Md,
                ["X-Apple-I-MD-M"] = anisette.MdM,
                ["X-Apple-I-MD-RINFO"] = rinfo,
                ["X-Apple-I-MD-LU"] = mdLu,
                ["X-Mme-Device-Id"] = !string.IsNullOrEmpty(anisette.MmeDeviceId)
                    ? anisette.MmeDeviceId
                    : deviceStore.GetOrCreateDeviceUuid(),
                ["X-Apple-I-SRL-NO"] = "0",
                ["bootstrap"] = true,
                ["icscrec"] = true,
                ["pbe"] = false,
                ["prkgen"] = true,
                ["ptkn"] = ptkn,
                ["svct"] = "iCloud"
            };
        }

        var isIos = style == AdiIdentityStyle.IosAkd;
        var serial = ResolveSerialNumber(anisette, deviceStore, isIos);

        var cpd = new Dictionary<string, object?>
        {
            ["X-Apple-I-Client-Time"] = anisette.ClientTimeUtc,
            ["X-Apple-I-MD"] = anisette.Md,
            ["X-Apple-I-MD-M"] = anisette.MdM,
            ["X-Apple-I-MD-RINFO"] = rinfo,
            ["X-Apple-I-MD-LU"] = mdLu,
            ["X-Apple-I-SRL-NO"] = serial,
            ["X-Apple-Locale"] = anisette.Locale,
            ["X-Apple-I-TimeZone"] = anisette.TimeZone,
            ["X-Apple-I-Device-Configuration-Mode"] = "0",
            ["bootstrap"] = true,
            ["ckgen"] = true,
            ["icscrec"] = true,
            ["loc"] = anisette.Locale,
            ["cou"] = anisette.CountryCode,
            ["at"] = 1,
            ["capp"] = isIos ? "com.apple.akd" : "com.apple.AuthKitWin",
            ["dc"] = isIos ? "#000000" : "#e4c1b9b9c0",
            ["dec"] = isIos ? "#000000" : "#e4e7e8ea",
            ["pbe"] = false,
            ["prkgen"] = true,
            ["prtn"] = isIos ? profile.ClientProductType : "PC",
            ["ptkn"] = ptkn,
            ["svct"] = "iCloud"
        };

        cpd["X-Mme-Device-Id"] = !string.IsNullOrEmpty(anisette.MmeDeviceId)
            ? anisette.MmeDeviceId
            : deviceStore.GetOrCreateDeviceUuid();

        return cpd;
    }

    private static string NormalizePushTokenHex(string? pushTokenHex)
    {
        if (string.IsNullOrWhiteSpace(pushTokenHex))
            return "0";
        var t = pushTokenHex.Trim();
        if (t.Equals("0", StringComparison.Ordinal))
            return "0";
        // GSA expects uppercase hex without spaces.
        return t.Replace(" ", "", StringComparison.Ordinal).ToUpperInvariant();
    }

    public static string FormatMdRinfo(string mdRinfo) =>
        ResolveWindowsMdRinfo(mdRinfo).ToString(CultureInfo.InvariantCulture);

    private static string ResolveSerialNumber(
        AnisetteHeaders anisette,
        AnisetteDeviceStore deviceStore,
        bool isIos)
    {
        // Anisette remota con MD-LU: serial esatto dal server (spesso "0" su docker).
        if (isIos && !string.IsNullOrEmpty(anisette.MdLu))
            return string.IsNullOrEmpty(anisette.SerialNumber) ? "0" : anisette.SerialNumber;
        if (!string.IsNullOrEmpty(anisette.SerialNumber) && anisette.SerialNumber != "0")
            return anisette.SerialNumber;
        return deviceStore.GetOrCreateSerialNumber();
    }

    private static ulong ResolveWindowsMdRinfo(string mdRinfo)
    {
        if (ulong.TryParse(mdRinfo, NumberStyles.Integer, CultureInfo.InvariantCulture, out var routing))
        {
            if (routing == IosMdRinfo)
                return WindowsMdRinfo;
            return routing;
        }

        return WindowsMdRinfo;
    }
}
