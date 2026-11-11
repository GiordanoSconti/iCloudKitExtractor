using System.Runtime.InteropServices;
using iCloudKitExtractor.Services.Auth;

namespace iCloudKitExtractor.Services.Http;

public static class AppleClientInfo
{
    /// <summary>AuthKit/akd session (validate, trusteddevice, authenticate, quota, GsService2 POST).</summary>
    public const string AuthKitAkdUserAgent = "CloudKit/829 (17A577)";

    /// <summary>Alias legacy.</summary>
    public const string CloudKitUserAgent = AuthKitAkdUserAgent;

    /// <summary>MidService provisioning HTTP (non login GsService2/lookup).</summary>
    public const string AkdUserAgent = "akd/1.0 CFNetwork/1404.0.5 Darwin/22.3.0";

    /// <summary>CloudKit daemon (lookup login, configurations/init, get_account_settings, mobileme plist).</summary>
    public const string CloudKitDaemonUserAgent = "CloudKit/482.30 (13G36)";

    /// <summary>Alias legacy (backup MMCS / CloudKitDaemon).</summary>
    public const string MmcsUserAgent = CloudKitDaemonUserAgent;

    /// <summary>
    /// Photos Sync Data authorizeGet (<c>capture_syncdata_20260826_085315</c>):
    /// <c>cloudd/…</c> — non CloudKitDaemon (quello è backup iOS).
    /// </summary>
    public const string PhotosMmcsUserAgent =
        "cloudd/258 CFNetwork/718 Darwin/14.0.0 (x86_64)";

    /// <summary>com.apple.lakitu → escrowproxy (Keychain / PCS recovery).</summary>
    public const string LakituUserAgent =
        "com.apple.lakitu/1.0 CFNetwork/1404.0.5 Darwin/22.3.0";

    public const string CloudKitDaemonClientInfo =
        "<iPad3,3> <iPhone OS;11.1;13G36> <com.apple.cloudkit.CloudKitDaemon/482.30 (com.apple.cloudd/482.30)>";

    /// <summary>
    /// Photos edge GET + authorizeGet: <c>com.apple.icloud.content</c>.
    /// Usare CloudKitDaemon qui → edge 403 (signature/header mismatch).
    /// </summary>
    public const string PhotosMmcsClientInfo =
        "<MacBookAir3,2> <Mac OS X;10.10;14A343f> <com.apple.icloud.content/320 (com.apple.CloudKit/(null))>";

    public const string AuthKitIphoneClientInfo =
        "<iPhone9,3> <iPhone OS;12.4.1;16G102> <com.apple.AuthKit/1 (com.apple.akd/1.0)>";

    /// <summary>
    /// Find My Items: sblocca dataclass SearchParty + <c>searchPartyToken</c> in get_account_settings
    /// (CloudKitDaemon non li restituisce).
    /// </summary>
    public const string FindMyUserAgent = "FindMy/4.0 CFNetwork/1410.0.3 Darwin/22.6.0";

    public const string FindMyClientInfo =
        "<iPhone14,5> <iPhone OS;16.6;20G75> <com.apple.findmy/4.0 (com.apple.findmy/4.0)>";

    /// <summary>Identità coerente stile dadoum/Provision (test diagnostico AKD_IDENTITY_MODE=provision).</summary>
    public const string ProvisionClientInfo =
        "<iMac11,3> <Mac OS X;10.15.6;19G2021> <com.apple.AuthKit/1 (com.apple.dt.Xcode/3594.4.19)>";

    /// <summary>Windows Store / CoreADI: must match native AuthKitWin, not spoofed iOS (AltServer -22410 fix).</summary>
    public static string GetWindowsAuthKitClientInfo() =>
        AnisetteDeviceStore.BuildAuthKitWinClientInfo("PC");


    public static bool UseWindowsNativeGsa =>
        RuntimeInformation.IsOSPlatform(OSPlatform.Windows);
}
