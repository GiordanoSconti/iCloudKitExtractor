using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>Stile identità dichiarata nel cpd/header GSA.</summary>
public enum AdiIdentityStyle
{
    WindowsAuthKit,
    IosAkd,
    ProvisionCompat,
    IphoneCoherent
}

/// <summary>Identità ADI / client info per provisioning GSA MidService.</summary>
public sealed class AdiDeviceProfile
{
    public required string Name { get; init; }
    public required string ProvisioningSubdir { get; init; }
    public required string DeviceStoreFileName { get; init; }
    public required string ClientProductType { get; init; }
    public required string ProvisioningClientInfo { get; init; }
    public required ulong TargetRouting { get; init; }
    public required bool ForceTargetRouting { get; init; }
    public required AdiIdentityStyle IdentityStyle { get; init; }

    /// <summary>true per profili "classe iPhone/Provision" (routing 17106176, locale en-US).</summary>
    public bool IsIosClass => IdentityStyle != AdiIdentityStyle.WindowsAuthKit;

    public static AdiDeviceProfile Windows { get; } = new()
    {
        Name = "windows",
        ProvisioningSubdir = "adi",
        DeviceStoreFileName = "device.json",
        ClientProductType = "PC",
        ProvisioningClientInfo = AppleClientInfo.GetWindowsAuthKitClientInfo(),
        TargetRouting = GrandSlamCpdBuilder.WindowsMdRinfo,
        ForceTargetRouting = true,
        IdentityStyle = AdiIdentityStyle.WindowsAuthKit
    };

    /// <summary> AuthKit/akd iPhone9,3, MD-RINFO 17106176.</summary>
    public static AdiDeviceProfile IosAkd { get; } = new()
    {
        Name = "ios",
        ProvisioningSubdir = "adi-ios",
        DeviceStoreFileName = "device-ios.json",
        ClientProductType = "iPhone9,3",
        ProvisioningClientInfo = AppleClientInfo.AuthKitIphoneClientInfo,
        TargetRouting = GrandSlamCpdBuilder.IosMdRinfo,
        ForceTargetRouting = true,
        IdentityStyle = AdiIdentityStyle.IosAkd
    };

    /// <summary>
    /// Test diagnostico: identità coerente stile dadoum/Provision (Android + Xcode).
    /// Stessa crypto ADI Android ma client-info/serial/cpd coerenti → isola se il
    /// blocco -22410 è l'incoerenza akd↔Android o un bug del pipeline.
    /// </summary>
    public static AdiDeviceProfile ProvisionCompat { get; } = new()
    {
        Name = "provision",
        ProvisioningSubdir = "adi-provision",
        DeviceStoreFileName = "device-provision.json",
        ClientProductType = "iMac11,3",
        ProvisioningClientInfo = AppleClientInfo.ProvisionClientInfo,
        TargetRouting = GrandSlamCpdBuilder.IosMdRinfo,
        ForceTargetRouting = true,
        IdentityStyle = AdiIdentityStyle.ProvisionCompat
    };

    /// <summary>
    /// iPhone coerente: client-info/provisioning iPhone akd + struttura cpd "vincente"
    /// (cpd minimale, serial 0, MD-LU base64-UUID). Isola se la stringa akd/iPhone è
    /// rifiutata o se contava solo la coerenza cpd/serial/MD-LU — senza valori Mac/Xcode.
    /// </summary>
    public static AdiDeviceProfile IphoneCoherent { get; } = new()
    {
        Name = "iphone-coherent",
        ProvisioningSubdir = "adi-iphone-coherent",
        DeviceStoreFileName = "device-iphone-coherent.json",
        ClientProductType = "iPhone9,3",
        ProvisioningClientInfo = AppleClientInfo.AuthKitIphoneClientInfo,
        TargetRouting = GrandSlamCpdBuilder.IosMdRinfo,
        ForceTargetRouting = true,
        IdentityStyle = AdiIdentityStyle.IphoneCoherent
    };

    /// <summary>
    /// Profilo iOS attivo via AKD_IDENTITY_MODE:
    /// <c>iphone-coherent</c> (default — cpd minimale vincente con ADI Android),
    /// <c>akd</c> (cpd pieno), <c>provision</c> (stile Xcode/Mac).
    /// </summary>
    public static AdiDeviceProfile Ios => ResolveIdentityMode() switch
    {
        "akd" => IosAkd,
        "provision" => ProvisionCompat,
        "mac" => ProvisionCompat,
        "xcode" => ProvisionCompat,
        _ => IphoneCoherent
    };

    public static string ResolveIdentityMode()
    {
        var raw = (Environment.GetEnvironmentVariable("AKD_IDENTITY_MODE") ?? "iphone-coherent")
            .Trim().ToLowerInvariant();
        return raw switch
        {
            "akd" or "ios" or "ios-akd" => "akd",
            "provision" or "mac" or "xcode" => "provision",
            _ => "iphone-coherent"
        };
    }
}
