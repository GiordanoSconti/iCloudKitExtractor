namespace iCloudKitExtractor.Services.Ids;

internal static class IdsConstants
{
    public const string ProtocolVersion = "1660";
    public const string DelegateService = "com.apple.private.ids";
    public const string MultiplexService = "com.apple.private.alloy.multiplex1";
    public const string InvitationUserAgent =
        "com.apple.invitation-registration macOS,13.2.1,22D68";

    public const string SigninV2Url = "https://setup.icloud.com/setup/signin/v2/login";
    public const string LoginDelegatesUrl =
        "https://setup.icloud.com/setup/iosbuddy/loginDelegates";
    public const string BagUrl =
        "https://init.ess.apple.com/WebObjects/VCInit.woa/wa/getBag?ix=3";

    public const string FallbackAuthenticateDs =
        "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/authenticateDS";
    // Bag ufficiale: profile.ess (NON identity.ess).
    public const string FallbackGetHandles =
        "https://profile.ess.apple.com/WebObjects/VCProfileService.woa/wa/idsGetHandles";
    public const string FallbackRegister =
        "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/register";

    public static readonly string[] FindMySubServices =
    [
        "com.apple.private.alloy.fmf",
        "com.apple.private.alloy.fmd",
        "com.apple.private.alloy.status.keysharing",
        "com.apple.private.alloy.status.personal",
        "com.apple.private.alloy.findmy.itemsharing-crossaccount",
        "com.apple.private.alloy.kcsharing.invite",
    ];
}
