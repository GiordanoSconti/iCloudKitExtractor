namespace iCloudKitExtractor.Services.Ids;

internal static class IdsConstants
{
    public const string ProtocolVersion = "1660";
    public const string DelegateService = "com.apple.private.ids";
    public const string MultiplexService = "com.apple.private.alloy.multiplex1";
    /// <summary>iMessage / FaceTime IDS service name.</summary>
    public const string MadridService = "com.apple.madrid";
    public const string InvitationUserAgent =
        "com.apple.invitation-registration macOS,13.2.1,22D68";
    public const string LookupUserAgent =
        "com.apple.madrid-lookup macOS,13.2.1,22D68";

    /// <summary>APS topic for IDS HTTP-over-APNs control.</summary>
    public const string IdsHttpOverApnsTopic = "com.apple.private.ids";

    /// <summary>Madrid sub-services (Apple Wiki / modern clients).</summary>
    public static readonly string[] MadridSubServices =
    [
        "com.apple.private.alloy.sms",
        "com.apple.private.alloy.gelato",
        "com.apple.private.alloy.biz",
        "com.apple.private.alloy.gamecenter.imessage",
    ];

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
    /// <summary>IDS handle lookup (HTTP-over-APNs bag key <c>id-query</c>).</summary>
    public const string FallbackIdQuery =
        "https://query.ess.apple.com/WebObjects/QueryService.woa/wa/query";

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
