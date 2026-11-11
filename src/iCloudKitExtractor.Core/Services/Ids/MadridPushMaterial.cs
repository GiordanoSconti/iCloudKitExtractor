using System.IO;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Push identity used for Madrid register / lookup / courier.
/// Prefer Frida iPhone APSClientIdentity when present; else Albert.
/// </summary>
public static class MadridPushMaterial
{
    public static bool TryResolveIphone(
        out byte[] pushToken,
        out string keyPem,
        out string certPem,
        out string detail)
    {
        pushToken = [];
        keyPem = "";
        certPem = "";
        detail = "";

        var iphone = IphoneIdsIdentityStore.TryLoad();
        var push = IphoneApsPushStore.TryLoad();
        if (iphone?.PushTokenHex is not { Length: >= 32 } hex || push is null)
        {
            detail = "iPhone APS material missing";
            return false;
        }

        try
        {
            var tok = Convert.FromHexString(hex.Trim());
            if (tok.Length < 16)
            {
                detail = "iPhone push token too short";
                return false;
            }

            pushToken = tok;
            keyPem = push.Value.KeyPem;
            certPem = push.Value.CertPem;
            detail = "iPhone APSClientIdentity token="
                     + ApsStorage.TokenHex(tok)[..Math.Min(16, ApsStorage.TokenHex(tok).Length)]
                     + "…";
            return true;
        }
        catch (Exception ex)
        {
            detail = "iPhone push parse: " + ex.Message;
            return false;
        }
    }

    public static (byte[] Token, string KeyPem, string CertPem, string Source) ResolveForMadrid()
    {
        if (TryResolveIphone(out var tok, out var key, out var cert, out var detail))
            return (tok, key, cert, detail);

        var albertTok = ApsStorage.TryLoadToken()
                        ?? throw new InvalidOperationException(
                            "APS push token missing — Connect APS (Albert) or capture iPhone APS.");
        var (k, c) = ApsStorage.LoadCertificate();
        return (albertTok, k, c, "Albert " + detail);
    }
}
