namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Opzioni per-request verso un <see cref="IAnisetteProvider"/>.
/// Per backend RAD, <see cref="AppleId"/> (email o MD5 hex) è obbligatorio.
/// </summary>
public sealed class AnisetteFetchOptions
{
    /// <summary>Header middleware: <c>X-IKE-Anisette-Phase</c>.</summary>
    public const string PhaseHeaderName = "X-IKE-Anisette-Phase";
    public const string PhaseLogin = "login";
    public const string PhaseSession = "session";

    /// <summary>Apple ID email (es. user@icloud.com) oppure MD5 hex 32 char.</summary>
    public string? AppleId { get; init; }

    /// <summary>
    /// Bypassa cache provider e richiede un mint OTP nuovo (stesso MD+Client-Time).
    /// Obbligatorio per GsService2 init/re-login: riusare MD con Client-Time avanzato → Apple ec=-22410.
    /// </summary>
    public bool ForceFresh { get; init; }

    /// <summary>
    /// True solo per Accedi / GrandSlam (primo login). Il burst-limit middleware (&gt;10/10s)
    /// si applica a questa fase; i remint in download usano <see cref="ForSessionRemint"/>.
    /// </summary>
    public bool LoginPhase { get; init; }

    public static AnisetteFetchOptions? ForAppleId(string? appleId) =>
        string.IsNullOrWhiteSpace(appleId)
            ? null
            : new AnisetteFetchOptions { AppleId = appleId.Trim(), LoginPhase = false };

    /// <summary>Mint fresco per SignIn / Accedi GrandSlam (anti -22410) — soggetto a burst-limit.</summary>
    public static AnisetteFetchOptions ForGrandSlamLogin(string? appleId) =>
        new()
        {
            AppleId = string.IsNullOrWhiteSpace(appleId) ? null : appleId.Trim(),
            ForceFresh = true,
            LoginPhase = true,
        };

    /// <summary>Mint fresco mid-session (401 CloudKit / OTP) — niente burst-limit Accedi.</summary>
    public static AnisetteFetchOptions ForSessionRemint(string? appleId) =>
        new()
        {
            AppleId = string.IsNullOrWhiteSpace(appleId) ? null : appleId.Trim(),
            ForceFresh = true,
            LoginPhase = false,
        };
}
