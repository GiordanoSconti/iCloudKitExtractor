namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Opzioni per-request verso un <see cref="IAnisetteProvider"/>.
/// Per backend RAD, <see cref="AppleId"/> (email o MD5 hex) è obbligatorio.
/// </summary>
public sealed class AnisetteFetchOptions
{
    /// <summary>Apple ID email (es. user@icloud.com) oppure MD5 hex 32 char.</summary>
    public string? AppleId { get; init; }

    /// <summary>
    /// Bypassa cache provider e richiede un mint OTP nuovo (stesso MD+Client-Time).
    /// Obbligatorio per GsService2 init/re-login: riusare MD con Client-Time avanzato → Apple ec=-22410.
    /// </summary>
    public bool ForceFresh { get; init; }

    public static AnisetteFetchOptions? ForAppleId(string? appleId) =>
        string.IsNullOrWhiteSpace(appleId) ? null : new AnisetteFetchOptions { AppleId = appleId.Trim() };

    /// <summary>Mint fresco per SignIn / re-login GrandSlam (anti -22410).</summary>
    public static AnisetteFetchOptions ForGrandSlamLogin(string? appleId) =>
        new()
        {
            AppleId = string.IsNullOrWhiteSpace(appleId) ? null : appleId.Trim(),
            ForceFresh = true,
        };
}
