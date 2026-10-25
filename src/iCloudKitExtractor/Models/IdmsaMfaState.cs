namespace iCloudKitExtractor.Models;

/// <summary>
/// Sessione idmsa per MFA SMS (signin/init + signin/complete), come iCloudDownloader.
/// </summary>
public sealed class IdmsaMfaState
{
    public Dictionary<string, string> Cookies { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    public string? Scnt { get; set; }
    public string? SessionId { get; set; }
    public string? AuthAttributes { get; set; }
    public string AccountCountryCode { get; set; } = "ITA";
    public bool SmsRequested { get; set; }

    public string? SessionToken { get; set; }
    public string? TrustToken { get; set; }

    /// <summary>HTTP status di <c>signin/complete</c> (200/204 ok, 409 = 2FA web ancora richiesto).</summary>
    public int? LastSignInCompleteStatus { get; set; }
}
