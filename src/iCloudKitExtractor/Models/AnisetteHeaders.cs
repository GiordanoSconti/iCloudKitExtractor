using System.Globalization;

namespace iCloudKitExtractor.Models;

public sealed class AnisetteHeaders
{
    /// <summary>
    /// Oltre questo age il Client-Time è considerato stallo: si aggiorna il clock (no remint).
    /// Remint vero solo su login / SMS request / 401 Apple.
    /// </summary>
    public static readonly TimeSpan SoftStaleAfter = TimeSpan.FromMinutes(3);

    public string Md { get; set; } = string.Empty;
    public string MdM { get; set; } = string.Empty;
    /// <summary>Local user UUID from ADI provisioning — must match MD-M (remote anisette).</summary>
    public string MdLu { get; set; } = string.Empty;
    public string MdRinfo { get; set; } = string.Empty;
    public string SerialNumber { get; set; } = string.Empty;
    /// <summary>Full X-MMe-Client-Info from remote anisette (must match MD-M provisioning).</summary>
    public string ClientMmeInfo { get; set; } = string.Empty;
    public string MmeDeviceId { get; set; } = string.Empty;
    public string ClientProductType { get; set; } = string.Empty;
    public string ClientTimeUtc { get; set; } = string.Empty;
    public string Locale { get; set; } = string.Empty;
    public string TimeZone { get; set; } = string.Empty;
    public string CountryCode { get; set; } = string.Empty;

    public bool HasMachineData =>
        !string.IsNullOrEmpty(Md) && !string.IsNullOrEmpty(MdM);

    /// <summary>
    /// Aggiorna solo Client-Time (MD invariata). Necessario: la sessione tiene Anisette
    /// congelata al login e CloudKit rifiuta richieste con skew &gt; pochi minuti (401).
    /// </summary>
    public void TouchClientTimeUtc() =>
        ClientTimeUtc = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'",
            CultureInfo.InvariantCulture);

    /// <summary>True se Client-Time manca o è più vecchio di <see cref="SoftStaleAfter"/>.</summary>
    public bool IsClientTimeStale(TimeSpan? maxAge = null)
    {
        var limit = maxAge ?? SoftStaleAfter;
        if (string.IsNullOrWhiteSpace(ClientTimeUtc))
            return true;
        if (!DateTime.TryParse(
                ClientTimeUtc,
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var t))
            return true;
        return DateTime.UtcNow - t > limit;
    }

    /// <summary>Se ha MD/MD-M, aggiorna Client-Time quando stallo. False se manca machine data.</summary>
    public bool TryReuseTouchingClientTime()
    {
        if (!HasMachineData)
            return false;
        if (IsClientTimeStale())
            TouchClientTimeUtc();
        return true;
    }
}
