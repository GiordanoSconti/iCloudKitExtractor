using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// akd emulato: OTP via worker ADI (no CoreADI64).
/// MidService: C# (default) oppure Anisette.py se <c>AKD_OWNS_MIDSERVICE=1</c>.
/// Profilo da AKD_IDENTITY_MODE (default iphone-coherent).
/// </summary>
public sealed class EmulatedAkdAnisetteProvider : IAnisetteProvider
{
    public EmulatedAkdAnisetteProvider(HttpClient http, string adiWorkerUrl)
    {
        var profile = AdiDeviceProfile.Ios;
        var crypto = new HttpAdiCryptoClient(http, adiWorkerUrl, profile);
        Inner = new CoreAdiAnisetteProvider(http, profile, crypto);
    }

    internal CoreAdiAnisetteProvider Inner { get; }

    /// <summary>Rilegge device-*.json dopo POST /provision (evita adi_id stale in RAM).</summary>
    public void InvalidateDeviceCache() => Inner.Provisioning.InvalidateDeviceCache();

    public Task<AnisetteHeaders> FetchAsync(CancellationToken ct = default) =>
        Inner.FetchAsync(ct);
}
