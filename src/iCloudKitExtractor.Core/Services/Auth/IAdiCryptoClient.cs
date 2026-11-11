namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Operazioni crittografiche ADI (spim→cpim, ptm/tk→stato, OTP).
/// Implementazioni: CoreADI Windows (bridge nativo) o worker akd emulato (HTTP).
/// </summary>
public interface IAdiCryptoClient
{
    bool RequiresWindowsCoreAdiRuntime { get; }

    /// <summary>
    /// True = MidService HTTP lo fa la libreria ADI (Anisette.py), non AdiProvisioningService C#.
    /// </summary>
    bool OwnsMidServiceHttp { get; }

    /// <summary>Provisioning MidService gestito dal backend crypto (es. Anisette.provision).</summary>
    Task WipeLibraryProvisioningAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        CancellationToken ct = default);

    Task ProvisionViaLibraryAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        long dsId = AdiProvisioningService.GrandSlamDsId,
        CancellationToken ct = default);

    Task<bool> IsProvisionedAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        long dsId = AdiProvisioningService.GrandSlamDsId,
        CancellationToken ct = default);

    Task<AdiStartProvisioningResult> StartProvisioningAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        byte[] spim,
        long dsId = AdiProvisioningService.GrandSlamDsId,
        CancellationToken ct = default);

    Task EndProvisioningAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        uint session,
        byte[] ptm,
        byte[] tk,
        CancellationToken ct = default);

    Task DestroySessionAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        uint session,
        CancellationToken ct = default);

    Task SetRoutingAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        ulong routingInfo,
        long dsId = AdiProvisioningService.GrandSlamDsId,
        CancellationToken ct = default);

    Task<AdiOtpHeaderResult> RequestOtpAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        long dsId = AdiProvisioningService.GrandSlamDsId,
        CancellationToken ct = default);
}

public sealed record AdiStartProvisioningResult(uint Session, byte[] Cpim);

public sealed record AdiOtpHeaderResult(string Md, string MdM, string MdRinfo);
