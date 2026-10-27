using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Public stub: lab-only AUTHZ probes live in the private tree.
/// Enable flag is always off here so MainWindow call sites compile as no-ops.
/// </summary>
public static class OctagonAuthzProbeRunner
{
    public static bool IsEnabled => false;

    public static Task RunRecoverableForPeerMatrixAsync(
        OctagonCuttlefishService cuttlefish,
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        _ = (cuttlefish, session, outputDirectory, log, ct);
        return Task.CompletedTask;
    }
}
