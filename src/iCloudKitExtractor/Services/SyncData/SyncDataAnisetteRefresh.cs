using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Backup;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Refresh Anisette periodico mid-Sync-Data (come PrivilegedBatch nel Backup):
/// solo MD/OTP, niente ckAppInit.
/// </summary>
public sealed class SyncDataAnisetteRefresh
{
    /// <summary>
    /// Intervallo proattivo. 90 s: con download MMCS paralleli un refresh ogni 45 s
    /// serializzava inutilmente i worker.
    /// </summary>
    public static readonly TimeSpan Interval = TimeSpan.FromSeconds(90);

    private readonly CloudKitAssetService.SessionRefreshDelegate _refresh;
    private readonly CloudKitGatewayClient _gateway;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private DateTime _lastUtc = DateTime.MinValue;

    public SyncDataAnisetteRefresh(
        CloudKitAssetService.SessionRefreshDelegate refresh,
        CloudKitGatewayClient gateway)
    {
        _refresh = refresh;
        _gateway = gateway;
    }

    public async Task EnsureFreshAsync(
        ICloudSession session,
        IProgress<string>? log,
        CancellationToken ct,
        bool force = false)
    {
        // Fast-path senza lock se ancora fresco.
        if (!force && _lastUtc != DateTime.MinValue
            && DateTime.UtcNow - _lastUtc < Interval)
            return;

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (!force && _lastUtc != DateTime.MinValue
                && DateTime.UtcNow - _lastUtc < Interval)
                return;

            log?.Report(
                force
                    ? "  remint Anisette (force/401)…"
                    : $"  reuse Anisette periodico ({Interval.TotalSeconds:0}s)…");
            // force=true solo su 401; periodico = Client-Time / riuso sessione.
            await _refresh(session, log, ct, forceRemint: force).ConfigureAwait(false);
            _gateway.ClearUnauthorized();
            MarkFresh();
        }
        finally
        {
            _gate.Release();
        }
    }

    /// <summary>Segna Anisette già fresca (es. dopo refresh iniziale a inizio Sync Data).</summary>
    public void MarkFresh() => _lastUtc = DateTime.UtcNow;
}
