using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Lab-only negative probes for Cuttlefish recoverable TLK entitlement.
/// Enable with <c>IKE_AUTHZ_PROBES=1</c>. See <c>tools/octagon_authz_probes/</c>.
/// </summary>
public static class OctagonAuthzProbeRunner
{
    public static bool IsEnabled
    {
        get
        {
            var env = Environment.GetEnvironmentVariable("IKE_AUTHZ_PROBES");
            return !string.IsNullOrWhiteSpace(env)
                   && env is "1" or "true" or "TRUE" or "yes" or "YES";
        }
    }

    public static async Task RunRecoverableForPeerMatrixAsync(
        OctagonCuttlefishService cuttlefish,
        ICloudSession session,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (session.OctagonPeerEncryptionPkcs8 is not { Length: > 0 }
            || string.IsNullOrWhiteSpace(session.OctagonPeerId))
        {
            log?.Report("AUTHZ probes: skip — serve peerId + enc PKCS#8.");
            return;
        }

        var dir = Path.Combine(outputDirectory, "authz_probes");
        Directory.CreateDirectory(dir);
        var self = session.OctagonPeerId!;
        var foreign = Environment.GetEnvironmentVariable("IKE_AUTHZ_FOREIGN_PEER");
        var randomPeer = "SHA256:" + Convert.ToHexString(RandomNumberGenerator.GetBytes(32))
            .ToLowerInvariant();

        var cases = new List<(string Id, string ForPeer, string Label)>
        {
            ("R1a", self, "self"),
            ("R1b", "", "empty"),
            ("R1c", randomPeer, "random-sha256"),
            ("R1d", "SHA256:deadbeef", "truncated-garbage"),
        };
        if (!string.IsNullOrWhiteSpace(foreign)
            && !string.Equals(foreign, self, StringComparison.Ordinal))
        {
            cases.Add(("R1e", foreign.Trim(), "foreign-env"));
        }

        // Optional half-ids (B19-style): bottle / stale peers via env (comma-separated).
        var halfEnv = Environment.GetEnvironmentVariable("IKE_AUTHZ_HALF_PEERS");
        if (!string.IsNullOrWhiteSpace(halfEnv))
        {
            var i = 0;
            foreach (var p in halfEnv.Split(',', StringSplitOptions.RemoveEmptyEntries
                                               | StringSplitOptions.TrimEntries))
            {
                if (string.Equals(p, self, StringComparison.Ordinal))
                    continue;
                i++;
                cases.Add(($"R1h{i}", p, "half-env"));
                if (i >= 8)
                    break;
            }
        }

        log?.Report($"AUTHZ probes: recoverable forPeer matrix ({cases.Count} cases) → {dir}");
        Environment.SetEnvironmentVariable("IKE_AUTHZ_ALLOW_EMPTY_FORPEER", "1");

        var results = new List<object>();
        try
        {
            foreach (var (id, forPeer, label) in cases)
            {
                ct.ThrowIfCancellationRequested();
                var caseDir = Path.Combine(dir, id);
                Directory.CreateDirectory(caseDir);
                log?.Report($"  [{id}] forPeer={label}…");

                RecoverableTlkSharesResult recov;
                try
                {
                    recov = await cuttlefish.FetchRecoverableTlkSharesAsync(
                            session, caseDir, forPeerId: forPeer, log, ct)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    results.Add(new
                    {
                        id,
                        forPeer = Trim(forPeer),
                        forPeerLabel = label,
                        rpcOk = false,
                        error = ex.Message,
                        shareRecords = 0,
                        views = Array.Empty<string>(),
                        unwrappedWithOurKey = 0,
                        criticalHint = false
                    });
                    log?.Report($"    ERR {ex.Message}");
                    continue;
                }

                var views = recov.TlkByView.Keys
                    .OrderBy(k => k, StringComparer.OrdinalIgnoreCase)
                    .ToList();
                // TlkByView only contains shares unwrapped with session PKCS#8.
                var unwrapped = recov.TlkByView.Count;
                var critical = id != "R1a" && unwrapped > 0;

                results.Add(new
                {
                    id,
                    forPeer = Trim(forPeer),
                    forPeerLabel = label,
                    rpcOk = recov.Success,
                    message = recov.Message,
                    shareRecords = recov.ShareRecords,
                    views,
                    unwrappedWithOurKey = unwrapped,
                    criticalHint = critical
                });

                log?.Report(
                    $"    rpc={(recov.Success ? "ok" : "fail")} shares={recov.ShareRecords} " +
                    $"unwrapWithUs={unwrapped} views=[{string.Join(",", views)}]" +
                    (critical ? " CRITICAL" : ""));
            }
        }
        finally
        {
            Environment.SetEnvironmentVariable("IKE_AUTHZ_ALLOW_EMPTY_FORPEER", null);
        }

        var report = new
        {
            generatedAtUtc = DateTime.UtcNow,
            peerSelf = self,
            note =
                "unwrappedWithOurKey>0 on non-R1a = possible entitlement/ECIES binding bug (lab).",
            cases = results
        };

        var jsonPath = Path.Combine(dir, "recoverable_forpeer_matrix.json");
        await File.WriteAllTextAsync(
            jsonPath,
            JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }),
            ct).ConfigureAwait(false);
        log?.Report($"AUTHZ probes: report → {jsonPath}");
    }

    private static string Trim(string forPeer) =>
        forPeer.Length > 120 ? forPeer[..120] + "…" : forPeer;
}
