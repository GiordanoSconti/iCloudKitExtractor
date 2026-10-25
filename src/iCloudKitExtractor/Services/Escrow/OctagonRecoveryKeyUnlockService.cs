using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Octagon Recovery Key → peer P-384 → <c>fetchRecoverableTLKShares</c> → CKKS OpenVault
/// (Manatee / PCS / Passwords). Alternative to device-passcode bottle unlock (no HSM attempt).
/// </summary>
public sealed class OctagonRecoveryKeyUnlockService
{
    private readonly OctagonCuttlefishService _cuttlefish;
    private readonly CkksVaultService _vault;
    private readonly ICloudBackupOrchestrator _orchestrator;

    public OctagonRecoveryKeyUnlockService(
        OctagonCuttlefishService cuttlefish,
        CkksVaultService vault,
        ICloudBackupOrchestrator orchestrator)
    {
        _cuttlefish = cuttlefish;
        _vault = vault;
        _orchestrator = orchestrator;
    }

    public sealed record Result(
        bool Success,
        string Message,
        string? PeerId = null,
        int LiveShares = 0,
        int LiveUnwrappedViews = 0,
        int VaultItems = 0,
        int PcsKeys = 0,
        string? OutputDirectory = null);

    /// <summary>
    /// Derive RK peer, bind session, live recoverable TLK + OpenVault.
    /// Does not persist the recovery key string.
    /// </summary>
    public async Task<Result> UnlockAsync(
        ICloudSession session,
        string recoveryKey,
        string? recoverySalt,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        IReadOnlyList<string>? views = null)
    {
        var rk = NormalizeRecoveryKeyInput(recoveryKey);
        if (string.IsNullOrWhiteSpace(rk))
            return new Result(false, "Recovery Key assente.");

        var salt = (recoverySalt ?? "").Trim();
        if (string.IsNullOrWhiteSpace(salt))
            salt = session.Adsid?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(salt))
            return new Result(false, "Serve altDSID/adsid (sessione o campo Salt).");

        Directory.CreateDirectory(outputDirectory);
        log?.Report($"Octagon RK: derive peer (salt={salt}, rkLen={rk.Length})…");

        OctagonRecoveryKey.Derived derived;
        try
        {
            derived = OctagonRecoveryKey.Derive(rk, salt);
        }
        catch (Exception ex)
        {
            return new Result(false, $"KDF RK fallita: {ex.Message}");
        }

        log?.Report($"  peerID={derived.PeerId}");

        await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "rk_encryption.pkcs8"), derived.EncryptionPkcs8, ct)
            .ConfigureAwait(false);
        await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, "rk_signing.pkcs8"), derived.SigningPkcs8, ct)
            .ConfigureAwait(false);
        await File.WriteAllTextAsync(
                Path.Combine(outputDirectory, "rk_peer_meta.json"),
                JsonSerializer.Serialize(new
                {
                    peerId = derived.PeerId,
                    salt,
                    rkLen = rk.Length,
                    note =
                        "HKDF-SHA384(rk, altDSID) → P-384. Recovery string not stored. " +
                        "Path: fetchRecoverableTLKShares → CKKS Manatee/PCS."
                }, new JsonSerializerOptions { WriteIndented = true }),
                ct).ConfigureAwait(false);

        session.OctagonPeerEncryptionPkcs8 = derived.EncryptionPkcs8;
        session.OctagonPeerSigningPkcs8 = derived.SigningPkcs8;
        session.OctagonPeerId = derived.PeerId;
        session.OctagonKeysDirectory = outputDirectory;

        log?.Report($"  ckAppInit → {OctagonCuttlefishService.ContainerId}…");
        await _orchestrator.CkAppInitAsync(session, OctagonCuttlefishService.ContainerId, log, ct)
            .ConfigureAwait(false);

        var liveDir = Path.Combine(outputDirectory, "live_fetch");
        Directory.CreateDirectory(liveDir);
        log?.Report(
            $"  fetchRecoverableTLKShares(forPeer={TrimId(derived.PeerId)}, f1→f2)…");
        var recov = await _cuttlefish.FetchRecoverableTlkSharesAsync(
                session, liveDir, forPeerId: derived.PeerId, log, ct,
                tryLegacyFieldVariants: false)
            .ConfigureAwait(false);

        log?.Report(
            $"  recoverable={(recov.Success ? "ok" : "fail")} shares={recov.ShareRecords} " +
            $"unwrap={recov.TlkByView.Count} — {recov.Message}");

        var tlkByView = new Dictionary<string, byte[]>(
            recov.TlkByView, StringComparer.OrdinalIgnoreCase);
        foreach (var (view, tlk) in tlkByView)
            log?.Report($"    TLK «{view}» {tlk.Length} B");

        if (tlkByView.Count == 0)
        {
            var detail = recov.ShareRecords > 0
                ? $"shares={recov.ShareRecords} ma ECIES unwrap=0 (chiave/salt?)."
                : $"nessun tlkshare (rpc: {recov.Message}).";
            return new Result(
                false,
                $"Nessun TLK unwrapped con questa RK — {detail}",
                derived.PeerId,
                recov.ShareRecords,
                0,
                OutputDirectory: outputDirectory);
        }

        session.CkksTlkByView = new Dictionary<string, byte[]>(
            tlkByView, StringComparer.OrdinalIgnoreCase);

        // Solo view utili al decrypt RK → PCS/Keychain (no LimitedPeersAllowed noise).
        var vaultViews = views ?? ["Manatee", "ProtectedCloudStorage", "Passwords"];
        var vaultDir = Path.Combine(outputDirectory, "ckks_vault");
        Directory.CreateDirectory(vaultDir);
        log?.Report($"  CKKS OpenVault ({tlkByView.Count} TLK, no re-fetch recoverable)…");
        var open = await _vault.OpenViewsAsync(
                session,
                vaultDir,
                views: vaultViews,
                log: log,
                ct: ct,
                preloadedTlks: tlkByView,
                prefetchRecoverableTlks: false)
            .ConfigureAwait(false);

        log?.Report(
            $"  vault={(open.Success ? "ok" : "fail")} items={open.ItemsDecrypted} " +
            $"pcsKeys={open.PcsKeysFound} — {open.Message}");

        var ok = open.PcsKeysFound > 0 || open.ItemsDecrypted > 0 || tlkByView.Count > 0;
        return new Result(
            ok,
            ok
                ? $"RK OK peer={derived.PeerId}: TLK={tlkByView.Count} pcsKeys={open.PcsKeysFound} items={open.ItemsDecrypted}"
                : open.Message,
            derived.PeerId,
            recov.ShareRecords,
            tlkByView.Count,
            open.ItemsDecrypted,
            open.PcsKeysFound,
            outputDirectory);
    }

    /// <summary>
    /// Trim + keep first iCloud Recovery Key token (XXXX-XXXX-… × 7).
    /// </summary>
    public static string NormalizeRecoveryKeyInput(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return "";
        var s = raw.Trim();
        // Prefer hyphenated 7-group form.
        var m = Regex.Match(
            s,
            @"\b([A-Z0-9]{4}(?:-[A-Z0-9]{4}){6})\b",
            RegexOptions.IgnoreCase);
        if (m.Success)
            return m.Groups[1].Value.ToUpperInvariant();
        // Compact 28 alnum
        var compact = Regex.Replace(s, @"[^A-Za-z0-9]", "");
        if (compact.Length == 28)
        {
            var sb = new StringBuilder(34);
            for (var i = 0; i < 28; i += 4)
            {
                if (i > 0)
                    sb.Append('-');
                sb.Append(compact.AsSpan(i, 4));
            }

            return sb.ToString().ToUpperInvariant();
        }

        return s;
    }

    private static string TrimId(string id) =>
        id.Length <= 40 ? id : id[..36] + "…";
}
