using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Garantisce seed PCS in sessione (<see cref="ICloudSession.PcsEscrowedKeySet"/> e/o
/// <see cref="ICloudSession.PcsManateeCompactKeys"/>) prima di CloudDocs/Backup crypto.
/// </summary>
public static class EscrowPcsSession
{
    private static readonly Regex ManateePcsXFile = new(
        @"^pcs_(\d+)_svc(.+)_x\.bin$",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// Risolve o sblocca il KeySet PCS e lo mette in sessione.
    /// Ordine: sessione KeySet → Manatee in sessione → Manatee da disco (Octagon/CKKS) →
    /// unlocked file → unlock offline → recover live → re-parse cached get_records.
    /// </summary>
    public static async Task<EscrowPcsEnsureResult> EnsureKeySetAsync(
        ICloudSession session,
        HttpClient http,
        string pcsKeysDirectory,
        string? iCloudSecurityCode = null,
        EscrowSmsOptions? sms = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var resolved = ResolvePcsKeysDirectory(
            pcsKeysDirectory,
            session.PcsKeysDirectory,
            session.OctagonKeysDirectory);
        if (!string.Equals(resolved, pcsKeysDirectory, StringComparison.OrdinalIgnoreCase))
            log?.Report($"  PCS dir → {resolved} (artifact Escrow/Octagon già presenti)");

        Directory.CreateDirectory(resolved);
        session.PcsKeysDirectory = resolved;

        if (session.PcsEscrowedKeySet is { Length: > 32 })
        {
            log?.Report(
                $"  PCS KeySet già in sessione ({session.PcsEscrowedKeySet.Length} B).");
            return new EscrowPcsEnsureResult(true, "session", session.PcsEscrowedKeySet);
        }

        // ADP / Octagon: CKKS OpenVault può aver già messo compact Manatee in sessione.
        if (session.PcsManateeCompactKeys is { Count: > 0 } manatee)
        {
            log?.Report(
                $"  PCS Manatee già in sessione ({manatee.Count} compact) — skip Escrow recover.");
            return new EscrowPcsEnsureResult(true, "manatee-session", null);
        }

        // Stesso account, nuova sessione: Manatee già sbloccato da Octagon/CKKS su disco.
        var fromManatee = TryLoadManateeFromDisk(session, resolved, log);
        if (fromManatee is not null)
            return fromManatee;

        var fromFile = await TryLoadUnlockedAsync(session, resolved, log, ct);
        if (fromFile is not null)
            return fromFile;

        var bagPath = Path.Combine(resolved, EscrowPcsKeyUnwrap.BackupBagPasswordFileName);
        var hasBag = File.Exists(bagPath);
        var hasEscrowed = EscrowPcsUnlock.ResolveEscrowedKeysPath(resolved) is not null;
        var recovery = new EscrowRecoveryService(http);

        // Bag sì, escrowed no: riprova solo il parse della get_records già fatta dal recover.
        if (hasBag && !hasEscrowed)
        {
            log?.Report(
                "  PCS: BackupBagPassword presente, pcs_escrowed_keys no — re-parse get_records cached…");
            hasEscrowed = await recovery.ReparseEscrowedKeysFromCachedGetRecordsAsync(
                resolved, log, ct);
        }

        if (hasBag && hasEscrowed)
        {
            log?.Report("  PCS: Unlock EscrowedKeys offline (BackupBagPassword + escrowed)…");
            var unlockOffline = await EscrowPcsUnlock.UnlockFromDirectoryAsync(
                resolved, log, ct);
            if (unlockOffline.Success && unlockOffline.Plaintext is { Length: > 32 } pt)
            {
                session.PcsEscrowedKeySet = pt;
                return new EscrowPcsEnsureResult(true, "unlock-offline", pt);
            }

            log?.Report($"  PCS unlock offline: {unlockOffline.Message}");
        }

        // Serve recover completo (include get_records una sola volta all'inizio).
        if (!hasBag)
        {
            var secret = string.IsNullOrWhiteSpace(iCloudSecurityCode)
                ? session.Dsid
                : iCloudSecurityCode.Trim();
            if (string.IsNullOrWhiteSpace(secret))
            {
                return new EscrowPcsEnsureResult(
                    false,
                    null,
                    null,
                    $"Manca KeySet PCS e DSID. Login iCloud + Unlock EscrowedKeys in «{resolved}».");
            }

            log?.Report(
                string.Equals(secret, session.Dsid, StringComparison.Ordinal)
                    ? "  PCS: Unlock EscrowedKeys live (secret=DSID)…"
                    : "  PCS: Unlock EscrowedKeys live (secret=iCSC campo)…");

            var recover = await recovery.FetchEncryptedKeyBagKeyAsync(
                session,
                secret,
                resolved,
                log,
                sms,
                ct: ct);
            if (!recover.Success)
            {
                return new EscrowPcsEnsureResult(
                    false, null, null, $"Escrow recover fallito: {recover.Message}");
            }

            fromFile = await TryLoadUnlockedAsync(session, resolved, log, ct);
            if (fromFile is not null)
                return fromFile;
        }

        if (!File.Exists(bagPath))
        {
            var unwrap = await recovery.CompletePcsUnwrapOfflineAsync(resolved, log, ct);
            if (!unwrap.Success)
            {
                return new EscrowPcsEnsureResult(
                    false, null, null, $"PCS unwrap fallito: {unwrap.Message}");
            }
        }

        // Ancora senza escrowed: solo re-parse della risposta salvata dal recover (no rete).
        if (EscrowPcsUnlock.ResolveEscrowedKeysPath(resolved) is null)
        {
            var ok = await recovery.ReparseEscrowedKeysFromCachedGetRecordsAsync(
                resolved, log, ct);
            if (!ok)
            {
                return new EscrowPcsEnsureResult(
                    false,
                    null,
                    null,
                    "Manca pcs_escrowed_keys.bin dopo recover. " +
                    "Controlla escrow_get_records_response (parse kPCSMetadataEscrowedKeys).");
            }
        }

        {
            var unlock = await recovery.CompletePcsUnlockOfflineAsync(resolved, log, ct);
            if (unlock.Success && unlock.Plaintext is { Length: > 32 } plain)
            {
                session.PcsEscrowedKeySet = plain;
                session.PcsKeysDirectory = resolved;
                log?.Report($"  PCS KeySet in sessione ({plain.Length} B) ← Unlock EscrowedKeys");
                return new EscrowPcsEnsureResult(true, "unlock-live", plain);
            }

            fromFile = await TryLoadUnlockedAsync(session, resolved, log, ct);
            if (fromFile is not null)
                return fromFile;

            // Ultima chance ADP: Manatee in sessione o ricaricato da disco Octagon/CKKS.
            if (session.PcsManateeCompactKeys is { Count: > 0 } manateeFb)
            {
                log?.Report(
                    $"  PCS unlock Escrow fallito, ma Manatee presente ({manateeFb.Count}) — uso quello.");
                return new EscrowPcsEnsureResult(true, "manatee-fallback", null);
            }

            var manateeDiskFb = TryLoadManateeFromDisk(session, resolved, log);
            if (manateeDiskFb is not null)
                return manateeDiskFb with { Source = "manatee-disk-fallback" };

            return new EscrowPcsEnsureResult(
                false, null, null, $"PCS unlock fallito: {unlock.Message}");
        }
    }

    /// <summary>
    /// Preferisce una cartella che ha già gli artifact Escrow (scheda KeyBagKey),
    /// risalendo dai path snapshot se necessario — evita get_records ridondanti.
    /// </summary>
    public static string ResolvePcsKeysDirectory(params string?[] candidates)
    {
        foreach (var raw in candidates)
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;

            var dir = Path.GetFullPath(raw.Trim());
            for (var i = 0; i < 6; i++)
            {
                if (DirectoryLooksLikePcsStore(dir))
                    return dir;

                var parent = Directory.GetParent(dir)?.FullName;
                if (string.IsNullOrEmpty(parent) || parent == dir)
                    break;
                dir = parent;
            }
        }

        foreach (var raw in candidates)
        {
            if (!string.IsNullOrWhiteSpace(raw))
                return Path.GetFullPath(raw.Trim());
        }

        return Path.GetFullPath(".");
    }

    private static bool DirectoryLooksLikePcsStore(string dir)
    {
        if (!Directory.Exists(dir))
            return false;

        if (FindUnlockedKeysFile(dir) is not null)
            return true;
        if (File.Exists(Path.Combine(dir, EscrowPcsKeyUnwrap.BackupBagPasswordFileName)))
            return true;
        if (EscrowPcsUnlock.ResolveEscrowedKeysPath(dir) is not null)
            return true;
        if (File.Exists(Path.Combine(dir, "escrow_get_records_response.bin"))
            || File.Exists(Path.Combine(dir, "escrow_get_records_response.xml")))
            return true;
        // Octagon/CKKS: Manatee compact keys già estratte (niente Escrow classic).
        if (FindManateeKeysDirectory(dir) is not null)
            return true;
        if (File.Exists(Path.Combine(dir, "octagon_peer_encryption.pkcs8"))
            || File.Exists(Path.Combine(dir, "ckks_vault_meta.json")))
            return true;

        return false;
    }

    /// <summary>
    /// Ricarica <see cref="ICloudSession.PcsManateeCompactKeys"/> da
    /// <c>manatee_pcs_keys/pcs_*_svc*_x.bin</c> + <c>_d.bin</c> (output CKKS OpenVault).
    /// </summary>
    public static EscrowPcsEnsureResult? TryLoadManateeFromDisk(
        ICloudSession session,
        string? rootDirectory,
        IProgress<string>? log = null)
    {
        if (session.PcsManateeCompactKeys is { Count: > 0 })
            return new EscrowPcsEnsureResult(true, "manatee-session", null);

        var candidates = new List<string?>
        {
            rootDirectory,
            session.OctagonKeysDirectory,
            session.PcsKeysDirectory,
        };

        foreach (var raw in candidates)
        {
            if (string.IsNullOrWhiteSpace(raw))
                continue;

            var root = Path.GetFullPath(raw.Trim());
            for (var climb = 0; climb < 4; climb++)
            {
                var keysDir = FindManateeKeysDirectory(root);
                if (keysDir is not null
                    && TryReadManateeKeys(keysDir, out var keys)
                    && keys.Count > 0)
                {
                    session.PcsManateeCompactKeys = keys;
                    if (string.IsNullOrWhiteSpace(session.OctagonKeysDirectory))
                        session.OctagonKeysDirectory = Path.GetDirectoryName(keysDir) ?? root;
                    log?.Report(
                        $"  PCS KeySet ← Manatee Octagon/CKKS ({keys.Count} compact) " +
                        $"da {keysDir}");
                    return new EscrowPcsEnsureResult(true, "manatee-disk", null);
                }

                var parent = Directory.GetParent(root)?.FullName;
                if (string.IsNullOrEmpty(parent) || parent == root)
                    break;
                root = parent;
            }
        }

        return null;
    }

    private static string? FindManateeKeysDirectory(string dir)
    {
        if (!Directory.Exists(dir))
            return null;

        var direct = Path.Combine(dir, "manatee_pcs_keys");
        if (Directory.Exists(direct) && Directory.EnumerateFiles(direct, "pcs_*_x.bin").Any())
            return direct;

        try
        {
            foreach (var sub in Directory.EnumerateDirectories(dir))
            {
                var name = Path.GetFileName(sub);
                if (name.Equals("manatee_pcs_keys", StringComparison.OrdinalIgnoreCase)
                    && Directory.EnumerateFiles(sub, "pcs_*_x.bin").Any())
                    return sub;
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static bool TryReadManateeKeys(string keysDir, out List<PcsCompactPrivateKey> keys)
    {
        keys = new List<PcsCompactPrivateKey>();
        try
        {
            var pairs = new List<(int Index, int? Service, string XPath, string DPath)>();
            foreach (var xPath in Directory.EnumerateFiles(keysDir, "pcs_*_x.bin"))
            {
                var name = Path.GetFileName(xPath);
                var m = ManateePcsXFile.Match(name);
                if (!m.Success)
                    continue;
                if (!int.TryParse(m.Groups[1].Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var idx))
                    continue;
                var svcTag = m.Groups[2].Value;
                int? service = null;
                if (!svcTag.Equals("na", StringComparison.OrdinalIgnoreCase)
                    && int.TryParse(svcTag, NumberStyles.Integer, CultureInfo.InvariantCulture, out var svc))
                    service = svc;

                // pcs_000_svc2_x.bin → pcs_000_svc2_d.bin
                var dPath = xPath[..^6] + "_d.bin";
                if (!File.Exists(dPath))
                    continue;
                pairs.Add((idx, service, xPath, dPath));
            }

            foreach (var p in pairs.OrderBy(p => p.Index))
            {
                var x = File.ReadAllBytes(p.XPath);
                var d = File.ReadAllBytes(p.DPath);
                if (x.Length != 32 || d.Length != 32)
                    continue;
                keys.Add(new PcsCompactPrivateKey(x, d, PcsDer.KeyIdOf(x), p.Service));
            }

            if (keys.Count == 0)
                return false;

            // SearchParty (82) in coda — stesso ordine di CkksVaultService.OpenViewsAsync.
            keys = keys
                .OrderBy(k => k.Service == PcsPrivateKeyDer.SearchPartyServiceType ? 1 : 0)
                .ThenBy(k => k.Service ?? int.MaxValue)
                .ToList();
            return true;
        }
        catch
        {
            keys = new List<PcsCompactPrivateKey>();
            return false;
        }
    }

    private static async Task<EscrowPcsEnsureResult?> TryLoadUnlockedAsync(
        ICloudSession session,
        string pcsKeysDirectory,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var unlocked = FindUnlockedKeysFile(pcsKeysDirectory);
        if (unlocked is null)
            return null;

        var der = await File.ReadAllBytesAsync(unlocked, ct);
        if (der.Length <= 32)
            return null;

        session.PcsEscrowedKeySet = der;
        session.PcsKeysDirectory = Path.GetDirectoryName(unlocked) ?? pcsKeysDirectory;
        log?.Report(
            $"  PCS KeySet ← {Path.GetFileName(unlocked)} ({der.Length} B) " +
            $"in {session.PcsKeysDirectory}");
        return new EscrowPcsEnsureResult(true, unlocked, der);
    }

    /// <summary>
    /// Cerca <c>escrowed_pcs_keys.bin</c> nella cartella Escrow (non dentro <c>whatsapp_docs_*</c>).
    /// </summary>
    public static string? FindUnlockedKeysFile(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory) || !Directory.Exists(directory))
            return null;

        var direct = Path.Combine(directory, EscrowPcsUnlock.UnlockedKeysFileName);
        if (File.Exists(direct))
            return direct;

        try
        {
            foreach (var sub in Directory.EnumerateDirectories(directory))
            {
                var name = Path.GetFileName(sub);
                if (name.StartsWith("whatsapp_docs_", StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("backup_", StringComparison.OrdinalIgnoreCase) ||
                    name.StartsWith("sync_data_", StringComparison.OrdinalIgnoreCase) ||
                    name.Equals("clouddocs_ck", StringComparison.OrdinalIgnoreCase))
                    continue;

                var candidate = Path.Combine(sub, EscrowPcsUnlock.UnlockedKeysFileName);
                if (File.Exists(candidate))
                    return candidate;
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }
}

public sealed record EscrowPcsEnsureResult(
    bool Success,
    string? Source,
    byte[]? KeySet,
    string? Message = null);
