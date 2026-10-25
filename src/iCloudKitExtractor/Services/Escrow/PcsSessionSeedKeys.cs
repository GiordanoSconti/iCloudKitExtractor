using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Pool chiavi PCS per crypto Backup/SyncData: EscrowedKeySet ∪ Manatee (CKKS/Octagon).
/// Con ADP il KeySet Escrow classico spesso non apre i blob; le compact da OpenVault sì.
/// Ordinamento backup-oriented: evita di provare SearchParty (82) prima delle PCS utili.
/// </summary>
public static class PcsSessionSeedKeys
{
    public static bool HasAny(ICloudSession session) =>
        session.PcsEscrowedKeySet is { Length: > 32 }
        || session.PcsManateeCompactKeys is { Count: > 0 };

    /// <summary>KeySet Escrow classico in sessione (consumo originale intatto).</summary>
    public static bool HasEscrowKeySet(ICloudSession session) =>
        session.PcsEscrowedKeySet is { Length: > 32 };

    /// <summary>
    /// Solo Manatee / ADP: niente KeySet Escrow. Narrow / speedup solo qui.
    /// Se c’è <see cref="HasEscrowKeySet"/>, i call-site devono usare
    /// <c>PcsDer.ParseKeySetPrivateKeys</c> (path HEAD) e non alterare Escrow.
    /// </summary>
    public static bool IsManateePrimary(ICloudSession session) =>
        !HasEscrowKeySet(session)
        && session.PcsManateeCompactKeys is { Count: > 0 };

    /// <summary>
    /// Pool backup. Con KeySet Escrow: solo <c>ParseKeySetPrivateKeys</c> (niente Manatee).
    /// Preferire comunque il ramo Escrow esplicito nei call-site critici (KEK/keybag).
    /// </summary>
    public static List<PcsCompactPrivateKey> Collect(
        ICloudSession session,
        IProgress<string>? log = null)
        => Collect(session, narrowToPreferred: false, log);

    /// <summary>
    /// Pool backup. <paramref name="narrowToPreferred"/> è onorato solo se
    /// <see cref="IsManateePrimary"/> (ADP): con KeySet Escrow non si restringe il pool.
    /// </summary>
    public static List<PcsCompactPrivateKey> Collect(
        ICloudSession session,
        bool narrowToPreferred,
        IProgress<string>? log = null)
    {
        var seeds = new List<PcsCompactPrivateKey>();
        if (session.PcsEscrowedKeySet is { Length: > 32 })
        {
            try
            {
                seeds.AddRange(PcsDer.ParseKeySetPrivateKeys(session.PcsEscrowedKeySet));
            }
            catch (Exception ex)
            {
                log?.Report($"  PCS Escrow KeySet parse: {ex.Message}");
            }
        }

        var escrowCount = seeds.Count;

        // Escrow classico: KeySet basta. Non mischiare/restringere/ordinare con Manatee.
        if (escrowCount > 0)
        {
            log?.Report($"  PCS seed: escrow={escrowCount} (KeySet classico)");
            return seeds;
        }

        var skipped82 = 0;
        if (session.PcsManateeCompactKeys is { Count: > 0 } manatee)
        {
            var seen = new HashSet<string>(StringComparer.Ordinal);
            foreach (var k in manatee)
            {
                if (k.Service == PcsPrivateKeyDer.SearchPartyServiceType)
                {
                    skipped82++;
                    continue; // Find My: non serve a mbksync / MMCS
                }

                var id = Convert.ToHexString(k.KeyId);
                if (seen.Add(id))
                    seeds.Add(k);
            }

            log?.Report(
                $"  PCS seed: manatee={manatee.Count - skipped82}" +
                (skipped82 > 0 ? $" (skip 82×{skipped82})" : "") +
                $" → pool={seeds.Count}");
        }

        seeds = OrderForBackup(session, seeds);

        // Narrow solo ADP/Manatee — mai sul KeySet Escrow.
        if (narrowToPreferred
            && IsManateePrimary(session)
            && session.PcsPreferredKeyIds is { Count: > 0 } pref)
        {
            var narrow = seeds
                .Where(k => pref.Contains(Convert.ToHexString(k.KeyId)))
                .ToList();
            if (narrow.Count > 0)
            {
                log?.Report(
                    $"  PCS seed narrow: {narrow.Count}/{seeds.Count} (KeyId zone già noti)");
                return narrow;
            }
        }

        return seeds;
    }

    /// <summary>
    /// Pool Sync Data / ADP: Escrow ∪ Manatee (incluso SearchParty 82 per BeaconStore/Find My).
    /// Diverso da <see cref="Collect"/> backup: lì Escrow-only se presente e 82 viene saltato.
    /// </summary>
    public static List<PcsCompactPrivateKey> CollectForSyncData(
        ICloudSession session,
        IProgress<string>? log = null)
    {
        var seeds = new List<PcsCompactPrivateKey>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        void Add(PcsCompactPrivateKey k)
        {
            var id = Convert.ToHexString(k.KeyId);
            if (seen.Add(id))
                seeds.Add(k);
        }

        if (session.PcsEscrowedKeySet is { Length: > 32 })
        {
            try
            {
                foreach (var k in PcsDer.ParseKeySetPrivateKeys(session.PcsEscrowedKeySet))
                    Add(k);
            }
            catch (Exception ex)
            {
                log?.Report($"  PCS Escrow KeySet parse: {ex.Message}");
            }
        }

        var escrowCount = seeds.Count;
        var manateeAdded = 0;
        if (session.PcsManateeCompactKeys is { Count: > 0 } manatee)
        {
            foreach (var k in manatee)
            {
                var before = seeds.Count;
                Add(k);
                if (seeds.Count > before)
                    manateeAdded++;
            }
        }

        seeds = OrderForBackup(session, seeds);
        log?.Report(
            $"  PCS seed SyncData: escrow={escrowCount} manatee=+{manateeAdded} → pool={seeds.Count}");
        return seeds;
    }

    /// <summary>
    /// Preferisci: KeyId già vincenti → Escrow (Service null da KeySet) → Manatee non-82 → SearchParty.
    /// </summary>
    public static List<PcsCompactPrivateKey> OrderForBackup(
        ICloudSession session,
        List<PcsCompactPrivateKey> seeds)
    {
        var preferred = session.PcsPreferredKeyIds;
        return seeds
            .OrderBy(k =>
            {
                var id = Convert.ToHexString(k.KeyId);
                if (preferred is { Count: > 0 }
                    && preferred.Contains(id))
                    return 0;
                if (k.Service == PcsPrivateKeyDer.SearchPartyServiceType)
                    return 3;
                if (k.Service is null)
                    return 1; // tipicamente da Escrow KeySet
                return 2; // Manatee / altri service
            })
            .ThenBy(k => k.Service ?? 0)
            .ToList();
    }

    /// <summary>
    /// Dopo unwrap zone/keybag riuscito: promuovi quei KeyId in testa per i batch successivi.
    /// </summary>
    public static void RememberSuccessful(
        ICloudSession session,
        IEnumerable<PcsCompactPrivateKey> usedKeys)
    {
        var set = session.PcsPreferredKeyIds;
        if (set is null)
        {
            set = new HashSet<string>(StringComparer.Ordinal);
            session.PcsPreferredKeyIds = set;
        }

        var n = 0;
        foreach (var k in usedKeys)
        {
            if (set.Add(Convert.ToHexString(k.KeyId)))
                n++;
        }

        // Riordina anche la lista Manatee in sessione (stesso criterio).
        if (n > 0 && session.PcsManateeCompactKeys is { Count: > 1 } manatee)
        {
            session.PcsManateeCompactKeys = OrderForBackup(session, manatee.ToList());
        }
    }

    /// <summary>Promuovi i KeyId delle zone già unwrapped (master KeyId = identity che ha matchato).</summary>
    public static void RememberFromZones(
        ICloudSession session,
        IEnumerable<ProtectionZoneKeys> zones,
        IReadOnlyList<PcsCompactPrivateKey> seeds)
    {
        var want = new HashSet<string>(StringComparer.Ordinal);
        foreach (var z in zones)
        {
            if (!string.IsNullOrEmpty(z.MasterKeyIdHex))
                want.Add(z.MasterKeyIdHex);
            if (z.MasterPublicMatched is { Length: > 0 } pub)
                want.Add(Convert.ToHexString(PcsDer.KeyIdOf(pub)));
        }

        if (want.Count == 0)
            return;

        RememberSuccessful(
            session,
            seeds.Where(k => want.Contains(Convert.ToHexString(k.KeyId))));
    }

    /// <summary>KeyId da cache zone masters su disco / meta.</summary>
    public static void RememberKeyIdHexes(ICloudSession session, IEnumerable<string> keyIdHexes)
    {
        var set = session.PcsPreferredKeyIds;
        if (set is null)
        {
            set = new HashSet<string>(StringComparer.Ordinal);
            session.PcsPreferredKeyIds = set;
        }

        foreach (var id in keyIdHexes)
        {
            if (!string.IsNullOrWhiteSpace(id))
                set.Add(id.Trim().ToUpperInvariant());
        }
    }
}
