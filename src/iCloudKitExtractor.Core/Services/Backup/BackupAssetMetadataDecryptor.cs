using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Decrypt metadata BackupAsset: InflatableDonkey
/// <c>zone.decrypt(encryptedAttributes, "encryptedAttributes")</c>
/// → domain / relativePath / EncryptionKey (+ protectionClass in chiaro sul record).
/// </summary>
public static class BackupAssetMetadataDecryptor
{
    public const string EncryptedAttributesField = "encryptedAttributes";
    private static int _classicEaFailLogged;

    /// <summary>
    /// Cache zone ShareProtection per snapshot classic-only (Donkey: base→zone PI→record PI).
    /// Null sul path moderno: nessun bootstrap.
    /// </summary>
    public sealed class ClassicMetaZoneCache
    {
        private readonly object _gate = new();
        public List<ProtectionZoneKeys> Zones { get; } = new();
        public List<PcsCompactPrivateKey> Pool { get; private set; } = new();
        public bool Bootstrapped { get; private set; }

        /// <summary>
        /// Preferisci zone già unwrapped da <c>EnsureZoneMastersCached</c> (stesso harvest keybag/MMCS).
        /// </summary>
        public void SeedFromCachedZones(
            IReadOnlyList<ProtectionZoneKeys>? cachedZones,
            List<PcsCompactPrivateKey> seedKeys,
            IProgress<string>? log)
        {
            if (cachedZones is not { Count: > 0 })
                return;

            lock (_gate)
            {
                if (Bootstrapped && Zones.Count > 0)
                    return;

                Pool = PcsProtectionZone.MergeKeys(seedKeys, cachedZones.ToList());
                foreach (var z in cachedZones)
                {
                    var mid = Convert.ToHexString(z.MasterKey);
                    if (Zones.All(x => !Convert.ToHexString(x.MasterKey).Equals(mid, StringComparison.Ordinal)))
                        Zones.Add(z);
                }

                Bootstrapped = true;
                log?.Report(
                    $"  classic EA: reuse cached zone ProtectionZone ×{Zones.Count}, pool={Pool.Count}");
            }
        }

        public void EnsureBootstrapped(
            byte[]? zonesPayload,
            List<PcsCompactPrivateKey> seedKeys,
            ICloudSession session,
            IProgress<string>? log)
        {
            lock (_gate)
            {
                if (Bootstrapped)
                    return;

                Pool = new List<PcsCompactPrivateKey>(seedKeys);
                if (zonesPayload is { Length: > 64 })
                {
                    var zoneKeys = PcsProtectionZone.TryUnwrapAllIterative(
                        zonesPayload, seedKeys, includeLight: false);
                    Zones.AddRange(zoneKeys);
                    Pool = PcsProtectionZone.MergeKeys(seedKeys, zoneKeys);
                    if (zoneKeys.Count > 0 && PcsSessionSeedKeys.IsManateePrimary(session))
                        PcsSessionSeedKeys.RememberFromZones(session, zoneKeys, seedKeys);
                    log?.Report(
                        $"  classic EA: zone ShareProtection → {zoneKeys.Count} master, " +
                        $"pool={Pool.Count}");
                }
                else
                {
                    log?.Report("  classic EA: zone payload missing — record PI only");
                }

                Bootstrapped = true;
            }
        }
    }

    public sealed record Result(
        bool Success,
        string? Domain,
        string? RelativePath,
        int? ProtectionClass,
        byte[]? EncryptionKey,
        string Message);

    /// <summary>
    /// Tenta di arricchire <paramref name="asset"/> con identity filesystem + EncryptionKey.
    /// <paramref name="classicZoneCache"/> non-null attiva la catena Donkey zone→record (solo classic-M).
    /// </summary>
        public static Result TryDecrypt(
        BackupAsset asset,
        byte[]? recordPayload,
        ICloudSession session,
        IosKeybag? unlockedKeybag,
        IProgress<string>? log = null,
        byte[]? classicMbksyncZonesPayload = null,
        ClassicMetaZoneCache? classicZoneCache = null,
        IReadOnlyList<ProtectionZoneKeys>? classicCachedZones = null)
    {
        _ = unlockedKeybag;

        if (asset.HasFilesystemIdentity)
        {
            asset.EnsureFileId();
            return new Result(
                true,
                asset.Domain,
                asset.RelativePath,
                asset.ProtectionClass,
                asset.EncryptionKey,
                "metadata already present");
        }

        var payload = recordPayload is { Length: > 32 }
            ? recordPayload
            : asset.RecordPayload;

        if (payload is not { Length: > 32 })
        {
            var stub = asset.RecordName.StartsWith("MMCS:", StringComparison.Ordinal);
            return Pending(stub
                ? "metadata pending — PreAuth asset (MMCS:) without CloudKit BackupAsset record"
                : "metadata decrypt pending — missing BackupAsset payload to isolate encryptedAttributes");
        }

        // protectionClass è in chiaro sul record (signed) quando presente (classico).
        if (asset.ProtectionClass is null
            && TryExtractSignedField(payload, "protectionClass", out var pc))
        {
            asset.ProtectionClass = pc;
        }

        // Marker attesi post-decrypt (payload già in chiaro — raro sul wire).
        var latin = Encoding.Latin1.GetString(payload);
        if (latin.Contains("relativePath", StringComparison.Ordinal)
            && TryExtractAsciiPathPair(latin, out var domainHint, out var pathHint))
        {
            asset.Domain = domainHint;
            asset.RelativePath = pathHint;
            asset.EnsureFileId();
            log?.Report($"  metadata plaintext → {domainHint} / {pathHint}");
            return new Result(true, domainHint, pathHint, asset.ProtectionClass, asset.EncryptionKey,
                "path trovati in chiaro nel payload");
        }

        var fields = CloudKitResponseParser.ExtractNamedByteFields(
            payload, EncryptedAttributesField);
        if (!fields.TryGetValue(EncryptedAttributesField, out var rawCt)
            || rawCt.Length < 16)
        {
            // moderno: BackupAsset = extension + contents (+ version); path da flist (EN:).
            var hasContents = latin.Contains("contents", StringComparison.Ordinal);
            return Pending(hasContents
                ? "metadata pending — modern BackupAsset without encryptedAttributes " +
                  "(path/EncryptionKey da flist EN:, non dal record)"
                : "metadata decrypt pending — encryptedAttributes field missing in payload");
        }

        if (!PcsSessionSeedKeys.HasAny(session))
        {
            return Pending("metadata decrypt pending — PCS KeySet missing");
        }

        var manateeFast = PcsSessionSeedKeys.IsManateePrimary(session);
        List<PcsCompactPrivateKey> seedKeys;
        if (PcsSessionSeedKeys.HasEscrowKeySet(session))
            seedKeys = PcsDer.ParseKeySetPrivateKeys(session.PcsEscrowedKeySet!);
        else
            seedKeys = PcsSessionSeedKeys.Collect(
                session,
                narrowToPreferred: manateeFast && session.PcsPreferredKeyIds is { Count: > 0 });
        if (seedKeys.Count == 0)
            return Pending("metadata decrypt pending — KeySet without private keys");

        var ct = BackupKeybagPcsUnlock.ExtractEncryptedBytesValue(rawCt);
        // Classic-M: Donkey PZFactory — zone PI → MergeKeys → record PI → GCM.
        // Modern leave classicZoneCache null → BuildDecryptZones legacy (identity già da flist).
        var classic = classicZoneCache is not null;
        if (classic)
        {
            classicZoneCache!.SeedFromCachedZones(classicCachedZones, seedKeys, log);
        }

        var zones = classic
            ? BuildDecryptZonesClassic(
                payload, asset, seedKeys, session, classicMbksyncZonesPayload, classicZoneCache!, log)
            : BuildDecryptZones(payload, asset, seedKeys, includeLight: false);

        // Donkey ProtectionZone.decrypt prova tutte le decryptKeys; expanded solo classic.
        byte[]? plain = TryDecryptEaWithZones(zones, ct, rawCt, expanded: classic);

        if (plain is null && !classic)
        {
            var embedded = PcsProtectionZone.TryUnwrapAll(
                ct, seedKeys, includeLight: false);
            plain = TryDecryptEaWithZones(embedded, ct, rawCt, expanded: false);
        }

        if (plain is not { Length: > 0 })
        {
            if (classic && Volatile.Read(ref _classicEaFailLogged) < 3)
            {
                Interlocked.Increment(ref _classicEaFailLogged);
                log?.Report(
                    $"  classic EA GCM miss: zones={zones.Count}, " +
                    $"bootstrap={(classicMbksyncZonesPayload?.Length ?? 0):N0} B, " +
                    $"cacheZones={classicZoneCache!.Zones.Count}, " +
                    $"ct={ct.Length} B, record={asset.RecordName}");
            }

            return Pending("metadata decrypt failed — PCS GCM encryptedAttributes");
        }

        if (!AssetEncryptedAttributesParser.TryParse(plain, out var attrs, out var parseErr)
            || attrs is null)
        {
            return Pending($"metadata plaintext non parsato: {parseErr}");
        }

        var domain = attrs.Domain;
        var relativePath = attrs.RelativePath;
        if (string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(asset.Domain))
            domain = asset.Domain;

        if (string.IsNullOrWhiteSpace(relativePath))
            return Pending("metadata OK PCS but relativePath missing");

        if (string.IsNullOrWhiteSpace(domain))
            domain = "UnknownDomain";

        log?.Report($"  metadata decrypt → {domain} / {relativePath}");
        return new Result(
            true,
            domain,
            relativePath,
            asset.ProtectionClass,
            attrs.EncryptionKey,
            "encryptedAttributes OK");
    }

    public static void Apply(BackupAsset asset, Result result)
    {
        if (!result.Success)
            return;
        if (!string.IsNullOrWhiteSpace(result.Domain))
            asset.Domain = result.Domain;
        if (!string.IsNullOrWhiteSpace(result.RelativePath))
            asset.RelativePath = result.RelativePath;
        if (result.ProtectionClass is int pc)
            asset.ProtectionClass = pc;
        if (result.EncryptionKey is { Length: > 0 } key)
            asset.EncryptionKey = key;
        asset.EnsureFileId();
    }

    private static byte[]? TryDecryptEaWithZones(
        IReadOnlyList<ProtectionZoneKeys> zones,
        byte[] ct,
        byte[] rawCt,
        bool expanded)
    {
        foreach (var zone in zones)
        {
            var plain = expanded
                ? PcsProtectionZone.TryDecryptFieldExpanded(
                    zone, ct, EncryptedAttributesField, "EncryptedAttributes")
                : PcsProtectionZone.TryDecryptField(
                    zone, ct, EncryptedAttributesField, "EncryptedAttributes");
            if (plain is { Length: > 0 })
                return plain;
        }

        // Retry outer Value wrapper (come keybag) se strip ha fallito.
        if (!ct.AsSpan().SequenceEqual(rawCt))
        {
            foreach (var zone in zones)
            {
                var plain = expanded
                    ? PcsProtectionZone.TryDecryptFieldExpanded(
                        zone, rawCt, EncryptedAttributesField, "EncryptedAttributes")
                    : PcsProtectionZone.TryDecryptField(
                        zone, rawCt, EncryptedAttributesField, "EncryptedAttributes");
                if (plain is { Length: > 0 })
                    return plain;
            }
        }

        return null;
    }

    /// <summary>
    /// Catena InflatableDonkey / BP: zone masters → pool → record PI candidates → decrypt keys.
    /// Solo con <see cref="ClassicMetaZoneCache"/>.
    /// </summary>
    private static List<ProtectionZoneKeys> BuildDecryptZonesClassic(
        byte[] payload,
        BackupAsset asset,
        List<PcsCompactPrivateKey> seedKeys,
        ICloudSession session,
        byte[]? zonesPayload,
        ClassicMetaZoneCache cache,
        IProgress<string>? log)
    {
        cache.EnsureBootstrapped(zonesPayload, seedKeys, session, log);

        var zones = new List<ProtectionZoneKeys>();
        var pool = new List<PcsCompactPrivateKey>(cache.Pool);
        // Zone DecryptKeys in testa (Donkey: latest protection zone first).
        zones.AddRange(cache.Zones);

        void ConsiderDer(byte[] der, string source)
        {
            var zone = PcsProtectionZone.TryUnwrap(der, pool);
            if (zone is not null)
            {
                zones.Insert(0, zone);
                if (zone.NestedPrivateKeys.Count > 0)
                    pool = PcsProtectionZone.MergeKeys(pool, [zone]);
                return;
            }

            foreach (var z in PcsProtectionZone.TryUnwrapAll(der, pool, includeLight: false))
            {
                zones.Insert(0, z);
                if (z.NestedPrivateKeys.Count > 0)
                    pool = PcsProtectionZone.MergeKeys(pool, [z]);
            }
        }

        if (asset.RecordProtectionInfoDerHex is { Length: > 0 } hex)
        {
            try
            {
                ConsiderDer(Convert.FromHexString(hex), "record-PI-hex");
            }
            catch
            {
                // hex malformato
            }
        }

        // Candidati ≥64 senza cap 900 (record PI classico può superare ~900 B).
        foreach (var der in PcsProtectionZone.TryExtractProtectionInfoCandidates(payload))
            ConsiderDer(der, "record-PI-cand");

        var fromPayload = PcsProtectionZone.TryUnwrapAll(payload, pool, includeLight: false);
        if (fromPayload.Count > 0)
        {
            zones.AddRange(fromPayload);
            pool = PcsProtectionZone.MergeKeys(pool, fromPayload);
        }

        if (zones.Count == 0)
            log?.Report("  classic EA: no ProtectionZone unwrapped (zone/record PI?)");

        return DedupZones(zones);
    }

    /// <summary>Path legacy (call site modern / senza cache): invariato.</summary>
    private static List<ProtectionZoneKeys> BuildDecryptZones(
        byte[] payload,
        BackupAsset asset,
        List<PcsCompactPrivateKey> seedKeys,
        bool includeLight = false)
    {
        var zones = new List<ProtectionZoneKeys>();
        var pool = new List<PcsCompactPrivateKey>(seedKeys);

        var fromPayload = PcsProtectionZone.TryUnwrapAll(payload, seedKeys, includeLight: includeLight);
        if (fromPayload.Count > 0)
        {
            zones.AddRange(fromPayload);
            pool = PcsProtectionZone.MergeKeys(seedKeys, fromPayload);
        }

        if (asset.RecordProtectionInfoDerHex is { Length: > 0 } hex)
        {
            try
            {
                var der = Convert.FromHexString(hex);
                var zone = PcsProtectionZone.TryUnwrap(der, pool);
                if (zone is not null)
                    zones.Insert(0, zone);
            }
            catch
            {
                // hex malformato
            }
        }

        return zones;
    }

    private static List<ProtectionZoneKeys> DedupZones(List<ProtectionZoneKeys> zones)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var result = new List<ProtectionZoneKeys>(zones.Count);
        foreach (var z in zones)
        {
            var id = Convert.ToHexString(z.MasterKey);
            if (seen.Add(id))
                result.Add(z);
        }

        return result;
    }

    private static Result Pending(string message) =>
        new(false, null, null, null, null, message);

    private static bool TryExtractSignedField(byte[] payload, string fieldName, out int value)
    {
        value = 0;
        var key = Encoding.ASCII.GetBytes(fieldName);
        var searchFrom = 0;
        while (searchFrom < payload.Length)
        {
            var rel = payload.AsSpan(searchFrom).IndexOf(key);
            if (rel < 0)
                return false;

            var after = searchFrom + rel + key.Length;
            // CloudKit Value: type INT64/UINT64 poi signed/unsigned varint.
            // Cerca tag 0x08 (field1 varint = type) poi 0x10 (field2 varint = value) nelle vicinanze.
            for (var probe = after; probe < after + 24 && probe < payload.Length - 2; probe++)
            {
                if (payload[probe] != 0x10)
                    continue;
                var pos = probe + 1;
                try
                {
                    var raw = ReadVarint(payload, ref pos);
                    value = unchecked((int)raw);
                    if (value is >= 1 and <= 11)
                        return true;
                }
                catch
                {
                    // next
                }
            }

            searchFrom += rel + 1;
        }

        return false;
    }

    private static ulong ReadVarint(byte[] data, ref int pos)
    {
        ulong result = 0;
        var shift = 0;
        while (pos < data.Length)
        {
            var b = data[pos++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return result;
            shift += 7;
            if (shift > 63)
                throw new InvalidDataException("varint");
        }

        throw new InvalidDataException("varint EOF");
    }

    private static bool TryExtractAsciiPathPair(
        string latin,
        out string domain,
        out string relativePath)
    {
        domain = "";
        relativePath = "";
        const string appDomain = "AppDomain";
        var dIdx = latin.IndexOf(appDomain, StringComparison.Ordinal);
        var pIdx = latin.IndexOf("Library/", StringComparison.Ordinal);
        if (dIdx < 0 || pIdx < 0)
            return false;

        domain = TakeToken(latin, dIdx);
        relativePath = TakeToken(latin, pIdx);
        return domain.Length > 8 && relativePath.Length > 4;
    }

    private static string TakeToken(string s, int start)
    {
        var end = start;
        while (end < s.Length)
        {
            var c = s[end];
            if (c < 32 || c > 126 || c is '"' or '\'' or ';' or ',')
                break;
            end++;
            if (end - start > 240)
                break;
        }

        return s[start..end].Trim();
    }
}
