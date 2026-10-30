using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Decifra <c>backupProperties</c> allineato al path (live x64dbg session 7dabb5):
/// ShareProtection zona/record → CUWK(label=<c>backupProperties</c>) → PCSFP-GCM AAD type0.
/// Non fa più pool-bruteforce per-snapshot su tutto il catalog.
/// </summary>
public static class SnapshotBackupPropertiesDecryptor
{
    public const string FieldName = "backupProperties";

    /// <summary>Solo AAD type0; varianti legacy solo nel fallback lento.</summary>
    private static readonly string[] FieldAadsLegacy =
    [
        FieldName,
        "BackupProperties",
        "backupproperties",
        "Backup Property",
    ];

    public sealed record DecryptSummary(int CipherCount, int DecryptedCount, string Message);

    public static DecryptSummary TryDecryptAll(
        ICloudSession session,
        IEnumerable<BackupSnapshot> snapshots,
        byte[]? mbksyncZonesPayload,
        IProgress<string>? log = null)
    {
        var swTotal = System.Diagnostics.Stopwatch.StartNew();
        var list = snapshots.ToList();
        var withCipher = list.Count(s => s.BackupPropertiesCiphertext is { Length: > 16 });
        // #region agent log
        AgentBpLog(
            "H-HANG3",
            "bp_decrypt_start",
            new
            {
                snapshots = list.Count,
                withCipher,
                keySetLen = session.PcsEscrowedKeySet?.Length ?? 0,
                zonesPayload = mbksyncZonesPayload?.Length ?? 0,
            });
        // #endregion
        if (withCipher == 0)
            return new DecryptSummary(0, 0, "nessun backupProperties cifrato");

        if (!PcsSessionSeedKeys.HasAny(session))
        {
            foreach (var s in list.Where(s => s.BackupPropertiesCiphertext is { Length: > 16 }))
                s.BackupPropertiesStatus ??= "cifrato (PCS KeySet assente)";
            // #region agent log
            AgentBpLog("H-BP1", "bp_keyset_absent", new { withCipher });
            // #endregion
            return new DecryptSummary(withCipher, 0, "PCS KeySet assente");
        }

        var manateeFast = PcsSessionSeedKeys.IsManateePrimary(session);
        // Escrow = ParseKeySet (HEAD) + light. Narrow/no-light solo ADP/Manatee.
        List<PcsCompactPrivateKey> seedKeys;
        if (PcsSessionSeedKeys.HasEscrowKeySet(session))
            seedKeys = PcsDer.ParseKeySetPrivateKeys(session.PcsEscrowedKeySet!);
        else
            seedKeys = PcsSessionSeedKeys.Collect(
                session,
                narrowToPreferred: manateeFast && session.PcsPreferredKeyIds is { Count: > 0 },
                log: log);
        if (seedKeys.Count == 0)
        {
            // #region agent log
            AgentBpLog("H-BP1", "bp_keyset_empty", new
            {
                withCipher,
                keySetLen = session.PcsEscrowedKeySet?.Length ?? 0,
                manatee = session.PcsManateeCompactKeys?.Count ?? 0,
            });
            // #endregion
            return new DecryptSummary(withCipher, 0, "KeySet senza chiavi private");
        }

        // #region agent log
        AgentBpLog(
            "H-BP1",
            "bp_decrypt_enter",
            new
            {
                withCipher,
                keySetLen = session.PcsEscrowedKeySet?.Length ?? 0,
                manatee = session.PcsManateeCompactKeys?.Count ?? 0,
                seedKeys = seedKeys.Count,
                seedPub8 = seedKeys
                    .Select(k => Convert.ToHexString(k.PublicX.AsSpan(0, Math.Min(8, k.PublicX.Length))))
                    .Take(8)
                    .ToArray(),
                zonesPayload = mbksyncZonesPayload?.Length ?? 0,
            });
        // #endregion

        //  CreatePcsShareProtection / zone unwrap UNA volta (non per ogni snapshot).
        // Manatee: includeLight:false (light 0xFF ×100 = minuti). Escrow: light default.
        var zoneKeys = new List<ProtectionZoneKeys>();
        var poolKeys = new List<PcsCompactPrivateKey>(seedKeys);
        if (mbksyncZonesPayload is { Length: > 64 })
        {
            // #region agent log
            AgentBpLog("H-HANG2", "zone_unwrap_begin", new { zonesPayload = mbksyncZonesPayload.Length, seedKeys = seedKeys.Count });
            // #endregion
            var swZone = System.Diagnostics.Stopwatch.StartNew();
            zoneKeys = PcsProtectionZone.TryUnwrapAllIterative(
                mbksyncZonesPayload, seedKeys, includeLight: !manateeFast);
            poolKeys = PcsProtectionZone.MergeKeys(seedKeys, zoneKeys);
            if (zoneKeys.Count > 0 && manateeFast)
                PcsSessionSeedKeys.RememberFromZones(session, zoneKeys, seedKeys);
            swZone.Stop();
            log?.Report(
                $"  backupProperties: zone ShareProtection → {zoneKeys.Count} master, pool={poolKeys.Count} ({swZone.ElapsedMilliseconds} ms)");
            // #region agent log
            AgentBpLog(
                zoneKeys.Count == 0 ? "H-BP2" : "H-BP2-ok",
                "zone_shareprotection_once",
                new
                {
                    zonesPayload = mbksyncZonesPayload.Length,
                    masters = zoneKeys.Count,
                    pool = poolKeys.Count,
                    ms = swZone.ElapsedMilliseconds,
                    masterPub8 = zoneKeys
                        .Select(z => z.MasterPublicMatched is { Length: > 0 } p
                            ? Convert.ToHexString(p.AsSpan(0, Math.Min(8, p.Length)))
                            : z.MasterKeyIdHex[..Math.Min(16, z.MasterKeyIdHex.Length)])
                        .Take(8)
                        .ToArray(),
                });
            // #endregion
        }
        else
        {
            log?.Report("  backupProperties: zone payload assente — unwrap da catalog");
        }

        // Runtime evidence (bp-align): zone-only DecryptKey non apre backupProperties;
        // serve unwrap del catalog snapshot UNA volta (non ×N snapshot). Poi solo GCM.
        var shareKeys = DedupZones(zoneKeys);
        // Dedup per contenuto (ReferenceEquals fallisce se ogni snapshot ha una copia).
        var uniqueCatalogs = list
            .Select(static s => s.CatalogPayload)
            .Where(static c => c is { Length: > 64 })
            .GroupBy(CatalogFingerprint)
            .Select(static g => g.First()!)
            .ToList();

        // Dopo zone OK (solo Manatee): catalog unwrap con preferred+nested.
        if (manateeFast && zoneKeys.Count > 0 && session.PcsPreferredKeyIds is { Count: > 0 })
        {
            var narrow = PcsSessionSeedKeys.Collect(session, narrowToPreferred: true, log: log);
            if (narrow.Count > 0)
                poolKeys = PcsProtectionZone.MergeKeys(narrow, zoneKeys);
        }

        // #region agent log
        AgentBpLog(
            "H-HANG2",
            "catalog_unwrap_plan",
            new
            {
                uniqueCatalogs = uniqueCatalogs.Count,
                lens = uniqueCatalogs.Select(c => c.Length).Take(12).ToArray(),
                pool = poolKeys.Count,
            });
        // #endregion

        for (var ci = 0; ci < uniqueCatalogs.Count; ci++)
        {
            var catalog = uniqueCatalogs[ci];
            // #region agent log
            AgentBpLog("H-HANG2", "catalog_unwrap_begin", new { ci, catalogLen = catalog.Length, pool = poolKeys.Count });
            // #endregion
            var swCat = System.Diagnostics.Stopwatch.StartNew();
            var fromCatalog = PcsProtectionZone.TryUnwrapAllIterative(
                catalog, poolKeys, maxRounds: 3, includeLight: !manateeFast);
            swCat.Stop();
            // #region agent log
            AgentBpLog(
                "H-HANG2",
                "catalog_unwrap_end",
                new
                {
                    ci,
                    catalogLen = catalog.Length,
                    added = fromCatalog.Count,
                    ms = swCat.ElapsedMilliseconds,
                });
            // #endregion
            if (fromCatalog.Count == 0)
                continue;
            shareKeys = DedupZones(shareKeys.Concat(fromCatalog));
            poolKeys = PcsProtectionZone.MergeKeys(poolKeys, fromCatalog);
            log?.Report(
                $"  backupProperties: catalog ShareProtection → +{fromCatalog.Count} (tot={shareKeys.Count}) ({swCat.ElapsedMilliseconds} ms)");
            // #region agent log
            AgentBpLog(
                "H-BP2",
                "catalog_shareprotection_once",
                new
                {
                    catalogLen = catalog.Length,
                    added = fromCatalog.Count,
                    shareTot = shareKeys.Count,
                    ms = swCat.ElapsedMilliseconds,
                });
            // #endregion
        }

        if (shareKeys.Count == 0)
        {
            log?.Report("  backupProperties: nessuna ShareProtection — decrypt impossibile");
            return new DecryptSummary(withCipher, 0, "ShareProtection assente");
        }

        var decrypted = 0;
        var viaRegular = 0;
        var viaFallback = 0;
        foreach (var snapshot in list)
        {
            if (snapshot.BackupPropertiesCiphertext is not { Length: > 16 } raw)
                continue;

            var ct = BackupKeybagPcsUnlock.ExtractEncryptedBytesValue(raw);
            var swSnap = System.Diagnostics.Stopwatch.StartNew();

            // Path  GCM con chiavi già bound (zona+catalog), AAD type0.
            var plain = TryDecryptLiveStyle(shareKeys, ct, raw, out var how);
            if (plain is not null)
                viaRegular++;
            else
            {
                // Solo AAD legacy sulla stessa chiave — niente re-unwrap per snapshot.
                plain = TryDecryptWithZonesLegacy(shareKeys, ct, raw, out how);
                if (plain is not null)
                {
                    how = "aad-legacy+" + how;
                    viaFallback++;
                }
            }

            swSnap.Stop();
            // #region agent log
            AgentBpLog(
                plain is null ? "H-BP-fail" : "H-BP-ok",
                plain is null ? "snapshot_fail" : "snapshot_ok",
                new
                {
                    record = snapshot.RecordName,
                    path = how,
                    ms = swSnap.ElapsedMilliseconds,
                    share = shareKeys.Count,
                    ctLen = ct.Length,
                    gcmVer = ct.Length > 0 ? (int)ct[0] : -1,
                });
            // #endregion

            if (plain is not { Length: > 0 })
            {
                snapshot.BackupPropertiesStatus = "decrypt fallito";
                continue;
            }

            if (!TryApplyPlist(snapshot, plain, out var err))
            {
                snapshot.BackupPropertiesStatus = $"plist: {err}";
                snapshot.BackupPropertiesPlaintext = plain;
                continue;
            }

            snapshot.BackupPropertiesPlaintext = plain;
            snapshot.BackupPropertiesStatus = "ok";
            decrypted++;
        }

        swTotal.Stop();
        var msg = decrypted > 0
            ? $"ok {decrypted}/{withCipher} (regular={viaRegular}, fallback={viaFallback}, {swTotal.ElapsedMilliseconds} ms)"
            : $"nessun decrypt riuscito ({withCipher} ciphertext, {swTotal.ElapsedMilliseconds} ms)";
        log?.Report($"  backupProperties: {msg}");
        // #region agent log
        AgentBpLog(
            "H-BP2",
            "decrypt_all_done",
            new
            {
                withCipher,
                decrypted,
                viaRegular,
                viaFallback,
                shareKeys = shareKeys.Count,
                catalogs = uniqueCatalogs.Count,
                ms = swTotal.ElapsedMilliseconds,
            });
        // #endregion
        return new DecryptSummary(withCipher, decrypted, msg);
    }

    private static string CatalogFingerprint(byte[]? c)
    {
        if (c is not { Length: > 0 })
            return "empty";
        var n = Math.Min(32, c.Length);
        var head = Convert.ToHexString(c.AsSpan(0, n));
        var tail = Convert.ToHexString(c.AsSpan(c.Length - n, n));
        return $"{c.Length}:{head}:{tail}";
    }

    // Kept for diagnostics / future record-local PI; not used on hot path after catalog-once.
    private static List<ProtectionZoneKeys> TryBindRecordShareProtection(
        BackupSnapshot snapshot,
        IReadOnlyList<PcsCompactPrivateKey> poolKeys)
    {
        if (snapshot.CatalogPayload is not { Length: > 64 } catalog)
            return [];

        var window = TryLocateRecordWindow(catalog, snapshot.RecordName);
        if (window is null)
            return [];

        var recordPi = PcsProtectionZone.TryExtractRecordProtectionInfoDer(window);
        if (recordPi is { Length: > 0 })
        {
            var fromPi = PcsProtectionZone.TryUnwrapAll(recordPi, poolKeys, includeLight: false);
            if (fromPi.Count > 0)
                return fromPi;
            fromPi = PcsProtectionZone.TryUnwrapAllIterative(
                recordPi, poolKeys, maxRounds: 2, includeLight: false);
            if (fromPi.Count > 0)
                return fromPi;
        }

        if (window.Length <= 8192)
            return PcsProtectionZone.TryUnwrapAll(window, poolKeys, includeLight: false);

        return [];
    }

    private static byte[]? TryLocateRecordWindow(byte[] catalog, string recordName)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            return null;

        var names = new List<string> { recordName };
        if (!recordName.StartsWith("S:", StringComparison.Ordinal))
            names.Add("S:" + recordName);
        else if (recordName.Length > 2)
            names.Add(recordName[2..]);

        foreach (var name in names)
        {
            foreach (var enc in new[] { Encoding.ASCII, Encoding.Unicode })
            {
                var needle = enc.GetBytes(name);
                var idx = IndexOfBytes(catalog, needle);
                if (idx < 0)
                    continue;
                var start = Math.Max(0, idx - 512);
                var end = Math.Min(catalog.Length, idx + needle.Length + 2048);
                return catalog.AsSpan(start, end - start).ToArray();
            }
        }

        return null;
    }

    private static int IndexOfBytes(byte[] hay, byte[] needle)
    {
        if (needle.Length == 0 || hay.Length < needle.Length)
            return -1;
        for (var i = 0; i <= hay.Length - needle.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (hay[i + j] != needle[j])
                {
                    ok = false;
                    break;
                }
            }

            if (ok)
                return i;
        }

        return -1;
    }

    /// <summary>type0: una sola AAD = field name; prova ct poi raw.</summary>
    private static byte[]? TryDecryptLiveStyle(
        IReadOnlyList<ProtectionZoneKeys> zones,
        byte[] ct,
        byte[] raw,
        out string how)
    {
        how = "";
        foreach (var zone in zones)
        {
            var plain = PcsProtectionZone.TryDecryptField(zone, ct, FieldName);
            if (plain is { Length: > 0 })
            {
                how = $"ike-ct+{zone.MasterKeyIdHex}";
                return plain;
            }

            if (!ReferenceEquals(ct, raw))
            {
                plain = PcsProtectionZone.TryDecryptField(zone, raw, FieldName);
                if (plain is { Length: > 0 })
                {
                    how = $"ike-raw+{zone.MasterKeyIdHex}";
                    return plain;
                }
            }
        }

        return null;
    }

    private static List<ProtectionZoneKeys> DedupZones(IEnumerable<ProtectionZoneKeys> zones) =>
        zones
            .GroupBy(static z => Convert.ToHexString(z.MasterKey), StringComparer.Ordinal)
            .Select(static g => g.First())
            .ToList();

    private static byte[]? TryDecryptWithZonesLegacy(
        IReadOnlyList<ProtectionZoneKeys> zones,
        byte[] ct,
        byte[] raw,
        out string how)
    {
        how = "";
        foreach (var zone in zones)
        {
            var plain = PcsProtectionZone.TryDecryptField(zone, ct, FieldAadsLegacy);
            if (plain is { Length: > 0 })
            {
                how = $"ct+{zone.MasterKeyIdHex}";
                return plain;
            }

            if (!ReferenceEquals(ct, raw))
            {
                plain = PcsProtectionZone.TryDecryptField(zone, raw, FieldAadsLegacy);
                if (plain is { Length: > 0 })
                {
                    how = $"raw+{zone.MasterKeyIdHex}";
                    return plain;
                }
            }
        }

        return null;
    }

    // #region agent log
    private static void AgentBpLog(string hypothesisId, string message, object data)
    {
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "backup-pcs1",
                ["hypothesisId"] = hypothesisId,
                ["location"] = "SnapshotBackupPropertiesDecryptor",
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    public static bool TryApplyPlist(BackupSnapshot snapshot, byte[] plain, out string? error)
    {
        error = null;
        Dictionary<string, object?>? dict = null;

        if (plain.Length >= 8 && plain.AsSpan(0, 6).SequenceEqual("bplist"u8))
        {
            if (!AppleBinaryPlist.TryParseDict(plain, out dict, out error) || dict is null)
                return false;
        }
        else
        {
            // XML plist (o frammento con <?xml …)
            var xmlStart = IndexOfXmlPlist(plain);
            if (xmlStart < 0)
            {
                error = "né bplist né xml";
                return false;
            }

            try
            {
                var slice = plain.AsSpan(xmlStart).ToArray();
                dict = AppleXmlPlist.Parse(slice);
            }
            catch (Exception ex)
            {
                error = ex.Message;
                return false;
            }
        }

        ApplyDict(snapshot, dict);
        return true;
    }

    private static void ApplyDict(BackupSnapshot snapshot, Dictionary<string, object?> dict)
    {
        if (TryGetString(dict, "Version") is { Length: > 0 } version)
            snapshot.BackupPropertiesVersion = version;

        if (TryGetString(dict, "SystemDomainsVersion") is { Length: > 0 } sysDom)
            snapshot.SystemDomainsVersion = sysDom;

        if (TryGetString(dict, "ActiveAppleID") is { Length: > 0 } appleId)
            snapshot.ActiveAppleId = appleId;

        if (TryGetBool(dict, "WasPasscodeSet") is bool passcode)
            snapshot.WasPasscodeSet = passcode;

        if (TryGetInt(dict, "AccountType") is int accountType)
            snapshot.AccountType = accountType;

        if (TryGetDate(dict, "Date") is { } propsDate)
        {
            snapshot.BackupPropertiesDate = propsDate;
            snapshot.BackupDate ??= propsDate;
        }

        // InflatableDonkey: Lockdown.* — UDID hardware, modello, seriale.
        if (dict.TryGetValue("Lockdown", out var lockdownObj)
            && lockdownObj is Dictionary<string, object?> lockdown)
        {
            if (TryGetString(lockdown, "UniqueDeviceID") is { Length: > 0 } uniqueId)
                snapshot.HardwareUdid = NormalizeHardwareUdid(uniqueId);

            if (string.IsNullOrWhiteSpace(snapshot.ProductVersion)
                && TryGetString(lockdown, "ProductVersion") is { Length: > 0 } ios)
                snapshot.ProductVersion = ios;

            if (string.IsNullOrWhiteSpace(snapshot.BuildVersion)
                && TryGetString(lockdown, "BuildVersion") is { Length: > 0 } build)
                snapshot.BuildVersion = build;

            if (TryGetString(lockdown, "ProductType") is { Length: > 0 } productType)
                snapshot.LockdownProductType = productType;

            if (TryGetString(lockdown, "SerialNumber") is { Length: > 0 } serial)
                snapshot.LockdownSerialNumber = serial;

            if (TryGetString(lockdown, "DeviceName") is { Length: > 0 } deviceName)
                snapshot.LockdownDeviceName = deviceName;
        }

        if (string.IsNullOrWhiteSpace(snapshot.ActiveAppleId)
            && dict.TryGetValue("AppleIDs", out var appleIdsObj)
            && appleIdsObj is Dictionary<string, object?> appleIds
            && appleIds.Keys.FirstOrDefault() is { Length: > 0 } firstId)
        {
            snapshot.ActiveAppleId = firstId;
        }
    }

    /// <summary>
    /// Propaga <c>Lockdown.UniqueDeviceID</c> (e campi correlati) dal plist snapshot al device.
    /// </summary>
    public static void ApplyHardwareIdentityToDevices(IEnumerable<BackupDevice> devices)
    {
        foreach (var device in devices)
        {
            foreach (var snapshot in device.Snapshots)
            {
                if (string.IsNullOrWhiteSpace(device.HardwareUdid)
                    && !string.IsNullOrWhiteSpace(snapshot.HardwareUdid))
                    device.HardwareUdid = snapshot.HardwareUdid;

                if (string.IsNullOrWhiteSpace(device.SerialNumber)
                    && !string.IsNullOrWhiteSpace(snapshot.LockdownSerialNumber))
                    device.SerialNumber = snapshot.LockdownSerialNumber;

                if (string.IsNullOrWhiteSpace(device.ProductType)
                    && !string.IsNullOrWhiteSpace(snapshot.LockdownProductType))
                    device.ProductType = snapshot.LockdownProductType;

                if (string.IsNullOrWhiteSpace(device.DisplayName)
                    && !string.IsNullOrWhiteSpace(snapshot.LockdownDeviceName))
                    device.DisplayName = snapshot.LockdownDeviceName;
            }
        }
    }

    /// <summary>
    /// Normalizza UniqueDeviceID: mantiene forma Apple <c>00008150-…</c> oppure hex continuo.
    /// </summary>
    public static string? NormalizeHardwareUdid(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var value = raw.Trim();
        // 00008150-0014153C2620401C
        if (Regex.IsMatch(value, @"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{16}$"))
            return value.ToUpperInvariant();

        var hex = value.Replace("-", "", StringComparison.Ordinal).Trim();
        if (Regex.IsMatch(hex, @"^[0-9A-Fa-f]{24,40}$"))
        {
            // Preferisci forma dashed se 24 hex (ECID-style modern UDID).
            if (hex.Length == 24)
                return $"{hex[..8]}-{hex[8..]}".ToUpperInvariant();
            return hex.ToLowerInvariant();
        }

        return value;
    }

    private static int IndexOfXmlPlist(byte[] data)
    {
        var marker = "<?xml"u8;
        var span = data.AsSpan();
        var idx = span.IndexOf(marker);
        return idx;
    }

    private static string? TryGetString(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value) || value is null)
            return null;
        return value switch
        {
            string s => s.Trim(),
            byte[] b => Encoding.UTF8.GetString(b).Trim(),
            _ => value.ToString()?.Trim()
        };
    }

    private static bool? TryGetBool(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value) || value is null)
            return null;
        return value switch
        {
            bool b => b,
            string s when bool.TryParse(s, out var b) => b,
            int i => i != 0,
            long l => l != 0,
            _ => null
        };
    }

    private static int? TryGetInt(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value) || value is null)
            return null;
        return value switch
        {
            int i => i,
            long l when l is >= int.MinValue and <= int.MaxValue => (int)l,
            string s when int.TryParse(s, NumberStyles.Integer, CultureInfo.InvariantCulture, out var n) => n,
            _ => null
        };
    }

    private static DateTimeOffset? TryGetDate(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value) || value is null)
            return null;
        return value switch
        {
            DateTimeOffset dto => dto,
            DateTime dt => new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)),
            string s when DateTimeOffset.TryParse(s, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var dto) => dto,
            double d => DateTimeOffset.FromUnixTimeSeconds(0).AddSeconds(d), // rare
            _ => null
        };
    }
}
