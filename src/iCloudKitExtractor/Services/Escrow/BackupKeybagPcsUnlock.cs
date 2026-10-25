using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>Esito unlock PCS dei record CloudKit <c>Keybag</c> (K:).</summary>
public sealed record BackupKeybagPcsUnlockResult(
    bool Success,
    string Message,
    int DecryptedCount,
    int UnlockedCount,
    string? DecryptedFile = null);

/// <summary>
/// InflatableDonkey <c>KeyBagFactory</c>: zone mbksync → PI record K: →
/// GCM decrypt <c>keybagData</c>/<c>secret</c> → TLV + unlock class keys.
/// Usa il KeySet già prodotto dalla scheda Escrow (<see cref="ICloudSession.PcsEscrowedKeySet"/>).
/// </summary>
public static class BackupKeybagPcsUnlock
{
    public const string DecryptedFileName = "keybag_decrypted.bin";
    public const string UnlockMetaFileName = "keybag_pcs_unlock_meta.json";

    public static BackupKeybagPcsUnlockResult Unlock(
        ICloudSession session,
        BackupDevice device,
        byte[]? mbksyncZonesPayload,
        string outputDirectory,
        IProgress<string>? log = null)
    {
        Directory.CreateDirectory(outputDirectory);

        if (!PcsSessionSeedKeys.HasAny(session))
        {
            return new BackupKeybagPcsUnlockResult(
                false,
                "PCS assente — Unlock EscrowedKeys e/o CKKS OpenVault (Octagon) prima.",
                0,
                0);
        }

        if (device.KeybagRawPayloads.Count == 0 && device.KeybagDataBlobs.Count == 0)
        {
            return new BackupKeybagPcsUnlockResult(
                false, "Nessun record K: / keybagData da sbloccare.", 0, 0);
        }

        // Escrow classico = HEAD (solo KeySet). Manatee ADP = Collect + Remember.
        var manateeFast = PcsSessionSeedKeys.IsManateePrimary(session);
        List<PcsCompactPrivateKey> seedKeys;
        if (PcsSessionSeedKeys.HasEscrowKeySet(session))
        {
            seedKeys = PcsDer.ParseKeySetPrivateKeys(session.PcsEscrowedKeySet!);
            TryAddBagPasswordKeys(session, seedKeys, log);
            log?.Report($"Keybag PCS: {seedKeys.Count} chiavi seed (escrow KeySet)");
        }
        else
        {
            seedKeys = PcsSessionSeedKeys.Collect(
                session,
                narrowToPreferred: manateeFast && session.PcsPreferredKeyIds is { Count: > 0 },
                log: log);
            TryAddBagPasswordKeys(session, seedKeys, log);
            log?.Report($"Keybag PCS: {seedKeys.Count} chiavi seed (manatee)");
        }

        var poolKeys = new List<PcsCompactPrivateKey>(seedKeys);
        var zoneDecryptKeys = new List<ProtectionZoneKeys>();

        if (mbksyncZonesPayload is { Length: > 64 })
        {
            // Escrow: firma HEAD (default light). Manatee: light ON (serve nested FL).
            var zoneZones = PcsProtectionZone.TryUnwrapAll(mbksyncZonesPayload, seedKeys);
            zoneDecryptKeys.AddRange(zoneZones);
            poolKeys = PcsProtectionZone.MergeKeys(seedKeys, zoneZones);
            if (zoneZones.Count > 0 && manateeFast)
                PcsSessionSeedKeys.RememberFromZones(session, zoneZones, seedKeys);
            log?.Report(
                $"  zone mbksync PI → {zoneZones.Count} master, pool chiavi={poolKeys.Count}");
        }
        else
        {
            log?.Report("  zone mbksync payload assente — provo solo PI sui record K:");
        }

        var decrypted = 0;
        var unlocked = 0;
        string? firstDecryptedPath = null;
        var details = new List<object>();

        foreach (var (id, payload) in device.KeybagRawPayloads)
        {
            var recordZones = PcsProtectionZone.TryUnwrapAll(payload, poolKeys);
            var decryptPool = new List<ProtectionZoneKeys>();
            decryptPool.AddRange(recordZones);
            decryptPool.AddRange(zoneDecryptKeys);
            // Dedup by master
            decryptPool = decryptPool
                .GroupBy(z => Convert.ToHexString(z.MasterKey), StringComparer.Ordinal)
                .Select(g => g.First())
                .ToList();

            if (decryptPool.Count == 0)
            {
                log?.Report($"  {id}: nessun ProtectionInfo unwrapped (serve zone mbksync?)");
                details.Add(new { id, ok = false, error = "no-protection-zone" });
                continue;
            }

            log?.Report($"  {id}: PI zones={recordZones.Count}, decrypt pool={decryptPool.Count}");

            var fields = CloudKitResponseParser.ExtractNamedByteFields(payload, "keybagData", "secret");
            if (!fields.TryGetValue("keybagData", out var rawKb)
                && device.KeybagDataBlobs.TryGetValue(id, out var cached))
                rawKb = cached;

            if (rawKb is null)
            {
                log?.Report($"  {id}: keybagData assente");
                details.Add(new { id, ok = false, error = "no-keybagData" });
                continue;
            }

            fields.TryGetValue("secret", out var rawSecret);

            var kbCt = ExtractEncryptedBytesValue(rawKb);
            var secretCt = rawSecret is null ? null : ExtractEncryptedBytesValue(rawSecret);

            byte[]? kbPlain = null;
            byte[]? secretPlain = null;
            string? usedKeyId = null;

            foreach (var zone in decryptPool)
            {
                kbPlain ??= PcsProtectionZone.TryDecryptField(zone, kbCt, "keybagData");
                if (secretCt is not null)
                    secretPlain ??= PcsProtectionZone.TryDecryptField(zone, secretCt, "secret");

                if (kbPlain is not null)
                {
                    usedKeyId = zone.MasterKeyIdHex;
                    if (secretCt is null || secretPlain is not null)
                        break;
                }
            }

            // Retry outer wrapper (Value completo) se lo strip ha fallito.
            if (kbPlain is null)
            {
                foreach (var zone in decryptPool)
                {
                    kbPlain = PcsProtectionZone.TryDecryptField(zone, rawKb, "keybagData");
                    if (kbPlain is not null)
                    {
                        usedKeyId = zone.MasterKeyIdHex;
                        break;
                    }
                }
            }

            if (secretPlain is null && rawSecret is not null)
            {
                foreach (var zone in decryptPool)
                {
                    secretPlain = PcsProtectionZone.TryDecryptField(zone, rawSecret, "secret");
                    if (secretPlain is not null)
                        break;
                }
            }

            if (kbPlain is null)
            {
                log?.Report($"  {id}: GCM keybagData FAIL (pool={decryptPool.Count})");
                details.Add(new { id, ok = false, error = "gcm-keybagData", zones = decryptPool.Count });
                continue;
            }

            decrypted++;
            var safe = Sanitize(id);
            var tlvName = $"keybag_tlv_{safe}.bin";
            var tlvPath = Path.Combine(outputDirectory, tlvName);
            File.WriteAllBytes(tlvPath, kbPlain);
            firstDecryptedPath ??= DecryptedFileName;
            File.WriteAllBytes(Path.Combine(outputDirectory, DecryptedFileName), kbPlain);

            if (secretPlain is not null)
            {
                File.WriteAllBytes(
                    Path.Combine(outputDirectory, $"keybag_secret_{safe}.bin"), secretPlain);
            }

            var unlockedOk = false;
            var classKeyCount = 0;
            string? format = null;
            string? bagKeyHex = null;
            string? modernErr = null;

            if (IosKeybag.TryParse(kbPlain, out var keybag, out var parseErr) && keybag is not null)
            {
                format = "classic-TLV";
                var asRecord = "K:" + Convert.ToBase64String(kbPlain);
                if (!device.Keybags.Contains(asRecord, StringComparer.Ordinal))
                    device.Keybags.Add(asRecord);

                if (secretPlain is { Length: > 0 } && keybag.TryUnlock(secretPlain))
                {
                    unlockedOk = true;
                    unlocked++;
                    classKeyCount = keybag.UnwrappedClassKeys.Count;
                    log?.Report(
                        $"  {id}: TLV OK ({kbPlain.Length:N0} B) unlocked " +
                        $"type={keybag.KeybagType} classKeys={classKeyCount} via {usedKeyId}");
                }
                else
                {
                    log?.Report(
                        $"  {id}: TLV OK ({kbPlain.Length:N0} B type={keybag.KeybagType}) " +
                        $"unlock class keys={(secretPlain is { Length: > 0 } ? "FAIL" : "skip-no-secret")}");
                }
            }
            else if (secretPlain is { Length: > 0 }
                     && ModernBackupKeybag.TryUnwrap(kbPlain, secretPlain, out var modern, out modernErr)
                     && modern is not null)
            {
                format = "modern-DER";
                unlockedOk = true;
                unlocked++;
                bagKeyHex = Convert.ToHexString(modern.BagKey);
                File.WriteAllBytes(Path.Combine(outputDirectory, $"keybag_key_{safe}.bin"), modern.BagKey);
                File.WriteAllBytes(Path.Combine(outputDirectory, DecryptedFileName), modern.BagKey);
                firstDecryptedPath = DecryptedFileName;
                log?.Report(
                    $"  {id}: modern Keybag OK — uuid={Convert.ToHexString(modern.Uuid)} " +
                    $"type={modern.Type} bagKey=32 B (PBKDF2-SHA256(secret,salt,1)+AES-KW)");
            }
            else
            {
                log?.Report(
                    $"  {id}: plaintext {kbPlain.Length:N0} B non TLV" +
                    (parseErr is null ? "" : $" ({parseErr})") +
                    (modernErr is null ? "" : $"; modern={modernErr}"));
            }

            details.Add(new
            {
                id,
                ok = unlockedOk || format is not null,
                format,
                keybagDataBytes = kbPlain.Length,
                secretBytes = secretPlain?.Length,
                tlv = tlvName,
                unlocked = unlockedOk,
                classKeys = classKeyCount,
                bagKeyHex,
                masterKeyId = usedKeyId
            });
        }

        var meta = JsonSerializer.Serialize(new
        {
            success = decrypted > 0,
            decrypted,
            unlocked,
            decryptedFile = firstDecryptedPath,
            seedKeys = seedKeys.Count,
            zoneMasters = zoneDecryptKeys.Count,
            details,
            note =
                "GCM(keybagData/secret) poi: classic TLV+PBKDF2 oppure " +
                "modern DER (uuid|wrapped|salt) → PBKDF2-SHA256(secret,salt,1)+AES-KW → bagKey 32 B."
        }, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(Path.Combine(outputDirectory, UnlockMetaFileName), meta);

        if (decrypted == 0)
        {
            return new BackupKeybagPcsUnlockResult(
                false,
                "Nessun keybagData decifrato — verificare KeySet Escrow e zone/retrieve mbksync.",
                0,
                0);
        }

        return new BackupKeybagPcsUnlockResult(
            true,
            $"OK — {decrypted} keybagData decifrati, {unlocked} sbloccati",
            decrypted,
            unlocked,
            firstDecryptedPath);
    }

    /// <summary>
    /// Estrae il ciphertext GCM da un Value CloudKit
    /// (<c>type=20 ENCRYPTED_BYTES</c> ‖ <c>bytesValue</c>) oppure restituisce il blob se già GCM.
    /// </summary>
    public static byte[] ExtractEncryptedBytesValue(byte[] raw)
    {
        // CloudKit Value: field1 type=20 (08 14), field2 bytesValue (12 <varint> <gcm>)
        // backupProperties usa varint multi-byte (es. ~16 KB) — non solo len < 0x80.
        if (raw.Length >= 5 && raw[0] == 0x08 && raw[1] == 0x14 && raw[2] == 0x12)
        {
            var pos = 3;
            var len = 0;
            var shift = 0;
            while (pos < raw.Length && shift <= 28)
            {
                var b = raw[pos++];
                len |= (b & 0x7F) << shift;
                if ((b & 0x80) == 0)
                {
                    if (len > 0 && pos + len <= raw.Length)
                        return raw.AsSpan(pos, len).ToArray();
                    break;
                }

                shift += 7;
            }
        }

        // Già GCM DataA (versione 0–3).
        if (raw.Length > 4 && raw[0] <= 3)
            return raw;

        return raw;
    }

    private static void TryAddBagPasswordKeys(
        ICloudSession session,
        List<PcsCompactPrivateKey> seedKeys,
        IProgress<string>? log)
    {
        var dir = session.PcsKeysDirectory;
        if (string.IsNullOrWhiteSpace(dir))
            return;

        var bagPath = Path.Combine(dir, EscrowPcsKeyUnwrap.BackupBagPasswordFileName);
        if (!File.Exists(bagPath))
            return;

        try
        {
            var bag = File.ReadAllBytes(bagPath);
            var extra = PcsDer.ParseKeySetPrivateKeys(bag);
            if (extra.Count == 0)
                return;

            var seen = new HashSet<string>(
                seedKeys.Select(k => Convert.ToHexString(k.KeyId)),
                StringComparer.Ordinal);
            var added = 0;
            foreach (var k in extra)
            {
                if (seen.Add(Convert.ToHexString(k.KeyId)))
                {
                    seedKeys.Add(k);
                    added++;
                }
            }

            if (added > 0)
                log?.Report($"  +{added} chiavi da BackupBagPassword.bin");
        }
        catch (Exception ex)
        {
            log?.Report($"  BackupBagPassword skip: {ex.Message}");
        }
    }

    private static string Sanitize(string recordId)
    {
        var s = recordId.StartsWith("K:", StringComparison.Ordinal) ? recordId[2..] : recordId;
        var chars = s.Select(c => char.IsLetterOrDigit(c) ? c : '_').ToArray();
        var stem = new string(chars);
        return stem.Length > 48 ? stem[..48] : stem;
    }
}
