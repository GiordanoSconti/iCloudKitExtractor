using System.IO;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Escrow;

public sealed record EscrowPcsUnlockResult(
    bool Success,
    string Message,
    string? OutputPath = null,
    byte[]? Plaintext = null,
    string? MasterKeyIdHex = null);

/// <summary>
/// Unlock <c>kPCSMetadataEscrowedKeys</c> con <c>BackupBagPassword</c>
/// (InflatableDonkey <c>ProtectedRecord.unlockData</c>).
/// </summary>
public static class EscrowPcsUnlock
{
    public const string EscrowedKeysFileName = "pcs_escrowed_keys.bin";
    public const string EscrowedKeysAltFileName = "kPCSMetadataEscrowedKeys.bin";
    public const string UnlockedKeysFileName = "escrowed_pcs_keys.bin";
    public const string UnlockMetaFileName = "escrow_pcs_unlock_meta.json";

    public static async Task<EscrowPcsUnlockResult> UnlockFromDirectoryAsync(
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var bagPath = Path.Combine(outputDirectory, EscrowPcsKeyUnwrap.BackupBagPasswordFileName);
        if (!File.Exists(bagPath))
        {
            return new EscrowPcsUnlockResult(
                false,
                $"Manca {EscrowPcsKeyUnwrap.BackupBagPasswordFileName} — esegui prima Unwrap PCS.");
        }

        var keysPath = ResolveEscrowedKeysPath(outputDirectory);
        if (keysPath is null)
        {
            return new EscrowPcsUnlockResult(
                false,
                $"Manca {EscrowedKeysFileName} (o {EscrowedKeysAltFileName}) — riesegui get_records / recover.");
        }

        var bag = await File.ReadAllBytesAsync(bagPath, ct);
        var escrowed = await File.ReadAllBytesAsync(keysPath, ct);
        log?.Report(
            $"  Unlock PCS: bag={bag.Length} B, escrowedKeys={escrowed.Length} B ← {Path.GetFileName(keysPath)}");

        return await UnlockAsync(bag, escrowed, outputDirectory, log, ct);
    }

    public static async Task<EscrowPcsUnlockResult> UnlockAsync(
        byte[] backupBagPassword,
        byte[] kPcsMetadataEscrowedKeys,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);

        // Crypto RFC6637/GCM su thread pool: non bloccare la UI durante PCS Identities.
        var crypto = await Task.Run(() =>
        {
            if (!PcsDer.TryParseBackupEscrow(kPcsMetadataEscrowedKeys, out var escrow) || escrow is null)
            {
                return (Ok: false, Message: "BackupEscrow DER (appl[4]) non parsabile.",
                    Plain: (byte[]?)null, KeyIdHex: (string?)null, Service: (int?)null);
            }

            List<PcsCompactPrivateKey> keys;
            try
            {
                keys = PcsDer.ParseKeySetPrivateKeys(backupBagPassword);
            }
            catch (Exception ex)
            {
                return (Ok: false, Message: $"KeySet BackupBagPassword non parsabile: {ex.Message}",
                    Plain: null, KeyIdHex: null, Service: null);
            }

            if (keys.Count == 0)
            {
                return (Ok: false, Message: "KeySet senza chiavi private.",
                    Plain: null, KeyIdHex: null, Service: null);
            }

            var master = PcsDer.FindByPublicX(keys, escrow.MasterKeyPublic);
            if (master is null)
            {
                return (Ok: false,
                    Message: $"Nessuna master key per public X={Convert.ToHexString(escrow.MasterKeyPublic.AsSpan(0, Math.Min(8, escrow.MasterKeyPublic.Length)))}…",
                    Plain: null, KeyIdHex: null, Service: null);
            }

            var keyIdHex = Convert.ToHexString(master.KeyId);
            byte[] sessionKey;
            try
            {
                sessionKey = Rfc6637Pcs.UnwrapSecp256R1(escrow.WrappedKey, master.PrivateD);
            }
            catch (Exception ex)
            {
                return (Ok: false, Message: $"RFC6637 unwrap fallito: {ex.Message}",
                    Plain: null, KeyIdHex: keyIdHex, Service: master.Service);
            }

            try
            {
                var plain = Rfc6637Pcs.GcmDecryptDataB(sessionKey, escrow.Data);
                return (Ok: true, Message: "ok", Plain: plain, KeyIdHex: keyIdHex, Service: master.Service);
            }
            catch (Exception ex)
            {
                return (Ok: false, Message: $"AES-GCM DataB fallito: {ex.Message}",
                    Plain: null, KeyIdHex: keyIdHex, Service: master.Service);
            }
        }, ct);

        if (!crypto.Ok || crypto.Plain is null)
            return new EscrowPcsUnlockResult(false, crypto.Message);

        log?.Report(
            $"  master KeyID={crypto.KeyIdHex} service={crypto.Service?.ToString() ?? "?"} " +
            $"→ session OK, plaintext {crypto.Plain.Length} B");

        var outPath = Path.Combine(outputDirectory, UnlockedKeysFileName);
        await File.WriteAllBytesAsync(outPath, crypto.Plain, ct);

        var meta = JsonSerializer.Serialize(new
        {
            success = true,
            method = "RFC6637-secp256r1+AES-KW+GCMDataB",
            masterKeyIdHex = crypto.KeyIdHex,
            masterService = crypto.Service,
            plaintextBytes = crypto.Plain.Length,
            output = UnlockedKeysFileName
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, UnlockMetaFileName), meta, ct);

        log?.Report($"  Unlock PCS OK → {outPath} ({crypto.Plain.Length} B)");
        return new EscrowPcsUnlockResult(
            true,
            $"PCS KeySet sbloccato ({crypto.Plain.Length} B)",
            outPath,
            crypto.Plain,
            crypto.KeyIdHex);
    }

    public static string? ResolveEscrowedKeysPath(string outputDirectory)
    {
        foreach (var name in new[]
                 {
                     EscrowedKeysFileName,
                     EscrowedKeysAltFileName,
                     "pcs_record_metadata.bin",
                 })
        {
            var p = Path.Combine(outputDirectory, name);
            if (!File.Exists(p))
                continue;
            // Prefer true BackupEscrow blobs (appl[4] = 0x64).
            try
            {
                var head = File.ReadAllBytes(p);
                if (head.Length > 4 && head[0] == 0x64)
                    return p;
            }
            catch
            {
                // ignore
            }
        }

        // Qualsiasi file esistente tra i candidati
        foreach (var name in new[] { EscrowedKeysFileName, EscrowedKeysAltFileName })
        {
            var p = Path.Combine(outputDirectory, name);
            if (File.Exists(p))
                return p;
        }

        return null;
    }
}
