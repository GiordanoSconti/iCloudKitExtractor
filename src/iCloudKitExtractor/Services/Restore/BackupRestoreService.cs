using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Restore;

namespace iCloudKitExtractor.Services.Restore;

public sealed record SingleFileRestoreResult(
    string Passcode,
    int ProtectionClass,
    string Method,
    string OutputPath);

/// <summary>
/// Restore di un singolo file: brute-force passcode → decifra blob scaricato.
/// </summary>
public static class BackupRestoreService
{
    public static async Task<SingleFileRestoreResult> RestoreSingleFileAsync(
        string encryptedFilePath,
        string outputDirectory,
        IReadOnlyList<string>? keybagRecords = null,
        string? keybagsJsonPath = null,
        int pinMinDigits = 4,
        int pinMaxDigits = 6,
        string? knownPasscode = null,
        IEnumerable<string>? extraCandidates = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (!File.Exists(encryptedFilePath))
            throw new FileNotFoundException("File cifrato non trovato", encryptedFilePath);

        Directory.CreateDirectory(outputDirectory);

        var keybags = keybagRecords?.ToList() ?? LoadKeybags(keybagsJsonPath, outputDirectory);
        if (keybags.Count == 0)
            throw new InvalidOperationException(
                "Nessun keybag trovato. Esegui prima il download (keybags.json / keybag_*.pb).");

        if (keybags.All(CloudKitResponseParser.IsKeybagRecordId))
            throw new InvalidOperationException(
                "keybags.json contiene solo id K:<uuid>, non i blob TLV. " +
                "I keybag_data_*.bin sono ancora cifrati PCS: esegui escrow recover (iCSC) " +
                "nella tab Decifra, poi riprova quando compare un keybag TLV chiaro.");

        // Se abbiamo solo payload non-TLV (PCS), gate esplicito.
        var parseable = keybags.Count(k => IosKeybag.TryParse(k, out _, out _));
        if (parseable == 0)
        {
            throw new InvalidOperationException(
                "Nessun keybag TLV in chiaro. keybagData è ancora protetto da PCS. " +
                "Passi: 1) login iCloud 2) iCSC → Escrow recover 3) unwrap PCS " +
                "4) passcode dispositivo su Manifest.db / file.");
        }

        log?.Report($"Keybag da provare: {keybags.Count} (TLV parseable={parseable})");

        PasscodeCrackResult? cracked = null;

        var candidates = new List<string>();
        if (!string.IsNullOrWhiteSpace(knownPasscode))
            candidates.Add(knownPasscode.Trim());
        if (extraCandidates is not null)
            candidates.AddRange(extraCandidates);

        if (candidates.Count > 0)
            cracked = KeybagPasscodeBruteforcer.TryPasscodes(keybags, candidates, log);

        cracked ??= KeybagPasscodeBruteforcer.BruteforceNumericPin(
            keybags, pinMinDigits, pinMaxDigits, log, ct);

        if (cracked is null)
            throw new InvalidOperationException(
                "Passcode non trovato. Verifica PIN dispositivo o fornisci candidati extra.");

        var encrypted = await File.ReadAllBytesAsync(encryptedFilePath, ct);
        var decrypted = BackupBlobDecryptor.TryDecryptFile(encrypted, cracked.ClassKeys, log)
            ?? throw new InvalidOperationException(
                "Passcode OK ma decifra blob fallita — potrebbe servire Manifest.db per la class key corretta.");

        var baseName = Path.GetFileNameWithoutExtension(encryptedFilePath);
        var outPath = Path.Combine(outputDirectory, baseName + ".dec");
        await File.WriteAllBytesAsync(outPath, decrypted.Plaintext, ct);

        var metaPath = Path.Combine(outputDirectory, baseName + ".restore.json");
        await File.WriteAllTextAsync(metaPath, JsonSerializer.Serialize(new
        {
            encryptedFile = encryptedFilePath,
            passcodeMasked = cracked.Passcode.Length,
            protectionClass = decrypted.ProtectionClass,
            method = decrypted.Method,
            output = outPath,
            note = "Passcode = PIN di blocco dispositivo (non password Apple ID / 2FA)"
        }, new JsonSerializerOptions { WriteIndented = true }), ct);

        log?.Report($"Salvato: {outPath}");

        return new SingleFileRestoreResult(
            cracked.Passcode,
            decrypted.ProtectionClass,
            decrypted.Method,
            outPath);
    }

    private static List<string> LoadKeybags(string? keybagsJsonPath, string outputDirectory)
    {
        var path = keybagsJsonPath;
        if (string.IsNullOrWhiteSpace(path))
            path = Path.Combine(outputDirectory, "keybags.json");

        var bags = new List<string>();
        if (File.Exists(path))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(path));
                if (doc.RootElement.TryGetProperty("keybags", out var arr))
                {
                    bags.AddRange(arr.EnumerateArray()
                        .Select(e => e.GetString())
                        .Where(s => !string.IsNullOrWhiteSpace(s))
                        .Cast<string>());
                }
            }
            catch
            {
                // fall through to .bin scan
            }
        }

        // Preferisci blob TLV completi; se keybags.json ha solo id, prova i .bin accanto.
        var full = bags.Where(CloudKitResponseParser.IsFullKeybagBlob).ToList();
        if (full.Count > 0)
            return full;

        var dir = Path.GetDirectoryName(path) ?? outputDirectory;
        if (Directory.Exists(dir))
        {
            foreach (var pattern in new[] { "keybag_decrypted.bin", "keybag_blob_tlv.bin", "keybag_blob_*.bin", "keybag_data_*.bin" })
            {
                foreach (var bin in Directory.EnumerateFiles(dir, pattern))
                {
                    try
                    {
                        var bytes = File.ReadAllBytes(bin);
                        if (IosKeybag.TryParse(bytes, out _, out _))
                            bags.Add("K:" + Convert.ToBase64String(bytes));
                    }
                    catch
                    {
                        // skip
                    }
                }
            }
        }

        full = bags.Where(CloudKitResponseParser.IsFullKeybagBlob).ToList();
        if (full.Count > 0)
            return full;

        // Ultimo fallback: id o stringhe grezze (falliranno al parse con messaggio chiaro).
        return bags;
    }
}
