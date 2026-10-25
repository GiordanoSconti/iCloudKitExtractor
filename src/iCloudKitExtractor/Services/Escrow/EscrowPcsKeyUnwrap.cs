using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Plaintext post AES(K_SRP): KeyVault type <c>0x0A</c>.
/// </summary>
public sealed record EscrowRecoverPlaintext(
    string Dsid,
    byte[] Salt,
    byte[] Section2,
    byte[] WrappedSec3,
    string Label,
    string Timestamp,
    byte[] Raw);

/// <summary>Esito unwrap PCS post-K_SRP (PBKDF2(dsid) → BackupBagPassword).</summary>
public sealed record EscrowPcsUnwrapResult(
    bool Success,
    string Message,
    string? Method = null,
    string? OutputPath = null,
    byte[]? BackupBagPassword = null,
    byte[]? BackupKeybagDigest = null,
    string? DetectedKind = null);

/// <summary>
/// Completa il gate post-SRP:
/// <list type="bullet">
/// <item> <c>type2 = PBKDF2-SHA256(dsid, salt64, 10000, 16)</c> + AesSiv → bplist</item>
/// <item>Legacy InflatableDonkey: same type2 + AES-128-CBC(IV=salt[0:16])</item>
/// </list>
/// </summary>
public static class EscrowPcsKeyUnwrap
{
    public const string UnwrappedFileName = "escrow_pcs_unwrapped.bin";
    public const string Sec3PlainFileName = "escrow_pcs_sec3_bplist.bin";
    public const string BackupBagPasswordFileName = "BackupBagPassword.bin";
    public const string BackupKeybagDigestFileName = "BackupKeybagDigest.bin";
    public const string KeybagKeyMetaFileName = "keybag_key_unwrap_meta.json";
    public const string SectionsDirName = "escrow_pcs_sections";
    public const int Pbkdf2Iterations = 10_000;

    /// <summary>KeyVault nested type 0x0A (6 sezioni).</summary>
    public static bool TryParseRecoverPlaintext(byte[] plain, out EscrowRecoverPlaintext? parsed)
    {
        parsed = null;
        if (plain.Length < 64)
            return false;

        if (BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(0, 4)) != 0x0A)
            return false;

        const int bodyBase = 32;
        if (plain.Length < bodyBase + 8)
            return false;

        var offsets = new int[7];
        for (var i = 0; i < 7; i++)
            offsets[i] = (int)BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(4 + i * 4, 4));

        var sections = new byte[6][];
        for (var i = 0; i < 6; i++)
        {
            var start = bodyBase + offsets[i];
            if (start + 4 > plain.Length)
                return false;
            var size = (int)BinaryPrimitives.ReadUInt32BigEndian(plain.AsSpan(start, 4));
            if (size < 0 || start + 4 + size > plain.Length)
                return false;
            sections[i] = plain[(start + 4)..(start + 4 + size)];
        }

        if (sections[0].Length is < 1 or > 32)
            return false;
        if (sections[1].Length != 64)
            return false;
        if (sections[3].Length < 32)
            return false;

        parsed = new EscrowRecoverPlaintext(
            Encoding.ASCII.GetString(sections[0]),
            sections[1],
            sections[2],
            sections[3],
            Encoding.ASCII.GetString(sections[4]),
            Encoding.ASCII.GetString(sections[5]),
            plain);
        return true;
    }

    public static async Task SaveSectionsAsync(
        string outputDirectory,
        EscrowRecoverPlaintext parsed,
        CancellationToken ct = default)
    {
        var dir = Path.Combine(outputDirectory, SectionsDirName);
        Directory.CreateDirectory(dir);
        await File.WriteAllBytesAsync(
            Path.Combine(dir, "sec0_dsid.bin"), Encoding.ASCII.GetBytes(parsed.Dsid), ct);
        await File.WriteAllBytesAsync(Path.Combine(dir, "sec1_salt.bin"), parsed.Salt, ct);
        await File.WriteAllBytesAsync(Path.Combine(dir, "sec2.bin"), parsed.Section2, ct);
        await File.WriteAllBytesAsync(Path.Combine(dir, "sec3_wrapped.bin"), parsed.WrappedSec3, ct);
        await File.WriteAllTextAsync(Path.Combine(dir, "sec4_label.txt"), parsed.Label, ct);
        await File.WriteAllTextAsync(Path.Combine(dir, "sec5_timestamp.txt"), parsed.Timestamp, ct);
    }

    /// <summary>
    /// Unwrap offline da <see cref="UnwrappedFileName"/> (dsid da sec0 — niente iCSC).
    /// </summary>
    public static async Task<EscrowPcsUnwrapResult> UnwrapFromDirectoryAsync(
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var path = Path.Combine(outputDirectory, UnwrappedFileName);
        if (!File.Exists(path))
        {
            return new EscrowPcsUnwrapResult(
                false,
                $"Manca {UnwrappedFileName} — esegui prima recover SRP (P=dsid).");
        }

        var plain = await File.ReadAllBytesAsync(path, ct);
        return await UnwrapAsync(plain, outputDirectory, log, ct);
    }

    public static async Task<EscrowPcsUnwrapResult> UnwrapAsync(
        byte[] recoverPlaintext,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);

        if (!TryParseRecoverPlaintext(recoverPlaintext, out var parsed) || parsed is null)
        {
            return new EscrowPcsUnwrapResult(
                false,
                "Plaintext recover non è KeyVault 0x0A (dsid|salt|…|sec3).");
        }

        await SaveSectionsAsync(outputDirectory, parsed, ct);
        log?.Report(
            $"  PCS KeyVault 0x0A: dsid={parsed.Dsid} label={parsed.Label} " +
            $"sec3={parsed.WrappedSec3.Length} B salt={parsed.Salt.Length} B");

        // MUT B: type2 = PBKDF2(dsid, sec1=RecordData_64, 10000, 16) → AesSiv(sec3).
        // Legacy: same type2 → AES-CBC(IV=salt[0:16]).
        byte[] sec3Plain;
        string sec3Method;
        try
        {
            sec3Plain = DecryptSec3(parsed.Dsid, parsed.Salt, parsed.WrappedSec3, out sec3Method);
        }
        catch (Exception ex)
        {
            return new EscrowPcsUnwrapResult(false, $"AES/AesSiv sec3 fallito: {ex.Message}");
        }

        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, Sec3PlainFileName), sec3Plain, ct);
        await File.WriteAllBytesAsync(
            Path.Combine(outputDirectory, SectionsDirName, "sec3_unwrapped.bin"), sec3Plain, ct);

        if (!sec3Plain.AsSpan().StartsWith("bplist"u8))
        {
            return new EscrowPcsUnwrapResult(
                false,
                $"sec3 decrypt OK ({sec3Plain.Length} B) ma non è bplist — schema inatteso.");
        }

        if (!AppleBinaryPlist.TryParseDict(sec3Plain, out var dict, out var plistErr))
        {
            return new EscrowPcsUnwrapResult(
                false, $"bplist sec3 non parsabile: {plistErr}");
        }

        byte[]? bagPassword = null;
        byte[]? digest = null;
        if (dict.TryGetValue("BackupBagPassword", out var bp) && bp is byte[] bpBytes)
            bagPassword = bpBytes;
        if (dict.TryGetValue("BackupKeybagDigest", out var dg) && dg is byte[] dgBytes)
            digest = dgBytes;

        if (bagPassword is null || bagPassword.Length < 32)
        {
            await File.WriteAllTextAsync(
                Path.Combine(outputDirectory, KeybagKeyMetaFileName),
                JsonSerializer.Serialize(new
                {
                    success = false,
                    keys = dict.Keys.ToList(),
                    note = "bplist senza BackupBagPassword",
                }, new JsonSerializerOptions { WriteIndented = true }),
                ct);
            return new EscrowPcsUnwrapResult(
                false,
                "bplist sec3 senza BackupBagPassword.");
        }

        var outPath = Path.Combine(outputDirectory, BackupBagPasswordFileName);
        await File.WriteAllBytesAsync(outPath, bagPassword, ct);
        if (digest is { Length: > 0 })
        {
            await File.WriteAllBytesAsync(
                Path.Combine(outputDirectory, BackupKeybagDigestFileName), digest, ct);
        }

        var version = dict.TryGetValue("BackupVersion", out var ver) ? ver?.ToString() : null;
        var ts = dict.TryGetValue("com.apple.securebackup.timestamp", out var t) ? t?.ToString() : null;

        var meta = JsonSerializer.Serialize(new
        {
            success = true,
            method = sec3Method,
            kind = "BackupBagPassword",
            dsid = parsed.Dsid,
            label = parsed.Label,
            timestamp = ts ?? parsed.Timestamp,
            backupVersion = version,
            backupBagPasswordBytes = bagPassword.Length,
            backupKeybagDigestHex = digest is null ? null : Convert.ToHexString(digest),
            note =
                "PCS unwrap (post type3 AesSiv / K_SRP) completato. " +
                "Prossimo/auto: unlock kPCSMetadataEscrowedKeys (RFC6637+GCM) → escrowed_pcs_keys.bin.",
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, KeybagKeyMetaFileName), meta, ct);

        log?.Report(
            $"  UNWRAP PCS OK → {BackupBagPasswordFileName} ({bagPassword.Length} B) via {sec3Method}");
        if (digest is { Length: > 0 })
            log?.Report($"  BackupKeybagDigest={Convert.ToHexString(digest)}");

        return new EscrowPcsUnwrapResult(
            true,
            $"OK — BackupBagPassword ({bagPassword.Length} B) via {sec3Method}",
            sec3Method,
            outPath,
            bagPassword,
            digest,
            "BackupBagPassword");
    }

    /// <summary>type2 AesSiv first; legacy AES-CBC fallback.</summary>
    public static byte[] DecryptSec3(string dsid, byte[] salt, byte[] sec3Ciphertext)
        => DecryptSec3(dsid, salt, sec3Ciphertext, out _);

    public static byte[] DecryptSec3(
        string dsid, byte[] salt, byte[] sec3Ciphertext, out string method)
    {
        if (salt.Length < 16)
            throw new ArgumentException("Salt escrow troppo corto.", nameof(salt));
        if (sec3Ciphertext.Length < 16)
            throw new ArgumentException("sec3 troppo corto.", nameof(sec3Ciphertext));

        var type2 = salt.Length == 64
            ? EscrowAesSiv.DeriveType2Key(dsid, salt)
            : Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(dsid),
                salt,
                Pbkdf2Iterations,
                HashAlgorithmName.SHA256,
                16);

        if (EscrowAesSiv.TryDecrypt(type2, sec3Ciphertext, out var sivPt, out var sivMethod)
            && sivPt is { Length: > 0 })
        {
            method = $"PBKDF2(dsid,salt64,10000,16)+{sivMethod}";
            return sivPt;
        }

        if (sec3Ciphertext.Length % 16 != 0)
            throw new CryptographicException(
                "sec3: AesSiv fallito e lunghezza non valida per AES-CBC legacy.");

        var iv = salt.AsSpan(0, 16).ToArray();
        using var aes = Aes.Create();
        aes.Key = type2;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        method = "PBKDF2(dsid,salt,10000,16)+AES-128-CBC(IV=salt[0:16])/legacy";
        return aes.CreateDecryptor().TransformFinalBlock(sec3Ciphertext, 0, sec3Ciphertext.Length);
    }
}
