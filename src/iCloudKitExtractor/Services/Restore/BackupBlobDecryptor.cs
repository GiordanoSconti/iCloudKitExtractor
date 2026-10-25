using System.Security.Cryptography;

namespace iCloudKitExtractor.Services.Restore;

/// <summary>
/// Tentativo di decifra un blob asset scaricato (MMCS) con le class key del keybag.
/// Senza Manifest.db prova euristiche AES-CBC comuni nei backup iOS.
/// </summary>
public static class BackupBlobDecryptor
{
    public sealed record DecryptAttempt(int ProtectionClass, string Method, byte[] Plaintext);

    public static DecryptAttempt? TryDecryptFile(
        byte[] encrypted,
        IReadOnlyDictionary<int, byte[]> classKeys,
        IProgress<string>? log = null)
    {
        if (encrypted.Length < 32)
        {
            log?.Report("  blob troppo corto per decifra");
            return null;
        }

        foreach (var (protectionClass, key) in classKeys.OrderByDescending(static kv => kv.Key))
        {
            foreach (var method in EnumerateMethods(encrypted))
            {
                try
                {
                    var plain = method.Decrypt(key);
                    if (LooksLikePlaintext(plain))
                    {
                        log?.Report($"  decifra OK: class={protectionClass} metodo={method.Name}");
                        return new DecryptAttempt(protectionClass, method.Name, plain);
                    }
                }
                catch
                {
                    // prova prossima combinazione
                }
            }
        }

        log?.Report("  nessuna combinazione class key + AES ha prodotto dati plausibili");
        return null;
    }

    private static IEnumerable<(string Name, Func<byte[], byte[]> Decrypt)> EnumerateMethods(byte[] blob)
    {
        if (blob.Length > 32)
        {
            var iv0 = blob[..16];
            var ct0 = blob[16..];
            yield return ("AES-CBC IV@0", key => AesCbcDecrypt(key, iv0, ct0));
        }

        yield return ("AES-CBC IV=0", key => AesCbcDecrypt(key, Array.Empty<byte>(), blob));

        if (blob.Length > 36)
        {
            var iv4 = blob[4..20];
            var ct4 = blob[20..];
            yield return ("AES-CBC skip4+IV", key => AesCbcDecrypt(key, iv4, ct4));
        }
    }

    private static byte[] AesCbcDecrypt(byte[] key, byte[] iv, byte[] ciphertext)
    {
        using var aes = Aes.Create();
        aes.Key = NormalizeAesKey(key);
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        aes.IV = iv.Length == 16 ? iv : new byte[16];

        using var dec = aes.CreateDecryptor();
        return dec.TransformFinalBlock(ciphertext, 0, ciphertext.Length);
    }

    private static byte[] NormalizeAesKey(byte[] key)
    {
        if (key.Length is 16 or 24 or 32)
            return key;
        if (key.Length > 32)
            return key[..32];
        var padded = new byte[16];
        key.AsSpan().CopyTo(padded);
        return padded;
    }

    private static bool LooksLikePlaintext(ReadOnlySpan<byte> data)
    {
        if (data.Length < 8)
            return false;

        // bplist ("bplist00")
        if (data.Length >= 8 && data[..6].SequenceEqual("bplist"u8))
            return true;

        // SQLite
        if (data.Length >= 16 && data[..16].SequenceEqual("SQLite format 3\u0000"u8))
            return true;

        // zlib/gzip
        if (data[0] == 0x78 && data[1] is 0x01 or 0x5E or 0x9C or 0xDA)
            return true;
        if (data[0] == 0x1F && data[1] == 0x8B)
            return true;

        // XML/plist testo
        if (data[0] == (byte)'<' && data.Length > 20)
            return true;

        // JPEG/PNG/PDF
        if (data[0] == 0xFF && data[1] == 0xD8)
            return true;
        if (data[0] == 0x89 && data[1] == 0x50)
            return true;
        if (data[0] == (byte)'%' && data[1] == (byte)'P')
            return true;

        // euristica: alta ratio byte stampabili
        var printable = 0;
        var sample = Math.Min(data.Length, 256);
        for (var i = 0; i < sample; i++)
        {
            var b = data[i];
            if (b is >= 0x20 and < 0x7F or 0x09 or 0x0A or 0x0D)
                printable++;
        }

        return printable > sample * 0.85;
    }
}
