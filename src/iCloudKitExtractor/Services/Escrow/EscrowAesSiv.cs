using System.Security.Cryptography;
using System.Text;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// escrow AesSiv (live 2026-09-12):
/// <list type="bullet">
/// <item>type=3 (32B) = <c>SHA256(bn2bin(S))</c> = <see cref="EscrowSrpClient.SessionKey"/> — MUT A / recover blob</item>
/// <item>type=2 (16B) = <c>PBKDF2-HMAC-SHA256(dsid, RecordData_64=KeyVault.sec1, 10000, 16)</c> — MUT B / sec3</item>
/// </list>
/// Ciphertext layout: RFC5297 <c>V(16) ‖ C</c>, AD empty on the escrow path observed.
/// </summary>
public static class EscrowAesSiv
{
    public const int Type2Pbkdf2Iterations = 10_000;

    /// <summary>type2 key from KeyVault sec1 / RecordData 64-byte salt.</summary>
    public static byte[] DeriveType2Key(string dsid, ReadOnlySpan<byte> recordData64)
    {
        if (string.IsNullOrEmpty(dsid))
            throw new ArgumentException("dsid required", nameof(dsid));
        if (recordData64.Length != 64)
            throw new ArgumentException("RecordData salt must be 64 bytes", nameof(recordData64));

        return Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(dsid),
            recordData64.ToArray(),
            Type2Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            16);
    }

    /// <summary>
    /// Try AesSiv decrypt with key material. For 16B keys also tries <c>key‖key</c>
    /// and <c>SHA256(key)</c> if K1=K2 fails (defensive; live path uses K1=K2).
    /// </summary>
    public static bool TryDecrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> tagAndCt,
        out byte[]? plaintext,
        out string? method)
    {
        plaintext = null;
        method = null;
        if (tagAndCt.Length < 16)
            return false;

        foreach (var (expanded, label) in ExpandKeys(key.ToArray()))
        {
            try
            {
                plaintext = FordMmcsDecryptor.AesSivRfc5297Decrypt(
                    expanded, tagAndCt, Array.Empty<byte[]>());
                method = label;
                return true;
            }
            catch (CryptographicException)
            {
                // next expansion / fail
            }
        }

        return false;
    }

    /// <summary>Scan common recover-blob offsets for AesSiv (same windows as legacy CBC scan).</summary>
    public static bool TryDecryptCandidates(
        ReadOnlySpan<byte> key,
        byte[] blob,
        out byte[]? plaintext,
        out string? method)
    {
        plaintext = null;
        method = null;
        foreach (var candidate in EnumerateCandidates(blob))
        {
            if (TryDecrypt(key, candidate, out plaintext, out method) && plaintext is { Length: > 0 })
                return true;
        }

        return false;
    }

    private static IEnumerable<(byte[] Key, string Label)> ExpandKeys(byte[] key)
    {
        if (key.Length is 32 or 48 or 64)
        {
            yield return (key, $"AesSiv-RFC5297/{key.Length}");
            yield break;
        }

        if (key.Length != 16)
            yield break;

        yield return (key, "AesSiv-type2/K1=K2");
        var doubled = new byte[32];
        Buffer.BlockCopy(key, 0, doubled, 0, 16);
        Buffer.BlockCopy(key, 0, doubled, 16, 16);
        yield return (doubled, "AesSiv-type2/key||key");
        yield return (SHA256.HashData(key), "AesSiv-type2/SHA256(key)");
    }

    private static IEnumerable<byte[]> EnumerateCandidates(byte[] blob)
    {
        yield return blob;
        if (blob.Length > 64)
            yield return blob[32..];
        if (blob.Length > 96)
            yield return blob[64..];
        if (blob.Length > 48)
            yield return blob[16..];
        if (blob.Length > 48)
            yield return blob[8..];
    }
}
