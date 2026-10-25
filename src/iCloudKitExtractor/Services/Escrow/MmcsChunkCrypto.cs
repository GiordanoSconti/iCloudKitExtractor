using System.Security.Cryptography;
using iCloudKitExtractor.Protocol;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Decifra chunk MMCS CloudDocs (InflatableDonkey <c>ChunkKeys</c> + <c>ChunkListDecrypter</c>):
/// type 0x02 AES-KW → AES-128-CFB (IV zero, feedback 128).
/// </summary>
public static class MmcsChunkCrypto
{
    /// <summary>
    /// <c>chunkEncryptionKey</c> authorizeGet: <c>0x02 ‖ AES-KW(24)</c> → chiave AES 16 B,
    /// oppure <c>0x01 ‖ key(16)</c> già unwrapped.
    /// </summary>
    public static byte[]? TryUnwrapChunkAesKey(ReadOnlySpan<byte> chunkEncryptionKey, ReadOnlySpan<byte> kek)
    {
        if (chunkEncryptionKey.IsEmpty)
            return null;

        return chunkEncryptionKey[0] switch
        {
            0x01 when chunkEncryptionKey.Length == 0x11
                => chunkEncryptionKey[1..].ToArray(),
            0x02 when chunkEncryptionKey.Length == 0x19
                => TryAesKw(kek, chunkEncryptionKey[1..]),
            _ => null,
        };
    }

    /// <summary>AES-CFB-128 decrypt (IV = 0), come InflatableDonkey.</summary>
    public static byte[] DecryptCfb(ReadOnlySpan<byte> aesKey16, ReadOnlySpan<byte> ciphertext)
    {
        if (aesKey16.Length != 16)
            throw new CryptographicException("AES-CFB richiede chiave 16 B");

        var cipher = new BufferedBlockCipher(new CfbBlockCipher(new AesEngine(), 128));
        cipher.Init(false, new KeyParameter(aesKey16.ToArray()));
        var input = ciphertext.ToArray();
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var n = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        n += cipher.DoFinal(output, n);
        if (n == output.Length)
            return output;
        return output.AsSpan(0, n).ToArray();
    }

    /// <summary>
    /// Decifra il ciphertext compact (concat dei GET edge in ordine authorizeGet) e
    /// riassembla il file con <see cref="AuthorizeGetDecryptPlan.References"/>.
    /// </summary>
    public static byte[] DecryptAndAssemble(
        ReadOnlySpan<byte> compactCiphertext,
        AuthorizeGetDecryptPlan plan,
        ReadOnlySpan<byte> kek)
    {
        if (plan.Containers.Count == 0 || plan.References.Count == 0)
            throw new InvalidOperationException("Decrypt plan vuoto");

        if (plan.TotalCryptoBytes != compactCiphertext.Length)
            throw new InvalidOperationException(
                $"cryptoSum {plan.TotalCryptoBytes} ≠ ciphertext {compactCiphertext.Length}");

        // Host packed multi-tenant: ogni ChunkInfo può avere un KEK Asset diverso.
        // Decifra SOLO i chunk citati da References (stesso KEK dell'asset corrente).
        var needed = new HashSet<(int C, int K)>();
        foreach (var r in plan.References)
            needed.Add((r.ContainerIndex, r.ChunkIndex));

        // plain[container][chunk] — null se non in refs
        var plain = new byte[plan.Containers.Count][][];
        var offset = 0;
        for (var c = 0; c < plan.Containers.Count; c++)
        {
            var chunks = plan.Containers[c];
            plain[c] = new byte[chunks.Count][];
            for (var k = 0; k < chunks.Count; k++)
            {
                var ch = chunks[k];
                if (ch.Length <= 0 || offset + ch.Length > compactCiphertext.Length)
                    throw new InvalidOperationException(
                        $"slice OOB container={c} chunk={k} len={ch.Length} off={offset}");

                if (needed.Contains((c, k)))
                {
                    var aesKey = TryUnwrapChunkAesKey(ch.EncryptionKey, kek)
                                 ?? throw new CryptographicException(
                                     $"chunk key unwrap fallito ({c}:{k})");
                    plain[c][k] = DecryptCfb(aesKey, compactCiphertext.Slice(offset, ch.Length));
                }

                offset += ch.Length;
            }
        }

        if (offset != compactCiphertext.Length)
            throw new InvalidOperationException(
                $"decrypt copre {offset}/{compactCiphertext.Length} B");

        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plain.Length
                || (uint)r.ChunkIndex >= (uint)plain[r.ContainerIndex].Length)
                throw new InvalidOperationException(
                    $"ref OOB {r.ContainerIndex}:{r.ChunkIndex} " +
                    $"(containers={plain.Length})");
        }

        var total = plan.References.Sum(r => plain[r.ContainerIndex][r.ChunkIndex]!.Length);
        var result = new byte[total];
        var o = 0;
        foreach (var r in plan.References)
        {
            var part = plain[r.ContainerIndex][r.ChunkIndex]
                       ?? throw new CryptographicException(
                           $"ref {r.ContainerIndex}:{r.ChunkIndex} non decifrato");
            Buffer.BlockCopy(part, 0, result, o, part.Length);
            o += part.Length;
        }


        return result;
    }

    /// <summary>
    /// Riassembla il ciphertext compact secondo <see cref="AuthorizeGetDecryptPlan.References"/>
    /// senza AES (stessa geometria di <see cref="DecryptAndAssemble"/>).
    /// </summary>
    public static byte[] AssembleByReferences(
        ReadOnlySpan<byte> compactCiphertext,
        AuthorizeGetDecryptPlan plan)
    {
        if (plan.Containers.Count == 0 || plan.References.Count == 0)
            throw new InvalidOperationException("Decrypt plan vuoto");

        if (plan.TotalCryptoBytes != compactCiphertext.Length)
            throw new InvalidOperationException(
                $"cryptoSum {plan.TotalCryptoBytes} ≠ ciphertext {compactCiphertext.Length}");

        var slices = new byte[plan.Containers.Count][][];
        var offset = 0;
        for (var c = 0; c < plan.Containers.Count; c++)
        {
            var chunks = plan.Containers[c];
            slices[c] = new byte[chunks.Count][];
            for (var k = 0; k < chunks.Count; k++)
            {
                var ch = chunks[k];
                if (offset + ch.Length > compactCiphertext.Length)
                    throw new InvalidOperationException($"slice OOB container={c} chunk={k}");

                slices[c][k] = compactCiphertext.Slice(offset, ch.Length).ToArray();
                offset += ch.Length;
            }
        }

        if (offset != compactCiphertext.Length)
            throw new InvalidOperationException(
                $"assemble copre {offset}/{compactCiphertext.Length} B");

        var total = plan.References.Sum(r => slices[r.ContainerIndex][r.ChunkIndex].Length);
        var result = new byte[total];
        var o = 0;
        foreach (var r in plan.References)
        {
            var part = slices[r.ContainerIndex][r.ChunkIndex];
            Buffer.BlockCopy(part, 0, result, o, part.Length);
            o += part.Length;
        }

        return result;
    }

    private static byte[]? TryAesKw(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrapped)
    {
        try
        {
            return AesKeyWrap.Unwrap(kek, wrapped);
        }
        catch
        {
            return null;
        }
    }
}
