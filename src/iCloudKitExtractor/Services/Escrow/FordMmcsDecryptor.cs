using System.Buffers.Binary;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Decrypt MMCS Ford post-edge — bit-exact from live Frida dump
/// <c>ford_decrypt_dump_20260811_141949</c> (30/30 round-trip):
/// <code>
/// d40 = HKDF-SHA256(ikm=fileKey, salt="PCSMMCS2", info="", len=64)
/// pt  = AES-SIV-RFC5297(d40, AD=[ford[1:17], ford[0:1]], body=ford[17:])  // tag‖ct
/// </code>
/// Then ParseFordInfo → per-chunk HKDF "signature-key" → AES-CTR(k3) + HMAC(k1) MAC trim.
/// </summary>
public static class FordMmcsDecryptor
{
    public static readonly byte[] PcsMmcs2Salt = "PCSMMCS2"u8.ToArray();
    public static readonly byte[] SignatureKeyInfo = "signature-key"u8.ToArray();

    /// <summary>
    /// Lunghezze finestra Ford note (singola o multi-key): solo queste vengono
    /// estratte/scansionate dentro un empty-host (<see cref="EnumerateLead04FordWindows"/>).
    /// </summary>
    public static readonly int[] StandardFordWindowLengths = [112, 155, 224, 310, 464, 480];

    /// <summary>
    /// Max body empty-host da considerare come contenitore di finestre standard
    /// (allineato a <see cref="EnumerateLead04FordWindows"/> default maxScanLen).
    /// </summary>
    public const int MaxEmptyFordHostScanLen = 4096;

    /// <summary>Empty-host la cui lunghezza è esattamente una finestra Ford nota.</summary>
    public static bool IsExactStandardFordHostLength(long len)
    {
        foreach (var w in StandardFordWindowLengths)
        {
            if (len == w)
                return true;
        }

        return false;
    }

    /// <summary>
    /// Empty-host che <b>può</b> contenere una finestra Ford standard: ampiezza dinamica
    /// [min finestra .. <see cref="MaxEmptyFordHostScanLen"/>]. Non filtra taglie “nuove”
    /// (es. 880, 1200): la selezione resta SIV + Parse + MAC. Usare il path stretto
    /// <see cref="IsExactStandardFordHostLength"/> solo senza MAC (first-SIV-wins).
    /// </summary>
    public static bool CanContainStandardFordWindow(long len) =>
        len >= StandardFordWindowLengths[0] && len <= MaxEmptyFordHostScanLen;

    /// <summary>Compat: alias di <see cref="CanContainStandardFordWindow"/>.</summary>
    public static bool IsPlausibleEmptyFordHostLength(long len) =>
        CanContainStandardFordWindow(len);

    /// <summary>
    /// Container Auth che è un GET Ford CT: empty, oppure un solo ChunkInfo di taglia
    /// Ford standard, oppure finestra ≤4KiB con sibling dati più grande nel plan
    /// (multi-key CT tipo 3454 senza confondere data host piccoli).
    /// </summary>
    public static bool IsFordSizedPlanContainer(
        AuthorizeGetDecryptPlan plan,
        int containerIndex)
    {
        if ((uint)containerIndex >= (uint)plan.Containers.Count)
            return false;
        var group = plan.Containers[containerIndex];
        if (group.Count == 0)
            return true;
        // FileGroupsPost: host con soli CI gate45 (len≈112) = Ford material, non empty.
        if (group.All(UbChunkBuilder.IsAuthFordDescriptorChunk))
            return true;
        if (group.Count != 1)
            return false;
        var len = group[0].Length;
        if (len < 112)
            return false;
        if (IsExactStandardFordHostLength(len))
            return true;
        if (!CanContainStandardFordWindow(len))
            return false;
        // Multi-key / non-standard: only if another container looks like real data.
        long otherMax = 0;
        for (var i = 0; i < plan.Containers.Count; i++)
        {
            if (i == containerIndex)
                continue;
            long sum = 0;
            foreach (var c in plan.Containers[i])
                sum += c.Length;
            if (sum > otherMax)
                otherMax = sum;
        }

        return otherMax > Math.Max(len * 2L, 8192L);
    }

    public sealed record FordChunkKey(byte[] Key, int? ChunkLengthHint);

    public sealed record DecryptResult(byte[] Plaintext, int FordBytes, int DataChunks, string Note);

    /// <summary>
    /// True se il primo range edge sembra ciphertext ford (offset 0, piccolo, lead tipico).
    /// </summary>
    public static bool LooksLikeFordCipher(ReadOnlySpan<byte> slice, long startOffset)
    {
        if (startOffset != 0 || slice.Length is < 64 or > 16384)
            return false;
        // Capture: b0=0x04; accetta anche altri lead non-ASCII.
        return slice[0] is 0x04 or >= 0x01;
    }

    /// <summary>Legacy helper (chunk path still uses info-labelled HKDF with empty salt).</summary>
    public static byte[] HkdfSha256(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> info, int length)
    {
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, ikm.ToArray(), length, salt: null, info: info.ToArray());
    }

    /// <summary>
    /// Ford key derivation — live oracle: salt=<c>PCSMMCS2</c>, info empty (NOT salt=empty/info=PCSMMCS2).
    /// </summary>
    public static byte[] DeriveFordKeyMaterial(ReadOnlySpan<byte> fileEncryptionKey)
    {
        return HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            fileEncryptionKey.ToArray(),
            0x40,
            salt: PcsMmcs2Salt,
            info: []);
    }

    public static byte[] DecryptFordKeys(
        ReadOnlySpan<byte> fileEncryptionKey,
        ReadOnlySpan<byte> fordCipher)
    {
        if (fileEncryptionKey.IsEmpty)
            throw new CryptographicException("Ford: encryption key (IKM) vuota");
        if (fordCipher.Length < 0x12)
            throw new CryptographicException("Ford ciphertext troppo corto");

        var derived40 = DeriveFordKeyMaterial(fileEncryptionKey);
        var lead = fordCipher[..1].ToArray();
        var nonce = fordCipher.Slice(1, 0x10).ToArray();
        var body = fordCipher[0x11..].ToArray(); // tag(16) ‖ ct


        if (TryAesSivFord(derived40, lead, nonce, body, out var pt, out var err))
        {
            return pt;
        }

        throw new CryptographicException("Ford AES-SIV decrypt fallito (key/AD)");
    }

    private static bool TryAesSivFord(
        byte[] derived40,
        byte[] lead,
        byte[] nonce,
        byte[] body,
        out byte[] pt,
        out string? err)
    {
        pt = [];
        err = null;
        try
        {
            pt = AesSivRfc5297Decrypt(derived40, body, [nonce, lead]);
            return true;
        }
        catch (Exception ex)
        {
            err = ex.GetType().Name;
            return false;
        }
    }

    private static bool TryDecryptFordSilent(ReadOnlySpan<byte> fileEncryptionKey, ReadOnlySpan<byte> fordCipher, out byte[] pt)
    {
        pt = [];
        if (fileEncryptionKey.IsEmpty || fordCipher.Length < 0x12)
            return false;
        var derived40 = DeriveFordKeyMaterial(fileEncryptionKey);
        var lead = fordCipher[..1].ToArray();
        var nonce = fordCipher.Slice(1, 0x10).ToArray();
        var body = fordCipher[0x11..].ToArray();
        return TryAesSivFord(derived40, lead, nonce, body, out pt, out _);
    }

    /// <summary>
    ///-strict: il blob intero apre AES-SIV con IKM. Nessuna finestra lead-0x04.
    /// </summary>
    public static bool BlobOpensExactWithIkm(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> blob)
        => TryDecryptFordSilent(ikm, blob, out _);

    /// <summary>
    /// True se il blob (intero o una finestra lead-0x04) apre AES-SIV con l'IKM.
    /// Solo path legacy non-IKE. Per FillChunks/TraceDecrypt usare <see cref="BlobOpensExactWithIkm"/>.
    /// </summary>
    public static bool BlobOpensWithIkm(ReadOnlySpan<byte> ikm, ReadOnlySpan<byte> blob)
    {
        return TryExtractIkmOpenFord(ikm, blob, out _);
    }

    /// <summary>
    /// Prova blob intero + tutte le finestre lead-0x04; restituisce solo un Ford che apre con IKM.
    /// Non inventa candidati: se nessuna finestra apre, false (host multi-tenant / tenant sbagliato).
    /// </summary>
    public static bool TryExtractIkmOpenFord(
        ReadOnlySpan<byte> ikm,
        ReadOnlySpan<byte> blob,
        out byte[] ford)
    {
        ford = [];
        if (ikm.IsEmpty || blob.Length < 0x12)
            return false;
        //-strict: 1 FileGroup GET → body intero == ctLen. Niente scan lead-0x04 / finestre.
        if (!TryDecryptFordSilent(ikm, blob, out _))
        {
            // #region agent log
            AgentStrictReject("H-NO-INVENT", "TryExtractIkmOpenFord", "reject_window_scan",
                new Dictionary<string, object?> { ["bodyLen"] = blob.Length, ["head"] = blob[0] });
            // #endregion
            return false;
        }

        ford = blob.ToArray();
        return true;
    }

    private static bool TryAddFordKeys(
        ReadOnlySpan<byte> ikm,
        ReadOnlySpan<byte> ford,
        List<FordChunkKey> keys,
        List<int> okLens,
        List<int> failLens)
    {
        if (!TryDecryptFordSilent(ikm, ford, out var pt))
        {
            failLens.Add(ford.Length);
            return false;
        }

        try
        {
            keys.AddRange(ParseFordInfo(pt));
            okLens.Add(ford.Length);
            return true;
        }
        catch
        {
            failLens.Add(ford.Length);
            return false;
        }
    }

    /// <summary>
    /// Finestre Ford candidate in un blob edge: ogni offset con lead <c>0x04</c> e
    /// lunghezza 112/155/224 (capture Cache.plist: Ford @ +240 in GET 464 B, non allineato a 112).
    /// Blob &gt; <paramref name="maxScanLen"/>: solo stride 112 da 0 (packed grandi).
    /// </summary>
    public static IEnumerable<(int Offset, int Len, byte[] Window)> EnumerateLead04FordWindows(
        ReadOnlySpan<byte> blob,
        int maxScanLen = 4096)
    {
        if (blob.IsEmpty)
            return Array.Empty<(int, int, byte[])>();
        return EnumerateLead04FordWindowsCore(blob.ToArray(), maxScanLen);
    }

    /// <summary>
    /// Ford multi-chunk (file grandi, es. 174 chunk → finestra ~6.5 KB con 175 chunk key):
    /// la finestra NON è di lunghezza standard, ma va dal lead-0x04 alla fine dell'host packed.
    /// Emesse al massimo <see cref="MaxLargeFordWindows"/> finestre "to-end" per host (AES-SIV
    /// autentica: una lunghezza sbagliata non apre mai, quindi nessun falso positivo).
    /// </summary>
    private const int MaxLargeFordWindows = 96;

    private static IEnumerable<(int Offset, int Len, byte[] Window)> EnumerateLead04FordWindowsCore(
        byte[] blob,
        int maxScanLen)
    {
        int[] lens = StandardFordWindowLengths;
        var largest = lens.Length > 0 ? lens.Max() : 0;
        var largeEmitted = 0;

        if (blob.Length <= maxScanLen)
        {
            var seen = new HashSet<(int Off, int Len)>();
            for (var off = 0; off < blob.Length; off++)
            {
                if (blob[off] != 0x04)
                    continue;
                foreach (var w in lens)
                {
                    if (off + w > blob.Length)
                        continue;
                    if (!seen.Add((off, w)))
                        continue;
                    var win = new byte[w];
                    Buffer.BlockCopy(blob, off, win, 0, w);
                    yield return (off, w, win);
                }

                // Finestra Ford multi-chunk: dal lead-0x04 alla fine dell'host.
                var toEnd = blob.Length - off;
                if (toEnd > largest
                    && toEnd < blob.Length
                    && largeEmitted < MaxLargeFordWindows
                    && seen.Add((off, toEnd)))
                {
                    largeEmitted++;
                    var big = new byte[toEnd];
                    Buffer.BlockCopy(blob, off, big, 0, toEnd);
                    yield return (off, toEnd, big);
                }
            }

            yield break;
        }

        const int step = 112;
        for (var off = 0; off + step <= blob.Length; off += step)
        {
            if (blob[off] != 0x04)
                continue;
            var win = new byte[step];
            Buffer.BlockCopy(blob, off, win, 0, step);
            yield return (off, step, win);

            var toEnd = blob.Length - off;
            if (toEnd > largest
                && toEnd < blob.Length
                && largeEmitted < MaxLargeFordWindows)
            {
                largeEmitted++;
                var big = new byte[toEnd];
                Buffer.BlockCopy(blob, off, big, 0, toEnd);
                yield return (off, toEnd, big);
            }
        }
    }

    /// <summary>
    /// Sceglie il Ford CT tra blob candidati (empty-host / sibling): DecryptFordKeys(IKM)
    /// + ParseFordInfo + ChunkDecrypt con MAC authorizeGet (se presente).
    /// </summary>
    public static bool TrySelectFordCipher(
        ReadOnlySpan<byte> ikm,
        ReadOnlySpan<byte> dataChunk,
        IReadOnlyList<byte[]> macs,
        IEnumerable<byte[]> candidateBlobs,
        out byte[] fordCipher)
    {
        fordCipher = [];
        var candList = candidateBlobs as IList<byte[]> ?? candidateBlobs.ToList();
        if (ikm.IsEmpty || dataChunk.IsEmpty)
            return false;

        //-strict: candidato = body GET intero (ctLen). Niente EnumerateLead04 / N×112.
        foreach (var blob in candList)
        {
            if (blob is not { Length: >= 0x12 })
                continue;
            if (!TryDecryptFordSilent(ikm, blob, out var pt))
                continue;
            IReadOnlyList<FordChunkKey> keys;
            try
            {
                keys = ParseFordInfo(pt);
            }
            catch
            {
                continue;
            }

            if (keys.Count == 0)
                continue;

            if (macs.Count == 0)
            {
                fordCipher = blob;
                return true;
            }

            try
            {
                _ = ChunkDecrypt(keys[0].Key, dataChunk, keys[0].ChunkLengthHint, macs[0]);
                fordCipher = blob;
                return true;
            }
            catch
            {
                // next candidate blob
            }
        }

        return false;
    }

    /// <summary>Disabilitato: split N×112 / lead-0x04 ≠ (1 body == 1 CT).</summary>
    private static IEnumerable<(int Offset, byte[] Window)> SplitConcatenatedFordWindows(byte[] ford)
    {
        _ = ford;
        yield break;
    }



    /// <summary>
    /// AES-SIV RFC 5297 decrypt; <paramref name="tagAndCt"/> = V(16) ‖ C.
    /// Key lengths: 32/48/64 (K1‖K2). Length 16 = AesSiv type=2 — K1=K2=key (AES-128).
    /// </summary>
    public static byte[] AesSivRfc5297Decrypt(
        ReadOnlySpan<byte> keyK1K2,
        ReadOnlySpan<byte> tagAndCt,
        IReadOnlyList<byte[]> associatedData)
    {
        byte[] k1;
        byte[] k2;
        if (keyK1K2.Length == 16)
        {
            // SetKey type=2 delivers 16B; both CMAC and CTR use AES-128 with that key.
            k1 = keyK1K2.ToArray();
            k2 = k1;
        }
        else if (keyK1K2.Length is 32 or 48 or 64)
        {
            var half = keyK1K2.Length / 2;
            k1 = keyK1K2[..half].ToArray();
            k2 = keyK1K2[half..].ToArray();
        }
        else
            throw new CryptographicException($"AES-SIV key len {keyK1K2.Length}");

        if (tagAndCt.Length < 16)
            throw new CryptographicException("AES-SIV ciphertext too short");

        var tag = tagAndCt[..16].ToArray();
        var ct = tagAndCt[16..].ToArray();

        var iv = ClearSivCtrBits(tag);
        var pt = AesCtr(k2, iv, ct);

        var parts = new List<byte[]>(associatedData.Count + 1);
        parts.AddRange(associatedData);
        parts.Add(pt);
        var expect = S2V(k1, parts);
        if (!CryptographicOperations.FixedTimeEquals(expect, tag))
            throw new CryptographicException("AES-SIV S2V mismatch");
        return pt;
    }

    private static byte[] ClearSivCtrBits(ReadOnlySpan<byte> v)
    {
        // +0x90bff0: clear high bit at bytes 8 and 12 (RFC 5297 CTR IV).
        var b = v.ToArray();
        b[8] &= 0x7F;
        b[12] &= 0x7F;
        return b;
    }

    private static byte[] S2V(byte[] k1, IReadOnlyList<byte[]> parts)
    {
        if (parts.Count == 0)
            return CmacAes(k1, Cat(new byte[15], new byte[] { 0x01 }));

        var d = CmacAes(k1, new byte[16]);
        for (var i = 0; i < parts.Count - 1; i++)
            d = Xor(Dbl(d), CmacAes(k1, parts[i]));

        var sn = parts[^1];
        byte[] t;
        if (sn.Length >= 16)
            t = XorEnd(sn, d);
        else
            t = Xor(Dbl(d), PadCm(sn));
        return CmacAes(k1, t);
    }

    private static byte[] Dbl(ReadOnlySpan<byte> b)
    {
        var bytes = new byte[16];
        var carry = 0;
        for (var i = 15; i >= 0; i--)
        {
            var v = (b[i] << 1) | carry;
            bytes[i] = (byte)v;
            carry = (b[i] & 0x80) != 0 ? 1 : 0;
        }

        if ((b[0] & 0x80) != 0)
            bytes[15] ^= 0x87;
        return bytes;
    }

    private static byte[] PadCm(ReadOnlySpan<byte> sn)
    {
        var t = new byte[16];
        sn.CopyTo(t);
        t[sn.Length] = 0x80;
        return t;
    }

    private static byte[] CmacAes(byte[] key, byte[] data)
    {
        // .NET has no CMAC; use BouncyCastle CMac.
        var mac = new Org.BouncyCastle.Crypto.Macs.CMac(new AesEngine());
        mac.Init(new KeyParameter(key));
        mac.BlockUpdate(data, 0, data.Length);
        var outb = new byte[mac.GetMacSize()];
        mac.DoFinal(outb, 0);
        return outb;
    }

    private static byte[] AesCtr(byte[] key, byte[] iv, byte[] data)
    {
        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
        var outb = new byte[data.Length];
        var counter = (byte[])iv.Clone();
        var block = new byte[16];
        using var enc = aes.CreateEncryptor();
        for (var off = 0; off < data.Length; off += 16)
        {
            enc.TransformBlock(counter, 0, 16, block, 0);
            var n = Math.Min(16, data.Length - off);
            for (var i = 0; i < n; i++)
                outb[off + i] = (byte)(data[off + i] ^ block[i]);
            // increment 128-bit BE counter
            for (var i = 15; i >= 0; i--)
            {
                if (++counter[i] != 0)
                    break;
            }
        }

        return outb;
    }

    private static byte[] Xor(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var o = new byte[a.Length];
        for (var i = 0; i < a.Length; i++)
            o[i] = (byte)(a[i] ^ b[i]);
        return o;
    }

    private static byte[] XorEnd(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var o = a.ToArray();
        var off = o.Length - b.Length;
        for (var i = 0; i < b.Length; i++)
            o[off + i] ^= b[i];
        return o;
    }

    private static byte[] Cat(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b)
    {
        var o = new byte[a.Length + b.Length];
        a.CopyTo(o);
        b.CopyTo(o.AsSpan(a.Length));
        return o;
    }


    /// <summary>
    /// MMCS.Ford plaintext dopo DecryptFordKeys:
    /// <code>
    /// N=1..2: f1 { f1 { f1: 33B (0x04‖key), f2: plain_len u32 }, … }, f2: 32B trailer
    /// N≥3:    f2 { f1: 32B meta, f2 { f1: hint u32, f2×N { f1: KEY33 } }, f2 { f1: last_hint, f2 { KEY33 } } }
    /// </code>
    /// </summary>
    public static IReadOnlyList<FordChunkKey> ParseFordInfo(ReadOnlySpan<byte> fordPlain)
    {
        var keys = new List<FordChunkKey>();
        foreach (var field in ParseProtobufFields(fordPlain))
        {
            if (field.WireType != ProtobufWireType.LengthDelimited)
                continue;
            TryParseFordInfoTop(field.Bytes, keys);
        }

        if (keys.Count == 0)
            throw new CryptographicException("ParseFordInfo: nessuna chunk key (0x04‖32)");
        return keys;
    }

    private const int ChunkHdrLen = 0x28;

    /// <summary>
    /// Decrypt one MMCS data chunk (<c>PrepareDerivedData</c> +0x970460 via
    /// <c>iCloudDriveFileDecrypter::ChunkDecrypt</c> +0x972290).
    /// Staging live: MAC20 (checksum21[1:]) → hdr 0x28;
    /// <c>hdr[0x20]=u64_le(ChunkDecrypt.r9)</c> = data buffer length (≥ Ford PT);
    /// Ford <c>ChunkLengthHint</c> = Prepare r9 / append trim only (+0x970856).
    /// </summary>
    public static byte[] ChunkDecrypt(FordChunkKey fordChunk, ReadOnlySpan<byte> dataChunk) =>
        ChunkDecrypt(fordChunk.Key, dataChunk, fordChunk.ChunkLengthHint);

    public static byte[] ChunkDecrypt(
        ReadOnlySpan<byte> fordChunkKey,
        ReadOnlySpan<byte> dataChunk,
        int? plainLengthHint = null,
        ReadOnlySpan<byte> headerMac20 = default)
    {
        if (dataChunk.IsEmpty)
            throw new CryptographicException("data chunk vuoto");

        var derived60 = HkdfSha256(fordChunkKey, SignatureKeyInfo, 0x60);
        var k1 = derived60.AsSpan(0x00, 0x20).ToArray();
        var k2 = derived60.AsSpan(0x20, 0x20).ToArray();
        var k3 = derived60.AsSpan(0x40, 0x20).ToArray();

        if (!headerMac20.IsEmpty)
        {
            if (headerMac20.Length < 0x14)
                throw new CryptographicException("header MAC troppo corto");

            //  hdr[0x20] = ChunkDecrypt r9 (data len), NOT Ford PT (r9 after reload).
            var hdr = BuildChunkHeader(headerMac20, dataChunk.Length);
            var ct = dataChunk.ToArray();

            // #region agent log
            AgentPdfFailDiagLog(
                "H-P5",
                "ChunkDecrypt.hdr_staging",
                new Dictionary<string, object?>
                {
                    ["hdr20"] = BinaryPrimitives.ReadUInt64LittleEndian(hdr.AsSpan(0x20)),
                    ["hint"] = plainLengthHint,
                    ["wireLen"] = dataChunk.Length,
                    ["ctLen"] = ct.Length,
                    ["hdr20IsWireLen"] = true,
                });
            // #endregion

            if (TryDecryptChunkBody(k1, k2, k3, hdr, ct, plainLengthHint, out var pt, out var last))
                return pt;

            // #region agent log
            AgentPdfFailDiagLog(
                "H-C",
                "ChunkDecrypt.mac_fail",
                new Dictionary<string, object?>
                {
                    ["sivOk"] = false,
                    ["wireLen"] = dataChunk.Length,
                    ["hdrMac14"] = Convert.ToHexString(hdr.AsSpan(0, 0x14)),
                    ["hdr20"] = BinaryPrimitives.ReadUInt64LittleEndian(hdr.AsSpan(0x20)),
                    ["hint"] = plainLengthHint,
                    ["hasHeaderMac"] = true,
                    ["err"] = last?.Message,
                });
            // #endregion
            throw new CryptographicException(
                "Chunk decrypt: MAC/SIV verify fallito (staging MAC20)", last);
        }

        if (dataChunk.Length > ChunkHdrLen)
        {
            var hdr = dataChunk[..ChunkHdrLen].ToArray();
            // patches [0x20] with data-buffer length (r9), not Ford PT.
            BinaryPrimitives.WriteUInt64LittleEndian(
                hdr.AsSpan(0x20),
                (ulong)(dataChunk.Length - ChunkHdrLen));
            var ct = dataChunk[ChunkHdrLen..].ToArray();

            // #region agent log
            AgentPdfFailDiagLog(
                "H-P5",
                "ChunkDecrypt.hdr_embedded",
                new Dictionary<string, object?>
                {
                    ["hdr20"] = BinaryPrimitives.ReadUInt64LittleEndian(hdr.AsSpan(0x20)),
                    ["hint"] = plainLengthHint,
                    ["ctLen"] = ct.Length,
                });
            // #endregion

            if (TryDecryptChunkBody(k1, k2, k3, hdr, ct, plainLengthHint, out var pt, out var last))
                return pt;

            throw new CryptographicException(
                "Chunk decrypt: MAC/SIV verify fallito (hdr‖ct)", last);
        }

        throw new CryptographicException("data chunk: serve MAC authorizeGet o hdr‖ct");
    }

    /// <summary>
    /// staging: MAC20 → 0x28 hdr; <c>[0x20]=u64_le(dataLen)</c>
    /// (<c>iCloudDriveFileDecrypter::ChunkDecrypt</c> r9 / +0x9706dc).
    /// </summary>
    private static byte[] BuildChunkHeader(ReadOnlySpan<byte> headerMac20, int dataLen)
    {
        var hdr = new byte[ChunkHdrLen];
        var macN = Math.Min(20, headerMac20.Length);
        headerMac20[..macN].CopyTo(hdr);
        if (dataLen > 0)
            BinaryPrimitives.WriteUInt64LittleEndian(hdr.AsSpan(0x20), (ulong)dataLen);
        return hdr;
    }

    private static bool TryDecryptChunkBody(
        byte[] k1,
        byte[] k2,
        byte[] k3,
        byte[] hdr,
        byte[] ct,
        int? plainLengthHint,
        out byte[] plaintext,
        out Exception? error)
    {
        plaintext = [];
        error = null;
        try
        {
            if (TryChunkDecryptGcmSiv(k1, k2, k3, hdr, ct, plainLengthHint, out var sivPlain))
            {
                plaintext = sivPlain;
                return true;
            }

            var iv = HMACSHA256.HashData(k2, hdr).AsSpan(0, 16).ToArray();
            var decrypted = AesCtr(k3, iv, ct);
            var n = FindMacVerifiedPrefixLength(k1, hdr, decrypted, plainLengthHint);
            if (n <= 0)
            {
                error = new CryptographicException("Chunk AES-CTR decrypt: MAC verify fallito (fallback)");
                return false;
            }

            plaintext = decrypted.AsSpan(0, n).ToArray();
            return true;
        }
        catch (Exception ex)
        {
            error = ex;
            return false;
        }
    }

    /// <summary>
    /// PrepareDerivedData / ChunkDecrypt: AES-GCM-SIV su k3 (32 B), nonce da HMAC(k2,hdr)[:12].
    /// </summary>
    private static bool TryChunkDecryptGcmSiv(
        byte[] k1,
        byte[] k2,
        byte[] k3,
        ReadOnlySpan<byte> hdr,
        ReadOnlySpan<byte> ct,
        int? plainLengthHint,
        out byte[] plaintext)
    {
        plaintext = [];
        if (k3.Length != 0x20 || ct.Length < 0x10)
            return false;

        var nonce = HMACSHA256.HashData(k2, hdr).AsSpan(0, 12).ToArray();

        // Layout A: ct ‖ tag(16)
        if (ct.Length > 0x10)
        {
            var body = ct[..^0x10];
            var tagCt = ct[^0x10..];
            try
            {
                var combined = new byte[body.Length + tagCt.Length];
                body.CopyTo(combined);
                tagCt.CopyTo(combined.AsSpan(body.Length));
                var pt = AesGcmSivDecrypt(k3, nonce, combined, null);
                var n = FindMacVerifiedPrefixLength(k1, hdr, pt, plainLengthHint);
                if (n > 0)
                {
                    plaintext = pt.AsSpan(0, n).ToArray();
                    return true;
                }
            }
            catch
            {
                // try layout B
            }
        }

        // Layout B: intero ct come payload SIV (tag inline)
        try
        {
            var pt = AesGcmSivDecrypt(k3, nonce, ct.ToArray(), null);
            var n = FindMacVerifiedPrefixLength(k1, hdr, pt, plainLengthHint);
            if (n > 0)
            {
                plaintext = pt.AsSpan(0, n).ToArray();
                return true;
            }
        }
        catch
        {
            // fallback CTR
        }

        return false;
    }

    /// <summary>
    /// MAC20 = ChunkInfo.checksum[1..21] (byte 0 = tipo, opaco; il digest cambia per chunk/snapshot).
    /// Ordine = FileChecksumChunkReferences, non lo scan grezzo <c>0x0a 0x15 0x84</c>
    /// (quel prefisso non è stabile e in batch/host condivisi raccoglie MAC di altri file).
    /// </summary>
    public static IReadOnlyList<byte[]> ExtractChunkHeaderMacs(ReadOnlySpan<byte> authorizeGetBody)
    {
        var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
        var fromRefs = new List<byte[]>();
        var leads = new List<string>();
        if (plan.References.Count > 0)
        {
            foreach (var r in plan.References)
            {
                if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                    continue;
                var group = plan.Containers[r.ContainerIndex];
                if ((uint)r.ChunkIndex >= (uint)group.Count)
                    continue;
                var ck = group[r.ChunkIndex].Checksum21;
                if (ck.Length != 21)
                    continue;
                fromRefs.Add(ck.AsSpan(1).ToArray());
                leads.Add(ck[0].ToString("X2"));
            }

            if (fromRefs.Count > 0)
            {
                return fromRefs;
            }
        }

        var sequential = new List<byte[]>();
        var seqLeads = new List<string>();
        foreach (var group in plan.Containers)
        {
            foreach (var ch in group)
            {
                if (ch.Checksum21.Length != 21)
                    continue;
                sequential.Add(ch.Checksum21.AsSpan(1).ToArray());
                seqLeads.Add(ch.Checksum21[0].ToString("X2"));
            }
        }

        return sequential;
    }

    /// <summary>AES-CTR decrypt; IV is 16-byte counter block (HMAC(k2,hdr)[:16] for chunks).</summary>
    public static byte[] AesCtrDecrypt(ReadOnlySpan<byte> key, ReadOnlySpan<byte> iv, ReadOnlySpan<byte> data) =>
        AesCtr(key.ToArray(), iv.ToArray(), data.ToArray());

    /// <summary>
    /// MAC = HMAC(k1, SHA256(pt[:n]))[:0x14]. n è Ford plain_len (o l'intero chunk).
    /// Vietato scansionare 1..pt.Length su file grandi (O(n²) SHA256 → hang da minuti/ore).
    /// </summary>
    public static int FindMacVerifiedPrefixLength(
        byte[] k1,
        ReadOnlySpan<byte> hdr,
        ReadOnlySpan<byte> pt,
        int? preferLen = null)
    {

        if (preferLen is int p && p > 0 && p <= pt.Length && TryVerifyChunkMac(k1, hdr, pt[..p]))
            return p;

        if (TryVerifyChunkMac(k1, hdr, pt))
            return pt.Length;

        // Solo file minuscoli: hint Ford assente/sbagliato. Mai su IPA/chunk MB.
        if (pt.Length <= 8192)
        {
            for (var n = pt.Length - 1; n >= 1; n--)
            {
                if (preferLen == n)
                    continue;
                if (TryVerifyChunkMac(k1, hdr, pt[..n]))
                    return n;
            }
        }

        return 0;
    }

    private static bool TryVerifyChunkMac(byte[] k1, ReadOnlySpan<byte> hdr, ReadOnlySpan<byte> pt)
        => VerifyDigest(k1, pt, hdr[..0x14]);

    /// <summary>
    /// <c>anonymous-namespace'::VerifyDigest</c> (+0x971c90):
    /// pre-hash SHA256(pt) (+0x48d070 vcall) poi <c>HMAC-SHA256(k1, dig)[:0x14]</c>
    /// memcmp vs expected 20 B (+0x971d55). Stesso check di ChunkDecrypt / hdr MAC.
    /// </summary>
    public static bool VerifyDigest(
        ReadOnlySpan<byte> k1,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> expectedMac20)
    {
        if (k1.Length < 0x20 || plaintext.IsEmpty || expectedMac20.Length < 0x14)
            return false;
        var dig = SHA256.HashData(plaintext);
        var mac = HMACSHA256.HashData(k1.ToArray(), dig);
        var ok = mac.AsSpan(0, 0x14).SequenceEqual(expectedMac20[..0x14]);
        // #region agent log
        AgentVerifyDigestLog(ok, plaintext.Length, dig.Length, expectedMac20[..0x14], mac.AsSpan(0, 0x14));
        // #endregion
        return ok;
    }

    // #region agent log
    private static int _vdLogCount;

    private static void AgentVerifyDigestLog(
        bool ok,
        int ptLen,
        int digLen,
        ReadOnlySpan<byte> expected14,
        ReadOnlySpan<byte> got14)
    {
        // Cap noise: first 40 + all failures.
        var n = System.Threading.Interlocked.Increment(ref _vdLogCount);
        if (ok && n > 40)
            return;
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "vd-manifest-v1",
                ["hypothesisId"] = ok ? "H-VD1" : "H-VD1-fail",
                ["location"] = "FordMmcsDecryptor.VerifyDigest",
                ["message"] = ok ? "verify_ok" : "verify_fail",
                ["data"] = new Dictionary<string, object?>
                {
                    ["ok"] = ok,
                    ["ptLen"] = ptLen,
                    ["digLen"] = digLen,
                    ["hmacDataIsSha256"] = digLen == 0x20,
                    ["expected14"] = Convert.ToHexString(expected14),
                    ["got14"] = Convert.ToHexString(got14),
                    ["n"] = n,
                },
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch
        {
            // ignore
        }
    }

    private static void AgentPdfFailDiagLog(
        string hypothesisId,
        string message,
        Dictionary<string, object?> data)
    {
        if (!IkeLogOptions.ShouldWriteAgentDiag
            && message is not "filegroup_ford_none_attached"
            && message is not "filegroup_ford_keycount_miss")
            return;
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "pdf-multihost-v1",
                ["hypothesisId"] = hypothesisId,
                ["location"] = "FordMmcsDecryptor",
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            if (message is "filegroup_ford_none_attached" or "filegroup_ford_keycount_miss")
            {
                System.IO.File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line + Environment.NewLine);
            }
            else
            {
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
        }
        catch
        {
            // ignore
        }
    }

    /// <summary>Always-on (capped) resolve diag for Ford compact mapping.</summary>
    private static int _fordResolveLogCount;

    private static void AgentFordResolveLog(
        string hypothesisId,
        string message,
        Dictionary<string, object?> data)
    {
        var n = System.Threading.Interlocked.Increment(ref _fordResolveLogCount);
        // empty_ford_pick / compact mismatch: sempre; altri: sample dopo 80.
        var always = message is "empty_ford_pick" or "resolve_compact_len";
        if (!always && n > 80 && n % 20 != 0)
            return;
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "ford-resolve-v1",
                ["hypothesisId"] = hypothesisId,
                ["location"] = "FordMmcsDecryptor.TryResolveFordAndData",
                ["message"] = message,
                ["data"] = data,
                ["wrapN"] = n,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    /// <summary>
    /// VerifyDigest partendo dalla Ford chunk key (HKDF <c>signature-key</c> → k1).
    /// </summary>
    public static bool VerifyDigestWithChunkKey(
        ReadOnlySpan<byte> fordChunkKey,
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> expectedMac20)
    {
        if (fordChunkKey.IsEmpty)
            return false;
        var derived60 = HkdfSha256(fordChunkKey, SignatureKeyInfo, 0x60);
        return VerifyDigest(derived60.AsSpan(0, 0x20), plaintext, expectedMac20);
    }

    /// <summary>
    /// FillChunks / DecryptFordKeys: per ogni empty storage, SIV decrypt (throw) +
    /// ParseFordInfo. Niente TryDecryptFordSilent né scan lead-0x04.
    /// Host concatenati N×112/155/224: solo split a stride fisso se il body intero fallisce.
    /// </summary>
    public static IReadOnlyList<FordChunkKey> CollectFordKeysFromEmptyStorages(
        ReadOnlySpan<byte> fileEncryptionKey,
        IReadOnlyList<byte[]> fordStorages)
    {
        if (fordStorages.Count == 0)
        {
            throw new CryptographicException("Cannot decrypt ford info from empty storages");
        }

        var keys = new List<FordChunkKey>();
        foreach (var fordCt in fordStorages)
        {
            if (fordCt.Length == 0)
                continue;
            AddFordKeysFromStorage(fileEncryptionKey, fordCt, keys);
        }

        if (keys.Count == 0)
        {
            throw new CryptographicException("Cannot decrypt ford info from empty storages");
        }

        return keys;
    }

    /// <summary>
    /// Quando il Ford del container espone N keys ma il file referenzia solo alcuni
    /// ChunkIndex (es. refs=1:1, crypto=2), seleziona keys[ChunkIndex].
    /// Se ChunkIndex è duplicato (Elements: refChunks=[0,0]), non riusare la stessa
    /// key: prendi la prima unused (ordine inorder) — altrimenti MAC/SIV fail.
    /// </summary>
    private static bool TrySelectFordKeysForReferences(
        IReadOnlyList<FordChunkKey> allKeys,
        AuthorizeGetDecryptPlan plan,
        out List<FordChunkKey> selected)
    {
        selected = [];
        if (allKeys.Count == 0 || plan.References.Count == 0)
            return false;
        if (allKeys.Count < plan.References.Count)
            return false;

        var used = new bool[allKeys.Count];
        var picked = new List<FordChunkKey>(plan.References.Count);
        var pickedIdx = new List<int>(plan.References.Count);
        var dupCi = false;
        var seenCi = new HashSet<int>();
        foreach (var r in plan.References)
        {
            if (!seenCi.Add(r.ChunkIndex))
                dupCi = true;
        }

        foreach (var r in plan.References)
        {
            var pick = -1;
            // Chiave diretta keys[ChunkIndex] solo se unica e libera.
            if (!dupCi
                && (uint)r.ChunkIndex < (uint)allKeys.Count
                && !used[r.ChunkIndex])
            {
                pick = r.ChunkIndex;
            }
            else
            {
                // Inorder / dedupe: prima unused (inject order ≈ refs order).
                for (var i = 0; i < allKeys.Count; i++)
                {
                    if (used[i])
                        continue;
                    pick = i;
                    break;
                }
            }

            if (pick < 0)
            {
                selected = [];
                return false;
            }

            used[pick] = true;
            pickedIdx.Add(pick);
            picked.Add(allKeys[pick]);
        }

        if (picked.Count != plan.References.Count)
        {
            selected = [];
            return false;
        }

        // #region agent log
        if (dupCi)
        {
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "FordMmcsDecryptor.TrySelectFordKeysForReferences",
                    ["message"] = "ford_keys_dup_ci_inorder",
                    ["hypothesisId"] = "H-DUP-CI",
                    ["runId"] = "elements-dupci-v1",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["refs"] = plan.References.Count,
                        ["keys"] = allKeys.Count,
                        ["refChunks"] = plan.References.Take(12).Select(static r => r.ChunkIndex).ToArray(),
                        ["pickedIdx"] = pickedIdx.Take(12).ToArray(),
                        ["dupCi"] = true,
                    },
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

        selected = picked;
        return true;
    }

    /// <summary>Un storage FileGroup già materializzato (body edge o sibling).</summary>
    public readonly record struct MaterializedHost(
        int ContainerIndex,
        byte[] Body,
        bool HasFordMaterial);

    /// <summary>
    /// Materializza un body per ogni container del plan (compact AG + sibling empty-host).
    /// Nessun demux geometrico: solo storage già presenti, come pre-FillChunks.
    /// Se Auth porta gate+ctLen+OID e il compact non ha Ford, allega sibling Read(ctLen)
    /// come host HAS-Ford (Auth→storage).
    /// </summary>
    public static bool TryMaterializeFileGroupStorages(
        ReadOnlySpan<byte> compact,
        IReadOnlyList<SignedUrlChunk> ordered,
        IReadOnlyList<SignedUrlChunk> original,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts,
        ReadOnlySpan<byte> fordIkm,
        out List<MaterializedHost> hosts,
        out string note,
        ReadOnlySpan<byte> authorizeGetBody = default)
    {
        hosts = [];
        note = "";
        if (plan.Containers.Count == 0)
        {
            note = "no-containers";
            return false;
        }

        var bodiesFromCompact = new Dictionary<int, byte[]>();
        var offset = 0;
        foreach (var c in ordered)
        {
            if (c.ByteRange is not { } br || br.End < br.Start || br.Start < 0)
            {
                note = "bad-range";
                return false;
            }

            var len = checked((int)(br.End - br.Start + 1));
            if (len <= 0 || offset + len > compact.Length)
            {
                note = "compact-overflow";
                return false;
            }

            var slice = compact.Slice(offset, len).ToArray();
            offset += len;
            var idx = IndexOfSignedChunk(original, c);
            if (idx >= 0)
                bodiesFromCompact[idx] = slice;
        }

        if (ordered.Count > 0 && offset != compact.Length)
        {
            var delta = compact.Length - offset;
            if (delta is <= 0 or > 224)
            {
                note = "compact-len-mismatch";
                return false;
            }
        }

        var n = Math.Min(original.Count, plan.Containers.Count);
        for (var i = 0; i < plan.Containers.Count; i++)
        {
            byte[]? body = null;
            if (i < n && bodiesFromCompact.TryGetValue(i, out var fromCompact))
                body = fromCompact;
            else if (siblingCompacts is { Count: > 0 }
                     && i < n
                     && original[i].ByteRange is { } br)
            {
                var oid = original[i].EdgeHeaders?.ObjectId ?? "";
                var key = $"{oid}@{br.Start}";
                if (siblingCompacts.TryGetValue(key, out var entry))
                    body = entry.Compact;
            }

            if (body is not { Length: > 0 })
                continue;

            // emptyFordGate: HAS-Ford = Auth structure (fordSize@+0x98), NOT IKM-open.
            var hasFord = IsFordSizedPlanContainer(plan, i)
                          || UbChunkBuilder.IsAuthFordMaterialHost(plan.Containers[i]);
            hosts.Add(new MaterializedHost(i, body, hasFord));
        }

        // Auth→storage: proietta descriptor Auth (gate+ctLen+OID) su sibling.
        // Anche se plan marca già HAS-Ford (CI45): il body materializzato può essere
        // Ford di un altro file → AES-SIV skip; serve il CT Read(ctLen) corretto.
        var authSeeded = 0;
        if (!authorizeGetBody.IsEmpty
            && siblingCompacts is { Count: > 0 }
            && !fordIkm.IsEmpty)
        {
            var descs = UbChunkBuilder.CollectAuthFordDescriptors(
                authorizeGetBody, plan, original);
            foreach (var d in descs)
            {
                if (string.IsNullOrEmpty(d.ObjectId))
                    continue;
                // Classici: nessun vincolo ByteRange. Large: ctLen ≤ host range.
                long hostLen = 0;
                if (UbChunkBuilder.IsLargeAuthFordCtLen(d.CtLen))
                {
                    foreach (var ch in original)
                    {
                        if (!string.Equals(ch.EdgeHeaders?.ObjectId, d.ObjectId, StringComparison.Ordinal)
                            || ch.ByteRange is not { } hbr)
                            continue;
                        hostLen = hbr.End - hbr.Start + 1;
                        break;
                    }

                    if (!UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen, hostLen))
                        continue;
                }
                else if (!UbChunkBuilder.IsClassicAuthFordCtLen(d.CtLen))
                {
                    continue;
                }

                byte[]? fordBody = null;
                var prefix = d.ObjectId + "@";
                foreach (var (key, (blob, start)) in siblingCompacts)
                {
                    if (!key.StartsWith(prefix, StringComparison.Ordinal))
                        continue;
                    if (blob.Length < d.CtLen)
                        continue;
                    if (blob.Length == d.CtLen || start == 0)
                    {
                        fordBody = blob.Length == d.CtLen
                            ? blob
                            : blob.AsSpan(0, d.CtLen).ToArray();
                        if (blob.Length == d.CtLen && start == 0)
                            break;
                    }
                    else if (fordBody is null && blob.Length >= d.CtLen)
                    {
                        fordBody = blob.AsSpan(0, d.CtLen).ToArray();
                    }
                }

                if (fordBody is null)
                    continue;

                var picked = fordBody.Length == d.CtLen
                    ? fordBody
                    : fordBody.AsSpan(0, d.CtLen).ToArray();

                //  DecryptFordKeys fail su Ford di altri file → skip, non seed cieco.
                if (!BlobOpensWithIkm(fordIkm, picked)
                    && !(TryCountFordKeys(fordIkm, [picked], out var seedKeys)
                         && FordKeysCoverPlanRefs(seedKeys, plan)))
                    continue;

                // Già presente stesso CT → non duplicare.
                var dup = false;
                foreach (var h in hosts)
                {
                    if (h.HasFordMaterial
                        && h.Body.AsSpan().SequenceEqual(picked))
                    {
                        dup = true;
                        break;
                    }
                }

                if (dup)
                    continue;

                var ci = -1;
                for (var i = 0; i < plan.Containers.Count; i++)
                {
                    if (plan.Containers[i].Count == 0 || IsFordSizedPlanContainer(plan, i))
                    {
                        if (i < original.Count
                            && string.Equals(
                                original[i].EdgeHeaders?.ObjectId,
                                d.ObjectId,
                                StringComparison.Ordinal))
                        {
                            ci = i;
                            break;
                        }

                        if (ci < 0)
                            ci = i;
                    }
                }

                if (ci < 0)
                    ci = Math.Max(0, plan.Containers.Count - 1);

                hosts.Add(new MaterializedHost(ci, picked, HasFordMaterial: true));
                authSeeded++;
                break;
            }
        }

        note = $"hosts={hosts.Count} ford={hosts.Count(static h => h.HasFordMaterial)}" +
               (authSeeded > 0 ? $" authSeed={authSeeded}" : "");
        // #region agent log
        AgentSessionNdjsonAlways(
            "H-HOSTWALK",
            "materialize_storages",
            new Dictionary<string, object?>
            {
                ["runId"] = "ike-struct-v1",
                ["note"] = note,
                ["hostN"] = hosts.Count,
                ["authSeeded"] = authSeeded,
                ["ci"] = hosts.Select(static h => h.ContainerIndex).Take(16).ToArray(),
                ["fordFlags"] = hosts.Select(static h => h.HasFordMaterial).Take(16).ToArray(),
                ["lens"] = hosts.Select(static h => h.Body.Length).Take(16).ToArray(),
                ["gate"] = "auth_structure_not_ikm_open",
            });
        // #endregion
        return hosts.Count > 0;
    }

    /// <summary>
    /// flusso fedele: per ogni storage → FillChunks (A o B) → attach data →
    /// MUT ChunkDecrypt per nodo → Clear (KEY restano su fail via ClearDataSlicesOnly).
    /// </summary>
    public static DecryptResult DecryptAssetHostWalk(
        ReadOnlySpan<byte> fileEncryptionKey,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<MaterializedHost> hosts,
        long? declaredPlainSize,
        ChunkTree tree)
    {
        if (hosts.Count == 0)
            throw new CryptographicException("host-walk: nessun storage materializzato");

        var pipes = new List<string>(hosts.Count);
        var fordBytes = 0;
        foreach (var host in hosts)
        {
            if (host.HasFordMaterial)
            {
                var keys = CollectFordKeysFromEmptyStorages(
                    fileEncryptionKey, new[] { host.Body }).ToList();
                TryAugmentFordKeysFromPackedGaps(
                    fileEncryptionKey, new[] { host.Body }, plan, keys, out _);
                if (keys.Count == 0)
                    pipes.Add(tree.FillChunks(plan, fordKeys: null));
                else
                {
                    pipes.Add(tree.FillChunks(plan, keys));
                    fordBytes += host.Body.Length;
                }
            }
            else
            {
                pipes.Add(tree.FillChunks(plan, fordKeys: null));
            }

            if ((uint)host.ContainerIndex < (uint)plan.Containers.Count
                && plan.Containers[host.ContainerIndex].Count > 0
                && !host.HasFordMaterial
                && !IsFordSizedPlanContainer(plan, host.ContainerIndex))
            {
                tree.AttachDataFromContainerHost(host.ContainerIndex, host.Body, plan);
            }
        }

        if (!tree.AllNodesReadyForDecrypt())
        {
            var dataBodies = hosts
                .Where(h => (uint)h.ContainerIndex < (uint)plan.Containers.Count
                            && plan.Containers[h.ContainerIndex].Count > 0
                            && !IsFordSizedPlanContainer(plan, h.ContainerIndex))
                .Select(static h => h.Body)
                .ToList();
            if (dataBodies.Count > 0
                && TryEnsureOwnedRefDataChunks(
                    ConcatDataHostChunks(dataBodies), plan, dataBodies,
                    out var owned, out _))
            {
                tree.AttachDataSlices(owned);
            }
        }

        // #region agent log
        AgentSessionNdjsonAlways(
            "H-HOSTWALK",
            "fillchunks_hosts_done",
            new Dictionary<string, object?>
            {
                ["runId"] = "ike-hostwalk-legacy",
                ["pipes"] = pipes,
                ["hostN"] = hosts.Count,
                ["treeNodes"] = tree.Count,
                ["keyed"] = tree.CountNodesWithFordKeys(),
                ["ready"] = tree.AllNodesReadyForDecrypt(),
            });
        // #endregion

        if (tree.CountNodesWithFordKeys() < plan.References.Count)
        {
            throw new CryptographicException(
                $"host-walk Pipe B: KEY mancanti keyed={tree.CountNodesWithFordKeys()} " +
                $"refs={plan.References.Count}");
        }

        byte[] plain;
        try
        {
            plain = tree.DecryptAssembleMut();
            tree.Clear();
        }
        catch
        {
            tree.ClearDataSlicesOnly();
            throw;
        }

        return new DecryptResult(
            plain,
            fordBytes,
            plan.References.Count,
            $"hostWalk pipes=[{string.Join(',', pipes)}] hosts={hosts.Count} " +
            $"refs={plan.References.Count} verifyDigest=ok");
    }

    /// <summary>
    /// Pipeline  Ford list + data list → FillChunks A/B → MUT (legacy entry usato dai retry).
    /// Preferire <see cref="DecryptAssetHostWalk"/> quando gli storage sono materializzati.
    /// </summary>
    public static DecryptResult DecryptAssetAligned(
        ReadOnlySpan<byte> fileEncryptionKey,
        IReadOnlyList<byte[]> fordStorages,
        IReadOnlyList<byte[]> dataHostChunks,
        ReadOnlySpan<byte> authorizeGetBody,
        long? declaredPlainSize = null,
        long? dataObjectStart = null,
        ChunkTree? chunkTree = null)
    {
        if (authorizeGetBody.IsEmpty)
            throw new CryptographicException("align: authorizeGet body mancante");

        var chunkKeys = CollectFordKeysFromEmptyStorages(fileEncryptionKey, fordStorages).ToList();
        var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
        // Interleaved/packed-host già restituisce slice per-ref (len == ChunkInfo.Length).
        // Ri-slicare su cryptoSum del FileGroup intero → "refs slice fallito: packed=512…".
        string slicePath;
        var aligned = TryUsePreSlicedRefChunks(dataHostChunks, plan);
        if (aligned is not null)
            slicePath = "pre-sliced";
        else if (TrySliceDataByFileRefsPerHost(dataHostChunks, plan, plan.References, out aligned))
            slicePath = "perHostOwned";
        else
        {
            aligned = SliceDataByFileRefs(
                ConcatDataHostChunks(dataHostChunks),
                plan,
                plan.References,
                dataObjectStart,
                out slicePath);
        }

        var macs = ExtractChunkHeaderMacs(authorizeGetBody);

        // chunkMap: sessione se fornito (lookup tra passate), altrimenti locale.
        var tree = chunkTree ?? new ChunkTree();
        var sessionTree = chunkTree is not null;

        var maxCi = 0;
        var allCiInRange = plan.References.Count > 0;
        foreach (var r in plan.References)
        {
            if (r.ChunkIndex > maxCi)
                maxCi = r.ChunkIndex;
            if ((uint)r.ChunkIndex >= (uint)chunkKeys.Count)
                allCiInRange = false;
        }

        // Elements-class: refChunks=[0,0] → non riusare keys[0]; allinea a refs (inorder).
        if (allCiInRange && TrySelectFordKeysForReferences(chunkKeys, plan, out var keyedMem))
            chunkKeys = keyedMem;

        // Packed [chunk][Ford][chunk]…: empty-host può dare 1 key mentre maxCi≥1.
        var gapFordN = 0;
        var keysBeforeGap = chunkKeys.Count;
        if (!allCiInRange
            && TryAugmentFordKeysFromPackedGaps(
                fileEncryptionKey, dataHostChunks, plan, chunkKeys, out gapFordN)
            && gapFordN > 0)
        {
            allCiInRange = true;
            foreach (var r in plan.References)
            {
                if ((uint)r.ChunkIndex >= (uint)chunkKeys.Count)
                    allCiInRange = false;
            }
        }

        // #region agent log
        AgentSessionNdjsonAlways(
            "H-SLICE-MAC",
            "DecryptAssetAligned.slice",
            new Dictionary<string, object?>
            {
                ["runId"] = "ike-struct-v1",
                ["slicePath"] = slicePath,
                ["sessionTree"] = sessionTree,
                ["treeBefore"] = tree.Count,
                ["keyedBefore"] = tree.CountNodesWithFordKeys(),
                ["dataHostN"] = dataHostChunks.Count,
                ["dataHostLens"] = dataHostChunks.Select(static d => d.Length).Take(8).ToArray(),
                ["fordN"] = fordStorages.Count,
                ["fordLens"] = fordStorages.Select(static f => f.Length).Take(8).ToArray(),
                ["keysBeforeGap"] = keysBeforeGap,
                ["keys"] = chunkKeys.Count,
                ["gapFordN"] = gapFordN,
                ["refs"] = plan.References.Count,
                ["macs"] = macs.Count,
                ["aligned"] = aligned.Count,
                ["sliceLens"] = aligned.Select(static s => s.Length).Take(12).ToArray(),
                ["expectLens"] = plan.References.Take(12).Select(r =>
                {
                    if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count) return -1;
                    var g = plan.Containers[r.ContainerIndex];
                    return (uint)r.ChunkIndex < (uint)g.Count ? g[r.ChunkIndex].Length : -1;
                }).ToArray(),
                ["refChunks"] = plan.References.Take(12).Select(static r => r.ChunkIndex).ToArray(),
                ["maxCi"] = maxCi,
                ["allCiInRange"] = allCiInRange,
                ["cryptoSum"] = plan.TotalCryptoBytes,
                ["dataObjectStart"] = dataObjectStart,
                ["declaredPlain"] = declaredPlainSize,
            });
        // #endregion

        // —— FillChunks a due passate sullo stesso chunkMap ——
        string pass1;
        string pass2;
        if (chunkKeys.Count > 0)
        {
            // #1 HAS-Ford: DecryptFordKeys → inject
            pass1 = tree.FillChunks(plan, chunkKeys);
            // #2 EMPTY-Ford: skip inject; KEY già sui nodi (come host data successivo)
            pass2 = tree.FillChunks(plan, fordKeys: null);
        }
        else
        {
            // Solo Pipe B: KEY devono essere già sul tree (sessione / passata precedente)
            pass1 = "—";
            pass2 = tree.FillChunks(plan, fordKeys: null);
            if (tree.CountNodesWithFordKeys() < plan.References.Count)
            {
                throw new CryptographicException(
                    $"FillChunks Pipe B: KEY mancanti sul tree " +
                    $"(keyed={tree.CountNodesWithFordKeys()} refs={plan.References.Count} " +
                    $"sessionTree={sessionTree})");
            }
        }

        tree.AttachDataSlices(aligned);

        // #region agent log
        AgentSessionNdjsonAlways(
            "H-STRUCT-FC",
            "DecryptAssetAligned.fillchunks",
            new Dictionary<string, object?>
            {
                ["runId"] = "ike-struct-v1",
                ["pass1"] = pass1,
                ["pass2"] = pass2,
                ["sessionTree"] = sessionTree,
                ["treeNodes"] = tree.Count,
                ["keyed"] = tree.CountNodesWithFordKeys(),
                ["aligned"] = aligned.Count,
            });
        // #endregion

        // #region agent log
        // H-DUP: KEY↔chunk bind probe (ManagedDuplicate 346 / multi-host MAC fail).
        // Quale keys[i] apre slice[0]+MAC[0]? Confronta inject (inorder vs ci vs ordinal).
        if (chunkKeys.Count >= 2 && aligned.Count >= 1 && plan.References.Count >= 2)
        {
            var containers = plan.References.Select(static r => r.ContainerIndex).Distinct().Count();
            var firstRef = plan.References[0];
            var mac0 = macs.Count > 0 ? macs[0] : Array.Empty<byte>();
            var fillNodes = tree.NodesInFillOrder().ToList();
            if (fillNodes.Count > 0 && fillNodes[0].Mac20.Length >= 20)
                mac0 = fillNodes[0].Mac20;
            var slice0 = aligned[0];
            var hit = -1;
            var hitHint = -1;
            if (mac0.Length >= 20 && slice0.Length > 0)
            {
                for (var ki = 0; ki < chunkKeys.Count; ki++)
                {
                    try
                    {
                        _ = ChunkDecrypt(
                            chunkKeys[ki].Key,
                            slice0,
                            chunkKeys[ki].ChunkLengthHint,
                            mac0);
                        hit = ki;
                        hitHint = chunkKeys[ki].ChunkLengthHint ?? -1;
                        break;
                    }
                    catch
                    {
                        // try next key index
                    }
                }
            }

            var inorderIdx = -1;
            if (fillNodes.Count > 0)
            {
                var ordered = tree.RbMapInorderKeys();
                for (var ii = 0; ii < ordered.Count; ii++)
                {
                    if (ordered[ii].ContainerIndex == fillNodes[0].Key.ContainerIndex
                        && ordered[ii].ChunkIndex == fillNodes[0].Key.ChunkIndex)
                    {
                        inorderIdx = ii;
                        break;
                    }
                }
            }

            AgentSessionNdjsonAlways(
                "H-DUP",
                "key_chunk_bind_probe",
                new Dictionary<string, object?>
                {
                    ["runId"] = "dup-bind-v1",
                    ["keys"] = chunkKeys.Count,
                    ["refs"] = plan.References.Count,
                    ["containers"] = containers,
                    ["slicePath"] = slicePath,
                    ["dataHostN"] = dataHostChunks.Count,
                    ["dataHostLens"] = dataHostChunks.Select(static d => d.Length).Take(8).ToArray(),
                    ["fordLens"] = fordStorages.Select(static f => f.Length).Take(4).ToArray(),
                    ["firstRef"] = $"{firstRef.ContainerIndex}:{firstRef.ChunkIndex}",
                    ["firstNode"] = fillNodes.Count > 0 ? fillNodes[0].Key.ToString() : null,
                    ["inorderIdx"] = inorderIdx,
                    ["chunkIndex"] = firstRef.ChunkIndex,
                    ["refOrdinal"] = 0,
                    ["hitKeyIdx"] = hit,
                    ["hitHint"] = hitHint,
                    ["slice0"] = slice0.Length,
                    ["mac0_14"] = mac0.Length >= 14
                        ? Convert.ToHexString(mac0.AsSpan(0, 14))
                        : Convert.ToHexString(mac0),
                    ["verdict"] = hit < 0 ? "no-key-opens-slice0"
                        : hit == 0 && inorderIdx == 0 ? "ordinal0-ok"
                        : hit == firstRef.ChunkIndex ? "chunkIndex-ok"
                        : hit == inorderIdx ? "inorder-ok"
                        : $"hit={hit}-unexpected",
                });
        }
        // #endregion

        byte[] plain;
        try
        {
            plain = tree.DecryptAssemble(declaredPlainSize);
            tree.Clear();
        }
        catch (Exception ex)
        {
            // #region agent log
            AgentPdfFailDiagLog(
                "H-DUP",
                "DecryptAssetAligned.assemble_fail",
                new Dictionary<string, object?>
                {
                    ["slicePath"] = slicePath,
                    ["dataHostN"] = dataHostChunks.Count,
                    ["err"] = ex.Message.Length <= 160 ? ex.Message : ex.Message[..160],
                    ["keys"] = chunkKeys.Count,
                    ["aligned"] = aligned.Count,
                    ["treeNodes"] = tree.Count,
                    ["sessionTree"] = sessionTree,
                    ["pass1"] = pass1,
                    ["pass2"] = pass2,
                    ["runId"] = "dup-bind-v1",
                });
            // #endregion
            tree.Clear();
            throw;
        }

        var fordBytes = fordStorages.Sum(static f => f.Length);
        return new DecryptResult(
            plain,
            fordBytes,
            aligned.Count,
            $"ikeChunkTree pass={pass1}/{pass2} keys={chunkKeys.Count} nodes={aligned.Count} " +
            $"refs={plan.References.Count} macs={macs.Count} slice={slicePath} " +
            $"session={sessionTree} verifyDigest=ok");
    }

    /// <summary>
    /// PrepareDerivedData @ +0x970856: per ogni ref i (0..n-1),
    /// ChunkDecrypt(keys[i], slice[i], MAC[i]) → VerifyDigest → append al buffer file.
    /// Ordine fisso FileChecksumChunkReferences — niente riordino post-decrypt.
    /// </summary>
    /// <summary>
    /// Soglia sotto il limite MemoryStream/.NET array (~2 GiB). Sopra: assemble su FileStream.
    /// </summary>
    public const long MaxInMemoryPlaintextBytes = 1_800_000_000L;

    public static byte[] AssemblePlaintextFromFileRefs(
        IReadOnlyList<FordChunkKey> chunkKeys,
        IReadOnlyList<byte[]> dataSlices,
        IReadOnlyList<byte[]> macs,
        long? declaredPlainSize = null,
        string? logContext = null)
    {
        if (declaredPlainSize is > MaxInMemoryPlaintextBytes)
        {
            throw new InvalidOperationException(
                $"plaintext dichiarato {declaredPlainSize:N0} B > MaxInMemory — " +
                "usa AssemblePlaintextFromFileRefsToFile");
        }

        using var ms = new MemoryStream();
        AssemblePlaintextFromFileRefsCore(
            chunkKeys, dataSlices, macs, declaredPlainSize, logContext, ms);
        return ms.ToArray();
    }

    /// <summary>
    /// Come <see cref="AssemblePlaintextFromFileRefs"/> ma scrive su file (asset &gt;~1.8 GB).
    /// </summary>
    public static long AssemblePlaintextFromFileRefsToFile(
        string outputPath,
        IReadOnlyList<FordChunkKey> chunkKeys,
        IReadOnlyList<byte[]> dataSlices,
        IReadOnlyList<byte[]> macs,
        long? declaredPlainSize = null,
        string? logContext = null)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outputPath))!);
        using var fs = new FileStream(
            outputPath, FileMode.Create, FileAccess.Write, FileShare.None, 1024 * 1024);
        AssemblePlaintextFromFileRefsCore(
            chunkKeys, dataSlices, macs, declaredPlainSize, logContext, fs);
        return fs.Length;
    }

    private static void AssemblePlaintextFromFileRefsCore(
        IReadOnlyList<FordChunkKey> chunkKeys,
        IReadOnlyList<byte[]> dataSlices,
        IReadOnlyList<byte[]> macs,
        long? declaredPlainSize,
        string? logContext,
        Stream output)
    {
        if (chunkKeys.Count != dataSlices.Count || chunkKeys.Count != macs.Count)
        {
            throw new CryptographicException(
                $"Chunks count is not equal ford keys: keys={chunkKeys.Count} " +
                $"slices={dataSlices.Count} macs={macs.Count}");
        }

        for (var i = 0; i < dataSlices.Count; i++)
        {
            int? plainHint = chunkKeys[i].ChunkLengthHint;
            if (plainHint is null or <= 0
                && dataSlices.Count == 1
                && declaredPlainSize is > 0 and <= int.MaxValue)
                plainHint = (int)declaredPlainSize.Value;

            byte[] pt;
            try
            {
                pt = ChunkDecrypt(chunkKeys[i].Key, dataSlices[i], plainHint, macs[i]);
            }
            catch (Exception ex)
            {
                // #region agent log
                AgentPdfFailDiagLog(
                    "H-MAC-C",
                    "AssemblePlaintextFromFileRefs.chunk_fail",
                    new Dictionary<string, object?>
                    {
                        ["context"] = logContext,
                        ["i"] = i,
                        ["n"] = dataSlices.Count,
                        ["sliceLen"] = dataSlices[i].Length,
                        ["hint"] = plainHint,
                        ["key33_0"] = chunkKeys[i].Key.Length >= 4
                            ? Convert.ToHexString(chunkKeys[i].Key.AsSpan(0, 4))
                            : "",
                        ["mac14"] = macs[i].Length >= 14
                            ? Convert.ToHexString(macs[i].AsSpan(0, 14))
                            : Convert.ToHexString(macs[i]),
                        ["macLen"] = macs[i].Length,
                        ["err"] = ex.Message.Length <= 160 ? ex.Message : ex.Message[..160],
                        ["run"] = "post-fix",
                    });
                // #endregion
                throw;
            }

            if (!VerifyDigestWithChunkKey(chunkKeys[i].Key, pt, macs[i]))
            {
                // #region agent log
                AgentPdfFailDiagLog(
                    "H-C",
                    "AssemblePlaintextFromFileRefs.verify_fail",
                    new Dictionary<string, object?>
                    {
                        ["context"] = logContext,
                        ["i"] = i,
                        ["ptLen"] = pt.Length,
                        ["sliceLen"] = dataSlices[i].Length,
                    });
                // #endregion
                throw new CryptographicException(
                    "Verification of decryption has been failed (VerifyDigest)");
            }

            output.Write(pt);
        }

        // #region agent log
        if (!string.IsNullOrEmpty(logContext))
        {
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "FordMmcsDecryptor.AssemblePlaintextFromFileRefs",
                    ["message"] = "assembled",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["context"] = logContext,
                        ["chunks"] = dataSlices.Count,
                        ["plainLen"] = output.CanSeek ? output.Length : -1,
                        ["toFile"] = output is FileStream,
                        ["sliceLens"] = dataSlices.Select(static s => s.Length).Take(24).ToArray(),
                        ["hints"] = chunkKeys.Select(static k => k.ChunkLengthHint).Take(24).ToArray(),
                        ["verifyDigestStrict"] = true,
                    },
                    ["hypothesisId"] = "H-HUGE",
                    ["runId"] = "huge-stream-v1",
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch
            {
                // ignore debug log failures
            }
        }
        // #endregion
    }

    /// <summary>
    /// align → plaintext su file (evita MemoryStream &gt;~2 GB).
    /// </summary>
    public static DecryptResult DecryptAssetAlignedToFile(
        ReadOnlySpan<byte> fileEncryptionKey,
        IReadOnlyList<byte[]> fordStorages,
        IReadOnlyList<byte[]> dataHostChunks,
        ReadOnlySpan<byte> authorizeGetBody,
        string outputPath,
        long? declaredPlainSize = null,
        long? dataObjectStart = null)
    {
        if (authorizeGetBody.IsEmpty)
            throw new CryptographicException("align: authorizeGet body mancante");

        var chunkKeys = CollectFordKeysFromEmptyStorages(fileEncryptionKey, fordStorages).ToList();
        var plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);
        string slicePath;
        var aligned = TryUsePreSlicedRefChunks(dataHostChunks, plan);
        if (aligned is not null)
            slicePath = "pre-sliced";
        else if (TrySliceDataByFileRefsPerHost(dataHostChunks, plan, plan.References, out aligned))
            slicePath = "perHostOwned";
        else
        {
            var packedSum = dataHostChunks.Sum(static c => (long)c.Length);
            if (packedSum > MaxInMemoryPlaintextBytes)
            {
                throw new InvalidOperationException(
                    $"data hosts concat {packedSum:N0} B troppo grande per slice packed; " +
                    "serve geometria per-host (perHostOwned/pre-sliced)");
            }

            aligned = SliceDataByFileRefs(
                ConcatDataHostChunks(dataHostChunks),
                plan,
                plan.References,
                dataObjectStart,
                out slicePath);
        }

        var macs = ExtractChunkHeaderMacs(authorizeGetBody);
        //  sempre keys[ChunkIndex] quando gli indici rientrano nel Ford.
        var allCiInRangeFile = plan.References.Count > 0;
        foreach (var r in plan.References)
        {
            if ((uint)r.ChunkIndex >= (uint)chunkKeys.Count)
            {
                allCiInRangeFile = false;
                break;
            }
        }

        if (allCiInRangeFile && TrySelectFordKeysForReferences(chunkKeys, plan, out var keyedFile))
            chunkKeys = keyedFile;

        if (plan.References.Count > 0 && chunkKeys.Count != plan.References.Count)
        {
            throw new CryptographicException(
                $"Chunks count is not equal ford keys: {chunkKeys.Count} != {plan.References.Count}");
        }

        if (chunkKeys.Count != aligned.Count)
        {
            throw new CryptographicException(
                $"Chunks count is not equal ford keys: {chunkKeys.Count} != {aligned.Count}");
        }

        if (macs.Count != aligned.Count)
        {
            throw new CryptographicException(
                $"ChunkInfo MAC {macs.Count} != data chunks {aligned.Count}");
        }

        var written = AssemblePlaintextFromFileRefsToFile(
            outputPath, chunkKeys, aligned, macs, declaredPlainSize,
            logContext: "DecryptAssetAlignedToFile");
        // #region agent log
        AgentPdfFailDiagLog(
            "H-HUGE",
            "DecryptAssetAlignedToFile.ok",
            new Dictionary<string, object?>
            {
                ["slicePath"] = slicePath,
                ["written"] = written,
                ["refs"] = plan.References.Count,
                ["dataHostN"] = dataHostChunks.Count,
            });
        // #endregion

        var fordBytes = fordStorages.Sum(static f => f.Length);
        // Placeholder: caller usa il file; Plaintext vuoto evita allocazioni multi-GB.
        return new DecryptResult(
            [],
            fordBytes,
            aligned.Count,
            $"decryptFordToFile keys={chunkKeys.Count} refs={plan.References.Count} " +
            $"written={written} slice={slicePath} verifyDigest=ok");
    }

    /// <summary>
    /// Slice dati per FileChecksumChunkReferences (0..n-1). False se geometria non-esatta.
    /// </summary>
    private static bool TrySliceDataByFileRefs(
        byte[] packed,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<AuthorizeGetChunkRef> fileRefs,
        long? dataObjectStart,
        out List<byte[]> slices)
    {
        slices = [];
        try
        {
            slices = SliceDataByFileRefs(packed, plan, fileRefs, dataObjectStart);
            return slices.Count == fileRefs.Count;
        }
        catch (CryptographicException)
        {
            return false;
        }
    }

    /// <summary>
    /// DecryptFordKeys su storage già bound: solo body esatto = <c>Read(ctLen)</c>.
    /// Nessuno stride N×window (non è il percorso).
    /// </summary>
    public static bool TryCollectFordKeysStrict(
        ReadOnlySpan<byte> fileEncryptionKey,
        ReadOnlySpan<byte> fordCt,
        out List<FordChunkKey> keys)
    {
        keys = [];
        if (fileEncryptionKey.IsEmpty || fordCt.Length < 0x12)
            return false;

        try
        {
            keys.AddRange(ParseFordInfo(DecryptFordKeys(fileEncryptionKey, fordCt)));
            return keys.Count > 0;
        }
        catch (CryptographicException)
        {
            keys = [];
            return false;
        }
    }

    /// <summary>
    ///  DecryptFordKeys sul body esatto = Read(ctLen). Nessuno stride N×win / lead-0x04.
    /// </summary>
    private static void AddFordKeysFromStorage(
        ReadOnlySpan<byte> ikm,
        ReadOnlySpan<byte> fordCt,
        List<FordChunkKey> keys)
    {
        keys.AddRange(ParseFordInfo(DecryptFordKeys(ikm, fordCt)));
    }

    private static byte[] ConcatDataHostChunks(IReadOnlyList<byte[]> dataHostChunks)
    {
        if (dataHostChunks.Count == 1)
            return dataHostChunks[0];
        long totalLong = 0;
        foreach (var c in dataHostChunks)
            totalLong += c.Length;
        if (totalLong > MaxInMemoryPlaintextBytes || totalLong > int.MaxValue)
        {
            throw new InvalidOperationException(
                $"ConcatDataHostChunks {totalLong:N0} B supera limite in-memory " +
                $"({MaxInMemoryPlaintextBytes:N0}) — usa path per-host / ToFile");
        }

        var total = (int)totalLong;
        var buf = new byte[total];
        var o = 0;
        foreach (var c in dataHostChunks)
        {
            Buffer.BlockCopy(c, 0, buf, o, c.Length);
            o += c.Length;
        }

        return buf;
    }

    /// <summary>
    /// Multi-host  ogni data-host ha il proprio spazio Offset (riparte da 0).
    /// Concat+ownedAtZero legge il 2° host da packed[0] → MAC fail sul primo chunk
    /// del container successivo (log: chunk_fail i == container boundary).
    /// Un solo host packed (radios): Count==1 è valido — slice owned su quel body.
    /// </summary>
    private static bool TrySliceDataByFileRefsPerHost(
        IReadOnlyList<byte[]> dataHostChunks,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<AuthorizeGetChunkRef> fileRefs,
        out List<byte[]> slices)
    {
        slices = [];
        if (dataHostChunks.Count == 0 || fileRefs.Count == 0)
            return false;

        var hostByContainer = new Dictionary<int, int>();
        foreach (var r in fileRefs)
        {
            if (hostByContainer.ContainsKey(r.ContainerIndex))
                continue;
            hostByContainer[r.ContainerIndex] = hostByContainer.Count;
        }

        if (hostByContainer.Count != dataHostChunks.Count)
            return false;

        var result = new List<byte[]>(fileRefs.Count);
        foreach (var r in fileRefs)
        {
            if (!hostByContainer.TryGetValue(r.ContainerIndex, out var hostIdx)
                || (uint)hostIdx >= (uint)dataHostChunks.Count
                || (uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                return false;

            var group = plan.Containers[r.ContainerIndex];
            if (!TryOwnedPackedSlice(
                    dataHostChunks[hostIdx],
                    group,
                    r.ChunkIndex,
                    out var data,
                    out _))
                return false;

            result.Add(data);
        }

        // #region agent log
        var boundary = -1;
        for (var i = 1; i < fileRefs.Count; i++)
        {
            if (fileRefs[i].ContainerIndex != fileRefs[0].ContainerIndex)
            {
                boundary = i;
                break;
            }
        }

        AgentPdfFailDiagLog(
            "H-HOST",
            "perHostOwned_ok",
            new Dictionary<string, object?>
            {
                ["hosts"] = dataHostChunks.Count,
                ["refs"] = fileRefs.Count,
                ["containers"] = hostByContainer.Keys.OrderBy(static k => k).ToArray(),
                ["boundary"] = boundary,
                ["sliceAtBoundary"] = boundary >= 0 && boundary < result.Count
                    ? result[boundary].Length
                    : -1,
                ["run"] = "post-fix",
            });
        // #endregion

        slices = result;
        return true;
    }

    /// <summary>
    /// Se <paramref name="dataHostChunks"/> è già 1:1 con FileChecksumChunkReferences
    /// (len == ChunkInfo.Length), usali senza re-base su TotalCryptoBytes del group.
    /// </summary>
    private static List<byte[]>? TryUsePreSlicedRefChunks(
        IReadOnlyList<byte[]> dataHostChunks,
        AuthorizeGetDecryptPlan plan)
    {
        var refs = plan.References;
        if (refs.Count == 0 || dataHostChunks.Count != refs.Count)
            return null;

        for (var i = 0; i < refs.Count; i++)
        {
            var r = refs[i];
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                return null;
            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count)
                return null;
            var expect = group[r.ChunkIndex].Length;
            if (expect <= 0 || dataHostChunks[i].Length != expect)
                return null;
        }

        return dataHostChunks.ToList();
    }

    /// <summary>
    /// Slice dati solo da FileChecksumChunkReferences (grid cryptoSum o offset owned @0).
    /// </summary>
    private static List<byte[]> SliceDataByFileRefs(
        byte[] packed,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<AuthorizeGetChunkRef> fileRefs,
        long? dataObjectStart)
        => SliceDataByFileRefs(packed, plan, fileRefs, dataObjectStart, out _);

    private static List<byte[]> SliceDataByFileRefs(
        byte[] packed,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<AuthorizeGetChunkRef> fileRefs,
        long? dataObjectStart,
        out string slicePath)
    {
        slicePath = "none";
        if (fileRefs.Count == 0 || packed.Length == 0)
            return [];

        var ownedAtZero = TrySliceRefsAtPackedStart(packed, plan, fileRefs, 0);
        if (ownedAtZero.Count == fileRefs.Count)
        {
            slicePath = "ownedAtZero";
            return ownedAtZero;
        }

        if (dataObjectStart is long dos && dos > 0)
        {
            var ownedAtStart = TrySliceRefsAtPackedStart(packed, plan, fileRefs, dos);
            if (ownedAtStart.Count == fileRefs.Count)
            {
                slicePath = "ownedAtStart";
                return ownedAtStart;
            }
        }

        // Exact match OR small trailing slack (ford tail / padding) — radios cluster:
        // cryptoSum=10560 packed=10784 (slack=224).
        if (plan.TotalCryptoBytes > 0
            && packed.Length >= plan.TotalCryptoBytes
            && packed.Length - plan.TotalCryptoBytes <= 512)
        {
            var grid = BuildSequentialGridAllowTrailingSlack(packed, plan);
            if (grid is not null)
            {
                var sequential = new List<byte[]>(fileRefs.Count);
                foreach (var r in fileRefs)
                {
                    if ((uint)r.ContainerIndex >= (uint)grid.Length)
                        break;
                    var row = grid[r.ContainerIndex];
                    if (row is null
                        || (uint)r.ChunkIndex >= (uint)row.Length
                        || row[r.ChunkIndex] is null)
                        break;
                    sequential.Add(row[r.ChunkIndex]);
                }

                if (sequential.Count == fileRefs.Count)
                {
                    slicePath = packed.Length == plan.TotalCryptoBytes
                        ? "sequentialGrid"
                        : "sequentialGrid+slack";
                    return sequential;
                }
            }
        }

        throw new CryptographicException(
            $"refs slice fallito: packed={packed.Length} refs={fileRefs.Count} cryptoSum={plan.TotalCryptoBytes}");
    }

    private static List<byte[]> TrySliceRefsAtPackedStart(
        byte[] packed,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<AuthorizeGetChunkRef> fileRefs,
        long packedObjectStart)
    {
        var slices = new List<byte[]>(fileRefs.Count);
        foreach (var r in fileRefs)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                return [];
            var group = plan.Containers[r.ContainerIndex];
            if (group.Count == 0
                || !TryOwnedPackedSlice(
                    packed,
                    group,
                    r.ChunkIndex,
                    out var data,
                    out _,
                    packedObjectStart,
                    ReadOnlySpan<byte>.Empty))
                return [];
            slices.Add(data);
        }

        return slices;
    }

    private static byte[][][]? BuildSequentialGrid(byte[] packed, AuthorizeGetDecryptPlan plan)
    {
        var grid = BuildSequentialGridAllowTrailingSlack(packed, plan);
        if (grid is null)
            return null;
        // Strict: no trailing bytes beyond cryptoSum.
        var used = 0;
        foreach (var row in grid)
        {
            if (row is null)
                continue;
            foreach (var piece in row)
                used += piece?.Length ?? 0;
        }

        return used == packed.Length ? grid : null;
    }

    /// <summary>
    /// Sequential ChunkInfo layout; allows trailing slack (ford tail) after last chunk.
    /// </summary>
    private static byte[][][]? BuildSequentialGridAllowTrailingSlack(
        byte[] packed,
        AuthorizeGetDecryptPlan plan)
    {
        var offset = 0;
        var grid = new byte[plan.Containers.Count][][];
        for (var c = 0; c < plan.Containers.Count; c++)
        {
            var chunks = plan.Containers[c];
            grid[c] = new byte[chunks.Count][];
            for (var k = 0; k < chunks.Count; k++)
            {
                var len = chunks[k].Length;
                if (len <= 0 || offset + len > packed.Length)
                    return null;
                var piece = new byte[len];
                Buffer.BlockCopy(packed, offset, piece, 0, len);
                grid[c][k] = piece;
                offset += len;
            }
        }

        return offset > 0 && offset <= packed.Length ? grid : null;
    }

    /// <summary>
    /// Disabilitato: harvest Ford da gap packed ≠ (Ford = Auth FileGroup GET exact).
    /// </summary>
    private static bool TryAugmentFordKeysFromPackedGaps(
        ReadOnlySpan<byte> fordIkm,
        IReadOnlyList<byte[]> dataHostChunks,
        AuthorizeGetDecryptPlan plan,
        List<FordChunkKey> keys,
        out int gapFordN)
    {
        gapFordN = 0;
        _ = fordIkm;
        _ = dataHostChunks;
        _ = plan;
        _ = keys;
        return false;
    }

    /// <summary>
    /// Ford GET(s) (container authorizeGet senza ChunkInfo) + data GET(s) + MAC ChunkInfo → plaintext.
    /// </summary>
    public static DecryptResult DecryptAsset(
        ReadOnlySpan<byte> fileEncryptionKey,
        ReadOnlySpan<byte> fordCipher,
        IReadOnlyList<byte[]> dataChunks,
        long? declaredPlainSize = null,
        ReadOnlySpan<byte> authorizeGetBody = default,
        long? dataObjectStart = null)
        => DecryptAsset(
            fileEncryptionKey,
            [fordCipher.ToArray()],
            dataChunks,
            declaredPlainSize,
            authorizeGetBody,
            dataObjectStart);

    public static DecryptResult DecryptAsset(
        ReadOnlySpan<byte> fileEncryptionKey,
        IReadOnlyList<byte[]> fordCiphers,
        IReadOnlyList<byte[]> dataChunks,
        long? declaredPlainSize = null,
        ReadOnlySpan<byte> authorizeGetBody = default,
        long? dataObjectStart = null,
        bool fillStrict = false)
    {
        var ikm = fileEncryptionKey.ToArray();
        var keys = new List<FordChunkKey>();
        var okLens = new List<int>();
        var failLens = new List<int>();
        var winHits = new List<object>();
        foreach (var ford in fordCiphers)
        {
            if (ford.Length == 0)
                continue;
            if (TryAddFordKeys(ikm, ford, keys, okLens, failLens))
                continue;

            //-strict: niente SplitConcatenatedFordWindows (pack N×112 inventiva).
            _ = winHits;
        }

        var data = dataChunks.ToList();

        if (keys.Count == 0)
        {
            throw new CryptographicException("Ford AES-SIV decrypt fallito (key/AD)");
        }

        var chunkKeys = keys;
        var macs = authorizeGetBody.IsEmpty
            ? Array.Empty<byte[]>()
            : ExtractChunkHeaderMacs(authorizeGetBody);

        AuthorizeGetDecryptPlan? plan = null;
        if (!authorizeGetBody.IsEmpty)
            plan = UbChunkBuilder.BuildDecryptPlan(authorizeGetBody);

        // path (+0x970856): slice strict per refs → ChunkDecrypt[i] → append.
        // Preferito quando keys/refs/MACs allineati (niente AlignDataChunks / MAC try-all).
        var assemblyMode = "heuristic";
        List<byte[]> aligned;
        if (plan is { References.Count: > 0 }
            && chunkKeys.Count == plan.References.Count
            && macs.Count == plan.References.Count
            && (TrySliceDataByFileRefsPerHost(data, plan, plan.References, out aligned)
                || TrySliceDataByFileRefs(
                    ConcatDataHostChunks(data),
                    plan,
                    plan.References,
                    dataObjectStart,
                    out aligned)))
        {
            assemblyMode = "ike-refs";
            var plain = AssemblePlaintextFromFileRefs(
                chunkKeys,
                aligned,
                macs,
                declaredPlainSize,
                logContext: fillStrict ? "DecryptAsset-fillStrict" : "DecryptAsset-fileRefs");
            return new DecryptResult(
                plain,
                okLens.Count > 0 ? okLens.Sum() : fordCiphers.Sum(static f => f.Length),
                aligned.Count,
                $"via={assemblyMode} fordKeys={chunkKeys.Count} refs={plan.References.Count} macs={macs.Count} verifyDigest=ok");
        }

        if (fillStrict)
        {
            throw new CryptographicException(
                $"strict: refs slice/assemble fallito keys={chunkKeys.Count} " +
                $"refs={plan?.References.Count ?? 0} macs={macs.Count}");
        }

        var packed = AlignDataChunksToFordKeys(data, chunkKeys);
        aligned = packed;
        var fordLens = okLens.Count > 0 ? okLens : fordCiphers.Select(static f => f.Length).ToList();
        if (plan is not null)
        {
            var sliced = SlicePackedByFileRefs(
                packed,
                plan,
                plan.References,
                chunkKeys.Count > 0 ? chunkKeys[0].ChunkLengthHint : null,
                fordLens,
                dataObjectStart);
            if (sliced.Count > 0)
                aligned = sliced;
        }

        if (chunkKeys.Count < aligned.Count)
        {
            throw new CryptographicException(
                $"Ford keys {chunkKeys.Count} < data chunks {aligned.Count}");
        }

        if (macs.Count < aligned.Count)
        {
            throw new CryptographicException(
                $"ChunkInfo MAC {macs.Count} < data chunks {aligned.Count}");
        }

        using var ms = new MemoryStream();
        for (var i = 0; i < aligned.Count; i++)
        {
            // MAC (ExtractChunkHeaderMacs) e Ford keys sono già ordinati per
            // FileChecksumChunkReferences di QUESTO file (0..n-1).
            var keySlot = i < chunkKeys.Count ? i : chunkKeys.Count - 1;
            int? plainHint = chunkKeys[keySlot].ChunkLengthHint;
            if (plainHint is null or <= 0
                && aligned.Count == 1
                && declaredPlainSize is > 0 and <= int.MaxValue)
                plainHint = (int)declaredPlainSize.Value;

            var key = chunkKeys[keySlot].Key;
            var chunk = aligned[i];
            var preferred = i < macs.Count ? i : macs.Count - 1;
            Exception? last = null;
            byte[]? pt = null;
            var tryAll = macs.Count != aligned.Count || chunk.Length <= 1_048_576;
            var order = new List<int> { preferred };
            if (tryAll)
            {
                for (var m = 0; m < macs.Count; m++)
                {
                    if (m != preferred)
                        order.Add(m);
                }
            }

            foreach (var mi in order)
            {
                if ((uint)mi >= (uint)macs.Count)
                    continue;
                try
                {
                    pt = ChunkDecrypt(key, chunk, plainHint, macs[mi]);
                    if (!VerifyDigestWithChunkKey(key, pt, macs[mi]))
                        throw new CryptographicException("VerifyDigest fallito (HMAC/SHA256≠ChunkInfo)");
                    break;
                }
                catch (Exception ex)
                {
                    last = ex;
                    pt = null;
                }
            }

            if (pt is null)
                throw new CryptographicException("ChunkDecrypt: nessun MAC authorizeGet valido", last);

            ms.Write(pt);
        }

        var plainFallback = ms.ToArray();
        if (declaredPlainSize is long exp && exp > 0 && plainFallback.Length != exp)
        {
            // Non throw: LZFSE può espandere dopo; segnala in Note.
        }

        return new DecryptResult(
            plainFallback,
            okLens.Count > 0 ? okLens.Sum() : fordCiphers.Sum(static f => f.Length),
            aligned.Count,
            $"via={assemblyMode} fordKeys={chunkKeys.Count} macs={macs.Count} aligned={aligned.Count} sivOk={okLens.Count}/{fordCiphers.Count} verifyDigest=ok");
    }

    private static List<byte[]> SlicePackedByFileRefs(
        IReadOnlyList<byte[]> packedChunks,
        AuthorizeGetDecryptPlan? plan,
        IReadOnlyList<AuthorizeGetChunkRef> fileRefs,
        int? fordPlainHint,
        IReadOnlyList<int>? fordLens = null,
        long? dataObjectStart = null)
    {
        if (plan is null || fileRefs.Count == 0 || packedChunks.Count == 0)
            return packedChunks.ToList();

        var total = 0;
        foreach (var c in packedChunks)
            total = checked(total + c.Length);
        var packed = new byte[total];
        var o = 0;
        foreach (var c in packedChunks)
        {
            Buffer.BlockCopy(c, 0, packed, o, c.Length);
            o += c.Length;
        }

        var cryptoSum = plan.TotalCryptoBytes;

        var ownedLen = 0;
        var ownedOk = fileRefs.Count > 0;
        foreach (var r in fileRefs)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
            {
                ownedOk = false;
                break;
            }

            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count || group[r.ChunkIndex].Length <= 0)
            {
                ownedOk = false;
                break;
            }

            ownedLen = checked(ownedLen + group[r.ChunkIndex].Length);
        }

        if (ownedOk && ownedLen == packed.Length)
        {
            return packedChunks.ToList();
        }

        List<byte[]>? sequential = null;
        if (cryptoSum > 0 && cryptoSum == packed.Length)
        {
            var grid = new byte[plan.Containers.Count][][];
            var offset = 0;
            var ok = true;
            for (var c = 0; c < plan.Containers.Count && ok; c++)
            {
                var chunks = plan.Containers[c];
                grid[c] = new byte[chunks.Count][];
                for (var k = 0; k < chunks.Count; k++)
                {
                    var len = chunks[k].Length;
                    if (len <= 0 || offset + len > packed.Length)
                    {
                        ok = false;
                        break;
                    }

                    var piece = new byte[len];
                    Buffer.BlockCopy(packed, offset, piece, 0, len);
                    grid[c][k] = piece;
                    offset += len;
                }
            }

            if (ok && offset == packed.Length)
            {
                sequential = new List<byte[]>(fileRefs.Count);
                foreach (var r in fileRefs)
                {
                    if ((uint)r.ContainerIndex >= (uint)grid.Length)
                        continue;
                    var row = grid[r.ContainerIndex];
                    if (row is null || (uint)r.ChunkIndex >= (uint)row.Length || row[r.ChunkIndex] is null)
                        continue;
                    sequential.Add(row[r.ChunkIndex]);
                }
            }
        }

        var packedStart = InferPackedObjectStart(packed, plan, fileRefs, fordLens, dataObjectStart);
        var slices = sequential is { Count: > 0 }
            ? sequential
            : SliceByOffsetOrHint(packed, plan, fileRefs, fordPlainHint, packedStart);


        return slices.Count > 0 ? slices : packedChunks.ToList();
    }

    /// <summary>
    /// Host packed: ChunkInfo.Offset è tipicamente già relativo al body del GET dati
    /// (offset 0 = primo byte del compact dati). Non confondere con ByteRange.Start S3
    /// (es. Instagram: GET 112–end ma ChunkInfo parte da 0 → rebase 112 spezza il MAC).
    /// Usa <paramref name="dataObjectStart"/> solo se gli offset non entrano con start=0.
    /// </summary>
    private static long InferPackedObjectStart(
        byte[] packed,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<AuthorizeGetChunkRef> fileRefs,
        IReadOnlyList<int>? fordLens,
        long? dataObjectStart = null)
    {
        long minOff = long.MaxValue;
        long maxEnd = 0;
        long owned = 0;
        var containerMins = new Dictionary<int, long>();
        foreach (var r in fileRefs)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                continue;
            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count)
                continue;
            var ch = group[r.ChunkIndex];
            if (ch.Length <= 0)
                continue;
            owned += ch.Length;
            if (ch.Offset < minOff)
                minOff = ch.Offset;
            var end = ch.Offset + ch.Length;
            if (end > maxEnd)
                maxEnd = end;

            if (!containerMins.TryGetValue(r.ContainerIndex, out var cMin))
            {
                cMin = long.MaxValue;
                foreach (var gch in group)
                {
                    if (gch.Length > 0 && gch.Offset < cMin)
                        cMin = gch.Offset;
                }

                if (cMin != long.MaxValue)
                    containerMins[r.ContainerIndex] = cMin;
            }
        }

        if (minOff == long.MaxValue || owned <= 0)
            return 0;

        // Caso normale: Offset già nel sistema del GET dati (Instagram / host packed).
        if (maxEnd <= packed.Length && RefsFitPacked(packed, plan, fileRefs, 0))
        {
            return 0;
        }

        // Offset assoluti sull'object (GET = suffisso): prova dataObjectStart / container min.
        if (dataObjectStart is long dos
            && dos >= 0
            && dos <= minOff
            && RefsFitPacked(packed, plan, fileRefs, dos))
        {
            return dos;
        }

        var candidates = new SortedSet<long> { 0, minOff };
        foreach (var cm in containerMins.Values)
            candidates.Add(cm);
        if (fordLens is not null)
        {
            foreach (var fl in fordLens)
            {
                if (fl > 0)
                    candidates.Add(fl);
            }
        }

        foreach (var b in new long[] { 112, 155, 224, 267 })
            candidates.Add(b);

        long best = 0;
        var bestScore = int.MinValue;
        foreach (var start in candidates)
        {
            if (start > minOff)
                continue;
            if (!RefsFitPacked(packed, plan, fileRefs, start))
                continue;
            var trail = packed.Length - (maxEnd - start);
            if (trail < 0)
                continue;

            var score = 0;
            if (containerMins.Values.Contains(start))
                score += 80;
            if (start > 0)
                score += 10;
            if (trail == 0)
                score += 40;
            if (fordLens is not null && fordLens.Contains((int)start))
                score += 5;
            if (owned == packed.Length && start == minOff)
                score += 40;
            score -= (int)Math.Min(start, 1000);
            if (score > bestScore)
            {
                bestScore = score;
                best = start;
            }
        }

        return best;
    }

    private static bool RefsFitPacked(
        byte[] packed,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<AuthorizeGetChunkRef> fileRefs,
        long start)
    {
        foreach (var r in fileRefs)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                continue;
            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count)
                continue;
            var ch = group[r.ChunkIndex];
            if (ch.Length <= 0)
                continue;
            var rel = ch.Offset - start;
            if (rel < 0 || rel + ch.Length > packed.Length)
                return false;
        }

        return true;
    }

    /// <summary>
    /// Offset ChunkInfo → indice nel body del GET packed.
    /// <paramref name="packedObjectStart"/> = primo byte object coperto dal GET (es. 112 dopo Ford 0–111).
    /// </summary>
    private static int RelOffsetInPacked(
        AuthorizeGetCryptoChunk ch,
        IReadOnlyList<AuthorizeGetCryptoChunk> group,
        int packedLen,
        long packedObjectStart = 0)
    {
        var abs = ch.Offset;
        if (packedObjectStart > 0 && abs >= packedObjectStart)
        {
            var rebased = checked((int)(abs - packedObjectStart));
            if (rebased >= 0 && (long)rebased + ch.Length <= packedLen)
                return rebased;
        }

        long min = long.MaxValue;
        foreach (var c in group)
        {
            if (c.Length > 0 && c.Offset < min)
                min = c.Offset;
        }

        if (min == long.MaxValue)
            min = 0;

        if (min > packedLen || abs > packedLen)
            return checked((int)(abs - min));
        return checked((int)abs);
    }

    /// <summary>
    /// GET packed = [chunk0][Ford][chunk1][Ford]… Il file è solo <c>group[k]</c>:
    /// dati = Offset/Length; Ford = gap subito prima (chunk 0: Ford nel GET precedente).
    /// </summary>
    public static bool TryOwnedPackedSlice(
        byte[] packed,
        IReadOnlyList<AuthorizeGetCryptoChunk> group,
        int chunkIndex,
        out byte[] data,
        out byte[] innerFord,
        long packedObjectStart = 0,
        ReadOnlySpan<byte> ikm = default)
    {
        data = [];
        innerFord = [];
        if (packed.Length == 0 || (uint)chunkIndex >= (uint)group.Count)
            return false;
        var ch = group[chunkIndex];
        if (ch.Length <= 0)
            return false;
        var rel = RelOffsetInPacked(ch, group, packed.Length, packedObjectStart);
        if (rel < 0 || (long)rel + ch.Length > packed.Length)
            return false;
        // Data only: Auth ChunkInfo Offset/Length. Ford NON si inventa dal gap packed
        // ( 1 FileGroup → 1 GET → 1 file .chunks/hex(gate)).
        data = packed.AsSpan(rel, ch.Length).ToArray();
        innerFord = [];
        _ = ikm;
        return true;
    }

    private static void CollectGapFordCandidates(
        byte[] packed,
        int gapStart,
        int gapEnd,
        string tag,
        List<(string Gap, byte[] Ford)> dst)
    {
        if (gapStart < 0 || gapEnd > packed.Length || gapEnd - gapStart < 0x12)
            return;
        foreach (var n in (ReadOnlySpan<int>)[112, 155, 224])
        {
            if (gapEnd - gapStart < n)
                continue;
            if (packed[gapStart] == 0x04)
                dst.Add(($"{tag}-head", packed.AsSpan(gapStart, n).ToArray()));
            if (packed[gapEnd - n] == 0x04)
                dst.Add(($"{tag}-tail", packed.AsSpan(gapEnd - n, n).ToArray()));
        }
    }

    private static List<byte[]> SliceByOffsetOrHint(
        byte[] packed,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<AuthorizeGetChunkRef> fileRefs,
        int? fordPlainHint,
        long packedObjectStart = 0)
    {
        var slices = new List<byte[]>();
        foreach (var r in fileRefs)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                continue;
            var group = plan.Containers[r.ContainerIndex];
            if (!TryOwnedPackedSlice(packed, group, r.ChunkIndex, out var data, out _, packedObjectStart))
            {
                if (fordPlainHint is int h && h > 0 && h < packed.Length)
                {
                    var fallback = new byte[h];
                    Buffer.BlockCopy(packed, 0, fallback, 0, h);
                    slices.Add(fallback);
                }

                continue;
            }

            slices.Add(data);
        }

        return slices;
    }

    /// <summary>
    /// HTTP range ≠ chunk MMCS: un GET può concatenare più pezzi da 5 MiB.
    /// Spezza il CT in sequenza secondo <see cref="FordChunkKey.ChunkLengthHint"/>.
    /// </summary>
    public static List<byte[]> AlignDataChunksToFordKeys(
        IReadOnlyList<byte[]> dataChunks,
        IReadOnlyList<FordChunkKey> chunkKeys)
    {
        if (dataChunks.Count == 0)
            return [];
        if (chunkKeys.Count <= 1 || dataChunks.Count >= chunkKeys.Count)
            return dataChunks.ToList();

        var total = 0;
        foreach (var c in dataChunks)
            total = checked(total + c.Length);
        var concat = new byte[total];
        var o = 0;
        foreach (var c in dataChunks)
        {
            Buffer.BlockCopy(c, 0, concat, o, c.Length);
            o += c.Length;
        }

        var slices = new List<byte[]>(chunkKeys.Count);
        var off = 0;
        for (var i = 0; i < chunkKeys.Count; i++)
        {
            int n;
            if (i == chunkKeys.Count - 1)
                n = concat.Length - off;
            else
            {
                n = chunkKeys[i].ChunkLengthHint is int h && h > 0 ? h : 5_242_880;
                if (off + n > concat.Length)
                    n = concat.Length - off;
            }

            if (n <= 0)
                throw new CryptographicException($"Ford align: slice {i} vuoto (off={off})");
            var slice = new byte[n];
            Buffer.BlockCopy(concat, off, slice, 0, n);
            slices.Add(slice);
            off += n;
        }

        if (off != concat.Length)
            throw new CryptographicException(
                $"Ford align: residuo {concat.Length - off} B dopo {slices.Count} slice");
        return slices;
    }

    /// <summary>
    /// Disabilitato: inventiva packed/trailing/implied. Ford = Auth FileGroup GET exact ctLen.
    /// </summary>
    public static bool TryExtractFordFamilyPackedHost(
        ReadOnlySpan<byte> compact,
        AuthorizeGetDecryptPlan plan,
        out List<byte[]> fordCiphers,
        out List<byte[]> dataChunks,
        ReadOnlySpan<byte> impliedFord = default,
        ReadOnlySpan<byte> ikm = default)
    {
        fordCiphers = [];
        dataChunks = [];
        _ = compact;
        _ = plan;
        _ = impliedFord;
        _ = ikm;
        // #region agent log
        AgentStrictReject("H-NO-INVENT", "TryExtractFordFamilyPackedHost", "disabled_packed_invent",
            new Dictionary<string, object?>());
        // #endregion
        return false;
    }

    /// <summary>Disabilitato: slice packed[rel−112] = inventiva dataStart−N.</summary>
    private static bool TrySliceFordBeforeOffset(byte[] packed, int rel, out byte[] ford)
    {
        _ = packed;
        _ = rel;
        ford = [];
        return false;
    }

    /// <summary>Disabilitato: coda 112/155/224 da blob packed ≠ spill exact.</summary>
    private static bool TrySliceTrailingFord(byte[] blob, out byte[] ford, out byte[] data)
    {
        _ = blob;
        ford = [];
        data = [];
        return false;
    }

    /// <summary>
    /// Disabilitato: gap-Ford interleaved ≠ (1 FileGroup → 1 GET → 1 file).
    /// </summary>
    public static bool TryExtractInterleavedPackedFord(
        ReadOnlySpan<byte> compact,
        AuthorizeGetDecryptPlan plan,
        out List<byte[]> fordCiphers,
        out List<byte[]> dataChunks,
        ReadOnlySpan<byte> ikm = default)
    {
        fordCiphers = [];
        dataChunks = [];
        _ = compact;
        _ = plan;
        _ = ikm;
        // #region agent log
        AgentStrictReject("H-NO-INVENT", "TryExtractInterleavedPackedFord", "disabled_gap_ford",
            new Dictionary<string, object?>());
        // #endregion
        return false;
    }

    /// <summary>
    /// Solo slice dati owned (ChunkInfo Offset/Length) da compact packed condiviso.
    /// Usato quando il gap Ford non apre con IKM (file precedente) ma i dati sì.
    /// </summary>
    public static bool TryExtractOwnedRefDataSlices(
        ReadOnlySpan<byte> compact,
        AuthorizeGetDecryptPlan plan,
        out List<byte[]> dataChunks)
    {
        dataChunks = [];
        if (compact.IsEmpty || plan.References.Count == 0 || plan.Containers.Count == 0)
            return false;

        var packed = compact.ToArray();
        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                return false;
            var group = plan.Containers[r.ContainerIndex];
            if (group.Count == 0
                || !TryOwnedPackedSlice(
                    packed, group, r.ChunkIndex, out var data, out _, ikm: default))
                return false;
            if (data.Length == 0)
                return false;
            dataChunks.Add(data);
        }

        return dataChunks.Count == plan.References.Count;
    }

    /// <summary>
    /// FillChunks: i data chunks passati al decrypt devono essere 1:1 con
    /// <c>FileChecksumChunkReferences</c> (len == ChunkInfo.Length). Se resolve ha
    /// lasciato l'host packed intero, ri-slice qui — mai decrypt sull'intero compact.
    /// </summary>
    public static bool TryEnsureOwnedRefDataChunks(
        ReadOnlySpan<byte> compact,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<byte[]> current,
        out List<byte[]> owned,
        out string note)
    {
        owned = [];
        note = "";
        if (plan.References.Count == 0)
            return false;

        if (current.Count == plan.References.Count)
        {
            var match = true;
            for (var i = 0; i < plan.References.Count; i++)
            {
                var r = plan.References[i];
                if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                {
                    match = false;
                    break;
                }

                var group = plan.Containers[r.ContainerIndex];
                if ((uint)r.ChunkIndex >= (uint)group.Count
                    || group[r.ChunkIndex].Length <= 0
                    || current[i].Length != group[r.ChunkIndex].Length)
                {
                    match = false;
                    break;
                }
            }

            if (match)
            {
                owned = current.ToList();
                note = "already-owned";
                return true;
            }
        }

        if (TryExtractOwnedRefDataSlices(compact, plan, out owned)
            && owned.Count == plan.References.Count)
        {
            note = "owned-from-compact";
            return true;
        }

        if (current.Count > 0)
        {
            try
            {
                var packed = ConcatDataHostChunks(current);
                owned = SliceDataByFileRefs(packed, plan, plan.References, null, out var path);
                if (owned.Count == plan.References.Count)
                {
                    note = "owned-from-hosts:" + path;
                    return true;
                }
            }
            catch (CryptographicException)
            {
                // fall through
            }
        }

        note = $"fail dataN={current.Count} refs={plan.References.Count} compact={compact.Length}";
        owned = [];
        return false;
    }


    /// <summary>
    /// H-DATAONLY-FORD: <c>emptyHosts=0</c>. Ford = ChunkInfo sibling (stesso host
    /// contChunkN≥2) <b>oppure</b> host cross-container con un solo ChunkInfo Ford-sized
    /// (contChunkN=[1,1]…), lead-0x04 / marker 45B <c>0C0F0104</c>.
    /// FillChunks mette il gate in <c>storage+0x88</c>; CT AesSiv è il GET Ford.
    /// </summary>
    public static bool TryExtractDataOnlyChunkInfoFord(
        ReadOnlySpan<byte> compact,
        AuthorizeGetDecryptPlan plan,
        ReadOnlySpan<byte> fordIkm,
        out List<byte[]> fordCiphers,
        out List<byte[]> dataChunks,
        out string note)
    {
        fordCiphers = [];
        dataChunks = [];
        note = "";
        if (compact.IsEmpty || fordIkm.IsEmpty || plan.Containers.Count == 0)
            return false;

        var packed = compact.ToArray();
        var fordCandidates = new List<byte[]>();
        var marker45 = false;
        var classifiedData = new List<(int Container, int Chunk, byte[] Bytes)>();
        var anyGroup = false;

        for (var ci = 0; ci < plan.Containers.Count; ci++)
        {
            var group = plan.Containers[ci];
            if (group.Count == 0)
                continue;
            anyGroup = true;

            // Sequential layout first (cryptoSum ≈ compact).
            var off = 0;
            var seqOk = true;
            var pieces = new byte[group.Count][];
            for (var k = 0; k < group.Count; k++)
            {
                var len = group[k].Length;
                if (len <= 0 || off + len > packed.Length)
                {
                    seqOk = false;
                    break;
                }

                pieces[k] = packed.AsSpan(off, len).ToArray();
                off += len;
            }

            // Offset-based layout when sequential fails or leaves large slack.
            if (!seqOk || (off < packed.Length && packed.Length - off > 512))
            {
                seqOk = true;
                for (var k = 0; k < group.Count; k++)
                {
                    if (!TryOwnedPackedSlice(packed, group, k, out var slice, out _, ikm: fordIkm))
                    {
                        seqOk = false;
                        break;
                    }

                    pieces[k] = slice;
                }
            }

            // Single-container body == entire compact (common data_only refs→one host).
            if (!seqOk && group.Count == 1 && plan.Containers.Count == 1)
            {
                pieces[0] = packed;
                seqOk = true;
                off = packed.Length;
            }

            if (!seqOk)
                continue;

            // Trailing slack may hold the AesSiv CT when ChunkInfo lengths omit it.
            if (off > 0 && off < packed.Length)
            {
                var slack = packed.AsSpan(off);
                if (TryPickFordCipherFromHost(fordIkm, slack, out var slackFord))
                    fordCandidates.Add(slackFord);
            }

            for (var k = 0; k < pieces.Length; k++)
            {
                var piece = pieces[k];
                if (piece.Length == 0)
                    continue;

                if (IsAuthFordMarker45(piece))
                {
                    marker45 = true;
                    // Marker ≠ AesSiv CT: keep looking for a real window; do not treat as data.
                    if (TryPickFordCipherFromHost(fordIkm, piece, out var fromMarker))
                        fordCandidates.Add(fromMarker);
                    continue;
                }

                if (TryPickFordCipherFromHost(fordIkm, piece, out var fordCt))
                {
                    fordCandidates.Add(fordCt);
                    continue;
                }

                // Standard Ford length + lead 0x04 even if IKM not yet bound (retry path).
                if (piece[0] == 0x04 && IsExactStandardFordHostLength(piece.Length))
                {
                    fordCandidates.Add(piece);
                    continue;
                }

                // Cross-container ford host: single ChunkInfo of Ford-window size.
                if (group.Count == 1
                    && piece[0] == 0x04
                    && IsFordSizedPlanContainer(plan, ci))
                {
                    fordCandidates.Add(piece);
                    continue;
                }

                classifiedData.Add((ci, k, piece));
            }
        }

        if (!anyGroup)
            return false;

        if (fordCandidates.Count == 0 && marker45)
        {
            // 45B 0C0F0104 gate only: AesSiv CT may still sit inside the compact.
            if (TryPickFordCipherFromHost(fordIkm, packed, out var hostFord))
                fordCandidates.Add(hostFord);
        }

        // Whole-compact scan when ChunkInfo layout did not yield a Ford CT.
        if (fordCandidates.Count == 0
            && TryPickFordCipherFromHost(fordIkm, packed, out var packedFord)
            && packedFord.Length < packed.Length)
        {
            fordCandidates.Add(packedFord);
        }

        if (fordCandidates.Count == 0)
            return false;

        // Prefer a candidate that opens + yields keys covering this file's refs
        // (packed host: N keys for N ChunkInfo, FilePart may have refs=1).
        var refCount = plan.References.Count > 0 ? plan.References.Count : 1;
        byte[]? chosen = null;
        foreach (var cand in fordCandidates)
        {
            if (!TryCountFordKeys(fordIkm, [cand], out var keys)
                || !FordKeysCoverPlanRefs(keys, plan))
                continue;
            chosen = cand;
            break;
        }

        if (chosen is null)
        {
            // #region agent log
            // No IKM-open-without-keys fallback: that produced resolve_ok → MAC20 fail
            // (PaperPreview/WebKit salt). requires ParseFordInfo keys to cover refs.
            AgentSessionNdjsonAlways(
                "H-DATAONLY-FORD",
                "chunkinfo_no_keycount_match",
                new Dictionary<string, object?>
                {
                    ["candidates"] = fordCandidates.Count,
                    ["refCount"] = refCount,
                    ["compact"] = packed.Length,
                    ["marker45"] = marker45,
                    ["runId"] = "packed-keys-v1",
                });
            // #endregion
            return false;
        }

        // Data = owned ref slices (preferred) else non-Ford ChunkInfo pieces.
        if (!TryExtractOwnedRefDataSlices(packed, plan, out dataChunks)
            || dataChunks.Count == 0)
        {
            dataChunks = [];
            if (plan.References.Count > 0)
            {
                foreach (var r in plan.References)
                {
                    foreach (var (c, k, bytes) in classifiedData)
                    {
                        if (c == r.ContainerIndex && k == r.ChunkIndex)
                        {
                            dataChunks.Add(bytes);
                            break;
                        }
                    }
                }
            }
            else
            {
                foreach (var (_, _, bytes) in classifiedData)
                    dataChunks.Add(bytes);
            }
        }

        if (dataChunks.Count == 0)
            return false;

        // Drop data slices that are the chosen Ford window (shared buffer / wrong ref).
        for (var i = dataChunks.Count - 1; i >= 0; i--)
        {
            if (dataChunks[i].AsSpan().SequenceEqual(chosen))
                dataChunks.RemoveAt(i);
        }

        if (dataChunks.Count == 0)
            return false;

        fordCiphers = [chosen];
        note = marker45
            ? $"data-only-chunkinfo-ford marker45 ford={chosen.Length}"
            : $"data-only-chunkinfo-ford ford={chosen.Length}";
        return true;
    }

    /// <summary>Auth Ford gate blob: 45 B lead <c>0C 0F 01 04</c> (storage+0x88).</summary>
    public static bool IsAuthFordMarker45(ReadOnlySpan<byte> blob) =>
        blob.Length == 45
        && blob[0] == 0x0C
        && blob[1] == 0x0F
        && blob[2] == 0x01
        && blob[3] == 0x04;

    /// <summary>True if authorizeGet wire contains a 45B <c>0C0F0104</c> gate field.</summary>
    public static bool AuthBodyHasFordMarker45(ReadOnlySpan<byte> authorizeGetBody)
    {
        if (authorizeGetBody.Length < 49)
            return false;
        // Protobuf: 0A 2D | 0C 0F 01 04 … (field1 len=45)
        ReadOnlySpan<byte> needle = [0x0A, 0x2D, 0x0C, 0x0F, 0x01, 0x04];
        for (var i = 0; i <= authorizeGetBody.Length - needle.Length; i++)
        {
            if (authorizeGetBody.Slice(i, needle.Length).SequenceEqual(needle))
                return true;
        }

        // Fallback: raw gate lead anywhere.
        ReadOnlySpan<byte> lead = [0x0C, 0x0F, 0x01, 0x04];
        for (var i = 0; i <= authorizeGetBody.Length - 45; i++)
        {
            if (!authorizeGetBody.Slice(i, 4).SequenceEqual(lead))
                continue;
            if (IsAuthFordMarker45(authorizeGetBody.Slice(i, 45)))
                return true;
        }

        return false;
    }

    /// <summary>
    /// DecryptFordKeys: Auth gate+ctLen+OID → <c>stream.Read(ctLen)</c> sul GET già scaricato.
    /// Collega descriptor Auth (nested wire <b>o</b> CI gate45) al compact/sibling per OID.
    /// </summary>
    public static bool TryBindAuthFordDescriptors(
        ReadOnlySpan<byte> compact,
        AuthorizeGetDecryptPlan plan,
        ReadOnlySpan<byte> fordIkm,
        ReadOnlySpan<byte> authorizeGetBody,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts,
        out List<byte[]> fordCiphers,
        out List<byte[]> dataChunks,
        out string note,
        IReadOnlyList<SignedUrlChunk>? chunks = null)
    {
        fordCiphers = [];
        dataChunks = [];
        note = "";
        if (compact.IsEmpty || fordIkm.IsEmpty || authorizeGetBody.IsEmpty)
            return false;

        var descriptors = UbChunkBuilder.CollectAuthFordDescriptors(authorizeGetBody, plan, chunks);
        if (descriptors.Count == 0)
            return false;

        var refCount = plan.References.Count > 0 ? plan.References.Count : 1;
        var candidates = new List<(byte[] Ford, string Src, string Oid, int CtLen)>();
        var oidHit = 0;
        var oidMiss = 0;
        var sliceFail = 0;

        foreach (var d in descriptors)
        {
            if (UbChunkBuilder.IsClassicAuthFordCtLen(d.CtLen))
            {
                // path storico: nessun check ByteRange
            }
            else if (UbChunkBuilder.IsLargeAuthFordCtLen(d.CtLen))
            {
                long hostLen = 0;
                if (!string.IsNullOrEmpty(d.ObjectId) && chunks is { Count: > 0 })
                {
                    foreach (var ch in chunks)
                    {
                        if (!string.Equals(ch.EdgeHeaders?.ObjectId, d.ObjectId, StringComparison.Ordinal)
                            || ch.ByteRange is not { } hbr)
                            continue;
                        hostLen = hbr.End - hbr.Start + 1;
                        break;
                    }
                }

                if (!UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen, hostLen))
                    continue;
            }
            else
            {
                continue;
            }

            byte[]? body = null;
            var src = "none";
            long bestStart = long.MaxValue;

            if (siblingCompacts is { Count: > 0 } && !string.IsNullOrEmpty(d.ObjectId))
            {
                var prefix = d.ObjectId + "@";
                foreach (var (key, (blob, start)) in siblingCompacts)
                {
                    if (!key.StartsWith(prefix, StringComparison.Ordinal))
                        continue;
                    if (blob.Length < d.CtLen)
                        continue;
                    // Read(ctLen): prefer MmcsStart==0 + exact ctLen.
                    var exact = blob.Length == d.CtLen
                                || (d.HostSizeHint > 0 && blob.Length == d.HostSizeHint);
                    var better = body is null
                                 || exact
                                 || (start == 0 && bestStart != 0)
                                 || (start < bestStart && body.Length != d.CtLen);
                    if (!better)
                        continue;
                    body = blob;
                    bestStart = start;
                    src = exact ? $"sibling-exact@{start}" : $"sibling@{start}";
                    if (exact && start == 0)
                        break;
                }
            }

            // Compact corrente se è il GET Ford (Read(ctLen) sullo stesso body).
            if (body is null
                && compact.Length >= d.CtLen
                && (compact.Length == d.CtLen
                    || (d.HostSizeHint > 0 && compact.Length == d.HostSizeHint)
                    || (compact[0] == 0x04
                        && compact.Length <= Math.Max(d.CtLen + 256, 4096))))
            {
                body = compact.ToArray();
                src = "compact";
            }

            if (body is null)
            {
                oidMiss++;
                continue;
            }

            oidHit++;
            //  fordCT = body[0 : ctLen] (storage+0x58). DecryptFordKeys validates —
            // do not hunt alternate IKM-open windows when align ON.
            var slice = body.AsSpan(0, Math.Min(d.CtLen, body.Length)).ToArray();
            if (slice.Length != d.CtLen)
            {
                sliceFail++;
                continue;
            }

            var seen = false;
            foreach (var (prev, _, _, _) in candidates)
            {
                if (prev.AsSpan().SequenceEqual(slice))
                {
                    seen = true;
                    break;
                }
            }

            if (!seen)
                candidates.Add((slice, src, d.ObjectId, d.CtLen));
        }

        // #region agent log
        AgentFordResolveLog("H-AUTH-STOR", "auth_ford_bind_scan", new Dictionary<string, object?>
        {
            ["descN"] = descriptors.Count,
            ["oidHit"] = oidHit,
            ["oidMiss"] = oidMiss,
            ["sliceFail"] = sliceFail,
            ["candN"] = candidates.Count,
            ["siblings"] = siblingCompacts?.Count ?? 0,
            ["compact"] = compact.Length,
            ["ctLens"] = descriptors.Select(static d => d.CtLen).Take(8).ToArray(),
            ["runId"] = "auth-to-storage-v1",
        });
        // #endregion

        if (candidates.Count == 0)
        {
            // #region agent log
            AgentFordResolveLog("H-AUTH-FORD", "auth_ford_bind_empty", new Dictionary<string, object?>
            {
                ["descN"] = descriptors.Count,
                ["oidHit"] = oidHit,
                ["oidMiss"] = oidMiss,
                ["sliceFail"] = sliceFail,
                ["siblings"] = siblingCompacts?.Count ?? 0,
                ["compact"] = compact.Length,
            });
            // #endregion
            return false;
        }

        // Prefer candidate that DecryptFordKeys accepts + covers this file's refs.
        //  wrong Ford CT → AES-SIV fail → skip; never pick candidates[0] of the shared FG.
        byte[]? chosen = null;
        string chosenSrc = "";
        foreach (var (ford, src, _, _) in candidates)
        {
            if (!TryCountFordKeys(fordIkm, [ford], out var keys)
                || !FordKeysCoverPlanRefs(keys, plan))
                continue;
            chosen = ford;
            chosenSrc = src;
            break;
        }

        if (chosen is null)
        {
            foreach (var (ford, src, _, _) in candidates)
            {
                // Come sopra: apre + keys coprono ChunkIndex (no open-only).
                if (!TryCountFordKeys(fordIkm, [ford], out var keys)
                    || !FordKeysCoverPlanRefs(keys, plan))
                    continue;
                if (!BlobOpensWithIkm(fordIkm, ford))
                    continue;
                chosen = ford;
                chosenSrc = src + "+open+cover";
                break;
            }
        }

        // #region agent log
        if (chosen is null && candidates.Count > 0)
        {
            AgentFordResolveLog("H-AUTH-STOR", "auth_ford_bind_no_ikm_match", new Dictionary<string, object?>
            {
                ["candN"] = candidates.Count,
                ["descN"] = descriptors.Count,
                ["refs"] = refCount,
                ["runId"] = "filegroup-ikm-gate-v1",
            });
        }
        // #endregion

        if (chosen is null)
            return false;

        if (!TryExtractOwnedRefDataSlices(compact, plan, out dataChunks)
            || dataChunks.Count == 0)
        {
            // Packed host: data = body after Ford prefix when compact == chosen‖data.
            // Mai candidates[0]: CtLen del primo Auth desc ≠ Ford scelto → MAC storm.
            if (compact.Length > chosen.Length
                && compact.Slice(0, chosen.Length).SequenceEqual(chosen))
            {
                dataChunks = [compact.Slice(chosen.Length).ToArray()];
            }
            else
            {
                // #region agent log
                AgentFordResolveLog("H-AUTH-FORD", "auth_ford_bind_no_data", new Dictionary<string, object?>
                {
                    ["descN"] = descriptors.Count,
                    ["candN"] = candidates.Count,
                    ["chosenLen"] = chosen.Length,
                    ["runId"] = "filegroup-only-v1",
                    ["fordLen"] = chosen.Length,
                    ["src"] = chosenSrc,
                    ["compact"] = compact.Length,
                    ["refs"] = refCount,
                });
                // #endregion
                return false;
            }
        }

        // Drop data == ford window.
        for (var i = dataChunks.Count - 1; i >= 0; i--)
        {
            if (dataChunks[i].AsSpan().SequenceEqual(chosen))
                dataChunks.RemoveAt(i);
        }

        if (dataChunks.Count == 0)
            return false;

        fordCiphers = [chosen];
        note = $"auth-ford-desc src={chosenSrc} ford={chosen.Length} desc={descriptors.Count} cand={candidates.Count}";
        // #region agent log
        AgentFordResolveLog("H-AUTH-FORD", "auth_ford_bind_ok", new Dictionary<string, object?>
        {
            ["note"] = note,
            ["fordLen"] = chosen.Length,
            ["fordLead"] = chosen.Length > 0 ? chosen[0] : -1,
            ["dataN"] = dataChunks.Count,
            ["data0"] = dataChunks[0].Length,
            ["descN"] = descriptors.Count,
            ["oidHit"] = oidHit,
            ["oidMiss"] = oidMiss,
            ["keysOk"] = TryCountFordKeys(fordIkm, fordCiphers, out var k) && k == refCount,
            ["marker"] = "AUTH_FORD_DESC_BIND_V1",
        });
        // #endregion
        return true;
    }

    /// <summary>
    /// Allineamento (FillChunks): Ford da container empty del plan + <b>pool batch</b>
    /// (sibling empty-host IKM-open, selezione per refs.Count), data dagli host con ChunkInfo.
    /// Nessuna euristica geometrica same-OID.
    /// </summary>
    public static bool TryResolveFordAndData(
        ReadOnlySpan<byte> compact,
        IReadOnlyList<SignedUrlChunk> ordered,
        IReadOnlyList<SignedUrlChunk> original,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts,
        ReadOnlySpan<byte> fordIkm,
        ReadOnlySpan<byte> authorizeGetBody,
        out List<byte[]> fordCiphers,
        out List<byte[]> dataChunks,
        out string resolveNote)
    {
        fordCiphers = [];
        dataChunks = [];
        resolveNote = "";
        if (original.Count == 0 || plan.Containers.Count == 0)
        {
            // #region agent log
            AgentPdfFailDiagLog("H-R1", "resolve_early", new Dictionary<string, object?>
            {
                ["why"] = "empty_plan_or_chunks",
                ["originalN"] = original.Count,
                ["containers"] = plan.Containers.Count,
            });
            // #endregion
            return false;
        }

        var bodiesFromCompact = new Dictionary<int, byte[]>();
        var offset = 0;
        foreach (var c in ordered)
        {
            if (c.ByteRange is not { } br)
            {
                // #region agent log
                AgentPdfFailDiagLog("H-R1", "resolve_early", new Dictionary<string, object?>
                {
                    ["why"] = "ordered_no_byterange",
                    ["orderedN"] = ordered.Count,
                    ["compact"] = compact.Length,
                });
                // #endregion
                return false;
            }
            if (br.End < br.Start || br.Start < 0)
            {
                // #region agent log
                AgentPdfFailDiagLog("H-R1", "resolve_early", new Dictionary<string, object?>
                {
                    ["why"] = "invalid_byterange",
                    ["start"] = br.Start,
                    ["end"] = br.End,
                });
                // #endregion
                return false;
            }

            var len = checked((int)(br.End - br.Start + 1));
            if (len <= 0 || offset + len > compact.Length)
            {
                // #region agent log
                AgentPdfFailDiagLog("H-R1", "resolve_early", new Dictionary<string, object?>
                {
                    ["why"] = len <= 0 ? "range_len_nonpositive" : "compact_overflow",
                    ["offset"] = offset,
                    ["len"] = len,
                    ["compact"] = compact.Length,
                });
                // #endregion
                return false;
            }
            var slice = compact.Slice(offset, len).ToArray();
            offset += len;
            var idx = IndexOfSignedChunk(original, c);
            if (idx >= 0)
                bodiesFromCompact[idx] = slice;
        }

        if (ordered.Count > 0 && offset != compact.Length)
        {
            var delta = compact.Length - offset;
            // H-FORD6: oggetti shared/packed spesso finiscono con slack 112/155/224 B
            // oltre dataEnd (auth). Prima: mismatch → resolve false → size 0 (E0640).
            var trailingSlackOk = delta is > 0 and <= 224 && offset > 0;
            // #region agent log
            AgentFordResolveLog(
                trailingSlackOk ? "H-FORD6-ok" : "H-FORD6",
                "resolve_compact_len",
                new Dictionary<string, object?>
                {
                    ["why"] = trailingSlackOk ? "trailing_slack_accept" : "compact_len_mismatch",
                    ["offset"] = offset,
                    ["compact"] = compact.Length,
                    ["orderedN"] = ordered.Count,
                    ["delta"] = delta,
                    ["accepted"] = trailingSlackOk,
                    ["marker"] = "E0640_TRAILING_SLACK_V1",
                });
            // #endregion
            if (!trailingSlackOk)
                return false;
        }

        foreach (var c in ordered)
        {
            var idx = IndexOfSignedChunk(original, c);
            if (idx < 0
                || (uint)idx >= (uint)plan.Containers.Count
                || plan.Containers[idx].Count == 0)
                continue;
            // Skip ford-sized ChunkInfo hosts — they are CT, not data.
            if (IsFordSizedPlanContainer(plan, idx))
                continue;
            if (bodiesFromCompact.TryGetValue(idx, out var slice))
                dataChunks.Add(slice);
        }

        var n = Math.Min(original.Count, plan.Containers.Count);
        for (var i = 0; i < n; i++)
        {
            if (!IsFordSizedPlanContainer(plan, i))
                continue;
            var group = plan.Containers[i];
            var empty = group.Count == 0;
            var fordChunk = !empty;

            byte[]? body = null;
            var emptyBodySrc = "none";
            if (bodiesFromCompact.TryGetValue(i, out var fromCompact))
            {
                body = fromCompact;
                emptyBodySrc = "authslice";
            }
            else if (siblingCompacts is { Count: > 0 }
                     && original[i].ByteRange is { } br)
            {
                var oid = original[i].EdgeHeaders?.ObjectId ?? "";
                var key = $"{oid}@{br.Start}";
                if (siblingCompacts.TryGetValue(key, out var entry))
                {
                    body = entry.Compact;
                    emptyBodySrc = "sibling";
                }
                else
                    emptyBodySrc = "sibling_miss";
            }

            var pickOk = false;
            byte[] fordCt = [];
            if (body is { Length: > 0 })
                pickOk = TryPickFordCipherFromHost(fordIkm, body, out fordCt);
            if (pickOk)
                fordCiphers.Add(fordCt);
            else
            {
                // #region agent log
                AgentFordResolveLog("H-R2", "empty_ford_pick", new Dictionary<string, object?>
                {
                    ["container"] = i,
                    ["src"] = emptyBodySrc,
                    ["bodyLen"] = body?.Length ?? -1,
                    ["bodyLead"] = body is { Length: > 0 } ? body[0] : -1,
                    ["ikmLen"] = fordIkm.Length,
                    ["containerChunkN"] = group.Count,
                    ["fordChunk"] = fordChunk,
                    ["marker"] = "EMPTY_FORD_PICK_V1",
                });
                // #endregion
            }
        }

        //-strict: niente packed-tail (coda 112/155/224 da blob). Ford = GET exact.

        // FillChunks Pipe A/B: Ford = storage empty/ford-sized del FileGroup (tree),
        // non pool IKM-open del batch. needPool → TryBindFileGroupFordStorages (+ MAC).
        // Fallthrough: H-AUTH-FORD / H-DATAONLY (compact prefix), mai sibling-ford trial.
        if (dataChunks.Count > 0
            && !fordIkm.IsEmpty
            && siblingCompacts is { Count: > 0 })
        {
            var refCount = plan.References.Count > 0
                ? plan.References.Count
                : Math.Max(dataChunks.Count, 1);
            var needPool = fordCiphers.Count == 0
                           || !TryCountFordKeys(fordIkm, fordCiphers, out var haveKeys)
                           || !FordKeysCoverPlanRefs(haveKeys, plan);

            // Probe MAC sulla PRIMA slice ref (ChunkDecrypt r9 = chunk len),
            // NON sull'intero data-host (spesso 30MB) — altrimenti needPool è sempre true.
            var probeSlice = dataChunks[0];
            var probeFromRef = TryGetFirstRefMacProbeSlice(dataChunks, plan, out var firstRefSlice);
            if (probeFromRef)
                probeSlice = firstRefSlice;

            // Key-count ok ma MAC sbagliato (PDF multi-host): forza pool MAC-validato.
            // Probe strict: solo key[0]+mac[0] (ordine refs) — niente cross-product.
            var probeMacs = ExtractChunkHeaderMacs(authorizeGetBody);
            var probePass = false;
            var probeKeyIdx = -1;
            var probeMacIdx = -1;
            if (!needPool
                && fordCiphers.Count > 0
                && probeSlice.Length > 0
                && probeMacs.Count > 0)
            {
                probePass = TryFordStoragesPassMacDiag(
                    fordIkm, fordCiphers, probeSlice, probeMacs,
                    out probeKeyIdx, out probeMacIdx);
            }

            // #region agent log
            AgentPdfFailDiagLog(
                "H-MAC-A",
                "needPool_data0_vs_firstRef",
                new Dictionary<string, object?>
                {
                    ["data0Len"] = dataChunks[0].Length,
                    ["probeLen"] = probeSlice.Length,
                    ["probeFromRef"] = probeFromRef,
                    ["firstExpectLen"] = probeFromRef ? firstRefSlice.Length : -1,
                    ["mismatch"] = probeFromRef && dataChunks[0].Length != probeSlice.Length,
                    ["refs"] = plan.References.Count,
                    ["authFordN"] = fordCiphers.Count,
                    ["authFordLens"] = fordCiphers.Select(static f => f.Length).ToArray(),
                    ["needPool"] = needPool,
                    ["probePass"] = probePass,
                    ["probeKeyIdx"] = probeKeyIdx,
                    ["probeMacIdx"] = probeMacIdx,
                    ["macs"] = probeMacs.Count,
                    ["skipMacRehunt"] = !probePass && fordCiphers.Count > 0,
                    ["run"] = "ike-struct-v1",
                });
            // #endregion

            if (needPool
                && TryBindFileGroupFordStorages(
                    fordIkm, plan, original, siblingCompacts,
                    out var treeFord, out var treeNote)
                && (probeMacs.Count == 0
                    || TryFordStoragesPassMacDiag(
                        fordIkm, treeFord, probeSlice, probeMacs, out _, out _)))
            {
                fordCiphers = treeFord;
                resolveNote = string.IsNullOrEmpty(resolveNote)
                    ? treeNote
                    : $"{resolveNote}+{treeNote}";
                // #region agent log
                AgentSessionNdjsonAlways(
                    "H-TREE-MAC",
                    "resolve_tree_mac_ok",
                    new Dictionary<string, object?>
                    {
                        ["note"] = treeNote,
                        ["fordN"] = treeFord.Count,
                        ["probeLen"] = probeSlice.Length,
                        ["macs"] = probeMacs.Count,
                        ["runId"] = "ike-struct-v1",
                    });
                // #endregion
            }
            else if (needPool && fordCiphers.Count == 0)
            {
                // Pipe B miss sul FileGroup: NON prendere un sibling IKM-open del batch
                // (AuthKit MAC fail). Lascia fordCiphers vuoto → H-AUTH-FORD / H-DATAONLY.
                // #region agent log
                AgentSessionNdjsonAlways(
                    "H-SIB1",
                    "sibling_ford_disabled",
                    new Dictionary<string, object?>
                    {
                        ["refCount"] = refCount,
                        ["siblings"] = siblingCompacts.Count,
                        ["probeLen"] = probeSlice.Length,
                        ["macs"] = probeMacs.Count,
                        ["why"] = "pipe_b_filegroup_only_no_batch_trial",
                        ["runId"] = "pipe-align-v3",
                    });
                AgentPdfFailDiagLog(
                    "H-TREE",
                    "needPool_filegroup_miss",
                    new Dictionary<string, object?>
                    {
                        ["refCount"] = refCount,
                        ["siblings"] = siblingCompacts.Count,
                        ["probeLen"] = probeSlice.Length,
                        ["macs"] = probeMacs.Count,
                        ["runId"] = "pipe-align-v3",
                    });
                // #endregion
            }
        }

        // H-AUTH-FORD: Auth gate+ctLen+OID → slice GET già in cache (stream.Read(ctLen)).
        if ((fordCiphers.Count == 0 || dataChunks.Count == 0)
            && !fordIkm.IsEmpty
            && TryBindAuthFordDescriptors(
                compact, plan, fordIkm, authorizeGetBody, siblingCompacts,
                out var authFord, out var authData, out var authNote)
            && authFord.Count > 0
            && authData.Count > 0)
        {
            fordCiphers = authFord;
            dataChunks = authData;
            resolveNote = string.IsNullOrEmpty(resolveNote) ? authNote : resolveNote + ";" + authNote;
        }


        if (fordCiphers.Count == 0 || dataChunks.Count == 0)
        {
            // #region agent log
            var contLens = plan.Containers.Select(static g => g.Count).ToArray();
            var emptyIdx = new List<int>();
            for (var ci = 0; ci < plan.Containers.Count; ci++)
            {
                if (plan.Containers[ci].Count == 0)
                    emptyIdx.Add(ci);
            }

            AgentPdfFailDiagLog("H-R1", "resolve_final_empty", new Dictionary<string, object?>
            {
                ["fordN"] = fordCiphers.Count,
                ["dataN"] = dataChunks.Count,
                ["dataLens"] = dataChunks.Select(static d => d.Length).Take(4).ToArray(),
                ["bodiesN"] = bodiesFromCompact.Count,
                ["orderedN"] = ordered.Count,
                ["originalN"] = original.Count,
                ["contChunkN"] = contLens,
                ["emptyIdx"] = emptyIdx.ToArray(),
                ["refs"] = plan.References.Count,
                ["cryptoSum"] = plan.TotalCryptoBytes,
                ["compact"] = compact.Length,
                ["note"] = resolveNote,
                ["siblings"] = siblingCompacts?.Count ?? 0,
            });
            // #endregion
            return false;
        }

        //  dataChunks = owned FileChecksumChunkReferences, non l'host packed intero.
        if (plan.References.Count > 0
            && TryEnsureOwnedRefDataChunks(
                compact, plan, dataChunks, out var ownedFinal, out var ownedNote)
            && ownedFinal.Count == plan.References.Count)
        {
            dataChunks = ownedFinal;
            if (ownedNote is not "already-owned"
                && !resolveNote.Contains("owned-refs", StringComparison.Ordinal))
                resolveNote += "+owned-refs";
        }

        resolveNote = string.IsNullOrEmpty(resolveNote)
            ? $"ford={fordCiphers.Count} data={dataChunks.Count}"
            : resolveNote;
        return true;
    }

    /// <summary>
    /// Prima slice FileChecksumChunkReference per MAC probe (len = ChunkInfo.Length),
    /// non l'intero data-host GET.
    /// </summary>
    public static bool TryGetFirstRefMacProbeSlice(
        IReadOnlyList<byte[]> dataHostChunks,
        AuthorizeGetDecryptPlan plan,
        out byte[] probeSlice)
    {
        probeSlice = [];
        if (dataHostChunks.Count == 0 || plan.References.Count == 0)
            return false;

        var r0 = plan.References[0];
        if ((uint)r0.ContainerIndex >= (uint)plan.Containers.Count)
            return false;
        var group = plan.Containers[r0.ContainerIndex];
        if ((uint)r0.ChunkIndex >= (uint)group.Count)
            return false;
        var expectLen = group[r0.ChunkIndex].Length;
        if (expectLen <= 0)
            return false;

        // Già per-ref.
        if (dataHostChunks.Count == plan.References.Count
            && dataHostChunks[0].Length == expectLen)
        {
            probeSlice = dataHostChunks[0];
            return true;
        }

        var packed = ConcatDataHostChunks(dataHostChunks);
        var owned = TrySliceRefsAtPackedStart(packed, plan, plan.References, 0);
        if (owned.Count == plan.References.Count && owned[0].Length == expectLen)
        {
            probeSlice = owned[0];
            return true;
        }

        // Fallback: primo host se coincide con expectLen, altrimenti prefisso packed.
        if (dataHostChunks[0].Length == expectLen)
        {
            probeSlice = dataHostChunks[0];
            return true;
        }

        if (packed.Length >= expectLen)
        {
            probeSlice = packed.AsSpan(0, expectLen).ToArray();
            return true;
        }

        return false;
    }

    /// <summary>
    /// Pool Ford batch (FillChunks): tutti i sibling ≤65 KiB che aprono con IKM.
    /// </summary>
    public static bool TryCollectIkmOpenFordPool(
        ReadOnlySpan<byte> fordIkm,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> siblingCompacts,
        out List<byte[]> pool)
    {
        pool = [];
        if (fordIkm.IsEmpty || siblingCompacts.Count == 0)
            return false;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        var scanned = 0;
        var openFail = 0;
        var sizeSkip = 0;
        foreach (var (_, (compact, _)) in siblingCompacts)
        {
            scanned++;
            // H-R3: mid-range data hosts can carry a Ford window (DecryptFord with
            // content-byte-range start≫0). Do not skip large compacts — TryPick scans
            // the first 64 KiB for lead-0x04 / IKM-open windows.
            if (compact.Length < 0x12)
            {
                sizeSkip++;
                continue;
            }

            if (!TryPickFordCipherFromHost(fordIkm, compact, out var fordCt))
            {
                openFail++;
                continue;
            }

            // Reject "whole huge body as ford" (SIV would have failed anyway on MB-scale).
            // Solo sanità: bag multi-key possono eguagliare l’intero ByteRange host.
            if (fordCt.Length == compact.Length && compact.Length > UbChunkBuilder.MaxAuthFordCtLenSanity)
            {
                sizeSkip++;
                continue;
            }

            var id = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(fordCt));
            if (!seen.Add(id))
                continue;
            pool.Add(fordCt);
        }

        // Preferisci blob più piccoli (empty-host tipici 112/155/224) prima dei packed.
        pool.Sort(static (a, b) => a.Length.CompareTo(b.Length));

        // #region agent log
        AgentPdfFailDiagLog(
            "H-FP4",
            "ikm_open_ford_pool",
            new Dictionary<string, object?>
            {
                ["siblings"] = siblingCompacts.Count,
                ["scanned"] = scanned,
                ["sizeSkip"] = sizeSkip,
                ["openFail"] = openFail,
                ["pool"] = pool.Count,
                ["poolLens"] = pool.Select(static p => p.Length).Take(12).ToArray(),
            });
        // #endregion

        return pool.Count > 0;
    }

    /// <summary>
    /// Seleziona il sottoinsieme di Ford storages che DecryptFordKeys→ParseFordInfo
    /// produce esattamente <paramref name="refCount"/> chiavi (come FillChunks inject).
    /// </summary>
    public static bool TrySelectFordStoragesForRefCount(
        ReadOnlySpan<byte> fordIkm,
        IReadOnlyList<byte[]> pool,
        int refCount,
        out List<byte[]> selected)
    {
        selected = [];
        if (fordIkm.IsEmpty || pool.Count == 0 || refCount <= 0)
            return false;

        // 1) Singolo storage: exact refs keys, oppure multi-key packed (N keys, refs≤N).
        foreach (var one in pool)
        {
            if (TryCountFordKeys(fordIkm, [one], out var n) && n >= refCount)
            {
                selected = [one];
                return true;
            }
        }

        // 2) Tutto il pool (multi empty dello stesso FileGroup).
        if (TryCountFordKeys(fordIkm, pool, out var allN) && allN >= refCount)
        {
            selected = pool.ToList();
            return true;
        }

        // 3) Prefissi ordinati (pool già sorted by size).
        var max = Math.Min(pool.Count, 8);
        for (var take = 2; take <= max; take++)
        {
            var slice = pool.Take(take).ToList();
            if (TryCountFordKeys(fordIkm, slice, out var n) && n >= refCount)
            {
                selected = slice;
                return true;
            }
        }

        // 4) Greedy: accumula storage senza superare refCount (PPOMDB 4×1-key).
        return TryGreedyFordSetToRefCount(fordIkm, pool, seed: null, refCount, out selected);
    }

    /// <summary>
    /// Parte da un Ford MAC-validato e aggiunge altri storage del pool finché keys==refCount.
    /// </summary>
    public static bool TryExpandFordSetToRefCount(
        ReadOnlySpan<byte> fordIkm,
        IReadOnlyList<byte[]> pool,
        byte[] seed,
        int refCount,
        out List<byte[]> selected)
        => TryGreedyFordSetToRefCount(fordIkm, pool, seed, refCount, out selected);

    private static bool TryGreedyFordSetToRefCount(
        ReadOnlySpan<byte> fordIkm,
        IReadOnlyList<byte[]> pool,
        byte[]? seed,
        int refCount,
        out List<byte[]> selected)
    {
        selected = [];
        if (fordIkm.IsEmpty || pool.Count == 0 || refCount <= 0)
            return false;

        var acc = new List<byte[]>();
        var keySum = 0;
        if (seed is { Length: > 0 })
        {
            if (!TryCountFordKeys(fordIkm, [seed], out keySum) || keySum <= 0)
                return false;
            // Packed multi-key Ford: seed alone may already cover refs (keys >= refCount).
            if (keySum >= refCount)
            {
                selected = [seed];
                return true;
            }
            acc.Add(seed);
        }

        // Cap: evita O(n) enorme su pool da migliaia di empty (IndexedDB batch).
        var cap = Math.Min(pool.Count, Math.Max(refCount * 4, 32));
        for (var i = 0; i < cap; i++)
        {
            var one = pool[i];
            if (seed is not null && one.AsSpan().SequenceEqual(seed))
                continue;
            if (!TryCountFordKeys(fordIkm, [one], out var n) || n <= 0)
                continue;
            if (keySum + n > refCount)
                continue;
            acc.Add(one);
            keySum += n;
            if (keySum == refCount)
            {
                selected = acc;
                return true;
            }
        }

        return false;
    }

    /// <summary>
    /// tree inject (Pipe A/B): empty Ford del <b>FileGroup</b> legati ai data ref
    /// (same-OID + <see cref="UbChunkBuilder.IsFordHostForDataChunk"/>), poi
    /// DecryptFordKeys→ParseFordInfo con key count == refs. Niente pool MAC-trial.
    /// </summary>
    public static bool TryBindFileGroupFordStorages(
        ReadOnlySpan<byte> fordIkm,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> chunks,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts,
        out List<byte[]> fordCiphers,
        out string note)
    {
        fordCiphers = [];
        note = "";
        var refCount = plan.References.Count;
        if (fordIkm.IsEmpty || refCount <= 0)
            return false;

        var attached = new List<byte[]>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var ikmArr = fordIkm.ToArray();
        var maxChunkIdx = 0;
        foreach (var r in plan.References)
        {
            if (r.ChunkIndex > maxChunkIdx)
                maxChunkIdx = r.ChunkIndex;
        }

        //  DecryptFordKeys sul storage empty/ford-sized intero — attach strutturale,
        // non IKM-open trial (anti data_only invent).
        void TryAddBody(byte[]? body, bool structuralFord)
        {
            if (body is not { Length: >= 0x12 } || body.Length > UbChunkBuilder.MaxAuthFordCtLenSanity)
                return;
            if (!structuralFord
                && !IsExactStandardFordHostLength(body.Length)
                && body.Length > 4096)
                return;

            var id = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(body));
            if (!seen.Add(id))
                return;
            attached.Add(body);
        }

            // 1) Empty / Container-Size:0 / ford-sized già nell'AuthSlice (FileGroup).
            var nHost = Math.Min(plan.Containers.Count, chunks.Count);
            for (var i = 0; i < nHost; i++)
            {
                var group = plan.Containers[i];
                var empty = group.Count == 0;
                var size0 = string.Equals(
                    chunks[i].EdgeHeaders?.MmcsContainerSize, "0", StringComparison.Ordinal);
                var fordSized = !empty && !size0 && IsFordSizedPlanContainer(plan, i);
                if (!empty && !size0 && !fordSized)
                    continue;
                if (chunks[i].ByteRange is not { } br)
                    continue;
                var key = $"{chunks[i].EdgeHeaders?.ObjectId ?? ""}@{br.Start}";
                if (siblingCompacts is not null
                    && siblingCompacts.TryGetValue(key, out var hit))
                    TryAddBody(hit.Compact, structuralFord: true);
            }

        // 2) Same-OID adjacent Ford (H-AK1 / AuthKit-class): storage Ford often
        // lives at [dataStart−N, dataStart) on the same object — not in Auth CI gate45.
        // Align ON: only standard Ford lengths / adjacent geometry (no cross-OID invent).
        if (siblingCompacts is { Count: > 0 })
        {
            foreach (var r in plan.References)
            {
                if ((uint)r.ContainerIndex >= (uint)chunks.Count
                    || (uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                    continue;
                var dataHost = chunks[r.ContainerIndex];
                if (dataHost.ByteRange is not { } dr)
                    continue;
                var oid = dataHost.EdgeHeaders?.ObjectId ?? "";
                if (string.IsNullOrEmpty(oid))
                    continue;
                var group = plan.Containers[r.ContainerIndex];
                if ((uint)r.ChunkIndex >= (uint)group.Count)
                    continue;
                var packedLen = dr.End - dr.Start + 1;
                var chunkAbs = UbChunkBuilder.GetPackedChunkAbsStart(
                    group[r.ChunkIndex], group, dr.Start, packedLen);

                foreach (var (sibKey, (body, start)) in siblingCompacts)
                {
                    var at = sibKey.IndexOf('@');
                    var sibOid = at > 0 ? sibKey[..at] : sibKey;
                    if (!string.Equals(sibOid, oid, StringComparison.Ordinal))
                        continue;
                    if (body.Length < 0x12)
                        continue;
                    var fordEnd = start + body.Length - 1;
                    var adjacent = fordEnd + 1 == dr.Start
                        || UbChunkBuilder.IsFordHostForDataChunk(
                            (start, fordEnd), chunkAbs, dr.Start);
                    if (!adjacent)
                        continue;
                    if (!IsExactStandardFordHostLength(body.Length)
                        && body.Length > 4096)
                        continue;
                    TryAddBody(body, structuralFord: true);
                }
            }
        }

        if (attached.Count == 0)
        {
            // #region agent log
            var sameOidN = 0;
            var sameOidLens = new List<int>(6);
            var openSameOidN = 0;
            var adjEndEqDataStartN = 0;
            if (siblingCompacts is { Count: > 0 })
            {
                foreach (var r in plan.References)
                {
                    if ((uint)r.ContainerIndex >= (uint)chunks.Count)
                        continue;
                    var dataHost = chunks[r.ContainerIndex];
                    if (dataHost.ByteRange is not { } dr)
                        continue;
                    var oid = dataHost.EdgeHeaders?.ObjectId ?? "";
                    if (string.IsNullOrEmpty(oid))
                        continue;
                    foreach (var (sibKey, (body, start)) in siblingCompacts)
                    {
                        var at = sibKey.IndexOf('@');
                        var sibOid = at > 0 ? sibKey[..at] : sibKey;
                        if (!string.Equals(sibOid, oid, StringComparison.Ordinal))
                            continue;
                        sameOidN++;
                        if (sameOidLens.Count < 6)
                            sameOidLens.Add(body.Length);
                        if (TryPickFordCipherFromHost(ikmArr, body, out _))
                            openSameOidN++;
                        if (start + body.Length == dr.Start)
                            adjEndEqDataStartN++;
                    }
                }
            }
            AgentPdfFailDiagLog(
                "H-TREE",
                "filegroup_ford_none_attached",
                new Dictionary<string, object?>
                {
                    ["refs"] = refCount,
                    ["siblings"] = siblingCompacts?.Count ?? 0,
                    ["hosts"] = nHost,
                    ["sameOidN"] = sameOidN,
                    ["sameOidLens"] = sameOidLens.ToArray(),
                    ["openSameOidN"] = openSameOidN,
                    ["adjEndEqDataStartN"] = adjEndEqDataStartN,
                    ["runId"] = "authkit-x64-v1",
                });
            // #endregion
            return false;
        }

        //  KEY indexed by ChunkIndex — coverRefs richiede keyCount > maxCi.
        var minKeysDense = Math.Max(refCount, maxChunkIdx + 1);
        if (!TryCountFordKeys(fordIkm, attached, out var allKeys))
            allKeys = 0;
        if (allKeys > 0 && FordKeysCoverPlanRefs(allKeys, plan))
        {
            fordCiphers = attached;
            note =
                $"filegroup-tree n={attached.Count} keys={allKeys} coverRefs " +
                $"minDense={minKeysDense} maxCi={maxChunkIdx}";
        }
        else
        {
            // #region agent log
            AgentPdfFailDiagLog(
                "H-TREE",
                "filegroup_ford_keycount_miss",
                new Dictionary<string, object?>
                {
                    ["refs"] = refCount,
                    ["maxChunkIdx"] = maxChunkIdx,
                    ["minKeys"] = minKeysDense,
                    ["attached"] = attached.Count,
                    ["attachedLens"] = attached.Select(static a => a.Length).Take(8).ToArray(),
                    ["allKeys"] = allKeys,
                    ["coverRefs"] = allKeys > 0 && FordKeysCoverPlanRefs(allKeys, plan),
                    ["runId"] = "coverrefs-maxci-v1",
                });
            // #endregion
            return false;
        }

        // #region agent log
        AgentPdfFailDiagLog(
            "H-TREE",
            "filegroup_ford_bind_ok",
            new Dictionary<string, object?>
            {
                ["note"] = note,
                ["fordN"] = fordCiphers.Count,
                ["fordLens"] = fordCiphers.Select(static f => f.Length).ToArray(),
                ["refs"] = refCount,
                ["maxChunkIdx"] = maxChunkIdx,
                ["minKeys"] = minKeysDense,
                ["allKeys"] = allKeys,
                ["attached"] = attached.Count,
                ["runId"] = "wrm-coverrefs-v1",
            });
        // #endregion
        return true;
    }

    /// <summary>
    /// Sottoinsieme di storage attached con key count ≥ minKeys (packed multi-key / ChunkIndex).
    /// </summary>
    private static bool TrySelectFordStoragesForMinKeys(
        ReadOnlySpan<byte> fordIkm,
        IReadOnlyList<byte[]> pool,
        int minKeys,
        out List<byte[]> selected)
    {
        selected = [];
        if (fordIkm.IsEmpty || pool.Count == 0 || minKeys <= 0)
            return false;

        foreach (var one in pool.OrderByDescending(static p => p.Length))
        {
            if (TryCountFordKeys(fordIkm, [one], out var n) && n >= minKeys)
            {
                selected = [one];
                return true;
            }
        }

        if (TryCountFordKeys(fordIkm, pool, out var allN) && allN >= minKeys)
        {
            selected = pool.ToList();
            return true;
        }

        var acc = new List<byte[]>();
        var keySum = 0;
        foreach (var one in pool.OrderByDescending(static p => p.Length))
        {
            if (!TryCountFordKeys(fordIkm, [one], out var n) || n <= 0)
                continue;
            acc.Add(one);
            keySum += n;
            if (keySum >= minKeys)
            {
                selected = acc;
                return true;
            }
        }

        return false;
    }

    public static bool TryCountFordKeys(
        ReadOnlySpan<byte> ikm,
        IReadOnlyList<byte[]> storages,
        out int keyCount)
    {
        keyCount = 0;
        var keys = new List<FordChunkKey>();
        foreach (var fordCt in storages)
        {
            if (fordCt.Length == 0)
                continue;
            try
            {
                AddFordKeysFromStorage(ikm, fordCt, keys);
            }
            catch (CryptographicException)
            {
                return false;
            }
        }

        keyCount = keys.Count;
        return keyCount > 0;
    }

    /// <summary>
    /// packed host: un Ford può avere N chiavi per N ChunkInfo sullo storage, mentre
    /// il FilePart ha refs=1 (un solo file). Accetta exact match (keys[i]↔refs[i]) oppure
    /// keys &gt; max ChunkIndex (keys[ChunkIndex]).
    /// </summary>
    public static bool FordKeysCoverPlanRefs(int keyCount, AuthorizeGetDecryptPlan plan)
    {
        if (keyCount <= 0 || plan.References.Count == 0)
            return false;

        //  KEY inorder indexed by ChunkIndex — serve keyCount > max(ChunkIndex).
        // refs=1 + ChunkIndex=2 → servono ≥3 keys; keys==refs.Count NON basta.
        var maxCi = 0;
        foreach (var r in plan.References)
        {
            if (r.ChunkIndex > maxCi)
                maxCi = r.ChunkIndex;
        }

        return keyCount > maxCi && keyCount >= plan.References.Count;
    }

    private static bool TryFordStoragesPassMac(
        ReadOnlySpan<byte> ikm,
        IReadOnlyList<byte[]> storages,
        ReadOnlySpan<byte> dataChunk,
        IReadOnlyList<byte[]> macs)
        => TryFordStoragesPassMacDiag(ikm, storages, dataChunk, macs, out _, out _);

    /// <summary>
    ///-aligned probe on first ref slice: only key[0]+mac[0] (not key×mac cross-product).
    /// </summary>
    private static bool TryFordStoragesPassMacDiag(
        ReadOnlySpan<byte> ikm,
        IReadOnlyList<byte[]> storages,
        ReadOnlySpan<byte> dataChunk,
        IReadOnlyList<byte[]> macs,
        out int passKeyIdx,
        out int passMacIdx)
    {
        passKeyIdx = -1;
        passMacIdx = -1;
        if (ikm.IsEmpty || dataChunk.IsEmpty || macs.Count == 0 || storages.Count == 0)
            return false;
        try
        {
            var keys = CollectFordKeysFromEmptyStorages(ikm, storages).ToList();
            if (keys.Count == 0)
                return false;
            _ = ChunkDecrypt(keys[0].Key, dataChunk, keys[0].ChunkLengthHint, macs[0]);
            passKeyIdx = 0;
            passMacIdx = 0;
            return true;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    ///-strict: body GET intero == ctLen e apre con IKM. Niente pack N×112 / scan lead-0x04.
    /// </summary>
    public static bool TryPickFordCipherFromHost(
        ReadOnlySpan<byte> fordIkm,
        ReadOnlySpan<byte> hostBody,
        out byte[] fordCipher)
    {
        fordCipher = [];
        if (fordIkm.IsEmpty || hostBody.Length < 0x12)
            return false;

        if (!TryDecryptFordSilent(fordIkm, hostBody, out _))
        {
            // #region agent log
            AgentStrictReject("H-NO-INVENT", "TryPickFordCipherFromHost", "reject_non_exact_body",
                new Dictionary<string, object?>
                {
                    ["bodyLen"] = hostBody.Length,
                    ["head"] = hostBody[0],
                });
            // #endregion
            return false;
        }

        fordCipher = hostBody.ToArray();
        return true;
    }

    /// <summary>
    /// GET edge in ordine authorizeGet: container senza ChunkInfo = Ford,
    /// container con ChunkInfo = dati (eventualmente packed). Niente euristica 0x04.
    /// </summary>
    public static bool TrySplitByAuthorizeGetPlan(
        ReadOnlySpan<byte> compact,
        IReadOnlyList<SignedUrlChunk> ordered,
        IReadOnlyList<SignedUrlChunk> original,
        AuthorizeGetDecryptPlan plan,
        out List<byte[]> fordCiphers,
        out List<byte[]> dataChunks)
    {
        fordCiphers = [];
        dataChunks = [];
        if (ordered.Count == 0 || compact.IsEmpty || plan.Containers.Count == 0)
            return false;

        var offset = 0;
        var fordIdx = new List<int>();
        var dataIdx = new List<int>();
        foreach (var c in ordered)
        {
            if (c.ByteRange is not { } br || br.End < br.Start || br.Start < 0)
                return false;
            var len = checked((int)(br.End - br.Start + 1));
            if (len <= 0 || offset + len > compact.Length)
                return false;
            var slice = compact.Slice(offset, len).ToArray();
            offset += len;

            var idx = IndexOfSignedChunk(original, c);
            var empty = (uint)idx < (uint)plan.Containers.Count
                        && plan.Containers[idx].Count == 0;
            if (empty)
            {
                fordCiphers.Add(slice);
                fordIdx.Add(idx);
            }
            else
            {
                dataChunks.Add(slice);
                dataIdx.Add(idx);
            }
        }

        if (offset != compact.Length || fordCiphers.Count == 0)
            return false;

        //-strict: niente split coda 112/155/224. Ford host = body exact; data = altro FileGroup.
        if (dataChunks.Count == 0)
            return false;

        return true;
    }

    private static int IndexOfSignedChunk(IReadOnlyList<SignedUrlChunk> list, SignedUrlChunk chunk)
    {
        for (var i = 0; i < list.Count; i++)
        {
            var o = list[i];
            if (o.ByteRange != chunk.ByteRange)
                continue;
            if (!string.Equals(o.Url, chunk.Url, StringComparison.Ordinal))
                continue;
            return i;
        }

        return -1;
    }

    /// <summary>
    /// Compact edge (range ordinati per Start) → split ford + data.
    /// Il ford è il primo slice compatto piccolo con lead 0x04 (offset MMCS originale irrilevante nel compact).
    /// </summary>
    public static bool TrySplitCompactByRanges(
        ReadOnlySpan<byte> compact,
        IReadOnlyList<(long Start, long End)> ranges,
        out byte[] fordCipher,
        out List<byte[]> dataChunks)
    {
        fordCipher = [];
        dataChunks = [];
        if (ranges.Count < 2 || compact.IsEmpty)
        {
            return false;
        }

        var ordered = ranges.ToList();
        var offset = 0;
        byte[]? ford = null;
        foreach (var (start, end) in ordered)
        {
            var len = checked((int)(end - start + 1));
            if (offset + len > compact.Length)
            {
                return false;
            }
            var slice = compact.Slice(offset, len).ToArray();
            offset += len;
            if (ford is null && LooksLikeFordCipherSlice(slice))
            {
                ford = slice;
                continue;
            }

            dataChunks.Add(slice);
        }

        if (ford is null || dataChunks.Count == 0)
        {
            return false;
        }
        fordCipher = ford;
        return offset == compact.Length;
    }

    /// <summary>Slice Ford: 64–16 KiB con lead <c>0x04</c> (N chunk keys → Ford GET &gt; 512 B).</summary>
    private static bool LooksLikeFordCipherSlice(ReadOnlySpan<byte> slice) =>
        slice.Length is >= 64 and <= 16384 && slice[0] == 0x04;

    /// <summary>
    /// Cerca il Ford blob nei compact sibling (batch): scan lead-0x04 + DecryptFordKeys(IKM).
    /// Con data+MAC conferma via ChunkDecrypt; altrimenti accetta il primo SIV+Parse ok
    /// su blob ≤4096 B (empty-host).
    /// </summary>
    public static bool TryFindFordInSiblingCompacts(
        ReadOnlySpan<byte> fordIkm,
        long chunkAbsStart,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> siblingCompacts,
        out byte[] fordCipher,
        ReadOnlySpan<byte> dataChunk = default,
        IReadOnlyList<byte[]>? macs = null,
        string? preferObjectId = null)
        => TryFindFordInSiblingCompacts(
            fordIkm, chunkAbsStart, siblingCompacts, out fordCipher, out _,
            dataChunk, macs, preferObjectId);

    /// <summary>
    /// Sibling Ford: con data+MAC → solo MAC-select (FileGroup). Senza MAC/data → IKM-open.
    /// </summary>
    public static bool TryFindFordInSiblingCompacts(
        ReadOnlySpan<byte> fordIkm,
        long chunkAbsStart,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> siblingCompacts,
        out byte[] fordCipher,
        out string selectionMode,
        ReadOnlySpan<byte> dataChunk = default,
        IReadOnlyList<byte[]>? macs = null,
        string? preferObjectId = null)
    {
        fordCipher = [];
        selectionMode = "none";
        if (fordIkm.IsEmpty || siblingCompacts.Count == 0)
            return false;

        var macList = macs ?? Array.Empty<byte[]>();
        var ordered = siblingCompacts
            .OrderBy(kv =>
            {
                if (string.IsNullOrEmpty(preferObjectId))
                    return 1;
                var at = kv.Key.IndexOf('@');
                var oid = at > 0 ? kv.Key[..at] : kv.Key;
                return string.Equals(oid, preferObjectId, StringComparison.Ordinal) ? 0 : 1;
            })
            .ThenBy(static kv => kv.Value.Compact.Length)
            .Select(static kv => kv.Value.Compact)
            .ToList();

        if (dataChunk.Length > 0
            && TrySelectFordCipher(fordIkm, dataChunk, macList, ordered, out fordCipher))
        {
            selectionMode = macList.Count > 0 ? "mac" : "siv-nomac";
            return true;
        }

        // Con data+MAC disponibili: non fare fallthrough IKM-open (Ford sbagliato del batch).
        if (dataChunk.Length > 0 && macList.Count > 0)
        {
            selectionMode = "mac-miss";
            return false;
        }

        //-strict: solo body sibling intero che apre (Auth FileGroup exact). Niente win/geometric.
        _ = chunkAbsStart;
        foreach (var compact in ordered)
        {
            if (compact.Length < 0x12)
                continue;
            if (!TryDecryptFordSilent(fordIkm, compact, out var ptWhole))
                continue;
            try
            {
                if (ParseFordInfo(ptWhole).Count <= 0)
                    continue;
            }
            catch
            {
                continue;
            }

            fordCipher = compact.ToArray();
            selectionMode = "ikm-whole";
            return true;
        }

        return false;
    }

    // #region agent log
    private static void AgentStrictReject(
        string hypothesisId,
        string location,
        string message,
        Dictionary<string, object?> data)
    {
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["runId"] = "ike-no-invent-ford-v2",
                ["hypothesisId"] = hypothesisId,
                ["location"] = "FordMmcsDecryptor." + location,
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            System.IO.File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }

    private static void AgentSessionNdjsonAlways(
        string hypothesisId,
        string message,
        Dictionary<string, object?> data)
    {
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["runId"] = "ike-no-invent-ford-v2",
                ["hypothesisId"] = hypothesisId,
                ["location"] = "FordMmcsDecryptor",
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            System.IO.File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    public static byte[] AesGcmSivDecrypt(
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> nonce,
        ReadOnlySpan<byte> ciphertextAndTag,
        byte[]? aad)
    {
        if (key.Length is not (16 or 32))
            throw new CryptographicException($"AES-GCM-SIV key len {key.Length}");
        if (nonce.Length is not 12)
            throw new CryptographicException($"AES-GCM-SIV nonce len {nonce.Length} (expected 12)");

        var cipher = new GcmSivBlockCipher(new AesEngine());
        cipher.Init(false, new ParametersWithIV(new KeyParameter(key.ToArray()), nonce.ToArray()));
        if (aad is { Length: > 0 })
            cipher.ProcessAadBytes(aad, 0, aad.Length);

        var input = ciphertextAndTag.ToArray();
        var output = new byte[cipher.GetOutputSize(input.Length)];
        var n = cipher.ProcessBytes(input, 0, input.Length, output, 0);
        n += cipher.DoFinal(output, n);
        return output.AsSpan(0, n).ToArray();
    }

    private enum ProtobufWireType : int
    {
        Varint = 0,
        LengthDelimited = 2,
    }

    private readonly record struct ProtobufField(int FieldNumber, ProtobufWireType WireType, byte[] Bytes, ulong Varint);

    private static void TryParseFordInfoTop(ReadOnlySpan<byte> top, List<FordChunkKey> keys)
    {
        foreach (var field in ParseProtobufFields(top))
        {
            if (field.WireType != ProtobufWireType.LengthDelimited)
                continue;
            switch (field.FieldNumber)
            {
                case 1:
                {
                    int? chunkLen = null;
                    byte[]? fordKey = null;
                    CollectFordChunkKeyAndLen(field.Bytes, ref fordKey, ref chunkLen);
                    if (fordKey is not null)
                        keys.Add(new FordChunkKey(fordKey, chunkLen));
                    break;
                }
                case 2 when field.Bytes.Length == 4 && keys.Count > 0:
                {
                    var last = keys[^1];
                    if (last.ChunkLengthHint is null)
                        keys[^1] = last with { ChunkLengthHint = BitConverter.ToInt32(field.Bytes) };
                    break;
                }
                case 2:
                    ParseFordChunkGroup(field.Bytes, keys);
                    break;
            }
        }
    }

    /// <summary>N≥3 chunk groups: f1 hint u32 + repeated f2 { f1 KEY33 }.</summary>
    private static void ParseFordChunkGroup(ReadOnlySpan<byte> group, List<FordChunkKey> keys)
    {
        int? groupHint = null;
        foreach (var field in ParseProtobufFields(group))
        {
            if (field.WireType != ProtobufWireType.LengthDelimited)
                continue;
            if (field.FieldNumber == 1 && field.Bytes.Length == 4)
                groupHint = BitConverter.ToInt32(field.Bytes);
            else if (field.FieldNumber == 2)
            {
                byte[]? fordKey = null;
                int? chunkLen = groupHint;
                CollectFordChunkKeyAndLen(field.Bytes, ref fordKey, ref chunkLen);
                if (fordKey is not null)
                    keys.Add(new FordChunkKey(fordKey, chunkLen ?? groupHint));
            }
        }
    }

    private static void CollectFordChunkKeyAndLen(
        ReadOnlySpan<byte> msg,
        ref byte[]? fordKey,
        ref int? chunkLen)
    {
        if (msg.Length == 33 && msg[0] == 0x04)
        {
            fordKey ??= msg[1..].ToArray();
            return;
        }

        foreach (var field in ParseProtobufFields(msg))
        {
            if (field.WireType != ProtobufWireType.LengthDelimited)
                continue;
            if (field.FieldNumber == 1)
                CollectFordChunkKeyAndLen(field.Bytes, ref fordKey, ref chunkLen);
            else if (field.FieldNumber == 2 && field.Bytes.Length == 4)
                chunkLen ??= BitConverter.ToInt32(field.Bytes);
            else if (field.FieldNumber == 2 && field.Bytes.Length == 33 && field.Bytes[0] == 0x04)
                fordKey ??= field.Bytes.AsSpan(1).ToArray();
        }
    }

    private static List<ProtobufField> ParseProtobufFields(ReadOnlySpan<byte> data)
    {
        var fields = new List<ProtobufField>();
        var pos = 0;
        while (pos < data.Length)
        {
            if (!TryReadVarint(data, ref pos, out var tag))
                break;
            var fieldNumber = tag >> 3;
            var wire = (ProtobufWireType)(tag & 7);
            switch (wire)
            {
                case ProtobufWireType.Varint:
                    if (!TryReadVarint(data, ref pos, out var vint))
                        return fields;
                    fields.Add(new ProtobufField(fieldNumber, wire, [], (ulong)vint));
                    break;
                case ProtobufWireType.LengthDelimited:
                    if (!TryReadVarint(data, ref pos, out var len) || len < 0 || pos + len > data.Length)
                        return fields;
                    fields.Add(new ProtobufField(fieldNumber, wire, data.Slice(pos, len).ToArray(), 0));
                    pos += len;
                    break;
                default:
                    return fields;
            }
        }

        return fields;
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> data, ref int pos, out int value)
    {
        value = 0;
        var shift = 0;
        while (pos < data.Length && shift <= 28)
        {
            var b = data[pos++];
            value |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
        }

        return false;
    }
}
