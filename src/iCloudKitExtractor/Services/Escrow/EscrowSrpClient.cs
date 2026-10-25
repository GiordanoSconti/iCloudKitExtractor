using System.Buffers.Binary;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// SRP-6a EscrowProxy (SHA-256, N=2048, g=2).
/// <list type="bullet">
/// <item><c>inner = SHA256(dsid ‖ ":" ‖ dsid)</c></item>
/// <item><c>x = SHA256(salt_64 ‖ inner)</c></item>
/// <item><c>k = H(PAD(N) ‖ PAD(g))</c>; <c>u = H(PAD(A) ‖ PAD(B))</c></item>
/// <item><c>S = (B − k·g^x)^(a + u·x) mod N</c>; <c>K = H(S_be)</c></item>
/// <item><c>M1 = H( (H(N)⊕H(g)) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K )</c></item>
/// </list>
/// </summary>
public sealed class EscrowSrpClient
{
    // RFC 5054 2048-bit group (G_2048).
    public static readonly BigInteger Modulus = BigInteger.Parse(
        "00" +
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
        "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50" +
        "E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B8" +
        "55F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773B" +
        "CA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748" +
        "544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6" +
        "AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB6" +
        "94B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
        System.Globalization.NumberStyles.HexNumber);

    private static BigInteger N => Modulus;
    private static readonly BigInteger G = 2;

    /// <summary>
    /// PBKDF2 per wrap AES KeyBagKey (HITCON p.30) — non usato nel calcolo di x SRP.
    /// </summary>
    public const int KeybagWrapPbkdf2Iterations = 10_000;

    private const int PadLength = 256;
    private byte[] _identityBytes;
    private readonly BigInteger _a;
    private readonly BigInteger _A;
    private readonly BigInteger _k;
    private byte[] _padA = [];
    private byte[] _K = [];
    private byte[] _M1 = [];
    private byte[] _M2 = [];

    public EscrowSrpClient(string identity)
    {
        _identityBytes = Encoding.UTF8.GetBytes(identity);
        _a = RandomBigInt(PadLength);
        _A = BigInteger.ModPow(G, _a, N);
        // k = H(PAD(N) ‖ PAD(g))
        _k = HashToBigInt(Concat(PadBigInt(N), PadBigInt(G)));
        _padA = PadBigInt(_A);
    }

    public byte[] PublicA => _padA;
    public byte[] M1 => _M1;
    public byte[] SessionKey => _K;

    /// <summary>
    /// Completa SRP dopo <c>srp_init</c>.
    /// <c>x = SHA256(salt ‖ SHA256(I ‖ ":" ‖ P))</c> con PAD su A/B/u/M1.
    /// PCS  <c>I=P=dsid</c>, <c>K=H(S_minimal)</c>.
    /// iCDP/Octagon (Laky-64/appleservices): <c>I=dsid</c>, <c>P=passcode</c>,
    /// <c>K=H(PAD(S))</c> — senza PAD su S il M1 viene rifiutato (-6015).
    /// </summary>
    /// <param name="password">Secret P (dsid per PCS; passcode dispositivo per iCDP).</param>
    /// <param name="identityOverride"><c>dsid</c> da srp_init (identità I).</param>
    /// <param name="padSessionKey">true → <c>K=H(PAD(S))</c> (iCDP); false → minimal (PCS).</param>
    public void Complete(
        string password,
        byte[] salt,
        byte[] serverB,
        string? identityOverride = null,
        bool padSessionKey = false)
    {
        if (!string.IsNullOrWhiteSpace(identityOverride))
            _identityBytes = Encoding.UTF8.GetBytes(identityOverride.Trim());

        var passwordBytes = Encoding.UTF8.GetBytes(NormalizeIcsc(password));
        if (!IsValidServerB(serverB))
            throw new InvalidOperationException("Chiave pubblica server escrow non valida (B).");

        var B = BytesToBigInt(serverB);
        var padA = _padA;
        var padB = PadBigInt(B);

        // u = H(PAD(A) ‖ PAD(B))
        var u = HashToBigInt(Concat(padA, padB));
        if (u == BigInteger.Zero)
            throw new InvalidOperationException("Parametro u SRP nullo.");

        // inner = SHA256(I || ":" || P); x = SHA256(salt_64 || inner)
        var inner = SHA256.HashData(Concat(_identityBytes, [0x3A], passwordBytes));
        var x = HashToBigInt(Concat(salt, inner));

        // S = (B − k·g^x)^(a + u·x) mod N
        var kgx = _k * BigInteger.ModPow(G, x, N) % N;
        var baseS = (B - kgx + N) % N;
        var S = BigInteger.ModPow(baseS, _a + u * x, N);
        // appleservices computeEscrowM: K = H(pad(S)); PCS  H(minimal(S)).
        _K = SHA256.HashData(padSessionKey ? PadBigInt(S) : MinimalBytes(S));

        // M1 = H( (H(N)⊕H(g)) ‖ H(I) ‖ salt ‖ A ‖ B ‖ K )
        _M1 = ComputeM1(padA, padB, _K, _identityBytes, salt);
        _M2 = SHA256.HashData(Concat(padA, _M1, _K));
    }

    /// <summary>
    /// HITCON p.30: hash iCSC/passcode per AES-wrap del KeyBagKey (post-recover).
    /// </summary>
    public static byte[] DeriveKeybagWrapKey(string secret, byte[] salt) =>
        Rfc2898DeriveBytes.Pbkdf2(
            SHA256.HashData(Encoding.UTF8.GetBytes(NormalizeIcsc(secret))),
            salt,
            KeybagWrapPbkdf2Iterations,
            HashAlgorithmName.SHA256,
            32);

    public byte[] GenerateM2() =>
        _M2.Length > 0 ? _M2 : SHA256.HashData(Concat(_padA, _M1, _K));

    public bool VerifyServerM2(byte[] serverM2)
    {
        if (_M1.Length == 0 || serverM2.Length < 32)
            return false;
        var expected = GenerateM2();
        var actual = serverM2.Length == 32 ? serverM2 : ExtractM2Proof(serverM2);
        return actual is not null
               && CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    public static byte[]? ExtractM2Proof(byte[] m2Section)
    {
        if (m2Section.Length >= 40
            && BinaryPrimitives.ReadUInt32BigEndian(m2Section.AsSpan(4, 4)) == 32)
            return m2Section[8..40];
        return m2Section.Length >= 32 ? m2Section[^32..] : null;
    }

    public static bool IsValidServerB(byte[] serverB)
    {
        if (serverB.Length is < 1 or > PadLength)
            return false;
        var B = BytesToBigInt(serverB);
        return B > BigInteger.Zero && B % N != BigInteger.Zero;
    }

    /// <summary>
    /// Belenko: <c>M = H(H(N)⊕H(g), H(ID), SALT, A, B, K)</c> — salt/A/B/K non pre-hashati.
    /// </summary>
    private static byte[] ComputeM1(
        byte[] padA, byte[] padB, byte[] key, byte[] username, byte[] salt)
    {
        var hashN = SHA256.HashData(PadBigInt(N));
        var hashG = SHA256.HashData(PadBigInt(G));
        var xorNg = new byte[hashN.Length];
        for (var i = 0; i < xorNg.Length; i++)
            xorNg[i] = (byte)(hashN[i] ^ hashG[i]);

        return SHA256.HashData(Concat(
            xorNg,
            SHA256.HashData(username),
            salt,
            padA,
            padB,
            key));
    }

    /// <summary>
    /// Decrypt recover ciphertext. Prefer AesSiv type=3 (<see cref="SessionKey"/>),
    /// then legacy AES-CBC scan (pre-AesSiv / InflatableDonkey).
    /// </summary>
    public byte[]? TryDecryptEscrowPayload(byte[] respBlobOrPayload)
        => TryDecryptEscrowPayload(respBlobOrPayload, out _);

    public byte[]? TryDecryptEscrowPayload(byte[] respBlobOrPayload, out string? method)
    {
        method = null;
        if (_K.Length == 0 || respBlobOrPayload.Length < 32)
            return null;

        // MUT A: AesSiv SetKey type=3, key = SHA256(bn2bin(S)) = SessionKey.
        if (EscrowAesSiv.TryDecryptCandidates(_K, respBlobOrPayload, out var sivPt, out var sivMethod)
            && sivPt is { Length: > 0 })
        {
            method = sivMethod;
            return sivPt;
        }

        foreach (var candidate in EnumerateDecryptCandidates(respBlobOrPayload))
        {
            try
            {
                var iv = candidate[..16];
                var ct = candidate[16..];
                if (ct.Length == 0 || ct.Length % 16 != 0)
                    continue;
                using var aes = Aes.Create();
                aes.Key = _K.Length == 16 ? _K : SHA256.HashData(_K)[..16];
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                var plain = aes.CreateDecryptor().TransformFinalBlock(ct, 0, ct.Length);
                if (plain.Length > 0)
                {
                    method = "AES-CBC(SHA256(K)[:16])/legacy";
                    return plain;
                }
            }
            catch
            {
                // next
            }

            try
            {
                var iv = candidate[..16];
                var ct = candidate[16..];
                if (ct.Length == 0 || ct.Length % 16 != 0)
                    continue;
                using var aes = Aes.Create();
                aes.Key = _K;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                method = "AES-CBC(K_SRP)/legacy";
                return aes.CreateDecryptor().TransformFinalBlock(ct, 0, ct.Length);
            }
            catch
            {
                // next
            }
        }

        return null;
    }

    public static string NormalizeIcsc(string icsc) => icsc.Trim();

    private static IEnumerable<byte[]> EnumerateDecryptCandidates(byte[] blob)
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

    private static BigInteger RandomBigInt(int bytes)
    {
        var buffer = RandomNumberGenerator.GetBytes(bytes);
        buffer[0] &= 0x7F;
        return BytesToBigInt(buffer);
    }

    private static BigInteger HashToBigInt(byte[] data) =>
        new(SHA256.HashData(data), isUnsigned: true, isBigEndian: true);

    private static byte[] MinimalBytes(BigInteger value) =>
        value.ToByteArray(isUnsigned: true, isBigEndian: true);

    private static byte[] PadBigInt(BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length >= PadLength)
            return bytes[^PadLength..];
        var padded = new byte[PadLength];
        Buffer.BlockCopy(bytes, 0, padded, PadLength - bytes.Length, bytes.Length);
        return padded;
    }

    private static BigInteger BytesToBigInt(byte[] bytes) =>
        new(bytes, isUnsigned: true, isBigEndian: true);

    private static byte[] Concat(params byte[][] parts)
    {
        var len = parts.Sum(static p => p.Length);
        var result = new byte[len];
        var o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, result, o, p.Length);
            o += p.Length;
        }

        return result;
    }
}

/// <summary>
/// KeyVault / SecureBackup binary messages (Sank6 <c>unpack_message</c> / <c>KeyVaultMessage</c>).
/// Layout: <c>u32be total | header | (n+1) BE offsets | body</c> where each section is
/// <c>u32be size || data</c> (sections may be zero-padded to a fixed slot size).
/// Not TLV: values like <c>0x14</c>/<c>0x58</c> are body offsets, and salt is exactly 64 B
/// (the last 4 bytes are salt, not a "tagB").
/// </summary>
public static class EscrowSecureBackupBlob
{
    /// <summary>
    /// <c>srp_init</c> respBlob: header_len=24, 3 sections = record_id | salt(64) | B(256).
    /// iCDP/clubType 1: <c>record_id</c> è spesso binario 8 B (NON ASCII) — non passare da
    /// <see cref="Encoding.ASCII"/> (byte ≥0x80 → '?').
    /// </summary>
    public static bool TryParseSrpInitResponse(
        byte[] respBlob,
        out byte[] sessionId,
        out byte[] recordId,
        out byte[] salt,
        out byte[] serverB)
    {
        sessionId = [];
        recordId = [];
        salt = [];
        serverB = [];

        if (!TryUnpack(respBlob, headerLen: 24, sectionCount: 3, out var header, out var sections))
            return false;

        var msg = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(0, 4));
        if (msg != 0xa4 || header.Length < 24)
            return false;

        sessionId = header[8..24];
        recordId = sections[0];
        salt = sections[1];
        serverB = sections[2];

        return sessionId.Length == 16
            && recordId.Length > 0
            && salt.Length == 64
            && serverB.Length == 256
            && EscrowSrpClient.IsValidServerB(serverB);
    }

    /// <summary>Hex se non stampabile; altrimenti ASCII (PCS record_id testuale).</summary>
    public static string FormatRecordId(byte[] recordId)
    {
        if (recordId.Length == 0)
            return "";
        var printable = true;
        foreach (var b in recordId)
        {
            if (b is < 0x20 or > 0x7E)
            {
                printable = false;
                break;
            }
        }

        return printable
            ? Encoding.ASCII.GetString(recordId)
            : Convert.ToHexString(recordId);
    }

    /// <summary>
    /// recover reqBlob: header msg=0xa5, version (di solito 0), 2 sections =
    /// record_id | M1(32).
    /// PCS  record_id in slot fisso 20 (<paramref name="padRecordIdTo20"/>).
    /// iCDP (appleservices <c>buildRecoverBlob</c>): clubID grezzo senza pad.
    /// </summary>
    public static byte[] BuildRecoverBlob(
        byte[] sessionId,
        byte[] recordId,
        byte[] m1,
        uint version = 0,
        bool padRecordIdTo20 = true)
    {
        if (sessionId.Length != 16)
            throw new ArgumentException("sessionId deve essere 16 byte.", nameof(sessionId));
        if (recordId.Length is < 1 or > 16)
            throw new ArgumentException("recordId 1..16 byte.", nameof(recordId));
        if (m1.Length != 32)
            throw new ArgumentException("M1 deve essere 32 byte SHA-256.", nameof(m1));

        var header = new byte[24];
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(0, 4), 0xa5);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4, 4), version);
        Buffer.BlockCopy(sessionId, 0, header, 8, 16);

        var idSection = padRecordIdTo20
            ? PadSection(recordId, slotSize: 20)
            : PrefixSize(recordId);

        return Pack(header, [idSection, PrefixSize(m1)]);
    }

    /// <summary>Compat: record_id testuale PCS → byte ASCII, slot 20.</summary>
    public static byte[] BuildRecoverBlob(byte[] sessionId, string correlationId, byte[] m1) =>
        BuildRecoverBlob(
            sessionId, Encoding.ASCII.GetBytes(correlationId), m1, version: 0, padRecordIdTo20: true);

    /// <summary>
    /// recover respBlob: KeyVault sections (Sank6: M2, then ciphertext pieces).
    /// Falls back to scanning sized blocks if header_len is 24 or 40.
    /// </summary>
    public static bool TryParseRecoverResponse(
        byte[] blob,
        out byte[] sessionId,
        out byte[] m2Section,
        out byte[] encryptedPayload)
    {
        sessionId = [];
        m2Section = [];
        encryptedPayload = [];
        if (blob.Length < 48)
            return false;
        if (BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(0, 4)) != (uint)blob.Length)
            return false;

        foreach (var headerLen in new[] { 24, 40 })
        {
            foreach (var sectionCount in new[] { 3, 2, 4 })
            {
                if (!TryUnpack(blob, headerLen, sectionCount, out var header, out var sections))
                    continue;
                if (header.Length < 24)
                    continue;

                sessionId = header[8..24];
                byte[]? m2 = null;
                byte[]? best = null;
                foreach (var s in sections)
                {
                    if (s.Length == 32)
                        m2 ??= s;
                    else if (s.Length > 32 && (best is null || s.Length > best.Length))
                        best = s;
                }

                if (best is null || best.Length < 64)
                    continue;

                m2Section = m2 ?? [];
                encryptedPayload = best;
                return true;
            }
        }

        return TryExtractLargestTaggedPayload(blob, out encryptedPayload);
    }

    /// <summary>
    /// Fallback: largest <c>u32be size || data</c> block after the KeyVault header.
    /// </summary>
    public static bool TryExtractLargestTaggedPayload(byte[] blob, out byte[] payload)
    {
        payload = [];
        if (blob.Length < 48)
            return false;

        byte[]? best = null;
        for (var i = 28; i + 8 < blob.Length; i++)
        {
            var plen = (int)BinaryPrimitives.ReadUInt32BigEndian(blob.AsSpan(i, 4));
            if (plen is < 32 or > 8192 || i + 4 + plen > blob.Length)
                continue;
            var value = blob[(i + 4)..(i + 4 + plen)];
            if (best is null || value.Length > best.Length)
                best = value;
        }

        if (best is null || best.Length < 32)
            return false;
        payload = best;
        return true;
    }

    /// <summary>Sank6 <c>unpack_message</c>.</summary>
    public static bool TryUnpack(
        byte[] bin,
        int headerLen,
        int sectionCount,
        out byte[] header,
        out byte[][] sections)
    {
        header = [];
        sections = [];
        if (bin.Length < 4 + headerLen + (sectionCount + 1) * 4)
            return false;

        var total = BinaryPrimitives.ReadUInt32BigEndian(bin.AsSpan(0, 4));
        if (total != (uint)bin.Length)
            return false;

        header = bin[4..(4 + headerLen)];
        var totalHeaderSize = headerLen + 4 + (sectionCount + 1) * 4;
        var offsetsStart = headerLen + 4;
        var list = new byte[sectionCount][];
        for (var i = 0; i < sectionCount; i++)
        {
            var offset = (int)BinaryPrimitives.ReadUInt32BigEndian(
                bin.AsSpan(offsetsStart + i * 4, 4));
            var start = totalHeaderSize + offset;
            if (start + 4 > bin.Length)
                return false;
            var size = (int)BinaryPrimitives.ReadUInt32BigEndian(bin.AsSpan(start, 4));
            if (size < 0 || start + 4 + size > bin.Length)
                return false;
            list[i] = bin[(start + 4)..(start + 4 + size)];
        }

        sections = list;
        return true;
    }

    /// <summary>
    /// Lab ENROLL blob mirroring real escrow KeyVault <c>section_sized</c> layout
    /// (from live <c>srp_init</c> resp: wire slots 20 / 68 / 260 — size‖data zero-padded).
    /// B20 learned: <c>PrefixSize</c>-only yields wire=L+4 (e.g. 1028) → "invalid sect size".
    /// </summary>
    /// <param name="payloadWireSlot">
    /// Exact wire length of section 3 (includes the 4-byte size prefix), e.g. 1024.
    /// </param>
    public static byte[] BuildLabIcdpEnrollBlob(
        string dsid,
        string passcode,
        uint messageType = 0xa1,
        byte[]? bottledPeerEntropy = null,
        int payloadWireSlot = 1000,
        bool nestInnerKeyVault = true)
    {
        if (string.IsNullOrWhiteSpace(dsid))
            throw new ArgumentException("dsid richiesto.", nameof(dsid));
        // Wire slot must fit size(4)+data; keep headroom for bottle body.
        if (payloadWireSlot is < 68 or > 8192)
            throw new ArgumentOutOfRangeException(nameof(payloadWireSlot));

        var pin = EscrowSrpClient.NormalizeIcsc(passcode);
        var salt = RandomNumberGenerator.GetBytes(64);
        var identity = Encoding.UTF8.GetBytes(dsid.Trim());
        var passwordBytes = Encoding.UTF8.GetBytes(pin);
        var innerHash = SHA256.HashData(ConcatBytes(identity, [0x3A], passwordBytes));
        var x = new BigInteger(SHA256.HashData(ConcatBytes(salt, innerHash)), isUnsigned: true,
            isBigEndian: true);
        var v = BigInteger.ModPow(2, x, EscrowSrpClient.Modulus);
        var verifier = PadTo256(v);

        var entropy = bottledPeerEntropy is { Length: 72 }
            ? bottledPeerEntropy
            : RandomNumberGenerator.GetBytes(72);
        var bottlePlist = AppleXmlPlist.ToEscrowProxyXmlBytes(new Dictionary<string, object?>
        {
            ["BottledPeerEntropy"] = entropy,
            ["pcslab"] = true,
            ["labelHint"] = "pcslab-enroll",
        });

        const int rounds = 10_000;
        var salt2 = RandomNumberGenerator.GetBytes(32);
        var derived = Rfc2898DeriveBytes.Pbkdf2(
            Encoding.UTF8.GetBytes(pin), salt2, rounds, HashAlgorithmName.SHA256, 16);
        using var aes = Aes.Create();
        aes.Key = derived;
        aes.IV = salt2[..16];
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        var bottleCt = aes.CreateEncryptor().TransformFinalBlock(bottlePlist, 0, bottlePlist.Length);

        byte[] payloadCore;
        if (nestInnerKeyVault)
        {
            var innerHeader = new byte[16];
            BinaryPrimitives.WriteUInt32BigEndian(innerHeader.AsSpan(0, 4), 0x0b);
            BinaryPrimitives.WriteUInt32BigEndian(innerHeader.AsSpan(8, 4), (uint)rounds);
            payloadCore = Pack(innerHeader,
            [
                PrefixSize(Encoding.UTF8.GetBytes(dsid.Trim())),
                PrefixSize(salt2),
                PrefixSize(RandomNumberGenerator.GetBytes(16)),
                PrefixSize(bottleCt),
                PrefixSize([]),
                PrefixSize([]),
            ]);
        }
        else
        {
            payloadCore = new byte[4 + salt2.Length + bottleCt.Length];
            BinaryPrimitives.WriteUInt32BigEndian(payloadCore.AsSpan(0, 4), (uint)rounds);
            Buffer.BlockCopy(salt2, 0, payloadCore, 4, salt2.Length);
            Buffer.BlockCopy(bottleCt, 0, payloadCore, 4 + salt2.Length, bottleCt.Length);
        }

        // Max data in slot = wireSlot - 4 (size prefix). Truncate/omit nest if too big.
        var maxData = payloadWireSlot - 4;
        if (payloadCore.Length > maxData)
        {
            // Prefer flat truncated bottle over failing the oracle.
            if (nestInnerKeyVault)
            {
                return BuildLabIcdpEnrollBlob(dsid, passcode, messageType, entropy,
                    payloadWireSlot, nestInnerKeyVault: false);
            }

            throw new InvalidOperationException(
                $"payload {payloadCore.Length} B non entra in wire slot {payloadWireSlot} " +
                $"(max data {maxData}).");
        }

        var header = new byte[24];
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(0, 4), messageType);
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(4, 4), 0);
        // B20: wire slot 1000 accepted when sizePrefix = real payload len (PadSection),
        // not when sizePrefix = 996 (zero-filled exact). F1 size≈627 → Auth failed;
        // exact size=996 → invalid sect size 1000 again.
        return Pack(header,
        [
            PadSection(salt, 68),
            PadSection(verifier, 260),
            PadSection(payloadCore, payloadWireSlot),
        ]);
    }

    /// <summary>
    /// Minimal 3-section oracle blob (dummy salt/verifier/payload).
    /// B20: salt@68 + ver@260 are accepted for msg 0xa1; only section-3 wire size is unknown.
    /// </summary>
    /// <param name="padPayload">
    /// true = <see cref="PadSection"/> to <paramref name="payloadWireSlot"/>;
    /// false = exact <c>size‖data</c> with dataLen = max(0, slot-4) (wire = slot).
    /// </param>
    public static byte[] BuildEnrollSectionSizeOracleBlob(
        uint messageType,
        int saltWireSlot,
        int verifierWireSlot,
        int payloadWireSlot,
        bool padPayload = true)
    {
        var saltDataLen = Math.Max(0, saltWireSlot - 4);
        var verDataLen = Math.Max(0, verifierWireSlot - 4);
        var payDataLen = Math.Max(0, payloadWireSlot - 4);
        var header = new byte[24];
        BinaryPrimitives.WriteUInt32BigEndian(header.AsSpan(0, 4), messageType);
        var payload = padPayload
            ? PadSection(new byte[payDataLen], payloadWireSlot)
            : PrefixSize(new byte[payDataLen]);
        return Pack(header,
        [
            PadSection(new byte[saltDataLen], saltWireSlot),
            PadSection(new byte[verDataLen], verifierWireSlot),
            payload,
        ]);
    }

    /// <summary>
    /// Lab ENROLL with exact payload wire (PadSection) once oracle finds an accepted slot.
    /// Live recover resp uses payload wire ≈ 1236 — primary candidate beyond 0xa1@1024 misses.
    /// </summary>
    public static byte[] BuildLabIcdpEnrollBlobExactPayloadWire(
        string dsid,
        string passcode,
        int payloadWireSlot,
        uint messageType = 0xa1,
        byte[]? bottledPeerEntropy = null) =>
        BuildLabIcdpEnrollBlob(
            dsid, passcode, messageType, bottledPeerEntropy,
            payloadWireSlot, nestInnerKeyVault: payloadWireSlot >= 768);

    private static byte[] PadTo256(BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length >= 256)
            return bytes[^256..];
        var padded = new byte[256];
        Buffer.BlockCopy(bytes, 0, padded, 256 - bytes.Length, bytes.Length);
        return padded;
    }

    private static byte[] ConcatBytes(params byte[][] parts)
    {
        var len = parts.Sum(static p => p.Length);
        var result = new byte[len];
        var o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, result, o, p.Length);
            o += p.Length;
        }

        return result;
    }

    /// <summary>Sank6 <c>KeyVaultMessage.pack</c>.</summary>
    public static byte[] Pack(byte[] header, IReadOnlyList<byte[]> sizedSections)
    {
        var body = new MemoryStream();
        var offsets = new List<int>(sizedSections.Count + 1);
        foreach (var section in sizedSections)
        {
            offsets.Add((int)body.Length);
            body.Write(section);
        }

        offsets.Add((int)body.Length);

        var bodyBytes = body.ToArray();
        var result = new byte[4 + header.Length + offsets.Count * 4 + bodyBytes.Length];
        BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(0, 4), (uint)result.Length);
        Buffer.BlockCopy(header, 0, result, 4, header.Length);
        var o = 4 + header.Length;
        foreach (var off in offsets)
        {
            BinaryPrimitives.WriteUInt32BigEndian(result.AsSpan(o, 4), (uint)off);
            o += 4;
        }

        Buffer.BlockCopy(bodyBytes, 0, result, o, bodyBytes.Length);
        return result;
    }

    private static byte[] PrefixSize(byte[] data)
    {
        var section = new byte[4 + data.Length];
        BinaryPrimitives.WriteUInt32BigEndian(section.AsSpan(0, 4), (uint)data.Length);
        Buffer.BlockCopy(data, 0, section, 4, data.Length);
        return section;
    }

    /// <summary>Sank6 <c>section_sized</c>: <c>size||data</c> zero-padded to <paramref name="slotSize"/>.</summary>
    public static byte[] PadSection(byte[] data, int slotSize)
    {
        var total = PrefixSize(data);
        if (total.Length > slotSize)
            throw new ArgumentException($"section {total.Length} > slot {slotSize}");
        if (total.Length == slotSize)
            return total;
        var padded = new byte[slotSize];
        Buffer.BlockCopy(total, 0, padded, 0, total.Length);
        return padded;
    }
}
