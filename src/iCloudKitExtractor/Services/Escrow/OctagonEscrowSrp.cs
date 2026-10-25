using System.Buffers.Binary;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// SRP-6a per bottle iCDP/Octagon (Sank6 / rustpush):
/// <c>x = H(salt ‖ H(dsid ":" passcode))</c>, A/B/S trimmed in u/M1/M2/K
/// (diverso dal path PCS che usa PAD e secret=dsid).
/// </summary>
public sealed class OctagonEscrowSrp
{
    private static readonly BigInteger N = EscrowSrpClient.Modulus;
    private static readonly BigInteger G = 2;
    private const int PadLength = 256;

    private readonly BigInteger _a;
    private readonly BigInteger _A;
    private byte[] _trimA = [];
    private byte[] _K = [];
    private byte[] _M1 = [];

    public OctagonEscrowSrp()
    {
        var buf = RandomNumberGenerator.GetBytes(32);
        buf[0] &= 0x7F;
        _a = new BigInteger(buf, isUnsigned: true, isBigEndian: true);
        _A = BigInteger.ModPow(G, _a, N);
        _trimA = TrimBigInt(_A);
    }

    /// <summary>A trimmed (wire + hash) — escrowproxy Octagon.</summary>
    public byte[] PublicA => _trimA;

    public byte[] M1 => _M1;
    public byte[] SessionKey => _K;

    public void Complete(string dsid, string passcode, byte[] salt, byte[] serverB)
    {
        var username = Encoding.UTF8.GetBytes(dsid.Trim());
        var password = Encoding.UTF8.GetBytes(EscrowSrpClient.NormalizeIcsc(passcode));
        if (!EscrowSrpClient.IsValidServerB(serverB))
            throw new InvalidOperationException("B server escrow non valida.");

        var B = BytesToBigInt(serverB);
        var trimB = TrimBigInt(B);
        var k = HashToBigInt(Concat(PadBigInt(N), PadBigInt(G)));
        var inner = SHA256.HashData(Concat(username, ":"u8.ToArray(), password));
        var x = HashToBigInt(Concat(salt, inner));
        var u = HashToBigInt(Concat(_trimA, trimB));
        if (u == BigInteger.Zero)
            throw new InvalidOperationException("Parametro u SRP nullo.");

        var kgx = k * BigInteger.ModPow(G, x, N) % N;
        var baseS = (B - kgx + N) % N;
        var S = BigInteger.ModPow(baseS, _a + u * x, N);
        _K = SHA256.HashData(TrimBigInt(S));

        var hashN = SHA256.HashData(PadBigInt(N));
        var hashG = SHA256.HashData(PadBigInt(G));
        var xorNg = new byte[hashN.Length];
        for (var i = 0; i < xorNg.Length; i++)
            xorNg[i] = (byte)(hashN[i] ^ hashG[i]);

        _M1 = SHA256.HashData(Concat(
            xorNg,
            SHA256.HashData(username),
            salt,
            _trimA,
            trimB,
            _K));
    }

    public bool VerifyServerM2(byte[] serverM2)
    {
        if (_M1.Length == 0 || serverM2.Length < 32)
            return false;
        var expected = SHA256.HashData(Concat(_trimA, _M1, _K));
        var actual = serverM2.Length == 32 ? serverM2 : EscrowSrpClient.ExtractM2Proof(serverM2);
        return actual is not null
               && CryptographicOperations.FixedTimeEquals(expected, actual);
    }

    /// <summary>
    /// Decrypt recover ciphertext (version 0 = AES-256-CBC, 2 = AES-256-GCM).
    /// </summary>
    public static byte[]? TryDecryptRecoverInner(
        byte[] sessionKeyK,
        uint version,
        byte[] ivOrNonce,
        byte[] ciphertext,
        out string? method)
    {
        method = null;
        if (sessionKeyK.Length is not (16 or 32) || ciphertext.Length < 16)
            return null;

        try
        {
            if (version == 0)
            {
                using var aes = Aes.Create();
                aes.Key = sessionKeyK.Length == 32 ? sessionKeyK : SHA256.HashData(sessionKeyK);
                aes.IV = ivOrNonce.Length >= 16 ? ivOrNonce[..16] : ivOrNonce;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                method = "AES-256-CBC(K)";
                return aes.CreateDecryptor().TransformFinalBlock(ciphertext, 0, ciphertext.Length);
            }

            if (version == 2)
            {
                var key = sessionKeyK.Length == 32 ? sessionKeyK : SHA256.HashData(sessionKeyK);
                // payloads[2] = ct ‖ tag(16)
                if (ciphertext.Length < 17)
                    return null;
                var tag = ciphertext[^16..];
                var ct = ciphertext[..^16];
                using var gcm = new AesGcm(key, 16);
                var plain = new byte[ct.Length];
                gcm.Decrypt(ivOrNonce, ct, tag, plain);
                method = "AES-256-GCM(K)";
                return plain;
            }
        }
        catch
        {
            return null;
        }

        return null;
    }

    /// <summary>
    /// Inner KeyVault (header 16, 6 sezioni) → PBKDF2(passcode, salt2, rounds, 16)
    /// → AES-128-CBC → EscrowBottle plist.
    /// </summary>
    public static bool TryUnwrapEscrowBottlePlist(
        byte[] inner,
        string passcode,
        out byte[] bottlePlist,
        out int rounds,
        out string? error)
    {
        bottlePlist = [];
        rounds = 0;
        error = null;
        if (!EscrowSecureBackupBlob.TryUnpack(inner, headerLen: 16, sectionCount: 6,
                out var header, out var sections)
            || sections.Length < 4
            || header.Length < 12)
        {
            error = "inner KeyVault non parsabile (atteso header=16, sezioni=6)";
            return false;
        }

        rounds = (int)BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(8, 4));
        if (rounds is < 1 or > 5_000_000)
        {
            error = $"rounds PBKDF2 sospetti: {rounds}";
            return false;
        }

        var salt2 = sections[1];
        var ct = sections[3];
        if (salt2.Length < 16 || ct.Length < 16)
        {
            error = $"salt2/ct corti (salt={salt2.Length}, ct={ct.Length})";
            return false;
        }

        try
        {
            var derived = Rfc2898DeriveBytes.Pbkdf2(
                Encoding.UTF8.GetBytes(EscrowSrpClient.NormalizeIcsc(passcode)),
                salt2,
                rounds,
                HashAlgorithmName.SHA256,
                16);
            using var aes = Aes.Create();
            aes.Key = derived;
            aes.IV = salt2[..16];
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;
            bottlePlist = aes.CreateDecryptor().TransformFinalBlock(ct, 0, ct.Length);
            return bottlePlist.Length > 0;
        }
        catch (Exception ex)
        {
            error = $"AES-128-CBC bottle: {ex.Message}";
            return false;
        }
    }

    private static byte[] TrimBigInt(BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        return bytes.Length == 0 ? [0] : bytes;
    }

    private static byte[] PadBigInt(BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length >= PadLength)
            return bytes[^PadLength..];
        var padded = new byte[PadLength];
        Buffer.BlockCopy(bytes, 0, padded, PadLength - bytes.Length, bytes.Length);
        return padded;
    }

    private static BigInteger HashToBigInt(byte[] data) =>
        new(SHA256.HashData(data), isUnsigned: true, isBigEndian: true);

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
