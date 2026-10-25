using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// SRP-6a modalità GSA (@foxt/js-srp Mode.GSA, SHA-256, 2048 bit).
/// </summary>
public sealed class GsaSrpClient
{
    private static readonly BigInteger N = BigInteger.Parse(
        "00" +
        "AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050" +
        "A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73",
        System.Globalization.NumberStyles.HexNumber);

    private const int PadLength = 256;
    private readonly byte[] _usernameBytes;
    private BigInteger _a;
    private BigInteger _A = BigInteger.Zero;
    private BigInteger _k = BigInteger.Zero;
    private byte[] _K = Array.Empty<byte>();
    private byte[] _M1 = Array.Empty<byte>();

    public GsaSrpClient(string username, byte[]? testPrivateExponent = null)
    {
        _usernameBytes = Encoding.UTF8.GetBytes(username);
        _a = testPrivateExponent is null ? RandomBigInt(PadLength) : BytesToBigInt(testPrivateExponent);
        _A = BigInteger.ModPow(2, _a, N);
        _k = HashToBigInt(Concat(MinimalBytes(N), PadBigInt(2)));
    }

    public byte[] PublicA => PadBigInt(_A);

    public byte[] DerivePassword(string protocol, string password, byte[] salt, int iterations)
    {
        var passHash = SHA256.HashData(Encoding.UTF8.GetBytes(password));
        if (protocol == "s2k_fo")
            passHash = Encoding.UTF8.GetBytes(Convert.ToHexString(passHash).ToLowerInvariant());

        return Rfc2898DeriveBytes.Pbkdf2(passHash, salt, iterations, HashAlgorithmName.SHA256, 32);
    }

    public void Generate(byte[] derivedPassword, byte[] salt, byte[] serverB)
    {
        var B = BytesToBigInt(serverB);
        if (B % N == BigInteger.Zero)
            throw new InvalidOperationException("Chiave pubblica server non valida.");

        var u = HashToBigInt(Concat(PadBigInt(_A), PadBigInt(B)));
        if (u == BigInteger.Zero)
            throw new InvalidOperationException("Parametro u nullo.");

        var x = HashToBigInt(Concat(salt, SHA256.HashData(Concat(
            new byte[] { 0x3A },
            derivedPassword))));
        var t0 = BigInteger.ModPow(2, x, N) * _k % N;
        var t1 = (B - t0 + N) % N;
        var t2 = _a + u * x;
        var S = BigInteger.ModPow(t1, t2, N);
        _K = SHA256.HashData(MinimalBytes(S));

        var hashN = SHA256.HashData(MinimalBytes(N));
        var hashG = SHA256.HashData(PadBigInt(2));
        var xorNg = new byte[hashN.Length];
        for (var i = 0; i < xorNg.Length; i++)
            xorNg[i] = (byte)(hashN[i] ^ hashG[i]);

        _M1 = SHA256.HashData(Concat(
            xorNg,
            SHA256.HashData(_usernameBytes),
            salt,
            MinimalBytes(_A),
            MinimalBytes(B),
            _K));
    }

    public byte[] M1 => _M1;

    public byte[] GenerateM2() =>
        SHA256.HashData(Concat(MinimalBytes(_A), _M1, _K));

    public byte[] SessionKey => _K;

    public byte[] DecryptSpd(byte[] encryptedSpd)
    {
        if (_K.Length == 0)
            throw new InvalidOperationException("Chiave di sessione SRP non disponibile.");
        return GsaSpdDecoder.DecryptSpd(_K, encryptedSpd);
    }

    public bool VerifyServerM2(byte[] serverM2) =>
        CryptographicOperations.FixedTimeEquals(GenerateM2(), serverM2);

    private static BigInteger RandomBigInt(int bytes)
    {
        var buffer = RandomNumberGenerator.GetBytes(bytes);
        buffer[0] &= 0x7F;
        return BytesToBigInt(buffer);
    }

    private static BigInteger HashToBigInt(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return new BigInteger(hash, isUnsigned: true, isBigEndian: true);
    }

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
        var length = parts.Sum(p => p.Length);
        var result = new byte[length];
        var offset = 0;
        foreach (var part in parts)
        {
            Buffer.BlockCopy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }
        return result;
    }
}
