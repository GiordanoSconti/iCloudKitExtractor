using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Restore;

/// <summary>Self-test round-trip per verificare PBKDF2 + AES-KW + decifra blob.</summary>
public static class IosKeybagSelfTest
{
    public sealed record SelfTestResult(
        bool KeybagUnlockOk,
        bool WrongPinRejected,
        bool BlobDecryptOk,
        string Message);

    public static string DebugWrapDiagnostics(string passcode)
    {
        var sb = new StringBuilder();
        // RFC 3394 test vector (AES-256 wrap 128-bit key)
        var kek = Convert.FromHexString("000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F");
        var plain = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        var expected = Convert.FromHexString("28C9F404C4B8106689266D5BF1835273B7BFB4AF8F2DB7F2");
        try
        {
            var w = AesKeyWrap.Wrap(kek, plain);
            sb.AppendLine($"RFC wrap match: {w.AsSpan().SequenceEqual(expected)} ours={Convert.ToHexString(w)}");
            var u = AesKeyWrap.Unwrap(kek, expected);
            sb.AppendLine($"RFC unwrap match: {u.AsSpan().SequenceEqual(plain)}");
            var u2 = AesKeyWrap.Unwrap(kek, w);
            sb.AppendLine($"our roundtrip: {u2.AsSpan().SequenceEqual(plain)}");
        }
        catch (Exception ex) { sb.AppendLine($"RFC vector FAIL: {ex.Message}"); }

        var salt = Convert.FromHexString("A1B2C3D4E5F60718293A4B5C6D7E8F9011223344");
        var classKey = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        const int iterations = 2000;
        var probe = new IosKeybag();
        var kek32 = probe.DerivePasscodeKeyFromParts(
            Encoding.UTF8.GetBytes(passcode), salt, iterations, null, null);
        var kek16 = kek32.AsSpan(0, 16).ToArray();
        foreach (var (label, derivedKek) in new[] { ("32", kek32), ("16", kek16) })
        {
            try
            {
                var wpky = AesKeyWrap.Wrap(derivedKek, classKey);
                var un = AesKeyWrap.Unwrap(derivedKek, wpky);
                sb.AppendLine($"{label}b roundtrip: {(un.AsSpan().SequenceEqual(classKey) ? "OK" : "MISMATCH")}");
            }
            catch (Exception ex) { sb.AppendLine($"{label}b FAIL: {ex.Message}"); }
        }

        var record = BuildSyntheticKeybagRecord(passcode, salt, iterations, 4, classKey);
        if (!IosKeybag.TryParse(record, out var kb, out var err) || kb is null)
            sb.AppendLine($"Parse: {err}");
        else
            sb.AppendLine($"TryUnlock={kb.TryUnlock(passcode)} type={kb.KeybagType} iter={kb.DetectedIterationCount}");
        return sb.ToString();
    }

    public static SelfTestResult VerifyPasscodeAlgorithm(string passcode)
    {
        const int protectionClass = 4;
        var classKey = Convert.FromHexString("00112233445566778899AABBCCDDEEFF");
        var salt = Convert.FromHexString("A1B2C3D4E5F60718293A4B5C6D7E8F9011223344");
        const int iterations = 2_000;

        var record = BuildSyntheticKeybagRecord(passcode, salt, iterations, protectionClass, classKey);
        if (!IosKeybag.TryParse(record, out var keybag, out var err) || keybag is null)
            return new SelfTestResult(false, false, false, $"parse: {err}");

        var unlockOk = keybag.TryUnlock(passcode);
        if (!unlockOk)
            return new SelfTestResult(false, false, false, "unlock fallito");

        if (!keybag.UnwrappedClassKeys.TryGetValue(protectionClass, out var unwrapped)
            || !unwrapped.AsSpan().SequenceEqual(classKey))
        {
            return new SelfTestResult(true, false, false, "class key non corrisponde dopo unwrap");
        }

        var wrongRejected = !keybag.TryUnlock("000000");
        if (!wrongRejected)
            return new SelfTestResult(true, false, false, "PIN errato non rifiutato");

        keybag.TryUnlock(passcode);

        if (!keybag.UnwrappedClassKeys.TryGetValue(protectionClass, out _))
            return new SelfTestResult(true, true, false, "re-unlock fallito");

        var plain = Encoding.UTF8.GetBytes("bplist00" + new string('X', 40));
        var iv = Convert.FromHexString("0102030405060708090A0B0C0D0E0F10");
        var cipher = AesCbcEncrypt(classKey, iv, plain);
        var blob = new byte[iv.Length + cipher.Length];
        iv.CopyTo(blob, 0);
        cipher.CopyTo(blob, iv.Length);

        var decrypted = BackupBlobDecryptor.TryDecryptFile(blob, keybag.UnwrappedClassKeys);
        var blobOk = decrypted is not null && decrypted.Plaintext.AsSpan().SequenceEqual(plain);

        return new SelfTestResult(true, true, blobOk,
            blobOk ? "algoritmo OK (keybag + decifra blob)" : "decifra blob fallita");
    }

    public static string BuildSyntheticKeybagRecord(
        string passcode,
        byte[] salt,
        int iterations,
        int protectionClass,
        byte[] classKey)
    {
        var probe = new IosKeybag();
        var kek = probe.DerivePasscodeKeyFromParts(
            Encoding.UTF8.GetBytes(passcode), salt, iterations, null, null);
        var wpky = AesKeyWrap.Wrap(kek, classKey);

        using var ms = new MemoryStream();
        WriteTlvUInt(ms, "TYPE", 3);
        WriteTlv(ms, "UUID", Convert.FromHexString("000102030405060708090A0B0C0D0E0F"));
        WriteTlvUInt(ms, "VERS", 4);
        WriteTlv(ms, "SALT", salt);
        WriteTlvUInt(ms, "ITER", (uint)iterations);
        WriteTlvUInt(ms, "CLAS", (uint)protectionClass);
        WriteTlvUInt(ms, "WRAP", 3);
        WriteTlv(ms, "WPKY", wpky);
        return "K:" + Convert.ToBase64String(ms.ToArray());
    }

    private static void WriteTlv(Stream s, string tag, byte[] value)
    {
        s.Write(Encoding.ASCII.GetBytes(tag));
        Span<byte> len = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(len, (uint)value.Length);
        s.Write(len);
        s.Write(value);
    }

    private static void WriteTlvUInt(Stream s, string tag, uint value)
    {
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, value);
        WriteTlv(s, tag, buf.ToArray());
    }

    private static byte[] AesCbcEncrypt(byte[] key, byte[] iv, byte[] plain)
    {
        using var aes = Aes.Create();
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;
        using var enc = aes.CreateEncryptor();
        return enc.TransformFinalBlock(plain, 0, plain.Length);
    }
}
