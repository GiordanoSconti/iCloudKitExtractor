using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Parser/unlock keybag iOS (TLV: TYPE, SALT, ITER, DPSL, DPIC, CLAS, WPKY, …).
/// Supporta Backup (1) e OTA/iCloud (3) con passcode dispositivo.
/// </summary>
public sealed class IosKeybag
{
    public const int TypeBackup = 1;
    public const int TypeOtaIcloud = 3;

    private readonly Dictionary<string, byte[]> _attrs = new(StringComparer.Ordinal);
    private readonly List<ClassKeyEntry> _classKeys = [];

    public int KeybagType { get; private set; }
    public string? Uuid { get; private set; }
    public bool IsUnlocked { get; private set; }

    private readonly Dictionary<int, byte[]> _unwrappedClassKeys = new();

    public IReadOnlyDictionary<int, byte[]> UnwrappedClassKeys => _unwrappedClassKeys;

    public static bool TryParse(string kRecord, out IosKeybag? keybag, out string? error)
    {
        keybag = null;
        error = null;
        if (string.IsNullOrWhiteSpace(kRecord))
        {
            error = "record K: vuoto";
            return false;
        }

        var trimmed = kRecord.Trim();
        if (trimmed.StartsWith("K:", StringComparison.Ordinal))
            trimmed = trimmed[2..];

        byte[] data;
        try
        {
            data = Convert.FromBase64String(trimmed);
        }
        catch
        {
            error = "K: non è base64 valido";
            return false;
        }

        return TryParse(data, out keybag, out error);
    }

    public static bool TryParse(ReadOnlySpan<byte> data, out IosKeybag? keybag, out string? error)
    {
        keybag = null;
        error = null;
        if (data.Length < 16)
        {
            error = $"keybag troppo corto ({data.Length} byte) — potrebbe essere un riferimento, non il blob completo";
            return false;
        }

        var kb = new IosKeybag();
        if (!kb.LoadTlv(data))
        {
            error = "struttura TLV keybag non riconosciuta";
            return false;
        }

        keybag = kb;
        return true;
    }

    private bool LoadTlv(ReadOnlySpan<byte> data)
    {
        var ok = false;
        WalkTlv(data, (tag, value) =>
        {
            if (tag == "TYPE" && value.Length >= 4)
            {
                KeybagType = BinaryPrimitives.ReadInt32BigEndian(value);
                ok = true;
            }
            else if (tag == "UUID" && value.Length >= 16)
            {
                Uuid = Convert.ToHexString(value[..16]).ToLowerInvariant();
            }
            else if (tag is "SALT" or "DPSL" or "DPIC" or "ITER" or "VERS" or "HMCK")
            {
                _attrs[tag] = value.ToArray();
            }
            else if (tag == "CLAS")
            {
                _classKeys.Add(new ClassKeyEntry { ProtectionClass = (int)ReadUInt32Be(value) });
            }
            else if (_classKeys.Count > 0)
            {
                var entry = _classKeys[^1];
                switch (tag)
                {
                    case "WRAP":
                        entry.Wrap = ReadUInt32Be(value);
                        break;
                    case "WPKY":
                        entry.WrappedKey = value.ToArray();
                        break;
                    case "KTYP":
                        entry.KeyType = ReadUInt32Be(value);
                        break;
                }
            }
        });

        return ok;
    }

    private static void WalkTlv(ReadOnlySpan<byte> data, Action<string, ReadOnlySpan<byte>> onTag)
    {
        var offset = 0;
        while (offset + 8 <= data.Length)
        {
            var tag = Encoding.ASCII.GetString(data.Slice(offset, 4));
            var length = BinaryPrimitives.ReadInt32BigEndian(data.Slice(offset + 4, 4));
            offset += 8;
            if (length < 0 || offset + length > data.Length)
                break;
            onTag(tag, data.Slice(offset, length));
            offset += length;
        }
    }

    private static uint ReadUInt32Be(ReadOnlySpan<byte> value) =>
        value.Length >= 4 ? BinaryPrimitives.ReadUInt32BigEndian(value) : 0;

    /// <summary>
    /// Deriva la KEK dal passcode (Backup/OTA). iOS 10.2+: doppio PBKDF2 se DPSL presente.
    /// </summary>
    public byte[] DerivePasscodeKey(string passcode) =>
        DerivePasscodeKey(Encoding.UTF8.GetBytes(passcode));

    /// <summary>
    /// KEK da passcode binario (campo CloudKit <c>secret</c> decifrato — InflatableDonkey).
    /// </summary>
    public byte[] DerivePasscodeKey(ReadOnlySpan<byte> passcode) =>
        DerivePasscodeKeyFromParts(
            passcode,
            _attrs.GetValueOrDefault("SALT"),
            DetectedIterationCount ?? 10_000_000,
            _attrs.GetValueOrDefault("DPSL"),
            _attrs.TryGetValue("DPIC", out var dpic) ? (int?)ReadUInt32Be(dpic) : null);

    internal byte[] DerivePasscodeKeyFromParts(
        ReadOnlySpan<byte> passcode,
        byte[]? salt,
        int iterations,
        byte[]? dpsl,
        int? dpic)
    {
        if (salt is null || salt.Length == 0)
            throw new InvalidOperationException("keybag senza SALT");
        if (passcode.IsEmpty)
            throw new InvalidOperationException("passcode keybag vuoto");

        if (iterations <= 0)
            iterations = 10_000_000;

        var passBytes = passcode.ToArray();
        if (dpsl is { Length: > 0 } && dpic is > 0)
        {
            var round1 = Rfc2898DeriveBytes.Pbkdf2(
                passBytes,
                dpsl,
                dpic.Value,
                HashAlgorithmName.SHA256,
                32);
            return Rfc2898DeriveBytes.Pbkdf2(round1, salt, iterations, HashAlgorithmName.SHA1, 32);
        }

        return Rfc2898DeriveBytes.Pbkdf2(
            passBytes,
            salt,
            iterations,
            HashAlgorithmName.SHA1,
            32);
    }

    public bool TryUnlock(string passcode) =>
        TryUnlock(Encoding.UTF8.GetBytes(passcode));

    /// <summary>
    /// Keybag moderno (bagKey 32 B da PCS): usa bagKey come class key per tutte le protection class.
    /// </summary>
    public static IosKeybag FromModernBagKey(ReadOnlySpan<byte> bagKey)
    {
        var kb = new IosKeybag();
        if (bagKey.Length >= 16)
        {
            var ck = bagKey.Length >= 32 ? bagKey[..32].ToArray() : bagKey[..16].ToArray();
            for (var pc = 1; pc <= 11; pc++)
                kb._unwrappedClassKeys[pc] = ck;
            kb.IsUnlocked = true;
        }

        return kb;
    }

    public bool TryUnlock(ReadOnlySpan<byte> passcode)
    {
        if (KeybagType is not (TypeBackup or TypeOtaIcloud))
            return false;

        byte[] kek;
        try
        {
            kek = DerivePasscodeKey(passcode);
        }
        catch
        {
            return false;
        }

        _unwrappedClassKeys.Clear();
        foreach (var entry in _classKeys)
        {
            if (entry.WrappedKey is null || entry.WrappedKey.Length < 24)
                continue;
            try
            {
                var unwrapped = AesKeyWrap.Unwrap(kek, entry.WrappedKey);
                if (unwrapped.Length is 16 or 24 or 32)
                    _unwrappedClassKeys[entry.ProtectionClass] = unwrapped;
            }
            catch
            {
                // passcode errato o CLAS non unwrap-able con questa KEK
            }
        }

        IsUnlocked = _unwrappedClassKeys.Count > 0;
        return IsUnlocked;
    }

    /// <summary>
    /// AES-KW della EncryptionKey persistente (40 B) con la class key già unwrapped.
    /// Equivalente a <c>Keybag.unwrapKeyForClass</c> di decryptor_CLI.
    /// </summary>
    public bool TryUnwrapKeyForClass(
        int protectionClass,
        ReadOnlySpan<byte> persistentKey,
        out byte[]? fileKey,
        out string? error)
    {
        fileKey = null;
        error = null;

        if (!IsUnlocked)
        {
            error = "keybag non sbloccato";
            return false;
        }

        if (persistentKey.Length is not (0x28 or 0x48))
        {
            error = $"EncryptionKey lunghezza {persistentKey.Length} (atteso 40 o 72)";
            return false;
        }

        if (!_unwrappedClassKeys.TryGetValue(protectionClass, out var classKey))
        {
            error = $"class key {protectionClass} assente";
            return false;
        }

        try
        {
            fileKey = AesKeyWrap.Unwrap(classKey, persistentKey);
            // wrap72 → fileKey 64 B: AES-CBC usa i primi 16 (come DefaultFCD).
            if (fileKey.Length > 32)
                fileKey = fileKey.AsSpan(0, 16).ToArray();
            return fileKey.Length is 16 or 24 or 32;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public int? DetectedIterationCount =>
        _attrs.TryGetValue("ITER", out var iter) ? (int)ReadUInt32Be(iter) : null;

    private sealed class ClassKeyEntry
    {
        public int ProtectionClass;
        public uint Wrap;
        public uint KeyType;
        public byte[]? WrappedKey;
    }
}

/// <summary>RFC 3394 AES Key Wrap (implementazione minimale per unwrap WPKY).</summary>
internal static class AesKeyWrap
{
    public static byte[] Unwrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> wrapped)
    {
        if (wrapped.Length % 8 != 0 || wrapped.Length < 24)
            throw new CryptographicException("WPKY lunghezza non valida");

        var n = wrapped.Length / 8 - 1;
        var a = BinaryPrimitives.ReadUInt64BigEndian(wrapped);
        var r = new ulong[n];
        for (var i = 0; i < n; i++)
            r[i] = BinaryPrimitives.ReadUInt64BigEndian(wrapped.Slice(8 + i * 8, 8));

        using var aes = Aes.Create();
        aes.Key = kek.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        for (var j = 5; j >= 0; j--)
        {
            for (var i = n; i >= 1; i--)
            {
                var t = (ulong)(n * j + i);
                var b = new byte[16];
                BinaryPrimitives.WriteUInt64BigEndian(b, a ^ t);
                BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(8), r[i - 1]);
                var dec = aes.DecryptEcb(b, PaddingMode.None);
                a = BinaryPrimitives.ReadUInt64BigEndian(dec);
                r[i - 1] = BinaryPrimitives.ReadUInt64BigEndian(dec.AsSpan(8));
            }
        }

        if (a != 0xA6A6A6A6A6A6A6A6)
            throw new CryptographicException("AES Key Unwrap integrity check fallito (passcode errato?)");

        var output = new byte[n * 8];
        for (var i = 0; i < n; i++)
            BinaryPrimitives.WriteUInt64BigEndian(output.AsSpan(i * 8), r[i]);
        return output;
    }

    public static byte[] Wrap(ReadOnlySpan<byte> kek, ReadOnlySpan<byte> key)
    {
        if (key.Length != 16)
            throw new CryptographicException("AES-KW richiede chiave di 16 byte");

        const ulong defaultA = 0xA6A6A6A6A6A6A6A6UL;
        var n = key.Length / 8;
        var r = new ulong[n];
        for (var i = 0; i < n; i++)
            r[i] = BinaryPrimitives.ReadUInt64BigEndian(key.Slice(i * 8, 8));

        var a = defaultA;

        using var aes = Aes.Create();
        aes.Key = kek.ToArray();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;

        for (var j = 0; j <= 5; j++)
        {
            for (var i = 1; i <= n; i++)
            {
                var t = (ulong)(n * j + i);
                var b = new byte[16];
                BinaryPrimitives.WriteUInt64BigEndian(b, a);
                BinaryPrimitives.WriteUInt64BigEndian(b.AsSpan(8), r[i - 1]);
                var enc = aes.EncryptEcb(b, PaddingMode.None);
                a = BinaryPrimitives.ReadUInt64BigEndian(enc) ^ t;
                r[i - 1] = BinaryPrimitives.ReadUInt64BigEndian(enc.AsSpan(8));
            }
        }

        var wrapped = new byte[8 + n * 8];
        BinaryPrimitives.WriteUInt64BigEndian(wrapped, a);
        for (var i = 0; i < n; i++)
            BinaryPrimitives.WriteUInt64BigEndian(wrapped.AsSpan(8 + i * 8), r[i]);
        return wrapped;
    }
}
