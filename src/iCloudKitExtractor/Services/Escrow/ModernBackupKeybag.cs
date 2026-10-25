using System.Security.Cryptography;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>Keybag CloudKit moderno (post-GCM): DER tagged, non TLV TYPE/SALT.</summary>
public sealed record ModernBackupKeybagBlob(
    byte[] Uuid,
    byte[] BagKey,
    byte Type,
    byte[] Salt,
    byte[] WrappedKey);

/// <summary>
/// Formato osservato 2026: dopo GCM su <c>keybagData</c> arriva
/// <c>SEQUENCE { [0] ver, [1] uuid16, [2] wrapped40, [3] salt16, [4] type }</c>.
/// Chiave: <c>PBKDF2-SHA256(secret, salt, 1, 32)</c> → AES-KW → bagKey 32 B.
/// </summary>
public static class ModernBackupKeybag
{
    public static bool TryUnwrap(
        ReadOnlySpan<byte> keybagDataPlain,
        ReadOnlySpan<byte> secretPlain,
        out ModernBackupKeybagBlob? result,
        out string? error)
    {
        result = null;
        error = null;

        if (!TryParseDer(keybagDataPlain, out var uuid, out var wrapped, out var salt, out var type, out error))
            return false;

        if (secretPlain.Length < 16)
        {
            error = $"secret troppo corto ({secretPlain.Length} B)";
            return false;
        }

        if (wrapped.Length != 40)
        {
            error = $"wrapped inatteso ({wrapped.Length} B, attesi 40)";
            return false;
        }

        try
        {
            var kek = Rfc2898DeriveBytes.Pbkdf2(
                secretPlain.ToArray(),
                salt,
                iterations: 1,
                HashAlgorithmName.SHA256,
                32);
            var bagKey = AesKeyWrap.Unwrap(kek, wrapped);
            if (bagKey.Length != 32)
            {
                error = $"bagKey length {bagKey.Length}";
                return false;
            }

            result = new ModernBackupKeybagBlob(uuid, bagKey, type, salt, wrapped);
            return true;
        }
        catch (Exception ex)
        {
            error = $"AES-KW/PBKDF2: {ex.Message}";
            return false;
        }
    }

    public static bool TryParseDer(
        ReadOnlySpan<byte> der,
        out byte[] uuid,
        out byte[] wrapped,
        out byte[] salt,
        out byte type,
        out string? error)
    {
        uuid = [];
        wrapped = [];
        salt = [];
        type = 0;
        error = null;

        if (der.Length < 20 || der[0] != 0x30)
        {
            error = "non è SEQUENCE DER";
            return false;
        }

        // Lunghezza corta (1 byte) tipica per ~86 B.
        var i = 2;
        if ((der[1] & 0x80) != 0)
        {
            error = "DER length lunga non supportata";
            return false;
        }

        byte[]? t0 = null, t1 = null, t2 = null, t3 = null, t4 = null;
        while (i + 2 <= der.Length)
        {
            var tag = der[i++];
            var len = der[i++];
            if (i + len > der.Length)
            {
                error = "DER truncated";
                return false;
            }

            var val = der.Slice(i, len).ToArray();
            i += len;
            switch (tag)
            {
                case 0x80: t0 = val; break;
                case 0x81: t1 = val; break;
                case 0x82: t2 = val; break;
                case 0x83: t3 = val; break;
                case 0x84: t4 = val; break;
            }
        }

        if (t1 is not { Length: 16 } || t2 is null || t3 is not { Length: 16 })
        {
            error = "campi [1]uuid/[2]wrapped/[3]salt mancanti";
            return false;
        }

        uuid = t1;
        wrapped = t2;
        salt = t3;
        type = t4 is { Length: > 0 } ? t4[0] : (byte)0;
        return true;
    }
}
