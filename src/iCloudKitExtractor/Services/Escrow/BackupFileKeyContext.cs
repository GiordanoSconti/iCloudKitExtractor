using System.Buffers.Binary;
using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Keybag classico (TLV + class keys) e bagKey moderni (DER, 32 B per UUID).
/// </summary>
public sealed class BackupFileKeyContext
{
    private readonly IosKeybag? _classicKeybag;
    private readonly Dictionary<string, byte[]> _modernBagKeys;

    private BackupFileKeyContext(IosKeybag? classicKeybag, Dictionary<string, byte[]> modernBagKeys)
    {
        _classicKeybag = classicKeybag;
        _modernBagKeys = modernBagKeys;
    }

    public bool HasClassicKeybag => _classicKeybag is not null;
    public IosKeybag? ClassicKeybag => _classicKeybag;
    public int ModernBagKeyCount => _modernBagKeys.Count;
    public bool IsEmpty => _classicKeybag is null && _modernBagKeys.Count == 0;

    public static BackupFileKeyContext Load(string snapshotDirectory, IProgress<string>? log = null)
    {
        IosKeybag? classic = null;

        try
        {
            foreach (var tlvPath in Directory.EnumerateFiles(snapshotDirectory, "keybag_tlv_*.bin")
                         .Concat(Directory.EnumerateFiles(snapshotDirectory, "keybag_*.pb")))
            {
                var data = File.ReadAllBytes(tlvPath);
                if (!IosKeybag.TryParse(data, out var kb, out _) || kb is null)
                    continue;

                var stem = Path.GetFileNameWithoutExtension(tlvPath);
                var safe = stem.StartsWith("keybag_tlv_", StringComparison.Ordinal)
                    ? stem["keybag_tlv_".Length..]
                    : stem.StartsWith("keybag_", StringComparison.Ordinal)
                        ? stem["keybag_".Length..]
                        : stem;

                var secretPath = Path.Combine(snapshotDirectory, $"keybag_secret_{safe}.bin");
                if (!File.Exists(secretPath))
                {
                    secretPath = Directory.EnumerateFiles(snapshotDirectory, "keybag_secret_*.bin")
                        .FirstOrDefault() ?? "";
                }

                if (string.IsNullOrEmpty(secretPath) || !File.Exists(secretPath))
                    continue;

                var secret = File.ReadAllBytes(secretPath);
                if (!kb.TryUnlock(secret))
                {
                    log?.Report($"  keybag unlock FAIL: {Path.GetFileName(tlvPath)}");
                    continue;
                }

                log?.Report(
                    $"  keybag unlocked: {Path.GetFileName(tlvPath)} " +
                    $"classKeys={kb.UnwrappedClassKeys.Count}");
                classic = kb;
                break;
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  keybag load skip: {ex.Message}");
        }

        var modern = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var keyPath in Directory.EnumerateFiles(snapshotDirectory, "keybag_key_*.bin"))
        {
            var bagKey = File.ReadAllBytes(keyPath);
            if (bagKey.Length != 32)
                continue;

            var stem = Path.GetFileNameWithoutExtension(keyPath)["keybag_key_".Length..];
            try
            {
                var core = stem.TrimEnd('_');
                var pad = (4 - core.Length % 4) % 4;
                var uuid = Convert.FromBase64String(core + new string('=', pad));
                if (uuid.Length == 16)
                    modern[Convert.ToHexString(uuid).ToLowerInvariant()] = bagKey;
            }
            catch
            {
                // filename non decodificabile come K: base64(uuid)
            }
        }

        if (modern.Count > 0)
        {
            log?.Report(
                classic is null
                    ? $"  keybag modern bagKey ×{modern.Count} (file-key unwrap via UUID match)"
                    : $"  keybag modern bagKey ×{modern.Count} + classic TLV");
        }

        return new BackupFileKeyContext(classic, modern);
    }

    public bool TryUnwrapFileKey(
        ReadOnlySpan<byte> encryptionKey,
        int protectionClass,
        out byte[]? fileKey,
        out string? error,
        out string source)
    {
        fileKey = null;
        error = null;
        source = "none";

        if (!TryExtractPersistentKey(encryptionKey, out var persistentKey, out var ekUuidHex))
        {
            error = "EncryptionKey persistentKey assente";
            return false;
        }

        if (_classicKeybag is not null
            && _classicKeybag.TryUnwrapKeyForClass(protectionClass, persistentKey, out fileKey, out error))
        {
            source = "ike-classic-class-key";
            return fileKey is not null;
        }

        if (ekUuidHex is not null
            && _modernBagKeys.TryGetValue(ekUuidHex, out var bagKey))
        {
            // modern: bagKey → class key → AES-KW(persistent@40) — path da confermare su live.
            var modernKb = IosKeybag.FromModernBagKey(bagKey);
            if (modernKb.TryUnwrapKeyForClass(protectionClass, persistentKey, out fileKey, out error))
            {
                source = "ike-modern-bagKey-class";
                return fileKey is not null;
            }

            var h4Err = error;

            // Fallback: protectionData-style AES-KW (non-oracle).
            if (encryptionKey.Length >= 36 + 72)
            {
                var wrap40 = encryptionKey.Slice(68, 40);
                foreach (var (kekLabel, kek) in new (string Label, byte[] Key)[]
                {
                    ("bag16", bagKey.AsSpan(0, 16).ToArray()),
                    ("wrapKek", PcsHmacKdf.DeriveWrappingKek(bagKey)),
                })
                {
                    try
                    {
                        var fk = AesKeyWrap.Unwrap(kek, wrap40);
                        if (fk.Length is 16 or 24 or 32)
                        {
                            fileKey = fk;
                            source = $"fallback-modern-pd-{kekLabel}";
                            return true;
                        }
                    }
                    catch (Exception ex)
                    {
                        // #region agent log
                        AgentDebugLog(
                            "BackupFileKeyContext.TryUnwrapFileKey",
                            "modern_pd_unwrap_fail",
                            new { ekUuidHex, protectionClass, kekLabel, err = ex.Message },
                            kekLabel == "bag16" ? "H5" : "H6");
                        // #endregion
                    }
                }
            }

            error = h4Err ?? error;
            // #region agent log
            AgentDebugLog(
                "BackupFileKeyContext.TryUnwrapFileKey",
                "modern_bagkey_all_fail",
                new { ekUuidHex, protectionClass, h4Err, ekLen = encryptionKey.Length },
                "H4");
            // #endregion
        }

        error ??= _classicKeybag is null && _modernBagKeys.Count == 0
            ? "keybag assente"
            : "unwrap class/bagKey fallito";
        return false;
    }

    // #region agent log
    private static void AgentDebugLog(string location, string message, object data, string hypothesisId)
    {
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = location,
                ["message"] = message,
                ["data"] = data,
                ["hypothesisId"] = hypothesisId,
                ["runId"] = "file-aes-ike-v1",
            });
            File.AppendAllText(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                line + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    private static bool TryExtractPersistentKey(
        ReadOnlySpan<byte> encryptionKey,
        out byte[] persistentKey,
        out string? uuidHex)
    {
        persistentKey = [];
        uuidHex = encryptionKey.Length >= 16
            ? Convert.ToHexString(encryptionKey[..16]).ToLowerInvariant()
            : null;

        if (encryptionKey.Length == 0x28)
        {
            persistentKey = encryptionKey.ToArray();
            return true;
        }

        if (encryptionKey.Length >= 36 + 40)
        {
            var beLen = BinaryPrimitives.ReadInt32BigEndian(encryptionKey.Slice(32, 4));
            // Classic wrap40; modern Cat.B can be wrap72 (AES-KW of 64 B file key).
            if (beLen is >= 40 and <= 72 && 36 + beLen <= encryptionKey.Length)
            {
                persistentKey = encryptionKey.Slice(36, beLen).ToArray();
                // #region agent log
                AgentDebugLog(
                    "BackupFileKeyContext.TryExtractPersistentKey",
                    "ek_wrap_len",
                    new { beLen, ekLen = encryptionKey.Length, uuidHex },
                    "H-K6");
                // #endregion
                return true;
            }
        }

        return false;
    }
}
