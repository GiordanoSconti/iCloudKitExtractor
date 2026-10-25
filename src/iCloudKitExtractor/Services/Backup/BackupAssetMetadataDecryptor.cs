using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Decrypt metadata BackupAsset: InflatableDonkey
/// <c>zone.decrypt(encryptedAttributes, "encryptedAttributes")</c>
/// → domain / relativePath / EncryptionKey (+ protectionClass in chiaro sul record).
/// </summary>
public static class BackupAssetMetadataDecryptor
{
    public const string EncryptedAttributesField = "encryptedAttributes";

    public sealed record Result(
        bool Success,
        string? Domain,
        string? RelativePath,
        int? ProtectionClass,
        byte[]? EncryptionKey,
        string Message);

    /// <summary>
    /// Tenta di arricchire <paramref name="asset"/> con identity filesystem + EncryptionKey.
    /// </summary>
    public static Result TryDecrypt(
        BackupAsset asset,
        byte[]? recordPayload,
        ICloudSession session,
        IosKeybag? unlockedKeybag,
        IProgress<string>? log = null)
    {
        _ = unlockedKeybag;

        if (asset.HasFilesystemIdentity)
        {
            asset.EnsureFileId();
            return new Result(
                true,
                asset.Domain,
                asset.RelativePath,
                asset.ProtectionClass,
                asset.EncryptionKey,
                "metadata già presente");
        }

        var payload = recordPayload is { Length: > 32 }
            ? recordPayload
            : asset.RecordPayload;

        if (payload is not { Length: > 32 })
        {
            var stub = asset.RecordName.StartsWith("MMCS:", StringComparison.Ordinal);
            return Pending(stub
                ? "metadata pending — asset PreAuth (MMCS:) senza record BackupAsset CloudKit"
                : "metadata decrypt pending — manca payload BackupAsset per isolare encryptedAttributes");
        }

        // protectionClass è in chiaro sul record (signed) quando presente (classico).
        if (asset.ProtectionClass is null
            && TryExtractSignedField(payload, "protectionClass", out var pc))
        {
            asset.ProtectionClass = pc;
        }

        // Marker attesi post-decrypt (payload già in chiaro — raro sul wire).
        var latin = Encoding.Latin1.GetString(payload);
        if (latin.Contains("relativePath", StringComparison.Ordinal)
            && TryExtractAsciiPathPair(latin, out var domainHint, out var pathHint))
        {
            asset.Domain = domainHint;
            asset.RelativePath = pathHint;
            asset.EnsureFileId();
            log?.Report($"  metadata plaintext → {domainHint} / {pathHint}");
            return new Result(true, domainHint, pathHint, asset.ProtectionClass, asset.EncryptionKey,
                "path trovati in chiaro nel payload");
        }

        var fields = CloudKitResponseParser.ExtractNamedByteFields(
            payload, EncryptedAttributesField);
        if (!fields.TryGetValue(EncryptedAttributesField, out var rawCt)
            || rawCt.Length < 16)
        {
            // moderno: BackupAsset = extension + contents (+ version); path da flist (EN:).
            var hasContents = latin.Contains("contents", StringComparison.Ordinal);
            return Pending(hasContents
                ? "metadata pending — BackupAsset moderno senza encryptedAttributes " +
                  "(path/EncryptionKey da flist EN:, non dal record)"
                : "metadata decrypt pending — campo encryptedAttributes assente nel payload");
        }

        if (!PcsSessionSeedKeys.HasAny(session))
        {
            return Pending("metadata decrypt pending — PCS KeySet assente");
        }

        var manateeFast = PcsSessionSeedKeys.IsManateePrimary(session);
        List<PcsCompactPrivateKey> seedKeys;
        if (PcsSessionSeedKeys.HasEscrowKeySet(session))
            seedKeys = PcsDer.ParseKeySetPrivateKeys(session.PcsEscrowedKeySet!);
        else
            seedKeys = PcsSessionSeedKeys.Collect(
                session,
                narrowToPreferred: manateeFast && session.PcsPreferredKeyIds is { Count: > 0 });
        if (seedKeys.Count == 0)
            return Pending("metadata decrypt pending — KeySet senza chiavi private");

        var ct = BackupKeybagPcsUnlock.ExtractEncryptedBytesValue(rawCt);
        var zones = BuildDecryptZones(payload, asset, seedKeys, includeLight: !manateeFast);

        byte[]? plain = null;
        foreach (var zone in zones)
        {
            plain = PcsProtectionZone.TryDecryptField(
                zone, ct, EncryptedAttributesField, "EncryptedAttributes");
            if (plain is { Length: > 0 })
                break;
        }

        if (plain is null)
        {
            var embedded = PcsProtectionZone.TryUnwrapAll(
                ct, seedKeys, includeLight: !manateeFast);
            foreach (var zone in embedded)
            {
                plain = PcsProtectionZone.TryDecryptField(
                    zone, ct, EncryptedAttributesField, "EncryptedAttributes");
                if (plain is { Length: > 0 })
                    break;
            }
        }

        if (plain is not { Length: > 0 })
            return Pending("metadata decrypt fallito — PCS GCM encryptedAttributes");

        if (!AssetEncryptedAttributesParser.TryParse(plain, out var attrs, out var parseErr)
            || attrs is null)
        {
            return Pending($"metadata plaintext non parsato: {parseErr}");
        }

        var domain = attrs.Domain;
        var relativePath = attrs.RelativePath;
        if (string.IsNullOrWhiteSpace(domain) && !string.IsNullOrWhiteSpace(asset.Domain))
            domain = asset.Domain;

        if (string.IsNullOrWhiteSpace(relativePath))
            return Pending("metadata ok PCS ma relativePath assente");

        if (string.IsNullOrWhiteSpace(domain))
            domain = "UnknownDomain";

        log?.Report($"  metadata decrypt → {domain} / {relativePath}");
        return new Result(
            true,
            domain,
            relativePath,
            asset.ProtectionClass,
            attrs.EncryptionKey,
            "encryptedAttributes OK");
    }

    public static void Apply(BackupAsset asset, Result result)
    {
        if (!result.Success)
            return;
        if (!string.IsNullOrWhiteSpace(result.Domain))
            asset.Domain = result.Domain;
        if (!string.IsNullOrWhiteSpace(result.RelativePath))
            asset.RelativePath = result.RelativePath;
        if (result.ProtectionClass is int pc)
            asset.ProtectionClass = pc;
        if (result.EncryptionKey is { Length: > 0 } key)
            asset.EncryptionKey = key;
        asset.EnsureFileId();
    }

    private static List<ProtectionZoneKeys> BuildDecryptZones(
        byte[] payload,
        BackupAsset asset,
        List<PcsCompactPrivateKey> seedKeys,
        bool includeLight = true)
    {
        var zones = new List<ProtectionZoneKeys>();
        var pool = new List<PcsCompactPrivateKey>(seedKeys);

        var fromPayload = PcsProtectionZone.TryUnwrapAll(payload, seedKeys, includeLight: includeLight);
        if (fromPayload.Count > 0)
        {
            zones.AddRange(fromPayload);
            pool = PcsProtectionZone.MergeKeys(seedKeys, fromPayload);
        }

        if (asset.RecordProtectionInfoDerHex is { Length: > 0 } hex)
        {
            try
            {
                var der = Convert.FromHexString(hex);
                var zone = PcsProtectionZone.TryUnwrap(der, pool);
                if (zone is not null)
                    zones.Insert(0, zone);
            }
            catch
            {
                // hex malformato
            }
        }

        return zones;
    }

    private static Result Pending(string message) =>
        new(false, null, null, null, null, message);

    private static bool TryExtractSignedField(byte[] payload, string fieldName, out int value)
    {
        value = 0;
        var key = Encoding.ASCII.GetBytes(fieldName);
        var searchFrom = 0;
        while (searchFrom < payload.Length)
        {
            var rel = payload.AsSpan(searchFrom).IndexOf(key);
            if (rel < 0)
                return false;

            var after = searchFrom + rel + key.Length;
            // CloudKit Value: type INT64/UINT64 poi signed/unsigned varint.
            // Cerca tag 0x08 (field1 varint = type) poi 0x10 (field2 varint = value) nelle vicinanze.
            for (var probe = after; probe < after + 24 && probe < payload.Length - 2; probe++)
            {
                if (payload[probe] != 0x10)
                    continue;
                var pos = probe + 1;
                try
                {
                    var raw = ReadVarint(payload, ref pos);
                    value = unchecked((int)raw);
                    if (value is >= 1 and <= 11)
                        return true;
                }
                catch
                {
                    // next
                }
            }

            searchFrom += rel + 1;
        }

        return false;
    }

    private static ulong ReadVarint(byte[] data, ref int pos)
    {
        ulong result = 0;
        var shift = 0;
        while (pos < data.Length)
        {
            var b = data[pos++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return result;
            shift += 7;
            if (shift > 63)
                throw new InvalidDataException("varint");
        }

        throw new InvalidDataException("varint EOF");
    }

    private static bool TryExtractAsciiPathPair(
        string latin,
        out string domain,
        out string relativePath)
    {
        domain = "";
        relativePath = "";
        const string appDomain = "AppDomain";
        var dIdx = latin.IndexOf(appDomain, StringComparison.Ordinal);
        var pIdx = latin.IndexOf("Library/", StringComparison.Ordinal);
        if (dIdx < 0 || pIdx < 0)
            return false;

        domain = TakeToken(latin, dIdx);
        relativePath = TakeToken(latin, pIdx);
        return domain.Length > 8 && relativePath.Length > 4;
    }

    private static string TakeToken(string s, int start)
    {
        var end = start;
        while (end < s.Length)
        {
            var c = s[end];
            if (c < 32 || c > 126 || c is '"' or '\'' or ';' or ',')
                break;
            end++;
            if (end - start > 240)
                break;
        }

        return s[start..end].Trim();
    }
}
