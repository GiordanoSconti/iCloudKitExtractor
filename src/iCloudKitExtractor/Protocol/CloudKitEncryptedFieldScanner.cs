using System.Text;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Isola campi CloudKit <c>ENCRYPTED_BYTES</c> (type=20) dal wire record/sync.
/// Pattern  <c>FieldName ‖ 0x12 &lt;len&gt; ‖ 0x08 0x14 ‖ 0x12 &lt;len&gt; ‖ GCM</c>.
/// </summary>
public static class CloudKitEncryptedFieldScanner
{
    public sealed record EncryptedField(
        string FieldName,
        byte[] RawValue,
        byte[] Ciphertext,
        int Offset);

    /// <summary>Campi noti Sync Data (Notes / Safari bookmarks / VoiceMemos).</summary>
    public static IReadOnlyList<string> SyncDataKnownFields { get; } =
    [
        // Notes
        "TitleEncrypted",
        "TextDataEncrypted",
        "SnippetEncrypted",
        "ReplicaIDToNotesVersionDataEncrypted",
        "ReplicaIDToUserIDEncrypted",
        "StandardizedContentEncrypted",
        "DisplayTextEncrypted",
        "MergeablePreferredViewSizeEncrypted",
        // Safari bookmarks / tabs / history (AAD = nome campo)
        "Title",
        "URL",
        "ShowIconOnly",
        "Key",
        "ImageURL",
        // VoiceMemos (Core Data CloudKit — non Photos mediaMetaDataEnc)
        "CD_encryptedTitle",
        "CD_versionedAudioFuture",
        "CD_customLabel",
        "mediaMetaDataEnc",
        // Photos CPL (PrimarySync)
        "albumNameEnc",
        "importedByBundleIdentifierEnc",
        "importedByDisplayNameEnc",
        "mediaMetaDataEnc",
        "filenameEnc",
        "originalFilenameEnc",
        "locationEnc",
        // generici / keychain-ish
        "encryptedData",
        "EncryptedData",
        "ciphertext",
        "Ciphertext",
        "dataEncrypted",
        "DataEncrypted",
    ];

    public static IReadOnlyList<EncryptedField> Scan(
        byte[] payload,
        IEnumerable<string>? preferredFieldNames = null)
    {
        if (payload is not { Length: > 32 })
            return [];

        var names = new List<string>();
        if (preferredFieldNames is not null)
            names.AddRange(preferredFieldNames);
        foreach (var n in SyncDataKnownFields)
        {
            if (!names.Contains(n, StringComparer.Ordinal))
                names.Add(n);
        }

        // Ordina per lunghezza desc: "TitleEncrypted" prima di "Title".
        names.Sort(static (a, b) => b.Length.CompareTo(a.Length));

        var results = new List<EncryptedField>();
        var seen = new HashSet<(string Name, int Offset)>();

        foreach (var name in names)
        {
            var key = Encoding.ASCII.GetBytes(name);
            var searchFrom = 0;
            while (searchFrom < payload.Length)
            {
                var rel = payload.AsSpan(searchFrom).IndexOf(key);
                if (rel < 0)
                    break;

                var nameAt = searchFrom + rel;
                var after = nameAt + key.Length;
                // Boundary: non matchare sottostringhe (es. Title in TitleEncrypted già gestito da ordine).
                if (nameAt > 0 && IsIdentChar(payload[nameAt - 1]))
                {
                    searchFrom = nameAt + 1;
                    continue;
                }

                if (after < payload.Length && IsIdentChar(payload[after]))
                {
                    searchFrom = nameAt + 1;
                    continue;
                }

                if (TryReadEncryptedValue(payload, after, out var raw, out var ct)
                    && seen.Add((name, nameAt)))
                {
                    results.Add(new EncryptedField(name, raw, ct, nameAt));
                }

                searchFrom = nameAt + 1;
            }
        }

        // Auto-discover: type=20 blobs non coperti dai nomi noti.
        DiscoverAnonymousType20(payload, results, seen);

        return DeduplicateByCiphertext(results);
    }

    /// <summary>Evita doppio conteggio nome-campo + type20@offset sullo stesso GCM.</summary>
    private static List<EncryptedField> DeduplicateByCiphertext(List<EncryptedField> results)
    {
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var deduped = new List<EncryptedField>(results.Count);
        foreach (var field in results.OrderBy(static f => f.Offset))
        {
            var key = field.FieldName + "|" + Convert.ToHexString(field.Ciphertext);
            if (!seen.Add(key))
                continue;
            deduped.Add(field);
        }

        return deduped;
    }

    private static void DiscoverAnonymousType20(
        byte[] payload,
        List<EncryptedField> results,
        HashSet<(string Name, int Offset)> seen)
    {
        // Cerca 08 14 12 <varint> <gcm starting 0x03>
        for (var i = 0; i < payload.Length - 8; i++)
        {
            if (payload[i] != 0x08 || payload[i + 1] != 0x14 || payload[i + 2] != 0x12)
                continue;

            var pos = i + 3;
            if (!TryReadVarint(payload, ref pos, out var len) || len is < 16 or > 1_048_576)
                continue;
            if (pos + (int)len > payload.Length)
                continue;
            if (payload[pos] > 3) // GCM DataA version
                continue;

            // Nome: stringa ASCII CamelCase immediatamente prima di 0x12 Value wrapper.
            // Tipico: <name> 12 <valueLen> 08 14 …
            var name = TryFindPrecedingFieldName(payload, i);
            if (string.IsNullOrEmpty(name))
                name = $"type20@{i:x}";

            var gcm = payload.AsSpan(pos, (int)len).ToArray();
            // Raw value = 08 14 12 <len> <gcm>
            var rawStart = i;
            var rawEnd = pos + (int)len;
            var raw = payload.AsSpan(rawStart, rawEnd - rawStart).ToArray();

            // Dedup contro scan nominato (stesso offset ciphertext).
            if (results.Any(r => r.Offset <= i && r.Offset + r.RawValue.Length >= rawEnd))
                continue;
            if (!seen.Add((name, i)))
                continue;

            results.Add(new EncryptedField(name, raw, gcm, i));
        }
    }

    private static string? TryFindPrecedingFieldName(byte[] payload, int type20At)
    {
        // Indietro fino a ~80 B cercando 0x12 (inizio Value) e prima una stringa.
        var searchStart = Math.Max(0, type20At - 80);
        for (var valueTag = type20At - 1; valueTag >= searchStart; valueTag--)
        {
            if (payload[valueTag] != 0x12)
                continue;

            // Verifica che questo 0x12 avvolga il type20.
            var p = valueTag + 1;
            if (!TryReadVarint(payload, ref p, out var wrapLen))
                continue;
            if (p > type20At || p + (int)wrapLen < type20At + 2)
                continue;

            // Nome subito prima del 0x12.
            var end = valueTag;
            var start = end - 1;
            while (start >= searchStart && IsIdentChar(payload[start]))
                start--;
            start++;
            var len = end - start;
            if (len is < 2 or > 64)
                continue;
            var name = Encoding.ASCII.GetString(payload, start, len);
            if (name.Any(char.IsLetter) && (name[0] is >= 'A' and <= 'Z' || name.Contains("Enc", StringComparison.Ordinal)))
                return name;
        }

        return null;
    }

    /// <summary>
    /// Dopo il nome campo: legge Value length-delimited e verifica type=20.
    /// </summary>
    public static bool TryReadEncryptedValue(
        byte[] data,
        int offset,
        out byte[] rawValue,
        out byte[] ciphertext)
    {
        rawValue = [];
        ciphertext = [];

        for (var probe = offset; probe < offset + 8 && probe < data.Length; probe++)
        {
            if (data[probe] != 0x12)
                continue;

            var pos = probe + 1;
            if (!TryReadVarint(data, ref pos, out var wrapLen) || wrapLen is < 8 or > 1_048_576)
                continue;
            if (pos + (int)wrapLen > data.Length)
                continue;

            var value = data.AsSpan(pos, (int)wrapLen).ToArray();
            // Value inizia con type=20 (08 14) oppure è già GCM.
            if (value.Length >= 5 && value[0] == 0x08 && value[1] == 0x14)
            {
                var ct = BackupKeybagPcsUnlock.ExtractEncryptedBytesValue(value);
                if (ct.Length >= 16)
                {
                    rawValue = value;
                    ciphertext = ct;
                    return true;
                }
            }
            // VoiceMemos CD_encryptedTitle: type=3 (BYTES) + nested 12 <len> 03… (GCM DataA)
            if (value.Length >= 8 && value[0] == 0x08 && value[1] == 0x03)
            {
                var p = 2;
                if (value[p] == 0x12)
                {
                    p++;
                    if (TryReadVarint(value, ref p, out var innerLen)
                        && innerLen >= 16
                        && p + (int)innerLen <= value.Length
                        && value[p] <= 3)
                    {
                        rawValue = value;
                        ciphertext = value.AsSpan(p, (int)innerLen).ToArray();
                        return true;
                    }
                }
            }
            else if (value.Length >= 16 && value[0] <= 3)
            {
                rawValue = value;
                ciphertext = value;
                return true;
            }
        }

        return false;
    }

    private static bool IsIdentChar(byte b) =>
        b is (>= (byte)'A' and <= (byte)'Z')
            or (>= (byte)'a' and <= (byte)'z')
            or (>= (byte)'0' and <= (byte)'9')
            or (byte)'_';

    private static bool TryReadVarint(byte[] data, ref int pos, out ulong value)
    {
        value = 0;
        var shift = 0;
        while (pos < data.Length && shift <= 63)
        {
            var b = data[pos++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
        }

        return false;
    }
}
