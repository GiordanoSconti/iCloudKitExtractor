using System.Text;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Parse dei record CloudKit <c>Domain</c> dalla risposta <c>N:</c> batch retrieve.
/// <para>
/// Ogni record è un catalogo per-domain: conteggi, <c>fileList</c> (CKAsset MMCS),
/// <c>fileListEncoding</c>, e opzionalmente <c>newAssets</c> / <c>deletedAssets</c>.
/// I path file non sono inline — solo l'handle MMCS da scaricare.
/// </para>
/// </summary>
public static class DomainFileListParser
{
    /// <summary>
    /// Valore tipico di <c>fileListEncoding</c>: blob MMCS → LZFSE → SQLite
    /// (<c>Assets</c>/<c>FileMetadata</c>), non protobuf.
    /// </summary>
    public const int FileListEncodingSqlite = 2;

    /// <summary>Alias storico (encoding=2 ≠ protobuf).</summary>
    public const int FileListEncodingProtobuf = FileListEncodingSqlite;

    /// <summary>
    /// Gruppo 1 = wire <c>A:pref4:…</c>. L’eventuale lettera prima di <c>A:</c> è il
    /// length-byte protobuf (illusione KA/MA/LA), non parte del nome.
    /// </summary>
    private static readonly Regex AssetRecordNameRegex = new(
        @"(?:[A-Z])?(A:[a-z0-9]{4}:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}:[A-Za-z0-9+/=_-]{6,120}=:\d+)",
        RegexOptions.Compiled);

    private static readonly Regex NRecordNameRegex = new(
        @"N:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}:[A-Za-z0-9+/=_-]{4,80}=:0",
        RegexOptions.Compiled);

    /// <summary>Descrittore MMCS del campo <c>fileList</c> (non il blob espanso).</summary>
    public sealed record FileListAsset(
        string DomainName,
        int Encoding,
        long SizeBytes,
        string SignatureHex,
        string? Token17Hex,
        string MmcsAuthHeader,
        string? ProtectionWrapHex,
        string? ContentBaseUrl,
        string? OwnerDsid,
        string? AssetReferenceUuid,
        string? SourceNRecordName);

    /// <summary>Un record Domain dalla retrieve N:.</summary>
    public sealed record DomainRecord(
        string? RecordName,
        string DomainName,
        /// <summary>Campo <c>domain</c> tipicamente ENCRYPTED (type≠STRING) — bytes grezzi se presenti.</summary>
        byte[]? EncryptedDomain,
        long Version,
        long CumulativeFileCount,
        long CumulativeDirectoryCount,
        long CumulativeAssetCount,
        long CumulativeEmptyFileCount,
        long CumulativeSymLinkCount,
        int? FileListEncoding,
        FileListAsset? FileList,
        IReadOnlyList<string> NewAssetRecordNames,
        IReadOnlyList<string> DeletedAssetRecordNames,
        /// <summary>
        /// Finestra wire del record <c>N:</c> (tagliata) per unwrap ProtectionInfo / MMCS KEK.
        /// </summary>
        byte[]? RecordWindow);

    /// <summary>Parsa tutti i Domain dai payload N: (merged o singoli).</summary>
    public static IReadOnlyList<DomainRecord> ParseDomains(params byte[]?[] payloads)
    {
        var results = new List<DomainRecord>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var payload in payloads)
        {
            if (payload is not { Length: > 0 })
                continue;

            foreach (var record in ParseOne(payload))
            {
                var key = record.FileList?.SignatureHex
                          ?? $"{record.RecordName}|{record.DomainName}";
                if (!seen.Add(key))
                    continue;
                results.Add(record);
            }
        }

        return results;
    }

    /// <summary>Solo gli Asset <c>fileList</c> con auth MMCS valida.</summary>
    public static IReadOnlyList<FileListAsset> Parse(params byte[]?[] payloads) =>
        ParseDomains(payloads)
            .Select(static r => r.FileList)
            .Where(static f => f is not null)
            .Cast<FileListAsset>()
            .ToList();

    private static List<DomainRecord> ParseOne(byte[] data)
    {
        var nPositions = FindNRecordStarts(data);
        var results = new List<DomainRecord>(nPositions.Count);

        for (var i = 0; i < nPositions.Count; i++)
        {
            var start = nPositions[i].Offset;
            var end = i + 1 < nPositions.Count ? nPositions[i + 1].Offset : data.Length;
            var windowLen = end - start;
            if (windowLen < 64)
                continue;

            var window = new byte[windowLen];
            Buffer.BlockCopy(data, start, window, 0, windowLen);

            var domainNameTag = Encoding.ASCII.GetBytes("domainName");
            var domainNamePos = IndexOfFieldName(window, domainNameTag);
            if (domainNamePos < 0)
                continue;

            var domainTyped = TryReadSiblingTypedValue(window, domainNamePos, domainNameTag.Length);
            var domainName = domainTyped is null ? null : TryReadStringValue(domainTyped);
            if (string.IsNullOrWhiteSpace(domainName))
                continue;

            var recordName = nPositions[i].Name;
            var encryptedDomain = TryReadEncryptedDomain(window);
            var version = TryReadNamedInt(window, "version") ?? 0;
            var fileCount = TryReadNamedInt(window, "cumulativeFileCount") ?? 0;
            var dirCount = TryReadNamedInt(window, "cumulativeDirectoryCount") ?? 0;
            var assetCount = TryReadNamedInt(window, "cumulativeAssetCount") ?? 0;
            var emptyCount = TryReadNamedInt(window, "cumulativeEmptyFileCount") ?? 0;
            var symlinkCount = TryReadNamedInt(window, "cumulativeSymLinkCount") ?? 0;
            var encoding = (int?)TryReadNamedInt(window, "fileListEncoding");

            var fileList = TryParseFileListAsset(
                window,
                domainName,
                encoding ?? FileListEncodingProtobuf,
                recordName);

            var newAssets = ExtractAssetRecordNames(window, "newAssets");
            var deletedAssets = ExtractAssetRecordNames(window, "deletedAssets");

            // PI all'inizio; fileList/newAssets cifrati possono stare oltre 8 KB — serve
            // abbastanza finestra per DecryptFields PCS (cap 256 KB per dominio).
            var recordWindow = window.Length <= 262_144
                ? window
                : window.AsSpan(0, 262_144).ToArray();

            results.Add(new DomainRecord(
                RecordName: recordName,
                DomainName: domainName,
                EncryptedDomain: encryptedDomain,
                Version: version,
                CumulativeFileCount: fileCount,
                CumulativeDirectoryCount: dirCount,
                CumulativeAssetCount: assetCount,
                CumulativeEmptyFileCount: emptyCount,
                CumulativeSymLinkCount: symlinkCount,
                FileListEncoding: encoding,
                FileList: fileList,
                NewAssetRecordNames: newAssets,
                DeletedAssetRecordNames: deletedAssets,
                RecordWindow: recordWindow));
        }

        return results;
    }

    private static List<(int Offset, string Name)> FindNRecordStarts(byte[] data)
    {
        var list = new List<(int, string)>();
        var text = Encoding.Latin1.GetString(data);
        foreach (Match m in NRecordNameRegex.Matches(text))
            list.Add((m.Index, m.Value));
        return list;
    }

    /// <summary>
    /// Parsa un CKAsset <c>fileList</c> da plaintext PCS (Value tipizzato, Asset raw, o finestra).
    /// </summary>
    public static FileListAsset? TryParseFileListFromDecrypted(
        byte[] plain,
        string domainName,
        int encoding = FileListEncodingSqlite,
        string? sourceN = null)
    {
        if (plain is not { Length: > 16 })
            return null;

        // 1) Value tipizzato CloudKit / Asset message diretto.
        var fromTyped = TryBuildFileListAsset(
            TryReadAssetMessage(plain) ?? plain, domainName, encoding, sourceN);
        if (fromTyped is not null)
            return fromTyped;

        // 2) Finestra con tag fileList / Asset annidato (post-decrypt di "domain").
        return TryParseFileListAsset(plain, domainName, encoding, sourceN);
    }

    /// <summary>Estrae nomi wire <c>A:pref4:rid</c> da plaintext PCS (newAssets/deletedAssets).</summary>
    public static IReadOnlyList<string> ExtractAssetRecordNamesFromBytes(byte[] data)
    {
        if (data is not { Length: > 8 })
            return [];
        var names = new List<string>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in AssetRecordNameRegex.Matches(Encoding.Latin1.GetString(data)))
        {
            var name = CloudKitMmcsIds.ToPrivilegedBatchWireName(m.Groups[1].Value)
                       ?? m.Groups[1].Value;
            if (seen.Add(name))
                names.Add(name);
        }

        return names;
    }

    private static FileListAsset? TryParseFileListAsset(
        byte[] window,
        string domainName,
        int encoding,
        string? sourceN)
    {
        var tag = Encoding.ASCII.GetBytes("fileList");
        foreach (var pos in FindAllFieldNames(window, tag))
        {
            var typed = TryReadSiblingTypedValue(window, pos, tag.Length);
            if (typed is null)
                continue;

            var asset = TryReadAssetMessage(typed);
            if (asset is null)
                continue;

            var built = TryBuildFileListAsset(asset, domainName, encoding, sourceN);
            if (built is not null)
                return built;
        }

        return null;
    }

    private static FileListAsset? TryBuildFileListAsset(
        byte[] asset,
        string domainName,
        int encoding,
        string? sourceN)
    {
        var sig = GetBytesField(asset, 2);
        var token17 = GetBytesField(asset, 17);
        var caog = GetBytesField(asset, 5);
        if (sig is not { Length: 21 } || caog is null || caog.Length < 16)
            return null;

        var caogText = Encoding.ASCII.GetString(caog);
        if (!caogText.StartsWith("CAog", StringComparison.Ordinal))
            return null;

        var sigHex = Convert.ToHexString(sig).ToLowerInvariant();
        var t17Hex = token17 is { Length: 21 }
            ? Convert.ToHexString(token17).ToLowerInvariant()
            : sigHex;
        var owner = GetBytesField(asset, 1) is { } o
            ? Encoding.ASCII.GetString(o)
            : null;
        var baseUrl = GetBytesField(asset, 8) is { } u
            ? Encoding.ASCII.GetString(u)
            : null;
        var assetUuid = GetBytesField(asset, 21) is { } id
            ? Encoding.ASCII.GetString(id)
            : null;
        var wrap = TryExtractWrap24(GetBytesField(asset, 15));
        var size = GetVarintField(asset, 4) ?? 0;

        return new FileListAsset(
            DomainName: domainName,
            Encoding: encoding,
            SizeBytes: size,
            SignatureHex: sigHex,
            Token17Hex: t17Hex,
            MmcsAuthHeader: $"{sigHex} {t17Hex} {caogText}",
            ProtectionWrapHex: wrap is null
                ? null
                : Convert.ToHexString(wrap).ToLowerInvariant(),
            ContentBaseUrl: baseUrl,
            OwnerDsid: owner,
            AssetReferenceUuid: assetUuid,
            SourceNRecordName: sourceN);
    }

    private static IReadOnlyList<string> ExtractAssetRecordNames(byte[] window, string fieldName)
    {
        var tag = Encoding.ASCII.GetBytes(fieldName);
        var pos = IndexOfFieldName(window, tag);
        if (pos < 0)
            return [];

        var typed = TryReadSiblingTypedValue(window, pos, tag.Length);
        if (typed is null || typed.Length == 0)
            return [];

        return ExtractAssetRecordNamesFromBytes(typed);
    }

    private static byte[]? TryReadEncryptedDomain(byte[] window)
    {
        // Campo "domain" (len=6), non "domainName".
        var tag = Encoding.ASCII.GetBytes("domain");
        for (var i = 0; i <= window.Length - tag.Length - 2; i++)
        {
            if (!IsFieldNameAt(window, i, tag))
                continue;
            // Evita match come prefisso di domainName: dopo il nome deve esserci 0x12.
            var afterName = i + 1;
            if (!TryReadVarint(window, ref afterName, out var nameLen) || (int)nameLen != tag.Length)
                continue;
            afterName += tag.Length;
            if (afterName >= window.Length || window[afterName] != 0x12)
                continue;

            var typed = TryReadSiblingTypedValue(window, i, tag.Length);
            if (typed is null)
                return null;

            // STRING (type=3) → il nome chiaro è in domainName; qui serve il blob cifrato.
            var type = GetVarintField(typed, 1);
            if (type is 3)
                return null;

            var fields = ReadFields(typed);
            if (fields.TryGetValue(2, out var payload) && payload.Length > 0)
                return payload;
            return typed;
        }

        return null;
    }

    private static long? TryReadNamedInt(byte[] window, string fieldName)
    {
        var tag = Encoding.ASCII.GetBytes(fieldName);
        var pos = IndexOfFieldName(window, tag);
        if (pos < 0)
            return null;
        var typed = TryReadSiblingTypedValue(window, pos, tag.Length);
        return typed is null ? null : TryReadIntValue(typed);
    }

    private static List<int> FindAllFieldNames(byte[] data, byte[] name)
    {
        var list = new List<int>();
        for (var i = 0; i <= data.Length - name.Length - 2; i++)
        {
            if (IsFieldNameAt(data, i, name))
                list.Add(i);
        }

        return list;
    }

    private static int IndexOfFieldName(byte[] window, byte[] name)
    {
        for (var i = 0; i <= window.Length - name.Length - 2; i++)
        {
            if (IsFieldNameAt(window, i, name))
                return i;
        }

        return -1;
    }

    private static bool IsFieldNameAt(byte[] data, int index, byte[] name)
    {
        if (index + 2 + name.Length > data.Length)
            return false;
        if (data[index] != 0x0a)
            return false;
        var i = index + 1;
        if (!TryReadVarint(data, ref i, out var len) || (int)len != name.Length)
            return false;
        for (var k = 0; k < name.Length; k++)
        {
            if (data[i + k] != name[k])
                return false;
        }

        return true;
    }

    private static byte[]? TryReadSiblingTypedValue(byte[] data, int namePos, int nameLen)
    {
        var i = namePos + 1;
        if (!TryReadVarint(data, ref i, out _) || i + nameLen > data.Length)
            return null;
        i += nameLen;
        if (i >= data.Length || data[i] != 0x12)
            return null;
        i++;
        if (!TryReadVarint(data, ref i, out var len) || len > (ulong)(data.Length - i))
            return null;
        return data.AsSpan(i, (int)len).ToArray();
    }

    private static byte[]? TryReadAssetMessage(byte[] typedValue)
    {
        var type = GetVarintField(typedValue, 1);
        if (type is not null and not 6)
            return null;

        var fields = ReadFields(typedValue);
        if (fields.TryGetValue(10, out var asset))
            return asset;
        if (fields.ContainsKey(2) && fields.ContainsKey(5))
            return typedValue;
        return null;
    }

    private static string? TryReadStringValue(byte[] typedValue)
    {
        var fields = ReadFields(typedValue);
        if (fields.TryGetValue(7, out var s) && s.Length > 0)
            return Encoding.UTF8.GetString(s);
        foreach (var kv in fields)
        {
            if (kv.Value.Length is >= 4 and <= 200
                && kv.Value[0] is >= (byte)'A' and <= (byte)'z')
                return Encoding.UTF8.GetString(kv.Value);
        }

        return null;
    }

    private static long? TryReadIntValue(byte[] typedValue)
    {
        var i = 0;
        long? found = null;
        while (i < typedValue.Length)
        {
            if (!TryReadVarint(typedValue, ref i, out var tag))
                break;
            var fn = (int)(tag >> 3);
            var wt = (int)(tag & 7);
            if (wt == 0)
            {
                if (!TryReadVarint(typedValue, ref i, out var v))
                    break;
                if (fn is 2 or 4)
                    found = (long)v;
            }
            else if (wt == 2)
            {
                if (!TryReadVarint(typedValue, ref i, out var len)
                    || len > (ulong)(typedValue.Length - i))
                    break;
                i += (int)len;
            }
            else if (wt == 5)
                i += 4;
            else if (wt == 1)
                i += 8;
            else
                break;
        }

        return found;
    }

    private static byte[]? GetBytesField(byte[] msg, int field)
    {
        var fields = ReadFields(msg);
        return fields.TryGetValue(field, out var v) ? v : null;
    }

    private static long? GetVarintField(byte[] msg, int field)
    {
        var i = 0;
        while (i < msg.Length)
        {
            if (!TryReadVarint(msg, ref i, out var tag))
                break;
            var fn = (int)(tag >> 3);
            var wt = (int)(tag & 7);
            if (wt == 0)
            {
                if (!TryReadVarint(msg, ref i, out var v))
                    break;
                if (fn == field)
                    return (long)v;
            }
            else if (wt == 2)
            {
                if (!TryReadVarint(msg, ref i, out var len)
                    || len > (ulong)(msg.Length - i))
                    break;
                i += (int)len;
            }
            else if (wt == 5)
                i += 4;
            else if (wt == 1)
                i += 8;
            else
                break;
        }

        return null;
    }

    private static byte[]? TryExtractWrap24(byte[]? protectionInfo)
    {
        if (protectionInfo is null)
            return null;
        var fields = ReadFields(protectionInfo);
        if (fields.TryGetValue(1, out var wrap) && wrap.Length == 24)
            return wrap;
        if (protectionInfo.Length == 24)
            return protectionInfo;
        return MmcsAssetProtection.TryExtract(protectionInfo);
    }

    private static Dictionary<int, byte[]> ReadFields(byte[] buffer)
    {
        var fields = new Dictionary<int, byte[]>();
        var index = 0;
        while (index < buffer.Length)
        {
            if (!TryReadVarint(buffer, ref index, out var tag))
                break;
            var fieldNumber = (int)(tag >> 3);
            var wire = (int)(tag & 7);
            switch (wire)
            {
                case 0:
                    if (!TryReadVarint(buffer, ref index, out _))
                        return fields;
                    break;
                case 1:
                    index += 8;
                    break;
                case 2:
                    if (!TryReadVarint(buffer, ref index, out var len)
                        || len > (ulong)(buffer.Length - index))
                        return fields;
                    if (!fields.ContainsKey(fieldNumber))
                        fields[fieldNumber] = buffer.AsSpan(index, (int)len).ToArray();
                    index += (int)len;
                    break;
                case 5:
                    index += 4;
                    break;
                default:
                    return fields;
            }
        }

        return fields;
    }

    private static bool TryReadVarint(byte[] data, ref int index, out ulong value)
    {
        value = 0;
        var shift = 0;
        while (index < data.Length && shift < 64)
        {
            var b = data[index++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
        }

        return false;
    }
}
