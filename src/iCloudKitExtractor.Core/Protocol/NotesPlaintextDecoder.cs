using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Dopo PCS GCM: decodifica payload Notes (mergeable protobuf / CRDT map)
/// e campi BeaconStore/Find My (pairingDate, stringhe length-prefixed).
/// </summary>
public static class NotesPlaintextDecoder
{
    /// <summary>Apple CFAbsoluteTime epoch: 2001-01-01 UTC.</summary>
    private static readonly DateTimeOffset AppleEpoch =
        new(2001, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public sealed record DecodeResult(byte[] Processed, string? TextPreview);

    public static DecodeResult DecodeField(string fieldName, byte[] plain)
    {
        if (plain is not { Length: > 0 })
            return new DecodeResult(plain ?? [], null);

        if (fieldName.Equals("pairingDate", StringComparison.OrdinalIgnoreCase))
        {
            if (TryDecodePairingDate(plain, out var iso))
                return new DecodeResult(plain, iso);
        }

        if (fieldName.Contains("TextData", StringComparison.OrdinalIgnoreCase)
            || fieldName.Contains("StandardizedContent", StringComparison.OrdinalIgnoreCase)
            || fieldName.Contains("DisplayText", StringComparison.OrdinalIgnoreCase))
        {
            var expanded = MaybeInflate(plain);
            var text = ExtractNoteBodyText(expanded);
            return new DecodeResult(expanded, text);
        }

        if (fieldName.Contains("Title", StringComparison.OrdinalIgnoreCase)
            || fieldName.Contains("Snippet", StringComparison.OrdinalIgnoreCase))
        {
            var expanded = MaybeInflate(plain);
            if (TryDecodeLengthPrefixedUtf8(expanded, out var titled) && IsPlausibleNoteTitle(titled))
                return new DecodeResult(expanded, titled);
            if (LooksLikeUtf8Text(expanded))
            {
                var t = Encoding.UTF8.GetString(expanded).TrimEnd('\0').Trim();
                if (IsPlausibleNoteTitle(t))
                    return new DecodeResult(expanded, t);
            }

            // Titolo = prima riga utile del documento, non il run UTF-8 più lungo
            // (altrimenti CRDT concatena frammenti tipo "Running plugs…").
            var firstLine = ExtractFirstPlausibleTitle(expanded);
            if (IsPlausibleNoteTitle(firstLine))
                return new DecodeResult(expanded, firstLine);
            return new DecodeResult(expanded, null);
        }

        if (fieldName.Contains("ReplicaID", StringComparison.OrdinalIgnoreCase))
        {
            // Metadati CRDT — mai usare come corpo nota nel viewer.
            var preview = SummarizeReplicaMap(plain);
            return new DecodeResult(plain, preview);
        }

        if (fieldName.Contains("MergeablePreferredViewSize", StringComparison.OrdinalIgnoreCase))
        {
            var preview = TryDecodeViewSize(plain);
            return new DecodeResult(plain, preview);
        }

        // BeaconStore: stringhe protobuf length-prefixed (es. 0x32 len utf8).
        if (TryDecodeLengthPrefixedUtf8(plain, out var ckStr) && !string.IsNullOrWhiteSpace(ckStr))
            return new DecodeResult(plain, ckStr);

        if (LooksLikeUtf8Text(plain))
            return new DecodeResult(plain, Encoding.UTF8.GetString(plain).TrimEnd('\0').Trim());

        return new DecodeResult(plain, null);
    }

    /// <summary>
    /// BeaconStore <c>pairingDate</c>: <c>2a 09 09 ‖ f64-LE CFAbsoluteTime</c>
    /// (field5 len-delimited → field1 fixed64).
    /// </summary>
    public static bool TryDecodePairingDate(ReadOnlySpan<byte> plain, out string? iso)
    {
        iso = null;
        if (TryReadCfAbsoluteDouble(plain, out var seconds))
        {
            iso = AppleEpoch.AddSeconds(seconds)
                .ToString("yyyy-MM-ddTHH:mm:ss.fffZ", CultureInfo.InvariantCulture);
            return true;
        }

        return false;
    }

    private static bool TryReadCfAbsoluteDouble(ReadOnlySpan<byte> data, out double seconds)
    {
        seconds = 0;
        // Canonical: 2a 09 09 <8 bytes LE double>
        if (data.Length >= 11
            && data[0] == 0x2a
            && data[1] == 0x09
            && data[2] == 0x09)
        {
            seconds = BinaryPrimitives.ReadDoubleLittleEndian(data.Slice(3, 8));
            return IsPlausibleCfAbs(seconds);
        }

        // Bare field1 fixed64: 09 <8 bytes>
        if (data.Length >= 9 && data[0] == 0x09)
        {
            seconds = BinaryPrimitives.ReadDoubleLittleEndian(data.Slice(1, 8));
            return IsPlausibleCfAbs(seconds);
        }

        // Raw 8-byte double
        if (data.Length == 8)
        {
            seconds = BinaryPrimitives.ReadDoubleLittleEndian(data);
            return IsPlausibleCfAbs(seconds);
        }

        return false;
    }

    private static bool IsPlausibleCfAbs(double seconds) =>
        seconds is > 100_000_000 and < 2_000_000_000; // ~2004–2064

    /// <summary>Protobuf wire string: tag(optional) ‖ len ‖ utf8.</summary>
    private static bool TryDecodeLengthPrefixedUtf8(ReadOnlySpan<byte> plain, out string text)
    {
        text = "";
        if (plain.Length < 2)
            return false;

        // Common CK string: field 6 (0x32) / field 2 (0x12) / field 1 (0x0a)
        var i = 0;
        if (plain[0] is 0x0a or 0x12 or 0x1a or 0x22 or 0x2a or 0x32)
        {
            i = 1;
            if (!TryReadVarint(plain, ref i, out var len))
                return false;
            if (len == 0 || len > (ulong)(plain.Length - i) || len > 512)
                return false;
            var slice = plain.Slice(i, (int)len);
            if (slice.Length == 1 && slice[0] == 0)
                return false; // empty placeholder "\0"
            if (!LooksLikeUtf8Text(slice))
                return false;
            text = Encoding.UTF8.GetString(slice).TrimEnd('\0').Trim();
            // Strip leading CloudKit type markers like "2$"
            if (text.StartsWith("2$", StringComparison.Ordinal))
                text = text[2..];
            else if (text.StartsWith("$", StringComparison.Ordinal))
                text = text[1..];
            return text.Length > 0;
        }

        return false;
    }

    /// <summary>
    /// Corpo nota: concatena tutti i run UTF-8 in ordine (non solo il più lungo),
    /// altrimenti paragrafi multipli risultano tagliati.
    /// </summary>
    public static string? ExtractNoteBodyText(ReadOnlySpan<byte> data)
    {
        data = MaybeInflate(data);
        var parts = new List<string>();
        CollectUtf8TextParts(data, parts, depth: 0);
        if (parts.Count == 0)
        {
            CollectUtf8Runs(data, parts);
            if (parts.Count == 0)
                return null;
        }

        var joined = JoinNoteParts(parts);
        return SanitizeNoteText(joined);
    }

    /// <summary>Estrae blocchi UTF-8 embedded nel mergeable protobuf Notes (il più lungo).</summary>
    public static string? ExtractLongestUtf8Text(ReadOnlySpan<byte> data)
    {
        var parts = new List<string>();
        CollectUtf8TextParts(data, parts, depth: 0);
        if (parts.Count == 0)
            return null;
        return parts.OrderByDescending(static p => p.Length).First();
    }

    /// <summary>Scan grezzo di run stampabili — recupera corpi quando il walk protobuf si interrompe.</summary>
    public static string? ExtractLongestUtf8Run(ReadOnlySpan<byte> data)
    {
        var parts = new List<string>();
        CollectUtf8Runs(data, parts);
        return parts.Count == 0 ? null : parts.OrderByDescending(static p => p.Length).First();
    }

    private static void CollectUtf8TextParts(ReadOnlySpan<byte> data, List<string> parts, int depth)
    {
        if (depth > 12 || data.Length == 0)
            return;

        var i = 0;
        while (i < data.Length)
        {
            if (!TryReadVarint(data, ref i, out var tag))
                break;

            var wireType = (int)(tag & 7);
            switch (wireType)
            {
                case 0:
                    if (!TryReadVarint(data, ref i, out _))
                        return;
                    break;
                case 1:
                    if (i + 8 > data.Length)
                        return;
                    i += 8;
                    break;
                case 2:
                    if (!TryReadVarint(data, ref i, out var len))
                        return;
                    if (len > (ulong)(data.Length - i))
                        return;
                    var chunk = data.Slice(i, (int)len);
                    i += (int)len;
                    var before = parts.Count;
                    CollectUtf8TextParts(chunk, parts, depth + 1);
                    if (parts.Count == before)
                    {
                        var direct = TryDecodeUtf8Text(chunk);
                        if (direct is not null
                            && IsPlausibleNoteBody(direct)
                            && !LooksLikeTypeName(direct))
                            AddUniquePart(parts, direct);
                    }

                    break;
                case 5:
                    if (i + 4 > data.Length)
                        return;
                    i += 4;
                    break;
                default:
                    return;
            }
        }
    }

    private static void CollectUtf8Runs(ReadOnlySpan<byte> data, List<string> parts)
    {
        var start = -1;
        for (var i = 0; i <= data.Length; i++)
        {
            var ok = i < data.Length && IsTextByte(data[i]);
            if (ok)
            {
                if (start < 0)
                    start = i;
                continue;
            }

            if (start >= 0)
            {
                var len = i - start;
                if (len >= 4)
                {
                    var slice = data.Slice(start, len);
                    if (LooksLikeUtf8Text(slice))
                    {
                        var text = Encoding.UTF8.GetString(slice).TrimEnd('\0').Trim();
                        if (IsPlausibleNoteBody(text) && !LooksLikeTypeName(text))
                            AddUniquePart(parts, text);
                    }
                }

                start = -1;
            }
        }
    }

    private static string? ExtractFirstPlausibleTitle(ReadOnlySpan<byte> data)
    {
        var parts = new List<string>();
        CollectUtf8TextParts(data, parts, depth: 0);
        if (parts.Count == 0)
            CollectUtf8Runs(data, parts);
        foreach (var p in parts)
        {
            var line = p.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault()?.Trim();
            if (IsPlausibleNoteTitle(line) && line!.Length <= 200)
                return line;
        }

        return null;
    }

    private static string JoinNoteParts(IReadOnlyList<string> parts)
    {
        if (parts.Count == 1)
            return parts[0];

        var sb = new StringBuilder();
        string? prev = null;
        foreach (var part in parts)
        {
            if (string.IsNullOrWhiteSpace(part))
                continue;
            if (prev is not null
                && (part.StartsWith(prev, StringComparison.Ordinal)
                    || prev.StartsWith(part, StringComparison.Ordinal)))
            {
                // Preferisci la variante più lunga se una contiene l'altra.
                if (part.Length > prev.Length)
                {
                    sb.Length = Math.Max(0, sb.Length - prev.Length);
                    if (sb.Length > 0 && sb[^1] != '\n')
                        sb.Append('\n');
                    sb.Append(part);
                    prev = part;
                }

                continue;
            }

            if (sb.Length > 0)
                sb.Append('\n');
            sb.Append(part);
            prev = part;
        }

        return sb.ToString();
    }

    private static void AddUniquePart(List<string> parts, string text)
    {
        if (parts.Count > 0
            && string.Equals(parts[^1], text, StringComparison.Ordinal))
            return;
        parts.Add(text);
    }

    private static byte[] MaybeInflate(byte[] data)
    {
        if (TryGunzip(data, out var gz))
            return gz;
        if (TryZlib(data, out var zl))
            return zl;
        return data;
    }

    private static ReadOnlySpan<byte> MaybeInflate(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 3 && data[0] == 0x1f && data[1] == 0x8b)
        {
            var arr = data.ToArray();
            if (TryGunzip(arr, out var gz))
                return gz;
        }

        if (data.Length >= 2 && data[0] == 0x78)
        {
            var arr = data.ToArray();
            if (TryZlib(arr, out var zl))
                return zl;
        }

        return data;
    }

    private static bool TryGunzip(byte[] data, out byte[] plain)
    {
        plain = [];
        if (data.Length < 3 || data[0] != 0x1f || data[1] != 0x8b)
            return false;
        try
        {
            using var ms = new MemoryStream(data);
            using var gz = new GZipStream(ms, CompressionMode.Decompress);
            using var outMs = new MemoryStream();
            gz.CopyTo(outMs);
            plain = outMs.ToArray();
            return plain.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryZlib(byte[] data, out byte[] plain)
    {
        plain = [];
        if (data.Length < 2 || data[0] != 0x78)
            return false;
        try
        {
            using var ms = new MemoryStream(data);
            using var zlib = new ZLibStream(ms, CompressionMode.Decompress);
            using var outMs = new MemoryStream();
            zlib.CopyTo(outMs);
            plain = outMs.ToArray();
            return plain.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool LooksLikeTypeName(string text) =>
        text.Contains("com.apple.", StringComparison.OrdinalIgnoreCase)
        || text.Contains("ICCloudSyncing", StringComparison.OrdinalIgnoreCase)
        || text.StartsWith("replica-map", StringComparison.OrdinalIgnoreCase);

    public static bool IsReplicaMapPreview(string? text) =>
        !string.IsNullOrWhiteSpace(text)
        && (text.StartsWith("replica-map", StringComparison.OrdinalIgnoreCase)
            || text.Contains("ICCloudSyncingObject", StringComparison.OrdinalIgnoreCase)
            || text.Contains("com.apple.notes.IC", StringComparison.OrdinalIgnoreCase));

    private static bool IsPlausibleNoteTitle(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || IsReplicaMapPreview(text))
            return false;
        if (text.Length > 400)
            return false;
        return CountLetters(text) >= 1 || text.Any(char.IsDigit);
    }

    private static bool IsPlausibleNoteBody(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || IsReplicaMapPreview(text))
            return false;
        if (text.StartsWith("viewSize", StringComparison.OrdinalIgnoreCase))
            return false;
        return CountLetters(text) >= 2 || text.Contains('\n');
    }

    private static string? SanitizeNoteText(string? text)
    {
        if (string.IsNullOrWhiteSpace(text) || IsReplicaMapPreview(text))
            return null;
        return text.Trim();
    }

    private static int CountLetters(string text)
    {
        var n = 0;
        foreach (var c in text)
            if (char.IsLetter(c))
                n++;
        return n;
    }

    private static bool IsTextByte(byte b) =>
        b is 9 or 10 or 13 || b is >= 32 and < 127 || b >= 128;

    private static string? SummarizeReplicaMap(ReadOnlySpan<byte> data)
    {
        var entries = CountTopLevelLengthDelimited(data);
        var typeHint = ExtractTypeHints(data);
        if (entries <= 0 && string.IsNullOrEmpty(typeHint))
            return null;
        return entries > 0
            ? $"replica-map entries={entries}{typeHint}"
            : typeHint;
    }

    private static string ExtractTypeHints(ReadOnlySpan<byte> data)
    {
        var text = Encoding.UTF8.GetString(data);
        const string marker = "com.apple.notes.";
        var idx = text.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0)
            return "";
        var end = idx;
        while (end < text.Length && text[end] is not ('*' or '\0' or '\n' or '\r'))
            end++;
        var slice = text[idx..end].Trim();
        return slice.Length > 0 ? $" ({slice})" : "";
    }

    private static int CountTopLevelLengthDelimited(ReadOnlySpan<byte> data)
    {
        var count = 0;
        var i = 0;
        while (i < data.Length)
        {
            if (!TryReadVarint(data, ref i, out var tag))
                break;
            var wireType = (int)(tag & 7);
            switch (wireType)
            {
                case 0:
                    if (!TryReadVarint(data, ref i, out _))
                        return count;
                    break;
                case 1:
                    i += 8;
                    break;
                case 2:
                    if (!TryReadVarint(data, ref i, out var len))
                        return count;
                    if (len > (ulong)(data.Length - i))
                        return count;
                    count++;
                    i += (int)len;
                    break;
                case 5:
                    i += 4;
                    break;
                default:
                    return count;
            }
        }

        return count;
    }

    private static string? TryDecodeViewSize(ReadOnlySpan<byte> data)
    {
        var i = 0;
        double? size = null;
        int? nested = null;
        while (i < data.Length)
        {
            if (!TryReadVarint(data, ref i, out var tag))
                break;
            var field = (int)(tag >> 3);
            var wireType = (int)(tag & 7);
            switch (wireType)
            {
                case 0:
                    if (!TryReadVarint(data, ref i, out var v))
                        return FormatViewSize(size, nested);
                    if (field == 1)
                        nested = (int)v;
                    break;
                case 1:
                    if (i + 8 > data.Length)
                        return FormatViewSize(size, nested);
                    if (field == 1)
                        size = BitConverter.Int64BitsToDouble(BitConverter.ToInt64(data.Slice(i, 8)));
                    i += 8;
                    break;
                case 2:
                    if (!TryReadVarint(data, ref i, out var len) || len > (ulong)(data.Length - i))
                        return FormatViewSize(size, nested);
                    i += (int)len;
                    break;
                case 5:
                    i += 4;
                    break;
                default:
                    return FormatViewSize(size, nested);
            }
        }

        return FormatViewSize(size, nested);
    }

    private static string? FormatViewSize(double? size, int? nested) =>
        size is not null
            ? $"viewSize={size:0.###}"
            : nested is not null
                ? $"viewSizeCode={nested}"
                : null;

    private static string? TryDecodeUtf8Text(ReadOnlySpan<byte> chunk)
    {
        if (chunk.Length < 2)
            return null;
        if (!LooksLikeUtf8Text(chunk))
            return null;
        var text = Encoding.UTF8.GetString(chunk).TrimEnd('\0').Trim();
        if (text.Length < 2)
            return null;
        var letters = 0;
        foreach (var c in text)
            if (char.IsLetter(c))
                letters++;
        return letters >= 2 ? text : null;
    }

    private static bool LooksLikeUtf8Text(ReadOnlySpan<byte> data)
    {
        if (data.Length == 0 || data.Length > 512_000)
            return false;
        var printable = 0;
        foreach (var b in data)
        {
            if (b is 9 or 10 or 13 || b is >= 32 and < 127)
                printable++;
            else if (b >= 128)
                printable++;
            else
                return false;
        }

        return printable >= data.Length * 0.85;
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> data, ref int pos, out ulong value)
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
