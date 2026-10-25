using System.Buffers.Binary;
using System.Collections;
using System.IO;
using System.Text;

namespace iCloudKitExtractor.Protocol;

/// <summary>Riferimento UID bplist (NSKeyedArchive <c>$top</c> → <c>$objects</c>).</summary>
public readonly record struct PlistUid(ulong Value);

/// <summary>
/// Parser minimale bplist00 (Apple binary property list).
/// Sufficiente per metadata escrow SecureBackup / PCS.
/// </summary>
public static class AppleBinaryPlist
{
    public static bool TryParse(ReadOnlySpan<byte> data, out object? root, out string? error)
    {
        root = null;
        error = null;
        if (data.Length < 40 || !data[..6].SequenceEqual("bplist"u8))
        {
            error = "magic bplist assente";
            return false;
        }

        try
        {
            var trailer = data[^32..];
            var offsetSize = trailer[6];
            var objectRefSize = trailer[7];
            var numObjects = BinaryPrimitives.ReadInt64BigEndian(trailer[8..16]);
            var topObject = BinaryPrimitives.ReadInt64BigEndian(trailer[16..24]);
            var offsetTableOffset = BinaryPrimitives.ReadInt64BigEndian(trailer[24..32]);

            if (offsetSize is < 1 or > 8 || objectRefSize is < 1 or > 8)
            {
                error = $"trailer sizes invalidi offset={offsetSize} ref={objectRefSize}";
                return false;
            }

            if (numObjects <= 0 || numObjects > 1_000_000)
            {
                error = $"numObjects fuori range ({numObjects})";
                return false;
            }

            if (offsetTableOffset < 8 || offsetTableOffset >= data.Length - 32)
            {
                error = $"offsetTableOffset fuori range ({offsetTableOffset})";
                return false;
            }

            var offsets = new long[numObjects];
            for (var i = 0; i < numObjects; i++)
            {
                var at = offsetTableOffset + i * offsetSize;
                if (at < 0 || at + offsetSize > data.Length)
                {
                    error = "offset table troncata";
                    return false;
                }

                offsets[i] = ReadSizedInt(data.Slice((int)at, offsetSize));
            }

            if (topObject < 0 || topObject >= numObjects)
            {
                error = $"topObject fuori range ({topObject})";
                return false;
            }

            var cache = new object?[numObjects];
            root = ReadObject(data, offsets, objectRefSize, topObject, cache, depth: 0);
            return true;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    public static bool TryParseDict(
        ReadOnlySpan<byte> data,
        out Dictionary<string, object?> dict,
        out string? error)
    {
        dict = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (!TryParse(data, out var root, out error))
            return false;
        if (root is not Dictionary<string, object?> d)
        {
            error = $"radice non è dict ({root?.GetType().Name})";
            return false;
        }

        dict = d;
        return true;
    }

    /// <summary>
    /// Serializza un oggetto CLR in bplist00 (dict/array/string/int/bool/date/data).
    /// </summary>
    public static byte[] Write(object? root)
    {
        var objects = new List<object?>();
        var seen = new Dictionary<object, int>(ReferenceEqualityComparer.Instance);
        Collect(root, objects, seen);

        var payloads = new List<byte[]>(objects.Count);
        for (var i = 0; i < objects.Count; i++)
            payloads.Add(EncodeObject(objects[i], objects, seen));

        var offsetSize = 1;
        long tentative = 8;
        foreach (var p in payloads)
            tentative += p.Length;
        tentative += (long)objects.Count; // worst-case ref size growth loop below
        while (1L << (8 * offsetSize) <= tentative + 32 && offsetSize < 8)
            offsetSize++;

        var objectRefSize = 1;
        while (1L << (8 * objectRefSize) <= objects.Count && objectRefSize < 8)
            objectRefSize++;

        // Rifare encode con objectRefSize definitivo (dict/array usano ref size).
        payloads.Clear();
        for (var i = 0; i < objects.Count; i++)
            payloads.Add(EncodeObject(objects[i], objects, seen, objectRefSize));

        using var ms = new MemoryStream();
        ms.Write("bplist00"u8);
        var offsets = new long[objects.Count];
        for (var i = 0; i < objects.Count; i++)
        {
            offsets[i] = ms.Position;
            ms.Write(payloads[i]);
        }

        var offsetTableOffset = ms.Position;
        foreach (var off in offsets)
            WriteSizedInt(ms, off, offsetSize);

        // Trailer 32 byte
        Span<byte> trailer = stackalloc byte[32];
        trailer.Clear();
        trailer[6] = (byte)offsetSize;
        trailer[7] = (byte)objectRefSize;
        BinaryPrimitives.WriteInt64BigEndian(trailer[8..16], objects.Count);
        BinaryPrimitives.WriteInt64BigEndian(trailer[16..24], 0); // top object = 0
        BinaryPrimitives.WriteInt64BigEndian(trailer[24..32], offsetTableOffset);
        ms.Write(trailer);
        return ms.ToArray();
    }

    private static void Collect(
        object? value,
        List<object?> objects,
        Dictionary<object, int> seen)
    {
        switch (value)
        {
            case null:
                if (objects.Exists(static o => o is null))
                    return;
                objects.Add(null);
                return;
            case string or byte[]:
                if (seen.ContainsKey(value))
                    return;
                seen[value] = objects.Count;
                objects.Add(value);
                return;
            case bool:
            case DateTime:
            case DateTimeOffset:
            case int:
            case long:
            case uint:
            case ulong:
                objects.Add(value);
                return;
            case Dictionary<string, object?> dict:
                if (seen.ContainsKey(dict))
                    return;
                seen[dict] = objects.Count;
                objects.Add(dict);
                foreach (var (k, v) in dict)
                {
                    Collect(k, objects, seen);
                    Collect(v, objects, seen);
                }

                return;
            case IList<object?> list:
                if (seen.ContainsKey(list))
                    return;
                seen[list] = objects.Count;
                objects.Add(list);
                foreach (var item in list)
                    Collect(item, objects, seen);
                return;
            case IList list:
                var boxed = new List<object?>(list.Count);
                foreach (var item in list)
                    boxed.Add(item);
                Collect(boxed, objects, seen);
                return;
            default:
                // Fallback string
                Collect(value.ToString() ?? "", objects, seen);
                return;
        }
    }

    private static int IndexOf(
        object? value,
        List<object?> objects,
        Dictionary<object, int> seen)
    {
        if (value is null)
        {
            for (var i = 0; i < objects.Count; i++)
                if (objects[i] is null)
                    return i;
            throw new InvalidOperationException("null object mancante");
        }

        if (seen.TryGetValue(value, out var idx))
            return idx;

        // Primitivi / value types: scan
        for (var i = 0; i < objects.Count; i++)
        {
            if (Equals(objects[i], value))
                return i;
        }

        throw new InvalidOperationException($"oggetto non indicizzato: {value.GetType().Name}");
    }

    private static byte[] EncodeObject(
        object? value,
        List<object?> objects,
        Dictionary<object, int> seen,
        int objectRefSize = 1)
    {
        switch (value)
        {
            case null:
                return [0x00];
            case bool b:
                return [b ? (byte)0x09 : (byte)0x08];
            case int i:
                return EncodeInteger(i);
            case long l:
                return EncodeInteger(l);
            case uint u:
                return EncodeInteger(u);
            case ulong ul when ul <= long.MaxValue:
                return EncodeInteger((long)ul);
            case string s:
                return EncodeString(s);
            case byte[] data:
                return EncodeData(data);
            case DateTime dt:
                return EncodeDate(new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc)));
            case DateTimeOffset dto:
                return EncodeDate(dto);
            case Dictionary<string, object?> dict:
            {
                using var ms = new MemoryStream();
                WriteMarkerWithCount(ms, 0xD0, dict.Count);
                foreach (var key in dict.Keys)
                    WriteSizedInt(ms, IndexOf(key, objects, seen), objectRefSize);
                foreach (var v in dict.Values)
                    WriteSizedInt(ms, IndexOf(v, objects, seen), objectRefSize);
                return ms.ToArray();
            }
            case IList<object?> list:
            {
                using var ms = new MemoryStream();
                WriteMarkerWithCount(ms, 0xA0, list.Count);
                foreach (var item in list)
                    WriteSizedInt(ms, IndexOf(item, objects, seen), objectRefSize);
                return ms.ToArray();
            }
            default:
                return EncodeString(value.ToString() ?? "");
        }
    }

    private static byte[] EncodeInteger(long value)
    {
        // Sempre unsigned big-endian come Apple (valori positivi tipici nei plist).
        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buf, value);
        var start = 0;
        while (start < 7 && buf[start] == 0)
            start++;
        var len = 8 - start;
        // Apple usa potenze di 2: 1,2,4,8
        var sized = len switch
        {
            1 => 1,
            2 => 2,
            <= 4 => 4,
            _ => 8
        };
        start = 8 - sized;
        var info = sized switch
        {
            1 => 0,
            2 => 1,
            4 => 2,
            _ => 3
        };
        var result = new byte[1 + sized];
        result[0] = (byte)(0x10 | info);
        buf[start..].CopyTo(result.AsSpan(1));
        return result;
    }

    private static byte[] EncodeString(string s)
    {
        var ascii = true;
        foreach (var ch in s)
        {
            if (ch > 0x7F)
            {
                ascii = false;
                break;
            }
        }

        if (ascii)
        {
            var bytes = Encoding.ASCII.GetBytes(s);
            using var ms = new MemoryStream(1 + 5 + bytes.Length);
            WriteMarkerWithCount(ms, 0x50, bytes.Length);
            ms.Write(bytes);
            return ms.ToArray();
        }

        var utf16 = Encoding.BigEndianUnicode.GetBytes(s);
        using var ms16 = new MemoryStream(1 + 5 + utf16.Length);
        WriteMarkerWithCount(ms16, 0x60, utf16.Length / 2);
        ms16.Write(utf16);
        return ms16.ToArray();
    }

    private static byte[] EncodeData(byte[] data)
    {
        using var ms = new MemoryStream(1 + 5 + data.Length);
        WriteMarkerWithCount(ms, 0x40, data.Length);
        ms.Write(data);
        return ms.ToArray();
    }

    private static byte[] EncodeDate(DateTimeOffset dto)
    {
        var appleEpoch = DateTimeOffset.FromUnixTimeSeconds(978307200);
        var seconds = (dto.ToUniversalTime() - appleEpoch).TotalSeconds;
        var result = new byte[9];
        result[0] = 0x33; // date, 8 bytes
        BinaryPrimitives.WriteDoubleBigEndian(result.AsSpan(1), seconds);
        return result;
    }

    private static void WriteMarkerWithCount(MemoryStream ms, int typeHi, int count)
    {
        if (count < 0xF)
        {
            ms.WriteByte((byte)(typeHi | count));
            return;
        }

        ms.WriteByte((byte)(typeHi | 0xF));
        var sizeObj = EncodeInteger(count);
        ms.Write(sizeObj);
    }

    private static void WriteSizedInt(Stream stream, long value, int size)
    {
        Span<byte> buf = stackalloc byte[8];
        BinaryPrimitives.WriteInt64BigEndian(buf, value);
        stream.Write(buf[^size..]);
    }

    private sealed class ReferenceEqualityComparer : IEqualityComparer<object>
    {
        public static readonly ReferenceEqualityComparer Instance = new();
        public new bool Equals(object? x, object? y) => ReferenceEquals(x, y);
        public int GetHashCode(object obj) => System.Runtime.CompilerServices.RuntimeHelpers.GetHashCode(obj);
    }

    private static object? ReadObject(
        ReadOnlySpan<byte> data,
        long[] offsets,
        int objectRefSize,
        long objectIndex,
        object?[] cache,
        int depth)
    {
        if (depth > 64)
            throw new InvalidDataException("bplist annidato troppo profondamente");
        if (objectIndex < 0 || objectIndex >= offsets.Length)
            throw new InvalidDataException($"objectIndex {objectIndex}");
        if (cache[objectIndex] is { } hit)
            return hit;

        var offset = offsets[objectIndex];
        if (offset < 8 || offset >= data.Length)
            throw new InvalidDataException($"object offset {offset}");

        var marker = data[(int)offset];
        var type = marker >> 4;
        var info = marker & 0x0F;
        var cursor = (int)offset + 1;

        object? value = type switch
        {
            0x0 => info switch
            {
                0x8 => (object)false,
                0x9 => (object)true,
                _ => null
            },
            0x1 => ReadSizedInt(ReadBytes(data, ref cursor, InlineOrExtendedSize(info, data, ref cursor))),
            0x2 => ReadReal(ReadBytes(data, ref cursor, InlineOrExtendedSize(info, data, ref cursor))),
            0x3 => ReadDate(ReadBytes(data, ref cursor, 8)),
            0x4 => ReadBytes(data, ref cursor, InlineOrExtendedSize(info, data, ref cursor)).ToArray(),
            0x5 => Encoding.ASCII.GetString(ReadBytes(data, ref cursor, InlineOrExtendedSize(info, data, ref cursor))),
            0x6 => Encoding.BigEndianUnicode.GetString(
                ReadBytes(data, ref cursor, InlineOrExtendedSize(info, data, ref cursor) * 2)),
            // UID: high nibble 0x8, low nibble = byte count − 1 (NSKeyedArchive).
            0x8 => new PlistUid((ulong)ReadSizedInt(ReadBytes(data, ref cursor, info + 1))),
            0xA => ReadArray(data, offsets, objectRefSize, cache, depth, ref cursor, info),
            0xD => ReadDict(data, offsets, objectRefSize, cache, depth, ref cursor, info),
            _ => throw new InvalidDataException($"marker bplist non supportato 0x{marker:X2}")
        };

        cache[objectIndex] = value;
        return value;
    }

    private static object?[] ReadArray(
        ReadOnlySpan<byte> data,
        long[] offsets,
        int objectRefSize,
        object?[] cache,
        int depth,
        ref int cursor,
        int info)
    {
        var count = InlineOrExtendedSize(info, data, ref cursor);
        var arr = new object?[count];
        for (var i = 0; i < count; i++)
        {
            var refId = ReadSizedInt(ReadBytes(data, ref cursor, objectRefSize));
            arr[i] = ReadObject(data, offsets, objectRefSize, refId, cache, depth + 1);
        }

        return arr;
    }

    private static Dictionary<string, object?> ReadDict(
        ReadOnlySpan<byte> data,
        long[] offsets,
        int objectRefSize,
        object?[] cache,
        int depth,
        ref int cursor,
        int info)
    {
        var count = InlineOrExtendedSize(info, data, ref cursor);
        var keyRefs = new long[count];
        var valRefs = new long[count];
        for (var i = 0; i < count; i++)
            keyRefs[i] = ReadSizedInt(ReadBytes(data, ref cursor, objectRefSize));
        for (var i = 0; i < count; i++)
            valRefs[i] = ReadSizedInt(ReadBytes(data, ref cursor, objectRefSize));

        var dict = new Dictionary<string, object?>(count, StringComparer.Ordinal);
        for (var i = 0; i < count; i++)
        {
            var keyObj = ReadObject(data, offsets, objectRefSize, keyRefs[i], cache, depth + 1);
            var key = keyObj switch
            {
                string s => s,
                byte[] b => Encoding.UTF8.GetString(b),
                _ => keyObj?.ToString() ?? $"#{keyRefs[i]}"
            };
            dict[key] = ReadObject(data, offsets, objectRefSize, valRefs[i], cache, depth + 1);
        }

        return dict;
    }

    private static int InlineOrExtendedSize(int info, ReadOnlySpan<byte> data, ref int cursor)
    {
        if (info < 0xF)
            return info;

        var marker = data[cursor++];
        var type = marker >> 4;
        var sizeInfo = marker & 0x0F;
        if (type != 0x1)
            throw new InvalidDataException($"size object non intero 0x{marker:X2}");
        var nbytes = 1 << sizeInfo;
        return checked((int)ReadSizedInt(ReadBytes(data, ref cursor, nbytes)));
    }

    private static ReadOnlySpan<byte> ReadBytes(ReadOnlySpan<byte> data, ref int cursor, int length)
    {
        if (length < 0 || cursor + length > data.Length)
            throw new InvalidDataException("bplist troncato");
        var slice = data.Slice(cursor, length);
        cursor += length;
        return slice;
    }

    private static long ReadSizedInt(ReadOnlySpan<byte> bytes)
    {
        long value = 0;
        foreach (var b in bytes)
            value = (value << 8) | b;
        return value;
    }

    private static double ReadReal(ReadOnlySpan<byte> bytes) => bytes.Length switch
    {
        4 => BinaryPrimitives.ReadSingleBigEndian(bytes),
        8 => BinaryPrimitives.ReadDoubleBigEndian(bytes),
        _ => throw new InvalidDataException($"real size {bytes.Length}")
    };

    private static DateTimeOffset ReadDate(ReadOnlySpan<byte> bytes)
    {
        var seconds = BinaryPrimitives.ReadDoubleBigEndian(bytes);
        // Apple epoch 2001-01-01
        return DateTimeOffset.FromUnixTimeSeconds(978307200).AddSeconds(seconds);
    }
}
