using System.Buffers.Binary;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;

namespace BackupViewer.Services;

/// <summary>Parser minimale Apple binary plist (<c>bplist00</c>).</summary>
public static class BinaryPlistParser
{
    private static readonly DateTime AppleEpoch = new(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static string ToPrettyJson(byte[] data)
    {
        var obj = Parse(data);
        return JsonSerializer.Serialize(obj, new JsonSerializerOptions { WriteIndented = true });
    }

    public static object? Parse(byte[] data)
    {
        if (data.Length < 40 || Encoding.ASCII.GetString(data, 0, 8) != "bplist00")
            throw new InvalidDataException("Non è un bplist00.");

        var trailer = data.AsSpan(data.Length - 32);
        var offsetSize = trailer[6];
        var objectRefSize = trailer[7];
        var numObjects = BinaryPrimitives.ReadUInt64BigEndian(trailer[8..16]);
        var topObject = BinaryPrimitives.ReadUInt64BigEndian(trailer[16..24]);
        var offsetTableOffset = BinaryPrimitives.ReadUInt64BigEndian(trailer[24..32]);

        var offsets = new long[numObjects];
        for (ulong i = 0; i < numObjects; i++)
        {
            var at = (long)offsetTableOffset + (long)i * offsetSize;
            offsets[i] = ReadSizedInt(data, at, offsetSize);
        }

        return ReadObject(data, offsets, objectRefSize, (long)topObject, 0);
    }

    private static object? ReadObject(
        byte[] data,
        long[] offsets,
        int objectRefSize,
        long objectIndex,
        int depth)
    {
        if (depth > 64)
            return "<max-depth>";
        if (objectIndex < 0 || objectIndex >= offsets.Length)
            return null;

        var pos = offsets[objectIndex];
        var marker = data[pos];
        var type = marker >> 4;
        var info = marker & 0x0F;
        pos++;

        switch (type)
        {
            case 0x0:
                return info switch
                {
                    0x0 => null,
                    0x8 => false,
                    0x9 => true,
                    0xF => null,
                    _ => $"null/{info:X}",
                };
            case 0x1:
            {
                var len = 1 << info;
                return ReadSizedInt(data, pos, len);
            }
            case 0x2:
            {
                var len = 1 << info;
                if (len == 4)
                    return ReadSingleBe(data, pos);
                if (len == 8)
                    return ReadDoubleBe(data, pos);
                return BitConverter.ToString(data, (int)pos, len);
            }
            case 0x3:
                return AppleEpoch.AddSeconds(ReadDoubleBe(data, pos));
            case 0x4:
            {
                var len = ReadLength(data, ref pos, info);
                return Convert.ToHexString(data.AsSpan((int)pos, (int)len));
            }
            case 0x5:
            {
                var len = ReadLength(data, ref pos, info);
                return Encoding.ASCII.GetString(data, (int)pos, (int)len);
            }
            case 0x6:
            {
                var len = ReadLength(data, ref pos, info);
                return Encoding.BigEndianUnicode.GetString(data, (int)pos, (int)(len * 2));
            }
            case 0xA:
            {
                var len = ReadLength(data, ref pos, info);
                var list = new List<object?>((int)len);
                for (var i = 0; i < (int)len; i++)
                {
                    var refIdx = ReadSizedInt(data, pos + i * objectRefSize, objectRefSize);
                    list.Add(ReadObject(data, offsets, objectRefSize, refIdx, depth + 1));
                }

                return list;
            }
            case 0xD:
            {
                var len = ReadLength(data, ref pos, info);
                var dict = new Dictionary<string, object?>((int)len);
                var keyStart = pos;
                var valStart = pos + len * objectRefSize;
                for (var i = 0; i < (int)len; i++)
                {
                    var keyIdx = ReadSizedInt(data, keyStart + i * objectRefSize, objectRefSize);
                    var valIdx = ReadSizedInt(data, valStart + i * objectRefSize, objectRefSize);
                    var keyObj = ReadObject(data, offsets, objectRefSize, keyIdx, depth + 1);
                    var key = keyObj?.ToString() ?? $"#{keyIdx}";
                    dict[key] = ReadObject(data, offsets, objectRefSize, valIdx, depth + 1);
                }

                return dict;
            }
            default:
                return $"type/{type:X}/{info:X}";
        }
    }

    private static long ReadLength(byte[] data, ref long pos, int info)
    {
        if (info != 0xF)
            return info;
        var marker = data[pos++];
        var size = 1 << (marker & 0x0F);
        var value = ReadSizedInt(data, pos, size);
        pos += size;
        return value;
    }

    private static long ReadSizedInt(byte[] data, long offset, int size)
    {
        long value = 0;
        for (var i = 0; i < size; i++)
            value = (value << 8) | data[offset + i];
        return value;
    }

    private static float ReadSingleBe(byte[] data, long offset)
    {
        Span<byte> tmp = stackalloc byte[4];
        data.AsSpan((int)offset, 4).CopyTo(tmp);
        if (BitConverter.IsLittleEndian)
            tmp.Reverse();
        return BitConverter.ToSingle(tmp);
    }

    private static double ReadDoubleBe(byte[] data, long offset)
    {
        Span<byte> tmp = stackalloc byte[8];
        data.AsSpan((int)offset, 8).CopyTo(tmp);
        if (BitConverter.IsLittleEndian)
            tmp.Reverse();
        return BitConverter.ToDouble(tmp);
    }

    public static string FormatLeaf(object? value) =>
        value switch
        {
            null => "null",
            bool b => b ? "true" : "false",
            DateTime dt => dt.ToString("O", CultureInfo.InvariantCulture),
            double d => d.ToString("G17", CultureInfo.InvariantCulture),
            float f => f.ToString("G9", CultureInfo.InvariantCulture),
            _ => Convert.ToString(value, CultureInfo.InvariantCulture) ?? "",
        };
}
