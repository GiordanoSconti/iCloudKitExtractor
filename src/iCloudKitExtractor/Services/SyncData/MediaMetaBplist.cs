using System.Buffers.Binary;
using System.Globalization;
using System.Text;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Decoder bplist00 per <c>mediaMetaDataEnc</c> (ImageIO).
/// <see cref="Protocol.AppleBinaryPlist"/> fallisce su questi payload (real size 3).
/// </summary>
internal static class MediaMetaBplist
{
    private static readonly DateTime AppleEpoch = new(2001, 1, 1, 0, 0, 0, DateTimeKind.Utc);

    public static object? TryDecode(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;

        var trimmed = text.Trim();
        byte[] data;
        if (trimmed.StartsWith("bplist00", StringComparison.Ordinal))
            data = Encoding.Latin1.GetBytes(trimmed);
        else
        {
            try { data = Convert.FromBase64String(trimmed); }
            catch { return null; }
        }

        if (data.Length < 8 || Encoding.ASCII.GetString(data, 0, 8) != "bplist00")
            return null;

        try { return Parse(data); }
        catch { return null; }
    }

    public static double? TryDouble(object? value) =>
        value switch
        {
            double d => d,
            float f => f,
            long l => l,
            int i => i,
            string s when double.TryParse(
                s.Replace(',', '.'), NumberStyles.Float, CultureInfo.InvariantCulture, out var d) => d,
            _ => null
        };

    private static object? Parse(byte[] data)
    {
        if (data.Length < 40)
            return null;

        var trailer = data.AsSpan(data.Length - 32);
        var offsetSize = trailer[6];
        var refSize = trailer[7];
        var objectCount = BinaryPrimitives.ReadInt64BigEndian(trailer.Slice(8, 8));
        var top = BinaryPrimitives.ReadInt64BigEndian(trailer.Slice(16, 8));
        var tableOffset = BinaryPrimitives.ReadInt64BigEndian(trailer.Slice(24, 8));
        if (objectCount <= 0 || objectCount > 200_000 || offsetSize is < 1 or > 8 || refSize is < 1 or > 8)
            return null;

        var offsets = new int[objectCount];
        for (var i = 0; i < objectCount; i++)
        {
            var at = tableOffset + i * offsetSize;
            offsets[i] = ReadSizedInt(data, (int)at, offsetSize);
        }

        return ReadObject(data, offsets, (int)top, refSize, 0);
    }

    private static object? ReadObject(byte[] data, int[] offsets, int index, int refSize, int depth)
    {
        if (index < 0 || index >= offsets.Length || depth > 32)
            return null;

        var o = offsets[index];
        if (o < 0 || o >= data.Length)
            return null;

        var marker = data[o];
        var type = marker >> 4;
        var nibble = marker & 0x0F;
        switch (type)
        {
            case 0x0:
                return nibble switch
                {
                    0 => null,
                    8 => false,
                    9 => true,
                    _ => null
                };
            case 0x1:
                return ReadSizedLong(data, o + 1, 1 << nibble);
            case 0x2:
            {
                var len = 1 << nibble;
                if (len == 4)
                    return BitConverter.Int32BitsToSingle(
                        BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(o + 1, 4)));
                if (len == 8)
                    return BitConverter.Int64BitsToDouble(
                        BinaryPrimitives.ReadInt64BigEndian(data.AsSpan(o + 1, 8)));
                return null;
            }
            case 0x3:
            {
                var seconds = BitConverter.Int64BitsToDouble(
                    BinaryPrimitives.ReadInt64BigEndian(data.AsSpan(o + 1, 8)));
                return AppleEpoch.AddSeconds(seconds);
            }
            case 0x4:
            {
                var (len, pos) = ReadLength(data, o, nibble);
                var slice = new byte[len];
                Buffer.BlockCopy(data, pos, slice, 0, len);
                return slice;
            }
            case 0x5:
            {
                var (len, pos) = ReadLength(data, o, nibble);
                return Encoding.ASCII.GetString(data, pos, len);
            }
            case 0x6:
            {
                var (len, pos) = ReadLength(data, o, nibble);
                return Encoding.BigEndianUnicode.GetString(data, pos, len * 2);
            }
            case 0xA:
            {
                var (len, pos) = ReadLength(data, o, nibble);
                var list = new List<object?>(len);
                for (var i = 0; i < len; i++)
                {
                    var ri = ReadSizedInt(data, pos + i * refSize, refSize);
                    list.Add(ReadObject(data, offsets, ri, refSize, depth + 1));
                }

                return list;
            }
            case 0xD:
            {
                var (len, pos) = ReadLength(data, o, nibble);
                var dict = new Dictionary<string, object?>(len, StringComparer.Ordinal);
                for (var i = 0; i < len; i++)
                {
                    var ki = ReadSizedInt(data, pos + i * refSize, refSize);
                    var vi = ReadSizedInt(data, pos + len * refSize + i * refSize, refSize);
                    var keyObj = ReadObject(data, offsets, ki, refSize, depth + 1);
                    var key = Convert.ToString(keyObj, CultureInfo.InvariantCulture) ?? i.ToString();
                    dict[key] = ReadObject(data, offsets, vi, refSize, depth + 1);
                }

                return dict;
            }
            default:
                return null;
        }
    }

    private static (int Length, int Pos) ReadLength(byte[] data, int markerAt, int nibble)
    {
        if (nibble != 0xF)
            return (nibble, markerAt + 1);

        var info = data[markerAt + 1];
        var lenBytes = 1 << (info & 0x0F);
        var len = ReadSizedInt(data, markerAt + 2, lenBytes);
        return (len, markerAt + 2 + lenBytes);
    }

    private static int ReadSizedInt(byte[] data, int offset, int size)
    {
        var v = 0;
        for (var i = 0; i < size; i++)
            v = (v << 8) | data[offset + i];
        return v;
    }

    private static long ReadSizedLong(byte[] data, int offset, int size)
    {
        long v = 0;
        for (var i = 0; i < size; i++)
            v = (v << 8) | data[offset + i];
        var bits = size * 8;
        if (bits < 64 && (v & (1L << (bits - 1))) != 0)
            v |= -1L << bits;
        return v;
    }
}
