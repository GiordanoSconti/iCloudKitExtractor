using System.IO;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Frame varint-delimited usati nei body ubchunk (PreAuth record/retrieve).
/// </summary>
public static class UbChunkDelimitedCodec
{
    public static IReadOnlyList<byte[]> EnumerateFrames(ReadOnlySpan<byte> data)
    {
        var frames = new List<byte[]>();
        var index = 0;

        while (index < data.Length)
        {
            var save = index;
            if (!TryReadVarint(data, ref index, out var length)
                || length == 0
                || length > (ulong)(data.Length - index))
            {
                index = save;
                break;
            }

            frames.Add(data.Slice(index, (int)length).ToArray());
            index += (int)length;
        }

        if (frames.Count == 0 && data.Length > 0)
            frames.Add(data.ToArray());

        return frames;
    }

    public static byte[] WriteFrame(ReadOnlySpan<byte> message)
    {
        var len = EncodeVarint((ulong)message.Length);
        var result = new byte[len.Length + message.Length];
        Buffer.BlockCopy(len, 0, result, 0, len.Length);
        message.CopyTo(result.AsSpan(len.Length));
        return result;
    }

    public static byte[] ConcatFrames(IEnumerable<byte[]> frames)
    {
        using var ms = new MemoryStream();
        foreach (var frame in frames)
            ms.Write(WriteFrame(frame));
        return ms.ToArray();
    }

    public static bool LooksLikeUbChunkBatch(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 2 && data[0] == (byte)'X' && data[1] == (byte)'B')
            return true;

        if (!TryReadVarint(data, 0, out var firstLen))
            return false;

        return firstLen is > 0 and < 16_384
               && 1 + CountVarintBytes(firstLen) + (int)firstLen <= data.Length;
    }

    private static int CountVarintBytes(ulong value)
    {
        var count = 0;
        do
        {
            count++;
            value >>= 7;
        } while (value > 0);

        return count;
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> data, int start, out ulong value)
    {
        value = 0;
        var index = start;
        var shift = 0;
        while (index < data.Length)
        {
            var b = data[index++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
            if (shift > 63)
                break;
        }

        return false;
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> data, ref int index, out ulong value)
    {
        var start = index;
        if (!TryReadVarint(data, start, out value))
            return false;

        while (start < data.Length)
        {
            start++;
            if ((data[start - 1] & 0x80) == 0)
                break;
        }

        index = start;
        return true;
    }

    private static byte[] EncodeVarint(ulong value)
    {
        var bytes = new List<byte>(5);
        while (value >= 0x80)
        {
            bytes.Add((byte)(value | 0x80));
            value >>= 7;
        }

        bytes.Add((byte)value);
        return bytes.ToArray();
    }
}
