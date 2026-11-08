using System.Text;

namespace BackupViewer.Services;

/// <summary>Ispezione wire protobuf senza .proto (tag / wire-type / payload).</summary>
public static class ProtobufWireInspector
{
    public static string Inspect(byte[] data, int maxFields = 400)
    {
        var sb = new StringBuilder(Math.Min(data.Length * 2, 256_000));
        sb.AppendLine($"# protobuf wire dump — {data.Length:N0} bytes");
        var pos = 0;
        var n = 0;
        while (pos < data.Length && n < maxFields)
        {
            var start = pos;
            if (!TryReadVarint(data, ref pos, out var key))
            {
                sb.AppendLine($"@0x{start:X}: truncated key");
                break;
            }

            var field = (int)(key >> 3);
            var wire = (int)(key & 0x7);
            switch (wire)
            {
                case 0: // varint
                {
                    var vStart = pos;
                    if (!TryReadVarint(data, ref pos, out var v))
                    {
                        sb.AppendLine($"field {field} varint: truncated");
                        return sb.ToString();
                    }

                    sb.AppendLine($"field {field} varint = {v} (0x{v:X}) @0x{vStart:X}");
                    break;
                }
                case 1: // 64-bit
                {
                    if (pos + 8 > data.Length)
                    {
                        sb.AppendLine($"field {field} fixed64: truncated");
                        return sb.ToString();
                    }

                    var hex = Convert.ToHexString(data.AsSpan(pos, 8));
                    pos += 8;
                    sb.AppendLine($"field {field} fixed64 = {hex}");
                    break;
                }
                case 2: // length-delimited
                {
                    if (!TryReadVarint(data, ref pos, out var len) || len > int.MaxValue)
                    {
                        sb.AppendLine($"field {field} bytes: bad length");
                        return sb.ToString();
                    }

                    var l = (int)len;
                    if (pos + l > data.Length)
                    {
                        sb.AppendLine($"field {field} bytes[{l}]: truncated");
                        return sb.ToString();
                    }

                    var slice = data.AsSpan(pos, l);
                    pos += l;
                    var preview = PreviewBytes(slice);
                    sb.AppendLine($"field {field} bytes[{l}] = {preview}");
                    break;
                }
                case 5: // 32-bit
                {
                    if (pos + 4 > data.Length)
                    {
                        sb.AppendLine($"field {field} fixed32: truncated");
                        return sb.ToString();
                    }

                    var hex = Convert.ToHexString(data.AsSpan(pos, 4));
                    pos += 4;
                    sb.AppendLine($"field {field} fixed32 = {hex}");
                    break;
                }
                default:
                    sb.AppendLine($"field {field} wire={wire} unsupported @0x{start:X}");
                    return sb.ToString();
            }

            n++;
        }

        if (pos < data.Length)
            sb.AppendLine($"# stopped at 0x{pos:X}, remaining {data.Length - pos:N0} bytes (cap {maxFields} fields)");
        return sb.ToString();
    }

    private static string PreviewBytes(ReadOnlySpan<byte> slice)
    {
        if (slice.Length == 0)
            return "\"\"";
        var printable = true;
        foreach (var b in slice)
        {
            if (b is < 32 and not (9 or 10 or 13) || b > 126)
            {
                printable = false;
                break;
            }
        }

        if (printable)
        {
            var s = Encoding.UTF8.GetString(slice);
            if (s.Length > 120)
                s = s[..120] + "…";
            return "\"" + s.Replace("\"", "\\\"") + "\"";
        }

        var take = Math.Min(slice.Length, 24);
        var hex = Convert.ToHexString(slice[..take]);
        return slice.Length > take ? hex + "…" : hex;
    }

    private static bool TryReadVarint(byte[] data, ref int pos, out ulong value)
    {
        value = 0;
        var shift = 0;
        while (pos < data.Length && shift < 64)
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
