using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace iCloudKitExtractor.Protocol;

public sealed class ProtobufReader
{
    private readonly byte[] _data;
    private int _pos;

    public ProtobufReader(ReadOnlySpan<byte> data)
    {
        _data = data.ToArray();
    }

    public ProtobufReader(byte[] data) => _data = data;

    public bool HasMore => _pos < _data.Length;

    public int Remaining => _data.Length - _pos;

    public (int FieldNumber, int WireType) ReadTag()
    {
        var value = ReadVarint();
        return ((int)(value >> 3), (int)(value & 0x7));
    }

    /// <summary>Legge un campo length-delimited solo se rientra nei limiti.</summary>
    public bool TryReadLengthDelimited(out byte[] slice)
    {
        slice = Array.Empty<byte>();
        var save = _pos;
        try
        {
            var len = (int)ReadVarint();
            if (len < 0 || _pos + len > _data.Length)
            {
                _pos = save;
                return false;
            }
            slice = _data.AsSpan(_pos, len).ToArray();
            _pos += len;
            return true;
        }
        catch
        {
            _pos = save;
            return false;
        }
    }

    public ulong ReadVarint()
    {
        ulong result = 0;
        var shift = 0;
        while (_pos < _data.Length)
        {
            var b = _data[_pos++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return result;
            shift += 7;
        }
        throw new InvalidDataException("Varint troncato.");
    }

    public byte[] ReadLengthDelimited()
    {
        var len = (int)ReadVarint();
        if (_pos + len > _data.Length)
            throw new InvalidDataException("Campo length-delimited fuori range.");
        var slice = _data.AsSpan(_pos, len).ToArray();
        _pos += len;
        return slice;
    }

    public void SkipField(int wireType)
    {
        switch (wireType)
        {
            case 0:
                ReadVarint();
                break;
            case 1:
                _pos += 8;
                break;
            case 2:
                _pos += (int)ReadVarint();
                break;
            case 3:
            case 4:
                break;
            case 5:
                _pos += 4;
                break;
            default:
                throw new InvalidDataException($"Wire type non supportato: {wireType}");
        }
    }
}

public sealed class ProtobufWriter
{
    private readonly MemoryStream _stream = new();

    public void WriteTag(int fieldNumber, int wireType) =>
        WriteVarint((ulong)((fieldNumber << 3) | wireType));

    public void WriteVarint(ulong value)
    {
        while (value >= 0x80)
        {
            _stream.WriteByte((byte)(value | 0x80));
            value >>= 7;
        }
        _stream.WriteByte((byte)value);
    }

    public void WriteVarint(int fieldNumber, ulong value)
    {
        WriteTag(fieldNumber, 0);
        WriteVarint(value);
    }

    public void WriteBytes(int fieldNumber, ReadOnlySpan<byte> data)
    {
        WriteTag(fieldNumber, 2);
        WriteVarint((ulong)data.Length);
        _stream.Write(data);
    }

    public void WriteString(int fieldNumber, string value) =>
        WriteBytes(fieldNumber, Encoding.UTF8.GetBytes(value));

    public void WriteFixed32(int fieldNumber, uint value)
    {
        WriteTag(fieldNumber, 5);
        Span<byte> buf = stackalloc byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buf, value);
        _stream.Write(buf);
    }

    public byte[] ToArray() => _stream.ToArray();
}

public static class ProtobufStringScanner
{
    public static IReadOnlyList<string> ExtractUtf8Strings(ReadOnlySpan<byte> data)
    {
        var results = new List<string>();
        var reader = new ProtobufReader(data);
        Walk(reader, results);
        return results;
    }

    private static void Walk(ProtobufReader reader, List<string> results)
    {
        while (reader.HasMore)
        {
            int field, wire;
            try
            {
                (field, wire) = reader.ReadTag();
            }
            catch
            {
                return;
            }

            if (wire == 2)
            {
                if (!reader.TryReadLengthDelimited(out var payload))
                    return;
                if (TryDecodeUtf8(payload, out var text) && text.Length >= 3)
                    results.Add(text);
                Walk(new ProtobufReader(payload), results);
            }
            else
            {
                try
                {
                    reader.SkipField(wire);
                }
                catch
                {
                    return;
                }
            }
        }
    }

    /// <summary>
    /// Estrae stringhe da un flusso "delimited" (concatenazione di messaggi
    /// ciascuno con prefisso varint di lunghezza), come le risposte CloudKit.
    /// Tollera framing assente o corrotto ricadendo su scan grezzo.
    /// </summary>
    public static IReadOnlyList<string> ExtractDelimited(ReadOnlySpan<byte> data)
    {
        var results = new List<string>();
        var reader = new ProtobufReader(data);
        while (reader.HasMore)
        {
            if (!reader.TryReadLengthDelimited(out var message) || message.Length == 0)
                break;
            Walk(new ProtobufReader(message), results);
        }

        // Supplemento robusto: run ASCII contigue (record id, zone, nomi).
        results.AddRange(ExtractAsciiRuns(data, 3));
        return results;
    }

    /// <summary>Trova sequenze contigue di caratteri ASCII stampabili.</summary>
    public static IReadOnlyList<string> ExtractAsciiRuns(ReadOnlySpan<byte> data, int minLength)
    {
        var results = new List<string>();
        var sb = new StringBuilder();
        foreach (var b in data)
        {
            if (b >= 0x20 && b < 0x7f)
            {
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minLength)
                    results.Add(sb.ToString());
                sb.Clear();
            }
        }
        if (sb.Length >= minLength)
            results.Add(sb.ToString());
        return results;
    }

    private static bool TryDecodeUtf8(ReadOnlySpan<byte> data, out string text)
    {
        try
        {
            text = Encoding.UTF8.GetString(data);
            return text.All(c => !char.IsControl(c) || c is '\t' or '\n' or '\r');
        }
        catch
        {
            text = string.Empty;
            return false;
        }
    }

    public static IReadOnlyList<string> FindBackupRecordNames(byte[] data) =>
        ExtractUtf8Strings(data).Where(s =>
            s.StartsWith("A:", StringComparison.Ordinal) ||
            s.StartsWith("C1BC-", StringComparison.Ordinal) ||
            s.Contains("BackupAsset", StringComparison.Ordinal)).ToList();
}
