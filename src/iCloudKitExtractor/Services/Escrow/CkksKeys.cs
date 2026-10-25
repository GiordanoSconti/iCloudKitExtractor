using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// CKKS AES-SIV key wrap / item decrypt (appleservices <c>ckks/keys.go</c>, <c>item.go</c>).
/// </summary>
public static class CkksKeys
{
    public const int KeyLen = 64;
    public const int ItemNonceLen = 16;

    public static byte[] UnwrapKey(ReadOnlySpan<byte> wrappingKey, ReadOnlySpan<byte> wrapped)
    {
        if (wrappingKey.Length != KeyLen)
            throw new CryptographicException($"CKKS wrapping key len {wrappingKey.Length}, want {KeyLen}");
        var key = FordMmcsDecryptor.AesSivRfc5297Decrypt(
            wrappingKey, wrapped, Array.Empty<byte[]>());
        if (key.Length != KeyLen)
            throw new CryptographicException($"CKKS unwrapped key len {key.Length}, want {KeyLen}");
        return key;
    }

    public static byte[] DecryptItem(
        ReadOnlySpan<byte> itemKey, ReadOnlySpan<byte> data, IReadOnlyList<byte[]> aad)
    {
        if (itemKey.Length != KeyLen)
            throw new CryptographicException($"CKKS item key len {itemKey.Length}, want {KeyLen}");
        if (data.Length < ItemNonceLen + 16)
            throw new CryptographicException($"CKKS item data troppo corto: {data.Length}");

        var nonce = data[..ItemNonceLen].ToArray();
        var ads = new List<byte[]>(aad.Count + 1) { nonce };
        ads.AddRange(aad);
        return FordMmcsDecryptor.AesSivRfc5297Decrypt(itemKey, data[ItemNonceLen..], ads);
    }

    /// <summary>
    /// <c>CuttlefishSerializedKey</c>: uuid=1, zoneName=2, keyclass=3, key=4.
    /// </summary>
    public static string? ZoneNameFromCkksKeyPlaintext(ReadOnlySpan<byte> plaintext)
    {
        try
        {
            var r = new ProtobufReader(plaintext);
            while (r.HasMore)
            {
                var (field, wire) = r.ReadTag();
                if (wire != 2)
                {
                    r.SkipField(wire);
                    continue;
                }

                var payload = r.ReadLengthDelimited();
                if (field == 2 && payload.Length > 0)
                    return Encoding.UTF8.GetString(payload);
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    /// <summary>
    /// CKKSKey plaintext → TLK 64 B (protobuf field 4, oppure raw 64 B).
    /// </summary>
    public static byte[] TlkFromCkksKeyPlaintext(ReadOnlySpan<byte> plaintext)
    {
        try
        {
            var r = new ProtobufReader(plaintext);
            while (r.HasMore)
            {
                var (field, wire) = r.ReadTag();
                if (wire != 2)
                {
                    r.SkipField(wire);
                    continue;
                }

                var payload = r.ReadLengthDelimited();
                if (field == 4 && payload.Length == KeyLen)
                    return payload;
            }
        }
        catch
        {
            // fallback raw
        }

        if (plaintext.Length == KeyLen)
            return plaintext.ToArray();

        throw new CryptographicException(
            $"CKKSKey senza key 64 B in field 4 (pt={plaintext.Length} B)");
    }

    public static byte[] LeInt64(long v)
    {
        var b = new byte[8];
        BinaryPrimitives.WriteInt64LittleEndian(b, v);
        return b;
    }

    public static byte[] TrimPkcs7StylePadding(byte[] padded)
    {
        var n = padded.Length;
        while (n > 0 && padded[n - 1] == 0x00)
            n--;
        if (n > 0 && padded[n - 1] == 0x80)
            n--;
        return padded.AsSpan(0, n).ToArray();
    }
}

/// <summary>Campo CloudKit tipizzato (CKKS zone record).</summary>
public readonly record struct CkksFieldValue(int Type, byte[] Bytes, long Int);

/// <summary>Record CKKS da record/sync (tlkshare / synckey / item).</summary>
public sealed class CkksRecord
{
    public string Type { get; set; } = "";
    public string Name { get; set; } = "";
    public string Etag { get; set; } = "";
    public Dictionary<string, CkksFieldValue> Fields { get; } = new(StringComparer.Ordinal);

    public string? FieldString(string name) =>
        Fields.TryGetValue(name, out var v) && v.Bytes is { Length: > 0 }
            ? Encoding.UTF8.GetString(v.Bytes)
            : null;

    public byte[]? FieldBytes(string name) =>
        Fields.TryGetValue(name, out var v) ? v.Bytes : null;

    public long? FieldInt(string name) =>
        Fields.TryGetValue(name, out var v) ? v.Int : null;
}

/// <summary>Parser zone CKKS (appleservices <c>ckks/zone.go</c> + <c>record.go</c>).</summary>
public static class CkksZoneParser
{
    public static List<CkksRecord> ParseZone(byte[] recordSyncBody)
    {
        var data = TryUnframe(recordSyncBody) ?? recordSyncBody;
        byte[]? zoneRecords = null;
        var r = new ProtobufReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field == 213)
                zoneRecords = payload;
        }

        if (zoneRecords is null)
            return [];

        var outList = new List<CkksRecord>();
        var zr = new ProtobufReader(zoneRecords);
        while (zr.HasMore)
        {
            var (field, wire) = zr.ReadTag();
            if (wire != 2)
            {
                zr.SkipField(wire);
                continue;
            }

            var recBytes = zr.ReadLengthDelimited();
            if (field != 1)
                continue;
            try
            {
                outList.Add(ParseRecord(recBytes));
            }
            catch
            {
                // skip malformed
            }
        }

        return outList;
    }

    private static byte[]? TryUnframe(byte[] body)
    {
        try
        {
            if (body.Length < 2)
                return null;
            var (n, off) = ConsumeUvarint(body);
            if (off + (int)n == body.Length && n > 0)
                return body.AsSpan(off).ToArray();
            return null;
        }
        catch
        {
            return null;
        }
    }

    private static (ulong N, int Offset) ConsumeUvarint(byte[] body)
    {
        ulong result = 0;
        var shift = 0;
        var i = 0;
        while (i < body.Length)
        {
            var b = body[i++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return (result, i);
            shift += 7;
            if (shift > 63)
                throw new InvalidDataException("uvarint overflow");
        }

        throw new InvalidDataException("uvarint troncato");
    }

    /// <summary>Parse un singolo CloudKit Record (corpo record/sync o Cuttlefish wrap).</summary>
    public static CkksRecord ParseRecordBytes(byte[] rec) => ParseRecord(rec);

    private static CkksRecord ParseRecord(byte[] rec)
    {
        byte[]? body = null;
        byte[]? recordId = null;
        // Flat layout (Cuttlefish fetchRecoverableTLKShares share wrap): type/name/fields
        // at top level — no CloudKit Record field-5 body.
        string? flatName = null;
        string? flatType = null;
        var flatFields = new Dictionary<string, CkksFieldValue>(StringComparer.Ordinal);
        var r = new ProtobufReader(rec);
        while (r.HasMore)
        {
            int field;
            int wire;
            try
            {
                (field, wire) = r.ReadTag();
                if (wire != 2)
                {
                    try { r.SkipField(wire); }
                    catch (InvalidDataException) { break; }
                    continue;
                }

                var payload = r.ReadLengthDelimited();
                switch (field)
                {
                    case 1:
                        recordId = payload;
                        break;
                    case 2:
                        flatName ??= ExtractLooseName(payload);
                        break;
                    case 3:
                        flatType ??= ExtractTypeName(payload);
                        if (string.IsNullOrEmpty(flatType))
                        {
                            var direct = Encoding.UTF8.GetString(payload);
                            if (IsCkksRecordType(direct))
                                flatType = direct;
                        }

                        break;
                    case 5:
                        body = payload;
                        break;
                    case 7:
                        if (TryParseNamedField(payload, out var fname, out var val))
                            flatFields[fname] = val;
                        break;
                }
            }
            catch (InvalidDataException)
            {
                break;
            }
        }

        // Classic CloudKit Record: identity in f1, body in f5.
        // In Cuttlefish recoverable shares, f5 is often timestamps — not a body.
        // Only accept classic parse if it yields a type or fields.
        if (body is not null)
        {
            var classic = new CkksRecord { Name = RecordNameFromId(recordId) };
            try
            {
                var inner = new ProtobufReader(body);
                while (inner.HasMore)
                {
                    var (field, wire) = inner.ReadTag();
                    if (wire != 2)
                    {
                        inner.SkipField(wire);
                        continue;
                    }

                    var payload = inner.ReadLengthDelimited();
                    switch (field)
                    {
                        case 1:
                            classic.Etag = Encoding.UTF8.GetString(payload);
                            break;
                        case 3:
                            classic.Type = ExtractTypeName(payload);
                            break;
                        case 7:
                            if (TryParseNamedField(payload, out var fname, out var val))
                                classic.Fields[fname] = val;
                            break;
                    }
                }
            }
            catch (InvalidDataException)
            {
                // not a CK body
            }

            if (!string.IsNullOrEmpty(classic.Type) || classic.Fields.Count > 0)
                return classic;
        }

        // Flat recoverable share / synckey (f2=name, f3=type, f7=fields).
        if (!string.IsNullOrEmpty(flatType) || flatFields.Count > 0)
        {
            var flat = new CkksRecord
            {
                Name = flatName ?? RecordNameFromId(recordId),
                Type = flatType ?? "",
            };
            foreach (var (k, v) in flatFields)
                flat.Fields[k] = v;
            return flat;
        }

        return new CkksRecord { Name = RecordNameFromId(recordId) };
    }

    private static bool IsCkksRecordType(string s) =>
        s is "tlkshare" or "synckey" or "item" or "currentitempointer" or "tlksharerequest";

    /// <summary>
    /// Record name as UTF-8, or protobuf <c>string name = 1</c>, or CK record-id ref.
    /// </summary>
    private static string? ExtractLooseName(byte[] payload)
    {
        if (payload.Length == 0)
            return null;

        // Prefer protobuf string name = 1 (avoids tag bytes in UTF-8 dump).
        try
        {
            var r = new ProtobufReader(payload);
            while (r.HasMore)
            {
                var (field, wire) = r.ReadTag();
                if (wire != 2)
                {
                    try { r.SkipField(wire); }
                    catch (InvalidDataException) { break; }
                    continue;
                }

                var inner = r.ReadLengthDelimited();
                if (field != 1)
                    continue;
                var s = Encoding.UTF8.GetString(inner);
                if (!string.IsNullOrWhiteSpace(s) && s.All(c => c is >= ' ' and < '\x7f'))
                    return s;
            }
        }
        catch
        {
            // fall through
        }

        try
        {
            var direct = Encoding.UTF8.GetString(payload);
            if (direct.All(c => c is >= ' ' and < '\x7f')
                && (direct.Contains("tlkshare-", StringComparison.Ordinal)
                    || direct.Contains("synckey-", StringComparison.Ordinal)
                    || direct.StartsWith("RK-", StringComparison.Ordinal)))
                return direct;
        }
        catch
        {
            // not utf8
        }

        return RefInnerName(payload);
    }

    private static string ExtractTypeName(byte[] typeMsg)
    {
        var r = new ProtobufReader(typeMsg);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field == 1)
                return Encoding.UTF8.GetString(payload);
        }

        return "";
    }

    private static string RecordNameFromId(byte[]? id)
    {
        if (id is null || id.Length == 0)
            return "";
        return RefInnerName(id) ?? "";
    }

    public static string? RefInnerName(byte[] msg)
    {
        var r = new ProtobufReader(msg);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field != 1)
                continue;
            var ir = new ProtobufReader(payload);
            while (ir.HasMore)
            {
                var (f2, w2) = ir.ReadTag();
                if (w2 != 2)
                {
                    ir.SkipField(w2);
                    continue;
                }

                var inner = ir.ReadLengthDelimited();
                if (f2 == 1)
                    return Encoding.UTF8.GetString(inner);
            }
        }

        return null;
    }

    public static string? RefTargetName(byte[] ckref)
    {
        var r = new ProtobufReader(ckref);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field == 2)
                return RefInnerName(payload);
        }

        return null;
    }

    private static bool TryParseNamedField(byte[] data, out string name, out CkksFieldValue val)
    {
        name = "";
        val = default;
        byte[]? nameMsg = null;
        byte[]? valueMsg = null;
        var r = new ProtobufReader(data);
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire != 2)
            {
                r.SkipField(wire);
                continue;
            }

            var payload = r.ReadLengthDelimited();
            if (field == 1)
                nameMsg = payload;
            else if (field == 2)
                valueMsg = payload;
        }

        if (nameMsg is null || valueMsg is null)
            return false;

        var nr = new ProtobufReader(nameMsg);
        while (nr.HasMore)
        {
            var (field, wire) = nr.ReadTag();
            if (wire != 2)
            {
                nr.SkipField(wire);
                continue;
            }

            var payload = nr.ReadLengthDelimited();
            if (field == 1)
                name = Encoding.UTF8.GetString(payload);
        }

        if (string.IsNullOrEmpty(name))
            return false;

        val = ParseCkValue(valueMsg);
        return true;
    }

    private static CkksFieldValue ParseCkValue(byte[] data)
    {
        var type = 0;
        long intVal = 0;
        byte[] bytes = [];
        var r = new ProtobufReader(data);
        var fields = new List<(int Num, int Wire, ulong Varint, byte[] Bytes)>();
        while (r.HasMore)
        {
            var (field, wire) = r.ReadTag();
            if (wire == 0)
            {
                var v = r.ReadVarint();
                fields.Add((field, wire, v, []));
                if (field == 1)
                    type = (int)v;
            }
            else if (wire == 2)
            {
                fields.Add((field, wire, 0, r.ReadLengthDelimited()));
            }
            else
            {
                r.SkipField(wire);
            }
        }

        var valueField = type switch
        {
            1 => 2,
            3 => 7,
            5 => 9,
            7 => 4,
            _ => -1
        };

        foreach (var f in fields)
        {
            if (f.Num != valueField)
                continue;
            if (type == 7 && f.Wire == 0)
                intVal = (long)f.Varint;
            else if (f.Wire == 2)
                bytes = f.Bytes;
        }

        return new CkksFieldValue(type, bytes, intVal);
    }
}
