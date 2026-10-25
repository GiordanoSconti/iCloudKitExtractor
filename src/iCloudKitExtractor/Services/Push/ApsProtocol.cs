using System.Buffers.Binary;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace iCloudKitExtractor.Services.Push;

/// <summary>Framing binario APS device-side (type + u32 length + TLV fields).</summary>
internal static class ApsProtocol
{
    public const byte TypeConnect = 0x07;
    public const byte TypeConnectAck = 0x08;
    public const byte TypeFilter = 0x09;
    public const byte TypeNotification = 0x0A;
    public const byte TypeNotificationAck = 0x0B;
    public const byte TypeKeepAlive = 0x0C;
    public const byte TypeKeepAliveAck = 0x0D;
    public const byte TypeSetState = 0x14;

    public static byte[] Serialize(byte type, IReadOnlyList<(byte Id, byte[] Value)> fields)
    {
        var payloadLen = 0;
        foreach (var (_, value) in fields)
            payloadLen += 1 + 2 + value.Length;

        var buf = new byte[1 + 4 + payloadLen];
        buf[0] = type;
        BinaryPrimitives.WriteUInt32BigEndian(buf.AsSpan(1, 4), (uint)payloadLen);
        var o = 5;
        foreach (var (id, value) in fields)
        {
            buf[o++] = id;
            BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(o, 2), (ushort)value.Length);
            o += 2;
            value.CopyTo(buf, o);
            o += value.Length;
        }

        return buf;
    }

    public static async Task<(byte Type, List<(byte Id, byte[] Value)> Fields)?> ReadMessageAsync(
        Stream stream,
        CancellationToken ct)
    {
        var header = new byte[5];
        if (!await ReadExactAsync(stream, header, ct).ConfigureAwait(false))
            return null;

        var type = header[0];
        if (type == 0)
            return null;

        var length = BinaryPrimitives.ReadUInt32BigEndian(header.AsSpan(1, 4));
        if (length > 16 * 1024 * 1024)
            throw new InvalidOperationException($"APS payload troppo grande: {length}");

        var body = new byte[length];
        if (length > 0 && !await ReadExactAsync(stream, body, ct).ConfigureAwait(false))
            return null;

        var fields = new List<(byte, byte[])>();
        var offset = 0;
        while (offset + 3 <= body.Length)
        {
            var id = body[offset];
            var flen = BinaryPrimitives.ReadUInt16BigEndian(body.AsSpan(offset + 1, 2));
            offset += 3;
            if (offset + flen > body.Length)
                break;
            var value = body.AsSpan(offset, flen).ToArray();
            offset += flen;
            fields.Add((id, value));
        }

        return (type, fields);
    }

    public static byte[]? GetField(IReadOnlyList<(byte Id, byte[] Value)> fields, byte id)
    {
        foreach (var (fid, value) in fields)
        {
            if (fid == id)
                return value;
        }

        return null;
    }

    public static byte[] TopicHash(string topic)
    {
        return SHA1.HashData(Encoding.UTF8.GetBytes(topic));
    }

    /// <summary>
    /// Connect pypush moderno: state + flags + cert DER + nonce + firma RSA-SHA1
    /// (<c>lifecycle.reconnect</c>).
    /// </summary>
    /// <param name="flags">pypush usa 65 (0x41); legacy root=true era 69.</param>
    /// <param name="signSha1Pkcs1">Firma PKCS#1 v1.5 SHA-1 sulla private key APS.</param>
    public static byte[] BuildConnect(
        byte[]? existingToken,
        byte[] certificateDer,
        Func<byte[], byte[]> signSha1Pkcs1,
        int flags = 65)
    {
        if (certificateDer is null || certificateDer.Length == 0)
            throw new ArgumentException("Serve certificato APS DER.", nameof(certificateDer));
        if (signSha1Pkcs1 is null)
            throw new ArgumentNullException(nameof(signSha1Pkcs1));

        // nonce = 0x00 || millis_be64 || random8  (pypush lifecycle.py)
        var nonce = new byte[17];
        nonce[0] = 0x00;
        BinaryPrimitives.WriteInt64BigEndian(
            nonce.AsSpan(1, 8),
            DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        RandomNumberGenerator.Fill(nonce.AsSpan(9, 8));

        var sigBody = signSha1Pkcs1(nonce);
        var signature = new byte[2 + sigBody.Length];
        signature[0] = 0x01;
        signature[1] = 0x01;
        Buffer.BlockCopy(sigBody, 0, signature, 2, sigBody.Length);

        var fields = new List<(byte, byte[])>();
        if (existingToken is { Length: > 0 })
            fields.Add((1, existingToken));

        fields.Add((2, new byte[] { 0x01 })); // state
        fields.Add((5, UInt32Be((uint)flags)));
        fields.Add((12, certificateDer));
        fields.Add((13, nonce));
        fields.Add((14, signature));
        fields.Add((16, UInt16Be(11))); // protocol_version

        return Serialize(TypeConnect, fields);
    }

    private static byte[] UInt32Be(uint v) =>
    [
        (byte)((v >> 24) & 0xFF),
        (byte)((v >> 16) & 0xFF),
        (byte)((v >> 8) & 0xFF),
        (byte)(v & 0xFF),
    ];

    private static byte[] UInt16Be(ushort v) =>
    [
        (byte)((v >> 8) & 0xFF),
        (byte)(v & 0xFF),
    ];

    public static byte[] BuildKeepAlive() => Serialize(TypeKeepAlive, Array.Empty<(byte, byte[])>());

    public static byte[] BuildSetState(byte state = 1) =>
        Serialize(TypeSetState, new List<(byte, byte[])>
        {
            (1, new[] { state }),
            (2, new byte[] { 0x7F, 0xFF, 0xFF, 0xFF }),
        });

    public static byte[] BuildFilter(byte[] token, IEnumerable<string> topics)
    {
        var fields = new List<(byte, byte[])> { (1, token) };
        foreach (var t in topics)
            fields.Add((2, TopicHash(t)));
        return Serialize(TypeFilter, fields);
    }

    public static byte[] BuildNotificationAck(byte[] token, byte[] messageId) =>
        Serialize(TypeNotificationAck, new List<(byte, byte[])>
        {
            (1, token),
            (4, messageId),
            (8, new byte[] { 0x00 }),
        });

    private static async Task<bool> ReadExactAsync(Stream stream, byte[] buffer, CancellationToken ct)
    {
        var read = 0;
        while (read < buffer.Length)
        {
            var n = await stream.ReadAsync(buffer.AsMemory(read, buffer.Length - read), ct)
                .ConfigureAwait(false);
            if (n == 0)
                return false;
            read += n;
        }

        return true;
    }
}
