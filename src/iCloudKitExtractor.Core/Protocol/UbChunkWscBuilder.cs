using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Text;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Batch PreAuth (record/retrieve post-Lock): frame delimited ubchunk wSc, non CKDFetchRecords.
/// Cattura capture_http_20260706_070218 req 00067.
/// </summary>
public static class UbChunkWscBuilder
{
    private static readonly Lazy<byte[]> SessionPrefix = new(LoadSessionPrefix);

    public static byte[] BuildSessionOnlyBody() => SessionPrefix.Value.ToArray();

    public static byte[] BuildWithSignedPaths(IReadOnlyList<SignedUrlChunk> chunks)
    {
        if (chunks.Count == 0)
            return BuildSessionOnlyBody();

        using var ms = new MemoryStream();
        ms.Write(SessionPrefix.Value);
        foreach (var chunk in chunks)
            WritePathFrame(ms, chunk);
        return ms.ToArray();
    }

    public static byte[] DecompressIfGzip(byte[] payload, IReadOnlyDictionary<string, IEnumerable<string>>? headers = null)
    {
        var wantsGzip = payload.Length >= 2 && payload[0] == 0x1F && payload[1] == 0x8B;
        if (!wantsGzip
            && headers is not null
            && headers.TryGetValue("Content-Encoding", out var values)
            && values.Any(v => v.Contains("gzip", StringComparison.OrdinalIgnoreCase)))
        {
            wantsGzip = true;
        }

        if (!wantsGzip)
            return payload;

        try
        {
            return Gunzip(payload);
        }
        catch (InvalidDataException)
        {
            // MITM/capture a volte salvano body già espansi o gzip corrotti: non fallire il round.
            return payload;
        }
        catch (IOException)
        {
            return payload;
        }
    }

    private static void WritePathFrame(Stream stream, SignedUrlChunk chunk)
    {
        var path = chunk.Url;
        if (path.StartsWith("https://edge.icloud-content.com", StringComparison.OrdinalIgnoreCase))
            path = path["https://edge.icloud-content.com".Length..];

        var inner = BuildPathInnerFrame(path, chunk.EdgeHeaders?.Uuid);
        WriteDelimitedFrame(stream, inner);
    }

    private static byte[] BuildPathInnerFrame(string path, string? clientRequestId)
    {
        // Struttura semplificata osservata in msg3  wrapper + sotto-frame Sc + path UTF-8.
        using var inner = new MemoryStream();
        inner.WriteByte(0xEC);
        inner.WriteByte(0xE7);
        var pathBytes = Encoding.UTF8.GetBytes(path);
        inner.Write(pathBytes);

        if (!string.IsNullOrWhiteSpace(clientRequestId))
        {
            var idBytes = Encoding.UTF8.GetBytes(clientRequestId);
            inner.Write(idBytes);
        }

        return inner.ToArray();
    }

    private static void WriteDelimitedFrame(Stream stream, byte[] message)
    {
        WriteVarint(stream, (ulong)message.Length);
        stream.Write(message);
    }

    private static void WriteVarint(Stream stream, ulong value)
    {
        while (value >= 0x80)
        {
            stream.WriteByte((byte)(value | 0x80));
            value >>= 7;
        }

        stream.WriteByte((byte)value);
    }

    private static byte[] Gunzip(byte[] data)
    {
        using var input = new MemoryStream(data);
        using var gzip = new GZipStream(input, CompressionMode.Decompress);
        using var output = new MemoryStream();
        gzip.CopyTo(output);
        return output.ToArray();
    }

    private static byte[] LoadSessionPrefix()
    {
        var assembly = Assembly.GetExecutingAssembly();
        const string name = "iCloudKitExtractor.Assets.ike.wsc_preauth_session_prefix.bin";
        using var stream = assembly.GetManifestResourceStream(name);
        if (stream is null)
            throw new InvalidOperationException($"Risorsa embedded mancante: {name}");

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
