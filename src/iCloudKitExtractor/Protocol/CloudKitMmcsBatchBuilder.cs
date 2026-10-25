using System.Text;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Costruisce batch MMCS (host + GET + path firmato) per query/retrieve e PreAuth.
/// Schema osservato nelle capture (es. recovery 00586).
/// </summary>
public static class CloudKitMmcsBatchBuilder
{
    private const ulong HttpsPort = 443;

    private static readonly Regex SignedPathRegex = new(
        @"(/[^\s\x00-\x1f""]{8,512}\?content-byte-range=\d+-\d+[^\s\x00-\x1f""]*)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>Estrae path MMCS già firmati embedded in payload CloudKit.</summary>
    public static IReadOnlyList<string> ExtractSignedPaths(ReadOnlySpan<byte> payload)
    {
        if (payload.IsEmpty)
            return [];

        var text = Encoding.UTF8.GetString(payload);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match match in SignedPathRegex.Matches(text))
        {
            var path = CleanSignedPath(match.Groups[1].Value);
            if (!string.IsNullOrWhiteSpace(path))
                paths.Add(path);
        }

        return paths.OrderBy(static p => p, StringComparer.Ordinal).ToList();
    }

    public static IReadOnlyList<SignedUrlChunk> ChunksFromSignedPaths(IEnumerable<string> paths)
    {
        var chunks = new List<SignedUrlChunk>();
        foreach (var path in paths)
        {
            var clean = CleanSignedPath(path);
            if (string.IsNullOrWhiteSpace(clean))
                continue;

            chunks.Add(new SignedUrlChunk
            {
                Url = $"https://edge.icloud-content.com{clean}"
            });
        }

        return chunks;
    }

    /// <summary>Messaggio query/retrieve con campo 31 (batch MMCS).</summary>
    public static byte[] BuildBatchQueryMessage(IReadOnlyList<SignedUrlChunk> chunks)
    {
        if (chunks.Count == 0)
            throw new ArgumentException("Nessun chunk MMCS nel batch.");

        var batchUuid = Guid.NewGuid().ToString().ToUpperInvariant();
        var sessionUuid = Guid.NewGuid().ToString();

        var opInner = new ProtobufWriter();
        opInner.WriteString(1, batchUuid);
        opInner.WriteVarint(2, CloudKitDelimitedRequest.QueryOperationType);
        opInner.WriteVarint(4, 1);

        var flags = new ProtobufWriter();
        flags.WriteVarint(1, 1);

        var batchPayload = new ProtobufWriter();
        batchPayload.WriteString(1, sessionUuid);
        batchPayload.WriteBytes(2, BuildChunkList(chunks));

        var payloadWrap = new ProtobufWriter();
        payloadWrap.WriteBytes(1, batchPayload.ToArray());

        var op = new ProtobufWriter();
        op.WriteBytes(2, opInner.ToArray());
        op.WriteBytes(3, flags.ToArray());
        op.WriteBytes(4, payloadWrap.ToArray());

        var outer = new ProtobufWriter();
        outer.WriteBytes(31, op.ToArray());
        return outer.ToArray();
    }

    /// <summary>Coda PreAuth record/retrieve (senza prefisso cifrato).</summary>
    public static byte[] BuildPreAuthTail(IReadOnlyList<SignedUrlChunk> chunks)
    {
        if (chunks.Count == 0)
            throw new ArgumentException("Nessun chunk MMCS nel batch.");

        var chunkBytes = BuildChunkList(chunks);
        var tail = new ProtobufWriter();
        tail.WriteVarint(30, (ulong)chunkBytes.Length);
        tail.WriteBytes(1, chunkBytes);
        return tail.ToArray();
    }

    public static byte[] BuildPreAuthRetrieveBody(
        string cloudKitUserId,
        IReadOnlyList<SignedUrlChunk> chunks)
    {
        var header = CloudKitDelimitedRequest.BuildPreAuthHeaderMessage(cloudKitUserId);
        return Concat(
            CloudKitDelimitedRequest.WrapDelimitedMessage(header),
            BuildPreAuthTail(chunks));
    }

    private static byte[] BuildChunkList(IReadOnlyList<SignedUrlChunk> chunks)
    {
        var list = new ProtobufWriter();
        foreach (var chunk in chunks)
        {
            var entry = new ProtobufWriter();
            entry.WriteBytes(1, BuildChunkEntry(chunk));
            list.WriteBytes(1, entry.ToArray());
        }

        return list.ToArray();
    }

    private static byte[] BuildChunkEntry(SignedUrlChunk chunk)
    {
        var uri = new Uri(chunk.Url);
        var path = CleanSignedPath(
            string.IsNullOrEmpty(uri.PathAndQuery) ? uri.AbsolutePath : uri.PathAndQuery);
        var host = uri.Host;

        var entry = new ProtobufWriter();
        entry.WriteString(1, host);
        entry.WriteVarint(2, HttpsPort);
        entry.WriteBytes(3, "GET"u8);
        entry.WriteString(4, path);
        AppendEdgeHeaders(entry, chunk);
        return entry.ToArray();
    }

    private static void AppendEdgeHeaders(ProtobufWriter entry, SignedUrlChunk chunk)
    {
        var headers = chunk.EdgeHeaders;
        if (headers is null)
            return;

        void Pair(string key, string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return;
            entry.WriteString(5, key);
            entry.WriteString(6, value);
        }

        Pair("https", "https");
        Pair("Accept", "*/*");
        Pair("X-Apple-Object-ID", headers.ObjectId);
        if (chunk.ByteRange is { } range)
            Pair("Range", $"bytes={range.Start}-{range.End}");
        Pair("Date", headers.HttpDate);
        Pair("x-apple-destination", headers.Destination);
        Pair("x-apple-mme-owner", headers.MmeOwner);
        Pair("x-apple-opaque-ownerid", headers.OpaqueOwnerId);
        Pair("x-apple-content-partition", headers.Partition);
        Pair("x-apple-uuid", headers.Uuid);
        Pair("x-apple-date", headers.Date);
        Pair("x-apple-expires", headers.Expires);
        Pair("x-apple-signature", headers.Signature);
        Pair("x-apple-boss-recommendation-used", headers.BossRecommendationUsed);
        Pair("x-apple-incoming-icloud-edge-pop", headers.IncomingEdgePop);
    }

    private static string CleanSignedPath(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return string.Empty;

        path = path.Trim();
        if (!path.StartsWith('/'))
            path = "/" + path;

        var end = path.Length;
        while (end > 0)
        {
            var c = path[end - 1];
            if (c is '"' or '\'' or '*' or ')' or 'B' or '%' or 'z' or 'X' or ' ' or ',')
            {
                end--;
                continue;
            }

            break;
        }

        return path[..end];
    }

    private static byte[] Concat(byte[] a, byte[] b)
    {
        var result = new byte[a.Length + b.Length];
        Buffer.BlockCopy(a, 0, result, 0, a.Length);
        Buffer.BlockCopy(b, 0, result, a.Length, b.Length);
        return result;
    }
}
