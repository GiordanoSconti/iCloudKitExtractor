using System.Collections.Generic;
using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Messaggi application/vnd.com.apple.me.ubchunk+protobuf (authorizeGet) e download edge.
/// </summary>
public static class UbChunkBuilder
{
    /// <summary>
    /// Cap storico Auth Ford CT (112 / empty / packed piccoli). Path classico invariato.
    /// </summary>
    public const int MaxAuthFordCtLen = 65_536;

    /// <summary>
    /// Sanità protobuf/DoS per bag multi-key (Unify ~110KiB+). Non usare sui Ford regolari.
    /// </summary>
    public const int MaxAuthFordCtLenSanity = 32 * 1024 * 1024;

    /// <summary>Ford CT classico: <c>[0x12 .. 64KiB]</c> — stesso gate di prima.</summary>
    public static bool IsClassicAuthFordCtLen(int ctLen) =>
        ctLen is >= 0x12 and <= MaxAuthFordCtLen;

    /// <summary>Bag multi-key: <c>ctLen &gt; 64KiB</c> (richiede ByteRange host).</summary>
    public static bool IsLargeAuthFordCtLen(int ctLen) =>
        ctLen > MaxAuthFordCtLen && ctLen <= MaxAuthFordCtLenSanity;

    /// <summary>
    /// Parse: classici sempre; large solo entro sanità (ByteRange a valle).
    /// </summary>
    public static bool IsPlausibleAuthFordCtLen(int ctLen) =>
        IsClassicAuthFordCtLen(ctLen) || IsLargeAuthFordCtLen(ctLen);

    /// <summary>
    /// Bind: classici <b>ignorano</b> hostLen (comportamento storico).
    /// Large: obbligatorio <c>ctLen ≤ ByteRange length</c>.
    /// </summary>
    public static bool IsPlausibleAuthFordCtLen(int ctLen, long hostByteRangeLen)
    {
        if (IsClassicAuthFordCtLen(ctLen))
            return true;
        if (!IsLargeAuthFordCtLen(ctLen))
            return false;
        return hostByteRangeLen > 0 && ctLen <= hostByteRangeLen;
    }

    private static readonly Regex AssetSizeSuffixRegex = new(
        @":(\d+)$",
        RegexOptions.Compiled);

    private static readonly Regex ContentByteRangeRegex = new(
        @"content-byte-range=(\d+)-(\d+)",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    /// <summary>
    /// Entry authorizeGet (capture 20260809_152923):
    /// field1 = assetSignature 21B (flist), field2 = authToken CAog…,
    /// field4 = companion 21B (0x01‖20B).
    /// </summary>
    public sealed record AuthorizeGetFileEntry(
        byte[] Signature21,
        string AuthToken,
        byte[] Companion21);

    /// <summary>
    /// Body authorizeGet: outer ripetuto field1 = file-entry.
    /// f1 = flist assetSignature (ground truth); f2/f4 da CK —
    /// DA CONFERMARE A RUNTIME: origine esatta di authToken/companion.
    /// </summary>
    public static byte[] BuildAuthorizeGetRequest(IReadOnlyList<AuthorizeGetFileEntry> entries)
    {
        if (entries is null || entries.Count == 0)
            throw new ArgumentException("Serve almeno una entry authorizeGet.", nameof(entries));

        var outer = new ProtobufWriter();
        foreach (var e in entries)
        {
            if (e.Signature21 is not { Length: 21 })
                throw new ArgumentException("Signature21 deve essere 21 byte (assetSignature).");
            if (e.Companion21 is not { Length: 21 })
                throw new ArgumentException("Companion21 deve essere 21 byte.");
            if (string.IsNullOrWhiteSpace(e.AuthToken))
                throw new ArgumentException("AuthToken CAog assente.");

            var inner = new ProtobufWriter();
            inner.WriteBytes(1, e.Signature21);
            inner.WriteString(2, e.AuthToken.Trim());
            inner.WriteBytes(4, e.Companion21);
            outer.WriteBytes(1, inner.ToArray());
        }

        return outer.ToArray();
    }

    /// <summary>
    /// Header <c>x-apple-mmcs-auth</c> = solo entry[0]:
    /// <c>hex(f1) hex(f4) ascii(f2)</c> (capture batch 12-file).
    /// </summary>
    public static string BuildMmcsAuthHeader(AuthorizeGetFileEntry entry0)
    {
        if (entry0.Signature21 is not { Length: 21 })
            throw new ArgumentException("Signature21 deve essere 21 byte.");
        if (entry0.Companion21 is not { Length: 21 })
            throw new ArgumentException("Companion21 deve essere 21 byte.");
        if (string.IsNullOrWhiteSpace(entry0.AuthToken))
            throw new ArgumentException("AuthToken assente.");

        return $"{Convert.ToHexString(entry0.Signature21).ToLowerInvariant()} " +
               $"{Convert.ToHexString(entry0.Companion21).ToLowerInvariant()} " +
               entry0.AuthToken.Trim();
    }

    /// <summary>Body authorizeGet monofile da header x-apple-mmcs-auth a 3 parti.</summary>
    public static byte[] BuildAuthorizeGetRequest(string mmcsAuthHeader)
    {
        if (string.IsNullOrWhiteSpace(mmcsAuthHeader))
            throw new ArgumentException("Header x-apple-mmcs-auth assente.", nameof(mmcsAuthHeader));

        var parts = mmcsAuthHeader.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
            throw new ArgumentException("Header x-apple-mmcs-auth incompleto (attesi 3 parti).");

        var entry = new AuthorizeGetFileEntry(
            DecodeAuthToken(parts[0]),
            parts[2],
            DecodeAuthToken(parts[1]));
        return BuildAuthorizeGetRequest([entry]);
    }

    /// <summary>
    /// Estrae le entry file (f1/f2/f4) da un body authorizeGet request —
    /// utile per correlazione flist↔capture.
    /// </summary>
    public static IReadOnlyList<AuthorizeGetFileEntry> ParseAuthorizeGetRequestEntries(
        ReadOnlySpan<byte> body)
    {
        var list = new List<AuthorizeGetFileEntry>();
        var reader = new ProtobufReader(body);
        while (reader.HasMore)
        {
            var (fn, wt) = reader.ReadTag();
            if (fn == 0)
                break;
            if (wt != 2)
            {
                reader.SkipField(wt);
                continue;
            }

            var entryBytes = reader.ReadLengthDelimited();
            if (fn != 1)
                continue;

            byte[]? sig = null;
            string? token = null;
            byte[]? companion = null;
            var inner = new ProtobufReader(entryBytes);
            while (inner.HasMore)
            {
                var (ifn, iwt) = inner.ReadTag();
                if (ifn == 0)
                    break;
                if (iwt != 2)
                {
                    inner.SkipField(iwt);
                    continue;
                }

                var raw = inner.ReadLengthDelimited();
                switch (ifn)
                {
                    case 1:
                        sig = raw;
                        break;
                    case 2:
                        token = Encoding.UTF8.GetString(raw);
                        break;
                    case 4:
                        companion = raw;
                        break;
                }
            }

            if (sig is { Length: 21 } && companion is { Length: 21 }
                && !string.IsNullOrWhiteSpace(token))
                list.Add(new AuthorizeGetFileEntry(sig, token, companion));
        }

        return list;
    }

    public static long? ExtractDeclaredSize(string recordName)
    {
        var m = AssetSizeSuffixRegex.Match(recordName);
        return m.Success && long.TryParse(m.Groups[1].Value, out var size) ? size : null;
    }

    public static IReadOnlyList<SignedUrlChunk> ParseAuthorizeGetResponse(ReadOnlySpan<byte> data)
    {
        // live (x64dbg 03cce7): URL = {scheme}://{host}:{port}{path} da FileGroup
        // HTTP template (f7/f1/f2/f4). Nessuna URL intera sul wire.
        var structured = TryParseAuthorizeGetResponseFromFileGroups(data);
        var usedStructured = structured.Count > 0;
        var chunks = usedStructured ? structured : ParseAuthorizeGetResponseLegacyScan(data);

        // Chiavi crypto: un oggetto edge può contenere N ChunkInfo (es. 6×5 MiB).
        // FileGroup.f2 = ChunkInfo {f1 checksum21/45, f2 key, f3 ctLen, f4 packOffset}.
        var crypto = ExtractAuthorizeGetCryptoChunks(data);
        if (crypto.Count > 0 && crypto.Count == chunks.Count)
        {
            for (var i = 0; i < chunks.Count; i++)
            {
                // Preferisci ctLen/offset già presi da FileGroup.f2; completa da crypto scan.
                var ct = chunks[i].CtLen > 0 ? chunks[i].CtLen : crypto[i].Length;
                var off = chunks[i].CtLen > 0 ? chunks[i].PackOffset : crypto[i].Offset;
                chunks[i] = chunks[i] with
                {
                    ChunkEncryptionKey = crypto[i].EncryptionKey,
                    PackOffset = off,
                    CtLen = ct,
                };
            }
        }
        else if (crypto.Count == 1 && chunks.Count == 1)
        {
            var ct = chunks[0].CtLen > 0 ? chunks[0].CtLen : crypto[0].Length;
            var off = chunks[0].CtLen > 0 ? chunks[0].PackOffset : crypto[0].Offset;
            chunks[0] = chunks[0] with
            {
                ChunkEncryptionKey = crypto[0].EncryptionKey,
                PackOffset = off,
                CtLen = ct,
            };
        }

        // #region agent log
        AgentUrlAlignLog(
            usedStructured,
            chunks.Count,
            chunks.Count > 0 ? chunks[0].Url : "",
            chunks.Count > 0 ? chunks[0].CtLen : 0,
            chunks.Count > 0 ? chunks[0].PackOffset : 0);
        // #endregion

        return chunks;
    }

    /// <summary>
    /// <c>BuildEdgeUrl +0x680320</c>: un FileGroup → un GET
    /// <c>{f7}://{f1}:{f2}{f4}</c> + headers f8.
    /// </summary>
    private static List<SignedUrlChunk> TryParseAuthorizeGetResponseFromFileGroups(
        ReadOnlySpan<byte> data)
    {
        var templates = new List<HttpTemplateWire>(8);
        CollectHttpTemplates(data, templates, depth: 0);
        if (templates.Count == 0)
            return [];

        var chunks = new List<SignedUrlChunk>(templates.Count);
        var skipPath = 0;
        foreach (var t in templates)
        {
            var path = CleanPath(t.Path);
            if (path.Length == 0 || !path.StartsWith('/'))
            {
                skipPath++;
                continue;
            }

            var scheme = string.IsNullOrEmpty(t.Scheme) ? "https" : t.Scheme;
            var host = string.IsNullOrEmpty(t.Host) ? "edge.icloud-content.com" : t.Host;
            var port = t.Port is > 0 and <= 65535 ? t.Port : 443;
            var url = $"{scheme}://{host}:{port}{path}";

            var headerMap = t.Headers;
            var edge = BuildEdgeHeaders(headerMap);
            var objectId = ExtractObjectId(path);
            if (!string.IsNullOrEmpty(objectId))
                edge = edge with { ObjectId = objectId };

            var urlUuid = ExtractClientRequestIdFromPath(path);
            if (!string.IsNullOrEmpty(urlUuid))
                edge = edge with { Uuid = urlUuid };
            else if (string.IsNullOrEmpty(edge.Uuid))
                edge = edge with { Uuid = SanitizeUuid(edge.Uuid) };

            var range = ExtractContentByteRange(path);
            if (!range.HasValue && headerMap.TryGetValue("Range", out var rangeHeader))
                range = ParseRange(rangeHeader);

            chunks.Add(new SignedUrlChunk
            {
                Url = url,
                ByteRange = range,
                EdgeHeaders = edge,
                CtLen = t.IntegrityCtLen,
                PackOffset = t.IntegrityPackOffset,
            });
        }

        // #region agent log
        if (templates.Count > 0 && chunks.Count == 0)
        {
            try
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = "ike-parity-wireoff-v7",
                        ["hypothesisId"] = "H-PARSE-HOST0",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "UbChunkBuilder.TryParseAuthorizeGetResponseFromFileGroups",
                        ["message"] = "templates_but_zero_chunks",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["templates"] = templates.Count,
                            ["skipPath"] = skipPath,
                            ["path0"] = templates[0].Path.Length > 80
                                ? templates[0].Path[..80]
                                : templates[0].Path,
                            ["host0"] = templates[0].Host,
                        },
                    }) + Environment.NewLine);
            }
            catch
            {
                /* ignore */
            }
        }
        // #endregion

        return chunks;
    }

    private readonly record struct HttpTemplateWire(
        string Scheme,
        string Host,
        int Port,
        string Path,
        Dictionary<string, string> Headers,
        int IntegrityCtLen,
        long IntegrityPackOffset);

    private static void CollectHttpTemplates(
        ReadOnlySpan<byte> buf,
        List<HttpTemplateWire> outList,
        int depth)
        => CollectHttpTemplates(buf, outList, outContainers: null, depth);

    /// <summary>
    ///  1 FileGroup → 1 GET host (+ ChunkInfo f2 del gruppo, 0..N).
    /// </summary>
    private static void CollectHttpTemplates(
        ReadOnlySpan<byte> buf,
        List<HttpTemplateWire> outList,
        List<List<AuthorizeGetCryptoChunk>>? outContainers,
        int depth)
    {
        if (depth > 12 || buf.Length < 8)
            return;

        // FileGroup: f1=HTTP template, f2=ChunkInfo integrity, …
        if (TryParseFileGroupHttp(buf, out var wire, out var cis))
        {
            outList.Add(wire);
            outContainers?.Add(cis);
            return;
        }

        var p = 0;
        while (p < buf.Length)
        {
            var start = p;
            if (!TryReadVarintInt(buf, ref p, out var key))
                break;
            var fn = key >> 3;
            var wt = key & 7;
            if (fn == 0)
                break;
            if (wt == 2)
            {
                if (!TryReadVarintInt(buf, ref p, out var len)
                    || len < 0
                    || (uint)p + (uint)len > (uint)buf.Length)
                    break;
                var chunk = buf.Slice(p, len);
                p += len;
                if (len >= 24)
                    CollectHttpTemplates(chunk, outList, outContainers, depth + 1);
            }
            else if (wt == 0)
            {
                if (!TryReadVarintLong(buf, ref p, out _))
                    break;
            }
            else if (wt == 1)
            {
                if (p + 8 > buf.Length)
                    break;
                p += 8;
            }
            else if (wt == 5)
            {
                if (p + 4 > buf.Length)
                    break;
                p += 4;
            }
            else
            {
                break;
            }

            if (p <= start)
                break;
        }
    }

    private static bool TryParseFileGroupHttp(
        ReadOnlySpan<byte> group,
        out HttpTemplateWire wire)
        => TryParseFileGroupHttp(group, out wire, out _);

    private static bool TryParseFileGroupHttp(
        ReadOnlySpan<byte> group,
        out HttpTemplateWire wire,
        out List<AuthorizeGetCryptoChunk> cis)
    {
        wire = default;
        cis = [];
        string? host = null;
        string? path = null;
        string? scheme = null;
        var port = 0;
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var ctLen = 0;
        long packOff = 0;
        var sawHttp = false;
        var parsedCis = new List<AuthorizeGetCryptoChunk>(2);

        var p = 0;
        while (p < group.Length)
        {
            if (!TryReadVarintInt(group, ref p, out var key))
                return false;
            var fn = key >> 3;
            var wt = key & 7;
            if (fn == 0)
                break;

            if (wt == 2)
            {
                if (!TryReadVarintInt(group, ref p, out var len)
                    || len < 0
                    || (uint)p + (uint)len > (uint)group.Length)
                    return false;
                var payload = group.Slice(p, len);
                p += len;

                if (fn == 1 && TryParseHttpTemplateMessage(payload, out host, out port, out path, out scheme, out headers))
                {
                    sawHttp = true;
                }
                else if (fn == 2
                         && TryParseChunkInfoMessage(
                             payload, out var ciKey, out var ciLen, out var ciCs, out var ciOff))
                {
                    // FileGroup.f2 = ChunkInfo: f3 ctLen, f4 pack offset (live).
                    ctLen = ciLen;
                    packOff = ciOff;
                    parsedCis.Add(new AuthorizeGetCryptoChunk
                    {
                        EncryptionKey = ciKey,
                        Length = ciLen,
                        Checksum21 = ciCs,
                        Offset = ciOff,
                    });
                }
            }
            else if (wt == 0)
            {
                if (!TryReadVarintLong(group, ref p, out _))
                    return false;
            }
            else if (wt == 1)
            {
                if (p + 8 > group.Length)
                    return false;
                p += 8;
            }
            else if (wt == 5)
            {
                if (p + 4 > group.Length)
                    return false;
                p += 4;
            }
            else
            {
                return false;
            }
        }

        if (!sawHttp || string.IsNullOrEmpty(path) || string.IsNullOrEmpty(host))
            return false;
        if (!path.Contains("content-byte-range", StringComparison.OrdinalIgnoreCase))
            return false;

        wire = new HttpTemplateWire(
            scheme ?? "https",
            host!,
            port > 0 ? port : 443,
            path!,
            headers,
            ctLen,
            packOff);
        cis = parsedCis;
        return true;
    }

    private static bool TryParseHttpTemplateMessage(
        ReadOnlySpan<byte> msg,
        out string? host,
        out int port,
        out string? path,
        out string? scheme,
        out Dictionary<string, string> headers)
    {
        host = null;
        path = null;
        scheme = null;
        port = 0;
        headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        var p = 0;
        while (p < msg.Length)
        {
            if (!TryReadVarintInt(msg, ref p, out var key))
                return false;
            var fn = key >> 3;
            var wt = key & 7;
            if (fn == 0)
                break;

            if (wt == 2)
            {
                if (!TryReadVarintInt(msg, ref p, out var len)
                    || len < 0
                    || (uint)p + (uint)len > (uint)msg.Length)
                    return false;
                var payload = msg.Slice(p, len);
                p += len;
                switch (fn)
                {
                    case 1 when IsAsciiHost(payload):
                        host = Encoding.ASCII.GetString(payload);
                        break;
                    case 3 when IsAsciiToken(payload):
                        // method GET — ignored for URL
                        break;
                    case 4 when payload.Length > 0 && payload[0] == (byte)'/':
                        path = Encoding.ASCII.GetString(payload);
                        break;
                    case 5 or 6:
                        break;
                    case 7 when IsAsciiToken(payload):
                        scheme = Encoding.ASCII.GetString(payload);
                        break;
                    case 8:
                        TryAddHeaderPair(payload, headers);
                        break;
                }
            }
            else if (wt == 0)
            {
                if (!TryReadVarintLong(msg, ref p, out var v))
                    return false;
                if (fn == 2 && v is > 0 and <= 65535)
                    port = (int)v;
            }
            else if (wt == 1)
            {
                if (p + 8 > msg.Length)
                    return false;
                p += 8;
            }
            else if (wt == 5)
            {
                if (p + 4 > msg.Length)
                    return false;
                p += 4;
            }
            else
            {
                return false;
            }
        }

        return !string.IsNullOrEmpty(host)
               && !string.IsNullOrEmpty(path)
               && path!.Contains("content-byte-range", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsAsciiHost(ReadOnlySpan<byte> b)
    {
        if (b.Length is < 3 or > 253)
            return false;
        var dot = false;
        foreach (var c in b)
        {
            if (c == (byte)'.')
                dot = true;
            else if (!((c is >= (byte)'a' and <= (byte)'z')
                       || (c is >= (byte)'A' and <= (byte)'Z')
                       || (c is >= (byte)'0' and <= (byte)'9')
                       || c is (byte)'-' or (byte)'_'))
                return false;
        }

        return dot;
    }

    private static bool IsAsciiToken(ReadOnlySpan<byte> b)
    {
        if (b.IsEmpty || b.Length > 32)
            return false;
        foreach (var c in b)
        {
            if (c is < 0x20 or > 0x7E)
                return false;
        }

        return true;
    }

    private static void TryAddHeaderPair(
        ReadOnlySpan<byte> headerMsg,
        Dictionary<string, string> headers)
    {
        string? name = null;
        string? value = null;
        var p = 0;
        while (p < headerMsg.Length)
        {
            if (!TryReadVarintInt(headerMsg, ref p, out var key))
                return;
            var fn = key >> 3;
            var wt = key & 7;
            if (wt != 2)
            {
                if (wt == 0)
                {
                    if (!TryReadVarintLong(headerMsg, ref p, out _))
                        return;
                }
                else
                    return;
                continue;
            }

            if (!TryReadVarintInt(headerMsg, ref p, out var len)
                || len < 0
                || (uint)p + (uint)len > (uint)headerMsg.Length)
                return;
            var raw = headerMsg.Slice(p, len);
            p += len;
            if (fn == 1)
                name = Encoding.ASCII.GetString(raw);
            else if (fn == 2)
                value = Encoding.UTF8.GetString(raw);
        }

        if (!string.IsNullOrEmpty(name) && value is not null && !headers.ContainsKey(name))
            headers[name] = CleanToken(value);
    }

    /// <summary>Fallback storico: scan stringhe ASCII (host hardcodato edge).</summary>
    private static List<SignedUrlChunk> ParseAuthorizeGetResponseLegacyScan(ReadOnlySpan<byte> data)
    {
        var ordered = CollectOrderedStrings(data);

        var pathIndices = new List<int>();
        for (var i = 0; i < ordered.Count; i++)
        {
            var s = ordered[i];
            if (s.StartsWith('/') && s.Contains("content-byte-range", StringComparison.Ordinal))
                pathIndices.Add(i);
        }

        if (pathIndices.Count == 0)
            return [];

        var pathByteOffsets = new List<int>(pathIndices.Count);
        foreach (var pathIdx in pathIndices)
        {
            var path = CleanPath(ordered[pathIdx]);
            var off = IndexOfBytes(data, Encoding.ASCII.GetBytes(ordered[pathIdx]));
            if (off < 0)
            {
                var objectPart = path.Contains('?', StringComparison.Ordinal)
                    ? path[..path.IndexOf('?')]
                    : path;
                off = IndexOfBytes(data, Encoding.ASCII.GetBytes(objectPart));
            }

            pathByteOffsets.Add(off);
        }

        var chunks = new List<SignedUrlChunk>(pathIndices.Count);
        for (var ci = 0; ci < pathIndices.Count; ci++)
        {
            var pathIdx = pathIndices[ci];
            var blockEnd = ci + 1 < pathIndices.Count ? pathIndices[ci + 1] : ordered.Count;
            var block = ordered.GetRange(pathIdx, blockEnd - pathIdx);
            var path = CleanPath(block[0]);

            Dictionary<string, string> pbHeaders;
            var rawStart = pathByteOffsets[ci];
            if (rawStart >= 0)
            {
                var rawEnd = ci + 1 < pathByteOffsets.Count && pathByteOffsets[ci + 1] > rawStart
                    ? pathByteOffsets[ci + 1]
                    : data.Length;
                pbHeaders = ExtractProtobufHeaderMap(data[rawStart..rawEnd]);
            }
            else
            {
                pbHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            }

            var headerMap = MergeHeaderMaps(pbHeaders, ParseHeaderMap(block));
            var edge = BuildEdgeHeaders(headerMap);

            var objectId = ExtractObjectId(path);
            if (!string.IsNullOrEmpty(objectId))
                edge = edge with { ObjectId = objectId };

            var urlUuid = ExtractClientRequestIdFromPath(path);
            if (!string.IsNullOrEmpty(urlUuid))
                edge = edge with { Uuid = urlUuid };
            else if (string.IsNullOrEmpty(edge.Uuid))
                edge = edge with { Uuid = SanitizeUuid(edge.Uuid) };

            var range = ExtractContentByteRange(path);
            if (!range.HasValue && headerMap.TryGetValue("Range", out var rangeHeader))
                range = ParseRange(rangeHeader);

            // Legacy: stesso host/port default di BuildEdgeUrl quando manca il template.
            chunks.Add(new SignedUrlChunk
            {
                Url = $"https://edge.icloud-content.com:443{path}",
                ByteRange = range,
                EdgeHeaders = edge
            });
        }

        return chunks;
    }

    // #region agent log
    private static int _urlAlignLogCount;
    private static void AgentUrlAlignLog(
        bool structured,
        int count,
        string firstUrl,
        int ctLen,
        long packOffset)
    {
        if (Interlocked.Increment(ref _urlAlignLogCount) > 8)
            return;
        try
        {
            var path = @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log";
            var url = firstUrl ?? "";
            var urlEsc = url.Replace("\\", "\\\\").Replace("\"", "\\\"");
            var hasPort = url.Contains(":443", StringComparison.Ordinal)
                          || url.Contains("://", StringComparison.Ordinal);
            var line =
                "{\"sessionId\":\"03cce7\",\"runId\":\"ike-url-align\",\"hypothesisId\":\"H-url\"," +
                "\"location\":\"UbChunkBuilder.ParseAuthorizeGetResponse\"," +
                "\"message\":\"authorizeGet URL assemble\"," +
                $"\"data\":{{\"structured\":{(structured ? "true" : "false")},\"chunks\":{count}," +
                $"\"firstUrl\":\"{urlEsc}\",\"ctLen\":{ctLen},\"packOffset\":{packOffset}," +
                $"\"hasSchemeHostPort\":{(hasPort ? "true" : "false")}}}," +
                $"\"timestamp\":{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}}}\n";
            File.AppendAllText(path, line);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    private static int IndexOfBytes(ReadOnlySpan<byte> hay, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || needle.Length > hay.Length)
            return -1;
        for (var i = 0; i <= hay.Length - needle.Length; i++)
        {
            if (hay.Slice(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }

    /// <summary>
    /// ChunkInfo authorizeGet (InflatableDonkey): checksum ‖ chunkEncryptionKey ‖ chunkLength.
    /// Un GET edge può trasportare più ChunkInfo concatenati; la somma delle length = size file.
    /// </summary>
    public static IReadOnlyList<AuthorizeGetCryptoChunk> ExtractAuthorizeGetCryptoChunks(
        ReadOnlySpan<byte> data)
    {
        var list = new List<AuthorizeGetCryptoChunk>();
        var bytes = data;
        for (var i = 0; i + 4 < bytes.Length; i++)
        {
            // field 2 length-delimited wrapping ChunkInfo: 0x12 ‖ varint(len) ‖ message
            if (bytes[i] != 0x12)
                continue;

            var pos = i + 1;
            if (!TryReadVarintInt(bytes, ref pos, out var msgLen))
                continue;
            // H-AOR2: false-positive ChunkInfo can decode a huge/negative len;
            // Gate45 CI (~50–70 B) + data CI; allow up to 128.
            if (msgLen is < 24 or > 128
                || (uint)pos + (uint)msgLen > (uint)bytes.Length)
                continue;

            ReadOnlySpan<byte> msg;
            try
            {
                msg = bytes.Slice(pos, msgLen);
            }
            catch (ArgumentOutOfRangeException)
            {
                continue;
            }

            if (!TryParseChunkInfoMessage(msg, out var key, out var chunkLen, out var checksum, out var offset))
                continue;

            list.Add(new AuthorizeGetCryptoChunk
            {
                EncryptionKey = key,
                Length = chunkLen,
                Checksum21 = checksum,
                Offset = offset
            });
            i = pos + msgLen - 1; // loop +1
        }

        return list;
    }

    /// <summary>
    /// Solo le chiavi, in ordine ChunkInfo (preferire <see cref="ExtractAuthorizeGetCryptoChunks"/>).
    /// </summary>
    public static IReadOnlyList<byte[]> ExtractChunkEncryptionKeys(ReadOnlySpan<byte> data) =>
        ExtractAuthorizeGetCryptoChunks(data).Select(static c => c.EncryptionKey).ToList();

    /// <summary>
    /// Piano decrypt MMCS: container edge (StorageHostChunkList) + ChunkInfo +
    /// <c>FileChecksumChunkReferences</c> per riassemblare il file nell'ordine corretto.
    /// </summary>
    public static AuthorizeGetDecryptPlan BuildDecryptPlan(ReadOnlySpan<byte> authorizeGetBody)
    {
        var data = authorizeGetBody;
        var positioned = ExtractAuthorizeGetCryptoChunksPositioned(data);

        //  1 FileGroup → 1 container → solo ChunkInfo f2 di quel gruppo.
        // Evita pathOffsets binning che mescola CI nested Auth in un host Ford.
        List<IReadOnlyList<AuthorizeGetCryptoChunk>> containers;
        var usedFileGroups = TryBuildContainersFromFileGroups(data, out var fgContainers);
        if (usedFileGroups)
        {
            containers = fgContainers!;
        }
        else
        {
            var pathOffsets = FindContentByteRangeOffsets(data);
            if (pathOffsets.Count == 0)
            {
                containers =
                [
                    positioned.Select(static p => p.Chunk).ToList()
                ];
            }
            else
            {
                containers = new List<IReadOnlyList<AuthorizeGetCryptoChunk>>(pathOffsets.Count);
                for (var pi = 0; pi < pathOffsets.Count; pi++)
                {
                    var start = pathOffsets[pi];
                    var end = pi + 1 < pathOffsets.Count ? pathOffsets[pi + 1] : data.Length;
                    var group = positioned
                        .Where(p => p.Position >= start && p.Position < end)
                        .Select(static p => p.Chunk)
                        .ToList();
                    containers.Add(group);
                }
            }
        }

        var totalChunks = containers.Sum(static c => c.Count);
        var lastChunkPos = positioned.Count > 0 ? positioned[^1].Position : 0;
        var trailingPayload = TryGetTrailingFileRefsPayload(data);
        IReadOnlyList<AuthorizeGetChunkRef> refs;
        byte[]? fileChecksum = null;
        byte[]? companionChecksum = null;
        if (trailingPayload is { Length: > 0 } tp)
        {
            refs = ParseRefsPayload(tp, containers.Count);
            TryExtractFileChecksumsFromRefsPayload(tp, out fileChecksum, out companionChecksum);
        }
        else
        {
            //  FileChecksumChunkReferences dal trailing Auth. Niente refs sequenziali inventate.
            refs = ExtractFileChunkReferences(data, containers, totalChunks, lastChunkPos);
        }

        // #region agent log
        AgentIkePlanLog(usedFileGroups, containers, positioned.Count);
        // #endregion

        return new AuthorizeGetDecryptPlan
        {
            Containers = containers,
            References = refs,
            FileChecksum = fileChecksum,
            CompanionChecksum = companionChecksum,
        };
    }

    /// <summary>
    /// FileGroups.ParseFrom: ogni FileGroup = un container con i suoi f2 ChunkInfo
    /// (0 = empty Ford, 1 = tipico Ford/data, N = multi-CI nello stesso GET).
    /// </summary>
    private static bool TryBuildContainersFromFileGroups(
        ReadOnlySpan<byte> data,
        out List<IReadOnlyList<AuthorizeGetCryptoChunk>>? containers)
    {
        containers = null;
        var templates = new List<HttpTemplateWire>(8);
        var cis = new List<List<AuthorizeGetCryptoChunk>>(8);
        CollectHttpTemplates(data, templates, cis, depth: 0);
        if (templates.Count == 0 || cis.Count != templates.Count)
            return false;

        containers = new List<IReadOnlyList<AuthorizeGetCryptoChunk>>(cis.Count);
        foreach (var g in cis)
            containers.Add(g);
        return true;
    }

    // #region agent log
    private static int _ikePlanLogCount;

    private static void AgentIkePlanLog(
        bool usedFileGroups,
        List<IReadOnlyList<AuthorizeGetCryptoChunk>> containers,
        int positionedCount)
    {
        if (Interlocked.Increment(ref _ikePlanLogCount) > 24)
            return;
        try
        {
            var fordHosts = 0;
            var multiFord = 0;
            var emptyHosts = 0;
            var mismatch112 = 0;
            for (var i = 0; i < containers.Count; i++)
            {
                var g = containers[i];
                if (g.Count == 0)
                {
                    emptyHosts++;
                    continue;
                }

                var fordN = 0;
                foreach (var ch in g)
                {
                    if (IsAuthFordDescriptorChunk(ch))
                        fordN++;
                }

                if (fordN > 0)
                    fordHosts++;
                if (fordN > 1)
                    multiFord++;
                if (fordN == 1 && g.Count == 1 && IsPlausibleAuthFordCtLen(g[0].Length))
                {
                    // placeholder: logged below via sample
                }

                if (g.Count >= 2 && fordN >= 2)
                    mismatch112++;
            }

            var path =
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log";
            var line =
                "{\"sessionId\":\"03cce7\",\"runId\":\"ike-fg-1to1\",\"hypothesisId\":\"H-IKE-FG\"," +
                "\"location\":\"UbChunkBuilder.BuildDecryptPlan\"," +
                "\"message\":\"decrypt_plan_containers\"," +
                $"\"data\":{{\"usedFileGroups\":{(usedFileGroups ? "true" : "false")}," +
                $"\"hosts\":{containers.Count},\"positionedScan\":{positionedCount}," +
                $"\"fordHosts\":{fordHosts},\"emptyHosts\":{emptyHosts}," +
                $"\"multiFordCiHosts\":{multiFord},\"multiFordPackedSuspect\":{mismatch112}}}," +
                $"\"timestamp\":{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}}}\n";
            File.AppendAllText(path, line);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    /// <summary>
    /// Wire: <c>FileChecksumChunkReferences</c> field1 = FileChecksum (21B),
    /// field3 = companion (21B). Gate45 = <c>0C0F01 ‖ FileChecksum ‖ Companion</c>.
    /// </summary>
    public static bool TryExtractFileChecksumsFromRefsPayload(
        ReadOnlySpan<byte> refsPayload,
        out byte[]? fileChecksum,
        out byte[]? companionChecksum)
    {
        fileChecksum = null;
        companionChecksum = null;
        var pos = 0;
        while (pos < refsPayload.Length)
        {
            var tag = refsPayload[pos++];
            var field = tag >> 3;
            var wire = tag & 0x07;
            if (wire == 2)
            {
                if (!TryReadVarintInt(refsPayload, ref pos, out var len)
                    || (uint)pos + (uint)len > (uint)refsPayload.Length)
                    break;
                var msg = refsPayload.Slice(pos, len);
                pos += len;
                if (len == 21 && msg[0] is 0x04 or 0x01)
                {
                    if (field == 1 && fileChecksum is null)
                        fileChecksum = msg.ToArray();
                    else if (field == 3 && companionChecksum is null)
                        companionChecksum = msg.ToArray();
                }
            }
            else if (wire == 0)
            {
                if (!TryReadVarintLong(refsPayload, ref pos, out _))
                    break;
            }
            else
            {
                break;
            }
        }

        return fileChecksum is { Length: 21 };
    }

    /// <summary>
    /// Gate45  <c>0C0F01 ‖ fileChecksum21 ‖ companion21</c>.
    /// </summary>
    public static bool GateEmbedsFileChecksum(
        ReadOnlySpan<byte> gate45,
        ReadOnlySpan<byte> fileChecksum21)
        => gate45.Length == 45
           && fileChecksum21.Length == 21
           && gate45[0] == 0x0C
           && gate45[1] == 0x0F
           && gate45[2] == 0x01
           && gate45.Slice(3, 21).SequenceEqual(fileChecksum21);

    /// <summary>
    /// Part owned dal Gate45: identity = FileChecksum (refs.field1) nel gate.
    /// Companion (gate[24:45]) viene dal descriptor Auth — non filtrare su
    /// <see cref="AuthorizeGetDecryptPlan.CompanionChecksum"/> (può essere stale/AG).
    /// </summary>
    public static bool GateOwnsPlan(ReadOnlySpan<byte> gate45, AuthorizeGetDecryptPlan plan)
    {
        if (gate45.Length != 45 || plan.FileChecksum is not { Length: 21 } fc)
            return false;
        return GateEmbedsFileChecksum(gate45, fc);
    }

    private static byte[]? TryGetTrailingFileRefsPayload(ReadOnlySpan<byte> authorizeGetBody)
    {
        var body = UnwrapSingleField1(authorizeGetBody);
        var fields = WalkLengthDelimitedFields(body);
        if (fields.Count == 0)
            fields = WalkLengthDelimitedFields(authorizeGetBody);

        PbField? last = null;
        foreach (var f in fields)
        {
            if (f.Field == 2)
                last = f;
        }

        return last is { } l ? l.Payload.ToArray() : null;
    }

    /// <summary>
    /// <c>FileChecksumChunkReferences</c> in coda all'authorizeGet (ultimo field 2).
    /// In slice per-file è già rimappato (es. 9:0 → 1:0). Non è la permutazione
    /// di tutti i ChunkInfo dell'host condiviso.
    /// </summary>
    public static IReadOnlyList<AuthorizeGetChunkRef> ParseTrailingFileRefs(
        ReadOnlySpan<byte> authorizeGetBody,
        int hostCount)
    {
        if (hostCount <= 0)
            return [];

        var payload = TryGetTrailingFileRefsPayload(authorizeGetBody);
        if (payload is null)
            return [];
        return ParseRefsPayload(payload, hostCount);
    }

    /// <summary>
    /// <c>FileGroups</c> è spesso wrappato in un field-1. Ogni file è un blocco
    /// <c>StorageHostChunkList+</c> seguito da <c>FileChecksumChunkReferences</c> (field 2).
    /// </summary>
    public static IReadOnlyList<byte[]> SplitFileGroups(ReadOnlySpan<byte> data)
    {
        var body = UnwrapSingleField1(data);
        var fields = WalkLengthDelimitedFields(body);
        if (fields.Count == 0)
            return [data.ToArray()];

        var groups = new List<byte[]>();
        var current = new List<byte[]>();
        foreach (var f in fields)
        {
            current.Add(f.Raw);
            if (f.Field != 2)
                continue;
            groups.Add(Concat(current));
            current.Clear();
        }

        if (current.Count > 0)
            groups.Add(Concat(current));

        if (groups.Count == 0)
            return [data.ToArray()];
        return groups;
    }

    /// <summary>
    /// FileGroups.ParseFrom: host list <b>condivisa</b> + un blocco refs per file.
    /// Indici container globali (nessun remap / demux). FillContainers scarica tutti;
    /// FillChunks per file cammina refs + storage HAS-Ford.
    /// </summary>
    public static IReadOnlyList<AuthorizeGetFilePart> ParseAuthorizeGetFiles(ReadOnlySpan<byte> data)
    {
        var original = data.ToArray();
        var body = UnwrapSingleField1(data);
        var fields = WalkLengthDelimitedFields(body);
        var hostFields = fields.Where(static f => f.Field == 1).ToList();
        var refFields = fields.Where(static f => f.Field == 2).ToList();
        if (hostFields.Count == 0 || refFields.Count <= 1)
            return [new AuthorizeGetFilePart(ParseAuthorizeGetResponse(original), original)];

        var hostConcat = Concat(hostFields.Select(static h => h.Raw).ToList());
        var allChunks = ParseAuthorizeGetResponse(hostConcat);
        if (allChunks.Count != hostFields.Count)
            return [new AuthorizeGetFilePart(ParseAuthorizeGetResponse(original), original)];

        var parts = new List<AuthorizeGetFilePart>(refFields.Count);
        foreach (var rf in refFields)
        {
            var fileRefs = ParseRefsPayload(rf.Payload, hostFields.Count);
            if (fileRefs.Count == 0)
                continue;

            // ParseFrom: tutti gli host + refs di questo file (indici globali).
            var sliceParts = new List<byte[]>(hostFields.Count + 1);
            foreach (var h in hostFields)
                sliceParts.Add(h.Raw);
            var field2 = new ProtobufWriter();
            field2.WriteBytes(2, rf.Payload);
            sliceParts.Add(field2.ToArray());
            parts.Add(new AuthorizeGetFilePart(allChunks, Concat(sliceParts)));
        }

        return parts.Count > 0
            ? parts
            : [new AuthorizeGetFilePart(ParseAuthorizeGetResponse(original), original)];
    }

    /// <summary>
    /// Host da scaricare/assemblare per <b>questo</b> FileGroup:
    /// container citati dai refs + Ford owned (gate⊃FileChecksum o empty adiacente).
    /// Mai tutti gli host dell'AG multi-file (Gemma 119× → compact 2.8 GB su ogni plist).
    /// </summary>
    public static List<int> SelectFileGroupDownloadHostIndices(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> allHosts)
    {
        var n = Math.Min(plan.Containers.Count, allHosts.Count);
        var needed = new HashSet<int>();

        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex < (uint)n)
                needed.Add(r.ContainerIndex);
        }

        var fc = plan.FileChecksum;
        for (var i = 0; i < n; i++)
        {
            if (needed.Contains(i))
                continue;
            if (string.IsNullOrEmpty(allHosts[i].Url) || allHosts[i].ByteRange is null)
                continue;

            var group = plan.Containers[i];
            var fordHost = IsAuthFordMaterialHost(group) || IsFordSizedHostLengths(group);
            if (!fordHost)
                continue;

            var owned = false;
            if (fc is { Length: 21 })
            {
                foreach (var ch in group)
                {
                    if (IsAuthFordDescriptorChunk(ch)
                        && GateEmbedsFileChecksum(ch.Checksum21, fc))
                    {
                        owned = true;
                        break;
                    }
                }
            }

            // Empty Ford host (ci==0) accanto a un data-host già needed (storages=2).
            if (!owned && group.Count == 0
                && (needed.Contains(i - 1) || needed.Contains(i + 1)))
                owned = true;

            if (owned)
                needed.Add(i);
        }

        // Piano senza refs (o parse povero): fallback storico = tutti gli host validi.
        if (needed.Count == 0)
        {
            for (var i = 0; i < n; i++)
            {
                if (!string.IsNullOrEmpty(allHosts[i].Url) && allHosts[i].ByteRange is not null)
                    needed.Add(i);
            }
        }

        var list = needed.Where(i =>
                (uint)i < (uint)allHosts.Count
                && !string.IsNullOrEmpty(allHosts[i].Url)
                && allHosts[i].ByteRange is not null)
            .OrderBy(static i => i)
            .ToList();

        // #region agent log
        if (Interlocked.Increment(ref _ikeSelectLogCount) <= 48)
        {
            try
            {
                var path =
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log";
                var line =
                    "{\"sessionId\":\"03cce7\",\"runId\":\"host-sel-v2\",\"hypothesisId\":\"H-IKE-SEL\"," +
                    "\"location\":\"UbChunkBuilder.SelectFileGroupDownloadHostIndices\"," +
                    "\"message\":\"hosts_refs_plus_owned_ford\"," +
                    $"\"data\":{{\"hosts\":{n},\"selected\":{list.Count}," +
                    $"\"refs\":{plan.References.Count}," +
                    $"\"hasFileCs\":{(fc is { Length: 21 } ? "true" : "false")}}}," +
                    $"\"timestamp\":{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()}}}\n";
                File.AppendAllText(path, line);
            }
            catch
            {
                // ignore
            }
        }
        // #endregion

        return list;
    }

    // #region agent log
    private static int _ikeSelectLogCount;
    // #endregion

    public static IReadOnlyList<SignedUrlChunk> SelectFileGroupDownloadChunks(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> allHosts)
    {
        var indices = SelectFileGroupDownloadHostIndices(plan, allHosts);
        if (indices.Count == 0)
            return allHosts;
        var list = new List<SignedUrlChunk>(indices.Count);
        foreach (var i in indices)
            list.Add(allHosts[i]);
        return list;
    }

    /// <summary>
    /// Seleziona la FilePart il cui <c>AuthSlice</c> corrisponde ad <c>Asset.signature</c>.
    /// Preferisce match nel payload refs (field 2): i host Ford vuoti di Fallback C sono
    /// condivisi tra fordSingle dello stesso batch e contengono le signature degli altri
    /// file come falsi positivi su <c>IndexOf</c> grezzo → fallback all’indice 0 sbagliato
    /// (Cache.plist/AuthKit/itunescloud nella run 20260820_023754Z).
    /// </summary>
    public static AuthorizeGetFilePart SelectFilePart(
        ReadOnlySpan<byte> authorizeGetBody,
        ReadOnlySpan<byte> assetSignature)
        => SelectFilePart(
            ParseAuthorizeGetFiles(authorizeGetBody),
            assetSignature,
            fallbackIndex: 0,
            expectedCryptoBytes: null);

    /// <param name="expectedCryptoBytes">
    /// Solo come ultimo disambiguatore offline quando signature e indice batch mancano.
    /// <b>Non</b> passare <c>sizeBytes</c> CloudKit: è spesso plaintext (es. salt=8) mentre
    /// <c>TotalCryptoBytes</c> è ciphertext/packed (64…MiB). Usarlo come veto su refs/index
    /// mappava decine di asset packed sullo stesso cryptoHit (AuthSlice condiviso falso).
    /// </param>
    public static AuthorizeGetFilePart SelectFilePart(
        IReadOnlyList<AuthorizeGetFilePart> parts,
        ReadOnlySpan<byte> assetSignature,
        int fallbackIndex = 0,
        long? expectedCryptoBytes = null)
    {
        if (parts.Count == 0)
            throw new InvalidOperationException("authorizeGet senza FileGroups");
        if (parts.Count == 1)
            return parts[0];

        // sizeBytes plaintext ≠ cryptoSum: ignora expect piccoli / non-crypto.
        var cryptoExpect = NormalizeCryptoExpect(expectedCryptoBytes);

        //  FileChecksum (refs.field1) == AssetSignature → part unica.
        AuthorizeGetFilePart? fcsHit = null;
        var fcsN = 0;
        if (assetSignature.Length == 21)
        {
            foreach (var p in parts)
            {
                var slice = p.AuthSlice.Length > 0 ? p.AuthSlice : [];
                if (slice.Length == 0)
                    continue;
                var plan = BuildDecryptPlan(slice);
                if (plan.FileChecksum is { Length: 21 } fc
                    && fc.AsSpan().SequenceEqual(assetSignature))
                {
                    fcsHit = p;
                    fcsN++;
                }
            }

            if (fcsN == 1 && fcsHit is not null)
                return fcsHit;
        }

        AuthorizeGetFilePart? refsHit = null;
        var refsN = 0;
        AuthorizeGetFilePart? rawHit = null;
        var rawN = 0;
        if (assetSignature.Length >= 16)
        {
            foreach (var p in parts)
            {
                if (AuthSliceRefsContainSignature(p.AuthSlice, assetSignature))
                {
                    refsHit = p;
                    refsN++;
                }

                if (p.AuthSlice.AsSpan().IndexOf(assetSignature) >= 0)
                {
                    rawHit = p;
                    rawN++;
                }
            }
        }

        AuthorizeGetFilePart? cryptoHit = null;
        long cryptoDelta = long.MaxValue;
        if (cryptoExpect is long exp)
        {
            foreach (var p in parts)
            {
                var crypto = BuildDecryptPlan(p.AuthSlice).TotalCryptoBytes;
                if (crypto <= 0)
                    continue;
                var d = Math.Abs(crypto - exp);
                if (d < cryptoDelta)
                {
                    cryptoDelta = d;
                    cryptoHit = p;
                }
            }
        }

        var pick = refsN == 1
            ? "refs"
            : rawN == 1
                ? "raw"
                : (uint)fallbackIndex < (uint)parts.Count
                    ? "fallbackIndex"
                    : cryptoHit is not null
                        ? "crypto"
                        : "fallback0";


        // Signature nei refs = ground truth. Mai veto con sizeBytes/cryptoSum.
        if (refsN == 1 && refsHit is not null)
            return refsHit;
        if (rawN == 1 && rawHit is not null)
            return rawHit;

        // Batch live: indice richiesta↔risposta. Non sostituire con cryptoHit su sizeBytes.
        if ((uint)fallbackIndex < (uint)parts.Count)
            return parts[fallbackIndex];

        if (cryptoHit is not null)
            return cryptoHit;
        return parts[0];

        // Solo valori che possono essere TotalCryptoBytes (non plaintext 8 B salt).
        static long? NormalizeCryptoExpect(long? expected)
        {
            if (expected is not long exp || exp < 64)
                return null;
            return exp;
        }
    }

    /// <summary>
    /// Multi-file AG: ownership = <c>Gate45 embeds FileChecksum</c> + <c>GateOwnsPlan</c>.
    /// Nessuno score KEY/hint.
    /// </summary>
    public static AuthorizeGetFilePart SelectFilePartForFordKeys(
        IReadOnlyList<AuthorizeGetFilePart> parts,
        ReadOnlySpan<byte> authWhole,
        IReadOnlyList<int> fordKeyHints,
        int dataLen = 0,
        ReadOnlySpan<byte> liveMac21 = default,
        ReadOnlySpan<byte> gate45 = default)
    {
        _ = fordKeyHints;
        _ = dataLen;
        _ = liveMac21;
        if (parts.Count == 0)
            throw new InvalidOperationException("authorizeGet senza FileGroups");
        if (parts.Count == 1)
            return parts[0];

        if (gate45.Length == 45)
        {
            for (var pi = 0; pi < parts.Count; pi++)
            {
                var slice = parts[pi].AuthSlice.Length > 0
                    ? parts[pi].AuthSlice
                    : authWhole.ToArray();
                var plan = BuildDecryptPlan(slice);
                if (plan.References.Count == 0 || !GateOwnsPlan(gate45, plan))
                    continue;
                return parts[pi];
            }
        }

        return parts[0];
    }

    /// <summary>
    ///  part il cui AuthSlice ha gate che incorpora FileChecksum.
    /// Senza gate owned → indice batch (non score crypto/hint).
    /// </summary>
    public static AuthorizeGetFilePart SelectFilePartAligned(
        IReadOnlyList<AuthorizeGetFilePart> parts,
        ReadOnlySpan<byte> authWhole,
        ReadOnlySpan<byte> assetSignature,
        int fallbackIndex = 0)
    {
        if (parts.Count == 0)
            throw new InvalidOperationException("authorizeGet senza FileGroups");
        if (parts.Count == 1)
            return parts[0];

        if (assetSignature.Length == 21 && authWhole.Length > 0)
        {
            foreach (var d in ExtractAuthFordDescriptors(authWhole))
            {
                if (d.Gate45.Length != 45)
                    continue;
                if (!GateEmbedsFileChecksum(d.Gate45, assetSignature))
                    continue;

                for (var pi = 0; pi < parts.Count; pi++)
                {
                    var slice = parts[pi].AuthSlice.Length > 0
                        ? parts[pi].AuthSlice
                        : authWhole.ToArray();
                    var plan = BuildDecryptPlan(slice);
                    if (plan.References.Count > 0 && GateOwnsPlan(d.Gate45, plan))
                        return parts[pi];
                }
            }
        }

        if ((uint)fallbackIndex < (uint)parts.Count)
            return parts[fallbackIndex];
        return parts[0];
    }

    /// <summary>Score refs di un FilePart vs Ford KEY hints / dataLen / MAC21.</summary>
    public static int ScorePartRefsAgainstHints(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyCollection<int> hints,
        int dataLen = 0,
        ReadOnlySpan<byte> liveMac21 = default)
    {
        var score = 0;
        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                continue;
            var g = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)g.Count)
                continue;
            var ch = g[r.ChunkIndex];
            if (!IsAuthDataChunk(ch))
                continue;
            if (dataLen > 0 && ch.Length == dataLen)
                score += 100;
            if (liveMac21.Length == 21
                && ch.Checksum21.Length == 21
                && ch.Checksum21.AsSpan().SequenceEqual(liveMac21))
                score += 500;
            if (hints.Contains(ch.Length))
                score += 50;
            foreach (var h in hints)
            {
                if (ch.Length > h && ch.Length - h < 256)
                    score += 20;
            }
        }

        return score;
    }

    /// <summary>
    /// True se <paramref name="signature"/> compare in un field protobuf 2 (refs) di AuthSlice.
    /// </summary>
    public static bool AuthSliceContainsAssetSignatureForDebug(
        ReadOnlySpan<byte> authSlice,
        ReadOnlySpan<byte> signature)
        => AuthSliceRefsContainSignature(authSlice, signature);

    /// <summary>
    /// True se <paramref name="signature"/> compare in un field protobuf 2 (refs) di AuthSlice.
    /// </summary>
    private static bool AuthSliceRefsContainSignature(
        ReadOnlySpan<byte> authSlice,
        ReadOnlySpan<byte> signature)
    {
        if (authSlice.IsEmpty || signature.IsEmpty)
            return false;

        var body = UnwrapSingleField1(authSlice);
        var fields = WalkLengthDelimitedFields(body);
        if (fields.Count == 0)
            fields = WalkLengthDelimitedFields(authSlice);

        foreach (var f in fields)
        {
            if (f.Field != 2)
                continue;
            if (f.Payload.AsSpan().IndexOf(signature) >= 0 || f.Raw.AsSpan().IndexOf(signature) >= 0)
                return true;
        }

        return false;
    }

    private static List<AuthorizeGetChunkRef> ParseRefsPayload(ReadOnlySpan<byte> payload, int hostCount)
    {
        var refs = new List<AuthorizeGetChunkRef>();
        var pos = 0;
        while (pos < payload.Length)
        {
            var tag = payload[pos++];
            var field = tag >> 3;
            var wire = tag & 0x07;
            if (wire == 2)
            {
                if (!TryReadVarintInt(payload, ref pos, out var len)
                    || (uint)pos + (uint)len > (uint)payload.Length)
                    break;
                var msg = payload.Slice(pos, len);
                pos += len;
                if (field != 2)
                    continue;
                int? container = null;
                int? chunk = null;
                var p = 0;
                while (p < msg.Length)
                {
                    var t = msg[p++];
                    if ((t & 0x07) != 0)
                        break;
                    if (!TryReadVarintInt(msg, ref p, out var v))
                        break;
                    if (t >> 3 == 1)
                        container = v;
                    else if (t >> 3 == 2)
                        chunk = v;
                }

                if (container is int c && chunk is int k && (uint)c < (uint)hostCount)
                    refs.Add(new AuthorizeGetChunkRef { ContainerIndex = c, ChunkIndex = k });
            }
            else if (wire == 0)
            {
                if (!TryReadVarintLong(payload, ref pos, out _))
                    break;
            }
            else
            {
                break;
            }
        }

        return refs;
    }

    private static byte[] RewriteRefsPayload(ReadOnlySpan<byte> payload, Dictionary<int, int> remap)
    {
        var writer = new ProtobufWriter();
        var pos = 0;
        while (pos < payload.Length)
        {
            var tag = payload[pos++];
            var field = tag >> 3;
            var wire = tag & 0x07;
            if (wire == 2)
            {
                if (!TryReadVarintInt(payload, ref pos, out var len)
                    || (uint)pos + (uint)len > (uint)payload.Length)
                    break;
                var msg = payload.Slice(pos, len);
                pos += len;
                if (field == 1)
                {
                    writer.WriteBytes(1, msg);
                    continue;
                }

                if (field != 2)
                    continue;

                int? container = null;
                int? chunk = null;
                var p = 0;
                while (p < msg.Length)
                {
                    var t = msg[p++];
                    if ((t & 0x07) != 0)
                        break;
                    if (!TryReadVarintInt(msg, ref p, out var v))
                        break;
                    if (t >> 3 == 1)
                        container = v;
                    else if (t >> 3 == 2)
                        chunk = v;
                }

                if (container is int c && chunk is int k && remap.TryGetValue(c, out var nc))
                {
                    var inner = new ProtobufWriter();
                    inner.WriteVarint(1, (ulong)nc);
                    inner.WriteVarint(2, (ulong)k);
                    writer.WriteBytes(2, inner.ToArray());
                }
            }
            else if (wire == 0)
            {
                if (!TryReadVarintLong(payload, ref pos, out _))
                    break;
            }
            else
            {
                break;
            }
        }

        return writer.ToArray();
    }

    private static ReadOnlySpan<byte> UnwrapSingleField1(ReadOnlySpan<byte> data)
    {
        var top = WalkLengthDelimitedFields(data);
        if (top.Count == 1 && top[0].Field == 1 && top[0].Payload.Length + 8 >= data.Length)
            return top[0].Payload;
        return data;
    }

    private readonly record struct PbField(int Field, byte[] Raw, byte[] Payload);

    private static List<PbField> WalkLengthDelimitedFields(ReadOnlySpan<byte> data)
    {
        var fields = new List<PbField>();
        var pos = 0;
        while (pos < data.Length)
        {
            var fieldStart = pos;
            var tag = data[pos++];
            var field = tag >> 3;
            var wire = tag & 0x07;
            if (wire == 2)
            {
                var lenPos = pos;
                if (!TryReadVarintInt(data, ref pos, out var len)
                    || (uint)pos + (uint)len > (uint)data.Length)
                    break;
                var payload = data.Slice(pos, len).ToArray();
                pos += len;
                fields.Add(new PbField(field, data[fieldStart..pos].ToArray(), payload));
            }
            else if (wire == 0)
            {
                if (!TryReadVarintLong(data, ref pos, out _))
                    break;
            }
            else if (wire == 1)
            {
                pos += 8;
            }
            else if (wire == 5)
            {
                pos += 4;
            }
            else
            {
                break;
            }
        }

        return fields;
    }

    private static byte[] Concat(List<byte[]> parts)
    {
        var n = 0;
        foreach (var p in parts)
            n += p.Length;
        var buf = new byte[n];
        var o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, buf, o, p.Length);
            o += p.Length;
        }

        return buf;
    }

    private static List<int> FindContentByteRangeOffsets(ReadOnlySpan<byte> data)
    {
        var needle = "content-byte-range="u8;
        var offsets = new List<int>();
        for (var i = 0; i + needle.Length <= data.Length; i++)
        {
            if (data.Slice(i, needle.Length).SequenceEqual(needle))
                offsets.Add(i);
        }

        return offsets;
    }

    private static List<(int Position, AuthorizeGetCryptoChunk Chunk)> ExtractAuthorizeGetCryptoChunksPositioned(
        ReadOnlySpan<byte> data)
    {
        var list = new List<(int, AuthorizeGetCryptoChunk)>();
        for (var i = 0; i + 4 < data.Length; i++)
        {
            if (data[i] != 0x12)
                continue;

            var pos = i + 1;
            if (!TryReadVarintInt(data, ref pos, out var msgLen))
                continue;
            if (msgLen is < 24 or > 128
                || (uint)pos + (uint)msgLen > (uint)data.Length)
                continue;

            ReadOnlySpan<byte> msg;
            try
            {
                msg = data.Slice(pos, msgLen);
            }
            catch (ArgumentOutOfRangeException)
            {
                continue;
            }

            if (!TryParseChunkInfoMessage(msg, out var key, out var chunkLen, out var checksum, out var offset))
                continue;

            list.Add((i, new AuthorizeGetCryptoChunk
            {
                EncryptionKey = key,
                Length = chunkLen,
                Checksum21 = checksum,
                Offset = offset
            }));
            i = pos + msgLen - 1;
        }

        return list;
    }

    /// <summary>
    /// <c>FileChecksumChunkReferences.chunk_references</c>: coppie (container_index, chunk_index).
    /// Cerca dopo l'ultimo ChunkInfo (zona tipica del blocco references).
    /// </summary>
    private static IReadOnlyList<AuthorizeGetChunkRef> ExtractFileChunkReferences(
        ReadOnlySpan<byte> data,
        IReadOnlyList<IReadOnlyList<AuthorizeGetCryptoChunk>> containers,
        int totalChunks,
        int searchFrom)
    {
        if (totalChunks == 0 || containers.Count == 0)
            return Array.Empty<AuthorizeGetChunkRef>();

        var from = Math.Clamp(searchFrom, 0, data.Length);
        var candidates = new List<AuthorizeGetChunkRef>();
        for (var i = from; i + 3 < data.Length; i++)
        {
            // ChunkReference: field1 varint (0x08) ‖ field2 varint (0x10)
            if (data[i] != 0x08)
                continue;

            var p = i + 1;
            if (!TryReadVarintLong(data, ref p, out var container))
                continue;
            if (p >= data.Length || data[p] != 0x10)
                continue;
            p++;
            if (!TryReadVarintLong(data, ref p, out var chunk))
                continue;

            if (container < 0 || container >= containers.Count)
                continue;
            if (chunk < 0 || chunk >= containers[(int)container].Count)
                continue;

            candidates.Add(new AuthorizeGetChunkRef
            {
                ContainerIndex = (int)container,
                ChunkIndex = (int)chunk
            });
            i = p - 1;
        }

        // Se il blocco post-ChunkInfo non basta, scansione intero body.
        if (from > 0)
        {
            var all = ExtractFileChunkReferences(data, containers, totalChunks, 0);
            if (all.Count == totalChunks)
                return all;
        }

        // FileChecksumChunkReferences sta in coda: se più finestre sono permutazioni
        // complete, l'ultima è il blocco refs (la prima è spesso l'ordine di comparsa).
        if (candidates.Count >= totalChunks)
        {
            IReadOnlyList<AuthorizeGetChunkRef>? last = null;
            for (var start = 0; start + totalChunks <= candidates.Count; start++)
            {
                var window = candidates.GetRange(start, totalChunks);
                if (IsCompletePermutation(window, containers))
                    last = window;
            }

            if (last is not null)
                return last;
        }

        return Array.Empty<AuthorizeGetChunkRef>();
    }

    private static bool IsCompletePermutation(
        IReadOnlyList<AuthorizeGetChunkRef> refs,
        IReadOnlyList<IReadOnlyList<AuthorizeGetCryptoChunk>> containers)
    {
        var seen = new HashSet<(int, int)>();
        foreach (var r in refs)
        {
            if (r.ContainerIndex < 0 || r.ContainerIndex >= containers.Count)
                return false;
            if (r.ChunkIndex < 0 || r.ChunkIndex >= containers[r.ContainerIndex].Count)
                return false;
            if (!seen.Add((r.ContainerIndex, r.ChunkIndex)))
                return false;
        }

        var expected = containers.Sum(static c => c.Count);
        return seen.Count == expected;
    }

    private static bool TryParseChunkInfoMessage(
        ReadOnlySpan<byte> msg,
        out byte[] key,
        out int chunkLength,
        out byte[] checksum,
        out long offset)
    {
        key = [];
        checksum = [];
        chunkLength = 0;
        offset = 0;
        byte[]? foundKey = null;
        byte[]? foundChecksum = null;
        int? foundLen = null;
        long? foundOffset = null;
        var p = 0;
        while (p < msg.Length)
        {
            var tag = msg[p++];
            var field = tag >> 3;
            var wire = tag & 0x07;
            if (wire == 2)
            {
                // H-AOR2: false-positive ChunkInfo can decode a huge/negative len;
                // unchecked p+len wraps and bypasses the bounds check → Slice throws.
                if (!TryReadVarintInt(msg, ref p, out var len)
                    || (uint)p + (uint)len > (uint)msg.Length)
                {
                    // #region agent log
                    if (len < 0 || (uint)p + (uint)len > (uint)msg.Length)
                        AgentAor2Log(msg.Length, p, len);
                    // #endregion
                    return false;
                }
                var payload = msg.Slice(p, len);
                p += len;
                // field 1 = chunk_checksum:
                //   • 21 B lead 0x84… = data MAC (MAC20 = [1:21]) — FileGroupsPost live
                //   • 45 B lead 0C0F0104 = Auth Ford gate45 descriptor (stesso FileGroup)
                // Prima IKE accettava solo len==21 → drop gate45 → chunk_index Auth fuori fase.
                if (field == 1 && (len == 21 || IsGate45ChecksumPayload(payload)))
                    foundChecksum = payload.ToArray();
                else if (field == 2 &&
                    len is 0x11 or 0x19 &&
                    payload[0] is 0x01 or 0x02 &&
                    ((payload[0] == 0x01 && len == 0x11) || (payload[0] == 0x02 && len == 0x19)))
                {
                    foundKey = payload.ToArray();
                }
            }
            else if (wire == 0)
            {
                if (!TryReadVarintLong(msg, ref p, out var v))
                    return false;
                if (field == 3 && v is > 0 and <= int.MaxValue)
                    foundLen = (int)v;
                else if (field == 4)
                    foundOffset = v;
            }
            else
            {
                return false;
            }
        }

        // ChunkInfo: lunghezza (f3) + checksum f1 (21 = data MAC | 45 = Ford gate).
        // La chiave AES-KW (f2) c'è nei file MMCS-CFB; nei file Ford è assente
        // (le chiavi arrivano da Ford SIV). Non richiedere f2.
        if (foundLen is null || foundChecksum is null)
            return false;

        key = foundKey ?? [];
        checksum = foundChecksum;
        chunkLength = foundLen.Value;
        offset = foundOffset ?? 0;
        // #region agent log
        if (checksum.Length == 45)
            AgentGate45ParseLog(chunkLength);
        // #endregion
        return true;
    }

    /// <summary>
    /// live FileGroupsPost: ChunkInfo Ford-descriptor =
    /// <c>chunk_checksum</c> len 45 lead <c>0C0F0104</c>, <c>chunk_length</c> ≈ 112/155/224.
    /// </summary>
    public static bool IsGate45ChecksumPayload(ReadOnlySpan<byte> payload) =>
        payload.Length == 45
        && payload[0] == 0x0C
        && payload[1] == 0x0F
        && payload[2] == 0x01
        && payload[3] == 0x04;

    /// <summary>True se il ChunkInfo Auth è descriptor Ford (gate45), non data MAC.</summary>
    public static bool IsAuthFordDescriptorChunk(AuthorizeGetCryptoChunk ch) =>
        ch.Checksum21.Length == 45 && IsGate45ChecksumPayload(ch.Checksum21);

    /// <summary>True se il ChunkInfo è data (checksum21 MAC), non Ford gate.</summary>
    public static bool IsAuthDataChunk(AuthorizeGetCryptoChunk ch) =>
        ch.Checksum21.Length == 21;

    /// <summary>
    /// Gap Ford (112) intercalato tra CI sul pack Auth data.
    /// Quando <c>pad = hostLen - ΣCI</c> è <c>112×N</c> o <c>112×(N-1)</c>,
    /// il body wire è <c>CI0‖ford‖CI1‖ford‖…</c> (eventuale ford finale / extra sull’ultimo CI).
    /// </summary>
    public static int AuthInterCiFordGap(long hostLen, long layoutSum, int ciCount)
    {
        if (ciCount <= 0 || hostLen <= layoutSum)
            return 0;
        var pad = hostLen - layoutSum;
        if (pad % 112 != 0)
            return 0;
        var nGaps = pad / 112;
        if (nGaps == ciCount || nGaps == ciCount - 1)
            return 112;
        return 0;
    }

    /// <summary>
    /// Wire offset del CI nel body GET host (PutChunk demux).
    /// Preferisci <c>ChunkInfo.chunk_offset</c>: spesso relativo all'inizio del
    /// ByteRange HostInfo (3014/3029/3008: off=240/624 nel pack). Fallback:
    /// offset assoluto MMCS (<c>offset - hostStart</c>), poi
    /// <see cref="AuthCiWireOffset"/>.
    /// </summary>
    public static long ResolveCiWireInHostBody(
        long chunkOffset,
        int chunkLength,
        long hostStart,
        long hostLen,
        long layoutOff,
        int chunkIndex,
        int ciCount,
        long layoutSum,
        bool fordOnlyHost)
    {
        // PutChunk: preferisci ChunkInfo.Offset (evidenza offline IKM-open:
        // 3021@240, 3028@176, 3053@624=IKE). La formula pad-dopo-CI0
        // (ci1@pad+layoutOff) su questi pack punta al CT sbagliato.
        if (chunkLength > 0 && hostLen > 0)
        {
            // Relativo al body scaricato.
            if (chunkOffset >= 0 && chunkOffset + chunkLength <= hostLen)
                return chunkOffset;
            // Assoluto nell'object MMCS.
            if (hostStart >= 0
                && chunkOffset >= hostStart
                && chunkOffset - hostStart + chunkLength <= hostLen)
                return chunkOffset - hostStart;
        }

        // Fallback: Ford-only con pad quando Offset manca / fuori range.
        if (fordOnlyHost
            && hostLen > 0
            && layoutSum > 0
            && hostLen > layoutSum
            && ciCount > 1)
        {
            return AuthCiWireOffset(
                layoutOff, chunkIndex, ciCount, hostLen, layoutSum, fordOnlyHost: true);
        }

        return AuthCiWireOffset(
            layoutOff, chunkIndex, ciCount, hostLen, layoutSum, fordOnlyHost);
    }

    /// <summary>
    /// Offset wire del CI <paramref name="chunkIndex"/> nel pack Auth.
    /// Data: <c>layoutOff + gap×i</c>, e se <c>pad = gap×N</c> l’ultimo CI ha +gap extra
    /// (ike_run 3028: Δ=1232=112×11, non 112×10).
    /// Ford-only con pad (anche non multiplo di 112): layout è
    /// <c>CI0 @0</c> poi <b>tutto</b> il pad, poi CI1… contigui
    /// → <c>wire = layoutOff + (ci&gt;0 ? pad : 0)</c>
    /// (ike 3014: pad=128 → ci1@240; 3015: pad=256 → ci1@368).
    /// Preferisci <see cref="ResolveCiWireInHostBody"/> quando hai
    /// <c>ChunkInfo.Offset</c>.
    /// </summary>
    public static long AuthCiWireOffset(
        long layoutOff,
        int chunkIndex,
        int ciCount,
        long hostLen,
        long layoutSum,
        bool fordOnlyHost = false)
    {
        if (ciCount <= 0 || hostLen < layoutSum || layoutOff < 0 || chunkIndex < 0)
            return layoutOff;

        var pad = hostLen - layoutSum;
        if (pad <= 0)
            return layoutOff;

        // #region agent log
        // Ford-only: pad unico dopo CI0 (evidenza cross↔IKE 3014/3015/3023).
        if (fordOnlyHost)
        {
            var fordWire = layoutOff + (chunkIndex > 0 ? pad : 0);
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-FORD-PAD",
                    ["runId"] = "ford-pad-v1",
                    ["location"] = "UbChunkBuilder.AuthCiWireOffset",
                    ["message"] = "ford_only_pad_wire",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["ci"] = chunkIndex,
                        ["n"] = ciCount,
                        ["hostLen"] = hostLen,
                        ["layoutSum"] = layoutSum,
                        ["pad"] = pad,
                        ["layoutOff"] = layoutOff,
                        ["wire"] = fordWire,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            return fordWire;
        }
        // #endregion

        var gap = AuthInterCiFordGap(hostLen, layoutSum, ciCount);
        if (gap <= 0)
            return layoutOff;

        var wire = layoutOff + gap * (long)chunkIndex;
        // Ultimo CI: pad == gap×N ⇒ un Ford in più prima dell’ultimo chunk.
        if (chunkIndex == ciCount - 1 && pad == gap * (long)ciCount)
            wire += gap;
        return wire;
    }

    /// <summary>
    /// Host Auth con solo descriptor Ford (o vuoto) — materiale Ford, non data CT.
    ///  spesso <c>ci&gt;0</c> con gate45, non solo <c>ci==0</c>.
    /// </summary>
    public static bool IsAuthFordMaterialHost(IReadOnlyList<AuthorizeGetCryptoChunk> host) =>
        host.Count == 0 || host.All(IsAuthFordDescriptorChunk);

    /// <summary>
    /// Host con length Ford standard (112/155/…) anche senza gate45 parse —
    /// twin locale di <c>IsFordSizedPlanContainer</c> senza dipendere da Escrow.
    /// </summary>
    public static bool IsFordSizedHostLengths(IReadOnlyList<AuthorizeGetCryptoChunk> host)
    {
        if (host.Count == 0)
            return true;
        if (host.All(IsAuthFordDescriptorChunk))
            return true;
        if (host.Count != 1)
            return false;
        // Solo taglie Ford “classiche” / multiplo piccolo.
        // I bag multi-key grandi (Unify ~110KiB) passano già da
        // host.All(IsAuthFordDescriptorChunk) sopra — non allargare qui
        // i data host mono-CI (stabilità vs IsPlausibleAuthFordCtLen).
        var len = host[0].Length;
        return len is 112 or 155 or 224 or 310 or 464 or 480
               || (len >= 112 && len <= 4096 && (len % 112 == 0 || len % 155 == 0));
    }

    // #region agent log
    private static int _aor2LogCount;
    private static int _gate45LogCount;
    private static void AgentAor2Log(int msgLen, int p, int len)
    {
        if (Interlocked.Increment(ref _aor2LogCount) > 8)
            return;
        try
        {
            var line =
                "{\"sessionId\":\"7dabb5\",\"hypothesisId\":\"H-AOR2\",\"location\":\"UbChunkBuilder.TryParseChunkInfoMessage\"," +
                $"\"message\":\"skip_overflow_len\",\"data\":{{\"msgLen\":{msgLen},\"p\":{p},\"len\":{len}}}," +
                $"\"timestamp\":{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()},\"runId\":\"post-fix\"}}" +
                Environment.NewLine;
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch
        {
            // ignore
        }
    }

    private static void AgentGate45ParseLog(int chunkLength)
    {
        if (Interlocked.Increment(ref _gate45LogCount) > 24)
            return;
        try
        {
            var line =
                "{\"sessionId\":\"7dabb5\",\"hypothesisId\":\"H-A1\",\"location\":\"UbChunkBuilder.TryParseChunkInfoMessage\"," +
                $"\"message\":\"auth_ford_gate45_ci\",\"data\":{{\"chunkLength\":{chunkLength},\"checksumLen\":45}}," +
                $"\"timestamp\":{DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()},\"runId\":\"ike-gate45-v1\"}}" +
                Environment.NewLine;
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    private static bool TryReadVarintInt(ReadOnlySpan<byte> data, ref int pos, out int value)
    {
        value = 0;
        if (!TryReadVarintLong(data, ref pos, out var v) || v > int.MaxValue)
            return false;
        value = (int)v;
        return true;
    }

    private static bool TryReadVarintLong(ReadOnlySpan<byte> data, ref int pos, out long value)
    {
        value = 0;
        var shift = 0;
        while (pos < data.Length && shift < 64)
        {
            var b = data[pos++];
            value |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
        }

        return false;
    }

    private static readonly string[] EdgeHeaderKeys =
    [
        "x-apple-destination",
        "x-apple-mme-owner",
        "x-apple-opaque-ownerid",
        "x-apple-content-partition",
        "x-apple-uuid",
        "x-apple-date",
        "x-apple-expires",
        "x-apple-signature",
        "X-Apple-Object-ID",
        "Date",
        "x-apple-boss-recommendation-used",
        "x-apple-incoming-icloud-edge-pop"
    ];

    /// <summary>
    /// Dopo ogni nome header come stringa protobuf, il valore è il successivo
    /// campo length-delimited (tag 0x12…). Così non si mangiano code base64
    /// uguali a tag stampabili (<c>B</c>, <c>J</c>, <c>z</c>, …).
    /// </summary>
    private static Dictionary<string, string> ExtractProtobufHeaderMap(ReadOnlySpan<byte> data)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var bytes = data.ToArray();

        foreach (var key in EdgeHeaderKeys)
        {
            if (map.ContainsKey(key))
                continue;

            var keyBytes = Encoding.ASCII.GetBytes(key);
            var searchFrom = 0;
            while (searchFrom < bytes.Length)
            {
                var rel = bytes.AsSpan(searchFrom).IndexOf(keyBytes);
                if (rel < 0)
                    break;

                var keyStart = searchFrom + rel;
                var afterKey = keyStart + keyBytes.Length;
                if (TryReadNextLengthDelimitedAscii(bytes, afterKey, out var value) &&
                    !string.IsNullOrEmpty(value))
                {
                    map[key] = value;
                    break;
                }

                searchFrom = keyStart + 1;
            }
        }

        return map;
    }

    private static bool TryReadNextLengthDelimitedAscii(byte[] data, int offset, out string value)
    {
        value = string.Empty;
        // Tolleranza: tra fine chiave e tag valore ci possono essere 0–3 byte di framing.
        for (var probe = offset; probe < offset + 4 && probe < data.Length; probe++)
        {
            var pos = probe;
            try
            {
                var tag = ReadVarint(data, ref pos);
                if ((tag & 0x7) != 2)
                    continue;

                var len = (int)ReadVarint(data, ref pos);
                if (len is < 1 or > 4096 || (uint)pos + (uint)len > (uint)data.Length)
                    continue;

                var slice = data.AsSpan(pos, len);
                if (!IsMostlyAscii(slice))
                    continue;

                value = Encoding.ASCII.GetString(slice);
                return true;
            }
            catch
            {
                // prova offset successivo
            }
        }

        return false;
    }

    private static ulong ReadVarint(byte[] data, ref int pos)
    {
        ulong result = 0;
        var shift = 0;
        while (pos < data.Length)
        {
            var b = data[pos++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return result;
            shift += 7;
            if (shift > 63)
                throw new InvalidDataException("Varint troppo lungo.");
        }

        throw new InvalidDataException("Varint troncato.");
    }

    private static bool IsMostlyAscii(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return false;
        var ok = 0;
        foreach (var b in data)
        {
            if (b is >= 0x20 and < 0x7f or 0x09 or 0x0a or 0x0d)
                ok++;
        }

        return ok * 10 >= data.Length * 9;
    }

    private static Dictionary<string, string> MergeHeaderMaps(
        IReadOnlyDictionary<string, string> preferred,
        IReadOnlyDictionary<string, string> fallback)
    {
        var map = new Dictionary<string, string>(fallback, StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in preferred)
        {
            if (!string.IsNullOrEmpty(v))
                map[k] = v;
        }

        return map;
    }

    private static byte[] DecodeAuthToken(string token)
    {
        if (token.Length % 2 == 0 && IsHex(token))
            return Convert.FromHexString(token);
        return Encoding.UTF8.GetBytes(token);
    }

    private static bool IsHex(string value)
    {
        foreach (var c in value)
        {
            var isHex = c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F';
            if (!isHex)
                return false;
        }

        return value.Length > 0;
    }

    private static List<string> CollectOrderedStrings(ReadOnlySpan<byte> data) =>
        ProtobufStringScanner.ExtractAsciiRuns(data, 3).ToList();

    /// <summary>
    /// Allega host authorizeGet senza ChunkInfo (Ford ciphertext 112–maxHostLen)
    /// da qualsiasi object-id del batch. Usato da Fallback C/D.
    /// </summary>
    private static int AttachCrossOidEmptyFordHosts(
        IReadOnlyList<SignedUrlChunk> allChunks,
        AuthorizeGetDecryptPlan hostPlan,
        HashSet<int> used,
        List<int> selected,
        long maxHostLen)
    {
        var attached = 0;
        for (var i = 0; i < allChunks.Count; i++)
        {
            if ((uint)i < (uint)hostPlan.Containers.Count
                && hostPlan.Containers[i].Count != 0)
                continue;
            if (allChunks[i].ByteRange is not { } br)
                continue;
            var hostLen = br.End - br.Start + 1;
            if (hostLen is < 112 || hostLen > maxHostLen)
                continue;
            if (!used.Add(i))
                continue;
            selected.Add(i);
            attached++;
        }

        return attached;
    }

    /// <summary>
    /// GET Ford del chunk: host vuoto che termina subito prima di
    /// packedStart+ChunkInfo.Offset (<c>End+1 == chunkAbs</c>), oppure
    /// overlap esterno (Amazon: inizia prima del packed e si estende dentro).
    /// Host interni al packed sono Ford solo se della misura di una finestra
    /// (112/155): un GET da 480 B (RemoteStrings) è Ford‖data‖Ford del chunk
    /// precedente, non la chiave di questo file.
    /// </summary>
    /// <summary>
    /// Ford host adiacente al chunk dati (stesse regole FileGroup / ParseAuthorizeGetFiles).
    /// </summary>
    public static bool IsFordHostForDataChunk(
        (long Start, long End) fordRange,
        long chunkAbsStart,
        long packedDataStart)
        => IsFordHostForChunk(fordRange, chunkAbsStart, packedDataStart);

    /// <summary>Offset relativo del ChunkInfo nel packed host (per abs start).</summary>
    public static long GetPackedChunkAbsStart(
        AuthorizeGetCryptoChunk ch,
        IReadOnlyList<AuthorizeGetCryptoChunk> group,
        long packedHostStart,
        long packedHostLen)
        => packedHostStart + PackedRelOffset(ch, group, packedHostLen);

    private static bool IsFordHostForChunk((long Start, long End) br, long chunkAbs, long packedStart)
    {
        if (chunkAbs == long.MinValue)
            return false;

        var len = br.End - br.Start + 1;
        var insidePacked = packedStart != long.MinValue && br.Start >= packedStart;
        if (br.End + 1 == chunkAbs)
        {
            if (!insidePacked)
                return true;
            // Ford interno al packed: accetta qualsiasi dimensione >= 112 B e <= 4096 B.
            // Include Ford multi-key (464 B, 480 B, …) usati quando il packed
            // contiene più chunk con chiavi condivise (es. Cache.plist in Numbers batch).
            return len is >= 112 and <= 4096;
        }

        if (insidePacked)
        {
            // Ford interno al packed come prefisso di un blob multi-key:
            // br.Start + fordLen == chunkAbs, con fordLen in {112, 155, 224, 310, 464, 480}.
            // Es.: host[02]=31968-32447 (480B) serve ChunkInfo[2] (absStart=32080): 31968+112=32080.
            var prefix2 = chunkAbs - br.Start;
            return prefix2 is 112 or 155 or 224 or 310 or 464 or 480
                   && br.End >= chunkAbs;
        }
        var prefix = chunkAbs - br.Start;
        return prefix >= 0x12
               && prefix <= 4096
               && br.Start < chunkAbs
               && br.End >= chunkAbs;
    }

    private static long PackedRelOffset(
        AuthorizeGetCryptoChunk ch,
        IReadOnlyList<AuthorizeGetCryptoChunk> group,
        long packedLen)
    {
        long min = long.MaxValue;
        foreach (var c in group)
        {
            if (c.Length > 0 && c.Offset < min)
                min = c.Offset;
        }

        if (min == long.MaxValue)
            min = 0;
        if (packedLen > 0 && (min > packedLen || ch.Offset > packedLen))
            return ch.Offset - min;
        return ch.Offset;
    }

    private static (long Start, long End)? ExtractContentByteRange(string path)
    {
        var m = ContentByteRangeRegex.Match(path);
        if (!m.Success)
            return null;
        if (!long.TryParse(m.Groups[1].Value, out var start))
            return null;
        if (!long.TryParse(m.Groups[2].Value, out var end))
            return null;
        return (start, end);
    }

    private static string? ExtractClientRequestIdFromPath(string path)
    {
        const string key = "x-client-request-id=";
        var idx = path.IndexOf(key, StringComparison.OrdinalIgnoreCase);
        if (idx < 0)
            return null;
        var start = idx + key.Length;
        var end = path.IndexOf('&', start);
        var value = end < 0 ? path[start..] : path[start..end];
        return SanitizeUuid(value);
    }

    private static string? ExtractObjectId(string path)
    {
        if (string.IsNullOrEmpty(path))
            return null;
        var trimmed = path.TrimStart('/');
        var q = trimmed.IndexOf('?');
        return q >= 0 ? trimmed[..q] : trimmed;
    }

    private static (long Start, long End)? ParseRange(string text)
    {
        var idx = text.IndexOf("bytes=", StringComparison.Ordinal);
        if (idx < 0)
            return null;
        var part = text[(idx + 6)..];
        var slash = part.IndexOf('/');
        if (slash > 0)
            part = part[..slash];
        var dash = part.IndexOf('-');
        if (dash < 0)
            return null;
        if (!long.TryParse(part[..dash], out var start))
            return null;
        if (!long.TryParse(part[(dash + 1)..], out var end))
            return null;
        return (start, end);
    }

    private static Dictionary<string, string> ParseHeaderMap(IReadOnlyList<string> strings)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (var i = 0; i + 1 < strings.Count; i++)
        {
            var key = strings[i].Trim();
            if (key is "GET" or "HTTP/1.1" or "HTTP/2" or "https" or "Accept" or "Host" or "Range")
                continue;
            if (key.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                continue;
            if (key.Contains(':', StringComparison.Ordinal))
                continue;
            if (!map.ContainsKey(key))
                map[key] = CleanToken(strings[i + 1]);
        }

        return map;
    }

    private static EdgeDownloadHeaders BuildEdgeHeaders(IReadOnlyDictionary<string, string> map)
    {
        map.TryGetValue("x-apple-destination", out var destination);
        map.TryGetValue("x-apple-mme-owner", out var owner);
        map.TryGetValue("x-apple-opaque-ownerid", out var opaqueOwner);
        map.TryGetValue("x-apple-content-partition", out var partition);
        map.TryGetValue("x-apple-uuid", out var uuid);
        map.TryGetValue("x-apple-date", out var date);
        map.TryGetValue("x-apple-expires", out var expires);
        map.TryGetValue("x-apple-signature", out var signature);
        map.TryGetValue("X-Apple-Object-ID", out var objectId);
        map.TryGetValue("Date", out var httpDate);
        map.TryGetValue("x-apple-boss-recommendation-used", out var bossRec);
        map.TryGetValue("x-apple-incoming-icloud-edge-pop", out var edgePop);
        map.TryGetValue("X-Apple-MMCS-Container-Size", out var mmcsContainerSize);
        if (string.IsNullOrEmpty(mmcsContainerSize))
            map.TryGetValue("x-apple-mmcs-container-size", out mmcsContainerSize);

        return new EdgeDownloadHeaders
        {
            Destination = SanitizeBase64Token(destination),
            MmeOwner = SanitizeDigits(owner),
            OpaqueOwnerId = SanitizeBase64Token(opaqueOwner),
            Partition = SanitizePartition(partition),
            Uuid = SanitizeUuid(uuid),
            Date = SanitizeMillisTimestamp(date),
            Expires = SanitizeMillisTimestamp(expires),
            Signature = SanitizeBase64Token(signature),
            ObjectId = SanitizeObjectId(objectId),
            HttpDate = SanitizeHttpDate(httpDate),
            BossRecommendationUsed = SanitizeBoolString(bossRec),
            IncomingEdgePop = SanitizeEdgePop(edgePop),
            MmcsContainerSize = SanitizeDigits(mmcsContainerSize),
        };
    }

    private static string CleanPath(string path) => CleanToken(path);

    /// <summary>
    /// Pulisce path / token non-base64. Solo junk non alfabetico in coda
    /// (<c>*</c>, spazi, virgolette…): <c>B</c>/<c>J</c>/<c>z</c> sono base64 validi
    /// e vanno lasciati (la lunghezza esatta arriva dal protobuf).
    /// </summary>
    private static string CleanToken(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        value = value.Trim().Trim('"', '\'');
        while (value.Length > 0 && value[0] is ',' or '$' or '#' or ' ' or '\t')
            value = value[1..];

        while (value.Length > 0)
        {
            var last = value[^1];
            if (last is '%' or '*' or ')' or '!' or ',' or '"' or '\'' or ' ' or '\t')
            {
                value = value[..^1];
                continue;
            }

            break;
        }

        return value;
    }

    /// <summary>
    /// destination / opaque-ownerid / signature: base64 o base64url (tiene <c>_</c>/<c>-</c>).
    /// Non rimuovere lettere in coda: sono parte del token.
    /// </summary>
    private static string SanitizeBase64Token(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        value = value.Trim().Trim('"', '\'');
        while (value.Length > 0 && value[0] is ',' or '$' or '#' or ' ' or '\t')
            value = value[1..];

        // Solo junk non-base64 in coda (tag ASCII fuori alfabeto, spazi, *…).
        while (value.Length > 0 && !IsBase64Char(value[^1]))
            value = value[..^1];

        var chars = new char[value.Length];
        var n = 0;
        foreach (var c in value)
        {
            if (IsBase64Char(c))
                chars[n++] = c;
        }

        return n == 0 ? string.Empty : new string(chars, 0, n);
    }

    private static bool IsBase64Char(char c) =>
        c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9')
            or '+' or '/' or '-' or '_' or '=';

    private static string SanitizeToken(string? value) => CleanToken(value);

    private static string SanitizeUuid(string? value)
    {
        value = CleanToken(value);
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        while (value.Length > 0 && value[0] is '$' or '#' or ',')
            value = value[1..];

        var dash = value.IndexOf('-');
        if (dash < 0)
            return value;

        return value.Length >= 36 ? value[..36] : value;
    }

    private static string SanitizeObjectId(string? value)
    {
        value = CleanToken(value);
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        // Object-ID edge: tipicamente 20 char base64url; eventuali tag protobuf in coda.
        var n = 0;
        while (n < value.Length && IsBase64Char(value[n]) && value[n] != '=')
            n++;
        return n > 0 ? value[..n] : value;
    }

    private static string SanitizeHttpDate(string? value)
    {
        value = CleanToken(value);
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        var gmt = value.IndexOf("GMT", StringComparison.Ordinal);
        return gmt >= 0 ? value[..(gmt + 3)] : value;
    }

    private static string SanitizeBoolString(string? value)
    {
        value = CleanToken(value);
        if (value.StartsWith("true", StringComparison.OrdinalIgnoreCase))
            return "true";
        if (value.StartsWith("false", StringComparison.OrdinalIgnoreCase))
            return "false";
        return value;
    }

    private static string SanitizePartition(string? value)
    {
        value = CleanToken(value);
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        // es. p178 — ignora tag protobuf in coda (p178B).
        if (value.Length >= 2 && value[0] == 'p')
        {
            var i = 1;
            while (i < value.Length && char.IsDigit(value[i]))
                i++;
            if (i > 1)
                return value[..i];
        }

        return value;
    }

    private static string SanitizeEdgePop(string? value)
    {
        value = CleanToken(value);
        if (string.IsNullOrEmpty(value))
            return string.Empty;

        var n = 0;
        while (n < value.Length && (char.IsAsciiLetterOrDigit(value[n]) || value[n] is '-' or '_'))
            n++;
        return n > 0 ? value[..n] : value;
    }

    private static string SanitizeDigits(string? value) =>
        string.IsNullOrEmpty(value) ? string.Empty : new string(value.Where(char.IsDigit).ToArray());

    /// <summary>x-apple-date / x-apple-expires: epoch ms (13 cifre).</summary>
    private static string SanitizeMillisTimestamp(string? value)
    {
        var digits = SanitizeDigits(value);
        return digits.Length switch
        {
            > 13 => digits[..13],
            _ => digits
        };
    }

    /// <summary>
    /// Ordine GET per compact Ford: HostInfo senza ChunkInfo (Ford) prima, poi i
    /// container nell'ordine <c>FileChecksumChunkReferences</c> (prima occorrenza).
    /// Esempio live IMG_2176.MOV (run_20260817_203050 seq 46084–87): refs
    /// <c>2:0..2:5, 1:0..1:4</c> → Ford 0–493 su 79ZUSKA, poi body 494–31457773
    /// sullo stesso object, poi body 0–21291007 su 1RJbZ4Q. L'authorizeGet elenca
    /// i host 0,1,2 (Ford, 1RJbZ4Q, 79ZUSKA-data): un dump concatenato in quell'ordine
    /// va rimappato con le chiavi range, non letto as-is. Non generalizzare il
    /// numero di GET/object: vale solo il piano refs di quel authorizeGet.
    /// Non raggruppare per object-id (Gemma: Ford e un chunk dati sullo stesso S3
    /// con un altro host in mezzo).
    /// </summary>
    public static List<SignedUrlChunk> OrderChunksForFordFile(
        IReadOnlyList<SignedUrlChunk> chunks,
        ReadOnlySpan<byte> authorizeGetBody)
    {
        var list = chunks.Where(static c => !string.IsNullOrEmpty(c.Url)).ToList();
        if (list.Count == 0)
            return list;

        var plan = BuildDecryptPlan(authorizeGetBody);
        if (plan.References.Count == 0 || plan.Containers.Count == 0)
            return SortSameObjectFordFirst(list);

        // FileGroup: HAS-Ford (empty/CI45) + container citati dai refs.
        // Mai append degli host unused (= data di altri file nello stesso AG).
        return SelectFileGroupDownloadChunks(plan, list).ToList();
    }

    /// <summary>
    /// Un solo object-id: Ford è il range piccolo in testa (0-111), poi i dati per Start.
    /// </summary>
    private static List<SignedUrlChunk> SortSameObjectFordFirst(List<SignedUrlChunk> list)
    {
        if (list.Count < 2)
            return list;
        var oids = list.Select(static c => c.EdgeHeaders?.ObjectId ?? "").Distinct().Count();
        if (oids != 1)
            return list;
        return list.OrderBy(static c => c.ByteRange?.Start ?? long.MaxValue).ToList();
    }

    /// <summary>
    /// ChunkInfo Ford-family single: keyLen=0, checksum lead 0x84 (MAC ChunkDecrypt).
    /// </summary>
    public static bool IsFordFamilySingleChunk(AuthorizeGetCryptoChunk ch) =>
        ch.EncryptionKey.Length == 0
        && ch.Checksum21.Length == 21
        && ch.Checksum21[0] == 0x84;

    /// <summary>
    /// Asset Ford-family (Cache.plist): un GET dati, ChunkInfo keyLen=0, checksum lead 0x84.
    /// Decrypt = DecryptFordKeys(Ford host / finestra lead-0x04) + ChunkDecrypt(MAC).
    /// </summary>
    public static bool IsFordFamilySingleGet(AuthorizeGetDecryptPlan plan)
    {
        if (plan.References.Count != 1 || plan.TotalCryptoChunks != 1)
            return false;

        var r = plan.References[0];
        if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
            return false;
        var group = plan.Containers[r.ContainerIndex];
        if ((uint)r.ChunkIndex >= (uint)group.Count)
            return false;

        return IsFordFamilySingleChunk(group[r.ChunkIndex]);
    }

    /// <summary>
    /// Host packed multi-chunk (es. METRICS_HIGH): tutti ChunkInfo con keyLen=0 e csLead=0x84.
    /// Ford nel prefix/gap, non MMCS AES-KW.
    /// </summary>
    public static bool IsFordFamilyZeroKeyPlan(AuthorizeGetDecryptPlan plan)
    {
        if (plan.TotalCryptoChunks == 0)
            return false;

        foreach (var group in plan.Containers)
        {
            foreach (var ch in group)
            {
                if (ch.EncryptionKey.Length != 0)
                    return false;
                if (ch.Checksum21.Length != 21 || ch.Checksum21[0] != 0x84)
                    return false;
            }
        }

        return true;
    }

    /// <summary>
    /// Auth→Ford wire (storage+0x88 gate / +0x58 ctLen): blocco nested
    /// <c>0A 2D ‖ gate45 0C0F0104… ‖ 18 ctLen ‖ 20 hostHint</c> + OID ascii 20B.
    /// </summary>
    public sealed record AuthFordDescriptor(
        byte[] Gate45,
        int CtLen,
        int HostSizeHint,
        string ObjectId,
        int WireOffset);

    /// <summary>
    /// Estrae i descriptor Ford dall'authorizeGet (allineato DecryptFordKeys).
    /// Non scarica: serve a sliceare il GET già in cache per OID/<paramref name="CtLen"/>.
    /// </summary>
    public static IReadOnlyList<AuthFordDescriptor> ExtractAuthFordDescriptors(
        ReadOnlySpan<byte> authorizeGetBody)
    {
        var list = new List<AuthFordDescriptor>();
        if (authorizeGetBody.Length < 49)
            return list;

        // Primary: protobuf field1 LD len=45 + gate lead 0C0F0104
        ReadOnlySpan<byte> needle = [0x0A, 0x2D, 0x0C, 0x0F, 0x01, 0x04];
        for (var i = 0; i <= authorizeGetBody.Length - needle.Length; i++)
        {
            if (!authorizeGetBody.Slice(i, needle.Length).SequenceEqual(needle))
                continue;
            TryAddAuthFordDescriptorAtGate(authorizeGetBody, gateStart: i + 2, wireOffset: i, list);
        }

        // Fallback: gate45 lead senza prefix 0A 2D (storage+0x88 ancora valorizzato).
        if (list.Count == 0)
        {
            ReadOnlySpan<byte> gateLead = [0x0C, 0x0F, 0x01, 0x04];

            for (var i = 0; i <= authorizeGetBody.Length - 45; i++)
            {
                if (!authorizeGetBody.Slice(i, gateLead.Length).SequenceEqual(gateLead))
                    continue;
                // Prefer frames that look like LD-wrapped gate (byte before lead = 0x2D).
                if (i >= 2 && authorizeGetBody[i - 1] == 0x2D)
                    TryAddAuthFordDescriptorAtGate(authorizeGetBody, gateStart: i, wireOffset: i - 2, list);
                else
                    TryAddAuthFordDescriptorAtGate(authorizeGetBody, gateStart: i, wireOffset: i, list);
                if (list.Count >= 8)
                    break;
            }
        }

        return list;
    }

    /// <summary>
    /// Parse ctLen/hostHint/OID after a 45B gate at <paramref name="gateStart"/>.
    /// When f3 (0x18) is missing, default ctLen=112 (storage+0x58 tipico).
    /// </summary>
    private static void TryAddAuthFordDescriptorAtGate(
        ReadOnlySpan<byte> authorizeGetBody,
        int gateStart,
        int wireOffset,
        List<AuthFordDescriptor> list)
    {
        if (gateStart < 0 || gateStart + 45 > authorizeGetBody.Length)
            return;

        var gate = authorizeGetBody.Slice(gateStart, 45).ToArray();
        if (!IsGate45ChecksumPayload(gate))
            return;

        var pos = gateStart + 45;
        var ctLen = 0;
        var hostHint = 0;

            // f3: classici ≤64KiB; large (Unify) accettati qui, ByteRange in Collect.
        if (pos < authorizeGetBody.Length && authorizeGetBody[pos] == 0x18)
        {
            pos++;
            if (!TryReadVarintInt(authorizeGetBody, ref pos, out ctLen)
                || !IsPlausibleAuthFordCtLen(ctLen))
                return;
        }
        else
        {
            // Gate senza f3: storage+0x58 tipico 112.
            ctLen = 112;
        }

        // f4 varint = host size hint (0 = solo Ford; 112+data = packed)
        if (pos < authorizeGetBody.Length && authorizeGetBody[pos] == 0x20)
        {
            pos++;
            if (!TryReadVarintInt(authorizeGetBody, ref pos, out hostHint) || hostHint < 0)
                hostHint = 0;
        }

        // OID: field3 LD len=20 ascii nello stesso HostInfo.
        // Dopo il gate possono esserci altri nested 0A2D (multi-ford pack) prima
        // del 1A14 OID — ike_run Sapphire 3661: OID @+212 dal gate (>96).
        var objectId = "";
        var scanLo = Math.Max(0, gateStart - 128);
        var scanEnd = Math.Min(authorizeGetBody.Length - 22, gateStart + 512);
        for (var k = scanLo; k <= scanEnd; k++)
        {
            if (authorizeGetBody[k] != 0x1A || authorizeGetBody[k + 1] != 0x14)
                continue;
            var oidSpan = authorizeGetBody.Slice(k + 2, 20);
            if (!IsPrintableAscii(oidSpan))
                continue;
            objectId = Encoding.ASCII.GetString(oidSpan);
            // Preferisci l'OID dopo il gate (pack shared); se solo prima, tienilo.
            if (k >= gateStart)
                break;
        }

        // Dedup: stesso gate+ctLen+oid
        foreach (var prev in list)
        {
            if (prev.CtLen == ctLen
                && string.Equals(prev.ObjectId, objectId, StringComparison.Ordinal)
                && prev.Gate45.AsSpan().SequenceEqual(gate))
                return;
        }

        list.Add(new AuthFordDescriptor(gate, ctLen, hostHint, objectId, wireOffset));
    }

    /// <summary>
    /// Auth→storage: nested wire è la fonte di <c>storage+0x58 ctLen</c>
    /// (live spill: file size = nested ctLen, es. 234). CI45 identifica lo stesso
    /// gate; la sua <c>Length</c> può differire e <b>non</b> crea un secondo descriptor
    /// né sovrascrive il ctLen nested.
    /// </summary>
    public static IReadOnlyList<AuthFordDescriptor> CollectAuthFordDescriptors(
        ReadOnlySpan<byte> authorizeGetBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk>? chunks = null)
    {
        // Nested 0A2D‖gate‖18 ctLen = storage+0x58 (priorità assoluta).
        var list = ExtractAuthFordDescriptors(authorizeGetBody).ToList();

        // CI45: solo se il gate non è già nel nested; ctLen = nested se noto, else CI.Length.
        for (var i = 0; i < plan.Containers.Count; i++)
        {
            var group = plan.Containers[i];
            if (group.Count == 0 || !group.Any(IsAuthFordDescriptorChunk))
                continue;
            var oid = "";
            if (chunks is not null
                && (uint)i < (uint)chunks.Count
                && !string.IsNullOrEmpty(chunks[i].EdgeHeaders?.ObjectId))
                oid = chunks[i].EdgeHeaders!.ObjectId!;

            foreach (var ch in group)
            {
                if (!IsAuthFordDescriptorChunk(ch) || !IsPlausibleAuthFordCtLen(ch.Length))
                    continue;
                var gate = ch.Checksum21;

                var existing = -1;
                for (var k = 0; k < list.Count; k++)
                {
                    if (list[k].Gate45.AsSpan().SequenceEqual(gate))
                    {
                        existing = k;
                        break;
                    }
                }

                if (existing >= 0)
                {
                    // Stesso gate: tieni ctLen nested; completa solo OID mancante.
                    var prev = list[existing];
                    if (string.IsNullOrEmpty(prev.ObjectId) && !string.IsNullOrEmpty(oid))
                        list[existing] = prev with { ObjectId = oid };
                    continue;
                }

                list.Add(new AuthFordDescriptor(gate, ch.Length, 0, oid, -1 - i));
            }
        }

        // Solo bag large: esigi ctLen ≤ ByteRange host. I classici non si toccano.
        if (chunks is { Count: > 0 } && list.Count > 0)
        {
            for (var di = list.Count - 1; di >= 0; di--)
            {
                var d = list[di];
                if (!IsLargeAuthFordCtLen(d.CtLen))
                    continue;
                long hostLen = 0;
                if (!string.IsNullOrEmpty(d.ObjectId))
                {
                    foreach (var ch in chunks)
                    {
                        if (!string.Equals(ch.EdgeHeaders?.ObjectId, d.ObjectId, StringComparison.Ordinal)
                            || ch.ByteRange is not { } br)
                            continue;
                        hostLen = br.End - br.Start + 1;
                        break;
                    }
                }

                if (!IsPlausibleAuthFordCtLen(d.CtLen, hostLen))
                    list.RemoveAt(di);
            }
        }

        return list;
    }

    private static bool IsPrintableAscii(ReadOnlySpan<byte> bytes)
    {
        foreach (var b in bytes)
        {
            if (b is < 0x20 or > 0x7E)
                return false;
        }

        return bytes.Length > 0;
    }

    /// <summary>
    /// Disabilitato: non inventa Ford da dataStart−N. Ford = FileGroup Auth GET exact.
    /// </summary>
    public static SignedUrlChunk? TryBuildImpliedFordChunk(SignedUrlChunk dataChunk, int fordLen = 112)
    {
        _ = dataChunk;
        _ = fordLen;
        return null;
    }

    /// <summary>Legacy: object-id then Start. Prefer <see cref="OrderChunksForFordFile"/>.</summary>
    public static List<SignedUrlChunk> OrderChunksForCompact(IEnumerable<SignedUrlChunk> chunks)
    {
        var list = chunks.Where(static c => !string.IsNullOrEmpty(c.Url)).ToList();
        static string Oid(SignedUrlChunk c) => c.EdgeHeaders?.ObjectId ?? "";
        var oidOrder = new List<string>();
        foreach (var c in list)
        {
            var oid = Oid(c);
            if (!oidOrder.Contains(oid, StringComparer.Ordinal))
                oidOrder.Add(oid);
        }

        var result = new List<SignedUrlChunk>(list.Count);
        foreach (var oid in oidOrder)
        {
            result.AddRange(
                list.Where(c => Oid(c) == oid)
                    .OrderBy(c => c.ByteRange?.Start ?? long.MaxValue));
        }

        return result;
    }
}

public sealed record SignedUrlChunk
{
    public string Url { get; init; } = string.Empty;
    public (long Start, long End)? ByteRange { get; init; }
    public EdgeDownloadHeaders? EdgeHeaders { get; init; }
    /// <summary>
    /// Solo se #path edge == #ChunkInfo (tipico single-object).
    /// Per multi-chunk crypto usa <see cref="UbChunkBuilder.ExtractAuthorizeGetCryptoChunks"/>.
    /// </summary>
    public byte[]? ChunkEncryptionKey { get; init; }
    /// <summary>FileGroup.f2 ChunkInfo.f3 — lunghezza ciphertext inclusiva (live).</summary>
    public int CtLen { get; init; }
    /// <summary>FileGroup.f2 ChunkInfo.f4 — offset nel pack (0 se non pack).</summary>
    public long PackOffset { get; init; }
}

/// <summary>Unità di cifratura MMCS (AES-CFB) dentro authorizeGet ChunkInfo.</summary>
public sealed record AuthorizeGetCryptoChunk
{
    public byte[] EncryptionKey { get; init; } = Array.Empty<byte>();
    public byte[] Checksum21 { get; init; } = Array.Empty<byte>();
    public int Length { get; init; }
    public long Offset { get; init; }
}

/// <summary>Riferimento <c>ChunkReference</c>: indice container edge + indice ChunkInfo.</summary>
public sealed record AuthorizeGetChunkRef
{
    public int ContainerIndex { get; init; }
    public int ChunkIndex { get; init; }
}

public sealed record AuthorizeGetFilePart(
    IReadOnlyList<SignedUrlChunk> Chunks,
    byte[] AuthSlice);

/// <summary>
/// Piano decrypt: ogni container = un GET edge; <see cref="References"/> = ordine file finale.
/// <see cref="FileChecksum"/> = identità file nel wire Auth (refs.field1); lega il Gate45 Ford.
/// </summary>
public sealed record AuthorizeGetDecryptPlan
{
    public IReadOnlyList<IReadOnlyList<AuthorizeGetCryptoChunk>> Containers { get; init; } =
        Array.Empty<IReadOnlyList<AuthorizeGetCryptoChunk>>();

    public IReadOnlyList<AuthorizeGetChunkRef> References { get; init; } =
        Array.Empty<AuthorizeGetChunkRef>();

    /// <summary>
    /// <c>FileChecksumChunkReferences.file_checksum</c> (21B). Stesso valore di
    /// <c>Assets.assetSignature</c> / gate45[3:24].
    /// </summary>
    public byte[]? FileChecksum { get; init; }

    /// <summary>
    /// <c>FileChecksumChunkReferences</c> field3 (21B) = gate45[24:45].
    /// </summary>
    public byte[]? CompanionChecksum { get; init; }

    public int TotalCryptoChunks
    {
        get
        {
            if (References.Count > 0)
            {
                var n = 0;
                foreach (var r in References)
                {
                    if ((uint)r.ContainerIndex >= (uint)Containers.Count)
                        continue;
                    var g = Containers[r.ContainerIndex];
                    if ((uint)r.ChunkIndex >= (uint)g.Count)
                        continue;
                    if (UbChunkBuilder.IsAuthDataChunk(g[r.ChunkIndex]))
                        n++;
                }

                return n;
            }

            return Containers.Sum(static c => c.Count(UbChunkBuilder.IsAuthDataChunk));
        }
    }

    /// <summary>
    /// Data CT del file: somma lengths dei ChunkInfo data citati dai <see cref="References"/>.
    /// (FileGroup: non sommare i data host degli altri file nello stesso AG.)
    /// </summary>
    public long TotalCryptoBytes
    {
        get
        {
            if (References.Count > 0)
            {
                long sum = 0;
                foreach (var r in References)
                {
                    if ((uint)r.ContainerIndex >= (uint)Containers.Count)
                        continue;
                    var g = Containers[r.ContainerIndex];
                    if ((uint)r.ChunkIndex >= (uint)g.Count)
                        continue;
                    var ch = g[r.ChunkIndex];
                    if (UbChunkBuilder.IsAuthDataChunk(ch))
                        sum += ch.Length;
                }

                return sum;
            }

            return Containers.Sum(static c =>
                c.Where(UbChunkBuilder.IsAuthDataChunk).Sum(static x => (long)x.Length));
        }
    }
}

public sealed record EdgeDownloadHeaders
{
    public string ObjectId { get; init; } = string.Empty;
    public string Destination { get; init; } = string.Empty;
    public string MmeOwner { get; init; } = string.Empty;
    public string OpaqueOwnerId { get; init; } = string.Empty;
    public string Partition { get; init; } = string.Empty;
    public string Uuid { get; init; } = string.Empty;
    public string Date { get; init; } = string.Empty;
    public string Expires { get; init; } = string.Empty;
    public string Signature { get; init; } = string.Empty;
    public string HttpDate { get; init; } = string.Empty;
    public string BossRecommendationUsed { get; init; } = string.Empty;
    public string IncomingEdgePop { get; init; } = string.Empty;
    /// <summary>
    /// live: <c>X-Apple-MMCS-Container-Size: 0</c> = empty Ford host (gate+ctLen GET).
    /// </summary>
    public string MmcsContainerSize { get; init; } = string.Empty;
}
