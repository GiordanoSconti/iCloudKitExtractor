using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Parser generico per risposte PreAuth/query: frame ubchunk delimited, path MMCS firmati,
/// nomi record asset e seed KA:/MA:/… (valori dipendono dalla sessione, non hardcoded).
/// </summary>
public static class UbChunkCatalogParser
{
    /// <summary>PreAuth usa N:{uuid}:{checksum}=:0 (non EN:).</summary>
    private static readonly Regex NRecordRegex = new(
        @"\bN:([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}):([A-Za-z0-9+/=]{8,80})=:0",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public static UbChunkCatalog Parse(byte[]? payload)
    {
        if (payload is not { Length: > 0 })
            return UbChunkCatalog.Empty;

        var recordNames = new HashSet<string>(StringComparer.Ordinal);
        var paths = new HashSet<string>(StringComparer.Ordinal);
        var chunks = new Dictionary<string, SignedUrlChunk>(StringComparer.OrdinalIgnoreCase);
        var auths = new Dictionary<string, string>(StringComparer.Ordinal);

        void Absorb(ReadOnlySpan<byte> block)
        {
            foreach (var name in CloudKitResponseParser.ExtractAssetRecordNames(block.ToArray()))
                recordNames.Add(name);

            foreach (var path in CloudKitMmcsBatchBuilder.ExtractSignedPaths(block))
                paths.Add(path);

            foreach (var chunk in UbChunkBuilder.ParseAuthorizeGetResponse(block))
            {
                if (!string.IsNullOrWhiteSpace(chunk.Url))
                    chunks[chunk.Url] = chunk;
            }

            foreach (var auth in MmcsAuthBuilder.ExtractStructuredAuths(block.ToArray()))
            {
                var key = auth.RecordName;
                if (string.IsNullOrWhiteSpace(key))
                {
                    // Chiave stabile = primo token hex (42 char) dell'header x-apple-mmcs-auth.
                    var sp = auth.Header.IndexOf(' ');
                    key = sp > 0 ? auth.Header[..sp] : $"auth:{auths.Count}";
                }

                auths[key] = auth.Header;
            }

            foreach (Match match in NRecordRegex.Matches(
                         System.Text.Encoding.Latin1.GetString(block)))
            {
                recordNames.Add(BuildNRecordName(match.Groups[1].Value, match.Groups[2].Value));
            }
        }

        Absorb(payload);

        foreach (var frame in UbChunkDelimitedCodec.EnumerateFrames(payload))
            Absorb(frame);

        var chunkList = chunks.Values.ToList();
        foreach (var path in paths)
        {
            foreach (var chunk in CloudKitMmcsBatchBuilder.ChunksFromSignedPaths([path]))
            {
                if (!chunks.ContainsKey(chunk.Url))
                    chunkList.Add(chunk);
            }
        }

        var orderedNames = recordNames
            .OrderBy(static n => n, StringComparer.Ordinal)
            .ToList();

        var seeds = orderedNames
            .Where(IsQuerySeed)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        foreach (var pair in auths)
        {
            if (IsQuerySeed(pair.Key) && !seeds.Contains(pair.Key, StringComparer.Ordinal))
                seeds.Add(pair.Key);
        }

        return new UbChunkCatalog
        {
            RecordNames = orderedNames,
            QuerySeeds = seeds,
            SignedChunks = chunkList,
            SignedPaths = paths.OrderBy(static p => p, StringComparer.Ordinal).ToList(),
            MmcsAuths = auths
        };
    }

    public static string? SelectPrimaryQuerySeed(UbChunkCatalog catalog)
    {
        if (catalog.QuerySeeds.Count == 0)
            return null;

        return catalog.QuerySeeds
            .OrderBy(static s => QuerySeedPriority(s))
            .ThenBy(static s => s, StringComparer.Ordinal)
            .First();
    }

    public static byte[]? TryExtractWscSessionPrefix(byte[]? payload)
    {
        if (payload is not { Length: > 64 })
            return null;

        var frames = UbChunkDelimitedCodec.EnumerateFrames(payload);
        if (frames.Count == 0)
            return null;

        var prefix = new List<byte[]>();
        foreach (var frame in frames)
        {
            prefix.Add(frame);
            if (frame.AsSpan().IndexOf("wSc"u8) >= 0)
                return UbChunkDelimitedCodec.ConcatFrames(prefix);
        }

        return null;
    }

    public static byte[]? TryExtractPreAuthSessionBlob(byte[]? payload)
    {
        if (payload is not { Length: > 512 })
            return null;

        foreach (var frame in UbChunkDelimitedCodec.EnumerateFrames(payload))
        {
            if (frame.Length is < 2800 or > 3200)
                continue;

            // Retrieve frame corti (141–190 B) già esclusi dalla lunghezza.
            // Il blob sessione (~2940 B) può contenere N: embedded: non filtrarlo.

            if (frame.AsSpan().IndexOf("Foreground Restore"u8) >= 0)
                continue;

            return frame;
        }

        return null;
    }

    public static byte[]? TryExtractForegroundSessionFrame(params byte[]?[] payloads)
    {
        foreach (var payload in payloads)
        {
            if (payload is not { Length: > 256 })
                continue;

            foreach (var frame in UbChunkDelimitedCodec.EnumerateFrames(payload))
            {
                if (frame.Length is >= 2800 and <= 3200 && ContainsForegroundRestore(frame))
                    return frame;

                if (frame.Length is >= 4096 and <= 16_384 && ContainsForegroundRestore(frame))
                    return frame;
            }

            if (payload.Length is >= 2800 and <= 16_384 && ContainsForegroundRestore(payload))
                return payload;
        }

        return null;
    }

    /// <summary>
    /// Nome record PreAuth / file-list  <c>N:{uuid}:{checksum}=:0</c>.
    /// Attenzione: lunghezza nome = 69 (<c>0x45</c> = <c>'E'</c>) + <c>N:</c> sembra <c>EN:</c> in ASCII grezzo.
    /// </summary>
    public static string BuildNRecordName(string fileUuid, string checksumBase64) =>
        CloudKitManifestChecksumParser.ToEnRecordName(
            new CloudKitManifestChecksumParser.CnEntry(fileUuid, checksumBase64));

    public static bool ContainsChunkRecordName(ReadOnlySpan<byte> data) =>
        data.IndexOf("N:"u8) >= 0 && data.IndexOf("=:0"u8) >= 0;

    private static bool ContainsForegroundRestore(ReadOnlySpan<byte> data)
    {
        return data.IndexOf("Foreground Restore"u8) >= 0
               && (data.IndexOf("CKDFetchRecordsOperation"u8) >= 0
                   || data.IndexOf("CKDFetch"u8) >= 0);
    }

    private static bool IsQuerySeed(string recordName) =>
        recordName.StartsWith("KA:", StringComparison.Ordinal)
        || recordName.StartsWith("MA:", StringComparison.Ordinal)
        || recordName.StartsWith("LA:", StringComparison.Ordinal)
        || recordName.StartsWith("NA:", StringComparison.Ordinal)
        || recordName.StartsWith("JA:", StringComparison.Ordinal);

    private static int QuerySeedPriority(string recordName)
    {
        if (recordName.StartsWith("KA:", StringComparison.Ordinal))
            return 0;
        if (recordName.StartsWith("MA:", StringComparison.Ordinal))
            return 1;
        if (recordName.StartsWith("LA:", StringComparison.Ordinal))
            return 2;
        if (recordName.StartsWith("NA:", StringComparison.Ordinal))
            return 3;
        return 4;
    }
}
