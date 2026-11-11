namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Catalogo estratto da risposte PreAuth / query ubchunk (parametri dipendono dalla sessione).
/// </summary>
public sealed record UbChunkCatalog
{
    public IReadOnlyList<string> RecordNames { get; init; } = [];
    public IReadOnlyList<string> QuerySeeds { get; init; } = [];
    public IReadOnlyList<SignedUrlChunk> SignedChunks { get; init; } = [];
    public IReadOnlyList<string> SignedPaths { get; init; } = [];
    public IReadOnlyDictionary<string, string> MmcsAuths { get; init; }
        = new Dictionary<string, string>(StringComparer.Ordinal);

    public static UbChunkCatalog Empty { get; } = new();

    public UbChunkCatalog Merge(UbChunkCatalog other)
    {
        var names = new HashSet<string>(RecordNames, StringComparer.Ordinal);
        foreach (var name in other.RecordNames)
            names.Add(name);

        var seeds = new HashSet<string>(QuerySeeds, StringComparer.Ordinal);
        foreach (var seed in other.QuerySeeds)
            seeds.Add(seed);

        var paths = new HashSet<string>(SignedPaths, StringComparer.Ordinal);
        foreach (var path in other.SignedPaths)
            paths.Add(path);

        var chunks = new Dictionary<string, SignedUrlChunk>(StringComparer.OrdinalIgnoreCase);
        foreach (var chunk in SignedChunks)
            chunks[chunk.Url] = chunk;
        foreach (var chunk in other.SignedChunks)
            chunks[chunk.Url] = chunk;

        var auths = new Dictionary<string, string>(MmcsAuths, StringComparer.Ordinal);
        foreach (var pair in other.MmcsAuths)
            auths[pair.Key] = pair.Value;

        return new UbChunkCatalog
        {
            RecordNames = names.OrderBy(static n => n, StringComparer.Ordinal).ToList(),
            QuerySeeds = seeds.OrderBy(static n => n, StringComparer.Ordinal).ToList(),
            SignedChunks = chunks.Values.ToList(),
            SignedPaths = paths.OrderBy(static p => p, StringComparer.Ordinal).ToList(),
            MmcsAuths = auths
        };
    }
}
