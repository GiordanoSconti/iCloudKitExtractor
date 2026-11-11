using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Models;

/// <summary>Risultato PreAuth post-Lock: catalogo dinamico per la sessione corrente.</summary>
public sealed record CloudKitPreAuthResult
{
    public UbChunkCatalog Catalog { get; init; } = UbChunkCatalog.Empty;

    public IReadOnlyList<string> RecordNames => Catalog.RecordNames;

    public IReadOnlyList<string> QuerySeeds => Catalog.QuerySeeds;

    public IReadOnlyList<SignedUrlChunk> SignedChunks => Catalog.SignedChunks;

    /// <summary>Voci :CN: già inviate in PreAuth (record + query).</summary>
    public int CnEntriesConsumed { get; init; }

    public int TotalCnEntries { get; init; }
}
