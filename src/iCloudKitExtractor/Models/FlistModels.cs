using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Models;

/// <summary>
/// Riga flist (temp <c>flist-*.db</c>): path nel dominio + link all'asset CloudKit/MMCS.
/// </summary>
public sealed class FlistEntry
{
    /// <summary>Domain iTunes se noto (es. <c>AppDomainGroup-…</c>); può arrivare dal contesto EN.</summary>
    public string? Domain { get; init; }

    public string RelativePath { get; init; } = string.Empty;

    /// <summary>
    /// Suffisso asset come in <c>Assets.recordIDSuffix</c>
    /// (es. <c>15067191-…:xlplPGwp…+BoNO8=:42</c>) —
    /// CK = <c>rid.Split(':')[0]</c>, MMCS = <c>F:{rid}:</c>.
    /// </summary>
    public string? RecordIdSuffix { get; init; }

    /// <summary>Nome record CloudKit (UUID da rid) se risolto.</summary>
    public string? AssetRecordName { get; init; }

    public byte[]? AssetSignature { get; init; }
    public byte[]? EncryptionKey { get; init; }
    public long AssetSize { get; init; }
    public int ProtectionClass { get; init; }
    public int Mode { get; init; }
    public string? SourceEnRecord { get; init; }
}

/// <summary>Esito del batch <c>EN:</c> / <c>N:</c> post-Lock.</summary>
public sealed class EnFetchResult
{
    public IReadOnlyList<string> RequestedNames { get; init; } = [];
    public IReadOnlyList<byte[]> ResponsePayloads { get; init; } = [];
    public IReadOnlyList<string> MmcsAuthHeaders { get; init; } = [];
    public IReadOnlyList<string> AssetRecordNames { get; init; } = [];
    public IReadOnlyList<string> QuerySeeds { get; init; } = [];
    public IReadOnlyList<FlistEntry> FlistEntries { get; init; } = [];
    /// <summary>Record Domain dalla retrieve N: (conteggi, fileList, delta asset).</summary>
    public IReadOnlyList<DomainFileListParser.DomainRecord> DomainRecords { get; init; } = [];
    /// <summary>
    /// Asset MMCS <c>Domain.fileList</c> (stesso schema di KA/MA) — inventario per dominio.
    /// </summary>
    public IReadOnlyList<DomainFileListParser.FileListAsset> FileListAssets { get; init; } = [];
    /// <summary>Path/chunk firmati estratti dalla risposta EN (edge MMCS).</summary>
    public IReadOnlyList<SignedUrlChunk> SignedChunks { get; init; } = [];
    public IReadOnlyList<string> SignedPaths { get; init; } = [];
    public int BatchCount { get; init; }
    public long TotalResponseBytes { get; init; }

    public bool HasAuth => MmcsAuthHeaders.Count > 0;

    /// <summary>EN utile per download: auth f2/f5/f17 e/o path edge firmati.</summary>
    public bool HasDownloadMaterial =>
        HasAuth || SignedChunks.Count > 0 || SignedPaths.Count > 0 || FileListAssets.Count > 0;
}
