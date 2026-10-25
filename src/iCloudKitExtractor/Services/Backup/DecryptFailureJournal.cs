using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Registro persistente file/chunk non decifrati durante il download live.
/// Output in <c>{snapshot}/decrypt_failures.jsonl</c> (machine) e
/// <c>{snapshot}/decrypt_failures.log</c> (human).
/// </summary>
public static class DecryptFailureJournal
{
    public const string JsonlFileName = "decrypt_failures.jsonl";
    public const string LogFileName = "decrypt_failures.log";

    private static readonly object Lock = new();
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static void Record(
        string snapshotDirectory,
        BackupAsset asset,
        string stage,
        string reason,
        DecryptFailureDetails? details = null)
    {
        if (string.IsNullOrWhiteSpace(snapshotDirectory))
            return;
        if (!IkeLogOptions.ShouldJournal(stage))
            return;

        details ??= new DecryptFailureDetails();
        var entry = BuildEntry(snapshotDirectory, asset, stage, reason, details);

        lock (Lock)
        {
            Directory.CreateDirectory(snapshotDirectory);
            var jsonlPath = Path.Combine(snapshotDirectory, JsonlFileName);
            File.AppendAllText(jsonlPath, JsonSerializer.Serialize(entry, JsonOpts) + "\n");

            var logPath = Path.Combine(snapshotDirectory, LogFileName);
            File.AppendAllText(logPath, FormatHumanLine(entry) + Environment.NewLine);
        }
    }

    public static void WriteSummary(string snapshotDirectory, IProgress<string>? log)
    {
        if (string.IsNullOrWhiteSpace(snapshotDirectory))
            return;

        var jsonlPath = Path.Combine(snapshotDirectory, JsonlFileName);
        if (!File.Exists(jsonlPath))
            return;

        var total = 0;
        var retryable = 0;
        foreach (var line in File.ReadLines(jsonlPath))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            total++;
            if (line.Contains("\"offlineRetryable\":true", StringComparison.Ordinal))
                retryable++;
        }

        log?.Report(
            $"Decrypt failures: {total} registrati in {JsonlFileName} " +
            $"({retryable} con pacchetto offline replay-ready)");
    }

    private static DecryptFailureEntry BuildEntry(
        string snapshotDirectory,
        BackupAsset asset,
        string stage,
        string reason,
        DecryptFailureDetails details)
    {
        var objectId = details.ObjectId ?? string.Empty;
        var offlineId = ResolveOfflineAssetId(asset, objectId);
        var pkgDir = Path.Combine(
            FordOfflineDumpWriter.ResolveRoot(snapshotDirectory),
            "assets",
            offlineId);

        var hasAuth = File.Exists(Path.Combine(pkgDir, "authorizeGet.bin"));
        var hasObj = File.Exists(Path.Combine(pkgDir, "obj_ciphertext.bin"));
        var hasWrap = File.Exists(Path.Combine(pkgDir, "wrap40.bin"))
                      || File.Exists(Path.Combine(pkgDir, "wrap24.bin"))
                      || !string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex);
        var hasIkm = File.Exists(Path.Combine(pkgDir, "ikm32.bin"))
                     || File.Exists(Path.Combine(pkgDir, "ikm16.bin"))
                     || asset.AssetUnwrappedKey is { Length: 16 or 32 };

        var edgeCompact = details.StagingObjectPath is { Length: > 0 } sp
            ? sp + ".edge_compact.bin"
            : null;
        var hasEdgeCompact = edgeCompact is not null && File.Exists(edgeCompact);

        var offlineRetryable = hasAuth && hasObj && (hasIkm || hasWrap);
        string? offlineNote = offlineRetryable
            ? "ford_offline/assets/{id}: authorizeGet + obj + wrap/IKM presenti — replay offline possibile"
                .Replace("{id}", offlineId, StringComparison.Ordinal)
            : BuildOfflineGapNote(hasAuth, hasObj, hasWrap, hasIkm, hasEdgeCompact);

        AuthorizeGetDecryptPlan? plan = null;
        if (details.AuthSlice is { Length: > 0 })
            plan = UbChunkBuilder.BuildDecryptPlan(details.AuthSlice);

        return new DecryptFailureEntry
        {
            TimestampUtc = DateTime.UtcNow.ToString("O", CultureInfo.InvariantCulture),
            Stage = stage,
            Reason = reason,
            RelativePath = asset.RelativePath,
            RecordName = asset.RecordName,
            AssetSignature = asset.AssetSignature is { Length: > 0 }
                ? Convert.ToHexString(asset.AssetSignature)
                : null,
            SizeBytes = asset.SizeBytes,
            ObjectId = string.IsNullOrEmpty(objectId) ? null : objectId,
            OfflineAssetId = offlineId,
            AssemblyMode = details.AssemblyMode,
            MmcsDecrypted = details.MmcsDecrypted,
            FileDecrypted = details.FileDecrypted,
            BodyLength = details.BodyLength,
            CompactLength = details.CompactLength,
            PlanCrypto = plan?.TotalCryptoChunks,
            PlanRefs = plan?.References.Count,
            PlanRefsList = plan?.References
                .Select(static r => $"{r.ContainerIndex}:{r.ChunkIndex}")
                .ToArray(),
            PlanHosts = plan?.Containers.Select(static c => c.Count).ToArray(),
            ChunkRanges = details.ChunkRanges,
            HasWrap = hasWrap,
            HasIkm = hasIkm,
            IkmLen = asset.AssetUnwrappedKey?.Length,
            OfflineRetryable = offlineRetryable,
            OfflineRetryNote = offlineNote,
            Artifacts = new DecryptFailureArtifacts
            {
                OfflinePackageDir = Directory.Exists(pkgDir) ? pkgDir : null,
                EdgeCompactPath = hasEdgeCompact ? edgeCompact : null,
                StagingObjectPath = details.StagingObjectPath is { Length: > 0 } stagingPath
                    && File.Exists(stagingPath)
                    ? stagingPath
                    : null,
                AuthSliceLength = details.AuthSlice?.Length,
            },
        };
    }

    private static string BuildOfflineGapNote(
        bool hasAuth,
        bool hasObj,
        bool hasWrap,
        bool hasIkm,
        bool hasEdgeCompact)
    {
        var missing = new List<string>(4);
        if (!hasAuth)
            missing.Add("authorizeGet.bin");
        if (!hasObj)
            missing.Add("obj_ciphertext.bin");
        if (!hasWrap)
            missing.Add("wrap");
        if (!hasIkm)
            missing.Add("IKM");
        if (!hasAuth && !hasObj && hasEdgeCompact)
            return "solo edge_compact in snapshot — dump ford_offline mancante, replay parziale";
        if (missing.Count == 0)
            return "artifact incompleti";
        return "mancano: " + string.Join(", ", missing);
    }

    private static string FormatHumanLine(DecryptFailureEntry e)
    {
        var path = e.RelativePath ?? e.RecordName ?? "?";
        var retry = e.OfflineRetryable ? "REPLAY=SI" : "REPLAY=NO";
        var sig = e.AssetSignature is { Length: >= 8 } s ? s[..8] + "…" : "-";
        return
            $"[{e.TimestampUtc}] {e.Stage.ToUpperInvariant()} | {path} | {e.Reason} | " +
            $"{retry} | sig={sig} | offline={e.OfflineAssetId}";
    }

    private static string ResolveOfflineAssetId(BackupAsset asset, string objectId)
    {
        if (asset.AssetSignature is { Length: >= 4 } sig)
        {
            var hex = Convert.ToHexString(sig);
            return "sig_" + hex[..Math.Min(40, hex.Length)].ToLowerInvariant();
        }

        return string.IsNullOrEmpty(objectId) ? "unknown" : "oid_" + objectId;
    }
}

public sealed class DecryptFailureDetails
{
    public string? ObjectId { get; init; }
    public string? StagingObjectPath { get; init; }
    public byte[]? AuthSlice { get; init; }
    public IReadOnlyList<SignedUrlChunk>? Chunks { get; init; }
    public string? AssemblyMode { get; init; }
    public bool? MmcsDecrypted { get; init; }
    public bool? FileDecrypted { get; init; }
    public int? BodyLength { get; init; }
    public int? CompactLength { get; init; }

    public string[]? ChunkRanges =>
        Chunks?
            .Where(static c => c.ByteRange is not null)
            .Select(static c =>
                $"{c.EdgeHeaders?.ObjectId}:{c.ByteRange!.Value.Start}-{c.ByteRange!.Value.End}")
            .ToArray();
}

internal sealed class DecryptFailureEntry
{
    public string TimestampUtc { get; init; } = "";
    public string Stage { get; init; } = "";
    public string Reason { get; init; } = "";
    public string? RelativePath { get; init; }
    public string? RecordName { get; init; }
    public string? AssetSignature { get; init; }
    public long? SizeBytes { get; init; }
    public string? ObjectId { get; init; }
    public string OfflineAssetId { get; init; } = "";
    public string? AssemblyMode { get; init; }
    public bool? MmcsDecrypted { get; init; }
    public bool? FileDecrypted { get; init; }
    public int? BodyLength { get; init; }
    public int? CompactLength { get; init; }
    public int? PlanCrypto { get; init; }
    public int? PlanRefs { get; init; }
    public string[]? PlanRefsList { get; init; }
    public int[]? PlanHosts { get; init; }
    public string[]? ChunkRanges { get; init; }
    public bool HasWrap { get; init; }
    public bool HasIkm { get; init; }
    public int? IkmLen { get; init; }
    public bool OfflineRetryable { get; init; }
    public string? OfflineRetryNote { get; init; }
    public DecryptFailureArtifacts? Artifacts { get; init; }
}

internal sealed class DecryptFailureArtifacts
{
    public string? OfflinePackageDir { get; init; }
    public string? EdgeCompactPath { get; init; }
    public string? StagingObjectPath { get; init; }
    public int? AuthSliceLength { get; init; }
}
