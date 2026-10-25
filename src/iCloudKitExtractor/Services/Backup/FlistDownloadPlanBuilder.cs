using System.IO;
using System.Linq;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// <c>GatherFilesToDownload</c> da flist SQLite (post <c>ReadIos26FileList</c>):
/// join Assets⇄FileMetadata → Domain+path+ek + assetSignature per authorizeGet.
/// <para>
/// Identità <c>CKFile+0x08</c>: <c>RecordName = A:{pref4}:{rid}</c>
/// (pref4 = <c>DevicePrefix4</c> = zonePref, es. <c>fd77</c>;
/// rid = <c>uuid:token=:size</c>); non collassare a UUID.
/// FileID/MMCS = <c>F:{uuid}:{token}:{size}:</c>;
/// authorizeGet field1 = <c>Assets.assetSignature</c> verbatim.
/// Batch authorizeGet/PrivilegedBatch = Asset di un fileList; flusso download
/// interleaved  FL → parse → Asset → FL successivo.
/// </para>
/// </summary>
public static class FlistDownloadPlanBuilder
{
    private const int S_IFMT = 0xF000;
    private const int S_IFDIR = 0x4000;
    private const int S_IFLNK = 0xA000;

    public sealed record Plan(
        IReadOnlyList<BackupAsset> Assets,
        /// <summary>Un batch per fileList SQLite (= Asset count di quel Domain.fileList).</summary>
        IReadOnlyList<IReadOnlyList<BackupAsset>> FileListBatches,
        int FlistDatabases,
        int RowsWithSuffix,
        int ResolvedNames,
        int UnresolvedSuffixes,
        int SkippedNoDomain,
        int SkippedEmptyFile,
        int SkippedNoSignature,
        int SkippedDirOrLink,
        int SkippedZeroSize,
        int EnNameIndexSize);

    /// <summary>
    /// Piano Asset da un singolo <c>flist_*.db</c> appena materializzato (flusso interleaved).
    /// </summary>
    public static IReadOnlyList<BackupAsset> BuildBatchFromDb(
        string dbPath,
        string snapshotDirectory,
        EnFetchResult? enFetch = null,
        ISet<string>? seenAssetSignatureHex = null,
        IProgress<string>? log = null,
        string? devicePrefix4 = null)
    {
        if (!File.Exists(dbPath))
            return [];

        var domainBySig = LoadDomainBySignature(snapshotDirectory, enFetch);
        var flToObj = LoadFlSignatureToObjectId(snapshotDirectory);
        var stem = Path.GetFileNameWithoutExtension(dbPath);
        if (!stem.StartsWith("flist_", StringComparison.OrdinalIgnoreCase))
            return [];
        var key = stem["flist_".Length..];
        var domain = ResolveDomain(key, domainBySig, flToObj, dbPath);
        if (string.IsNullOrWhiteSpace(domain))
        {
            log?.Report($"  piano skip {Path.GetFileName(dbPath)}: domain assente");
            return [];
        }

        var seen = seenAssetSignatureHex
            ?? new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var batch = CollectBatchFromInventory(
            dbPath, domain, seen, out var stats, devicePrefix4);
        if (batch.Count > 0 || stats.MetaRows > 0)
        {
            log?.Report(
                $"  piano {domain}: {batch.Count} file da scaricare " +
                $"(FileMetadata={stats.MetaRows} incl. dir/link={stats.SkipDir}, " +
                $"Assets={stats.AssetRows}, empty={stats.SkipEmpty}, noSig={stats.SkipNoSig}, " +
                $"size0={stats.SkipZero}, dup={stats.SkipDup})");
        }


        return batch;
    }

    public static Plan Build(
        string snapshotDirectory,
        BackupDevice device,
        EnFetchResult? enFetch = null,
        IProgress<string>? log = null)
    {
        var pref4 = CloudKitRecordNames.DevicePrefix4(device.DeviceUuid ?? "");
        var dbFiles = Directory.EnumerateFiles(snapshotDirectory, "flist_*.db")
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var batches = new List<IReadOnlyList<BackupAsset>>();
        var withSuffix = 0;
        var resolved = 0;
        var unresolved = 0;
        var skipDomain = 0;
        var skipEmpty = 0;
        var skipNoSig = 0;
        var skipDir = 0;
        var skipZero = 0;

        var domainBySig = LoadDomainBySignature(snapshotDirectory, enFetch);
        var flToObj = LoadFlSignatureToObjectId(snapshotDirectory);

        foreach (var dbPath in dbFiles)
        {
            var stem = Path.GetFileNameWithoutExtension(dbPath);
            if (!stem.StartsWith("flist_", StringComparison.OrdinalIgnoreCase))
                continue;
            var key = stem["flist_".Length..];
            var domain = ResolveDomain(key, domainBySig, flToObj, dbPath);
            if (string.IsNullOrWhiteSpace(domain))
            {
                skipDomain++;
                continue;
            }

            var batch = CollectBatchFromInventory(
                dbPath, domain, seen, out var stats, pref4);
            withSuffix += stats.WithSuffix;
            resolved += stats.Resolved;
            unresolved += stats.Unresolved;
            skipEmpty += stats.SkipEmpty;
            skipNoSig += stats.SkipNoSig;
            skipDir += stats.SkipDir;
            skipZero += stats.SkipZero;
            if (batch.Count > 0)
                batches.Add(batch);
        }

        var list = batches.SelectMany(static b => b).ToList();
        var batchSizes = batches.Count == 0
            ? "∅"
            : string.Join(",", batches.Select(static b => b.Count).Take(12))
              + (batches.Count > 12 ? ",…" : "");

        log?.Report(
            $"Piano file da flist (GatherFiles): db={dbFiles.Count}, " +
            $"batches={batches.Count} (size/fileList=[{batchSizes}]), " +
            $"ck=A:pref4:rid, authGet.f1=assetSignature, " +
            $"conSuffix={withSuffix}, nomiOK={resolved}, unresolved={unresolved}, " +
            $"emptyFile={skipEmpty}, noSig={skipNoSig}, dir/link={skipDir}, " +
            $"size0={skipZero}, skipDomain={skipDomain}, assetUnici={list.Count}");

        return new Plan(
            list, batches, dbFiles.Count, withSuffix, resolved, unresolved,
            skipDomain, skipEmpty, skipNoSig, skipDir, skipZero, 0);
    }

    private readonly record struct CollectStats(
        int MetaRows,
        int AssetRows,
        int WithSuffix,
        int Resolved,
        int Unresolved,
        int SkipEmpty,
        int SkipNoSig,
        int SkipDir,
        int SkipZero,
        int SkipDup);

    private static List<BackupAsset> CollectBatchFromInventory(
        string dbPath,
        string domain,
        ISet<string> seenAssetSignatureHex,
        out CollectStats stats,
        string? devicePrefix4 = null)
    {
        stats = default;
        var inventory = FileListSqliteParser.ParseInventory(dbPath);
        if (!inventory.Ok)
            return [];

        var batch = new List<BackupAsset>();
        var withSuffix = 0;
        var resolved = 0;
        var unresolved = 0;
        var skipEmpty = 0;
        var skipNoSig = 0;
        var skipDir = 0;
        var skipZero = 0;
        var skipDup = 0;

        foreach (var row in inventory.Rows)
        {
            if (string.IsNullOrWhiteSpace(row.RelativePath))
                continue;

            if (IsDirOrSymlink(row.Mode))
            {
                skipDir++;
                continue;
            }

            if (string.IsNullOrWhiteSpace(row.RecordIdSuffix))
                continue;

            var rid = row.RecordIdSuffix.Trim();
            if (IsEmptyFileMarker(rid))
            {
                skipEmpty++;
                continue;
            }

            withSuffix++;

            if (row.AssetSignature is not { Length: 21 })
            {
                skipNoSig++;
                continue;
            }

            var assetSize = row.AssetSize is > 0 ? row.AssetSize.Value
                : row.Size > 0 ? row.Size : 0L;
            if (assetSize <= 0)
            {
                skipZero++;
                continue;
            }

            var ckUuid = CloudKitMmcsIds.CkRecordNameFromRid(rid);
            var mmcsFileId = CloudKitMmcsIds.ToMmcsFileId(rid);
            if (ckUuid is null || mmcsFileId is null)
            {
                unresolved++;
                continue;
            }

            // CKFile+0x08: A:{zonePref}:{rid} — zonePref ≡ DevicePrefix4(deviceSha).
            var recordKey = !string.IsNullOrWhiteSpace(devicePrefix4)
                ? CloudKitMmcsIds.ToPrivilegedBatchSeed(devicePrefix4, rid)
                : null;

            var sigKey = Convert.ToHexString(row.AssetSignature).ToLowerInvariant();
            resolved++;
            var asset = new BackupAsset
            {
                RecordName = recordKey ?? ckUuid,
                ZoneName = "_defaultZone",
                MmcsFileId = mmcsFileId,
                RecordIdSuffix = rid,
                AssetSignature = row.AssetSignature,
                CompressionMethod = row.CompressionMethod,
                Domain = domain,
                RelativePath = row.RelativePath,
                EncryptionKey = row.EncryptionKey,
                ProtectionClass = row.ProtectionClass > 0 ? row.ProtectionClass : null,
                SizeBytes = assetSize
            };
            asset.EnsureFileId();
            if (!seenAssetSignatureHex.Add(sigKey))
            {
                skipDup++;
                asset.ContentFromExistingSignature = true;
                batch.Add(asset);
                continue;
            }

            batch.Add(asset);
        }

        stats = new CollectStats(
            inventory.FileMetadataRows, inventory.AssetRows,
            withSuffix, resolved, unresolved, skipEmpty, skipNoSig, skipDir, skipZero, skipDup);
        return batch;
    }

    /// <summary>
    /// Applica Domain/path/EK/sig dal piano a un asset scaricato solo per nome (PrivilegedBatch).
    /// </summary>
    public static void ApplyIdentity(BackupAsset target, BackupAsset? fromPlan)
    {
        if (fromPlan is null)
            return;
        if (string.IsNullOrWhiteSpace(target.Domain) && !string.IsNullOrWhiteSpace(fromPlan.Domain))
            target.Domain = fromPlan.Domain;
        if (string.IsNullOrWhiteSpace(target.RelativePath)
            && !string.IsNullOrWhiteSpace(fromPlan.RelativePath))
            target.RelativePath = fromPlan.RelativePath;
        if (target.EncryptionKey is not { Length: > 0 }
            && fromPlan.EncryptionKey is { Length: > 0 })
            target.EncryptionKey = fromPlan.EncryptionKey;
        if (target.ProtectionClass is null && fromPlan.ProtectionClass is not null)
            target.ProtectionClass = fromPlan.ProtectionClass;
        if (target.SizeBytes is null && fromPlan.SizeBytes is not null)
            target.SizeBytes = fromPlan.SizeBytes;
        if (string.IsNullOrWhiteSpace(target.MmcsFileId)
            && !string.IsNullOrWhiteSpace(fromPlan.MmcsFileId))
            target.MmcsFileId = fromPlan.MmcsFileId;
        if (string.IsNullOrWhiteSpace(target.RecordIdSuffix)
            && !string.IsNullOrWhiteSpace(fromPlan.RecordIdSuffix))
            target.RecordIdSuffix = fromPlan.RecordIdSuffix;
        if (target.AssetSignature is not { Length: 21 }
            && fromPlan.AssetSignature is { Length: 21 })
            target.AssetSignature = fromPlan.AssetSignature;
        if (target.CompressionMethod is null && fromPlan.CompressionMethod is not null)
            target.CompressionMethod = fromPlan.CompressionMethod;
        // Promote UUID-only → recordKey A:pref4:rid when the plan has it.
        if (!string.IsNullOrWhiteSpace(fromPlan.RecordName)
            && CloudKitMmcsIds.IsAssetRecordName(fromPlan.RecordName)
            && (string.IsNullOrWhiteSpace(target.RecordName)
                || CloudKitMmcsIds.IsUuidRecordName(target.RecordName)))
            target.RecordName = fromPlan.RecordName;
        target.EnsureFileId();
    }

    private static bool IsEmptyFileMarker(string rid) =>
        rid.Equals("EMPTY_FILE", StringComparison.OrdinalIgnoreCase);

    private static bool IsDirOrSymlink(long mode)
    {
        var type = (int)mode & S_IFMT;
        return type is S_IFDIR or S_IFLNK;
    }

    private static Dictionary<string, string> LoadDomainBySignature(
        string snapshotDirectory,
        EnFetchResult? enFetch)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (enFetch is not null)
        {
            foreach (var d in enFetch.DomainRecords)
            {
                if (d.FileList is null || string.IsNullOrWhiteSpace(d.DomainName))
                    continue;
                map[d.FileList.SignatureHex] = d.DomainName;
            }

            foreach (var fl in enFetch.FileListAssets)
                map[fl.SignatureHex] = fl.DomainName;
        }

        var mapPath = Path.Combine(snapshotDirectory, "domain_filelists.json");
        if (!File.Exists(mapPath))
            return map;

        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(mapPath));
            foreach (var el in doc.RootElement.EnumerateArray())
            {
                var sig = el.TryGetProperty("signatureHex", out var s) ? s.GetString() : null;
                var domain = el.TryGetProperty("domain", out var d) ? d.GetString() : null;
                if (!string.IsNullOrWhiteSpace(sig) && !string.IsNullOrWhiteSpace(domain))
                    map[sig] = domain;
            }
        }
        catch
        {
            // ignore
        }

        return map;
    }

    private static Dictionary<string, string> LoadFlSignatureToObjectId(string snapshotDirectory)
    {
        var objs = Directory.EnumerateFiles(snapshotDirectory, "OBJ_*.bin")
            .Where(static p => !p.EndsWith(".ciphertext", StringComparison.OrdinalIgnoreCase))
            .Select(static p =>
            {
                var name = Path.GetFileNameWithoutExtension(p);
                return name.StartsWith("OBJ_", StringComparison.Ordinal) ? name[4..] : name;
            })
            .Where(static s => s.Length > 0)
            .ToHashSet(StringComparer.Ordinal);

        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var auth in Directory.EnumerateFiles(snapshotDirectory, "AUTH_FL_*_authorizeGet.bin"))
        {
            var name = Path.GetFileName(auth);
            const string prefix = "AUTH_FL_";
            const string suffix = "_authorizeGet.bin";
            if (!name.StartsWith(prefix, StringComparison.OrdinalIgnoreCase)
                || !name.EndsWith(suffix, StringComparison.OrdinalIgnoreCase))
                continue;
            var sig = name[prefix.Length..^suffix.Length];
            byte[] body;
            try { body = File.ReadAllBytes(auth); }
            catch { continue; }
            var text = Encoding.Latin1.GetString(body);
            foreach (var oid in objs)
            {
                if (!text.Contains(oid, StringComparison.Ordinal))
                    continue;
                map[sig.ToLowerInvariant()] = oid;
                break;
            }
        }

        return map;
    }

    private static string? ResolveDomain(
        string flistKey,
        IReadOnlyDictionary<string, string> domainBySig,
        IReadOnlyDictionary<string, string> flToObj,
        string dbPath)
    {
        if (domainBySig.TryGetValue(flistKey, out var domain))
            return domain;
        var keyLower = flistKey.ToLowerInvariant();
        if (domainBySig.TryGetValue(keyLower, out domain))
            return domain;

        foreach (var (sig, oid) in flToObj)
        {
            if (!string.Equals(oid, flistKey, StringComparison.Ordinal)
                && !string.Equals(oid, keyLower, StringComparison.OrdinalIgnoreCase))
                continue;
            if (domainBySig.TryGetValue(sig, out domain)
                || domainBySig.TryGetValue(sig.ToLowerInvariant(), out domain))
                return domain;
        }

        var metaPath = Path.Combine(
            Path.GetDirectoryName(dbPath)!,
            Path.GetFileNameWithoutExtension(dbPath) + "_meta.json");
        if (!File.Exists(metaPath))
            return null;
        try
        {
            using var doc = JsonDocument.Parse(File.ReadAllText(metaPath));
            if (doc.RootElement.TryGetProperty("domain", out var d))
                return d.GetString();
        }
        catch
        {
            // ignore
        }

        return null;
    }
}
