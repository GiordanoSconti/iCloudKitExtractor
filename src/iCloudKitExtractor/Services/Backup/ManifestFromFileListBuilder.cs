using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Ricostruisce <c>Manifest.db</c> stile iTunes/iTunes da DB <c>flist_*.db</c>
/// (<c>FileMetadata</c> + <c>Assets</c>) dopo MMCS+LZFSE.
/// </summary>
public static class ManifestFromFileListBuilder
{
    public sealed record RebuildResult(
        int FileListDatabases,
        int DomainsResolved,
        int RowsUpserted,
        int SkippedNoDomain,
        int SkippedNoPath,
        long ManifestBytes);

    /// <summary>
    /// Legge tutti i <c>flist_*.db</c> dalla cartella work e upserta <c>Files</c>
    /// nella cartella snapshot pulita (<c>Backup/</c>).
    /// </summary>
    public static async Task<RebuildResult> RebuildAsync(
        string workDirectory,
        IReadOnlyDictionary<string, string>? domainByFileListSignature = null,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        string? cleanBackupDirectory = null)
    {
        Directory.CreateDirectory(workDirectory);
        var cleanDir = cleanBackupDirectory
                       ?? IkeBackupOutputPaths.ResolveCleanBackupDirectory(workDirectory);
        Directory.CreateDirectory(cleanDir);

        var domainMap = await LoadDomainMapAsync(workDirectory, domainByFileListSignature, ct);
        var flToObj = LoadFlSignatureToObjectId(workDirectory);

        var dbFiles = Directory.EnumerateFiles(workDirectory, "flist_*.db")
            .Where(static p => !p.EndsWith("_meta.db", StringComparison.OrdinalIgnoreCase))
            .OrderBy(p => p, StringComparer.OrdinalIgnoreCase)
            .ToList();

        await using var writer = await BackupFilesystemWriter.OpenAsync(cleanDir, ct);
        var upserted = 0;
        var skippedDomain = 0;
        var skippedPath = 0;
        var domainsUsed = new HashSet<string>(StringComparer.Ordinal);
        var seenFileIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var batch = new List<(string FileId, string Domain, string RelativePath, int Flags, byte[] Plist)>(
            capacity: 4096);

        foreach (var dbPath in dbFiles)
        {
            ct.ThrowIfCancellationRequested();
            var stem = Path.GetFileNameWithoutExtension(dbPath);
            if (!stem.StartsWith("flist_", StringComparison.OrdinalIgnoreCase))
                continue;
            var key = stem["flist_".Length..];

            var domain = ResolveDomain(key, domainMap, flToObj, dbPath);
            if (string.IsNullOrWhiteSpace(domain))
            {
                skippedDomain++;
                continue;
            }

            domainsUsed.Add(domain);
            var inventory = FileListSqliteParser.ParseInventory(dbPath);
            if (!inventory.Ok)
            {
                log?.Report($"  Manifest skip {Path.GetFileName(dbPath)}: {inventory.Error}");
                continue;
            }

            foreach (var row in inventory.Rows)
            {
                if (string.IsNullOrWhiteSpace(row.RelativePath))
                {
                    skippedPath++;
                    continue;
                }

                var fileId = BackupAsset.ComputeFileId(domain, row.RelativePath);
                if (!seenFileIds.Add(fileId))
                    continue;

                var flags = IsDirectoryMode(row.Mode) ? 2 : 1;
                var plist = BuildFilePlist(domain, row);
                batch.Add((fileId, domain, row.RelativePath, flags, plist));
                upserted++;

                if (batch.Count >= 2000)
                {
                    await writer.UpsertManifestEntriesBatchAsync(batch, ct).ConfigureAwait(false);
                    batch.Clear();
                }
            }
        }

        if (batch.Count > 0)
            await writer.UpsertManifestEntriesBatchAsync(batch, ct).ConfigureAwait(false);

        var manifestPath = Path.Combine(cleanDir, "Manifest.db");
        var manifestBytes = File.Exists(manifestPath) ? new FileInfo(manifestPath).Length : 0;

        var meta = JsonSerializer.Serialize(new
        {
            rebuiltFrom = "flist_*.db",
            cleanBackupDirectory = IkeBackupOutputPaths.CleanBackupFolderName,
            fileListDatabases = dbFiles.Count,
            domainsResolved = domainsUsed.Count,
            rowsUpserted = upserted,
            skippedNoDomain = skippedDomain,
            skippedNoPath = skippedPath,
            manifestBytes,
            note = "Manifest.db in Backup/: fileID=SHA1(domain+\"-\"+relativePath); " +
                   "flags 1=file 2=dir; blob=plist XML (9 chiavi). flist_*.db in work/."
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(
            Path.Combine(workDirectory, "manifest_from_flist_meta.json"), meta, ct);

        log?.Report(
            $"Manifest da fileList: db={dbFiles.Count}, domains={domainsUsed.Count}, " +
            $"Files={upserted:N0}, skipDomain={skippedDomain}, skipPath={skippedPath} " +
            $"→ {IkeBackupOutputPaths.CleanBackupFolderName}/Manifest.db ({manifestBytes:N0} B)");

        return new RebuildResult(
            dbFiles.Count,
            domainsUsed.Count,
            upserted,
            skippedDomain,
            skippedPath,
            manifestBytes);
    }

    public static async Task WriteDomainMapAsync(
        string outputDirectory,
        IEnumerable<DomainFileListParser.DomainRecord> domains,
        CancellationToken ct = default)
    {
        var rows = domains
            .Where(static d => d.FileList is not null)
            .Select(static d => new
            {
                domain = d.DomainName,
                recordName = d.RecordName,
                signatureHex = d.FileList!.SignatureHex,
                sizeBytes = d.FileList.SizeBytes,
                encoding = d.FileListEncoding,
                files = d.CumulativeFileCount,
                directories = d.CumulativeDirectoryCount,
                assets = d.CumulativeAssetCount
            })
            .ToList();

        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "domain_filelists.json"),
            JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true }),
            ct);
    }

    private static async Task<Dictionary<string, string>> LoadDomainMapAsync(
        string snapshotDirectory,
        IReadOnlyDictionary<string, string>? seed,
        CancellationToken ct)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        if (seed is not null)
        {
            foreach (var kv in seed)
            {
                if (!string.IsNullOrWhiteSpace(kv.Key) && !string.IsNullOrWhiteSpace(kv.Value))
                    map[NormalizeSig(kv.Key)] = kv.Value;
            }
        }

        var mapPath = Path.Combine(snapshotDirectory, "domain_filelists.json");
        if (File.Exists(mapPath))
        {
            try
            {
                await using var fs = File.OpenRead(mapPath);
                using var doc = await JsonDocument.ParseAsync(fs, cancellationToken: ct);
                foreach (var el in doc.RootElement.EnumerateArray())
                {
                    var sig = el.TryGetProperty("signatureHex", out var s) ? s.GetString() : null;
                    var domain = el.TryGetProperty("domain", out var d) ? d.GetString() : null;
                    if (!string.IsNullOrWhiteSpace(sig) && !string.IsNullOrWhiteSpace(domain))
                        map[NormalizeSig(sig)] = domain;
                }
            }
            catch
            {
                // ignore corrupt map
            }
        }

        foreach (var metaPath in Directory.EnumerateFiles(snapshotDirectory, "flist_*_meta.json"))
        {
            try
            {
                await using var fs = File.OpenRead(metaPath);
                using var doc = await JsonDocument.ParseAsync(fs, cancellationToken: ct);
                var root = doc.RootElement;
                var domain = root.TryGetProperty("domain", out var d) ? d.GetString() : null;
                var record = root.TryGetProperty("record", out var r) ? r.GetString() : null;
                if (string.IsNullOrWhiteSpace(domain))
                    continue;
                var sig = record is not null && record.StartsWith("FL:", StringComparison.Ordinal)
                    ? record["FL:".Length..]
                    : Path.GetFileNameWithoutExtension(metaPath);
                if (sig.StartsWith("flist_", StringComparison.OrdinalIgnoreCase))
                    sig = sig["flist_".Length..];
                if (sig.EndsWith("_meta", StringComparison.OrdinalIgnoreCase))
                    sig = sig[..^"_meta".Length];
                map[NormalizeSig(sig)] = domain;
            }
            catch
            {
                // ignore
            }
        }

        // Offline: parse EN batches se la mappa è ancora vuota.
        if (map.Count == 0)
        {
            foreach (var batch in Directory.EnumerateFiles(snapshotDirectory, "en_batch_*records.bin"))
            {
                try
                {
                    var domains = DomainFileListParser.ParseDomains(File.ReadAllBytes(batch));
                    foreach (var d in domains)
                    {
                        if (d.FileList is null || string.IsNullOrWhiteSpace(d.DomainName))
                            continue;
                        map[NormalizeSig(d.FileList.SignatureHex)] = d.DomainName;
                    }
                }
                catch
                {
                    // ignore
                }
            }
        }

        return map;
    }

    /// <summary>AUTH_FL_&lt;sig&gt;_authorizeGet.bin → objectId presente in OBJ_*.bin.</summary>
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
                if (text.Contains(oid, StringComparison.Ordinal))
                {
                    map[NormalizeSig(sig)] = oid;
                    break;
                }
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
        var key = NormalizeSig(flistKey);
        if (domainBySig.TryGetValue(key, out var domain))
            return domain;

        // flist nominato con objectId (offline LZFSE): objectId → FL sig → domain
        foreach (var (sig, oid) in flToObj)
        {
            if (!string.Equals(oid, flistKey, StringComparison.Ordinal)
                && !string.Equals(NormalizeSig(oid), key, StringComparison.OrdinalIgnoreCase))
                continue;
            if (domainBySig.TryGetValue(sig, out domain))
                return domain;
        }

        // meta sibling
        var metaPath = Path.Combine(
            Path.GetDirectoryName(dbPath)!,
            Path.GetFileNameWithoutExtension(dbPath) + "_meta.json");
        if (File.Exists(metaPath))
        {
            try
            {
                using var doc = JsonDocument.Parse(File.ReadAllText(metaPath));
                if (doc.RootElement.TryGetProperty("domain", out var d))
                {
                    var v = d.GetString();
                    if (!string.IsNullOrWhiteSpace(v))
                        return v;
                }
            }
            catch
            {
                // ignore
            }
        }

        return null;
    }

    private static string NormalizeSig(string sig)
    {
        sig = sig.Trim();
        if (sig.StartsWith("FL:", StringComparison.OrdinalIgnoreCase))
            sig = sig[3..];
        return sig.ToLowerInvariant();
    }

    private static bool IsDirectoryMode(long mode) => (mode & 0xF000) == 0x4000;

    /// <summary> sole 9 chiavi nel blob Files.file (niente EncryptionKey/Digest/…).</summary>
    public static byte[] BuildFilePlist(string domain, FileListSqliteParser.InventoryRow row) =>
        ManifestFilePlist.BuildFromInventory(domain, row);
}
