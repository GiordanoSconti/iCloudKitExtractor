using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace iCloudKitExtractor.Services.Forensics;

/// <summary>
/// Forensic integrity for downloaded results: <c>HASHES.sha256</c> (GNU style) + <c>integrity.json</c>.
/// </summary>
public static class OutputHashManifest
{
    public const string Sha256FileName = "HASHES.sha256";
    public const string JsonFileName = "integrity.json";

    private static readonly HashSet<string> DefaultExcludedDirNames = new(StringComparer.OrdinalIgnoreCase)
    {
        ".chunks",
        "tmp",
        ".tmp",
        "obj",
        "bin",
    };

    public static async Task<HashManifestResult> WriteForDirectoryAsync(
        string rootDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        IEnumerable<string>? extraExcludeDirNames = null)
    {
        if (string.IsNullOrWhiteSpace(rootDirectory) || !Directory.Exists(rootDirectory))
            return new HashManifestResult(0, 0, null, null);

        var excluded = new HashSet<string>(DefaultExcludedDirNames, StringComparer.OrdinalIgnoreCase);
        if (extraExcludeDirNames is not null)
        {
            foreach (var n in extraExcludeDirNames)
                if (!string.IsNullOrWhiteSpace(n))
                    excluded.Add(n.Trim());
        }

        // Rilascia handle residui del pool Microsoft.Data.Sqlite (Notes.db / Photos.db /
        // Manifest.db) prima di aprire i file in sola lettura.
        try { Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools(); }
        catch { /* ignore */ }

        var files = EnumerateFiles(rootDirectory, excluded)
            .OrderBy(p => Path.GetRelativePath(rootDirectory, p).Replace('\\', '/'), StringComparer.Ordinal)
            .ToList();

        var entries = new List<HashFileEntry>(files.Count);
        var shaLines = new StringBuilder(files.Count * 96);
        long totalBytes = 0;

        foreach (var path in files)
        {
            ct.ThrowIfCancellationRequested();
            var rel = Path.GetRelativePath(rootDirectory, path).Replace('\\', '/');
            var leaf = Path.GetFileName(path);
            // Skip manifest files at any depth (viewer nested HASHES/integrity).
            if (string.Equals(leaf, Sha256FileName, StringComparison.OrdinalIgnoreCase)
                || string.Equals(leaf, JsonFileName, StringComparison.OrdinalIgnoreCase))
                continue;

            string hex;
            long size;
            try
            {
                // ReadWrite|Delete: Manifest.db (+ -wal/-shm) può restare aperto da SQLite
                // in WAL durante il download; FileShare.Read esclusivo faceva "hash skip".
                await using var stream = File.Open(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);
                size = stream.Length;
                var hash = await SHA256.HashDataAsync(stream, ct).ConfigureAwait(false);
                hex = Convert.ToHexString(hash).ToLowerInvariant();
            }
            catch (Exception ex)
            {
                log?.Report($"  hash skip {rel}: {ex.Message}");
                continue;
            }

            totalBytes += size;
            entries.Add(new HashFileEntry(rel, size, hex));
            // GNU coreutils: "<hash><two spaces><path>"
            shaLines.Append(hex);
            shaLines.Append("  ");
            shaLines.Append(rel);
            shaLines.Append('\n');
        }

        var shaPath = Path.Combine(rootDirectory, Sha256FileName);
        var jsonPath = Path.Combine(rootDirectory, JsonFileName);
        await File.WriteAllTextAsync(shaPath, shaLines.ToString(), Encoding.UTF8, ct).ConfigureAwait(false);

        var doc = new HashManifestDocument
        {
            Algorithm = "SHA-256",
            GeneratedAt = DateTimeOffset.UtcNow,
            Root = Path.GetFullPath(rootDirectory),
            FileCount = entries.Count,
            TotalBytes = totalBytes,
            Files = entries,
        };
        await File.WriteAllTextAsync(
            jsonPath,
            JsonSerializer.Serialize(doc, new JsonSerializerOptions
            {
                WriteIndented = true,
                DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
            }),
            Encoding.UTF8,
            ct).ConfigureAwait(false);

        log?.Report(
            $"  integrity: {entries.Count:N0} file, {totalBytes:N0} B → {Sha256FileName} + {JsonFileName}");
        return new HashManifestResult(entries.Count, totalBytes, shaPath, jsonPath);
    }

    public static string? TryComputeSha256Hex(string path)
    {
        try
        {
            if (!File.Exists(path))
                return null;
            using var stream = File.Open(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);
            return Convert.ToHexString(SHA256.HashData(stream)).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static IEnumerable<string> EnumerateFiles(string root, HashSet<string> excludedDirNames)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> subDirs;
            try { subDirs = Directory.EnumerateDirectories(dir); }
            catch { continue; }

            foreach (var sub in subDirs)
            {
                var name = Path.GetFileName(sub);
                if (excludedDirNames.Contains(name))
                    continue;
                stack.Push(sub);
            }

            IEnumerable<string> filePaths;
            try { filePaths = Directory.EnumerateFiles(dir); }
            catch { continue; }

            foreach (var f in filePaths)
                yield return f;
        }
    }
}

public sealed record HashManifestResult(
    int FileCount,
    long TotalBytes,
    string? Sha256Path,
    string? JsonPath);

public sealed class HashManifestDocument
{
    [JsonPropertyName("algorithm")]
    public string Algorithm { get; set; } = "SHA-256";

    [JsonPropertyName("generatedAt")]
    public DateTimeOffset GeneratedAt { get; set; }

    [JsonPropertyName("root")]
    public string? Root { get; set; }

    [JsonPropertyName("fileCount")]
    public int FileCount { get; set; }

    [JsonPropertyName("totalBytes")]
    public long TotalBytes { get; set; }

    [JsonPropertyName("files")]
    public List<HashFileEntry> Files { get; set; } = new();
}

public sealed record HashFileEntry(
    [property: JsonPropertyName("path")] string Path,
    [property: JsonPropertyName("bytes")] long Bytes,
    [property: JsonPropertyName("sha256")] string Sha256);
