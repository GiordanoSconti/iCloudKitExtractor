using System.IO;
using System.Text.Json;
using System.Threading;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services;
using Microsoft.Data.Sqlite;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Scrive file nello layout (<c>Backup/xx/fileID</c>) e aggiorna Manifest.db stile iTunes.
/// </summary>
public sealed class BackupFilesystemWriter : IAsyncDisposable
{
    private readonly string _snapshotDirectory;
    private readonly string _dbPath;
    private readonly SqliteConnection _conn;
    private readonly SemaphoreSlim _dbWrite = new(1, 1);
    private bool _opened;

    private BackupFilesystemWriter(string snapshotDirectory, string dbPath, SqliteConnection conn)
    {
        _snapshotDirectory = snapshotDirectory;
        _dbPath = dbPath;
        _conn = conn;
    }

    public static async Task<BackupFilesystemWriter> OpenAsync(
        string snapshotDirectory,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(snapshotDirectory);
        var dbPath = Path.Combine(snapshotDirectory, "Manifest.db");
        var conn = new SqliteConnection($"Data Source={dbPath};Default Timeout=30");
        await conn.OpenAsync(ct);

        await using (var cmd = conn.CreateCommand())
        {
            cmd.CommandText =
                """
                PRAGMA journal_mode=WAL;
                PRAGMA busy_timeout=30000;
                CREATE TABLE IF NOT EXISTS Files (
                  fileID TEXT PRIMARY KEY,
                  domain TEXT,
                  relativePath TEXT,
                  flags INTEGER,
                  file BLOB
                );
                CREATE TABLE IF NOT EXISTS Properties (
                  key TEXT PRIMARY KEY,
                  value BLOB
                );
                """;
            await cmd.ExecuteNonQueryAsync(ct);
        }

        return new BackupFilesystemWriter(snapshotDirectory, dbPath, conn) { _opened = true };
    }

    public async Task<SqliteTransaction> BeginTransactionAsync(CancellationToken ct = default) =>
        (SqliteTransaction)await _conn.BeginTransactionAsync(ct);

    /// <summary>
    /// lascia <c>Properties</c> vuota: solo assicura che lo schema esista.
    /// </summary>
    public Task WriteSkeletonPropertiesAsync(
        BackupDevice device,
        BackupSnapshot snapshot,
        string catalogSource,
        CancellationToken ct = default) =>
        Task.CompletedTask;

    /// <summary>
    /// Scrive il corpo file in <c>xx/fileID</c> e upsert riga Manifest con plist metadati.
    /// Richiede <see cref="BackupAsset.HasFilesystemIdentity"/>.
    /// </summary>
    public async Task<string> WriteFileAsync(
        BackupAsset asset,
        byte[] content,
        CancellationToken ct = default)
    {
        if (!asset.HasFilesystemIdentity)
            throw new InvalidOperationException(
                "WriteFile richiede Domain+RelativePath (metadata decrypt).");

        var fileId = asset.EnsureFileId()
                     ?? throw new InvalidOperationException("fileID non calcolabile");

        var path = IkeBackupOutputPaths.ToShardedFilePath(_snapshotDirectory, fileId);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllBytesAsync(path, content, ct);

        var plist = ManifestFilePlist.BuildFromAsset(asset, content.Length);
        await UpsertFileRowAsync(fileId, asset.Domain!, asset.RelativePath!, plist, ct);
        return path;
    }

    /// <summary>Come <see cref="WriteFileAsync"/> ma da path (asset multi-GB senza byte[]).</summary>
    public async Task<string> WriteFileFromPathAsync(
        BackupAsset asset,
        string sourcePath,
        CancellationToken ct = default)
    {
        if (!asset.HasFilesystemIdentity)
            throw new InvalidOperationException(
                "WriteFile richiede Domain+RelativePath (metadata decrypt).");

        var fileId = asset.EnsureFileId()
                     ?? throw new InvalidOperationException("fileID non calcolabile");

        var path = IkeBackupOutputPaths.ToShardedFilePath(_snapshotDirectory, fileId);
        var srcFull = Path.GetFullPath(sourcePath);
        var dstFull = Path.GetFullPath(path);
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        if (!string.Equals(srcFull, dstFull, StringComparison.OrdinalIgnoreCase))
        {
            await Task.Run(() => File.Copy(srcFull, dstFull, overwrite: true), ct)
                .ConfigureAwait(false);
        }

        var size = new FileInfo(dstFull).Length;
        var plist = ManifestFilePlist.BuildFromAsset(asset, size);
        await UpsertFileRowAsync(fileId, asset.Domain!, asset.RelativePath!, plist, ct);
        return path;
    }

    /// <summary>
    /// Copia un body già scaricato su un altro fileID iTunes (stesso assetSignature, path diverso).
    /// </summary>
    public async Task<string> CopyExistingAsync(
        BackupAsset asset,
        string sourcePath,
        CancellationToken ct = default)
    {
        if (!asset.HasFilesystemIdentity)
            throw new InvalidOperationException(
                "CopyExisting richiede Domain+RelativePath (metadata decrypt).");

        var fileId = asset.EnsureFileId()
                     ?? throw new InvalidOperationException("fileID non calcolabile");
        var path = IkeBackupOutputPaths.ToShardedFilePath(_snapshotDirectory, fileId);
        var srcFull = Path.GetFullPath(sourcePath);
        var dstFull = Path.GetFullPath(path);
        if (string.Equals(srcFull, dstFull, StringComparison.OrdinalIgnoreCase))
            return path;

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await Task.Run(() => File.Copy(srcFull, dstFull, overwrite: true), ct).ConfigureAwait(false);
        var size = new FileInfo(dstFull).Length;
        var plist = ManifestFilePlist.BuildFromAsset(asset, size);
        await UpsertFileRowAsync(fileId, asset.Domain!, asset.RelativePath!, plist, ct);
        return path;
    }

    /// <summary>Staging quando i path non sono ancora noti (equivalente <c>.chunks</c>).</summary>
    public static async Task<string> WriteChunkStagingAsync(
        string rootDirectory,
        BackupAsset asset,
        byte[] content,
        CancellationToken ct = default)
    {
        var chunks = IkeBackupOutputPaths.ChunksStagingDirectory(rootDirectory);
        Directory.CreateDirectory(chunks);

        var tag = MmcsAuthBuilder.TryExtractFileChecksumHex(asset.MmcsAuth ?? "")
                  ?? BackupAsset.ComputeFileId("staging", asset.RecordName);
        var safe = Sanitize(asset.RecordName);
        if (safe.Length > 48)
            safe = safe[..48];
        var path = Path.Combine(chunks, $"{tag}_{safe}.bin");
        await File.WriteAllBytesAsync(path, content, ct);
        return path;
    }

    /// <summary>
    /// Upsert solo metadati Manifest (senza scrivere bytes in <c>xx/fileID</c>).
    /// Usato dalla ricostruzione da fileList SQLite.
    /// </summary>
    public async Task UpsertManifestEntryAsync(
        string fileId,
        string domain,
        string relativePath,
        int flags,
        byte[] filePlistXml,
        CancellationToken ct = default)
    {
        // Un solo writer (WAL): lock + connessione condivisa così BeginTransactionAsync sul rebuild funziona.
        await _dbWrite.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            // #region agent log
            int? existingPlistLen = null;
            try
            {
                await using var sel = _conn.CreateCommand();
                sel.CommandText = "SELECT length(file) FROM Files WHERE fileID = $id LIMIT 1;";
                sel.Parameters.AddWithValue("$id", fileId);
                var o = await sel.ExecuteScalarAsync(ct).ConfigureAwait(false);
                if (o is not null and not DBNull)
                    existingPlistLen = Convert.ToInt32(o);
            }
            catch
            {
                // ignore probe
            }

            var wouldOverwrite = existingPlistLen is not null;
            var thinnerOverwrite = wouldOverwrite
                                   && existingPlistLen is int el
                                   && filePlistXml.Length + 32 < el;
            AgentSqliteDebugLog(
                "BackupFilesystemWriter.UpsertManifestEntryAsync",
                wouldOverwrite ? (thinnerOverwrite ? "overwrite_thinner" : "overwrite") : "insert",
                new
                {
                    fileId,
                    domain,
                    relativePath,
                    flags,
                    newPlistLen = filePlistXml.Length,
                    existingPlistLen,
                    thinnerOverwrite,
                    insertOnlyWouldSkip = wouldOverwrite,
                },
                thinnerOverwrite ? "H-MAN2" : "H-MAN1",
                "vd-manifest-v1");
            // #endregion

            await using var cmd = _conn.CreateCommand();
            cmd.CommandText =
                """
                INSERT INTO Files (fileID, domain, relativePath, flags, file)
                VALUES ($id, $domain, $path, $flags, $file)
                ON CONFLICT(fileID) DO UPDATE SET
                  domain = excluded.domain,
                  relativePath = excluded.relativePath,
                  flags = excluded.flags,
                  file = excluded.file;
                """;
            cmd.Parameters.AddWithValue("$id", fileId);
            cmd.Parameters.AddWithValue("$domain", domain);
            cmd.Parameters.AddWithValue("$path", relativePath);
            cmd.Parameters.AddWithValue("$flags", flags);
            cmd.Parameters.AddWithValue("$file", filePlistXml);
            try
            {
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                // #region agent log
                AgentSqliteDebugLog(
                    "BackupFilesystemWriter.UpsertManifestEntryAsync",
                    "upsert_fail",
                    new
                    {
                        fileId,
                        connState = _conn.State.ToString(),
                        error = ex.Message,
                    },
                    "H-SQLITE",
                    "vd-manifest-v1");
                // #endregion
                throw;
            }
        }
        finally
        {
            _dbWrite.Release();
        }
    }

    /// <summary>
    /// Upsert batch in una sola transazione (rebuild Manifest da flist).
    /// </summary>
    public async Task UpsertManifestEntriesBatchAsync(
        IReadOnlyList<(string FileId, string Domain, string RelativePath, int Flags, byte[] Plist)> rows,
        CancellationToken ct = default)
    {
        if (rows.Count == 0)
            return;

        await _dbWrite.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await using var tx = (SqliteTransaction)await _conn.BeginTransactionAsync(ct)
                .ConfigureAwait(false);
            await using var cmd = _conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText =
                """
                INSERT INTO Files (fileID, domain, relativePath, flags, file)
                VALUES ($id, $domain, $path, $flags, $file)
                ON CONFLICT(fileID) DO UPDATE SET
                  domain = excluded.domain,
                  relativePath = excluded.relativePath,
                  flags = excluded.flags,
                  file = excluded.file;
                """;
            var pId = cmd.Parameters.Add("$id", SqliteType.Text);
            var pDomain = cmd.Parameters.Add("$domain", SqliteType.Text);
            var pPath = cmd.Parameters.Add("$path", SqliteType.Text);
            var pFlags = cmd.Parameters.Add("$flags", SqliteType.Integer);
            var pFile = cmd.Parameters.Add("$file", SqliteType.Blob);

            foreach (var row in rows)
            {
                ct.ThrowIfCancellationRequested();
                pId.Value = row.FileId;
                pDomain.Value = row.Domain;
                pPath.Value = row.RelativePath;
                pFlags.Value = row.Flags;
                pFile.Value = row.Plist;
                await cmd.ExecuteNonQueryAsync(ct).ConfigureAwait(false);
            }

            await tx.CommitAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _dbWrite.Release();
        }
    }

    private async Task UpsertFileRowAsync(
        string fileId,
        string domain,
        string relativePath,
        byte[] filePlistXml,
        CancellationToken ct)
    {
        await UpsertManifestEntryAsync(fileId, domain, relativePath, 1, filePlistXml, ct);
    }

    /// <summary>Plist XML (9 chiavi) — delega a <see cref="ManifestFilePlist"/>.</summary>
    public static byte[] BuildMetadataPlistXml(BackupAsset asset, int sizeBytes) =>
        ManifestFilePlist.BuildFromAsset(asset, sizeBytes);

    private static string Sanitize(string name)
    {
        var chars = name.Select(c =>
            char.IsLetterOrDigit(c) || c is '-' or '_' or '.' ? c : '_').ToArray();
        return new string(chars);
    }

    public async ValueTask DisposeAsync()
    {
        if (_opened)
            await _conn.DisposeAsync();
        _dbWrite.Dispose();
    }

    // #region agent log
    private static void AgentSqliteDebugLog(
        string location,
        string message,
        object data,
        string hypothesisId,
        string runId)
    {
        if (!IkeLogOptions.ShouldWriteAgentDiag)
            return;
        try
        {
            var line = JsonSerializer.Serialize(new
            {
                sessionId = "7dabb5",
                runId,
                hypothesisId,
                location,
                message,
                data,
                timestamp = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            IkeLogOptions.AppendAgentNdjson(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                line);
        }
        catch
        {
            // ignore debug log failures
        }
    }
    // #endregion
}
