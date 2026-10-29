using System.IO;
using System.Text;
using Microsoft.Data.Sqlite;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Verifica che ogni riga Manifest <c>flags=1</c> abbia lo shard su disco
/// (<c>xx/fileID</c>), e scrive il checkpoint dei missing.
/// </summary>
public readonly record struct BackupCompletenessReport(
    int ExpectedFileRows,
    int PresentOnDisk,
    int MissingOnDisk,
    IReadOnlyList<(string FileId, string Domain, string RelativePath)> Missing);

public static class BackupCompleteness
{
    public const string MissingFilesFileName = "MissingFiles.txt";

    /// <summary>
    /// Completo solo se Manifest ha almeno una riga file e zero missing su disco.
    /// </summary>
    public static bool IsFinished(in BackupCompletenessReport report) =>
        report.ExpectedFileRows > 0 && report.MissingOnDisk == 0;

    public static BackupCompletenessReport Evaluate(string cleanBackupDirectory)
    {
        var manifestPath = Path.Combine(cleanBackupDirectory, "Manifest.db");
        if (!File.Exists(manifestPath))
            return new BackupCompletenessReport(0, 0, 0, []);

        var missing = new List<(string FileId, string Domain, string RelativePath)>();
        var present = 0;
        var expected = 0;

        try
        {
            using var con = new SqliteConnection(
                $"Data Source={manifestPath};Mode=ReadOnly");
            con.Open();
            using var cmd = con.CreateCommand();
            cmd.CommandText =
                "SELECT fileID, domain, relativePath FROM Files WHERE flags = 1;";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                expected++;
                var fid = r.IsDBNull(0) ? "" : r.GetString(0);
                var domain = r.IsDBNull(1) ? "" : r.GetString(1);
                var rel = r.IsDBNull(2) ? "" : r.GetString(2);
                if (fid.Length < 2)
                {
                    missing.Add((fid, domain, rel));
                    continue;
                }

                var path = IkeBackupOutputPaths.ToShardedFilePath(cleanBackupDirectory, fid);
                // 0-byte OK: empty/no-MMCS materializzati (lock/sentinel/symlink).
                if (File.Exists(path))
                    present++;
                else
                    missing.Add((fid, domain, rel));
            }
        }
        catch
        {
            return new BackupCompletenessReport(0, 0, 0, []);
        }

        return new BackupCompletenessReport(expected, present, missing.Count, missing);
    }

    /// <summary>
    /// Scrive <c>MissingFiles.txt</c> nella radice snapshot (parent di Backup/).
    /// Se completo, rimuove il file precedente.
    /// </summary>
    public static async Task WriteMissingCheckpointAsync(
        string snapshotWorkDirectory,
        BackupCompletenessReport report,
        CancellationToken ct = default)
    {
        var path = Path.Combine(
            IkeBackupOutputPaths.ResolveSnapshotRoot(snapshotWorkDirectory),
            MissingFilesFileName);

        if (report.MissingOnDisk == 0)
        {
            try
            {
                if (File.Exists(path))
                    File.Delete(path);
            }
            catch
            {
                // ignore
            }

            return;
        }

        var sb = new StringBuilder(Math.Min(report.Missing.Count, 500_000) * 64);
        sb.Append("# MissingFiles — Manifest flags=1 assenti su disco").Append('\n');
        sb.Append("# expected=").Append(report.ExpectedFileRows)
            .Append(" present=").Append(report.PresentOnDisk)
            .Append(" missing=").Append(report.MissingOnDisk)
            .Append('\n');
        sb.Append("# domain\trelativePath\tfileID").Append('\n');
        foreach (var (fileId, domain, relativePath) in report.Missing)
        {
            sb.Append(domain).Append('\t')
                .Append(relativePath).Append('\t')
                .Append(fileId).Append('\n');
        }

        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        await File.WriteAllTextAsync(path, sb.ToString(), ct).ConfigureAwait(false);
    }
}
