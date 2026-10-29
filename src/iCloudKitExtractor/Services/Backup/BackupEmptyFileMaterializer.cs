using System.IO;
using System.Text.RegularExpressions;
using Microsoft.Data.Sqlite;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Crea shard a 0 byte per le righe Manifest <c>flags=1</c> con <c>size=0</c>
/// (EMPTY_FILE / lock / sentinel / symlink catalogati senza payload MMCS).
/// </summary>
public static class BackupEmptyFileMaterializer
{
    private static readonly Regex SizeRegex = new(
        @"<key>size</key>\s*<integer>(\d+)</integer>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public readonly record struct Result(int Examined, int Created, int AlreadyPresent, int SkippedNonEmpty);

    public static Result MaterializeFromManifest(
        string cleanBackupDirectory,
        IProgress<string>? log = null)
    {
        var manifestPath = Path.Combine(cleanBackupDirectory, "Manifest.db");
        if (!File.Exists(manifestPath))
            return default;

        var created = 0;
        var already = 0;
        var skipped = 0;
        var examined = 0;

        try
        {
            using var con = new SqliteConnection(
                $"Data Source={manifestPath};Mode=ReadOnly");
            con.Open();
            using var cmd = con.CreateCommand();
            cmd.CommandText =
                "SELECT fileID, file FROM Files WHERE flags = 1;";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var fid = r.IsDBNull(0) ? "" : r.GetString(0);
                if (fid.Length < 2)
                    continue;

                var blob = r.IsDBNull(1) ? null : (byte[]?)r.GetValue(1);
                if (blob is null || !TryReadSize(blob, out var size) || size != 0)
                {
                    if (blob is not null && TryReadSize(blob, out var sz) && sz > 0)
                        skipped++;
                    continue;
                }

                examined++;
                var path = IkeBackupOutputPaths.ToShardedFilePath(cleanBackupDirectory, fid);
                if (File.Exists(path))
                {
                    already++;
                    continue;
                }

                try
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(path)!);
                    using (File.Create(path))
                    {
                        // 0 bytes
                    }

                    created++;
                }
                catch
                {
                    // non bloccare il sidecar se un touch fallisce
                }
            }
        }
        catch (Exception ex)
        {
            log?.Report($"  empty materialize skip: {ex.Message}");
            return new Result(examined, created, already, skipped);
        }

        if (created > 0 || examined > 0)
            log?.Report(
                $"Empty/no-MMCS: materializzati {created:N0} shard a 0 B " +
                $"(catalogo size=0: {examined:N0}, già presenti={already:N0})");

        return new Result(examined, created, already, skipped);
    }

    private static bool TryReadSize(byte[] plistBlob, out long size)
    {
        size = 0;
        // ManifestFilePlist usa XML con chiave "size" minuscola.
        var m = SizeRegex.Match(System.Text.Encoding.UTF8.GetString(plistBlob));
        if (!m.Success)
            return false;
        return long.TryParse(m.Groups[1].Value, out size);
    }
}
