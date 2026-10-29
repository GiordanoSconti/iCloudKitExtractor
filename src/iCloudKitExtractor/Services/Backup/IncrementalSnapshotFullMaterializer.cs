using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Protocol;
using Microsoft.Data.Sqlite;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Ricompone una vista <b>full</b> dello snapshot corrente copiando da Backup/
/// degli snapshot <b>più vecchi</b> dello stesso device i fileID assenti nel FL
/// incrementale (stesso modello EPB: IsFullBackup).
/// </summary>
public static class IncrementalSnapshotFullMaterializer
{
    private static readonly Regex SizeRegex = new(
        @"<key>size</key>\s*<integer>(\d+)</integer>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public readonly record struct Result(
        int PriorsScanned,
        int FilledHoles,
        int AddedFromPriors,
        int CopiedBytesApprox,
        int SkippedNoSource);

    public static async Task<Result> MaterializeAsync(
        string cleanBackupDirectory,
        string? deviceDirectory = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(cleanBackupDirectory);
        var work = IkeBackupOutputPaths.ResolveSnapshotWorkDirectoryFromCleanBackup(
            cleanBackupDirectory);
        deviceDirectory ??= Path.GetDirectoryName(
            IkeBackupOutputPaths.ResolveSnapshotRoot(work));
        if (string.IsNullOrWhiteSpace(deviceDirectory) || !Directory.Exists(deviceDirectory))
        {
            log?.Report("  Full-merge: device dir assente — skip");
            return default;
        }

        var currentDate = TryReadBackupDate(cleanBackupDirectory);
        var priors = EnumerateOlderSiblings(deviceDirectory, work, currentDate);
        if (priors.Count == 0)
        {
            log?.Report("  Full-merge: nessun snapshot più vecchio sul device — skip");
            return default;
        }

        log?.Report(
            $"  Full-merge: {priors.Count} snapshot precedenti " +
            $"(più recente→più vecchio) → {cleanBackupDirectory}");

        var fill = FillMissingShardsFromPriors(cleanBackupDirectory, priors, ct);
        var add = await AddMissingManifestRowsFromPriorsAsync(
            cleanBackupDirectory, priors, log, ct).ConfigureAwait(false);

        var filled = fill.Filled;
        var added = add.Added;
        var skipped = fill.Skipped + add.Skipped;
        var copiedBytes = fill.CopiedBytes + add.CopiedBytes;

        if (filled > 0 || added > 0)
            log?.Report(
                $"  Full-merge: buchi riempiti={filled:N0}, " +
                $"file aggiunti da prior={added:N0}, " +
                $"~{copiedBytes:N0} B copiati, skip={skipped:N0}");
        else
            log?.Report("  Full-merge: niente da aggiungere (già coperto o prior senza shard)");

        return new Result(priors.Count, filled, added, (int)Math.Min(copiedBytes, int.MaxValue), skipped);
    }

    /// <summary>
    /// Sibling con data backup ≤ corrente, escluso current; ordine dal più recente al più vecchio.
    /// </summary>
    public static IReadOnlyList<string> EnumerateOlderSiblings(
        string deviceDirectory,
        string currentWorkDirectory,
        DateTimeOffset? currentBackupDate)
    {
        var currentFull = Path.GetFullPath(
            IkeBackupOutputPaths.ResolveSnapshotRoot(currentWorkDirectory));
        var list = new List<(string Path, DateTimeOffset Date)>();
        foreach (var dir in Directory.EnumerateDirectories(deviceDirectory))
        {
            var name = Path.GetFileName(dir);
            if (name.Length == 0 || name[0] != '[' || name[0] == '.')
                continue;
            try
            {
                var full = Path.GetFullPath(dir);
                if (string.Equals(full, currentFull, StringComparison.OrdinalIgnoreCase))
                    continue;
                var clean = IkeBackupOutputPaths.ResolveCleanBackupDirectory(dir);
                if (!Directory.Exists(clean) || !File.Exists(Path.Combine(clean, "Manifest.db")))
                    continue;
                var date = TryReadBackupDate(clean)
                           ?? new DateTimeOffset(Directory.GetLastWriteTimeUtc(dir), TimeSpan.Zero);
                if (currentBackupDate is { } cur && date > cur)
                    continue; // più nuovo del corrente: non fa parte della catena fino a qui
                list.Add((dir, date));
            }
            catch
            {
                // skip
            }
        }

        // Più recente prima: la versione più vicina allo snapshot corrente vince.
        list.Sort(static (a, b) => b.Date.CompareTo(a.Date));
        return list.ConvertAll(static x => x.Path);
    }

    private readonly record struct FillResult(int Filled, int Skipped, long CopiedBytes);
    private readonly record struct AddResult(int Added, int Skipped, long CopiedBytes);

    private static FillResult FillMissingShardsFromPriors(
        string cleanDir,
        IReadOnlyList<string> priorWorks,
        CancellationToken ct)
    {
        var manifestPath = Path.Combine(cleanDir, "Manifest.db");
        if (!File.Exists(manifestPath))
            return default;

        var filled = 0;
        var skipped = 0;
        long copiedBytes = 0;
        using var con = new SqliteConnection($"Data Source={manifestPath};Mode=ReadOnly");
        con.Open();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT fileID, flags, file FROM Files WHERE flags = 1;";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            ct.ThrowIfCancellationRequested();
            var fid = r.IsDBNull(0) ? "" : r.GetString(0);
            if (fid.Length < 2)
                continue;
            var dest = IkeBackupOutputPaths.ToShardedFilePath(cleanDir, fid);
            if (File.Exists(dest))
                continue;

            var blob = r.IsDBNull(2) ? null : (byte[]?)r.GetValue(2);
            long? expect = null;
            if (blob is not null && TryReadSize(blob, out var sz))
                expect = sz;

            var src = FindShardInPriors(priorWorks, fid, expect);
            if (src is null)
            {
                skipped++;
                continue;
            }

            if (TryCopyShard(src, dest, ref copiedBytes))
                filled++;
            else
                skipped++;
        }

        return new FillResult(filled, skipped, copiedBytes);
    }

    private static async Task<AddResult> AddMissingManifestRowsFromPriorsAsync(
        string cleanDir,
        IReadOnlyList<string> priorWorks,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var manifestPath = Path.Combine(cleanDir, "Manifest.db");
        Directory.CreateDirectory(cleanDir);

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (File.Exists(manifestPath))
        {
            await using var conSeen = new SqliteConnection(
                $"Data Source={manifestPath};Mode=ReadOnly");
            await conSeen.OpenAsync(ct).ConfigureAwait(false);
            await using var cmdSeen = conSeen.CreateCommand();
            cmdSeen.CommandText = "SELECT fileID FROM Files;";
            await using var rs = await cmdSeen.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await rs.ReadAsync(ct).ConfigureAwait(false))
            {
                if (!rs.IsDBNull(0))
                    seen.Add(rs.GetString(0));
            }
        }

        await using var writer = await BackupFilesystemWriter.OpenAsync(cleanDir, ct)
            .ConfigureAwait(false);
        var batch = new List<(string FileId, string Domain, string RelativePath, int Flags, byte[] Plist)>(
            512);
        var added = 0;
        var skipped = 0;
        long copiedBytes = 0;

        foreach (var priorWork in priorWorks)
        {
            ct.ThrowIfCancellationRequested();
            var priorClean = IkeBackupOutputPaths.ResolveCleanBackupDirectory(priorWork);
            var priorManifest = Path.Combine(priorClean, "Manifest.db");
            if (!File.Exists(priorManifest))
                continue;

            await using var con = new SqliteConnection(
                $"Data Source={priorManifest};Mode=ReadOnly");
            await con.OpenAsync(ct).ConfigureAwait(false);
            await using var cmd = con.CreateCommand();
            cmd.CommandText =
                "SELECT fileID, domain, relativePath, flags, file FROM Files;";
            await using var r = await cmd.ExecuteReaderAsync(ct).ConfigureAwait(false);
            while (await r.ReadAsync(ct).ConfigureAwait(false))
            {
                ct.ThrowIfCancellationRequested();
                var fid = r.IsDBNull(0) ? "" : r.GetString(0);
                if (fid.Length < 2 || !seen.Add(fid))
                    continue;

                var domain = r.IsDBNull(1) ? "" : r.GetString(1);
                var rel = r.IsDBNull(2) ? "" : r.GetString(2);
                var flags = r.IsDBNull(3) ? 1 : r.GetInt32(3);
                var plist = r.IsDBNull(4) ? Array.Empty<byte>() : (byte[])r.GetValue(4);

                if (flags == 1)
                {
                    long? expect = null;
                    if (plist.Length > 0 && TryReadSize(plist, out var sz))
                        expect = sz;
                    var src = IkeBackupOutputPaths.ToShardedFilePath(priorClean, fid);
                    if (!File.Exists(src))
                    {
                        // Prova altri prior più vecchi per lo stesso fileID.
                        src = FindShardInPriors(priorWorks, fid, expect) ?? "";
                    }

                    if (string.IsNullOrEmpty(src) || !File.Exists(src))
                    {
                        // size=0: crea placeholder; altrimenti skip riga (niente ghost Manifest).
                        if (expect is 0)
                        {
                            var dest0 = IkeBackupOutputPaths.ToShardedFilePath(cleanDir, fid);
                            Directory.CreateDirectory(Path.GetDirectoryName(dest0)!);
                            if (!File.Exists(dest0))
                                File.WriteAllBytes(dest0, []);
                        }
                        else
                        {
                            seen.Remove(fid);
                            skipped++;
                            continue;
                        }
                    }
                    else
                    {
                        var dest = IkeBackupOutputPaths.ToShardedFilePath(cleanDir, fid);
                        if (!TryCopyShard(src, dest, ref copiedBytes))
                        {
                            seen.Remove(fid);
                            skipped++;
                            continue;
                        }
                    }
                }

                batch.Add((fid, domain, rel, flags, plist));
                added++;
                if (batch.Count >= 500)
                {
                    await writer.UpsertManifestEntriesBatchAsync(batch, ct).ConfigureAwait(false);
                    batch.Clear();
                }
            }
        }

        if (batch.Count > 0)
            await writer.UpsertManifestEntriesBatchAsync(batch, ct).ConfigureAwait(false);

        _ = log;
        return new AddResult(added, skipped, copiedBytes);
    }

    private static string? FindShardInPriors(
        IReadOnlyList<string> priorWorks,
        string fileId,
        long? expectedSizeBytes)
    {
        foreach (var work in priorWorks)
        {
            try
            {
                var clean = IkeBackupOutputPaths.ResolveCleanBackupDirectory(work);
                var path = IkeBackupOutputPaths.ToShardedFilePath(clean, fileId);
                if (!File.Exists(path))
                    continue;
                var len = new FileInfo(path).Length;
                if (expectedSizeBytes is null)
                    return path;
                if (expectedSizeBytes.Value == 0 && len == 0)
                    return path;
                if (expectedSizeBytes.Value > 0 && len == expectedSizeBytes.Value)
                    return path;
                // size sconosciuta in plist ma file non vuoto: accetta solo match esatto se expect>0
            }
            catch
            {
                // next
            }
        }

        return null;
    }

    private static bool TryCopyShard(string src, string dest, ref long copiedBytes)
    {
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(dest)!);
            if (File.Exists(dest))
                return true;
            File.Copy(src, dest, overwrite: false);
            try { copiedBytes += new FileInfo(dest).Length; }
            catch { /* ignore */ }
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static DateTimeOffset? TryReadBackupDate(string cleanBackupDirectory)
    {
        try
        {
            var statusPath = Path.Combine(cleanBackupDirectory, "Status.plist");
            if (File.Exists(statusPath)
                && AppleBinaryPlist.TryParseDict(
                    File.ReadAllBytes(statusPath), out var dict, out _)
                && dict is not null
                && dict.TryGetValue("Date", out var d))
            {
                if (d is DateTime dt)
                    return new DateTimeOffset(DateTime.SpecifyKind(dt, DateTimeKind.Utc));
                if (d is DateTimeOffset dto)
                    return dto.ToUniversalTime();
            }
        }
        catch
        {
            // fall through Info
        }

        try
        {
            var infoPath = Path.Combine(cleanBackupDirectory, "Info.plist");
            if (!File.Exists(infoPath))
                return null;
            // Info is XML — Last Backup Date
            var text = File.ReadAllText(infoPath);
            var m = Regex.Match(
                text,
                @"<key>\s*Last Backup Date\s*</key>\s*<date>([^<]+)</date>",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
            if (m.Success
                && DateTimeOffset.TryParse(
                    m.Groups[1].Value,
                    CultureInfo.InvariantCulture,
                    DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                    out var dto))
                return dto;
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static bool TryReadSize(byte[] plistBlob, out long size)
    {
        size = 0;
        var m = SizeRegex.Match(System.Text.Encoding.UTF8.GetString(plistBlob));
        return m.Success && long.TryParse(m.Groups[1].Value, out size);
    }
}
