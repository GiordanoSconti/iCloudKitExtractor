using System.Globalization;
using System.IO;
using System.Security.Cryptography;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Forensics;

/// <summary>
/// Aggregates case metadata, ops journal, folder inventory and integrity manifests
/// into a presentation-ready report model (no tokens / secrets).
/// </summary>
public static class IkeCaseReportBuilder
{
    private static readonly (string Folder, string Label)[] Areas =
    [
        (IkeCaseSession.BackupFolder, "Device backups"),
        (IkeCaseSession.EscrowFolder, "Escrow / Octagon"),
        (IkeCaseSession.WhatsAppFolder, "WhatsApp CloudKit"),
        (IkeCaseSession.DriveFolder, "iCloud Drive"),
        (IkeCaseSession.FilesFolder, "iCloud Files"),
        (IkeCaseSession.SyncDataFolder, "Sync Data"),
        (IkeCaseSession.MailFolder, "IMAP Mail"),
        (IkeCaseSession.LogsFolder, "Session logs"),
        (IkeCaseSession.OpsFolder, "Operations journal"),
        (IkeCaseSession.ReportFolder, "Reports"),
    ];

    public static IkeCaseReportModel Build(IkeCaseSession session, byte[]? logoPng = null)
    {
        var ops = IkeCaseOpsJournal.ReadAll(session).ToList();
        var areas = new List<IkeCaseReportArea>();
        var integrity = new List<IkeCaseReportIntegrity>();

        foreach (var (folder, label) in Areas)
        {
            var path = Path.Combine(session.RootPath, folder);
            var stats = MeasureDirectory(path);
            areas.Add(new IkeCaseReportArea
            {
                Id = folder,
                Label = label,
                RelativePath = folder + "/",
                Exists = Directory.Exists(path),
                FileCount = stats.Files,
                TotalBytes = stats.Bytes,
                OldestUtc = stats.Oldest,
                NewestUtc = stats.Newest,
            });
        }

        foreach (var integrityPath in EnumerateFilesSafe(session.RootPath, OutputHashManifest.JsonFileName))
        {
            try
            {
                var rel = Path.GetRelativePath(session.RootPath, integrityPath).Replace('\\', '/');
                var json = File.ReadAllText(integrityPath);
                using var doc = JsonDocument.Parse(json);
                var root = doc.RootElement;
                var fileCount = root.TryGetProperty("fileCount", out var fc) ? fc.GetInt32() : 0;
                var totalBytes = root.TryGetProperty("totalBytes", out var tb) ? tb.GetInt64() : 0;
                DateTimeOffset? generated = null;
                if (root.TryGetProperty("generatedAt", out var ga)
                    && ga.ValueKind == JsonValueKind.String
                    && DateTimeOffset.TryParse(ga.GetString(), CultureInfo.InvariantCulture,
                        DateTimeStyles.RoundtripKind, out var g))
                    generated = g;

                string? hashesSha = null;
                var hashesPath = Path.Combine(Path.GetDirectoryName(integrityPath)!, OutputHashManifest.Sha256FileName);
                if (File.Exists(hashesPath))
                    hashesSha = OutputHashManifest.TryComputeSha256Hex(hashesPath);

                integrity.Add(new IkeCaseReportIntegrity
                {
                    RelativePath = rel,
                    FileCount = fileCount,
                    TotalBytes = totalBytes,
                    GeneratedAt = generated,
                    HashesFileSha256 = hashesSha,
                });
            }
            catch
            {
                // skip unreadable manifests
            }
        }

        // Synthesize timeline bookmarks from area activity when journal is thin.
        if (ops.Count == 0)
        {
            foreach (var a in areas.Where(x => x.FileCount > 0 && x.NewestUtc is not null))
            {
                ops.Add(new IkeCaseOperationEntry
                {
                    Utc = a.NewestUtc!.Value,
                    Area = a.Id,
                    Action = "artifacts-present",
                    Detail = $"{a.FileCount:N0} files · {FormatBytes(a.TotalBytes)}",
                    Status = "inferred",
                });
            }

            ops = ops.OrderBy(o => o.Utc).ToList();
        }

        string? caseJsonSha = null;
        if (File.Exists(session.CaseJsonPath))
            caseJsonSha = OutputHashManifest.TryComputeSha256Hex(session.CaseJsonPath);

        return new IkeCaseReportModel
        {
            GeneratedAt = DateTimeOffset.UtcNow,
            Title = "iCloudKitExtractor — CloudKit Report",
            Case = session.Info,
            CaseJsonSha256 = caseJsonSha,
            Operations = ops,
            Areas = areas,
            IntegrityManifests = integrity.OrderBy(i => i.RelativePath, StringComparer.OrdinalIgnoreCase).ToList(),
            LogoPng = logoPng,
            ToolVersion = typeof(IkeCaseReportBuilder).Assembly.GetName().Version?.ToString() ?? "dev",
        };
    }

    public static string FormatBytes(long bytes)
    {
        if (bytes < 1024)
            return $"{bytes} B";
        double v = bytes;
        string[] u = ["KB", "MB", "GB", "TB"];
        var i = -1;
        do
        {
            v /= 1024;
            i++;
        } while (v >= 1024 && i < u.Length - 1);
        return $"{v:0.##} {u[i]}";
    }

    private static (int Files, long Bytes, DateTimeOffset? Oldest, DateTimeOffset? Newest) MeasureDirectory(string path)
    {
        if (!Directory.Exists(path))
            return (0, 0, null, null);

        var files = 0;
        long bytes = 0;
        DateTime? oldest = null;
        DateTime? newest = null;
        foreach (var f in EnumerateFilesRecursive(path))
        {
            try
            {
                var info = new FileInfo(f);
                files++;
                bytes += info.Length;
                var utc = info.LastWriteTimeUtc;
                if (oldest is null || utc < oldest)
                    oldest = utc;
                if (newest is null || utc > newest)
                    newest = utc;
            }
            catch
            {
                // skip
            }
        }

        return (files, bytes,
            oldest.HasValue ? new DateTimeOffset(DateTime.SpecifyKind(oldest.Value, DateTimeKind.Utc)) : null,
            newest.HasValue ? new DateTimeOffset(DateTime.SpecifyKind(newest.Value, DateTimeKind.Utc)) : null);
    }

    private static IEnumerable<string> EnumerateFilesRecursive(string root)
    {
        var stack = new Stack<string>();
        stack.Push(root);
        while (stack.Count > 0)
        {
            var dir = stack.Pop();
            IEnumerable<string> subs;
            try { subs = Directory.EnumerateDirectories(dir); }
            catch { continue; }
            foreach (var s in subs)
                stack.Push(s);
            IEnumerable<string> files;
            try { files = Directory.EnumerateFiles(dir); }
            catch { continue; }
            foreach (var f in files)
                yield return f;
        }
    }

    private static IEnumerable<string> EnumerateFilesSafe(string root, string fileName)
    {
        foreach (var f in EnumerateFilesRecursive(root))
        {
            if (string.Equals(Path.GetFileName(f), fileName, StringComparison.OrdinalIgnoreCase))
                yield return f;
        }
    }
}

public sealed class IkeCaseReportModel
{
    public DateTimeOffset GeneratedAt { get; init; }
    public string Title { get; init; } = "";
    public IkeCaseInfo Case { get; init; } = new();
    public string? CaseJsonSha256 { get; init; }
    public IReadOnlyList<IkeCaseOperationEntry> Operations { get; init; } = Array.Empty<IkeCaseOperationEntry>();
    public IReadOnlyList<IkeCaseReportArea> Areas { get; init; } = Array.Empty<IkeCaseReportArea>();
    public IReadOnlyList<IkeCaseReportIntegrity> IntegrityManifests { get; init; } = Array.Empty<IkeCaseReportIntegrity>();
    public byte[]? LogoPng { get; init; }
    public string ToolVersion { get; init; } = "";
}

public sealed class IkeCaseReportArea
{
    public string Id { get; init; } = "";
    public string Label { get; init; } = "";
    public string RelativePath { get; init; } = "";
    public bool Exists { get; init; }
    public int FileCount { get; init; }
    public long TotalBytes { get; init; }
    public DateTimeOffset? OldestUtc { get; init; }
    public DateTimeOffset? NewestUtc { get; init; }
}

public sealed class IkeCaseReportIntegrity
{
    public string RelativePath { get; init; } = "";
    public int FileCount { get; init; }
    public long TotalBytes { get; init; }
    public DateTimeOffset? GeneratedAt { get; init; }
    public string? HashesFileSha256 { get; init; }
}
