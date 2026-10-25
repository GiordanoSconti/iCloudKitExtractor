using System.IO;
using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Costruisce <c>Notes.db</c> da payload <c>record/sync</c> + plaintext PCS in <c>crypto/</c>.
/// </summary>
public static class NotesLibraryBuilder
{
    private sealed record FieldRow(
        string Field,
        string RecordName,
        string PlainPath,
        string? Text);

    public sealed record BuildSummary(
        int Folders,
        int Notes,
        int PlaintextFields,
        string DbPath);

    public static async Task<BuildSummary> BuildAsync(
        string containerDir,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(containerDir);
        var db = await NotesCatalogSqlite.OpenAsync(containerDir, ct);
        await db.ClearAsync(ct);

        var syncFiles = Directory.GetFiles(containerDir, "record_sync_*.bin")
            .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var parsedByRecord = new Dictionary<string, NotesSyncRecordParser.ParsedRecord>(StringComparer.OrdinalIgnoreCase);
        var folderByKey = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        foreach (var syncPath in syncFiles)
        {
            ct.ThrowIfCancellationRequested();
            var tag = Path.GetFileNameWithoutExtension(syncPath);
            var payload = await File.ReadAllBytesAsync(syncPath, ct);
            foreach (var rec in NotesSyncRecordParser.ParseRecords(payload))
            {
                var key = $"{rec.RecordType}:{rec.RecordName}";
                parsedByRecord[key] = rec with { };

                if (rec.RecordType.Equals("Folder", StringComparison.Ordinal))
                {
                    var name = rec.TitleHint;
                    if (string.IsNullOrWhiteSpace(name) && rec.FolderKey is not null)
                        name = ExtractFolderDisplayName(rec.FolderKey);

                    var isSystem = rec.FolderKey is "DefaultFolder-CloudKit" or "TrashFolder-CloudKit"
                                   || (rec.FolderKey?.Contains("DefaultFolder-CloudKit", StringComparison.Ordinal) == true)
                                   || (rec.FolderKey?.Contains("TrashFolder-CloudKit", StringComparison.Ordinal) == true);

                    await db.UpsertFolderAsync(
                        rec.RecordName,
                        name,
                        rec.FolderKey,
                        rec.FolderHashId,
                        isSystem,
                        tag,
                        ct);

                    if (!string.IsNullOrWhiteSpace(rec.FolderKey))
                        folderByKey[rec.FolderKey] = rec.RecordName;
                }
            }
        }

        // Cartelle di sistema anche se non compaiono come record Folder dedicati.
        await EnsureSystemFolderAsync(
            db, folderByKey, "DefaultFolder-CloudKit", "Note", ct);
        await EnsureSystemFolderAsync(
            db, folderByKey, "TrashFolder-CloudKit", "Eliminate", ct);

        var fieldRows = LoadFieldRecords(containerDir);
        var byRecord = fieldRows
            .GroupBy(static r => r.RecordName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.ToList(), StringComparer.OrdinalIgnoreCase);

        var noteCount = 0;
        var plainCount = 0;

        foreach (var (recordName, rows) in byRecord)
        {
            ct.ThrowIfCancellationRequested();
            var hasText = rows.Any(static r =>
                r.Field.Equals("TextDataEncrypted", StringComparison.Ordinal));
            if (!hasText)
                continue;

            var title = BestText(rows, "TitleEncrypted");
            var snippet = BestText(rows, "SnippetEncrypted")
                          ?? BestText(rows, "DisplayTextEncrypted");
            var body = BestText(rows, "TextDataEncrypted");

            if (string.IsNullOrWhiteSpace(snippet) && !string.IsNullOrWhiteSpace(body))
                snippet = TruncatePreview(body, 240);

            if (string.IsNullOrWhiteSpace(title) && !string.IsNullOrWhiteSpace(body))
                title = TruncatePreview(body, 80);

            parsedByRecord.TryGetValue($"Note:{recordName}", out var parsed);
            var folderKey = parsed?.FolderKey ?? "DefaultFolder-CloudKit";
            folderByKey.TryGetValue(folderKey, out var folderRecordName);

            await db.UpsertNoteAsync(
                recordName,
                title,
                snippet,
                folderKey,
                folderRecordName,
                "Note",
                deleted: folderKey.Contains("TrashFolder", StringComparison.OrdinalIgnoreCase),
                syncTag: FindSyncTagFromPlainPath(rows[0].PlainPath),
                ct);
            noteCount++;

            foreach (var row in rows)
            {
                await db.UpsertPlaintextAsync(
                    recordName,
                    row.Field,
                    row.PlainPath,
                    row.Text,
                    ct);
                plainCount++;
            }
        }

        // Folder-only da sync (nome cartella senza note in field_records).
        foreach (var rec in parsedByRecord.Values.Where(static r =>
                     r.RecordType.Equals("Folder", StringComparison.Ordinal)))
        {
            if (byRecord.ContainsKey(rec.RecordName))
                continue;

            var name = rec.TitleHint;
            if (string.IsNullOrWhiteSpace(name) && rec.FolderKey is not null)
                name = ExtractFolderDisplayName(rec.FolderKey);

            await db.UpsertFolderAsync(
                rec.RecordName,
                name,
                rec.FolderKey,
                rec.FolderHashId,
                rec.FolderKey is "DefaultFolder-CloudKit" or "TrashFolder-CloudKit",
                syncTag: null,
                ct);
        }

        var folderCount = await db.CountAsync("folders", ct);
        var dbPath = Path.Combine(containerDir, "Notes.db");
        log?.Report(
            $"  Notes.db: cartelle={folderCount}, note={noteCount}, plaintext={plainCount} → {dbPath}");

        await db.DisposeAsync();
        return new BuildSummary(folderCount, noteCount, plainCount, dbPath);
    }

    private static async Task EnsureSystemFolderAsync(
        NotesCatalogSqlite db,
        Dictionary<string, string> folderByKey,
        string folderKey,
        string displayName,
        CancellationToken ct)
    {
        if (folderByKey.ContainsKey(folderKey))
            return;

        var recordName = $"system:{folderKey}";
        await db.UpsertFolderAsync(recordName, displayName, folderKey, null, isSystem: true, syncTag: null, ct);
        folderByKey[folderKey] = recordName;
    }

    private static string? BestText(IReadOnlyList<FieldRow> rows, string fieldName)
    {
        return rows
            .Where(r => r.Field.Equals(fieldName, StringComparison.Ordinal))
            .Select(static r => r.Text?.Trim())
            .Where(static t => !string.IsNullOrWhiteSpace(t))
            .OrderByDescending(static t => t!.Length)
            .FirstOrDefault();
    }

    private static string? ExtractFolderDisplayName(string folderKey)
    {
        var sep = folderKey.LastIndexOf("::", StringComparison.Ordinal);
        if (sep >= 0 && sep + 2 < folderKey.Length)
            return folderKey[(sep + 2)..];
        return folderKey;
    }

    private static string? FindSyncTagFromPlainPath(string plainPath)
    {
        // .../crypto/record_sync_Notes_p1/plaintext/...
        var parts = plainPath.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var cryptoIdx = Array.FindIndex(parts, static p => p.Equals("crypto", StringComparison.OrdinalIgnoreCase));
        if (cryptoIdx >= 0 && cryptoIdx + 1 < parts.Length)
            return parts[cryptoIdx + 1];
        return null;
    }

    private static List<FieldRow> LoadFieldRecords(string containerDir)
    {
        var rows = new List<FieldRow>();
        var cryptoRoot = Path.Combine(containerDir, "crypto");
        if (!Directory.Exists(cryptoRoot))
            return rows;

        foreach (var tsvPath in Directory.GetFiles(cryptoRoot, "field_records.tsv", SearchOption.AllDirectories))
        {
            foreach (var line in File.ReadAllLines(tsvPath).Skip(1))
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var parts = line.Split('\t');
                if (parts.Length < 5)
                    continue;

                var field = parts[0];
                var recordName = parts[2].Trim().ToUpperInvariant();
                var plainPath = parts[4];
                var text = parts.Length > 5 ? NullIfEmpty(parts[5]) : null;
                if (string.IsNullOrWhiteSpace(recordName))
                    continue;

                rows.Add(new FieldRow(field, recordName, plainPath, text));
            }
        }

        return rows
            .GroupBy(static r => $"{r.RecordName}|{r.Field}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g
                .OrderByDescending(static r => r.Text?.Length ?? 0)
                .ThenBy(static r => r.PlainPath, StringComparer.OrdinalIgnoreCase)
                .First())
            .ToList();
    }

    private static string TruncatePreview(string value, int maxLen)
    {
        var trimmed = value.Trim();
        if (trimmed.Length <= maxLen)
            return trimmed;
        return trimmed[..maxLen].TrimEnd() + "…";
    }

    private static string? NullIfEmpty(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}
