using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Inventario Voice Memos: tutti i record <c>CD_*</c> da <c>record/sync</c>,
/// titoli PCS da <c>crypto/field_records.tsv</c>, audio scaricati in <c>audio/</c>.
/// Scrive <c>voicememos_inventory.tsv</c> + <c>voicememos_inventory.json</c>.
/// </summary>
public static class VoiceMemosInventoryBuilder
{
    public sealed record InventorySummary(
        int Records,
        int CloudRecordings,
        int Migrations,
        int WithAudio,
        string TsvPath,
        string JsonPath);

    private sealed record Row(
        string RecordName,
        string RecordType,
        string? EntityName,
        string? Title,
        string? UniqueId,
        string? DateUtc,
        string? DeviceHint,
        bool HasCkAsset,
        string? AudioFile,
        string SyncTag,
        string Fields);

    public static InventorySummary Build(
        string containerDirectory,
        IProgress<string>? log = null)
    {
        Directory.CreateDirectory(containerDirectory);
        var titles = LoadTitles(containerDirectory);
        var audioByTitle = IndexAudioFiles(containerDirectory);
        var rows = new List<Row>();

        foreach (var syncPath in Directory.GetFiles(containerDirectory, "record_sync_*.bin")
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            var tag = Path.GetFileNameWithoutExtension(syncPath);
            byte[] payload;
            try
            {
                payload = File.ReadAllBytes(syncPath);
            }
            catch
            {
                continue;
            }

            foreach (var rec in VoiceMemosSyncRecordParser.ParseRecords(payload))
            {
                titles.TryGetValue(rec.RecordName, out var title);
                string? audio = null;
                if (!string.IsNullOrWhiteSpace(title)
                    && audioByTitle.TryGetValue(title.Trim(), out var byTitle))
                    audio = byTitle;
                else if (rec.HasCkAsset)
                    audio = GuessAudioNearRecord(audioByTitle.Values, title);

                rows.Add(new Row(
                    rec.RecordName,
                    rec.RecordType,
                    rec.EntityName,
                    title,
                    rec.UniqueId,
                    rec.DateUtc,
                    rec.DeviceHint,
                    rec.HasCkAsset,
                    audio,
                    tag,
                    string.Join(",", rec.FieldNames)));
            }
        }

        // Dedup by type:name, prefer row with title/audio.
        rows = rows
            .GroupBy(static r => $"{r.RecordType}:{r.RecordName}", StringComparer.OrdinalIgnoreCase)
            .Select(static g => g
                .OrderByDescending(static r => !string.IsNullOrWhiteSpace(r.Title))
                .ThenByDescending(static r => !string.IsNullOrWhiteSpace(r.AudioFile))
                .ThenByDescending(static r => r.HasCkAsset)
                .First())
            .OrderBy(static r => r.RecordType, StringComparer.Ordinal)
            .ThenBy(static r => r.DateUtc ?? "", StringComparer.Ordinal)
            .ThenBy(static r => r.RecordName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var tsvPath = Path.Combine(containerDirectory, "voicememos_inventory.tsv");
        var jsonPath = Path.Combine(containerDirectory, "voicememos_inventory.json");
        WriteTsv(tsvPath, rows);
        WriteJson(jsonPath, rows);

        var recordings = rows.Count(static r =>
            r.RecordType.Contains("CloudRecording", StringComparison.OrdinalIgnoreCase));
        var migrations = rows.Count(static r =>
            r.RecordType.Contains("Migration", StringComparison.OrdinalIgnoreCase));
        var withAudio = rows.Count(static r => !string.IsNullOrWhiteSpace(r.AudioFile));

        log?.Report(
            $"  Voice Memos inventory: {rows.Count} record " +
            $"(CloudRecording={recordings}, Migration={migrations}, audio={withAudio}) " +
            $"→ {Path.GetFileName(tsvPath)}");

        return new InventorySummary(
            rows.Count, recordings, migrations, withAudio, tsvPath, jsonPath);
    }

    private static Dictionary<string, string> LoadTitles(string containerDirectory)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var crypto = Path.Combine(containerDirectory, "crypto");
        if (!Directory.Exists(crypto))
            return map;

        foreach (var tsv in Directory.GetFiles(crypto, "field_records.tsv", SearchOption.AllDirectories))
        {
            foreach (var line in File.ReadLines(tsv).Skip(1))
            {
                var parts = line.Split('\t');
                if (parts.Length < 6)
                    continue;
                if (!parts[0].Contains("encryptedTitle", StringComparison.OrdinalIgnoreCase)
                    && !parts[0].Contains("customLabel", StringComparison.OrdinalIgnoreCase))
                    continue;
                var record = parts[2].Trim();
                var text = parts[5].Trim();
                if (record.Length > 0 && text.Length > 0)
                    map[record] = text;
            }
        }

        return map;
    }

    private static Dictionary<string, string> IndexAudioFiles(string containerDirectory)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var audioDir = Path.Combine(containerDirectory, "audio");
        if (!Directory.Exists(audioDir))
            return map;

        foreach (var f in Directory.GetFiles(audioDir, "*.*")
                     .Where(static p =>
                         p.EndsWith(".m4a", StringComparison.OrdinalIgnoreCase)
                         || p.EndsWith(".mp4", StringComparison.OrdinalIgnoreCase)
                         || p.EndsWith(".caf", StringComparison.OrdinalIgnoreCase)
                         || p.EndsWith(".wav", StringComparison.OrdinalIgnoreCase)))
        {
            var name = Path.GetFileNameWithoutExtension(f);
            if (name.EndsWith(".ct", StringComparison.OrdinalIgnoreCase))
                continue;
            map[name] = Path.GetFileName(f);
        }

        return map;
    }

    private static string? GuessAudioNearRecord(
        IEnumerable<string> audioFiles,
        string? title)
    {
        if (!string.IsNullOrWhiteSpace(title))
        {
            var hit = audioFiles.FirstOrDefault(a =>
                Path.GetFileNameWithoutExtension(a)
                    .Contains(title.Trim(), StringComparison.OrdinalIgnoreCase));
            if (hit is not null)
                return hit;
        }

        return audioFiles.Count() == 1 ? audioFiles.First() : null;
    }

    private static void WriteTsv(string path, List<Row> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine(
            "record_name\trecord_type\tentity\ttitle\tunique_id\tdate_utc\tdevice\thas_ckasset\taudio_file\tsync_tag\tfields");
        foreach (var r in rows)
        {
            sb.Append(Esc(r.RecordName)).Append('\t')
                .Append(Esc(r.RecordType)).Append('\t')
                .Append(Esc(r.EntityName)).Append('\t')
                .Append(Esc(r.Title)).Append('\t')
                .Append(Esc(r.UniqueId)).Append('\t')
                .Append(Esc(r.DateUtc)).Append('\t')
                .Append(Esc(r.DeviceHint)).Append('\t')
                .Append(r.HasCkAsset ? "1" : "0").Append('\t')
                .Append(Esc(r.AudioFile)).Append('\t')
                .Append(Esc(r.SyncTag)).Append('\t')
                .Append(Esc(r.Fields))
                .AppendLine();
        }

        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    private static void WriteJson(string path, List<Row> rows)
    {
        var payload = new
        {
            generatedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
            count = rows.Count,
            records = rows.Select(static r => new
            {
                recordName = r.RecordName,
                recordType = r.RecordType,
                entityName = r.EntityName,
                title = r.Title,
                uniqueId = r.UniqueId,
                dateUtc = r.DateUtc,
                deviceHint = r.DeviceHint,
                hasCkAsset = r.HasCkAsset,
                audioFile = r.AudioFile,
                syncTag = r.SyncTag,
                fields = r.Fields.Split(',', StringSplitOptions.RemoveEmptyEntries),
            }),
        };
        File.WriteAllText(
            path,
            JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string Esc(string? s)
    {
        if (string.IsNullOrEmpty(s))
            return "";
        return s.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
    }
}
