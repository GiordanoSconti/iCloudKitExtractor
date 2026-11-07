using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Inventario Voice Memos: record <c>CD_*</c>, device <c>metadata_zone</c>,
/// titoli PCS e audio in <c>audio/</c> con sidecar <c>*.meta.json</c>.
/// </summary>
public static class VoiceMemosInventoryBuilder
{
    public sealed record InventorySummary(
        int Records,
        int CloudRecordings,
        int Migrations,
        int Devices,
        int WithAudio,
        int Sidecars,
        string TsvPath,
        string JsonPath);

    private sealed record Row(
        string Kind,
        string RecordName,
        string RecordType,
        string? EntityName,
        string? Title,
        string? UniqueId,
        string? DateUtc,
        string? DeviceHint,
        double? DurationSeconds,
        bool HasCkAsset,
        string? AudioFile,
        string? AudioMetaFile,
        string SyncTag,
        string Fields,
        string? OsType = null,
        string? OsVersion = null,
        string? OsBuild = null,
        string? SoftwareBundleId = null);

    public static InventorySummary Build(
        string containerDirectory,
        IProgress<string>? log = null)
    {
        Directory.CreateDirectory(containerDirectory);
        var titles = LoadTitles(containerDirectory);
        var audioByTitle = IndexAudioFiles(containerDirectory);
        var rows = new List<Row>();
        var sidecars = 0;
        var parsedDevices = new List<VoiceMemosSyncRecordParser.ParsedMetadataDevice>();
        var parsedRecordings = new List<(VoiceMemosSyncRecordParser.ParsedRecord Rec, string? Title, string Tag)>();
        string? migrationDeviceHint = null;

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

            var isMetadataZone = tag.Contains("metadata_zone", StringComparison.OrdinalIgnoreCase);

            if (isMetadataZone)
            {
                foreach (var dev in VoiceMemosSyncRecordParser.ParseMetadataDevices(payload))
                {
                    parsedDevices.Add(dev);
                    rows.Add(new Row(
                        Kind: "device",
                        RecordName: dev.RecordName,
                        RecordType: "metadata_device",
                        EntityName: "metadata_device",
                        Title: null,
                        UniqueId: dev.DeviceId,
                        DateUtc: null,
                        DeviceHint: dev.DeviceClass,
                        DurationSeconds: null,
                        HasCkAsset: false,
                        AudioFile: null,
                        AudioMetaFile: null,
                        SyncTag: tag,
                        Fields: "DeviceOSBuild,DeviceOSVersion,DeviceOSType",
                        OsType: dev.OsType,
                        OsVersion: dev.OsVersion,
                        OsBuild: dev.OsBuild,
                        SoftwareBundleId: dev.SoftwareBundleId));
                }

                continue;
            }

            foreach (var rec in VoiceMemosSyncRecordParser.ParseRecords(payload))
            {
                titles.TryGetValue(rec.RecordName, out var title);
                var isRecording = rec.RecordType.Contains("CloudRecording", StringComparison.OrdinalIgnoreCase)
                                  || rec.RecordType.Contains("SavedRecording", StringComparison.OrdinalIgnoreCase);

                if (isRecording)
                    parsedRecordings.Add((rec, title, tag));
                else
                {
                    if (!string.IsNullOrWhiteSpace(rec.DeviceHint))
                        migrationDeviceHint ??= rec.DeviceHint;
                    rows.Add(new Row(
                        Kind: "migration",
                        RecordName: rec.RecordName,
                        RecordType: rec.RecordType,
                        EntityName: rec.EntityName,
                        Title: null,
                        UniqueId: null,
                        DateUtc: rec.DateUtc,
                        DeviceHint: rec.DeviceHint,
                        DurationSeconds: null,
                        HasCkAsset: false,
                        AudioFile: null,
                        AudioMetaFile: null,
                        SyncTag: tag,
                        Fields: string.Join(",", rec.FieldNames)));
                }
            }
        }

        foreach (var (rec, title, tag) in parsedRecordings)
        {
            string? audio = null;
            string? metaFile = null;
            if (!string.IsNullOrWhiteSpace(title)
                && audioByTitle.TryGetValue(title.Trim(), out var byTitle))
                audio = byTitle;
            else if (rec.HasCkAsset && audioByTitle.Count == 1)
                audio = audioByTitle.Values.First();

            var deviceHint = rec.DeviceHint ?? migrationDeviceHint;
            var relatedDevices = parsedDevices
                .Where(d =>
                    !string.IsNullOrWhiteSpace(deviceHint)
                    && string.Equals(d.DeviceClass, deviceHint, StringComparison.OrdinalIgnoreCase)
                    && (!string.IsNullOrWhiteSpace(d.OsBuild) || !string.IsNullOrWhiteSpace(d.OsVersion)))
                // Prefer richer / newer OS rows, keep distinct builds.
                .GroupBy(static d => d.OsBuild ?? d.OsVersion ?? d.DeviceId, StringComparer.OrdinalIgnoreCase)
                .Select(static g => g.First())
                .Take(8)
                .ToList();

            if (!string.IsNullOrWhiteSpace(audio))
            {
                metaFile = WriteAudioSidecar(
                    containerDirectory,
                    audio,
                    rec with { DeviceHint = deviceHint },
                    title,
                    relatedDevices);
                if (metaFile is not null)
                    sidecars++;
            }

            rows.Add(new Row(
                Kind: "recording",
                RecordName: rec.RecordName,
                RecordType: rec.RecordType,
                EntityName: rec.EntityName,
                Title: title,
                UniqueId: rec.UniqueId,
                DateUtc: rec.DateUtc,
                DeviceHint: deviceHint,
                DurationSeconds: rec.DurationSeconds,
                HasCkAsset: rec.HasCkAsset,
                AudioFile: audio,
                AudioMetaFile: metaFile,
                SyncTag: tag,
                Fields: string.Join(",", rec.FieldNames)));
        }

        rows = DedupRows(rows);

        var tsvPath = Path.Combine(containerDirectory, "voicememos_inventory.tsv");
        var jsonPath = Path.Combine(containerDirectory, "voicememos_inventory.json");
        WriteTsv(tsvPath, rows);
        WriteJson(jsonPath, rows);

        var recordings = rows.Count(static r => r.Kind == "recording");
        var migrations = rows.Count(static r => r.Kind == "migration");
        var devices = rows.Count(static r => r.Kind == "device");
        var withAudio = rows.Count(static r => !string.IsNullOrWhiteSpace(r.AudioFile));

        log?.Report(
            $"  Voice Memos inventory: {rows.Count} rows " +
            $"(recordings={recordings}, migrations={migrations}, devices={devices}, " +
            $"audio={withAudio}, sidecars={sidecars}) → {Path.GetFileName(tsvPath)}");

        return new InventorySummary(
            rows.Count, recordings, migrations, devices, withAudio, sidecars, tsvPath, jsonPath);
    }

    private static List<Row> DedupRows(List<Row> rows) =>
        rows
            .GroupBy(static r => $"{r.Kind}:{r.RecordType}:{r.RecordName}", StringComparer.OrdinalIgnoreCase)
            .Select(static g => g
                .OrderByDescending(static r => !string.IsNullOrWhiteSpace(r.Title))
                .ThenByDescending(static r => !string.IsNullOrWhiteSpace(r.AudioFile))
                .ThenByDescending(static r => !string.IsNullOrWhiteSpace(r.OsBuild))
                .First())
            .OrderBy(static r => r.Kind, StringComparer.Ordinal)
            .ThenBy(static r => r.DateUtc ?? r.OsVersion ?? "", StringComparer.Ordinal)
            .ThenBy(static r => r.RecordName, StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static string? WriteAudioSidecar(
        string containerDirectory,
        string audioFileName,
        VoiceMemosSyncRecordParser.ParsedRecord rec,
        string? title,
        IReadOnlyList<VoiceMemosSyncRecordParser.ParsedMetadataDevice> relatedDevices)
    {
        var audioDir = Path.Combine(containerDirectory, "audio");
        var audioPath = Path.Combine(audioDir, audioFileName);
        if (!File.Exists(audioPath))
            return null;

        var metaName = Path.GetFileNameWithoutExtension(audioFileName) + ".meta.json";
        var metaPath = Path.Combine(audioDir, metaName);
        var payload = new
        {
            audioFile = audioFileName,
            title,
            recordName = rec.RecordName,
            recordType = rec.RecordType,
            entityName = rec.EntityName,
            uniqueId = rec.UniqueId,
            dateUtc = rec.DateUtc,
            deviceHint = rec.DeviceHint,
            durationSeconds = rec.DurationSeconds,
            hasCkAsset = rec.HasCkAsset,
            fields = rec.FieldNames,
            relatedDevices = relatedDevices.Select(static d => new
            {
                deviceId = d.DeviceId,
                deviceClass = d.DeviceClass,
                osType = d.OsType,
                osVersion = d.OsVersion,
                osBuild = d.OsBuild,
                softwareBundleId = d.SoftwareBundleId,
            }),
            associatedAtUtc = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
        };
        File.WriteAllText(
            metaPath,
            JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
        return metaName;
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

    private static void WriteTsv(string path, List<Row> rows)
    {
        var sb = new StringBuilder();
        sb.AppendLine(
            "kind\trecord_name\trecord_type\tentity\ttitle\tunique_id\tdate_utc\tduration_s\tdevice\thas_ckasset\taudio_file\taudio_meta\tos_type\tos_version\tos_build\tbundle\tsync_tag\tfields");
        foreach (var r in rows)
        {
            sb.Append(Esc(r.Kind)).Append('\t')
                .Append(Esc(r.RecordName)).Append('\t')
                .Append(Esc(r.RecordType)).Append('\t')
                .Append(Esc(r.EntityName)).Append('\t')
                .Append(Esc(r.Title)).Append('\t')
                .Append(Esc(r.UniqueId)).Append('\t')
                .Append(Esc(r.DateUtc)).Append('\t')
                .Append(r.DurationSeconds?.ToString(CultureInfo.InvariantCulture) ?? "").Append('\t')
                .Append(Esc(r.DeviceHint)).Append('\t')
                .Append(r.HasCkAsset ? "1" : "0").Append('\t')
                .Append(Esc(r.AudioFile)).Append('\t')
                .Append(Esc(r.AudioMetaFile)).Append('\t')
                .Append(Esc(r.OsType)).Append('\t')
                .Append(Esc(r.OsVersion)).Append('\t')
                .Append(Esc(r.OsBuild)).Append('\t')
                .Append(Esc(r.SoftwareBundleId)).Append('\t')
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
            recordings = rows.Where(static r => r.Kind == "recording").Select(ToJsonRow),
            migrations = rows.Where(static r => r.Kind == "migration").Select(ToJsonRow),
            devices = rows.Where(static r => r.Kind == "device").Select(ToJsonRow),
        };
        File.WriteAllText(
            path,
            JsonSerializer.Serialize(payload, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static object ToJsonRow(Row r) => new
    {
        kind = r.Kind,
        recordName = r.RecordName,
        recordType = r.RecordType,
        entityName = r.EntityName,
        title = r.Title,
        uniqueId = r.UniqueId,
        dateUtc = r.DateUtc,
        durationSeconds = r.DurationSeconds,
        deviceHint = r.DeviceHint,
        hasCkAsset = r.HasCkAsset,
        audioFile = r.AudioFile,
        audioMetaFile = r.AudioMetaFile,
        osType = r.OsType,
        osVersion = r.OsVersion,
        osBuild = r.OsBuild,
        softwareBundleId = r.SoftwareBundleId,
        syncTag = r.SyncTag,
        fields = string.IsNullOrWhiteSpace(r.Fields)
            ? Array.Empty<string>()
            : r.Fields.Split(',', StringSplitOptions.RemoveEmptyEntries),
    };

    private static string Esc(string? s)
    {
        if (string.IsNullOrEmpty(s))
            return "";
        return s.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
    }
}
