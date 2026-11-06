using System.Text;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Estrae record Core Data CloudKit Voice Memos dal payload <c>record/sync</c>
/// (<c>CD_CloudRecording</c>, <c>CD_Migration</c>, altri <c>CD_*</c>).
/// </summary>
public static class VoiceMemosSyncRecordParser
{
    private static readonly Regex UuidRegex = new(
        @"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex IsoDateRegex = new(
        @"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly HashSet<string> KnownTypes = new(StringComparer.Ordinal)
    {
        "CD_CloudRecording",
        "CD_Migration",
        "CD_Folder",
        "CD_SavedRecording",
        "CD_CloudRecordingEncrypted",
    };

    public sealed record ParsedRecord(
        string RecordName,
        string RecordType,
        string? EntityName,
        string? UniqueId,
        string? DateUtc,
        string? DeviceHint,
        bool HasCkAsset,
        IReadOnlyList<string> FieldNames);

    public static IReadOnlyList<ParsedRecord> ParseRecords(byte[] payload)
    {
        if (payload is not { Length: > 64 })
            return [];

        var results = new List<ParsedRecord>();
        foreach (var type in KnownTypes)
            ScanMarker(payload, Encoding.ASCII.GetBytes(type + "\"%"), type, results);

        // Catch-all: any CD_*"% marker not already known.
        ScanGenericCdMarkers(payload, results);
        return Deduplicate(results);
    }

    private static void ScanGenericCdMarkers(byte[] payload, List<ParsedRecord> results)
    {
        var text = Encoding.ASCII.GetString(payload);
        foreach (Match m in Regex.Matches(text, @"CD_[A-Za-z][A-Za-z0-9_]+""%"))
        {
            var type = m.Value[..^2]; // strip "%
            if (KnownTypes.Contains(type))
                continue;
            if (type.Contains("encrypted", StringComparison.OrdinalIgnoreCase)
                || type.Contains("versioned", StringComparison.OrdinalIgnoreCase)
                || type.Contains("ckAsset", StringComparison.OrdinalIgnoreCase)
                || type is "CD_entityName" or "CD_uniqueID" or "CD_date" or "CD_flags"
                    or "CD_duration" or "CD_customLabel" or "CD_playbackSpeed"
                    or "CD_audioFutureFlags" or "CD_skipSilenceEnabled")
                continue;

            var at = m.Index;
            var marker = Encoding.ASCII.GetBytes(m.Value);
            CollectAt(payload, at, marker.Length, type, results);
        }
    }

    private static void ScanMarker(
        byte[] payload,
        ReadOnlySpan<byte> marker,
        string recordType,
        List<ParsedRecord> results)
    {
        var start = 0;
        while (start <= payload.Length - marker.Length)
        {
            var at = IndexOf(payload, marker, start);
            if (at < 0)
                break;
            CollectAt(payload, at, marker.Length, recordType, results);
            start = at + marker.Length;
        }
    }

    private static void CollectAt(
        byte[] payload,
        int at,
        int markerLen,
        string recordType,
        List<ParsedRecord> results)
    {
        var windowStart = Math.Max(0, at - 512);
        var windowEnd = Math.Min(payload.Length, at + 2048);
        var before = payload.AsSpan(windowStart, at - windowStart);
        var around = payload.AsSpan(at, windowEnd - at);
        var recordName = FindLastUuid(before) ?? FindLastUuid(around);
        if (string.IsNullOrWhiteSpace(recordName))
            return;

        var strings = ExtractAsciiStrings(around, maxLen: 4000);
        var fieldNames = strings
            .Where(static s => s.StartsWith("CD_", StringComparison.Ordinal)
                               && s.Length is >= 4 and <= 64
                               && !s.Contains('"')
                               && s.All(static c => char.IsLetterOrDigit(c) || c == '_'))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var entityName = strings.FirstOrDefault(static s =>
            s is "CloudRecording" or "Migration" or "Folder" or "SavedRecording");

        var uniqueId = strings.FirstOrDefault(s =>
            UuidRegex.IsMatch(s)
            && !s.Equals(recordName, StringComparison.OrdinalIgnoreCase)
            && fieldNames.Contains("CD_uniqueID"));
        // Prefer UUID immediately after CD_uniqueID marker in the window.
        uniqueId ??= FindUuidAfterMarker(around, "CD_uniqueID"u8);

        var dateUtc = strings.Select(static s => IsoDateRegex.Match(s))
            .FirstOrDefault(static m => m.Success)?.Value;

        var deviceHint = strings.FirstOrDefault(static s =>
            s is "iPhone" or "iPad" or "Mac" or "Watch"
            || s.StartsWith("iPhone", StringComparison.Ordinal)
            || s.StartsWith("iPad", StringComparison.Ordinal));

        var hasAsset = strings.Any(static s =>
            s.Contains("ckAsset", StringComparison.OrdinalIgnoreCase)
            || s.Contains("content.icloud.com", StringComparison.OrdinalIgnoreCase)
            || s.StartsWith("CAog", StringComparison.Ordinal));

        results.Add(new ParsedRecord(
            recordName.ToUpperInvariant(),
            recordType,
            entityName,
            uniqueId?.ToUpperInvariant(),
            dateUtc,
            deviceHint,
            hasAsset,
            fieldNames));

        _ = markerLen;
    }

    private static string? FindUuidAfterMarker(ReadOnlySpan<byte> window, ReadOnlySpan<byte> marker)
    {
        var at = IndexOf(window, marker);
        if (at < 0)
            return null;
        var after = window[(at + marker.Length)..];
        var limit = Math.Min(after.Length, 256);
        return FindFirstUuid(after[..limit]);
    }

    private static string? FindLastUuid(ReadOnlySpan<byte> window)
    {
        var text = Encoding.UTF8.GetString(window);
        Match? last = null;
        foreach (Match m in UuidRegex.Matches(text))
            last = m;
        return last?.Groups[1].Value.ToUpperInvariant();
    }

    private static string? FindFirstUuid(ReadOnlySpan<byte> window)
    {
        var text = Encoding.UTF8.GetString(window);
        var m = UuidRegex.Match(text);
        return m.Success ? m.Groups[1].Value.ToUpperInvariant() : null;
    }

    private static IReadOnlyList<ParsedRecord> Deduplicate(List<ParsedRecord> records)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deduped = new List<ParsedRecord>();
        foreach (var rec in records)
        {
            var key = $"{rec.RecordType}:{rec.RecordName}";
            if (!seen.Add(key))
                continue;
            deduped.Add(rec);
        }

        return deduped;
    }

    private static List<string> ExtractAsciiStrings(ReadOnlySpan<byte> data, int maxLen)
    {
        var limit = Math.Min(data.Length, maxLen);
        var list = new List<string>();
        var i = 0;
        while (i < limit)
        {
            if (data[i] is >= 32 and < 127)
            {
                var start = i;
                while (i < limit && data[i] is >= 32 and < 127)
                    i++;
                if (i - start >= 2)
                    list.Add(Encoding.ASCII.GetString(data[start..i]));
            }
            else
            {
                i++;
            }
        }

        return list;
    }

    private static int IndexOf(byte[] haystack, ReadOnlySpan<byte> needle, int start)
    {
        for (var i = start; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.AsSpan(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack[i..].StartsWith(needle))
                return i;
        }

        return -1;
    }
}
