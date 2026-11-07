using System.Text;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Estrae record Core Data CloudKit Voice Memos e device da <c>metadata_zone</c>
/// dai payload <c>record/sync</c>.
/// </summary>
public static class VoiceMemosSyncRecordParser
{
    private static readonly Regex UuidRegex = new(
        @"\b([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})\b",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex IsoDateRegex = new(
        @"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex MetadataDeviceRegex = new(
        @"metadata_device_([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly Regex OsTripleRegex = new(
        @"<(iOS|iPadOS|macOS|watchOS);([^;<>]+);([^;<>]+)>",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly HashSet<string> KnownTypes = new(StringComparer.Ordinal)
    {
        "CD_CloudRecording",
        "CD_Migration",
        "CD_Folder",
        "CD_SavedRecording",
    };

    private static readonly HashSet<string> DeviceClasses = new(StringComparer.Ordinal)
    {
        "iPhone", "iPad", "Mac", "Watch", "AppleTV", "Vision",
    };

    public sealed record ParsedRecord(
        string RecordName,
        string RecordType,
        string? EntityName,
        string? UniqueId,
        string? DateUtc,
        string? DeviceHint,
        double? DurationSeconds,
        bool HasCkAsset,
        IReadOnlyList<string> FieldNames,
        int Offset);

    public sealed record ParsedMetadataDevice(
        string DeviceId,
        string RecordName,
        string? OsType,
        string? OsVersion,
        string? OsBuild,
        string? DeviceClass,
        string? SoftwareBundleId);

    public static IReadOnlyList<ParsedRecord> ParseRecords(byte[] payload)
    {
        if (payload is not { Length: > 64 })
            return [];

        var results = new List<ParsedRecord>();
        foreach (var type in KnownTypes)
            ScanTypedRecords(payload, type, results);

        return Deduplicate(results);
    }

    public static IReadOnlyList<ParsedMetadataDevice> ParseMetadataDevices(byte[] payload)
    {
        if (payload is not { Length: > 64 })
            return [];

        var text = Encoding.ASCII.GetString(payload);
        var matches = MetadataDeviceRegex.Matches(text);
        if (matches.Count == 0)
            return [];

        // First occurrence wins; later duplicates of the same UUID are ignored.
        var order = new List<(string Id, int Index)>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in matches)
        {
            var id = m.Groups[1].Value.ToUpperInvariant();
            if (!seen.Add(id))
                continue;
            order.Add((id, m.Index));
        }

        var meta = new Dictionary<string, (string? OsType, string? OsVersion, string? OsBuild, string? DeviceClass, string? Bundle)>(
            StringComparer.OrdinalIgnoreCase);

        string? NearestDevice(int pos)
        {
            string? best = null;
            var bestDist = int.MaxValue;
            foreach (var (id, index) in order)
            {
                if (index > pos)
                    continue;
                var dist = pos - index;
                if (dist < bestDist)
                {
                    bestDist = dist;
                    best = id;
                }
            }

            return bestDist <= 1200 ? best : null;
        }

        void Set(string id, string? osType, string? osVersion, string? osBuild, string? deviceClass, string? bundle)
        {
            meta.TryGetValue(id, out var cur);
            meta[id] = (
                osType ?? cur.OsType,
                osVersion ?? cur.OsVersion,
                osBuild ?? cur.OsBuild,
                deviceClass ?? cur.DeviceClass,
                bundle ?? cur.Bundle);
        }

        foreach (Match t in OsTripleRegex.Matches(text))
        {
            var id = NearestDevice(t.Index);
            if (id is null)
                continue;
            Set(id, t.Groups[1].Value, t.Groups[3].Value.Trim(), t.Groups[2].Value.Trim(), null, null);
        }

        // Labels DeviceOSBuild / DeviceOSVersionNumber often sit just before the values.
        for (var i = 0; i < text.Length;)
        {
            var buildAt = text.IndexOf("DeviceOSBuild", i, StringComparison.Ordinal);
            if (buildAt < 0)
                break;
            var id = NearestDevice(buildAt);
            var window = text.Substring(buildAt, Math.Min(160, text.Length - buildAt));
            var build = Regex.Match(window, @"DeviceOSBuild[^\w]*([0-9][0-9A-Za-z.]{2,15})");
            var ver = Regex.Match(window, @"DeviceOSVersionNumber[^\w]*([0-9][0-9.]{1,15})");
            if (id is not null && (build.Success || ver.Success))
                Set(id, "iOS",
                    ver.Success ? ver.Groups[1].Value : null,
                    build.Success ? build.Groups[1].Value : null,
                    null, null);
            i = buildAt + 12;
        }

        foreach (var cls in DeviceClasses)
        {
            var idx = 0;
            while ((idx = text.IndexOf(cls, idx, StringComparison.Ordinal)) >= 0)
            {
                var id = NearestDevice(idx);
                if (id is not null)
                    Set(id, null, null, null, cls, null);
                idx += cls.Length;
            }
        }

        foreach (var bundle in new[] { "com.apple.voicememod", "com.apple.VoiceMemos" })
        {
            var idx = 0;
            while ((idx = text.IndexOf(bundle, idx, StringComparison.Ordinal)) >= 0)
            {
                var id = NearestDevice(idx);
                if (id is not null)
                    Set(id, null, null, null, null, bundle);
                idx += bundle.Length;
            }
        }

        return order.Select(d =>
            {
                meta.TryGetValue(d.Id, out var m);
                return new ParsedMetadataDevice(
                    d.Id,
                    $"metadata_device_{d.Id}",
                    m.OsType,
                    m.OsVersion,
                    m.OsBuild,
                    m.DeviceClass,
                    m.Bundle);
            })
            .OrderByDescending(static d => d.OsVersion ?? "")
            .ThenBy(static d => d.DeviceId, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void ScanTypedRecords(byte[] payload, string recordType, List<ParsedRecord> results)
    {
        var marker = Encoding.ASCII.GetBytes(recordType + "\"%");
        var start = 0;
        while (start <= payload.Length - marker.Length)
        {
            var at = IndexOf(payload, marker, start);
            if (at < 0)
                break;

            var next = FindNextRecordMarker(payload, at + marker.Length);
            var bodyEnd = next < 0 ? Math.Min(payload.Length, at + 1600) : next;
            // Record name UUID sits just before the type marker.
            var nameWindowStart = Math.Max(0, at - 220);
            var recordName = FindLastUuid(payload.AsSpan(nameWindowStart, at - nameWindowStart));
            if (string.IsNullOrWhiteSpace(recordName))
            {
                start = at + marker.Length;
                continue;
            }

            var body = payload.AsSpan(at, bodyEnd - at);
            var fieldNames = ExtractFieldNames(body, recordType);
            var isRecording = recordType.Contains("CloudRecording", StringComparison.Ordinal)
                              || recordType.Contains("SavedRecording", StringComparison.Ordinal);

            var entityName = ExtractTypedStringAfterField(body, "CD_entityName"u8)
                             ?? (recordType == "CD_CloudRecording" ? "CloudRecording"
                                 : recordType == "CD_Migration" ? "Migration"
                                 : null);
            // Strip accidental protobuf tail glued to ASCII runs ("MigrationJ%", "iPhonej").
            entityName = CleanToken(entityName);

            // Value is a type=3 string (36-char UUID); trailing protobuf bytes may glue as "…88J%".
            var uniqueId = isRecording
                ? (ExtractTypedStringAfterField(body, "CD_uniqueID"u8)
                   ?? ExtractUuidAfterField(body, "CD_uniqueID"u8))
                : null;
            if (uniqueId is not null && !UuidRegex.IsMatch(uniqueId))
                uniqueId = UuidRegex.Match(uniqueId) is { Success: true } um
                    ? um.Groups[1].Value.ToUpperInvariant()
                    : null;
            var dateUtc = ExtractIsoDate(body);
            var deviceHint = ExtractDeviceClass(body);
            var duration = isRecording ? ExtractDurationSeconds(body) : null;
            var hasAsset = isRecording
                           && (fieldNames.Contains("CD_versionedAudioFuture_ckAsset", StringComparer.Ordinal)
                               || ContainsAscii(body, "CD_versionedAudioFuture_ckAsset"u8)
                               || ContainsAscii(body, "content.icloud.com"u8));

            // Migration / non-recording must never inherit asset flags from a neighbour.
            if (!isRecording)
            {
                hasAsset = false;
                uniqueId = null;
                duration = null;
                var bodyBytes = body.ToArray();
                fieldNames = fieldNames
                    .Where(static f => f is "CD_date" or "CD_flags" or "CD_entityName")
                    .Where(f => ContainsAscii(bodyBytes, Encoding.ASCII.GetBytes(f)))
                    .Distinct(StringComparer.Ordinal)
                    .ToList();
            }

            results.Add(new ParsedRecord(
                recordName.ToUpperInvariant(),
                recordType,
                entityName,
                uniqueId?.ToUpperInvariant(),
                dateUtc,
                deviceHint,
                duration,
                hasAsset,
                fieldNames,
                at));

            start = at + marker.Length;
        }
    }

    private static int FindNextRecordMarker(byte[] payload, int from)
    {
        var best = -1;
        foreach (var type in KnownTypes)
        {
            var marker = Encoding.ASCII.GetBytes(type + "\"%");
            var at = IndexOf(payload, marker, from);
            if (at >= 0 && (best < 0 || at < best))
                best = at;
        }

        return best;
    }

    private static List<string> ExtractFieldNames(ReadOnlySpan<byte> body, string recordType)
    {
        var strings = ExtractAsciiStrings(body, body.Length);
        var fields = strings
            .Where(static s => s.StartsWith("CD_", StringComparison.Ordinal)
                               && s.Length is >= 4 and <= 64
                               && s.All(static c => char.IsLetterOrDigit(c) || c == '_'))
            .Distinct(StringComparer.Ordinal)
            .ToList();

        // Drop the record-type token itself if it leaked in.
        fields.RemoveAll(f => f.Equals(recordType, StringComparison.Ordinal));
        return fields;
    }

    /// <summary>
    /// Core Data string field on wire: after name, <c>08 03 3a &lt;len&gt; &lt;bytes&gt;</c>.
    /// </summary>
    private static string? ExtractTypedStringAfterField(ReadOnlySpan<byte> body, ReadOnlySpan<byte> fieldName)
    {
        var at = IndexOf(body, fieldName);
        if (at < 0)
            return null;
        var after = body[(at + fieldName.Length)..];
        var limit = Math.Min(after.Length - 4, 96);
        for (var i = 0; i < limit; i++)
        {
            if (after[i] != 0x08 || after[i + 1] != 0x03 || after[i + 2] != 0x3a)
                continue;
            var len = after[i + 3];
            if (len is 0 or > 80 || i + 4 + len > after.Length)
                continue;
            var s = Encoding.ASCII.GetString(after.Slice(i + 4, len));
            return CleanToken(s);
        }

        return null;
    }

    private static string? ExtractUuidAfterField(ReadOnlySpan<byte> body, ReadOnlySpan<byte> fieldName)
    {
        var at = IndexOf(body, fieldName);
        if (at < 0)
            return null;
        var after = body[(at + fieldName.Length)..];
        var limit = Math.Min(after.Length, 160);
        // No trailing \b: wire often continues with a letter tag ("…88J%").
        var loose = new Regex(
            @"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        var m = loose.Match(Encoding.ASCII.GetString(after[..limit]));
        return m.Success ? m.Groups[1].Value.ToUpperInvariant() : null;
    }

    private static string? CleanToken(string? s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return null;
        s = s.Trim();
        // Cut at first non identifier char (protobuf tags glued as "MigrationJ%" / "iPhonej").
        var end = 0;
        while (end < s.Length && (char.IsLetterOrDigit(s[end]) || s[end] is '_' or '-' or '.'))
            end++;
        if (end == 0)
            return null;
        return s[..end];
    }

    private static string? ExtractIsoDate(ReadOnlySpan<byte> body)
    {
        var text = Encoding.ASCII.GetString(body);
        var m = IsoDateRegex.Match(text);
        return m.Success ? m.Value : null;
    }

    private static string? ExtractDeviceClass(ReadOnlySpan<byte> body)
    {
        // Wire: … Z <len=6> iPhone <next tag 'j'> — follower is often a letter-looking tag.
        foreach (var name in DeviceClasses)
        {
            var needle = Encoding.ASCII.GetBytes(name);
            var at = IndexOf(body, needle);
            if (at < 0)
                continue;
            if (at > 0 && body[at - 1] == needle.Length)
                return name;
            var end = at + needle.Length;
            if (end >= body.Length || !char.IsLetter((char)body[end]))
                return name;
        }

        return null;
    }

    private static double? ExtractDurationSeconds(ReadOnlySpan<byte> body)
    {
        var field = "CD_duration"u8;
        var at = IndexOf(body, field);
        if (at < 0)
            return null;

        // Wire: CD_duration … tag with wire=1 (fixed64), e.g. 0x29, then double LE.
        var after = body[(at + field.Length)..];
        Span<byte> tmp = stackalloc byte[8];
        for (var i = 0; i < Math.Min(after.Length - 9, 64); i++)
        {
            var tag = after[i];
            if ((tag & 0x07) != 1)
                continue;
            after.Slice(i + 1, 8).CopyTo(tmp);
            var value = BitConverter.ToDouble(tmp);
            if (double.IsFinite(value) && value is > 0 and < 86_400 * 7)
                return Math.Round(value, 3);
        }

        return null;
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

    private static string? FindLastUuid(ReadOnlySpan<byte> window)
    {
        var text = Encoding.ASCII.GetString(window);
        Match? last = null;
        foreach (Match m in UuidRegex.Matches(text))
            last = m;
        return last?.Groups[1].Value.ToUpperInvariant();
    }

    private static bool ContainsAscii(ReadOnlySpan<byte> hay, ReadOnlySpan<byte> needle) =>
        IndexOf(hay, needle) >= 0;

    private static bool ContainsAscii(byte[] hay, ReadOnlySpan<byte> needle) =>
        IndexOf((ReadOnlySpan<byte>)hay, needle) >= 0;

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
