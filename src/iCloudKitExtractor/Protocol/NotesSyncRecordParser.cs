using System.Text;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Estrae record Note/Folder dal payload <c>record/sync</c> Notes (CloudKit delimited).
/// </summary>
public static class NotesSyncRecordParser
{
    private static readonly Regex UuidRegex = new(
        @"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>
    /// Record name compositi share/device overlay — non sono recuperabili col solo UUID finale.
    /// </summary>
    private static readonly Regex UserSpecificNameRegex = new(
        @"(Note_UserSpecific|Attachment_UserSpecific|Folder_UserSpecific)::(" +
        @"_[0-9a-fA-F]+/Private::Notes::_[0-9a-fA-F]+::" +
        @"[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    private static readonly HashSet<string> SkipStrings = new(StringComparer.Ordinal)
    {
        "Note", "Folder", "Notes", "Hashtag", "Attachment", "CreationDate", "ModificationDate",
        "FoldersModificationDate", "Folders", "Deleted", "iPhone", "IsPinned", "IsSystemPaper",
        "PaperStyleType", "AttachmentViewType", "NoteUUID", "MinimumSupportedNotesVersion",
        "Note_UserSpecific", "Attachment_UserSpecific", "Folder_UserSpecific",
    };

    public sealed record ParsedRecord(
        string RecordName,
        string RecordType,
        string? FolderKey,
        string? TitleHint,
        string? FolderHashId);

    public static IReadOnlyList<ParsedRecord> ParseRecords(byte[] payload)
    {
        if (payload is not { Length: > 64 })
            return [];

        var results = new List<ParsedRecord>();
        // Marker "Note\"%" non matcha Note_UserSpecific — UUID UserSpecific arrivavano
        // solo perché FindLastUuid prendeva l'UUID successivo nella finestra (falso positivo).
        ScanMarker(payload, "Note\"%"u8, "Note", results);
        ScanMarker(payload, "Folder\"%"u8, "Folder", results);
        ScanMarker(payload, "Hashtag\"%"u8, "Hashtag", results);
        ScanMarker(payload, "Attachment\"%"u8, "Attachment", results);
        ScanUserSpecificNames(payload, results);

        return Deduplicate(results);
    }

    /// <summary>
    /// UUID da usare in <c>record/retrieve</c>: solo Note/Folder/Hashtag/Attachment
    /// con record name = UUID. Esclude overlay <c>*_UserSpecific::…</c> (nome composto).
    /// </summary>
    public static IReadOnlyList<string> RetrieveRecordNames(byte[] payload) =>
        ParseRecords(payload)
            .Where(static r =>
                r.RecordType is "Note" or "Folder" or "Hashtag" or "Attachment"
                && UuidRegex.IsMatch(r.RecordName)
                && r.RecordName.Length == 36)
            .Select(static r => r.RecordName)
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

    private static void ScanUserSpecificNames(byte[] payload, List<ParsedRecord> results)
    {
        var text = Encoding.UTF8.GetString(payload);
        foreach (Match m in UserSpecificNameRegex.Matches(text))
        {
            var type = m.Groups[1].Value;
            var fullName = m.Value; // Type::owner/Private::Notes::owner::UUID
            results.Add(new ParsedRecord(fullName, type, null, null, null));
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

            // UUID del record è tipicamente PRIMA del type marker — non dopo
            // (dopo spesso c'è un Note_UserSpecific::…::UUID vicino → ck1onjkgg).
            var lookback = Math.Min(at, 256);
            var recordName = FindUuidClosestToEnd(payload.AsSpan(at - lookback, lookback));
            var windowEnd = Math.Min(payload.Length, at + 1536);
            var strings = ExtractAsciiStrings(payload.AsSpan(at, windowEnd - at), maxLen: 4000);

            var folderKey = strings.FirstOrDefault(static s =>
                s.StartsWith("Folder_UserSpecific", StringComparison.Ordinal)
                || s is "DefaultFolder-CloudKit" or "TrashFolder-CloudKit"
                || s.EndsWith("Folder-CloudKit", StringComparison.Ordinal));

            var folderHash = strings.FirstOrDefault(static s =>
                s.Length == 40 && s.All(static c => c is >= '0' and <= '9' or >= 'A' and <= 'F' or >= 'a' and <= 'f'));

            var titleHint = strings.FirstOrDefault(s =>
                !SkipStrings.Contains(s)
                && !s.StartsWith("Folder_", StringComparison.Ordinal)
                && !s.StartsWith("Note_", StringComparison.Ordinal)
                && !s.StartsWith("Attachment_", StringComparison.Ordinal)
                && !s.StartsWith("!_", StringComparison.Ordinal)
                && !s.StartsWith("$", StringComparison.Ordinal)
                && !s.Contains("Encrypted", StringComparison.Ordinal)
                && !UuidRegex.IsMatch(s)
                && s.Length is >= 2 and <= 256);

            if (!string.IsNullOrWhiteSpace(recordName))
            {
                results.Add(new ParsedRecord(
                    recordName.ToUpperInvariant(),
                    recordType,
                    folderKey,
                    titleHint,
                    folderHash));
            }

            start = at + marker.Length;
        }
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

    /// <summary>UUID più vicino alla fine dello span (= più vicino al type marker).</summary>
    private static string? FindUuidClosestToEnd(ReadOnlySpan<byte> window)
    {
        if (window.IsEmpty)
            return null;
        var text = Encoding.UTF8.GetString(window);
        Match? last = null;
        foreach (Match m in UuidRegex.Matches(text))
        {
            // Evita UUID che sono solo coda di *UserSpecific::…::UUID nello stesso lookback.
            var before = text[..m.Index];
            if (before.Contains("UserSpecific::", StringComparison.Ordinal))
            {
                var us = before.LastIndexOf("UserSpecific::", StringComparison.Ordinal);
                var slice = before[us..];
                if (slice.Contains("Private::Notes::", StringComparison.Ordinal))
                    continue;
            }

            last = m;
        }

        return last?.Groups[1].Value.ToUpperInvariant();
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
}
