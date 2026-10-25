using System.Text.RegularExpressions;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

public static class MbsManifestParser
{
    private static readonly Regex AssetRecordRegex = new(
        @"^(?:KA|MA|LA|NA|JA|A):[^\s\x00-\x1f]{8,320}$",
        RegexOptions.Compiled);

    public static IReadOnlyList<string> ExtractAssetRecordNames(byte[]? manifest, int maxRecords = 50_000)
    {
        if (manifest is not { Length: > 0 })
            return [];

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in ProtobufStringScanner.ExtractAsciiRuns(manifest, 8))
        {
            if (!AssetRecordRegex.IsMatch(s))
                continue;
            names.Add(s);
            if (names.Count >= maxRecords)
                break;
        }

        return names
            .OrderBy(static n => Priority(n))
            .ThenBy(static n => n, StringComparer.Ordinal)
            .ToList();
    }

    private static int Priority(string recordName)
    {
        if (recordName.StartsWith("KA:", StringComparison.Ordinal)) return 0;
        if (recordName.StartsWith("MA:", StringComparison.Ordinal)) return 1;
        if (recordName.StartsWith("LA:", StringComparison.Ordinal)) return 2;
        return 3;
    }
}
