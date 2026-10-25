using System.Text;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Catalogo file backup CloudKit classico (InflatableDonkey / iOS9 POC):
/// <c>S:</c> → <c>manifestIDs</c> → record <c>M:…:0</c> → campo <c>files</c>.
/// Il path moderno (<c>:CN:</c>) è in <see cref="CloudKitManifestChecksumParser"/>.
/// </summary>
public static class CloudKitManifestCatalogParser
{
    /// <summary><c>M:&lt;uuid&gt;:&lt;hmacBase64&gt;</c> (senza suffisso <c>:0</c>).</summary>
    private static readonly Regex ManifestIdRegex = new(
        @"M:[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}:[A-Za-z0-9+/=_-]{8,96}",
        RegexOptions.Compiled);

    /// <summary>Riferimenti file nel campo <c>files</c> (F:/KA:/MA:/…).</summary>
    private static readonly Regex FileRecordRegex = new(
        @"(?:F|KA|MA|LA|NA|JA|A):[^\s\x00-\x1f""]{8,320}",
        RegexOptions.Compiled);

    /// <summary>
    /// Estrae gli ID manifest dal payload snapshot <c>S:</c> (campo <c>manifestIDs</c>).
    /// </summary>
    public static IReadOnlyList<string> ExtractManifestIds(byte[]? snapshotPayload)
    {
        if (snapshotPayload is not { Length: > 0 })
            return [];

        var text = Encoding.Latin1.GetString(snapshotPayload);
        var region = SliceAfterMarker(text, "manifestIDs", maxChars: 512_000)
                     ?? text;

        var ids = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in ManifestIdRegex.Matches(region))
        {
            var id = NormalizeManifestId(m.Value);
            if (id is not null)
                ids.Add(id);
        }

        // Fallback: tutto il payload se la finestra dopo il marker è vuota.
        if (ids.Count == 0 && !ReferenceEquals(region, text))
        {
            foreach (Match m in ManifestIdRegex.Matches(text))
            {
                var id = NormalizeManifestId(m.Value);
                if (id is not null)
                    ids.Add(id);
            }
        }

        return ids.OrderBy(static s => s, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// Nome record CloudKit da fetchare: <c>M:uuid:hash:0</c> in <c>_defaultZone</c>.
    /// </summary>
    public static string ToManifestRecordName(string manifestId)
    {
        var id = NormalizeManifestId(manifestId) ?? manifestId.Trim();
        return id.EndsWith(":0", StringComparison.Ordinal) ? id : id + ":0";
    }

    /// <summary>
    /// Estrae i nomi record file dal payload del record <c>M:…:0</c> (campo <c>files</c>).
    /// </summary>
    public static IReadOnlyList<string> ExtractFileRecordNames(byte[]? manifestRecordPayload)
    {
        if (manifestRecordPayload is not { Length: > 0 })
            return [];

        var text = Encoding.Latin1.GetString(manifestRecordPayload);
        // Preferisci la regione dopo il marker di campo "files" (non "fileChecksum" ecc.).
        var region = SliceAfterFieldName(text, "files", maxChars: 2_000_000) ?? text;

        var names = new HashSet<string>(StringComparer.Ordinal);
        foreach (Match m in FileRecordRegex.Matches(region))
        {
            var name = m.Value.Trim();
            if (name.StartsWith("M:", StringComparison.Ordinal))
                continue;
            names.Add(name);
        }

        if (names.Count == 0 && !ReferenceEquals(region, text))
        {
            foreach (Match m in FileRecordRegex.Matches(text))
            {
                var name = m.Value.Trim();
                if (name.StartsWith("M:", StringComparison.Ordinal))
                    continue;
                names.Add(name);
            }
        }

        return names
            .OrderBy(static n => FilePriority(n))
            .ThenBy(static n => n, StringComparer.Ordinal)
            .ToList();
    }

    private static string? NormalizeManifestId(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var id = raw.Trim();
        // Match regex può includere caratteri di confini; taglia a M:…:hash
        var m = ManifestIdRegex.Match(id);
        if (!m.Success)
            return null;
        id = m.Value;
        while (id.EndsWith(":0", StringComparison.Ordinal))
            id = id[..^2];
        return id;
    }

    private static string? SliceAfterMarker(string text, string marker, int maxChars)
    {
        var idx = text.IndexOf(marker, StringComparison.Ordinal);
        if (idx < 0)
            return null;
        var start = idx + marker.Length;
        var len = Math.Min(maxChars, text.Length - start);
        return len <= 0 ? null : text.Substring(start, len);
    }

    /// <summary>
    /// Cerca il nome campo protobuf come token (evita sottostringhe tipo fileChecksum).
    /// </summary>
    private static string? SliceAfterFieldName(string text, string fieldName, int maxChars)
    {
        var searchFrom = 0;
        while (searchFrom < text.Length)
        {
            var idx = text.IndexOf(fieldName, searchFrom, StringComparison.Ordinal);
            if (idx < 0)
                return null;

            var beforeOk = idx == 0 || !IsIdentChar(text[idx - 1]);
            var after = idx + fieldName.Length;
            var afterOk = after >= text.Length || !IsIdentChar(text[after]);
            if (beforeOk && afterOk)
            {
                var len = Math.Min(maxChars, text.Length - after);
                return len <= 0 ? null : text.Substring(after, len);
            }

            searchFrom = idx + 1;
        }

        return null;
    }

    private static bool IsIdentChar(char c) =>
        char.IsLetterOrDigit(c) || c is '_' or '-';

    private static int FilePriority(string name)
    {
        if (name.StartsWith("F:", StringComparison.Ordinal)) return 0;
        if (name.StartsWith("KA:", StringComparison.Ordinal)) return 1;
        if (name.StartsWith("MA:", StringComparison.Ordinal)) return 2;
        if (name.StartsWith("A:", StringComparison.Ordinal)) return 3;
        return 4;
    }
}
