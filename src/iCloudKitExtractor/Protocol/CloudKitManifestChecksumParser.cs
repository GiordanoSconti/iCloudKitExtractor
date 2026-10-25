using System.Text;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Estrae voci :CN:uuid:checksum da manifestChecksums nei record snapshot (mbksync).
/// non espone KA:/MA: in chiaro nel bootstrap; le UUID file compaiono come :CN:…
/// nelle catture (es. batch 512 KB, req 00062 in capture_http_20260706_070218).
/// </summary>
public static class CloudKitManifestChecksumParser
{
    private static readonly Regex CnEntryRegex = new(
        @":CN:([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}):([A-Za-z0-9+/=]{8,80})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly string[] ProbeTypes = ["JA", "KA", "LA", "MA", "A"];

    private static readonly int[] ProbeSizes =
    [
        2, 42, 80, 85, 92, 124, 139, 156, 544, 1039, 1408, 1426, 1709, 1738
    ];

    public sealed record CnEntry(string FileUuid, string ChecksumBase64);

    /// <summary>Nome catalogo stabile: <c>:CN:uuid:checksum</c> (senza size suffix).</summary>
    public static string ToCatalogRecordName(CnEntry entry) =>
        $":CN:{entry.FileUuid}:{entry.ChecksumBase64}";

    /// <summary>
    /// Record file-list / PreAuth  <c>N:uuid:checksum=:0</c> in <c>_defaultZone</c>.
    /// Cattura 134619: in ASCII grezzo sembra <c>EN:</c> perché la lunghezza protobuf del nome
    /// (69 = <c>0x45</c> = <c>'E'</c>) precede <c>N:</c>. Il nome vero è <c>N:</c>, non <c>EN:</c>
    /// (<c>EN:</c> → Record not found; <c>N:</c> → MB di auth/path come PreAuth).
    /// </summary>
    public static string ToEnRecordName(CnEntry entry) =>
        $"N:{entry.FileUuid.ToUpperInvariant()}:{CleanCnChecksum(entry.ChecksumBase64)}=:0";

    /// <summary>Ripristina il padding <c>=</c> richiesto dai record <c>EN:</c> sul wire.</summary>
    public static string PadBase64Checksum(string checksum)
    {
        if (string.IsNullOrWhiteSpace(checksum))
            return string.Empty;

        var value = checksum.Trim().TrimEnd('=');
        var pad = (4 - value.Length % 4) % 4;
        return pad == 0 ? value : value + new string('=', pad);
    }

    public static IReadOnlyList<CnEntry> ParseCnEntries(params byte[]?[] payloads)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var entries = new List<CnEntry>();

        foreach (var payload in payloads)
        {
            if (payload is not { Length: > 0 })
                continue;

            var text = Encoding.Latin1.GetString(payload);
            foreach (Match match in CnEntryRegex.Matches(text))
            {
                var uuid = match.Groups[1].Value.ToUpperInvariant();
                var hash = CleanCnChecksum(match.Groups[2].Value);
                if (string.IsNullOrWhiteSpace(hash))
                    continue;

                var key = $"{uuid}|{hash}";
                if (!seen.Add(key))
                    continue;

                entries.Add(new CnEntry(uuid, hash));
            }
        }

        return entries;
    }

    /// <summary>
    /// Catalogo file moderno: tutte le voci <c>:CN:</c> nello snapshot <c>S:</c>
    /// (incl. <c>domainBaseRecordIDs</c> / manifestChecksums).
    /// </summary>
    public static IReadOnlyList<CnEntry> ParseCatalogCnEntries(byte[]? snapshotPayload) =>
        ParseCnEntries(snapshotPayload);

    /// <summary>
    /// Voci <c>:CN:</c> per file list / <c>EN:</c>: preferisce <c>manifestChecksums</c>
    /// (UUID file) ed esclude <c>domainBaseRecordIDs</c> (UUID = snapshot).
    /// Se non ci sono UUID file, fallback a tutte le voci.
    /// </summary>
    public static IReadOnlyList<CnEntry> ParseFileCnEntries(
        byte[]? snapshotPayload,
        string? snapshotUuid = null)
    {
        var all = ParseCnEntries(snapshotPayload);
        if (all.Count == 0)
            return all;

        var snap = NormalizeSnapshotUuid(snapshotUuid);
        if (string.IsNullOrEmpty(snap))
        {
            // Heuristica: se un solo UUID domina l'intero set, è quasi certamente domainBase.
            var byUuid = all.GroupBy(static e => e.FileUuid, StringComparer.OrdinalIgnoreCase).ToList();
            if (byUuid.Count == 1)
                return all;
            var dominant = byUuid.OrderByDescending(static g => g.Count()).First();
            if (dominant.Count() == all.Count)
                return all;
            var withoutDominant = all
                .Where(e => !string.Equals(e.FileUuid, dominant.Key, StringComparison.OrdinalIgnoreCase))
                .ToList();
            return withoutDominant.Count > 0 ? withoutDominant : all;
        }

        var fileEntries = all
            .Where(e => !string.Equals(e.FileUuid, snap, StringComparison.OrdinalIgnoreCase))
            .ToList();
        return fileEntries.Count > 0 ? fileEntries : all;
    }

    /// <summary>Estrae UUID snapshot da <c>S:uuid</c> / <c>&amp;S:uuid</c> / UUID nudo.</summary>
    public static string? NormalizeSnapshotUuid(string? recordOrUuid)
    {
        if (string.IsNullOrWhiteSpace(recordOrUuid))
            return null;

        var s = recordOrUuid.Trim();
        if (s.StartsWith("&S:", StringComparison.OrdinalIgnoreCase))
            s = s[3..];
        else if (s.StartsWith("S:", StringComparison.OrdinalIgnoreCase))
            s = s[2..];

        var colon = s.IndexOf(':');
        if (colon > 0)
            s = s[..colon];

        return Guid.TryParse(s, out var g) ? g.ToString("D").ToUpperInvariant() : null;
    }

    /// <summary>
    /// Costruisce nomi record candidati per PrivilegedBatchRecordFetch (cold start senza cache iOS).
    /// </summary>
    public static IEnumerable<string> BuildProbeRecordNames(
        string devicePrefix4,
        IEnumerable<CnEntry> entries,
        int maxCandidates = 64)
    {
        if (string.IsNullOrWhiteSpace(devicePrefix4))
            yield break;

        var prefix = devicePrefix4.Length >= 4 ? devicePrefix4[..4] : devicePrefix4;
        var yielded = 0;

        foreach (var entry in entries)
        {
            yield return $":CN:{entry.FileUuid}:{entry.ChecksumBase64}";
            yield return $"CN:{prefix}:{entry.FileUuid}:{entry.ChecksumBase64}";

            foreach (var type in ProbeTypes)
            {
                foreach (var size in ProbeSizes)
                {
                    yield return $"{type}:{prefix}:{entry.FileUuid}:{entry.ChecksumBase64}:{size}";
                    if (++yielded >= maxCandidates)
                        yield break;
                }

                if (yielded >= maxCandidates)
                    yield break;
            }

            if (yielded >= maxCandidates)
                yield break;
        }
    }

    public static string CleanCnChecksum(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return string.Empty;

        var value = raw.Trim();
        if (value.EndsWith("ZG", StringComparison.Ordinal))
            value = value[..^2];
        return value.TrimEnd('=');
    }
}
