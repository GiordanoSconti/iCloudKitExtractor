using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Download;

/// <summary>
/// Host MMCS e validazione authorizeGet — indipendenti dal contenuto account;
/// derivati da session.Partition e metadati record.
/// </summary>
internal static class MmcsContentEndpoints
{
    /// <summary>
    ///  authorizeGet su <c>{partition}-content.icloud.com</c>; opzionale ContentBaseUrl
    /// per-record se non è il gateway generico.
    /// </summary>
    public static IReadOnlyList<string> BuildAuthorizeGetHosts(
        ICloudSession session,
        string? recordContentBaseUrl)
    {
        var hosts = new List<string>();
        if (!string.IsNullOrWhiteSpace(session.Partition))
            hosts.Add($"https://{session.Partition}-content.icloud.com");

        if (!string.IsNullOrWhiteSpace(recordContentBaseUrl))
        {
            var url = recordContentBaseUrl.TrimEnd('/');
            if (!url.Contains("gateway.icloud.com", StringComparison.OrdinalIgnoreCase)
                && !hosts.Contains(url, StringComparer.OrdinalIgnoreCase))
                hosts.Add(url);
        }

        return hosts;
    }

    /// <summary>
    /// Risposta authorizeGet incompleta se mancano chunk/firme o la somma range &lt; size dichiarato.
    /// </summary>
    public static bool IsAuthorizeGetIncomplete(
        IReadOnlyList<SignedUrlChunk> chunks,
        long? declaredSizeBytes)
    {
        if (chunks.Count == 0)
            return true;
        if (chunks.Any(static c => string.IsNullOrEmpty(c.Url)))
            return true;
        if (chunks.Any(static c => c.EdgeHeaders?.Signature is not { Length: > 0 }))
            return true;

        if (declaredSizeBytes is not > 0)
            return false;

        var rangeSum = chunks
            .Where(static c => c.ByteRange.HasValue)
            .Select(static c => (long)(c.ByteRange!.Value.End - c.ByteRange!.Value.Start + 1))
            .Sum();
        return rangeSum > 0 && rangeSum < declaredSizeBytes.Value;
    }
}
