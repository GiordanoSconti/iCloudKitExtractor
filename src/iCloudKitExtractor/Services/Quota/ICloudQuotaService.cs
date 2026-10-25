using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Quota;

/// <summary>
/// Read-only Quota iCloud (<c>getQuotaInfo</c>, <c>storageUsageInfo</c>, <c>storageUsageDetails</c>).
/// Auth  <c>Basic dsid:MobileMeAuthToken</c> (+ anisette sessione).
/// </summary>
public sealed class ICloudQuotaService
{
    private readonly HttpClient _http;

    public ICloudQuotaService(HttpClient http) => _http = http;

    public async Task<string> FetchDetailsTextAsync(
        ICloudSession session,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Sessione senza DSID.");

        var secret = SessionMmeAuth.ResolveSecret(session);
        if (string.IsNullOrWhiteSpace(secret))
        {
            throw new InvalidOperationException(
                "Manca secret Quota (MobileMeAuthToken / AppleCloudKitContext / gs.icloud.auth).");
        }

        var baseUrl = ResolveQuotaBaseUrl(session);
        session.Anisette.TouchClientTimeUtc();

        var infoPlist = await SendAsync(
            HttpMethod.Get, $"{baseUrl}/getQuotaInfo", session, secret, body: null, ct)
            .ConfigureAwait(false);

        var usageJson = await SendAsync(
            HttpMethod.Post, $"{baseUrl}/storageUsageInfo", session, secret, body: Array.Empty<byte>(), ct)
            .ConfigureAwait(false);

        var detailsJson = await SendAsync(
            HttpMethod.Post, $"{baseUrl}/storageUsageDetails", session, secret, body: Array.Empty<byte>(), ct)
            .ConfigureAwait(false);

        return FormatSummary(infoPlist, usageJson, detailsJson, session.Dsid, baseUrl);
    }

    internal static string ResolveQuotaBaseUrl(ICloudSession session)
    {
        foreach (var key in new[]
                 {
                     "Quota.quotaInfoURL",
                     "com.apple.Dataclass.Quota.quotaInfoURL",
                     "Quota.storageInfoURL",
                     "com.apple.Dataclass.Quota.storageInfoURL",
                 })
        {
            if (session.DataclassServiceUrls.TryGetValue(key, out var url)
                && !string.IsNullOrWhiteSpace(url)
                && TryStripQuotaLeaf(url, out var bas))
                return bas;
        }

        foreach (var kv in session.DataclassServiceUrls)
        {
            if (kv.Key.Contains("Quota", StringComparison.OrdinalIgnoreCase)
                && kv.Value.Contains("/quotaservice/", StringComparison.OrdinalIgnoreCase)
                && TryStripQuotaLeaf(kv.Value, out var bas))
                return bas;
        }

        var partition = string.IsNullOrWhiteSpace(session.Partition) ? "p116" : session.Partition.Trim();
        if (!partition.StartsWith('p'))
            partition = "p" + partition;
        return $"https://{partition}-quota.icloud.com/quotaservice/external/ios/{session.Dsid.Trim()}";
    }

    private static bool TryStripQuotaLeaf(string url, out string baseUrl)
    {
        baseUrl = url.Trim().TrimEnd('/');
        // togli :443 se presente
        baseUrl = baseUrl.Replace(":443/", "/", StringComparison.Ordinal);
        foreach (var leaf in new[]
                 {
                     "/getQuotaInfo", "/storageUsageInfo", "/storageUsageDetails",
                     "/storageAppList", "/getManageCloudStorage", "/fetchOffers",
                 })
        {
            if (baseUrl.EndsWith(leaf, StringComparison.OrdinalIgnoreCase))
            {
                baseUrl = baseUrl[..^leaf.Length];
                return true;
            }
        }

        var idx = baseUrl.IndexOf("/quotaservice/external/ios/", StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
        {
            var after = baseUrl[(idx + "/quotaservice/external/ios/".Length)..];
            var slash = after.IndexOf('/');
            if (slash < 0)
            {
                // already base …/ios/{dsid}
                return true;
            }

            baseUrl = baseUrl[..(idx + "/quotaservice/external/ios/".Length + slash)];
            return true;
        }

        return false;
    }

    private async Task<string> SendAsync(
        HttpMethod method,
        string url,
        ICloudSession session,
        string secret,
        byte[]? body,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, url);
        if (body is not null)
        {
            request.Content = new ByteArrayContent(body);
            request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/json");
            request.Content.Headers.ContentLength = body.Length;
        }

        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic",
            AppleHttpExtensions.BasicAuth(session.Dsid, secret));
        session.Anisette.TouchClientTimeUtc();
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);
        if (!string.IsNullOrEmpty(session.Anisette.MdLu))
            request.Headers.TryAddWithoutValidation("X-Apple-I-MD-LU", session.Anisette.MdLu);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var preview = text.Length > 240 ? text[..240] : text;
            throw new InvalidOperationException(
                $"Quota {method} {url[(url.LastIndexOf('/') + 1)..]} HTTP {(int)response.StatusCode}: {preview}");
        }

        return text;
    }

    private static string FormatSummary(
        string infoPlist,
        string usageJson,
        string detailsJson,
        string dsid,
        string baseUrl)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Spazio iCloud (Quota) ===");
        sb.AppendLine($"DSID: {dsid}");
        sb.AppendLine($"Base: {baseUrl}");
        sb.AppendLine();

        AppendUsageInfoJson(sb, usageJson);
        sb.AppendLine();
        AppendDetailsJson(sb, detailsJson);

        // getQuotaInfo plist: solo se JSON usage non ha dato i totali
        if (!usageJson.Contains("usedStorageInBytes", StringComparison.Ordinal))
        {
            sb.AppendLine();
            sb.AppendLine("--- getQuotaInfo (raw excerpt) ---");
            sb.AppendLine(infoPlist.Length > 800 ? infoPlist[..800] + "…" : infoPlist.Trim());
        }

        return sb.ToString().TrimEnd();
    }

    private static void AppendUsageInfoJson(StringBuilder sb, string json)
    {
        sb.AppendLine("--- Riepilogo ---");
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("storageUsageInfo", out var info))
            {
                var used = GetLong(info, "usedStorageInBytes");
                var total = GetLong(info, "totalStorageInBytes");
                var commerce = GetLong(info, "commerceStorageInBytes");
                sb.AppendLine($"Usato:     {FormatBytes(used)}");
                sb.AppendLine($"Totale:    {FormatBytes(total)}");
                if (commerce > 0)
                    sb.AppendLine($"Piano:     {FormatBytes(commerce)}");
                if (total > 0)
                    sb.AppendLine($"Libero:    {FormatBytes(Math.Max(0, total - used))}");
            }

            if (root.TryGetProperty("quotaStatus", out var st))
            {
                sb.AppendLine(
                    $"Stato:     overQuota={GetBool(st, "overQuota")}  paidQuota={GetBool(st, "paidQuota")}");
            }

            if (root.TryGetProperty("storageUsageByMedia", out var media)
                && media.ValueKind == JsonValueKind.Array)
            {
                sb.AppendLine();
                sb.AppendLine("Per categoria:");
                foreach (var item in media.EnumerateArray())
                {
                    var label = item.TryGetProperty("displayLabel", out var l) ? l.GetString() : null;
                    label ??= item.TryGetProperty("mediaKey", out var k) ? k.GetString() : "?";
                    var bytes = GetLong(item, "usageInBytes");
                    sb.AppendLine($"  • {label}: {FormatBytes(bytes)}");
                }
            }
        }
        catch (JsonException)
        {
            sb.AppendLine("(storageUsageInfo non JSON — omesso)");
        }
    }

    private static void AppendDetailsJson(StringBuilder sb, string json)
    {
        sb.AppendLine("--- Dettaglio ---");
        if (string.IsNullOrWhiteSpace(json))
        {
            sb.AppendLine("(vuoto)");
            return;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (root.TryGetProperty("backups", out var backups) && backups.ValueKind == JsonValueKind.Array)
            {
                sb.AppendLine("Backup:");
                foreach (var b in backups.EnumerateArray())
                {
                    var name = b.TryGetProperty("name", out var n) ? n.GetString()
                        : b.TryGetProperty("deviceName", out var d) ? d.GetString() : "device";
                    sb.AppendLine($"  • {name}: {FormatBytes(GetLong(b, "storageUsedInBytes"))}");
                }
            }

            if (root.TryGetProperty("photo", out var photo) && photo.ValueKind == JsonValueKind.Array)
            {
                sb.AppendLine("Foto:");
                foreach (var p in photo.EnumerateArray())
                {
                    var name = p.TryGetProperty("name", out var n) ? n.GetString() : "Photos";
                    sb.AppendLine($"  • {name}: {FormatBytes(GetLong(p, "storageUsedInBytes"))}");
                }
            }

            if (root.TryGetProperty("documentSets", out var docs) && docs.ValueKind == JsonValueKind.Array)
            {
                sb.AppendLine("Documenti / app:");
                var items = docs.EnumerateArray()
                    .Select(d => (
                        Name: d.TryGetProperty("name", out var n) ? n.GetString() ?? "?" : "?",
                        Bytes: GetLong(d, "storageUsedInBytes")))
                    .OrderByDescending(x => x.Bytes)
                    .ToList();
                foreach (var (name, bytes) in items.Take(20))
                    sb.AppendLine($"  • {name}: {FormatBytes(bytes)}");
                if (items.Count > 20)
                    sb.AppendLine($"  … +{items.Count - 20} altri");
            }

            if (root.TryGetProperty("mail", out var mail) && mail.ValueKind == JsonValueKind.Array)
            {
                foreach (var m in mail.EnumerateArray())
                    sb.AppendLine($"Mail: {FormatBytes(GetLong(m, "storageUsedInBytes"))}");
            }

            if (root.TryGetProperty("usageByApp", out var apps) && apps.ValueKind == JsonValueKind.Object)
            {
                sb.AppendLine();
                sb.AppendLine("usageByApp:");
                foreach (var prop in apps.EnumerateObject().OrderBy(p => p.Name, StringComparer.Ordinal))
                {
                    var bytes = prop.Value.ValueKind switch
                    {
                        JsonValueKind.Number => prop.Value.TryGetInt64(out var n) ? n : 0,
                        JsonValueKind.Object => GetLong(prop.Value, "storageUsedInBytes") is var u and > 0
                            ? u
                            : GetLong(prop.Value, "usedStorageInBytes"),
                        _ => 0L,
                    };
                    if (bytes > 0)
                        sb.AppendLine($"  • {prop.Name}: {FormatBytes(bytes)}");
                    else
                        sb.AppendLine($"  • {prop.Name}");
                }
            }
        }
        catch (JsonException ex)
        {
            sb.AppendLine($"(parse details fallito: {ex.Message})");
        }
    }

    private static long GetLong(JsonElement el, string name)
    {
        if (!el.TryGetProperty(name, out var p))
            return 0;
        if (p.ValueKind == JsonValueKind.Number && p.TryGetInt64(out var n))
            return n;
        if (p.ValueKind == JsonValueKind.String
            && long.TryParse(p.GetString(), NumberStyles.Integer, CultureInfo.InvariantCulture, out var s))
            return s;
        return 0;
    }

    private static bool GetBool(JsonElement el, string name) =>
        el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.True;

    private static string FormatBytes(long bytes)
    {
        if (bytes < 0)
            bytes = 0;
        double v = bytes;
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        var u = 0;
        while (v >= 1024 && u < units.Length - 1)
        {
            v /= 1024;
            u++;
        }

        return u == 0
            ? $"{bytes:N0} B"
            : string.Create(CultureInfo.InvariantCulture, $"{v:0.##} {units[u]} ({bytes:N0} B)");
    }
}
