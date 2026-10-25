using System.Net.Http.Headers;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Http;
using iCloudKitExtractor.Services;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Client iCloud KeyValue store (<c>{partition}-keyvalueservice.icloud.com/sync</c>) —
/// Sync Data: dump XML/plist dopo Escrow (sbd3, Safari tabs, Maps, …).
/// Auth: preferisce <c>Basic</c> (come Quota/Contacts); fallback <c>X-MobileMe-AuthToken</c>.
/// </summary>
public sealed class KeyValueSyncClient
{
    public sealed record KvApp(string KvStoreId, string BundleId);

    /// <summary>App KVS viste in capture <c>capture_http_20260802_054842</c>.</summary>
    public static IReadOnlyList<KvApp> DefaultApps { get; } =
    [
        new("com.apple.sbd3", "com.apple.sbd"),
        new("com.apple.Safari.SyncedTabs", "com.apple.Safari"),
        new("com.apple.MapsSupport.history", "com.apple.Maps"),
        new("com.apple.MapsSupport.bookmarks", "com.apple.Maps"),
    ];

    private readonly HttpClient _http;

    public KeyValueSyncClient(HttpClient http) => _http = http;

    public async Task<(byte[] Body, string Url)> SyncAsync(
        ICloudSession session,
        IReadOnlyList<KvApp> apps,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Sessione senza DSID.");

        var secrets = SessionMmeAuth.ResolveSecretCandidates(session);
        if (secrets.Count == 0)
            throw new InvalidOperationException("Sessione senza MobileMeAuthToken / UAEA… (serve per KVS).");

        var url = ResolveSyncUrl(session);
        var xml = BuildRequestPlist(apps);
        var bodyBytes = Encoding.UTF8.GetBytes(xml);
        var errors = new List<string>();

        foreach (var secret in secrets)
        {
            // Basic prima (probe live 200 con UAEA); XMM come legacy.
            foreach (var style in new[] { "Basic", "X-MobileMe-AuthToken" })
            {
                var (code, body) = await PostSyncAsync(session, url, bodyBytes, secret, style, ct)
                    .ConfigureAwait(false);
                if (code is >= 200 and < 300)
                    return (body, url);

                var preview = Encoding.UTF8.GetString(body.AsSpan(0, Math.Min(body.Length, 160)));
                errors.Add($"{style} token={Prefix(secret)} → HTTP {code}: {preview}");
            }
        }

        throw new InvalidOperationException(
            "KVS sync fallito.\n" + string.Join("\n", errors));
    }

    /// <summary>Sync default apps e testo formattato per UI forense.</summary>
    public async Task<string> FetchDefaultAppsTextAsync(
        ICloudSession session,
        CancellationToken ct = default)
    {
        var (body, url) = await SyncAsync(session, DefaultApps, ct).ConfigureAwait(false);
        var text = Encoding.UTF8.GetString(body);
        var sb = new StringBuilder();
        sb.AppendLine("=== KeyValue — /sync ===");
        sb.AppendLine($"URL: {url}");
        sb.AppendLine($"Apps: {string.Join(", ", DefaultApps.Select(a => a.KvStoreId))}");
        sb.AppendLine($"Bytes: {body.Length:N0}");
        sb.AppendLine();
        sb.AppendLine(text.Length > 200_000 ? text[..200_000] + "\n…(troncato)" : text);
        return sb.ToString().TrimEnd();
    }

    internal static string ResolveSyncUrl(ICloudSession session)
    {
        foreach (var key in new[]
                 {
                     "com.apple.Dataclass.KeyValue",
                     "KeyValue",
                     "com.apple.Dataclass.KeyValue.url",
                     "com.apple.Dataclass.KeyValue.configURL",
                     "KeyValue.configURL",
                 })
        {
            if (!session.DataclassServiceUrls.TryGetValue(key, out var raw)
                || string.IsNullOrWhiteSpace(raw))
                continue;
            var cleaned = raw.Replace(":443", "", StringComparison.Ordinal).TrimEnd('/');
            if (cleaned.EndsWith("/config", StringComparison.OrdinalIgnoreCase))
                cleaned = cleaned[..^"/config".Length];
            if (cleaned.EndsWith("/sync", StringComparison.OrdinalIgnoreCase))
                return cleaned;
            if (Uri.TryCreate(cleaned, UriKind.Absolute, out var uri))
                return $"{uri.Scheme}://{uri.Host}/sync";
        }

        var partition = string.IsNullOrWhiteSpace(session.Partition) ? "p116" : session.Partition.Trim();
        if (!partition.StartsWith('p'))
            partition = "p" + partition;
        return $"https://{partition}-keyvalueservice.icloud.com/sync";
    }

    private async Task<(int Code, byte[] Body)> PostSyncAsync(
        ICloudSession session,
        string url,
        byte[] bodyBytes,
        string secret,
        string authStyle,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new ByteArrayContent(bodyBytes);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("text/xml");
        request.Headers.TryAddWithoutValidation(
            "Authorization",
            $"{authStyle} {AppleHttpExtensions.BasicAuth(session.Dsid, secret)}");
        session.Anisette.TouchClientTimeUtc();
        request.ApplyAuthKitAkdIdentity(session.Anisette);
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);
        if (!string.IsNullOrEmpty(session.Anisette.MdLu))
            request.Headers.TryAddWithoutValidation("X-Apple-I-MD-LU", session.Anisette.MdLu);
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        return ((int)response.StatusCode, body);
    }

    private static string Prefix(string secret) =>
        secret.Length <= 8 ? secret : secret[..8] + "…";

    private static string BuildRequestPlist(IReadOnlyList<KvApp> apps)
    {
        var sb = new StringBuilder();
        sb.Append("""
            <?xml version="1.0" encoding="UTF-8"?>
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0">
            <dict>
              <key>apps</key>
              <array>
            """);
        foreach (var app in apps)
        {
            sb.Append("""
                  <dict>
                    <key>kvstore-id</key>
                    <string>
            """);
            sb.Append(System.Security.SecurityElement.Escape(app.KvStoreId));
            sb.Append("""
                    </string>
                    <key>bundle-id</key>
                    <string>
            """);
            sb.Append(System.Security.SecurityElement.Escape(app.BundleId));
            sb.Append("""
                    </string>
                    <key>registry-version</key>
                    <string></string>
                  </dict>
            """);
        }

        sb.Append("""
              </array>
              <key>service-id</key>
              <string>iOS</string>
            </dict>
            </plist>
            """);
        return sb.ToString();
    }
}
