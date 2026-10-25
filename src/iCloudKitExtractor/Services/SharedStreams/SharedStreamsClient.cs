using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.SharedStreams;

/// <summary>
/// Shared Streams account-scoped API (solo lettura).
/// <c>POST /{dsid}/sharedstreams/webgetalbumslist</c> con
/// <c>Authorization: X-MobileMe-AuthToken</c> (Basic → 401). Segue HTTP 330.
/// </summary>
public sealed class SharedStreamsClient
{
    private readonly HttpClient _http;

    public SharedStreamsClient(HttpClient http) => _http = http;

    public async Task<string> FetchAlbumListTextAsync(
        ICloudSession session,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Sessione senza DSID.");

        var secrets = SessionMmeAuth.ResolveSecretCandidates(session);
        if (secrets.Count == 0)
            throw new InvalidOperationException("Manca secret sessione (MobileMeAuthToken / UAEA…).");

        var host = ResolveHost(session);
        var url = $"{host.TrimEnd('/')}/{session.Dsid.Trim()}/sharedstreams/webgetalbumslist";
        var errors = new List<string>();

        foreach (var secret in secrets)
        {
            var (code, text, finalUrl) = await PostAlbumListAsync(session, url, secret, ct)
                .ConfigureAwait(false);

            // Apple redirect partition
            if (code == 330)
            {
                var redirected = TryResolveMmeHostRedirect(text, session.Dsid.Trim());
                if (redirected is not null)
                {
                    (code, text, finalUrl) = await PostAlbumListAsync(session, redirected, secret, ct)
                        .ConfigureAwait(false);
                }
            }

            if (code is >= 200 and < 300)
                return FormatAlbumList(finalUrl, text);

            var preview = text.Length > 160 ? text[..160] : text;
            errors.Add($"token={Prefix(secret)} → HTTP {code}: {preview}");
        }

        throw new InvalidOperationException(
            "SharedStreams webgetalbumslist fallito.\n" + string.Join("\n", errors));
    }

    private async Task<(int Code, string Text, string Url)> PostAlbumListAsync(
        ICloudSession session,
        string url,
        string secret,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        //  text/plain senza charset
        request.Content = new ByteArrayContent("{}"u8.ToArray());
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("text/plain");
        request.Headers.TryAddWithoutValidation(
            "Authorization",
            $"X-MobileMe-AuthToken {AppleHttpExtensions.BasicAuth(session.Dsid, secret)}");
        session.Anisette.TouchClientTimeUtc();
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);
        if (!string.IsNullOrEmpty(session.Anisette.MdLu))
            request.Headers.TryAddWithoutValidation("X-Apple-I-MD-LU", session.Anisette.MdLu);
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        return ((int)response.StatusCode, text, url);
    }

    internal static string ResolveHost(ICloudSession session)
    {
        foreach (var key in new[]
                 {
                     "com.apple.Dataclass.SharedStreams",
                     "SharedStreams",
                     "com.apple.Dataclass.SharedStreams.url",
                 })
        {
            if (session.DataclassServiceUrls.TryGetValue(key, out var url)
                && !string.IsNullOrWhiteSpace(url)
                && Uri.TryCreate(url.Replace(":443", "", StringComparison.Ordinal), UriKind.Absolute, out var uri))
                return $"{uri.Scheme}://{uri.Host}";
        }

        // SharedStreams è spesso su partizione dedicata (p154), non sulla partition quota.
        return "https://p154-sharedstreams.icloud.com";
    }

    private static string? TryResolveMmeHostRedirect(string body, string dsid)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("X-Apple-MMe-Host", out var hostEl))
                return null;
            var host = hostEl.GetString()?.Trim();
            if (string.IsNullOrWhiteSpace(host))
                return null;
            if (!host.StartsWith("http", StringComparison.OrdinalIgnoreCase))
                host = "https://" + host;
            host = host.Replace(":443", "", StringComparison.Ordinal).TrimEnd('/');
            return $"{host}/{dsid}/sharedstreams/webgetalbumslist";
        }
        catch (JsonException)
        {
            return null;
        }
    }

    private static string Prefix(string secret) =>
        secret.Length <= 8 ? secret : secret[..8] + "…";

    private static string FormatAlbumList(string url, string json)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== SharedStreams — webgetalbumslist ===");
        sb.AppendLine($"URL: {url}");
        sb.AppendLine();
        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.TryGetProperty("callerId", out var caller))
                sb.AppendLine($"callerId: {caller.GetString()}");
            if (root.TryGetProperty("rootctag", out var ctag))
                sb.AppendLine($"rootctag: {ctag.GetString()}");

            if (root.TryGetProperty("albums", out var albums)
                && albums.ValueKind == JsonValueKind.Array)
            {
                sb.AppendLine($"albums: {albums.GetArrayLength()}");
                var i = 0;
                foreach (var album in albums.EnumerateArray())
                {
                    i++;
                    sb.AppendLine($"--- album [{i}] ---");
                    foreach (var prop in album.EnumerateObject())
                        sb.AppendLine($"  {prop.Name}: {prop.Value}");
                }

                if (albums.GetArrayLength() == 0)
                    sb.AppendLine("(nessun album Shared Streams sull'account)");
            }

            sb.AppendLine();
            sb.AppendLine("--- JSON grezzo ---");
            sb.AppendLine(JsonSerializer.Serialize(root, new JsonSerializerOptions { WriteIndented = true }));
        }
        catch (JsonException)
        {
            sb.AppendLine(json);
        }

        return sb.ToString().TrimEnd();
    }
}
