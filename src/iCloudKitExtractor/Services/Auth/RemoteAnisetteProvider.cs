using System.Globalization;
using System.IO;
using System.Net.Http.Json;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Client HTTP verso anisette remota (Mac: dadoum/anisette-v3-server, omnisette, AnisetteServer compatibile).
/// </summary>
public sealed class RemoteAnisetteProvider : IAnisetteProvider
{
    private readonly HttpClient _http;
    private readonly Uri _baseUri;

    public RemoteAnisetteProvider(HttpClient http, string baseUrl)
    {
        _http = http;
        _baseUri = new Uri(baseUrl.TrimEnd('/') + "/");
    }

    public Uri BaseUri => _baseUri;

    /// <summary>
    /// Optional license header for commercial Anisette backends.
    /// Public builds: no-op (private tree may attach a license token).
    /// </summary>
    public static void ApplyLicenseHeader(HttpRequestMessage request) =>
        _ = request;

    public Task<AnisetteHeaders> FetchAsync(CancellationToken ct = default) =>
        FetchAsync(null, ct);

    public async Task<AnisetteHeaders> FetchAsync(AnisetteFetchOptions? options, CancellationToken ct = default)
    {
        Exception? lastError = null;
        var errors = new List<string>(3);
        var appleId = options?.AppleId?.Trim();
        var forceFresh = options?.ForceFresh == true;

        foreach (var relativePath in ProbePaths())
        {
            try
            {
                return await FetchFromPathAsync(relativePath, appleId, forceFresh, ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                lastError = ex;
                var label = string.IsNullOrEmpty(relativePath) ? "/" : relativePath;
                errors.Add($"{label}: {ex.Message}");

                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "anisette-401",
                        ["hypothesisId"] = "H-ANI-PATH",
                        ["location"] = "RemoteAnisetteProvider.FetchAsync",
                        ["message"] = "anisette_probe_fail",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new { path = label, error = ex.Message },
                    });
                    File.AppendAllText(
                        System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion

                // Se GET / ha risposto (5xx/parse) non ha senso probe get_headers sullo stesso host.
                if (string.IsNullOrEmpty(relativePath)
                    && TryGetHttpStatus(ex, out var code)
                    && code != 404)
                {
                    break;
                }
            }
        }

        var detail = errors.Count > 0
            ? string.Join(" | ", errors)
            : lastError?.Message ?? "nessun endpoint valido";
        throw new InvalidOperationException(
            $"Anisette remota non raggiungibile ({_baseUri}): {detail}");
    }

    /// <summary>GET /health → backend name (rad, akd-emulated, …), o null se non disponibile.</summary>
    public async Task<string?> TryGetBackendAsync(CancellationToken ct = default)
    {
        try
        {
            using var resp = await _http.GetAsync(new Uri(_baseUri, "health"), ct).ConfigureAwait(false);
            var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("backend", out var b))
                return b.GetString()?.Trim().ToLowerInvariant();
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static IEnumerable<string> ProbePaths()
    {
        // AnisetteServer IKE: solo GET /
        yield return string.Empty;
        // Compat dadoum/omnisette (solo se / → 404)
        yield return "v1/get_headers";
        yield return "get_headers";
    }

    private static bool TryGetHttpStatus(Exception ex, out int status)
    {
        status = 0;
        var msg = ex.Message;
        // "HTTP 404 GET …" / "HTTP 500 GET …"
        if (!msg.StartsWith("HTTP ", StringComparison.Ordinal))
            return false;
        var sp = msg.IndexOf(' ', 5);
        if (sp < 0)
            sp = msg.Length;
        return int.TryParse(msg.AsSpan(5, sp - 5), out status);
    }

    private async Task<AnisetteHeaders> FetchFromPathAsync(
        string relativePath, string? appleId, bool forceFresh, CancellationToken ct)
    {
        var uri = string.IsNullOrEmpty(relativePath)
            ? _baseUri
            : new Uri(_baseUri, relativePath);

        var queryParts = new List<string>();
        if (!string.IsNullOrEmpty(appleId))
            queryParts.Add("apple_id=" + Uri.EscapeDataString(appleId));
        // Frida/AnisetteServer: mint OTP nuovo (evita MD cached + Client-Time drift → -22410).
        if (forceFresh)
            queryParts.Add("fresh=1");
        if (queryParts.Count > 0)
        {
            var ub = new UriBuilder(uri);
            var existing = ub.Query.TrimStart('?');
            var append = string.Join("&", queryParts);
            ub.Query = string.IsNullOrEmpty(existing) ? append : existing + "&" + append;
            uri = ub.Uri;
        }

        using var response = await _http.GetAsync(uri, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"HTTP {(int)response.StatusCode} GET {uri}: {TrimBody(body)}");
        }

        if (AnisetteJsonParser.TryParseHeaders(body, out var payload))
            return payload.ToHeaders();

        return await ParseLegacyJsonAsync(body, ct).ConfigureAwait(false);
    }

    private static async Task<AnisetteHeaders> ParseLegacyJsonAsync(string body, CancellationToken ct)
    {
        using var stream = new MemoryStream(Encoding.UTF8.GetBytes(body));
        var payload = await JsonSerializer.DeserializeAsync<AnisetteServerResponse>(stream, cancellationToken: ct)
            .ConfigureAwait(false)
            ?? throw new InvalidOperationException("Risposta anisette JSON vuota.");

        if (string.IsNullOrEmpty(payload.Md) || string.IsNullOrEmpty(payload.MdM))
            throw new InvalidOperationException("JSON anisette senza X-Apple-I-MD / X-Apple-I-MD-M.");

        return new AnisetteHeaders
        {
            Md = payload.Md,
            MdM = payload.MdM,
            MdLu = payload.MdLu ?? string.Empty,
            MdRinfo = string.IsNullOrEmpty(payload.MdRinfo) || payload.MdRinfo == "84215040"
                ? GrandSlamCpdBuilder.IosMdRinfo.ToString(CultureInfo.InvariantCulture)
                : payload.MdRinfo,
            ClientTimeUtc = string.IsNullOrEmpty(payload.ClientTime)
                ? DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
                : payload.ClientTime,
            SerialNumber = payload.SerialNumber ?? string.Empty,
            ClientMmeInfo = payload.ClientMmeInfo ?? string.Empty,
            MmeDeviceId = payload.MmeDeviceId ?? string.Empty,
            ClientProductType = payload.ClientProductType ?? string.Empty,
            Locale = string.IsNullOrEmpty(payload.Locale) ? "en_US" : payload.Locale,
            TimeZone = payload.TimeZone ?? TimeZoneInfo.Local.Id,
            CountryCode = payload.CountryCode ?? "US"
        };
    }

    private static string TrimBody(string body) =>
        body.Length <= 200 ? body : body[..200] + "…";

    private sealed class AnisetteServerResponse
    {
        [JsonPropertyName("X-Apple-I-MD")]
        public string? Md { get; set; }

        [JsonPropertyName("X-Apple-I-MD-M")]
        public string? MdM { get; set; }

        [JsonPropertyName("X-Apple-I-MD-LU")]
        public string? MdLu { get; set; }

        [JsonPropertyName("X-Apple-I-MD-RINFO")]
        public string? MdRinfo { get; set; }

        [JsonPropertyName("X-Apple-I-Client-Time")]
        public string? ClientTime { get; set; }

        [JsonPropertyName("serialNumber")]
        public string? SerialNumber { get; set; }

        [JsonPropertyName("X-MMe-Client-Info")]
        public string? ClientMmeInfo { get; set; }

        [JsonPropertyName("X-Mme-Device-Id")]
        public string? MmeDeviceId { get; set; }

        [JsonPropertyName("clientProductType")]
        public string? ClientProductType { get; set; }

        [JsonPropertyName("locale")]
        public string? Locale { get; set; }

        [JsonPropertyName("timeZone")]
        public string? TimeZone { get; set; }

        [JsonPropertyName("countryCode")]
        public string? CountryCode { get; set; }
    }
}
