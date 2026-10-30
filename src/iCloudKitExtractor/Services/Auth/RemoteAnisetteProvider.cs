using System.Globalization;
using System.IO;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Client HTTP verso anisette remota (Mac middleware Licensed, dadoum, AnisetteServer).
/// </summary>
public sealed class RemoteAnisetteProvider : IAnisetteProvider
{
    private readonly HttpClient _http;
    private readonly Uri _baseUri;
    private string? _licenseBearer;
    private readonly bool _sendFingerprintWhenUnlicensed;

    /// <summary>Raised once when the server returns a first-connection Package C license bundle.</summary>
    public event Action<string>? LicenseBundleIssued;

    /// <summary>App-wide hook (MainWindow overlay) for any remote provider instance.</summary>
    public static event Action<string>? AnyLicenseBundleIssued;

    public RemoteAnisetteProvider(HttpClient http, string baseUrl, string? licenseBearer = null)
    {
        _http = http;
        _baseUri = new Uri(baseUrl.TrimEnd('/') + "/");
        _licenseBearer = string.IsNullOrWhiteSpace(licenseBearer)
            ? ResolveLicenseBearerFromEnv()
            : licenseBearer.Trim();
        _sendFingerprintWhenUnlicensed = string.IsNullOrWhiteSpace(_licenseBearer);
    }

    public Uri BaseUri => _baseUri;

    /// <summary>
    /// ANISETTE_LICENSE = raw Bearer token, Package-C Base64, or path to a .license file.
    /// </summary>
    public static string? ResolveLicenseBearerFromEnv()
    {
        var raw = Environment.GetEnvironmentVariable("ANISETTE_LICENSE")?.Trim();
        if (string.IsNullOrEmpty(raw))
            return null;
        if (File.Exists(raw))
        {
            var line = File.ReadAllLines(raw)
                .Select(l => l.Trim())
                .FirstOrDefault(l => l.Length > 0 && !l.StartsWith('#'));
            return string.IsNullOrEmpty(line) ? null : line;
        }
        return raw;
    }

    public static void ApplyLicenseHeader(HttpRequestMessage request)
    {
        var bearer = AnisetteProviderFactory.ResolveLicenseBearer();
        if (!string.IsNullOrEmpty(bearer))
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + bearer);
    }

    public void SetLicenseBundle(string bundleBase64)
    {
        _licenseBearer = bundleBase64.Trim();
    }

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
        yield return string.Empty;
        yield return "v1/get_headers";
        yield return "get_headers";
    }

    private static bool TryGetHttpStatus(Exception ex, out int status)
    {
        status = 0;
        var msg = ex.Message;
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

        using var request = new HttpRequestMessage(HttpMethod.Get, uri);
        var license = !string.IsNullOrEmpty(_licenseBearer)
            ? _licenseBearer
            : AnisetteProviderFactory.ResolveLicenseBearer();
        if (!string.IsNullOrEmpty(license))
        {
            // Send full Package-C Base64 (or raw token); server unwraps.
            request.Headers.TryAddWithoutValidation("Authorization", "Bearer " + license);
        }
        else
        {
            IkeClientIdentity.ApplyFingerprintHeaders(request);
        }

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);

        TryCaptureIssuedBundle(response, body);

        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"HTTP {(int)response.StatusCode} GET {uri}: {TrimBody(body)}");
        }

        if (AnisetteJsonParser.TryParseHeaders(body, out var payload))
            return payload.ToHeaders();

        return await ParseLegacyJsonAsync(body, ct).ConfigureAwait(false);
    }

    private void TryCaptureIssuedBundle(HttpResponseMessage response, string body)
    {
        if (!_sendFingerprintWhenUnlicensed)
            return;
        if (!string.IsNullOrWhiteSpace(_licenseBearer))
            return;

        string? bundle = null;
        if (response.Headers.TryGetValues(IkeClientIdentity.ResponseBundleHeader, out var vals))
            bundle = vals.FirstOrDefault();

        if (string.IsNullOrWhiteSpace(bundle))
        {
            try
            {
                using var doc = JsonDocument.Parse(body);
                if (doc.RootElement.TryGetProperty("license_bundle", out var lb)
                    && lb.ValueKind == JsonValueKind.String)
                    bundle = lb.GetString();
            }
            catch
            {
                // ignore
            }
        }

        if (string.IsNullOrWhiteSpace(bundle))
            return;

        _licenseBearer = bundle.Trim();
        LicenseBundleIssued?.Invoke(_licenseBearer);
        AnyLicenseBundleIssued?.Invoke(_licenseBearer);
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

        [JsonPropertyName("license_bundle")]
        public string? LicenseBundle { get; set; }
    }
}
