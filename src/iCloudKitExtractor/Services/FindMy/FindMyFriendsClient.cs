using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Auth;
using iCloudKitExtractor.Services.Http;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.FindMy;

/// <summary>
/// Find My People / FMF friends — sola lettura.
/// Contesto allineato a findmylocated / articolo zerotistic:
/// <c>apsToken</c> (courier APS) + path <c>friends/fmfd/{dsid}/{udid}/initClient</c>.
/// Auth: <c>Basic dsid:mmeFMFAppToken</c>. Nessuna azione wipe/lost/invite.
/// </summary>
public sealed class FindMyFriendsClient
{
    private readonly HttpClient _http;

    /// <summary>Echo di <c>X-FMF-Model-Version</c> tra refresh (come i client nativi).</summary>
    private static string? s_fmfModelVersion;

    public FindMyFriendsClient(HttpClient http) => _http = http;

    public async Task<string> FetchFriendsTextAsync(
        ICloudSession session,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Sessione senza DSID.");

        var token = session.MmeFmfAppToken;
        if (string.IsNullOrWhiteSpace(token))
        {
            throw new InvalidOperationException(
                "Manca mmeFMFAppToken in sessione. Completa login + get_account_settings.");
        }

        var apsToken = ApsSessionService.TryGetPushTokenHex();
        if (string.IsNullOrWhiteSpace(apsToken))
        {
            throw new InvalidOperationException(
                "Manca push token APS (apsToken). In Dispositivi fidati: Attiva Albert → Connetti APS, poi riprova Find My People.");
        }

        var deviceStore = new AnisetteDeviceStore(AdiDeviceProfile.Windows);
        var deviceUdid = deviceStore.GetOrCreateDeviceUuid();
        var productType = deviceStore.GetOrCreateClientProductType();
        if (string.IsNullOrWhiteSpace(productType) || productType.Equals("PC", StringComparison.OrdinalIgnoreCase))
            productType = "windows1,1";

        var host = ResolveFmfMobileHost(session);
        var partition = ExtractPartition(host);
        var dsid = session.Dsid.Trim();

        // Preferisci initClient findmylocated (articolo); fallback refreshClient legacy.
        var attempts = new (string Path, string Label)[]
        {
            ($"/fmipservice/friends/fmfd/{dsid}/{deviceUdid}/initClient", "initClient fmfd"),
            ($"/fmipservice/friends/{dsid}/refreshClient", "refreshClient"),
            ($"/fmipservice/friends/fmfd/{dsid}/initClient", "initClient fmfd (no udid)"),
        };

        var log = new StringBuilder();
        log.AppendLine($"Host: {host}");
        log.AppendLine($"apsToken: {apsToken}");
        log.AppendLine($"deviceUDID: {deviceUdid}");
        log.AppendLine($"productType: {productType}");
        log.AppendLine();

        Exception? last = null;
        foreach (var (path, label) in attempts)
        {
            var url = host.TrimEnd('/') + path;
            try
            {
                var (status, text, modelVer) = await SendFriendsAsync(
                    session, url, partition, token, apsToken, deviceUdid, productType, ct)
                    .ConfigureAwait(false);

                if (modelVer is not null)
                    s_fmfModelVersion = modelVer;

                if (status is >= 200 and < 300)
                {
                    log.AppendLine($"OK via {label} HTTP {status}");
                    log.AppendLine();
                    log.Append(FormatResponse(url, text));
                    return log.ToString();
                }

                last = new InvalidOperationException(
                    $"FMF {label} HTTP {status}: {ExplainFmfError(status, text)}");
                log.AppendLine($"— {label} → HTTP {status}: {Trim(text, 200)}");
            }
            catch (Exception ex) when (ex is not InvalidOperationException || !ex.Message.StartsWith("FMF ", StringComparison.Ordinal))
            {
                last = ex;
                log.AppendLine($"— {label} → {ex.Message}");
            }
        }

        throw new InvalidOperationException(
            (last?.Message ?? "FMF: tutte le varianti fallite.")
            + Environment.NewLine + log);
    }

    private async Task<(int Status, string Body, string? ModelVersion)> SendFriendsAsync(
        ICloudSession session,
        string url,
        string partition,
        string fmfAppToken,
        string apsToken,
        string deviceUdid,
        string productType,
        CancellationToken ct)
    {
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var clientContext = new Dictionary<string, object?>
        {
            ["appName"] = "findmylocated",
            ["appVersion"] = "1.0",
            ["apiVersion"] = "3.0",
            ["apsToken"] = apsToken,
            ["callerHandleId"] = session.AppleId,
            ["contextBundleApp"] = "com.apple.findmy.findmylocated",
            ["currentTime"] = nowMs,
            ["deviceUDID"] = deviceUdid,
            ["productType"] = productType,
            ["osVersion"] = "10.6.4",
            ["deviceListVersion"] = 1,
            ["fmly"] = true,
            ["shouldLocate"] = false,
            ["selectedDevice"] = "all",
        };
        if (!string.IsNullOrWhiteSpace(s_fmfModelVersion))
            clientContext["modelVersion"] = s_fmfModelVersion;

        // authToken: token MobileMe FMF (spesso inviato raw o base64 — provo base64 del token).
        var authTokenB64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(fmfAppToken));
        var bodyObj = new Dictionary<string, object?>
        {
            ["clientContext"] = clientContext,
            ["serverContext"] = new Dictionary<string, object?>
            {
                ["authToken"] = authTokenB64,
                ["prsId"] = session.Dsid,
            },
        };

        var body = JsonSerializer.Serialize(bodyObj);
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new StringContent(body, Encoding.UTF8, "application/json");
        request.Headers.TryAddWithoutValidation(
            "Authorization",
            $"Basic {AppleHttpExtensions.BasicAuth(session.Dsid, fmfAppToken)}");
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation(
            "User-Agent",
            "findmylocated/1.0 CFNetwork/1490.0.4 Darwin/23.6.0");
        request.Headers.TryAddWithoutValidation("X-Apple-Find-Partition", partition);
        if (!string.IsNullOrWhiteSpace(s_fmfModelVersion))
            request.Headers.TryAddWithoutValidation("X-FMF-Model-Version", s_fmfModelVersion);

        session.Anisette.TouchClientTimeUtc();
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);
        if (!string.IsNullOrEmpty(session.Anisette.MdLu))
            request.Headers.TryAddWithoutValidation("X-Apple-I-MD-LU", session.Anisette.MdLu);
        request.Headers.TryAddWithoutValidation("X-Mme-Device-Id", deviceUdid);

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        string? modelVer = null;
        if (response.Headers.TryGetValues("X-FMF-Model-Version", out var mv))
            modelVer = mv.FirstOrDefault();
        return ((int)response.StatusCode, text, modelVer);
    }

    private static string ExplainFmfError(int status, string body)
    {
        if (status == 503 && body.Contains("itunes.apple.com", StringComparison.OrdinalIgnoreCase))
        {
            return body.Trim()
                   + " — tipico quando manca apsToken / clientContext findmylocated "
                   + "(servizio chiede l’app Find My Friends). Connetti APS e riprova.";
        }

        return Trim(body, 300);
    }

    internal static string ResolveFmfMobileHost(ICloudSession session)
    {
        foreach (var key in new[]
                 {
                     "com.apple.Dataclass.ShareLocation.appHostname",
                     "com.apple.Dataclass.ShareLocation",
                     "ShareLocation",
                 })
        {
            if (!session.DataclassServiceUrls.TryGetValue(key, out var raw)
                || string.IsNullOrWhiteSpace(raw))
                continue;

            if (!raw.Contains("://", StringComparison.Ordinal))
                raw = "https://" + raw;
            if (Uri.TryCreate(raw.Replace(":443", "", StringComparison.Ordinal), UriKind.Absolute, out var uri))
            {
                var host = uri.Host;
                if (host.Contains("fmf", StringComparison.OrdinalIgnoreCase)
                    && !host.Contains("mobile", StringComparison.OrdinalIgnoreCase))
                    host = host.Replace("fmf.", "fmfmobile.", StringComparison.OrdinalIgnoreCase);
                return $"{uri.Scheme}://{host}";
            }
        }

        var part = string.IsNullOrWhiteSpace(session.Partition) ? "p116" : session.Partition.Trim();
        if (!part.StartsWith('p'))
            part = "p" + part;
        return $"https://{part}-fmfmobile.icloud.com";
    }

    private static string ExtractPartition(string hostUrl)
    {
        if (Uri.TryCreate(hostUrl, UriKind.Absolute, out var uri))
        {
            var m = System.Text.RegularExpressions.Regex.Match(uri.Host, @"p(\d+)");
            if (m.Success)
                return m.Groups[1].Value;
        }

        return "116";
    }

    private static string FormatResponse(string url, string json)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"URL: {url}");
        sb.AppendLine("Auth: Basic dsid:mmeFMFAppToken + clientContext.apsToken");
        sb.AppendLine("Nota: location cifrata People richiede IDS (articolo zerotistic); qui solo friends RO.");
        sb.AppendLine();

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            sb.AppendLine($"fetchStatus: {GetStr(root, "fetchStatus")}");
            var devices = root.TryGetProperty("devices", out var d) && d.ValueKind == JsonValueKind.Array
                ? d.GetArrayLength()
                : 0;
            var following = root.TryGetProperty("following", out var f) && f.ValueKind == JsonValueKind.Array
                ? f.GetArrayLength()
                : 0;
            var followers = root.TryGetProperty("followers", out var fo) && fo.ValueKind == JsonValueKind.Array
                ? fo.GetArrayLength()
                : 0;
            var locations = root.TryGetProperty("locations", out var loc) && loc.ValueKind == JsonValueKind.Array
                ? loc.GetArrayLength()
                : 0;
            sb.AppendLine(
                $"devices: {devices} · following: {following} · followers: {followers} · locations: {locations}");

            if (root.TryGetProperty("myInfo", out var my) && my.ValueKind == JsonValueKind.Object)
            {
                sb.AppendLine(
                    $"myInfo: firstName={GetStr(my, "firstName")} meDeviceId={GetStr(my, "meDeviceId")}");
            }

            sb.AppendLine();
            sb.AppendLine("--- following ---");
            if (root.TryGetProperty("following", out var folArr) && folArr.ValueKind == JsonValueKind.Array)
            {
                var i = 0;
                foreach (var item in folArr.EnumerateArray())
                {
                    sb.AppendLine(
                        $"[{i}] id={GetStr(item, "id")} secureLocationsCapable={GetBool(item, "secureLocationsCapable")} " +
                        $"fallbackToLegacyAllowed={GetBool(item, "fallbackToLegacyAllowed")}");
                    i++;
                }

                if (i == 0)
                    sb.AppendLine("(vuoto — nessuna share People, o serve IDS/distributeKeys)");
            }

            sb.AppendLine();
            sb.AppendLine("--- devices ---");
            if (root.TryGetProperty("devices", out var devArr) && devArr.ValueKind == JsonValueKind.Array)
            {
                var i = 0;
                foreach (var item in devArr.EnumerateArray())
                {
                    var name = GetStr(item, "name");
                    var ids = GetStr(item, "idsDeviceId");
                    sb.AppendLine($"[{i}] name=\"{name}\" ids={ids}");
                    i++;
                }
            }
        }
        catch (JsonException)
        {
            sb.AppendLine(Trim(json, 4000));
            return sb.ToString();
        }

        sb.AppendLine();
        sb.AppendLine("--- raw (troncato) ---");
        sb.AppendLine(Trim(json, 6000));
        return sb.ToString();
    }

    private static string GetStr(JsonElement el, string name) =>
        el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.String
            ? p.GetString() ?? ""
            : "";

    private static bool GetBool(JsonElement el, string name) =>
        el.TryGetProperty(name, out var p) && p.ValueKind == JsonValueKind.True;

    private static string Trim(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
