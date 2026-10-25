using System.Net.Http.Json;
using System.Text;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// ADI crypto via worker Python (Unicorn ARM). Nessun CoreADI64.dll Windows.
/// </summary>
public sealed class HttpAdiCryptoClient : IAdiCryptoClient
{
    private readonly HttpClient _http;
    private readonly Uri _baseUri;
    private readonly AnisetteDeviceStore _deviceStore;

    public HttpAdiCryptoClient(HttpClient http, string baseUrl, AdiDeviceProfile? profile = null)
    {
        _http = http;
        _baseUri = new Uri(baseUrl.TrimEnd('/') + "/");
        _deviceStore = new AnisetteDeviceStore(profile ?? AdiDeviceProfile.Ios);
    }

    public bool RequiresWindowsCoreAdiRuntime => false;

    /// <summary>
    /// Default false: MidService HTTP in C# (header akd) + worker solo crypto.
    /// <c>AKD_OWNS_MIDSERVICE=1</c>: MidService nella lib Android (Anisette.py) — esperimento MD-M nativo.
    /// </summary>
    public bool OwnsMidServiceHttp =>
        IsTruthyEnv("AKD_OWNS_MIDSERVICE");

    private static bool IsTruthyEnv(string name)
    {
        var raw = Environment.GetEnvironmentVariable(name);
        if (string.IsNullOrWhiteSpace(raw))
            return false;
        return raw.Trim() is "1" or "true" or "TRUE" or "yes" or "YES" or "on" or "ON";
    }

    public Task WipeLibraryProvisioningAsync(
        string runtimeDir, string provisioningDir, string adiId, CancellationToken ct = default) =>
        InvokeOkAsync("reset-adi", adiId, provisioningDir, new Dictionary<string, string>(), ct);

    public async Task ProvisionViaLibraryAsync(
        string runtimeDir, string provisioningDir, string adiId, long dsId = -2, CancellationToken ct = default)
    {
        using var doc = await InvokeAsync("anisette-provision", adiId, provisioningDir, new Dictionary<string, string>
        {
            ["dsid"] = dsId.ToString()
        }, ct).ConfigureAwait(false);
        if (!doc.RootElement.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
        {
            var err = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : "anisette-provision";
            throw new InvalidOperationException($"ADI worker anisette-provision: {err}");
        }
    }

    public Task<bool> IsProvisionedAsync(
        string runtimeDir, string provisioningDir, string adiId, long dsId = -2, CancellationToken ct = default) =>
        InvokeBoolAsync("is-provisioned", adiId, provisioningDir, new Dictionary<string, string>
        {
            ["dsid"] = dsId.ToString()
        }, ct);

    public async Task<AdiStartProvisioningResult> StartProvisioningAsync(
        string runtimeDir, string provisioningDir, string adiId, byte[] spim, long dsId = -2, CancellationToken ct = default)
    {
        using var doc = await InvokeAsync("start-provisioning", adiId, provisioningDir, new Dictionary<string, string>
        {
            ["dsid"] = dsId.ToString(),
            ["spim"] = Convert.ToBase64String(spim)
        }, ct).ConfigureAwait(false);

        var root = doc.RootElement;
        var session = root.TryGetProperty("session", out var sessionEl) ? sessionEl.GetUInt32() : 0;
        var cpim = root.TryGetProperty("cpim", out var cpimEl) ? cpimEl.GetString() ?? "" : "";
        return new AdiStartProvisioningResult(session, Convert.FromBase64String(cpim));
    }

    public Task EndProvisioningAsync(
        string runtimeDir, string provisioningDir, string adiId, uint session, byte[] ptm, byte[] tk,
        CancellationToken ct = default) =>
        InvokeOkAsync("end-provisioning", adiId, provisioningDir, new Dictionary<string, string>
        {
            ["session"] = session.ToString(),
            ["ptm"] = Convert.ToBase64String(ptm),
            ["tk"] = Convert.ToBase64String(tk)
        }, ct);

    public Task DestroySessionAsync(
        string runtimeDir, string provisioningDir, string adiId, uint session, CancellationToken ct = default) =>
        InvokeOkAsync("destroy-session", adiId, provisioningDir, new Dictionary<string, string>
        {
            ["session"] = session.ToString()
        }, ct);

    public Task SetRoutingAsync(
        string runtimeDir, string provisioningDir, string adiId, ulong routingInfo, long dsId = -2,
        CancellationToken ct = default) =>
        InvokeOkAsync("set-routing", adiId, provisioningDir, new Dictionary<string, string>
        {
            ["dsid"] = dsId.ToString(),
            ["routing"] = routingInfo.ToString()
        }, ct);

    public async Task<AdiOtpHeaderResult> RequestOtpAsync(
        string runtimeDir, string provisioningDir, string adiId, long dsId = -2, CancellationToken ct = default)
    {
        using var doc = await InvokeAsync("request-otp", adiId, provisioningDir, new Dictionary<string, string>
        {
            ["dsid"] = dsId.ToString()
        }, ct).ConfigureAwait(false);

        var root = doc.RootElement;
        return new AdiOtpHeaderResult(
            GetString(root, "X-Apple-I-MD"),
            GetString(root, "X-Apple-I-MD-M"),
            GetString(root, "X-Apple-I-MD-RINFO"));
    }

    private async Task<bool> InvokeBoolAsync(
        string command, string adiId, string provisioningDir, Dictionary<string, string> args, CancellationToken ct)
    {
        using var doc = await InvokeAsync(command, adiId, provisioningDir, args, ct).ConfigureAwait(false);
        return doc.RootElement.TryGetProperty("provisioned", out var p) && p.ValueKind == JsonValueKind.True;
    }

    private async Task InvokeOkAsync(
        string command, string adiId, string provisioningDir, Dictionary<string, string> args, CancellationToken ct)
    {
        using var doc = await InvokeAsync(command, adiId, provisioningDir, args, ct).ConfigureAwait(false);
        if (!doc.RootElement.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
        {
            var err = doc.RootElement.TryGetProperty("error", out var e) ? e.GetString() : command;
            throw new InvalidOperationException($"ADI worker: {err}");
        }
    }

    private async Task<JsonDocument> InvokeAsync(
        string command, string adiId, string provisioningDir, Dictionary<string, string> args, CancellationToken ct)
    {
        if (string.IsNullOrWhiteSpace(adiId))
        {
            throw new InvalidOperationException(
                "Identificatore ADI mancante (device-ios.json / AdiIdentifier). " +
                "Esegui configure-emulated-ios-anisette.ps1 o elimina device-ios.json per rigenerarlo.");
        }

        // Passa l'identità MidService al worker: evita cpim su UUID random ≠ header HTTP → 433.
        _deviceStore.InvalidateCache();
        var body = new Dictionary<string, string>(StringComparer.Ordinal)
        {
            ["command"] = command,
            ["adi_id"] = adiId.Trim(),
            ["provision_dir"] = provisioningDir,
            ["device_uuid"] = _deviceStore.GetOrCreateDeviceUuid(),
            ["local_user_uuid"] = _deviceStore.GetOrCreateLocalUserUuid(),
            ["client_info"] = _deviceStore.GetProvisioningClientInfo(),
        };
        foreach (var kv in args)
            body[kv.Key] = kv.Value;

        var json = JsonSerializer.Serialize(body);
        using var content = new ByteArrayContent(Encoding.UTF8.GetBytes(json));
        content.Headers.ContentType = new System.Net.Http.Headers.MediaTypeHeaderValue("application/json");

        try
        {
            using var response = await _http.PostAsync(
                    new Uri(_baseUri, "v1/bridge"),
                    content,
                    ct)
                .ConfigureAwait(false);
            var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException($"ADI worker HTTP {(int)response.StatusCode}: {text}");

            var doc = JsonDocument.Parse(text);
            if (doc.RootElement.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True)
                return doc;

            var error = doc.RootElement.TryGetProperty("error", out var err) ? err.GetString() : text;
            throw new InvalidOperationException($"ADI worker: {error}");
        }
        catch (HttpRequestException ex)
        {
            throw new InvalidOperationException(
                $"ADI worker non raggiungibile su {_baseUri.GetLeftPart(UriPartial.Authority)} " +
                $"(avvia: python scripts/akd-adi-worker/akd_adi_worker.py --port 6973): {ex.Message}",
                ex);
        }
        catch (TaskCanceledException ex) when (!ct.IsCancellationRequested)
        {
            throw new InvalidOperationException(
                $"ADI worker timeout su {_baseUri.GetLeftPart(UriPartial.Authority)}: {ex.Message}",
                ex);
        }
    }

    private static string GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;
}
