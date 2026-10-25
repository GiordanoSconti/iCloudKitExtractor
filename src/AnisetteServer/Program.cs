using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Text.Json.Serialization;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Auth;
using iCloudKitExtractor.Services.Http;

var port = ResolvePort(args);
var urls = Environment.GetEnvironmentVariable("ANISETTE_SERVER_URLS")
    ?? $"http://127.0.0.1:{port}";

// CLI --backend wins over env (avoids stale $env from setup-emulated-akd.ps1 in the same session).
var backend = ResolveBackend(args);

var adiWorkerUrl = Environment.GetEnvironmentVariable("AKD_ADI_WORKER_URL")?.Trim()
    ?? "http://127.0.0.1:6973";

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls(urls);

builder.Services.AddSingleton(_ =>
{
    var handler = new SocketsHttpHandler
    {
        AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate,
        PooledConnectionLifetime = TimeSpan.FromMinutes(5),
        SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = AppleCertificateTrust.ValidateServerCertificate
        }
    };
    return new HttpClient(handler) { Timeout = TimeSpan.FromMinutes(2) };
});

builder.Services.AddSingleton<IAnisetteProvider>(sp =>
{
    var http = sp.GetRequiredService<HttpClient>();
    if (backend is "frida" or "iphone-frida" or "jb-frida")
        return new FridaIphoneAnisetteProvider();
    return backend is "akd-emulated" or "akd"
        ? new EmulatedAkdAnisetteProvider(http, adiWorkerUrl)
        : new CoreAdiAnisetteProvider(http, AdiDeviceProfile.Ios);
});

var app = builder.Build();

app.MapGet("/health", async (HttpRequest req, IAnisetteProvider anisette, CancellationToken ct) =>
{
    // Frida iPhone: health senza attach (lento); mint solo su GET /.
    if (backend is "frida" or "iphone-frida" or "jb-frida")
    {
        var fr = anisette as FridaIphoneAnisetteProvider;
        return Results.Json(new
        {
            ok = fr is not null && File.Exists(fr.FetchScript),
            backend,
            provisioned = true,
            needsAppleId = false,
            host = fr?.Host,
            process = fr?.ProcessName,
            lite = fr?.Lite,
            fetchScript = fr?.FetchScript,
        });
    }

    try
    {
        _ = await anisette.FetchAsync(OptionsFromRequest(req), ct);
        return Results.Json(new { ok = true, backend, provisioned = true });
    }
    catch (Exception ex)
    {
        return FailResult(ex, backend, adiWorkerUrl);
    }
});

app.MapGet("/", async (HttpRequest req, IAnisetteProvider anisette, CancellationToken ct) =>
{
    try
    {
        var headers = await anisette.FetchAsync(OptionsFromRequest(req), ct);
        return Results.Json(new AnisetteResponse(headers));
    }
    catch (Exception ex)
    {
        return FailResult(ex, backend, adiWorkerUrl);
    }
});

// Compat RemoteAnisetteProvider / dadoum-style clients
app.MapGet("/get_headers", async (HttpRequest req, IAnisetteProvider anisette, CancellationToken ct) =>
{
    try
    {
        var headers = await anisette.FetchAsync(OptionsFromRequest(req), ct);
        return Results.Json(new AnisetteResponse(headers));
    }
    catch (Exception ex)
    {
        return FailResult(ex, backend, adiWorkerUrl);
    }
});
app.MapGet("/v1/get_headers", async (HttpRequest req, IAnisetteProvider anisette, CancellationToken ct) =>
{
    try
    {
        var headers = await anisette.FetchAsync(OptionsFromRequest(req), ct);
        return Results.Json(new AnisetteResponse(headers));
    }
    catch (Exception ex)
    {
        return FailResult(ex, backend, adiWorkerUrl);
    }
});

// Soft (default): se ADI già provisionata → no-op (OTP = GET / → request-otp).
// ?forceMid=1: stessa device identity, riparte MidService (wipe solo stato ADI).
// ?newIdentity=1: wipe UUID+ADI + MidService (può dare HTTP 433 da Apple se abusato).
app.MapPost("/provision", async (HttpRequest req, HttpClient http, IAnisetteProvider anisette, CancellationToken ct) =>
{
    try
    {
        var newIdentity = req.Query.TryGetValue("newIdentity", out var ni)
            && (ni == "1" || ni == "true");
        var forceMid = req.Query.TryGetValue("forceMid", out var fm)
            && (fm == "1" || fm == "true");

        var provisioning = CreateProvisioning(http, adiWorkerUrl, backend);

        // Wipe worker solo su newIdentity: soft repair non deve distruggere sessioni ADI
        // a ogni GET / (causa loop MidService 433). forceMid wipe via RepairProvisioning.
        if (newIdentity && backend is "akd-emulated" or "akd")
            await WipeAkdWorkerAsync(http, adiWorkerUrl, ct).ConfigureAwait(false);

        string fingerprint;
        if (newIdentity)
        {
            fingerprint = await provisioning
                .ForceNewIdentityAndProvisionAsync(ct)
                .ConfigureAwait(false);
        }
        else
        {
            // Soft / forceMid: stessa device-*.json.
            fingerprint = await provisioning
                .RepairProvisioningAsync(ct, forceMidService: forceMid)
                .ConfigureAwait(false);
        }

        // Invalidate after provision: singleton EmulatedAkd altrimenti tiene adi_id vecchio in RAM.
        if (anisette is EmulatedAkdAnisetteProvider emu)
            emu.InvalidateDeviceCache();
        else if (anisette is CoreAdiAnisetteProvider core)
            core.Provisioning.InvalidateDeviceCache();

        return Results.Json(new
        {
            ok = true,
            backend,
            profile = AdiDeviceProfile.Ios.Name,
            newIdentity,
            forceMid,
            fingerprint
        });
    }
    catch (Exception ex)
    {
        return FailResult(ex, backend, adiWorkerUrl);
    }
});

// Solo OTP fresco da ADI già provisionata (no MidService). Stesso di GET /.
app.MapPost("/otp", async (HttpRequest req, IAnisetteProvider anisette, CancellationToken ct) =>
{
    try
    {
        var headers = await anisette.FetchAsync(OptionsFromRequest(req), ct);
        return Results.Json(new AnisetteResponse(headers));
    }
    catch (Exception ex)
    {
        return FailResult(ex, backend, adiWorkerUrl);
    }
});

static AdiProvisioningService CreateProvisioning(HttpClient http, string workerUrl, string backendName) =>
    backendName is "akd-emulated" or "akd"
        ? new AdiProvisioningService(
            http,
            AdiDeviceProfile.Ios,
            new HttpAdiCryptoClient(http, workerUrl, AdiDeviceProfile.Ios))
        : new AdiProvisioningService(http, AdiDeviceProfile.Ios);

static async Task WipeAkdWorkerAsync(HttpClient http, string workerUrl, CancellationToken ct)
{
    try
    {
        using var wipe = await http
            .PostAsync($"{workerUrl.TrimEnd('/')}/provision", null, ct)
            .ConfigureAwait(false);
        _ = wipe;
    }
    catch (Exception ex)
    {
        throw new InvalidOperationException(
            $"ADI worker wipe fallito ({workerUrl}): {ex.Message}", ex);
    }
}

// #region agent log
static void AgentAniLog(string message, object data)
{
    try
    {
        var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["sessionId"] = "7dabb5",
            ["runId"] = "anisette-worker",
            ["hypothesisId"] = "H-ADI-WORKER",
            ["location"] = "AnisetteServer.Program",
            ["message"] = message,
            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            ["data"] = data,
        });
        File.AppendAllText(
            System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
            line + Environment.NewLine);
    }
    catch { /* ignore */ }
}
// #endregion

static IResult FailResult(Exception ex, string backendName, string workerUrl)
{
    var detail = ex.InnerException is not null
        ? $"{ex.Message} ({ex.InnerException.Message})"
        : ex.Message;
    var workerDown = detail.Contains("127.0.0.1:6973", StringComparison.OrdinalIgnoreCase)
        || detail.Contains("connection refused", StringComparison.OrdinalIgnoreCase)
        || detail.Contains("rifiuto persistente", StringComparison.OrdinalIgnoreCase)
        || detail.Contains("actively refused", StringComparison.OrdinalIgnoreCase);
    var mid433 = detail.Contains("HTTP 433", StringComparison.OrdinalIgnoreCase)
        || detail.Contains("midFinishProvisioning", StringComparison.OrdinalIgnoreCase)
        || detail.Contains("midStartProvisioning", StringComparison.OrdinalIgnoreCase);
    string? hint = null;
    if (workerDown)
    {
        hint = $"ADI worker spento su {workerUrl}. Avvia: .\\scripts\\setup-emulated-akd.ps1 " +
               "(o python scripts\\akd-adi-worker\\akd_adi_worker.py --port 6973).";
    }
    else if (mid433)
    {
        hint = "Apple MidService HTTP 433 = Anisette Reprovision Required (machine data changed). " +
               "Non ripetere wipe newIdentity: attendi qualche minuto, poi POST /provision (soft repair).";
    }
    else if (backendName is "frida" or "iphone-frida" or "jb-frida")
    {
        hint = "Frida/akd: verifica frida-server sull'iPhone (USB/Wi‑Fi), stessa versione frida-tools, " +
               "processo akd vivo. Attach serializzati + cache 90s — se 503 a raffica, ripeti dopo 1–2s.";
    }

    Console.Error.WriteLine($"[anisette] FAIL backend={backendName}: {detail}");
    if (hint is not null)
        Console.Error.WriteLine($"[anisette] {hint}");
    // #region agent log
    AgentAniLog("anisette_endpoint_fail", new
    {
        backend = backendName,
        workerUrl,
        workerDown,
        mid433,
        error = detail.Length > 240 ? detail[..240] : detail,
    });
    // #endregion
    return Results.Json(
        new { ok = false, backend = backendName, error = detail, hint, workerUrl },
        statusCode: 503);
}

Console.WriteLine($"AnisetteServer — {urls} (backend={backend})");
if (backend is "frida" or "iphone-frida" or "jb-frida")
{
    var fr = app.Services.GetRequiredService<IAnisetteProvider>() as FridaIphoneAnisetteProvider;
    Console.WriteLine("  backend Frida: iPhone jailbroken → fetch_anisette.py → AuthKit/akd");
    Console.WriteLine($"  Host:    {fr?.Host ?? "?"}");
    Console.WriteLine($"  Process: {fr?.ProcessName ?? "akd"} (lite={fr?.Lite})");
    Console.WriteLine($"  Script:  {fr?.FetchScript ?? FridaIphoneAnisetteProvider.ResolveFetchScriptPath()}");
    Console.WriteLine("  Env: FRIDA_ANISETTE_HOST, FRIDA_ANISETTE_PROCESS, FRIDA_ANISETTE_FETCH_PY,");
    Console.WriteLine("       FRIDA_ANISETTE_PYTHON, FRIDA_ANISETTE_LITE, FRIDA_ANISETTE_TIMEOUT");
    Console.WriteLine("  Serve frida-server sull'iPhone + frida-tools sul PC (stessa versione).");
}
else if (backend is "akd-emulated" or "akd")
{
    Console.WriteLine("  akd emulato: MidService Anisette.py + ADI worker Android (no CoreADI64)");
    Console.WriteLine($"  ADI worker: {adiWorkerUrl}");
    Console.WriteLine("  Vedi docs/EMULATED_AKD.md");
    // Probe worker at startup (non-blocking failure — just warn).
    try
    {
        using var probe = new HttpClient { Timeout = TimeSpan.FromSeconds(3) };
        var health = await probe.GetAsync($"{adiWorkerUrl.TrimEnd('/')}/health");
        if (health.IsSuccessStatusCode)
            Console.WriteLine("  ADI worker: OK");
        else
            Console.WriteLine($"  ADI worker: HTTP {(int)health.StatusCode} — OTP fallirà finché non è su.");
    }
    catch (Exception ex)
    {
        Console.WriteLine($"  ADI worker: NON RAGGIUNGIBILE ({ex.Message})");
        Console.WriteLine("  Avvia prima: python scripts\\akd-adi-worker\\akd_adi_worker.py --port 6973");
        Console.WriteLine("  Oppure: .\\scripts\\setup-emulated-akd.ps1");
        // #region agent log
        AgentAniLog("adi_worker_unreachable_at_startup", new
        {
            workerUrl = adiWorkerUrl,
            error = ex.Message,
        });
        // #endregion
    }
}
else
{
    Console.WriteLine("  ATTENZIONE: backend CoreADI Windows — non è akd iPhone emulato.");
    Console.WriteLine("  Usa ANISETTE_SERVER_BACKEND=akd-emulated");
}

Console.WriteLine("  GET  /              → OTP fresco (ADI provisionata → request-otp)");
Console.WriteLine("  GET  /get_headers   → alias /");
Console.WriteLine("  GET  /v1/get_headers → alias /");
Console.WriteLine("  POST /otp           → alias OTP (no MidService)");
Console.WriteLine("  POST /provision → soft: no-op se già provisionata");
Console.WriteLine("  POST /provision?forceMid=1 → MidService stessa identity");
Console.WriteLine("  POST /provision?newIdentity=1 → wipe UUID+ADI (può dare HTTP 433)");

await app.RunAsync();

static AnisetteFetchOptions? OptionsFromRequest(HttpRequest req)
{
    var appleId = req.Query["apple_id"].FirstOrDefault()
        ?? req.Query["appleId"].FirstOrDefault()
        ?? req.Headers["X-Apple-Id"].FirstOrDefault();
    var fresh = req.Query.TryGetValue("fresh", out var fv)
        && (fv == "1" || fv == "true");
    if (!fresh && string.IsNullOrWhiteSpace(appleId))
        return null;
    return new AnisetteFetchOptions
    {
        AppleId = string.IsNullOrWhiteSpace(appleId) ? null : appleId.Trim(),
        ForceFresh = fresh,
    };
}

static string ResolveBackend(string[] args)
{
    string? chosen = null;
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "--backend" or "-b")
        {
            var v = args[i + 1]?.Trim().ToLowerInvariant();
            if (!string.IsNullOrEmpty(v))
                chosen = v;
        }
    }

    chosen ??= Environment.GetEnvironmentVariable("ANISETTE_SERVER_BACKEND")?.Trim().ToLowerInvariant()
        ?? "coreadi";

    if (chosen is "rad" or "elcomsoft-rad" or "epb" or "epb-oracle")
    {
        throw new InvalidOperationException(
            $"Backend anisette '{chosen}' rimosso. Usa: frida | akd-emulated | coreadi.");
    }

    return chosen;
}

static int ResolvePort(string[] args)
{
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (args[i] is "--port" or "-p" && int.TryParse(args[i + 1], out var port))
            return port;
    }

    if (int.TryParse(Environment.GetEnvironmentVariable("ANISETTE_SERVER_PORT"), out var envPort))
        return envPort;

    return 6969;
}

sealed class AnisetteResponse
{
    public AnisetteResponse(AnisetteHeaders h)
    {
        Md = h.Md;
        MdM = h.MdM;
        MdLu = h.MdLu;
        MdRinfo = h.MdRinfo;
        ClientMmeInfo = h.ClientMmeInfo;
        MmeDeviceId = h.MmeDeviceId;
        ClientTime = h.ClientTimeUtc;
        SerialNumber = h.SerialNumber;
        ClientProductType = h.ClientProductType;
        Locale = h.Locale;
        TimeZone = h.TimeZone;
        CountryCode = h.CountryCode;
    }

    [JsonPropertyName("X-Apple-I-MD")]
    public string Md { get; }

    [JsonPropertyName("X-Apple-I-MD-M")]
    public string MdM { get; }

    [JsonPropertyName("X-Apple-I-MD-LU")]
    public string MdLu { get; }

    [JsonPropertyName("X-Apple-I-MD-RINFO")]
    public string MdRinfo { get; }

    [JsonPropertyName("X-MMe-Client-Info")]
    public string ClientMmeInfo { get; }

    [JsonPropertyName("X-Mme-Device-Id")]
    public string MmeDeviceId { get; }

    [JsonPropertyName("X-Apple-I-Client-Time")]
    public string ClientTime { get; }

    [JsonPropertyName("serialNumber")]
    public string SerialNumber { get; }

    [JsonPropertyName("clientProductType")]
    public string ClientProductType { get; }

    [JsonPropertyName("locale")]
    public string Locale { get; }

    [JsonPropertyName("timeZone")]
    public string TimeZone { get; }

    [JsonPropertyName("countryCode")]
    public string CountryCode { get; }
}
