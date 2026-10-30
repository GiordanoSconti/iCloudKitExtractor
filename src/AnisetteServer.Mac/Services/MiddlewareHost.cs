using System.Globalization;
using System.Text.Json.Serialization;
using iCloudKitExtractor.AnisetteLicense;
using iCloudKitExtractor.AnisetteServer.Licensed.Hosting;
using iCloudKitExtractor.AnisetteServer.Licensed.Licensing;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Auth;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace AnisetteServer.Mac.Services;

public sealed class MiddlewareHost : IAsyncDisposable
{
    private WebApplication? _app;
    private CancellationTokenSource? _cts;
    private Task? _runTask;

    public bool IsRunning => _app is not null;
    public string StatusText { get; private set; } = "Stopped";
    public string LastError { get; private set; } = "";
    public string LastMintSummary { get; private set; } = "";
    public event Action? Changed;

    public async Task StartAsync(MiddlewareSettings settings)
    {
        if (_app is not null)
            return;

        settings.EnsureKeys();
        settings.ApplyToEnvironment();
        settings.Save();

        LastError = "";
        StatusText = "Starting…";
        Changed?.Invoke();

        var builder = WebApplication.CreateBuilder(new WebApplicationOptions
        {
            Args = Array.Empty<string>(),
            ApplicationName = typeof(MiddlewareHost).Assembly.FullName,
        });
        builder.Logging.ClearProviders();
        builder.Logging.AddConsole();
        AnisetteHttpsHosting.Configure(builder, settings.ListenUrls);

        builder.Services.AddSingleton(_ => new LicenseDatabase(LicensePaths.DatabasePath));
        builder.Services.AddSingleton(sp =>
            new LicenseValidator(LicensePaths.PublicKeyPath, sp.GetRequiredService<LicenseDatabase>()));
        builder.Services.AddSingleton(sp =>
            new LicenseIssuer(
                LicensePaths.PrivateKeyPath,
                LicensePaths.PublicKeyPath,
                sp.GetRequiredService<LicenseDatabase>()));
        builder.Services.AddSingleton<IAnisetteProvider>(_ =>
            new FridaIphoneAnisetteProvider(new FridaAnisetteOptions
            {
                Host = settings.FridaHost,
                ProcessName = settings.FridaProcess,
                Python = settings.Python,
                FetchScript = settings.FetchScript,
                Lite = settings.Lite,
                TimeoutSec = settings.TimeoutSec,
            }));

        var app = builder.Build();
        app.UseMiddleware<LicenseAuthMiddleware>();

        app.MapGet("/health", (IAnisetteProvider anisette) =>
        {
            var fr = anisette as FridaIphoneAnisetteProvider;
            return Results.Json(new
            {
                ok = fr is not null && File.Exists(fr.FetchScript),
                backend = "frida",
                host = fr?.Host,
                process = fr?.ProcessName,
                lite = fr?.Lite,
                fetchScript = fr?.FetchScript,
                licensed = true,
            });
        });

        async Task<IResult> Mint(HttpContext ctx, IAnisetteProvider anisette, CancellationToken ct)
        {
            try
            {
                var forceFresh = ctx.Request.Query.TryGetValue("fresh", out var f)
                    && (f == "1" || f == "true");
                var headers = await anisette
                    .FetchAsync(new AnisetteFetchOptions { ForceFresh = forceFresh }, ct)
                    .ConfigureAwait(false);
                var bundle = ctx.Items.TryGetValue("anisette_license_bundle", out var b)
                    ? b as string
                    : null;
                LastMintSummary = $"{DateTime.Now:HH:mm:ss} OK MD-M={Truncate(headers.MdM, 12)}";
                Changed?.Invoke();
                return Results.Json(new MintResponse(headers, bundle));
            }
            catch (Exception ex)
            {
                LastError = ex.Message;
                LastMintSummary = $"{DateTime.Now:HH:mm:ss} FAIL: {Truncate(ex.Message, 80)}";
                Changed?.Invoke();
                return Results.Json(new
                {
                    ok = false,
                    backend = "frida",
                    error = ex.Message,
                }, statusCode: 503);
            }
        }

        app.MapGet("/", Mint);
        app.MapGet("/get_headers", Mint);
        app.MapGet("/v1/get_headers", Mint);
        app.MapPost("/otp", Mint);

        _cts = new CancellationTokenSource();
        _app = app;
        _runTask = app.RunAsync(_cts.Token);
        var tlsNote = settings.ListenUrls.Contains("https://", StringComparison.OrdinalIgnoreCase)
            ? $" · TLS {AnisetteTlsCertificate.CerPath}"
            : "";
        StatusText = $"Listening {settings.ListenUrls} → Frida {settings.FridaHost}{tlsNote}";
        Changed?.Invoke();

        // Surface startup failures quickly
        _ = Task.Run(async () =>
        {
            try
            {
                await Task.Delay(800).ConfigureAwait(false);
                if (_runTask.IsFaulted)
                {
                    LastError = _runTask.Exception?.GetBaseException().Message ?? "host faulted";
                    StatusText = "Faulted";
                    Changed?.Invoke();
                }
            }
            catch
            {
                // ignore
            }
        });

        await Task.CompletedTask;
    }

    public async Task StopAsync()
    {
        if (_app is null)
            return;

        try
        {
            await _app.StopAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
        }

        try
        {
            _cts?.Cancel();
            if (_runTask is not null)
                await _runTask.ConfigureAwait(false);
        }
        catch
        {
            // ignore cancel
        }

        await _app.DisposeAsync().ConfigureAwait(false);
        _app = null;
        _cts = null;
        _runTask = null;
        StatusText = "Stopped";
        Changed?.Invoke();
    }

    public async ValueTask DisposeAsync() => await StopAsync().ConfigureAwait(false);

    private static string Truncate(string? s, int n)
    {
        if (string.IsNullOrEmpty(s))
            return "";
        return s.Length <= n ? s : s[..n] + "…";
    }

    private sealed class MintResponse
    {
        public MintResponse(AnisetteHeaders h, string? licenseBundle)
        {
            Md = h.Md;
            MdM = h.MdM;
            MdLu = h.MdLu;
            MdRinfo = h.MdRinfo;
            ClientMmeInfo = h.ClientMmeInfo;
            MmeDeviceId = h.MmeDeviceId;
            ClientTime = string.IsNullOrEmpty(h.ClientTimeUtc)
                ? DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
                : h.ClientTimeUtc;
            SerialNumber = h.SerialNumber;
            ClientProductType = h.ClientProductType;
            Locale = h.Locale;
            TimeZone = h.TimeZone;
            CountryCode = h.CountryCode;
            LicenseBundle = licenseBundle;
        }

        [JsonPropertyName("X-Apple-I-MD")] public string Md { get; }
        [JsonPropertyName("X-Apple-I-MD-M")] public string MdM { get; }
        [JsonPropertyName("X-Apple-I-MD-LU")] public string MdLu { get; }
        [JsonPropertyName("X-Apple-I-MD-RINFO")] public string MdRinfo { get; }
        [JsonPropertyName("X-MMe-Client-Info")] public string ClientMmeInfo { get; }
        [JsonPropertyName("X-Mme-Device-Id")] public string MmeDeviceId { get; }
        [JsonPropertyName("X-Apple-I-Client-Time")] public string ClientTime { get; }
        [JsonPropertyName("serialNumber")] public string SerialNumber { get; }
        [JsonPropertyName("clientProductType")] public string ClientProductType { get; }
        [JsonPropertyName("locale")] public string Locale { get; }
        [JsonPropertyName("timeZone")] public string TimeZone { get; }
        [JsonPropertyName("countryCode")] public string CountryCode { get; }
        [JsonPropertyName("license_bundle")]
        [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
        public string? LicenseBundle { get; }
    }
}
