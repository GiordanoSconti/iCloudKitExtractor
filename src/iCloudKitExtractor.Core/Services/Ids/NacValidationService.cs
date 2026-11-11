using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Services.Auth;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Genera <c>validation-data</c> NAC.
/// Preferenza: HTTP relay (<c>IKE_NAC_RELAY_URL</c> / Anisette localhost) → locale pypush Unicorn.
/// </summary>
public sealed class NacValidationService
{
    private readonly string _scriptRoot;
    private readonly string _pythonExe;
    private static readonly HttpClient SharedHttp = CreateRelayHttp();

    public NacValidationService(string? scriptRoot = null, string? pythonExe = null)
    {
        _scriptRoot = scriptRoot ?? ResolveScriptRoot();
        _pythonExe = pythonExe ?? ResolvePython();
    }

    public string ScriptRoot => _scriptRoot;

    /// <summary>Resolved relay URL, or null when local Unicorn should run.</summary>
    public static string? ResolveRelayUrl()
    {
        var explicitUrl = Environment.GetEnvironmentVariable("IKE_NAC_RELAY_URL")?.Trim();
        if (!string.IsNullOrEmpty(explicitUrl))
            return explicitUrl;

        // Derive from Anisette when loopback (local IKE / SSH tunnel). Non-loopback only
        // when IKE_NAC_RELAY_FROM_ANISETTE=1 (same Mac Mini LAN URL).
        var anisette = Environment.GetEnvironmentVariable("ANISETTE_SERVER_URL")?.Trim();
        if (string.IsNullOrEmpty(anisette))
            return null;

        if (!Uri.TryCreate(anisette, UriKind.Absolute, out var baseUri))
            return null;

        if (!IsLoopbackHost(baseUri.Host))
        {
            var allow = Environment.GetEnvironmentVariable("IKE_NAC_RELAY_FROM_ANISETTE")?.Trim();
            if (!string.Equals(allow, "1", StringComparison.OrdinalIgnoreCase)
                && !string.Equals(allow, "true", StringComparison.OrdinalIgnoreCase))
                return null;
        }

        var root = anisette.TrimEnd('/');
        return root + "/validation-data";
    }

    public static bool IsRelayConfigured => !string.IsNullOrEmpty(ResolveRelayUrl());

    public async Task<byte[]> GenerateAsync(
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var relay = ResolveRelayUrl();
        if (!string.IsNullOrEmpty(relay))
        {
            try
            {
                return await GenerateViaRelayAsync(relay, log, ct).ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                log?.Invoke($"NAC relay failed ({relay}): {ex.Message} — falling back to local Unicorn.");
            }
        }

        return await GenerateLocalAsync(log, ct).ConfigureAwait(false);
    }

    /// <summary>Base64 per header <c>X-Mme-Nas-Qualify</c>.</summary>
    public async Task<string> GenerateNasQualifyBase64Async(
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var data = await GenerateAsync(log, ct).ConfigureAwait(false);
        return Convert.ToBase64String(data);
    }

    private static async Task<byte[]> GenerateViaRelayAsync(
        string url, Action<string>? log, CancellationToken ct)
    {
        log?.Invoke($"NAC relay: GET {url}");
        using var req = new HttpRequestMessage(HttpMethod.Get, url);
        RemoteAnisetteProvider.ApplyLicenseHeader(req);
        using var resp = await SharedHttp.SendAsync(req, ct).ConfigureAwait(false);
        var body = await resp.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!resp.IsSuccessStatusCode)
        {
            var detail = TryExtractError(body) ?? body;
            throw new InvalidOperationException(
                $"HTTP {(int)resp.StatusCode}: {Truncate(detail, 240)}");
        }

        using var doc = JsonDocument.Parse(body);
        var root = doc.RootElement;
        if (root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.False)
        {
            var err = root.TryGetProperty("error", out var e) ? e.GetString() : "relay ok=false";
            throw new InvalidOperationException(err ?? "relay ok=false");
        }

        if (!root.TryGetProperty("validation_data_b64", out var b64El))
            throw new InvalidOperationException("relay JSON missing validation_data_b64");

        var b64 = b64El.GetString()
                  ?? throw new InvalidOperationException("relay validation_data_b64 null");
        var bytes = Convert.FromBase64String(b64);
        var serial = root.TryGetProperty("serial", out var s) ? s.GetString() : null;
        var source = root.TryGetProperty("source", out var src) ? src.GetString() : "relay";
        log?.Invoke(
            $"NAC relay OK — validation-data {bytes.Length} B"
            + (string.IsNullOrEmpty(serial) ? "" : $" serial={serial}")
            + $" source={source}");
        if (root.TryGetProperty("warning", out var w) && w.ValueKind == JsonValueKind.String)
        {
            var warn = w.GetString();
            if (!string.IsNullOrEmpty(warn))
                log?.Invoke("NAC relay: " + warn);
        }

        return bytes;
    }

    private async Task<byte[]> GenerateLocalAsync(Action<string>? log, CancellationToken ct)
    {
        var script = Path.Combine(_scriptRoot, "generate_validation_data.py");
        if (!File.Exists(script))
            throw new InvalidOperationException(
                $"NAC script missing: {script}. Requires scripts/nac-pypush from pypush emulated.");

        var dataPlist = MadridDevicePersona.HasPersona()
            ? MadridDevicePersona.DataPlistPath
            : null;
        if (dataPlist is not null)
            log?.Invoke("NAC: using imported Mac persona → " + dataPlist);
        else
            log?.Invoke("NAC: using bundled pypush data.plist (spoofed Mac) — import a real Mac persona for Madrid.");

        log?.Invoke($"NAC local: {_pythonExe} {script} --json");

        var argList = new List<string>();
        if (string.Equals(Path.GetFileNameWithoutExtension(_pythonExe), "py", StringComparison.OrdinalIgnoreCase))
            argList.Add("-3");
        argList.Add(script);
        argList.Add("--json");
        if (dataPlist is not null)
        {
            argList.Add("--data-plist");
            argList.Add(dataPlist);
        }

        var args = string.Join(" ", argList.Select(a => a.Contains(' ') ? $"\"{a}\"" : a));

        var psi = new ProcessStartInfo
        {
            FileName = _pythonExe,
            Arguments = args,
            WorkingDirectory = _scriptRoot,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (dataPlist is not null)
            psi.Environment["IKE_NAC_DATA_PLIST"] = dataPlist;

        using var proc = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) =>
        {
            if (e.Data is null) return;
            stderr.AppendLine(e.Data);
            log?.Invoke("NAC: " + e.Data);
        };

        if (!proc.Start())
            throw new InvalidOperationException("NAC: cannot start Python.");

        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        if (proc.ExitCode != 0)
        {
            var err = stderr.ToString().Trim();
            if (string.IsNullOrEmpty(err))
                err = stdout.ToString().Trim();
            throw new InvalidOperationException(
                $"NAC exit={proc.ExitCode}: {(string.IsNullOrEmpty(err) ? "(no output)" : err)}");
        }

        var text = stdout.ToString().Trim();
        if (string.IsNullOrEmpty(text))
            throw new InvalidOperationException("NAC: empty stdout.");

        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.TryGetProperty("validation_data_b64", out var b64El))
            {
                var b64 = b64El.GetString()
                          ?? throw new InvalidOperationException("NAC JSON missing validation_data_b64.");
                var bytes = Convert.FromBase64String(b64);
                log?.Invoke($"NAC OK — validation-data {bytes.Length} B (local)");
                return bytes;
            }
        }
        catch (JsonException)
        {
            // fallback: raw base64 line
        }

        var raw = Convert.FromBase64String(text.Split('\n', StringSplitOptions.RemoveEmptyEntries)[^1].Trim());
        log?.Invoke($"NAC OK — validation-data {raw.Length} B (raw b64 local)");
        return raw;
    }

    private static HttpClient CreateRelayHttp()
    {
        var http = new HttpClient { Timeout = TimeSpan.FromSeconds(90) };
        http.DefaultRequestHeaders.TryAddWithoutValidation("User-Agent", "iCloudKitExtractor-NAC/1.0");
        return http;
    }

    private static bool IsLoopbackHost(string host) =>
        string.Equals(host, "localhost", StringComparison.OrdinalIgnoreCase)
        || string.Equals(host, "127.0.0.1", StringComparison.OrdinalIgnoreCase)
        || string.Equals(host, "::1", StringComparison.OrdinalIgnoreCase)
        || string.Equals(host, "[::1]", StringComparison.OrdinalIgnoreCase);

    private static string? TryExtractError(string body)
    {
        try
        {
            using var doc = JsonDocument.Parse(body);
            if (doc.RootElement.TryGetProperty("error", out var e))
                return e.GetString();
            if (doc.RootElement.TryGetProperty("detail", out var d))
                return d.GetString();
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static string Truncate(string s, int n) =>
        s.Length <= n ? s : s[..n] + "…";

    private static string ResolveScriptRoot()
    {
        var env = Environment.GetEnvironmentVariable("IKE_NAC_SCRIPT_ROOT")?.Trim();
        if (!string.IsNullOrEmpty(env) && Directory.Exists(env))
            return env;

        var baseDir = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "scripts", "nac-pypush")),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "scripts", "nac-pypush")),
            Path.GetFullPath(Path.Combine(baseDir, "scripts", "nac-pypush")),
            Path.GetFullPath(Path.Combine(baseDir, "nac-pypush")),
            Path.GetFullPath(Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
                "Desktop", "PROGRAMMAZIONE", "Projects", "iCloudKitExtractor", "scripts", "nac-pypush")),
        };

        foreach (var c in candidates)
        {
            if (File.Exists(Path.Combine(c, "generate_validation_data.py")))
                return c;
        }

        return candidates[^1];
    }

    private static string ResolvePython()
    {
        var env = Environment.GetEnvironmentVariable("IKE_PYTHON")?.Trim();
        if (!string.IsNullOrEmpty(env))
            return env;

        if (OperatingSystem.IsWindows())
            return "py";
        return "python3";
    }
}
