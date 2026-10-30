using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Anisette da iPhone jailbroken via Frida (<c>fetch_anisette.py</c> → <c>frida_tools.repl</c> → AuthKit/akd).
/// Backend: <c>ANISETTE_SERVER_BACKEND=frida</c> (alias: <c>iphone-frida</c>, <c>jb-frida</c>).
/// Attach serializzato + cache corta: IKE remint paralleli non devono martellare akd.
/// </summary>
public sealed class FridaIphoneAnisetteProvider : IAnisetteProvider
{
    private static readonly Regex ProductTypeRx = new(
        @"<(?<model>[A-Za-z0-9,]+)>",
        RegexOptions.Compiled | RegexOptions.CultureInvariant);

    /// <summary>Riuso OTP tra GET paralleli / mid-download (Frida attach è costoso).</summary>
    private static readonly TimeSpan CacheTtl = TimeSpan.FromMinutes(5);

    private readonly string _python;
    private readonly string _fetchScript;
    private readonly string _host;
    private readonly string _processName;
    private readonly bool _lite;
    private readonly int _timeoutSec;
    private readonly SemaphoreSlim _gate = new(1, 1);
    private AnisetteHeaders? _cache;
    private DateTime _cacheUtc;

    public FridaIphoneAnisetteProvider()
        : this(null)
    {
    }

    /// <summary>Explicit Frida/host settings (Mac middleware UI); null fields fall back to env/defaults.</summary>
    public FridaIphoneAnisetteProvider(FridaAnisetteOptions? options)
    {
        _python = ResolvePythonExecutable(
            options?.Python,
            Environment.GetEnvironmentVariable("FRIDA_ANISETTE_PYTHON"));
        _fetchScript = FirstNonEmpty(
            options?.FetchScript,
            Environment.GetEnvironmentVariable("FRIDA_ANISETTE_FETCH_PY"),
            null) is { Length: > 0 } customScript
            ? NormalizeFetchPyPath(customScript)
            : ResolveFetchScriptPath();
        _host = FirstNonEmpty(
            options?.Host,
            Environment.GetEnvironmentVariable("FRIDA_ANISETTE_HOST"),
            "127.0.0.1:27042")!;
        _processName = FirstNonEmpty(
            options?.ProcessName,
            Environment.GetEnvironmentVariable("FRIDA_ANISETTE_PROCESS"),
            "akd")!;
        if (options?.Lite is bool liteOpt)
            _lite = liteOpt;
        else
        {
            var liteEnv = Environment.GetEnvironmentVariable("FRIDA_ANISETTE_LITE")?.Trim();
            _lite = string.IsNullOrEmpty(liteEnv)
                || liteEnv is "1" or "true" or "yes";
        }

        if (options?.TimeoutSec is int to && to > 0)
            _timeoutSec = to;
        else
        {
            _timeoutSec = int.TryParse(
                Environment.GetEnvironmentVariable("FRIDA_ANISETTE_TIMEOUT")?.Trim(),
                out var t) && t > 0
                ? t
                : 60;
        }
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values)
        {
            if (!string.IsNullOrWhiteSpace(v))
                return v.Trim();
        }
        return null;
    }

    /// <summary>
    /// Resolve a real Python interpreter. On Windows, <c>python</c> / <c>python3</c> on PATH may be
    /// the Microsoft Store alias under <c>WindowsApps</c> (exit 9009) even when a normal install
    /// exists later on PATH — interactive shells sometimes hit a different order than GUI apps.
    /// We pick the first non-Store hit and return its <b>absolute</b> path so CreateProcess
    /// cannot fall back to the stub.
    /// </summary>
    public static string ResolvePythonExecutable(params string?[] preferred)
    {
        foreach (var p in preferred)
        {
            if (string.IsNullOrWhiteSpace(p))
                continue;
            var t = p.Trim();
            if (File.Exists(t) && !IsWindowsStorePythonStubPath(t))
                return t;
            var fromPath = FindOnPath(t);
            if (fromPath is not null)
                return fromPath;
        }

        // Windows labs usually invoke `python` (python3 is often the Store stub).
        // macOS/Linux typically have `python3`.
        string[] candidates = OperatingSystem.IsWindows()
            ?
            [
                "python.exe", "python",
                "python3.exe", "python3",
            ]
            :
            [
                "python3", "python",
            ];

        foreach (var candidate in candidates)
        {
            var hit = FindOnPath(candidate);
            if (hit is not null)
                return hit;
        }

        return OperatingSystem.IsWindows() ? "python" : "python3";
    }

    private static string? FindOnPath(string fileName)
    {
        if (fileName.IndexOfAny(['/', '\\', ':']) >= 0)
            return File.Exists(fileName) && !IsWindowsStorePythonStubPath(fileName) ? fileName : null;

        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? "";
        foreach (var dir in pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries))
        {
            try
            {
                var baseDir = dir.Trim().Trim('"');
                if (baseDir.Length == 0)
                    continue;

                foreach (var name in ExecutableNameVariants(fileName))
                {
                    var full = Path.Combine(baseDir, name);
                    if (File.Exists(full) && !IsWindowsStorePythonStubPath(full))
                        return full;
                }
            }
            catch
            {
                // ignore bad PATH entries
            }
        }

        return null;
    }

    private static IEnumerable<string> ExecutableNameVariants(string fileName)
    {
        yield return fileName;
        if (OperatingSystem.IsWindows()
            && !fileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
            yield return fileName + ".exe";
    }

    private static bool IsWindowsStorePythonStubPath(string fullPath) =>
        fullPath.Contains(@"\WindowsApps\", StringComparison.OrdinalIgnoreCase)
        || fullPath.Contains(@"\Microsoft\WindowsApps\", StringComparison.OrdinalIgnoreCase);

    public string Host => _host;
    public string ProcessName => _processName;
    public string FetchScript => _fetchScript;
    public bool Lite => _lite;

    public Task<AnisetteHeaders> FetchAsync(CancellationToken ct = default) =>
        FetchCoreAsync(forceFresh: false, ct);

    public Task<AnisetteHeaders> FetchAsync(AnisetteFetchOptions? options, CancellationToken ct = default) =>
        FetchCoreAsync(forceFresh: options?.ForceFresh == true, ct);

    /// <summary>Scarta OTP in cache (re-login GrandSlam / dopo sessione scaduta).</summary>
    public void InvalidateCache()
    {
        _cache = null;
        _cacheUtc = default;
    }

    private async Task<AnisetteHeaders> FetchCoreAsync(bool forceFresh, CancellationToken ct)
    {
        if (forceFresh)
            InvalidateCache();
        else if (TryGetCached(out var cachedHit))
            return cachedHit;

        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (forceFresh)
                InvalidateCache();
            else if (TryGetCached(out var lockedHit))
                return lockedHit;

            var fresh = await MintViaFridaAsync(ct).ConfigureAwait(false);
            _cache = fresh;
            _cacheUtc = DateTime.UtcNow;
            // Snapshot esatto del mint (MD + Client-Time). Non TouchClientTime qui:
            // GsService2 rifiuta stesso MD con clock avanzato (ec=-22410).
            return Clone(fresh);
        }
        finally
        {
            _gate.Release();
        }
    }

    private bool TryGetCached(out AnisetteHeaders headers)
    {
        headers = null!;
        var cached = _cache;
        if (cached is null || !cached.HasMachineData)
            return false;
        if (DateTime.UtcNow - _cacheUtc > CacheTtl)
            return false;
        // Soft reuse mid-download: aggiorna solo Client-Time (CloudKit tollera; GSA no —
        // i path GrandSlam devono usare ForceFresh).
        headers = Clone(cached);
        headers.TouchClientTimeUtc();
        return true;
    }

    private async Task<AnisetteHeaders> MintViaFridaAsync(CancellationToken ct)
    {
        if (!File.Exists(_fetchScript))
        {
            throw new FileNotFoundException(
                "fetch_anisette.py assente. Imposta FRIDA_ANISETTE_FETCH_PY " +
                "sul file o sulla directory ios_akd_probe (scripts/ios_akd_probe).",
                _fetchScript);
        }

        var args = new StringBuilder();
        args.Append(QuoteArg(_fetchScript));
        args.Append(" -H ").Append(QuoteArg(_host));
        args.Append(" -n ").Append(QuoteArg(_processName));
        args.Append(" --timeout ").Append(_timeoutSec.ToString(CultureInfo.InvariantCulture));
        if (_lite)
            args.Append(" --lite");

        var psi = new ProcessStartInfo
        {
            FileName = _python,
            Arguments = args.ToString(),
            WorkingDirectory = Path.GetDirectoryName(_fetchScript) ?? Environment.CurrentDirectory,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8,
        };

        using var proc = new Process { StartInfo = psi };
        if (!proc.Start())
            throw new InvalidOperationException($"Impossibile avviare {_python}");

        var stdoutTask = proc.StandardOutput.ReadToEndAsync(ct);
        var stderrTask = proc.StandardError.ReadToEndAsync(ct);

        using var reg = ct.Register(() =>
        {
            try
            {
                if (!proc.HasExited)
                    proc.Kill(entireProcessTree: true);
            }
            catch
            {
                /* ignore */
            }
        });

        // Frida attach + script; budget = timeout script + margine
        var waitMs = Math.Max(15_000, (_timeoutSec + 30) * 1000);
        var exited = await Task.Run(() => proc.WaitForExit(waitMs), ct).ConfigureAwait(false);
        if (!exited)
        {
            try { proc.Kill(entireProcessTree: true); } catch { /* ignore */ }
            throw new TimeoutException(
                $"Frida anisette timeout dopo {waitMs}ms (host={_host}, process={_processName}).");
        }

        var stdout = (await stdoutTask.ConfigureAwait(false)).Trim();
        var stderr = (await stderrTask.ConfigureAwait(false)).Trim();

        if (proc.ExitCode != 0 && string.IsNullOrWhiteSpace(stdout))
        {
            var detail = stderr.Length > 0 ? stderr : "(no output)";
            if (proc.ExitCode == 9009
                || detail.Contains("Python was not found", StringComparison.OrdinalIgnoreCase)
                || detail.Contains("Microsoft Store", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"fetch_anisette exit={proc.ExitCode}: {detail} " +
                    $"— interpreter tried: '{_python}'. Set FRIDA_ANISETTE_PYTHON to the full path from " +
                    $"`where.exe python` (avoid WindowsApps Store stubs), or the Mac UI Python field.");
            }

            throw new InvalidOperationException(
                $"fetch_anisette exit={proc.ExitCode}: {detail}");
        }

        // Ultima riga JSON (stdout può avere rumore raro)
        var jsonLine = stdout;
        var lastNl = stdout.LastIndexOf('\n');
        if (lastNl >= 0 && lastNl < stdout.Length - 1)
            jsonLine = stdout[(lastNl + 1)..].Trim();
        if (string.IsNullOrWhiteSpace(jsonLine))
        {
            throw new InvalidOperationException(
                $"fetch_anisette: stdout vuoto. stderr={Truncate(stderr, 400)}");
        }

        using var doc = JsonDocument.Parse(jsonLine);
        var root = doc.RootElement;
        if (root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.False)
        {
            var err = root.TryGetProperty("error", out var e) ? e.GetString() : "ok=false";
            throw new InvalidOperationException($"Frida anisette: {err}");
        }

        string Pick(params string[] keys)
        {
            foreach (var k in keys)
            {
                if (root.TryGetProperty(k, out var el))
                {
                    if (el.ValueKind == JsonValueKind.String)
                    {
                        var s = el.GetString()?.Trim();
                        if (!string.IsNullOrEmpty(s) && s is not "null")
                            return s;
                    }
                    else if (el.ValueKind == JsonValueKind.Number)
                    {
                        return el.GetRawText();
                    }
                }
            }

            return "";
        }

        var md = Pick("X-Apple-I-MD");
        var mdM = Pick("X-Apple-I-MD-M");
        if (string.IsNullOrEmpty(md) || string.IsNullOrEmpty(mdM))
        {
            throw new InvalidOperationException(
                "Frida anisette: mancano X-Apple-I-MD / X-Apple-I-MD-M nel JSON.");
        }

        var clientInfo = Pick("X-MMe-Client-Info");
        var product = ExtractProductType(clientInfo);
        var rinfo = Pick("X-Apple-I-MD-RINFO");
        if (string.IsNullOrEmpty(rinfo))
            rinfo = "33883392";

        return new AnisetteHeaders
        {
            Md = md,
            MdM = mdM,
            MdLu = Pick("X-Apple-I-MD-LU"),
            MdRinfo = rinfo,
            MmeDeviceId = Pick("X-Mme-Device-Id"),
            ClientMmeInfo = clientInfo,
            ClientProductType = product,
            SerialNumber = Pick("serialNumber", "X-Apple-I-SRL-NO"),
            Locale = "en_US",
            TimeZone = TimeZoneInfo.Local.Id,
            CountryCode = "US",
            ClientTimeUtc = DateTime.UtcNow.ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
        };
    }

    private static AnisetteHeaders Clone(AnisetteHeaders h) => new()
    {
        Md = h.Md,
        MdM = h.MdM,
        MdLu = h.MdLu,
        MdRinfo = h.MdRinfo,
        MmeDeviceId = h.MmeDeviceId,
        ClientMmeInfo = h.ClientMmeInfo,
        ClientProductType = h.ClientProductType,
        SerialNumber = h.SerialNumber,
        Locale = h.Locale,
        TimeZone = h.TimeZone,
        CountryCode = h.CountryCode,
        ClientTimeUtc = h.ClientTimeUtc,
    };

    /// <summary>
    /// Path a <c>fetch_anisette.py</c>.
    /// <c>FRIDA_ANISETTE_FETCH_PY</c> può essere il file oppure la directory
    /// <c>ios_akd_probe</c> (si usa <c>fetch_anisette.py</c> al suo interno).
    /// Default: <c>ios_akd_probe/</c> accanto all'exe (publish) o
    /// <c>scripts/ios_akd_probe/</c> nel repo.
    /// </summary>
    public static string ResolveFetchScriptPath()
    {
        var env = Environment.GetEnvironmentVariable("FRIDA_ANISETTE_FETCH_PY")?.Trim();
        if (!string.IsNullOrEmpty(env))
            return NormalizeFetchPyPath(env);

        var here = AppContext.BaseDirectory;
        var candidates = new[]
        {
            // Publish / run output: scripts copiati in ios_akd_probe/
            Path.GetFullPath(Path.Combine(here, "ios_akd_probe", "fetch_anisette.py")),
            // Dev: AnisetteServer bin → …/src/AnisetteServer → repo root scripts/
            Path.GetFullPath(Path.Combine(here, "..", "..", "..", "..", "..",
                "scripts", "ios_akd_probe", "fetch_anisette.py")),
            Path.GetFullPath(Path.Combine(here, "..", "..", "..", "..",
                "scripts", "ios_akd_probe", "fetch_anisette.py")),
            // Legacy sibling iCloudDownloader checkout
            Path.GetFullPath(Path.Combine(here, "..", "..", "..", "..", "..",
                "iCloudDownloader", "mitm", "ios_akd_probe", "fetch_anisette.py")),
        };

        foreach (var c in candidates)
        {
            if (File.Exists(c))
                return c;
        }

        return candidates[0];
    }

    /// <summary>
    /// Accetta path al .py oppure alla cartella <c>ios_akd_probe</c>.
    /// </summary>
    public static string NormalizeFetchPyPath(string pathOrDir)
    {
        var full = Path.GetFullPath(pathOrDir.Trim());
        if (Directory.Exists(full))
            return Path.Combine(full, "fetch_anisette.py");
        return full;
    }

    private static string ExtractProductType(string clientInfo)
    {
        if (string.IsNullOrEmpty(clientInfo))
            return "iPhone";
        var m = ProductTypeRx.Match(clientInfo);
        return m.Success ? m.Groups["model"].Value : "iPhone";
    }

    private static string QuoteArg(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "\"\"";
        if (value.Contains('"', StringComparison.Ordinal))
            value = value.Replace("\"", "\\\"", StringComparison.Ordinal);
        return value.Contains(' ', StringComparison.Ordinal) ? $"\"{value}\"" : value;
    }

    private static string Truncate(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
