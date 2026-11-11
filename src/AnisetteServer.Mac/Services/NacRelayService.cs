using System.Diagnostics;
using System.Text;
using System.Text.Json;

namespace AnisetteServer.Mac.Services;

/// <summary>
/// Local NAC validation-data for IKE.
/// Prefers native Absinthe (<c>native/AbsintheNac</c>), falls back to pypush Unicorn.
/// </summary>
public sealed class NacRelayService
{
    private static readonly string IokitGuid = "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14";
    private readonly SemaphoreSlim _gate = new(1, 1);
    private readonly string _backend;

    public string ScriptRoot { get; }
    public string AbsintheScript { get; }
    public string PythonExe { get; }
    public string DataPlistPath { get; }
    public string? LastWarning { get; private set; }
    public string LastBackend { get; private set; } = "";

    public NacRelayService(MiddlewareSettings settings)
    {
        PythonExe = string.IsNullOrWhiteSpace(settings.Python) ? "python3" : settings.Python.Trim();
        ScriptRoot = ResolveScriptRoot(settings.NacScriptRoot);
        AbsintheScript = ResolveAbsintheScript(settings.NacAbsintheScript);
        DataPlistPath = ResolveDataPlistPath(settings);
        _backend = ResolveBackend(settings.NacBackend);
    }

    public async Task<NacRelayResult> GenerateAsync(CancellationToken ct = default)
    {
        await _gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            return await GenerateCoreAsync(ct).ConfigureAwait(false);
        }
        finally
        {
            _gate.Release();
        }
    }

    private async Task<NacRelayResult> GenerateCoreAsync(CancellationToken ct)
    {
        var preferAbsinthe = _backend is "auto" or "absinthe";
        var preferPypush = _backend is "auto" or "pypush";

        if (preferAbsinthe && File.Exists(AbsintheScript))
        {
            var absinthe = await RunPythonJsonAsync(
                AbsintheScript,
                workingDir: Path.GetDirectoryName(AbsintheScript)!,
                extraArgs: ["--json"],
                env: null,
                ct).ConfigureAwait(false);
            if (absinthe.Success)
            {
                LastBackend = "absinthe-native";
                LastWarning = absinthe.Warning;
                return absinthe with { Warning = MergeWarn(absinthe.Warning, "source=absinthe-native") };
            }

            if (_backend == "absinthe")
                return absinthe;

            LastWarning = "Absinthe native failed → pypush: " + absinthe.Error;
        }
        else if (_backend == "absinthe")
        {
            return NacRelayResult.Fail($"Absinthe script missing: {AbsintheScript}");
        }

        if (!preferPypush)
            return NacRelayResult.Fail($"NAC backend '{_backend}' unavailable.");

        EnsurePersona(out var personaNote);
        LastWarning = MergeWarn(LastWarning, personaNote);

        var script = Path.Combine(ScriptRoot, "generate_validation_data.py");
        if (!File.Exists(script))
        {
            return NacRelayResult.Fail(
                $"NAC script missing: {script}. Set nacScriptRoot or IKE_NAC_SCRIPT_ROOT.");
        }

        var binary = Path.Combine(ScriptRoot, "emulated", "IMDAppleServices");
        if (!File.Exists(binary))
        {
            return NacRelayResult.Fail(
                $"IMDAppleServices missing at {binary}. Download from JJTech0130/nacserver.");
        }

        var pypush = await RunPythonJsonAsync(
            script,
            workingDir: ScriptRoot,
            extraArgs: ["--json", "--data-plist", DataPlistPath],
            env: new Dictionary<string, string> { ["IKE_NAC_DATA_PLIST"] = DataPlistPath },
            ct).ConfigureAwait(false);
        if (pypush.Success)
        {
            LastBackend = "nac-pypush";
            return pypush with { Warning = MergeWarn(pypush.Warning, LastWarning) };
        }

        return pypush;
    }

    private async Task<NacRelayResult> RunPythonJsonAsync(
        string script,
        string workingDir,
        IReadOnlyList<string> extraArgs,
        Dictionary<string, string>? env,
        CancellationToken ct)
    {
        var argList = new List<string> { script };
        argList.AddRange(extraArgs);
        var args = string.Join(" ", argList.Select(QuoteArg));

        var psi = new ProcessStartInfo
        {
            FileName = PythonExe,
            Arguments = args,
            WorkingDirectory = workingDir,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
        };
        if (env is not null)
        {
            foreach (var (k, v) in env)
                psi.Environment[k] = v;
        }

        using var proc = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        proc.OutputDataReceived += (_, e) => { if (e.Data is not null) stdout.AppendLine(e.Data); };
        proc.ErrorDataReceived += (_, e) => { if (e.Data is not null) stderr.AppendLine(e.Data); };

        if (!proc.Start())
            return NacRelayResult.Fail("Cannot start Python for NAC.");

        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();
        await proc.WaitForExitAsync(ct).ConfigureAwait(false);

        if (proc.ExitCode != 0)
        {
            var err = stderr.ToString().Trim();
            if (string.IsNullOrEmpty(err))
                err = stdout.ToString().Trim();
            try
            {
                using var doc = JsonDocument.Parse(stdout.ToString().Trim());
                if (doc.RootElement.TryGetProperty("error", out var e))
                    err = e.GetString() ?? err;
            }
            catch
            {
                // ignore
            }

            return NacRelayResult.Fail(
                $"NAC exit={proc.ExitCode}: {(string.IsNullOrEmpty(err) ? "(no output)" : err)}");
        }

        var text = stdout.ToString().Trim();
        if (string.IsNullOrEmpty(text))
            return NacRelayResult.Fail("NAC: empty stdout.");

        try
        {
            using var doc = JsonDocument.Parse(text);
            var root = doc.RootElement;
            if (root.TryGetProperty("ok", out var okEl) && okEl.ValueKind == JsonValueKind.False)
            {
                var err = root.TryGetProperty("error", out var e) ? e.GetString() : "ok=false";
                return NacRelayResult.Fail(err ?? "ok=false");
            }

            var b64 = root.TryGetProperty("validation_data_b64", out var el)
                ? el.GetString()
                : null;
            if (string.IsNullOrEmpty(b64))
                return NacRelayResult.Fail("NAC JSON missing validation_data_b64.");

            var bytes = Convert.FromBase64String(b64);
            string? serial = null;
            if (root.TryGetProperty("serial", out var serEl))
                serial = serEl.GetString();
            string? warning = null;
            if (root.TryGetProperty("warning", out var w) && w.ValueKind == JsonValueKind.String)
                warning = w.GetString();
            var source = root.TryGetProperty("source", out var src) ? src.GetString() : null;

            return NacRelayResult.Ok(b64, bytes.Length, serial, MergeWarn(warning, source));
        }
        catch (Exception ex) when (ex is JsonException or FormatException)
        {
            return NacRelayResult.Fail("NAC JSON parse failed: " + ex.Message + "\n" + stderr);
        }
    }

    private void EnsurePersona(out string? warning)
    {
        warning = null;
        Directory.CreateDirectory(Path.GetDirectoryName(DataPlistPath)!);

        if (!File.Exists(DataPlistPath) || new FileInfo(DataPlistPath).Length < 64)
        {
            if (!OperatingSystem.IsMacOS())
            {
                warning = "data.plist missing and host is not macOS — cannot auto-capture IOKit.";
                return;
            }

            var capture = Path.Combine(ScriptRoot, "capture_mac_persona.py");
            if (!File.Exists(capture))
            {
                warning = $"capture_mac_persona.py missing at {capture}";
                return;
            }

            var psi = new ProcessStartInfo
            {
                FileName = PythonExe,
                Arguments = $"{QuoteArg(capture)} -o {QuoteArg(DataPlistPath)}",
                WorkingDirectory = ScriptRoot,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true,
            };
            using var proc = Process.Start(psi)
                             ?? throw new InvalidOperationException("Cannot start capture_mac_persona.py");
            var stdout = proc.StandardOutput.ReadToEnd();
            var stderr = proc.StandardError.ReadToEnd();
            proc.WaitForExit(60_000);
            if (proc.ExitCode != 0 || !File.Exists(DataPlistPath))
            {
                warning = $"IOKit capture failed: {(string.IsNullOrWhiteSpace(stderr) ? stdout : stderr).Trim()}";
                return;
            }
        }

        if (File.Exists(DataPlistPath))
        {
            var raw = File.ReadAllText(DataPlistPath);
            var hasMlb = raw.Contains($"{IokitGuid}:MLB", StringComparison.Ordinal)
                         || raw.Contains(">MLB<", StringComparison.Ordinal);
            var hasRom = raw.Contains($"{IokitGuid}:ROM", StringComparison.Ordinal)
                         || raw.Contains(">ROM<", StringComparison.Ordinal);
            if (!hasMlb || !hasRom)
            {
                warning =
                    "WARNING: MLB/ROM missing in data.plist (common on Apple Silicon) — Apple may return 6009.";
            }
        }
    }

    private static string ResolveBackend(string? configured)
    {
        var env = Environment.GetEnvironmentVariable("IKE_NAC_BACKEND")?.Trim().ToLowerInvariant();
        if (!string.IsNullOrEmpty(env))
            return env;
        var c = configured?.Trim().ToLowerInvariant();
        return string.IsNullOrEmpty(c) ? "auto" : c;
    }

    private static string? MergeWarn(string? a, string? b)
    {
        if (string.IsNullOrEmpty(a)) return b;
        if (string.IsNullOrEmpty(b)) return a;
        return a + " · " + b;
    }

    private static string ResolveDataPlistPath(MiddlewareSettings settings)
    {
        if (!string.IsNullOrWhiteSpace(settings.NacDataPlist))
            return Path.GetFullPath(settings.NacDataPlist);

        var env = Environment.GetEnvironmentVariable("IKE_NAC_DATA_PLIST")?.Trim();
        if (!string.IsNullOrEmpty(env))
            return Path.GetFullPath(env);

        var root = string.IsNullOrWhiteSpace(settings.DataRoot)
            ? MiddlewareSettings.DefaultDataRoot()
            : Path.GetFullPath(settings.DataRoot);
        return Path.Combine(root, "data", "nac", "data.plist");
    }

    public static string ResolveAbsintheScript(string? configured)
    {
        if (!string.IsNullOrWhiteSpace(configured) && File.Exists(configured))
            return Path.GetFullPath(configured);

        var env = Environment.GetEnvironmentVariable("IKE_ABSINTHE_SCRIPT")?.Trim();
        if (!string.IsNullOrEmpty(env) && File.Exists(env))
            return Path.GetFullPath(env);

        var baseDir = AppContext.BaseDirectory;
        var candidates = new List<string>
        {
            Path.Combine(baseDir, "AbsintheNac", "absinthe_nac.py"),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "native", "AbsintheNac", "absinthe_nac.py")),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "native", "AbsintheNac", "absinthe_nac.py")),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "native", "AbsintheNac", "absinthe_nac.py")),
        };
        try
        {
            var dir = new DirectoryInfo(baseDir);
            for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
                candidates.Add(Path.Combine(dir.FullName, "native", "AbsintheNac", "absinthe_nac.py"));
        }
        catch
        {
            // ignore
        }

        foreach (var c in candidates.Distinct(StringComparer.Ordinal))
        {
            if (File.Exists(c))
                return c;
        }

        return candidates[0];
    }

    public static string ResolveScriptRoot(string? configured)
    {
        if (!string.IsNullOrWhiteSpace(configured))
        {
            var p = Path.GetFullPath(configured);
            if (File.Exists(Path.Combine(p, "generate_validation_data.py")))
                return p;
        }

        var env = Environment.GetEnvironmentVariable("IKE_NAC_SCRIPT_ROOT")?.Trim();
        if (!string.IsNullOrEmpty(env))
        {
            var p = Path.GetFullPath(env);
            if (File.Exists(Path.Combine(p, "generate_validation_data.py")))
                return p;
        }

        var baseDir = AppContext.BaseDirectory;
        var candidates = new List<string>
        {
            Path.Combine(baseDir, "nac-pypush"),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "scripts", "nac-pypush")),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "scripts", "nac-pypush")),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "scripts", "nac-pypush")),
        };

        try
        {
            var dir = new DirectoryInfo(baseDir);
            for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
                candidates.Add(Path.Combine(dir.FullName, "scripts", "nac-pypush"));
        }
        catch
        {
            // ignore
        }

        foreach (var c in candidates.Distinct(StringComparer.Ordinal))
        {
            if (File.Exists(Path.Combine(c, "generate_validation_data.py")))
                return c;
        }

        return candidates[0];
    }

    private static string QuoteArg(string a) =>
        a.Contains(' ', StringComparison.Ordinal) ? $"\"{a}\"" : a;
}

public sealed record NacRelayResult
{
    public bool Success { get; init; }
    public string? ValidationDataB64 { get; init; }
    public int Length { get; init; }
    public string? Serial { get; init; }
    public string? Warning { get; init; }
    public string? Error { get; init; }

    public static NacRelayResult Ok(string b64, int length, string? serial, string? warning) => new()
    {
        Success = true,
        ValidationDataB64 = b64,
        Length = length,
        Serial = serial,
        Warning = warning,
    };

    public static NacRelayResult Fail(string error) => new()
    {
        Success = false,
        Error = error,
    };
}
