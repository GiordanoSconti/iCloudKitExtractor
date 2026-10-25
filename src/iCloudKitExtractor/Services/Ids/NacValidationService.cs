using System.Diagnostics;
using System.IO;
using System.Text;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Genera <c>validation-data</c> NAC via helper pypush (<c>scripts/nac-pypush</c>).
/// Pipeline: IMDAppleServices (Unicorn) → initializeValidation → nac_sign.
/// </summary>
public sealed class NacValidationService
{
    private readonly string _scriptRoot;
    private readonly string _pythonExe;

    public NacValidationService(string? scriptRoot = null, string? pythonExe = null)
    {
        _scriptRoot = scriptRoot ?? ResolveScriptRoot();
        _pythonExe = pythonExe ?? ResolvePython();
    }

    public string ScriptRoot => _scriptRoot;

    public async Task<byte[]> GenerateAsync(
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var script = Path.Combine(_scriptRoot, "generate_validation_data.py");
        if (!File.Exists(script))
            throw new InvalidOperationException(
                $"NAC script assente: {script}. Serve scripts/nac-pypush da pypush emulated.");

        log?.Invoke($"NAC: {_pythonExe} {script} --json");

        // `py` launcher richiede -3; python/python3 no.
        var args = string.Equals(Path.GetFileNameWithoutExtension(_pythonExe), "py", StringComparison.OrdinalIgnoreCase)
            ? $"-3 \"{script}\" --json"
            : $"\"{script}\" --json";

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
            throw new InvalidOperationException("NAC: impossibile avviare Python.");

        proc.BeginOutputReadLine();
        proc.BeginErrorReadLine();

        await proc.WaitForExitAsync(ct).ConfigureAwait(false);
        if (proc.ExitCode != 0)
        {
            var err = stderr.ToString().Trim();
            if (string.IsNullOrEmpty(err))
                err = stdout.ToString().Trim();
            throw new InvalidOperationException(
                $"NAC exit={proc.ExitCode}: {(string.IsNullOrEmpty(err) ? "(nessun output)" : err)}");
        }

        var text = stdout.ToString().Trim();
        if (string.IsNullOrEmpty(text))
            throw new InvalidOperationException("NAC: stdout vuoto.");

        try
        {
            using var doc = JsonDocument.Parse(text);
            if (doc.RootElement.TryGetProperty("validation_data_b64", out var b64El))
            {
                var b64 = b64El.GetString()
                          ?? throw new InvalidOperationException("NAC JSON senza validation_data_b64.");
                var bytes = Convert.FromBase64String(b64);
                log?.Invoke($"NAC OK — validation-data {bytes.Length} B");
                return bytes;
            }
        }
        catch (JsonException)
        {
            // fallback: raw base64 line
        }

        var raw = Convert.FromBase64String(text.Split('\n', StringSplitOptions.RemoveEmptyEntries)[^1].Trim());
        log?.Invoke($"NAC OK — validation-data {raw.Length} B (raw b64)");
        return raw;
    }

    /// <summary>Base64 per header <c>X-Mme-Nas-Qualify</c>.</summary>
    public async Task<string> GenerateNasQualifyBase64Async(
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var data = await GenerateAsync(log, ct).ConfigureAwait(false);
        return Convert.ToBase64String(data);
    }

    private static string ResolveScriptRoot()
    {
        var env = Environment.GetEnvironmentVariable("IKE_NAC_SCRIPT_ROOT")?.Trim();
        if (!string.IsNullOrEmpty(env) && Directory.Exists(env))
            return env;

        // bin/Debug/netX → …/iCloudKitExtractor/scripts/nac-pypush
        var baseDir = AppContext.BaseDirectory;
        var candidates = new[]
        {
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "..", "scripts", "nac-pypush")),
            Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "scripts", "nac-pypush")),
            Path.GetFullPath(Path.Combine(baseDir, "scripts", "nac-pypush")),
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

        // Prefer py launcher on Windows.
        if (OperatingSystem.IsWindows())
            return "py";
        return "python3";
    }
}
