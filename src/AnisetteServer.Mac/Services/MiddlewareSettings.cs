using System.Text.Json;
using System.Text.Json.Serialization;
using iCloudKitExtractor.AnisetteLicense;

namespace AnisetteServer.Mac.Services;

public sealed class MiddlewareSettings
{
    [JsonPropertyName("fridaHost")]
    public string FridaHost { get; set; } = "192.168.1.50:27042";

    [JsonPropertyName("fridaProcess")]
    public string FridaProcess { get; set; } = "akd";

    [JsonPropertyName("python")]
    public string Python { get; set; } = "python3";

    [JsonPropertyName("fetchScript")]
    public string? FetchScript { get; set; }

    [JsonPropertyName("lite")]
    public bool Lite { get; set; } = true;

    [JsonPropertyName("timeoutSec")]
    public int TimeoutSec { get; set; } = 60;

    [JsonPropertyName("listenUrls")]
    public string ListenUrls { get; set; } = "http://0.0.0.0:6971";

    [JsonPropertyName("dataRoot")]
    public string? DataRoot { get; set; }

    public static string DefaultConfigPath()
    {
        var dir = DefaultDataRoot();
        return Path.Combine(dir, "middleware.json");
    }

    public static string DefaultDataRoot()
    {
        var env = Environment.GetEnvironmentVariable("ANISETTE_LICENSE_ROOT")?.Trim();
        if (!string.IsNullOrEmpty(env))
            return Path.GetFullPath(env);

        // Strict OS roots — do not infer macOS from a %USERPROFILE%\Library folder on Windows.
        if (OperatingSystem.IsMacOS())
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            return Path.Combine(home, "Library", "Application Support", "ForensisLab", "AnisetteMiddleware");
        }

        if (OperatingSystem.IsWindows())
        {
            return Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "ForensisLab",
                "AnisetteMiddleware");
        }

        // Linux / other: XDG-style under ~/.local/share
        var xdg = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        if (string.IsNullOrWhiteSpace(xdg))
            xdg = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
        return Path.Combine(xdg, "ForensisLab", "AnisetteMiddleware");
    }

    /// <summary>
    /// Point <see cref="LicensePaths"/> at this middleware data root (keys + SQLite).
    /// Call before any license UI / Kestrel host touches the DB.
    /// </summary>
    public static void EnsureLicenseEnvironment(string? dataRoot = null)
    {
        var root = string.IsNullOrWhiteSpace(dataRoot) ? DefaultDataRoot() : Path.GetFullPath(dataRoot);
        Directory.CreateDirectory(root);
        Directory.CreateDirectory(Path.Combine(root, "keys"));
        Directory.CreateDirectory(Path.Combine(root, "data"));
        Environment.SetEnvironmentVariable("ANISETTE_LICENSE_ROOT", root);
    }

    public void ApplyToEnvironment()
    {
        EnsureLicenseEnvironment(string.IsNullOrWhiteSpace(DataRoot) ? null : DataRoot);
        Environment.SetEnvironmentVariable("FRIDA_ANISETTE_HOST", FridaHost);
        Environment.SetEnvironmentVariable("FRIDA_ANISETTE_PROCESS", FridaProcess);
        Environment.SetEnvironmentVariable("FRIDA_ANISETTE_PYTHON", Python);
        Environment.SetEnvironmentVariable("FRIDA_ANISETTE_LITE", Lite ? "1" : "0");
        Environment.SetEnvironmentVariable("FRIDA_ANISETTE_TIMEOUT", TimeoutSec.ToString());
        if (!string.IsNullOrWhiteSpace(FetchScript))
            Environment.SetEnvironmentVariable("FRIDA_ANISETTE_FETCH_PY", FetchScript);
    }

    public void EnsureKeys()
    {
        ApplyToEnvironment();
        if (!File.Exists(LicensePaths.PrivateKeyPath) || !File.Exists(LicensePaths.PublicKeyPath))
            LicenseCrypto.GenerateKeyPair(LicensePaths.PrivateKeyPath, LicensePaths.PublicKeyPath);
    }

    public static MiddlewareSettings Load()
    {
        var path = DefaultConfigPath();
        try
        {
            if (File.Exists(path))
            {
                var json = File.ReadAllText(path);
                return JsonSerializer.Deserialize<MiddlewareSettings>(json) ?? new MiddlewareSettings();
            }
        }
        catch
        {
            // fall through
        }

        return new MiddlewareSettings();
    }

    public void Save()
    {
        var path = DefaultConfigPath();
        Directory.CreateDirectory(Path.GetDirectoryName(path)!);
        var json = JsonSerializer.Serialize(this, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(path, json);
    }
}
