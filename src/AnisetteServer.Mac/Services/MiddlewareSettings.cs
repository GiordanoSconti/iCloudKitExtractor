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
    public string ListenUrls { get; set; } = "http://127.0.0.1:6971";

    /// <summary>Path to scripts/nac-pypush (generate_validation_data.py). Empty = auto-resolve.</summary>
    [JsonPropertyName("nacScriptRoot")]
    public string? NacScriptRoot { get; set; }

    /// <summary>Mac NAC data.plist. Empty = {dataRoot}/data/nac/data.plist (auto-captured on macOS).</summary>
    [JsonPropertyName("nacDataPlist")]
    public string? NacDataPlist { get; set; }

    /// <summary>auto | absinthe | pypush. Default auto = native Absinthe then Unicorn fallback.</summary>
    [JsonPropertyName("nacBackend")]
    public string NacBackend { get; set; } = "auto";

    /// <summary>Path to native/AbsintheNac/absinthe_nac.py. Empty = auto-resolve.</summary>
    [JsonPropertyName("nacAbsintheScript")]
    public string? NacAbsintheScript { get; set; }

    [JsonPropertyName("dataRoot")]
    public string? DataRoot { get; set; }

    /// <summary>When true, VPN/proxy-like clients need a matching allowlist pattern.</summary>
    [JsonPropertyName("requireVpnConsent")]
    public bool RequireVpnConsent { get; set; } = true;

    /// <summary>Manual VPN consent patterns (provider token, IP, or hint substring).</summary>
    [JsonPropertyName("vpnConsentAllow")]
    public List<string> VpnConsentAllow { get; set; } = new();

    /// <summary>
    /// When true, remote clients need an Authorization Bearer whose license id /
    /// Package-C / token is listed in <see cref="LicenseAllowlist"/>.
    /// </summary>
    [JsonPropertyName("requireLicenseAllowlist")]
    public bool RequireLicenseAllowlist { get; set; }

    /// <summary>
    /// Allowed Authorization licenses: license id, subject, Package-C Base64, or raw Bearer token.
    /// </summary>
    [JsonPropertyName("licenseAllowlist")]
    public List<string> LicenseAllowlist { get; set; } = new();

    /// <summary>
    /// Peer Anisette base URL(s) for license sync. With one Tunnel + two replicas,
    /// set this to the shared public hostname on both machines.
    /// </summary>
    [JsonPropertyName("licensePeers")]
    public string? LicensePeers { get; set; }

    /// <summary>Shared secret for /internal/license-sync between Tunnel replicas.</summary>
    [JsonPropertyName("licenseSyncSecret")]
    public string? LicenseSyncSecret { get; set; }

    /// <summary>
    /// Unique id for this origin (e.g. mini-it / mini-my). Required so same-hostname
    /// LB sync can tell self from the other replica.
    /// </summary>
    [JsonPropertyName("licenseReplicaId")]
    public string? LicenseReplicaId { get; set; }

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

        string preferred;
        string legacy;

        // Strict OS roots — do not infer macOS from a %USERPROFILE%\Library folder on Windows.
        if (OperatingSystem.IsMacOS())
        {
            var home = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            var appSupport = Path.Combine(home, "Library", "Application Support");
            preferred = Path.Combine(appSupport, "iCloudKitExtractor", "AnisetteMiddleware");
            legacy = Path.Combine(appSupport, "ForensisLab", "AnisetteMiddleware");
        }
        else if (OperatingSystem.IsWindows())
        {
            var roaming = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData);
            preferred = Path.Combine(roaming, "iCloudKitExtractor", "AnisetteMiddleware");
            legacy = Path.Combine(roaming, "ForensisLab", "AnisetteMiddleware");
        }
        else
        {
            // Linux / other: XDG-style under ~/.local/share
            var xdg = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
            if (string.IsNullOrWhiteSpace(xdg))
                xdg = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".local", "share");
            preferred = Path.Combine(xdg, "iCloudKitExtractor", "AnisetteMiddleware");
            legacy = Path.Combine(xdg, "ForensisLab", "AnisetteMiddleware");
        }

        // Keep using the old folder if it already has keys/db and the new one does not.
        if (!HasMiddlewareData(preferred) && HasMiddlewareData(legacy))
            return legacy;
        return preferred;
    }

    private static bool HasMiddlewareData(string root) =>
        File.Exists(Path.Combine(root, "keys", "anisette_ed25519_private.pem"))
        || File.Exists(Path.Combine(root, "middleware.json"))
        || File.Exists(Path.Combine(root, "data", "anisette-licenses.db"));

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

        if (!string.IsNullOrWhiteSpace(LicensePeers))
            Environment.SetEnvironmentVariable(LicenseSyncOptions.EnvPeers, LicensePeers.Trim());
        if (!string.IsNullOrWhiteSpace(LicenseSyncSecret))
            Environment.SetEnvironmentVariable(LicenseSyncOptions.EnvSecret, LicenseSyncSecret.Trim());
        if (!string.IsNullOrWhiteSpace(LicenseReplicaId))
        {
            Environment.SetEnvironmentVariable(LicenseSyncOptions.EnvReplicaId, LicenseReplicaId.Trim());
            LicenseSyncOptions.InvalidateReplicaIdCache();
        }
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
