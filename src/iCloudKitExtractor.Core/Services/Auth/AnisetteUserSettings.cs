using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Config anisette remota (%AppData%\iCloudKitExtractor\anisette.json).
/// Le variabili d'ambiente ANISETTE_SERVER_URL / ICLOUD_AUTH_MODE / ANISETTE_LICENSE
/// hanno priorità sulla UI/JSON.
/// </summary>
public sealed class AnisetteUserSettings
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public static string SettingsPath =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "iCloudKitExtractor",
            "anisette.json");

    /// <summary>
    /// true = usa <see cref="ServerUrl"/>; false = locale
    /// <c>http://127.0.0.1:6971</c> (or <c>https://…</c> when the middleware uses TLS). null = legacy (serverUrl non vuoto ⇒ remoto).
    /// </summary>
    [JsonPropertyName("useRemoteServer")]
    public bool? UseRemoteServer { get; set; }

    [JsonPropertyName("serverUrl")]
    public string? ServerUrl { get; set; }

    /// <summary>hybrid | iphone</summary>
    [JsonPropertyName("authMode")]
    public string? AuthMode { get; set; }

    /// <summary>
    /// Package-C Base64 bundle (token+pubkey), raw Bearer token, o path a file <c>.license</c>.
    /// Sovrascritto da <c>ANISETTE_LICENSE</c> se presente.
    /// </summary>
    [JsonPropertyName("license")]
    public string? License { get; set; }

    /// <summary>Accept any Anisette HTTPS certificate (lab only). Env: ANISETTE_TLS_INSECURE.</summary>
    [JsonPropertyName("tlsInsecure")]
    public bool? TlsInsecure { get; set; }

    /// <summary>Pin Anisette HTTPS cert thumbprint. Env: ANISETTE_TLS_THUMBPRINT.</summary>
    [JsonPropertyName("tlsThumbprint")]
    public string? TlsThumbprint { get; set; }

    /// <summary>Path to Anisette HTTPS .cer to trust. Env: ANISETTE_TLS_CA.</summary>
    [JsonPropertyName("tlsCaPath")]
    public string? TlsCaPath { get; set; }

    public bool IsRemoteServerEnabled()
    {
        if (UseRemoteServer is bool flag)
            return flag;
        return !string.IsNullOrWhiteSpace(ServerUrl);
    }

    public static AnisetteUserSettings Load()
    {
        try
        {
            if (!File.Exists(SettingsPath))
                return new AnisetteUserSettings();

            var json = File.ReadAllText(SettingsPath);
            return JsonSerializer.Deserialize<AnisetteUserSettings>(json, JsonOptions)
                   ?? new AnisetteUserSettings();
        }
        catch
        {
            return new AnisetteUserSettings();
        }
    }

    public static void Save(AnisetteUserSettings settings)
    {
        var dir = Path.GetDirectoryName(SettingsPath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(SettingsPath, JsonSerializer.Serialize(settings, JsonOptions));
    }

    public static string? ExampleMacUrl => "http://192.168.1.50:6971";
}
