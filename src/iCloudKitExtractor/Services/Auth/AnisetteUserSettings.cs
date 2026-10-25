using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Config anisette remota (%AppData%\iCloudKitExtractor\anisette.json).
/// Le variabili d'ambiente ANISETTE_SERVER_URL / ICLOUD_AUTH_MODE hanno priorità.
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

    [JsonPropertyName("serverUrl")]
    public string? ServerUrl { get; set; }

    /// <summary>hybrid | iphone</summary>
    [JsonPropertyName("authMode")]
    public string? AuthMode { get; set; }

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

    public static string? ExampleMacUrl => "http://192.168.1.50:6969";
}
