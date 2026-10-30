using System.Text.Json.Serialization;

namespace iCloudKitExtractor.AnisetteLicense;

public sealed class LicensePayload
{
    [JsonPropertyName("license_id")]
    public string LicenseId { get; set; } = "";

    [JsonPropertyName("sub")]
    public string Subject { get; set; } = "";

    [JsonPropertyName("iat")]
    public long IssuedAtUnix { get; set; }

    [JsonPropertyName("exp")]
    public long? ExpiresAtUnix { get; set; }

    [JsonPropertyName("note")]
    public string? Note { get; set; }

    [JsonPropertyName("client_ip")]
    public string? ClientIp { get; set; }

    [JsonPropertyName("machine_id")]
    public string? MachineId { get; set; }

    [JsonPropertyName("hostname")]
    public string? Hostname { get; set; }

    [JsonPropertyName("os")]
    public string? Os { get; set; }

    [JsonPropertyName("app_instance")]
    public string? AppInstance { get; set; }

    /// <summary>Stable hash of machine_id|hostname|os|app_instance (server-side).</summary>
    [JsonPropertyName("fingerprint")]
    public string? Fingerprint { get; set; }
}
