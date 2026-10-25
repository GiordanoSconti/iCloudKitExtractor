using System.Text.Json;
using System.Text.Json.Serialization;

namespace AnisetteBridge;

public static class BridgeJson
{
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };
}

public sealed class BridgeRegisterMessage
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "register";

    [JsonPropertyName("token")]
    public string Token { get; init; } = string.Empty;

    [JsonPropertyName("anisetteUrl")]
    public string AnisetteUrl { get; init; } = "http://127.0.0.1:6969/";
}

public sealed class BridgeRegisteredMessage
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "registered";

    [JsonPropertyName("ok")]
    public bool Ok { get; init; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

public sealed class BridgeFetchMessage
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "fetch";

    [JsonPropertyName("id")]
    public string Id { get; init; } = string.Empty;
}

public sealed class BridgeFetchResultMessage
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "fetchResult";

    [JsonPropertyName("id")]
    public string Id { get; set; } = string.Empty;

    [JsonPropertyName("ok")]
    public bool Ok { get; set; }

    [JsonPropertyName("status")]
    public int Status { get; set; }

    [JsonPropertyName("body")]
    public string? Body { get; set; }

    [JsonPropertyName("error")]
    public string? Error { get; set; }
}

public sealed class BridgePingMessage
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "ping";
}

public sealed class BridgePongMessage
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "pong";
}

public static class LineJsonProtocol
{
    public static async Task WriteAsync<T>(StreamWriter writer, T message, CancellationToken ct)
    {
        var line = JsonSerializer.Serialize(message, BridgeJson.Options);
        await writer.WriteLineAsync(line.AsMemory(), ct).ConfigureAwait(false);
        await writer.FlushAsync(ct).ConfigureAwait(false);
    }

    public static async Task<string?> ReadLineAsync(StreamReader reader, CancellationToken ct)
    {
        var line = await reader.ReadLineAsync(ct).ConfigureAwait(false);
        return string.IsNullOrWhiteSpace(line) ? null : line;
    }
}
