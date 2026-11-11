namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Remote Anisette pulled this client's license onto a replica that did not have it yet.
/// The operator should reconnect; the next request will hit a synchronized replica DB.
/// </summary>
public sealed class AnisetteLicenseReplicaSyncedException : InvalidOperationException
{
    public const string ErrorCode = "license_replica_synced";

    public const string UserMessage =
        "Your Anisette license was missing on this server replica and has now been synchronized across all replicas. Please reconnect and try again.";

    public AnisetteLicenseReplicaSyncedException(string? detail = null)
        : base(string.IsNullOrWhiteSpace(detail) ? UserMessage : detail.Trim())
    {
    }

    public static bool TryParse(string? body, out string detail)
    {
        detail = UserMessage;
        if (string.IsNullOrWhiteSpace(body))
            return false;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            var root = doc.RootElement;
            var error = root.TryGetProperty("error", out var e) ? e.GetString() : null;
            if (!string.Equals(error, ErrorCode, StringComparison.OrdinalIgnoreCase)
                && !body.Contains(ErrorCode, StringComparison.OrdinalIgnoreCase))
                return false;
            if (root.TryGetProperty("detail", out var d) && d.ValueKind == System.Text.Json.JsonValueKind.String)
            {
                var text = d.GetString();
                if (!string.IsNullOrWhiteSpace(text))
                    detail = text.Trim();
            }
            return true;
        }
        catch
        {
            return body.Contains(ErrorCode, StringComparison.OrdinalIgnoreCase);
        }
    }
}
