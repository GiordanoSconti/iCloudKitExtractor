namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Anisette remota ha risposto HTTP 429 / <c>rate_limited</c>.
/// Non ritentare fino a <see cref="BlockedUntilUtc"/> (o cooldown locale).
/// </summary>
public sealed class AnisetteRateLimitedException : InvalidOperationException
{
    public AnisetteRateLimitedException(string message, DateTimeOffset? blockedUntilUtc = null)
        : base(message)
    {
        BlockedUntilUtc = blockedUntilUtc;
    }

    public DateTimeOffset? BlockedUntilUtc { get; }

    public static bool TryParseBlockedUntilUtc(string? body, out DateTimeOffset until)
    {
        until = default;
        if (string.IsNullOrWhiteSpace(body))
            return false;
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(body);
            if (!doc.RootElement.TryGetProperty("blocked_until_utc", out var el))
                return false;
            var raw = el.GetString();
            return !string.IsNullOrWhiteSpace(raw)
                && DateTimeOffset.TryParse(
                    raw,
                    System.Globalization.CultureInfo.InvariantCulture,
                    System.Globalization.DateTimeStyles.RoundtripKind,
                    out until);
        }
        catch
        {
            return false;
        }
    }
}
