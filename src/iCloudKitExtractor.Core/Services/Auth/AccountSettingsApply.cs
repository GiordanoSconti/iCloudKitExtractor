using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Estrae da <c>get_account_settings</c> → <c>com.apple.mobileme</c>:
/// dataclass abilitate e URL/endpoint dei servizi Apple (campo <c>url</c>,
/// <c>escrowProxyUrl</c>, altri *Url).
/// </summary>
public static class AccountSettingsApply
{
    public static void ApplyMobileMeDict(
        ICloudSession session,
        Dictionary<string, object?> mobileMeDict)
    {
        session.AvailableDataclasses = CollectAvailableDataclasses(mobileMeDict);
        session.DataclassServiceUrls = CollectServiceUrls(mobileMeDict);

        if (session.DataclassServiceUrls.TryGetValue(
                "com.apple.Dataclass.KeychainSync.escrowProxyUrl", out var escrow)
            && !string.IsNullOrWhiteSpace(escrow))
        {
            session.EscrowProxyUrl = escrow.TrimEnd('/');
        }
        else if (session.DataclassServiceUrls.TryGetValue(
                     "com.apple.Dataclass.KeychainSync", out var keychainUrl)
                 && keychainUrl.Contains("escrowproxy", StringComparison.OrdinalIgnoreCase))
        {
            session.EscrowProxyUrl = keychainUrl.TrimEnd('/');
        }
    }

    public static IReadOnlyList<string> CollectAvailableDataclasses(
        Dictionary<string, object?> mobileMeDict)
    {
        var set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var key in mobileMeDict.Keys)
        {
            if (key.StartsWith("com.apple.Dataclass.", StringComparison.OrdinalIgnoreCase))
                set.Add(key);
        }

        if (mobileMeDict.TryGetValue("availableFeatures", out var features)
            && features is IList<object?> featureList)
        {
            foreach (var item in featureList)
            {
                if (item is string s
                    && s.StartsWith("com.apple.Dataclass.", StringComparison.OrdinalIgnoreCase))
                    set.Add(s);
            }
        }

        return set.OrderBy(static s => s, StringComparer.OrdinalIgnoreCase).ToList();
    }

    /// <summary>
    /// Chiavi: <c>com.apple.Dataclass.X</c> (campo <c>url</c>) oppure
    /// <c>com.apple.Dataclass.X.escrowProxyUrl</c> per altri endpoint.
    /// </summary>
    public static Dictionary<string, string> CollectServiceUrls(
        Dictionary<string, object?> mobileMeDict)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var (key, value) in mobileMeDict)
        {
            if (!key.StartsWith("com.apple.Dataclass.", StringComparison.OrdinalIgnoreCase))
                continue;
            if (value is not Dictionary<string, object?> fields)
                continue;

            foreach (var (field, raw) in fields)
            {
                if (raw is not string text || !LooksLikeServiceUrl(text))
                    continue;

                var trimmed = text.Trim().TrimEnd('/');
                if (field.Equals("url", StringComparison.OrdinalIgnoreCase))
                    map[key] = trimmed;
                else if (field.EndsWith("Url", StringComparison.OrdinalIgnoreCase)
                         || field.EndsWith("URL", StringComparison.Ordinal))
                    map[$"{key}.{field}"] = trimmed;
            }
        }

        return map
            .OrderBy(static kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                static kv => kv.Key,
                static kv => kv.Value,
                StringComparer.OrdinalIgnoreCase);
    }

    private static bool LooksLikeServiceUrl(string text) =>
        text.StartsWith("https://", StringComparison.OrdinalIgnoreCase)
        || text.StartsWith("http://", StringComparison.OrdinalIgnoreCase);
}
