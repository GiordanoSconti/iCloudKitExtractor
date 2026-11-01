using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text.RegularExpressions;

namespace AnisetteServer.Mac.Services;

/// <summary>
/// Best-effort offline hints for known VPN / proxy / anonymity networks.
/// Heuristics only (rDNS + headers + common provider tokens) — not a full IP intel feed.
/// </summary>
public static partial class VpnHintProbe
{
    private static readonly ConcurrentDictionary<string, string> Cache = new(StringComparer.Ordinal);

    private static readonly string[] ProviderTokens =
    [
        "nordvpn", "expressvpn", "mullvad", "protonvpn", "proton.", "surfshark",
        "cyberghost", "privateinternetaccess", "pia.", "windscribe", "tunnelbear",
        "vyprvpn", "hotspotshield", "ipvanish", "purevpn", "astrill", "hide.me",
        "hidemyass", "hma.", "tor-exit", "torservers", "cloudflare-warp", "warp.",
        "ovpn.", "openvpn", "vpn.", ".vpn", "proxy.", "anonymizer", "datacamp",
        "choopa", "vultr", "digitalocean", "linode", "hetzner", "ovh.", "contabo",
        "m247", "cdn77", "netcup",
    ];

    public static bool LooksLikeVpnOrProxy(string? hint)
    {
        if (string.IsNullOrWhiteSpace(hint))
            return false;
        var h = hint.ToLowerInvariant();
        if (h.StartsWith("local/private"))
            return false;
        return h.Contains("likely-vpn", StringComparison.Ordinal)
               || h.Contains("vpn", StringComparison.Ordinal)
               || h.Contains("proxy", StringComparison.Ordinal)
               || h.Contains("tor", StringComparison.Ordinal)
               || h.Contains("warp", StringComparison.Ordinal);
    }

    /// <summary>
    /// Tokens too broad for an allowlist entry (would admit every "proxy"/"vpn" client).
    /// Prefer <see cref="SuggestIpPattern"/> instead.
    /// </summary>
    private static readonly HashSet<string> GenericConsentTokens = new(StringComparer.OrdinalIgnoreCase)
    {
        "proxy", "vpn", "host", "tor", "warp", "openvpn", "ovpn", "anonymizer",
        "likely-vpn", "likely-vpn/proxy", "unknown", "local", "private",
    };

    public static bool IsGenericConsentToken(string? pattern)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return true;
        var p = pattern.Trim().Trim('.');
        return GenericConsentTokens.Contains(p)
               || p.Equals("host", StringComparison.OrdinalIgnoreCase);
    }

    public static bool LooksLikeIpLiteral(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return false;
        var s = value.Trim();
        // Strip optional CIDR for recognition; matching is exact-IP for now.
        var slash = s.IndexOf('/');
        if (slash > 0)
            s = s[..slash];
        return IPAddress.TryParse(s, out _);
    }

    /// <summary>Client IP for IP-scoped allowlist entries (empty if unknown).</summary>
    public static string SuggestIpPattern(string? clientIp)
    {
        if (string.IsNullOrWhiteSpace(clientIp) || clientIp is "-" or "?")
            return "";
        return clientIp.Trim();
    }

    /// <summary>
    /// Best pattern for the consent allowlist: named provider when specific,
    /// otherwise the client IP (never a generic "proxy"/"vpn" token).
    /// </summary>
    public static string SuggestConsentPattern(string? vpnHint, string? clientIp)
    {
        var ip = SuggestIpPattern(clientIp);
        var hint = vpnHint ?? "";
        // likely-vpn/proxy (mullvad · host…)
        var open = hint.IndexOf('(', StringComparison.Ordinal);
        var close = hint.IndexOf(')', StringComparison.Ordinal);
        if (open >= 0 && close > open)
        {
            var inner = hint[(open + 1)..close];
            var token = inner.Split('·', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)
                .FirstOrDefault();
            if (!string.IsNullOrWhiteSpace(token))
            {
                var clean = token.Trim().Trim('.');
                if (!IsGenericConsentToken(clean))
                    return clean;
            }
        }

        foreach (var t in ProviderTokens)
        {
            var clean = t.Trim('.');
            if (clean.Length >= 3
                && !IsGenericConsentToken(clean)
                && hint.Contains(clean, StringComparison.OrdinalIgnoreCase))
                return clean;
        }

        if (!string.IsNullOrEmpty(ip))
            return ip;
        return hint.Length <= 40 ? hint : hint[..40];
    }

    public static async Task<string> ClassifyAsync(
        IPAddress? ip,
        string? userAgent,
        string? forwarded,
        CancellationToken ct = default)
    {
        if (ip is null)
            return "-";

        if (IPAddress.IsLoopback(ip) || IsPrivate(ip))
            return AppendHeaderHints("local/private", userAgent, forwarded);

        var key = ip.ToString();
        if (Cache.TryGetValue(key, out var cached))
            return AppendHeaderHints(cached, userAgent, forwarded);

        var hint = await ResolveHostHintAsync(ip, ct).ConfigureAwait(false);
        Cache[key] = hint;
        return AppendHeaderHints(hint, userAgent, forwarded);
    }

    private static async Task<string> ResolveHostHintAsync(IPAddress ip, CancellationToken ct)
    {
        try
        {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeout.CancelAfter(TimeSpan.FromMilliseconds(350));
            var entry = await Dns.GetHostEntryAsync(ip.ToString(), timeout.Token).ConfigureAwait(false);
            var name = entry.HostName?.Trim().ToLowerInvariant() ?? "";
            if (string.IsNullOrEmpty(name) || name == ip.ToString())
                return "unknown";

            foreach (var token in ProviderTokens)
            {
                if (name.Contains(token, StringComparison.Ordinal))
                    return $"likely-vpn/proxy ({token.Trim('.')} · {Truncate(name, 48)})";
            }

            if (VpnLikeHostRegex().IsMatch(name))
                return $"likely-vpn/proxy (host · {Truncate(name, 48)})";

            return $"host {Truncate(name, 48)}";
        }
        catch (OperationCanceledException)
        {
            return "unknown (rDNS timeout)";
        }
        catch (SocketException)
        {
            return "unknown";
        }
        catch (ArgumentException)
        {
            return "unknown";
        }
        catch
        {
            return "unknown";
        }
    }

    private static string AppendHeaderHints(string baseHint, string? userAgent, string? forwarded)
    {
        var extras = new List<string>();
        if (!string.IsNullOrWhiteSpace(forwarded))
            extras.Add("X-Forwarded-For/Via present");
        if (!string.IsNullOrWhiteSpace(userAgent)
            && (userAgent.Contains("vpn", StringComparison.OrdinalIgnoreCase)
                || userAgent.Contains("proxy", StringComparison.OrdinalIgnoreCase)))
            extras.Add("UA mentions vpn/proxy");

        if (extras.Count == 0)
            return baseHint;
        return baseHint + " · " + string.Join(" · ", extras);
    }

    private static bool IsPrivate(IPAddress ip)
    {
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        if (ip.AddressFamily != AddressFamily.InterNetwork)
            return false;

        var b = ip.GetAddressBytes();
        return b[0] == 10
               || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
               || (b[0] == 192 && b[1] == 168)
               || (b[0] == 169 && b[1] == 254);
    }

    private static string Truncate(string s, int n) =>
        s.Length <= n ? s : s[..n] + "…";

    [GeneratedRegex(@"\b(vpn|proxy|tor|exit|relay)\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex VpnLikeHostRegex();
}
