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
