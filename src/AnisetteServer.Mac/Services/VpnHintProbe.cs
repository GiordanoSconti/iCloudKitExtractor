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
        // Tunnel path alone must not force the VPN consent gate (every CF client would need allowlisting).
        var h = StripTunnelDecoration(hint).ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(h) || h.StartsWith("local/private"))
            return false;
        return h.Contains("likely-vpn", StringComparison.Ordinal)
               || h.Contains("vpn", StringComparison.Ordinal)
               || h.Contains("proxy", StringComparison.Ordinal)
               || h.Contains("tor", StringComparison.Ordinal)
               || h.Contains("warp", StringComparison.Ordinal);
    }

    /// <summary>
    /// Clients whose <c>vpn=</c> line is <c>proxy/host/unknown … identity</c> must pass the allowlist
    /// (identity or IP). Plain residential reverse-DNS without those types is not gated.
    /// </summary>
    public static bool NeedsConsentGate(string? hint)
    {
        var h = StripTunnelDecoration(hint);
        if (string.IsNullOrWhiteSpace(h) || h.StartsWith("local/private", StringComparison.OrdinalIgnoreCase))
            return false;
        if (LooksLikeVpnOrProxy(h))
            return true;
        // "host foo.example.edu" / "unknown" — tipo dopo vpn= che l'operatore autorizza per identità/IP.
        if (h.StartsWith("host ", StringComparison.OrdinalIgnoreCase)
            || h.Equals("host", StringComparison.OrdinalIgnoreCase)
            || h.StartsWith("unknown", StringComparison.OrdinalIgnoreCase))
            return true;
        return false;
    }

    /// <summary>
    /// Removes Cloudflare Tunnel decoration appended by ConnectionGuard so consent
    /// matching uses the real VPN/host classification.
    /// </summary>
    public static string StripTunnelDecoration(string? hint)
    {
        if (string.IsNullOrWhiteSpace(hint))
            return "";
        var h = hint.Trim();
        // "… · via Cloudflare Tunnel/proxy" or "… · via Cloudflare Tunnel"
        const string marker = " · via Cloudflare Tunnel";
        var idx = h.IndexOf(marker, StringComparison.OrdinalIgnoreCase);
        if (idx >= 0)
            h = h[..idx].TrimEnd();
        // Also strip header extras: " · X-Forwarded-For/Via present"
        var extra = h.IndexOf(" · X-Forwarded-For", StringComparison.OrdinalIgnoreCase);
        if (extra >= 0)
            h = h[..extra].TrimEnd();
        var ua = h.IndexOf(" · UA mentions", StringComparison.OrdinalIgnoreCase);
        if (ua >= 0)
            h = h[..ua].TrimEnd();
        if (h.Equals("via Cloudflare Tunnel/proxy", StringComparison.OrdinalIgnoreCase)
            || h.Equals("via Cloudflare Tunnel", StringComparison.OrdinalIgnoreCase))
            return "";
        return h;
    }

    /// <summary>
    /// Identities from <c>vpn=tipo identità</c> / <c>likely-vpn/proxy (id · host)</c> for allowlist match.
    /// </summary>
    public static IReadOnlyList<string> ExtractIdentities(string? vpnHint)
    {
        var hint = StripTunnelDecoration(vpnHint);
        var list = new List<string>();
        void Add(string? s)
        {
            if (string.IsNullOrWhiteSpace(s))
                return;
            var clean = s.Trim().TrimEnd('…', '.', ',', ';', ')').Trim();
            // Strip UTF-8 ellipsis if present as single char
            clean = clean.TrimEnd('\u2026').Trim();
            if (clean.Length < 2 || IsGenericConsentToken(clean))
                return;
            if (list.Any(x => string.Equals(x, clean, StringComparison.OrdinalIgnoreCase)))
                return;
            list.Add(clean);
        }

        if (string.IsNullOrWhiteSpace(hint))
            return list;

        // likely-vpn/proxy (mullvad · host.example.com) or (host · host.example.com)
        var open = hint.IndexOf('(', StringComparison.Ordinal);
        var close = hint.IndexOf(')', StringComparison.Ordinal);
        if (open >= 0 && close > open)
        {
            var inner = hint[(open + 1)..close];
            foreach (var part in inner.Split(['·', '|', ','], StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                Add(part.Trim().Trim('.'));
        }

        // "host foo.example.edu" / "proxy foo" / "unknown" (no id)
        foreach (var prefix in new[] { "host ", "proxy ", "vpn ", "unknown " })
        {
            if (!hint.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                continue;
            Add(hint[prefix.Length..].Trim());
        }

        // Bare domains in the hint (fallback).
        foreach (Match m in DomainInHintRegex().Matches(hint))
            Add(m.Value);

        return list;
    }

    /// <summary>True if allowlist <paramref name="pattern"/> matches hint text or extracted identities.</summary>
    public static bool IdentityMatchesAllowPattern(string pattern, string? vpnHint)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            return false;
        var p = pattern.Trim().TrimEnd('…', '\u2026');
        if (p.Length < 2 || (IsGenericConsentToken(p) && !LooksLikeIpLiteral(p)))
            return false;

        var hint = StripTunnelDecoration(vpnHint);
        if (hint.Contains(p, StringComparison.OrdinalIgnoreCase))
            return true;

        foreach (var id in ExtractIdentities(hint))
        {
            if (string.Equals(id, p, StringComparison.OrdinalIgnoreCase))
                return true;
            // Suffix / parent domain: allow "uni-kassel.de" vs "vpn.uni-kassel.de"
            if (id.EndsWith("." + p, StringComparison.OrdinalIgnoreCase)
                || p.EndsWith("." + id, StringComparison.OrdinalIgnoreCase))
                return true;
            if (id.Contains(p, StringComparison.OrdinalIgnoreCase)
                || p.Contains(id, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
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
    /// Best pattern for the consent allowlist: provider or host <b>identity</b> after
    /// <c>vpn=tipo</c>, never a generic "proxy"/"vpn"/"host" token.
    /// </summary>
    public static string SuggestConsentPattern(string? vpnHint, string? clientIp)
    {
        var ip = SuggestIpPattern(clientIp);
        var ids = ExtractIdentities(vpnHint);
        // Prefer provider-looking token, then hostname identity, then IP.
        foreach (var id in ids)
        {
            if (id.Contains('.', StringComparison.Ordinal) && !LooksLikeIpLiteral(id))
                continue; // hostnames second pass
            if (!IsGenericConsentToken(id))
                return id;
        }

        foreach (var id in ids)
        {
            if (!IsGenericConsentToken(id))
                return id;
        }

        var hint = StripTunnelDecoration(vpnHint);
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

    [GeneratedRegex(@"\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex DomainInHintRegex();
}
