using System.Net;
using System.Net.Sockets;

namespace iCloudKitExtractor.AnisetteLicense;

/// <summary>
/// Resolve the real client IP when traffic arrives via Cloudflare Tunnel / reverse proxy
/// (TCP peer is often <c>127.0.0.1</c> while <c>CF-Connecting-IP</c> / <c>X-Forwarded-For</c> carry the origin).
/// </summary>
public static class InboundClientAddress
{
    public const string ItemsKey = "anisette_client_ip";
    public const string TunnelItemsKey = "anisette_via_tunnel";

    /// <summary>
    /// True only for genuine local callers: loopback TCP and no proxy/tunnel client headers.
    /// Cloudflare Tunnel to localhost must NOT count as free loopback.
    /// </summary>
    public static bool IsTrustedLocalLoopback(IPAddress? remoteIp, Func<string, string?> header)
    {
        if (!IsLoopback(remoteIp))
            return false;
        return TryGetForwardedClientIp(header) is null;
    }

    public static string Resolve(IPAddress? remoteIp, Func<string, string?> header)
    {
        var forwarded = TryGetForwardedClientIp(header);
        if (forwarded is not null)
            return forwarded;
        return FormatIp(remoteIp) ?? "unknown";
    }

    public static bool HasTunnelOrProxyHeaders(Func<string, string?> header) =>
        TryGetForwardedClientIp(header) is not null
        || !string.IsNullOrWhiteSpace(header("CF-RAY"))
        || !string.IsNullOrWhiteSpace(header("CF-IPCountry"));

    /// <summary>Best-effort parse of Cloudflare / proxy client IP headers.</summary>
    public static string? TryGetForwardedClientIp(Func<string, string?> header)
    {
        if (TryParseIp(header("CF-Connecting-IP"), out var cf))
            return cf;
        if (TryParseIp(header("True-Client-IP"), out var trueClient))
            return trueClient;

        var xff = header("X-Forwarded-For");
        if (!string.IsNullOrWhiteSpace(xff))
        {
            string? any = null;
            foreach (var part in xff.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                if (!TryParseIp(part, out var xffIp))
                    continue;
                any ??= xffIp;
                if (!IsLoopback(IPAddress.Parse(xffIp)))
                    return xffIp;
            }

            if (any is not null)
                return any;
        }

        var forwarded = header("Forwarded");
        if (!string.IsNullOrWhiteSpace(forwarded))
        {
            foreach (var segment in forwarded.Split(',', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
            {
                foreach (var kv in segment.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries))
                {
                    if (!kv.StartsWith("for=", StringComparison.OrdinalIgnoreCase))
                        continue;
                    var raw = kv[4..].Trim().Trim('"');
                    if (raw.StartsWith('['))
                    {
                        var end = raw.IndexOf(']');
                        if (end > 1)
                            raw = raw[1..end];
                    }
                    else
                    {
                        var colon = raw.LastIndexOf(':');
                        if (colon > 0 && raw.Contains('.'))
                            raw = raw[..colon];
                    }

                    if (TryParseIp(raw, out var fwdIp))
                        return fwdIp;
                }
            }
        }

        return null;
    }

    public static string? ForwardedHeadersSummary(Func<string, string?> header)
    {
        var parts = new List<string>();
        void Add(string name)
        {
            var v = header(name);
            if (!string.IsNullOrWhiteSpace(v))
                parts.Add($"{name}={v}");
        }

        Add("CF-Connecting-IP");
        Add("True-Client-IP");
        Add("X-Forwarded-For");
        Add("Forwarded");
        Add("CF-RAY");
        Add("CF-IPCountry");
        Add("Via");
        return parts.Count == 0 ? null : string.Join(" · ", parts);
    }

    public static bool IsLoopback(IPAddress? ip)
    {
        if (ip is null)
            return false;
        if (IPAddress.IsLoopback(ip))
            return true;
        if (ip.IsIPv4MappedToIPv6)
            return IPAddress.IsLoopback(ip.MapToIPv4());
        return false;
    }

    private static string? FormatIp(IPAddress? ip)
    {
        if (ip is null)
            return null;
        if (ip.IsIPv4MappedToIPv6)
            ip = ip.MapToIPv4();
        return ip.ToString();
    }

    private static bool TryParseIp(string? raw, out string normalized)
    {
        normalized = "";
        if (string.IsNullOrWhiteSpace(raw))
            return false;
        raw = raw.Trim().Trim('"');
        if (raw.StartsWith("for=", StringComparison.OrdinalIgnoreCase))
            raw = raw[4..].Trim();
        if (raw.StartsWith('[') && raw.Contains(']'))
        {
            var end = raw.IndexOf(']');
            raw = raw[1..end];
        }

        if (!IPAddress.TryParse(raw, out var ip))
            return false;
        if (ip.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
            return false;
        normalized = FormatIp(ip)!;
        return true;
    }
}
