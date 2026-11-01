using System.Net;
using System.Text;
using iCloudKitExtractor.AnisetteLicense;
using Microsoft.AspNetCore.Http;

namespace AnisetteServer.Mac.Services;

/// <summary>
/// Logs inbound connections (full request headers, VPN hints) and enforces per-IP burst abuse limits.
/// Uses Cloudflare / proxy client IP when TCP peer is loopback (Tunnel).
/// </summary>
public sealed class ConnectionGuardMiddleware
{
    private const int MaxHeadersChars = 24_000;

    private readonly RequestDelegate _next;
    private readonly ConnectionLogStore _log;
    private readonly AbuseRateLimiter _limiter;
    private readonly VpnConsentStore _vpnConsent;

    public ConnectionGuardMiddleware(
        RequestDelegate next,
        ConnectionLogStore log,
        AbuseRateLimiter limiter,
        VpnConsentStore vpnConsent)
    {
        _next = next;
        _log = log;
        _limiter = limiter;
        _vpnConsent = vpnConsent;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        string? Header(string name) => ctx.Request.Headers[name].ToString();
        var ip = InboundClientAddress.Resolve(ctx.Connection.RemoteIpAddress, Header);
        ctx.Items[InboundClientAddress.ItemsKey] = ip;
        var viaTunnel = InboundClientAddress.HasTunnelOrProxyHeaders(Header)
                        || InboundClientAddress.TryGetForwardedClientIp(Header) is not null;
        ctx.Items[InboundClientAddress.TunnelItemsKey] = viaTunnel;

        var path = ctx.Request.Path.Value ?? "/";
        var query = ctx.Request.QueryString.HasValue ? ctx.Request.QueryString.Value : null;
        var method = ctx.Request.Method;
        var scheme = ctx.Request.Scheme;
        var host = ctx.Request.Host.Value;
        var ua = ctx.Request.Headers.UserAgent.ToString();
        var forwarded = InboundClientAddress.ForwardedHeadersSummary(Header);
        var allHeaders = CaptureAllHeaders(ctx);

        // /health + true local loopback skip abuse; Tunnel clients are rate-limited by real IP.
        var skipAbuse = string.Equals(path, "/health", StringComparison.OrdinalIgnoreCase)
                        || InboundClientAddress.IsTrustedLocalLoopback(ctx.Connection.RemoteIpAddress, Header);

        IPAddress? classifyIp = IPAddress.TryParse(ip, out var parsed)
            ? parsed
            : ctx.Connection.RemoteIpAddress;

        string vpnHint;
        try
        {
            vpnHint = await VpnHintProbe
                .ClassifyAsync(classifyIp, ua, forwarded, ctx.RequestAborted)
                .ConfigureAwait(false);
            if (viaTunnel && !vpnHint.Contains("tunnel", StringComparison.OrdinalIgnoreCase))
                vpnHint += " · via Cloudflare Tunnel/proxy";
        }
        catch
        {
            vpnHint = viaTunnel ? "unknown · via Cloudflare Tunnel/proxy" : "unknown";
        }

        var skipVpnGate = skipAbuse; // loopback + /health
        if (!skipVpnGate && !_vpnConsent.IsAllowed(ip, vpnHint))
        {
            _vpnConsent.RememberDenied(ip, vpnHint);
            var suggested = VpnHintProbe.SuggestConsentPattern(vpnHint, ip);
            ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
            await ctx.Response.WriteAsJsonAsync(new
            {
                ok = false,
                error = "vpn_consent_required",
                detail = "This VPN/proxy is not on the operator allowlist. Approve it in Anisette Middleware → Connections → VPN consent.",
                client_ip = ip,
                vpn = vpnHint,
                suggested_pattern = suggested,
            }).ConfigureAwait(false);

            _log.Add(MakeEntry(
                ip, method, path, query, scheme, host,
                StatusCodes.Status403Forbidden, "VPN_DENIED",
                vpnHint, ua, forwarded, allHeaders));
            return;
        }

        if (!skipAbuse)
        {
            if (_limiter.IsBlocked(ip, out var until)
                || !_limiter.TryAdmit(ip, out until))
            {
                ctx.Response.StatusCode = StatusCodes.Status429TooManyRequests;
                ctx.Response.Headers.RetryAfter = ((int)AbuseRateLimiter.BlockDuration.TotalSeconds).ToString();
                await ctx.Response.WriteAsJsonAsync(new
                {
                    ok = false,
                    error = "rate_limited",
                    detail = AbuseRateLimiter.ExcessiveOriginMessage,
                    blocked_until_utc = until?.UtcDateTime.ToString("o"),
                    client_ip = ip,
                }).ConfigureAwait(false);

                _log.Add(MakeEntry(
                    ip, method, path, query, scheme, host,
                    StatusCodes.Status429TooManyRequests, "RATE_LIMITED",
                    vpnHint, ua, forwarded, allHeaders));
                return;
            }
        }

        await _next(ctx).ConfigureAwait(false);

        _log.Add(MakeEntry(
            ip, method, path, query, scheme, host,
            ctx.Response.StatusCode, OutcomeFor(ctx.Response.StatusCode),
            vpnHint, ua, forwarded, allHeaders));
    }

    private static ConnectionLogEntry MakeEntry(
        string ip,
        string method,
        string path,
        string? query,
        string? scheme,
        string? host,
        int status,
        string outcome,
        string vpnHint,
        string? ua,
        string? forwarded,
        string allHeaders) =>
        new(
            DateTimeOffset.UtcNow,
            ip,
            method,
            path,
            query,
            scheme,
            host,
            status,
            outcome,
            vpnHint,
            Truncate(ua, 200),
            Truncate(forwarded, 500),
            allHeaders);

    /// <summary>Dump every request header (Cloudflare CF-*, X-Forwarded-*, client, etc.).</summary>
    internal static string CaptureAllHeaders(HttpContext ctx)
    {
        var sb = new StringBuilder();
        // Stable-ish order: Cloudflare / proxy first, then the rest alphabetically.
        var names = ctx.Request.Headers.Keys
            .OrderBy(n => CloudflareSortKey(n))
            .ThenBy(n => n, StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var name in names)
        {
            var values = ctx.Request.Headers[name];
            var value = values.Count == 0 ? "" : string.Join(", ", values.ToArray());
            sb.Append(name);
            sb.Append(": ");
            sb.Append(value);
            sb.AppendLine();
            if (sb.Length >= MaxHeadersChars)
            {
                sb.AppendLine("… (headers truncated)");
                break;
            }
        }

        // Extra connection metadata useful behind Tunnel.
        sb.AppendLine($"X-IKE-Remote-Tcp: {ctx.Connection.RemoteIpAddress}");
        sb.AppendLine($"X-IKE-Local-Tcp: {ctx.Connection.LocalIpAddress}:{ctx.Connection.LocalPort}");
        sb.AppendLine($"X-IKE-Protocol: {ctx.Request.Protocol}");
        if (ctx.Request.Headers.Count == 0)
            sb.AppendLine("(no HTTP headers)");

        return sb.ToString().TrimEnd();
    }

    private static int CloudflareSortKey(string name)
    {
        if (name.StartsWith("CF-", StringComparison.OrdinalIgnoreCase)
            || name.StartsWith("Cf-", StringComparison.OrdinalIgnoreCase))
            return 0;
        if (name.StartsWith("X-Forwarded-", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Forwarded", StringComparison.OrdinalIgnoreCase)
            || name.Equals("True-Client-IP", StringComparison.OrdinalIgnoreCase)
            || name.Equals("Via", StringComparison.OrdinalIgnoreCase))
            return 1;
        return 2;
    }

    private static string OutcomeFor(int code) =>
        code switch
        {
            >= 200 and < 300 => "OK",
            401 => "UNAUTHORIZED",
            403 => "VPN_DENIED",
            429 => "RATE_LIMITED",
            503 => "UPSTREAM",
            _ => $"HTTP_{code}",
        };

    private static string? Truncate(string? s, int n)
    {
        if (string.IsNullOrEmpty(s))
            return null;
        return s.Length <= n ? s : s[..n] + "…";
    }
}
