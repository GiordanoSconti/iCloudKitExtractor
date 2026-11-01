using System.Net;
using iCloudKitExtractor.AnisetteLicense;
using Microsoft.AspNetCore.Http;

namespace AnisetteServer.Mac.Services;

/// <summary>
/// Logs inbound connections (VPN hints) and enforces per-IP burst abuse limits.
/// Uses Cloudflare / proxy client IP when TCP peer is loopback (Tunnel).
/// </summary>
public sealed class ConnectionGuardMiddleware
{
    private readonly RequestDelegate _next;
    private readonly ConnectionLogStore _log;
    private readonly AbuseRateLimiter _limiter;

    public ConnectionGuardMiddleware(
        RequestDelegate next,
        ConnectionLogStore log,
        AbuseRateLimiter limiter)
    {
        _next = next;
        _log = log;
        _limiter = limiter;
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
        var method = ctx.Request.Method;
        var ua = ctx.Request.Headers.UserAgent.ToString();
        var forwarded = InboundClientAddress.ForwardedHeadersSummary(Header);

        // /health + true local loopback skip abuse; Tunnel clients are rate-limited by real IP.
        var skipAbuse = string.Equals(path, "/health", StringComparison.OrdinalIgnoreCase)
                        || InboundClientAddress.IsTrustedLocalLoopback(ctx.Connection.RemoteIpAddress, Header);

        IPAddress? classifyIp = null;
        if (IPAddress.TryParse(ip, out var parsed))
            classifyIp = parsed;
        else
            classifyIp = ctx.Connection.RemoteIpAddress;

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

                _log.Add(new ConnectionLogEntry(
                    DateTimeOffset.UtcNow,
                    ip,
                    method,
                    path,
                    StatusCodes.Status429TooManyRequests,
                    "RATE_LIMITED",
                    vpnHint,
                    Truncate(ua, 80),
                    Truncate(forwarded, 120)));
                return;
            }
        }

        await _next(ctx).ConfigureAwait(false);

        _log.Add(new ConnectionLogEntry(
            DateTimeOffset.UtcNow,
            ip,
            method,
            path,
            ctx.Response.StatusCode,
            OutcomeFor(ctx.Response.StatusCode),
            vpnHint,
            Truncate(ua, 80),
            Truncate(forwarded, 120)));
    }

    private static string OutcomeFor(int code) =>
        code switch
        {
            >= 200 and < 300 => "OK",
            401 => "UNAUTHORIZED",
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
