using System.Net;
using iCloudKitExtractor.AnisetteLicense;
using Microsoft.AspNetCore.Http;

namespace iCloudKitExtractor.AnisetteServer.Licensed.Licensing;

/// <summary>
/// Loopback → free. /health → free.
/// Remote: Bearer Package-C/token, or first-connection auto-issue (once per fingerprint).
/// </summary>
public sealed class LicenseAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly LicenseValidator _validator;
    private readonly LicenseIssuer _issuer;

    private static readonly HashSet<string> PublicExact = new(StringComparer.OrdinalIgnoreCase)
    {
        "/health",
    };

    public LicenseAuthMiddleware(RequestDelegate next, LicenseValidator validator, LicenseIssuer issuer)
    {
        _next = next;
        _validator = validator;
        _issuer = issuer;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        var path = ctx.Request.Path.Value ?? "/";
        if (PublicExact.Contains(path))
        {
            await _next(ctx);
            return;
        }

        if (IsLoopback(ctx.Connection.RemoteIpAddress))
        {
            await _next(ctx);
            return;
        }

        var auth = ctx.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(auth))
        {
            if (!_validator.TryValidateBearer(auth, out var error, out var payload))
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                ctx.Response.Headers.WWWAuthenticate = "Bearer";
                await ctx.Response.WriteAsJsonAsync(new
                {
                    ok = false,
                    error = "license_required",
                    detail = error,
                });
                return;
            }

            ctx.Items["anisette_license_id"] = payload!.LicenseId;
            ctx.Items["anisette_license_sub"] = payload.Subject;
            await _next(ctx);
            return;
        }

        // No Bearer: auto-issue once using fingerprint headers.
        var machineId = ctx.Request.Headers[ClientFingerprint.HeaderMachineId].ToString();
        var hostname = ctx.Request.Headers[ClientFingerprint.HeaderHostname].ToString();
        var os = ctx.Request.Headers[ClientFingerprint.HeaderOs].ToString();
        var appInstance = ctx.Request.Headers[ClientFingerprint.HeaderAppInstance].ToString();
        var clientIp = ctx.Connection.RemoteIpAddress?.ToString();

        var auto = _issuer.TryAutoIssue(clientIp, machineId, hostname, os, appInstance);
        if (auto.Ok && !string.IsNullOrEmpty(auto.BundleBase64))
        {
            ctx.Items["anisette_license_id"] = auto.LicenseId;
            ctx.Items["anisette_license_bundle"] = auto.BundleBase64;
            ctx.Response.Headers[ClientFingerprint.ResponseBundleHeader] = auto.BundleBase64;
            await _next(ctx);
            return;
        }

        ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
        ctx.Response.Headers.WWWAuthenticate = "Bearer";
        await ctx.Response.WriteAsJsonAsync(new
        {
            ok = false,
            error = auto.Error ?? "license_required",
            detail = auto.Detail ?? "Authorization Bearer license required",
            license_id = auto.LicenseId,
        });
    }

    private static bool IsLoopback(IPAddress? ip)
    {
        if (ip is null)
            return false;
        if (IPAddress.IsLoopback(ip))
            return true;
        if (ip.IsIPv4MappedToIPv6)
            return IPAddress.IsLoopback(ip.MapToIPv4());
        return false;
    }
}
