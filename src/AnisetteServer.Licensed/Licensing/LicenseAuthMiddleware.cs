using iCloudKitExtractor.AnisetteLicense;
using Microsoft.AspNetCore.Http;

namespace iCloudKitExtractor.AnisetteServer.Licensed.Licensing;

/// <summary>
/// Trusted local loopback (no tunnel headers) → free.
/// /health → free.
/// Cloudflare Tunnel / proxy (TCP may be 127.0.0.1 but CF-Connecting-IP present) → remote rules.
/// Remote: Bearer Package-C/token, or first-connection auto-issue (once per fingerprint).
/// </summary>
public sealed class LicenseAuthMiddleware
{
    private readonly RequestDelegate _next;
    private readonly LicenseValidator _validator;
    private readonly LicenseIssuer _issuer;
    private readonly ILicenseAllowlist _allowlist;

    private static readonly HashSet<string> PublicExact = new(StringComparer.OrdinalIgnoreCase)
    {
        "/health",
    };

    public LicenseAuthMiddleware(
        RequestDelegate next,
        LicenseValidator validator,
        LicenseIssuer issuer,
        ILicenseAllowlist? allowlist = null)
    {
        _next = next;
        _validator = validator;
        _issuer = issuer;
        _allowlist = allowlist ?? PermissiveLicenseAllowlist.Instance;
    }

    public async Task InvokeAsync(HttpContext ctx)
    {
        var path = ctx.Request.Path.Value ?? "/";
        if (PublicExact.Contains(path))
        {
            await _next(ctx);
            return;
        }

        // Peer license sync (Cloudflare Tunnel / multi-LAN) — secret gate, not Package-C.
        if (LicenseSyncEndpoints.IsSyncPath(path))
        {
            if (!LicenseSyncEndpoints.IsAuthorizedSyncRequest(ctx.Request))
            {
                ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
                await ctx.Response.WriteAsJsonAsync(new { ok = false, error = "sync_unauthorized" });
                return;
            }

            await _next(ctx);
            return;
        }

        string? Header(string name) => ctx.Request.Headers[name].ToString();
        var clientIp = InboundClientAddress.Resolve(ctx.Connection.RemoteIpAddress, Header);
        ctx.Items[InboundClientAddress.ItemsKey] = clientIp;
        ctx.Items[InboundClientAddress.TunnelItemsKey] =
            InboundClientAddress.HasTunnelOrProxyHeaders(Header)
            || InboundClientAddress.TryGetForwardedClientIp(Header) is not null;

        // Only skip licensing for true local clients — not Cloudflare Tunnel to localhost.
        if (InboundClientAddress.IsTrustedLocalLoopback(ctx.Connection.RemoteIpAddress, Header))
        {
            await _next(ctx);
            return;
        }

        var auth = ctx.Request.Headers.Authorization.ToString();
        if (!string.IsNullOrWhiteSpace(auth))
        {
            if (!_validator.TryValidateBearer(auth, out var error, out var payload, out var syncedFromPeer))
            {
                if (syncedFromPeer
                    || string.Equals(error, LicenseValidator.ReplicaSyncedError, StringComparison.Ordinal))
                {
                    // License was pulled onto this replica — ask IKE to reconnect once.
                    ctx.Response.StatusCode = StatusCodes.Status503ServiceUnavailable;
                    ctx.Response.Headers["X-Anisette-License-Synced"] = "1";
                    await ctx.Response.WriteAsJsonAsync(new
                    {
                        ok = false,
                        error = LicenseValidator.ReplicaSyncedError,
                        detail = LicenseValidator.ReplicaSyncedDetail,
                        license_id = payload?.LicenseId,
                    });
                    return;
                }

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

            var rawBearer = auth.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
                ? auth["Bearer ".Length..].Trim()
                : auth.Trim();
            if (!_allowlist.IsAllowed(payload!, rawBearer))
            {
                ctx.Response.StatusCode = StatusCodes.Status403Forbidden;
                await ctx.Response.WriteAsJsonAsync(new
                {
                    ok = false,
                    error = "license_not_allowlisted",
                    detail =
                        "This license is valid but not on the server Authorization allowlist. " +
                        "Add the license id / Package-C / Bearer in Anisette Middleware → Licenses.",
                    license_id = payload!.LicenseId,
                    subject = payload.Subject,
                });
                return;
            }

            ctx.Items["anisette_license_id"] = payload!.LicenseId;
            ctx.Items["anisette_license_sub"] = payload.Subject;
            await _next(ctx);
            return;
        }

        // When Authorization allowlist is enforced, do not auto-issue — operator must
        // supply a Bearer already listed (license id / Package-C / token).
        if (_allowlist.IsEnforced)
        {
            ctx.Response.StatusCode = StatusCodes.Status401Unauthorized;
            ctx.Response.Headers.WWWAuthenticate = "Bearer";
            await ctx.Response.WriteAsJsonAsync(new
            {
                ok = false,
                error = "license_allowlist_enforced",
                detail =
                    "Authorization license allowlist is enabled. " +
                    "Send Authorization: Bearer <allowlisted Package-C or token>. Auto-issue is disabled.",
                client_ip = clientIp,
            });
            return;
        }

        // No Bearer: auto-issue once using fingerprint headers (works behind Tunnel too).
        var machineId = ctx.Request.Headers[ClientFingerprint.HeaderMachineId].ToString();
        var hostname = ctx.Request.Headers[ClientFingerprint.HeaderHostname].ToString();
        var os = ctx.Request.Headers[ClientFingerprint.HeaderOs].ToString();
        var appInstance = ctx.Request.Headers[ClientFingerprint.HeaderAppInstance].ToString();

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
            client_ip = clientIp,
        });
    }
}
