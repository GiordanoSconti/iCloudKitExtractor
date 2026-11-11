using iCloudKitExtractor.AnisetteLicense;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace iCloudKitExtractor.AnisetteServer.Licensed.Licensing;

public static class LicenseSyncEndpoints
{
    public static bool IsSyncPath(string? path) =>
        !string.IsNullOrEmpty(path)
        && path.StartsWith("/internal/license", StringComparison.OrdinalIgnoreCase);

    public static bool IsAuthorizedSyncRequest(HttpRequest req) =>
        LicenseSyncOptions.IsAuthorized(
            req.Headers[LicenseSyncOptions.HeaderName].ToString(),
            req.Headers.Authorization.ToString());

    public static IEndpointRouteBuilder MapLicenseSync(this IEndpointRouteBuilder app)
    {
        app.MapPost("/internal/license-sync", async (HttpRequest req, HttpResponse res, LicenseDatabase db) =>
        {
            StampReplica(res);
            if (!IsAuthorizedSyncRequest(req))
                return Results.Json(new { ok = false, error = "sync_unauthorized" }, statusCode: 401);

            LicenseSyncRecord? body;
            try
            {
                body = await req.ReadFromJsonAsync<LicenseSyncRecord>().ConfigureAwait(false);
            }
            catch
            {
                return Results.Json(new { ok = false, error = "bad_json" }, statusCode: 400);
            }

            if (body is null || string.IsNullOrWhiteSpace(body.LicenseId))
                return Results.Json(new { ok = false, error = "license_id_required" }, statusCode: 400);

            db.UpsertSync(body);
            return Results.Json(new
            {
                ok = true,
                license_id = body.LicenseId,
                replica_id = LicenseSyncOptions.LocalReplicaId,
            });
        });

        app.MapGet("/internal/license/{id}", (string id, HttpRequest req, HttpResponse res, LicenseDatabase db) =>
        {
            StampReplica(res);
            if (!IsAuthorizedSyncRequest(req))
                return Results.Json(new { ok = false, error = "sync_unauthorized" }, statusCode: 401);

            if (!db.TryGet(id, out var row, out var err) || row is null)
                return Results.Json(new { ok = false, error = err }, statusCode: 404);

            return Results.Json(LicenseSyncRecord.FromRow(row));
        });

        app.MapGet("/internal/license/by-fingerprint/{fp}", (string fp, HttpRequest req, HttpResponse res, LicenseDatabase db) =>
        {
            StampReplica(res);
            if (!IsAuthorizedSyncRequest(req))
                return Results.Json(new { ok = false, error = "sync_unauthorized" }, statusCode: 401);

            var row = db.FindByFingerprint(fp);
            if (row is null)
                return Results.Json(new { ok = false, error = "not_found" }, statusCode: 404);

            return Results.Json(LicenseSyncRecord.FromRow(row));
        });

        return app;
    }

    private static void StampReplica(HttpResponse res) =>
        res.Headers[LicenseSyncOptions.ReplicaHeaderName] = LicenseSyncOptions.LocalReplicaId;
}
