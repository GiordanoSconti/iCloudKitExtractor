namespace iCloudKitExtractor.AnisetteLicense;

public sealed class LicenseValidator
{
    public const string ReplicaSyncedError = "license_replica_synced";

    public const string ReplicaSyncedDetail =
        "This Anisette replica did not have your license yet. " +
        "The license has been synchronized across all replicas. " +
        "Please reconnect and try again.";

    private readonly string _publicKeyPath;
    private readonly LicenseDatabase _db;
    private readonly LicenseSyncClient? _sync;

    public LicenseValidator(string publicKeyPath, LicenseDatabase db, LicenseSyncClient? sync = null)
    {
        _publicKeyPath = publicKeyPath;
        _db = db;
        _sync = sync;
    }

    public bool TryValidateBearer(string? authorizationHeader, out string error, out LicensePayload? payload) =>
        TryValidateBearer(authorizationHeader, out error, out payload, out _);

    public bool TryValidateBearer(
        string? authorizationHeader,
        out string error,
        out LicensePayload? payload,
        out bool syncedFromPeer)
    {
        payload = null;
        error = "";
        syncedFromPeer = false;

        if (string.IsNullOrWhiteSpace(authorizationHeader))
        {
            error = "missing Authorization Bearer license";
            return false;
        }

        const string prefix = "Bearer ";
        string raw;
        if (authorizationHeader.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
            raw = authorizationHeader[prefix.Length..].Trim();
        else
            raw = authorizationHeader.Trim();

        if (string.IsNullOrEmpty(raw))
        {
            error = "empty Bearer token";
            return false;
        }

        if (!LicenseCrypto.TryExtractToken(raw, out var token, out var bundle, out error))
            return false;

        if (bundle is not null && !LicenseCrypto.PublicKeyMatches(_publicKeyPath, bundle.PublicKey))
        {
            error = "bundle public_key does not match server";
            return false;
        }

        if (!LicenseCrypto.TryVerify(token, _publicKeyPath, out payload, out error))
            return false;

        if (_db.TryGetActive(payload!.LicenseId, out _, out error))
            return true;

        var missing = error.Contains("not registered", StringComparison.OrdinalIgnoreCase);
        if (!missing)
            return false;

        var hubOk = false;

        // 1) Pull from Worker hub / peers
        if (_sync is not null && LicenseSyncOptions.IsConfigured)
        {
            try
            {
                var pulled = _sync.PullByIdAsync(payload.LicenseId).GetAwaiter().GetResult();
                if (pulled is not null && _db.TryGetActive(payload.LicenseId, out _, out error))
                {
                    syncedFromPeer = true;
                    error = ReplicaSyncedError;
                    return false;
                }
            }
            catch
            {
                // fall through to signature rehydrate
            }
        }

        // 2) Signature already proved authenticity — rehydrate local SQLite and push to hub.
        try
        {
            var hint = token.Length <= 24 ? token : token[..12] + "…" + token[^8..];
            _db.UpsertFromVerifiedPayload(payload, hint);
            if (_sync is not null && LicenseSyncOptions.IsConfigured
                && _db.TryGet(payload.LicenseId, out var row, out _) && row is not null)
            {
                try
                {
                    hubOk = _sync.PushRowAsync(row, hint).GetAwaiter().GetResult();
                }
                catch
                {
                    hubOk = false;
                }
            }

            if (_db.TryGetActive(payload.LicenseId, out _, out error))
            {
                // Only claim cross-replica sync when the hub (or other Mini) acknowledged.
                syncedFromPeer = hubOk;
                error = hubOk
                    ? ReplicaSyncedError
                    : "license rehydrated locally but hub sync failed — check ANISETTE_LICENSE_SYNC_SECRET";
                // Allow the request if hub push failed but local row exists — otherwise UX loops forever.
                return !hubOk;
            }
        }
        catch (Exception ex)
        {
            error = "license_id not registered; rehydrate failed: " + ex.Message;
        }

        return false;
    }
}
