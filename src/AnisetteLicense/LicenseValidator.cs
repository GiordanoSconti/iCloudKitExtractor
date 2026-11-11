namespace iCloudKitExtractor.AnisetteLicense;

public sealed class LicenseValidator
{
    private readonly string _publicKeyPath;
    private readonly LicenseDatabase _db;
    private readonly LicenseSyncClient? _sync;

    public LicenseValidator(string publicKeyPath, LicenseDatabase db, LicenseSyncClient? sync = null)
    {
        _publicKeyPath = publicKeyPath;
        _db = db;
        _sync = sync;
    }

    public bool TryValidateBearer(string? authorizationHeader, out string error, out LicensePayload? payload)
    {
        payload = null;
        error = "";

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

        // Replica miss: pull from peer tunnels then retry (multi-LAN HA).
        if (_sync is not null
            && LicenseSyncOptions.IsConfigured
            && error.Contains("not registered", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var pulled = _sync.PullByIdAsync(payload.LicenseId).GetAwaiter().GetResult();
                if (pulled is not null && _db.TryGetActive(payload.LicenseId, out _, out error))
                    return true;
            }
            catch
            {
                // fall through with original error
            }
        }

        return false;
    }
}
