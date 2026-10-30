namespace iCloudKitExtractor.AnisetteLicense;

/// <summary>Manual + automatic first-connection license issuance (Package C).</summary>
public sealed class LicenseIssuer
{
    private readonly string _privateKeyPath;
    private readonly string _publicKeyPath;
    private readonly LicenseDatabase _db;
    private readonly object _gate = new();

    public LicenseIssuer(string privateKeyPath, string publicKeyPath, LicenseDatabase db)
    {
        _privateKeyPath = privateKeyPath;
        _publicKeyPath = publicKeyPath;
        _db = db;
    }

    public string IssueManual(
        string subject,
        int? days,
        string? note,
        string? fingerprint,
        string? clientIp,
        out LicensePayload payload,
        out string bundleBase64)
    {
        var now = DateTimeOffset.UtcNow;
        payload = new LicensePayload
        {
            LicenseId = Guid.NewGuid().ToString("N"),
            Subject = subject.Trim(),
            IssuedAtUnix = now.ToUnixTimeSeconds(),
            ExpiresAtUnix = days is int d ? now.AddDays(d).ToUnixTimeSeconds() : null,
            Note = string.IsNullOrWhiteSpace(note) ? null : note.Trim(),
            Fingerprint = string.IsNullOrWhiteSpace(fingerprint) ? null : fingerprint.Trim(),
            ClientIp = string.IsNullOrWhiteSpace(clientIp) ? null : clientIp.Trim(),
        };

        var bundle = LicenseCrypto.IssueBundle(payload, _privateKeyPath, _publicKeyPath);
        bundleBase64 = bundle.ToBase64();
        var hint = bundle.Token.Length <= 24
            ? bundle.Token
            : bundle.Token[..12] + "…" + bundle.Token[^8..];
        _db.Insert(payload, hint, emittedOnce: false);
        return bundle.Token;
    }

    /// <summary>
    /// First remote connection without Bearer: issue once per fingerprint.
    /// Returns bundle Base64 to embed in the response, or null if already issued / not eligible.
    /// </summary>
    public AutoIssueResult TryAutoIssue(
        string? clientIp,
        string? machineId,
        string? hostname,
        string? os,
        string? appInstance)
    {
        lock (_gate)
        {
            var fp = ClientFingerprint.Compute(machineId, hostname, os, appInstance);
            if (string.IsNullOrWhiteSpace(machineId) && string.IsNullOrWhiteSpace(hostname))
            {
                return AutoIssueResult.Fail(
                    "fingerprint_required",
                    "Send X-IKE-Machine-Id / X-IKE-Hostname on first connection");
            }

            var existing = _db.FindByFingerprint(fp);
            if (existing is not null)
            {
                if (existing.EmittedOnce || !string.IsNullOrEmpty(existing.RevokedAt) || existing.Enabled)
                {
                    return AutoIssueResult.ForAlreadyIssued(existing.LicenseId);
                }
            }

            var now = DateTimeOffset.UtcNow;
            var payload = new LicensePayload
            {
                LicenseId = Guid.NewGuid().ToString("N"),
                Subject = ClientFingerprint.SubjectFromFingerprint(fp, hostname),
                IssuedAtUnix = now.ToUnixTimeSeconds(),
                ExpiresAtUnix = null,
                Note = "auto-issued on first connection",
                ClientIp = clientIp,
                MachineId = machineId,
                Hostname = hostname,
                Os = os,
                AppInstance = appInstance,
                Fingerprint = fp,
            };

            var bundle = LicenseCrypto.IssueBundle(payload, _privateKeyPath, _publicKeyPath);
            var b64 = bundle.ToBase64();
            var hint = bundle.Token.Length <= 24
                ? bundle.Token
                : bundle.Token[..12] + "…" + bundle.Token[^8..];
            _db.Insert(payload, hint, emittedOnce: true);
            return AutoIssueResult.Issued(payload.LicenseId, b64, fp);
        }
    }
}

public sealed class AutoIssueResult
{
    public bool Ok { get; private init; }
    public bool AlreadyIssued { get; private init; }
    public string? LicenseId { get; private init; }
    public string? BundleBase64 { get; private init; }
    public string? Fingerprint { get; private init; }
    public string? Error { get; private init; }
    public string? Detail { get; private init; }

    public static AutoIssueResult Issued(string id, string bundle, string fp) => new()
    {
        Ok = true,
        LicenseId = id,
        BundleBase64 = bundle,
        Fingerprint = fp,
    };

    public static AutoIssueResult ForAlreadyIssued(string id) => new()
    {
        Ok = false,
        AlreadyIssued = true,
        LicenseId = id,
        Error = "license_already_issued",
        Detail = "License was already issued for this machine; paste it in the License field",
    };

    public static AutoIssueResult Fail(string error, string detail) => new()
    {
        Ok = false,
        Error = error,
        Detail = detail,
    };
}
