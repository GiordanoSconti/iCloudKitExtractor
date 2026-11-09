namespace iCloudKitExtractor.AnisetteLicense;

/// <summary>
/// Optional gate after crypto+DB validation: only listed licenses may use
/// <c>Authorization: Bearer …</c> when <see cref="IsEnforced"/> is true.
/// </summary>
public interface ILicenseAllowlist
{
    bool IsEnforced { get; }

    /// <summary>
    /// Returns true if this validated license / raw Bearer material is on the allowlist.
    /// When not enforced, always true.
    /// </summary>
    bool IsAllowed(LicensePayload payload, string rawBearerOrBundle);
}
