using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>Placeholder when a platform-specific Anisette backend is not available.</summary>
public sealed class UnavailableAnisetteProvider(string reason) : IAnisetteProvider
{
    public Task<AnisetteHeaders> FetchAsync(CancellationToken ct = default) =>
        throw new InvalidOperationException(reason);
}
