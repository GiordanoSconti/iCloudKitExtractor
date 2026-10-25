using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

public interface IAnisetteProvider
{
    Task<AnisetteHeaders> FetchAsync(CancellationToken ct = default);

    /// <summary>
    /// Fetch con contesto (es. Apple ID per RAD). Default: ignora options.
    /// </summary>
    Task<AnisetteHeaders> FetchAsync(AnisetteFetchOptions? options, CancellationToken ct = default) =>
        FetchAsync(ct);
}
