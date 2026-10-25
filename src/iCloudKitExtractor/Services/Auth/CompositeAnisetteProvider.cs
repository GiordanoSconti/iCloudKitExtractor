using System.IO;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

public sealed class CompositeAnisetteProvider : IAnisetteProvider
{
    private readonly IAnisetteProvider _primary;
    private readonly IAnisetteProvider _fallback;

    public CompositeAnisetteProvider(IAnisetteProvider primary, IAnisetteProvider fallback)
    {
        _primary = primary;
        _fallback = fallback;
    }

    public Task<AnisetteHeaders> FetchAsync(CancellationToken ct = default) =>
        FetchAsync(null, ct);

    public async Task<AnisetteHeaders> FetchAsync(AnisetteFetchOptions? options, CancellationToken ct = default)
    {
        try
        {
            return await _primary.FetchAsync(options, ct).ConfigureAwait(false);
        }
        catch (Exception primaryEx) when (primaryEx is InvalidOperationException or IOException)
        {
            try
            {
                return await _fallback.FetchAsync(options, ct).ConfigureAwait(false);
            }
            catch (Exception fallbackEx)
            {
                throw new InvalidOperationException(
                    $"Anisette CoreADI fallita ({primaryEx.Message}); fallback AOSKit fallito ({fallbackEx.Message}).",
                    primaryEx);
            }
        }
    }
}
