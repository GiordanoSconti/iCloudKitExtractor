using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>Bag IDS (<c>getBag?ix=3</c>) — outer bplist firmato con chiave <c>bag</c> interna.</summary>
public sealed class IdsBag
{
    private readonly HttpClient _http;
    private Dictionary<string, string>? _urls;

    public IdsBag(HttpClient http) => _http = http;

    public async Task EnsureLoadedAsync(CancellationToken ct = default)
    {
        if (_urls is not null)
            return;

        _urls = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["id-authenticate-ds-id"] = IdsConstants.FallbackAuthenticateDs,
            ["id-get-handles"] = IdsConstants.FallbackGetHandles,
            ["id-register"] = IdsConstants.FallbackRegister,
        };

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, IdsConstants.BagUrl);
            request.Headers.TryAddWithoutValidation("User-Agent", IdsConstants.InvitationUserAgent);
            request.Headers.TryAddWithoutValidation("Accept", "*/*");
            using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
            var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            var unzipped = IdsSigning.TryGunzip(bytes) ?? bytes;
            var bag = ParseIdsBag(unzipped);
            if (bag is null)
                return;

            foreach (var key in new[] { "id-authenticate-ds-id", "id-get-handles", "id-register" })
            {
                if (bag.TryGetValue(key, out var val) && val is string url && !string.IsNullOrWhiteSpace(url))
                    _urls[key] = url;
            }
        }
        catch
        {
            // fallback già impostati
        }
    }

    public async Task<string> GetAsync(string bagKey, CancellationToken ct = default)
    {
        await EnsureLoadedAsync(ct).ConfigureAwait(false);
        if (_urls!.TryGetValue(bagKey, out var url) && !string.IsNullOrWhiteSpace(url))
            return url;
        throw new InvalidOperationException($"Bag IDS senza URL per {bagKey}.");
    }

    /// <summary>URL effettivi caricati (diagnostica).</summary>
    public async Task<IReadOnlyDictionary<string, string>> SnapshotAsync(CancellationToken ct = default)
    {
        await EnsureLoadedAsync(ct).ConfigureAwait(false);
        return _urls!;
    }

    private static Dictionary<string, object?>? ParseIdsBag(byte[] data)
    {
        Dictionary<string, object?>? outer = null;
        if (data.Length >= 6 && data.AsSpan(0, 6).SequenceEqual("bplist"u8))
        {
            if (!AppleBinaryPlist.TryParseDict(data, out outer, out _) || outer is null)
                return null;
        }
        else
        {
            var text = Encoding.UTF8.GetString(data);
            if (!text.Contains("<plist", StringComparison.OrdinalIgnoreCase))
                return null;
            outer = AppleXmlPlist.Parse(data);
        }

        // Outer firmato: { signature, certs, bag: <bytes|dict> }
        if (outer.TryGetValue("bag", out var bagObj))
        {
            switch (bagObj)
            {
                case Dictionary<string, object?> nested:
                    return nested;
                case byte[] bagBytes:
                {
                    var inner = IdsSigning.TryGunzip(bagBytes) ?? bagBytes;
                    if (inner.Length >= 6 && inner.AsSpan(0, 6).SequenceEqual("bplist"u8))
                    {
                        if (AppleBinaryPlist.TryParseDict(inner, out var dict, out _) && dict is not null)
                            return dict;
                    }
                    else
                    {
                        try { return AppleXmlPlist.Parse(inner); }
                        catch { /* ignore */ }
                    }

                    break;
                }
            }
        }

        // Già bag “piatto”
        return outer;
    }
}
