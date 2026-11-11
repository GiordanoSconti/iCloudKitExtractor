using System.Text;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Estrae il descrittore MMCS dal campo CloudKit <c>contents</c> di un BackupAsset.
/// Strategia  parse messaggio <c>Asset</c> → signature <c>f2</c> + wrap <c>f15</c> insieme.
/// </summary>
public static class BackupAssetContentsParser
{
    public sealed record ContentsInfo(
        string? MmcsAuth,
        string? Extension,
        byte[]? AssetProtectionWrap,
        byte[]? AssetSignature = null);

    /// <summary>
    /// Analizza la finestra record per <c>contents</c>.
    /// Se <paramref name="preferSignature"/> è noto, prende wrap/auth dallo stesso Asset.
    /// </summary>
    public static ContentsInfo Parse(
        ReadOnlySpan<byte> window,
        ReadOnlySpan<byte> preferSignature = default)
    {
        if (window.IsEmpty)
            return new ContentsInfo(null, null, null);

        var extension = TryExtractExtension(window);
        var contentsIdx = IndexOf(window, "contents"u8);
        var search = contentsIdx >= 0 ? window[contentsIdx..] : window;

        //  wrap file-specific (f2/f17/contents-matching), mai primo wrap del batch.
        byte[]? contentsWrap = null;
        if (!preferSignature.IsEmpty)
            contentsWrap = CloudKitAssetProto.TryResolveContentsFieldWrap(
                window, preferSignature, out _);

        // 1)  Asset protobuf strutturale (match signature se nota).
        if (!preferSignature.IsEmpty
            && CloudKitAssetProto.TryFindBySignature(window, preferSignature) is { } matched)
        {
            var pi = contentsWrap is { Length: 24 or 40 }
                ? contentsWrap
                : matched.ProtectionWrap;
            return new ContentsInfo(
                matched.DownloadAuth,
                extension,
                pi,
                matched.Signature);
        }

        if (contentsWrap is { Length: 24 or 40 })
        {
            return new ContentsInfo(null, extension, contentsWrap, null);
        }

        var assets = CloudKitAssetProto.EnumerateAssets(
            CloudKitAssetProto.SliceContentsFieldValue(window));
        if (assets.Count == 0)
            assets = CloudKitAssetProto.EnumerateAssets(search);
        if (assets.Count == 0)
            assets = CloudKitAssetProto.EnumerateAssets(window);

        if (assets.Count > 0)
        {
            var a = assets[0];
            if (!preferSignature.IsEmpty)
            {
                var want = preferSignature.ToArray();
                var hit = assets.FirstOrDefault(x =>
                    x.Signature.AsSpan().SequenceEqual(want));
                if (hit is null && want.Length == 21)
                {
                    var digest = want.AsSpan(1).ToArray();
                    hit = assets.FirstOrDefault(x =>
                        x.Signature.Length == 21
                        && x.Signature.AsSpan(1).SequenceEqual(digest));
                }

                if (hit is not null)
                    a = hit;
            }

            var authFromAsset = a.DownloadAuth;
            if (string.IsNullOrWhiteSpace(authFromAsset))
            {
                var structured = MmcsAuthBuilder.ExtractStructuredAuths(search.ToArray());
                if (structured.Count > 0)
                    authFromAsset = structured[0].Header;
            }

            return new ContentsInfo(
                authFromAsset,
                extension,
                a.ProtectionWrap,
                a.Signature);
        }

        // 2) Fallback legacy (auth string-scan + wrap).
        string? auth = null;
        var structuredFallback = MmcsAuthBuilder.ExtractStructuredAuths(search.ToArray());
        if (structuredFallback.Count > 0)
            auth = structuredFallback[0].Header;
        if (string.IsNullOrWhiteSpace(auth))
        {
            var ready = MmcsAuthBuilder.ExtractAllReadyMadeAuths(search.ToArray());
            auth = ready.FirstOrDefault();
        }

        byte[]? wrap = null;
        if (!preferSignature.IsEmpty)
        {
            wrap = CloudKitAssetProto.TryGetWrapForSignature(search, preferSignature)
                   ?? CloudKitAssetProto.TryGetWrapForSignature(window, preferSignature);
        }
        else
        {
            wrap = MmcsAssetProtection.TryExtract(search) ?? MmcsAssetProtection.TryExtract(window);
        }

        return new ContentsInfo(auth, extension, wrap);
    }

    private static string? TryExtractExtension(ReadOnlySpan<byte> window)
    {
        var idx = IndexOf(window, "extension"u8);
        if (idx < 0)
            return null;

        var tail = window[(idx + "extension".Length)..];
        var plist = IndexOf(tail, "plist"u8);
        if (plist >= 0 && plist < 64)
            return "plist";

        for (var i = 0; i < Math.Min(tail.Length, 48); i++)
        {
            if (tail[i] is < (byte)'a' or > (byte)'z')
                continue;
            var start = i;
            while (i < tail.Length && tail[i] is >= (byte)'a' and <= (byte)'z')
                i++;
            var len = i - start;
            if (len is >= 3 and <= 16)
                return Encoding.ASCII.GetString(tail.Slice(start, len));
        }

        return null;
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || haystack.Length < needle.Length)
            return -1;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack[i..].StartsWith(needle))
                return i;
        }

        return -1;
    }
}
