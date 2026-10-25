namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Estrae <c>Asset.protectionInfo.protectionInfo</c> (AES-KW) dal wire CloudKit.
/// Preferisce il parse strutturale (<see cref="CloudKitAssetProto"/>):
/// signature <c>f2</c> + wrap <c>f15.f1</c> dallo stesso messaggio Asset.
/// </summary>
public static class MmcsAssetProtection
{
    /// <summary>
    /// Preferisce wrap 40 B (<c>7a 2a 0a 28</c> / <c>0a 28</c>), poi 24 B
    /// (<c>7a 1a 0a 18</c> / <c>0a 18</c>) subito dopo <c>contents</c> / <c>fileContent</c>.
    /// </summary>
    public static byte[]? TryExtract(ReadOnlySpan<byte> window)
    {
        // Se c'è un solo Asset parsabile, usa il suo wrap (stesso messaggio).
        var assets = CloudKitAssetProto.EnumerateAssets(window);
        if (assets.Count == 1 && assets[0].ProtectionWrap is { Length: 24 or 40 } only)
            return only;

        return TryExtractCore(window);
    }

    /// <summary>
    /// Wrap legato alla <paramref name="assetSignature"/> via parse Asset .
    /// Fallback euristico solo se il proto non è riconoscibile ma la signature è nel blob.
    /// </summary>
    public static byte[]? TryExtractForSignature(
        ReadOnlySpan<byte> window,
        ReadOnlySpan<byte> assetSignature)
    {
        if (window.IsEmpty || assetSignature.Length < 4)
            return TryExtractCore(window);

        var structured = CloudKitAssetProto.TryGetWrapForSignature(window, assetSignature);
        if (structured is { Length: 24 or 40 })
            return structured;

        // Fallback: signature presente ma messaggio Asset non parseable → regione locale.
        var sigIdx = IndexOf(window, assetSignature);
        if (sigIdx < 0)
            return null;

        var fromSig = window[sigIdx..];
        var wrap = TryExtractCore(fromSig);
        if (wrap is not null)
            return wrap;

        var start = Math.Max(0, sigIdx - 96);
        var len = Math.Min(window.Length - start, 768);
        return TryExtractCore(window.Slice(start, len));
    }

    /// <summary>
    /// True se <paramref name="window"/> contiene la signature asset (binding wrap↔MMCS object).
    /// </summary>
    public static bool WindowContainsSignature(
        ReadOnlySpan<byte> window,
        ReadOnlySpan<byte> assetSignature)
        => assetSignature.Length >= 4 && IndexOf(window, assetSignature) >= 0;

    /// <summary>True se <paramref name="wrap"/> è una lunghezza AES-KW valida (24 o 40 B).</summary>
    public static bool IsValidWrapLength(int length) => length is 24 or 40;

    private static byte[]? TryExtractCore(ReadOnlySpan<byte> window)
    {
        if (window.IsEmpty)
            return null;

        var fc = IndexOf(window, "fileContent"u8);
        if (fc < 0)
            fc = IndexOf(window, "contents"u8);
        var searchFrom = fc >= 0 ? fc : 0;

        // Backup: ProtectionInfo f15 len=42 → f1 len=40.
        for (var i = searchFrom; i <= window.Length - 44; i++)
        {
            if (window[i] == 0x7a && window[i + 1] == 0x2a &&
                window[i + 2] == 0x0a && window[i + 3] == 0x28)
                return window.Slice(i + 4, 40).ToArray();
        }

        for (var i = searchFrom; i <= window.Length - 42; i++)
        {
            if (window[i] != 0x0a || window[i + 1] != 0x28)
                continue;
            var wrap = window.Slice(i + 2, 40);
            if (LooksBinary(wrap, maxPrintableRatio: 0.55))
                return wrap.ToArray();
        }

        // CloudDocs / legacy: wrap 24 B.
        for (var i = searchFrom; i <= window.Length - 28; i++)
        {
            if (window[i] == 0x7a && window[i + 1] == 0x1a &&
                window[i + 2] == 0x0a && window[i + 3] == 0x18)
                return window.Slice(i + 4, 24).ToArray();
        }

        for (var i = searchFrom; i <= window.Length - 26; i++)
        {
            if (window[i] != 0x0a || window[i + 1] != 0x18)
                continue;
            var wrap = window.Slice(i + 2, 24);
            if (LooksBinary(wrap, maxPrintableRatio: 0.75))
                return wrap.ToArray();
        }

        return null;
    }

    private static bool LooksBinary(ReadOnlySpan<byte> wrap, double maxPrintableRatio)
    {
        var printable = 0;
        foreach (var b in wrap)
        {
            if (b is >= 32 and < 127)
                printable++;
        }

        return printable <= (int)(wrap.Length * maxPrintableRatio);
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || haystack.Length < needle.Length)
            return -1;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.Slice(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }
}
