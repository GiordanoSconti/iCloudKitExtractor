using System.IO;
using LzfseSharp;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Decompressione Apple LZFSE/LZVN (<c>bvx-</c>/<c>bvx1</c>/<c>bvx2</c>/<c>bvxn</c>).
/// Dopo MMCS AES-CFB i blob <c>Domain.fileList</c> (encoding=2) sono ancora compressi così.
/// </summary>
public static class LzfseDecompressor
{
    /// <summary>
    /// Se <paramref name="data"/> inizia con magic <c>bvx</c>, decompressa; altrimenti restituisce l'input.
    /// </summary>
    public static byte[] ExpandIfNeeded(ReadOnlySpan<byte> data)
    {
        if (!IsLzfseMagic(data))
            return data.ToArray();

        using var src = new MemoryStream(data.ToArray(), writable: false);
        using var dst = new MemoryStream(Math.Max(data.Length * 4, 4096));
        LzfseDecoder.Decompress(src, dst);
        return dst.ToArray();
    }

    /// <summary>Tenta decompressione; fallisce senza eccezione se non è LZFSE o il decode fallisce.</summary>
    public static bool TryExpand(ReadOnlySpan<byte> data, out byte[] expanded)
    {
        expanded = [];
        if (!IsLzfseMagic(data))
            return false;

        try
        {
            expanded = ExpandIfNeeded(data);
            return expanded.Length > 0 && !IsLzfseMagic(expanded);
        }
        catch
        {
            expanded = [];
            return false;
        }
    }

    public static bool IsLzfseMagic(ReadOnlySpan<byte> data) =>
        data.Length >= 4
        && data[0] == (byte)'b'
        && data[1] == (byte)'v'
        && data[2] == (byte)'x';
}
