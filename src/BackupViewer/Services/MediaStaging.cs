using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace BackupViewer.Services;

/// <summary>
/// Gli shard iTunes non hanno estensione: MediaElement/codec Windows ne hanno bisogno.
/// Copia (una volta) lo shard in temp con il nome originale.
/// </summary>
public static class MediaStaging
{
    private static readonly string Root = Path.Combine(
        Path.GetTempPath(), "BackupViewer", "media");

    public static string StageWithExtension(string shardPath, string relativePath)
    {
        Directory.CreateDirectory(Root);
        var ext = Path.GetExtension(relativePath);
        if (string.IsNullOrWhiteSpace(ext))
            ext = ".bin";

        var key = Convert.ToHexString(
            SHA1.HashData(Encoding.UTF8.GetBytes(shardPath + "|" + relativePath)))
            .ToLowerInvariant();
        var dest = Path.Combine(Root, key + ext);

        if (File.Exists(dest))
        {
            try
            {
                var srcInfo = new FileInfo(shardPath);
                var dstInfo = new FileInfo(dest);
                if (dstInfo.Length == srcInfo.Length
                    && dstInfo.LastWriteTimeUtc >= srcInfo.LastWriteTimeUtc)
                    return dest;
            }
            catch
            {
                // fall through to recopy
            }
        }

        File.Copy(shardPath, dest, overwrite: true);
        return dest;
    }
}
