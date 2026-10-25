using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PhotosViewer.Services;

/// <summary>Cache JPEG su disco per thumbs già decodificate (HEIC/video costosi).</summary>
internal static class ThumbDiskCache
{
    private static readonly string Root = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PhotosViewer", "thumbcache");

    public static ImageSource? TryLoad(string path, int decodeWidth)
    {
        try
        {
            var file = CachePath(path, decodeWidth);
            if (!File.Exists(file))
                return null;
            var bmp = new BitmapImage();
            bmp.BeginInit();
            bmp.UriSource = new Uri(file);
            bmp.CacheOption = BitmapCacheOption.OnLoad;
            bmp.CreateOptions = BitmapCreateOptions.IgnoreColorProfile;
            bmp.EndInit();
            bmp.Freeze();
            return bmp;
        }
        catch
        {
            return null;
        }
    }

    public static void TrySave(string path, int decodeWidth, BitmapSource src)
    {
        try
        {
            Directory.CreateDirectory(Root);
            var file = CachePath(path, decodeWidth);
            var enc = new JpegBitmapEncoder { QualityLevel = 82 };
            enc.Frames.Add(BitmapFrame.Create(src));
            using var fs = File.Create(file);
            enc.Save(fs);
        }
        catch
        {
            // ignore
        }
    }

    private static string CachePath(string path, int decodeWidth)
    {
        long ticks = 0;
        try { ticks = File.GetLastWriteTimeUtc(path).Ticks; } catch { /* ignore */ }
        var raw = $"{path}|{decodeWidth}|{ticks}";
        var hash = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(raw)));
        return Path.Combine(Root, hash + ".jpg");
    }
}
