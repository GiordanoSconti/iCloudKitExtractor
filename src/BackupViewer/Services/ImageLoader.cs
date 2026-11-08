using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Openize.Heic.Decoder;
using HeicPixelFormat = Openize.Heic.Decoder.PixelFormat;

namespace BackupViewer.Services;

public static class ImageLoader
{
    public static BitmapSource? Load(string path, int decodePixelWidth = 1600)
    {
        var ext = Path.GetExtension(path);
        if (ext.Equals(".heic", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".heif", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".hif", StringComparison.OrdinalIgnoreCase))
            return LoadHeic(path, decodePixelWidth);

        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var decoder = BitmapDecoder.Create(
            fs,
            BitmapCreateOptions.PreservePixelFormat,
            BitmapCacheOption.OnLoad);
        var frame = decoder.Frames[0];
        if (decodePixelWidth > 0 && frame.PixelWidth > decodePixelWidth)
        {
            var scale = (double)decodePixelWidth / frame.PixelWidth;
            var transformed = new TransformedBitmap(frame, new ScaleTransform(scale, scale));
            transformed.Freeze();
            return transformed;
        }

        frame.Freeze();
        return frame;
    }

    private static BitmapSource? LoadHeic(string path, int decodePixelWidth)
    {
        try
        {
            using var fs = File.OpenRead(path);
            if (!HeicImage.CanLoad(fs))
                return null;
            fs.Position = 0;
            var heic = HeicImage.Load(fs);
            if (heic.Frames.Count == 0)
                return null;

            var frame = heic.Frames.Values.First();
            var width = (int)frame.Width;
            var height = (int)frame.Height;
            if (width <= 0 || height <= 0)
                return null;

            var pixels = frame.GetByteArray(HeicPixelFormat.Bgra32);
            if (pixels is null || pixels.Length < width * height * 4)
                return null;

            var wb = new WriteableBitmap(width, height, 96, 96, PixelFormats.Bgra32, null);
            wb.WritePixels(new Int32Rect(0, 0, width, height), pixels, width * 4, 0);
            wb.Freeze();

            if (decodePixelWidth > 0 && width > decodePixelWidth)
            {
                var scale = (double)decodePixelWidth / width;
                var scaled = new TransformedBitmap(wb, new ScaleTransform(scale, scale));
                scaled.Freeze();
                return scaled;
            }

            return wb;
        }
        catch
        {
            return null;
        }
    }
}
