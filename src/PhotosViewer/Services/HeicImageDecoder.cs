using System.IO;
using System.Windows;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using Openize.Heic.Decoder;
using Openize.IsoBmff;
using HeicPixelFormat = Openize.Heic.Decoder.PixelFormat;

namespace PhotosViewer.Services;

/// <summary>
/// Decodifica HEIC/HEIF in-process via Openize.Heic (ISO/IEC 23008-12, open source).
/// Preferisce il frame thumbnail incorporato quando presente.
/// </summary>
public static class HeicImageDecoder
{
    public static bool IsHeicPath(string path)
    {
        var ext = Path.GetExtension(path);
        return ext.Equals(".heic", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".heif", StringComparison.OrdinalIgnoreCase)
               || ext.Equals(".hif", StringComparison.OrdinalIgnoreCase);
    }

    public static ImageSource? TryDecode(byte[] bytes, int decodeWidth)
    {
        if (bytes.Length < 12)
            return null;

        try
        {
            using var ms = new MemoryStream(bytes, writable: false);
            if (!HeicImage.CanLoad(ms))
                return null;
            ms.Position = 0;

            var heic = HeicImage.Load(ms);
            var frame = ChooseFrame(heic, decodeWidth);
            if (frame is null)
                return null;

            var width = (int)frame.Width;
            var height = (int)frame.Height;
            if (width <= 0 || height <= 0)
                return null;

            var pixels = frame.GetByteArray(HeicPixelFormat.Bgra32);
            if (pixels is null || pixels.Length < width * height * 4)
                return null;

            var targetW = Math.Clamp(decodeWidth, 48, 2048);
            byte[] outPixels;
            int outW, outH;
            if (width <= targetW)
            {
                outPixels = pixels;
                outW = width;
                outH = height;
            }
            else
            {
                outW = targetW;
                outH = Math.Max(1, (int)Math.Round(height * ((double)targetW / width)));
                outPixels = DownsampleBgra32(pixels, width, height, outW, outH);
            }

            var bmp = new WriteableBitmap(outW, outH, 96, 96, PixelFormats.Bgra32, null);
            bmp.WritePixels(new Int32Rect(0, 0, outW, outH), outPixels, 4 * outW, 0);
            bmp.Freeze();
            return bmp;
        }
        catch
        {
            return null;
        }
    }

    private static HeicImageFrame? ChooseFrame(HeicImage heic, int decodeWidth)
    {
        // Thumbnail incorporato (BoxType.thmb): tipicamente ~300px, ~100ms vs secondi full-res.
        try
        {
            var thumbs = heic.AllFrames.Values
                .Where(static f => f.DerivativeType == BoxType.thmb && f.Width >= 64 && f.Height >= 64)
                .OrderByDescending(static f => f.Width)
                .ToList();
            if (thumbs.Count > 0)
            {
                var thmb = thumbs[0];
                // Griglia/mappa (≤512): solo thmb. Full frame solo per anteprime grandi.
                if (decodeWidth <= 512)
                    return thmb;
                if (decodeWidth <= (int)thmb.Width * 2 || decodeWidth <= 640)
                    return thmb;
            }
        }
        catch
        {
            // fallback
        }

        return heic.DefaultFrame;
    }

    private static byte[] DownsampleBgra32(byte[] src, int sw, int sh, int dw, int dh)
    {
        var dest = new byte[dw * dh * 4];
        for (var y = 0; y < dh; y++)
        {
            var sy = Math.Min(sh - 1, (int)((y + 0.5) * sh / dh));
            for (var x = 0; x < dw; x++)
            {
                var sx = Math.Min(sw - 1, (int)((x + 0.5) * sw / dw));
                var si = (sy * sw + sx) * 4;
                var di = (y * dw + x) * 4;
                dest[di] = src[si];
                dest[di + 1] = src[si + 1];
                dest[di + 2] = src[si + 2];
                dest[di + 3] = src[si + 3];
            }
        }

        return dest;
    }
}
