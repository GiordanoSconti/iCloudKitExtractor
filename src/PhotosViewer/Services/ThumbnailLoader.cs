using System.Collections.Concurrent;
using System.Diagnostics;
using System.IO;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PhotosViewer.Services;

/// <summary>Decode thumbnail async: cache memoria + disco, Shell per video, decode JPEG lazy.</summary>
public static class ThumbnailLoader
{
    private static readonly string[] VideoExt = [".mov", ".mp4", ".m4v", ".avi", ".hevc"];
    private static readonly ConcurrentDictionary<string, ImageSource> Cache = new(StringComparer.OrdinalIgnoreCase);
    private static readonly ConcurrentDictionary<string, bool> HeicThumbProbe = new(StringComparer.OrdinalIgnoreCase);
    private static readonly object LruGate = new();
    private static readonly LinkedList<string> Lru = new();
    private const int MaxCache = 384;
    private const int HeicThumbProbeMaxBytes = 256 * 1024;

    public static bool IsVideoPath(string path)
    {
        var ext = Path.GetExtension(path);
        return VideoExt.Contains(ext, StringComparer.OrdinalIgnoreCase);
    }

    public static async Task<ImageSource?> LoadAsync(string path, int decodeWidth, CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        decodeWidth = Math.Clamp(decodeWidth, 48, 720);
        var key = CacheKey(path, decodeWidth);
        if (Cache.TryGetValue(key, out var hit))
        {
            Touch(key);
            return hit;
        }

        ct.ThrowIfCancellationRequested();
        var sw = Stopwatch.StartNew();
        var ext = Path.GetExtension(path);
        long fileBytes = 0;
        try { fileBytes = new FileInfo(path).Length; } catch { /* ignore */ }

        try
        {
            var disk = await Task.Run(() => ThumbDiskCache.TryLoad(path, decodeWidth), ct).ConfigureAwait(false);
            if (disk is not null)
            {
                Put(key, disk);
                return disk;
            }

            ImageSource? bmp;
            string method;
            if (IsVideoPath(path))
            {
                bmp = await Task.Run(() => ShellThumbnail.TryGet(path, decodeWidth), ct).ConfigureAwait(false);
                method = "shell-video";
            }
            else if (HeicImageDecoder.IsHeicPath(path))
            {
                bmp = await LoadHeicThumbAsync(path, decodeWidth, ct).ConfigureAwait(false);
                method = bmp is null ? "heic-none" : HeicThumbProbe.GetValueOrDefault(path, false) ? "openize-thmb" : "shell-no-thmb";
            }
            else
            {
                bmp = await Task.Run(() => DecodeRasterFast(path, decodeWidth), ct).ConfigureAwait(false);
                method = "bitmap-decode";
                bmp ??= await Task.Run(() => ShellThumbnail.TryGet(path, decodeWidth), ct).ConfigureAwait(false);
                if (bmp is not null && method == "bitmap-decode")
                    method = "shell-fallback";
            }

            if (bmp is not null)
            {
                Put(key, bmp);
                if (bmp is BitmapSource bs)
                    await Task.Run(() => ThumbDiskCache.TrySave(path, decodeWidth, bs), ct).ConfigureAwait(false);
            }


            return bmp;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// HEIC iPhone: thmb incorporato → Openize (~100ms).
    /// HEIC Meta AI (fullPicture, senza thmb): Shell (~100–450ms), non full-frame Openize (~2.5s).
    /// </summary>
    private static async Task<ImageSource?> LoadHeicThumbAsync(string path, int decodeWidth, CancellationToken ct)
    {
        var hasThmb = await Task.Run(() => HasEmbeddedHeicThumb(path), ct).ConfigureAwait(false);
        HeicThumbProbe[path] = hasThmb;

        if (hasThmb)
        {
            var openize = await DecodeHeicAsync(path, decodeWidth, ct).ConfigureAwait(false);
            if (openize is not null)
                return openize;
        }

        var shell = await Task.Run(() => ShellThumbnail.TryGet(path, decodeWidth), ct).ConfigureAwait(false);
        if (shell is not null)
            return shell;

        // Ultimo tentativo: Openize full-frame (lento).
        return await DecodeHeicAsync(path, decodeWidth, ct).ConfigureAwait(false);
    }

    private static bool HasEmbeddedHeicThumb(string path)
    {
        if (HeicThumbProbe.TryGetValue(path, out var cached))
            return cached;

        try
        {
            var info = new FileInfo(path);
            if (!info.Exists)
                return false;

            var len = (int)Math.Min(info.Length, HeicThumbProbeMaxBytes);
            if (len < 12)
                return false;

            var buf = new byte[len];
            using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Read(buf, 0, len) < 12)
                return false;

            for (var i = 0; i <= buf.Length - 4; i++)
            {
                if (buf[i] == (byte)'t' && buf[i + 1] == (byte)'h' && buf[i + 2] == (byte)'m' && buf[i + 3] == (byte)'b')
                    return true;
            }

            return false;
        }
        catch
        {
            return false;
        }
    }

    private static async Task<ImageSource?> DecodeHeicAsync(string path, int decodeWidth, CancellationToken ct)
    {
        byte[] bytes;
        await using (var fs = new FileStream(
                         path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite,
                         bufferSize: 128 * 1024,
                         options: FileOptions.Asynchronous | FileOptions.SequentialScan))
        {
            await using var ms = new MemoryStream((int)Math.Min(fs.Length, int.MaxValue));
            await fs.CopyToAsync(ms, ct).ConfigureAwait(false);
            bytes = ms.ToArray();
        }

        ct.ThrowIfCancellationRequested();
        return await Task.Run(() => HeicImageDecoder.TryDecode(bytes, decodeWidth), ct).ConfigureAwait(false);
    }

    private static ImageSource? DecodeRasterFast(string path, int decodeWidth)
    {
        try
        {
            var image = new BitmapImage();
            image.BeginInit();
            image.UriSource = new Uri(path);
            image.DecodePixelWidth = decodeWidth;
            image.CacheOption = BitmapCacheOption.OnLoad;
            image.CreateOptions = BitmapCreateOptions.IgnoreColorProfile;
            image.EndInit();
            image.Freeze();
            return image;
        }
        catch
        {
            return null;
        }
    }

    private static string CacheKey(string path, int w) => path + "|" + w;

    private static void Put(string key, ImageSource src)
    {
        Cache[key] = src;
        Touch(key);
        Trim();
    }

    private static void Touch(string key)
    {
        lock (LruGate)
        {
            Lru.Remove(key);
            Lru.AddFirst(key);
        }
    }

    private static void Trim()
    {
        lock (LruGate)
        {
            while (Lru.Count > MaxCache)
            {
                var last = Lru.Last!.Value;
                Lru.RemoveLast();
                Cache.TryRemove(last, out _);
            }
        }
    }
}
