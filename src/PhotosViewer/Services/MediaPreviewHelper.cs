using System.IO;
using PhotosViewer.Models;

namespace PhotosViewer.Services;

public static class MediaPreviewHelper
{
    private static readonly string[] VideoExt = [".mov", ".mp4", ".m4v", ".avi", ".hevc"];

    public static bool HasInlineVideoPreview(MediaItem item)
    {
        if (item.IsVideo)
            return File.Exists(item.AbsolutePath);
        return item.IsLive && GetInlineVideoPath(item) is not null;
    }

    public static string? GetInlineVideoPath(MediaItem item)
    {
        if (item.IsVideo && File.Exists(item.AbsolutePath))
            return item.AbsolutePath;

        if (!item.IsLive && !IsMovPath(item.AbsolutePath))
            return null;

        if (IsMovPath(item.AbsolutePath) && File.Exists(item.AbsolutePath))
            return item.AbsolutePath;

        return FindLiveCompanionMov(item);
    }

    public static bool IsMovPath(string path) =>
        string.Equals(Path.GetExtension(path), ".mov", StringComparison.OrdinalIgnoreCase);

    private static string? FindLiveCompanionMov(MediaItem item)
    {
        var dir = Path.GetDirectoryName(item.AbsolutePath);
        if (string.IsNullOrEmpty(dir))
            return null;

        var baseName = Path.GetFileNameWithoutExtension(item.AbsolutePath);
        foreach (var ext in VideoExt)
        {
            var candidate = Path.Combine(dir, baseName + ext);
            if (File.Exists(candidate))
                return candidate;
        }

        return null;
    }
}
