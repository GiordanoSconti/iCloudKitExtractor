using System.Diagnostics;
using System.IO;

namespace PhotosViewer.Services;

public static class MediaFileOpener
{
    public static bool TryOpen(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return false;

        try
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
            return true;
        }
        catch
        {
            return false;
        }
    }
}
