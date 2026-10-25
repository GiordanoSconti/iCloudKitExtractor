using System.IO;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Copia il visualizzatore WPF portatile in <c>photos/Viewer/</c>
/// alla fine di download/decrypt/organize.
/// </summary>
public static class PhotosViewerPublisher
{
    public const string ViewerFolderName = "Viewer";

    public static void Publish(string photosDir, IProgress<string>? log = null)
    {
        if (string.IsNullOrWhiteSpace(photosDir) || !Directory.Exists(photosDir))
            return;

        var payload = ResolvePayloadDirectory();
        if (payload is null)
        {
            log?.Report("  Viewer: payload non trovato (compila PhotosViewer)");
            return;
        }

        var dest = Path.Combine(photosDir, ViewerFolderName);
        try
        {
            Directory.CreateDirectory(dest);
            var copied = 0;
            foreach (var file in Directory.EnumerateFiles(payload, "*", SearchOption.AllDirectories))
            {
                if (file.EndsWith(".pdb", StringComparison.OrdinalIgnoreCase))
                    continue;

                var rel = Path.GetRelativePath(payload, file);
                var target = Path.Combine(dest, rel);
                Directory.CreateDirectory(Path.GetDirectoryName(target)!);
                File.Copy(file, target, overwrite: true);
                copied++;
            }

            var launcher = Path.Combine(photosDir, "Apri Libreria.cmd");
            File.WriteAllText(launcher,
                """
                @echo off
                start "" "%~dp0Viewer\PhotosViewer.exe" "%~dp0"
                """);

            log?.Report($"  Viewer → {dest} ({copied} file)");
        }
        catch (Exception ex)
        {
            log?.Report($"  Viewer: copia fallita ({ex.Message})");
        }
    }

    public static string? ResolvePayloadDirectory()
    {
        foreach (var candidate in CandidatePayloadDirs())
        {
            var exe = Path.Combine(candidate, "PhotosViewer.exe");
            if (File.Exists(exe))
                return candidate;
        }

        return null;
    }

    private static IEnumerable<string> CandidatePayloadDirs()
    {
        var baseDir = AppContext.BaseDirectory;
        yield return Path.Combine(baseDir, "viewer-payload");

        // IKE bin → src/PhotosViewer/bin/{Config}/net10.0-windows
        var dir = new DirectoryInfo(baseDir);
        for (var i = 0; i < 8 && dir is not null; i++, dir = dir.Parent)
        {
            foreach (var cfg in new[] { "Release", "Debug" })
            {
                yield return Path.Combine(dir.FullName, "PhotosViewer", "bin", cfg, "net10.0-windows");
                yield return Path.Combine(dir.FullName, "src", "PhotosViewer", "bin", cfg, "net10.0-windows");
            }
        }
    }
}
