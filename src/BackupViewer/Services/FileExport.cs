using System.IO;
using System.Windows;
using BackupViewer.Models;
using Microsoft.Win32;

namespace BackupViewer.Services;

public static class FileExport
{
    public static bool TrySaveShard(
        string? shardPath,
        string preferredFileName,
        out string? savedPath,
        Window? owner = null)
    {
        savedPath = null;
        if (string.IsNullOrWhiteSpace(shardPath) || !File.Exists(shardPath))
            return false;

        var name = SanitizeFileName(
            string.IsNullOrWhiteSpace(preferredFileName)
                ? Path.GetFileName(shardPath)
                : preferredFileName);
        if (string.IsNullOrWhiteSpace(Path.GetExtension(name)))
            name += GuessExtension(preferredFileName) ?? ".bin";

        var dlg = new SaveFileDialog
        {
            Title = "Salva file",
            FileName = name,
            Filter = "Tutti i file (*.*)|*.*",
            OverwritePrompt = true,
            AddExtension = true,
        };

        var ok = owner is null ? dlg.ShowDialog() == true : dlg.ShowDialog(owner) == true;
        if (!ok || string.IsNullOrWhiteSpace(dlg.FileName))
            return false;

        var dir = Path.GetDirectoryName(dlg.FileName);
        if (!string.IsNullOrWhiteSpace(dir))
            Directory.CreateDirectory(dir);
        File.Copy(shardPath, dlg.FileName, overwrite: true);
        savedPath = dlg.FileName;
        return true;
    }

    public static bool TrySaveEntry(BackupFileEntry entry, out string? savedPath, Window? owner = null)
    {
        savedPath = null;
        if (entry.IsDirectory || string.IsNullOrWhiteSpace(entry.AbsolutePath) || !entry.ExistsOnDisk)
            return false;
        return TrySaveShard(entry.AbsolutePath, entry.DisplayName, out savedPath, owner);
    }

    public static bool TrySaveStagedOrShard(
        string? stagedPath,
        string? shardPath,
        string preferredFileName,
        out string? savedPath,
        Window? owner = null)
    {
        var src = !string.IsNullOrWhiteSpace(stagedPath) && File.Exists(stagedPath)
            ? stagedPath
            : shardPath;
        return TrySaveShard(src, preferredFileName, out savedPath, owner);
    }

    private static string SanitizeFileName(string name)
    {
        foreach (var c in Path.GetInvalidFileNameChars())
            name = name.Replace(c, '_');
        return name.Trim();
    }

    private static string? GuessExtension(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;
        var ext = Path.GetExtension(path.Replace('\\', '/'));
        return string.IsNullOrWhiteSpace(ext) ? null : ext;
    }
}
