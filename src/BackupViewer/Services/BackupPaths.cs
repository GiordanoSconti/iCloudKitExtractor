using System.IO;

namespace BackupViewer.Services;

public static class BackupPaths
{
    public static string? ResolveBackupRoot(string path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return null;

        path = Path.GetFullPath(path.Trim().Trim('"'));
        if (File.Exists(path) && path.EndsWith("Manifest.db", StringComparison.OrdinalIgnoreCase))
            return Path.GetDirectoryName(path);

        if (!Directory.Exists(path))
            return null;

        if (File.Exists(Path.Combine(path, "Manifest.db")))
            return path;

        var nested = Path.Combine(path, "Backup");
        if (File.Exists(Path.Combine(nested, "Manifest.db")))
            return nested;

        return null;
    }

    public static string ToShardPath(string backupRoot, string fileId)
    {
        if (fileId.Length < 2)
            return Path.Combine(backupRoot, fileId);
        return Path.Combine(backupRoot, fileId[..2], fileId);
    }

    public static string? TryFindFromArgsOrCwd()
    {
        var args = Environment.GetCommandLineArgs();
        for (var i = 1; i < args.Length; i++)
        {
            var root = ResolveBackupRoot(args[i]);
            if (root is not null)
                return root;
        }

        return ResolveBackupRoot(Environment.CurrentDirectory);
    }
}
