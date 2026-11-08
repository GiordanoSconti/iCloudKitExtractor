using System.Collections.ObjectModel;

namespace BackupViewer.Models;

/// <summary>Nodo della struttura cartelle/file ricostruita dal RelativePath.</summary>
public sealed class PathNode
{
    public required string Name { get; init; }
    public string RelativePath { get; init; } = "";
    public bool IsDirectory { get; init; }
    public BackupFileEntry? File { get; init; }
    public ObservableCollection<PathNode> Children { get; } = [];

    public string Caption =>
        IsDirectory
            ? (Children.Count > 0 ? $"{Name} ({CountFiles():N0})" : Name)
            : Name;

    public int CountFiles()
    {
        if (!IsDirectory)
            return File is null ? 0 : 1;
        var n = 0;
        foreach (var c in Children)
            n += c.CountFiles();
        return n;
    }
}
