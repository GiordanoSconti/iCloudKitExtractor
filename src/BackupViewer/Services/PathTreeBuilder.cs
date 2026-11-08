using System.Collections.ObjectModel;
using BackupViewer.Models;

namespace BackupViewer.Services;

public static class PathTreeBuilder
{
    /// <summary>
    /// Albero path sotto un singolo domain (App/Domain): segmenti di RelativePath.
    /// </summary>
    public static ObservableCollection<PathNode> BuildForDomain(
        IEnumerable<BackupFileEntry> files,
        string? search = null)
    {
        var root = new PathNode { Name = "/", IsDirectory = true, RelativePath = "" };
        foreach (var file in files.Where(static f => !f.IsDirectory))
        {
            if (!MatchesSearch(file, search))
                continue;
            InsertPath(root, file.RelativePath, file);
        }

        SortRecursive(root);
        return root.Children;
    }

    /// <summary>
    /// FileSystem completo: Domain → RelativePath.
    /// </summary>
    public static ObservableCollection<PathNode> BuildFileSystem(
        IEnumerable<BackupFileEntry> files,
        string? search = null)
    {
        var root = new PathNode { Name = "FileSystem", IsDirectory = true, RelativePath = "" };
        foreach (var file in files.Where(static f => !f.IsDirectory))
        {
            if (!MatchesSearch(file, search))
                continue;

            var domainName = string.IsNullOrWhiteSpace(file.Domain) ? "(senza domain)" : file.Domain;
            var domainNode = GetOrCreateChild(root, domainName, domainName, isDirectory: true);
            var virtualPath = string.IsNullOrWhiteSpace(file.RelativePath)
                ? file.DisplayName
                : file.RelativePath;
            InsertPath(domainNode, virtualPath, file);
        }

        SortRecursive(root);
        return root.Children;
    }

    /// <summary>Albero piatto per categorie: solo elenco file (foglie sotto root virtuale).</summary>
    public static ObservableCollection<PathNode> BuildFlatFiles(
        IEnumerable<BackupFileEntry> files,
        string? search = null)
    {
        var list = new ObservableCollection<PathNode>();
        foreach (var file in files.Where(static f => !f.IsDirectory)
                     .Where(f => MatchesSearch(f, search))
                     .OrderBy(static f => f.DisplayName, NameComparer)
                     .ThenBy(static f => f.RelativePath, NameComparer))
        {
            list.Add(new PathNode
            {
                Name = file.DisplayName,
                RelativePath = file.RelativePath,
                IsDirectory = false,
                File = file,
            });
        }

        return list;
    }

    private static bool MatchesSearch(BackupFileEntry file, string? search)
    {
        if (string.IsNullOrWhiteSpace(search))
            return true;
        var q = search.Trim();
        return file.RelativePath.Contains(q, StringComparison.OrdinalIgnoreCase)
               || file.Domain.Contains(q, StringComparison.OrdinalIgnoreCase)
               || file.FileId.Contains(q, StringComparison.OrdinalIgnoreCase)
               || file.DisplayName.Contains(q, StringComparison.OrdinalIgnoreCase);
    }

    private static void InsertPath(PathNode root, string relativePath, BackupFileEntry file)
    {
        var norm = (relativePath ?? "").Replace('\\', '/').Trim('/');
        if (string.IsNullOrEmpty(norm))
        {
            root.Children.Add(new PathNode
            {
                Name = file.DisplayName,
                RelativePath = file.RelativePath,
                IsDirectory = false,
                File = file,
            });
            return;
        }

        var parts = norm.Split('/', StringSplitOptions.RemoveEmptyEntries);
        var current = root;
        var prefix = root.RelativePath;
        for (var i = 0; i < parts.Length; i++)
        {
            var part = parts[i];
            var isLast = i == parts.Length - 1;
            prefix = string.IsNullOrEmpty(prefix) ? part : prefix + "/" + part;
            if (isLast)
            {
                current.Children.Add(new PathNode
                {
                    Name = part,
                    RelativePath = prefix,
                    IsDirectory = false,
                    File = file,
                });
            }
            else
            {
                current = GetOrCreateChild(current, part, prefix, isDirectory: true);
            }
        }
    }

    private static PathNode GetOrCreateChild(
        PathNode parent,
        string name,
        string relativePath,
        bool isDirectory)
    {
        foreach (var child in parent.Children)
        {
            if (child.IsDirectory == isDirectory
                && string.Equals(child.Name, name, StringComparison.OrdinalIgnoreCase))
                return child;
        }

        var node = new PathNode
        {
            Name = name,
            RelativePath = relativePath,
            IsDirectory = isDirectory,
        };
        parent.Children.Add(node);
        return node;
    }

    private static readonly StringComparer NameComparer =
        StringComparer.Create(System.Globalization.CultureInfo.CurrentCulture, ignoreCase: true);

    private static void SortRecursive(PathNode node)
    {
        var ordered = node.Children
            .OrderByDescending(static c => c.IsDirectory) // cartelle prima dei file
            .ThenBy(static c => c.Name, NameComparer)
            .ThenBy(static c => c.RelativePath, NameComparer)
            .ToList();
        node.Children.Clear();
        foreach (var c in ordered)
        {
            if (c.IsDirectory)
                SortRecursive(c);
            node.Children.Add(c);
        }
    }
}
