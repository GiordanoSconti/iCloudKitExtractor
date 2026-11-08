using System.IO;
using BackupViewer.Models;
using Microsoft.Data.Sqlite;

namespace BackupViewer.Services;

public sealed class BackupCatalog
{
    public required string BackupRoot { get; init; }
    public IReadOnlyList<BackupFileEntry> Files { get; init; } = [];
    public IReadOnlyList<NavNode> Navigation { get; init; } = [];
    public int FileCount { get; init; }
    public int PresentCount { get; init; }
    public int MissingCount { get; init; }

    public static BackupCatalog Load(string backupRoot)
    {
        SQLitePCL.Batteries_V2.Init();
        var manifest = Path.Combine(backupRoot, "Manifest.db");
        if (!File.Exists(manifest))
            throw new FileNotFoundException("Manifest.db non trovato.", manifest);

        var entries = new List<BackupFileEntry>(65_536);
        var cs = new SqliteConnectionStringBuilder
        {
            DataSource = manifest,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString();

        using var con = new SqliteConnection(cs);
        con.Open();
        using var cmd = con.CreateCommand();
        cmd.CommandText =
            """
            SELECT fileID, domain, relativePath, flags
            FROM Files
            ORDER BY domain, relativePath;
            """;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var fileId = r.IsDBNull(0) ? "" : r.GetString(0);
            var domain = r.IsDBNull(1) ? "" : r.GetString(1);
            var rel = r.IsDBNull(2) ? "" : r.GetString(2);
            var flags = r.IsDBNull(3) ? 0 : r.GetInt32(3);
            if (string.IsNullOrWhiteSpace(fileId))
                continue;

            string? abs = null;
            long size = 0;
            var exists = false;
            if (flags != 2)
            {
                abs = BackupPaths.ToShardPath(backupRoot, fileId);
                try
                {
                    var fi = new FileInfo(abs);
                    exists = fi.Exists;
                    size = exists ? fi.Length : 0;
                }
                catch
                {
                    exists = false;
                }
            }

            var entry = new BackupFileEntry
            {
                FileId = fileId,
                Domain = domain,
                RelativePath = rel.Replace('\\', '/'),
                Flags = flags,
                AbsolutePath = abs,
                SizeBytes = size,
                ExistsOnDisk = exists,
            };
            FileKindDetector.Classify(entry);
            entries.Add(entry);
        }

        var present = entries.Count(static e => !e.IsDirectory && e.ExistsOnDisk);
        var missing = entries.Count(static e => !e.IsDirectory && !e.ExistsOnDisk);
        var nav = BuildNavigation(entries);
        return new BackupCatalog
        {
            BackupRoot = backupRoot,
            Files = entries,
            Navigation = nav,
            FileCount = entries.Count(static e => !e.IsDirectory),
            PresentCount = present,
            MissingCount = missing,
        };
    }

    public IReadOnlyList<BackupFileEntry> Filter(NavNode? node)
    {
        if (node is null || node.FilterKind == NavFilterKind.All)
            return Files.Where(static e => !e.IsDirectory).ToList();

        return node.FilterKind switch
        {
            NavFilterKind.Category => Files
                .Where(e => !e.IsDirectory && e.CategoryKey == node.FilterKey)
                .ToList(),
            NavFilterKind.Domain => Files
                .Where(e => !e.IsDirectory && e.Domain == node.FilterKey)
                .ToList(),
            NavFilterKind.App => Files
                .Where(e => !e.IsDirectory && e.Domain == node.FilterKey)
                .ToList(),
            NavFilterKind.FileSystem => Files
                .Where(static e => !e.IsDirectory)
                .ToList(),
            _ => Files.Where(static e => !e.IsDirectory).ToList(),
        };
    }

    public bool UsesPathTree(NavNode node) =>
        node.FilterKind is NavFilterKind.App
            or NavFilterKind.Domain
            or NavFilterKind.FileSystem;

    private static List<NavNode> BuildNavigation(IReadOnlyList<BackupFileEntry> files)
    {
        var content = files.Where(static e => !e.IsDirectory).ToList();
        var root = new List<NavNode>();

        var all = new NavNode
        {
            Title = "Tutti i file",
            FilterKind = NavFilterKind.All,
            Count = content.Count,
        };
        root.Add(all);

        root.Add(new NavNode
        {
            Title = "FileSystem",
            FilterKind = NavFilterKind.FileSystem,
            Count = content.Count,
        });

        var personal = new NavNode { Title = "Dati personali", FilterKind = NavFilterKind.All };
        personal.Children.Add(new NavNode { Title = "Chat", FilterKind = NavFilterKind.CoreChat });
        personal.Children.Add(new NavNode { Title = "Chiamate", FilterKind = NavFilterKind.CoreCalls });
        personal.Children.Add(new NavNode { Title = "Calendario", FilterKind = NavFilterKind.CoreCalendar });
        personal.Children.Add(new NavNode { Title = "Contatti", FilterKind = NavFilterKind.CoreContacts });
        root.Add(personal);

        var categories = new NavNode { Title = "Categorie", FilterKind = NavFilterKind.All };
        AddCategory(categories, content, "media", "Media");
        AddCategory(categories, content, "databases", "Database SQLite");
        AddCategory(categories, content, "plist", "Plist");
        AddCategory(categories, content, "structured", "JSON / XML");
        AddCategory(categories, content, "protobuf", "Protobuf");
        AddCategory(categories, content, "text", "Testo");
        AddCategory(categories, content, "binary", "Binari");
        AddCategory(categories, content, "missing", "Assenti su disco");
        AddCategory(categories, content, "empty", "Vuoti");
        root.Add(categories);

        var apps = new NavNode { Title = "App", FilterKind = NavFilterKind.All };
        foreach (var g in content
                     .Where(static e => e.Domain.StartsWith("AppDomain", StringComparison.Ordinal))
                     .GroupBy(static e => e.Domain, StringComparer.Ordinal)
                     .OrderBy(static g => FriendlyAppName(g.Key), StringComparer.CurrentCultureIgnoreCase))
        {
            apps.Children.Add(new NavNode
            {
                Title = FriendlyAppName(g.Key),
                FilterKey = g.Key,
                FilterKind = NavFilterKind.App,
                Count = g.Count(),
            });
        }

        if (apps.Children.Count > 0)
            root.Add(apps);

        var domains = new NavNode { Title = "Domain", FilterKind = NavFilterKind.All };
        foreach (var g in content
                     .Where(static e => !e.Domain.StartsWith("AppDomain", StringComparison.Ordinal))
                     .GroupBy(static e => e.Domain, StringComparer.Ordinal)
                     .OrderBy(static g => string.IsNullOrWhiteSpace(g.Key) ? "(senza domain)" : g.Key,
                         StringComparer.CurrentCultureIgnoreCase))
        {
            domains.Children.Add(new NavNode
            {
                Title = string.IsNullOrWhiteSpace(g.Key) ? "(senza domain)" : g.Key,
                FilterKey = g.Key,
                FilterKind = NavFilterKind.Domain,
                Count = g.Count(),
            });
        }

        if (domains.Children.Count > 0)
            root.Add(domains);

        return root;
    }

    private static void AddCategory(
        NavNode parent,
        IReadOnlyList<BackupFileEntry> content,
        string key,
        string title)
    {
        var n = content.Count(e => e.CategoryKey == key);
        if (n == 0)
            return;
        parent.Children.Add(new NavNode
        {
            Title = title,
            FilterKey = key,
            FilterKind = NavFilterKind.Category,
            Count = n,
        });
    }

    private static string FriendlyAppName(string domain)
    {
        // AppDomain-com.example.app → com.example.app
        const string prefix = "AppDomain-";
        const string plugin = "AppDomainPlugin-";
        const string group = "AppDomainGroup-";
        if (domain.StartsWith(prefix, StringComparison.Ordinal))
            return domain[prefix.Length..];
        if (domain.StartsWith(plugin, StringComparison.Ordinal))
            return "plugin · " + domain[plugin.Length..];
        if (domain.StartsWith(group, StringComparison.Ordinal))
            return "group · " + domain[group.Length..];
        return domain;
    }
}
