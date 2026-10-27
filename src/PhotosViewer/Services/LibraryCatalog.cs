using System.IO;
using Microsoft.Data.Sqlite;
using PhotosViewer.Models;

namespace PhotosViewer.Services;

public sealed class LibraryCatalog
{
    public string Root { get; }
    public IReadOnlyList<MediaItem> Media { get; }
    public IReadOnlyList<FolderNode> Folders { get; }
    public IReadOnlyList<ISidebarEntry> Sidebar { get; }
    public IReadOnlyList<string> AppDisplayNames { get; }

    private readonly Dictionary<string, HashSet<string>> _albumTokens;

    private LibraryCatalog(
        string root,
        IReadOnlyList<MediaItem> media,
        IReadOnlyList<FolderNode> folders,
        IReadOnlyList<ISidebarEntry> sidebar,
        Dictionary<string, HashSet<string>> albumTokens,
        IReadOnlyList<string> appDisplayNames)
    {
        Root = root;
        Media = media;
        Folders = folders;
        Sidebar = sidebar;
        _albumTokens = albumTokens;
        AppDisplayNames = appDisplayNames;
    }

    public static Task<LibraryCatalog> LoadAsync(string root, CancellationToken ct = default) =>
        Task.Run(() =>
        {
            ct.ThrowIfCancellationRequested();
            return Load(root);
        }, ct);

    public static LibraryCatalog Load(string root)
    {

        var dbPath = Path.Combine(root, "Photos.db");
        var media = new List<MediaItem>();
        var byToken = new Dictionary<string, MediaItem>(StringComparer.OrdinalIgnoreCase);
        var albumTokens = new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
        var albumNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var albumFolders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        if (File.Exists(dbPath))
        {
            using var conn = new SqliteConnection($"Data Source={dbPath};Mode=ReadOnly");
            conn.Open();
            var hasSha = HasColumn(conn, "Media", "sha256");
            using (var cmd = conn.CreateCommand())
            {
                cmd.CommandText = hasSha
                    ? """
                      SELECT token, record_name, file_name, relative_path, extension, size_bytes,
                             hidden, trashed, favorite, is_live, bundle_id, app_display_name, sha256
                      FROM Media
                      """
                    : """
                      SELECT token, record_name, file_name, relative_path, extension, size_bytes,
                             hidden, trashed, favorite, is_live, bundle_id, app_display_name, NULL
                      FROM Media
                      """;
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    var token = r.GetString(0);
                    var fileName = r.IsDBNull(2) ? token : r.GetString(2);
                    var rel = r.IsDBNull(3) ? "" : r.GetString(3);
                    var ext = r.IsDBNull(4) ? Path.GetExtension(fileName) : r.GetString(4);
                    var item = new MediaItem
                    {
                        Token = token,
                        FileName = fileName,
                        RelativePath = rel.Replace('/', Path.DirectorySeparatorChar),
                        Extension = ext,
                        SizeBytes = r.IsDBNull(5) ? 0 : r.GetInt64(5),
                        Hidden = !r.IsDBNull(6) && r.GetInt64(6) != 0,
                        Trashed = !r.IsDBNull(7) && r.GetInt64(7) != 0,
                        Favorite = !r.IsDBNull(8) && r.GetInt64(8) != 0,
                        IsLive = !r.IsDBNull(9) && r.GetInt64(9) != 0,
                        BundleId = r.IsDBNull(10) ? null : r.GetString(10),
                        AppDisplayName = r.IsDBNull(11) ? null : r.GetString(11),
                        Sha256 = r.IsDBNull(12) ? null : r.GetString(12),
                        IsVideo = IsVideoExt(ext)
                    };
                    item.AbsolutePath = ResolveExisting(root, item.RelativePath, fileName, token);
                    TouchFileInfo(item);
                    media.Add(item);
                    byToken[token] = item;
                }
            }

            if (TableExists(conn, "MediaMetadata"))
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT media_token, field_name, text_value FROM MediaMetadata";
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    var token = r.GetString(0);
                    if (!byToken.TryGetValue(token, out var item))
                        continue;
                    var field = r.GetString(1);
                    var raw = r.IsDBNull(2) ? "" : r.GetString(2);
                    ApplyMetadata(item, field, raw);
                }
            }

            // mediaMetaDataEnc CloudKit a volte è sul record sbagliato: EXIF/QuickTime del file vince.
            EnrichGpsFromFiles(media);

            if (TableExists(conn, "Albums"))
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT record_name, name, folder FROM Albums";
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    var id = r.GetString(0);
                    albumNames[id] = r.IsDBNull(1) ? id : r.GetString(1);
                    albumFolders[id] = r.IsDBNull(2) ? albumNames[id] : r.GetString(2);
                }
            }

            if (TableExists(conn, "AlbumMedia"))
            {
                using var cmd = conn.CreateCommand();
                cmd.CommandText = "SELECT album_record_name, media_token FROM AlbumMedia";
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    var album = r.GetString(0);
                    var token = r.GetString(1);
                    if (!albumTokens.TryGetValue(album, out var set))
                    {
                        set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                        albumTokens[album] = set;
                    }

                    set.Add(token);
                }
            }
        }

        AbsorbFolderFiles(root, "Sfoglia", media, byToken, hidden: false, trashed: false, favorite: false);
        AbsorbFolderFiles(root, "Preferiti", media, byToken, hidden: false, trashed: false, favorite: true);
        AbsorbFolderFiles(root, "Nascoste", media, byToken, hidden: true, trashed: false, favorite: false);
        AbsorbFolderFiles(root, "Eliminate", media, byToken, hidden: false, trashed: true, favorite: false);

        var folders = new List<FolderNode>
        {
            Node("sfoglia", "Sfoglia", Path.Combine(root, "Sfoglia"), FolderKind.Sfoglia,
                media.Count(static m => !m.Trashed && m.FileExists)),
            Node("fav", "Preferiti", Path.Combine(root, "Preferiti"), FolderKind.Preferiti,
                media.Count(static m => m.Favorite)),
            Node("hidden", "Nascoste", Path.Combine(root, "Nascoste"), FolderKind.Nascoste,
                media.Count(static m => m.Hidden)),
            Node("trash", "Eliminate", Path.Combine(root, "Eliminate"), FolderKind.Eliminate,
                media.Count(static m => m.Trashed))
        };

        var albumsRoot = Path.Combine(root, "Album");
        if (Directory.Exists(albumsRoot))
        {
            foreach (var dir in Directory.GetDirectories(albumsRoot).OrderBy(Path.GetFileName, StringComparer.OrdinalIgnoreCase))
            {
                var name = Path.GetFileName(dir);
                var id = albumFolders.FirstOrDefault(kv =>
                    string.Equals(kv.Value, name, StringComparison.OrdinalIgnoreCase)).Key;
                if (string.IsNullOrEmpty(id))
                    id = "album:" + name;
                if (!albumTokens.ContainsKey(id))
                    albumTokens[id] = [];
                var count = albumTokens.TryGetValue(id, out var set) && set.Count > 0
                    ? set.Count
                    : Directory.EnumerateFiles(dir).Count(IsMediaFile);
                folders.Add(Node(id, name, dir, FolderKind.Album, count));
            }
        }
        else
        {
            foreach (var (id, name) in albumNames.OrderBy(static kv => kv.Value, StringComparer.OrdinalIgnoreCase))
            {
                var folder = albumFolders.GetValueOrDefault(id, name);
                folders.Add(Node(id, name, Path.Combine(root, "Album", folder), FolderKind.Album,
                    albumTokens.GetValueOrDefault(id)?.Count ?? 0));
            }
        }

        var mapNode = Node("map", "Mappa", null, FolderKind.Mappa,
            media.Count(static m => m.HasGeo));

        var sidebar = new List<ISidebarEntry>();
        foreach (var f in folders)
            sidebar.Add(new SidebarFolderEntry { Folder = f });
        sidebar.Add(new SidebarSectionHeader { Title = "Geolocalizzazioni" });
        sidebar.Add(new SidebarFolderEntry { Folder = mapNode });
        folders.Add(mapNode);


        var apps = media
            .Select(static m => m.AppDisplayName)
            .Where(static s => !string.IsNullOrWhiteSpace(s))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static s => s, StringComparer.OrdinalIgnoreCase)
            .Cast<string>()
            .ToList();

        return new LibraryCatalog(root, media, folders, sidebar, albumTokens, apps);
    }

    public IReadOnlyList<MediaItem> ItemsFor(FolderNode folder)
    {
        // Nessun I/O qui: FileExists/FileWriteTime popolati in Load.
        IEnumerable<MediaItem> q = Media.Where(static m => m.FileExists);
        q = folder.Kind switch
        {
            FolderKind.Sfoglia => q.Where(static m =>
                m.RelativePath.StartsWith("Sfoglia", StringComparison.OrdinalIgnoreCase)
                || (!m.Trashed && !m.Hidden)),
            FolderKind.Preferiti => q.Where(static m => m.Favorite),
            FolderKind.Nascoste => q.Where(static m => m.Hidden),
            FolderKind.Eliminate => q.Where(static m => m.Trashed),
            FolderKind.Mappa => q.Where(static m => m.HasGeo),
            FolderKind.Album when _albumTokens.TryGetValue(folder.Id, out var tokens) && tokens.Count > 0
                => q.Where(m => tokens.Contains(m.Token)),
            FolderKind.Album when !string.IsNullOrWhiteSpace(folder.AbsolutePath)
                => q.Where(m => string.Equals(
                    Path.GetDirectoryName(m.AbsolutePath), folder.AbsolutePath, StringComparison.OrdinalIgnoreCase)),
            _ => q
        };
        return q.OrderByDescending(static m => m.ShotDate ?? DateTime.MinValue)
            .ThenBy(static m => m.FileName, StringComparer.OrdinalIgnoreCase)
            .ToList();
    }

    private static void TouchFileInfo(MediaItem item)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(item.AbsolutePath) || !File.Exists(item.AbsolutePath))
            {
                item.FileExists = false;
                return;
            }

            item.FileExists = true;
            item.FileWriteTime = File.GetLastWriteTime(item.AbsolutePath);
        }
        catch
        {
            item.FileExists = false;
        }
    }

    private static void ApplyMetadata(MediaItem item, string field, string raw)
    {
        var decoded = BplistDecoder.TryDecode(raw);
        if (decoded is null)
            return;

        if (decoded is string plain && !LooksLikeBplist(raw))
        {
            item.Metadata[field] = plain;
            if (field.Equals("timeZoneNameEnc", StringComparison.OrdinalIgnoreCase))
                item.Metadata["timeZone"] = plain;
            return;
        }

        foreach (var (k, v) in BplistDecoder.Flatten(decoded, field))
            item.Metadata[k] = v;

        if (field.Equals("locationEnc", StringComparison.OrdinalIgnoreCase) && decoded is Dictionary<string, object?> loc)
        {
            ApplyLatLon(item,
                BplistDecoder.TryDouble(loc.GetValueOrDefault("lat")),
                BplistDecoder.TryDouble(loc.GetValueOrDefault("lon")));
            item.TakenAt ??= BplistDecoder.TryDate(loc.GetValueOrDefault("timestamp"));
        }

        if (field.Equals("lastViewedDateEnc", StringComparison.OrdinalIgnoreCase))
            item.TakenAt ??= BplistDecoder.TryDate(decoded);

        if (decoded is Dictionary<string, object?> dict)
        {
            if (dict.TryGetValue("{Exif}", out var exifObj)
                && exifObj is Dictionary<string, object?> exif)
            {
                item.TakenAt ??= BplistDecoder.TryDate(exif.GetValueOrDefault("DateTimeOriginal"))
                                 ?? ParseExifDate(exif.GetValueOrDefault("DateTimeOriginal"));
            }

            // CPL mediaMetaDataEnc embeds ImageIO {GPS}; può essere sul record sbagliato —
            // EnrichGpsFromFiles sovrascrive con EXIF del file quando disponibile.
            if ((dict.TryGetValue("{GPS}", out var gpsObj) || dict.TryGetValue("GPS", out gpsObj))
                && gpsObj is Dictionary<string, object?> gps)
            {
                var lat = BplistDecoder.TryDouble(gps.GetValueOrDefault("Latitude"));
                var lon = BplistDecoder.TryDouble(gps.GetValueOrDefault("Longitude"));
                if (lat is { } la && lon is { } lo)
                {
                    if (IsSouthOrWest(gps.GetValueOrDefault("LatitudeRef")))
                        la = -la;
                    if (IsSouthOrWest(gps.GetValueOrDefault("LongitudeRef")))
                        lo = -lo;
                    ApplyLatLon(item, la, lo);
                }
            }
        }
    }

    private static void EnrichGpsFromFiles(List<MediaItem> media)
    {
        Parallel.ForEach(
            media.Where(static m => m.FileExists && !string.IsNullOrWhiteSpace(m.AbsolutePath)),
            new ParallelOptions { MaxDegreeOfParallelism = Math.Clamp(Environment.ProcessorCount, 2, 8) },
            item =>
            {
                if (!ExifMetadataReader.TryReadGps(item.AbsolutePath, out var lat, out var lon))
                    return;
                item.Latitude = lat;
                item.Longitude = lon;
                item.Metadata["lat"] = lat.ToString("0.######");
                item.Metadata["lon"] = lon.ToString("0.######");
                item.Metadata["gpsSource"] = "file";
            });
    }

    private static void ApplyLatLon(MediaItem item, double? lat, double? lon)
    {
        if (lat is null || lon is null)
            return;
        item.Latitude = lat;
        item.Longitude = lon;
        item.Metadata["lat"] = lat.Value.ToString("0.######");
        item.Metadata["lon"] = lon.Value.ToString("0.######");
    }

    private static bool IsSouthOrWest(object? refValue) =>
        refValue is string s
        && s.Length > 0
        && (s[0] is 'S' or 's' or 'W' or 'w');

    private static DateTime? ParseExifDate(object? value)
    {
        var s = Convert.ToString(value);
        if (string.IsNullOrWhiteSpace(s))
            return null;
        if (DateTime.TryParseExact(
                s, "yyyy:MM:dd HH:mm:ss",
                System.Globalization.CultureInfo.InvariantCulture,
                System.Globalization.DateTimeStyles.AssumeLocal,
                out var dt))
            return dt;
        return null;
    }

    private static void AbsorbFolderFiles(
        string root,
        string folderName,
        List<MediaItem> media,
        Dictionary<string, MediaItem> byToken,
        bool hidden,
        bool trashed,
        bool favorite)
    {
        var dir = Path.Combine(root, folderName);
        if (!Directory.Exists(dir))
            return;

        foreach (var path in Directory.EnumerateFiles(dir))
        {
            if (!IsMediaFile(path))
                continue;
            var name = Path.GetFileName(path);
            var existing = media.FirstOrDefault(m =>
                string.Equals(m.FileName, name, StringComparison.OrdinalIgnoreCase)
                || string.Equals(m.AbsolutePath, path, StringComparison.OrdinalIgnoreCase));
            if (existing is not null)
            {
                if (string.IsNullOrWhiteSpace(existing.AbsolutePath) || !existing.FileExists)
                {
                    existing.AbsolutePath = path;
                    TouchFileInfo(existing);
                }

                continue;
            }

            var token = Path.GetFileNameWithoutExtension(path);
            var item = new MediaItem
            {
                Token = token,
                FileName = name,
                AbsolutePath = path,
                RelativePath = Path.Combine(folderName, name),
                Extension = Path.GetExtension(path),
                SizeBytes = new FileInfo(path).Length,
                Hidden = hidden,
                Trashed = trashed,
                Favorite = favorite,
                IsVideo = IsVideoExt(Path.GetExtension(path)),
                FileExists = true,
                FileWriteTime = File.GetLastWriteTime(path)
            };
            media.Add(item);
            byToken[token] = item;
        }
    }

    private static FolderNode Node(string id, string title, string? path, FolderKind kind, int count) =>
        new()
        {
            Id = id,
            Title = title,
            AbsolutePath = path,
            Kind = kind,
            Count = count
        };

    private static string ResolveExisting(
        string root, string relative, string fileName, string? token = null)
    {
        // Token-named orphan wins: dopo collisioni filenameEnc Organize può lasciare
        // {token}.* in Sfoglia mentre relative_path punta al display name di un altro.
        if (!string.IsNullOrWhiteSpace(token))
        {
            foreach (var sub in new[] { "Sfoglia", "Eliminate", "Nascoste", "Preferiti" })
            {
                var dir = Path.Combine(root, sub);
                if (!Directory.Exists(dir))
                    continue;
                try
                {
                    foreach (var path in Directory.EnumerateFiles(dir, token + ".*"))
                    {
                        if (IsMediaFile(path))
                            return path;
                    }
                }
                catch
                {
                    // ignore
                }
            }
        }

        if (!string.IsNullOrWhiteSpace(relative))
        {
            var p = Path.Combine(root, relative);
            if (File.Exists(p))
                return p;
        }

        foreach (var sub in new[] { "Sfoglia", "Eliminate", "Nascoste", "Preferiti" })
        {
            var p = Path.Combine(root, sub, fileName);
            if (File.Exists(p))
                return p;
        }

        return Path.Combine(root, relative);
    }

    private static bool IsMediaFile(string path)
    {
        var ext = Path.GetExtension(path);
        if (ext.Equals(".ct", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".bin", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".txt", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".hex", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".json", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".db", StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    private static bool IsVideoExt(string? ext) =>
        ext is not null && ext.ToLowerInvariant() is ".mov" or ".mp4" or ".m4v" or ".avi" or ".hevc";

    private static bool LooksLikeBplist(string raw) =>
        raw.StartsWith("bplist00", StringComparison.Ordinal)
        || raw.StartsWith("YnBsaXN0", StringComparison.Ordinal);

    private static bool TableExists(SqliteConnection conn, string name)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT 1 FROM sqlite_master WHERE type='table' AND name=$n LIMIT 1";
        cmd.Parameters.AddWithValue("$n", name);
        return cmd.ExecuteScalar() is not null;
    }

    private static bool HasColumn(SqliteConnection conn, string table, string column)
    {
        using var cmd = conn.CreateCommand();
        cmd.CommandText = $"PRAGMA table_info({table})";
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            if (string.Equals(r.GetString(1), column, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }
}
