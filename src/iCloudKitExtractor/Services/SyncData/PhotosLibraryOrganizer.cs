using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Dopo MMCS decrypt + crypto/: rinomina con filename originale, copia negli Album,
/// aggiorna Nascoste/Eliminate/Preferiti e scrive <c>Photos.db</c>.
/// </summary>
public static class PhotosLibraryOrganizer
{
    public static async Task<int> OrganizeAsync(
        string photosDir,
        PhotosMediaMetaCache cache,
        IReadOnlyList<CplPhotosRecordParser.CplAlbum> albums,
        IReadOnlyList<CplPhotosRecordParser.CplRelation> relations,
        IReadOnlyDictionary<string, string> albumNames,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var sfoglia = Path.Combine(photosDir, "Sfoglia");
        var albumsRoot = Path.Combine(photosDir, "Album");
        var hiddenDir = Path.Combine(photosDir, "Nascoste");
        var deletedDir = Path.Combine(photosDir, "Eliminate");
        var favDir = Path.Combine(photosDir, "Preferiti");
        Directory.CreateDirectory(sfoglia);
        Directory.CreateDirectory(albumsRoot);
        Directory.CreateDirectory(hiddenDir);
        Directory.CreateDirectory(deletedDir);
        Directory.CreateDirectory(favDir);

        foreach (var old in Directory.EnumerateDirectories(albumsRoot))
        {
            try { Directory.Delete(old, recursive: true); }
            catch { /* ignore */ }
        }

        ClearDirFiles(hiddenDir);
        ClearDirFiles(deletedDir);
        ClearDirFiles(favDir);

        var albumFolderById = albums.ToDictionary(
            a => a.RecordName,
            a =>
            {
                var folderName = CplPhotosRecordParser.ClassifyAlbumFolder(
                    a, albumNames.GetValueOrDefault(a.RecordName));
                return Path.Combine(albumsRoot, folderName);
            },
            StringComparer.OrdinalIgnoreCase);
        foreach (var dir in albumFolderById.Values)
            Directory.CreateDirectory(dir);

        var containersByItem = relations
            .GroupBy(r => r.ItemId, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(
                g => g.Key,
                g => g.Select(x => x.ContainerId).Distinct(StringComparer.OrdinalIgnoreCase).ToList(),
                StringComparer.OrdinalIgnoreCase);

        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var hiddenUsed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var deletedUsed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var favUsed = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var renamed = 0;
        var albumCopies = 0;
        var dbMedia = 0;
        var dbMetadata = 0;
        var dbHashed = 0;
        var entries = cache.Entries;

        await using var db = await PhotosCatalogSqlite.OpenAsync(photosDir, ct);
        await db.ClearAsync(ct);

        foreach (var album in albums)
        {
            var name = albumNames.GetValueOrDefault(album.RecordName);
            var folder = CplPhotosRecordParser.ClassifyAlbumFolder(album, name);
            await db.UpsertAlbumAsync(
                album.RecordName, name ?? folder, album.AlbumType, album.IsRootFolder, folder, ct);
        }

        foreach (var entry in entries)
        {
            ct.ThrowIfCancellationRequested();
            try
            {
                var plainPath = LocatePlainFile(
                    photosDir, sfoglia, hiddenDir, deletedDir, favDir, entry, cache);
                if (plainPath is null)
                    continue;

                var ext = Path.GetExtension(plainPath);
                if (string.IsNullOrWhiteSpace(ext) || ext.Equals(".bin", StringComparison.OrdinalIgnoreCase))
                    ext = GuessExtFromRecord(entry, cache) ?? ext;

                var display = cache.ResolveDisplayFileName(entry.RecordName, ext, entry.MmcsAuth);
                if (string.IsNullOrWhiteSpace(display))
                    display = entry.Token + ext;
                // Allinea estensione al contenuto reale (binding filename a volte sbaglia .png↔.heic).
                display = AlignExtensionToMagic(plainPath, display);
                display = EnsureUniqueFileName(sfoglia, display, usedNames, ownedPath: plainPath);

                var dest = Path.Combine(sfoglia, display);
                var beforeName = Path.GetFileName(plainPath);
                if (!string.Equals(plainPath, dest, StringComparison.OrdinalIgnoreCase))
                {
                    if (File.Exists(dest))
                        File.Delete(dest);
                    File.Move(plainPath, dest);
                    if (!beforeName.Equals(display, StringComparison.OrdinalIgnoreCase))
                        renamed++;
                }

                entry.PlainRelativePath = Path.Combine("Sfoglia", display);
                var meta = cache.GetMetaForAuth(entry.MmcsAuth)
                           ?? cache.GetMetaForRecord(entry.RecordName)
                           ?? cache.GetMetaForRecord(
                               entry.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase)
                                   ? entry.RecordName[..^5]
                                   : entry.RecordName);

                if (entry.Hidden)
                    await CopyAsync(dest, Path.Combine(hiddenDir, EnsureUniqueFileName(hiddenDir, display, hiddenUsed)), ct);
                if (entry.Trashed)
                    await CopyAsync(dest, Path.Combine(deletedDir, EnsureUniqueFileName(deletedDir, display, deletedUsed)), ct);
                if (entry.Favorite)
                    await CopyAsync(dest, Path.Combine(favDir, EnsureUniqueFileName(favDir, display, favUsed)), ct);

                var relationKey = ResolveRelationItemId(entry);
                if (containersByItem.TryGetValue(relationKey, out var albumIds))
                {
                    foreach (var albumId in albumIds)
                    {
                        if (!albumFolderById.TryGetValue(albumId, out var folder))
                            continue;
                        Directory.CreateDirectory(folder);
                        await CopyAsync(dest, Path.Combine(folder, display), ct);
                        await db.LinkAlbumMediaAsync(albumId, entry.Token, ct);
                        albumCopies++;
                    }
                }

                var fi = new FileInfo(dest);
                var sha256 = TryComputeSha256Hex(dest);
                if (sha256 is not null)
                    dbHashed++;
                await db.UpsertMediaAsync(
                    entry.Token,
                    entry.RecordName,
                    entry.AssetRecordName,
                    display,
                    entry.PlainRelativePath,
                    ext,
                    fi.Exists ? fi.Length : entry.SizeBytes,
                    entry.Hidden,
                    entry.Trashed,
                    entry.Favorite,
                    entry.IsLive,
                    meta?.BundleId,
                    meta?.AppDisplayName,
                    entry.MmcsAuth,
                    sha256,
                    ct);
                dbMedia++;

                var extra = cache.GetExtraForAuth(entry.MmcsAuth);
                if (extra is { Count: > 0 })
                {
                    await db.UpsertMediaMetadataAsync(entry.Token, extra, ct);
                    dbMetadata += extra.Count;
                }
            }
            catch (Exception ex)
            {
                log?.Report(
                    $"  organize skip {entry.Token}: {ex.GetType().Name}: {ex.Message}");
            }
        }

        var specialRenamed = RenameSpecialFolderFiles(
            photosDir, hiddenDir, deletedDir, favDir, cache, entries);

        cache.SaveIndex();


        log?.Report(
            $"  Libreria: rinominati={renamed}, speciali={specialRenamed}, copie album={albumCopies}, " +
            $"media DB={dbMedia}/{entries.Count}, sha256={dbHashed}, metadati={dbMetadata} → Photos.db");
        return renamed + specialRenamed;
    }

    private static string? TryComputeSha256Hex(string path)
    {
        try
        {
            if (!File.Exists(path))
                return null;
            using var stream = File.OpenRead(path);
            var hash = SHA256.HashData(stream);
            return Convert.ToHexString(hash).ToLowerInvariant();
        }
        catch
        {
            return null;
        }
    }

    private static string ResolveRelationItemId(PhotosMediaMetaCache.MediaEntry entry)
    {
        if (!string.IsNullOrWhiteSpace(entry.AssetRecordName))
            return entry.AssetRecordName;
        if (entry.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase))
            return entry.RecordName[..^5];
        return entry.RecordName;
    }

    private static string? LocatePlainFile(
        string photosDir,
        string sfoglia,
        string hiddenDir,
        string deletedDir,
        string favDir,
        PhotosMediaMetaCache.MediaEntry entry,
        PhotosMediaMetaCache cache)
    {
        if (!string.IsNullOrWhiteSpace(entry.PlainRelativePath))
        {
            var fromRel = Path.Combine(photosDir, entry.PlainRelativePath);
            if (File.Exists(fromRel) && IsMediaPlain(fromRel))
                return fromRel;
        }

        // Già rinominato in un run precedente: cerca il display name da filenameEnc.
        var displayGuess = cache.ResolveDisplayFileName(entry.RecordName, ".bin", entry.MmcsAuth);
        if (!string.IsNullOrWhiteSpace(displayGuess))
        {
            foreach (var dir in new[] { sfoglia, hiddenDir, deletedDir, favDir })
            {
                if (!Directory.Exists(dir))
                    continue;
                var candidate = Path.Combine(dir, displayGuess);
                if (File.Exists(candidate) && IsMediaPlain(candidate))
                    return candidate;
                // Live: IMG_0001.MOV vs IMG_0001_Live.MOV
                if (entry.IsLive || entry.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase))
                {
                    var stem = Path.GetFileNameWithoutExtension(displayGuess);
                    var ext = Path.GetExtension(displayGuess);
                    if (!stem.EndsWith("_Live", StringComparison.OrdinalIgnoreCase))
                    {
                        candidate = Path.Combine(dir, stem + "_Live" + ext);
                        if (File.Exists(candidate) && IsMediaPlain(candidate))
                            return candidate;
                    }
                }
            }
        }

        foreach (var dir in new[] { sfoglia, hiddenDir, deletedDir, favDir })
        {
            var found = LocatePlainFileInDir(dir, entry);
            if (found is not null)
                return found;
        }

        return null;
    }

    private static string? LocatePlainFileInDir(
        string dir,
        PhotosMediaMetaCache.MediaEntry entry)
    {
        if (!Directory.Exists(dir))
            return null;

        foreach (var path in Directory.EnumerateFiles(dir, entry.Token + ".*"))
        {
            if (IsMediaPlain(path))
                return path;
        }

        // RecordName CPL può contenere '/' e '+' (base64url). Non usarlo grezzo in
        // EnumerateFiles: Windows lo interpreta come sotto-path (es. Adml1O10G/…).
        var recordToken = CplPhotosRecordParser.SanitizeFileToken(entry.RecordName);
        if (!string.IsNullOrWhiteSpace(recordToken)
            && !recordToken.Equals(entry.Token, StringComparison.OrdinalIgnoreCase))
        {
            foreach (var path in Directory.EnumerateFiles(dir, recordToken + ".*"))
            {
                if (IsMediaPlain(path))
                    return path;
            }
        }

        var dec = Path.Combine(dir, entry.Token + ".dec.bin");
        return File.Exists(dec) ? dec : null;
    }

    /// <summary>
    /// Rinomina file residui in Nascoste/Eliminate/Preferiti (token/UUID → nome decifrato).
    /// </summary>
    private static int RenameSpecialFolderFiles(
        string photosDir,
        string hiddenDir,
        string deletedDir,
        string favDir,
        PhotosMediaMetaCache cache,
        IReadOnlyList<PhotosMediaMetaCache.MediaEntry> entries)
    {
        var renamed = 0;
        foreach (var (dir, flag) in new (string Dir, Func<PhotosMediaMetaCache.MediaEntry, bool> Flag)[]
                 {
                     (hiddenDir, static e => e.Hidden),
                     (deletedDir, static e => e.Trashed),
                     (favDir, static e => e.Favorite)
                 })
        {
            if (!Directory.Exists(dir))
                continue;

            var used = new HashSet<string>(
                Directory.EnumerateFiles(dir).Select(Path.GetFileName)!,
                StringComparer.OrdinalIgnoreCase);

            foreach (var path in Directory.EnumerateFiles(dir).ToList())
            {
                if (!IsMediaPlain(path))
                    continue;

                var entry = MatchEntryForFile(path, entries);
                if (entry is null || !flag(entry))
                    continue;

                var ext = Path.GetExtension(path);
                var display = cache.ResolveDisplayFileName(entry.RecordName, ext, entry.MmcsAuth);
                if (string.IsNullOrWhiteSpace(display))
                    display = entry.Token + ext;

                var targetName = EnsureUniqueFileName(dir, display, used);
                var dest = Path.Combine(dir, targetName);
                if (string.Equals(path, dest, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (File.Exists(dest))
                    File.Delete(dest);
                File.Move(path, dest);
                renamed++;
            }
        }

        return renamed;
    }

    private static PhotosMediaMetaCache.MediaEntry? MatchEntryForFile(
        string path,
        IReadOnlyList<PhotosMediaMetaCache.MediaEntry> entries)
    {
        var fileName = Path.GetFileNameWithoutExtension(path);
        if (string.IsNullOrWhiteSpace(fileName))
            return null;

        var stem = fileName;
        var under = stem.LastIndexOf('_');
        if (under > 0 && int.TryParse(stem[(under + 1)..], out _))
            stem = stem[..under];

        foreach (var entry in entries)
        {
            var recordToken = CplPhotosRecordParser.SanitizeFileToken(entry.RecordName);
            if (stem.Equals(entry.Token, StringComparison.OrdinalIgnoreCase)
                || stem.Equals(recordToken, StringComparison.OrdinalIgnoreCase))
                return entry;
        }

        return null;
    }

    private static int CountMediaFiles(string dir) =>
        !Directory.Exists(dir)
            ? 0
            : Directory.EnumerateFiles(dir).Count(IsMediaPlain);

    private static int CountUnknownNames(string dir)
    {
        if (!Directory.Exists(dir))
            return 0;
        return Directory.EnumerateFiles(dir).Count(path =>
        {
            if (!IsMediaPlain(path))
                return false;
            var name = Path.GetFileName(path);
            return name.StartsWith("UNKNOWN_", StringComparison.OrdinalIgnoreCase);
        });
    }

    private static int CountHumanNames(string dir)
    {
        if (!Directory.Exists(dir))
            return 0;

        var count = 0;
        foreach (var path in Directory.EnumerateFiles(dir))
        {
            if (!IsMediaPlain(path))
                continue;
            var stem = Path.GetFileNameWithoutExtension(path);
            if (stem is null || stem.Length < 36)
            {
                count++;
                continue;
            }

            if (!Guid.TryParse(stem.Length > 36 ? stem[..36] : stem, out _))
                count++;
        }

        return count;
    }

    private static bool IsMediaPlain(string path)
    {
        var ext = Path.GetExtension(path);
        if (ext.Equals(".ct", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".bin", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".ag.bin", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".wrap.hex", StringComparison.OrdinalIgnoreCase)
            || path.EndsWith(".mmcsauth.txt", StringComparison.OrdinalIgnoreCase))
            return false;
        return true;
    }

    private static string? GuessExtFromRecord(
        PhotosMediaMetaCache.MediaEntry entry,
        PhotosMediaMetaCache cache)
    {
        var name = cache.ResolveDisplayFileName(entry.RecordName, ".jpg", entry.MmcsAuth);
        return name is null ? null : Path.GetExtension(name);
    }

    /// <summary>
    /// Se il file è già al path target (re-organize), non forzare _2/_3.
    /// </summary>
    private static string EnsureUniqueFileName(
        string directory,
        string fileName,
        HashSet<string> used,
        string? ownedPath = null)
    {
        var safe = SanitizeFileName(fileName);
        var dest = Path.Combine(directory, safe);
        var ownsDest = ownedPath is not null
                       && string.Equals(ownedPath, dest, StringComparison.OrdinalIgnoreCase);
        if (ownsDest)
        {
            used.Add(safe);
            return safe;
        }

        if (used.Add(safe) && !File.Exists(dest))
            return safe;

        used.Remove(safe);
        var stem = Path.GetFileNameWithoutExtension(safe);
        var ext = Path.GetExtension(safe);
        for (var i = 2; i < 10_000; i++)
        {
            var candidate = $"{stem}_{i}{ext}";
            var candidatePath = Path.Combine(directory, candidate);
            if (ownedPath is not null
                && string.Equals(ownedPath, candidatePath, StringComparison.OrdinalIgnoreCase))
            {
                used.Add(candidate);
                return candidate;
            }

            if (used.Add(candidate) && !File.Exists(candidatePath))
                return candidate;
        }

        return $"{stem}_{Guid.NewGuid():N}{ext}";
    }

    /// <summary>
    /// Corregge l'estensione del display name in base al magic del plaintext MMCS.
    /// </summary>
    private static string AlignExtensionToMagic(string plainPath, string displayName)
    {
        var magicExt = GuessExtensionFromMagic(plainPath);
        if (magicExt is null)
            return displayName;
        var currentExt = Path.GetExtension(displayName);
        if (currentExt.Equals(magicExt, StringComparison.OrdinalIgnoreCase))
            return displayName;
        return Path.GetFileNameWithoutExtension(displayName) + magicExt;
    }

    private static string? GuessExtensionFromMagic(string path)
    {
        try
        {
            using var fs = File.OpenRead(path);
            Span<byte> b = stackalloc byte[16];
            var n = fs.Read(b);
            if (n >= 3 && b[0] == 0xFF && b[1] == 0xD8)
                return ".jpg";
            if (n >= 8 && b[0] == 0x89 && b[1] == 0x50 && b[2] == 0x4E && b[3] == 0x47)
                return ".png";
            if (n >= 12 && b[4] == (byte)'f' && b[5] == (byte)'t' && b[6] == (byte)'y' && b[7] == (byte)'p')
            {
                var brand = Encoding.ASCII.GetString(b.Slice(8, 4));
                if (brand.Contains("heic", StringComparison.OrdinalIgnoreCase)
                    || brand.Contains("mif1", StringComparison.OrdinalIgnoreCase)
                    || brand.Contains("msf1", StringComparison.OrdinalIgnoreCase)
                    || brand.Contains("heix", StringComparison.OrdinalIgnoreCase)
                    || brand.Contains("hevc", StringComparison.OrdinalIgnoreCase))
                    return ".heic";
                if (brand.Contains("qt", StringComparison.OrdinalIgnoreCase))
                    return ".mov";
                return ".mp4";
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static string SanitizeFileName(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name.Trim())
        {
            if (c is '\\' or '/' or ':' or '*' or '?' or '"' or '<' or '>' or '|')
                sb.Append('_');
            else
                sb.Append(c);
        }

        var s = sb.ToString().Trim();
        return string.IsNullOrWhiteSpace(s) ? "unnamed" : s;
    }

    private static async Task CopyAsync(string src, string dst, CancellationToken ct)
    {
        Directory.CreateDirectory(Path.GetDirectoryName(dst)!);
        await using var input = File.OpenRead(src);
        await using var output = File.Create(dst);
        await input.CopyToAsync(output, ct);
    }

    private static void ClearDirFiles(string dir)
    {
        if (!Directory.Exists(dir))
            return;
        foreach (var f in Directory.EnumerateFiles(dir))
        {
            try { File.Delete(f); }
            catch { /* ignore */ }
        }
    }

}
