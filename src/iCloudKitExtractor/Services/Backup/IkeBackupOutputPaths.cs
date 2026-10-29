using System.IO;
using System.Globalization;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Layout cartelle stile 
/// <c>{root}/{deviceUdid}/[{snapshotGuid}][{yyyyMMdd_HHmmssZ}]/</c> = radice snapshot;
/// <c>…/Backup/</c> = snapshot iTunes pulito (Manifest.db, xx/fileID, Info/Status/Manifest.plist);
/// <c>…/tmp/</c> = intermezzo (flist, AUTH, keybag, mmcs_cache, .chunks) — rimossa a fine download.
/// </summary>
public static class IkeBackupOutputPaths
{
    /// <summary>Sottocartella snapshot finale (senza file di intermezzo).</summary>
    public const string CleanBackupFolderName = "Backup";

    /// <summary>Sottocartella work/intermezzo (eliminata a fine snapshot).</summary>
    public const string TmpFolderName = "tmp";

    private static readonly Regex HardwareUdidRegex = new(
        @"^(?:[0-9a-f]{24,40}|[0-9a-f]{8}-[0-9a-f]{16})$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex GuidRegex = new(
        @"^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    /// <summary>
    /// Preferisce UDID hardware (es. <c>00008150…</c>) se presente; altrimenti hash CloudKit D:.
    /// </summary>
    public static string ResolveDeviceFolderName(BackupDevice device)
    {
        foreach (var candidate in new[]
                 {
                     device.HardwareUdid,
                     device.SerialNumber,
                     device.DeviceUuid
                 })
        {
            if (string.IsNullOrWhiteSpace(candidate))
                continue;
            var trimmed = candidate.Trim();
            if (HardwareUdidRegex.IsMatch(trimmed))
                return trimmed.ToLowerInvariant();
        }

        return string.IsNullOrWhiteSpace(device.DeviceUuid)
            ? "unknown-device"
            : CloudKitRecordNames.StripDevicePrefix(device.DeviceUuid);
    }

    public static string ResolveSnapshotGuid(BackupSnapshot snapshot)
    {
        if (!string.IsNullOrWhiteSpace(snapshot.BackupUuid)
            && GuidRegex.IsMatch(snapshot.BackupUuid.Trim()))
            return snapshot.BackupUuid.Trim().ToUpperInvariant();

        var stripped = CloudKitRecordNames.StripSnapshotPrefix(snapshot.RecordName);
        if (!string.IsNullOrWhiteSpace(stripped) && GuidRegex.IsMatch(stripped))
            return stripped.ToUpperInvariant();

        return string.IsNullOrWhiteSpace(stripped) ? "UNKNOWN-SNAPSHOT" : stripped.ToUpperInvariant();
    }

    public static string FormatSnapshotFolderName(BackupSnapshot snapshot, DateTimeOffset utcNow) =>
        $"[{ResolveSnapshotGuid(snapshot)}][{utcNow.UtcDateTime.ToString("yyyyMMdd_HHmmss", CultureInfo.InvariantCulture)}Z]";

    public static string ResolveDeviceDirectory(string root, BackupDevice device) =>
        Path.Combine(root, ResolveDeviceFolderName(device));

    /// <summary>Cartella radice dello snapshot (<c>[guid][timestamp]/c>).</summary>
    public static string ResolveSnapshotDirectory(
        string root,
        BackupDevice device,
        BackupSnapshot snapshot,
        DateTimeOffset? utcNow = null)
    {
        var deviceDir = ResolveDeviceDirectory(root, device);
        var stamp = utcNow ?? DateTimeOffset.UtcNow;
        return Path.Combine(deviceDir, FormatSnapshotFolderName(snapshot, stamp));
    }

    private static string TrimDir(string path) =>
        path.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);

    /// <summary>
    /// Radice snapshot partendo da radice, <c>tmp/</c> o <c>Backup/</c>.
    /// </summary>
    public static string ResolveSnapshotRoot(string snapshotOrWorkOrBackup)
    {
        if (string.IsNullOrWhiteSpace(snapshotOrWorkOrBackup))
            throw new ArgumentException("Percorso snapshot richiesto.", nameof(snapshotOrWorkOrBackup));

        var trimmed = TrimDir(snapshotOrWorkOrBackup);
        var name = Path.GetFileName(trimmed);
        if (string.Equals(name, TmpFolderName, StringComparison.OrdinalIgnoreCase)
            || string.Equals(name, CleanBackupFolderName, StringComparison.OrdinalIgnoreCase))
        {
            var parent = Path.GetDirectoryName(trimmed);
            if (!string.IsNullOrEmpty(parent))
                return parent;
        }

        return trimmed;
    }

    /// <summary>Cartella intermezzo: <c>{snapshot}/tmp/</c> (idempotente se già <c>tmp</c>).</summary>
    public static string ResolveTmpDirectory(string snapshotOrWorkDirectory)
    {
        if (string.IsNullOrWhiteSpace(snapshotOrWorkDirectory))
            throw new ArgumentException("Percorso snapshot richiesto.", nameof(snapshotOrWorkDirectory));

        var trimmed = TrimDir(snapshotOrWorkDirectory);
        if (string.Equals(Path.GetFileName(trimmed), TmpFolderName, StringComparison.OrdinalIgnoreCase))
            return trimmed;

        return Path.Combine(ResolveSnapshotRoot(trimmed), TmpFolderName);
    }

    /// <summary>
    /// Snapshot iTunes pulito: <c>{snapshot}/Backup/</c>
    /// (Manifest.db, <c>xx/fileID</c>, Info/Status/Manifest.plist).
    /// Accetta radice, <c>tmp/</c> o già <c>Backup/</c>.
    /// </summary>
    public static string ResolveCleanBackupDirectory(string snapshotOrWorkDirectory)
    {
        if (string.IsNullOrWhiteSpace(snapshotOrWorkDirectory))
            throw new ArgumentException("workDirectory richiesto.", nameof(snapshotOrWorkDirectory));

        var trimmed = TrimDir(snapshotOrWorkDirectory);
        if (string.Equals(Path.GetFileName(trimmed), CleanBackupFolderName, StringComparison.OrdinalIgnoreCase))
            return trimmed;

        return Path.Combine(ResolveSnapshotRoot(trimmed), CleanBackupFolderName);
    }

    /// <summary>Path iTunes/ <c>{cleanBackupDir}/{fileID[0..2]}/{fileID}</c>.</summary>
    public static string ToShardedFilePath(string cleanBackupDirectory, string fileId)
    {
        if (string.IsNullOrWhiteSpace(fileId) || fileId.Length < 2)
            throw new ArgumentException("fileID deve essere SHA1 hex (≥2 char).", nameof(fileId));

        var id = fileId.Trim().ToLowerInvariant();
        return Path.Combine(cleanBackupDirectory, id[..2], id);
    }

    /// <summary>Staging intermezzo: <c>{snapshot}/tmp/.chunks</c>.</summary>
    public static string ChunksStagingDirectory(string snapshotOrWorkDirectory) =>
        Path.Combine(ResolveTmpDirectory(snapshotOrWorkDirectory), ".chunks");

    /// <summary>
    /// Elimina <c>{snapshot}/tmp/</c> a fine download (ignora se assente).
    /// </summary>
    public static bool TryDeleteTmpDirectory(string snapshotDirectory, IProgress<string>? log = null)
    {
        if (string.IsNullOrWhiteSpace(snapshotDirectory))
            return false;

        string tmp;
        try
        {
            tmp = ResolveTmpDirectory(snapshotDirectory);
        }
        catch
        {
            return false;
        }

        if (!string.Equals(Path.GetFileName(TrimDir(tmp)), TmpFolderName, StringComparison.OrdinalIgnoreCase))
            return false;
        if (!Directory.Exists(tmp))
            return false;

        try
        {
            Directory.Delete(tmp, recursive: true);
            log?.Report($"tmp rimosso → {tmp}");
            return true;
        }
        catch (Exception ex)
        {
            log?.Report($"tmp non rimosso ({tmp}): {ex.Message}");
            return false;
        }
    }

    /// <summary>
    /// Indice signature→shard <b>per snapshot</b> (niente riuso cross-UUID).
    /// Un file per hex(sig21) sotto <c>{snapshotWork}/.ike_sig_cache/</c>.
    /// </summary>
    public const string DeviceSigCacheFolderName = ".ike_sig_cache";

    /// <summary>
    /// Cache legacy device-wide (non usare per bind cross-snapshot: contaminava fileID/size).
    /// </summary>
    public static string ResolveDeviceSigCacheDirectory(string deviceDirectory) =>
        Path.Combine(deviceDirectory, DeviceSigCacheFolderName);

    public static string ResolveDeviceSigCacheEntryPath(string deviceDirectory, string sigHex21) =>
        Path.Combine(
            ResolveDeviceSigCacheDirectory(deviceDirectory),
            sigHex21.Trim().ToLowerInvariant());

    /// <summary>Radice snapshot (cartella <c>[GUID][…]</c>) da <c>…/Backup</c> o dalla work dir.</summary>
    public static string ResolveSnapshotWorkDirectoryFromCleanBackup(string cleanBackupDirectory)
    {
        var trimmed = cleanBackupDirectory.TrimEnd(
            Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar);
        var name = Path.GetFileName(trimmed);
        if (string.Equals(name, CleanBackupFolderName, StringComparison.OrdinalIgnoreCase))
            return Path.GetDirectoryName(trimmed) ?? trimmed;
        return trimmed;
    }

    public static string ResolveSnapshotSigCacheDirectory(string snapshotWorkDirectory) =>
        Path.Combine(ResolveSnapshotRoot(snapshotWorkDirectory), DeviceSigCacheFolderName);

    public static string ResolveSnapshotSigCacheEntryPath(
        string snapshotWorkDirectory,
        string sigHex21) =>
        Path.Combine(
            ResolveSnapshotSigCacheDirectory(snapshotWorkDirectory),
            sigHex21.Trim().ToLowerInvariant());

    /// <summary>
    /// Snapshot work sibling sotto lo stesso device (escluso <paramref name="currentWorkDirectory"/>),
    /// più recenti prima. <paramref name="currentWorkDirectory"/> può essere radice o <c>tmp/</c>.
    /// </summary>
    public static IReadOnlyList<string> EnumerateSiblingSnapshotWorkDirs(
        string deviceDirectory,
        string? currentWorkDirectory = null)
    {
        if (string.IsNullOrWhiteSpace(deviceDirectory) || !Directory.Exists(deviceDirectory))
            return [];

        string? currentFull = null;
        if (!string.IsNullOrWhiteSpace(currentWorkDirectory))
        {
            try { currentFull = Path.GetFullPath(ResolveSnapshotRoot(currentWorkDirectory)); }
            catch { /* ignore */ }
        }

        var list = new List<(string Path, DateTime Mtime)>();
        foreach (var dir in Directory.EnumerateDirectories(deviceDirectory))
        {
            var name = Path.GetFileName(dir);
            if (name.Length > 0 && name[0] == '.')
                continue;
            if (name.Length == 0 || name[0] != '[')
                continue;
            try
            {
                var full = Path.GetFullPath(dir);
                if (currentFull is not null
                    && string.Equals(full, currentFull, StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!Directory.Exists(Path.Combine(dir, CleanBackupFolderName)))
                    continue;
                list.Add((dir, Directory.GetLastWriteTimeUtc(dir)));
            }
            catch
            {
                // skip locked / inaccessible
            }
        }

        list.Sort(static (a, b) => b.Mtime.CompareTo(a.Mtime));
        return list.ConvertAll(static x => x.Path);
    }

    /// <summary>
    /// Cerca un file già materializzato in Backup/ di uno snapshot precedente.
    /// Stesso fileID <b>e</b> stessa size (obbligatoria): senza size match si contaminano
    /// snapshot diversi che condividono il path iTunes ma non il contenuto.
    /// </summary>
    public static string? TryFindPriorBackupShard(
        string deviceDirectory,
        string fileId,
        string? currentWorkDirectory = null,
        long? expectedSizeBytes = null)
    {
        if (string.IsNullOrWhiteSpace(fileId) || fileId.Length < 2)
            return null;
        // Size obbligatoria: fileID da solo non implica contenuto invariato tra snapshot.
        if (expectedSizeBytes is not > 0)
            return null;

        foreach (var work in EnumerateSiblingSnapshotWorkDirs(deviceDirectory, currentWorkDirectory))
        {
            try
            {
                var clean = ResolveCleanBackupDirectory(work);
                var path = ToShardedFilePath(clean, fileId);
                if (!File.Exists(path))
                    continue;
                var len = new FileInfo(path).Length;
                if (len == expectedSizeBytes.Value)
                    return path;
            }
            catch
            {
                // next sibling
            }
        }

        return null;
    }
}
