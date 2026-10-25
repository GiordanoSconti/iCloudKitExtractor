using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Indice catalogo JSON + skeleton Manifest.db (senza righe Files fittizie da :CN:).
/// Le righe Files arrivano da <see cref="BackupFilesystemWriter"/> durante il download.
/// </summary>
public static class LocalBackupManifestWriter
{
    public static async Task WriteAsync(
        string outputDirectory,
        BackupDevice device,
        BackupSnapshot snapshot,
        DeterministicFileCatalog catalog,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var cleanDir = IkeBackupOutputPaths.ResolveCleanBackupDirectory(outputDirectory);
        Directory.CreateDirectory(cleanDir);

        var assets = catalog.FileRecordNames.Select(name => new
        {
            recordName = name,
            sizeBytes = UbChunkBuilder.ExtractDeclaredSize(name)
        }).ToList();

        var json = JsonSerializer.Serialize(new
        {
            source = catalog.Source,
            snapshot = snapshot.RecordName,
            device = device.DeviceUuid,
            backupUuid = snapshot.BackupUuid,
            workDirectory = outputDirectory,
            cleanBackupDirectory = cleanDir,
            manifestIds = catalog.ManifestIds,
            cnEntryCount = catalog.CnEntryCount,
            filesPerManifest = catalog.FilesPerManifest,
            recordCount = assets.Count,
            totalDeclaredBytes = assets.Sum(a => a.sizeBytes ?? 0),
            note = "Catalogo CloudKit (work). Snapshot iTunes pulito in sottocartella Backup/.",
            assets
        }, new JsonSerializerOptions { WriteIndented = true });

        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "backup_manifest.json"), json, ct);

        await using var fs = await BackupFilesystemWriter.OpenAsync(cleanDir, ct);
        await fs.WriteSkeletonPropertiesAsync(device, snapshot, catalog.Source, ct);

        var meta = JsonSerializer.Serialize(new
        {
            manifestDb = Path.Combine(IkeBackupOutputPaths.CleanBackupFolderName, "Manifest.db"),
            cleanBackupDirectory = IkeBackupOutputPaths.CleanBackupFolderName,
            mmcsDecrypted = false,
            encrypted = false,
            builtLocally = true,
            backupLayout = true,
            note = "Manifest.db + xx/fileID nella cartella Backup/; " +
                   "flist/AUTH/keybag/mmcs_cache/.chunks restano in tmp/ (rimossa a fine snapshot).",
            catalogFileCount = assets.Count,
            catalogSource = catalog.Source,
            cnEntryCount = catalog.CnEntryCount,
            manifestIds = catalog.ManifestIds.Count
        }, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "manifest_db_meta.json"), meta, ct);
    }
}
