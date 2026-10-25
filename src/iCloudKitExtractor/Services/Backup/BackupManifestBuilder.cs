using System.IO;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Ricostruisce il catalogo file backup (manifest) dai record asset scoperti in PreAuth/query.
/// I nomi KA:/MA:/LA:/NA:/JA: con suffisso :<size> sono l'indice file; mbs account è spesso stub.
/// </summary>
public static class BackupManifestBuilder
{
    private static readonly Regex AssetRecordRegex = new(
        @"^(?:KA|MA|LA|NA|JA|A):[^\s\x00-\x1f]{8,320}$",
        RegexOptions.Compiled);

    public static IReadOnlyList<BackupAsset> FromRecordNames(IEnumerable<string> recordNames)
    {
        var assets = new Dictionary<string, BackupAsset>(StringComparer.Ordinal);
        foreach (var name in recordNames)
        {
            if (string.IsNullOrWhiteSpace(name) || !AssetRecordRegex.IsMatch(name))
                continue;

            assets[name] = new BackupAsset
            {
                RecordName = name,
                SizeBytes = UbChunkBuilder.ExtractDeclaredSize(name)
            };
        }

        return assets.Values
            .OrderBy(static a => PrefixPriority(a.RecordName))
            .ThenBy(static a => a.RecordName, StringComparer.Ordinal)
            .ToList();
    }

    public static async Task WriteAsync(
        string outputDirectory,
        BackupDevice device,
        BackupSnapshot snapshot,
        IEnumerable<string> recordNames,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var assets = FromRecordNames(recordNames);
        var byPrefix = assets
            .GroupBy(static a => a.RecordName.Split(':', 2)[0])
            .ToDictionary(static g => g.Key, static g => g.Count(), StringComparer.Ordinal);

        var manifest = new
        {
            source = "preauth-catalog",
            snapshot = snapshot.RecordName,
            device = device.DeviceUuid,
            backupUuid = snapshot.BackupUuid,
            keybagCount = device.Keybags.Count,
            recordCount = assets.Count,
            byPrefix,
            totalDeclaredBytes = assets.Sum(static a => a.SizeBytes ?? 0),
            assets = assets.Select(static a => new
            {
                a.RecordName,
                a.SizeBytes,
                encrypted = true,
                hasMmcsAuth = !string.IsNullOrWhiteSpace(a.MmcsAuth)
            })
        };

        var path = Path.Combine(outputDirectory, "backup_manifest.json");
        var json = JsonSerializer.Serialize(manifest, new JsonSerializerOptions { WriteIndented = true });
        await File.WriteAllTextAsync(path, json, ct);
    }

    private static int PrefixPriority(string recordName)
    {
        if (recordName.StartsWith("KA:", StringComparison.Ordinal)) return 0;
        if (recordName.StartsWith("MA:", StringComparison.Ordinal)) return 1;
        if (recordName.StartsWith("LA:", StringComparison.Ordinal)) return 2;
        if (recordName.StartsWith("NA:", StringComparison.Ordinal)) return 3;
        if (recordName.StartsWith("JA:", StringComparison.Ordinal)) return 4;
        return 5;
    }
}
