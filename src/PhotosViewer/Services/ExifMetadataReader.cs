using System.IO;
using MetadataExtractor;

namespace PhotosViewer.Services;

/// <summary>Parse EXIF / metadata file-side (JPEG, HEIC, PNG, video QuickTime, …).</summary>
public static class ExifMetadataReader
{
    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "File", "File Type", "Huffman", "ICC Profile"
    };

    public static Task<IReadOnlyList<MetaEntry>> ReadAsync(string path, CancellationToken ct = default) =>
        Task.Run(() => Read(path), ct);

    public static IReadOnlyList<MetaEntry> Read(string path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return [];

        try
        {
            var dirs = ImageMetadataReader.ReadMetadata(path);
            var list = new List<MetaEntry>();
            foreach (var dir in dirs)
            {
                if (SkipDirs.Contains(dir.Name))
                    continue;
                foreach (var tag in dir.Tags)
                {
                    if (tag.HasName && !string.IsNullOrWhiteSpace(tag.Description))
                        list.Add(new MetaEntry($"{dir.Name} · {tag.Name}", tag.Description.Trim()));
                }
            }

            return list
                .GroupBy(static e => e.Key, StringComparer.OrdinalIgnoreCase)
                .Select(static g => g.First())
                .OrderBy(static e => e.Key, StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
        catch
        {
            return [];
        }
    }
}

public readonly record struct MetaEntry(string Key, string Value);
