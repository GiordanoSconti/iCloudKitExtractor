using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using MetadataExtractor;

namespace PhotosViewer.Services;

/// <summary>Parse EXIF / metadata file-side (JPEG, HEIC, PNG, video QuickTime, …).</summary>
public static class ExifMetadataReader
{
    private static readonly HashSet<string> SkipDirs = new(StringComparer.OrdinalIgnoreCase)
    {
        "File", "File Type", "Huffman", "ICC Profile"
    };

    private static readonly Regex QuickTimeGps = new(
        @"([+-]\d+\.?\d*)([+-]\d+\.?\d*)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

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

    /// <summary>
    /// GPS dal file (EXIF / QuickTime). Affidabile sui byte scaricati; mediaMetaDataEnc
    /// CloudKit a volte è agganciato al record sbagliato.
    /// </summary>
    public static bool TryReadGps(string path, out double latitude, out double longitude)
    {
        latitude = 0;
        longitude = 0;
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return false;

        try
        {
            double? lat = null, lon = null;
            string? latRef = null, lonRef = null;

            foreach (var dir in ImageMetadataReader.ReadMetadata(path))
            {
                var isGps = dir.Name.Contains("GPS", StringComparison.OrdinalIgnoreCase);
                var isQt = dir.Name.Contains("QuickTime", StringComparison.OrdinalIgnoreCase);
                if (!isGps && !isQt)
                    continue;

                foreach (var tag in dir.Tags)
                {
                    var name = tag.Name ?? "";
                    var desc = tag.Description;
                    if (string.IsNullOrWhiteSpace(desc))
                        continue;

                    if (name is "GPS Latitude" or "Latitude")
                        lat = ParseGpsComponent(desc);
                    else if (name is "GPS Longitude" or "Longitude")
                        lon = ParseGpsComponent(desc);
                    else if (name is "GPS Latitude Ref")
                        latRef = desc;
                    else if (name is "GPS Longitude Ref")
                        lonRef = desc;
                    else if (name is "GPS Location")
                        ParseQuickTimeLocation(desc, ref lat, ref lon);
                }
            }

            if (lat is null || lon is null)
                return false;

            if (latRef is not null && latRef.StartsWith("S", StringComparison.OrdinalIgnoreCase))
                lat = -lat;
            if (lonRef is not null && lonRef.StartsWith("W", StringComparison.OrdinalIgnoreCase))
                lon = -lon;

            latitude = lat.Value;
            longitude = lon.Value;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void ParseQuickTimeLocation(string loc, ref double? lat, ref double? lon)
    {
        var m = QuickTimeGps.Match(loc);
        if (!m.Success)
            return;
        if (double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var a)
            && double.TryParse(m.Groups[2].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var b))
        {
            lat = a;
            lon = b;
        }
    }

    private static double? ParseGpsComponent(string desc)
    {
        desc = desc.Trim().Replace(',', '.');
        if (desc.Contains('°', StringComparison.Ordinal))
        {
            var parts = desc.Split(['°', '\'', '"', ' '], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0
                || !double.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var deg))
                return null;
            double min = 0, sec = 0;
            if (parts.Length > 1)
                double.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out min);
            if (parts.Length > 2)
                double.TryParse(parts[2], NumberStyles.Float, CultureInfo.InvariantCulture, out sec);
            return deg + min / 60.0 + sec / 3600.0;
        }

        return double.TryParse(desc, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
    }
}

public readonly record struct MetaEntry(string Key, string Value);
