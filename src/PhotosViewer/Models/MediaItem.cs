namespace PhotosViewer.Models;

public sealed class MediaItem
{
    public string Token { get; init; } = "";
    public string FileName { get; init; } = "";
    public string AbsolutePath { get; set; } = "";
    public string RelativePath { get; init; } = "";
    public string Extension { get; init; } = "";
    public long SizeBytes { get; init; }
    public string? Sha256 { get; init; }
    public bool Hidden { get; init; }
    public bool Trashed { get; init; }
    public bool Favorite { get; init; }
    public bool IsLive { get; init; }
    public string? BundleId { get; init; }
    public string? AppDisplayName { get; init; }
    public double? Latitude { get; set; }
    public double? Longitude { get; set; }
    public DateTime? TakenAt { get; set; }
    public DateTime? FileWriteTime { get; set; }
    public bool FileExists { get; set; }
    public bool IsVideo { get; init; }
    public Dictionary<string, string> Metadata { get; } = new(StringComparer.Ordinal);

    public bool HasGeo => Latitude is not null && Longitude is not null;
    public DateTime? ShotDate => TakenAt ?? FileWriteTime;
}

public sealed class FolderNode
{
    public string Id { get; init; } = "";
    public string Title { get; init; } = "";
    public string? AbsolutePath { get; init; }
    public FolderKind Kind { get; init; }
    public int Count { get; set; }
    public string Caption => Count > 0 ? $"{Title}  {Count}" : Title;
}

public enum FolderKind
{
    Sfoglia,
    Preferiti,
    Nascoste,
    Eliminate,
    Album,
    Mappa
}

public sealed class MediaRow
{
    public MediaRow(IReadOnlyList<MediaItem> cells) => Cells = cells;
    public IReadOnlyList<MediaItem> Cells { get; }
}

public enum SizeFilterKind
{
    All,
    Under500Kb,
    From500KbTo2Mb,
    From2MbTo8Mb,
    Over8Mb
}
