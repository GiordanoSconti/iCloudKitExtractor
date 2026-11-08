namespace BackupViewer.Models;

public sealed class BackupFileEntry
{
    public required string FileId { get; init; }
    public required string Domain { get; init; }
    public required string RelativePath { get; init; }
    public int Flags { get; init; }
    public string? AbsolutePath { get; init; }
    public long SizeBytes { get; init; }
    public bool ExistsOnDisk { get; init; }

    public bool IsDirectory => Flags == 2;
    public string DisplayName =>
        string.IsNullOrWhiteSpace(RelativePath)
            ? FileId
            : RelativePath.Replace('\\', '/').Split('/')[^1];

    public string CategoryKey { get; set; } = "other";
    public FileKind Kind { get; set; } = FileKind.Unknown;
}
