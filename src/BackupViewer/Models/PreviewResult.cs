using System.Windows.Media.Imaging;

namespace BackupViewer.Models;

public enum PreviewMode
{
    None,
    Status,
    Text,
    Image,
    Video,
    Audio,
    Sqlite,
}

public sealed class PreviewResult
{
    public PreviewMode Mode { get; init; } = PreviewMode.None;
    public string Title { get; init; } = "";
    public string? TextBody { get; init; }
    public BitmapSource? Image { get; init; }
    public string? MediaPath { get; init; }
    public string? SqlitePath { get; init; }
    public string? Error { get; init; }

    public static PreviewResult Status(string title, string body) => new()
    {
        Mode = PreviewMode.Status,
        Title = title,
        TextBody = body,
    };

    public static PreviewResult Fail(string title, string error) => new()
    {
        Mode = PreviewMode.Status,
        Title = title,
        Error = error,
        TextBody = error,
    };
}
