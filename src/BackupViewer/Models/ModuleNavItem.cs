namespace BackupViewer.Models;

public enum ModuleKind
{
    Overview,
    Chat,
    Calls,
    Calendar,
    Contacts,
    Files,
}

public sealed class ModuleNavItem
{
    public required ModuleKind Kind { get; init; }
    public required string Title { get; init; }
    public required string Glyph { get; init; }
    public int Count { get; set; }

    public string Caption => Count > 0 ? $"{Title}  {Count:N0}" : Title;
}
