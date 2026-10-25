namespace PhotosViewer.Models;

public interface ISidebarEntry
{
    bool IsSectionHeader { get; }
}

public sealed class SidebarSectionHeader : ISidebarEntry
{
    public string Title { get; init; } = "";
    public bool IsSectionHeader => true;
}

public sealed class SidebarFolderEntry : ISidebarEntry
{
    public FolderNode Folder { get; init; } = null!;
    public bool IsSectionHeader => false;
    public string Caption => Folder.Caption;
}
