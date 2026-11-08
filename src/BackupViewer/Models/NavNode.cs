using System.Collections.ObjectModel;

namespace BackupViewer.Models;

public sealed class NavNode
{
    public required string Title { get; init; }
    public string? FilterKey { get; init; }
    public NavFilterKind FilterKind { get; init; }
    public int Count { get; set; }
    public ObservableCollection<NavNode> Children { get; } = [];

    public string Caption => Count > 0 ? $"{Title} ({Count:N0})" : Title;
}

public enum NavFilterKind
{
    All,
    Category,
    Domain,
    App,
    FileSystem,
    CoreChat,
    CoreCalls,
    CoreCalendar,
    CoreContacts,
}
