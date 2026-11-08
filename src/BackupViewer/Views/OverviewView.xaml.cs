using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using BackupViewer.Models;
using BackupViewer.Services;

namespace BackupViewer.Views;

public partial class OverviewView : UserControl
{
    public event Action<ModuleKind>? ModuleRequested;

    public OverviewView()
    {
        InitializeComponent();
    }

    public void Bind(BackupCatalog catalog, CoreDataService core)
    {
        var name = System.IO.Path.GetFileName(
            System.IO.Path.GetDirectoryName(catalog.BackupRoot.TrimEnd('\\', '/'))
            ?? catalog.BackupRoot);
        DeviceTitle.Text = string.IsNullOrWhiteSpace(name) ? "Backup" : name;
        DeviceSub.Text = catalog.BackupRoot;

        BackupStats.Text =
            $"File catalogati: {catalog.FileCount:N0}\n"
            + $"Presenti su disco: {catalog.PresentCount:N0}\n"
            + $"Assenti: {catalog.MissingCount:N0}";

        var s = core.Snapshot;
        PersonalStats.Text =
            $"Chat: {s.ChatSources.Sum(static c => c.Conversations.Count):N0} conversazioni\n"
            + $"Chiamate: {s.Calls.Count:N0}\n"
            + $"Calendario: {s.Events.Count:N0} eventi · {s.Calendars.Count:N0} calendari\n"
            + $"Contatti: {s.Contacts.Count:N0}";

        ModuleGrid.Children.Clear();
        AddModuleCard("Chat", ModuleKind.Chat, s.ChatSources.Sum(static c => c.Conversations.Count));
        AddModuleCard("Chiamate", ModuleKind.Calls, s.Calls.Count);
        AddModuleCard("Calendario", ModuleKind.Calendar, s.Events.Count);
        AddModuleCard("Contatti", ModuleKind.Contacts, s.Contacts.Count);
        AddModuleCard("File", ModuleKind.Files, catalog.FileCount);
    }

    private void AddModuleCard(string title, ModuleKind kind, int count)
    {
        var border = new Border
        {
            Style = (Style)FindResource("CardBorder"),
            Margin = new Thickness(0, 0, 10, 10),
            Cursor = Cursors.Hand,
            Tag = kind,
        };
        border.MouseLeftButtonUp += (_, _) => ModuleRequested?.Invoke(kind);
        border.Child = new StackPanel
        {
            Children =
            {
                new TextBlock
                {
                    Text = title,
                    FontSize = 15,
                    FontWeight = FontWeights.SemiBold,
                    Foreground = (Brush)FindResource("InkBrush"),
                },
                new TextBlock
                {
                    Text = $"{count:N0} elementi",
                    Margin = new Thickness(0, 6, 0, 0),
                    FontSize = 12,
                    Foreground = (Brush)FindResource("MutedBrush"),
                },
            },
        };
        ModuleGrid.Children.Add(border);
    }
}
