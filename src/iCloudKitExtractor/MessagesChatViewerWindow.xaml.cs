using System.Collections.ObjectModel;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using iCloudKitExtractor.Services.SyncData;

namespace iCloudKitExtractor;

public partial class MessagesChatViewerWindow : Window
{
    private readonly string _inventoryPath;
    private readonly IReadOnlyList<string> _ownHandles;
    private MessagesLibrary? _library;
    private readonly ObservableCollection<ChatThread> _visibleChats = new();

    public MessagesChatViewerWindow(
        string inventoryOrRootPath,
        IEnumerable<string>? ownHandles = null)
    {
        InitializeComponent();
        _ownHandles = ownHandles?.Where(h => !string.IsNullOrWhiteSpace(h)).Distinct().ToList()
                      ?? [];
        _inventoryPath = MessagesChatCatalog.FindInventoryPath(inventoryOrRootPath)
                         ?? inventoryOrRootPath;
        ChatList.ItemsSource = _visibleChats;
        Loaded += (_, _) => Reload();
    }

    public static MessagesChatViewerWindow? TryOpen(
        Window owner,
        string syncDataRootOrInventory,
        IEnumerable<string>? ownHandles = null)
    {
        var path = MessagesChatCatalog.FindInventoryPath(syncDataRootOrInventory);
        if (path is null || !File.Exists(path))
            return null;

        var win = new MessagesChatViewerWindow(path, ownHandles)
        {
            Owner = owner,
        };
        win.Show();
        return win;
    }

    private void Reload_Click(object sender, RoutedEventArgs e) => Reload();

    private void Reload()
    {
        try
        {
            if (!File.Exists(_inventoryPath))
            {
                SummaryText.Text = "inventory assente";
                _visibleChats.Clear();
                MessageList.ItemsSource = null;
                EmptyHint.Visibility = Visibility.Visible;
                return;
            }

            _library = MessagesChatCatalog.Load(_inventoryPath, _ownHandles);
            SummaryText.Text =
                $"{_library.Chats.Count} chat · {_library.TotalMessages} msg " +
                $"({_library.WithText} con testo)";
            ApplyFilter(SearchBox.Text);
            EmptyHint.Visibility = _visibleChats.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
            if (_visibleChats.Count > 0 && ChatList.SelectedItem is null)
                ChatList.SelectedIndex = 0;
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Messages", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void SearchBox_OnTextChanged(object sender, TextChangedEventArgs e) =>
        ApplyFilter(SearchBox.Text);

    private void ApplyFilter(string? query)
    {
        if (_library is null)
            return;

        var q = (query ?? "").Trim();
        IEnumerable<ChatThread> src = _library.Chats;
        if (q.Length > 0)
        {
            src = _library.Chats.Where(c =>
                c.Title.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.Preview.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.Key.Contains(q, StringComparison.OrdinalIgnoreCase)
                || c.Messages.Any(m =>
                    (m.DisplayText?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false)
                    || (m.Sender?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false)));
        }

        var selectedKey = (ChatList.SelectedItem as ChatThread)?.Key;
        _visibleChats.Clear();
        foreach (var c in src)
            _visibleChats.Add(c);

        EmptyHint.Visibility = _visibleChats.Count == 0 ? Visibility.Visible : Visibility.Collapsed;

        if (selectedKey is not null)
        {
            var match = _visibleChats.FirstOrDefault(c =>
                string.Equals(c.Key, selectedKey, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
                ChatList.SelectedItem = match;
        }
    }

    private void ChatList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ChatList.SelectedItem is not ChatThread chat)
        {
            ThreadTitle.Text = "Seleziona una chat";
            ThreadSubtitle.Text = "";
            MessageList.ItemsSource = null;
            return;
        }

        var q = (SearchBox.Text ?? "").Trim();
        IEnumerable<ChatMessage> messages = chat.Messages;
        if (q.Length > 0
            && !chat.Title.Contains(q, StringComparison.OrdinalIgnoreCase)
            && !chat.Key.Contains(q, StringComparison.OrdinalIgnoreCase))
        {
            // Se il filtro è su contenuto messaggio, evidenzia solo i match nel thread.
            var filtered = chat.Messages
                .Where(m =>
                    (m.DisplayText?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false)
                    || (m.Sender?.Contains(q, StringComparison.OrdinalIgnoreCase) ?? false))
                .ToList();
            if (filtered.Count > 0)
                messages = filtered;
        }

        ThreadTitle.Text = chat.Title;
        ThreadSubtitle.Text = $"{chat.Subtitle} · {chat.MessageCount} messaggi";
        MessageList.ItemsSource = messages.ToList();
        EmptyHint.Visibility = Visibility.Collapsed;

        Dispatcher.BeginInvoke(DispatcherPriority.Loaded, () =>
        {
            ThreadScroll.ScrollToEnd();
        });
    }
}
