using System.Collections.ObjectModel;
using Avalonia;
using Avalonia.Controls;
using Avalonia.Controls.Templates;
using Avalonia.Interactivity;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Threading;
using iCloudKitExtractor.Services.SyncData;

namespace iCloudKitExtractor;

public partial class MessagesChatViewerWindow : Window
{
    private readonly string _inventoryPath;
    private readonly IReadOnlyList<string> _ownHandles;
    private MessagesLibrary? _library;
    private readonly ObservableCollection<ChatThread> _visibleChats = new();

    public MessagesChatViewerWindow()
        : this(string.Empty, null)
    {
    }

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
        MessageList.ItemTemplate = new FuncDataTemplate<ChatMessage>((m, _) => BuildBubble(m), supportsRecycling: false);
        SearchBox.TextChanged += (_, _) => ApplyFilter(SearchBox.Text);
        Opened += (_, _) => Reload();
    }

    public static MessagesChatViewerWindow? TryOpen(
        Window owner,
        string syncDataRootOrInventory,
        IEnumerable<string>? ownHandles = null)
    {
        var path = MessagesChatCatalog.FindInventoryPath(syncDataRootOrInventory);
        if (path is null || !File.Exists(path))
            return null;

        var win = new MessagesChatViewerWindow(path, ownHandles);
        win.Show(owner);
        return win;
    }

    private static Control BuildBubble(ChatMessage? m)
    {
        if (m is null)
            return new Panel();

        IBrush bubbleBg = m.IsSystem ? Brushes.Transparent
            : m.IsFromMe ? new SolidColorBrush(Color.Parse("#007AFF"))
            : Brushes.White;
        IBrush fg = m.IsFromMe ? Brushes.White : new SolidColorBrush(Color.Parse("#1B1C1F"));
        IBrush timeFg = m.IsFromMe ? new SolidColorBrush(Color.Parse("#CCFFFFFF")) : new SolidColorBrush(Color.Parse("#8E8E93"));

        var stack = new StackPanel();
        if (!m.IsFromMe && !m.IsSystem)
        {
            stack.Children.Add(new TextBlock
            {
                Text = m.SenderLabel,
                FontSize = 11,
                FontWeight = FontWeight.SemiBold,
                Foreground = new SolidColorBrush(Color.Parse("#007AFF")),
                Margin = new Thickness(0, 0, 0, 2),
            });
        }

        if (!string.IsNullOrEmpty(m.Reply))
        {
            stack.Children.Add(new Border
            {
                Background = new SolidColorBrush(m.IsFromMe ? Color.Parse("#22FFFFFF") : Color.Parse("#14000000")),
                CornerRadius = new CornerRadius(8),
                Padding = new Thickness(8, 4),
                Margin = new Thickness(0, 0, 0, 6),
                Child = new TextBlock
                {
                    Text = m.Reply,
                    FontSize = 11,
                    FontStyle = FontStyle.Italic,
                    Foreground = m.IsFromMe ? Brushes.White : new SolidColorBrush(Color.Parse("#6B6B70")),
                    TextWrapping = TextWrapping.Wrap,
                },
            });
        }

        stack.Children.Add(new TextBlock
        {
            Text = m.DisplayText,
            FontSize = m.IsSystem ? 12 : 14,
            Foreground = m.IsSystem ? new SolidColorBrush(Color.Parse("#6B6B70")) : fg,
            TextWrapping = TextWrapping.Wrap,
            TextAlignment = m.IsSystem ? TextAlignment.Center : TextAlignment.Left,
        });

        var footer = new StackPanel { Orientation = Orientation.Horizontal, Margin = new Thickness(0, 4, 0, 0) };
        if (!string.IsNullOrEmpty(m.AssociatedEmoji))
            footer.Children.Add(new TextBlock { Text = m.AssociatedEmoji, FontSize = 12, Margin = new Thickness(0, 0, 6, 0) });
        footer.Children.Add(new TextBlock { Text = m.TimeDisplay, FontSize = 10, Foreground = timeFg });
        footer.HorizontalAlignment = m.IsSystem ? HorizontalAlignment.Center : HorizontalAlignment.Right;
        stack.Children.Add(footer);

        var bubble = new Border
        {
            MaxWidth = 520,
            Padding = new Thickness(12, 8),
            CornerRadius = new CornerRadius(16),
            Background = bubbleBg,
            BorderBrush = new SolidColorBrush(Color.Parse("#10000000")),
            BorderThickness = new Thickness(m.IsFromMe || m.IsSystem ? 0 : 1),
            HorizontalAlignment = m.IsSystem ? HorizontalAlignment.Center
                : m.IsFromMe ? HorizontalAlignment.Right : HorizontalAlignment.Left,
            Child = stack,
        };
        return new Grid { Margin = new Thickness(0, 3), Children = { bubble } };
    }

    private void Reload_Click(object? sender, RoutedEventArgs e) => Reload();

    private void Reload()
    {
        try
        {
            if (!File.Exists(_inventoryPath))
            {
                SummaryText.Text = "inventory assente";
                _visibleChats.Clear();
                MessageList.ItemsSource = null;
                EmptyHint.IsVisible = true;
                return;
            }

            _library = MessagesChatCatalog.Load(_inventoryPath, _ownHandles);
            SummaryText.Text =
                $"{_library.Chats.Count} chat · {_library.TotalMessages} msg " +
                $"({_library.WithText} con testo)";
            ApplyFilter(SearchBox.Text);
            EmptyHint.IsVisible = _visibleChats.Count == 0;
            if (_visibleChats.Count > 0 && ChatList.SelectedItem is null)
                ChatList.SelectedIndex = 0;
        }
        catch (Exception ex)
        {
            SummaryText.Text = "Errore: " + ex.Message;
        }
    }

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

        EmptyHint.IsVisible = _visibleChats.Count == 0;

        if (selectedKey is not null)
        {
            var match = _visibleChats.FirstOrDefault(c =>
                string.Equals(c.Key, selectedKey, StringComparison.OrdinalIgnoreCase));
            if (match is not null)
                ChatList.SelectedItem = match;
        }
    }

    private void ChatList_OnSelectionChanged(object? sender, SelectionChangedEventArgs e)
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
        EmptyHint.IsVisible = false;

        Dispatcher.UIThread.Post(() => ThreadScroll.ScrollToEnd(), DispatcherPriority.Loaded);
    }
}
