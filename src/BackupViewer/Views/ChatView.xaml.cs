using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using BackupViewer.Models;
using BackupViewer.Services;

namespace BackupViewer.Views;

public partial class ChatView : UserControl
{
    private CoreDataService? _core;
    private IReadOnlyList<ChatMessage> _messages = [];
    private string? _kindFilter;
    private CancellationTokenSource? _cts;
    private string? _stagedMediaPath;
    private string? _shardMediaPath;
    private string? _preferredSaveName;
    private IMediaPlayback? _vlc;
    private CancellationTokenSource? _mediaCts;
    private bool _mediaNeedsVideo;

    public ChatView()
    {
        InitializeComponent();
        Unloaded += (_, _) =>
        {
            StopMedia();
            _vlc?.Dispose();
            _vlc = null;
        };
    }

    private IMediaPlayback EnsureVlc()
    {
        if (_vlc is not null)
            return _vlc;
        _vlc = MediaPlaybackFactory.TryCreate(MediaVlcHost, out var error)
               ?? throw new InvalidOperationException(
                   error ?? MediaPlaybackFactory.LastLoadError
                   ?? "Motore media VLC non disponibile.");
        return _vlc;
    }

    public void Bind(CoreDataService core)
    {
        _core = core;
        AppList.ItemsSource = core.Snapshot.ChatSources;
        ThreadList.ItemsSource = null;
        MessageList.ItemsSource = null;
        ClearMediaPreview();
        ChatTitle.Text = core.Snapshot.ChatSources.Count == 0
            ? "Nessuna chat nel backup"
            : "Seleziona una conversazione";
        ChatEmpty.Visibility = Visibility.Collapsed;
        if (core.Snapshot.ChatSources.Count > 0)
            AppList.SelectedIndex = 0;
    }

    public void ApplySearch(string query)
    {
        if (_core is null || AppList.SelectedItem is not ChatSource src)
            return;
        query ??= "";
        IEnumerable<ChatConversation> q = src.Conversations;
        if (!string.IsNullOrWhiteSpace(query))
        {
            q = q.Where(c =>
                c.Title.Contains(query, StringComparison.OrdinalIgnoreCase)
                || (c.Subtitle?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
                || (c.LastPreview?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false));
        }

        ThreadList.ItemsSource = q
            .OrderBy(static c => c.Title, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
        ThreadHeader.Text = $"CONVERSAZIONI · {ThreadList.Items.Count:N0}";
    }

    private void AppList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (AppList.SelectedItem is not ChatSource src)
            return;
        ThreadList.ItemsSource = src.Conversations;
        ThreadHeader.Text = $"CONVERSAZIONI · {src.Conversations.Count:N0}";
        MessageList.ItemsSource = null;
        ClearMediaPreview();
        ChatTitle.Text = "Seleziona una conversazione";
    }

    private async void ThreadList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (_core is null || ThreadList.SelectedItem is not ChatConversation conv)
            return;

        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        var ct = _cts.Token;
        ChatTitle.Text = conv.Title;
        MessageList.ItemsSource = null;
        ClearMediaPreview();
        ChatEmpty.Text = "Caricamento messaggi…";
        ChatEmpty.Visibility = Visibility.Visible;

        try
        {
            var messages = await Task.Run(() => _core.LoadMessages(conv.SourceId, conv.Id), ct)
                .ConfigureAwait(true);
            ct.ThrowIfCancellationRequested();
            _messages = messages;
            ApplyMessageFilter();
        }
        catch (OperationCanceledException)
        {
            // superseded
        }
        catch (Exception ex)
        {
            ChatEmpty.Text = ex.Message;
            ChatEmpty.Visibility = Visibility.Visible;
        }
    }

    private void KindFilter_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || MessageList is null || ChatEmpty is null)
            return;
        if (KindFilter.SelectedItem is not ComboBoxItem item)
            return;
        _kindFilter = item.Tag as string;
        ApplyMessageFilter();
    }

    private void ApplyMessageFilter()
    {
        if (MessageList is null || ChatEmpty is null)
            return;

        IEnumerable<ChatMessage> q = _messages;
        if (!string.IsNullOrWhiteSpace(_kindFilter)
            && Enum.TryParse<ChatMessageKind>(_kindFilter, out var kind))
            q = q.Where(m => m.Kind == kind);

        var list = q.ToList();
        MessageList.ItemsSource = list;
        ChatEmpty.Visibility = list.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        ChatEmpty.Text = list.Count == 0 ? "Nessun messaggio per questo filtro." : "";
        if (list.Count > 0)
            MessageList.ScrollIntoView(list[^1]);
    }

    private void MessageList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (MessageList.SelectedItem is ChatMessage msg)
            _ = ShowMediaAsync(msg);
    }

    private void MessageList_OnMouseDoubleClick(object sender, MouseButtonEventArgs e)
    {
        if (MessageList.SelectedItem is ChatMessage msg)
            _ = ShowMediaAsync(msg);
    }

    private async Task ShowMediaAsync(ChatMessage msg)
    {
        StopMedia();
        MediaImage.Source = null;
        MediaImage.Visibility = Visibility.Collapsed;
        MediaVlcHost.Visibility = Visibility.Collapsed;
        MediaEmpty.Visibility = Visibility.Visible;
        _stagedMediaPath = null;
        _shardMediaPath = msg.MediaShardPath;
        _preferredSaveName = msg.FileName ?? Path.GetFileName(msg.MediaRelativePath ?? "") ?? "media.bin";

        if (msg.MediaKind == ChatMediaKind.None)
        {
            MediaInfo.Text = string.IsNullOrWhiteSpace(msg.SenderLabel)
                ? "Messaggio senza allegato."
                : msg.SenderLabel;
            return;
        }

        MediaInfo.Text = msg.MediaLabel
                         + (string.IsNullOrWhiteSpace(msg.MediaRelativePath)
                             ? ""
                             : "\n" + msg.MediaRelativePath)
                         + (string.IsNullOrWhiteSpace(msg.Caption) ? "" : "\n" + msg.Caption);

        if (string.IsNullOrWhiteSpace(msg.MediaShardPath) || !File.Exists(msg.MediaShardPath))
        {
            MediaEmpty.Text = msg.MediaMissing
                ? "File non presente nel backup."
                : "Percorso media non risolto.";
            return;
        }

        try
        {
            var relative = msg.MediaRelativePath ?? msg.FileName ?? "media.bin";
            var staged = await Task.Run(() =>
                    MediaStaging.StageWithExtension(msg.MediaShardPath, relative))
                .ConfigureAwait(true);
            _stagedMediaPath = staged;
            MediaEmpty.Visibility = Visibility.Collapsed;

            if (msg.MediaKind == ChatMediaKind.Image)
            {
                var img = await Task.Run(() => ImageLoader.Load(staged, decodePixelWidth: 900))
                    .ConfigureAwait(true);
                MediaImage.Source = img;
                MediaImage.Visibility = Visibility.Visible;
            }
            else if (msg.MediaKind is ChatMediaKind.Video or ChatMediaKind.Audio)
            {
                _mediaNeedsVideo = msg.MediaKind == ChatMediaKind.Video;
                MediaVlcHost.Visibility = _mediaNeedsVideo ? Visibility.Visible : Visibility.Collapsed;
                _mediaCts?.Cancel();
                _mediaCts = new CancellationTokenSource();
                var ok = await EnsureVlc()
                    .PlayAsync(staged, _mediaNeedsVideo, _mediaCts.Token)
                    .ConfigureAwait(true);
                if (!ok)
                {
                    MediaEmpty.Visibility = Visibility.Visible;
                    MediaEmpty.Text = "VLC non ha avviato il media — prova Salva come… / Apri file.";
                    MediaVlcHost.Visibility = Visibility.Collapsed;
                }
            }
            else
            {
                MediaEmpty.Visibility = Visibility.Visible;
                MediaEmpty.Text = "Anteprima non disponibile — usa Salva come… o Apri file.";
            }
        }
        catch (Exception ex)
        {
            MediaEmpty.Visibility = Visibility.Visible;
            MediaEmpty.Text = "Errore media: " + ex.Message;
        }
    }

    private async void MediaPlay_OnClick(object sender, RoutedEventArgs e)
    {
        if (!string.IsNullOrWhiteSpace(_stagedMediaPath)
            && (_mediaNeedsVideo ? MediaVlcHost.Visibility == Visibility.Visible : true))
        {
            _mediaCts?.Cancel();
            _mediaCts = new CancellationTokenSource();
            try
            {
                if (_mediaNeedsVideo)
                    MediaVlcHost.Visibility = Visibility.Visible;
                var ok = await EnsureVlc()
                    .PlayAsync(_stagedMediaPath, _mediaNeedsVideo, _mediaCts.Token)
                    .ConfigureAwait(true);
                if (!ok)
                {
                    MediaEmpty.Visibility = Visibility.Visible;
                    MediaEmpty.Text = "VLC non ha avviato il media — prova Salva come… / Apri file.";
                }
            }
            catch (OperationCanceledException)
            {
                // superseded
            }
            catch (Exception ex)
            {
                MediaEmpty.Visibility = Visibility.Visible;
                MediaEmpty.Text = "Errore media: " + ex.Message;
            }
        }
        else if (MessageList.SelectedItem is ChatMessage msg)
            _ = ShowMediaAsync(msg);
    }

    private void MediaStop_OnClick(object sender, RoutedEventArgs e) => StopMedia();

    private void MediaSave_OnClick(object sender, RoutedEventArgs e)
    {
        var owner = Window.GetWindow(this);
        try
        {
            if (FileExport.TrySaveStagedOrShard(
                    _stagedMediaPath,
                    _shardMediaPath,
                    _preferredSaveName ?? "media.bin",
                    out var saved,
                    owner))
            {
                MediaInfo.Text = "Salvato:\n" + saved;
            }
        }
        catch (Exception ex)
        {
            MediaEmpty.Text = "Salvataggio fallito: " + ex.Message;
            MediaEmpty.Visibility = Visibility.Visible;
        }
    }

    private void MediaOpen_OnClick(object sender, RoutedEventArgs e)
    {
        var path = _stagedMediaPath;
        if (string.IsNullOrWhiteSpace(path) && !string.IsNullOrWhiteSpace(_shardMediaPath))
        {
            path = MediaStaging.StageWithExtension(_shardMediaPath, _preferredSaveName ?? "media.bin");
            _stagedMediaPath = path;
        }

        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return;

        try
        {
            Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MediaEmpty.Text = "Impossibile aprire: " + ex.Message;
            MediaEmpty.Visibility = Visibility.Visible;
        }
    }

    private void StopMedia()
    {
        _mediaCts?.Cancel();
        _vlc?.Stop();
    }

    private void ClearMediaPreview()
    {
        StopMedia();
        MediaImage.Source = null;
        MediaImage.Visibility = Visibility.Collapsed;
        MediaVlcHost.Visibility = Visibility.Collapsed;
        MediaEmpty.Visibility = Visibility.Visible;
        MediaEmpty.Text = "Nessuna anteprima.";
        MediaInfo.Text = "Seleziona un messaggio con allegato.";
        _stagedMediaPath = null;
        _shardMediaPath = null;
        _preferredSaveName = null;
        _mediaNeedsVideo = false;
    }
}
