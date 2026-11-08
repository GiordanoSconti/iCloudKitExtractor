using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using BackupViewer.Models;
using BackupViewer.Services;
using Microsoft.Win32;

namespace BackupViewer;

public partial class MainWindow : Window
{
    private BackupCatalog? _catalog;
    private CoreDataService? _core;
    private NavNode? _currentNav;
    private ModuleKind _module = ModuleKind.Overview;
    private CancellationTokenSource? _previewCts;
    private CancellationTokenSource? _loadCts;
    private CancellationTokenSource? _sqliteCts;
    private string _search = "";
    private string? _activeSqlitePath;
    private BackupFileEntry? _previewEntry;
    private string? _previewStagedPath;
    private bool _previewNeedsVideo;
    private CancellationTokenSource? _mediaCts;
    private readonly ObservableCollection<ModuleNavItem> _modules = [];
    private IMediaPlayback? _vlc;

    public MainWindow()
    {
        InitializeComponent();
        BuildModuleList();
        ModuleList.ItemsSource = _modules;
        Loaded += (_, _) => _ = OnWindowLoadedAsync();
        Closed += (_, _) =>
        {
            _previewCts?.Cancel();
            _loadCts?.Cancel();
            _sqliteCts?.Cancel();
            _mediaCts?.Cancel();
            StopMedia();
            _vlc?.Dispose();
            _vlc = null;
        };
    }

    private async Task OnWindowLoadedAsync()
    {
        // Mostra la UI subito; VLC e backup automatico dopo.
        await System.Windows.Threading.Dispatcher.Yield(
            System.Windows.Threading.DispatcherPriority.Background);
        _ = MediaPlaybackFactory.WarmupSafeAsync();
        await BootstrapAsync().ConfigureAwait(true);
    }

    private IMediaPlayback EnsureVlc()
    {
        if (_vlc is not null)
            return _vlc;
        _vlc = MediaPlaybackFactory.TryCreate(PreviewMediaHost, out var error)
               ?? throw new InvalidOperationException(
                   error ?? MediaPlaybackFactory.LastLoadError
                   ?? "Motore media VLC non disponibile.");
        return _vlc;
    }

    private void BuildModuleList()
    {
        _modules.Clear();
        // Glyphs: Segoe MDL2 Assets
        _modules.Add(new ModuleNavItem { Kind = ModuleKind.Overview, Title = "Overview", Glyph = "\uE80F" });
        _modules.Add(new ModuleNavItem { Kind = ModuleKind.Chat, Title = "Chat", Glyph = "\uE8F2" });
        _modules.Add(new ModuleNavItem { Kind = ModuleKind.Calls, Title = "Chiamate", Glyph = "\uE717" });
        _modules.Add(new ModuleNavItem { Kind = ModuleKind.Calendar, Title = "Calendario", Glyph = "\uE787" });
        _modules.Add(new ModuleNavItem { Kind = ModuleKind.Contacts, Title = "Contatti", Glyph = "\uE77B" });
        _modules.Add(new ModuleNavItem { Kind = ModuleKind.Files, Title = "File", Glyph = "\uE8B7" });
    }

    private async Task BootstrapAsync()
    {
        var auto = BackupPaths.TryFindFromArgsOrCwd();
        if (auto is not null)
            await LoadBackupAsync(auto).ConfigureAwait(true);
    }

    private async void OpenBackup_OnClick(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Seleziona cartella Backup (con Manifest.db)",
        };
        if (dlg.ShowDialog(this) != true)
            return;

        var root = BackupPaths.ResolveBackupRoot(dlg.FolderName);
        if (root is null)
        {
            MessageBox.Show(
                this,
                "Manifest.db non trovato nella cartella (né in Backup/).",
                "Backup Viewer",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        await LoadBackupAsync(root).ConfigureAwait(true);
    }

    private async Task LoadBackupAsync(string backupRoot)
    {
        _loadCts?.Cancel();
        _loadCts = new CancellationTokenSource();
        var ct = _loadCts.Token;

        StatusLeft.Text = "Lettura Manifest.db…";
        PathLabel.Text = backupRoot;
        NavTree.ItemsSource = null;
        PathTree.ItemsSource = null;
        _core = null;
        ClearPreview();
        IsEnabled = false;

        try
        {
            var catalog = await Task.Run(() => BackupCatalog.Load(backupRoot), ct)
                .ConfigureAwait(true);
            ct.ThrowIfCancellationRequested();

            StatusLeft.Text = "Parsing dati personali…";
            var core = await Task.Run(() =>
            {
                var svc = new CoreDataService(catalog);
                svc.Load();
                return svc;
            }, ct).ConfigureAwait(true);
            ct.ThrowIfCancellationRequested();

            _catalog = catalog;
            _core = core;
            UpdatePersonalNavCounts(catalog, core);
            RefreshModuleCounts(core, catalog);
            NavTree.ItemsSource = catalog.Navigation;
            StatusRight.Text =
                $"file={catalog.FileCount:N0}  presenti={catalog.PresentCount:N0}  missing={catalog.MissingCount:N0}";
            StatusLeft.Text = "Catalogo pronto";

            SelectModule(ModuleKind.Overview);
        }
        catch (OperationCanceledException)
        {
            StatusLeft.Text = "Caricamento annullato";
        }
        catch (Exception ex)
        {
            StatusLeft.Text = "Errore caricamento";
            MessageBox.Show(this, ex.Message, "Backup Viewer", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            IsEnabled = true;
        }
    }

    private void RefreshModuleCounts(CoreDataService core, BackupCatalog catalog)
    {
        var selected = (ModuleList.SelectedItem as ModuleNavItem)?.Kind ?? ModuleKind.Overview;
        BuildModuleList();
        foreach (var m in _modules)
        {
            m.Count = m.Kind switch
            {
                ModuleKind.Chat => core.Snapshot.ChatSources.Sum(static s => s.Conversations.Count),
                ModuleKind.Calls => core.Snapshot.Calls.Count,
                ModuleKind.Calendar => core.Snapshot.Events.Count,
                ModuleKind.Contacts => core.Snapshot.Contacts.Count,
                ModuleKind.Files => catalog.FileCount,
                _ => 0,
            };
        }

        ModuleList.ItemsSource = null;
        ModuleList.ItemsSource = _modules;
        ModuleList.SelectedItem = _modules.FirstOrDefault(m => m.Kind == selected);
    }

    private static void UpdatePersonalNavCounts(BackupCatalog catalog, CoreDataService core)
    {
        var personal = catalog.Navigation.FirstOrDefault(static n => n.Title == "Dati personali");
        if (personal is null)
            return;
        foreach (var child in personal.Children)
        {
            child.Count = child.FilterKind switch
            {
                NavFilterKind.CoreChat => core.Snapshot.ChatSources.Sum(static s => s.Conversations.Count),
                NavFilterKind.CoreCalls => core.Snapshot.Calls.Count,
                NavFilterKind.CoreCalendar => core.Snapshot.Events.Count,
                NavFilterKind.CoreContacts => core.Snapshot.Contacts.Count,
                _ => 0,
            };
        }
    }

    private void ModuleList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ModuleList.SelectedItem is ModuleNavItem item)
            ShowModule(item.Kind);
    }

    private void Overview_OnModuleRequested(ModuleKind kind) => SelectModule(kind);

    private void SelectModule(ModuleKind kind)
    {
        var item = _modules.FirstOrDefault(m => m.Kind == kind);
        if (item is null)
            return;
        if (Equals(ModuleList.SelectedItem, item))
            ShowModule(kind);
        else
            ModuleList.SelectedItem = item;
    }

    private void ShowModule(ModuleKind kind)
    {
        _module = kind;
        OverviewPanel.Visibility = Visibility.Collapsed;
        CoreHost.Visibility = Visibility.Collapsed;
        FilesHost.Visibility = Visibility.Collapsed;
        ChatPanel.Visibility = Visibility.Collapsed;
        CallsPanel.Visibility = Visibility.Collapsed;
        CalendarPanel.Visibility = Visibility.Collapsed;
        ContactsPanel.Visibility = Visibility.Collapsed;

        if (_catalog is null)
            return;

        switch (kind)
        {
            case ModuleKind.Overview:
                if (_core is not null)
                {
                    OverviewPanel.Visibility = Visibility.Visible;
                    OverviewPanel.Bind(_catalog, _core);
                    StatusLeft.Text = "Overview";
                }
                break;

            case ModuleKind.Chat:
                ShowCore(NavFilterKind.CoreChat);
                break;
            case ModuleKind.Calls:
                ShowCore(NavFilterKind.CoreCalls);
                break;
            case ModuleKind.Calendar:
                ShowCore(NavFilterKind.CoreCalendar);
                break;
            case ModuleKind.Contacts:
                ShowCore(NavFilterKind.CoreContacts);
                break;

            case ModuleKind.Files:
                FilesHost.Visibility = Visibility.Visible;
                var fs = _catalog.Navigation.FirstOrDefault(static n => n.FilterKind == NavFilterKind.FileSystem)
                         ?? new NavNode { Title = "FileSystem", FilterKind = NavFilterKind.FileSystem };
                ApplyNav(fs);
                break;
        }
    }

    private void ShowCore(NavFilterKind kind)
    {
        if (_core is null)
            return;

        StopMedia();
        CoreHost.Visibility = Visibility.Visible;

        switch (kind)
        {
            case NavFilterKind.CoreChat:
                ChatPanel.Visibility = Visibility.Visible;
                ChatPanel.Bind(_core);
                ChatPanel.ApplySearch(_search);
                StatusLeft.Text =
                    $"Chat · {_core.Snapshot.ChatSources.Sum(static s => s.Conversations.Count):N0} conversazioni";
                break;
            case NavFilterKind.CoreCalls:
                CallsPanel.Visibility = Visibility.Visible;
                CallsPanel.Bind(_core);
                CallsPanel.ApplySearch(_search);
                StatusLeft.Text = $"Chiamate · {_core.Snapshot.Calls.Count:N0}";
                break;
            case NavFilterKind.CoreCalendar:
                CalendarPanel.Visibility = Visibility.Visible;
                CalendarPanel.Bind(_core);
                CalendarPanel.ApplySearch(_search);
                StatusLeft.Text = $"Calendario · {_core.Snapshot.Events.Count:N0} eventi";
                break;
            case NavFilterKind.CoreContacts:
                ContactsPanel.Visibility = Visibility.Visible;
                ContactsPanel.Bind(_core);
                ContactsPanel.ApplySearch(_search);
                StatusLeft.Text = $"Contatti · {_core.Snapshot.Contacts.Count:N0}";
                break;
        }

        if (_core.Snapshot.Notes.Count > 0)
            StatusRight.Text = string.Join(" · ", _core.Snapshot.Notes.Take(2));
    }

    private void NavTree_OnSelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is NavNode node)
            ApplyNav(node);
    }

    private void ApplyNav(NavNode node)
    {
        if (_catalog is null || _module != ModuleKind.Files)
            return;

        // Core nav nodes inside the files tree still open personal modules
        if (node.FilterKind is NavFilterKind.CoreChat or NavFilterKind.CoreCalls
            or NavFilterKind.CoreCalendar or NavFilterKind.CoreContacts)
        {
            SelectModule(node.FilterKind switch
            {
                NavFilterKind.CoreChat => ModuleKind.Chat,
                NavFilterKind.CoreCalls => ModuleKind.Calls,
                NavFilterKind.CoreCalendar => ModuleKind.Calendar,
                _ => ModuleKind.Contacts,
            });
            return;
        }

        _currentNav = node;
        var files = _catalog.Filter(node);
        ObservableCollection<PathNode> tree;

        if (node.FilterKind == NavFilterKind.FileSystem)
            tree = PathTreeBuilder.BuildFileSystem(files, _search);
        else if (_catalog.UsesPathTree(node))
            tree = PathTreeBuilder.BuildForDomain(files, _search);
        else
            tree = PathTreeBuilder.BuildFlatFiles(files, _search);

        PathTree.ItemsSource = tree;
        var count = files.Count(f =>
            string.IsNullOrWhiteSpace(_search)
            || f.RelativePath.Contains(_search, StringComparison.OrdinalIgnoreCase)
            || f.Domain.Contains(_search, StringComparison.OrdinalIgnoreCase)
            || f.DisplayName.Contains(_search, StringComparison.OrdinalIgnoreCase)
            || f.FileId.Contains(_search, StringComparison.OrdinalIgnoreCase));
        ListHeader.Text = $"{node.Title.ToUpperInvariant()} · {count:N0}";
        StatusLeft.Text = $"Struttura: {count:N0} file";
    }

    private void SearchBox_OnTextChanged(object sender, TextChangedEventArgs e)
    {
        _search = SearchBox.Text ?? "";
        if (_core is null)
            return;

        switch (_module)
        {
            case ModuleKind.Chat:
                ChatPanel.ApplySearch(_search);
                break;
            case ModuleKind.Calls:
                CallsPanel.ApplySearch(_search);
                break;
            case ModuleKind.Calendar:
                CalendarPanel.ApplySearch(_search);
                break;
            case ModuleKind.Contacts:
                ContactsPanel.ApplySearch(_search);
                break;
            case ModuleKind.Files when _currentNav is not null:
                ApplyNav(_currentNav);
                break;
            case ModuleKind.Files:
                ApplyNav(new NavNode { Title = "FileSystem", FilterKind = NavFilterKind.FileSystem });
                break;
        }
    }

    private async void PathTree_OnSelectedItemChanged(object sender, RoutedPropertyChangedEventArgs<object> e)
    {
        if (e.NewValue is not PathNode node)
            return;
        if (node.IsDirectory || node.File is null)
            return;
        await ShowPreviewAsync(node.File).ConfigureAwait(true);
    }

    private async Task ShowPreviewAsync(BackupFileEntry entry)
    {
        _previewCts?.Cancel();
        _previewCts = new CancellationTokenSource();
        var ct = _previewCts.Token;

        StopMedia();
        HideAllPreviewSurfaces();
        _previewEntry = entry;
        _previewStagedPath = null;
        SaveFileButton.Visibility = entry.ExistsOnDisk && !entry.IsDirectory
            ? Visibility.Visible
            : Visibility.Collapsed;
        PreviewTitle.Text = $"{entry.Kind} · {entry.DisplayName}";
        StatusLeft.Text = "Anteprima…";

        try
        {
            var result = await PreviewService.BuildAsync(entry, ct).ConfigureAwait(true);
            ct.ThrowIfCancellationRequested();
            await ApplyPreviewAsync(result, ct).ConfigureAwait(true);
            StatusLeft.Text = result.Error is null ? "Anteprima ok" : "Anteprima con errori";
        }
        catch (OperationCanceledException)
        {
            // superseded
        }
        catch (Exception ex)
        {
            await ApplyPreviewAsync(PreviewResult.Fail(entry.DisplayName, ex.Message), CancellationToken.None)
                .ConfigureAwait(true);
            StatusLeft.Text = "Errore anteprima";
        }
    }

    private async Task ApplyPreviewAsync(PreviewResult result, CancellationToken ct)
    {
        PreviewTitle.Text = string.IsNullOrWhiteSpace(result.Title) ? "Anteprima" : result.Title;
        HideAllPreviewSurfaces();

        switch (result.Mode)
        {
            case PreviewMode.Image when result.Image is not null:
                PreviewImage.Source = result.Image;
                PreviewImageHost.Visibility = Visibility.Visible;
                break;

            case PreviewMode.Video when result.MediaPath is not null:
            case PreviewMode.Audio when result.MediaPath is not null:
                _previewStagedPath = result.MediaPath;
                _previewNeedsVideo = result.Mode == PreviewMode.Video;
                MediaControls.Visibility = Visibility.Visible;
                PreviewMediaHost.Visibility = _previewNeedsVideo ? Visibility.Visible : Visibility.Collapsed;
                await PlayPreviewMediaAsync(result.MediaPath, _previewNeedsVideo, ct).ConfigureAwait(true);
                break;

            case PreviewMode.Sqlite when result.SqlitePath is not null:
                PreviewSqliteHost.Visibility = Visibility.Visible;
                await LoadSqliteAsync(result.SqlitePath, ct).ConfigureAwait(true);
                break;

            case PreviewMode.Text:
            case PreviewMode.Status:
                PreviewText.Text = result.TextBody ?? result.Error ?? "";
                PreviewText.Visibility = Visibility.Visible;
                break;

            default:
                PreviewEmpty.Text = result.Error ?? "Nessuna anteprima.";
                PreviewEmpty.Visibility = Visibility.Visible;
                break;
        }
    }

    private async Task LoadSqliteAsync(string path, CancellationToken ct)
    {
        _sqliteCts?.Cancel();
        _sqliteCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var localCt = _sqliteCts.Token;
        _activeSqlitePath = path;
        SqliteTableList.ItemsSource = null;
        PreviewGrid.ItemsSource = null;
        SqliteStatus.Text = "Lettura schema…";

        try
        {
            var tables = await Task.Run(() => SqliteBrowser.ListTables(path), localCt)
                .ConfigureAwait(true);
            localCt.ThrowIfCancellationRequested();
            SqliteTableList.ItemsSource = tables;
            SqliteStatus.Text = tables.Count == 0
                ? "Nessuna tabella"
                : $"{tables.Count:N0} tabelle — seleziona una tabella";
            if (tables.Count > 0)
                SqliteTableList.SelectedIndex = 0;
        }
        catch (OperationCanceledException)
        {
            // ignore
        }
        catch (Exception ex)
        {
            SqliteStatus.Text = ex.Message;
        }
    }

    private async void SqliteTableList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (SqliteTableList.SelectedItem is not SqliteTableInfo table)
            return;
        if (string.IsNullOrWhiteSpace(_activeSqlitePath))
            return;

        _sqliteCts?.Cancel();
        _sqliteCts = new CancellationTokenSource();
        var ct = _sqliteCts.Token;
        var path = _activeSqlitePath;
        var name = table.Name;
        SqliteStatus.Text = $"Carico {name}…";
        PreviewGrid.ItemsSource = null;

        try
        {
            var view = await Task.Run(() => SqliteBrowser.LoadTable(path, name), ct)
                .ConfigureAwait(true);
            ct.ThrowIfCancellationRequested();
            PreviewGrid.ItemsSource = view;
            var shown = view.Count;
            var total = table.RowCount;
            SqliteStatus.Text = total >= 0 && total > shown
                ? $"{name}: {shown:N0}/{total:N0} righe (prime {shown:N0})"
                : $"{name}: {shown:N0} righe";
        }
        catch (OperationCanceledException)
        {
            // ignore
        }
        catch (Exception ex)
        {
            SqliteStatus.Text = ex.Message;
        }
    }

    private void HideAllPreviewSurfaces()
    {
        PreviewText.Visibility = Visibility.Collapsed;
        PreviewImageHost.Visibility = Visibility.Collapsed;
        PreviewMediaHost.Visibility = Visibility.Collapsed;
        PreviewSqliteHost.Visibility = Visibility.Collapsed;
        PreviewEmpty.Visibility = Visibility.Collapsed;
        MediaControls.Visibility = Visibility.Collapsed;
        PreviewImage.Source = null;
        PreviewGrid.ItemsSource = null;
        SqliteTableList.ItemsSource = null;
    }

    private async void MediaPlay_OnClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(_previewStagedPath))
            return;
        await PlayPreviewMediaAsync(_previewStagedPath, _previewNeedsVideo).ConfigureAwait(true);
    }

    private void MediaPause_OnClick(object sender, RoutedEventArgs e) => _vlc?.Pause();
    private void MediaStop_OnClick(object sender, RoutedEventArgs e) => StopMedia();

    private async Task PlayPreviewMediaAsync(string path, bool needsVideo, CancellationToken ct = default)
    {
        _mediaCts?.Cancel();
        _mediaCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var localCt = _mediaCts.Token;
        try
        {
            StatusLeft.Text = "Avvio media…";
            if (!await EnsureVlc().PlayAsync(path, needsVideo, localCt).ConfigureAwait(true))
                throw new InvalidOperationException("LibVLC non ha avviato il media.");
            StatusLeft.Text = "Media (VLC) in riproduzione";
        }
        catch (OperationCanceledException)
        {
            // superseded
        }
        catch (Exception ex)
        {
            PreviewText.Text =
                "Riproduzione VLC non riuscita:\n"
                + ex.Message + "\n" + path
                + "\nUsa «Salva come…» e apri con un player esterno.";
            PreviewText.Visibility = Visibility.Visible;
            MediaControls.Visibility = Visibility.Collapsed;
            PreviewMediaHost.Visibility = Visibility.Collapsed;
            StatusLeft.Text = "Errore media";
        }
    }

    private void SaveFile_OnClick(object sender, RoutedEventArgs e)
    {
        if (_previewEntry is null)
            return;
        try
        {
            if (FileExport.TrySaveStagedOrShard(
                    _previewStagedPath,
                    _previewEntry.AbsolutePath,
                    _previewEntry.DisplayName,
                    out var saved,
                    this))
            {
                StatusLeft.Text = "Salvato: " + saved;
            }
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Salva file", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void StopMedia()
    {
        _mediaCts?.Cancel();
        _vlc?.Stop();
    }

    private void ClearPreview()
    {
        StopMedia();
        _activeSqlitePath = null;
        _previewEntry = null;
        _previewNeedsVideo = false;
        _previewStagedPath = null;
        SaveFileButton.Visibility = Visibility.Collapsed;
        HideAllPreviewSurfaces();
        PreviewEmpty.Visibility = Visibility.Visible;
        PreviewEmpty.Text = "Apri un backup iTunes/IKE e seleziona un file.";
        PreviewTitle.Text = "Anteprima";
        PreviewText.Text = "";
    }
}
