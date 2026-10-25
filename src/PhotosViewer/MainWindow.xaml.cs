using System.Diagnostics;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Animation;
using PhotosViewer.Models;
using PhotosViewer.Services;

namespace PhotosViewer;

public partial class MainWindow : Window
{
    private static readonly int[] ZoomColumns = [3, 6, 9, 12];
    private const int ScrollBufferRows = 2;
    private const int MaxConcurrentThumbs = 10;

    private LibraryCatalog? _catalog;
    private FolderNode? _folder;
    private IReadOnlyList<MediaItem> _current = [];
    private MediaItem? _selected;
    private string? _previewVideoPath;
    private DateTime _lastClick;
    private MediaItem? _lastClickItem;

    private double _tileSize = 120;
    private int _decodePx = 160;
    private int _visibleFrom = -1;
    private int _visibleTo = -1;
    private CancellationTokenSource? _gridThumbCts;
    private CancellationTokenSource? _previewCts;
    private readonly Dictionary<int, TileVisual> _liveTiles = [];
    private int _gridGeneration;
    private int _filterGeneration;
    private int _gridRelayoutToken;
    private double _laidOutViewportW = -1;

    public MainWindow()
    {
        InitializeComponent();
        MapView.ItemSelected += ShowDetails;
        Loaded += (_, _) => _ = BootstrapAsync();
        Unloaded += (_, _) =>
        {
            _gridThumbCts?.Cancel();
            _previewCts?.Cancel();
        };
    }

    private async Task BootstrapAsync()
    {
        SubtitleText.Text = "Caricamento libreria…";
        FolderList.IsEnabled = false;
        ZoomSlider.IsEnabled = false;
        var sw = Stopwatch.StartNew();

        try
        {
            var result = await Task.Run(() =>
            {
                var t0 = Stopwatch.StartNew();
                var root = ResolveLibraryRoot();
                if (root is null)
                    return (Root: (string?)null, Catalog: (LibraryCatalog?)null);

                var loadSw = Stopwatch.StartNew();
                var catalog = LibraryCatalog.Load(root);
                return (Root: (string?)root, Catalog: (LibraryCatalog?)catalog);
            }).ConfigureAwait(true);


            if (result.Root is null || result.Catalog is null)
            {
                MessageBox.Show(
                    "Photos.db / cartella Sfoglia non trovati.\nAvvia il viewer dalla cartella photos del backup.",
                    "Libreria",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                SubtitleText.Text = "Libreria non trovata";
                return;
            }

            _catalog = result.Catalog;
            SubtitleText.Text = result.Root;
            PopulateAppFilter(_catalog);
            FolderList.ItemsSource = _catalog.Sidebar;
            if (_catalog.Sidebar.FirstOrDefault(static e => e is SidebarFolderEntry) is SidebarFolderEntry first)
                FolderList.SelectedItem = first;
        }
        finally
        {
            FolderList.IsEnabled = true;
            ZoomSlider.IsEnabled = _folder?.Kind != FolderKind.Mappa;
        }
    }

    private static string? ResolveLibraryRoot()
    {
        var args = Environment.GetCommandLineArgs();
        if (args.Length > 1 && Directory.Exists(args[1]) && LooksLikeLibrary(args[1]))
            return Path.GetFullPath(args[1]);

        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        for (var i = 0; i < 5 && dir is not null; i++, dir = dir.Parent)
        {
            if (LooksLikeLibrary(dir.FullName))
                return dir.FullName;
        }

        return null;
    }

    private static bool LooksLikeLibrary(string path) =>
        File.Exists(Path.Combine(path, "Photos.db"))
        || Directory.Exists(Path.Combine(path, "Sfoglia"));

    private void PopulateAppFilter(LibraryCatalog catalog)
    {
        AppFilter.SelectionChanged -= Filter_OnChanged;
        try
        {
            AppFilter.Items.Clear();
            AppFilter.Items.Add(new ComboBoxItem { Content = "Tutte", Tag = "" });
            foreach (var name in catalog.AppDisplayNames)
                AppFilter.Items.Add(new ComboBoxItem { Content = name, Tag = name });
            AppFilter.SelectedIndex = 0;
        }
        finally
        {
            AppFilter.SelectionChanged += Filter_OnChanged;
        }
    }

    private int CurrentColumns =>
        ZoomColumns[Math.Clamp((int)Math.Round(ZoomSlider.Value), 0, ZoomColumns.Length - 1)];

    private void ZoomSlider_OnValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e)
    {
        if (ZoomLabel is null)
            return;
        ZoomLabel.Text = $"{CurrentColumns}×N";
        ResetVirtualGrid();
    }

    private void FolderList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (FolderList.SelectedItem is SidebarSectionHeader)
        {
            if (e.RemovedItems.Count > 0)
                FolderList.SelectedItem = e.RemovedItems[0];
            return;
        }

        if (FolderList.SelectedItem is not SidebarFolderEntry { Folder: var folder } || _catalog is null)
            return;
        _folder = folder;
        var mapMode = folder.Kind == FolderKind.Mappa;
        GridScroller.Visibility = mapMode ? Visibility.Collapsed : Visibility.Visible;
        MapView.Visibility = mapMode ? Visibility.Visible : Visibility.Collapsed;
        GridFilters.Visibility = mapMode ? Visibility.Collapsed : Visibility.Visible;
        MapFilters.Visibility = mapMode ? Visibility.Visible : Visibility.Collapsed;
        ZoomSlider.IsEnabled = !mapMode;
        _ = ApplyFiltersAndRefreshAsync();
    }

    private void Filter_OnChanged(object sender, EventArgs e) => _ = ApplyFiltersAndRefreshAsync();

    private void GridScroller_OnSizeChanged(object sender, SizeChangedEventArgs e)
    {
        if (!e.WidthChanged && !e.HeightChanged)
            return;
        ScheduleGridRelayout("SizeChanged");
    }

    private void GridScroller_OnScrollChanged(object sender, ScrollChangedEventArgs e)
    {
        // Il resize orizzontale aggiorna ViewportWidth qui; SizeChanged spesso vede ancora il vecchio valore.
        if (Math.Abs(e.ViewportWidthChange) > 0.5)
        {
            ScheduleGridRelayout("ViewportWidth");
            return;
        }

        if (e.VerticalChange != 0 || e.ViewportHeightChange != 0 || e.ExtentHeightChange != 0)
            RefreshVisibleWindow();
    }

    private void ScheduleGridRelayout(string reason)
    {
        var token = ++_gridRelayoutToken;
        // Dopo il layout pass ViewportWidth è aggiornato (Loaded/ContextIdle).
        Dispatcher.BeginInvoke(new Action(() =>
        {
            if (token != _gridRelayoutToken)
                return;
            ResetVirtualGrid();
        }), System.Windows.Threading.DispatcherPriority.Loaded);
    }

    private void ApplyFiltersAndRefresh() => _ = ApplyFiltersAndRefreshAsync();

    private async Task ApplyFiltersAndRefreshAsync()
    {
        if (_catalog is null || _folder is null)
            return;

        var gen = ++_filterGeneration;
        var catalog = _catalog;
        var folder = _folder;
        var mapMode = folder.Kind == FolderKind.Mappa;
        var mapType = MapTypeFilter.SelectedIndex;
        var mapFrom = MapFromDate.SelectedDate;
        var mapTo = MapToDate.SelectedDate;
        var gridFrom = FromDate.SelectedDate;
        var gridTo = ToDate.SelectedDate;
        var sizeIdx = SizeFilter.SelectedIndex;
        var appTag = (AppFilter.SelectedItem as ComboBoxItem)?.Tag as string
                     ?? (AppFilter.SelectedItem as ComboBoxItem)?.Content as string
                     ?? "";
        if (AppFilter.SelectedIndex <= 0)
            appTag = "";

        if (mapMode)
            MapResultCount.Text = "Filtro…";
        else
            ResultCount.Text = "Filtro…";

        var sw = Stopwatch.StartNew();

        var list = await Task.Run(() =>
        {

            IEnumerable<MediaItem> q = catalog.ItemsFor(folder);

            if (!string.IsNullOrWhiteSpace(appTag))
            {
                q = q.Where(m => string.Equals(
                    m.AppDisplayName, appTag, StringComparison.OrdinalIgnoreCase));
            }

            if (mapMode)
            {
                q = mapType switch
                {
                    1 => q.Where(static m => !m.IsVideo),
                    2 => q.Where(static m => m.IsVideo),
                    _ => q
                };
                if (mapFrom is { } from)
                    q = q.Where(m => m.ShotDate?.Date >= from.Date);
                if (mapTo is { } to)
                    q = q.Where(m => m.ShotDate?.Date <= to.Date);
            }
            else
            {
                if (gridFrom is { } gFrom)
                    q = q.Where(m => m.ShotDate?.Date >= gFrom.Date);
                if (gridTo is { } gTo)
                    q = q.Where(m => m.ShotDate?.Date <= gTo.Date);

                q = sizeIdx switch
                {
                    1 => q.Where(static m => m.SizeBytes < 500 * 1024),
                    2 => q.Where(static m => m.SizeBytes is >= 500 * 1024 and < 2L * 1024 * 1024),
                    3 => q.Where(static m => m.SizeBytes is >= 2L * 1024 * 1024 and < 8L * 1024 * 1024),
                    4 => q.Where(static m => m.SizeBytes >= 8L * 1024 * 1024),
                    _ => q
                };
            }

            return q.ToList();
        }).ConfigureAwait(true);


        if (gen != _filterGeneration)
            return;

        _current = list;
        if (mapMode)
        {
            MapResultCount.Text = $"{_current.Count} sulla mappa";
            MapView.SetItems(_current);
        }
        else
        {
            ResultCount.Text = $"{_current.Count} elementi";
            ResetVirtualGrid();
        }
    }

    private void ResetVirtualGrid()
    {
        if (TileHost is null || GridScroller is null)
            return;
        if (_folder?.Kind == FolderKind.Mappa)
            return;

        var cols = Math.Max(1, CurrentColumns);
        var viewport = GridScroller.ViewportWidth;
        if (viewport < 40)
            viewport = Math.Max(GridScroller.ActualWidth - SystemParameters.VerticalScrollBarWidth, 400);
        if (viewport < 40)
            viewport = 400;

        _gridThumbCts?.Cancel();
        _gridThumbCts = new CancellationTokenSource();
        _gridGeneration++;
        _liveTiles.Clear();
        TileHost.Children.Clear();
        _visibleFrom = -1;
        _visibleTo = -1;
        _laidOutViewportW = viewport;

        const double gap = 2;
        _tileSize = Math.Max(72, (viewport - 4) / cols - gap);
        // Decode più basso a zoom denso: griglia snella, thmb HEIC / cache disco.
        _decodePx = cols >= 9
            ? (int)Math.Clamp(_tileSize * 1.1, 72, 160)
            : (int)Math.Clamp(_tileSize * 1.25, 96, 240);

        var rows = _current.Count == 0 ? 0 : (_current.Count + cols - 1) / cols;
        TileHost.Width = viewport;
        // Gap stile Foto iCloud: ~2px
        TileHost.Height = Math.Max(rows * (_tileSize + gap), GridScroller.ViewportHeight);


        RefreshVisibleWindow();
    }

    private void RefreshVisibleWindow()
    {
        if (TileHost is null || GridScroller is null || _folder?.Kind == FolderKind.Mappa)
            return;

        var cols = Math.Max(1, CurrentColumns);
        const double gap = 2;
        var rowH = _tileSize + gap;
        if (rowH < 1 || _current.Count == 0)
            return;

        var firstRow = Math.Max(0, (int)(GridScroller.VerticalOffset / rowH) - ScrollBufferRows);
        var visibleRows = (int)Math.Ceiling(GridScroller.ViewportHeight / rowH) + ScrollBufferRows * 2;
        var from = firstRow * cols;
        var to = Math.Min(_current.Count, from + Math.Max(visibleRows, 1) * cols);
        if (from == _visibleFrom && to == _visibleTo && _liveTiles.Count > 0)
            return;

        _visibleFrom = from;
        _visibleTo = to;
        var gen = _gridGeneration;

        foreach (var idx in _liveTiles.Keys.ToList())
        {
            if (idx >= from && idx < to)
                continue;
            TileHost.Children.Remove(_liveTiles[idx].Root);
            _liveTiles[idx].Cancel();
            _liveTiles.Remove(idx);
        }

        for (var i = from; i < to; i++)
        {
            if (_liveTiles.ContainsKey(i))
                continue;
            var tile = CreateTile(_current[i], i, cols, gen, gap);
            _liveTiles[i] = tile;
            TileHost.Children.Add(tile.Root);
        }

        _ = PumpVisibleThumbsAsync(gen, _gridThumbCts?.Token ?? CancellationToken.None);
    }

    private async Task PumpVisibleThumbsAsync(int generation, CancellationToken ct)
    {
        try
        {
            using var gate = new SemaphoreSlim(MaxConcurrentThumbs);
            var snapshot = _liveTiles.Values.ToList();
            var tasks = snapshot.Select(async tile =>
            {
                if (tile.Image.Source is not null)
                    return;
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    if (generation != _gridGeneration || ct.IsCancellationRequested)
                        return;
                    var src = await ThumbnailLoader.LoadAsync(tile.Item.AbsolutePath, _decodePx, ct)
                        .ConfigureAwait(false);
                    if (src is null || generation != _gridGeneration)
                    {
                        await Dispatcher.InvokeAsync(() =>
                        {
                            if (generation == _gridGeneration)
                                tile.HideSpinner();
                        });
                        return;
                    }
                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (generation != _gridGeneration)
                            return;
                        tile.Image.Source = src;
                        tile.HideSpinner();
                    });
                }
                catch (OperationCanceledException)
                {
                    // ignore
                }
                finally
                {
                    gate.Release();
                }
            });
            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // ignore
        }
    }

    private TileVisual CreateTile(MediaItem item, int index, int cols, int generation, double gap)
    {
        var col = index % cols;
        var row = index / cols;
        var image = new Image { Stretch = Stretch.UniformToFill, SnapsToDevicePixels = true };
        var spinner = BuildTileSpinner(_tileSize);

        var grid = new Grid { Background = new SolidColorBrush(Color.FromRgb(0xF5, 0xF5, 0xF7)) };
        grid.Children.Add(image);
        grid.Children.Add(spinner);
        if (item.IsVideo)
        {
            grid.Children.Add(new Border
            {
                Background = new SolidColorBrush(Color.FromArgb(0x88, 0x00, 0x00, 0x00)),
                IsHitTestVisible = false,
                Child = new TextBlock
                {
                    Text = "▶",
                    Foreground = Brushes.White,
                    FontSize = Math.Clamp(_tileSize * 0.18, 14, 28),
                    HorizontalAlignment = HorizontalAlignment.Center,
                    VerticalAlignment = VerticalAlignment.Center
                }
            });
        }

        var border = new Border
        {
            Width = _tileSize,
            Height = _tileSize,
            CornerRadius = new CornerRadius(2),
            Background = new SolidColorBrush(Color.FromRgb(0xF5, 0xF5, 0xF7)),
            BorderThickness = new Thickness(0),
            Cursor = Cursors.Hand,
            Child = grid,
            Tag = item,
            ToolTip = item.FileName
        };
        Canvas.SetLeft(border, col * (_tileSize + gap));
        Canvas.SetTop(border, row * (_tileSize + gap));
        border.MouseLeftButtonUp += Tile_OnClick;

        return new TileVisual(item, border, image, spinner, generation);
    }

    private static FrameworkElement BuildTileSpinner(double tileSize)
    {
        var size = Math.Clamp(tileSize * 0.28, 18, 40);
        var ring = new System.Windows.Shapes.Ellipse
        {
            Width = size,
            Height = size,
            StrokeThickness = Math.Max(2.0, size / 9.0),
            Stroke = new SolidColorBrush(Color.FromRgb(0x00, 0x71, 0xE3)),
            StrokeDashArray = new DoubleCollection { 1.6, 1.2 },
            Fill = Brushes.Transparent,
            IsHitTestVisible = false
        };
        var rotate = new RotateTransform();
        ring.RenderTransform = rotate;
        ring.RenderTransformOrigin = new Point(0.5, 0.5);
        rotate.BeginAnimation(
            RotateTransform.AngleProperty,
            new DoubleAnimation(0, 360, new Duration(TimeSpan.FromSeconds(0.85)))
            {
                RepeatBehavior = RepeatBehavior.Forever
            });

        return new Grid
        {
            Width = size,
            Height = size,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            IsHitTestVisible = false,
            Children = { ring }
        };
    }

    private void Tile_OnClick(object sender, MouseButtonEventArgs e)
    {
        if (sender is not FrameworkElement { Tag: MediaItem item })
            return;

        var now = DateTime.UtcNow;
        if (_lastClickItem == item && (now - _lastClick).TotalMilliseconds < 350)
            MediaFileOpener.TryOpen(item.AbsolutePath);
        else
            ShowDetails(item);

        _lastClick = now;
        _lastClickItem = item;
    }

    private void ShowDetails(MediaItem item)
    {
        _selected = item;
        DetailTitle.Text = item.FileName;

        var lines = new List<string>
        {
            $"Percorso: {item.RelativePath}",
            $"Dimensione: {FormatSize(item.SizeBytes)}",
            $"Estensione: {item.Extension}"
        };
        if (!string.IsNullOrWhiteSpace(item.AppDisplayName) || !string.IsNullOrWhiteSpace(item.BundleId))
            lines.Add($"App: {item.AppDisplayName ?? "—"} ({item.BundleId ?? "—"})");
        if (item.TakenAt is { } taken)
            lines.Add($"Data scatto/registrazione: {taken.ToLocalTime():yyyy-MM-dd HH:mm:ss}");
        if (item.HasGeo)
            lines.Add($"Coordinate: {item.Latitude:0.######}, {item.Longitude:0.######}");
        if (!string.IsNullOrWhiteSpace(item.Sha256))
            lines.Add($"SHA-256: {item.Sha256}");
        if (item.IsLive)
            lines.Add("Live Photo companion");
        if (item.Trashed)
            lines.Add("Eliminato");
        if (item.Hidden)
            lines.Add("Nascosto");
        if (item.Favorite)
            lines.Add("Preferito");
        DetailProps.Text = string.Join("\n", lines);

        var downloadMeta = item.Metadata
            .OrderBy(static kv => kv.Key, StringComparer.OrdinalIgnoreCase)
            .Select(static kv => new MetaKv(kv.Key, kv.Value))
            .ToList();
        if (item.HasGeo)
        {
            downloadMeta.Insert(0, new MetaKv("lon", item.Longitude!.Value.ToString("0.######")));
            downloadMeta.Insert(0, new MetaKv("lat", item.Latitude!.Value.ToString("0.######")));
        }

        if (!string.IsNullOrWhiteSpace(item.AppDisplayName))
            downloadMeta.Insert(0, new MetaKv("appDisplayName", item.AppDisplayName));
        if (!string.IsNullOrWhiteSpace(item.BundleId))
            downloadMeta.Insert(0, new MetaKv("bundleId", item.BundleId));

        DownloadMetaList.ItemsSource = downloadMeta;
        DownloadHeaderText.Text = $"Metadati download ({downloadMeta.Count})";

        ExifHeaderText.Text = "Metadati EXIF…";
        ExifMetaList.ItemsSource = Array.Empty<MetaKv>();

        _previewCts?.Cancel();
        _previewCts = new CancellationTokenSource();
        var ct = _previewCts.Token;

        PreviewVideo.Stop();
        PreviewVideo.Source = null;
        PreviewVideo.Visibility = Visibility.Collapsed;
        PreviewImage.Visibility = Visibility.Visible;
        PreviewImage.Source = null;
        PreviewPlayOverlay.Visibility = Visibility.Collapsed;
        _previewVideoPath = null;

        _ = LoadExifAsync(item.AbsolutePath, ct);

        var videoPath = MediaPreviewHelper.GetInlineVideoPath(item);
        if (videoPath is not null)
        {
            _previewVideoPath = videoPath;
            PreviewVideo.Visibility = Visibility.Collapsed;
            PreviewImage.Visibility = Visibility.Visible;
            PreviewVideo.Source = new Uri(videoPath);
            PreviewVideo.Position = TimeSpan.Zero;
            PreviewVideo.Stop();
            PreviewPlayOverlay.Visibility = Visibility.Visible;
            PreviewPlayHint.Text = item.IsLive && !item.IsVideo
                ? "Clic per Live Photo"
                : "Clic per riprodurre";
        }

        _ = LoadPreviewAsync(item.AbsolutePath, ct);
    }

    private void StartPreviewVideo()
    {
        if (_previewVideoPath is null)
            return;
        PreviewVideo.Visibility = Visibility.Visible;
        PreviewImage.Visibility = Visibility.Collapsed;
        PreviewPlayOverlay.Visibility = Visibility.Collapsed;
        if (PreviewVideo.Source is null)
            PreviewVideo.Source = new Uri(_previewVideoPath);
        PreviewVideo.Play();
    }

    private void StopPreviewVideo()
    {
        PreviewVideo.Stop();
        PreviewVideo.Position = TimeSpan.Zero;
        PreviewVideo.Visibility = Visibility.Collapsed;
        PreviewImage.Visibility = Visibility.Visible;
        if (_previewVideoPath is not null)
            PreviewPlayOverlay.Visibility = Visibility.Visible;
    }

    private async Task LoadExifAsync(string path, CancellationToken ct)
    {
        try
        {
            var entries = await ExifMetadataReader.ReadAsync(path, ct).ConfigureAwait(false);
            if (ct.IsCancellationRequested)
                return;
            var items = entries.Select(static e => new MetaKv(e.Key, e.Value)).ToList();
            await Dispatcher.InvokeAsync(() =>
            {
                if (ct.IsCancellationRequested)
                    return;
                ExifMetaList.ItemsSource = items;
                ExifHeaderText.Text = items.Count == 0
                    ? "Metadati EXIF (nessuno)"
                    : $"Metadati EXIF ({items.Count})";
            });
        }
        catch (OperationCanceledException)
        {
            // ignore
        }
        catch
        {
            await Dispatcher.InvokeAsync(() =>
            {
                if (!ct.IsCancellationRequested)
                    ExifHeaderText.Text = "Metadati EXIF (errore lettura)";
            });
        }
    }

    private async Task LoadPreviewAsync(string path, CancellationToken ct)
    {
        try
        {
            var src = await ThumbnailLoader.LoadAsync(path, 640, ct).ConfigureAwait(false);
            if (src is null || ct.IsCancellationRequested)
                return;
            await Dispatcher.InvokeAsync(() =>
            {
                if (ct.IsCancellationRequested)
                    return;
                // Sempre mostra il frame (anche per video/Live): overlay play sopra.
                PreviewImage.Source = src;
                if (_previewVideoPath is not null && PreviewVideo.Visibility != Visibility.Visible)
                    PreviewImage.Visibility = Visibility.Visible;
            });
        }
        catch (OperationCanceledException)
        {
            // ignore
        }
    }

    private void PreviewVideo_OnMediaEnded(object sender, RoutedEventArgs e) => StopPreviewVideo();

    private void Preview_OnMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
    {
        if (_selected is null)
            return;

        if (e.ClickCount >= 2)
        {
            var openPath = MediaPreviewHelper.GetInlineVideoPath(_selected) ?? _selected.AbsolutePath;
            MediaFileOpener.TryOpen(openPath);
            e.Handled = true;
            return;
        }

        if (e.ClickCount == 1 && _previewVideoPath is not null)
        {
            StartPreviewVideo();
            e.Handled = true;
        }
    }

    private static string FormatSize(long bytes)
    {
        if (bytes < 1024)
            return $"{bytes} B";
        if (bytes < 1024 * 1024)
            return $"{bytes / 1024.0:0.#} KB";
        if (bytes < 1024L * 1024 * 1024)
            return $"{bytes / (1024.0 * 1024):0.##} MB";
        return $"{bytes / (1024.0 * 1024 * 1024):0.##} GB";
    }

    private sealed record MetaKv(string Key, string Value);

    private sealed class TileVisual
    {
        public MediaItem Item { get; }
        public Border Root { get; }
        public Image Image { get; }
        public FrameworkElement Spinner { get; }
        public int Generation { get; }
        private readonly CancellationTokenSource _cts = new();

        public TileVisual(MediaItem item, Border root, Image image, FrameworkElement spinner, int generation)
        {
            Item = item;
            Root = root;
            Image = image;
            Spinner = spinner;
            Generation = generation;
        }

        public void HideSpinner()
        {
            Spinner.Visibility = Visibility.Collapsed;
            if (Spinner.RenderTransform is RotateTransform rot)
                rot.BeginAnimation(RotateTransform.AngleProperty, null);
            else if (Spinner is Panel { Children.Count: > 0 } panel
                     && panel.Children[0].RenderTransform is RotateTransform childRot)
                childRot.BeginAnimation(RotateTransform.AngleProperty, null);
        }

        public void Cancel() => _cts.Cancel();
    }
}
