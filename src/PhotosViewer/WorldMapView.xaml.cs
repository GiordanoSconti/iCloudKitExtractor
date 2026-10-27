using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Shapes;
using System.Windows.Threading;
using PhotosViewer.Models;
using PhotosViewer.Services;

namespace PhotosViewer;

public partial class WorldMapView : UserControl
{
    private const int CardW = 88;
    private const int CardH = 100;
    private const int ThumbDecode = 72;
    private const int MaxConcurrentThumbs = 4;
    private const int MaxThumbCards = 36;
    private const int ClusterCellPx = 72;
    private const double CullMargin = 80;
    private const int ZoomCardsFrom = 14;

    private static readonly SolidColorBrush AccentBrush = Freeze(Color.FromRgb(0x00, 0x71, 0xE3));
    private static readonly SolidColorBrush AccentSoftBrush = Freeze(Color.FromArgb(0xEE, 0x00, 0x71, 0xE3));
    private static readonly SolidColorBrush WhiteBrush = Brushes.White;
    private static readonly SolidColorBrush CardBg = Brushes.White;
    private static readonly SolidColorBrush CardBorder = Freeze(Color.FromRgb(0xD2, 0xD2, 0xD7));
    private static readonly SolidColorBrush CardBorderSel = AccentBrush;
    private static readonly SolidColorBrush NameFg = Freeze(Color.FromRgb(0x1D, 0x1D, 0x1F));
    private static readonly SolidColorBrush ThumbBg = Freeze(Color.FromRgb(0xF5, 0xF5, 0xF7));
    private static readonly SolidColorBrush DotStroke = Freeze(Color.FromArgb(0xCC, 0xFF, 0xFF, 0xFF));

    private IReadOnlyList<MediaItem> _items = [];
    private readonly List<MarkerVisual> _markers = [];
    private CancellationTokenSource? _thumbCts;
    private MediaItem? _selected;
    private DateTime _lastPinClick;
    private MediaItem? _lastPinClickItem;
    private int _layoutVersion;
    private SlippyMapLayer? _map;

    private bool _dragging;
    private Point _dragStart;
    private double _dragCenterLat;
    private double _dragCenterLon;
    private bool _viewInitialized;
    private bool _dirtyDuringDrag;
    private DispatcherTimer? _settleTimer;

    public event Action<MediaItem>? ItemSelected;

    public WorldMapView()
    {
        InitializeComponent();
        _map = new SlippyMapLayer(TileCanvas);
        AttributionText.Text = SlippyMapLayer.Attribution;
        SizeChanged += (_, _) => OnViewportChanged(resetView: false);
        Unloaded += (_, _) =>
        {
            _thumbCts?.Cancel();
            _settleTimer?.Stop();
        };
        _settleTimer = new DispatcherTimer(DispatcherPriority.Background)
        {
            Interval = TimeSpan.FromMilliseconds(120)
        };
        _settleTimer.Tick += (_, _) =>
        {
            _settleTimer.Stop();
            ApplyView(fullRebuild: true);
        };
    }

    public void SetItems(IReadOnlyList<MediaItem> items)
    {
        _items = items.Where(static m => m.HasGeo).ToList();
        EmptyHint.Visibility = _items.Count == 0 ? Visibility.Visible : Visibility.Collapsed;
        MapHost.Visibility = _items.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        ZoomInBtn.Visibility = _items.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        ZoomOutBtn.Visibility = _items.Count == 0 ? Visibility.Collapsed : Visibility.Visible;
        _viewInitialized = false;
        OnViewportChanged(resetView: true);
    }

    public void ClearSelection()
    {
        _selected = null;
        foreach (var m in _markers)
            m.SetSelected(false);
    }

    private void OnViewportChanged(bool resetView)
    {
        if (_map is null || ActualWidth < 10 || ActualHeight < 10)
            return;

        if (resetView || !_viewInitialized)
        {
            var geo = _items.Select(static m => (m.Latitude!.Value, m.Longitude!.Value)).ToList();
            _map.FitBounds(geo, ActualWidth, ActualHeight);
            _viewInitialized = true;
            ApplyView(fullRebuild: true);
            return;
        }

        _map.SetView(_map.Zoom, _map.CenterLat, _map.CenterLon, ActualWidth, ActualHeight);
        ScheduleSettle();
    }

    private void ScheduleSettle()
    {
        if (_settleTimer is null)
            return;
        _settleTimer.Stop();
        _settleTimer.Start();
    }

    private void ApplyView(bool fullRebuild)
    {
        if (_map is null)
            return;

        if (fullRebuild)
        {
            _map.RefreshTiles();
            RebuildMarkers();
        }
        else
        {
            _map.RepositionTiles();
            // marker positions stay correct relative to map center only after Rebuild;
            // during drag we use canvas TranslateTransform instead.
        }

        StatusHint.Text = _items.Count == 0
            ? ""
            : $"{_items.Count} geolocalizzati · {_markers.Count} sulla mappa · z{_map.Zoom}";
    }

    private void RebuildMarkers()
    {
        _layoutVersion++;
        var version = _layoutVersion;
        PinsCanvas.Children.Clear();
        PinsCanvas.RenderTransform = null;
        TileCanvas.RenderTransform = null;
        _markers.Clear();
        _thumbCts?.Cancel();
        _thumbCts = new CancellationTokenSource();

        if (_map is null || _items.Count == 0)
            return;

        var clusters = BuildClusters();
        var thumbBudget = MaxThumbCards;

        foreach (var cluster in clusters)
        {
            FrameworkElement root;
            MarkerVisual visual;

            if (cluster.Items.Count == 1)
            {
                var item = cluster.Items[0];
                var showCard = _map.Zoom >= ZoomCardsFrom && thumbBudget > 0;
                if (showCard)
                    thumbBudget--;

                root = showCard ? BuildCard(item) : BuildDot(item);
                visual = new MarkerVisual(item, root, isCluster: false, cluster.Items);
            }
            else
            {
                root = BuildClusterBubble(cluster.Items.Count, cluster.Items);
                visual = new MarkerVisual(cluster.Items[0], root, isCluster: true, cluster.Items);
            }

            Canvas.SetLeft(root, cluster.Screen.X - root.Width / 2.0);
            Canvas.SetTop(root, cluster.Screen.Y - root.Height / 2.0);
            PinsCanvas.Children.Add(root);
            _markers.Add(visual);

            if (_selected is not null
                && !visual.IsCluster
                && ReferenceEquals(_selected, visual.Item))
                visual.SetSelected(true);

            WireMarkerInput(visual);
        }

        _ = PumpThumbnailsAsync(version, _thumbCts.Token);
    }

    private List<Cluster> BuildClusters()
    {
        var result = new List<Cluster>();
        if (_map is null)
            return result;

        var w = ActualWidth;
        var h = ActualHeight;
        var cell = Math.Max(40, ClusterCellPx - Math.Max(0, _map.Zoom - 10) * 4);
        var buckets = new Dictionary<(int, int), Cluster>();

        foreach (var item in _items)
        {
            var pt = _map.LatLonToScreen(item.Latitude!.Value, item.Longitude!.Value);
            if (pt.X < -CullMargin || pt.Y < -CullMargin || pt.X > w + CullMargin || pt.Y > h + CullMargin)
                continue;

            // Zoom alto: niente cluster, un marker per punto (ancora cullati).
            if (_map.Zoom >= ZoomCardsFrom)
            {
                result.Add(new Cluster(pt, [item]));
                continue;
            }

            var cx = (int)Math.Floor(pt.X / cell);
            var cy = (int)Math.Floor(pt.Y / cell);
            if (!buckets.TryGetValue((cx, cy), out var cluster))
            {
                cluster = new Cluster(pt, []);
                buckets[(cx, cy)] = cluster;
            }

            cluster.Items.Add(item);
            // baricentro progressivo
            var n = cluster.Items.Count;
            cluster.Screen = new Point(
                (cluster.Screen.X * (n - 1) + pt.X) / n,
                (cluster.Screen.Y * (n - 1) + pt.Y) / n);
        }

        if (_map.Zoom < ZoomCardsFrom)
            result.AddRange(buckets.Values);

        return result;
    }

    private void WireMarkerInput(MarkerVisual visual)
    {
        visual.Root.MouseLeftButtonDown += (_, ev) =>
        {
            ev.Handled = true;
            if (visual.IsCluster)
            {
                ZoomIntoCluster(visual.Members);
                return;
            }

            var item = visual.Item;
            var now = DateTime.UtcNow;
            if (_lastPinClickItem == item && (now - _lastPinClick).TotalMilliseconds < 350)
            {
                MediaFileOpener.TryOpen(MediaPreviewHelper.GetInlineVideoPath(item) ?? item.AbsolutePath);
                return;
            }

            _selected = item;
            foreach (var m in _markers)
                m.SetSelected(!m.IsCluster && ReferenceEquals(m.Item, item));
            ItemSelected?.Invoke(item);
            _lastPinClick = now;
            _lastPinClickItem = item;
        };
    }

    private void ZoomIntoCluster(IReadOnlyList<MediaItem> members)
    {
        if (_map is null || members.Count == 0)
            return;

        var geo = members.Select(static m => (m.Latitude!.Value, m.Longitude!.Value)).ToList();
        _map.FitBounds(geo, ActualWidth, ActualHeight);
        if (_map.Zoom < ZoomCardsFrom)
            _map.ZoomAt(Math.Min(ZoomCardsFrom, _map.Zoom + 2), ActualWidth / 2.0, ActualHeight / 2.0);
        ApplyView(fullRebuild: true);
    }

    private void MapHost_OnMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (_map is null || _items.Count == 0)
            return;

        var pos = e.GetPosition(MapHost);
        var delta = e.Delta > 0 ? 1 : -1;
        _map.ZoomAt(_map.Zoom + delta, pos.X, pos.Y);
        ApplyView(fullRebuild: true);
        e.Handled = true;
    }

    private void MapHost_OnMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (_map is null || _items.Count == 0 || e.ChangedButton != MouseButton.Left)
            return;
        if (e.OriginalSource is FrameworkElement fe && fe.DataContext is MarkerVisual)
            return;
        // ignore clicks on markers (they handle MouseLeftButtonDown)
        if (FindMarkerRoot(e.OriginalSource as DependencyObject) is not null)
            return;

        _dragging = true;
        _dirtyDuringDrag = false;
        _dragStart = e.GetPosition(MapHost);
        _dragCenterLat = _map.CenterLat;
        _dragCenterLon = _map.CenterLon;
        MapHost.CaptureMouse();
        MapHost.Cursor = Cursors.SizeAll;
        e.Handled = true;
    }

    private static FrameworkElement? FindMarkerRoot(DependencyObject? src)
    {
        while (src is not null)
        {
            if (src is FrameworkElement { Tag: MediaItem or IReadOnlyList<MediaItem> } fe)
                return fe;
            src = VisualTreeHelper.GetParent(src);
        }

        return null;
    }

    private void MapHost_OnMouseMove(object sender, MouseEventArgs e)
    {
        if (!_dragging || _map is null)
            return;

        var p = e.GetPosition(MapHost);
        var dx = p.X - _dragStart.X;
        var dy = p.Y - _dragStart.Y;

        _map.SetView(_map.Zoom, _dragCenterLat, _dragCenterLon, ActualWidth, ActualHeight);
        _map.PanByPixels(dx, dy);

        // Pan fluido: trasla i canvas già disegnati, niente rebuild / fetch.
        var tt = new TranslateTransform(dx, dy);
        TileCanvas.RenderTransform = tt;
        PinsCanvas.RenderTransform = tt;
        _dirtyDuringDrag = true;
    }

    private void EndDrag()
    {
        if (!_dragging)
            return;
        _dragging = false;
        MapHost.ReleaseMouseCapture();
        MapHost.Cursor = Cursors.Arrow;
        TileCanvas.RenderTransform = null;
        PinsCanvas.RenderTransform = null;

        if (_dirtyDuringDrag && _map is not null)
        {
            // Centro già aggiornato durante il drag: rebuild markers + tile settle.
            ApplyView(fullRebuild: true);
            _dirtyDuringDrag = false;
        }
    }

    private void MapHost_OnMouseUp(object sender, MouseButtonEventArgs e) => EndDrag();

    private void MapHost_OnMouseLeave(object sender, MouseEventArgs e)
    {
        if (_dragging)
            EndDrag();
    }

    private void ZoomInBtn_OnClick(object sender, RoutedEventArgs e)
    {
        if (_map is null)
            return;
        _map.ZoomAt(_map.Zoom + 1, ActualWidth / 2.0, ActualHeight / 2.0);
        ApplyView(fullRebuild: true);
    }

    private void ZoomOutBtn_OnClick(object sender, RoutedEventArgs e)
    {
        if (_map is null)
            return;
        _map.ZoomAt(_map.Zoom - 1, ActualWidth / 2.0, ActualHeight / 2.0);
        ApplyView(fullRebuild: true);
    }

    private async Task PumpThumbnailsAsync(int version, CancellationToken ct)
    {
        try
        {
            var cards = _markers
                .Where(static m => !m.IsCluster && m.Image is not null)
                .Take(MaxThumbCards)
                .ToList();
            if (cards.Count == 0)
                return;

            using var gate = new SemaphoreSlim(MaxConcurrentThumbs);
            var tasks = cards.Select(async marker =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    if (version != _layoutVersion || ct.IsCancellationRequested || marker.Image is null)
                        return;

                    var src = await ThumbnailLoader.LoadAsync(marker.Item.AbsolutePath, ThumbDecode, ct)
                        .ConfigureAwait(false);
                    if (src is null || version != _layoutVersion || ct.IsCancellationRequested)
                        return;

                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (version != _layoutVersion || marker.Image is null)
                            return;
                        marker.Image.Source = src;
                        if (marker.Placeholder is not null)
                            marker.Placeholder.Visibility = Visibility.Collapsed;
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

    private FrameworkElement BuildDot(MediaItem item)
    {
        const double size = 14;
        var ellipse = new Ellipse
        {
            Width = size,
            Height = size,
            Fill = AccentBrush,
            Stroke = DotStroke,
            StrokeThickness = 2,
            Cursor = Cursors.Hand,
            Tag = item,
            ToolTip = $"{item.FileName}\n{item.Latitude:0.######}, {item.Longitude:0.######}"
        };
        return ellipse;
    }

    private FrameworkElement BuildClusterBubble(int count, IReadOnlyList<MediaItem> members)
    {
        var size = count >= 100 ? 44 : count >= 20 ? 38 : 32;
        var grid = new Grid
        {
            Width = size,
            Height = size,
            Cursor = Cursors.Hand,
            Tag = members
        };
        grid.Children.Add(new Ellipse
        {
            Fill = AccentSoftBrush,
            Stroke = WhiteBrush,
            StrokeThickness = 2,
            IsHitTestVisible = false
        });
        grid.Children.Add(new TextBlock
        {
            Text = count >= 1000 ? $"{count / 1000.0:0.#}k" : count.ToString(),
            FontSize = count >= 100 ? 11 : 12,
            FontWeight = FontWeights.SemiBold,
            Foreground = WhiteBrush,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            IsHitTestVisible = false
        });
        grid.ToolTip = $"{count} elementi — clic per avvicinare";
        return grid;
    }

    private FrameworkElement BuildCard(MediaItem item)
    {
        var videoPath = MediaPreviewHelper.GetInlineVideoPath(item);
        var image = new Image
        {
            Width = 72,
            Height = 56,
            Stretch = Stretch.UniformToFill,
            SnapsToDevicePixels = true
        };

        var placeholder = new TextBlock
        {
            Text = videoPath is not null ? "▶" : "●",
            FontSize = 16,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = AccentBrush
        };

        var thumbHost = new Grid
        {
            Width = 72,
            Height = 56,
            Background = ThumbBg
        };
        thumbHost.Children.Add(placeholder);
        thumbHost.Children.Add(image);

        var name = new TextBlock
        {
            Text = item.FileName,
            FontSize = 9,
            Margin = new Thickness(2, 3, 2, 0),
            TextTrimming = TextTrimming.CharacterEllipsis,
            TextAlignment = TextAlignment.Center,
            Foreground = NameFg,
            MaxWidth = 80
        };

        var stack = new StackPanel();
        stack.Children.Add(thumbHost);
        stack.Children.Add(name);

        var border = new Border
        {
            Width = CardW,
            Height = CardH,
            CornerRadius = new CornerRadius(8),
            BorderThickness = new Thickness(1),
            BorderBrush = CardBorder,
            Background = CardBg,
            Padding = new Thickness(6, 6, 6, 3),
            Child = stack,
            Cursor = Cursors.Hand,
            Tag = item,
            ToolTip = $"{item.FileName}\n{item.Latitude:0.######}, {item.Longitude:0.######}"
        };

        // stash image/placeholder on Tag via MarkerVisual lookup after
        border.SetValue(FrameworkElement.TagProperty, item);
        border.Uid = "card";
        // Keep refs via attached storage on border NameScope-free: use DataContext
        border.DataContext = new CardParts(image, placeholder, videoPath);
        return border;
    }

    private static SolidColorBrush Freeze(Color c)
    {
        var b = new SolidColorBrush(c);
        b.Freeze();
        return b;
    }

    private sealed class Cluster
    {
        public Point Screen;
        public List<MediaItem> Items { get; }

        public Cluster(Point screen, List<MediaItem> items)
        {
            Screen = screen;
            Items = items;
        }
    }

    private sealed record CardParts(Image Image, TextBlock Placeholder, string? VideoPath);

    private sealed class MarkerVisual
    {
        public MediaItem Item { get; }
        public FrameworkElement Root { get; }
        public bool IsCluster { get; }
        public IReadOnlyList<MediaItem> Members { get; }
        public Image? Image { get; }
        public TextBlock? Placeholder { get; }

        public MarkerVisual(
            MediaItem item, FrameworkElement root, bool isCluster, IReadOnlyList<MediaItem> members)
        {
            Item = item;
            Root = root;
            IsCluster = isCluster;
            Members = members;
            if (root.DataContext is CardParts parts)
            {
                Image = parts.Image;
                Placeholder = parts.Placeholder;
            }
        }

        public void SetSelected(bool selected)
        {
            if (Root is Border border)
            {
                border.BorderThickness = new Thickness(selected ? 2 : 1);
                border.BorderBrush = selected ? CardBorderSel : CardBorder;
                return;
            }

            if (Root is Ellipse ellipse)
            {
                ellipse.StrokeThickness = selected ? 3 : 2;
                ellipse.Width = selected ? 16 : 14;
                ellipse.Height = selected ? 16 : 14;
            }
        }
    }
}
