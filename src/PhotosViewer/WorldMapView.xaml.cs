using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Threading;
using PhotosViewer.Models;
using PhotosViewer.Services;

namespace PhotosViewer;

public partial class WorldMapView : UserControl
{
    private const int CardW = 96;
    private const int CardH = 112;
    private const int ThumbDecode = 96;
    private const int MaxConcurrentThumbs = 6;

    private IReadOnlyList<MediaItem> _items = [];
    private readonly List<PinVisual> _pins = [];
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

    public event Action<MediaItem>? ItemSelected;

    public WorldMapView()
    {
        InitializeComponent();
        _map = new SlippyMapLayer(TileCanvas);
        AttributionText.Text = SlippyMapLayer.Attribution;
        SizeChanged += (_, _) => OnViewportChanged(resetView: false);
        Unloaded += (_, _) => _thumbCts?.Cancel();
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
        foreach (var pin in _pins)
            pin.SetSelected(false);
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
        }
        else
        {
            _map.SetView(_map.Zoom, _map.CenterLat, _map.CenterLon, ActualWidth, ActualHeight);
        }

        ApplyView();
    }

    private void ApplyView()
    {
        if (_map is null)
            return;

        _map.RefreshTiles();
        RebuildPins();
        StatusHint.Text = _items.Count == 0
            ? ""
            : $"{_items.Count} punti · zoom {_map.Zoom} · trascina per spostare";
    }

    private void RebuildPins()
    {
        _layoutVersion++;
        var version = _layoutVersion;
        PinsCanvas.Children.Clear();
        _pins.Clear();
        _thumbCts?.Cancel();
        _thumbCts = new CancellationTokenSource();

        if (_map is null || _items.Count == 0)
            return;

        foreach (var item in _items)
        {
            var pt = _map.LatLonToScreen(item.Latitude!.Value, item.Longitude!.Value);
            var pin = BuildPin(item);
            Canvas.SetLeft(pin.Root, pt.X - CardW / 2.0);
            Canvas.SetTop(pin.Root, pt.Y - CardH / 2.0);
            PinsCanvas.Children.Add(pin.Root);
            _pins.Add(pin);
            if (_selected is not null && ReferenceEquals(_selected, item))
                pin.SetSelected(true);
        }

        _ = PumpThumbnailsAsync(version, _thumbCts.Token);
    }

    private void MapHost_OnMouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (_map is null || _items.Count == 0)
            return;

        var pos = e.GetPosition(MapHost);
        var delta = e.Delta > 0 ? 1 : -1;
        _map.ZoomAt(_map.Zoom + delta, pos.X, pos.Y);
        ApplyView();
        e.Handled = true;
    }

    private void MapHost_OnMouseDown(object sender, MouseButtonEventArgs e)
    {
        if (_map is null || _items.Count == 0 || e.ChangedButton != MouseButton.Left)
            return;
        if (e.OriginalSource is FrameworkElement { Tag: MediaItem })
            return;

        _dragging = true;
        _dragStart = e.GetPosition(MapHost);
        _dragCenterLat = _map.CenterLat;
        _dragCenterLon = _map.CenterLon;
        MapHost.CaptureMouse();
        MapHost.Cursor = Cursors.SizeAll;
        e.Handled = true;
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
        ApplyView();
    }

    private void MapHost_OnMouseUp(object sender, MouseButtonEventArgs e)
    {
        if (!_dragging)
            return;
        _dragging = false;
        MapHost.ReleaseMouseCapture();
        MapHost.Cursor = Cursors.Arrow;
    }

    private void MapHost_OnMouseLeave(object sender, MouseEventArgs e)
    {
        if (!_dragging)
            return;
        _dragging = false;
        MapHost.ReleaseMouseCapture();
        MapHost.Cursor = Cursors.Arrow;
    }

    private void ZoomInBtn_OnClick(object sender, RoutedEventArgs e)
    {
        if (_map is null)
            return;
        _map.ZoomAt(_map.Zoom + 1, ActualWidth / 2.0, ActualHeight / 2.0);
        ApplyView();
    }

    private void ZoomOutBtn_OnClick(object sender, RoutedEventArgs e)
    {
        if (_map is null)
            return;
        _map.ZoomAt(_map.Zoom - 1, ActualWidth / 2.0, ActualHeight / 2.0);
        ApplyView();
    }

    private async Task PumpThumbnailsAsync(int version, CancellationToken ct)
    {
        try
        {
            using var gate = new SemaphoreSlim(MaxConcurrentThumbs);
            var tasks = _pins.Select(async pin =>
            {
                await gate.WaitAsync(ct).ConfigureAwait(false);
                try
                {
                    if (version != _layoutVersion || ct.IsCancellationRequested)
                        return;

                    // Per video/Live: AbsolutePath = still (HEIC) oppure file video → Shell first frame.
                    var src = await ThumbnailLoader.LoadAsync(pin.Item.AbsolutePath, ThumbDecode, ct)
                        .ConfigureAwait(false);
                    if (src is null || version != _layoutVersion || ct.IsCancellationRequested)
                        return;

                    await Dispatcher.InvokeAsync(() =>
                    {
                        if (version != _layoutVersion)
                            return;
                        pin.Image.Source = src;
                        pin.Placeholder.Visibility = Visibility.Collapsed;
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

    private void StopAllPinVideos()
    {
        foreach (var pin in _pins)
            pin.StopVideo();
    }

    private PinVisual BuildPin(MediaItem item)
    {
        var videoPath = MediaPreviewHelper.GetInlineVideoPath(item);
        var image = new Image
        {
            Width = 80,
            Height = 64,
            Stretch = Stretch.UniformToFill,
            SnapsToDevicePixels = true
        };

        var placeholder = new TextBlock
        {
            Text = videoPath is not null ? "▶" : "●",
            FontSize = 18,
            HorizontalAlignment = HorizontalAlignment.Center,
            VerticalAlignment = VerticalAlignment.Center,
            Foreground = new SolidColorBrush(Color.FromRgb(0x00, 0x71, 0xE3))
        };

        var playOverlay = new Border
        {
            Background = new SolidColorBrush(Color.FromArgb(0x88, 0x00, 0x00, 0x00)),
            Visibility = videoPath is not null ? Visibility.Visible : Visibility.Collapsed,
            IsHitTestVisible = false,
            Child = new TextBlock
            {
                Text = "▶",
                FontSize = 22,
                Foreground = Brushes.White,
                HorizontalAlignment = HorizontalAlignment.Center,
                VerticalAlignment = VerticalAlignment.Center
            }
        };

        var thumbHost = new Grid
        {
            Width = 80,
            Height = 64,
            Background = new SolidColorBrush(Color.FromRgb(0xF5, 0xF5, 0xF7)),
            Cursor = videoPath is not null ? Cursors.Hand : Cursors.Arrow
        };
        thumbHost.Children.Add(placeholder);
        thumbHost.Children.Add(image);
        thumbHost.Children.Add(playOverlay);

        var name = new TextBlock
        {
            Text = item.FileName,
            FontSize = 10,
            Margin = new Thickness(4, 4, 4, 4),
            TextTrimming = TextTrimming.CharacterEllipsis,
            TextAlignment = TextAlignment.Center,
            Foreground = new SolidColorBrush(Color.FromRgb(0x1D, 0x1D, 0x1F)),
            MaxWidth = 88
        };

        var stack = new StackPanel();
        stack.Children.Add(thumbHost);
        stack.Children.Add(name);

        var border = new Border
        {
            Width = CardW,
            Height = CardH,
            CornerRadius = new CornerRadius(10),
            BorderThickness = new Thickness(1),
            BorderBrush = new SolidColorBrush(Color.FromRgb(0xD2, 0xD2, 0xD7)),
            Background = Brushes.White,
            Padding = new Thickness(6, 6, 6, 4),
            Child = stack,
            Cursor = Cursors.Hand,
            Tag = item,
            ToolTip = videoPath is not null
                ? $"{item.FileName}\n{item.Latitude:0.######}, {item.Longitude:0.######}\nClic anteprima per riprodurre · doppio clic per aprire"
                : $"{item.FileName}\n{item.Latitude:0.######}, {item.Longitude:0.######}\nDoppio clic per aprire",
            Effect = new System.Windows.Media.Effects.DropShadowEffect
            {
                BlurRadius = 12,
                ShadowDepth = 1,
                Opacity = 0.18,
                Direction = 270,
                Color = Colors.Black
            }
        };

        var pin = new PinVisual(item, border, image, placeholder, thumbHost, playOverlay, videoPath);

        thumbHost.MouseLeftButtonDown += (_, ev) =>
        {
            if (videoPath is null)
                return;
            ev.Handled = true;
            StopAllPinVideos();
            pin.PlayVideo();
        };

        border.MouseLeftButtonUp += (_, ev) =>
        {
            ev.Handled = true;
            var now = DateTime.UtcNow;
            if (_lastPinClickItem == item && (now - _lastPinClick).TotalMilliseconds < 350)
            {
                StopAllPinVideos();
                MediaFileOpener.TryOpen(videoPath ?? item.AbsolutePath);
                return;
            }

            StopAllPinVideos();
            _selected = item;
            foreach (var p in _pins)
                p.SetSelected(ReferenceEquals(p.Item, item));
            ItemSelected?.Invoke(item);
            _lastPinClick = now;
            _lastPinClickItem = item;
        };
        border.MouseLeftButtonDown += (_, ev) => ev.Handled = true;
        return pin;
    }

    private sealed class PinVisual
    {
        public MediaItem Item { get; }
        public Border Root { get; }
        public Image Image { get; }
        public TextBlock Placeholder { get; }
        public string? VideoPath { get; }
        private readonly Grid _thumbHost;
        private readonly Border _playOverlay;
        private MediaElement? _video;

        public PinVisual(
            MediaItem item, Border root, Image image, TextBlock placeholder,
            Grid thumbHost, Border playOverlay, string? videoPath)
        {
            Item = item;
            Root = root;
            Image = image;
            Placeholder = placeholder;
            _thumbHost = thumbHost;
            _playOverlay = playOverlay;
            VideoPath = videoPath;
        }

        public void PlayVideo()
        {
            if (VideoPath is null)
                return;

            _video ??= new MediaElement
            {
                Width = 80,
                Height = 64,
                Stretch = Stretch.UniformToFill,
                LoadedBehavior = MediaState.Manual,
                UnloadedBehavior = MediaState.Stop,
                Source = new Uri(VideoPath)
            };
            _video.MediaEnded += (_, _) => StopVideo();

            if (!_thumbHost.Children.Contains(_video))
                _thumbHost.Children.Add(_video);

            Image.Visibility = Visibility.Collapsed;
            Placeholder.Visibility = Visibility.Collapsed;
            _playOverlay.Visibility = Visibility.Collapsed;
            _video.Visibility = Visibility.Visible;
            _video.Position = TimeSpan.Zero;
            _video.Play();
        }

        public void StopVideo()
        {
            if (_video is not null)
            {
                _video.Stop();
                _video.Visibility = Visibility.Collapsed;
            }

            Image.Visibility = Visibility.Visible;
            if (Image.Source is null)
                Placeholder.Visibility = Visibility.Visible;
            if (VideoPath is not null)
                _playOverlay.Visibility = Visibility.Visible;
        }

        public void SetSelected(bool selected)
        {
            Root.BorderThickness = new Thickness(selected ? 2 : 1);
            Root.BorderBrush = new SolidColorBrush(
                selected ? Color.FromRgb(0x00, 0x71, 0xE3) : Color.FromRgb(0xD2, 0xD2, 0xD7));
            Root.Effect = new System.Windows.Media.Effects.DropShadowEffect
            {
                BlurRadius = selected ? 16 : 12,
                ShadowDepth = 1,
                Opacity = selected ? 0.28 : 0.18,
                Direction = 270,
                Color = selected ? Color.FromRgb(0x00, 0x71, 0xE3) : Colors.Black
            };
        }
    }
}
