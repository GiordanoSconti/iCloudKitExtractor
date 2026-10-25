using System.Collections.Concurrent;
using System.IO;
using System.Net.Http;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;

namespace PhotosViewer.Services;

/// <summary>
/// Tile layer stile Leaflet: schema XYZ {z}/{x}/{y}.png, Web Mercator, nessuna API key.
/// Non usa CARTO (watermark "API KEY REQUIRED") né tile.openstreetmap.org (vietato alle app).
/// </summary>
public sealed class SlippyMapLayer
{
    public const int TileSize = 256;
    public const int MinZoom = 2;
    public const int MaxZoom = 18;

    private const int MaxParallelFetches = 3;
    private const int MinTileBytes = 900;
    private static readonly string[] Subdomains = ["a", "b", "c"];
    private static readonly (string Id, string UrlTemplate)[] TileProviders =
    [
        ("osmfr", "https://{s}.tile.openstreetmap.fr/osmfr/{z}/{x}/{y}.png"),
        ("opentopomap", "https://{s}.tile.opentopomap.org/{z}/{x}/{y}.png"),
        ("wikimedia", "https://maps.wikimedia.org/osm-intl/{z}/{x}/{y}.png")
    ];

    private static readonly HttpClient Http = CreateClient();
    private static readonly ConcurrentDictionary<string, byte[]> MemCache = new(StringComparer.Ordinal);
    private static readonly string DiskRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
        "PhotosViewer", "maptiles-v2");

    static SlippyMapLayer() => PurgeLegacyCartoCache();

    private readonly Canvas _host;
    private CancellationTokenSource? _cts;
    private int _version;

    public SlippyMapLayer(Canvas host) => _host = host;

    public int Zoom { get; private set; } = 2;
    public double CenterLat { get; private set; }
    public double CenterLon { get; private set; }
    public double ViewW { get; private set; }
    public double ViewH { get; private set; }

    public static string Attribution =>
        "© OpenStreetMap · OSM France · OpenTopoMap";

    public void SetView(int zoom, double centerLat, double centerLon, double viewW, double viewH)
    {
        Zoom = Math.Clamp(zoom, MinZoom, MaxZoom);
        CenterLat = Math.Clamp(centerLat, -85, 85);
        CenterLon = NormalizeLon(centerLon);
        ViewW = viewW;
        ViewH = viewH;
    }

    public void FitBounds(IReadOnlyList<(double Lat, double Lon)> points, double viewW, double viewH)
    {
        ViewW = viewW;
        ViewH = viewH;
        if (points.Count == 0)
        {
            Zoom = 2;
            CenterLat = 20;
            CenterLon = 0;
            return;
        }

        var minLat = points.Min(static p => p.Lat);
        var maxLat = points.Max(static p => p.Lat);
        var minLon = points.Min(static p => p.Lon);
        var maxLon = points.Max(static p => p.Lon);

        var dLat = Math.Max(0.08, (maxLat - minLat) * 0.15);
        var dLon = Math.Max(0.08, (maxLon - minLon) * 0.15);
        minLat = Math.Clamp(minLat - dLat, -85, 85);
        maxLat = Math.Clamp(maxLat + dLat, -85, 85);
        minLon = NormalizeLon(minLon - dLon);
        maxLon = NormalizeLon(maxLon + dLon);

        if (Math.Abs(maxLon - minLon) < 0.01) { minLon -= 0.4; maxLon += 0.4; }
        if (Math.Abs(maxLat - minLat) < 0.01) { minLat -= 0.25; maxLat += 0.25; }

        CenterLat = (minLat + maxLat) / 2.0;
        CenterLon = NormalizeLon((minLon + maxLon) / 2.0);

        Zoom = MinZoom;
        for (var z = MaxZoom; z >= MinZoom; z--)
        {
            var (x0, y0) = LatLonToWorld(maxLat, minLon, z);
            var (x1, y1) = LatLonToWorld(minLat, maxLon, z);
            var w = Math.Abs(x1 - x0);
            var h = Math.Abs(y1 - y0);
            if (w <= viewW * 0.92 && h <= viewH * 0.92)
            {
                Zoom = z;
                break;
            }
        }
    }

    public Point LatLonToScreen(double lat, double lon)
    {
        var (wx, wy) = LatLonToWorld(lat, lon, Zoom);
        var (cx, cy) = LatLonToWorld(CenterLat, CenterLon, Zoom);
        return new Point(wx - cx + ViewW / 2.0, wy - cy + ViewH / 2.0);
    }

    public (double Lat, double Lon) ScreenToLatLon(double sx, double sy)
    {
        var (cx, cy) = LatLonToWorld(CenterLat, CenterLon, Zoom);
        var wx = cx + sx - ViewW / 2.0;
        var wy = cy + sy - ViewH / 2.0;
        return WorldToLatLon(wx, wy, Zoom);
    }

    public void PanByPixels(double dx, double dy)
    {
        var (cx, cy) = LatLonToWorld(CenterLat, CenterLon, Zoom);
        var (lat, lon) = WorldToLatLon(cx - dx, cy - dy, Zoom);
        CenterLat = lat;
        CenterLon = lon;
    }

    public void ZoomAt(int newZoom, double screenX, double screenY)
    {
        var anchor = ScreenToLatLon(screenX, screenY);
        Zoom = Math.Clamp(newZoom, MinZoom, MaxZoom);
        var (wx, wy) = LatLonToWorld(anchor.Lat, anchor.Lon, Zoom);
        var newCx = wx - screenX + ViewW / 2.0;
        var newCy = wy - screenY + ViewH / 2.0;
        (CenterLat, CenterLon) = WorldToLatLon(newCx, newCy, Zoom);
    }

    public void RefreshTiles()
    {
        _version++;
        var version = _version;
        _cts?.Cancel();
        _cts = new CancellationTokenSource();
        _host.Children.Clear();

        if (ViewW < 20 || ViewH < 20)
            return;

        _ = LoadTilesAsync(version, _cts.Token);
    }

    private async Task LoadTilesAsync(int version, CancellationToken ct)
    {
        try
        {
            var z = Zoom;
            var n = 1 << z;
            var (cx, cy) = LatLonToWorld(CenterLat, CenterLon, Zoom);
            var originX = cx - ViewW / 2.0;
            var originY = cy - ViewH / 2.0;

            var minTx = Math.Max(0, (int)Math.Floor(originX / TileSize) - 1);
            var maxTx = Math.Min(n - 1, (int)Math.Ceiling((originX + ViewW) / TileSize));
            var minTy = Math.Max(0, (int)Math.Floor(originY / TileSize) - 1);
            var maxTy = Math.Min(n - 1, (int)Math.Ceiling((originY + ViewH) / TileSize));

            using var gate = new SemaphoreSlim(MaxParallelFetches);
            var tasks = new List<Task>();
            for (var x = minTx; x <= maxTx; x++)
            {
                for (var y = minTy; y <= maxTy; y++)
                {
                    var tx = x;
                    var ty = y;
                    tasks.Add(PumpOneAsync(version, originX, originY, z, tx, ty, gate, ct));
                }
            }

            await Task.WhenAll(tasks).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // ignore
        }
    }

    private async Task PumpOneAsync(
        int version, double originX, double originY, int z, int tx, int ty,
        SemaphoreSlim gate, CancellationToken ct)
    {
        await gate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (version != _version || ct.IsCancellationRequested)
                return;

            var bytes = await FetchTileBytesAsync(z, tx, ty, ct).ConfigureAwait(false);
            if (bytes is null || version != _version)
                return;

            var left = tx * TileSize - originX;
            var top = ty * TileSize - originY;

            await _host.Dispatcher.InvokeAsync(() =>
            {
                if (version != _version)
                    return;
                try
                {
                    var bmp = new BitmapImage();
                    bmp.BeginInit();
                    bmp.StreamSource = new MemoryStream(bytes);
                    bmp.CacheOption = BitmapCacheOption.OnLoad;
                    bmp.EndInit();
                    bmp.Freeze();

                    var el = new Image
                    {
                        Source = bmp,
                        Width = TileSize,
                        Height = TileSize,
                        Stretch = Stretch.Fill,
                        IsHitTestVisible = false,
                        SnapsToDevicePixels = true
                    };
                    Canvas.SetLeft(el, left);
                    Canvas.SetTop(el, top);
                    _host.Children.Add(el);
                }
                catch
                {
                    // ignore
                }
            }, DispatcherPriority.Background);
        }
        catch (OperationCanceledException)
        {
            // ignore
        }
        finally
        {
            gate.Release();
        }
    }

    private static async Task<byte[]?> FetchTileBytesAsync(int z, int x, int y, CancellationToken ct)
    {
        var key = $"{z}/{x}/{y}";
        if (MemCache.TryGetValue(key, out var hit) && IsValidTile(hit))
            return hit;

        foreach (var (providerId, template) in TileProviders)
        {
            var url = BuildTileUrl(template, z, x, y);
            var bytes = await TryFetchUrlAsync(url, providerId, z, x, y, ct).ConfigureAwait(false);
            if (bytes is not null && IsValidTile(bytes))
                return CacheTile(key, bytes, providerId);
        }

        return null;
    }

    private static string BuildTileUrl(string template, int z, int x, int y)
    {
        var sub = Subdomains[(x + y) % Subdomains.Length];
        return template
            .Replace("{s}", sub, StringComparison.Ordinal)
            .Replace("{z}", z.ToString(), StringComparison.Ordinal)
            .Replace("{x}", x.ToString(), StringComparison.Ordinal)
            .Replace("{y}", y.ToString(), StringComparison.Ordinal);
    }

    private static bool IsValidTile(byte[] bytes)
    {
        if (bytes.Length < MinTileBytes)
            return false;
        // PNG signature
        if (bytes.Length < 8 || bytes[0] != 0x89 || bytes[1] != 0x50 || bytes[2] != 0x4E || bytes[3] != 0x47)
            return false;
        // Rifiuta tile CARTO con watermark testuale (se presente)
        var ascii = System.Text.Encoding.ASCII.GetString(bytes);
        return !ascii.Contains("API KEY", StringComparison.OrdinalIgnoreCase)
               && !ascii.Contains("carto.com/basemaps", StringComparison.OrdinalIgnoreCase);
    }

    private static void PurgeLegacyCartoCache()
    {
        try
        {
            var root = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "PhotosViewer", "maptiles");
            if (!Directory.Exists(root))
                return;
            foreach (var dir in Directory.EnumerateDirectories(root))
            {
                if (dir.Contains("cartocdn", StringComparison.OrdinalIgnoreCase)
                    || dir.Contains("carto", StringComparison.OrdinalIgnoreCase))
                {
                    Directory.Delete(dir, recursive: true);
                }
            }
        }
        catch
        {
            // ignore
        }
    }

    private static async Task<byte[]?> TryFetchUrlAsync(
        string url, string providerId, int z, int x, int y, CancellationToken ct)
    {
        try
        {
            Directory.CreateDirectory(DiskRoot);
            var diskPath = Path.Combine(DiskRoot, providerId, $"{z}_{x}_{y}.png");
            if (File.Exists(diskPath))
            {
                var fromDisk = await File.ReadAllBytesAsync(diskPath, ct).ConfigureAwait(false);
                if (IsValidTile(fromDisk))
                    return fromDisk;
                File.Delete(diskPath);
            }

            using var resp = await Http.GetAsync(url, HttpCompletionOption.ResponseHeadersRead, ct)
                .ConfigureAwait(false);
            if (!resp.IsSuccessStatusCode)
            {
                return null;
            }

            var bytes = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            if (!IsValidTile(bytes))
            {
                return null;
            }

            try
            {
                Directory.CreateDirectory(Path.GetDirectoryName(diskPath)!);
                await File.WriteAllBytesAsync(diskPath, bytes, ct).ConfigureAwait(false);
            }
            catch { /* ignore */ }

            return bytes;
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch
        {
            return null;
        }
    }

    private static byte[] CacheTile(string key, byte[] bytes, string provider)
    {
        MemCache[key] = bytes;
        if (MemCache.Count > 800)
        {
            foreach (var k in MemCache.Keys.Take(100).ToList())
                MemCache.TryRemove(k, out _);
        }

        return bytes;
    }

    public static (double X, double Y) LatLonToWorld(double lat, double lon, int zoom)
    {
        lat = Math.Clamp(lat, -85.05112878, 85.05112878);
        var n = 1 << zoom;
        var x = (NormalizeLon(lon) + 180.0) / 360.0 * n * TileSize;
        var sinLat = Math.Sin(lat * Math.PI / 180.0);
        var y = (0.5 - Math.Log((1 + sinLat) / (1 - sinLat)) / (4 * Math.PI)) * n * TileSize;
        return (x, y);
    }

    public static (double Lat, double Lon) WorldToLatLon(double wx, double wy, int zoom)
    {
        var n = 1 << zoom;
        var world = n * TileSize;
        var lon = wx / world * 360.0 - 180.0;
        var merc = Math.PI - 2.0 * Math.PI * wy / world;
        var lat = 180.0 / Math.PI * Math.Atan(Math.Sinh(merc));
        return (Math.Clamp(lat, -85.05112878, 85.05112878), NormalizeLon(lon));
    }

    private static double NormalizeLon(double lon)
    {
        while (lon < -180) lon += 360;
        while (lon > 180) lon -= 360;
        return lon;
    }

    private static HttpClient CreateClient()
    {
        var handler = new HttpClientHandler { AutomaticDecompression = System.Net.DecompressionMethods.All };
        var c = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(25) };
        c.DefaultRequestHeaders.TryAddWithoutValidation(
            "User-Agent",
            "PhotosViewer/1.0 (WPF slippy map; Leaflet-style XYZ; personal use)");
        c.DefaultRequestHeaders.TryAddWithoutValidation("Accept", "image/png,image/*;q=0.8,*/*;q=0.5");
        return c;
    }
}
