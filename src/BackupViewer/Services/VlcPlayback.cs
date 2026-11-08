using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;
using LibVLCSharp.Shared;
using LibVLCSharp.WPF;
using MediaPlayer = LibVLCSharp.Shared.MediaPlayer;

namespace BackupViewer.Services;

/// <summary>
/// LibVLC senza bloccare la UI: Core/LibVLC/Stop/Media restano fuori dal
/// thread WPF; VideoView solo per il video e creato senza deadlock.
/// </summary>
public sealed class VlcPlayback : IMediaPlayback
{
    private static readonly object EngineGate = new();
    private static Task? _engineTask;
    private static LibVLC? _sharedLib;
    private static int _coreInit;

    private readonly SemaphoreSlim _playGate = new(1, 1);
    private MediaPlayer? _player;
    private VideoView? _view;
    private Border? _host;
    private bool _disposed;
    private int _playEpoch;

    public bool IsReady => _player is not null;

    public static void EnsureCore()
    {
        if (Interlocked.Exchange(ref _coreInit, 1) == 0)
            Core.Initialize();
    }

    public static Task WarmupAsync(CancellationToken ct = default) => EnsureEngineAsync(ct);

    private static Task EnsureEngineAsync(CancellationToken ct = default)
    {
        lock (EngineGate)
        {
            _engineTask ??= Task.Run(static () =>
            {
                EnsureCore();
                _sharedLib ??= new LibVLC(
                    "--no-video-title-show",
                    "--quiet",
                    "--no-osd",
                    "--avcodec-hw=any");
            }, CancellationToken.None);
        }

        return _engineTask.WaitAsync(ct);
    }

    public void AttachHost(Border host)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        _host = host;
    }

    public async Task<bool> PlayAsync(string path, bool needsVideo, CancellationToken ct = default)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return false;

        var epoch = Interlocked.Increment(ref _playEpoch);
        await EnsureEngineAsync(ct).ConfigureAwait(false);
        if (_disposed || epoch != Volatile.Read(ref _playEpoch))
            return false;

        var lib = _sharedLib ?? throw new InvalidOperationException("LibVLC non inizializzato.");

        await _playGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            if (_disposed || epoch != Volatile.Read(ref _playEpoch))
                return false;

            _player ??= new MediaPlayer(lib);
            var player = _player;

            await Task.Run(() =>
            {
                try { player.Stop(); }
                catch { /* ignore */ }
            }, ct).ConfigureAwait(false);

            if (_disposed || epoch != Volatile.Read(ref _playEpoch))
                return false;

            if (needsVideo)
            {
                await EnsureVideoViewAsync(ct).ConfigureAwait(false);
                if (_disposed || epoch != Volatile.Read(ref _playEpoch))
                    return false;
            }

            using var media = await Task.Run(() => new Media(lib, path, FromType.FromPath), ct)
                .ConfigureAwait(false);
            if (_disposed || epoch != Volatile.Read(ref _playEpoch))
                return false;

            return player.Play(media);
        }
        finally
        {
            _playGate.Release();
        }
    }

    private async Task EnsureVideoViewAsync(CancellationToken ct)
    {
        var dispatcher = Application.Current?.Dispatcher
                         ?? throw new InvalidOperationException("Nessun Dispatcher WPF.");

        if (dispatcher.CheckAccess())
        {
            BindVideoView();
            await Dispatcher.Yield(DispatcherPriority.Loaded);
            ct.ThrowIfCancellationRequested();
            return;
        }

        await dispatcher.InvokeAsync(BindVideoView, DispatcherPriority.Normal)
            .Task.WaitAsync(ct).ConfigureAwait(false);

        await dispatcher.InvokeAsync(static () => { }, DispatcherPriority.Loaded)
            .Task.WaitAsync(ct).ConfigureAwait(false);
    }

    private void BindVideoView()
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        if (_host is null)
            throw new InvalidOperationException("VLC host non assegnato.");
        if (_sharedLib is null)
            throw new InvalidOperationException("LibVLC non inizializzato.");

        _player ??= new MediaPlayer(_sharedLib);

        if (_view is null)
        {
            _view = new VideoView
            {
                HorizontalAlignment = HorizontalAlignment.Stretch,
                VerticalAlignment = VerticalAlignment.Stretch,
            };
            _host.Child = _view;
        }

        void Bind()
        {
            if (_view is null || _player is null || _disposed)
                return;
            if (!ReferenceEquals(_view.MediaPlayer, _player))
                _view.MediaPlayer = _player;
        }

        if (_view.IsLoaded)
            Bind();
        else
        {
            void OnLoaded(object sender, RoutedEventArgs e)
            {
                _view!.Loaded -= OnLoaded;
                Bind();
            }

            _view.Loaded += OnLoaded;
        }
    }

    public void Stop()
    {
        Interlocked.Increment(ref _playEpoch);
        var player = _player;
        if (player is null)
            return;

        _ = Task.Run(() =>
        {
            try { player.Stop(); }
            catch { /* ignore */ }
        });
    }

    public void Pause()
    {
        var player = _player;
        if (player is null)
            return;
        _ = Task.Run(() =>
        {
            try
            {
                if (player.IsPlaying)
                    player.SetPause(true);
                else
                    player.SetPause(false);
            }
            catch { /* ignore */ }
        });
    }

    public void Dispose()
    {
        if (_disposed)
            return;
        _disposed = true;
        Interlocked.Increment(ref _playEpoch);

        var player = _player;
        var view = _view;
        var host = _host;
        _player = null;
        _view = null;
        _host = null;

        try
        {
            var dispatcher = Application.Current?.Dispatcher;
            if (dispatcher is not null && !dispatcher.HasShutdownStarted)
            {
                void ClearUi()
                {
                    try
                    {
                        if (view is not null)
                            view.MediaPlayer = null;
                        if (host is not null)
                            host.Child = null;
                    }
                    catch { /* ignore */ }
                }

                if (dispatcher.CheckAccess())
                    ClearUi();
                else
                    dispatcher.BeginInvoke(ClearUi, DispatcherPriority.Background);
            }
        }
        catch { /* ignore */ }

        _ = Task.Run(() =>
        {
            try
            {
                player?.Stop();
                player?.Dispose();
            }
            catch { /* ignore */ }
        });

        try { _playGate.Dispose(); }
        catch { /* ignore */ }
    }
}
