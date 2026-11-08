using System.Windows.Controls;

namespace BackupViewer.Services;

public interface IMediaPlayback : IDisposable
{
    void AttachHost(Border host);
    Task<bool> PlayAsync(string path, bool needsVideo, CancellationToken ct = default);
    void Stop();
    void Pause();
}
