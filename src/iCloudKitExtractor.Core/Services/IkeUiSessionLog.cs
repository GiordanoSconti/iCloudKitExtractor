using System.Collections.Concurrent;
using System.IO;
using System.Text;

namespace iCloudKitExtractor.Services;

/// <summary>
/// Persists on-screen UI panel logs under
/// <c>%AppData%/iCloudKitExtractor/logs/ui_*</c> (macOS: Application Support).
/// Independent from HTTP <see cref="IkeLogOptions.PersistRunLogs"/> capture.
/// Disable with <c>IKE_UI_LOG=0</c>.
/// </summary>
public static class IkeUiSessionLog
{
    private static readonly object Gate = new();
    private static readonly ConcurrentDictionary<string, object> ChannelLocks = new(StringComparer.Ordinal);
    private static string? _sessionDirectory;
    private static int _enabled = -1; // -1 lazy
    private static int _announced;

    public static string? SessionDirectory
    {
        get
        {
            EnsureSession();
            return Volatile.Read(ref _sessionDirectory);
        }
    }

    public static bool IsEnabled
    {
        get
        {
            var v = Volatile.Read(ref _enabled);
            if (v >= 0)
                return v != 0;
            var env = Environment.GetEnvironmentVariable("IKE_UI_LOG");
            // Default on: persist UI panels; opt out with IKE_UI_LOG=0.
            var on = string.IsNullOrWhiteSpace(env)
                     || env is not ("0" or "false" or "FALSE" or "no" or "NO" or "off" or "OFF");
            Volatile.Write(ref _enabled, on ? 1 : 0);
            return on;
        }
    }

    public static void SetEnabled(bool enabled) =>
        Volatile.Write(ref _enabled, enabled ? 1 : 0);

    /// <summary>Append one UI log line (channel = auth, escrow, download, …).</summary>
    public static void Append(string channel, string? line)
    {
        if (!IsEnabled || string.IsNullOrWhiteSpace(line))
            return;

        try
        {
            var dir = EnsureSession();
            if (dir is null)
                return;

            var safe = SanitizeChannel(channel);
            var stamp = DateTime.Now.ToString("HH:mm:ss");
            var text = $"[{stamp}] {line.TrimEnd()}{Environment.NewLine}";
            var channelPath = Path.Combine(dir, $"{safe}.log");
            var allPath = Path.Combine(dir, "ui_all.log");

            // Disk I/O off the UI thread.
            _ = Task.Run(() =>
            {
                try
                {
                    var chLock = ChannelLocks.GetOrAdd(safe, static _ => new object());
                    lock (chLock)
                        File.AppendAllText(channelPath, text, Encoding.UTF8);
                    lock (Gate)
                        File.AppendAllText(allPath, $"[{safe}] {text}", Encoding.UTF8);
                }
                catch
                {
                    // ignore disk errors
                }
            });
        }
        catch
        {
            // ignore
        }
    }

    /// <summary>One-shot path announcement for the UI (null if disabled / already announced).</summary>
    public static string? TryTakeSessionAnnouncement()
    {
        if (!IsEnabled)
            return null;
        if (Interlocked.Exchange(ref _announced, 1) != 0)
            return null;
        var dir = EnsureSession();
        return dir is null ? null : $"UI logs → {dir}";
    }

    private static string? EnsureSession()
    {
        if (!IsEnabled)
            return null;

        var existing = Volatile.Read(ref _sessionDirectory);
        if (existing is not null)
            return existing;

        lock (Gate)
        {
            if (_sessionDirectory is not null)
                return _sessionDirectory;

            try
            {
                var root = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "iCloudKitExtractor",
                    "logs");
                Directory.CreateDirectory(root);
                var dir = Path.Combine(root, "ui_" + DateTime.Now.ToString("yyyyMMdd_HHmmss"));
                Directory.CreateDirectory(dir);
                File.WriteAllText(
                    Path.Combine(dir, "manifest.txt"),
                    $"startedUtc={DateTime.UtcNow:O}{Environment.NewLine}" +
                    $"channels=auth,escrow,download,whatsapp,drive,files,syncdata,trusted,imap,exploratory{Environment.NewLine}" +
                    $"combined=ui_all.log{Environment.NewLine}");
                Volatile.Write(ref _sessionDirectory, dir);
                return dir;
            }
            catch
            {
                Volatile.Write(ref _enabled, 0);
                return null;
            }
        }
    }

    private static string SanitizeChannel(string channel)
    {
        if (string.IsNullOrWhiteSpace(channel))
            return "ui";
        var sb = new StringBuilder(channel.Length);
        foreach (var c in channel.Trim().ToLowerInvariant())
        {
            if (char.IsAsciiLetterOrDigit(c) || c is '-' or '_')
                sb.Append(c);
        }

        return sb.Length == 0 ? "ui" : sb.ToString();
    }
}
