using System.Collections.Concurrent;
using System.Text;

namespace AnisetteServer.Mac.Services;

public sealed record ConnectionLogEntry(
    DateTimeOffset AtUtc,
    string ClientIp,
    string Method,
    string Path,
    string? Query,
    string? Scheme,
    string? Host,
    int StatusCode,
    string Outcome,
    string VpnHint,
    string? UserAgent,
    string? Forwarded,
    /// <summary>All request headers as multiline <c>Name: value</c> (Cloudflare + client).</summary>
    string AllHeaders);

/// <summary>In-memory ring of inbound connection events for the UI panel.</summary>
public sealed class ConnectionLogStore
{
    private readonly object _gate = new();
    private readonly LinkedList<ConnectionLogEntry> _entries = new();
    private readonly int _capacity;
    private string? _fileLogPath;

    public ConnectionLogStore(int capacity = 500) =>
        _capacity = Math.Clamp(capacity, 50, 5000);

    public event Action? Changed;

    /// <summary>Optional append-only file under the middleware data root.</summary>
    public void SetFileLogPath(string? path)
    {
        _fileLogPath = string.IsNullOrWhiteSpace(path) ? null : Path.GetFullPath(path);
        if (_fileLogPath is not null)
            Directory.CreateDirectory(Path.GetDirectoryName(_fileLogPath)!);
    }

    public void Add(ConnectionLogEntry entry)
    {
        lock (_gate)
        {
            _entries.AddFirst(entry);
            while (_entries.Count > _capacity)
                _entries.RemoveLast();
        }

        TryAppendFile(entry);
        Changed?.Invoke();
    }

    public IReadOnlyList<ConnectionLogEntry> Snapshot()
    {
        lock (_gate)
            return _entries.ToList();
    }

    public void Clear()
    {
        lock (_gate)
            _entries.Clear();
        Changed?.Invoke();
    }

    private void TryAppendFile(ConnectionLogEntry e)
    {
        var path = _fileLogPath;
        if (path is null)
            return;

        try
        {
            var sb = new StringBuilder(512 + (e.AllHeaders?.Length ?? 0));
            sb.AppendLine("====");
            sb.AppendLine($"{e.AtUtc:o}  {e.Method} {e.Scheme}://{e.Host}{e.Path}{e.Query}");
            sb.AppendLine($"client_ip={e.ClientIp}  status={e.StatusCode}  outcome={e.Outcome}");
            sb.AppendLine($"vpn={e.VpnHint}");
            if (!string.IsNullOrEmpty(e.Forwarded))
                sb.AppendLine($"forwarded_summary={e.Forwarded}");
            sb.AppendLine("-- headers --");
            sb.AppendLine(e.AllHeaders);
            sb.AppendLine();
            File.AppendAllText(path, sb.ToString());
        }
        catch
        {
            // UI log must not fail the request path
        }
    }
}

/// <summary>
/// Burst limiter Accedi: more than <see cref="BurstLimit"/> login-phase requests from the
/// same IP inside <see cref="BurstWindow"/> → block for <see cref="BlockDuration"/>.
/// Non si applica ai remint mid-download (<c>X-IKE-Anisette-Phase: session</c>).
/// </summary>
public sealed class AbuseRateLimiter
{
    public const int BurstLimit = 10;
    public static readonly TimeSpan BurstWindow = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan BlockDuration = TimeSpan.FromHours(1);

    public const string ExcessiveOriginMessage =
        "richieste eccessive in fase Accedi dalla stessa origine, attendere un'ora prima di riprovare";

    private readonly ConcurrentDictionary<string, IpState> _states = new(StringComparer.Ordinal);

    private sealed class IpState
    {
        public readonly object Gate = new();
        public readonly Queue<DateTimeOffset> Recent = new();
        public DateTimeOffset? BlockedUntilUtc;
    }

    public bool IsBlocked(string ip, out DateTimeOffset? untilUtc)
    {
        untilUtc = null;
        if (string.IsNullOrWhiteSpace(ip))
            return false;

        var state = _states.GetOrAdd(ip, _ => new IpState());
        lock (state.Gate)
        {
            if (state.BlockedUntilUtc is { } until && until > DateTimeOffset.UtcNow)
            {
                untilUtc = until;
                return true;
            }

            if (state.BlockedUntilUtc is not null)
                state.BlockedUntilUtc = null;
            return false;
        }
    }

    /// <summary>Record a request. Returns false when the IP must be rejected.</summary>
    public bool TryAdmit(string ip, out DateTimeOffset? blockedUntilUtc)
    {
        blockedUntilUtc = null;
        if (string.IsNullOrWhiteSpace(ip))
            return true;

        var now = DateTimeOffset.UtcNow;
        var state = _states.GetOrAdd(ip, _ => new IpState());
        lock (state.Gate)
        {
            if (state.BlockedUntilUtc is { } until && until > now)
            {
                blockedUntilUtc = until;
                return false;
            }

            state.BlockedUntilUtc = null;
            while (state.Recent.Count > 0 && now - state.Recent.Peek() > BurstWindow)
                state.Recent.Dequeue();

            state.Recent.Enqueue(now);
            if (state.Recent.Count > BurstLimit)
            {
                state.BlockedUntilUtc = now.Add(BlockDuration);
                blockedUntilUtc = state.BlockedUntilUtc;
                state.Recent.Clear();
                return false;
            }

            return true;
        }
    }
}
