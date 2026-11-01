using System.Collections.Concurrent;

namespace AnisetteServer.Mac.Services;

public sealed record ConnectionLogEntry(
    DateTimeOffset AtUtc,
    string ClientIp,
    string Method,
    string Path,
    int StatusCode,
    string Outcome,
    string VpnHint,
    string? UserAgent,
    string? Forwarded);

/// <summary>In-memory ring of inbound connection events for the UI panel.</summary>
public sealed class ConnectionLogStore
{
    private readonly object _gate = new();
    private readonly LinkedList<ConnectionLogEntry> _entries = new();
    private readonly int _capacity;

    public ConnectionLogStore(int capacity = 500) =>
        _capacity = Math.Clamp(capacity, 50, 5000);

    public event Action? Changed;

    public void Add(ConnectionLogEntry entry)
    {
        lock (_gate)
        {
            _entries.AddFirst(entry);
            while (_entries.Count > _capacity)
                _entries.RemoveLast();
        }

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
}

/// <summary>
/// Burst limiter: more than <see cref="BurstLimit"/> requests from the same IP
/// inside <see cref="BurstWindow"/> → block that IP for <see cref="BlockDuration"/>.
/// </summary>
public sealed class AbuseRateLimiter
{
    public const int BurstLimit = 10;
    public static readonly TimeSpan BurstWindow = TimeSpan.FromSeconds(10);
    public static readonly TimeSpan BlockDuration = TimeSpan.FromHours(1);

    public const string ExcessiveOriginMessage =
        "richieste eccessive provenienti dalla stessa origine, attendere un'ora prima di riprovare";

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
