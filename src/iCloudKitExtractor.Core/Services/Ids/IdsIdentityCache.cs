namespace iCloudKitExtractor.Services.Ids;

/// <summary>Cache risultati <c>id-query</c> per (topic, selfHandle, peerUri).</summary>
public sealed class IdsIdentityCache
{
    private readonly object _gate = new();
    private readonly Dictionary<string, CacheEntry> _entries = new(StringComparer.Ordinal);

    public void Put(string topic, string selfHandle, IdsPeerIdentity identity)
    {
        ArgumentNullException.ThrowIfNull(identity);
        var key = MakeKey(topic, selfHandle, identity.Uri);
        var expires = DateTimeOffset.UtcNow.AddSeconds(
            Math.Max(60, identity.SessionTokenExpiresSeconds ?? 3600));
        lock (_gate)
        {
            _entries[key] = new CacheEntry(identity, expires, topic, selfHandle);
        }
    }

    public void PutAll(string topic, string selfHandle, IEnumerable<IdsPeerIdentity> identities)
    {
        foreach (var id in identities)
            Put(topic, selfHandle, id);
    }

    public bool TryGet(
        string topic,
        string selfHandle,
        string peerUri,
        out IdsPeerIdentity? identity)
    {
        identity = null;
        var key = MakeKey(topic, selfHandle, peerUri);
        lock (_gate)
        {
            if (!_entries.TryGetValue(key, out var entry))
                return false;
            if (entry.ExpiresUtc <= DateTimeOffset.UtcNow)
            {
                _entries.Remove(key);
                return false;
            }

            identity = entry.Identity;
            return true;
        }
    }

    public IReadOnlyList<IdsPeerIdentity> GetTargets(
        string topic,
        string selfHandle,
        IEnumerable<string> peerUris)
    {
        var list = new List<IdsPeerIdentity>();
        foreach (var uri in peerUris)
        {
            if (TryGet(topic, selfHandle, uri, out var id) && id is not null)
                list.Add(id);
        }

        return list;
    }

    public void Clear()
    {
        lock (_gate)
            _entries.Clear();
    }

    public int Count
    {
        get
        {
            lock (_gate)
                return _entries.Count;
        }
    }

    private static string MakeKey(string topic, string selfHandle, string peerUri) =>
        topic.Trim() + "\n" + selfHandle.Trim() + "\n" + peerUri.Trim();

    private sealed record CacheEntry(
        IdsPeerIdentity Identity,
        DateTimeOffset ExpiresUtc,
        string Topic,
        string SelfHandle);
}
