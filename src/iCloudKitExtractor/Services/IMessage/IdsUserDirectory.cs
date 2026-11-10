using System.Collections.Concurrent;

namespace iCloudKitExtractor.Services.IMessage;

/// <summary>Cache of IDS lookup identities (public keys / push tokens / session tokens).</summary>
public sealed class IdsUserDirectory
{
    private readonly ConcurrentDictionary<string, IdsLookupResult> _cache =
        new(StringComparer.OrdinalIgnoreCase);

    public void Put(string handle, IdsLookupResult result) =>
        _cache[Normalize(handle)] = result;

    public bool TryGet(string handle, out IdsLookupResult result) =>
        _cache.TryGetValue(Normalize(handle), out result!);

    public void Clear() => _cache.Clear();

    public IReadOnlyDictionary<string, IdsLookupResult> Snapshot =>
        new Dictionary<string, IdsLookupResult>(_cache, StringComparer.OrdinalIgnoreCase);

    private static string Normalize(string handle) => handle.Trim();
}

public sealed class IdsLookupResult
{
    public string Handle { get; init; } = "";
    public bool Success { get; init; }
    public string? Error { get; init; }
    public List<IdsRemoteIdentity> Identities { get; init; } = [];
    public DateTimeOffset LookedUpUtc { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class IdsRemoteIdentity
{
    /// <summary>Push token of the remote device (hex).</summary>
    public string? PushTokenHex { get; init; }
    /// <summary>Session token proving a recent lookup (opaque base64/hex).</summary>
    public string? SessionToken { get; init; }
    /// <summary>Public message-identity blob (legacy / NGM).</summary>
    public byte[]? PublicIdentity { get; init; }
    public string? DeviceName { get; init; }
}
