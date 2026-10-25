using System.Collections.Concurrent;
using System.IO;
using System.Text;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Download;

/// <summary>
/// Cache chunk MMCS cifrati (modello <c>CChunkCache</c>).
/// Default: <b>solo RAM</b> (<see cref="ConcurrentDictionary{TKey,TValue}"/>) — niente WriteAllBytes
/// per chunk sul hot path. Spill disco opzionale via <c>IKE_MMCS_CACHE_DISK=1</c>.
/// Chiave primaria: hex(checksum21); fallback: slot host+range.
/// </summary>
public sealed class MmcsChunkStore
{
    private readonly string _root;
    private readonly bool _persistToDisk;
    private readonly ConcurrentDictionary<string, byte[]> _ram =
        new(StringComparer.OrdinalIgnoreCase);

    // #region agent log
    private long _putCount;
    private long _putBytes;
    private long _getHit;
    private long _getMiss;
    // #endregion

    public MmcsChunkStore(string rootDirectory, bool? persistToDisk = null)
    {
        _root = rootDirectory;
        _persistToDisk = persistToDisk
            ?? string.Equals(
                Environment.GetEnvironmentVariable("IKE_MMCS_CACHE_DISK"),
                "1",
                StringComparison.Ordinal);
        if (_persistToDisk)
            Directory.CreateDirectory(_root);
    }

    public string RootDirectory => _root;

    /// <summary>True se i Put vanno anche su disco (debug / compat).</summary>
    public bool PersistToDisk => _persistToDisk;

    public int EntryCount => _ram.Count;

    public long ApproximateBytes
    {
        get
        {
            // Stessa istanza byte[] può essere aliasata sotto più chiavi (host+sig).
            long n = 0;
            var seen = new HashSet<object>(ReferenceEqualityComparer.Instance);
            foreach (var kv in _ram)
            {
                if (!seen.Add(kv.Value))
                    continue;
                n += kv.Value.LongLength;
            }

            return n;
        }
    }

    public static string SignatureToKey(ReadOnlySpan<byte> signature21) =>
        Convert.ToHexString(signature21).ToLowerInvariant();

    public static string HostRangeKey(int containerIndex, string objectId, long start, long end)
    {
        var safeOid = SanitizeFileToken(objectId);
        return $"host_{containerIndex}_{safeOid}_{start}_{end}";
    }

    public bool Has(string key)
    {
        if (string.IsNullOrEmpty(key))
            return false;
        if (_ram.ContainsKey(key))
            return true;
        if (!_persistToDisk)
            return false;
        return File.Exists(Path.Combine(_root, key));
    }

    public void Put(string key, ReadOnlySpan<byte> body)
    {
        if (string.IsNullOrEmpty(key))
            throw new ArgumentException("Cache key required", nameof(key));

        var copy = body.ToArray();
        PutShared([key], copy);
    }

    /// <summary>
    /// Una sola istanza <paramref name="body"/> sotto tutte le <paramref name="keys"/>
    /// (host-range + signature) — evita 2× RAM per ogni chunk.
    /// </summary>
    public void PutShared(IReadOnlyList<string> keys, byte[] body)
    {
        if (keys.Count == 0 || body is null)
            return;

        var first = true;
        foreach (var key in keys)
        {
            if (string.IsNullOrEmpty(key))
                continue;
            _ram[key] = body;
            // .chunks/<hex(sig)>: solo checksum21 (42 hex). Mai Gate45 (90 hex) —
            // i Ford vanno in cache solo dopo IKM-open (PutChunks / BindOwnedFord).
            if (key.Length == 42 && ChunkFileCache.IsSignatureFileName(key))
                ChunkFileCache.Put(Convert.FromHexString(key), body);
            if (!first)
                continue;
            first = false;
            // #region agent log
            Interlocked.Increment(ref _putCount);
            Interlocked.Add(ref _putBytes, body.LongLength);
            // #endregion
            if (_persistToDisk)
                File.WriteAllBytes(Path.Combine(_root, key), body);
        }
    }

    public byte[]? TryGet(string key)
    {
        if (string.IsNullOrEmpty(key))
            return null;

        if (_ram.TryGetValue(key, out var hit))
        {
            // #region agent log
            Interlocked.Increment(ref _getHit);
            // #endregion
            return hit;
        }

        if (!_persistToDisk)
        {
            // #region agent log
            Interlocked.Increment(ref _getMiss);
            // #endregion
            return null;
        }

        var path = Path.Combine(_root, key);
        if (!File.Exists(path))
        {
            // #region agent log
            Interlocked.Increment(ref _getMiss);
            // #endregion
            return null;
        }

        var fromDisk = File.ReadAllBytes(path);
        _ram[key] = fromDisk;
        // #region agent log
        Interlocked.Increment(ref _getHit);
        // #endregion
        return fromDisk;
    }

    public bool Remove(string key)
    {
        if (string.IsNullOrEmpty(key))
            return false;

        var removed = _ram.TryRemove(key, out _);
        if (_persistToDisk)
        {
            var path = Path.Combine(_root, key);
            if (File.Exists(path))
            {
                try
                {
                    File.Delete(path);
                    removed = true;
                }
                catch
                {
                    // Non bloccare il download per un file locked.
                }
            }
        }

        return removed;
    }

    /// <summary>
    /// Elimina tutti i chunk in cache (RAM + eventuale spill disco).
    /// </summary>
    public int Clear()
    {
        // #region agent log
        AgentRamCachePerfLog("clear");
        // #endregion

        var removed = _ram.Count;
        _ram.Clear();

        if (!_persistToDisk || !Directory.Exists(_root))
            return removed;

        foreach (var path in Directory.EnumerateFiles(_root))
        {
            try
            {
                File.Delete(path);
                removed++;
            }
            catch
            {
                // Non bloccare il download per un file locked.
            }
        }

        return removed;
    }

    // #region agent log
    public void AgentRamCachePerfLog(string reason)
    {
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "mmcs-ram-cache",
                ["hypothesisId"] = "H-RAM-CACHE",
                ["location"] = "MmcsChunkStore",
                ["message"] = "mmcs_cache_perf",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new
                {
                    reason,
                    persistToDisk = _persistToDisk,
                    putCount = Interlocked.Read(ref _putCount),
                    putBytes = Interlocked.Read(ref _putBytes),
                    getHit = Interlocked.Read(ref _getHit),
                    getMiss = Interlocked.Read(ref _getMiss),
                    entryCount = _ram.Count,
                    approxBytes = ApproximateBytes,
                },
            });
            File.AppendAllText(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                line + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    private static string SanitizeFileToken(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "unknown";
        var sb = new StringBuilder(value.Length);
        foreach (var ch in value)
            sb.Append(char.IsAsciiLetterOrDigit(ch) || ch is '-' or '_' ? ch : '_');
        return sb.ToString();
    }
}
