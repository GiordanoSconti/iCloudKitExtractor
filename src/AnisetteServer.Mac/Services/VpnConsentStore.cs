using System.Collections.Concurrent;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace AnisetteServer.Mac.Services;

/// <summary>
/// Manual VPN consent allowlist. Operator recognizes a VPN (provider token, IP, or hint substring)
/// and adds a pattern; ConnectionGuard admits matching clients, blocks the rest when enabled.
/// </summary>
public sealed class VpnConsentStore
{
    private readonly object _gate = new();
    private readonly List<string> _allowed = new();
    private readonly ConcurrentDictionary<string, VpnConsentPending> _pending = new(StringComparer.OrdinalIgnoreCase);
    private string? _path;

    public event Action? Changed;

    public bool RequireConsent { get; private set; } = true;

    public void Configure(string dataRoot, bool requireConsent, IEnumerable<string>? seedPatterns = null)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(Path.Combine(dataRoot, "data"));
            _path = Path.Combine(dataRoot, "data", "vpn-consent.json");
            RequireConsent = requireConsent;
            _allowed.Clear();
            if (seedPatterns is not null)
            {
                foreach (var p in seedPatterns)
                    AddPatternUnlocked(p);
            }

            LoadUnlocked();
            // Settings may override require flag after load
            RequireConsent = requireConsent;
            SaveUnlocked();
        }

        Changed?.Invoke();
    }

    public IReadOnlyList<string> AllowedPatterns
    {
        get
        {
            lock (_gate)
                return _allowed.ToList();
        }
    }

    public IReadOnlyList<VpnConsentPending> Pending
    {
        get
        {
            return _pending.Values
                .OrderByDescending(p => p.LastSeenUtc)
                .Take(100)
                .ToList();
        }
    }

    public void SetRequireConsent(bool value)
    {
        lock (_gate)
        {
            RequireConsent = value;
            SaveUnlocked();
        }

        Changed?.Invoke();
    }

    public void SetAllowedFromText(string? multiline)
    {
        lock (_gate)
        {
            _allowed.Clear();
            if (!string.IsNullOrWhiteSpace(multiline))
            {
                foreach (var line in multiline.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    AddPatternUnlocked(line);
            }

            SaveUnlocked();
        }

        Changed?.Invoke();
    }

    public bool TryAllow(string pattern)
    {
        lock (_gate)
        {
            if (!AddPatternUnlocked(pattern))
                return false;
            SaveUnlocked();
        }

        // Drop pending that now match
        foreach (var kv in _pending.ToArray())
        {
            if (IsAllowed(kv.Value.ClientIp, kv.Value.VpnHint))
                _pending.TryRemove(kv.Key, out _);
        }

        Changed?.Invoke();
        return true;
    }

    public bool RemovePattern(string pattern)
    {
        lock (_gate)
        {
            var n = _allowed.RemoveAll(p => string.Equals(p, pattern.Trim(), StringComparison.OrdinalIgnoreCase));
            if (n == 0)
                return false;
            SaveUnlocked();
        }

        Changed?.Invoke();
        return true;
    }

    /// <summary>True if this client may pass the VPN consent gate.</summary>
    public bool IsAllowed(string? clientIp, string? vpnHint)
    {
        if (!RequireConsent)
            return true;
        if (!VpnHintProbe.LooksLikeVpnOrProxy(vpnHint))
            return true; // non-VPN traffic not gated here

        lock (_gate)
        {
            if (_allowed.Count == 0)
                return false;

            var ip = (clientIp ?? "").Trim();
            var hint = vpnHint ?? "";
            foreach (var p in _allowed)
            {
                // Ignore legacy ultra-generic entries (would open every "proxy" client).
                if (VpnHintProbe.IsGenericConsentToken(p) && !VpnHintProbe.LooksLikeIpLiteral(p))
                    continue;

                // IP literals match only the client address (not every "proxy" hint).
                if (VpnHintProbe.LooksLikeIpLiteral(p))
                {
                    if (IpEquals(ip, p))
                        return true;
                    continue;
                }

                if (hint.Contains(p, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
        }

        return false;
    }

    private static bool IpEquals(string clientIp, string pattern)
    {
        if (string.IsNullOrWhiteSpace(clientIp) || string.IsNullOrWhiteSpace(pattern))
            return false;
        var a = clientIp.Trim();
        var b = pattern.Trim();
        var slash = b.IndexOf('/');
        if (slash > 0)
            b = b[..slash];
        return string.Equals(a, b, StringComparison.OrdinalIgnoreCase);
    }

    public void RememberDenied(string clientIp, string vpnHint)
    {
        var key = string.IsNullOrWhiteSpace(clientIp) ? vpnHint : clientIp.Trim();
        if (string.IsNullOrWhiteSpace(key))
            return;

        var suggested = VpnHintProbe.SuggestConsentPattern(vpnHint, clientIp);
        _pending.AddOrUpdate(
            key,
            _ => new VpnConsentPending(clientIp, vpnHint, suggested, DateTimeOffset.UtcNow, 1),
            (_, old) => old with
            {
                VpnHint = vpnHint,
                SuggestedPattern = suggested,
                LastSeenUtc = DateTimeOffset.UtcNow,
                Hits = old.Hits + 1,
            });
        Changed?.Invoke();
    }

    public void ClearPending()
    {
        _pending.Clear();
        Changed?.Invoke();
    }

    private bool AddPatternUnlocked(string? raw)
    {
        var p = (raw ?? "").Trim();
        if (p.Length < 2 || p.StartsWith('#'))
            return false;
        // Refuse ultra-generic tokens — they would allow every VPN labeled "proxy"/"vpn".
        // Operators should allow the client IP instead.
        if (VpnHintProbe.IsGenericConsentToken(p) && !VpnHintProbe.LooksLikeIpLiteral(p))
            return false;
        if (_allowed.Any(x => string.Equals(x, p, StringComparison.OrdinalIgnoreCase)))
            return false;
        _allowed.Add(p);
        return true;
    }

    private void LoadUnlocked()
    {
        if (string.IsNullOrEmpty(_path) || !File.Exists(_path))
            return;
        try
        {
            var json = File.ReadAllText(_path);
            var dto = JsonSerializer.Deserialize<VpnConsentFile>(json);
            if (dto is null)
                return;
            RequireConsent = dto.RequireConsent;
            _allowed.Clear();
            foreach (var p in dto.Allowed ?? [])
                AddPatternUnlocked(p);
        }
        catch
        {
            // ignore corrupt file
        }
    }

    private void SaveUnlocked()
    {
        if (string.IsNullOrEmpty(_path))
            return;
        var dto = new VpnConsentFile
        {
            RequireConsent = RequireConsent,
            Allowed = _allowed.ToList(),
        };
        var json = JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true });
        File.WriteAllText(_path, json);
    }

    private sealed class VpnConsentFile
    {
        [JsonPropertyName("requireConsent")]
        public bool RequireConsent { get; set; } = true;

        [JsonPropertyName("allowed")]
        public List<string>? Allowed { get; set; }
    }
}

public sealed record VpnConsentPending(
    string ClientIp,
    string VpnHint,
    string SuggestedPattern,
    DateTimeOffset LastSeenUtc,
    int Hits);
