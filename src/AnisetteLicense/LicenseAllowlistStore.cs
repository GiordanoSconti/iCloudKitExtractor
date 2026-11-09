using System.Text.Json;
using System.Text.Json.Serialization;

namespace iCloudKitExtractor.AnisetteLicense;

/// <summary>
/// Operator allowlist of licenses permitted in the Authorization header.
/// Entries may be license IDs, subjects, Package-C Base64, or raw Bearer tokens (one per line).
/// Persisted under <c>{dataRoot}/data/license-allowlist.json</c>.
/// </summary>
public sealed class LicenseAllowlistStore : ILicenseAllowlist
{
    private readonly object _gate = new();
    private readonly List<string> _allowed = new();
    private string? _path;
    private bool _enforced;

    public event Action? Changed;

    public bool IsEnforced
    {
        get
        {
            lock (_gate)
                return _enforced;
        }
    }

    public IReadOnlyList<string> AllowedEntries
    {
        get
        {
            lock (_gate)
                return _allowed.ToList();
        }
    }

    public void Configure(string dataRoot, bool enforce, IEnumerable<string>? seed = null)
    {
        lock (_gate)
        {
            Directory.CreateDirectory(Path.Combine(dataRoot, "data"));
            _path = Path.Combine(dataRoot, "data", "license-allowlist.json");
            _enforced = enforce;
            _allowed.Clear();
            if (seed is not null)
            {
                foreach (var e in seed)
                    AddUnlocked(e);
            }

            LoadUnlocked();
            _enforced = enforce;
            SaveUnlocked();
        }

        Changed?.Invoke();
    }

    public void SetEnforced(bool value)
    {
        lock (_gate)
        {
            _enforced = value;
            SaveUnlocked();
        }

        Changed?.Invoke();
    }

    public void SetFromText(string? multiline)
    {
        lock (_gate)
        {
            _allowed.Clear();
            if (!string.IsNullOrWhiteSpace(multiline))
            {
                foreach (var line in multiline.Split(
                             ['\r', '\n'],
                             StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                    AddUnlocked(line);
            }

            SaveUnlocked();
        }

        Changed?.Invoke();
    }

    public bool TryAdd(string entry)
    {
        lock (_gate)
        {
            if (!AddUnlocked(entry))
                return false;
            SaveUnlocked();
        }

        Changed?.Invoke();
        return true;
    }

    public bool IsAllowed(LicensePayload payload, string rawBearerOrBundle)
    {
        lock (_gate)
        {
            if (!_enforced)
                return true;

            if (_allowed.Count == 0)
                return false;

            var raw = (rawBearerOrBundle ?? "").Trim();
            if (raw.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                raw = raw["Bearer ".Length..].Trim();

            foreach (var entry in _allowed)
            {
                if (EntryMatches(entry, payload, raw))
                    return true;
            }

            return false;
        }
    }

    private static bool EntryMatches(string entry, LicensePayload payload, string raw)
    {
        if (string.IsNullOrWhiteSpace(entry))
            return false;

        if (!string.IsNullOrWhiteSpace(payload.LicenseId)
            && string.Equals(entry, payload.LicenseId, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.IsNullOrWhiteSpace(payload.Subject)
            && string.Equals(entry, payload.Subject, StringComparison.OrdinalIgnoreCase))
            return true;

        if (!string.IsNullOrEmpty(raw)
            && string.Equals(entry, raw, StringComparison.Ordinal))
            return true;

        // Package-C: compare license_id inside bundle if entry is a bundle.
        if (LicenseBundle.TryParseBase64(entry, out var bundle, out _)
            && bundle is not null
            && !string.IsNullOrWhiteSpace(bundle.LicenseId)
            && string.Equals(bundle.LicenseId, payload.LicenseId, StringComparison.OrdinalIgnoreCase))
            return true;

        // Prefix match for truncated IDs shown in UI (at least 8 hex chars).
        if (entry.Length >= 8
            && !string.IsNullOrWhiteSpace(payload.LicenseId)
            && payload.LicenseId.StartsWith(entry, StringComparison.OrdinalIgnoreCase)
            && entry.All(c => char.IsAsciiHexDigit(c)))
            return true;

        return false;
    }

    private bool AddUnlocked(string? raw)
    {
        var e = (raw ?? "").Trim();
        if (e.Length < 2 || e.StartsWith('#'))
            return false;
        if (e.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
            e = e["Bearer ".Length..].Trim();
        if (e.Length < 2)
            return false;
        if (_allowed.Any(x => string.Equals(x, e, StringComparison.Ordinal)))
            return false;
        _allowed.Add(e);
        return true;
    }

    private void LoadUnlocked()
    {
        if (string.IsNullOrEmpty(_path) || !File.Exists(_path))
            return;
        try
        {
            var json = File.ReadAllText(_path);
            var dto = JsonSerializer.Deserialize<AllowlistFile>(json);
            if (dto is null)
                return;
            _enforced = dto.Enforce;
            _allowed.Clear();
            foreach (var e in dto.Allowed ?? [])
                AddUnlocked(e);
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
        var dto = new AllowlistFile
        {
            Enforce = _enforced,
            Allowed = _allowed.ToList(),
        };
        File.WriteAllText(
            _path,
            JsonSerializer.Serialize(dto, new JsonSerializerOptions { WriteIndented = true }));
    }

    private sealed class AllowlistFile
    {
        [JsonPropertyName("enforce")]
        public bool Enforce { get; set; }

        [JsonPropertyName("allowed")]
        public List<string>? Allowed { get; set; }
    }
}

/// <summary>No-op allowlist (enforcement off) for hosts that do not configure one.</summary>
public sealed class PermissiveLicenseAllowlist : ILicenseAllowlist
{
    public static PermissiveLicenseAllowlist Instance { get; } = new();

    public bool IsEnforced => false;

    public bool IsAllowed(LicensePayload payload, string rawBearerOrBundle) => true;
}
