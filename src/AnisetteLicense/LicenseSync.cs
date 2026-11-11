using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace iCloudKitExtractor.AnisetteLicense;

/// <summary>
/// Cross-replica license sync. Typical peer for a single www hostname is the
/// Cloudflare Worker hub (<c>deploy/anisette-license-hub</c>) which answers as
/// replica id <c>license-hub</c>. Dedicated per-Mini hostnames also work.
/// </summary>
public static class LicenseSyncOptions
{
    public const string HeaderName = "X-Anisette-License-Sync";
    public const string HopHeaderName = "X-Anisette-Sync-Hop";
    public const string ReplicaHeaderName = "X-Anisette-Replica-Id";
    public const string HubReplicaId = "license-hub";
    public const string EnvPeers = "ANISETTE_LICENSE_PEERS";
    public const string EnvSecret = "ANISETTE_LICENSE_SYNC_SECRET";
    public const string EnvReplicaId = "ANISETTE_LICENSE_REPLICA_ID";
    public const string EnvAttempts = "ANISETTE_LICENSE_SYNC_ATTEMPTS";

    private static string? _cachedReplicaId;

    public static IReadOnlyList<string> PeerBaseUrls
    {
        get
        {
            var raw = Environment.GetEnvironmentVariable(EnvPeers)?.Trim();
            if (string.IsNullOrWhiteSpace(raw))
                return Array.Empty<string>();
            return raw.Split([',', ';', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Select(u => u.TrimEnd('/'))
                .Where(u => u.StartsWith("http://", StringComparison.OrdinalIgnoreCase)
                            || u.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                .Distinct(StringComparer.OrdinalIgnoreCase)
                .ToList();
        }
    }

    public static string? SyncSecret =>
        Environment.GetEnvironmentVariable(EnvSecret)?.Trim();

    public static bool IsConfigured =>
        PeerBaseUrls.Count > 0 && !string.IsNullOrWhiteSpace(SyncSecret);

    public static int SyncAttempts
    {
        get
        {
            var raw = Environment.GetEnvironmentVariable(EnvAttempts)?.Trim();
            if (int.TryParse(raw, out var n) && n is >= 1 and <= 40)
                return n;
            return 12;
        }
    }

    public static string LocalReplicaId
    {
        get
        {
            if (!string.IsNullOrWhiteSpace(_cachedReplicaId))
                return _cachedReplicaId;

            var env = Environment.GetEnvironmentVariable(EnvReplicaId)?.Trim();
            if (!string.IsNullOrWhiteSpace(env))
            {
                _cachedReplicaId = env;
                return env;
            }

            try
            {
                Directory.CreateDirectory(LicensePaths.DataDir);
                var path = Path.Combine(LicensePaths.DataDir, "replica-id.txt");
                if (File.Exists(path))
                {
                    var existing = File.ReadAllText(path).Trim();
                    if (!string.IsNullOrWhiteSpace(existing))
                    {
                        _cachedReplicaId = existing;
                        return existing;
                    }
                }

                var generated = "r-" + Guid.NewGuid().ToString("N")[..12];
                File.WriteAllText(path, generated);
                _cachedReplicaId = generated;
                return generated;
            }
            catch
            {
                _cachedReplicaId = "r-" + Guid.NewGuid().ToString("N")[..12];
                return _cachedReplicaId;
            }
        }
    }

    public static void InvalidateReplicaIdCache() => _cachedReplicaId = null;

    public static bool IsAuthorized(string? syncHeader, string? authorizationHeader)
    {
        var secret = SyncSecret;
        if (string.IsNullOrWhiteSpace(secret))
            return false;
        if (!string.IsNullOrWhiteSpace(syncHeader)
            && string.Equals(syncHeader.Trim(), secret, StringComparison.Ordinal))
            return true;
        if (!string.IsNullOrWhiteSpace(authorizationHeader)
            && authorizationHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)
            && string.Equals(authorizationHeader["Bearer ".Length..].Trim(), secret, StringComparison.Ordinal))
            return true;
        return false;
    }

    /// <summary>True when the response came from the Worker hub or another Mini (not self).</summary>
    public static bool IsSuccessfulSyncPeer(string? responseReplicaId)
    {
        if (string.IsNullOrWhiteSpace(responseReplicaId))
            return false;
        var id = responseReplicaId.Trim();
        if (string.Equals(id, HubReplicaId, StringComparison.OrdinalIgnoreCase))
            return true;
        return !string.Equals(id, LocalReplicaId, StringComparison.OrdinalIgnoreCase);
    }
}

public sealed class LicenseSyncRecord
{
    [JsonPropertyName("license_id")]
    public string LicenseId { get; set; } = "";

    [JsonPropertyName("subject")]
    public string Subject { get; set; } = "";

    [JsonPropertyName("issued_at")]
    public string IssuedAt { get; set; } = "";

    [JsonPropertyName("expires_at")]
    public string? ExpiresAt { get; set; }

    [JsonPropertyName("revoked_at")]
    public string? RevokedAt { get; set; }

    [JsonPropertyName("note")]
    public string? Note { get; set; }

    [JsonPropertyName("token_hint")]
    public string? TokenHint { get; set; }

    [JsonPropertyName("fingerprint")]
    public string? Fingerprint { get; set; }

    [JsonPropertyName("client_ip")]
    public string? ClientIp { get; set; }

    [JsonPropertyName("enabled")]
    public bool Enabled { get; set; } = true;

    [JsonPropertyName("emitted_once")]
    public bool EmittedOnce { get; set; }

    public static LicenseSyncRecord FromRow(LicenseRow row, string? tokenHint = null) => new()
    {
        LicenseId = row.LicenseId,
        Subject = row.Subject,
        IssuedAt = row.IssuedAt,
        ExpiresAt = row.ExpiresAt,
        RevokedAt = row.RevokedAt,
        Note = row.Note,
        TokenHint = tokenHint,
        Fingerprint = row.Fingerprint,
        ClientIp = row.ClientIp,
        Enabled = row.Enabled,
        EmittedOnce = row.EmittedOnce,
    };
}

public sealed class LicenseSyncClient
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };

    private readonly HttpClient _http;
    private readonly LicenseDatabase _db;

    public LicenseSyncClient(HttpClient http, LicenseDatabase db)
    {
        _http = http;
        _db = db;
    }

    public void UpsertLocal(LicenseSyncRecord record) => _db.UpsertSync(record);

    /// <returns>True if the hub or another replica acknowledged the row.</returns>
    public async Task<bool> PushAsync(LicenseSyncRecord record, CancellationToken ct = default)
    {
        if (!LicenseSyncOptions.IsConfigured)
            return false;

        var secret = LicenseSyncOptions.SyncSecret!;
        var attempts = LicenseSyncOptions.SyncAttempts;
        var reached = false;

        foreach (var peer in LicenseSyncOptions.PeerBaseUrls)
        {
            for (var i = 0; i < attempts && !reached; i++)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Post, peer + "/internal/license-sync");
                    req.Headers.TryAddWithoutValidation(LicenseSyncOptions.HeaderName, secret);
                    req.Headers.TryAddWithoutValidation(LicenseSyncOptions.HopHeaderName, "1");
                    req.Content = JsonContent.Create(record, options: JsonOpts);
                    using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
                    var remoteId = ReadReplicaId(resp);
                    if (resp.IsSuccessStatusCode && LicenseSyncOptions.IsSuccessfulSyncPeer(remoteId))
                        reached = true;
                }
                catch
                {
                    // peer unreachable / tunnel blip — retry
                }

                if (!reached && i + 1 < attempts)
                    await Task.Delay(40 + (i * 25), ct).ConfigureAwait(false);
            }
        }

        return reached;
    }

    public async Task<bool> PushRowAsync(LicenseRow row, string? tokenHint = null, CancellationToken ct = default) =>
        await PushAsync(LicenseSyncRecord.FromRow(row, tokenHint), ct).ConfigureAwait(false);

    public async Task<LicenseSyncRecord?> PullByIdAsync(string licenseId, CancellationToken ct = default)
    {
        if (!LicenseSyncOptions.IsConfigured || string.IsNullOrWhiteSpace(licenseId))
            return null;

        return await PullWithRetriesAsync(
            peer => peer + "/internal/license/" + Uri.EscapeDataString(licenseId.Trim()),
            acceptNotFoundFromOther: true,
            ct).ConfigureAwait(false);
    }

    public async Task<LicenseSyncRecord?> PullByFingerprintAsync(string fingerprint, CancellationToken ct = default)
    {
        if (!LicenseSyncOptions.IsConfigured || string.IsNullOrWhiteSpace(fingerprint))
            return null;

        return await PullWithRetriesAsync(
            peer => peer + "/internal/license/by-fingerprint/" + Uri.EscapeDataString(fingerprint.Trim()),
            acceptNotFoundFromOther: true,
            ct).ConfigureAwait(false);
    }

    /// <summary>Pull every id listed by the hub index into the local SQLite DB.</summary>
    public async Task<int> PullAllFromHubAsync(CancellationToken ct = default)
    {
        if (!LicenseSyncOptions.IsConfigured)
            return 0;

        var ids = await PullIndexAsync(ct).ConfigureAwait(false);
        var n = 0;
        foreach (var id in ids)
        {
            var rec = await PullByIdAsync(id, ct).ConfigureAwait(false);
            if (rec is not null)
                n++;
        }

        return n;
    }

    public async Task<IReadOnlyList<string>> PullIndexAsync(CancellationToken ct = default)
    {
        if (!LicenseSyncOptions.IsConfigured)
            return Array.Empty<string>();

        var secret = LicenseSyncOptions.SyncSecret!;
        var attempts = LicenseSyncOptions.SyncAttempts;

        foreach (var peer in LicenseSyncOptions.PeerBaseUrls)
        {
            for (var i = 0; i < attempts; i++)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, peer + "/internal/license/index");
                    req.Headers.TryAddWithoutValidation(LicenseSyncOptions.HeaderName, secret);
                    req.Headers.TryAddWithoutValidation(LicenseSyncOptions.HopHeaderName, "1");
                    using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
                    var remoteId = ReadReplicaId(resp);
                    if (!LicenseSyncOptions.IsSuccessfulSyncPeer(remoteId))
                    {
                        if (i + 1 < attempts)
                            await Task.Delay(40 + (i * 25), ct).ConfigureAwait(false);
                        continue;
                    }

                    if (!resp.IsSuccessStatusCode)
                    {
                        if (i + 1 < attempts)
                            await Task.Delay(40 + (i * 25), ct).ConfigureAwait(false);
                        continue;
                    }

                    await using var stream = await resp.Content.ReadAsStreamAsync(ct).ConfigureAwait(false);
                    using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct).ConfigureAwait(false);
                    if (!doc.RootElement.TryGetProperty("ids", out var arr)
                        || arr.ValueKind != JsonValueKind.Array)
                        return Array.Empty<string>();

                    return arr.EnumerateArray()
                        .Select(e => e.GetString()?.Trim())
                        .Where(s => !string.IsNullOrWhiteSpace(s))
                        .Select(s => s!)
                        .Distinct(StringComparer.OrdinalIgnoreCase)
                        .ToList();
                }
                catch
                {
                    // retry
                }

                if (i + 1 < attempts)
                    await Task.Delay(40 + (i * 25), ct).ConfigureAwait(false);
            }
        }

        return Array.Empty<string>();
    }

    private async Task<LicenseSyncRecord?> PullWithRetriesAsync(
        Func<string, string> urlForPeer,
        bool acceptNotFoundFromOther,
        CancellationToken ct)
    {
        var secret = LicenseSyncOptions.SyncSecret!;
        var attempts = LicenseSyncOptions.SyncAttempts;

        foreach (var peer in LicenseSyncOptions.PeerBaseUrls)
        {
            for (var i = 0; i < attempts; i++)
            {
                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Get, urlForPeer(peer));
                    req.Headers.TryAddWithoutValidation(LicenseSyncOptions.HeaderName, secret);
                    req.Headers.TryAddWithoutValidation(LicenseSyncOptions.HopHeaderName, "1");
                    using var resp = await _http.SendAsync(req, ct).ConfigureAwait(false);
                    var remoteId = ReadReplicaId(resp);

                    if (!LicenseSyncOptions.IsSuccessfulSyncPeer(remoteId))
                    {
                        if (i + 1 < attempts)
                            await Task.Delay(40 + (i * 25), ct).ConfigureAwait(false);
                        continue;
                    }

                    if (resp.StatusCode == System.Net.HttpStatusCode.NotFound && acceptNotFoundFromOther)
                        return null;

                    if (!resp.IsSuccessStatusCode)
                    {
                        if (i + 1 < attempts)
                            await Task.Delay(40 + (i * 25), ct).ConfigureAwait(false);
                        continue;
                    }

                    var rec = await resp.Content.ReadFromJsonAsync<LicenseSyncRecord>(JsonOpts, ct)
                        .ConfigureAwait(false);
                    if (rec is not null && !string.IsNullOrWhiteSpace(rec.LicenseId))
                    {
                        _db.UpsertSync(rec);
                        return rec;
                    }
                }
                catch
                {
                    // try again
                }

                if (i + 1 < attempts)
                    await Task.Delay(40 + (i * 25), ct).ConfigureAwait(false);
            }
        }

        return null;
    }

    private static string? ReadReplicaId(HttpResponseMessage resp)
    {
        if (resp.Headers.TryGetValues(LicenseSyncOptions.ReplicaHeaderName, out var values))
            return values.FirstOrDefault();
        return null;
    }
}
