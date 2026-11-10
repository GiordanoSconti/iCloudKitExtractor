using System.IO;
using System.Text;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Ids;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.IMessage;

/// <summary>
/// IDS handle lookup (keyserver) for Madrid via HTTP-over-APNs (pypush <c>ids/query.py</c>).
/// Direct HTTPS to identity.ess returns 401 — Apple expects the APNs tunnel.
/// </summary>
public sealed class IdsLookupClient
{
    private readonly IdsBag _bag;
    private readonly IdsUserDirectory _directory;

    public IdsLookupClient(HttpClient http, IdsBag bag, IdsUserDirectory directory)
    {
        _ = http;
        _bag = bag;
        _directory = directory;
    }

    public Task<IdsLookupResult> LookupAsync(
        string handle,
        string profileId,
        string idKeyPem,
        string idCertPem,
        byte[] pushToken,
        Action<string>? log = null,
        CancellationToken ct = default) =>
        LookupAsync(handle, profileId, idKeyPem, idCertPem, pushToken, null, null, null, null, log, ct);

    public Task<IdsLookupResult> LookupAsync(
        string handle,
        string profileId,
        string idKeyPem,
        string idCertPem,
        byte[] pushToken,
        string? pushKeyPem,
        string? pushCertPem,
        Action<string>? log = null,
        CancellationToken ct = default) =>
        LookupAsync(handle, profileId, idKeyPem, idCertPem, pushToken, pushKeyPem, pushCertPem, null, null, log, ct);

    public async Task<IdsLookupResult> LookupAsync(
        string handle,
        string profileId,
        string idKeyPem,
        string idCertPem,
        byte[] pushToken,
        string? pushKeyPem,
        string? pushCertPem,
        ApsCourierClient? courier,
        string? selfUri,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        _ = profileId;
        _ = pushKeyPem;
        _ = pushCertPem;
        var uri = NormalizeHandle(handle);
        log?.Invoke($"IDS lookup: {uri}");

        try
        {
            if (courier is null || !courier.IsConnected)
                throw new InvalidOperationException(
                    "APS courier required for id-query (HTTP-over-APNs). Connect APS first.");

            await _bag.EnsureLoadedAsync(ct).ConfigureAwait(false);
            var snap = await _bag.SnapshotAsync(ct).ConfigureAwait(false);
            var url = snap.GetValueOrDefault("id-query")
                      ?? snap.GetValueOrDefault("id-query-gateway")
                      ?? throw new InvalidOperationException("IDS bag missing id-query URL.");

            var bodyDict = new Dictionary<string, object?>
            {
                ["uris"] = new List<object?> { uri },
            };
            var xml = AppleXmlPlist.ToXmlBytes(bodyDict);
            var gzipped = IdsSigning.GzipMtime0(xml);

            var self = string.IsNullOrWhiteSpace(selfUri)
                ? uri
                : NormalizeHandle(selfUri!);
            var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                ["x-id-self-uri"] = self,
                ["x-protocol-version"] = IdsConstants.ProtocolVersion,
                ["User-Agent"] = "com.apple.madrid-lookup [macOS,13.2.1,22D68]",
            };
            // pypush add_id_signature: ID sig only (no push-sig) for id-query.
            IdsSigning.AddIdSignature(headers, gzipped, "id-query", idKeyPem, idCertPem, pushToken);

            log?.Invoke($"IDS lookup via APNs → {url}");
            var unzipped = await courier
                .HttpOverApnsAsync("com.apple.madrid", url, headers, gzipped, ct)
                .ConfigureAwait(false);
            log?.Invoke($"IDS lookup APNs OK, body={unzipped.Length} B");

            var result = ParseLookupResponse(uri, unzipped, log);
            _directory.Put(uri, result);
            return result;
        }
        catch (Exception ex)
        {
            log?.Invoke("IDS lookup error: " + ex.Message);
            var fail = new IdsLookupResult { Handle = uri, Success = false, Error = ex.Message };
            _directory.Put(uri, fail);
            return fail;
        }
    }

    private static IdsLookupResult ParseLookupResponse(string handle, byte[] data, Action<string>? log)
    {
        try
        {
            var dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "iCloudKitExtractor", "madrid-persona");
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(Path.Combine(dir, "last-id-query.bin"), data);
        }
        catch
        {
            // ignore
        }

        Dictionary<string, object?> root;
        if (data.Length >= 6 && data.AsSpan(0, 6).SequenceEqual("bplist"u8))
        {
            if (!AppleBinaryPlist.TryParseDict(data, out var dict, out var err) || dict is null)
                return new IdsLookupResult { Handle = handle, Success = false, Error = err };
            root = dict;
        }
        else
        {
            root = AppleXmlPlist.Parse(data);
        }

        log?.Invoke(
            "IDS lookup root keys=["
            + string.Join(", ", root.Keys)
            + "] status="
            + (AppleXmlPlist.GetInt(root, "status")?.ToString() ?? "?"));

        var status = AppleXmlPlist.GetInt(root, "status");
        if (status is not null and not 0)
        {
            return new IdsLookupResult
            {
                Handle = handle,
                Success = false,
                Error = $"status={status} {AppleXmlPlist.GetString(root, "message")}"
            };
        }

        var identities = new List<IdsRemoteIdentity>();
        if (root.TryGetValue("results", out var resultsObj)
            && resultsObj is Dictionary<string, object?> results)
        {
            log?.Invoke(
                "IDS lookup results keys=["
                + string.Join(", ", results.Keys)
                + "]");

            // Match URI case-insensitively (Apple sometimes normalizes mailto).
            object? perHandle = null;
            foreach (var kv in results)
            {
                if (string.Equals(kv.Key, handle, StringComparison.OrdinalIgnoreCase))
                {
                    perHandle = kv.Value;
                    break;
                }
            }

            // Fallback: single-entry results map.
            if (perHandle is null && results.Count == 1)
                perHandle = results.Values.First();

            if (perHandle is Dictionary<string, object?> perDict)
            {
                var uriStatus = AppleXmlPlist.GetInt(perDict, "status");
                log?.Invoke(
                    $"IDS lookup per-uri keys=[{string.Join(", ", perDict.Keys)}] "
                    + $"uriStatus={uriStatus?.ToString() ?? "-"}");
                if (perDict.TryGetValue("identities", out var idObj) && idObj is List<object?> idList)
                {
                    foreach (var item in idList)
                        TryAddIdentity(identities, item);
                }
            }
        }
        else if (root.TryGetValue("identities", out var flat)
                 && flat is List<object?> flatList)
        {
            foreach (var item in flatList)
                TryAddIdentity(identities, item);
        }

        log?.Invoke($"IDS lookup: {identities.Count} identity(ies) for {handle}");
        string? errMsg = null;
        if (identities.Count == 0)
        {
            errMsg =
                "no identities in response — Apple often returns empty results for "
                + "unofficial / low-score registrations (warmup). "
                + "Saved %AppData%/iCloudKitExtractor/madrid-persona/last-id-query.bin";
        }

        return new IdsLookupResult
        {
            Handle = handle,
            Success = identities.Count > 0,
            Identities = identities,
            Error = errMsg,
        };
    }

    private static void TryAddIdentity(List<IdsRemoteIdentity> list, object? item)
    {
        if (item is not Dictionary<string, object?> d)
            return;
        var push = AppleXmlPlist.GetData(d, "push-token")
                   ?? AppleXmlPlist.GetData(d, "pushToken");
        var session = AppleXmlPlist.GetData(d, "session-token")
                      ?? AppleXmlPlist.GetData(d, "sessionToken");
        var pub = AppleXmlPlist.GetData(d, "client-data")
                  ?? AppleXmlPlist.GetData(d, "public-message-identity-key");
        if (pub is null
            && d.TryGetValue("client-data", out var cd)
            && cd is Dictionary<string, object?> cdDict)
        {
            pub = AppleXmlPlist.GetData(cdDict, "public-message-identity-key");
        }

        list.Add(new IdsRemoteIdentity
        {
            PushTokenHex = push is null ? null : Convert.ToHexString(push),
            SessionToken = session is null ? null : Convert.ToBase64String(session),
            PublicIdentity = pub,
            DeviceName = AppleXmlPlist.GetString(d, "device-name"),
        });
    }

    public static string NormalizeHandle(string handle)
    {
        var h = handle.Trim();
        if (h.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase)
            || h.StartsWith("tel:", StringComparison.OrdinalIgnoreCase))
            return h;
        if (h.Contains('@', StringComparison.Ordinal))
            return "mailto:" + h;
        var digits = new string(h.Where(char.IsDigit).ToArray());
        if (digits.Length >= 8)
            return "tel:+" + digits.TrimStart('0');
        return h;
    }
}
