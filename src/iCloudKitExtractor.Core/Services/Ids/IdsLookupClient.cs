using System.Net.Http.Headers;
using System.Text;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Ids;

/// <summary><c>id-query</c> — lookup identità peer (HTTP-over-APNs, fallback HTTPS).</summary>
public sealed class IdsLookupClient
{
    private readonly IdsBag _bag;
    private readonly IdsApsTransport _transport;
    private readonly HttpClient _http;
    private readonly Action<string>? _log;

    public IdsLookupClient(
        IdsBag bag,
        IdsApsTransport transport,
        HttpClient http,
        Action<string>? log = null)
    {
        _bag = bag;
        _transport = transport;
        _http = http;
        _log = log;
    }

    public async Task<IdsLookupResult> QueryAsync(
        string topic,
        string selfHandle,
        IReadOnlyList<string> uris,
        string idKeyPem,
        string idCertPem,
        byte[] pushToken,
        bool preferHttpOverApns = true,
        CancellationToken ct = default)
    {
        if (uris.Count == 0)
            throw new ArgumentException("Serve almeno un URI da interrogare.", nameof(uris));

        var url = await _bag.GetAsync("id-query", ct).ConfigureAwait(false);
        var bodyDict = new Dictionary<string, object?>
        {
            ["uris"] = uris.Cast<object?>().ToList(),
        };
        var xml = AppleXmlPlist.ToXmlBytes(bodyDict);
        var gzipped = IdsSigning.GzipMtime0(xml);

        var (pushKeyPem, pushCertPem) = ApsStorage.LoadCertificate();
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-id-self-uri"] = selfHandle,
            ["x-protocol-version"] = IdsConstants.ProtocolVersion,
            ["User-Agent"] = IdsConstants.LookupUserAgent,
            ["x-push-token"] = Convert.ToBase64String(pushToken),
            ["Content-Type"] = "application/x-apple-plist",
            ["Content-Encoding"] = "gzip",
        };
        IdsSigning.AddIdAndPushSignatures(
            headers, gzipped, "id-query",
            idKeyPem, idCertPem, pushKeyPem, pushCertPem, pushToken);

        byte[] responseBytes;
        if (preferHttpOverApns)
        {
            try
            {
                _log?.Invoke($"id-query via APS → {uris.Count} URI topic={topic}");
                responseBytes = await _transport.HttpOverApnsAsync(url, headers, gzipped, ct: ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                _log?.Invoke("id-query APS fallito (" + ex.Message + ") — fallback HTTPS…");
                responseBytes = await QueryHttpsAsync(url, headers, gzipped, ct).ConfigureAwait(false);
            }
        }
        else
        {
            responseBytes = await QueryHttpsAsync(url, headers, gzipped, ct).ConfigureAwait(false);
        }

        return ParseQueryResponse(topic, selfHandle, uris, responseBytes);
    }

    private async Task<byte[]> QueryHttpsAsync(
        string url,
        Dictionary<string, string> headers,
        byte[] gzipped,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        foreach (var (k, v) in headers)
            request.Headers.TryAddWithoutValidation(k, v);
        request.Content = new ByteArrayContent(gzipped);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-apple-plist");
        request.Content.Headers.ContentEncoding.Add("gzip");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        var unzipped = IdsSigning.TryGunzip(bytes) ?? bytes;
        _log?.Invoke($"id-query HTTPS {(int)response.StatusCode}, body={unzipped.Length} B");
        return unzipped;
    }

    internal static IdsLookupResult ParseQueryResponse(
        string topic,
        string selfHandle,
        IReadOnlyList<string> queried,
        byte[] responseBytes)
    {
        var root = ParsePlist(responseBytes);
        var status = AppleXmlPlist.GetInt(root, "status") ?? -1;
        var identities = new List<IdsPeerIdentity>();

        if (root.TryGetValue("results", out var resultsObj)
            && resultsObj is Dictionary<string, object?> results)
        {
            foreach (var (uri, value) in results)
            {
                if (value is not Dictionary<string, object?> entry)
                    continue;
                if (!entry.TryGetValue("identities", out var idsObj) || idsObj is not List<object?> idList)
                    continue;

                foreach (var item in idList)
                {
                    if (item is not Dictionary<string, object?> idDict)
                        continue;
                    identities.Add(ParseIdentity(uri, idDict));
                }
            }
        }

        return new IdsLookupResult
        {
            Topic = topic,
            SelfHandle = selfHandle,
            QueriedUris = queried,
            Identities = identities,
            Status = status,
            RawSummary = $"status={status} identities={identities.Count} bytes={responseBytes.Length}",
        };
    }

    private static IdsPeerIdentity ParseIdentity(string uri, Dictionary<string, object?> idDict)
    {
        Dictionary<string, object?>? clientData = null;
        if (idDict.TryGetValue("client-data", out var cd) && cd is Dictionary<string, object?> cdDict)
            clientData = cdDict;

        byte[]? preKey = null;
        byte[]? legacy = null;
        byte[]? devicePub = null;
        if (clientData is not null)
        {
            preKey = AppleXmlPlist.GetData(clientData, "public-message-ngm-device-prekey-data-key");
            legacy = AppleXmlPlist.GetData(clientData, "public-message-identity-key");
            if (clientData.TryGetValue("kt-loggable-data", out var kt)
                || (idDict.TryGetValue("kt-loggable-data", out kt)))
            {
                if (kt is byte[] ktBytes)
                    devicePub = TryExtractDevicePublicFromKt(ktBytes);
            }
        }

        if (devicePub is null && idDict.TryGetValue("kt-loggable-data", out var ktRoot)
            && ktRoot is byte[] ktRootBytes)
        {
            devicePub = TryExtractDevicePublicFromKt(ktRootBytes);
        }

        return new IdsPeerIdentity
        {
            Uri = uri,
            PushToken = AppleXmlPlist.GetData(idDict, "push-token"),
            SessionToken = AppleXmlPlist.GetData(idDict, "session-token"),
            SessionTokenExpiresSeconds = AppleXmlPlist.GetInt(idDict, "session-token-expires-seconds"),
            SessionTokenRefreshSeconds = AppleXmlPlist.GetInt(idDict, "session-token-refresh-seconds"),
            ClientData = clientData,
            NgmPreKeyData = preKey,
            NgmDevicePublicKey = devicePub,
            LegacyIdentityKey = legacy,
        };
    }

    private static byte[]? TryExtractDevicePublicFromKt(byte[] ktLoggable)
    {
        try
        {
            // KtLoggableData { deviceIdentity { publicKey = 1 } = 1 }
            var outer = new ProtobufReader(ktLoggable);
            while (outer.HasMore)
            {
                var (fn, wt) = outer.ReadTag();
                if (fn == 1 && wt == 2)
                {
                    var innerBytes = outer.ReadLengthDelimited();
                    var inner = new ProtobufReader(innerBytes);
                    while (inner.HasMore)
                    {
                        var (ifn, iwt) = inner.ReadTag();
                        if (ifn == 1 && iwt == 2)
                            return inner.ReadLengthDelimited();
                        inner.SkipField(iwt);
                    }
                }
                else
                {
                    outer.SkipField(wt);
                }
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static Dictionary<string, object?> ParsePlist(byte[] data)
    {
        if (data.Length >= 6 && data.AsSpan(0, 6).SequenceEqual("bplist"u8))
        {
            if (!AppleBinaryPlist.TryParseDict(data, out var dict, out var err) || dict is null)
                throw new InvalidOperationException("id-query bplist non valido: " + err);
            return dict;
        }

        return AppleXmlPlist.Parse(data);
    }
}
