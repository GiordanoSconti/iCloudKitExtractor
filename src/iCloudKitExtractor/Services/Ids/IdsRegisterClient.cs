using System.Net.Http.Headers;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>id-get-handles + id-register (multiplex1 / Find My).</summary>
public sealed class IdsRegisterClient
{
    private readonly HttpClient _http;
    private readonly IdsBag _bag;

    public IdsRegisterClient(HttpClient http, IdsBag bag)
    {
        _http = http;
        _bag = bag;
    }

    public async Task<IReadOnlyList<string>> GetHandlesAsync(
        string profileId,
        string authKeyPem,
        string authCertPem,
        byte[] pushToken,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var url = await _bag.GetAsync("id-get-handles", ct).ConfigureAwait(false);
        log?.Invoke($"id-get-handles URL: {url}");
        var (pushKeyPem, pushCertPem) = ApsStorage.LoadCertificate();

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-protocol-version"] = IdsConstants.ProtocolVersion,
            ["x-auth-user-id"] = profileId,
            ["User-Agent"] = IdsConstants.InvitationUserAgent,
            ["Accept"] = "*/*",
            ["Accept-Encoding"] = "gzip",
        };
        IdsSigning.AddAuthAndPushSignatures(
            headers, [], "id-get-handles",
            authKeyPem, authCertPem, pushKeyPem, pushCertPem, pushToken,
            authNumber: null);

        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        foreach (var (k, v) in headers)
            request.Headers.TryAddWithoutValidation(k, v);

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        var unzipped = IdsSigning.TryGunzip(bytes) ?? bytes;
        log?.Invoke($"id-get-handles HTTP {(int)response.StatusCode}, body={unzipped.Length} B");

        if (unzipped.Length == 0)
            throw new InvalidOperationException(
                $"id-get-handles HTTP {(int)response.StatusCode} body vuoto ({url}).");

        var root = ParseIdsPlist(unzipped);
        var status = AppleXmlPlist.GetInt(root, "status");
        if (status is not null and not 0)
            throw new InvalidOperationException($"id-get-handles status={status}");

        if (!root.TryGetValue("handles", out var handlesObj) || handlesObj is not List<object?> handles)
            throw new InvalidOperationException("id-get-handles: nessun handles.");

        var uris = new List<string>();
        foreach (var h in handles)
        {
            if (h is not Dictionary<string, object?> dict)
                continue;
            var uri = AppleXmlPlist.GetString(dict, "uri");
            var hStatus = AppleXmlPlist.GetInt(dict, "status");
            if (!string.IsNullOrWhiteSpace(uri))
            {
                log?.Invoke($"  handle {uri} status={hStatus?.ToString() ?? "?"}");
                uris.Add(uri!);
            }
        }

        if (uris.Count == 0)
            throw new InvalidOperationException("id-get-handles: lista URI vuota.");
        return uris;
    }

    public async Task<(string IdCertPem, int Status)> RegisterAsync(
        string profileId,
        IReadOnlyList<string> handleUris,
        string authKeyPem,
        string authCertPem,
        byte[] pushToken,
        IdsIdentity identity,
        byte[]? validationData,
        AnisetteHeaders anisette,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var url = await _bag.GetAsync("id-register", ct).ConfigureAwait(false);
        var (pushKeyPem, pushCertPem) = ApsStorage.LoadCertificate();
        var (serial, _) = ApsStorage.ResolveWindowsIdentity();

        var uris = handleUris
            .Select(u => (object?)new Dictionary<string, object?> { ["uri"] = u })
            .ToList();

        var clientData = new Dictionary<string, object?>
        {
            ["public-message-identity-key"] = identity.EncodeLegacyIdentity(),
            ["public-message-identity-version"] = 2,
            ["ec-version"] = 1,
            ["public-message-identity-ngm-version"] = 13,
            ["public-message-ngm-device-prekey-data-key"] = identity.BuildPreKeyData(),
            ["kt-version"] = 5,
            ["supports-fmd-v2"] = true,
            ["supports-incoming-fmd-v1"] = true,
            ["supports-findmy-plugin-messages"] = true,
            ["supports-beacon-sharing-v3"] = true,
            ["supports-beacon-sharing-v2"] = true,
        };

        var user = new Dictionary<string, object?>
        {
            ["client-data"] = clientData,
            ["kt-loggable-data"] = identity.BuildKtLoggableData(),
            ["uris"] = uris,
            ["user-id"] = profileId,
        };

        var service = new Dictionary<string, object?>
        {
            ["capabilities"] = new List<object?>
            {
                new Dictionary<string, object?>
                {
                    ["flags"] = 1,
                    ["name"] = "com.apple.private.alloy",
                    ["version"] = 1,
                },
            },
            ["service"] = IdsConstants.MultiplexService,
            ["sub-services"] = IdsConstants.FindMySubServices.Cast<object?>().ToList(),
            ["users"] = new List<object?> { user },
        };

        var deviceName = string.IsNullOrWhiteSpace(anisette.ClientProductType)
            ? "iCloudKitExtractor"
            : anisette.ClientProductType;

        var bodyDict = new Dictionary<string, object?>
        {
            ["device-name"] = deviceName,
            ["hardware-version"] = "MacBookPro18,3",
            ["language"] = "en-US",
            ["os-version"] = "macOS,13.2.1,22D68",
            ["private-device-data"] = new Dictionary<string, object?>
            {
                ["ap"] = "0",
                ["s"] = serial,
            },
            ["retry-count"] = 0,
            ["services"] = new List<object?> { service },
            ["software-version"] = "22D68",
        };
        if (validationData is { Length: > 0 })
            bodyDict["validation-data"] = validationData;

        var xml = AppleXmlPlist.ToXmlBytes(bodyDict);
        var gzipped = IdsSigning.GzipMtime0(xml);
        log?.Invoke(
            $"id-register: XML+gzip={gzipped.Length} B; services=1 subservices={IdsConstants.FindMySubServices.Length}; handles={handleUris.Count}; validation={(validationData?.Length ?? 0)} B");

        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-protocol-version"] = IdsConstants.ProtocolVersion,
            ["x-auth-user-id-0"] = profileId,
            ["User-Agent"] = IdsConstants.InvitationUserAgent,
            ["Accept"] = "*/*",
            ["Accept-Encoding"] = "gzip",
        };
        IdsSigning.AddAuthAndPushSignatures(
            headers, gzipped, "id-register",
            authKeyPem, authCertPem, pushKeyPem, pushCertPem, pushToken,
            authNumber: 0);

        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        foreach (var (k, v) in headers)
            request.Headers.TryAddWithoutValidation(k, v);
        request.Content = new ByteArrayContent(gzipped);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-apple-plist");
        request.Content.Headers.ContentEncoding.Add("gzip");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        var unzipped = IdsSigning.TryGunzip(bytes) ?? bytes;
        log?.Invoke($"id-register HTTP {(int)response.StatusCode}, resp={unzipped.Length} B");

        var root = ParseIdsPlist(unzipped);
        var status = AppleXmlPlist.GetInt(root, "status") ?? -1;
        if (status == 6004)
            throw new InvalidOperationException(
                "id-register status=6004 (validation-data assente/scaduta — serve NAC dall'anisette).");
        if (status != 0)
        {
            var msg = AppleXmlPlist.GetString(root, "message") ?? "";
            throw new InvalidOperationException($"id-register status={status} {msg}".Trim());
        }

        if (!root.TryGetValue("services", out var servicesObj)
            || servicesObj is not List<object?> services
            || services.Count == 0
            || services[0] is not Dictionary<string, object?> svc0)
        {
            throw new InvalidOperationException("id-register: services assente nella risposta.");
        }

        var svcStatus = AppleXmlPlist.GetInt(svc0, "status");
        log?.Invoke($"id-register services[0].status={svcStatus?.ToString() ?? "?"}");

        if (!svc0.TryGetValue("users", out var usersObj)
            || usersObj is not List<object?> users
            || users.Count == 0
            || users[0] is not Dictionary<string, object?> user0)
        {
            throw new InvalidOperationException("id-register: users assente.");
        }

        var userStatus = AppleXmlPlist.GetInt(user0, "status") ?? -1;
        if (userStatus != 0)
        {
            var alert = user0.TryGetValue("alert", out var a) ? a?.ToString() : null;
            throw new InvalidOperationException(
                $"id-register user status={userStatus}" + (alert is null ? "" : " alert=" + alert));
        }

        var certDer = AppleXmlPlist.GetData(user0, "cert")
                      ?? throw new InvalidOperationException("id-register: cert utente assente.");
        var idCertPem = IdsSigning.ArmourCertDer(certDer);
        IdsStorage.SaveIdCertificate(idCertPem);
        log?.Invoke($"id-register OK — ID cert DER={certDer.Length} B.");
        return (idCertPem, status);
    }

    private static Dictionary<string, object?> ParseIdsPlist(byte[] data)
    {
        if (data.Length >= 6 && data.AsSpan(0, 6).SequenceEqual("bplist"u8))
        {
            if (!AppleBinaryPlist.TryParseDict(data, out var dict, out var err) || dict is null)
                throw new InvalidOperationException("IDS bplist non valido: " + err);
            return dict;
        }

        return AppleXmlPlist.Parse(data);
    }
}
