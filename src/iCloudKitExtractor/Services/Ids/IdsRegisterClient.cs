using System.Net.Http.Headers;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Ids;

public enum IdsRegisterServiceKind
{
    FindMyMultiplex = 0,
    Madrid = 1,
}

/// <summary>id-get-handles + id-register (multiplex1 / Find My / Madrid).</summary>
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
        CancellationToken ct = default,
        string? pushKeyPem = null,
        string? pushCertPem = null)
    {
        var url = await _bag.GetAsync("id-get-handles", ct).ConfigureAwait(false);
        log?.Invoke($"id-get-handles URL: {url}");
        if (string.IsNullOrWhiteSpace(pushKeyPem) || string.IsNullOrWhiteSpace(pushCertPem))
            (pushKeyPem, pushCertPem) = ApsStorage.LoadCertificate();

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
            authKeyPem, authCertPem, pushKeyPem!, pushCertPem!, pushToken,
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
                $"id-get-handles HTTP {(int)response.StatusCode} empty body ({url}).");

        var root = ParseIdsPlist(unzipped);
        var status = AppleXmlPlist.GetInt(root, "status");
        if (status is not null and not 0)
            throw new InvalidOperationException($"id-get-handles status={status}");

        if (!root.TryGetValue("handles", out var handlesObj) || handlesObj is not List<object?> handles)
            throw new InvalidOperationException("id-get-handles: no handles.");

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

    public Task<(string IdCertPem, int Status)> RegisterAsync(
        string profileId,
        IReadOnlyList<string> handleUris,
        string authKeyPem,
        string authCertPem,
        byte[] pushToken,
        IdsIdentity identity,
        byte[]? validationData,
        AnisetteHeaders anisette,
        Action<string>? log = null,
        CancellationToken ct = default) =>
        RegisterAsync(
            profileId, handleUris, authKeyPem, authCertPem, pushToken, identity,
            validationData, anisette, IdsRegisterServiceKind.FindMyMultiplex, log, ct);

    public async Task<(string IdCertPem, int Status)> RegisterAsync(
        string profileId,
        IReadOnlyList<string> handleUris,
        string authKeyPem,
        string authCertPem,
        byte[] pushToken,
        IdsIdentity identity,
        byte[]? validationData,
        AnisetteHeaders anisette,
        IdsRegisterServiceKind serviceKind,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var url = await _bag.GetAsync("id-register", ct).ConfigureAwait(false);
        var (albertKeyPem, albertCertPem) = ApsStorage.LoadCertificate();
        var pushKeyPem = albertKeyPem;
        var pushCertPem = albertCertPem;
        var effectivePushToken = pushToken;
        var (winSerial, _) = ApsStorage.ResolveWindowsIdentity();
        var persona = MadridDevicePersona.TryLoadMeta();
        var iphone = serviceKind == IdsRegisterServiceKind.Madrid
            ? IphoneIdsIdentityStore.TryLoad()
            : null;
        var iphonePush = serviceKind == IdsRegisterServiceKind.Madrid
            ? IphoneApsPushStore.TryLoad()
            : null;

        // Madrid identity precedence: Frida iPhone capture → Mac data.plist → Windows Albert.
        var serial = winSerial;
        var hardwareVersion = "MacBookPro18,3";
        var osVersion = "macOS,13.2.1,22D68";
        var softwareVersion = "22D68";
        var language = "en-US";
        var deviceName = string.IsNullOrWhiteSpace(anisette.ClientProductType)
            ? "iCloudKitExtractor"
            : anisette.ClientProductType;
        Dictionary<string, object?>? privateDeviceData = null;
        string? userAgentOverride = null;
        var pushSigSource = "Albert";

        if (iphone is not null
            && iphonePush is not null
            && !string.IsNullOrWhiteSpace(iphone.PushTokenHex)
            && iphone.PushTokenHex!.Length >= 32)
        {
            try
            {
                var phoneTok = Convert.FromHexString(iphone.PushTokenHex);
                if (phoneTok.Length >= 16)
                {
                    effectivePushToken = phoneTok;
                    pushKeyPem = iphonePush.Value.KeyPem;
                    pushCertPem = iphonePush.Value.CertPem;
                    pushSigSource = "iPhone-APS";
                }
            }
            catch
            {
                // keep Albert
            }
        }

        if (iphone is not null)
        {
            hardwareVersion = iphone.HardwareVersion ?? hardwareVersion;
            osVersion = iphone.OsVersion ?? osVersion;
            softwareVersion = iphone.SoftwareVersion ?? softwareVersion;
            language = iphone.Language ?? language;
            deviceName = iphone.DeviceName ?? deviceName;
            if (iphone.PrivateDeviceData is { Count: > 0 })
                privateDeviceData = new Dictionary<string, object?>(iphone.PrivateDeviceData);
            userAgentOverride = iphone.UserAgent;
            log?.Invoke(
                $"id-register Madrid: Frida iPhone identity hw={hardwareVersion} os={osVersion} "
                + $"pushPhone={(iphone.PushTokenHex is { Length: > 8 } h ? h[..8] + "…" : "?")} "
                + $"APS sig={pushSigSource}"
                + (pushSigSource == "Albert"
                    ? " — mismatch may keep 6009 (run fetch_aps_push_identity.py)"
                    : " — matched iPhone push cert/key"));
        }
        else if (persona is not null)
        {
            if (!string.IsNullOrWhiteSpace(persona.SerialNumber))
                serial = persona.SerialNumber!;
            if (!string.IsNullOrWhiteSpace(persona.HardwareVersion))
                hardwareVersion = persona.HardwareVersion!;
            if (!string.IsNullOrWhiteSpace(persona.OsVersion))
                osVersion = persona.OsVersion!;
            if (!string.IsNullOrWhiteSpace(persona.SoftwareVersion))
                softwareVersion = persona.SoftwareVersion!;
            privateDeviceData = new Dictionary<string, object?> { ["ap"] = "0", ["s"] = serial };
            log?.Invoke($"id-register Madrid: Mac persona serial={serial} hw={hardwareVersion}");
        }
        else if (serviceKind == IdsRegisterServiceKind.Madrid)
        {
            privateDeviceData = new Dictionary<string, object?> { ["ap"] = "0", ["s"] = serial };
            log?.Invoke(
                "id-register Madrid: no iPhone/Mac identity — Windows/APS serial (likely 6009).");
        }
        else
        {
            privateDeviceData = new Dictionary<string, object?> { ["ap"] = "0", ["s"] = serial };
        }

        var uris = handleUris
            .Select(u => (object?)new Dictionary<string, object?> { ["uri"] = u })
            .ToList();

        var clientData = serviceKind == IdsRegisterServiceKind.Madrid
            ? BuildMadridClientData(identity)
            : BuildFindMyClientData(identity);

        // Madrid (pypush): client-data + uris + user-id only.
        // Find My: also publishes kt-loggable-data / NGM prekeys.
        var user = new Dictionary<string, object?>
        {
            ["client-data"] = clientData,
            ["uris"] = uris,
            ["user-id"] = profileId,
        };
        if (serviceKind != IdsRegisterServiceKind.Madrid)
            user["kt-loggable-data"] = identity.BuildKtLoggableData();

        Dictionary<string, object?> service;
        if (serviceKind == IdsRegisterServiceKind.Madrid)
        {
            service = new Dictionary<string, object?>
            {
                // pypush / Apple Wiki: capability name is "Messenger", flags=17.
                ["capabilities"] = new List<object?>
                {
                    new Dictionary<string, object?>
                    {
                        ["flags"] = 17,
                        ["name"] = "Messenger",
                        ["version"] = 1,
                    },
                },
                ["service"] = IdsConstants.MadridService,
                ["sub-services"] = IdsConstants.MadridSubServices.Cast<object?>().ToList(),
                ["users"] = new List<object?> { user },
            };
        }
        else
        {
            service = new Dictionary<string, object?>
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
        }

        var bodyDict = new Dictionary<string, object?>
        {
            ["device-name"] = deviceName,
            ["hardware-version"] = hardwareVersion,
            ["language"] = language,
            ["os-version"] = osVersion,
            ["private-device-data"] = privateDeviceData
                ?? new Dictionary<string, object?> { ["ap"] = "0", ["s"] = serial },
            ["retry-count"] = 0,
            ["services"] = new List<object?> { service },
            ["software-version"] = softwareVersion,
        };
        if (validationData is { Length: > 0 })
            bodyDict["validation-data"] = validationData;

        var xml = AppleXmlPlist.ToXmlBytes(bodyDict);
        var gzipped = IdsSigning.GzipMtime0(xml);
        log?.Invoke(
            $"id-register ({serviceKind}): XML+gzip={gzipped.Length} B; handles={handleUris.Count}; validation={(validationData?.Length ?? 0)} B");
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
        {
            ["x-protocol-version"] = IdsConstants.ProtocolVersion,
            ["x-auth-user-id-0"] = profileId,
            ["User-Agent"] = string.IsNullOrWhiteSpace(userAgentOverride)
                ? IdsConstants.InvitationUserAgent
                : userAgentOverride!,
            ["Accept"] = "*/*",
            ["Accept-Encoding"] = "gzip",
        };
        IdsSigning.AddAuthAndPushSignatures(
            headers, gzipped, "id-register",
            authKeyPem, authCertPem, pushKeyPem, pushCertPem, effectivePushToken,
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
                "id-register status=6004 (validation-data missing/expired — NAC from anisette required).");
        if (status != 0)
        {
            var msg = AppleXmlPlist.GetString(root, "message") ?? "";
            if (status == 6001 || msg.Contains("SED:", StringComparison.OrdinalIgnoreCase))
            {
                throw new InvalidOperationException(
                    $"id-register status={status} {msg}".Trim()
                    + Environment.NewLine
                    + "Apple rejected Madrid registration (often validation-data / device persona / account score). "
                    + "Find My multiplex1 can still succeed while Madrid is stricter. "
                    + "Retry after rebuild (Messenger flags=17 client-data). Lab Apple ID only — SED can mean customer-code risk.");
            }

            throw new InvalidOperationException($"id-register status={status} {msg}".Trim());
        }

        if (!root.TryGetValue("services", out var servicesObj)
            || servicesObj is not List<object?> services
            || services.Count == 0
            || services[0] is not Dictionary<string, object?> svc0)
        {
            throw new InvalidOperationException("id-register: services missing in response.");
        }

        var svcStatus = AppleXmlPlist.GetInt(svc0, "status");
        log?.Invoke($"id-register services[0].status={svcStatus?.ToString() ?? "?"}");

        if (!svc0.TryGetValue("users", out var usersObj)
            || usersObj is not List<object?> users
            || users.Count == 0
            || users[0] is not Dictionary<string, object?> user0)
        {
            throw new InvalidOperationException("id-register: users missing.");
        }

        var userStatus = AppleXmlPlist.GetInt(user0, "status") ?? -1;
        if (userStatus != 0)
        {
            var alertText = FormatRegisterAlert(user0);
            // 6009 = Apple user-level alert (often customer-code / registration blocked).
            throw new InvalidOperationException(
                $"id-register user status={userStatus}"
                + (string.IsNullOrWhiteSpace(alertText) ? "" : Environment.NewLine + alertText));
        }

        var certDer = AppleXmlPlist.GetData(user0, "cert")
                      ?? throw new InvalidOperationException("id-register: user cert missing.");
        var idCertPem = IdsSigning.ArmourCertDer(certDer);
        if (serviceKind == IdsRegisterServiceKind.Madrid)
            IdsStorage.SaveMadridIdCertificate(idCertPem);
        else
            IdsStorage.SaveIdCertificate(idCertPem);
        log?.Invoke($"id-register OK ({serviceKind}) — ID cert DER={certDer.Length} B.");

        // Log per-URI statuses when present.
        if (user0.TryGetValue("uris", out var urisObj) && urisObj is List<object?> uriRows)
        {
            foreach (var row in uriRows)
            {
                if (row is not Dictionary<string, object?> ud)
                    continue;
                var u = AppleXmlPlist.GetString(ud, "uri");
                var us = AppleXmlPlist.GetInt(ud, "status");
                if (!string.IsNullOrWhiteSpace(u))
                    log?.Invoke($"  register uri {u} status={us?.ToString() ?? "?"}");
            }
        }

        return (idCertPem, status);
    }

    private static Dictionary<string, object?> BuildFindMyClientData(IdsIdentity identity) =>
        new()
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

    /// <summary>Classic pypush Madrid client-data (Messenger registration).</summary>
    private static Dictionary<string, object?> BuildMadridClientData(IdsIdentity identity) =>
        new()
        {
            ["is-c2k-equipment"] = true,
            ["optionally-receive-typing-indicators"] = true,
            ["public-message-identity-key"] = identity.EncodeLegacyIdentity(),
            ["public-message-identity-version"] = 2,
            ["show-peer-errors"] = true,
            ["supports-ack-v1"] = true,
            ["supports-activity-sharing-v1"] = true,
            ["supports-audio-messaging-v2"] = true,
            ["supports-autoloopvideo-v1"] = true,
            ["supports-be-v1"] = true,
            ["supports-ca-v1"] = true,
            ["supports-fsm-v1"] = true,
            ["supports-fsm-v2"] = true,
            ["supports-fsm-v3"] = true,
            ["supports-ii-v1"] = true,
            ["supports-impact-v1"] = true,
            ["supports-inline-attachments"] = true,
            ["supports-keep-receipts"] = true,
            ["supports-location-sharing"] = true,
            ["supports-media-v2"] = true,
            ["supports-photos-extension-v1"] = true,
            ["supports-st-v1"] = true,
            ["supports-update-attachments-v1"] = true,
        };

    private static Dictionary<string, object?> ParseIdsPlist(byte[] data)
    {
        if (data.Length >= 6 && data.AsSpan(0, 6).SequenceEqual("bplist"u8))
        {
            if (!AppleBinaryPlist.TryParseDict(data, out var dict, out var err) || dict is null)
                throw new InvalidOperationException("Invalid IDS bplist: " + err);
            return dict;
        }

        return AppleXmlPlist.Parse(data);
    }

    /// <summary>
    /// Formats Apple's 6009 <c>alert</c> dict (title/body/action) so the UI shows the real message
    /// instead of <c>Dictionary`2</c>.ToString().
    /// </summary>
    private static string FormatRegisterAlert(Dictionary<string, object?> user0)
    {
        if (!user0.TryGetValue("alert", out var alertObj) || alertObj is null)
            return "";

        if (alertObj is not Dictionary<string, object?> alert)
            return "alert=" + alertObj;

        var title = AppleXmlPlist.GetString(alert, "title")
                    ?? AppleXmlPlist.GetString(alert, "Title");
        var body = AppleXmlPlist.GetString(alert, "body")
                   ?? AppleXmlPlist.GetString(alert, "message")
                   ?? AppleXmlPlist.GetString(alert, "Body");
        string? actionUrl = null;
        string? actionButton = null;
        if (alert.TryGetValue("action", out var actObj) && actObj is Dictionary<string, object?> act)
        {
            actionUrl = AppleXmlPlist.GetString(act, "url");
            actionButton = AppleXmlPlist.GetString(act, "button");
        }

        var sb = new System.Text.StringBuilder();
        sb.AppendLine("Apple alert (status 6009 — registration blocked / customer-code style):");
        if (!string.IsNullOrWhiteSpace(title))
            sb.AppendLine("  title: " + title);
        if (!string.IsNullOrWhiteSpace(body))
            sb.AppendLine("  body:  " + body);
        if (!string.IsNullOrWhiteSpace(actionButton) || !string.IsNullOrWhiteSpace(actionUrl))
            sb.AppendLine($"  action: {actionButton ?? "(button)"} → {actionUrl ?? "(no url)"}");

        // Dump remaining keys for lab debugging when title/body missing.
        if (string.IsNullOrWhiteSpace(title) && string.IsNullOrWhiteSpace(body))
        {
            foreach (var kv in alert)
                sb.AppendLine($"  {kv.Key}={FormatAlertValue(kv.Value)}");
        }

        return sb.ToString().TrimEnd();
    }

    private static string FormatAlertValue(object? v) =>
        v switch
        {
            null => "(null)",
            string s => s,
            byte[] b => $"data:{b.Length}B",
            Dictionary<string, object?> d =>
                "{" + string.Join(", ", d.Select(kv => kv.Key + "=" + FormatAlertValue(kv.Value))) + "}",
            List<object?> list =>
                "[" + string.Join(", ", list.Select(FormatAlertValue)) + "]",
            _ => v.ToString() ?? "",
        };
}
