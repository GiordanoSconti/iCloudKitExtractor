using System.Globalization;
using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Provisioning GSA (midStart/midFinish) in C#; operazioni crittografiche via CoreAdiBridge.
/// </summary>
public sealed class AdiProvisioningService
{
    public const long GrandSlamDsId = -2;

    private readonly HttpClient _http;
    private readonly IAdiCryptoClient _bridge;
    private readonly AppleRuntimeLocator _runtime = new();
    private readonly AnisetteDeviceStore _deviceStore;
    private readonly AdiDeviceProfile _profile;

    public AdiProvisioningService(HttpClient http, AdiDeviceProfile? profile = null, IAdiCryptoClient? crypto = null)
    {
        _http = http;
        _profile = profile ?? AdiDeviceProfile.Windows;
        _bridge = crypto ?? new CoreAdiBridgeClient();
        _deviceStore = new AnisetteDeviceStore(_profile);
    }

    public AdiDeviceProfile Profile => _profile;

    public AnisetteDeviceStore DeviceStore => _deviceStore;

    public void InvalidateDeviceCache() => _deviceStore.InvalidateCache();

    /// <summary>
    /// Soft MidService sulla stessa device identity (UUID/adi_id invariati).
    /// <paramref name="forceMidService"/>=false: se ADI già provisionata → no-op
    /// (l'OTP fresco arriva da <see cref="RequestOtpHeadersAsync"/> / GET /).
    /// <paramref name="forceMidService"/>=true: wipe solo stato ADI locale, poi midStart/midFinish
    /// di nuovo (MD-M può ruotare; identity device resta).
    /// </summary>
    public async Task<string> RepairProvisioningAsync(
        CancellationToken ct = default,
        bool forceMidService = false)
    {
        var provisionDir = _runtime.GetProvisioningDirectory(_profile);
        _runtime.EnsureProvisioningDirectory(_profile);
        var adiId = _deviceStore.GetOrCreateAdiIdentifier();
        var runtimeDir = _bridge.RequiresWindowsCoreAdiRuntime
            ? await _runtime.EnsureRuntimeAsync(ct).ConfigureAwait(false)
            : string.Empty;

        var already = await _bridge.IsProvisionedAsync(
                runtimeDir, provisionDir, adiId, GrandSlamDsId, ct)
            .ConfigureAwait(false);

        // Soft: ADI ok → non toccare MidService (OTP = request-otp locale).
        if (already && !forceMidService)
            return FormatFingerprint("repair-skip-already-provisioned");

        // Stessa identity device-*.json; solo riparte MidService / ADI session.
        ResetProvisioningData(provisionDir);
        if (_bridge.OwnsMidServiceHttp)
        {
            await _bridge.WipeLibraryProvisioningAsync(
                    string.Empty, provisionDir, adiId, ct)
                .ConfigureAwait(false);
        }
        try
        {
            await EnsureProvisionedAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex) when (IsMidService433(ex))
        {
            throw WrapMidService433(ex, softRepair: true);
        }

        return FormatFingerprint(forceMidService ? "repair-force-mid" : "repair");
    }

    /// <summary>
    /// Nuova identità device + wipe ADI MidService, poi midStart/midFinish.
    /// In caso di HTTP 433 ripristina il device-*.json precedente.
    /// </summary>
    public async Task<string> ForceNewIdentityAndProvisionAsync(CancellationToken ct = default)
    {
        var provisionDir = _runtime.GetProvisioningDirectory(_profile);
        var backupPath = _deviceStore.StorePath + ".bak-hsa2";
        TryBackupDeviceStore(backupPath);

        _deviceStore.ResetIdentity();
        ResetProvisioningData(provisionDir);
        _runtime.EnsureProvisioningDirectory(_profile);
        try
        {
            await EnsureProvisionedAsync(ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            TryRestoreDeviceStore(backupPath);
            if (IsMidService433(ex))
                throw WrapMidService433(ex, softRepair: false);
            throw;
        }

        TryDeleteFile(backupPath);
        return FormatFingerprint("newIdentity");
    }

    private string FormatFingerprint(string mode)
    {
        var uuid = _deviceStore.GetOrCreateDeviceUuid();
        var adi = _deviceStore.GetOrCreateAdiIdentifier();
        var u = uuid.Length >= 8 ? uuid[..8] : uuid;
        var a = adi.Length >= 8 ? adi[..8] : adi;
        return $"mode={mode} profile={_profile.Name} uuid={u}… adi={a}…";
    }

    private void TryBackupDeviceStore(string backupPath)
    {
        try
        {
            if (File.Exists(_deviceStore.StorePath))
                File.Copy(_deviceStore.StorePath, backupPath, overwrite: true);
        }
        catch
        {
            // best-effort
        }
    }

    private void TryRestoreDeviceStore(string backupPath)
    {
        try
        {
            if (!File.Exists(backupPath))
                return;
            File.Copy(backupPath, _deviceStore.StorePath, overwrite: true);
            _deviceStore.InvalidateCache();
        }
        catch
        {
            // best-effort
        }
    }

    private static void TryDeleteFile(string path)
    {
        try
        {
            if (File.Exists(path))
                File.Delete(path);
        }
        catch
        {
            // ignore
        }
    }

    private static bool IsMidService433(Exception ex)
    {
        var msg = ex.Message + (ex.InnerException?.Message ?? "");
        return msg.Contains("HTTP 433", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("midFinishProvisioning HTTP 433", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("midStartProvisioning HTTP 433", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("'ptm'", StringComparison.OrdinalIgnoreCase)
               || msg.Contains("KeyError: 'ptm'", StringComparison.OrdinalIgnoreCase);
    }

    private static InvalidOperationException WrapMidService433(Exception ex, bool softRepair) =>
        new(
            "Apple MidService HTTP 433 (Anisette Reprovision Required / machine data changed). " +
            (softRepair
                ? "Riprova tra qualche minuto con POST /provision (soft). "
                : "Il wipe newIdentity è stato annullato (device store ripristinato). " +
                  "Non ripetere newIdentity a raffica — causa 503 su :6971. ") +
            "Dettaglio: " + ex.Message,
            ex);

    public async Task EnsureProvisionedAsync(CancellationToken ct = default)
    {
        _deviceStore.InvalidateCache();
        var runtimeDir = _bridge.RequiresWindowsCoreAdiRuntime
            ? await _runtime.EnsureRuntimeAsync(ct).ConfigureAwait(false)
            : string.Empty;
        var provisionDir = _runtime.GetProvisioningDirectory(_profile);
        _runtime.EnsureProvisioningDirectory(_profile);
        if (_deviceStore.EnsureIdentityConsistency())
            ResetProvisioningData(provisionDir);

        var adiId = _deviceStore.GetOrCreateAdiIdentifier();

        if (await _bridge.IsProvisionedAsync(runtimeDir, provisionDir, adiId, GrandSlamDsId, ct)
                .ConfigureAwait(false))
            return;

        // Android ADI / Anisette.py: MidService nella libreria (header coerenti, no SRL-NO C#).
        // Il MidService C# stile iPhone su crypto Android → Apple HTTP 433.
        if (_bridge.OwnsMidServiceHttp)
        {
            await _bridge.ProvisionViaLibraryAsync(
                    runtimeDir, provisionDir, adiId, GrandSlamDsId, ct)
                .ConfigureAwait(false);
            return;
        }

        var urlBag = await LoadUrlBagAsync(ct).ConfigureAwait(false);
        var midStart = GetUrl(urlBag, "midStartProvisioning");
        var midFinish = GetUrl(urlBag, "midFinishProvisioning");

        // Stesso snapshot anisette (UUID + Client-Time) su midStart e midFinish —
        // drift Client-Time / Header assente → Apple HTTP 433.
        var midAnisette = BuildProvisioningAnisette();

        var spim = await FetchSpimAsync(midStart, midAnisette, ct).ConfigureAwait(false);
        var start = await _bridge.StartProvisioningAsync(
            runtimeDir, provisionDir, adiId, spim, GrandSlamDsId, ct).ConfigureAwait(false);

        try
        {
            var (ptm, tk, routing) = await FinishProvisioningAsync(
                    midFinish, start.Cpim, midAnisette, ct)
                .ConfigureAwait(false);
            await _bridge.EndProvisioningAsync(
                runtimeDir, provisionDir, adiId, start.Session, ptm, tk, ct).ConfigureAwait(false);

            var targetRouting = _profile.ForceTargetRouting ? _profile.TargetRouting : routing;
            await _bridge.SetRoutingAsync(
                runtimeDir, provisionDir, adiId, targetRouting, GrandSlamDsId, ct).ConfigureAwait(false);
        }
        catch
        {
            await _bridge.DestroySessionAsync(
                runtimeDir, provisionDir, adiId, start.Session, ct).ConfigureAwait(false);
            throw;
        }
    }

    public async Task<AdiOtpHeaderResult> RequestOtpHeadersAsync(CancellationToken ct = default)
    {
        await EnsureProvisionedAsync(ct).ConfigureAwait(false);
        var runtimeDir = _bridge.RequiresWindowsCoreAdiRuntime
            ? await _runtime.EnsureRuntimeAsync(ct).ConfigureAwait(false)
            : string.Empty;
        var provisionDir = _runtime.GetProvisioningDirectory(_profile);
        return await _bridge.RequestOtpAsync(
            runtimeDir, provisionDir, _deviceStore.GetOrCreateAdiIdentifier(), GrandSlamDsId, ct)
            .ConfigureAwait(false);
    }

    private async Task<Dictionary<string, object?>> LoadUrlBagAsync(CancellationToken ct)
    {
        using var request = BuildProvisioningRequest(HttpMethod.Get, "https://gsa.apple.com/grandslam/GsService2/lookup");
        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);

        var root = AppleXmlPlist.Parse(body);
        if (root.TryGetValue("urls", out var urls) && urls is Dictionary<string, object?> dict)
            return dict;

        if (root.TryGetValue("Response", out var responseNode)
            && responseNode is Dictionary<string, object?> responseDict
            && responseDict.TryGetValue("urls", out var nested)
            && nested is Dictionary<string, object?> nestedDict)
            return nestedDict;

        throw new InvalidOperationException("URL bag provisioning non trovato nella risposta lookup.");
    }

    private static readonly byte[] EmptyMidStartPlist = Encoding.UTF8.GetBytes(
        """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>Header</key><dict/>
          <key>Request</key><dict/>
        </dict></plist>
        """);

    private async Task<byte[]> FetchSpimAsync(
        string url,
        AnisetteHeaders anisette,
        CancellationToken ct)
    {
        using var request = BuildProvisioningRequest(HttpMethod.Post, url, anisette);
        request.Content = new ByteArrayContent(EmptyMidStartPlist);
        request.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");
        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var preview = Encoding.UTF8.GetString(body);
            if (preview.Length > 240)
                preview = preview[..240] + "…";
            throw new InvalidOperationException(
                $"midStartProvisioning HTTP {(int)response.StatusCode} ({url}): {preview}");
        }

        var dict = AppleXmlPlist.GetResponseDict(body)
            ?? throw new InvalidOperationException("Risposta midStartProvisioning non valida.");
        var spim = AppleXmlPlist.GetString(dict, "spim")
            ?? throw new InvalidOperationException("SPIM mancante in midStartProvisioning.");
        return Convert.FromBase64String(spim);
    }

    private async Task<(byte[] Ptm, byte[] Tk, ulong Routing)> FinishProvisioningAsync(
        string url,
        byte[] cpim,
        AnisetteHeaders anisette,
        CancellationToken ct)
    {
        var plistBody = BuildFinishProvisioningPlist(cpim);
        using var request = BuildProvisioningRequest(HttpMethod.Post, url, anisette);
        request.Content = new ByteArrayContent(plistBody);
        request.Content.Headers.ContentType =
            new System.Net.Http.Headers.MediaTypeHeaderValue("application/x-www-form-urlencoded");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            var preview = Encoding.UTF8.GetString(body);
            if (preview.Length > 400)
                preview = preview[..400] + "…";
            throw new InvalidOperationException(
                $"midFinishProvisioning HTTP {(int)response.StatusCode} ({url}): {preview}");
        }

        var dict = AppleXmlPlist.GetResponseDict(body)
            ?? throw new InvalidOperationException("Risposta midFinishProvisioning non valida.");

        var ptmText = AppleXmlPlist.GetString(dict, "ptm")
            ?? throw new InvalidOperationException("PTM mancante.");
        var tkText = AppleXmlPlist.GetString(dict, "tk")
            ?? throw new InvalidOperationException("TK mancante.");
        var rinfoText = AppleXmlPlist.GetString(dict, "X-Apple-I-MD-RINFO")
            ?? throw new InvalidOperationException("X-Apple-I-MD-RINFO mancante.");

        if (!ulong.TryParse(rinfoText, NumberStyles.Integer, CultureInfo.InvariantCulture, out var routing))
            throw new InvalidOperationException("X-Apple-I-MD-RINFO non numerico.");

        return (Convert.FromBase64String(ptmText), Convert.FromBase64String(tkText), routing);
    }

    /// <summary>
    /// Formato/Dadoum: Header vuoto + Request.cpim (senza Header Apple risponde 433).
    /// </summary>
    private static byte[] BuildFinishProvisioningPlist(byte[] cpim)
    {
        var sb = new StringBuilder();
        sb.Append("""<?xml version="1.0" encoding="UTF-8"?>""");
        sb.Append(
            """
            <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
            <plist version="1.0"><dict>
              <key>Header</key><dict/>
              <key>Request</key><dict>
                <key>cpim</key><string>
            """);
        sb.Append(Convert.ToBase64String(cpim));
        sb.Append("</string></dict></dict></plist>");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    private HttpRequestMessage BuildProvisioningRequest(
        HttpMethod method,
        string url,
        AnisetteHeaders? anisette = null)
    {
        var request = new HttpRequestMessage(method, url);
        request.ApplyAkdProvisioningHeaders(anisette ?? BuildProvisioningAnisette());
        return request;
    }

    private AnisetteHeaders BuildProvisioningAnisette() => new()
    {
        ClientMmeInfo = _deviceStore.GetProvisioningClientInfo(),
        MmeDeviceId = _deviceStore.GetOrCreateDeviceUuid(),
        MdLu = _deviceStore.GetOrCreateLocalUserUuid(),
        SerialNumber = _profile.IdentityStyle switch
        {
            AdiIdentityStyle.IosAkd => _deviceStore.GetOrCreateSerialNumber(),
            AdiIdentityStyle.ProvisionCompat or AdiIdentityStyle.IphoneCoherent => "0",
            _ => string.Empty
        },
        ClientTimeUtc = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture),
    };

    private static string GetUrl(Dictionary<string, object?> bag, string key) =>
        bag.TryGetValue(key, out var value) && value is string url && !string.IsNullOrWhiteSpace(url)
            ? url
            : throw new InvalidOperationException($"URL bag privo di '{key}'.");

    private static void ResetProvisioningData(string provisionDir)
    {
        if (!Directory.Exists(provisionDir))
            return;

        foreach (var file in Directory.EnumerateFiles(provisionDir, "*", SearchOption.AllDirectories))
        {
            try { File.Delete(file); } catch { /* best effort */ }
        }
    }
}
