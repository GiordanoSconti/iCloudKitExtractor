using System.IO;
using System.Linq;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Sync Data → Account Info (<c>DownloadAccountInfo</c> / <c>chkAccountDetails</c>).
/// Capture <c>capture_syncdata_accountinfo_20260827_073741</c>: GET setup getPhoto +
/// GSA appleid settings (manage / payment / security / devices) + CDN icone.
/// </summary>
public sealed class AccountInfoSyncClient
{
    private readonly HttpClient _http;

    public AccountInfoSyncClient(HttpClient http) => _http = http;

    public sealed record Result(
        long TotalBytes,
        int DeviceCount,
        int ImageCount,
        string OutputDirectory,
        string? Warning);

    public async Task<Result> DumpAsync(
        ICloudSession session,
        string outDir,
        IProgress<string>? log,
        SyncDataAnisetteRefresh? anisetteRefresh,
        CancellationToken ct)
    {
        Directory.CreateDirectory(outDir);
        long total = 0;
        var images = 0;
        string? warning = null;

        EnsureAccountInfoAuth(session);

        async Task RefreshAsync(bool force = false)
        {
            if (anisetteRefresh is not null)
                await anisetteRefresh.EnsureFreshAsync(session, log, ct, force).ConfigureAwait(false);
            else
                session.Anisette.TouchClientTimeUtc();
        }

        await RefreshAsync(force: true).ConfigureAwait(false);

        // 1) Avatar
        try
        {
            log?.Report("  Account Info: getPhoto…");
            var photo = await GetPhotoAsync(session, ct).ConfigureAwait(false);
            total += photo.Length;
            var photoPath = Path.Combine(outDir, DetectImageExt(photo, "getPhoto.jpg"));
            await File.WriteAllBytesAsync(photoPath, photo, ct).ConfigureAwait(false);
            log?.Report($"    → {photo.Length:N0} B → {Path.GetFileName(photoPath)}");
        }
        catch (Exception ex)
        {
            warning = $"getPhoto: {ex.Message}";
            log?.Report($"  getPhoto skip: {ex.Message}");
        }

        await RefreshAsync().ConfigureAwait(false);

        // 2) Profilo manage
        byte[]? manageJson = null;
        try
        {
            log?.Report("  Account Info: manage…");
            manageJson = await GsaGetAsync(
                session,
                "https://gsa.apple.com/appleid/settings/account/manage",
                ct).ConfigureAwait(false);
            total += manageJson.Length;
            await File.WriteAllBytesAsync(Path.Combine(outDir, "manage.json"), manageJson, ct)
                .ConfigureAwait(false);
            log?.Report($"    → manage {manageJson.Length:N0} B");
        }
        catch (Exception ex)
        {
            warning = AppendWarn(warning, $"manage: {ex.Message}");
            log?.Report($"  manage skip: {ex.Message}");
        }

        // 3) payment + security (parallelo logico, sequenziale per Anisette)
        foreach (var (name, url) in new[]
                 {
                     ("payment", "https://gsa.apple.com/appleid/settings/account/manage/payment"),
                     ("security", "https://gsa.apple.com/appleid/settings/account/manage/security"),
                 })
        {
            try
            {
                await RefreshAsync().ConfigureAwait(false);
                log?.Report($"  Account Info: {name}…");
                var body = await GsaGetAsync(session, url, ct).ConfigureAwait(false);
                total += body.Length;
                await File.WriteAllBytesAsync(Path.Combine(outDir, $"{name}.json"), body, ct)
                    .ConfigureAwait(false);
                log?.Report($"    → {name} {body.Length:N0} B");
            }
            catch (Exception ex)
            {
                warning = AppendWarn(warning, $"{name}: {ex.Message}");
                log?.Report($"  {name} skip: {ex.Message}");
            }
        }

        // 4) Lista device
        var devicesDir = Path.Combine(outDir, "devices");
        Directory.CreateDirectory(devicesDir);
        var deviceIds = new List<string>();
        try
        {
            await RefreshAsync().ConfigureAwait(false);
            log?.Report("  Account Info: devices list…");
            var listBody = await GsaGetAsync(
                session,
                "https://gsa.apple.com/appleid/account/manage/security/devices",
                ct).ConfigureAwait(false);
            total += listBody.Length;
            await File.WriteAllBytesAsync(Path.Combine(devicesDir, "list.json"), listBody, ct)
                .ConfigureAwait(false);
            deviceIds = ExtractDeviceIds(listBody);
            log?.Report($"    → list {listBody.Length:N0} B ({deviceIds.Count} device)");
        }
        catch (Exception ex)
        {
            warning = AppendWarn(warning, $"devices: {ex.Message}");
            log?.Report($"  devices list skip: {ex.Message}");
        }

        // 5) Dettaglio per device + icone CDN
        var imagesDir = Path.Combine(outDir, "images");
        Directory.CreateDirectory(imagesDir);
        var imageUrls = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < deviceIds.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var id = deviceIds[i];
            try
            {
                // Evita raffica 503: distanzia i GET device; non martellare dopo list.
                if (i > 0)
                    await Task.Delay(350, ct).ConfigureAwait(false);
                await RefreshAsync().ConfigureAwait(false);
                log?.Report($"  Account Info: device {i + 1}/{deviceIds.Count}…");
                var detail = await GsaGetAsync(
                    session,
                    "https://gsa.apple.com/appleid/account/manage/security/devices/" +
                    Uri.EscapeDataString(id),
                    ct).ConfigureAwait(false);
                total += detail.Length;
                var safe = SanitizeFileToken(id);
                await File.WriteAllBytesAsync(
                    Path.Combine(devicesDir, $"{safe}.json"), detail, ct).ConfigureAwait(false);
                foreach (var u in ExtractImageUrls(detail))
                    imageUrls.Add(u);
            }
            catch (Exception ex)
            {
                warning = AppendWarn(warning, $"device {id}: {ex.Message}");
                log?.Report($"  device {id} skip: {ex.Message}");
            }
        }

        // Anche URL icone dal manage (profileImageUrl)
        if (manageJson is { Length: > 0 })
        {
            foreach (var u in ExtractImageUrls(manageJson))
                imageUrls.Add(u);
        }

        foreach (var url in imageUrls)
        {
            if (!url.StartsWith("https://appleid.cdn-apple.com/", StringComparison.OrdinalIgnoreCase)
                && !url.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                continue;
            try
            {
                var bytes = await CdnGetAsync(url, ct).ConfigureAwait(false);
                if (bytes.Length == 0)
                    continue;
                total += bytes.Length;
                var name = SanitizeFileToken(Path.GetFileName(new Uri(url).AbsolutePath));
                if (string.IsNullOrWhiteSpace(name))
                    name = "image.bin";
                await File.WriteAllBytesAsync(Path.Combine(imagesDir, name), bytes, ct)
                    .ConfigureAwait(false);
                images += 1;
            }
            catch (Exception ex)
            {
                log?.Report($"  image skip: {ex.Message}");
            }
        }

        await File.WriteAllTextAsync(
            Path.Combine(outDir, "summary.txt"),
            $"devices={deviceIds.Count}\r\nimages={images}\r\nbytes={total}\r\n" +
            $"warning={warning}\r\n",
            ct).ConfigureAwait(false);

        log?.Report(
            $"  Account Info: devices={deviceIds.Count} images={images} → {outDir}" +
            (warning is null ? "" : $" ({warning})"));

        return new Result(total, deviceIds.Count, images, outDir, warning);
    }

    private static void EnsureAccountInfoAuth(ICloudSession session)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Account Info: sessione senza DSID.");

        var identity = ResolveIdentityToken(session);
        if (string.IsNullOrWhiteSpace(identity)
            && string.IsNullOrWhiteSpace(session.MobileMeAuthToken)
            && string.IsNullOrWhiteSpace(session.GsICloudAuthToken))
        {
            throw new InvalidOperationException(
                "Account Info: servono IdentityToken (GSA) e/o MobileMeAuthToken.");
        }
    }

    private static string? ResolveIdentityToken(ICloudSession session)
    {
        // Candidati-aligned (ordine): icloud.auth settings → GsIdmsToken → PET.
        // Capture: manage Basic len≈700 (tok~476); validate Identity len≈412 (tok~260).
        foreach (var c in EnumerateAppleIdIdentityCandidates(session))
            return c.Token;
        return null;
    }

    private static IEnumerable<(string Source, string Token)> EnumerateAppleIdIdentityCandidates(
        ICloudSession session)
    {
        if (string.IsNullOrWhiteSpace(session.Adsid))
            yield break;

        var adsid = session.Adsid!;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var list = new List<(string Source, string Token, int SecretLen, int Rank)>();

        void Add(string source, string? secret, int rank)
        {
            if (string.IsNullOrWhiteSpace(secret))
                return;
            var body = NormalizeGsSecret(secret!);
            if (body.Length < 16)
                return;
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{adsid}:{body}"));
            if (!seen.Add(token))
                return;
            list.Add((source, token, body.Length, rank));
        }

        // Runtime 133259: manage/payment/security/devices → 200 solo con
        // spd:com.apple.gs.appleid.auth (secretLen 476). icloud.auth stesso len → sempre 401.
        // Identity len 700 = stesso formato; il servizio corretto è appleid.auth.
        // IdentityToken SPD di login è GsIdms corto (~280): non preferirlo finché non è
        // stato pinnato da un GET Account Info riuscito (secret ≈476).
        if (LooksLikeAppleIdIdentityToken(session.IdentityToken))
        {
            try
            {
                var text = Encoding.UTF8.GetString(Convert.FromBase64String(session.IdentityToken!));
                var colon = text.IndexOf(':');
                var secLen = colon >= 0 ? text.Length - colon - 1 : text.Length;
                if (secLen is >= 450 and <= 520 && seen.Add(session.IdentityToken!))
                    list.Add(("IdentityToken", session.IdentityToken!, secLen, 0));
            }
            catch { /* ignore */ }
        }

        if (session.GsServiceTokens.TryGetValue("com.apple.gs.appleid.auth", out var appleIdAuth))
            Add("spd:com.apple.gs.appleid.auth", appleIdAuth, 1);

        Add("icloud.auth", session.GsICloudAuthToken, 5);
        if (session.GsServiceTokens.TryGetValue("com.apple.gs.icloud.auth", out var icloudAuth))
            Add("spd:com.apple.gs.icloud.auth", icloudAuth, 5);

        Add("GsIdmsToken", session.GsIdmsToken, 9);
        Add("pet", DecodePeSecret(session.PeToken), 9);

        foreach (var c in list.OrderBy(x => x.Rank).ThenBy(x => Math.Abs(x.SecretLen - 476)))
            yield return (c.Source, c.Token);
    }

    private static string NormalizeGsSecret(string secret)
    {
        var body = secret;
        if (body.StartsWith("com.apple.gs.", StringComparison.Ordinal))
        {
            var c = body.IndexOf(':');
            if (c > 0)
                body = body[(c + 1)..];
            return body;
        }

        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(body));
            if (decoded.StartsWith("com.apple.gs.", StringComparison.Ordinal))
            {
                var c = decoded.IndexOf(':');
                if (c > 0)
                    return decoded[(c + 1)..];
            }
        }
        catch
        {
            // plain secret
        }

        return body;
    }

    private static string? DecodePeSecret(string? encoded)
    {
        if (string.IsNullOrWhiteSpace(encoded))
            return null;
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var colon = decoded.IndexOf(':');
            return colon >= 0 ? decoded[(colon + 1)..] : decoded;
        }
        catch
        {
            return encoded;
        }
    }
    /// <summary>
    /// Capture Account Info: Authorization Basic e X-Apple-GS-Token sono lo STESSO
    /// IdentityToken (adsid:secret). I token validate <c>com.apple.gs.*.auth</c> da soli no.
    /// </summary>
    private static bool LooksLikeAppleIdIdentityToken(string? token)
    {
        if (string.IsNullOrWhiteSpace(token) || token.Length < 32)
            return false;
        try
        {
            var raw = Convert.FromBase64String(token);
            if (raw.Length < 20 || raw[0] < 0x20)
                return false;
            var text = Encoding.UTF8.GetString(raw);
            if (text.StartsWith("com.apple.gs.", StringComparison.Ordinal))
                return false;
            var colon = text.IndexOf(':');
            return colon is >= 20 and <= 80 && colon < text.Length - 16;
        }
        catch
        {
            return false;
        }
    }

    private async Task<byte[]> GetPhotoAsync(ICloudSession session, CancellationToken ct)
    {
        var mme = session.MobileMeAuthToken
                  ?? session.GsICloudAuthToken
                  ?? session.CloudKitGsToken;
        if (string.IsNullOrWhiteSpace(mme))
            throw new InvalidOperationException("getPhoto: manca MobileMeAuthToken.");

        using var request = new HttpRequestMessage(
            HttpMethod.Get, "https://setup.icloud.com/setup/account/getPhoto");
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", AppleHttpExtensions.BasicAuth(session.Dsid, mme));
        session.Anisette.TouchClientTimeUtc();
        request.ApplyAuthKitAkdAnisette(session.Anisette);
        request.Headers.Accept.Clear();
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        request.Headers.TryAddWithoutValidation("Accept-Language", "en-US");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
        {
            throw new InvalidOperationException(
                $"getPhoto HTTP {(int)response.StatusCode}: {Preview(body)}");
        }

        return body;
    }

    /// <summary>
    /// Header GSA appleid/settings come (062952/073741): UA + X-MMe-Client-Info +
    /// anisette MD/MD-M/RINFO — senza X-Apple-I-MD-LU.
    /// </summary>
    private static void ApplyAccountInfoGsaHeaders(HttpRequestMessage request, ICloudSession session)
    {
        session.Anisette.TouchClientTimeUtc();
        request.Headers.Remove("User-Agent");
        request.Headers.TryAddWithoutValidation("User-Agent", "CloudKit/829 (17A577)");
        request.Headers.Remove("X-MMe-Client-Info");
        request.Headers.TryAddWithoutValidation(
            "X-MMe-Client-Info",
            AkdHttpHeaders.ResolveAkdClientInfo(session.Anisette));
        request.Headers.Remove("Accept-Language");
        request.Headers.TryAddWithoutValidation("Accept-Language", "en-US");
        request.Headers.Remove("X-Apple-I-MD-LU");
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);
        request.Headers.Accept.Clear();
        request.Headers.TryAddWithoutValidation("Accept", "application/json; q=0.01");
    }

    private async Task<byte[]> GsaGetAsync(ICloudSession session, string url, CancellationToken ct)
    {
        var candidates = EnumerateAppleIdIdentityCandidates(session).ToList();
        if (candidates.Count == 0)
        {
            throw new InvalidOperationException(
                "GSA: nessun Identity SPD per Account Info (manca Adsid + appleid.auth). " +
                "Rifai login GSA: serve spd t/com.apple.gs.appleid.auth.");
        }

        Exception? last = null;
        foreach (var (source, identity) in candidates)
        {
            var secretLen = 0;
            try
            {
                var text = Encoding.UTF8.GetString(Convert.FromBase64String(identity));
                var colon = text.IndexOf(':');
                secretLen = colon > 0 ? text.Length - colon - 1 : 0;
            }
            catch { /* ignore */ }

            // 503/429: stesso Identity (auth OK), Apple rate-limit — non passare al candidato successivo.
            for (var attempt = 0; attempt < 4; attempt++)
            {
                if (attempt > 0)
                    await Task.Delay(400 * attempt, ct).ConfigureAwait(false);


                using var request = new HttpRequestMessage(HttpMethod.Get, url);
                request.Headers.TryAddWithoutValidation("Authorization", "Basic " + identity);
                request.Headers.TryAddWithoutValidation("X-Apple-GS-Token", identity);
                ApplyAccountInfoGsaHeaders(request, session);

                using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
                var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                var status = (int)response.StatusCode;


                if (response.IsSuccessStatusCode)
                {
                    session.IdentityToken = identity;
                    return body;
                }

                last = new InvalidOperationException(
                    $"GSA HTTP {status} {url} via {source}: {Preview(body)}");

                if (status is 503 or 502 or 429)
                    continue; // retry same identity

                if (status == 401)
                    break; // next candidate

                throw last; // other errors: stop
            }
        }

        throw last ?? new InvalidOperationException("GSA Account Info: tutti i candidati Identity falliti.");
    }

    private async Task<byte[]> CdnGetAsync(string url, CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            return [];
        return await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
    }

    private static List<string> ExtractDeviceIds(byte[] json)
    {
        var ids = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            if (!doc.RootElement.TryGetProperty("devices", out var devices)
                || devices.ValueKind != JsonValueKind.Array)
                return ids;

            foreach (var d in devices.EnumerateArray())
            {
                if (d.TryGetProperty("id", out var idEl)
                    && idEl.ValueKind == JsonValueKind.String
                    && !string.IsNullOrWhiteSpace(idEl.GetString()))
                {
                    ids.Add(idEl.GetString()!);
                    continue;
                }

                if (d.TryGetProperty("deviceDetailUri", out var uriEl)
                    && uriEl.ValueKind == JsonValueKind.String)
                {
                    var uri = uriEl.GetString() ?? "";
                    var slash = uri.LastIndexOf('/');
                    if (slash >= 0 && slash < uri.Length - 1)
                        ids.Add(uri[(slash + 1)..]);
                }
            }
        }
        catch
        {
            /* ignore parse errors */
        }

        return ids;
    }

    private static IEnumerable<string> ExtractImageUrls(byte[] json)
    {
        var found = new List<string>();
        try
        {
            using var doc = JsonDocument.Parse(json);
            CollectUrls(doc.RootElement, found);
        }
        catch
        {
            /* ignore */
        }

        return found;
    }

    private static void CollectUrls(JsonElement el, List<string> found)
    {
        switch (el.ValueKind)
        {
            case JsonValueKind.Object:
                foreach (var p in el.EnumerateObject())
                {
                    if (p.Value.ValueKind == JsonValueKind.String)
                    {
                        var s = p.Value.GetString();
                        if (s is not null
                            && (s.StartsWith("https://appleid.cdn-apple.com/", StringComparison.OrdinalIgnoreCase)
                                || (p.Name.Contains("Image", StringComparison.OrdinalIgnoreCase)
                                    && s.StartsWith("https://", StringComparison.OrdinalIgnoreCase))))
                        {
                            found.Add(s);
                        }
                    }
                    else
                    {
                        CollectUrls(p.Value, found);
                    }
                }

                break;
            case JsonValueKind.Array:
                foreach (var c in el.EnumerateArray())
                    CollectUrls(c, found);
                break;
        }
    }

    private static string DetectImageExt(byte[] data, string fallback)
    {
        if (data.Length >= 3 && data[0] == 0xff && data[1] == 0xd8 && data[2] == 0xff)
            return "getPhoto.jpg";
        if (data.Length >= 8
            && data[0] == 0x89 && data[1] == 0x50 && data[2] == 0x4e && data[3] == 0x47)
            return "getPhoto.png";
        return fallback;
    }

    private static string SanitizeFileToken(string value)
    {
        var chars = value.ToCharArray();
        for (var i = 0; i < chars.Length; i++)
        {
            var c = chars[i];
            if (char.IsLetterOrDigit(c) || c is '-' or '_' or '.')
                continue;
            chars[i] = '_';
        }

        var s = new string(chars);
        return s.Length > 120 ? s[..120] : s;
    }

    private static string Preview(byte[] body)
    {
        if (body.Length == 0)
            return "(empty)";
        return Encoding.UTF8.GetString(body.AsSpan(0, Math.Min(body.Length, 180)));
    }

    private static string AppendWarn(string? existing, string next) =>
        string.IsNullOrWhiteSpace(existing) ? next : existing + "; " + next;
}
