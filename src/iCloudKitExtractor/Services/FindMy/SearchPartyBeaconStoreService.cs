using System.IO;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Auth;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Http;
using iCloudKitExtractor.Services.SyncData;

namespace iCloudKitExtractor.Services.FindMy;

/// <summary>
/// Find My Items / AirTag — sola lettura.
/// Flusso: get_account_settings (Client-Info Find My) → ckAppInit searchparty →
/// zone/retrieve + record/sync <c>BeaconStore</c> → PCS decrypt con
/// <see cref="ICloudSession.PcsEscrowedKeySet"/> (Unlock EscrowedKeys).
/// Opzionale: <c>acsnservice/fetch</c> se c’è <c>searchPartyToken</c> (report posizioni
/// solo con beacon ids già noti — senza ids la risposta è vuota).
/// </summary>
public sealed class SearchPartyBeaconStoreService
{
    public const string BeaconStoreZone = "BeaconStore";
    private const int MaxSyncPages = 24;

    /// <summary>Esito Find My Items: log testuale + tabella dispositivi decifrati.</summary>
    public sealed record FetchResult(
        string LogText,
        IReadOnlyList<BeaconDeviceInventory.DeviceRow> Devices,
        string OutputDirectory);

    private static readonly Regex GuidLike = new(
        @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        RegexOptions.Compiled);

    private readonly HttpClient _http;
    private readonly ICloudBackupOrchestrator _orchestrator;
    private readonly CloudKitGatewayClient _gateway;

    public SearchPartyBeaconStoreService(HttpClient http, ICloudBackupOrchestrator orchestrator)
    {
        _http = http;
        _orchestrator = orchestrator;
        _gateway = new CloudKitGatewayClient(http);
    }

    public async Task<string> FetchBeaconStoreTextAsync(
        ICloudSession session,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        var result = await FetchBeaconStoreAsync(session, progress, ct).ConfigureAwait(false);
        return result.LogText;
    }

    public async Task<FetchResult> FetchBeaconStoreAsync(
        ICloudSession session,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Sessione senza DSID — effettua il login.");

        var hasEscrow = session.PcsEscrowedKeySet is { Length: > 32 };
        var hasManatee = session.PcsManateeCompactKeys is { Count: > 0 };
        if (!hasEscrow && !hasManatee)
        {
            throw new InvalidOperationException(
                "Manca PCS KeySet in sessione. Unlock EscrowedKeys e/o CKKS OpenVault (LimitedPeersAllowed), poi riprova.");
        }

        var log = new StringBuilder();
        var logGate = new object();
        void L(string m = "")
        {
            lock (logGate)
                log.AppendLine(m);
            if (!string.IsNullOrWhiteSpace(m))
                progress?.Report(m);
        }

        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var outDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "iCloudKitExtractor",
            "searchparty",
            $"beaconstore_{stamp}");
        Directory.CreateDirectory(outDir);
        L($"Output: {outDir}");
        if (hasEscrow)
            L($"PCS KeySet Escrow: {session.PcsEscrowedKeySet!.Length} B");
        if (hasManatee)
            L($"PCS Manatee (CKKS): {session.PcsManateeCompactKeys!.Count} compact keys");
        L();

        await EnsureSearchPartyAccountSettingsAsync(session, L, ct).ConfigureAwait(false);

        var binding = CloudKitContainerBinding.SearchParty;
        var savedUserId = session.CloudKitUserId;
        var savedToken = session.CloudKitAuthToken;
        var savedGateway = session.CloudKitGatewayUrl;

        try
        {
            L($"ckAppInit → {binding.ContainerId} (bundle {binding.BundleId})…");
            await _orchestrator.CkAppInitAsync(session, binding.ContainerId, null, ct)
                .ConfigureAwait(false);
            if (string.IsNullOrWhiteSpace(session.CloudKitUserId))
                throw new InvalidOperationException("ckAppInit searchparty senza cloudKitUserId.");
            if (string.IsNullOrWhiteSpace(session.CloudKitAuthToken))
                throw new InvalidOperationException("ckAppInit searchparty senza cloudKitToken.");
            L($"  ckUserId={session.CloudKitUserId} tokenLen={session.CloudKitAuthToken.Length}");
            L();

            byte[]? zonePayload = null;
            foreach (var zoneAttempt in new[] { BeaconStoreZone, "default", "_defaultZone" })
            {
                ct.ThrowIfCancellationRequested();
                L($"zone/retrieve → {zoneAttempt}…");
                try
                {
                    var zoneBody = CloudKitDelimitedRequest.BuildZoneRetrieve(
                        session.CloudKitUserId, [zoneAttempt], container: binding);
                    var payload = await _gateway.ZoneRetrieveAsync(
                            session, zoneBody, ct, container: binding)
                        .ConfigureAwait(false);
                    await File.WriteAllBytesAsync(
                        Path.Combine(outDir, $"zones_{Sanitize(zoneAttempt)}.bin"), payload, ct)
                        .ConfigureAwait(false);
                    var strings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                    await File.WriteAllLinesAsync(
                        Path.Combine(outDir, $"zones_{Sanitize(zoneAttempt)}_strings.txt"),
                        strings, ct).ConfigureAwait(false);
                    var note = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var err)
                        ? err
                        : CloudKitResponseParser.DescribeCompactPayload(payload);
                    L($"  → {payload.Length:N0} B" + (note is null ? "" : $" — {note}"));
                    if (zonePayload is null
                        || (!CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _)
                            && payload.Length > zonePayload.Length))
                    {
                        zonePayload = payload;
                    }
                }
                catch (Exception ex)
                {
                    L($"  skip: {ex.Message}");
                }
            }

            L();
            L($"record/sync → {BeaconStoreZone}…");
            byte[]? token = null;
            var pages = 0;
            long syncBytes = 0;
            for (var page = 1; page <= MaxSyncPages; page++)
            {
                ct.ThrowIfCancellationRequested();
                var body = CloudKitDelimitedRequest.BuildRecordRetrieveChanges(
                    session.CloudKitUserId, BeaconStoreZone, token, binding);
                byte[] payload;
                try
                {
                    payload = await _gateway.RecordChangesAsync(session, body, ct, binding)
                        .ConfigureAwait(false);
                }
                catch (Exception ex)
                {
                    L($"  p{page}: {ex.Message}");
                    break;
                }

                pages++;
                syncBytes += payload.Length;
                var tag = $"record_sync_{Sanitize(BeaconStoreZone)}_p{page}";
                await File.WriteAllBytesAsync(Path.Combine(outDir, $"{tag}.bin"), payload, ct)
                    .ConfigureAwait(false);
                var pageStrings = CloudKitResponseParser.ExtractDiagnosticStrings(payload);
                await File.WriteAllLinesAsync(
                    Path.Combine(outDir, $"{tag}_strings.txt"), pageStrings, ct)
                    .ConfigureAwait(false);

                var pageNote = CloudKitResponseParser.IsCloudKitErrorPayload(payload, out var serr)
                    ? serr
                    : CloudKitResponseParser.DescribeCompactPayload(payload);
                L($"  p{page} → {payload.Length:N0} B" + (pageNote is null ? "" : $" — {pageNote}"));

                if (CloudKitResponseParser.IsCloudKitErrorPayload(payload, out _))
                    break;

                var cont = CloudKitResponseParser.TryExtractRecordSyncContinuation(payload);
                var stringMore = pageStrings.Any(static s =>
                    s.Contains("moreComing", StringComparison.OrdinalIgnoreCase));
                var shouldContinue = cont.MoreComing
                                     || (stringMore && cont.SyncContinuationToken is { Length: > 0 });
                if (!shouldContinue || cont.SyncContinuationToken is not { Length: > 0 })
                    break;
                if (token is not null
                    && token.AsSpan().SequenceEqual(cont.SyncContinuationToken))
                {
                    L("  syncToken invariato — stop");
                    break;
                }

                token = cont.SyncContinuationToken;
                await Task.Delay(100, ct).ConfigureAwait(false);
            }

            L($"  sync pages={pages} bytes={syncBytes:N0}");
            L();

            // Sempre decrypt fresco su questa cartella run (niente riuso di crypto precedenti).
            var cryptoRoot = Path.Combine(outDir, "crypto");
            if (Directory.Exists(cryptoRoot))
                Directory.Delete(cryptoRoot, recursive: true);

            L("PCS decrypt completo (KeySet Escrow → campi type=20 di questa sync)…");
            var pcsProgress = new Progress<string>(m => L(m));
            var cryptoSummary = await Task.Run(
                    () => SyncDataPcsDecryptor.DecryptContainerDirectory(
                        session, outDir, binding.ContainerId, pcsProgress),
                    ct)
                .ConfigureAwait(false);
            L($"  → {cryptoSummary.Message} (fields={cryptoSummary.FieldCount}, " +
              $"decrypted={cryptoSummary.DecryptedCount}, zoneKeys={cryptoSummary.ZoneKeys})");
            if (cryptoSummary.DecryptedCount == 0 && cryptoSummary.ZoneKeys == 0)
            {
                L();
                L("DIAGNOSI: zoneKeys=0 — ProtectionInfo BeaconStore non unwrapato.");
                L("Serve identità Manatee: Unlock Octagon → OTBottle/Peer → CKKS OpenVault");
                L("(LimitedPeersAllowed), poi rilancia Find My Items.");
            }

            L();

            var deviceTable = BeaconDeviceInventory.BuildFromRunDirectory(outDir);
            L("=== Dispositivi (1 riga = 1 MasterBeacon decifrato) ===");
            L(deviceTable.Message);
            foreach (var line in BeaconDeviceInventory.FormatLogLines(deviceTable.Devices))
                L(line);

            L();
            var inventory = SummarizeFromFreshPlaintext(outDir);
            L("=== Inventario campi (plaintext grezzo) ===");
            if (inventory.Count == 0)
            {
                L("(nessun testo utile — vedi crypto/*/plaintext/ e decrypt_index.tsv)");
                var wireHints = SummarizeFromSyncStrings(outDir);
                if (wireHints.Count > 0)
                {
                    L("--- tipi/nomi già in chiaro nella sync (non da decrypt) ---");
                    foreach (var line in wireHints.Take(20))
                        L("  · " + line);
                }
            }
            else
            {
                foreach (var line in inventory.Take(40))
                    L("  · " + line);
            }

            L();
            L("=== searchPartyToken / acsnservice ===");
            L($"searchPartyToken: {(string.IsNullOrWhiteSpace(session.SearchPartyToken) ? "NO" : "OK")}");
            if (!string.IsNullOrWhiteSpace(session.SearchPartyToken))
            {
                L("acsnservice/fetch (ids=[])…");
                var acsn = await ProbeAcsnEmptyAsync(session, outDir, ct).ConfigureAwait(false);
                L(acsn);
            }
            else
            {
                L("Skip acsnservice — token assente (get_account_settings Find My non l’ha restituito).");
            }

            L();
            L("Sola lettura: nessun wipe/lost/erase.");
            string logText;
            lock (logGate)
                logText = log.ToString();
            return new FetchResult(logText, deviceTable.Devices, outDir);
        }
        finally
        {
            session.CloudKitUserId = savedUserId;
            session.CloudKitAuthToken = savedToken;
            session.CloudKitGatewayUrl = savedGateway;
        }
    }

    /// <summary>
    /// get_account_settings con Client-Info Find My per ottenere SearchParty + searchPartyToken.
    /// </summary>
    private async Task EnsureSearchPartyAccountSettingsAsync(
        ICloudSession session,
        Action<string> log,
        CancellationToken ct)
    {
        var secret = ResolveSetupSecret(session);
        if (string.IsNullOrWhiteSpace(secret))
        {
            log("get_account_settings Find My: skip — manca PET/mmeAuthToken.");
            return;
        }

        var user = !string.IsNullOrWhiteSpace(session.AppleId)
            ? session.AppleId.Trim()
            : session.Dsid;

        log($"get_account_settings (Find My Client-Info) come {user}…");
        using var request = new HttpRequestMessage(
            HttpMethod.Get, "https://setup.icloud.com/setup/get_account_settings");
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic", AppleHttpExtensions.BasicAuth(user, secret));
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.FindMyUserAgent);
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", AppleClientInfo.FindMyClientInfo);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        request.Headers.TryAddWithoutValidation("Accept-Language", "en-US");
        session.Anisette.TouchClientTimeUtc();
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);
        if (!string.IsNullOrEmpty(session.Anisette.MdLu))
            request.Headers.TryAddWithoutValidation("X-Apple-I-MD-LU", session.Anisette.MdLu);

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var body = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode && (int)response.StatusCode != 409)
        {
            log($"  HTTP {(int)response.StatusCode} len={body.Length} — token Search Party possono mancare.");
            return;
        }

        try
        {
            var dict = AppleXmlPlist.GetResponseDict(body) ?? new Dictionary<string, object?>();
            ApplySearchPartyHints(session, dict, log);
        }
        catch (Exception ex)
        {
            log($"  parse skip: {ex.Message}");
        }
    }

    private static void ApplySearchPartyHints(
        ICloudSession session,
        Dictionary<string, object?> accountSettings,
        Action<string> log)
    {
        var hasSearchParty = false;
        if (accountSettings.TryGetValue("com.apple.mobileme", out var mobileMe)
            && mobileMe is Dictionary<string, object?> mobileMeDict)
        {
            if (mobileMeDict.ContainsKey("com.apple.Dataclass.SearchParty"))
                hasSearchParty = true;

            if (mobileMeDict.TryGetValue("tokens", out var tokensObj)
                && tokensObj is Dictionary<string, object?> tokens)
            {
                if (tokens.TryGetValue("searchPartyToken", out var sp)
                    && sp is string spTok
                    && !string.IsNullOrWhiteSpace(spTok))
                {
                    session.SearchPartyToken = spTok;
                }

                if (tokens.TryGetValue("mmeFMIPToken", out var fmip)
                    && fmip is string fmipTok
                    && !string.IsNullOrWhiteSpace(fmipTok))
                {
                    session.MmeFmipToken = fmipTok;
                }

                if (tokens.TryGetValue("mmeFMFAppToken", out var fmf)
                    && fmf is string fmfTok
                    && !string.IsNullOrWhiteSpace(fmfTok))
                {
                    session.MmeFmfAppToken = fmfTok;
                }

                if (tokens.TryGetValue("mmeAuthToken", out var mme)
                    && mme is string mmeTok
                    && !string.IsNullOrWhiteSpace(mmeTok))
                {
                    session.MobileMeAuthToken = mmeTok;
                }
            }
        }

        log($"  SearchParty dataclass: {(hasSearchParty ? "sì" : "no")}");
        log($"  searchPartyToken: {(string.IsNullOrWhiteSpace(session.SearchPartyToken) ? "NO" : "OK")}");
    }

    private static string? ResolveSetupSecret(ICloudSession session)
    {
        if (!string.IsNullOrWhiteSpace(session.PeToken))
        {
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(session.PeToken));
                var colon = decoded.IndexOf(':');
                if (colon >= 0)
                    return decoded[(colon + 1)..];
            }
            catch
            {
                // fall through
            }
        }

        if (!string.IsNullOrWhiteSpace(session.MobileMeAuthToken))
            return session.MobileMeAuthToken;

        if (!string.IsNullOrWhiteSpace(session.GsICloudAuthToken))
            return GsaGrandSlamAuthService.ExtractGsICloudAuthPasswordForBootstrap(
                session.GsICloudAuthToken);

        return null;
    }

    private async Task<string> ProbeAcsnEmptyAsync(
        ICloudSession session,
        string outDir,
        CancellationToken ct)
    {
        var nowMs = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var startMs = nowMs - 7L * 24 * 3600 * 1000;
        var bodyObj = new Dictionary<string, object?>
        {
            ["search"] = new object[]
            {
                new Dictionary<string, object?>
                {
                    ["startDate"] = startMs,
                    ["endDate"] = nowMs,
                    ["ids"] = Array.Empty<string>(),
                },
            },
        };
        var json = JsonSerializer.Serialize(bodyObj);
        using var request = new HttpRequestMessage(
            HttpMethod.Post, "https://gateway.icloud.com/acsnservice/fetch");
        request.Content = new StringContent(json, Encoding.UTF8, "application/json");
        request.Headers.Authorization = new AuthenticationHeaderValue(
            "Basic",
            AppleHttpExtensions.BasicAuth(session.Dsid, session.SearchPartyToken!));
        request.Headers.TryAddWithoutValidation("Accept", "application/json");
        request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.FindMyUserAgent);
        request.Headers.TryAddWithoutValidation("X-MMe-Client-Info", AppleClientInfo.FindMyClientInfo);
        session.Anisette.TouchClientTimeUtc();
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var raw = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        await File.WriteAllBytesAsync(Path.Combine(outDir, "acsn_fetch_empty.bin"), raw, ct)
            .ConfigureAwait(false);

        var preview = Encoding.UTF8.GetString(raw);
        var resultsN = 0;
        try
        {
            using var doc = JsonDocument.Parse(raw);
            if (doc.RootElement.TryGetProperty("results", out var results)
                && results.ValueKind == JsonValueKind.Array)
            {
                resultsN = results.GetArrayLength();
            }
        }
        catch
        {
            // ignore
        }

        return $"acsnservice/fetch (ids=[]) → HTTP {(int)response.StatusCode} " +
               $"results={resultsN} — atteso vuoto senza beacon ids; " +
               $"body={Trim(preview, 120)}";
    }

    /// <summary>
    /// Inventario solo da <c>crypto/**/plaintext</c> di questa run (niente dump precedenti).
    /// </summary>
    private static List<string> SummarizeFromFreshPlaintext(string outDir)
    {
        var hits = new List<string>();
        var crypto = Path.Combine(outDir, "crypto");
        if (!Directory.Exists(crypto))
            return hits;

        foreach (var file in Directory.EnumerateFiles(crypto, "*", SearchOption.AllDirectories))
        {
            var name = Path.GetFileName(file);
            var dir = Path.GetFileName(Path.GetDirectoryName(file) ?? "");
            // Preferisci .txt prodotti dal decrypt; bin piccoli con testo UTF-8
            if (name.EndsWith(".tsv", StringComparison.OrdinalIgnoreCase))
                continue;
            if (!name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                && !name.EndsWith(".bin", StringComparison.OrdinalIgnoreCase)
                && !name.EndsWith(".plist", StringComparison.OrdinalIgnoreCase))
            {
                continue;
            }

            byte[] bytes;
            try
            {
                var fi = new FileInfo(file);
                if (fi.Length is 0 or > 256_000)
                    continue;
                bytes = File.ReadAllBytes(file);
            }
            catch
            {
                continue;
            }

            string? text = null;
            if (name.EndsWith(".txt", StringComparison.OrdinalIgnoreCase)
                || LooksLikeUtf8Inventory(bytes))
            {
                text = Encoding.UTF8.GetString(bytes).TrimEnd('\0').Trim();
            }

            if (string.IsNullOrWhiteSpace(text) || text.Length > 200)
                continue;
            if (Regex.IsMatch(text, @"^[\x00-\x08\x0b\x0c\x0e-\x1f]+"))
                continue;

            var field = dir is { Length: > 0 } ? dir : name;
            if (field.StartsWith("type20_", StringComparison.OrdinalIgnoreCase)
                && text.Length < 2)
            {
                continue;
            }

            hits.Add($"{field}: {text}");
        }

        // field_records.tsv di questa run
        foreach (var tsv in Directory.EnumerateFiles(crypto, "field_records.tsv", SearchOption.AllDirectories))
        {
            try
            {
                foreach (var line in File.ReadLines(tsv).Skip(1))
                {
                    var parts = line.Split('\t');
                    if (parts.Length < 6)
                        continue;
                    var field = parts[0];
                    var preview = parts[^1];
                    if (string.IsNullOrWhiteSpace(preview) || preview.Length > 120)
                        continue;
                    hits.Add($"{field}: {preview}");
                }
            }
            catch
            {
                // ignore
            }
        }

        return hits
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static s => s, StringComparer.OrdinalIgnoreCase)
            .Take(80)
            .ToList();
    }

    private static bool LooksLikeUtf8Inventory(byte[] bytes)
    {
        if (bytes.Length is 0 or > 512)
            return false;
        var printable = 0;
        foreach (var b in bytes)
        {
            if (b is >= 32 and < 127 or >= 192 or 9 or 10 or 13)
                printable++;
        }

        return printable * 10 >= bytes.Length * 8;
    }

    /// <summary>
    /// Hint inventariali dai dump stringhe CloudKit (solo supporto se decrypt vuoto).
    /// </summary>
    private static List<string> SummarizeFromSyncStrings(string outDir)
    {
        var hits = new List<string>();
        var typeCounts = new Dictionary<string, int>(StringComparer.OrdinalIgnoreCase);
        var types = new[]
        {
            "MasterBeaconRecord", "BeaconNamingRecord", "SharedBeaconRecord",
            "KeyAlignmentRecord", "LostModeRecord", "SafeLocation",
            "OwnedDeviceKeyRecord", "LeashRecord",
        };

        foreach (var file in Directory.EnumerateFiles(outDir, "*_strings.txt", SearchOption.TopDirectoryOnly))
        {
            string[] lines;
            try
            {
                lines = File.ReadAllLines(file);
            }
            catch
            {
                continue;
            }

            foreach (var raw in lines)
            {
                var line = raw.Trim();
                if (line.Length is < 2 or > 120)
                    continue;

                foreach (var t in types)
                {
                    if (line.Equals(t, StringComparison.OrdinalIgnoreCase)
                        || line.StartsWith(t, StringComparison.OrdinalIgnoreCase))
                    {
                        typeCounts[t] = typeCounts.GetValueOrDefault(t) + 1;
                    }
                }

                if (LooksLikeDeviceDisplayName(line))
                    hits.Add($"nome: {line}");

                if (line is "iPhone" or "iPad" or "AirTag" or "Apple Watch"
                    || line.StartsWith("MacBook", StringComparison.OrdinalIgnoreCase)
                    || line.StartsWith("Mac mini", StringComparison.OrdinalIgnoreCase)
                    || line.StartsWith("iMac", StringComparison.OrdinalIgnoreCase))
                {
                    hits.Add($"model/class: {line}");
                }
            }
        }

        foreach (var (t, n) in typeCounts.OrderByDescending(static kv => kv.Value))
            hits.Insert(0, $"record type {t} × {n}");

        return hits
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(60)
            .ToList();
    }

    private static bool LooksLikeDeviceDisplayName(string line)
    {
        if (line.Length is < 4 or > 80)
            return false;
        if (GuidLike.IsMatch(line))
            return false;
        if (Regex.IsMatch(line, @"^[0-9A-Fa-f]{20,}$"))
            return false;
        if (line.Contains("Record", StringComparison.OrdinalIgnoreCase))
            return false;
        if (line is "BeaconStore" or "privateKey" or "publicKey" or "sharedSecret"
            or "productId" or "stableIdentifier" or "batteryLevel" or "systemVersion"
            or "pairingDate" or "vendorId" or "isZeus" or "emoji" or "roleId"
            or "associatedBeacon" or "beaconIdentifier" or "latitude" or "longitude")
            return false;

        var letters = line.Count(char.IsLetter);
        return letters >= 3 && line.Any(char.IsWhiteSpace);
    }

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        return sb.ToString();
    }

    private static string Trim(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
