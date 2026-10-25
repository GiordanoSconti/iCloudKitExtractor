using System.Text;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Backup;

public sealed class CloudKitBackupService
{
    private const string MbksyncZone = "mbksync";
    private const string BackupAccountRecord = "BackupAccount";
    private const int MinFullRecordBytes = 256;
    private const int SnapshotBatchSize = 4;

    private readonly CloudKitGatewayClient _gateway;

    public CloudKitBackupService(HttpClient http) => _gateway = new CloudKitGatewayClient(http);

    public Task<IReadOnlyList<BackupDevice>> ListDevicesAsync(
        ICloudSession session,
        CancellationToken ct = default)
        => ListDevicesAsync(session, null, null, ct);

    public Task<IReadOnlyList<BackupDevice>> ListDevicesAsync(
        ICloudSession session,
        IProgress<string>? log,
        CancellationToken ct = default)
        => ListDevicesAsync(session, log, null, ct);

    /// <summary>
    /// Elenco backup: FetchRecordZones → BackupAccount → D: → S:.
    /// Header Foreground + f30 MMCS costruiti dalla sessione corrente (non da cattura).
    /// </summary>
    public async Task<IReadOnlyList<BackupDevice>> ListDevicesAsync(
        ICloudSession session,
        IProgress<string>? log,
        byte[]? mbsManifest,
        CancellationToken ct = default)
    {
        var catalog = RestoreSessionState.Create(session);
        catalog.EnsureForeground(session);
        var ctx = catalog.ToRequestContext();

        log?.Report("CloudKit: record/retrieve FetchRecordZones …");
        var zonesBody = CloudKitDelimitedRequest.BuildZoneRetrieve(
            session.CloudKitUserId, CloudKitDelimitedRequest.BackupZones, ctx);
        byte[] zonesPayload;
        try
        {
            zonesPayload = await _gateway.RecordRetrieveZonesAsync(session, zonesBody, ct, catalog);
            log?.Report($"  record/retrieve FetchRecordZones → {zonesPayload.Length:N0} byte");
        }
        catch (Exception ex)
        {
            log?.Report($"  record/retrieve FetchRecordZones skip: {ex.Message} — fallback zone/retrieve");
            zonesPayload = await _gateway.ZoneRetrieveAsync(session, zonesBody, ct, catalog);
            log?.Report($"  zone/retrieve → {zonesPayload.Length:N0} byte");
        }

        catalog.TryAbsorbFromPayload(zonesPayload);

        log?.Report($"CloudKit: FetchRecords {BackupAccountRecord}…");
        var accountPayload = await FetchRecordsAsync(session, MbksyncZone, [BackupAccountRecord], catalog, ct);

        var deviceRecordNames = CloudKitBackupCatalogParser.ExtractDeviceRecordsFromBackupAccount(accountPayload);
        if (deviceRecordNames.Count == 0)
        {
            deviceRecordNames = CloudKitBackupCatalogParser.ExtractDeviceRecords(zonesPayload).ToList();
            if (deviceRecordNames.Count > 0)
                log?.Report($"  device da FetchRecordZones → {deviceRecordNames.Count}");
        }

        if (deviceRecordNames.Count == 0 && mbsManifest is { Length: > 32 })
        {
            deviceRecordNames = CloudKitBackupCatalogParser.ExtractDeviceRecords(mbsManifest).ToList();
            if (deviceRecordNames.Count > 0)
                log?.Report($"  device da mbs manifest → {deviceRecordNames.Count}");
        }

        log?.Report(
            $"CloudKit: BackupAccount → {deviceRecordNames.Count} device record ({accountPayload.Length:N0} byte)");
        if (deviceRecordNames.Count == 0)
        {
            if (accountPayload.Length < MinFullRecordBytes)
            {
                var hint = CloudKitResponseParser.DescribeCompactPayload(accountPayload);
                log?.Report(
                    $"  risposta BackupAccount troppo piccola (stub?{ (hint is null ? "" : $" {hint}") }) — " +
                    "verifica ckAppInit token e header Foreground");
            }

            return [];
        }

        var devices = new List<BackupDevice>();
        foreach (var deviceRecord in deviceRecordNames)
        {
            BackupDevice? device = null;
            byte[]? bestPayload = null;
            foreach (var fetchName in CloudKitRecordNames.ListFetchCandidates(deviceRecord))
            {
                log?.Report($"CloudKit: FetchRecords Device {fetchName}…");
                var devicePayload = await FetchRecordsAsync(session, MbksyncZone, [fetchName], catalog, ct);
                if (bestPayload is null || devicePayload.Length > bestPayload.Length)
                    bestPayload = devicePayload;

                var parsed = BuildDeviceFromPayload(devicePayload, deviceRecord);
                foreach (var name in CloudKitResponseParser.ExtractAssetRecordNames(devicePayload))
                    parsed.AssetHints.Add(name);
                device = parsed;

                if (devicePayload.Length >= MinFullRecordBytes && parsed.Snapshots.Count > 0)
                    break;
            }

            if (device is not null && bestPayload is not null && device.Snapshots.Count == 0)
                device = BuildDeviceFromPayload(bestPayload, deviceRecord);

            if (device is not null)
            {
                log?.Report(
                    $"  {device.ModelLabel} | seriale {device.SerialNumber ?? "-"} | " +
                    $"{device.Snapshots.Count} snapshot");
                devices.Add(device);
            }
        }

        var snapshotNames = devices
            .SelectMany(d => d.Snapshots)
            .Select(s => s.RecordName)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        if (snapshotNames.Count > 0)
        {
            var fetchNames = snapshotNames
                .Select(CloudKitRecordNames.PrimaryFetchName)
                .Distinct(StringComparer.Ordinal)
                .ToList();

            log?.Report($"CloudKit: FetchRecords {fetchNames.Count} snapshot (S:)…");
            for (var i = 0; i < fetchNames.Count; i += SnapshotBatchSize)
            {
                var chunk = fetchNames.Skip(i).Take(SnapshotBatchSize).ToList();
                var snapshotPayload = await FetchRecordsAsync(session, MbksyncZone, chunk, catalog, ct);
                log?.Report($"  batch {i / SnapshotBatchSize + 1} → {snapshotPayload.Length:N0} byte ({chunk.Count} record)");
                EnrichSnapshots(devices, snapshotPayload);
            }

            await RefetchIncompleteSnapshotsAsync(session, devices, catalog, log, ct);

            _lastMbksyncZonesPayload = zonesPayload;

            foreach (var device in devices)
            {
                foreach (var snapshot in device.Snapshots)
                {
                    var label = snapshot.ShortUuid;
                    var udid = snapshot.Udid is not null ? $" udid={snapshot.Udid}" : string.Empty;
                    var props = snapshot.BackupPropertiesCiphertext is { Length: > 0 }
                        ? " props=cifrato"
                        : string.Empty;
                    var details = $"{snapshot.DateLabel} | {snapshot.IosLabel} | {snapshot.SizeLabel}";
                    log?.Report($"  snapshot {label}{udid}{props} {details}");
                }
            }
        }

        return devices.Where(d => d.Snapshots.Count > 0).ToList();
    }

    /// <summary>Payload zone/retrieve mbksync dell’ultima <see cref="ListDevicesAsync"/> (per PCS decrypt).</summary>
    public byte[]? LastMbksyncZonesPayload => _lastMbksyncZonesPayload;

    private byte[]? _lastMbksyncZonesPayload;

    /// <summary>
    /// Decrypt PCS di <c>backupProperties</c> su thread pool (non blocca la UI).
    /// </summary>
    public Task<SnapshotBackupPropertiesDecryptor.DecryptSummary> DecryptBackupPropertiesAsync(
        ICloudSession session,
        IEnumerable<BackupDevice> devices,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var snapshots = devices.SelectMany(d => d.Snapshots).ToList();
        var zones = _lastMbksyncZonesPayload;
        return Task.Run(
            () =>
            {
                ct.ThrowIfCancellationRequested();
                var summary = SnapshotBackupPropertiesDecryptor.TryDecryptAll(
                    session, snapshots, zones, log);
                SnapshotBackupPropertiesDecryptor.ApplyHardwareIdentityToDevices(devices);
                var withUdid = devices.Count(d => !string.IsNullOrWhiteSpace(d.HardwareUdid));
                if (withUdid > 0)
                    log?.Report($"  HardwareUdid da Lockdown.UniqueDeviceID → {withUdid} device");
                if (summary.CipherCount > 0)
                    log?.Report($"CloudKit: backupProperties {summary.Message}");
                return summary;
            },
            ct);
    }

    private static BackupDevice BuildDeviceFromPayload(byte[] payload, string deviceRecordName)
    {
        var catalog = CloudKitBackupCatalogParser.ParseDeviceRecord(payload, deviceRecordName);
        var snapshotNames = catalog.SnapshotRecordNames.Count > 0
            ? catalog.SnapshotRecordNames
            : ExtractSnapshotRecordNamesLegacy(payload);

        // DeviceUuid = hash D: (40 hex) — non è l'UDID hardware; CloudKit non lo espone sul record Device.
        var device = new BackupDevice
        {
            DeviceUuid = CloudKitRecordNames.StripDevicePrefix(deviceRecordName),
            MarketingName = catalog.MarketingName,
            ProductType = catalog.ProductType,
            HardwareModel = catalog.HardwareModel,
            SerialNumber = catalog.SerialNumber,
            DisplayName = catalog.DeviceName ?? catalog.MarketingName,
            Snapshots = snapshotNames.Select(name =>
            {
                var canonical = CloudKitRecordNames.CanonicalSnapshotRecordName(name);
                var backupDate = CloudKitBackupCatalogParser.ResolveSnapshotDate(
                    canonical,
                    catalog.OrderedSnapshotRecordNames,
                    catalog.CommittedDatesOrdered);

                return new BackupSnapshot
                {
                    RecordName = canonical,
                    ZoneName = MbksyncZone,
                    BackupUuid = CloudKitRecordNames.StripSnapshotPrefix(name),
                    BackupDate = backupDate,
                };
            }).ToList()
        };

        return device;
    }

    private static List<string> ExtractSnapshotRecordNamesLegacy(byte[] payload)
    {
        var names = new HashSet<string>(StringComparer.Ordinal);
        var regex = new Regex(
            @"&?S:[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        foreach (var s in CollectStrings(payload))
        {
            foreach (Match m in regex.Matches(s))
                names.Add(CloudKitRecordNames.CanonicalSnapshotRecordName(m.Value));
        }

        return names.Take(64).ToList();
    }

    private static void EnrichSnapshots(IEnumerable<BackupDevice> devices, byte[] snapshotPayload)
    {
        var catalogs = CloudKitBackupCatalogParser.ParseSnapshotBatch(snapshotPayload);

        foreach (var device in devices)
        {
            foreach (var name in CloudKitResponseParser.ExtractAssetRecordNames(snapshotPayload))
                device.AssetHints.Add(name);

            foreach (var snapshot in device.Snapshots)
            {
                if (catalogs.TryGetValue(snapshot.RecordName, out var catalog))
                {
                    CloudKitBackupCatalogParser.ApplyToSnapshot(snapshot, catalog);
                    snapshot.CatalogPayload = snapshotPayload;
                }
            }
        }
    }

    private async Task RefetchIncompleteSnapshotsAsync(
        ICloudSession session,
        IReadOnlyList<BackupDevice> devices,
        RestoreSessionState catalog,
        IProgress<string>? log,
        CancellationToken ct)
    {
        foreach (var snapshot in devices.SelectMany(d => d.Snapshots))
        {
            if (!CloudKitBackupCatalogParser.IsMetadataIncomplete(snapshot))
                continue;

            byte[]? bestPayload = null;
            foreach (var candidate in CloudKitRecordNames.RestoreFetchCandidates(snapshot.RecordName))
            {
                var payload = await FetchRecordsAsync(session, MbksyncZone, [candidate], catalog, ct);
                if (bestPayload is null || payload.Length > bestPayload.Length)
                    bestPayload = payload;
                if (payload.Length >= MinFullRecordBytes)
                    break;
            }

            if (bestPayload is not { Length: > 64 })
                continue;

            var catalogs = CloudKitBackupCatalogParser.ParseSnapshotBatch(bestPayload);
            if (catalogs.TryGetValue(snapshot.RecordName, out var catalogEntry))
            {
                CloudKitBackupCatalogParser.ApplyToSnapshot(snapshot, catalogEntry);
                snapshot.CatalogPayload = bestPayload;
                log?.Report($"  refetch {snapshot.ShortUuid} → metadati completati ({bestPayload.Length:N0} byte)");
            }
        }
    }

    private static IEnumerable<string> CollectStrings(byte[]? payload)
    {
        if (payload is not { Length: > 0 })
            yield break;

        foreach (var s in ProtobufStringScanner.ExtractDelimited(payload))
            yield return s;
        foreach (var s in ProtobufStringScanner.ExtractAsciiRuns(payload, 3))
            yield return s;
    }

    public static void ParseCkAppInitProtobuf(ICloudSession session, byte[] body)
    {
        foreach (var text in ProtobufStringScanner.ExtractUtf8Strings(body))
        {
            if (text.StartsWith('_') && text.Length == 33)
                session.CloudKitUserId = text;
            if (text.StartsWith("EAM", StringComparison.Ordinal))
                session.CloudKitAuthToken = text;
            if (text.StartsWith("https://gateway", StringComparison.OrdinalIgnoreCase))
                session.CloudKitGatewayUrl = text;
        }
    }

    private Task<byte[]> FetchRecordsAsync(
        ICloudSession session,
        string zoneName,
        IReadOnlyList<string> recordNames,
        RestoreSessionState catalog,
        CancellationToken ct)
    {
        var body = CloudKitDelimitedRequest.BuildRecordRetrieve(
            session.CloudKitUserId, zoneName, recordNames, catalog.ToRequestContext());
        return _gateway.RecordRetrieveAsync(session, body, ct, catalog);
    }
}

public sealed class MobileBackupService
{
    private const int MbsStubMaxBytes = 64;
    private const int MinFullManifestBytes = 32_768;
    private const int ParallelBurstSize = 2;
    private const int MaxFetchRounds = 2;

    private readonly HttpClient _http;

    public MobileBackupService(HttpClient http) => _http = http;

    public Task<byte[]> GetAccountManifestAsync(
        ICloudSession session,
        CancellationToken ct = default,
        IProgress<string>? log = null) =>
        GetAccountManifestBestAsync(session, ct, log);

    /// <summary>
    ///  2 GET mbs identici in parallelo (stesso Request-UUID); uno può essere stub 13 B, l'altro ~648 KB.
    /// </summary>
    public async Task<byte[]> GetAccountManifestBestAsync(
        ICloudSession session,
        CancellationToken ct = default,
        IProgress<string>? log = null)
    {
        byte[]? best = null;

        for (var round = 0; round < MaxFetchRounds; round++)
        {
            if (round > 0)
                await Task.Delay(200 + round * 200, ct);

            foreach (var host in ResolveMbsHosts(session))
            {
                foreach (var token in ResolveMbsAuthTokens(session))
                {
                    var requestUuid = Guid.NewGuid().ToString();
                    var tasks = new Task<byte[]?>[ParallelBurstSize];
                    for (var i = 0; i < ParallelBurstSize; i++)
                    {
                        tasks[i] = FetchOnceAsync(session, host, token, requestUuid, ct);
                    }

                    var burst = await Task.WhenAll(tasks);
                    foreach (var payload in burst)
                    {
                        if (payload is null)
                            continue;

                        if (IsMbsStub(payload, session.Dsid))
                        {
                            if (round == 0 && log is not null)
                                log.Report($"  mbs stub ({payload.Length} B) da {host}");
                            continue;
                        }

                        if (best is null || payload.Length > best.Length)
                            best = payload;
                    }
                }

                if (best is { Length: > MinFullManifestBytes })
                    break;
            }

            if (best is { Length: > MinFullManifestBytes })
                break;

            if (round > 0)
                log?.Report($"  mbs round {round + 1}: migliore {(best?.Length ?? 0):N0} byte");
        }

        if (best is null or { Length: <= MbsStubMaxBytes })
            log?.Report("  mbs: nessun manifest completo (solo stub dsid)");

        return best ?? [];
    }

    private static IReadOnlyList<string> ResolveMbsHosts(ICloudSession session)
    {
        // 201505 usa p32-mobilebackup dopo bootstrap; partition come fallback.
        var hosts = new List<string> { "https://p32-mobilebackup.icloud.com" };
        var partition = session.Partition?.Trim();
        if (!string.IsNullOrWhiteSpace(partition))
        {
            if (!partition.StartsWith('p'))
                partition = "p" + partition;
            var partitionHost = $"https://{partition}-mobilebackup.icloud.com";
            if (!hosts.Contains(partitionHost, StringComparer.OrdinalIgnoreCase))
                hosts.Add(partitionHost);
        }

        return hosts;
    }

    private async Task<byte[]?> FetchOnceAsync(
        ICloudSession session,
        string hostBase,
        string token,
        string requestUuid,
        CancellationToken ct)
    {
        try
        {
            var url = $"{hostBase}/mbs/{session.Dsid}";
            using var request = new HttpRequestMessage(HttpMethod.Get, url);
            request.Headers.TryAddWithoutValidation("Accept", "application/vnd.com.apple.mbs+protobuf");
            request.Headers.TryAddWithoutValidation("X-Apple-MBS-Protocol-Version", "2.2");
            request.Headers.TryAddWithoutValidation("Accept-Language", "en-US");
            request.Headers.TryAddWithoutValidation("Authorization",
                $"X-MobileMe-AuthToken {AppleHttpExtensions.BasicAuth(session.Dsid, token)}");
            request.Headers.TryAddWithoutValidation("User-Agent", AppleClientInfo.AuthKitAkdUserAgent);
            request.Headers.TryAddWithoutValidation("X-Apple-Request-UUID", requestUuid);
            session.Anisette.TouchClientTimeUtc();
            request.ApplyAuthKitAkdAnisette(session.Anisette);

            using var response = await _http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, ct);
            if (!response.IsSuccessStatusCode)
                return null;

            return await response.Content.ReadAsByteArrayAsync(ct);
        }
        catch
        {
            return null;
        }
    }

    private static bool IsMbsStub(byte[] payload, string dsid)
    {
        if (payload.Length <= MbsStubMaxBytes)
            return true;

        // stub: \n\x0b{dsid} (protobuf field 1 = dsid string only).
        if (!string.IsNullOrWhiteSpace(dsid)
            && payload.Length <= 24
            && payload.AsSpan().IndexOf(Encoding.UTF8.GetBytes(dsid)) >= 0)
        {
            return true;
        }

        return false;
    }

    private static IEnumerable<string> ResolveMbsAuthTokens(ICloudSession session)
    {
        if (IsPeAuthToken(session.MobileMeAuthToken))
            yield return session.MobileMeAuthToken;

        if (IsPeAuthToken(session.CloudKitAuthToken)
            && !string.Equals(session.CloudKitAuthToken, session.MobileMeAuthToken, StringComparison.Ordinal))
        {
            yield return session.CloudKitAuthToken;
        }
    }

    private static bool IsPeAuthToken(string? token) =>
        !string.IsNullOrWhiteSpace(token)
        && (token.StartsWith("EAA", StringComparison.Ordinal)
            || token.StartsWith("EBA", StringComparison.Ordinal)
            || token.StartsWith("EAM", StringComparison.Ordinal));

    public async Task<byte[]> GetAccountManifestFromHostAsync(
        ICloudSession session,
        string hostBase,
        CancellationToken ct = default)
    {
        byte[]? best = null;
        foreach (var token in ResolveMbsAuthTokens(session))
        {
            var payload = await FetchOnceAsync(session, hostBase, token, Guid.NewGuid().ToString(), ct);
            if (payload is not null && (best is null || payload.Length > best.Length))
                best = payload;
        }

        return best ?? [];
    }
}
