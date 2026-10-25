using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Post-Lock  <c>:CN:</c> → <c>N:uuid:checksum=:0</c> batch <c>record/retrieve</c>
/// in <c>_defaultZone</c> (cattura 134619: ~392 poi ~248). Ogni record è un Domain
/// con <c>fileList</c> Asset MMCS + KA/MA refs; estrazione auth / path firmati / fileList.
/// </summary>
public sealed class BackupEnRecordService
{
    /// <summary>req 00249: primo batch ~391–392 EN.</summary>
    public const int FirstBatchSize = UbChunkPreAuthRequestBuilder.MaxEnFramesFirstRound;

    /// <summary>req 00259: batch successivi ~248–252 EN.</summary>
    public const int SubsequentBatchSize = UbChunkPreAuthRequestBuilder.MaxEnFramesPerRound;

    /// <summary>Compat: default = primo batch.</summary>
    public const int DefaultBatchSize = FirstBatchSize;

    private static readonly Regex FlistSuffixRegex = new(
        @"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}):([A-Za-z0-9_\-+/=]{4,80})(?:=:(\d+))?",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex RelativePathRegex = new(
        @"(?:^|[\x00-\x1f])((?:Library|Applications|Media|HomeDomain|AppDomain|AppDomainGroup|AppDomainPlugin|SysContainer|SysSharedContainer|DatabaseDomain|CameraRollDomain|MediaDomain|WirelessDomain|KeychainDomain|ManagedPreferencesDomain|RootDomain)[A-Za-z0-9_.+\-/]*)",
        RegexOptions.Compiled);

    private readonly CloudKitGatewayClient _gateway;

    public BackupEnRecordService(HttpClient http)
        : this(new CloudKitGatewayClient(http))
    {
    }

    public BackupEnRecordService(CloudKitGatewayClient gateway) => _gateway = gateway;

    /// <summary>Costruisce i nomi <c>EN:</c> dal catalogo <c>:CN:</c>.</summary>
    public static IReadOnlyList<string> BuildEnRecordNames(
        IEnumerable<CloudKitManifestChecksumParser.CnEntry> cnEntries)
    {
        return cnEntries
            .Select(CloudKitManifestChecksumParser.ToEnRecordName)
            .Where(static n => n.Length > 8)
            .Distinct(StringComparer.Ordinal)
            .OrderBy(static n => n, StringComparer.Ordinal)
            .ToList();
    }

    public static IReadOnlyList<string> BuildEnRecordNamesFromCatalogNames(
        IEnumerable<string> catalogRecordNames)
    {
        var entries = new List<CloudKitManifestChecksumParser.CnEntry>();
        foreach (var name in catalogRecordNames)
        {
            if (!name.StartsWith(":CN:", StringComparison.OrdinalIgnoreCase))
                continue;
            var parts = name.Split(':', 4, StringSplitOptions.None);
            // ":CN:uuid:checksum" → ["", "CN", uuid, checksum]
            if (parts.Length < 4)
                continue;
            var uuid = parts[2];
            var chk = CloudKitManifestChecksumParser.CleanCnChecksum(parts[3]);
            if (uuid.Length < 32 || string.IsNullOrWhiteSpace(chk))
                continue;
            entries.Add(new CloudKitManifestChecksumParser.CnEntry(uuid.ToUpperInvariant(), chk));
        }

        return BuildEnRecordNames(entries);
    }

    public async Task<EnFetchResult> FetchAsync(
        ICloudSession session,
        IReadOnlyList<string> enRecordNames,
        string outputDirectory,
        RestoreSessionState? restore = null,
        int firstBatchSize = FirstBatchSize,
        int subsequentBatchSize = SubsequentBatchSize,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        byte[]? zonesPayload = null)
    {
        Directory.CreateDirectory(outputDirectory);
        if (enRecordNames.Count == 0)
        {
            log?.Report("  EN: nessun nome da :CN: — skip");
            return new EnFetchResult();
        }

        var first = firstBatchSize > 0 ? firstBatchSize : FirstBatchSize;
        var next = subsequentBatchSize > 0 ? subsequentBatchSize : SubsequentBatchSize;
        var payloads = new List<byte[]>();
        var requested = enRecordNames.ToList();
        var batchCount = 0;

        log?.Report(
            $"CloudKit: N: record/retrieve post-Lock ({requested.Count:N0} record, " +
            $"batch={first}/{next})…");

        var offset = 0;
        while (offset < requested.Count)
        {
            ct.ThrowIfCancellationRequested();
            // Cede il sync-context (UI) prima di build protobuf + HTTP + dump disco.
            await Task.Yield();

            var size = batchCount == 0 ? first : next;
            var batch = requested.Skip(offset).Take(size).ToList();
            batchCount++;
            log?.Report(
                $"  EN: batch {batchCount} → {batch.Count} record " +
                $"({offset + 1}–{offset + batch.Count}/{requested.Count})");

            try
            {
                var body = await Task.Run(
                    () => CloudKitDelimitedRequest.BuildRecordRetrieve(
                        session.CloudKitUserId,
                        "_defaultZone",
                        batch,
                        restore?.ToRequestContext()),
                    ct).ConfigureAwait(false);

                var tag = $"en_batch_{batchCount:D2}_{batch.Count}records";
                await File.WriteAllBytesAsync(
                    Path.Combine(outputDirectory, tag + "_request.bin"), body, ct)
                    .ConfigureAwait(false);
                await File.WriteAllTextAsync(
                    Path.Combine(outputDirectory, tag + "_names.txt"),
                    string.Join('\n', batch),
                    ct).ConfigureAwait(false);

                var payload = await _gateway.RecordRetrieveAsync(session, body, ct, restore)
                    .ConfigureAwait(false);
                payloads.Add(payload);
                await File.WriteAllBytesAsync(
                    Path.Combine(outputDirectory, tag + ".bin"), payload, ct)
                    .ConfigureAwait(false);

                var notFound = CountAscii(payload, "Record not found");
                if (payload.Length < 256)
                {
                    var hint = CloudKitResponseParser.DescribeCompactPayload(payload);
                    log?.Report(
                        $"  EN: batch {batchCount} stub {payload.Length} B" +
                        (hint is null ? "" : $" ({hint})"));
                }
                else if (notFound > 0)
                {
                    log?.Report(
                        $"  EN: batch {batchCount} NOT FOUND {notFound}/{batch.Count} " +
                        $"({payload.Length:N0} byte) — sample {batch[0]}");
                }
                else
                {
                    log?.Report($"  EN: batch {batchCount} OK ({payload.Length:N0} byte)");
                }
            }
            catch (Exception ex)
            {
                log?.Report($"  EN: batch {batchCount} FAIL: {ex.Message}");
            }

            offset += batch.Count;
            if (offset < requested.Count)
                await Task.Delay(400, ct).ConfigureAwait(false);
        }

        // Parse/decrypt Domain: CPU pesante su multi-MB — thread pool, non UI.
        var zonesForParse = zonesPayload ?? TryLoadZonesPayload(outputDirectory);
        var parseResult = await Task.Run(() =>
        {
            var mergedLocal = MergePayloads(payloads);
            var catalogLocal = UbChunkCatalogParser.Parse(mergedLocal);
            var (domainsLocal, pcsSummaryLocal) = DomainPcsFieldDecryptor.ParseDomainsDecrypted(
                session, zonesForParse, payloads, outputDirectory, log: null);
            var fileListsLocal = domainsLocal
                .Select(static d => d.FileList)
                .Where(static f => f is not null)
                .Cast<DomainFileListParser.FileListAsset>()
                .ToList();
            var flistLocal = ParseFlistHints(mergedLocal, catalogLocal);
            if (flistLocal.Count == 0)
                flistLocal = ParseFlistHintsFromCatalogSeeds(catalogLocal);
            return (mergedLocal, catalogLocal, domainsLocal, pcsSummaryLocal, fileListsLocal, flistLocal);
        }, ct).ConfigureAwait(false);

        var catalog = parseResult.catalogLocal;
        var domains = parseResult.domainsLocal;
        var pcsSummary = parseResult.pcsSummaryLocal;
        var fileLists = parseResult.fileListsLocal;
        var flist = parseResult.flistLocal;

        if (pcsSummary.FieldsDecrypted > 0 || pcsSummary.FieldsSeen > 0)
        {
            log?.Report(
                $"  EN PCS Domain: decrypt={pcsSummary.FieldsDecrypted}/{pcsSummary.FieldsSeen}, " +
                $"+fileList={pcsSummary.FileListsFilled}, +newAssets={pcsSummary.NewAssetsFilled}");
        }

        // newAssets tipizzati → anche in AssetRecordNames per join rid→TYPE.
        var newAssetNames = domains
            .SelectMany(static d => d.NewAssetRecordNames)
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (newAssetNames.Count > 0)
        {
            catalog = catalog with
            {
                RecordNames = catalog.RecordNames
                    .Concat(newAssetNames)
                    .Distinct(StringComparer.Ordinal)
                    .ToList()
            };
        }

        var authHeaders = catalog.MmcsAuths.Values
            .Where(static h => h.Split(' ', StringSplitOptions.RemoveEmptyEntries).Length >= 3)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        var notFoundTotal = payloads.Sum(static p => CountAscii(p, "Record not found"));
        var fileListBytes = fileLists.Sum(static f => f.SizeBytes);
        var newAssetRefs = domains.Sum(static d => d.NewAssetRecordNames.Count);
        var deletedAssetRefs = domains.Sum(static d => d.DeletedAssetRecordNames.Count);

        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "en_fetch_summary.json"),
            JsonSerializer.Serialize(new
            {
                requested = requested.Count,
                batches = batchCount,
                firstBatchSize = first,
                subsequentBatchSize = next,
                responseBytes = payloads.Sum(static p => (long)p.Length),
                mmcsAuths = authHeaders.Count,
                signedChunks = catalog.SignedChunks.Count,
                signedPaths = catalog.SignedPaths.Count,
                assetNames = catalog.RecordNames.Count,
                querySeeds = catalog.QuerySeeds.Count,
                domainRecords = domains.Count,
                fileListAssets = fileLists.Count,
                fileListBytes,
                fileListEncoding = domains
                    .Select(static d => d.FileListEncoding)
                    .Where(static e => e is not null)
                    .Distinct()
                    .ToList(),
                cumulativeTotals = new
                {
                    files = domains.Sum(static d => d.CumulativeFileCount),
                    directories = domains.Sum(static d => d.CumulativeDirectoryCount),
                    assets = domains.Sum(static d => d.CumulativeAssetCount),
                    emptyFiles = domains.Sum(static d => d.CumulativeEmptyFileCount),
                    symlinks = domains.Sum(static d => d.CumulativeSymLinkCount)
                },
                newAssetRefs,
                deletedAssetRefs,
                pcsDomain = new
                {
                    pcsSummary.FieldsSeen,
                    pcsSummary.FieldsDecrypted,
                    pcsSummary.FileListsFilled,
                    pcsSummary.NewAssetsFilled,
                    pcsSummary.ZoneKeys,
                    pcsSummary.Message
                },
                flistEntries = flist.Count,
                notFoundTotal,
                nameSample = requested.Take(6),
                seedSample = catalog.QuerySeeds.Take(12),
                pathSample = catalog.SignedPaths.Take(8),
                domainSample = domains.Take(12).Select(static d => new
                {
                    d.DomainName,
                    d.RecordName,
                    d.Version,
                    d.CumulativeFileCount,
                    d.CumulativeAssetCount,
                    encoding = d.FileListEncoding,
                    fileListSize = d.FileList?.SizeBytes,
                    newAssets = d.NewAssetRecordNames.Count,
                    deletedAssets = d.DeletedAssetRecordNames.Count
                }),
                flistSample = flist.Take(12).Select(static e => new
                {
                    e.Domain,
                    e.RelativePath,
                    e.AssetRecordName,
                    e.RecordIdSuffix,
                    e.AssetSize
                })
            }, new JsonSerializerOptions { WriteIndented = true }),
            ct).ConfigureAwait(false);

        await ManifestFromFileListBuilder.WriteDomainMapAsync(outputDirectory, domains, ct)
            .ConfigureAwait(false);

        // Indice rid → TYPE:pref4:rid per Fase 2 (join flist senza riscan payload).
        try
        {
            var indexPath = Path.Combine(outputDirectory, "en_newassets_rid_index.tsv");
            await using var sw = new StreamWriter(indexPath, false, Encoding.UTF8);
            await sw.WriteLineAsync("recordIDSuffix\tfullRecordName\tdomain").ConfigureAwait(false);
            var seenRid = new HashSet<string>(StringComparer.Ordinal);
            foreach (var domain in domains)
            {
                foreach (var name in domain.NewAssetRecordNames)
                {
                    var rid = CloudKitMmcsIds.ToRecordIdSuffix(name);
                    if (rid is null || !seenRid.Add(rid))
                        continue;
                    await sw.WriteLineAsync($"{rid}\t{name}\t{domain.DomainName}")
                        .ConfigureAwait(false);
                }
            }

            log?.Report($"  EN newAssets index → {seenRid.Count:N0} rid in en_newassets_rid_index.tsv");
        }
        catch (Exception ex)
        {
            log?.Report($"  EN newAssets index skip: {ex.Message}");
        }

        log?.Report(
            $"  EN: fatto → domains={domains.Count}, fileList={fileLists.Count} ({fileListBytes:N0} B), " +
            $"enc=[{string.Join(',', domains.Select(static d => d.FileListEncoding).Where(static e => e is not null).Distinct())}], " +
            $"Δnew={newAssetRefs}, Δdel={deletedAssetRefs}, " +
            $"PCS={pcsSummary.FieldsDecrypted}/{pcsSummary.FieldsSeen}, " +
            $"auth={authHeaders.Count}, signed={catalog.SignedChunks.Count}, " +
            $"notFound={notFoundTotal}, seed={catalog.QuerySeeds.Count}");

        return new EnFetchResult
        {
            RequestedNames = requested,
            ResponsePayloads = payloads,
            MmcsAuthHeaders = authHeaders,
            AssetRecordNames = catalog.RecordNames,
            QuerySeeds = catalog.QuerySeeds,
            FlistEntries = flist,
            DomainRecords = domains,
            FileListAssets = fileLists,
            SignedChunks = catalog.SignedChunks,
            SignedPaths = catalog.SignedPaths,
            BatchCount = batchCount,
            TotalResponseBytes = payloads.Sum(static p => (long)p.Length)
        };
    }

    /// <summary>
    /// Costruisce <see cref="BackupAsset"/>: prima i <c>Domain.fileList</c> (MMCS),
    /// poi gli altri auth EN mappati a KA/LA/MA noti.
    /// </summary>
    public static List<BackupAsset> BuildAssetsFromEn(EnFetchResult en)
    {
        var byChecksum = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var name in en.AssetRecordNames.Concat(en.QuerySeeds))
        {
            var hex = MmcsAuthBuilder.TryExtractAssetChecksumHex(name);
            if (hex is null || byChecksum.ContainsKey(hex))
                continue;
            byChecksum[hex] = name;
        }

        foreach (var entry in en.FlistEntries)
        {
            if (string.IsNullOrWhiteSpace(entry.AssetRecordName))
                continue;
            var hex = MmcsAuthBuilder.TryExtractAssetChecksumHex(entry.AssetRecordName);
            if (hex is null || byChecksum.ContainsKey(hex))
                continue;
            byChecksum[hex] = entry.AssetRecordName;
        }

        var flistByRecord = en.FlistEntries
            .Where(static e => !string.IsNullOrWhiteSpace(e.AssetRecordName))
            .GroupBy(static e => e.AssetRecordName!, StringComparer.Ordinal)
            .ToDictionary(static g => g.Key, static g => g.First(), StringComparer.Ordinal);

        var assets = new List<BackupAsset>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var fileListAuths = new HashSet<string>(StringComparer.Ordinal);

        // Domain.fileList = Asset MMCS (stesso authorizeGet/edge di KA/MA).
        // Preferisci DomainRecords (window/PI) rispetto alla sola lista FileListAssets.
        var fileListSources = en.DomainRecords.Count > 0
            ? en.DomainRecords
                .Where(static d => d.FileList is not null)
                .Select(static d => ((DomainFileListParser.DomainRecord?)d, d.FileList!))
            : en.FileListAssets.Select(static fl =>
                ((DomainFileListParser.DomainRecord?)null, fl));

        foreach (var (domain, fl) in fileListSources)
        {
            var recordName = $"FL:{fl.SignatureHex}";
            if (!seen.Add(recordName))
                continue;

            fileListAuths.Add(fl.MmcsAuthHeader);

            string? recordPiHex = null;
            byte[]? recordWindow = domain?.RecordWindow;
            if (recordWindow is { Length: > 0 })
            {
                var der = PcsProtectionZone.TryExtractRecordProtectionInfoDer(recordWindow);
                if (der is null)
                {
                    // Domain PI spesso ~100–150 B (sotto la soglia CloudDocs 200).
                    der = PcsProtectionZone.TryExtractProtectionInfoCandidates(recordWindow)
                        .FirstOrDefault(static c => c.Length is >= 96 and <= 512);
                }

                if (der is { Length: > 0 })
                    recordPiHex = Convert.ToHexString(der);
            }

            // Domain = contexto catalogo; RelativePath arriva solo dopo decode del blob fileList.
            byte[]? assetSignature = null;
            try
            {
                if (fl.SignatureHex.Length == 42)
                    assetSignature = Convert.FromHexString(fl.SignatureHex);
            }
            catch
            {
                // ignore malformed signature hex from Domain.fileList
            }

            assets.Add(new BackupAsset
            {
                RecordName = recordName,
                ZoneName = "_defaultZone",
                Domain = fl.DomainName,
                SizeBytes = fl.SizeBytes > 0 ? fl.SizeBytes : null,
                MmcsAuth = fl.MmcsAuthHeader,
                AssetSignature = assetSignature is { Length: 21 } ? assetSignature : null,
                AssetProtectionInfoHex = fl.ProtectionWrapHex,
                RecordProtectionInfoDerHex = recordPiHex,
                RecordPayload = recordWindow
            });
        }

        var i = 0;
        foreach (var auth in en.MmcsAuthHeaders)
        {
            if (fileListAuths.Contains(auth))
            {
                i++;
                continue;
            }

            var f2 = MmcsAuthBuilder.TryExtractFileChecksumHex(auth) ?? $"en{i}";
            string recordName;
            if (byChecksum.TryGetValue(f2, out var known))
                recordName = known;
            else
                recordName = $"N/MMCS:{f2}";

            if (!seen.Add(recordName))
            {
                i++;
                continue;
            }

            var asset = new BackupAsset
            {
                RecordName = recordName,
                ZoneName = "_defaultZone",
                MmcsAuth = auth
            };

            if (flistByRecord.TryGetValue(recordName, out var hint))
            {
                asset.Domain = hint.Domain;
                asset.RelativePath = hint.RelativePath;
                asset.EncryptionKey = hint.EncryptionKey;
                asset.ProtectionClass = hint.ProtectionClass > 0 ? hint.ProtectionClass : null;
                asset.SizeBytes = hint.AssetSize > 0 ? hint.AssetSize : null;
                asset.EnsureFileId();
            }

            assets.Add(asset);
            i++;
        }

        foreach (var hint in en.FlistEntries)
        {
            if (string.IsNullOrWhiteSpace(hint.AssetRecordName))
                continue;
            if (!seen.Add(hint.AssetRecordName))
                continue;

            var asset = new BackupAsset
            {
                RecordName = hint.AssetRecordName,
                ZoneName = "_defaultZone",
                Domain = hint.Domain,
                RelativePath = hint.RelativePath,
                EncryptionKey = hint.EncryptionKey,
                ProtectionClass = hint.ProtectionClass > 0 ? hint.ProtectionClass : null,
                SizeBytes = hint.AssetSize > 0 ? hint.AssetSize : null
            };
            asset.EnsureFileId();
            assets.Add(asset);
        }

        return assets;
    }

    /// <summary>
    /// Ricostruisce <c>{type}:{pref4}:{uuid}:{token}:{size}</c> solo se <paramref name="preferredType"/>
    /// è già noto (es. da EN). Non usare un default inventato.
    /// </summary>
    public static string? TryBuildAssetRecordName(
        string devicePrefix4,
        string recordIdSuffix,
        string preferredType)
    {
        if (string.IsNullOrWhiteSpace(recordIdSuffix))
            return null;
        if (string.IsNullOrWhiteSpace(preferredType))
            return null;

        var rid = recordIdSuffix.Trim();
        // Già nome completo CloudKit (A:pref4:… o illusione XA:…).
        if (CloudKitMmcsIds.ToPrivilegedBatchWireName(rid) is { } wire)
            return wire;

        // uuid:token=:size  (token può contenere + / =)
        string core;
        string? sizePart = null;
        var sizeSep = rid.LastIndexOf("=:", StringComparison.Ordinal);
        if (sizeSep > 0)
        {
            var sizeText = rid[(sizeSep + 2)..];
            if (sizeText.Length > 0 && sizeText.All(char.IsAsciiDigit))
            {
                sizePart = sizeText;
                core = rid[..(sizeSep + 1)]; // include '=' finale del token
            }
            else
            {
                core = rid;
            }
        }
        else
        {
            core = rid;
        }

        var colon = core.IndexOf(':');
        if (colon <= 0 || colon >= core.Length - 1)
            return null;

        var uuid = core[..colon];
        var token = core[(colon + 1)..];
        if (uuid.Length < 32 || token.Length < 4)
            return null;

        var plus = token.IndexOf('+');
        // Non strippare '+' qui: compare nei capture come parte del token.
        _ = plus;

        var prefix = devicePrefix4.Length >= 4
            ? devicePrefix4[..4].ToLowerInvariant()
            : devicePrefix4.ToLowerInvariant();
        // Wire CloudKit: sempre A: (preferredType KA/MA/… = illusione length-byte).
        _ = preferredType;
        var built = sizePart is null
            ? $"A:{prefix}:{uuid}:{token}"
            : $"A:{prefix}:{uuid}:{token}:{sizePart}";
        // Normalizza token=:size se manca '=' prima di :size (formato rid).
        return CloudKitMmcsIds.ToPrivilegedBatchWireName(built) ?? built;
    }

    private static byte[]? TryLoadZonesPayload(string outputDirectory)
    {
        try
        {
            var path = Path.Combine(outputDirectory, CloudKitAssetService.MbksyncZonesFileName);
            if (File.Exists(path))
                return File.ReadAllBytes(path);

            // A volte zones è nella cartella padre dello snapshot.
            var parent = Directory.GetParent(outputDirectory)?.FullName;
            if (parent is not null)
            {
                path = Path.Combine(parent, CloudKitAssetService.MbksyncZonesFileName);
                if (File.Exists(path))
                    return File.ReadAllBytes(path);
            }
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static int CountAscii(byte[] payload, string ascii)
    {
        if (payload.Length == 0 || string.IsNullOrEmpty(ascii))
            return 0;
        var needle = Encoding.ASCII.GetBytes(ascii);
        var count = 0;
        for (var i = 0; i <= payload.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (payload[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }

            if (match)
                count++;
        }

        return count;
    }

    private static byte[] MergePayloads(IReadOnlyList<byte[]> payloads)
    {
        if (payloads.Count == 0)
            return [];
        if (payloads.Count == 1)
            return payloads[0];

        var total = payloads.Sum(static p => p.Length);
        var merged = new byte[total];
        var offset = 0;
        foreach (var p in payloads)
        {
            Buffer.BlockCopy(p, 0, merged, offset, p.Length);
            offset += p.Length;
        }

        return merged;
    }

    private static List<FlistEntry> ParseFlistHints(byte[] payload, UbChunkCatalog catalog)
    {
        var text = Encoding.Latin1.GetString(payload);
        var entries = new List<FlistEntry>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (Match pathMatch in RelativePathRegex.Matches(text))
        {
            var path = pathMatch.Groups[1].Value.Trim('\0', ' ', '\r', '\n');
            if (path.Length < 4 || !seen.Add("p:" + path))
                continue;

            entries.Add(new FlistEntry { RelativePath = path });
        }

        foreach (var seed in catalog.QuerySeeds.Concat(catalog.RecordNames))
        {
            if (!seen.Add("a:" + seed))
                continue;
            entries.Add(new FlistEntry
            {
                AssetRecordName = seed,
                RecordIdSuffix = StripAssetPrefix(seed)
            });
        }

        return entries;
    }

    private static List<FlistEntry> ParseFlistHintsFromCatalogSeeds(UbChunkCatalog catalog)
    {
        return catalog.QuerySeeds
            .Concat(catalog.RecordNames)
            .Distinct(StringComparer.Ordinal)
            .Select(static s => new FlistEntry
            {
                AssetRecordName = s,
                RecordIdSuffix = StripAssetPrefix(s)
            })
            .ToList();
    }

    private static string? StripAssetPrefix(string recordName)
    {
        var parts = recordName.Split(':', 4);
        if (parts.Length >= 4)
            return $"{parts[2]}:{parts[3]}";
        return recordName;
    }
}
