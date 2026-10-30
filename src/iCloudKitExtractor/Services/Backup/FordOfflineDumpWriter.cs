using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Dump per replay offline Ford: CK <c>BackupAsset</c> (contents), authorizeGet, OBJ edge,
/// candidati ford blob. Cartella <c>{work}/ford_offline/</c>.
/// </summary>
public static class FordOfflineDumpWriter
{
    public const string FolderName = "ford_offline";
    private static readonly object IndexLock = new();
    private static readonly object WrapIndexLock = new();
    private static string? WrapIndexRoot;
    private static Dictionary<string, byte[]>? WrapBySig;
    /// <summary>
    /// Tutti i wrap visti per signature (PrivilegedBatch). Necessario per E0640:
    /// stesso sig → wrap diversi; <see cref="WrapBySig"/> tiene solo l'ultimo.
    /// </summary>
    private static Dictionary<string, List<byte[]>>? WrapCandidatesBySig;
    private static bool WrapIndexFullyBuilt;

    /// <summary>
    /// Dump offline disabilitati di default (perf). Abilita con <c>IKE_FORD_OFFLINE_DUMP=1</c>.
    /// </summary>
    public static bool Enabled { get; set; } =
        string.Equals(
            Environment.GetEnvironmentVariable("IKE_FORD_OFFLINE_DUMP"),
            "1",
            StringComparison.Ordinal);

    public static string ResolveRoot(string workDirectory) =>
        Path.Combine(workDirectory, FolderName);

    /// <summary>
    /// Salva risposta PrivilegedBatch/query e finestre per-record (contents / wrap).
    /// </summary>
    public static async Task DumpCloudKitQueryAsync(
        string workDirectory,
        byte[] payload,
        IReadOnlyList<string>? seeds = null,
        string? tag = null,
        CancellationToken ct = default)
    {
        if (!Enabled)
            return;
        if (string.IsNullOrWhiteSpace(workDirectory) || payload.Length < 32)
            return;

        var root = ResolveRoot(workDirectory);
        var ckDir = Path.Combine(root, "ck");
        Directory.CreateDirectory(ckDir);

        var stamp = tag ?? DateTime.UtcNow.ToString("HHmmssfff", CultureInfo.InvariantCulture);
        var seedHint = seeds is { Count: > 0 }
            ? Sanitize(seeds[0], 48)
            : "multi";
        var rawName = $"query_{seedHint}_{stamp}_{payload.Length}.bin";
        var rawPath = Path.Combine(ckDir, rawName);
        await File.WriteAllBytesAsync(rawPath, payload, ct).ConfigureAwait(false);

        var assets = CloudKitAssetService.ParseAssetsFromPayload(payload);
        IndexWrapsFromWindow(payload);
        foreach (var asset in assets)
            await DumpAssetRecordAsync(workDirectory, asset, payload, rawName, ct)
                .ConfigureAwait(false);

        // Anche seed richiesti senza harvest auth: salva finestra se il nome compare.
        if (seeds is { Count: > 0 })
        {
            foreach (var seed in seeds)
            {
                if (assets.Any(a =>
                        string.Equals(a.RecordName, seed, StringComparison.Ordinal)
                        || a.RecordName.Contains(seed, StringComparison.Ordinal)))
                    continue;

                var parsed = CloudKitAssetService.ParseAssetRecord(payload, seed);
                if (parsed is not null)
                {
                    await DumpAssetRecordAsync(workDirectory, parsed, payload, rawName, ct)
                        .ConfigureAwait(false);
                    continue;
                }

                var window = TryExtractNamedWindow(payload, seed);
                if (window is { Length: > 32 })
                {
                    var safe = Sanitize(seed, 72);
                    await File.WriteAllBytesAsync(
                        Path.Combine(ckDir, $"record_{safe}.bin"), window, ct)
                        .ConfigureAwait(false);
                    await TryDumpContentsSliceAsync(ckDir, safe, window, ct)
                        .ConfigureAwait(false);
                }
            }
        }
    }

    /// <summary>
    /// Pacchetto per un asset: AUTH request/response, OBJ compact edge, wrap40, IKM32, meta.
    /// </summary>
    public static async Task DumpEdgePackageAsync(
        string workDirectory,
        BackupAsset asset,
        byte[]? authorizeGetRequest,
        byte[] authorizeGetResponse,
        string objectId,
        byte[] objectCiphertext,
        CancellationToken ct = default)
    {
        if (!Enabled)
            return;
        if (string.IsNullOrWhiteSpace(workDirectory)
            || authorizeGetResponse.Length == 0
            || objectCiphertext.Length == 0)
            return;

        var root = ResolveRoot(workDirectory);
        var id = ResolveAssetFolderId(asset, objectId);
        var dir = Path.Combine(root, "assets", id);
        Directory.CreateDirectory(dir);

        // Bind wrap = Asset.signature (stesso criterio del live).
        var wrapSrc = BindWrapToSignature(workDirectory, asset);

        byte[] authToStore = authorizeGetResponse;
        var compactToStore = objectCiphertext;
        IReadOnlyList<SignedUrlChunk>? planChunks = null;
        if (asset.AssetSignature is { Length: >= 4 } dumpSig)
        {
            var parts = UbChunkBuilder.ParseAuthorizeGetFiles(authorizeGetResponse);
            // Già lo slice del file (batch live passa part.AuthSlice): non ri-selezionare.
            // Su batch intero: solo signature (refs/raw) — mai fallbackIndex 0 + sizeBytes
            // (collapse di N salt packed → stesso AuthSlice da 4 KiB).
            AuthorizeGetFilePart? part = parts.Count == 0
                ? null
                : parts.Count == 1
                    ? parts[0]
                    : UbChunkBuilder.SelectFilePartAligned(
                        parts,
                        authorizeGetResponse,
                        dumpSig,
                        fallbackIndex: -1);
            if (part is { AuthSlice.Length: > 0 })
            {
                if (part.AuthSlice.Length != authorizeGetResponse.Length)
                {
                    await File.WriteAllBytesAsync(
                        Path.Combine(dir, "authorizeGet.batch.bin"),
                        authorizeGetResponse,
                        ct).ConfigureAwait(false);
                }

                authToStore = part.AuthSlice;
                planChunks = part.Chunks;
                compactToStore = AlignCompactToFordOrder(
                    objectCiphertext, authorizeGetResponse, part) ?? objectCiphertext;
            }
        }

        if (authorizeGetRequest is { Length: > 0 })
        {
            await File.WriteAllBytesAsync(
                Path.Combine(dir, "authorizeGet_request.bin"),
                authorizeGetRequest,
                ct).ConfigureAwait(false);
        }

        await File.WriteAllBytesAsync(
            Path.Combine(dir, "authorizeGet.bin"),
            authToStore,
            ct).ConfigureAwait(false);

        await File.WriteAllBytesAsync(
            Path.Combine(dir, "obj_ciphertext.bin"),
            compactToStore,
            ct).ConfigureAwait(false);

        if (asset.RecordPayload is { Length: > 32 } ck)
        {
            await File.WriteAllBytesAsync(
                Path.Combine(dir, "ck_record_window.bin"), ck, ct).ConfigureAwait(false);
            await TryDumpContentsSliceAsync(dir, "ck", ck, ct).ConfigureAwait(false);
        }

        // wrap40 + IKM32 (CKFile+0x160) accanto all'obj.
        byte[]? wrapBytes = null;
        if (!string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
        {
            try
            {
                wrapBytes = Convert.FromHexString(asset.AssetProtectionInfoHex);
            }
            catch
            {
                wrapBytes = null;
            }
        }

        if (wrapBytes is { Length: 24 or 40 })
        {
            await File.WriteAllBytesAsync(
                Path.Combine(dir, $"wrap{wrapBytes.Length}.bin"), wrapBytes, ct)
                .ConfigureAwait(false);
            await File.WriteAllTextAsync(
                Path.Combine(dir, "protectionInfo.wrap.hex"),
                Convert.ToHexString(wrapBytes),
                ct).ConfigureAwait(false);
        }

        if (asset.AssetUnwrappedKey is not { Length: 16 or 32 }
            && wrapBytes is { Length: 24 or 40 })
        {
            var fromDisk = TryUnwrapWithSavedMasters(workDirectory, Convert.ToHexString(wrapBytes));
            if (fromDisk is { Length: 16 or 32 })
            {
                asset.AssetUnwrappedKey = fromDisk;
                asset.AssetUnwrappedKeyWrapHex = Convert.ToHexString(wrapBytes);
            }
        }

        if (asset.AssetUnwrappedKey is { Length: 16 or 32 } uk)
        {
            await File.WriteAllBytesAsync(
                Path.Combine(dir, "unwrapped_key.bin"), uk, ct).ConfigureAwait(false);
            await File.WriteAllTextAsync(
                Path.Combine(dir, "unwrapped_key.hex"),
                Convert.ToHexString(uk),
                ct).ConfigureAwait(false);
        }

        var fordDir = Path.Combine(dir, "ford_candidates");
        var fordCount = DumpFordCandidates(authToStore, fordDir);

        if (planChunks is { Count: > 0 })
        {
            var plan = UbChunkBuilder.BuildDecryptPlan(authToStore);
            var edgePlan = JsonSerializer.Serialize(new
            {
                wrapSource = wrapSrc,
                objectId,
                ranges = planChunks.Select(c => new
                {
                    start = c.ByteRange?.Start,
                    end = c.ByteRange?.End,
                    objectId = c.EdgeHeaders?.ObjectId,
                }),
                refs = plan.References.Select(static r => $"{r.ContainerIndex}:{r.ChunkIndex}"),
                containers = plan.Containers.Select(static c => c.Count),
            }, new JsonSerializerOptions { WriteIndented = true });
            await File.WriteAllTextAsync(
                Path.Combine(dir, "edge_plan.json"), edgePlan, ct).ConfigureAwait(false);
        }

        var meta = new Dictionary<string, object?>
        {
            ["recordName"] = asset.RecordName,
            ["domain"] = asset.Domain,
            ["relativePath"] = asset.RelativePath,
            ["objectId"] = objectId,
            ["objBytes"] = compactToStore.Length,
            ["authBytes"] = authToStore.Length,
            ["sizeBytes"] = asset.SizeBytes,
            ["protectionClass"] = asset.ProtectionClass,
            ["encryptionKeyLen"] = asset.EncryptionKey?.Length ?? 0,
            ["assetSignatureHex"] = asset.AssetSignature is { Length: > 0 } s
                ? Convert.ToHexString(s)
                : null,
            ["mmcsAuth"] = asset.MmcsAuth,
            ["assetProtectionInfoHex"] = asset.AssetProtectionInfoHex,
            ["assetUnwrappedKeyHex"] = asset.AssetUnwrappedKey is { Length: > 0 } ukHex
                ? Convert.ToHexString(ukHex)
                : null,
            ["extension"] = asset.Extension,
            ["fordCandidateCount"] = fordCount,
            ["hasCkWindow"] = asset.RecordPayload is { Length: > 32 },
            ["ikmRole"] = "CKFile+0x160 / Ford HKDF PCSMMCS2",
            ["wrapSource"] = wrapSrc,
            ["authSliceBytes"] = authToStore.Length,
            ["compactBytes"] = compactToStore.Length,
        };
        await File.WriteAllTextAsync(
            Path.Combine(dir, "meta.json"),
            JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }),
            ct).ConfigureAwait(false);

        AppendIndex(workDirectory, new Dictionary<string, object?>
        {
            ["kind"] = "edge",
            ["id"] = id,
            ["recordName"] = asset.RecordName,
            ["objectId"] = objectId,
            ["objBytes"] = objectCiphertext.Length,
            ["path"] = asset.RelativePath,
            ["domain"] = asset.Domain,
            ["assetDir"] = Path.Combine(FolderName, "assets", id).Replace('\\', '/'),
            ["fordCandidates"] = fordCount,
            ["wrapHex"] = asset.AssetProtectionInfoHex,
            ["unwrappedKeyHex"] = asset.AssetUnwrappedKey is { Length: > 0 } k
                ? Convert.ToHexString(k)
                : null,
            ["assetSignatureHex"] = asset.AssetSignature is { Length: > 0 } sig
                ? Convert.ToHexString(sig)
                : null,
            ["utc"] = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)
        });
    }

    /// <summary>
    /// Unwrap wrap24/40 con i master già salvati in <c>mbksync_zone_masters/master_*.bin</c>.
    /// </summary>
    public static byte[]? TryUnwrapWithSavedMasters(string workDirectory, string? wrapHex)
    {
        if (string.IsNullOrWhiteSpace(wrapHex))
            return null;

        byte[] wrap;
        try
        {
            wrap = Convert.FromHexString(wrapHex);
        }
        catch
        {
            return null;
        }

        if (wrap.Length is not (24 or 40))
            return null;

        foreach (var dir in EnumerateMasterDirectories(workDirectory))
        {
            foreach (var file in Directory.EnumerateFiles(dir, "master_*.bin"))
            {
                try
                {
                    var master = File.ReadAllBytes(file);
                    if (master.Length < 16)
                        continue;
                    var plain = PcsProtectionZone.TryUnwrapWrappingKey(master, wrap);
                    if (plain is { Length: 16 or 32 })
                        return plain;
                }
                catch
                {
                    // try next master
                }
            }
        }

        return null;
    }

    private static IEnumerable<string> EnumerateMasterDirectories(string workDirectory)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in new[]
                 {
                     Path.Combine(workDirectory, CloudKitAssetService.ZoneMastersDirectoryName),
                     Path.Combine(ResolveRoot(workDirectory), CloudKitAssetService.ZoneMastersDirectoryName),
                 })
        {
            if (Directory.Exists(dir) && seen.Add(dir))
                yield return dir;
        }
    }

    /// <summary>
    /// Stesso bind del live: wrap = <c>Asset.protectionInfo</c> del messaggio
    /// con <c>Asset.signature</c> uguale. Mai fidarsi di un wrap prebound senza match.
    /// </summary>
    /// <summary>
    /// FL / signature lead <c>0x01</c> + wrap24 = MMCS KEK per Pipe C type02.
    /// Non va scartato come wrap Ford “alien” (owned-match fallisce spesso su RP tronca).
    /// </summary>
    public static bool ShouldKeepFlMmcsPreboundWrap(BackupAsset asset, out string reason)
    {
        reason = "";
        if (string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
            return false;

        int wrapLen;
        try
        {
            wrapLen = asset.AssetProtectionInfoHex.Length / 2;
        }
        catch
        {
            return false;
        }

        if (wrapLen != 24)
            return false;

        var name = asset.RecordName ?? "";
        var path = asset.RelativePath ?? "";
        if (name.StartsWith("FL:", StringComparison.OrdinalIgnoreCase)
            || path.StartsWith("FL:", StringComparison.OrdinalIgnoreCase))
        {
            reason = "FL-prefix+wrap24";
            return true;
        }

        if (asset.AssetSignature is { Length: > 0 } sig && sig[0] == 0x01)
        {
            reason = "sigLead01+wrap24";
            return true;
        }

        return false;
    }

    public static string BindWrapToSignature(string workDirectory, BackupAsset asset)
    {
        if (asset.AssetSignature is not { Length: >= 4 } sig)
            return string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex) ? "missing" : "no-signature";

        byte[]? matched = null;
        var source = "missing";

        // FillFordIkmFromContents: map["contents"] wrap PRIMA, poi f2/f17, poi CK.
        if (asset.RecordPayload is { Length: > 32 } rp)
        {
            IndexWrapsFromWindow(rp);
            matched = CloudKitAssetProto.TryResolveOwnedWrap(rp, sig, out source);
            if (matched is { Length: 24 or 40 }
                && source.StartsWith("map-contents", StringComparison.Ordinal))
            {
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-CKFILE-CONTENTS",
                        ["runId"] = "map-contents-first-v2",
                        ["location"] = "FordOfflineDumpWriter.BindWrapToSignature",
                        ["message"] = "bound_map_contents_wrap",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["sig8"] = Convert.ToHexString(sig.AsSpan(0, Math.Min(8, sig.Length))),
                            ["sigLead"] = sig[0],
                            ["wrapLen"] = matched.Length,
                            ["source"] = source,
                            ["payloadLen"] = rp.Length,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
            }
        }

        // CK: solo TryResolveOwnedWrap sui dump (non WrapBySig globale).
        // RecordPayload spesso è finestra incompleta → NON vetoare un wrap ck-owned.
        if (matched is null && !string.IsNullOrWhiteSpace(workDirectory))
        {
            var fromCk = TryFindOwnedWrapInCk(workDirectory, sig, out var ckSrc);
            if (fromCk is { Length: 24 or 40 })
            {
                matched = fromCk;
                source = ckSrc;
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-WEAK-RP",
                        ["runId"] = "ck-owned-noveto-v1",
                        ["location"] = "FordOfflineDumpWriter.BindWrapToSignature",
                        ["message"] = "accepted_ck_owned_wrap",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["sig8"] = Convert.ToHexString(sig.AsSpan(0, Math.Min(8, sig.Length))),
                            ["ckWrapLen"] = fromCk.Length,
                            ["ckSrc"] = ckSrc,
                            ["payloadLen"] = asset.RecordPayload?.Length ?? 0,
                            ["payloadOwnedMiss"] = asset.RecordPayload is { Length: > 32 } rpMiss
                                && CloudKitAssetProto.TryResolveOwnedWrap(rpMiss, sig, out _) is null,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
            }
            else
            {
                // Diagnostica: WrapBySig avrebbe dato un alieno / digest hit non owned.
                var loose = TryFindWrapBySignature(workDirectory, sig);
                if (loose is { Length: 24 or 40 })
                {
                    // #region agent log
                    try
                    {
                        var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "03cce7",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["hypothesisId"] = "H-ALIEN-DIGEST",
                            ["runId"] = "ck-owned-noveto-v1",
                            ["location"] = "FordOfflineDumpWriter.BindWrapToSignature",
                            ["message"] = "rejected_wrapbysig_not_ck_owned",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["path"] = asset.RelativePath ?? asset.RecordName,
                                ["sig8"] = Convert.ToHexString(sig.AsSpan(0, Math.Min(8, sig.Length))),
                                ["looseWrapLen"] = loose.Length,
                            },
                        });
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                            line + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion
                }
            }
        }

        if (matched is not { Length: 24 or 40 })
        {
            // Multi-asset: wrap prebound alieno (AuthKit 2 asset / 1 wrap su sibling non-ref)
            // → IKM sbagliato → fordOpen=0.  niente wrap se non owned.
            // Eccezione FL / sig 0x01 + wrap24: MMCS KEK per Pipe C type02 — non clearare.
            if (!string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
            {
                if (ShouldKeepFlMmcsPreboundWrap(asset, out var keepWhy))
                {
                    // #region agent log
                    try
                    {
                        var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "b3df71",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["hypothesisId"] = "H-FL-KEK",
                            ["runId"] = "fl-keep-wrap24-v1",
                            ["location"] = "FordOfflineDumpWriter.BindWrapToSignature",
                            ["message"] = "keep_prebound_fl_mmcs_wrap24",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["path"] = asset.RelativePath ?? asset.RecordName,
                                ["sig8"] = Convert.ToHexString(sig.AsSpan(0, Math.Min(8, sig.Length))),
                                ["sigLead"] = sig[0],
                                ["wrapLen"] = asset.AssetProtectionInfoHex!.Length / 2,
                                ["why"] = keepWhy,
                                ["payloadLen"] = asset.RecordPayload?.Length ?? 0,
                            },
                        });
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                            line + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion
                    return "keep-prebound-fl-mmcs";
                }

                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-WRAP-CLEAR",
                        ["runId"] = "ck-owned-noveto-v1",
                        ["location"] = "FordOfflineDumpWriter.BindWrapToSignature",
                        ["message"] = "cleared_alien_prebound_wrap",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["sig8"] = Convert.ToHexString(sig.AsSpan(0, Math.Min(8, sig.Length))),
                            ["hadWrapLen"] = asset.AssetProtectionInfoHex!.Length / 2,
                            ["payloadLen"] = asset.RecordPayload?.Length ?? 0,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                asset.AssetProtectionInfoHex = null;
                asset.AssetUnwrappedKey = null;
                asset.AssetUnwrappedKeyWrapHex = null;
                return "cleared-prebound";
            }

            return "missing";
        }

        // matched è owned su RP oppure su CK file — non richiedere anche ownership su RP debole.

        var hex = Convert.ToHexString(matched);
        if (!string.Equals(asset.AssetProtectionInfoHex, hex, StringComparison.OrdinalIgnoreCase))
        {
            asset.AssetProtectionInfoHex = hex;
            asset.AssetUnwrappedKey = null;
            asset.AssetUnwrappedKeyWrapHex = null;
        }

        return source;
    }

    public static byte[]? TryFindWrapBySignature(string workDirectory, ReadOnlySpan<byte> signature)
    {
        if (signature.Length < 4)
            return null;

        var hex = Convert.ToHexString(signature);
        var digestHex = signature.Length == 21
            ? Convert.ToHexString(signature[1..])
            : null;

        // Memoria (PrivilegedBatch già harvestati in questa sessione) prima del rebuild disco.
        lock (WrapIndexLock)
        {
            if (WrapBySig is not null)
            {
                if (WrapBySig.TryGetValue(hex, out var mem))
                    return mem;
                if (digestHex is not null && WrapBySig.TryGetValue(digestHex, out mem))
                    return mem;
            }
        }

        EnsureWrapIndex(workDirectory);
        lock (WrapIndexLock)
        {
            if (WrapBySig is null)
                return null;
            if (WrapBySig.TryGetValue(hex, out var wrap))
                return wrap;
            if (digestHex is not null && WrapBySig.TryGetValue(digestHex, out wrap))
                return wrap;
            if (signature.Length > 20
                && WrapBySig.TryGetValue(Convert.ToHexString(signature[..20]), out wrap))
                return wrap;
        }

        // Indice stale (build senza lead 0x01, o ck dump arrivati dopo FullyBuilt):
        // rescans mirato + rebuild forzato.
        var scanned = TryScanWrapInCkContents(workDirectory, signature);
        if (scanned is { Length: 24 or 40 })
        {
            lock (WrapIndexLock)
            {
                WrapBySig ??= new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                WrapBySig[hex] = scanned;
                if (digestHex is not null)
                    WrapBySig[digestHex] = scanned;
            }

            return scanned;
        }

        lock (WrapIndexLock)
        {
            WrapIndexFullyBuilt = false;
        }

        EnsureWrapIndex(workDirectory);
        lock (WrapIndexLock)
        {
            if (WrapBySig is null)
                return null;
            if (WrapBySig.TryGetValue(hex, out var wrap))
                return wrap;
            if (digestHex is not null && WrapBySig.TryGetValue(digestHex, out wrap))
                return wrap;
        }

        return null;
    }

    /// <summary>
    /// Cerca wrap-owned (f2+f15 / f17) nei dump CK — non usa WrapBySig (digest/alien).
    /// </summary>
    public static byte[]? TryFindOwnedWrapInCk(
        string workDirectory,
        ReadOnlySpan<byte> signature,
        out string source)
    {
        source = "missing";
        if (signature.Length < 4 || string.IsNullOrWhiteSpace(workDirectory))
            return null;

        var needle = signature.ToArray();
        foreach (var file in EnumerateWrapScanFiles(workDirectory))
        {
            try
            {
                var len = new FileInfo(file).Length;
                if (len is <= 32 or > 2_000_000)
                    continue;
                var data = File.ReadAllBytes(file);
                if (data.AsSpan().IndexOf(needle) < 0
                    && !(signature.Length == 21
                         && data.AsSpan().IndexOf(signature[1..]) >= 0))
                    continue;

                var wrap = CloudKitAssetProto.TryResolveOwnedWrap(data, signature, out var src);
                if (wrap is not { Length: 24 or 40 })
                    continue;

                source = "ck-owned/" + src + ":" + Path.GetFileName(file);
                lock (WrapIndexLock)
                {
                    WrapBySig ??= new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
                    var hex = Convert.ToHexString(signature);
                    WrapBySig[hex] = wrap;
                    if (signature.Length == 21)
                        WrapBySig[Convert.ToHexString(signature[1..])] = wrap;
                }

                return wrap;
            }
            catch
            {
                // best-effort
            }
        }

        return null;
    }

    /// <summary>
    /// Cerca wrap nei dump CK e nelle risposte PrivilegedBatch già su disco (kalama).
    /// </summary>
    private static byte[]? TryScanWrapInCkContents(string workDirectory, ReadOnlySpan<byte> signature)
    {
        // Preferisci ownership; fallback legacy solo per indice/compat.
        var owned = TryFindOwnedWrapInCk(workDirectory, signature, out _);
        if (owned is { Length: 24 or 40 })
            return owned;

        if (signature.Length < 4)
            return null;

        var needle = signature.ToArray();
        foreach (var file in EnumerateWrapScanFiles(workDirectory))
        {
            try
            {
                var len = new FileInfo(file).Length;
                if (len is <= 32 or > 2_000_000)
                    continue;
                var data = File.ReadAllBytes(file);
                if (data.AsSpan().IndexOf(needle) < 0
                    && !(signature.Length == 21
                         && data.AsSpan().IndexOf(signature[1..]) >= 0))
                    continue;
                var wrap = CloudKitAssetProto.TryGetWrapForSignature(data, signature);
                if (wrap is { Length: 24 or 40 })
                    return wrap;
            }
            catch
            {
                // best-effort
            }
        }

        return null;
    }

    private static IEnumerable<string> EnumerateWrapScanFiles(string workDirectory)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ckDir = Path.Combine(ResolveRoot(workDirectory), "ck");
        if (Directory.Exists(ckDir))
        {
            foreach (var file in Directory.EnumerateFiles(ckDir, "*.contents.bin"))
            {
                if (seen.Add(file))
                    yield return file;
            }

            foreach (var file in Directory.EnumerateFiles(ckDir, "query_*.bin"))
            {
                if (seen.Add(file))
                    yield return file;
            }
        }

        var kalama = Path.Combine(workDirectory, "kalama_records");
        if (Directory.Exists(kalama))
        {
            foreach (var file in Directory.EnumerateFiles(kalama, "query_*.bin"))
            {
                if (seen.Add(file))
                    yield return file;
            }
        }
    }

    /// <summary>
    /// Indicizza wrap40/24 per Asset.signature dal payload CK (batch PrivilegedBatch).
    /// Independente da <see cref="Enabled"/> — serve al bind live.
    /// </summary>
    public static void AbsorbWrapsFromPayload(ReadOnlySpan<byte> payload) =>
        IndexWrapsFromWindow(payload);

    /// <summary>
    /// Tutti i wrap assorbiti in sessione per questa signature (dedupe).
    /// Usato da IKM rebind senza richiedere <c>kalama_records/</c> su disco.
    /// </summary>
    public static IReadOnlyList<byte[]> GetWrapCandidatesForSignature(ReadOnlySpan<byte> signature)
    {
        if (signature.Length < 4)
            return [];

        var hex = Convert.ToHexString(signature);
        var digestHex = signature.Length == 21
            ? Convert.ToHexString(signature[1..])
            : null;

        lock (WrapIndexLock)
        {
            if (WrapCandidatesBySig is null)
                return [];

            var map = WrapCandidatesBySig;
            var acc = new List<byte[]>();
            void Take(string key)
            {
                if (!map.TryGetValue(key, out var list))
                    return;
                foreach (var w in list)
                {
                    if (w.Length is not (24 or 40))
                        continue;
                    if (acc.Any(a => a.AsSpan().SequenceEqual(w)))
                        continue;
                    acc.Add(w);
                }
            }

            Take(hex);
            if (digestHex is not null)
                Take(digestHex);
            if (signature.Length > 20)
                Take(Convert.ToHexString(signature[..20]));
            return acc;
        }
    }

    private static void IndexWrapsFromWindow(ReadOnlySpan<byte> window)
    {
        if (window.IsEmpty)
            return;
        lock (WrapIndexLock)
        {
            WrapBySig ??= new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            WrapCandidatesBySig ??= new Dictionary<string, List<byte[]>>(StringComparer.OrdinalIgnoreCase);
            foreach (var parsed in CloudKitAssetProto.EnumerateAssets(window))
            {
                if (parsed.Signature is not { Length: >= 4 })
                    continue;
                if (parsed.ProtectionWrap is not { Length: 24 or 40 } wrap)
                    continue;
                var hex = Convert.ToHexString(parsed.Signature);
                WrapBySig[hex] = wrap;
                AddWrapCandidateLocked(hex, wrap);
                // Anche digest 20B (lead-agnostic) per flist 0x01 vs contents 0x04.
                if (parsed.Signature.Length == 21)
                {
                    var dig = Convert.ToHexString(parsed.Signature.AsSpan(1));
                    WrapBySig[dig] = wrap;
                    AddWrapCandidateLocked(dig, wrap);
                }
            }
        }
    }

    private static void AddWrapCandidateLocked(string hex, byte[] wrap)
    {
        WrapCandidatesBySig ??= new Dictionary<string, List<byte[]>>(StringComparer.OrdinalIgnoreCase);
        if (!WrapCandidatesBySig.TryGetValue(hex, out var list))
        {
            list = [];
            WrapCandidatesBySig[hex] = list;
        }

        foreach (var existing in list)
        {
            if (existing.AsSpan().SequenceEqual(wrap))
                return;
        }

        list.Add(wrap);
    }

    /// <summary>
    /// Indicizza wrap da kalama/ck su disco (anche senza Dump) prima del rebind live.
    /// </summary>
    public static void EnsureWrapIndexBuilt(string workDirectory) =>
        EnsureWrapIndex(workDirectory);

    private static void EnsureWrapIndex(string workDirectory)
    {
        var indexKey = Path.GetFullPath(workDirectory);
        lock (WrapIndexLock)
        {
            if (WrapIndexFullyBuilt
                && string.Equals(WrapIndexRoot, indexKey, StringComparison.OrdinalIgnoreCase))
                return;

            WrapBySig ??= new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
            WrapCandidatesBySig ??= new Dictionary<string, List<byte[]>>(StringComparer.OrdinalIgnoreCase);
            WrapIndexRoot = indexKey;

            foreach (var file in EnumerateWrapScanFiles(workDirectory))
            {
                try
                {
                    var len = new FileInfo(file).Length;
                    if (len is <= 32 or > 2_000_000)
                        continue;
                    foreach (var parsed in CloudKitAssetProto.EnumerateAssets(File.ReadAllBytes(file)))
                    {
                        if (parsed.Signature is not { Length: >= 4 })
                            continue;
                        if (parsed.ProtectionWrap is not { Length: 24 or 40 } wrap)
                            continue;
                        var hex = Convert.ToHexString(parsed.Signature);
                        WrapBySig[hex] = wrap;
                        AddWrapCandidateLocked(hex, wrap);
                        if (parsed.Signature.Length == 21)
                        {
                            var dig = Convert.ToHexString(parsed.Signature.AsSpan(1));
                            WrapBySig[dig] = wrap;
                            AddWrapCandidateLocked(dig, wrap);
                        }
                    }
                }
                catch
                {
                    // dump best-effort
                }
            }

            WrapIndexFullyBuilt = true;
        }
    }

    private static byte[]? AlignCompactToFordOrder(
        byte[] compact,
        byte[] authorizeGetBody,
        AuthorizeGetFilePart part)
    {
        var wanted = part.Chunks
            .Where(static c => c.ByteRange is not null)
            .ToList();
        var wantSum = wanted.Sum(static c => c.ByteRange!.Value.End - c.ByteRange.Value.Start + 1);
        if (wantSum <= 0)
            return null;

        if (compact.Length == wantSum)
        {
            var asWanted = RebuildCompact(compact, wanted, wanted);
            if (asWanted is not null)
                return asWanted;
        }

        var stored = UbChunkBuilder.ParseAuthorizeGetResponse(authorizeGetBody)
            .Where(static c => c.ByteRange is not null)
            .ToList();
        if (stored.Count == 0 || stored.Sum(static c => c.ByteRange!.Value.End - c.ByteRange.Value.Start + 1) != compact.Length)
            return compact.Length == wantSum ? compact : null;

        return RebuildCompact(compact, stored, wanted) ?? (compact.Length == wantSum ? compact : null);
    }

    private static byte[]? RebuildCompact(
        byte[] compact,
        IReadOnlyList<SignedUrlChunk> stored,
        IReadOnlyList<SignedUrlChunk> wanted)
    {
        var off = 0L;
        var slices = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        foreach (var c in stored)
        {
            var len = c.ByteRange!.Value.End - c.ByteRange.Value.Start + 1;
            if (off + len > compact.Length)
                return null;
            var key = $"{c.ByteRange.Value.Start}-{c.ByteRange.Value.End}:{c.EdgeHeaders?.ObjectId}";
            slices[key] = compact.AsSpan((int)off, (int)len).ToArray();
            off += len;
        }

        if (off != compact.Length)
            return null;

        using var ms = new MemoryStream();
        foreach (var c in wanted)
        {
            var key = $"{c.ByteRange!.Value.Start}-{c.ByteRange.Value.End}:{c.EdgeHeaders?.ObjectId}";
            if (!slices.TryGetValue(key, out var s))
                return null;
            ms.Write(s);
        }

        return ms.ToArray();
    }

    /// <summary>
    /// Completa wrap/IKM per il dump: wrap già bindata resta; altrimenti payload, poi CK dump.
    /// </summary>
    private static string BindWrapForDump(string workDirectory, BackupAsset asset)
        => BindWrapToSignature(workDirectory, asset);

    private static byte[]? TryFindWrapInCkDump(string workDirectory, BackupAsset asset)
    {
        if (asset.AssetSignature is not { Length: >= 4 } sig)
            return null;

        var ckDir = Path.Combine(ResolveRoot(workDirectory), "ck");
        if (!Directory.Exists(ckDir))
            return null;

        var hint = Sanitize(asset.RecordName, 72);
        var preferred = new List<string>();
        var rest = new List<string>();
        foreach (var file in Directory.EnumerateFiles(ckDir, "*.contents.bin"))
        {
            if (!string.IsNullOrEmpty(hint)
                && Path.GetFileName(file).Contains(hint, StringComparison.OrdinalIgnoreCase))
                preferred.Add(file);
            else
                rest.Add(file);
        }

        foreach (var file in preferred.Concat(rest))
        {
            try
            {
                var wrap = CloudKitAssetProto.TryGetWrapForSignature(
                    File.ReadAllBytes(file), sig);
                if (wrap is { Length: 24 or 40 })
                    return wrap;
            }
            catch
            {
                // dump best-effort
            }
        }

        return null;
    }

    private static void EnsureWrapOnAsset(BackupAsset asset)
    {
        if (asset.RecordPayload is not { Length: > 32 } window)
            return;

        byte[]? wrap = null;
        if (asset.AssetSignature is { Length: >= 4 } sig)
        {
            //  stesso messaggio Asset (f2 signature + f15 wrap).
            wrap = CloudKitAssetProto.TryGetWrapForSignature(window, sig);
        }
        else
        {
            var parsed = CloudKitAssetProto.EnumerateAssets(window);
            if (parsed.Count == 1)
            {
                asset.AssetSignature ??= parsed[0].Signature;
                wrap = parsed[0].ProtectionWrap;
            }
        }

        if (wrap is null
            && asset.AssetSignature is not { Length: >= 4 }
            && string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
            wrap = MmcsAssetProtection.TryExtract(window);

        if (wrap is { Length: 24 or 40 })
        {
            var hex = Convert.ToHexString(wrap);
            if (!string.Equals(asset.AssetProtectionInfoHex, hex, StringComparison.OrdinalIgnoreCase))
            {
                asset.AssetProtectionInfoHex = hex;
                asset.AssetUnwrappedKey = null;
                asset.AssetUnwrappedKeyWrapHex = null;
            }
        }
    }


    private static async Task DumpAssetRecordAsync(
        string workDirectory,
        BackupAsset asset,
        byte[] fullPayload,
        string rawQueryFile,
        CancellationToken ct)
    {
        var ckDir = Path.Combine(ResolveRoot(workDirectory), "ck");
        Directory.CreateDirectory(ckDir);
        var safe = Sanitize(asset.RecordName, 72);
        var window = asset.RecordPayload is { Length: > 32 }
            ? asset.RecordPayload
            : TryExtractNamedWindow(fullPayload, asset.RecordName) ?? fullPayload;

        await File.WriteAllBytesAsync(
            Path.Combine(ckDir, $"record_{safe}.bin"), window, ct).ConfigureAwait(false);
        await TryDumpContentsSliceAsync(ckDir, safe, window, ct).ConfigureAwait(false);

        if (!string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
        {
            await File.WriteAllTextAsync(
                Path.Combine(ckDir, $"record_{safe}.wrap.hex"),
                asset.AssetProtectionInfoHex,
                ct).ConfigureAwait(false);
        }
        else
        {
            EnsureWrapOnAsset(asset);
            if (!string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
            {
                await File.WriteAllTextAsync(
                    Path.Combine(ckDir, $"record_{safe}.wrap.hex"),
                    asset.AssetProtectionInfoHex,
                    ct).ConfigureAwait(false);
            }
        }

        if (asset.AssetUnwrappedKey is not { Length: 16 or 32 }
            && !string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
        {
            var fromDisk = TryUnwrapWithSavedMasters(workDirectory, asset.AssetProtectionInfoHex);
            if (fromDisk is { Length: 16 or 32 })
            {
                asset.AssetUnwrappedKey = fromDisk;
                asset.AssetUnwrappedKeyWrapHex = asset.AssetProtectionInfoHex;
            }
        }

        if (asset.AssetUnwrappedKey is { Length: > 0 } uk)
        {
            await File.WriteAllBytesAsync(
                Path.Combine(ckDir, $"record_{safe}.unwrapped_key.bin"),
                uk,
                ct).ConfigureAwait(false);
        }

        AppendIndex(workDirectory, new Dictionary<string, object?>
        {
            ["kind"] = "ck",
            ["recordName"] = asset.RecordName,
            ["ckRecord"] = Path.Combine(FolderName, "ck", $"record_{safe}.bin")
                .Replace('\\', '/'),
            ["ckQuery"] = Path.Combine(FolderName, "ck", rawQueryFile).Replace('\\', '/'),
            ["mmcsAuth"] = asset.MmcsAuth,
            ["wrapHex"] = asset.AssetProtectionInfoHex,
            ["unwrappedKeyHex"] = asset.AssetUnwrappedKey is { Length: > 0 } k
                ? Convert.ToHexString(k)
                : null,
            ["utc"] = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture)
        });
    }

    private static async Task TryDumpContentsSliceAsync(
        string dir,
        string safePrefix,
        byte[] window,
        CancellationToken ct)
    {
        var idx = IndexOf(window, "contents"u8);
        if (idx < 0)
            return;

        // Finestra dopo il marker: abbastanza per contents cifrato + PreAuth.
        var start = idx;
        var len = Math.Min(window.Length - start, 12288);
        var slice = window.AsSpan(start, len).ToArray();
        await File.WriteAllBytesAsync(
            Path.Combine(dir, $"{safePrefix}.contents.bin"), slice, ct).ConfigureAwait(false);

        if (IndexOf(window, "encryptedAttributes"u8) is >= 0 and var ea)
        {
            var eaLen = Math.Min(window.Length - ea, 8192);
            await File.WriteAllBytesAsync(
                Path.Combine(dir, $"{safePrefix}.encryptedAttributes.bin"),
                window.AsSpan(ea, eaLen).ToArray(),
                ct).ConfigureAwait(false);
        }
    }

    /// <summary>
    /// Euristica: campi length-delimited non-ASCII lunghi nella risposta authorizeGet
    /// (possibili ford storage; mapping FileGroups ancora aperto).
    /// </summary>
    public static int DumpFordCandidates(byte[] authorizeGetResponse, string fordDir)
    {
        Directory.CreateDirectory(fordDir);
        var count = 0;
        var i = 0;
        while (i < authorizeGetResponse.Length - 2)
        {
            var key = authorizeGetResponse[i];
            if ((key & 0x07) != 2)
            {
                i++;
                continue;
            }

            var pos = i + 1;
            if (!TryReadVarint(authorizeGetResponse, ref pos, out var len))
            {
                i++;
                continue;
            }

            if (len is < 64 or > 65536 || pos + len > authorizeGetResponse.Length)
            {
                i++;
                continue;
            }

            var blob = authorizeGetResponse.AsSpan(pos, len);
            // Scarta host/header ASCII tipici.
            var printable = 0;
            var n = Math.Min(blob.Length, 64);
            for (var k = 0; k < n; k++)
            {
                if (blob[k] is >= 32 and < 127)
                    printable++;
            }

            if (printable > n * 0.7)
            {
                i = pos + len;
                continue;
            }

            count++;
            var name = $"cand_{count:D2}_off{i}_len{len}.bin";
            File.WriteAllBytes(Path.Combine(fordDir, name), blob.ToArray());
            i = pos + len;
        }

        return count;
    }

    private static byte[]? TryExtractNamedWindow(byte[] payload, string recordName)
    {
        if (payload.Length == 0 || string.IsNullOrEmpty(recordName))
            return null;
        var nameBytes = Encoding.UTF8.GetBytes(recordName);
        var idx = IndexOf(payload, nameBytes);
        if (idx < 0)
            return payload.Length <= 16384 ? payload : null;
        var end = Math.Min(payload.Length, idx + 16384);
        return payload.AsSpan(idx, end - idx).ToArray();
    }

    private static string ResolveAssetFolderId(BackupAsset asset, string objectId)
    {
        if (asset.AssetSignature is { Length: >= 4 } sig)
            return "sig_" + Convert.ToHexString(sig)[..Math.Min(40, sig.Length * 2)].ToLowerInvariant();

        var rid = asset.RecordName;
        if (rid.StartsWith("A:", StringComparison.OrdinalIgnoreCase))
        {
            var parts = rid.Split(':');
            if (parts.Length >= 3 && Guid.TryParse(parts[2], out _))
                return "uuid_" + parts[2];
        }

        if (Guid.TryParse(rid.Split(':')[0], out var g))
            return "uuid_" + g.ToString("D").ToUpperInvariant();

        return "oid_" + Sanitize(objectId, 40);
    }

    private static void AppendIndex(string workDirectory, Dictionary<string, object?> row)
    {
        try
        {
            var root = ResolveRoot(workDirectory);
            Directory.CreateDirectory(root);
            var line = JsonSerializer.Serialize(row) + Environment.NewLine;
            lock (IndexLock)
            {
                File.AppendAllText(Path.Combine(root, "index.jsonl"), line, Encoding.UTF8);
            }
        }
        catch
        {
            // dump best-effort
        }
    }

    private static string Sanitize(string value, int max)
    {
        var chars = value.Select(c => char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_').ToArray();
        var s = new string(chars);
        return s.Length <= max ? s : s[..max];
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || haystack.Length < needle.Length)
            return -1;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack[i..].StartsWith(needle))
                return i;
        }

        return -1;
    }

    private static bool TryReadVarint(byte[] data, ref int pos, out int value)
    {
        value = 0;
        var shift = 0;
        while (pos < data.Length && shift <= 28)
        {
            var b = data[pos++];
            value |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
        }

        return false;
    }
}
