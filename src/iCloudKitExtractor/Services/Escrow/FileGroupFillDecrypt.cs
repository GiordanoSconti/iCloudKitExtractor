using System.IO;
using System.Security.Cryptography;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Download;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Unico algoritmo (oracle live Backup-Books / projection):
/// <c>Auth ford descriptor (0A2D‖gate / CI45) owned by FileChecksum
/// → storage gate+ctLen+OID → Read(ctLen) → FillChunks A/B → ChunkDecrypt</c>.
/// Companion = bytes Auth (no FC‖refs rebuild, no f17 trial).
/// Riferimenti: <c>auth_to_storage_projection_oracle.md</c>.
/// </summary>
public static class FileGroupFillDecrypt
{
    /// <summary>
    /// Storage dopo proiezione Auth: <c>+0x98 fordSize</c>, <c>+0x58 ctLen</c>, body cache.
    /// Costruito strutturalmente — niente trial IKM in questa fase.
    /// </summary>
    public readonly record struct BoundStorage(
        int ContainerIndex,
        bool HasFord,
        byte[]? FordCt,
        string Note);

    public readonly record struct Outcome(
        byte[] Plaintext,
        string Note,
        string FailReason);

    /// <summary>
    /// Snapshot IKE Auth→storage→FillChunks→(opz.) MUT per confronto oracle.
    /// Su fail intermedio i campi già calcolati restano valorizzati.
    /// </summary>
    public readonly record struct StageTrace(
        IReadOnlyList<BoundStorage> Storages,
        int FordN,
        int FordOpen,
        int FordSkip,
        int PipeA,
        int PipeB,
        int KeyedNodes,
        int NodeCount,
        byte[]? Plaintext,
        string Note,
        string FailReason);

    /// <summary>Adapter verso il tipo Result usato dal download service.</summary>
    public static BackupAssetDecryptPipeline.Result ToResult(Outcome o)
    {
        if (string.IsNullOrEmpty(o.FailReason) && o.Plaintext.Length > 0)
            return new BackupAssetDecryptPipeline.Result(o.Plaintext, "filegroup", o.Note, true, o.Note);
        return new BackupAssetDecryptPipeline.Result(
            [],
            "filegroup",
            string.IsNullOrEmpty(o.Note) ? "no-resolve" : o.Note,
            false,
            null,
            o.FailReason);
    }

    public static BackupAssetDecryptPipeline.Result DecryptToResult(
        BackupAsset asset,
        byte[] compact,
        byte[] authBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        IReadOnlyList<SignedUrlChunk> chunks,
        byte[]? fordIkm,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts,
        bool canMmcs,
        byte[]? mmcsKek16)
        => ToResult(Decrypt(
            asset, compact, authBody, plan, orderedChunks, chunks,
            fordIkm ?? [], siblingCompacts, canMmcs, mmcsKek16));

    public static Outcome Decrypt(
        BackupAsset asset,
        byte[] compact,
        byte[] authBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        IReadOnlyList<SignedUrlChunk> chunks,
        byte[] fordIkm,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts,
        bool canMmcs,
        byte[]? mmcsKek16)
    {
        var t = TraceDecrypt(
            asset, compact, authBody, plan, orderedChunks, chunks,
            fordIkm, siblingCompacts, canMmcs, mmcsKek16);
        if (!string.IsNullOrEmpty(t.FailReason))
            return Fail(t.FailReason, string.IsNullOrEmpty(t.Note) ? t.FailReason : t.Note);
        return new Outcome(t.Plaintext ?? [], t.Note, "");
    }

    /// <summary>
    /// Stesso flusso di <see cref="Decrypt"/>, ma restituisce contatori FillChunks/tree
    /// anche se data/MUT falliscono (probe oracle stage-by-stage).
    /// </summary>
    public static StageTrace TraceDecrypt(
        BackupAsset asset,
        byte[] compact,
        byte[] authBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        IReadOnlyList<SignedUrlChunk> chunks,
        byte[] fordIkm,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts,
        bool canMmcs,
        byte[]? mmcsKek16)
    {
        IReadOnlyList<BoundStorage> storages = Array.Empty<BoundStorage>();
        var fordN = 0;

        if (plan.References.Count == 0)
        {
            return new StageTrace(
                storages, 0, 0, 0, 0, 0, 0, 0, null,
                "FileGroup senza file_checksum_chunk_references",
                "ike-no-refs");
        }

        // live da zero (live_ford_demux_x64dbg):
        // L1 PutChunk(.chunks/hex(gate)) → L2 pool.lookup(gate).Read(ctLen)
        // → DecryptFordKeys(IKM). Nessun demux/scan/ikm-rebind al bind.
        _ = orderedChunks;
        var sibCache = siblingCompacts is Dictionary<string, (byte[] Compact, long MmcsStart)> d0
            ? d0
            : siblingCompacts is not null
                ? new Dictionary<string, (byte[] Compact, long MmcsStart)>(
                    siblingCompacts, StringComparer.Ordinal)
                : new Dictionary<string, (byte[] Compact, long MmcsStart)>(StringComparer.Ordinal);
        // Unico path  SpillOpen exact/wire/packScan(IKM) → pool → Bind → FillChunks.
        var putN = LiveFillPipeline.PutChunksFromHostBodies(
            sibCache, plan, chunks, authBody, fordIkm);
        // Data plant (sig:) — Ford solo da PutChunksFromHostBodies / .chunks.
        PlantAuthChecksumSlicesIntoMap(sibCache, plan, chunks, sibCache, fordIkm: fordIkm);
        // Pass AssetSignature: batch AG plan.FileChecksum can miss the Ford gate that embeds CK sig.
        storages = LiveFillPipeline.BindOwnedFordStorages(
            authBody, plan, chunks, sibCache,
            fileChecksum21: asset.AssetSignature,
            fordIkm: fordIkm);
        // Aggiungi storage data (refs host senza Ford) come Phase A.
        var refHosts = CollectRefHostIndices(plan);
        for (var i = 0; i < plan.Containers.Count; i++)
        {
            if (!refHosts.Contains(i))
                continue;
            var group = plan.Containers[i];
            if (group.Count > 0 && !group.Any(UbChunkBuilder.IsAuthFordDescriptorChunk)
                && storages.All(s => s.ContainerIndex != i))
            {
                storages = storages.Append(new BoundStorage(i, false, null, "data")).ToList();
            }
        }

        fordN = storages.Count(static s => s.HasFord && s.FordCt is { Length: > 0 });
        // #region agent log
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = LiveFillPipeline.RunId,
                    ["hypothesisId"] = "H-IKE-PIPELINE",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "FileGroupFillDecrypt.TraceDecrypt",
                    ["message"] = "live_pipeline",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["path"] = asset.RelativePath ?? asset.RecordName,
                        ["putN"] = putN,
                        ["fordN"] = fordN,
                        ["sib"] = sibCache.Count,
                        ["gateN"] = sibCache.Keys.Count(static k =>
                            k.StartsWith("gate:", StringComparison.Ordinal)),
                        ["exactHost"] = sibCache.Count(static kv =>
                            !kv.Key.StartsWith("gate:", StringComparison.Ordinal)
                            && !kv.Key.StartsWith("sig:", StringComparison.Ordinal)
                            && kv.Value.Compact.Length is >= 0x12 and <= 512
                            && kv.Value.Compact[0] == 0x04),
                        ["ikmLen"] = fordIkm.Length,
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        // #region agent log
        if (fordN > 0 && fordIkm.Length > 0)
        {
            try
            {
                var fordSt = storages.Where(static s => s.HasFord && s.FordCt is { Length: > 0 }).Take(3)
                    .Select(s =>
                    {
                        var ct = s.FordCt!;
                        return new Dictionary<string, object?>
                        {
                            ["h"] = s.ContainerIndex,
                            ["note"] = s.Note,
                            ["fordLen"] = ct.Length,
                            ["fordHead8"] = Convert.ToHexString(ct.AsSpan(0, Math.Min(8, ct.Length))),
                            ["opens"] = FordMmcsDecryptor.BlobOpensExactWithIkm(fordIkm, ct),
                        };
                    }).ToList();
                var anyOpens = fordSt.Any(static d => d["opens"] is true);
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = anyOpens ? "H-IKE-PIPELINE" : "H-IKM-MISS",
                        ["runId"] = LiveFillPipeline.RunId,
                        ["location"] = "FileGroupFillDecrypt.TraceDecrypt",
                        ["message"] = "ford_ikm_open_probe",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["ikmLen"] = fordIkm.Length,
                            ["fordN"] = fordN,
                            ["anyOpens"] = anyOpens,
                            ["fords"] = fordSt,
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
        }
        // #endregion

        var hasPipeC = PlanHasChunkEncryptionKeys(plan);

        if (fordN == 0 && !hasPipeC)
        {
            // #region agent log
            try
            {
                var descsDiag = UbChunkBuilder.CollectAuthFordDescriptors(
                    authBody, plan, chunks);
                var assetSig = asset.AssetSignature;
                var gateDiag = descsDiag.Take(6).Select(d =>
                {
                    var emb4 = d.Gate45.Length == 45
                        ? Convert.ToHexString(d.Gate45.AsSpan(3, 4))
                        : "";
                    var lead3 = d.Gate45.Length >= 3
                        ? Convert.ToHexString(d.Gate45.AsSpan(0, 3))
                        : "";
                    var ownsPlan = UbChunkBuilder.GateOwnsPlan(d.Gate45, plan);
                    var ownsAsset = assetSig is { Length: 21 }
                                    && UbChunkBuilder.GateEmbedsFileChecksum(
                                        d.Gate45, assetSig);
                    return new Dictionary<string, object?>
                    {
                        ["gate8"] = d.Gate45.Length >= 8
                            ? Convert.ToHexString(d.Gate45.AsSpan(0, 8))
                            : "",
                        ["lead3"] = lead3,
                        ["embFc4"] = emb4,
                        ["owns"] = ownsPlan,
                        ["ownsAsset"] = ownsAsset,
                        ["ctLen"] = d.CtLen,
                        ["oid8"] = d.ObjectId is { Length: >= 8 } o
                            ? o[..8]
                            : d.ObjectId,
                    };
                }).ToList();
                var fordCiN = plan.Containers.Sum(static g =>
                    g.Count(UbChunkBuilder.IsAuthFordDescriptorChunk));
                var ownsN = descsDiag.Count(d =>
                    UbChunkBuilder.GateOwnsPlan(d.Gate45, plan)
                    || (assetSig is { Length: 21 }
                        && UbChunkBuilder.GateEmbedsFileChecksum(d.Gate45, assetSig)));
                var payload = new Dictionary<string, object?>
                {
                    ["sessionId"] = "b3df71",
                    ["runId"] = "case3-noford-v1",
                    ["hypothesisId"] = "H-F-GATEOWN",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "FileGroupFillDecrypt.TraceDecrypt",
                    ["message"] = "no_ford",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["path"] = asset.RelativePath ?? asset.RecordName,
                        ["putN"] = putN,
                        ["hosts"] = plan.Containers.Count,
                        ["refs"] = plan.References.Count,
                        ["sib"] = sibCache.Count,
                        ["gateN"] = sibCache.Keys.Count(static k =>
                            k.StartsWith("gate:", StringComparison.Ordinal)),
                        ["exactFg"] = CountExactFordBodies(sibCache, plan, chunks),
                        ["hasPlanFc"] = plan.FileChecksum is { Length: 21 },
                        ["fc21"] = plan.FileChecksum is { Length: 21 } fc
                            ? Convert.ToHexString(fc.AsSpan(0, 4))
                            : null,
                        ["fcLead"] = plan.FileChecksum is { Length: 21 } fc2
                            ? fc2[0]
                            : -1,
                        ["assetSig4"] = assetSig is { Length: 21 } asg
                            ? Convert.ToHexString(asg.AsSpan(0, 4))
                            : null,
                        ["assetSigLead"] = assetSig is { Length: 21 } asg2
                            ? asg2[0]
                            : -1,
                        ["descs"] = descsDiag.Count,
                        ["fordCiN"] = fordCiN,
                        ["ownsN"] = ownsN,
                        ["gates"] = gateDiag,
                        ["hasPipeC"] = hasPipeC,
                        ["ikmLen"] = fordIkm.Length,
                        ["emptyHosts"] = plan.Containers.Count(static c => c.Count == 0),
                    },
                };
                var line = System.Text.Json.JsonSerializer.Serialize(payload)
                    + Environment.NewLine;
                // Small files first: debug-03cce7 (~17GB) AppendAllText often throws and
                // previously swallowed the whole diagnostic (no b3df71 / no_ford for Unify).
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-unify-ford.jsonl",
                        line);
                }
                catch { /* ignore */ }
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
                }
                catch { /* ignore */ }
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                        line);
                }
                catch { /* ignore */ }
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line);
                }
                catch { /* ignore */ }
                // #region agent log
                // Dump AG wire on TM / Unify / no-ford so we can compare authDescN vs fordCi offline.
                try
                {
                    var rel = asset.RelativePath ?? asset.RecordName ?? "";
                    var dumpTm = rel.Contains("translations-models", StringComparison.OrdinalIgnoreCase)
                        || rel.Contains("UnifyStorage", StringComparison.OrdinalIgnoreCase)
                        || (plan.FileChecksum is { Length: 21 } fcDump
                            && fcDump[0] == 0x04 && fcDump[1] == 0xC0 && fcDump[2] == 0x55
                            && fcDump[3] == 0xB5);
                    if (dumpTm && authBody is { Length: > 0 })
                    {
                        var outDir = rel.Contains("UnifyStorage", StringComparison.OrdinalIgnoreCase)
                            ? @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\mitm\captures\unify_ford"
                            : @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\mitm\captures\translations_models_x64dbg";
                        Directory.CreateDirectory(outDir);
                        var agPath = Path.Combine(outDir, "ike_ag_wire.bin");
                        File.WriteAllBytes(agPath, authBody);
                        var dumpLine = System.Text.Json.JsonSerializer.Serialize(
                            new Dictionary<string, object?>
                            {
                                ["sessionId"] = "9a5651",
                                ["runId"] = "tm-ag-dump-v1",
                                ["hypothesisId"] = "H-AG-IKE",
                                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                ["location"] = "FileGroupFillDecrypt.TraceDecrypt",
                                ["message"] = "tm_ag_wire_dumped",
                                ["data"] = new Dictionary<string, object?>
                                {
                                    ["path"] = rel,
                                    ["agPath"] = agPath,
                                    ["authBodyLen"] = authBody.Length,
                                    ["descs"] = descsDiag.Count,
                                    ["fordCiN"] = fordCiN,
                                    ["ownsN"] = gateDiag.Count(static g => g["owns"] is true),
                                    ["fc21"] = plan.FileChecksum is { Length: 21 } fc3
                                        ? Convert.ToHexString(fc3)
                                        : null,
                                },
                            }) + Environment.NewLine;
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                            dumpLine);
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                            dumpLine);
                    }
                }
                catch { /* ignore */ }
                // #endregion
            }
            catch { /* ignore */ }
            // #endregion
            // H-ORDER: pending con path per plant tardivo + retry assemble.
            if (fordIkm.Length > 0)
            {
                foreach (var d in UbChunkBuilder.CollectAuthFordDescriptors(
                             authBody, plan, chunks))
                {
                    if (d.Gate45.Length != 45 || string.IsNullOrEmpty(d.ObjectId))
                        continue;
                    if (plan.FileChecksum is { Length: 21 }
                        && !UbChunkBuilder.GateOwnsPlan(d.Gate45, plan))
                        continue;
                    OidHostBodyCache.RegisterPending(
                        d.ObjectId,
                        d.Gate45,
                        d.CtLen,
                        fordIkm,
                        asset.RelativePath ?? asset.RecordName);
                    break;
                }
            }

            var noFord = new StageTrace(
                storages, fordN, 0, 0, 0, 0, 0, 0, null,
                $"Auth→storage Ford assente hosts={plan.Containers.Count} refs={plan.References.Count}",
                "no-ford");
            TryDumpOraclePair(
                asset, authBody, plan, fordIkm, storages, null, null, null, noFord, sibCache);
            ReleaseChunkFilesAfterUse(plan, storages, decryptOk: false);
            return noFord;
        }

        if (fordN > 0 && fordIkm.Length == 0)
        {
            var noIkm = new StageTrace(
                storages, fordN, 0, 0, 0, 0, 0, 0, null,
                "manca IKM asset (FillFordIkmFromContents)",
                "no-ikm");
            TryDumpOraclePair(
                asset, authBody, plan, fordIkm, storages, null, null, null, noIkm, sibCache);
            ReleaseChunkFilesAfterUse(plan, storages, decryptOk: false);
            return noIkm;
        }

        // 2) Data = slice per-host dei ChunkInfo citati dai refs.
        if (!TryExtractRefDataFromHostBodies(
                plan, compact, orderedChunks, chunks, sibCache, out var dataChunks, fordIkm)
            || dataChunks.Count == 0)
        {
            // H-NODATA: Invalidate senza host oid@ distrugge sig: condivisi del batch e
            // rende ike-no-data permanente (seed ok → invalidate → re-plant miss).
            // Re-plant distruttivo SOLO se i body host dei refs sono in map.
            var canReplant = RefDataHostBodiesPresent(plan, chunks, sibCache);
            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(
                    new Dictionary<string, object?>
                    {
                        ["sessionId"] = "4ff690",
                        ["runId"] = "nodata-fix-v1",
                        ["hypothesisId"] = "H-NODATA-INV",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "FileGroupFillDecrypt.TraceDecrypt",
                        ["message"] = "extract_miss_replant_gate",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["path"] = asset.RelativePath ?? asset.RecordName,
                            ["canReplant"] = canReplant,
                            ["refs"] = plan.References.Count,
                            ["oidHosts"] = CountOidHosts(sibCache),
                            ["mapCount"] = sibCache.Count,
                        },
                    }) + Environment.NewLine;
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\AIAgent\debug-4ff690.log",
                    line);
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-4ff690.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion
            if (canReplant)
            {
                InvalidatePoisonedDataSigs(plan, sibCache);
                PlantAuthChecksumSlicesIntoMap(
                    sibCache, plan, chunks, sibCache, fordIkm: fordIkm, overwriteChunkFiles: true);
            }
            else
            {
                // Non-destructive: riempie sig: mancanti senza cancellare quelli condivisi.
                PlantAuthChecksumSlicesIntoMap(
                    sibCache, plan, chunks, sibCache, fordIkm: fordIkm, overwriteChunkFiles: false);
            }
            if (!TryExtractRefDataFromHostBodies(
                    plan, compact, orderedChunks, chunks, sibCache, out dataChunks, fordIkm)
                || dataChunks.Count == 0)
            {
                // Sapphire/FileBus: wire Auth è spesso lead≠04; lead-04 gate → miss.
                // Prova candidati wire/scan e lascia che ChunkDecrypt scelga (sotto).
                if (fordN > 0
                    && fordIkm.Length > 0
                    && TryPickDataChunksByMac20Candidates(
                        plan, chunks, sibCache, fordIkm, storages, mmcsKek16,
                        asset.RelativePath ?? asset.RecordName,
                        priorData: null,
                        out var earlyData,
                        out var earlyFill)
                    && earlyFill.Plaintext is { Length: > 0 })
                {
                    var earlyNote = $"storages={storages.Count} fordN={fordN} {earlyFill.Note}";
                    var earlyOk = new StageTrace(
                        storages,
                        fordN,
                        earlyFill.FordOpen,
                        earlyFill.FordSkip,
                        earlyFill.PipeA,
                        earlyFill.PipeB,
                        earlyFill.KeyedNodes,
                        earlyFill.NodeCount,
                        earlyFill.Plaintext,
                        earlyNote,
                        "");
                    TryDumpOraclePair(
                        asset, authBody, plan, fordIkm, storages, earlyData,
                        earlyFill.BestFordCt, earlyFill.BestKeys, earlyOk, sibCache);
                    ReleaseChunkFilesAfterUse(plan, storages, decryptOk: true);
                    return earlyOk;
                }

                // #region agent log
                try
                {
                    var refDiag = new List<Dictionary<string, object?>>();
                    foreach (var r in plan.References.Take(6))
                    {
                        if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count
                            || (uint)r.ContainerIndex >= (uint)chunks.Count)
                        {
                            refDiag.Add(new Dictionary<string, object?>
                            {
                                ["h"] = r.ContainerIndex,
                                ["ci"] = r.ChunkIndex,
                                ["why"] = "bad_ref_index",
                            });
                            continue;
                        }

                        var group = plan.Containers[r.ContainerIndex];
                        if ((uint)r.ChunkIndex >= (uint)group.Count)
                        {
                            refDiag.Add(new Dictionary<string, object?>
                            {
                                ["h"] = r.ContainerIndex,
                                ["ci"] = r.ChunkIndex,
                                ["why"] = "bad_ci_index",
                                ["groupN"] = group.Count,
                            });
                            continue;
                        }

                        var ch = group[r.ChunkIndex];
                        var sigKey = ch.Checksum21 is { Length: 21 } cs
                            ? "sig:" + Convert.ToHexString(cs).ToLowerInvariant()
                            : "";
                        var sigMapLen = 0;
                        var sigInMap = false;
                        if (sigKey.Length > 0
                            && sibCache.TryGetValue(sigKey, out var sigEnt))
                        {
                            sigInMap = true;
                            sigMapLen = sigEnt.Compact.Length;
                        }

                        var host = chunks[r.ContainerIndex];
                        var oid = host.EdgeHeaders?.ObjectId ?? "";
                        long authLen = -1;
                        var bodyLen = 0;
                        var hostKeyHit = false;
                        var wireOff = -1L;
                        var wouldFit = false;
                        if (host.ByteRange is { } br)
                        {
                            authLen = br.End - br.Start + 1;
                            var hk = !string.IsNullOrEmpty(oid)
                                ? $"{oid}@{br.Start}"
                                : $"host:{r.ContainerIndex}@{br.Start}";
                            if (sibCache.TryGetValue(hk, out var hbHit))
                            {
                                hostKeyHit = true;
                                bodyLen = hbHit.Compact.Length;
                            }
                            else if (!string.IsNullOrEmpty(oid)
                                     && TryAssembleHostBodyFromMap(
                                         sibCache, oid, br.Start, authLen, out var hbAsm))
                            {
                                hostKeyHit = true;
                                bodyLen = hbAsm.Compact.Length;
                            }

                            if (hostKeyHit && ch.Length > 0)
                            {
                                long layoutSum = 0;
                                foreach (var c in group)
                                    layoutSum += c.Length;
                                var layoutOff = 0;
                                for (var jj = 0; jj < r.ChunkIndex && jj < group.Count; jj++)
                                    layoutOff += Math.Max(0, group[jj].Length);
                                wireOff = UbChunkBuilder.ResolveCiWireInHostBody(
                                    ch.Offset, ch.Length, br.Start, bodyLen,
                                    layoutOff, r.ChunkIndex, group.Count, layoutSum,
                                    fordOnlyHost: false);
                                wouldFit = wireOff >= 0
                                           && wireOff + ch.Length <= bodyLen;
                            }
                        }

                        string why;
                        if (!UbChunkBuilder.IsAuthDataChunk(ch))
                            why = "not_data_ci";
                        else if (ch.Checksum21 is not { Length: 21 })
                            why = "bad_checksum_len";
                        else if (!hostKeyHit)
                            why = "host_body_missing";
                        else if (!wouldFit)
                            why = "wire_out_of_range";
                        else if (!sigInMap)
                            why = "planted_but_sig_missing";
                        else if (sigMapLen != ch.Length)
                            why = "sig_len_mismatch";
                        else
                            why = "sig_present_extract_failed";

                        refDiag.Add(new Dictionary<string, object?>
                        {
                            ["h"] = r.ContainerIndex,
                            ["ci"] = r.ChunkIndex,
                            ["wantLen"] = ch.Length,
                            ["sig8"] = ch.Checksum21 is { Length: >= 8 } s
                                ? Convert.ToHexString(s.AsSpan(0, 8))
                                : "",
                            ["oid8"] = oid.Length >= 8 ? oid[..8] : oid,
                            ["hostKeyHit"] = hostKeyHit,
                            ["bodyLen"] = bodyLen,
                            ["authLen"] = authLen,
                            ["wireOff"] = wireOff,
                            ["wouldFit"] = wouldFit,
                            ["sigInMap"] = sigInMap,
                            ["sigMapLen"] = sigMapLen,
                            ["why"] = why,
                        });
                    }

                    var line = System.Text.Json.JsonSerializer.Serialize(
                        new Dictionary<string, object?>
                        {
                            ["sessionId"] = "b3df71",
                            ["runId"] = "case-nodata-v1",
                            ["hypothesisId"] = "H-NODATA-PLANT",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["location"] = "FileGroupFillDecrypt.TraceDecrypt",
                            ["message"] = "no_data",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["path"] = asset.RelativePath ?? asset.RecordName,
                                ["fordN"] = fordN,
                                ["putN"] = putN,
                                ["hosts"] = plan.Containers.Count,
                                ["refs"] = plan.References.Count,
                                ["oidHosts"] = CountOidHosts(sibCache),
                                ["sib"] = sibCache.Count,
                                ["ikmLen"] = fordIkm.Length,
                                ["refsDiag"] = refDiag,
                            },
                        }) + Environment.NewLine;
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log",
                        line);
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line);
                }
                catch { /* ignore */ }
                // #endregion

                var miss = new StageTrace(
                    storages, fordN, 0, 0, 0, 0, 0, 0, null,
                    $"refs data miss oidHosts={CountOidHosts(sibCache)} refs={plan.References.Count}",
                    "ike-no-data");
                TryDumpOraclePair(
                    asset, authBody, plan, fordIkm, storages, null, null, null, miss, sibCache);
                ReleaseChunkFilesAfterUse(plan, storages, decryptOk: false);
                return miss;
            }
        }

        // 3) FillChunks per storage → tree KEY inject → (opz.) MUT ChunkDecrypt.
        // Pipe C (chunkEncryptionKey): passa KEK anche se canMmcs era false per mancanza wrap
        // (type 0x01 non serve KEK; type 0x02 sì). Non azzerare il KEK con canMmcs.
        var fill = FillChunksPerStorageAndDecryptTrace(
            fordIkm,
            storages,
            dataChunks,
            plan,
            mmcsKek16);

        // fordOpen=1 + MAC20: prova candidati wire Auth (anche non-04) + finestre lead-04.
        // Il solo re-plant first-wins spesso rilegge un altro sameLenCi → altro MAC20.
        if (fill.Plaintext is not { Length: > 0 }
            && fill.FordOpen > 0
            && fill.FailReason.Contains("ike-fillchunks", StringComparison.Ordinal)
            && (fill.Note.Contains("MAC/SIV", StringComparison.OrdinalIgnoreCase)
                || fill.Note.Contains("staging MAC20", StringComparison.OrdinalIgnoreCase)))
        {
            // Stesso gate: non wipe sig: condivisi se non c'è host per re-plant.
            if (RefDataHostBodiesPresent(plan, chunks, sibCache))
                InvalidatePoisonedDataSigs(plan, sibCache);
            if (TryPickDataChunksByMac20Candidates(
                    plan, chunks, sibCache, fordIkm, storages, mmcsKek16,
                    asset.RelativePath ?? asset.RecordName,
                    priorData: dataChunks,
                    out var dataRetry,
                    out var fillRetry)
                && fillRetry.Plaintext is { Length: > 0 })
            {
                dataChunks = dataRetry;
                fill = fillRetry;
            }
            else
            {
                // Fallback legacy: re-plant + un extract.
                PlantAuthChecksumSlicesIntoMap(
                    sibCache, plan, chunks, sibCache, fordIkm: fordIkm, overwriteChunkFiles: true);
                if (TryExtractRefDataFromHostBodies(
                        plan, compact, orderedChunks, chunks, sibCache, out dataRetry, fordIkm)
                    && dataRetry.Count == plan.References.Count)
                {
                    var sameHead = dataChunks.Count > 0
                                   && dataRetry.Count > 0
                                   && dataChunks[0].Length == dataRetry[0].Length
                                   && dataChunks[0].AsSpan(0, Math.Min(8, dataChunks[0].Length))
                                       .SequenceEqual(
                                           dataRetry[0].AsSpan(0, Math.Min(8, dataRetry[0].Length)));
                    if (!sameHead)
                    {
                        dataChunks = dataRetry;
                        fill = FillChunksPerStorageAndDecryptTrace(
                            fordIkm, storages, dataChunks, plan, mmcsKek16);
                    }
                }
            }
        }

        var note = $"storages={storages.Count} fordN={fordN} {fill.Note}";
        var result = new StageTrace(
            storages,
            fordN,
            fill.FordOpen,
            fill.FordSkip,
            fill.PipeA,
            fill.PipeB,
            fill.KeyedNodes,
            fill.NodeCount,
            fill.Plaintext,
            string.IsNullOrEmpty(fill.FailReason) ? note : $"{note} | {fill.FailReason}",
            fill.FailReason);
        TryDumpOraclePair(
            asset, authBody, plan, fordIkm, storages, dataChunks,
            fill.BestFordCt, fill.BestKeys, result, sibCache);

        //  rimuove .chunks quando il CT non serve più (dopo FillChunks/DecryptFord).
        // Su MAC20 fail: cancella anche data CI21 poison (altrimenti retry riusa D621…).
        var ok = result.Plaintext is { Length: > 0 };
        // Su MAC20 fail: invalida solo se possiamo ripiantare — altrimenti i sibling
        // dello stesso AG batch perdono sig: e finiscono in ike-no-data.
        if (!ok && fill.FordOpen > 0
            && (fill.Note.Contains("MAC/SIV", StringComparison.OrdinalIgnoreCase)
                || fill.Note.Contains("staging MAC20", StringComparison.OrdinalIgnoreCase))
            && RefDataHostBodiesPresent(plan, chunks, sibCache))
            InvalidatePoisonedDataSigs(plan, sibCache);
        ReleaseChunkFilesAfterUse(plan, storages, ok);

        return result;
    }

    /// <summary>
    /// Rimuove sig: map + .chunks CI21 per i refs data (re-plant dopo miss / MAC retry).
    /// </summary>
    private static void InvalidatePoisonedDataSigs(
        AuthorizeGetDecryptPlan plan,
        IDictionary<string, (byte[] Compact, long MmcsStart)> map)
    {
        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                continue;
            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count)
                continue;
            var ch = group[r.ChunkIndex];
            if (!UbChunkBuilder.IsAuthDataChunk(ch) || ch.Checksum21 is not { Length: 21 })
                continue;
            var sigKey = "sig:" + Convert.ToHexString(ch.Checksum21).ToLowerInvariant();
            map.Remove(sigKey);
            ChunkFileCache.TryDelete(ch.Checksum21);
        }
    }

    /// <summary>
    /// hygiene: cancella Gate45 Ford e CI data da <c>Downloads\.chunks</c>
    /// <b>solo</b> dopo decrypt riuscito. Su fail non toccare — AG multi-file
    /// condivide host/Ford con asset ancora in volo (ike-no-data intermittente).
    /// </summary>
    private static void ReleaseChunkFilesAfterUse(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<BoundStorage> storages,
        bool decryptOk)
    {
        _ = storages;
        if (!decryptOk)
            return;

        var deleted = 0;
        try
        {
            foreach (var group in plan.Containers)
            {
                foreach (var ch in group)
                {
                    if (ch.Checksum21.Length is 21 or 45
                        && ChunkFileCache.TryDelete(ch.Checksum21))
                        deleted++;
                }
            }

            // #region agent log
            if (deleted > 0)
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = "ike-chunks-hygiene-v1",
                        ["hypothesisId"] = "H-CHUNKS-HYGIENE",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "FileGroupFillDecrypt.ReleaseChunkFilesAfterUse",
                        ["message"] = "chunks_released",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["deleted"] = deleted,
                            ["decryptOk"] = decryptOk,
                            ["fc8"] = plan.FileChecksum is { Length: >= 4 } fc
                                ? Convert.ToHexString(fc.AsSpan(0, 4))
                                : "",
                        },
                    }) + Environment.NewLine);
            }
            // #endregion
        }
        catch { /* ignore */ }
    }

    private static int CountOidHosts(
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings)
    {
        if (siblings is null)
            return 0;
        var n = 0;
        foreach (var k in siblings.Keys)
        {
            if (k.Contains('@', StringComparison.Ordinal)
                && !k.StartsWith("sig:", StringComparison.Ordinal)
                && !k.StartsWith("gate:", StringComparison.Ordinal))
                n++;
        }

        return n;
    }

    /// <summary>
    /// True se ogni ref data ha un body host in map (<c>oid@{Start}</c> / <c>host:i@{Start}</c>)
    /// da cui <see cref="PlantAuthChecksumSlicesIntoMap"/> può re-slice dopo Invalidate.
    /// </summary>
    private static bool RefDataHostBodiesPresent(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> chunks,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> map)
    {
        if (plan.References.Count == 0)
            return false;

        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                return false;
            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count)
                return false;
            var ch = group[r.ChunkIndex];
            if (!UbChunkBuilder.IsAuthDataChunk(ch) || ch.Length <= 0)
                return false;

            var found = false;
            if ((uint)r.ContainerIndex < (uint)chunks.Count
                && chunks[r.ContainerIndex].ByteRange is { } br)
            {
                var oid = chunks[r.ContainerIndex].EdgeHeaders?.ObjectId ?? "";
                if (!string.IsNullOrEmpty(oid)
                    && map.TryGetValue($"{oid}@{br.Start}", out var byOid)
                    && byOid.Compact.Length >= ch.Length)
                    found = true;
                else if (map.TryGetValue($"host:{r.ContainerIndex}@{br.Start}", out var byHost)
                         && byHost.Compact.Length >= ch.Length)
                    found = true;
            }

            if (!found)
                return false;
        }

        return true;
    }

    private static void TryDumpOraclePair(
        BackupAsset asset,
        byte[] authBody,
        AuthorizeGetDecryptPlan plan,
        byte[] fordIkm,
        IReadOnlyList<BoundStorage> storages,
        IReadOnlyList<byte[]>? dataChunks,
        byte[]? bestFordCt,
        IReadOnlyList<FordMmcsDecryptor.FordChunkKey>? bestKeys,
        StageTrace trace,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? hostSiblings)
    {
        try
        {
            IkeOraclePairDumpWriter.TryDump(new IkeOraclePairDumpWriter.PairMaterials(
                asset,
                authBody,
                hostSiblings,
                plan,
                fordIkm,
                storages,
                dataChunks,
                bestFordCt,
                bestKeys,
                trace.FailReason,
                trace.Note,
                trace.FordOpen,
                trace.FordSkip));
        }
        catch
        {
            // dump best-effort
        }
    }

    /// <summary>
    /// Auth→storage (live Backup-Books / projection oracle):
    /// descriptor Ford Auth (nested <c>0A2D‖gate</c> + CI45) che embedda FileChecksum
    /// → gate+ctLen+OID → <c>Read(ctLen)</c>. Companion = bytes Auth (no rebuild / no f17 trial).
    /// </summary>
    public static List<BoundStorage> MaterializeAuthStorages(
        ReadOnlySpan<byte> authBody,
        AuthorizeGetDecryptPlan plan,
        ReadOnlySpan<byte> compact,
        IReadOnlyList<SignedUrlChunk> ordered,
        IReadOnlyList<SignedUrlChunk> original,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        ReadOnlySpan<byte> assetSignature = default,
        ReadOnlySpan<byte> fordIkm = default)
    {
        _ = compact;
        _ = ordered;
        _ = assetSignature;
        // Stesso unico path di TraceDecrypt (niente TryBindFordByOwnedGates / PlantGates).
        var sibCache = siblings is Dictionary<string, (byte[] Compact, long MmcsStart)> d0
            ? d0
            : siblings is not null
                ? new Dictionary<string, (byte[] Compact, long MmcsStart)>(
                    siblings, StringComparer.Ordinal)
                : new Dictionary<string, (byte[] Compact, long MmcsStart)>(StringComparer.Ordinal);
        var auth = authBody.ToArray();
        LiveFillPipeline.PutChunksFromHostBodies(
            sibCache, plan, original, auth, fordIkm);
        PlantAuthChecksumSlicesIntoMap(sibCache, plan, original, sibCache, fordIkm: fordIkm);
        var list = LiveFillPipeline.BindOwnedFordStorages(
            auth, plan, original, sibCache, fordIkm: fordIkm);
        var refHosts = CollectRefHostIndices(plan);
        for (var i = 0; i < plan.Containers.Count; i++)
        {
            var group = plan.Containers[i];
            if (refHosts.Contains(i)
                && group.Count > 0
                && !group.Any(UbChunkBuilder.IsAuthFordDescriptorChunk)
                && list.All(s => s.ContainerIndex != i))
                list.Add(new BoundStorage(i, false, null, "data"));
        }

        return list;
    }

    /// <summary>
    /// <c>storage.gate → stream.Read(ctLen)</c> per ogni Gate45 Auth owned del file.
    /// </summary>
    private static bool TryBindFordByOwnedGates(
        IReadOnlyList<UbChunkBuilder.AuthFordDescriptor> nestedDescs,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> original,
        Dictionary<int, byte[]> bodies,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        HashSet<int> refHosts,
        List<BoundStorage> list,
        HashSet<string> fordBoundOids,
        byte[]? fileChecksum21,
        HashSet<string>? seenCtSha = null,
        ReadOnlySpan<byte> fordIkm = default)
    {
        _ = refHosts;
        var any = false;
        seenCtSha ??= new HashSet<string>(StringComparer.Ordinal);

        foreach (var d in nestedDescs)
        {
            if (d.Gate45.Length != 45 || !UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen))
                continue;

            var hostCi = -1;
            var oid = d.ObjectId ?? "";
            if (TryFindFordHostForGate(d, plan, original, out var hi, out var hostOid))
            {
                hostCi = hi;
                if (!string.IsNullOrEmpty(hostOid))
                    oid = hostOid;
            }
            else if (!string.IsNullOrEmpty(d.ObjectId)
                     && TryFindChunkIndexByOid(original, d.ObjectId, out var oi))
            {
                hostCi = oi;
            }

            byte[]? gateCt = null;
            var how = "";
            var hostSizeHint = hostCi >= 0
                               && (uint)hostCi < (uint)original.Count
                               && original[hostCi].ByteRange is { } brHint
                ? (int)(brHint.End - brHint.Start + 1)
                : 0;

            //-strict L2: .chunks/<hex(gate)> → Read(ctLen). Nessun IKM-check
            // al bind (DecryptFordKeys valuta IKM dopo); nessun scan cross-OID.
            if (ChunkFileCache.TryRead(d.Gate45, d.CtLen, out var fileCt))
            {
                gateCt = fileCt;
                how = "chunkfile";
            }

            if (gateCt is null
                && TryReadFordCtFromGateCache(d.Gate45, d.CtLen, siblings, out var cacheCt))
            {
                gateCt = cacheCt;
                how = "gate-cache";
            }

            //  niente CI.Offset / head[0:ctLen]. Solo spill exact già in .chunks / gate:.
            // (live: PutChunk=0; writer = string size==ctLen → OPEN_ALWAYS)
            if (gateCt is null
                && hostCi >= 0
                && TryReadFordCtFromOidCache(
                    oid, d.CtLen, hostSizeHint, original, hostCi, bodies, siblings, plan,
                    out var oidCt)
                && oidCt.Length == d.CtLen
                && oidCt[0] == 0x04)
            {
                gateCt = oidCt;
                how = "oid-exact";
            }

            // #region agent log
            try
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = "ike-strict-v1",
                        ["hypothesisId"] = "H-IKE-STRICT",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "FileGroupFillDecrypt.TryBindFordByOwnedGates",
                        ["message"] = "ford_bind_strict",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["how"] = how.Length > 0 ? how : "miss",
                            ["gateHex12"] = Convert.ToHexString(d.Gate45.AsSpan(0, 12)),
                            ["ctLen"] = d.CtLen,
                            ["h"] = hostCi,
                            ["oid8"] = oid.Length >= 8 ? oid[..8] : oid,
                            ["ikmLen"] = fordIkm.Length,
                            ["ikmOpens"] = gateCt is { Length: > 0 }
                                          && fordIkm.Length > 0
                                          && FordMmcsDecryptor.BlobOpensExactWithIkm(fordIkm, gateCt),
                            ["head8"] = gateCt is { Length: >= 8 } g8
                                ? Convert.ToHexString(g8.AsSpan(0, 8))
                                : "",
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion

            if (gateCt is null)
            {
                AgentLogFordRead(
                    "ford_gate_cache_miss",
                    d.ObjectId,
                    hostCi,
                    d.CtLen,
                    0,
                    null);
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "03cce7",
                            ["runId"] = "ike-demux-align-v1",
                            ["hypothesisId"] = "H-DEMUX",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["location"] = "FileGroupFillDecrypt.TryBindFordByOwnedGates",
                            ["message"] = "ford_demux_miss",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["gateHex12"] = Convert.ToHexString(d.Gate45.AsSpan(0, 12)),
                                ["ctLen"] = d.CtLen,
                                ["h"] = hostCi,
                                ["oid8"] = oid.Length >= 8 ? oid[..8] : oid,
                                ["hint"] = hostSizeHint,
                                ["ikmLen"] = fordIkm.Length,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                continue;
            }

            var ctSha = Convert.ToHexString(SHA256.HashData(gateCt).AsSpan(0, 8));
            if (!seenCtSha.Add(ctSha))
                continue;

            // Plant under Auth gate key so subsequent lookups use wire companion.
            if (siblings is IDictionary<string, (byte[] Compact, long MmcsStart)> mut)
            {
                mut["gate:" + Convert.ToHexString(d.Gate45).ToLowerInvariant()] =
                    (gateCt, 0L);
            }

            list.Add(new BoundStorage(
                hostCi, true, gateCt,
                $"{how} ctLen={d.CtLen} h={hostCi}"));
            if (!string.IsNullOrEmpty(oid))
                fordBoundOids.Add(oid);
            any = true;
            // #region agent log
            AgentLogFordRead(
                how == "gate-cache" ? "ford_gate_cache" : "ford_oid_read",
                oid,
                hostCi,
                d.CtLen,
                gateCt.Length,
                gateCt);
            try
            {
                var fc = fileChecksum21 is { Length: 21 } ? fileChecksum21 : null;
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-DEMUX",
                    ["runId"] = "ike-demux-align-v1",
                    ["location"] = "FileGroupFillDecrypt.TryBindFordByOwnedGates",
                    ["message"] = "ford_gate_bind",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["how"] = how,
                        ["gateHex12"] = Convert.ToHexString(d.Gate45.AsSpan(0, 12)),
                        ["comp4"] = d.Gate45.Length >= 28
                            ? Convert.ToHexString(d.Gate45.AsSpan(24, 4))
                            : "",
                        ["fc4"] = fc is { Length: >= 4 }
                            ? Convert.ToHexString(fc.AsSpan(0, 4))
                            : "",
                        ["fcEmbed"] = fc is not null
                            && UbChunkBuilder.GateEmbedsFileChecksum(d.Gate45, fc),
                        ["ctLen"] = d.CtLen,
                        ["h"] = hostCi,
                        ["head8"] = Convert.ToHexString(
                            gateCt.AsSpan(0, Math.Min(8, gateCt.Length))),
                        ["ikmOpens"] = fordIkm.Length > 0
                            && FordMmcsDecryptor.BlobOpensExactWithIkm(fordIkm, gateCt),
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
        }

        return any;
    }

    /// <summary>
    /// Disabilitato: non slicea Ford al CI.Offset (spill = body exact ctLen).
    /// </summary>
    private static bool TrySliceOwnedGateCiOffset(
        UbChunkBuilder.AuthFordDescriptor d,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> original,
        Dictionary<int, byte[]> bodies,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        int hostCi,
        out byte[] fordCt)
    {
        _ = d;
        _ = plan;
        _ = original;
        _ = bodies;
        _ = siblings;
        _ = hostCi;
        fordCt = [];
        return false;
    }

    private static HashSet<int> CollectRefHostIndices(AuthorizeGetDecryptPlan plan)
    {
        var set = new HashSet<int>();
        foreach (var r in plan.References)
            set.Add(r.ContainerIndex);
        return set;
    }

    /// <summary>
    /// Host HAS-Ford owned: CI45 incorpora FileChecksum (GateOwns).
    /// Senza FC: solo AG monofile (≤2 host).
    /// </summary>
    private static bool IsFileOwnedFordHost(
        int hostIndex,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> original,
        IReadOnlyList<UbChunkBuilder.AuthFordDescriptor> nestedDescs,
        HashSet<int> refHosts,
        byte[]? fileChecksum21)
    {
        _ = nestedDescs;
        _ = original;
        _ = refHosts;
        if ((uint)hostIndex >= (uint)plan.Containers.Count)
            return false;

        var group = plan.Containers[hostIndex];
        if (fileChecksum21 is { Length: 21 })
        {
            foreach (var ch in group)
            {
                if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                    && UbChunkBuilder.GateEmbedsFileChecksum(ch.Checksum21, fileChecksum21))
                    return true;
            }

            return false;
        }

        return plan.Containers.Count <= 2;
    }

    /// <summary>
    /// Descriptor Ford owned: gate incorpora FileChecksum (refs.field1).
    /// Senza FC: solo AG monofile — niente ownership per OID.
    /// </summary>
    private static bool IsFileOwnedFordDescriptor(
        UbChunkBuilder.AuthFordDescriptor d,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> original,
        HashSet<int> refHosts,
        byte[]? fileChecksum21)
    {
        _ = refHosts;
        if (fileChecksum21 is { Length: 21 } && d.Gate45.Length == 45)
        {
            if (!UbChunkBuilder.GateEmbedsFileChecksum(d.Gate45, fileChecksum21))
                return false;
            // FileGroup: gate deve essere CI45 su un host, oppure nested con OID host.
            // Nested empty-OID senza CI45 = gate di altri FileGroup nello stesso AG → skip.
            for (var i = 0; i < plan.Containers.Count; i++)
            {
                foreach (var ch in plan.Containers[i])
                {
                    if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                        && ch.Checksum21.Length == 45
                        && ch.Checksum21.AsSpan().SequenceEqual(d.Gate45))
                        return true;
                }
            }

            return !string.IsNullOrEmpty(d.ObjectId)
                   && TryFindChunkIndexByOid(original, d.ObjectId, out _);
        }

        return plan.Containers.Count <= 2;
    }

    private static AuthorizeGetCryptoChunk? SelectOwnedGateChunk(
        IReadOnlyList<AuthorizeGetCryptoChunk> group,
        byte[]? fileChecksum21)
    {
        if (fileChecksum21 is { Length: 21 })
        {
            foreach (var ch in group)
            {
                if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                    && UbChunkBuilder.GateEmbedsFileChecksum(ch.Checksum21, fileChecksum21))
                    return ch;
            }

            return null;
        }

        return group.FirstOrDefault(UbChunkBuilder.IsAuthFordDescriptorChunk);
    }

    private static bool TryFindChunkIndexByOid(
        IReadOnlyList<SignedUrlChunk> chunks,
        string oid,
        out int index)
    {
        for (var i = 0; i < chunks.Count; i++)
        {
            if (HostOidEquals(chunks, i, oid))
            {
                index = i;
                return true;
            }
        }

        index = -1;
        return false;
    }

    /// <summary>
    /// <c>stream.Read(ctLen)</c> sul body Auth dell'host Ford (<c>oid@{Auth.Start}</c>).
    /// Equivalente a head <c>body[0:ctLen]</c> sul ByteRange di quel storage — non pack inventato.
    /// Pack multi-gate: va via <c>gate:</c> cache (plant per-gate), non da qui.
    /// </summary>
    private static bool TryReadFordCtFromOidCache(
        string oid,
        int ctLen,
        int hostSizeHint,
        IReadOnlyList<SignedUrlChunk> original,
        int hostCi,
        Dictionary<int, byte[]> bodies,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        AuthorizeGetDecryptPlan plan,
        out byte[] fordCt)
    {
        fordCt = [];
        if (!UbChunkBuilder.IsPlausibleAuthFordCtLen(ctLen))
            return false;
        if ((uint)hostCi >= (uint)plan.Containers.Count)
            return false;
        //  OID spesso vuoto sui Ford — demux = gate/host stream, non richiede OID.

        var group = plan.Containers[hostCi];
        var isEmpty = group.Count == 0;
        var hasData = group.Any(UbChunkBuilder.IsAuthDataChunk);
        var isFordMaterial = isEmpty
                             || UbChunkBuilder.IsAuthFordMaterialHost(group)
                             || group.Any(UbChunkBuilder.IsAuthFordDescriptorChunk)
                             || UbChunkBuilder.IsFordSizedHostLengths(group);
        if (!isFordMaterial || hasData)
        {
            // #region agent log
            AgentLogFordRead("ford_read_reject_data_host", oid, hostCi, ctLen, 0, null);
            // #endregion
            return false;
        }

        var size0 = (uint)hostCi < (uint)original.Count
                    && string.Equals(
                        original[hostCi].EdgeHeaders?.MmcsContainerSize,
                        "0",
                        StringComparison.Ordinal);
        var fordOnly = group.Count > 0 && group.All(UbChunkBuilder.IsAuthFordDescriptorChunk);

        if (!TryGetHostBody(hostCi, bodies, original, siblings, out var hostBody)
            || hostBody.Length < ctLen)
        {
            // Solo Auth key esatta (oid@ o host:i@) — niente altre finestre.
            if (siblings is null
                || (uint)hostCi >= (uint)original.Count
                || original[hostCi].ByteRange is not { } abr)
                return false;
            var authKey = !string.IsNullOrEmpty(oid)
                ? $"{oid}@{abr.Start}"
                : $"host:{hostCi}@{abr.Start}";
            if (!siblings.TryGetValue(authKey, out var authEntry)
                || authEntry.Compact.Length < ctLen)
                return false;
            hostBody = authEntry.Compact;
        }

        //  solo body exact == ctLen (niente head[0:ctLen]).
        _ = isEmpty; _ = size0; _ = fordOnly; _ = hostSizeHint;
        if (hostBody.Length == ctLen && hostBody[0] == 0x04)
        {
            fordCt = hostBody;
            AgentLogFordRead("ford_read_exact_ctLen", oid, hostCi, ctLen, ctLen, fordCt);
            return true;
        }

        // #region agent log
        AgentLogFordRead("ford_read_need_gate_cache", oid, hostCi, ctLen, hostBody.Length, hostBody);
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = "ike-demux-align-v1",
                    ["hypothesisId"] = "H-DEMUX",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "FileGroupFillDecrypt.TryReadFordCtFromOidCache",
                    ["message"] = "need_gate_cache_multigate",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["oid8"] = oid.Length >= 8 ? oid[..8] : oid,
                        ["h"] = hostCi,
                        ["ctLen"] = ctLen,
                        ["bodyLen"] = hostBody.Length,
                        ["ciN"] = group.Count,
                        ["size0"] = size0,
                        ["fordOnly"] = fordOnly,
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
        return false;
    }

    /// <summary>
    /// <c>ChunkStream(.chunks/{gate45hex}).Read(ctLen)</c>:
    /// esattamente <paramref name="ctLen"/> byte dallo stream (prefix se file più lungo).
    /// </summary>
    private static bool TryReadFordCtFromGateCache(
        byte[] gate45,
        int ctLen,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        out byte[] fordCt)
    {
        fordCt = [];
        if (siblings is null || gate45.Length != 45 || !UbChunkBuilder.IsPlausibleAuthFordCtLen(ctLen))
            return false;
        var gateKey = "gate:" + Convert.ToHexString(gate45).ToLowerInvariant();
        if (!siblings.TryGetValue(gateKey, out var entry))
            return false;
        if (entry.Compact.Length < ctLen)
        {
            // #region agent log
            try
            {
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-DEMUX",
                        ["runId"] = "ike-demux-align-v1",
                        ["location"] = "FileGroupFillDecrypt.TryReadFordCtFromGateCache",
                        ["message"] = "gate_cache_short",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["gateHex12"] = Convert.ToHexString(gate45.AsSpan(0, 12)),
                            ["ctLen"] = ctLen,
                            ["entryLen"] = entry.Compact.Length,
                        },
                    }) + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            return false;
        }

        // spill file = exact ctLen. Niente prefix.
        if (entry.Compact.Length != ctLen || entry.Compact[0] != 0x04)
            return false;
        fordCt = entry.Compact;
        return true;
    }

    /// <summary>
    /// spill: body solo se Length == ctLen. Nessuno slice CI.Offset.
    /// </summary>
    private static bool TrySliceFordCtForGatePlant(
        byte[] body,
        AuthorizeGetCryptoChunk ch,
        int ctLen,
        long hostStart,
        long hostLen,
        long layoutOff,
        int chunkIndex,
        int ciCount,
        long layoutSum,
        bool fordOnly,
        bool size0,
        out byte[] fordSlice,
        out long plantOff,
        ReadOnlySpan<byte> fordIkm = default)
    {
        fordSlice = [];
        plantOff = -1;
        _ = ch; _ = hostStart; _ = hostLen; _ = layoutOff; _ = chunkIndex;
        _ = ciCount; _ = layoutSum; _ = fordOnly; _ = size0; _ = fordIkm;
        if (!UbChunkBuilder.IsPlausibleAuthFordCtLen(ctLen) || body.Length != ctLen || body[0] != 0x04)
            return false;
        fordSlice = body;
        plantOff = 0;
        return true;
    }

    public static Dictionary<string, (byte[] Compact, long MmcsStart)> EnrichSiblingChecksumCache(
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts,
        ReadOnlySpan<byte> authBody = default,
        ReadOnlySpan<byte> fordIkm = default)
    {
        var map = siblings is null
            ? new Dictionary<string, (byte[] Compact, long MmcsStart)>(StringComparer.Ordinal)
            : new Dictionary<string, (byte[] Compact, long MmcsStart)>(siblings, StringComparer.Ordinal);
        // storage+0x58: ctLen nested Auth (non CI.Length) per plant gate:.
        Dictionary<string, int>? nestedGateCt = null;
        if (authBody.Length > 0)
        {
            nestedGateCt = new Dictionary<string, int>(StringComparer.Ordinal);
            foreach (var d in UbChunkBuilder.ExtractAuthFordDescriptors(authBody))
            {
                if (d.Gate45.Length != 45 || !UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen))
                    continue;
                nestedGateCt[Convert.ToHexString(d.Gate45).ToLowerInvariant()] = d.CtLen;
            }
        }

        var planted = PlantAuthChecksumSlicesIntoMap(
            map, plan, hosts, map, nestedGateCt, fordIkm);
        // Ford: SpillOpen exact/wire/packScan(IKM).
        if (authBody.Length > 0)
            planted += LiveFillPipeline.PutChunksFromHostBodies(
                map, plan, hosts, authBody.ToArray(), fordIkm);
        // #region agent log
        if (planted > 0)
        {
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-NODATA-SIB",
                    ["runId"] = LiveFillPipeline.RunId,
                    ["location"] = "FileGroupFillDecrypt.EnrichSiblingChecksumCache",
                    ["message"] = "plant_sig_putchunks_only",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["planted"] = planted,
                        ["mapCount"] = map.Count,
                        ["oidN"] = map.Keys.Count(static k =>
                            k.Contains('@', StringComparison.Ordinal)
                            && !k.StartsWith("sig:", StringComparison.Ordinal)
                            && !k.StartsWith("gate:", StringComparison.Ordinal)),
                        ["gateN"] = map.Keys.Count(static k => k.StartsWith("gate:", StringComparison.Ordinal)),
                        ["sigN"] = map.Keys.Count(static k => k.StartsWith("sig:", StringComparison.Ordinal)),
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
        }
        // #endregion
        return map;
    }

    /// <summary>
    /// PutChunk / CChunkCache: data → <c>sig:</c> (layout pack Auth).
    /// Ford CI45: non piantare qui — solo <see cref="LiveFillPipeline.PutChunksFromHostBodies"/>.
    /// Con <paramref name="fordIkm"/> scarta slice il cui prefisso apre come Ford (wireOff poison).
    /// <paramref name="overwriteChunkFiles"/>: MAC-retry — bypass first-wins su lead-04.
    /// </summary>
    public static int PlantAuthChecksumSlicesIntoMap(
        IDictionary<string, (byte[] Compact, long MmcsStart)> map,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> hostBodies,
        IReadOnlyDictionary<string, int>? nestedGateCtLen = null,
        ReadOnlySpan<byte> fordIkm = default,
        bool overwriteChunkFiles = false)
    {
        var planted = 0;
        // FL / pipe-C (no Ford): data spesso lead≠0x04.
        // Class B: solo il CI in plan.References su host esatto (body==CI==auth) —
        // non gli altri host del pack condiviso (poison → MAC20).
        var flStyleNoFord = !PlanHasAnyFordDescriptor(plan);
        var fordCtLens = CollectFordCtLens(plan);
        for (var i = 0; i < plan.Containers.Count && i < hosts.Count; i++)
        {
            if (hosts[i].ByteRange is not { } br)
                continue;
            var oid = hosts[i].EdgeHeaders?.ObjectId ?? "";
            var hk = !string.IsNullOrEmpty(oid)
                ? $"{oid}@{br.Start}"
                : $"host:{i}@{br.Start}";
            if (!hostBodies.TryGetValue(hk, out var hb) || hb.Compact.Length == 0)
            {
                // Nessun oid@exactStart: prova ricucire da pezzi overlapping (GET spezzati).
                if (string.IsNullOrEmpty(oid))
                    continue;
                var authLenMiss = br.End - br.Start + 1;
                if (!TryAssembleHostBodyFromMap(hostBodies, oid, br.Start, authLenMiss, out hb))
                    continue;
            }

            var group = plan.Containers[i];
            long layoutSum = 0;
            foreach (var c in group)
                layoutSum += c.Length;
            if (layoutSum <= 0 && group.Count > 0)
                continue;

            var body = hb.Compact;
            var authLen = br.End - br.Start + 1;
            // Solo se un CI non ci sta nel frammento (Offset oltre bodyLen) —
            // es. Auth 0-479 con GET spezzati @0=112+@112=… (3072). Non ricucire
            // ogni host corto: mescola range data alieni e avvelena il gate.
            var needsSpan = body.Length < authLen
                            && group.Any(ch =>
                                ch.Length > 0 && ch.Offset + ch.Length > body.Length);
            if (needsSpan
                && TryAssembleHostBodyFromMap(hostBodies, oid, br.Start, authLen, out var assembled)
                && assembled.Compact.Length == authLen)
            {
                body = assembled.Compact;
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-RES3",
                        ["runId"] = "assemble-host-v2",
                        ["location"] = "FileGroupFillDecrypt.PlantAuthChecksumSlicesIntoMap",
                        ["message"] = "assembled_auth_host_span",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["h"] = i,
                            ["oid"] = oid.Length > 12 ? oid[..12] : oid,
                            ["start"] = br.Start,
                            ["authLen"] = authLen,
                            ["fragLen"] = hb.Compact.Length,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
            }

            long hostLen = body.Length;
            if (body.Length == authLen)
                hostLen = authLen;
            var hostStart = br.Start;

            var size0 = string.Equals(
                hosts[i].EdgeHeaders?.MmcsContainerSize, "0", StringComparison.Ordinal);
            var fordMaterial = group.Count == 0
                               || UbChunkBuilder.IsAuthFordMaterialHost(group)
                               || UbChunkBuilder.IsFordSizedHostLengths(group)
                               || size0;
            var hasData = group.Any(UbChunkBuilder.IsAuthDataChunk);
            var hasGate = group.Any(UbChunkBuilder.IsAuthFordDescriptorChunk);
            var mixedDataFord = hasData && hasGate;
            var fordOnly = hasGate && !hasData && group.Count > 0;

            var layoutOff = 0;
            for (var j = 0; j < group.Count; j++)
            {
                var ch = group[j];
                // Data only: Auth ChunkInfo.Offset/Length nel body del FileGroup già GET.
                // Non inventa Ford. Ford CI45 → solo LiveFillPipeline (body==ctLen).
                if (ch.Checksum21 is { Length: 21 } && ch.Length > 0)
                {
                    var wireOff = UbChunkBuilder.ResolveCiWireInHostBody(
                        ch.Offset, ch.Length, hostStart, hostLen,
                        layoutOff, j, group.Count, layoutSum, fordOnlyHost: false);
                    if (wireOff >= 0 && wireOff + ch.Length <= body.Length)
                    {
                        var slice = body.AsSpan((int)wireOff, ch.Length).ToArray();
                        var sigKey = "sig:" + Convert.ToHexString(ch.Checksum21).ToLowerInvariant();
                        var exactHost = IsExactAuthDataHost(ch, body.Length, authLen);
                        var isRefCi = IsReferencedDataChunk(plan, i, j);
                        // live (2026-10-09): data CI sotto hex(checksum21) anche con
                        // lead≠0x04 (es. C4D2…). 0x04 = Ford CT tipico, non gate data.
                        // Anti-poison: solo IsFordPrefixPoison (slice == Ford CT / gate).
                        _ = exactHost;
                        _ = isRefCi;
                        _ = flStyleNoFord;
                        if (UbChunkBuilder.IsAuthDataChunk(ch)
                                 && IsFordPrefixPoison(slice, fordIkm, fordCtLens))
                        {
                            // #region agent log
                            AgentLogDataSlice(
                                "data_plant_skip_ford_prefix",
                                i, j, (int)wireOff, ch.Length, body.Length, authLen,
                                CountSameLengthDataCi(plan, ch.Length), slice);
                            // #endregion
                            map.Remove(sigKey);
                            if (overwriteChunkFiles)
                                ChunkFileCache.TryDelete(ch.Checksum21);
                        }
                        else if (map.TryGetValue(sigKey, out var cur)
                                 && cur.Compact.Length == slice.Length
                                 && LooksLikeMmcsDataCipher(cur.Compact)
                                 && !LooksLikeMmcsDataCipher(slice)
                                 && !IsFordPrefixPoison(cur.Compact, fordIkm, fordCtLens)
                                 && !overwriteChunkFiles)
                        {
                            // Preferisci un 04 già buono su un non-04 ambiguo (stessa len).
                            // #region agent log
                            AgentLogDataSlice(
                                "data_plant_keep_good",
                                i, j, (int)wireOff, ch.Length, body.Length, authLen,
                                CountSameLengthDataCi(plan, ch.Length), cur.Compact);
                            // #endregion
                        }
                        else
                        {
                            map[sigKey] = (slice, 0L);
                            // Class B: sopravvive a siblingCompacts.Clear / ReleaseDataChunks
                            // (retry cross-batch: Ford in .chunks sì, sig: map no → ike-no-data).
                            if (overwriteChunkFiles)
                                ChunkFileCache.PutOverwrite(ch.Checksum21, slice);
                            else
                                ChunkFileCache.Put(ch.Checksum21, slice);
                            planted++;
                            // #region agent log
                            AgentLogDataSlice(
                                LooksLikeMmcsDataCipher(slice)
                                    ? "data_plant_ok_04"
                                    : "data_plant_ok_non04",
                                i, j, (int)wireOff, ch.Length, body.Length, authLen,
                                CountSameLengthDataCi(plan, ch.Length), slice);
                            // #endregion
                        }
                    }
                }
                else if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch))
                {
                    _ = fordMaterial;
                    _ = mixedDataFord;
                    _ = fordOnly;
                    _ = nestedGateCtLen;
                }

                layoutOff += Math.Max(0, ch.Length);
            }

            // Empty / size0 senza CI in plan: se body == ctLen tipico, non abbiamo gate45 qui.
            _ = fordMaterial;
        }

        // Descriptor Auth: plant gate miss da OID Ford-material (Read(ctLen)).
        // (chiamato anche da Enrich con authBody via PlantGatesFromAuthDescriptors)
        return planted;
    }

    /// <summary>
    /// Ricuce <c>[start, start+len)</c> sull'ObjectID da pezzi <c>oid@*</c> già in mappa
    /// (GET edge spezzati vs ByteRange Auth contiguo — ike_run 3072).
    /// </summary>
    public static bool TryAssembleHostBodyFromMap(
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> hostBodies,
        string oid,
        long start,
        long len,
        out (byte[] Compact, long MmcsStart) assembled)
    {
        assembled = default;
        if (string.IsNullOrEmpty(oid) || len <= 0 || len > 64L * 1024 * 1024)
            return false;

        var buf = new byte[len];
        var filled = new bool[len];
        var any = false;
        var prefix = oid + "@";
        foreach (var kv in hostBodies)
        {
            if (!kv.Key.StartsWith(prefix, StringComparison.Ordinal))
                continue;
            var piece = kv.Value.Compact;
            if (piece is not { Length: > 0 })
                continue;
            var pieceStart = kv.Value.MmcsStart;
            // Se MmcsStart non affidabile, parse dalla chiave.
            var at = kv.Key.LastIndexOf('@');
            if (at > 0 && long.TryParse(kv.Key.AsSpan(at + 1), out var keyStart))
                pieceStart = keyStart;
            var pieceEnd = pieceStart + piece.Length;
            var spanEnd = start + len;
            if (pieceEnd <= start || pieceStart >= spanEnd)
                continue;
            var copyFrom = Math.Max(pieceStart, start);
            var copyTo = Math.Min(pieceEnd, spanEnd);
            var srcOff = (int)(copyFrom - pieceStart);
            var dstOff = (int)(copyFrom - start);
            var n = (int)(copyTo - copyFrom);
            if (srcOff < 0 || dstOff < 0 || n <= 0 || srcOff + n > piece.Length || dstOff + n > buf.Length)
                continue;
            Buffer.BlockCopy(piece, srcOff, buf, dstOff, n);
            for (var i = 0; i < n; i++)
                filled[dstOff + i] = true;
            any = true;
        }

        if (!any)
            return false;
        for (var i = 0; i < filled.Length; i++)
        {
            if (!filled[i])
                return false;
        }

        assembled = (buf, start);
        return true;
    }

    /// <summary>
    /// Gate nested Auth: se <c>gate:</c> manca, <c>Read(ctLen)</c> dal body OID Ford-material.
    /// Non sovrascrive Put già presente (es. fordDump oracle / Put precedente).
    /// </summary>
    private static int PlantGatesFromAuthDescriptors(
        IDictionary<string, (byte[] Compact, long MmcsStart)> map,
        ReadOnlySpan<byte> authBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> hostBodies,
        ReadOnlySpan<byte> fordIkm = default)
    {
        var planted = 0;
        var descs = UbChunkBuilder.ExtractAuthFordDescriptors(authBody);
        foreach (var d in descs)
        {
            if (d.Gate45.Length != 45 || !UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen))
                continue;
            var gk = "gate:" + Convert.ToHexString(d.Gate45).ToLowerInvariant();
            if (ChunkFileCache.TryRead(d.Gate45, d.CtLen, out var diskCt)
                && diskCt.Length == d.CtLen
                && diskCt[0] == 0x04
                && (fordIkm.IsEmpty
                    || FordMmcsDecryptor.BlobOpensExactWithIkm(fordIkm, diskCt)))
            {
                map[gk] = (diskCt, 0L);
                planted++;
                continue;
            }

            // Cache head-04 che non apre con IKM: non riusarla come gate.
            if (!fordIkm.IsEmpty
                && ChunkFileCache.TryRead(d.Gate45, d.CtLen, out _))
                ChunkFileCache.TryDelete(d.Gate45);

            // Solo entry esatta ctLen = PutChunk. Body più lungo = plant sbagliato: ripianta.
            if (map.TryGetValue(gk, out var ex) && ex.Compact.Length == d.CtLen)
                continue;

            // 1) Host FileGroup che contiene il gate ( qualsiasi host del plan).
            for (var i = 0; i < plan.Containers.Count && i < hosts.Count; i++)
            {
                var group = plan.Containers[i];
                var fordCi = -1;
                for (var j = 0; j < group.Count; j++)
                {
                    var ch = group[j];
                    if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                        && ch.Checksum21.Length == 45
                        && ch.Checksum21.AsSpan().SequenceEqual(d.Gate45))
                    {
                        fordCi = j;
                        break;
                    }
                }

                // Empty host: match per OID nested (sotto). Con CI serve il gate nel group.
                if (fordCi < 0 && group.Count > 0)
                    continue;
                if (hosts[i].ByteRange is not { } br)
                    continue;
                var oid = hosts[i].EdgeHeaders?.ObjectId ?? "";
                //  OID può essere vuoto — prova oid@ poi host:i@.
                (byte[] Compact, long MmcsStart) hb = default;
                var haveHb = false;
                if (!string.IsNullOrEmpty(oid)
                    && hostBodies.TryGetValue($"{oid}@{br.Start}", out hb)
                    && hb.Compact.Length >= d.CtLen)
                    haveHb = true;
                else if (hostBodies.TryGetValue($"host:{i}@{br.Start}", out hb)
                         && hb.Compact.Length >= d.CtLen)
                    haveHb = true;
                if (!haveHb)
                    continue;

                // Path 1: CI45 — SpillOpen exact | Read @ Auth ChunkInfo.Offset (probe).
                var idx = fordCi >= 0 ? fordCi : 0;
                AuthorizeGetCryptoChunk? gateCh = idx < group.Count ? group[idx] : null;
                if (ChunkFileCache.TryRead(d.Gate45, d.CtLen, out var fromFile))
                {
                    map[gk] = (fromFile, 0L);
                    planted++;
                    goto NextDesc;
                }

                byte[]? fordSlice = null;
                var how = "";
                if (gateCh is not null)
                {
                    var authLen = br.End - br.Start + 1;
                    if (LiveFillPipeline.TryMaterializeFordCt(
                            hb.Compact, authLen, d.CtLen, gateCh.Offset, br.Start, idx,
                            out fordSlice, out how, fordIkm))
                    {
                        /* ok */
                    }
                    else
                        fordSlice = null;
                }

                if (fordSlice is null)
                    continue;
                ChunkFileCache.PutOverwrite(d.Gate45, fordSlice);
                map[gk] = (fordSlice, 0L);
                planted++;
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H1",
                        ["runId"] = LiveFillPipeline.RunId,
                        ["location"] = "FileGroupFillDecrypt.PlantGatesFromAuthDescriptors",
                        ["message"] = "gate_put_spill",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["ctLen"] = d.CtLen,
                            ["bodyLen"] = hb.Compact.Length,
                            ["how"] = how,
                            ["gate8"] = Convert.ToHexString(d.Gate45.AsSpan(0, 8)),
                            ["head8"] = Convert.ToHexString(
                                fordSlice.AsSpan(0, Math.Min(8, fordSlice.Length))),
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                goto NextDesc;
            }

            // 2) Match per OID descriptor (empty / size0 / ford-sized).
            if (string.IsNullOrEmpty(d.ObjectId))
                continue;
            for (var i = 0; i < hosts.Count; i++)
            {
                if (!string.Equals(
                        hosts[i].EdgeHeaders?.ObjectId, d.ObjectId, StringComparison.Ordinal))
                    continue;
                var group = (uint)i < (uint)plan.Containers.Count
                    ? plan.Containers[i]
                    : Array.Empty<AuthorizeGetCryptoChunk>();
                if (group.Any(UbChunkBuilder.IsAuthDataChunk))
                    continue;
                var size0 = string.Equals(
                    hosts[i].EdgeHeaders?.MmcsContainerSize, "0", StringComparison.Ordinal);
                var fordMaterial = group.Count == 0
                                   || UbChunkBuilder.IsAuthFordMaterialHost(group)
                                   || UbChunkBuilder.IsFordSizedHostLengths(group)
                                   || size0;
                if (!fordMaterial)
                    continue;
                if (hosts[i].ByteRange is not { } br)
                    continue;
                var hk = $"{d.ObjectId}@{br.Start}";
                if (!hostBodies.TryGetValue(hk, out var hb) || hb.Compact.Length < d.CtLen)
                    continue;
                //  exact GET == Auth ctLen only (no size0 head slice).
                // Con IKM: non piantare CT che non apre (evita poison .chunks).
                if (hb.Compact.Length != d.CtLen || hb.Compact[0] != 0x04)
                    continue;
                if (fordIkm.Length > 0
                    && !FordMmcsDecryptor.BlobOpensExactWithIkm(fordIkm, hb.Compact))
                    continue;
                ChunkFileCache.PutOverwrite(d.Gate45, hb.Compact);
                map[gk] = (hb.Compact, 0L);
                planted++;
                break;
            }

            NextDesc: ;
        }

        return planted;
    }

    /// <summary>
    /// Host Auth Ford per gate/OID — mai il data-ref host.
    /// </summary>
    private static bool TryFindFordHostForGate(
        UbChunkBuilder.AuthFordDescriptor d,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> original,
        out int hostCi,
        out string oid)
    {
        hostCi = -1;
        oid = d.ObjectId ?? "";

        for (var i = 0; i < plan.Containers.Count; i++)
        {
            var group = plan.Containers[i];
            foreach (var ch in group)
            {
                if (!UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                    || ch.Checksum21.Length != 45
                    || d.Gate45.Length != 45
                    || !ch.Checksum21.AsSpan().SequenceEqual(d.Gate45))
                    continue;
                hostCi = i;
                var hostOid = HostOid(original, i);
                if (!string.IsNullOrEmpty(hostOid))
                    oid = hostOid;
                return true;
            }
        }

        if (string.IsNullOrEmpty(d.ObjectId))
            return false;

        for (var i = 0; i < plan.Containers.Count && i < original.Count; i++)
        {
            if (!string.Equals(
                    original[i].EdgeHeaders?.ObjectId, d.ObjectId, StringComparison.Ordinal))
                continue;
            var g = plan.Containers[i];
            if (g.Count == 0
                || UbChunkBuilder.IsAuthFordMaterialHost(g)
                || g.Any(UbChunkBuilder.IsAuthFordDescriptorChunk)
                || UbChunkBuilder.IsFordSizedHostLengths(g)
                || string.Equals(
                    original[i].EdgeHeaders?.MmcsContainerSize, "0", StringComparison.Ordinal))
            {
                hostCi = i;
                oid = d.ObjectId;
                return true;
            }
        }

        return false;
    }

    // #region agent log
    private static void AgentLogFordRead(
        string message,
        string? oid,
        int hostCi,
        int ctLen,
        int bodyLen,
        byte[]? sample)
    {
        try
        {
            var o = oid ?? "";
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-FORD-IKE",
                ["runId"] = "ford-ike-v1",
                ["location"] = "FileGroupFillDecrypt.TryReadFordCtFromOidCache",
                ["message"] = message,
                ["data"] = new Dictionary<string, object?>
                {
                    ["oid"] = o.Length > 16 ? o[..16] : o,
                    ["h"] = hostCi,
                    ["ctLen"] = ctLen,
                    ["bodyLen"] = bodyLen,
                    ["head8"] = sample is { Length: > 0 }
                        ? Convert.ToHexString(sample.AsSpan(0, Math.Min(8, sample.Length)))
                        : null,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
    }
    // #endregion

    private static bool HostBodyIsOnlyDataCi(
        AuthorizeGetDecryptPlan plan,
        int hostCi,
        int bodyLen)
    {
        if ((uint)hostCi >= (uint)plan.Containers.Count)
            return false;
        var g = plan.Containers[hostCi];
        if (g.Count == 0 || !g.All(UbChunkBuilder.IsAuthDataChunk))
            return false;
        var dataLen = 0;
        foreach (var c in g)
            dataLen += c.Length;
        return dataLen == bodyLen;
    }

    /// <summary>Disabilitato: non demuxa Ford da finestre adjacent / oid@* len==ctLen.</summary>
    private static bool TryReadImpliedAdjacentFordCt(
        string oid,
        int ctLen,
        IReadOnlyList<SignedUrlChunk> original,
        int hostCi,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        out byte[] fordCt)
    {
        fordCt = [];
        _ = oid;
        _ = ctLen;
        _ = original;
        _ = hostCi;
        _ = siblings;
        return false;
    }

    private static bool IsPlanRefHost(AuthorizeGetDecryptPlan plan, int containerIndex)
    {
        foreach (var r in plan.References)
        {
            if (r.ContainerIndex == containerIndex)
                return true;
        }

        return false;
    }

    private static bool TryFindFirstRefHost(AuthorizeGetDecryptPlan plan, out int containerIndex)
    {
        containerIndex = -1;
        foreach (var r in plan.References)
        {
            containerIndex = r.ContainerIndex;
            return true;
        }

        return false;
    }

    /// <summary><c>cache[oid].Read(0, ctLen)</c> — nessun demux / magic-byte.</summary>
    private static bool TryReadFordCtFromCache(
        string oid,
        int ctLen,
        IReadOnlyList<SignedUrlChunk> original,
        int hostCi,
        Dictionary<int, byte[]> bodies,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        out byte[] fordCt)
    {
        fordCt = [];
        if (!UbChunkBuilder.IsPlausibleAuthFordCtLen(ctLen))
            return false;

        if (TryGetHostBody(hostCi, bodies, original, siblings, out var hostBody)
            && hostBody.Length == ctLen
            && hostBody[0] == 0x04)
        {
            fordCt = hostBody;
            return true;
        }

        if (siblings is null || string.IsNullOrEmpty(oid))
            return false;

        var prefix = oid + "@";
        foreach (var (key, (blob, _)) in siblings)
        {
            if (!key.StartsWith(prefix, StringComparison.Ordinal))
                continue;
            if (blob.Length != ctLen)
                continue;
            fordCt = blob;
            return true;
        }

        // Vietato: inventare CT da oid@(dataStart-ctLen) / head slice.
        _ = original;
        _ = hostCi;
        return false;
    }

    /// <summary>
    /// FillChunks per storage sullo stesso chunkMap
    /// (<c>fillchunks_pipelines_oracle.md</c>):
    /// HAS-Ford → Pipe A (DecryptFordKeys + inject zip);
    /// fordSize=0 → Pipe B. Ordine: Ford storages poi data.
    /// </summary>
    private readonly record struct FillTrace(
        int FordOpen,
        int FordSkip,
        int PipeA,
        int PipeB,
        int KeyedNodes,
        int NodeCount,
        byte[]? Plaintext,
        string Note,
        string FailReason,
        byte[]? BestFordCt,
        IReadOnlyList<FordMmcsDecryptor.FordChunkKey>? BestKeys);

    private static FillTrace FillChunksPerStorageAndDecryptTrace(
        ReadOnlySpan<byte> fordIkm,
        IReadOnlyList<BoundStorage> storages,
        IReadOnlyList<byte[]> dataChunks,
        AuthorizeGetDecryptPlan plan,
        byte[]? mmcsKek16)
    {
        var tree = new ChunkTree();
        var pipeA = 0;
        var pipeB = 0;
        var fordOpen = 0;
        var fordSkip = 0;
        string? lastFordNote = null;
        var pipes = new List<string>(storages.Count);
        IReadOnlyList<FordMmcsDecryptor.FordChunkKey>? bestKeys = null;
        byte[]? bestFordCt = null;

        //  FillChunks #1 HAS-Ford → DecryptFordKeys+inject; #2 data → Pipe B.
        var ordered = new List<BoundStorage>(storages.Count);
        foreach (var s in storages)
        {
            if (s.HasFord && s.FordCt is { Length: > 0 })
                ordered.Add(s);
        }

        foreach (var s in storages)
        {
            if (!s.HasFord || s.FordCt is not { Length: > 0 })
                ordered.Add(s);
        }

        foreach (var storage in ordered)
        {
            if (storage.HasFord && storage.FordCt is { Length: > 0 })
            {
                if (fordIkm.Length == 0
                    || !FordMmcsDecryptor.TryCollectFordKeysStrict(
                        fordIkm, storage.FordCt, out var opened)
                    || opened.Count == 0)
                {
                    fordSkip++;
                    // #region agent log
                    try
                    {
                        var blobOpens = fordIkm.Length > 0
                            && FordMmcsDecryptor.BlobOpensExactWithIkm(fordIkm, storage.FordCt);
                        var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "03cce7",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["hypothesisId"] = "H-FORD-CT",
                            ["runId"] = "ike-algo-v1",
                            ["location"] = "FileGroupFillDecrypt.FillChunksPerStorageAndDecryptTrace",
                            ["message"] = "ford_skip_ikm_ford_mismatch",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["h"] = storage.ContainerIndex,
                                ["note"] = storage.Note,
                                ["fordLen"] = storage.FordCt.Length,
                                ["fordHead8"] = Convert.ToHexString(
                                    storage.FordCt.AsSpan(0, Math.Min(8, storage.FordCt.Length))),
                                ["fordSha8"] = Convert.ToHexString(
                                    System.Security.Cryptography.SHA256.HashData(storage.FordCt).AsSpan(0, 8)),
                                ["ikmLen"] = fordIkm.Length,
                                ["ikmHead8"] = fordIkm.Length >= 8
                                    ? Convert.ToHexString(fordIkm[..8])
                                    : "",
                                ["blobOpens"] = blobOpens,
                            },
                        });
                        File.AppendAllText(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                            line + Environment.NewLine);
                    }
                    catch { /* ignore */ }
                    // #endregion
                    continue;
                }

                fordOpen++;
                lastFordNote = storage.Note;
                bestKeys = opened;
                bestFordCt = storage.FordCt;
                pipes.Add(tree.FillChunks(plan, opened));
                pipeA++;
                // #region agent log
                try
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["hypothesisId"] = "H-PER-STORAGE",
                        ["runId"] = "ike-algo-v1",
                        ["location"] = "FileGroupFillDecrypt.FillChunksPerStorageAndDecryptTrace",
                        ["message"] = "ford_storage_pipe_a",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["h"] = storage.ContainerIndex,
                            ["note"] = storage.Note,
                            ["keyN"] = opened.Count,
                            ["fordLen"] = storage.FordCt.Length,
                            ["pipeA"] = pipeA,
                            ["keyed"] = tree.CountNodesWithFordKeys(),
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                continue;
            }

            pipes.Add(tree.FillChunks(plan, fordKeys: null));
            pipeB++;
        }

        if (pipeB == 0)
        {
            pipes.Add(tree.FillChunks(plan, fordKeys: null));
            pipeB++;
        }

        var nodeCount = tree.Count;
        var keyed = tree.CountNodesWithFordKeys();
        var fillNote =
            $"fill pipeA={pipeA} pipeB={pipeB} fordOpen={fordOpen} fordSkip={fordSkip} " +
            $"keyed={keyed} nodes={nodeCount} ford=[{lastFordNote ?? "none"}] " +
            $"pipes=[{string.Join(',', pipes)}]";

        bestFordCt ??= storages
            .FirstOrDefault(static s => s.HasFord && s.FordCt is { Length: > 0 }).FordCt;

        if (dataChunks.Count != plan.References.Count)
        {
            tree.Clear();
            return new FillTrace(
                fordOpen, fordSkip, pipeA, pipeB, keyed, nodeCount, null,
                $"{fillNote} | FillChunks data attach: slices={dataChunks.Count} refs={plan.References.Count}",
                "ike-fillchunks", bestFordCt, bestKeys);
        }

        tree.AttachDataSlices(dataChunks.ToList());

        var pipeCNodes = tree.CountNodesWithChunkEncryptionKeys();
        if (!tree.EveryNodeHasDecryptMaterial())
        {
            // #region agent log
            try
            {
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-ike-align",
                    ["location"] = "FileGroupFillDecrypt.FillChunks",
                    ["message"] = "fordOpen_zero_pipeB_miss",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["fordOpen"] = fordOpen,
                        ["fordSkip"] = fordSkip,
                        ["keyed"] = keyed,
                        ["pipeC"] = pipeCNodes,
                        ["nodes"] = nodeCount,
                        ["fordNote"] = lastFordNote,
                        ["refs"] = plan.References.Count,
                        ["storages"] = storages.Count,
                        ["planPipeC"] = PlanHasChunkEncryptionKeys(plan),
                        ["hasKek"] = mmcsKek16 is { Length: 16 },
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            tree.Clear();
            var failCode = fordOpen == 0 && fordSkip > 0 && fordIkm.Length > 0
                ? "ike-ford-ikm-mismatch"
                : "ike-fillchunks";
            return new FillTrace(
                fordOpen, fordSkip, pipeA, pipeB, keyed, nodeCount, null,
                $"{fillNote} | MUT ChunkDecrypt: Pipe B miss keyed={keyed} pipeC={pipeCNodes} " +
                $"nodes={nodeCount} (fordOpen={fordOpen} fordSkip={fordSkip})",
                failCode, bestFordCt, bestKeys);
        }

        try
        {
            var plain = tree.DecryptAssembleMut(mmcsKek16);
            tree.Clear();
            return new FillTrace(
                fordOpen, fordSkip, pipeA, pipeB, keyed, nodeCount, plain, fillNote, "",
                bestFordCt, bestKeys);
        }
        catch (Exception ex)
        {
            // #region agent log
            try
            {
                string? dataHead = dataChunks.Count > 0
                    ? Convert.ToHexString(dataChunks[0].AsSpan(0, Math.Min(8, dataChunks[0].Length)))
                    : null;
                int? hint = bestKeys is { Count: > 0 } ? bestKeys[0].ChunkLengthHint : null;
                var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["hypothesisId"] = "H-MAC-KEY",
                    ["runId"] = "identity-v2",
                    ["location"] = "FileGroupFillDecrypt.FillChunks",
                    ["message"] = "chunkdecrypt_fail",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["err"] = Clip(ex.Message),
                        ["fordOpen"] = fordOpen,
                        ["fordSkip"] = fordSkip,
                        ["fordNote"] = lastFordNote,
                        ["pickMode"] = "per-storage",
                        ["keyN"] = bestKeys?.Count ?? 0,
                        ["hint"] = hint,
                        ["data0Len"] = dataChunks.Count > 0 ? dataChunks[0].Length : 0,
                        ["data0Head8"] = dataHead,
                        ["ref0"] = plan.References.Count > 0
                            ? $"{plan.References[0].ContainerIndex}:{plan.References[0].ChunkIndex}"
                            : null,
                    },
                });
                File.AppendAllText(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                    line + Environment.NewLine);
            }
            catch { /* ignore */ }
            // #endregion
            tree.ClearDataSlicesOnly();
            tree.Clear();
            return new FillTrace(
                fordOpen, fordSkip, pipeA, pipeB, keyed, nodeCount, null,
                $"{fillNote} | {Clip(ex.Message)}",
                "ike-fillchunks", bestFordCt, bestKeys);
        }
    }

    private static string HostOid(IReadOnlyList<SignedUrlChunk> original, int index)
    {
        if ((uint)index >= (uint)original.Count)
            return "";
        return original[index].EdgeHeaders?.ObjectId ?? "";
    }


    private static bool TryFindPlanHostByOid(
        IReadOnlyList<SignedUrlChunk> original,
        AuthorizeGetDecryptPlan plan,
        string oid,
        out int containerIndex)
    {
        containerIndex = -1;
        var n = Math.Min(plan.Containers.Count, original.Count);
        for (var i = 0; i < n; i++)
        {
            if (!HostOidEquals(original, i, oid))
                continue;
            containerIndex = i;
            return true;
        }

        return false;
    }

    /// <summary>
    /// ctLen empty-host: nested Auth OID → <c>storage+0x58</c>; altrimenti body = CT puro
    /// (solo lunghezze Ford standard — mai body arbitrario).
    /// </summary>
    private static int ResolveEmptyHostCtLen(
        IReadOnlyList<UbChunkBuilder.AuthFordDescriptor> descs,
        IReadOnlyList<SignedUrlChunk> original,
        int containerIndex,
        int bodyLen)
    {
        foreach (var d in descs)
        {
            if (!UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen) || d.CtLen > bodyLen)
                continue;
            if (string.IsNullOrEmpty(d.ObjectId)
                || HostOidEquals(original, containerIndex, d.ObjectId))
                return d.CtLen;
        }

        // Empty GET = CT puro = Auth ctLen (live 112 / 155 / 224 / 234 / …).
        if (UbChunkBuilder.IsPlausibleAuthFordCtLen(bodyLen))
            return bodyLen;

        return 0;
    }

    /// <summary>
    /// Body del container host: = solo buffer per OID (<c>oid@{Start}</c>).
    /// Niente compact concatenato.
    /// </summary>
    private static bool TryGetHostBody(
        int containerIndex,
        Dictionary<int, byte[]> bodies,
        IReadOnlyList<SignedUrlChunk> original,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        out byte[] body)
    {
        if (bodies.TryGetValue(containerIndex, out var fromMap) && fromMap.Length > 0)
        {
            body = fromMap;
            return true;
        }

        if (siblings is not null
            && (uint)containerIndex < (uint)original.Count
            && original[containerIndex].ByteRange is { } br)
        {
            var oid = original[containerIndex].EdgeHeaders?.ObjectId ?? "";
            if (!string.IsNullOrEmpty(oid))
            {
                var key = $"{oid}@{br.Start}";
                if (siblings.TryGetValue(key, out var entry) && entry.Compact.Length > 0)
                {
                    body = entry.Compact;
                    return true;
                }
            }

            // Ford OID-vuoto: body keyed per host index (seed post-GET).
            var hostKey = $"host:{containerIndex}@{br.Start}";
            if (siblings.TryGetValue(hostKey, out var hostEntry) && hostEntry.Compact.Length > 0)
            {
                body = hostEntry.Compact;
                return true;
            }
        }

        body = [];
        return false;
    }

    /// <summary>
    /// Mappa containerIndex → body host da sibling <c>oid@{Start}</c> soltanto.
    /// </summary>
    private static Dictionary<int, byte[]> BuildHostBodies(
        IReadOnlyList<SignedUrlChunk> original,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        ReadOnlySpan<byte> compact,
        IReadOnlyList<SignedUrlChunk> ordered)
    {
        _ = compact;
        _ = ordered;
        var map = new Dictionary<int, byte[]>();
        var fromSibling = 0;
        for (var i = 0; i < original.Count; i++)
        {
            if (original[i].ByteRange is not { } br || siblings is null)
                continue;
            var oid = original[i].EdgeHeaders?.ObjectId ?? "";
            var key = !string.IsNullOrEmpty(oid)
                ? $"{oid}@{br.Start}"
                : $"host:{i}@{br.Start}";
            if (!siblings.TryGetValue(key, out var entry) || entry.Compact.Length == 0)
                continue;
            map[i] = entry.Compact;
            fromSibling++;
        }

        // #region agent log
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-COMPACT",
                ["runId"] = "per-host-no-fallback",
                ["location"] = "FileGroupFillDecrypt.BuildHostBodies",
                ["message"] = "host_bodies_sibling_only",
                ["data"] = new Dictionary<string, object?>
                {
                    ["fromSibling"] = fromSibling,
                    ["mapCount"] = map.Count,
                    ["ignoredCompactLen"] = compact.Length,
                    ["original"] = original.Count,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        return map;
    }

    private static bool HostOidEquals(
        IReadOnlyList<SignedUrlChunk> original,
        int index,
        string oid)
    {
        if ((uint)index >= (uint)original.Count)
            return false;
        return string.Equals(
            original[index].EdgeHeaders?.ObjectId,
            oid,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Preferenza soft: lead <c>0x04</c> (anche Ford CT). Non è requisito data —
    /// pianta CI21 con lead arbitrario sotto checksum21.
    /// </summary>
    private static bool LooksLikeMmcsDataCipher(ReadOnlySpan<byte> body) =>
        body.Length > 0 && body[0] == 0x04;

    /// <summary>
    /// ctLen Ford tipici del plan (+112). Usati per rilevare data slice col prefisso = Ford CT.
    /// </summary>
    private static int[] CollectFordCtLens(AuthorizeGetDecryptPlan plan)
    {
        var set = new HashSet<int> { 112 };
        foreach (var g in plan.Containers)
        {
            foreach (var ch in g)
            {
                if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                    && UbChunkBuilder.IsPlausibleAuthFordCtLen(ch.Length))
                    set.Add(ch.Length);
            }
        }

        return set.ToArray();
    }

    /// <summary>
    /// True se <paramref name="data"/> è (o inizia con) un Ford CT che apre con l'IKM.
    /// Sintomo classico: wireOff=0 / identity su pack che inizia col Ford → MAC20.
    /// </summary>
    private static bool IsFordPrefixPoison(
        ReadOnlySpan<byte> data,
        ReadOnlySpan<byte> fordIkm,
        ReadOnlySpan<int> fordCtLens)
    {
        if (fordIkm.IsEmpty || data.Length < 0x12 || data[0] != 0x04)
            return false;

        foreach (var ctLen in fordCtLens)
        {
            if (ctLen < 0x12 || data.Length < ctLen)
                continue;
            if (FordMmcsDecryptor.BlobOpensExactWithIkm(fordIkm, data[..ctLen]))
                return true;
        }

        return false;
    }

    /// <summary>True se il FileGroup ha almeno un Ford CI45 (non FL / pipe-C).</summary>
    private static bool PlanHasAnyFordDescriptor(AuthorizeGetDecryptPlan plan)
    {
        foreach (var g in plan.Containers)
        {
            if (g.Any(UbChunkBuilder.IsAuthFordDescriptorChunk))
                return true;
        }

        return false;
    }

    /// <summary>CI data citato da <c>file_checksum_chunk_references</c>.</summary>
    private static bool IsReferencedDataChunk(
        AuthorizeGetDecryptPlan plan,
        int containerIndex,
        int chunkIndex)
    {
        foreach (var r in plan.References)
        {
            if (r.ContainerIndex == containerIndex && r.ChunkIndex == chunkIndex)
                return true;
        }

        return false;
    }

    /// <summary>Host Auth = un solo data CI (bodyLen == CI == authLen).</summary>
    private static bool IsExactAuthDataHost(
        AuthorizeGetCryptoChunk ch,
        int bodyLen,
        long authHostLen) =>
        UbChunkBuilder.IsAuthDataChunk(ch)
        && ch.Length > 0
        && bodyLen == ch.Length
        && authHostLen == ch.Length;

    /// <summary>
    /// unico modello: data = ChunkStream(.chunks/{sig21hex}) intero.
    /// Preferisce body lead-0x04; scarta map poison (D621… / Ford-prefix) a favore di re-slice.
    /// Accetta lead≠04 se piantato sotto checksum21 (FL no-Ford o Class B ref+exact).
    /// </summary>
    private static bool TryExtractRefDataFromHostBodies(
        AuthorizeGetDecryptPlan plan,
        ReadOnlySpan<byte> compact,
        IReadOnlyList<SignedUrlChunk> ordered,
        IReadOnlyList<SignedUrlChunk> original,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        out List<byte[]> dataChunks,
        ReadOnlySpan<byte> fordIkm = default)
    {
        _ = compact;
        _ = ordered;
        dataChunks = [];
        if (siblings is null)
            return false;

        var flStyleNoFord = !PlanHasAnyFordDescriptor(plan);
        var fordCtLens = CollectFordCtLens(plan);
        var mutMap = siblings as IDictionary<string, (byte[] Compact, long MmcsStart)>;

        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                return false;
            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count)
                return false;
            var ch = group[r.ChunkIndex];
            if (!UbChunkBuilder.IsAuthDataChunk(ch) || ch.Length <= 0)
                return false;
            if (ch.Checksum21 is not { Length: 21 })
                return false;

            var sigKey = "sig:" + Convert.ToHexString(ch.Checksum21).ToLowerInvariant();
            byte[]? chosen = null;
            string how = "miss";

            // Map keyed by Auth checksum21: accetta qualsiasi lead (non solo 0x04).
            if (siblings.TryGetValue(sigKey, out var bySig) && bySig.Compact.Length == ch.Length)
            {
                if (IsFordPrefixPoison(bySig.Compact, fordIkm, fordCtLens))
                {
                    // #region agent log
                    AgentLogDataSlice(
                        "data_sig_reject_ford_prefix_map",
                        r.ContainerIndex, r.ChunkIndex, 0, ch.Length, bySig.Compact.Length,
                        -1, CountSameLengthDataCi(plan, ch.Length), bySig.Compact);
                    // #endregion
                    mutMap?.Remove(sigKey);
                    ChunkFileCache.TryDelete(ch.Checksum21);
                }
                else
                {
                    chosen = bySig.Compact;
                    how = LooksLikeMmcsDataCipher(bySig.Compact) ? "map_sig" : "map_sig_non04";
                }
            }

            if (chosen is null
                && ChunkFileCache.TryRead(ch.Checksum21, ch.Length, out var fromFile)
                && fromFile.Length == ch.Length)
            {
                if (IsFordPrefixPoison(fromFile, fordIkm, fordCtLens))
                {
                    // #region agent log
                    AgentLogDataSlice(
                        "data_sig_reject_ford_prefix_chunkfile",
                        r.ContainerIndex, r.ChunkIndex, 0, ch.Length, fromFile.Length,
                        -1, CountSameLengthDataCi(plan, ch.Length), fromFile);
                    // #endregion
                    ChunkFileCache.TryDelete(ch.Checksum21);
                }
                else
                {
                    chosen = fromFile;
                    how = LooksLikeMmcsDataCipher(fromFile) ? "chunkfile" : "chunkfile_non04";
                    if (mutMap is not null)
                        mutMap[sigKey] = (fromFile, 0L);
                }
            }

            if (chosen is null
                && TryResliceDataCiFromHostBodies(
                    plan, original, siblings, r.ContainerIndex, r.ChunkIndex, ch,
                    out var resliced, fordIkm, fordCtLens))
            {
                chosen = resliced;
                how = "reslice";
                if (mutMap is not null)
                    mutMap[sigKey] = (resliced, 0L);
                // Overwrite: potrebbe esserci ancora un file poison same-len lead-04.
                ChunkFileCache.PutOverwrite(ch.Checksum21, resliced);
            }

            _ = flStyleNoFord;

            if (chosen is null)
            {
                // #region agent log
                AgentLogDataSlice(
                    "data_sig_miss",
                    r.ContainerIndex,
                    r.ChunkIndex,
                    0,
                    ch.Length,
                    0,
                    -1,
                    CountSameLengthDataCi(plan, ch.Length),
                    ch.Checksum21);
                // #endregion
                return false;
            }

            dataChunks.Add(chosen);
            // #region agent log
            AgentLogDataSlice(
                "data_sig_" + how,
                r.ContainerIndex,
                r.ChunkIndex,
                0,
                ch.Length,
                chosen.Length,
                -1,
                CountSameLengthDataCi(plan, ch.Length),
                chosen);
            // #endregion
        }

        return dataChunks.Count == plan.References.Count;
    }

    /// <summary>
    /// MAC20 + Ford aperto: prova candidati data (wire Auth anche non-04, layout, lead-04)
    /// finché <see cref="FillChunksPerStorageAndDecryptTrace"/> produce plaintext.
    /// Solo refs=1 (Sapphire/FileBus packed sameLen).
    /// </summary>
    private static bool TryPickDataChunksByMac20Candidates(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> original,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> siblings,
        ReadOnlySpan<byte> fordIkm,
        IReadOnlyList<BoundStorage> storages,
        byte[]? mmcsKek16,
        string? path,
        IReadOnlyList<byte[]>? priorData,
        out List<byte[]> dataChunks,
        out FillTrace fill)
    {
        dataChunks = [];
        fill = new FillTrace(0, 0, 0, 0, 0, 0, null, "", "ike-fillchunks", null, null);
        if (plan.References.Count != 1)
            return false;

        var cands = CollectMac20DataCandidates(plan, original, siblings, fordIkm);
        if (cands.Count == 0)
            return false;

        // Evita di ritestare lo stesso prior head.
        byte[]? prior = priorData is { Count: > 0 } ? priorData[0] : null;
        var tried = 0;
        foreach (var (slice, how, off) in cands)
        {
            if (prior is not null
                && prior.Length == slice.Length
                && prior.AsSpan().SequenceEqual(slice))
                continue;

            tried++;
            var one = new List<byte[]> { slice };
            var attempt = FillChunksPerStorageAndDecryptTrace(
                fordIkm, storages, one, plan, mmcsKek16);
            if (attempt.Plaintext is { Length: > 0 })
            {
                // #region agent log
                try
                {
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "03cce7",
                            ["runId"] = "mac20-cand-v1",
                            ["hypothesisId"] = "H-MAC-DATA",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["location"] = "FileGroupFillDecrypt.TryPickDataChunksByMac20Candidates",
                            ["message"] = "mac20_cand_ok",
                            ["data"] = new Dictionary<string, object?>
                            {
                                ["path"] = path,
                                ["how"] = how,
                                ["off"] = off,
                                ["tried"] = tried,
                                ["candN"] = cands.Count,
                                ["head8"] = Convert.ToHexString(
                                    slice.AsSpan(0, Math.Min(8, slice.Length))),
                                ["len"] = slice.Length,
                            },
                        }) + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion

                // Persisti il vincitore sotto sig Auth (retry futuri).
                var r = plan.References[0];
                var ch = plan.Containers[r.ContainerIndex][r.ChunkIndex];
                if (ch.Checksum21 is { Length: 21 })
                    ChunkFileCache.PutOverwrite(ch.Checksum21, slice);

                dataChunks = one;
                fill = attempt;
                return true;
            }
        }

        // #region agent log
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = "mac20-cand-v1",
                    ["hypothesisId"] = "H-MAC-DATA",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "FileGroupFillDecrypt.TryPickDataChunksByMac20Candidates",
                    ["message"] = "mac20_cand_miss",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["path"] = path,
                        ["tried"] = tried,
                        ["candN"] = cands.Count,
                        ["priorHead8"] = prior is { Length: > 0 }
                            ? Convert.ToHexString(prior.AsSpan(0, Math.Min(8, prior.Length)))
                            : null,
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion

        return false;
    }

    /// <summary>
    /// Candidati data per 1 ref: wire Auth (qualsiasi lead), layoutOff, scan lead-0x04
    /// same-len nel host (max 24). Scarta Ford-prefix IKM-open.
    /// </summary>
    private static List<(byte[] Slice, string How, int Off)> CollectMac20DataCandidates(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> original,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> siblings,
        ReadOnlySpan<byte> fordIkm)
    {
        var list = new List<(byte[] Slice, string How, int Off)>();
        if (plan.References.Count != 1)
            return list;

        var r = plan.References[0];
        if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count
            || (uint)r.ContainerIndex >= (uint)original.Count)
            return list;
        var group = plan.Containers[r.ContainerIndex];
        if ((uint)r.ChunkIndex >= (uint)group.Count)
            return list;
        var ch = group[r.ChunkIndex];
        if (!UbChunkBuilder.IsAuthDataChunk(ch) || ch.Length <= 0)
            return list;

        var host = original[r.ContainerIndex];
        if (host.ByteRange is not { } br)
            return list;
        var oid = host.EdgeHeaders?.ObjectId ?? "";
        var authLen = br.End - br.Start + 1;
        var hk = !string.IsNullOrEmpty(oid)
            ? $"{oid}@{br.Start}"
            : $"host:{r.ContainerIndex}@{br.Start}";
        if (!siblings.TryGetValue(hk, out var hb) || hb.Compact.Length == 0)
        {
            if (string.IsNullOrEmpty(oid)
                || !TryAssembleHostBodyFromMap(siblings, oid, br.Start, authLen, out hb))
                return list;
        }

        var body = hb.Compact;
        var fordCtLensArr = fordIkm.IsEmpty ? Array.Empty<int>() : CollectFordCtLens(plan);
        var ikmCopy = fordIkm.IsEmpty ? Array.Empty<byte>() : fordIkm.ToArray();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        bool TryAdd(int off, string how)
        {
            if (off < 0 || off + ch.Length > body.Length)
                return false;
            var span = body.AsSpan(off, ch.Length);
            if (ikmCopy.Length > 0 && IsFordPrefixPoison(span, ikmCopy, fordCtLensArr))
                return false;
            var key = Convert.ToHexString(span[..Math.Min(16, span.Length)])
                      + ":" + span.Length;
            if (!seen.Add(key))
                return false;
            list.Add((span.ToArray(), how, off));
            return true;
        }

        long layoutSum = 0;
        foreach (var c in group)
            layoutSum += c.Length;
        var layoutOff = 0;
        for (var j = 0; j < r.ChunkIndex && j < group.Count; j++)
            layoutOff += Math.Max(0, group[j].Length);

        var wire = UbChunkBuilder.ResolveCiWireInHostBody(
            ch.Offset, ch.Length, br.Start, body.Length,
            layoutOff, r.ChunkIndex, group.Count, layoutSum, fordOnlyHost: false);
        if (wire >= 0)
            TryAdd((int)wire, "auth_wire");

        if (body.Length == ch.Length)
            TryAdd(0, "exact_host");

        TryAdd(layoutOff, "layout");

        // Altri CI same-len sullo stesso host (packed Sapphire).
        var lay = 0;
        for (var j = 0; j < group.Count; j++)
        {
            var sib = group[j];
            if (!UbChunkBuilder.IsAuthDataChunk(sib) || sib.Length != ch.Length)
            {
                lay += Math.Max(0, sib.Length);
                continue;
            }

            var w = UbChunkBuilder.ResolveCiWireInHostBody(
                sib.Offset, sib.Length, br.Start, body.Length,
                lay, j, group.Count, layoutSum, fordOnlyHost: false);
            if (w >= 0)
                TryAdd((int)w, "host_ci");
            lay += Math.Max(0, sib.Length);
        }

        // Scan lead-0x04 (cap) — spesso il CT SIV giusto non è all'Offset Auth.
        var leadN = 0;
        for (var i = 0; i + ch.Length <= body.Length && leadN < 24; i++)
        {
            if (body[i] != 0x04)
                continue;
            if (TryAdd(i, "lead04"))
                leadN++;
        }

        return list;
    }

    /// <summary>
    /// Re-slice data CI dall'host oid@ — prova Offset / layout e tiene solo lead-0x04
    /// (scarta Ford-prefix se <paramref name="fordIkm"/> presente).
    /// </summary>
    private static bool TryResliceDataCiFromHostBodies(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> original,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> siblings,
        int containerIndex,
        int chunkIndex,
        AuthorizeGetCryptoChunk ch,
        out byte[] slice,
        ReadOnlySpan<byte> fordIkm = default,
        ReadOnlySpan<int> fordCtLens = default)
    {
        slice = [];
        if ((uint)containerIndex >= (uint)plan.Containers.Count
            || (uint)containerIndex >= (uint)original.Count
            || ch.Length <= 0)
            return false;

        var group = plan.Containers[containerIndex];
        if ((uint)chunkIndex >= (uint)group.Count)
            return false;

        var host = original[containerIndex];
        if (host.ByteRange is not { } br)
            return false;
        var oid = host.EdgeHeaders?.ObjectId ?? "";
        var authLen = br.End - br.Start + 1;
        var hk = !string.IsNullOrEmpty(oid) ? $"{oid}@{br.Start}" : $"host:{containerIndex}@{br.Start}";
        if (!siblings.TryGetValue(hk, out var hb) || hb.Compact.Length == 0)
        {
            if (string.IsNullOrEmpty(oid)
                || !TryAssembleHostBodyFromMap(siblings, oid, br.Start, authLen, out hb))
                return false;
        }

        if (fordCtLens.IsEmpty && !fordIkm.IsEmpty)
            fordCtLens = CollectFordCtLens(plan);

        var body = hb.Compact;
        // Host data exact: body == CI. Lead qualsiasi (live non-04 sotto checksum21).
        if (body.Length == ch.Length
            && !IsFordPrefixPoison(body, fordIkm, fordCtLens))
        {
            slice = body;
            return true;
        }

        long layoutSum = 0;
        foreach (var c in group)
            layoutSum += c.Length;
        var layoutOff = 0;
        for (var j = 0; j < chunkIndex && j < group.Count; j++)
            layoutOff += Math.Max(0, group[j].Length);

        var candidates = new long[]
        {
            UbChunkBuilder.ResolveCiWireInHostBody(
                ch.Offset, ch.Length, br.Start, body.Length,
                layoutOff, chunkIndex, group.Count, layoutSum, fordOnlyHost: false),
            ch.Offset,
            ch.Offset >= br.Start ? ch.Offset - br.Start : -1,
            layoutOff,
        };
        // Preferisci lead-04 se presente, altrimenti primo non-poison.
        byte[]? fallbackNon04 = null;
        foreach (var off in candidates)
        {
            if (off < 0 || off + ch.Length > body.Length)
                continue;
            var cand = body.AsSpan((int)off, ch.Length);
            if (IsFordPrefixPoison(cand, fordIkm, fordCtLens))
            {
                // #region agent log
                AgentLogDataSlice(
                    "data_reslice_skip_ford_prefix",
                    containerIndex, chunkIndex, (int)off, ch.Length, body.Length, authLen,
                    CountSameLengthDataCi(plan, ch.Length), cand.ToArray());
                // #endregion
                continue;
            }

            if (LooksLikeMmcsDataCipher(cand))
            {
                slice = cand.ToArray();
                // #region agent log
                AgentLogDataSlice(
                    "data_reslice_ok",
                    containerIndex,
                    chunkIndex,
                    (int)off,
                    ch.Length,
                    body.Length,
                    authLen,
                    CountSameLengthDataCi(plan, ch.Length),
                    slice);
                // #endregion
                return true;
            }

            fallbackNon04 ??= cand.ToArray();
        }

        if (fallbackNon04 is not null)
        {
            slice = fallbackNon04;
            // #region agent log
            AgentLogDataSlice(
                "data_reslice_ok_non04",
                containerIndex,
                chunkIndex,
                0,
                ch.Length,
                body.Length,
                authLen,
                CountSameLengthDataCi(plan, ch.Length),
                slice);
            // #endregion
            return true;
        }

        return false;
    }

    private static int CountSameLengthDataCi(AuthorizeGetDecryptPlan plan, int length)
    {
        var n = 0;
        foreach (var g in plan.Containers)
        {
            foreach (var c in g)
            {
                if (UbChunkBuilder.IsAuthDataChunk(c) && c.Length == length)
                    n++;
            }
        }

        return n;
    }

    /// <summary>unico modello: data = solo <c>sig:</c> cache (niente oid@ demux).</summary>
    private static bool TryExtractRefDataFromSiblings(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> chunks,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        out List<byte[]> dataChunks)
    {
        _ = chunks;
        dataChunks = [];
        if (siblings is null || siblings.Count == 0)
            return false;

        var flStyleNoFord = !PlanHasAnyFordDescriptor(plan);
        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                return false;
            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count)
                return false;
            var ch = group[r.ChunkIndex];
            if (!UbChunkBuilder.IsAuthDataChunk(ch)
                || ch.Length <= 0
                || ch.Checksum21 is not { Length: 21 })
                return false;

            var sigKey = "sig:" + Convert.ToHexString(ch.Checksum21).ToLowerInvariant();
            byte[]? chosen = null;
            _ = flStyleNoFord;
            if (siblings.TryGetValue(sigKey, out var bySig)
                && bySig.Compact.Length == ch.Length)
                chosen = bySig.Compact;
            if (chosen is null
                && ChunkFileCache.TryRead(ch.Checksum21, ch.Length, out var fromFile)
                && fromFile.Length == ch.Length)
            {
                chosen = fromFile;
                if (siblings is IDictionary<string, (byte[] Compact, long MmcsStart)> mut)
                    mut[sigKey] = (fromFile, 0L);
            }

            if (chosen is null)
                return false;

            dataChunks.Add(chosen);
        }

        return dataChunks.Count == plan.References.Count;
    }

    // #region agent log
    private static void AgentLogDataSlice(
        string message, int host, int ci, int off, int wantLen, int bodyLen, byte[] sample)
        => AgentLogDataSlice(message, host, ci, off, wantLen, bodyLen, -1, -1, sample);

    private static void AgentLogDataSlice(
        string message,
        int host,
        int ci,
        int off,
        int wantLen,
        int bodyLen,
        long authHostLen,
        int sameLen,
        byte[] sample)
    {
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-DATA-IKE",
                ["runId"] = "data-ike-v1",
                ["location"] = "FileGroupFillDecrypt.TryExtractRefDataFromHostBodies",
                ["message"] = message,
                ["data"] = new Dictionary<string, object?>
                {
                    ["h"] = host,
                    ["ci"] = ci,
                    ["off"] = off,
                    ["wantLen"] = wantLen,
                    ["bodyLen"] = bodyLen,
                    ["authHostLen"] = authHostLen,
                    ["sameLenCi"] = sameLen,
                    ["head8"] = sample is { Length: > 0 }
                        ? Convert.ToHexString(sample.AsSpan(0, Math.Min(8, sample.Length)))
                        : null,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
    }
    // #endregion

    // SliceCompactByOrderedRanges / IndexOfChunk rimossi: non concatena host bodies.

    /// <summary>Quanti host FileGroup hanno body exact == ctLen di un CI45 (SpillOpen-ready).</summary>
    private static int CountExactFordBodies(
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> sib,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts)
    {
        var n = 0;
        for (var i = 0; i < plan.Containers.Count && i < hosts.Count; i++)
        {
            if (hosts[i].ByteRange is not { } br)
                continue;
            var oid = hosts[i].EdgeHeaders?.ObjectId ?? "";
            byte[]? body = null;
            if (!string.IsNullOrEmpty(oid)
                && sib.TryGetValue($"{oid}@{br.Start}", out var e))
                body = e.Compact;
            else if (sib.TryGetValue($"host:{i}@{br.Start}", out var e2))
                body = e2.Compact;
            if (body is null || body.Length < 0x12 || body[0] != 0x04)
                continue;
            foreach (var ch in plan.Containers[i])
            {
                if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                    && ch.Length == body.Length)
                {
                    n++;
                    break;
                }
            }
        }

        return n;
    }

    /// <summary>
    /// True se almeno un CI <b>citato dai refs</b> ha <c>chunkEncryptionKey</c> (Pipe C / FL).
    /// </summary>
    public static bool PlanHasChunkEncryptionKeys(AuthorizeGetDecryptPlan plan)
    {
        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                continue;
            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count)
                continue;
            if (group[r.ChunkIndex].EncryptionKey.Length > 0)
                return true;
        }

        return false;
    }

    private static Outcome Fail(string mode, string reason) =>
        new([], mode, reason);

    private static string Clip(string s) =>
        s.Length <= 160 ? s : s[..160];
}
