using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Download;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Pipeline Ford allineata a live (x64dbg 03cce7):
/// <code>
/// authorizeGet → FileGroups
/// FillContainers: GET ogni host = content-byte-range del FileGroup
/// Ford:  SpillOpen string size == ctLen, head 0x04 → .chunks/hex(gate)
/// Data:  refs → body/CI (PlantAuthChecksumSlices / FillChunks)
/// </code>
/// SpillOpen: string size == ctLen (PutChunk=0).
/// Exact FG (<c>body==ctLen</c>) oppure pack FG (<c>body==authLen</c>) →
/// <c>Read(ctLen)</c> @ Auth <c>ChunkInfo.Offset</c> (f2.f4 wire — non j×112 inventato).
/// </summary>
public static class LiveFillPipeline
{
    public const string RunId = "ike-pack-open-v1";

    /// <summary>
    /// SpillOpen: per ogni CI45, materializza CT con <c>size == ctLen</c>.
    /// Con <paramref name="fordIkm"/>: scarta cache/CT che non aprono; pack → scan lead-0x04
    /// (probe IkeOnly: ike_run packed host win@Offset).
    /// </summary>
    public static int PutChunksFromHostBodies(
        IDictionary<string, (byte[] Compact, long MmcsStart)> hostBodies,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts,
        byte[]? authBody = null,
        ReadOnlySpan<byte> fordIkm = default)
    {
        if (hostBodies.Count == 0 || plan.Containers.Count == 0)
            return 0;

        // Books live (03cce7): SeedSibling chiama PutChunks PRIMA di FillFord →
        // spill_ok ikmLen=0 pianta 043A2AC4… sotto gate → gate-mirror poison → no-ford.
        // Senza IKM: lascia solo oid@start in RAM; spill Ford solo dopo unwrap.
        if (fordIkm.IsEmpty)
        {
            AgentLog(
                "H-NO-IKM-SPILL",
                "PutChunksFromHostBodies",
                "skip_all_ford_spill_no_ikm",
                new Dictionary<string, object?>
                {
                    ["hosts"] = hosts.Count,
                    ["sib"] = hostBodies.Count,
                });
            return 0;
        }

        var nestedCt = BuildNestedCtLenMap(authBody);
        var planted = 0;
        var ikmBytes = fordIkm.ToArray();

        for (var i = 0; i < plan.Containers.Count && i < hosts.Count; i++)
        {
            if (hosts[i].ByteRange is not { } br)
                continue;
            var authLen = br.End - br.Start + 1;
            if (authLen < 0x12)
                continue;

            var oid = hosts[i].EdgeHeaders?.ObjectId ?? "";
            if (!TryGetHostBody(hostBodies, oid, i, br.Start, out var body)
                || body.Length < 0x12)
                continue;

            // Body = GET FileGroup (authLen) o CT exact già tagliato (ctLen).
            if (body.Length != authLen && body.Length < 0x12)
                continue;

            var group = plan.Containers[i];

            // Empty host (ci==0): body intero == nested ctLen, head 0x04.
            if (group.Count == 0)
            {
                if (body.Length == authLen && body[0] == 0x04
                    && FordMmcsDecryptor.BlobOpensExactWithIkm(ikmBytes, body))
                    planted += PutEmptyHostExactByOid(
                        body, oid, authBody, nestedCt, hostBodies, i);
                continue;
            }

            for (var j = 0; j < group.Count; j++)
            {
                var ch = group[j];
                if (!UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                    || ch.Checksum21.Length != 45)
                    continue;

                var gateHex = Convert.ToHexString(ch.Checksum21).ToLowerInvariant();
                var ctLen = nestedCt.TryGetValue(gateHex, out var nCt)
                            && UbChunkBuilder.IsPlausibleAuthFordCtLen(nCt)
                    ? nCt
                    : UbChunkBuilder.IsPlausibleAuthFordCtLen(ch.Length) ? ch.Length : 0;
                if (ctLen < 0x12)
                    continue;

                // Cache: solo se apre con IKM (altrimenti poison → fo=0).
                if (ChunkFileCache.TryRead(ch.Checksum21, ctLen, out var have)
                    && have.Length == ctLen
                    && have[0] == 0x04
                    && FordMmcsDecryptor.BlobOpensExactWithIkm(ikmBytes, have))
                {
                    hostBodies["gate:" + gateHex] = (have, 0L);
                    continue;
                }

                if (!TryMaterializeFordCt(
                        body, authLen, ctLen, ch.Offset, br.Start, j,
                        out var fordCt, out var how, ikmBytes))
                {
                    AgentLog(
                        "H1",
                        "PutChunksFromHostBodies",
                        "spill_skip",
                        new Dictionary<string, object?>
                        {
                            ["h"] = i,
                            ["ci"] = j,
                            ["ctLen"] = ctLen,
                            ["bodyLen"] = body.Length,
                            ["authLen"] = authLen,
                            ["ciOff"] = ch.Offset,
                            ["hostStart"] = br.Start,
                            ["how"] = how,
                            ["ikmLen"] = ikmBytes.Length,
                            ["gate8"] = Convert.ToHexString(ch.Checksum21.AsSpan(0, 8)),
                        });
                    // Drop stale gate: mirror so Bind non riusa CT morto.
                    hostBodies.Remove("gate:" + gateHex);
                    continue;
                }

                ChunkFileCache.PutOverwrite(ch.Checksum21, fordCt);
                hostBodies["gate:" + gateHex] = (fordCt, 0L);
                planted++;
                AgentLog(
                    "H1",
                    "PutChunksFromHostBodies",
                    "spill_ok",
                    new Dictionary<string, object?>
                    {
                        ["h"] = i,
                        ["ci"] = j,
                        ["ctLen"] = ctLen,
                        ["bodyLen"] = body.Length,
                        ["authLen"] = authLen,
                        ["how"] = how,
                        ["ikmLen"] = ikmBytes.Length,
                        ["gate8"] = Convert.ToHexString(ch.Checksum21.AsSpan(0, 8)),
                        ["head8"] = Convert.ToHexString(
                            fordCt.AsSpan(0, Math.Min(8, fordCt.Length))),
                    });
            }
        }

        return planted;
    }

    /// <summary>
    /// SpillOpen: <c>string size == ctLen</c>, head <c>0x04</c>.
    /// Exact FG oppure <c>Read(ctLen)</c> @ Auth ChunkInfo.Offset nel pack GET.
    /// Con IKM: se wire/exact non apre → scan lead-0x04 nel pack (ike_run probe).
    /// </summary>
    internal static bool TryMaterializeFordCt(
        byte[] body,
        long authLen,
        int ctLen,
        long ciOffset,
        long hostStart,
        int ciIndex,
        out byte[] fordCt,
        out string how,
        ReadOnlySpan<byte> fordIkm = default)
    {
        _ = ciIndex;
        fordCt = [];
        how = "miss";
        if (ctLen < 0x12 || body.Length < ctLen)
        {
            how = "short";
            return false;
        }

        // Copy span: local Accept cannot capture ref-like fordIkm (CS9108).
        var ikm = fordIkm.IsEmpty ? Array.Empty<byte>() : fordIkm.ToArray();

        if (body.Length == ctLen)
        {
            if (body[0] == 0x04
                && (ikm.Length == 0
                    || FordMmcsDecryptor.BlobOpensExactWithIkm(ikm, body)))
            {
                fordCt = body.ToArray();
                how = "exact";
                return true;
            }

            how = body[0] != 0x04 ? "exact_bad_head" : "exact_ikm_miss";
            return false;
        }

        // Pack FG: prefer Auth wire Offset (f2.f4).
        long rel = -1;
        if (ciOffset >= hostStart && ciOffset - hostStart + ctLen <= body.Length)
            rel = ciOffset - hostStart;
        else if (ciOffset >= 0 && ciOffset + ctLen <= body.Length)
            rel = ciOffset;

        if (rel >= 0 && body.Length == authLen)
        {
            var win = body.AsSpan((int)rel, ctLen);
            if (win[0] == 0x04
                && (ikm.Length == 0
                    || FordMmcsDecryptor.BlobOpensExactWithIkm(ikm, win)))
            {
                fordCt = win.ToArray();
                how = "wireOff";
                return true;
            }

            how = win[0] != 0x04 ? "wireOff_bad_head" : "wireOff_ikm_miss";
        }
        else if (body.Length != authLen)
        {
            how = "body_ne_authLen";
        }
        else
        {
            how = "wireOff_oob";
        }

        // Probe IkeOnly / ike_run: packed multi-tenant — finestra lead-0x04 che apre con IKM.
        if (ikm.Length > 0
            && TryScanPackOpenFord(body, ctLen, ikm, out fordCt, out var scanHow))
        {
            how = scanHow;
            return true;
        }

        return false;
    }

    /// <summary>
    /// Pack host: cerca CT <paramref name="ctLen"/> lead-0x04 che apre con IKM.
    /// Usato solo se wire/exact falliscono (evidenza probe: win@480/@2160).
    /// </summary>
    private static bool TryScanPackOpenFord(
        ReadOnlySpan<byte> body,
        int ctLen,
        ReadOnlySpan<byte> fordIkm,
        out byte[] fordCt,
        out string how)
    {
        fordCt = [];
        how = "packScan_miss";
        if (fordIkm.IsEmpty || body.Length < ctLen)
            return false;

        if (body.Length <= 8192)
        {
            for (var off = 0; off + ctLen <= body.Length; off++)
            {
                if (body[off] != 0x04) continue;
                var win = body.Slice(off, ctLen);
                if (!FordMmcsDecryptor.BlobOpensExactWithIkm(fordIkm, win))
                    continue;
                fordCt = win.ToArray();
                how = "packScan@" + off;
                return true;
            }
        }
        else
        {
            for (var off = 0; off + ctLen <= body.Length; off += ctLen)
            {
                if (body[off] != 0x04) continue;
                var win = body.Slice(off, ctLen);
                if (!FordMmcsDecryptor.BlobOpensExactWithIkm(fordIkm, win))
                    continue;
                fordCt = win.ToArray();
                how = "packStride@" + off;
                return true;
            }
        }

        return false;
    }

    private static bool TryGetHostBody(
        IDictionary<string, (byte[] Compact, long MmcsStart)> hostBodies,
        string oid,
        int hostIndex,
        long start,
        out byte[] body)
    {
        body = [];
        if (!string.IsNullOrEmpty(oid)
            && hostBodies.TryGetValue($"{oid}@{start}", out var byOid)
            && byOid.Compact.Length >= 0x12)
        {
            body = byOid.Compact;
            return true;
        }

        if (hostBodies.TryGetValue($"host:{hostIndex}@{start}", out var byIdx)
            && byIdx.Compact.Length >= 0x12)
        {
            body = byIdx.Compact;
            return true;
        }

        return false;
    }

    /// <summary>
    /// L2 emptyFordGate + DecryptFordKeys:
    /// ownership = <see cref="UbChunkBuilder.GateOwnsPlan"/> (FileChecksum Auth nel gate);
    /// HAS-Ford = pool.lookup(gate) → Read(ctLen) — equival. <c>storage+0x98==45</c>.
    /// </summary>
    public static List<FileGroupFillDecrypt.BoundStorage> BindOwnedFordStorages(
        byte[] authBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        byte[]? fileChecksum21 = null,
        ReadOnlySpan<byte> fordIkm = default)
    {
        // Ownership: plan.FileChecksum (refs) OR AssetSignature (CK) embedded in gate45.
        // Batch AG: plan FC can be stale/wrong while AssetSignature still matches the Ford gate.
        var assetSig = fileChecksum21 is { Length: 21 } ? fileChecksum21 : null;
        var list = new List<FileGroupFillDecrypt.BoundStorage>();
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var descs = UbChunkBuilder.CollectAuthFordDescriptors(authBody, plan, hosts);

        var skipFc = 0;
        var skipPlan = 0;
        var missCt = 0;
        var poisonSkip = 0;
        // Copy span once: local CtOk cannot capture ref-like fordIkm (CS9108).
        var ikmBytes = fordIkm.IsEmpty ? Array.Empty<byte>() : fordIkm.ToArray();
        foreach (var d in descs)
        {
            if (d.Gate45.Length != 45 || !UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen))
                continue;

            // gate embeds FileChecksum (refs.field1) and/or AssetSignature.
            if (plan.FileChecksum is { Length: 21 } || assetSig is { Length: 21 })
            {
                var ownsPlan = plan.FileChecksum is { Length: 21 }
                               && UbChunkBuilder.GateOwnsPlan(d.Gate45, plan);
                var ownsAsset = assetSig is { Length: 21 }
                                && UbChunkBuilder.GateEmbedsFileChecksum(d.Gate45, assetSig);
                if (!ownsPlan && !ownsAsset)
                {
                    skipFc++;
                    continue;
                }
            }

            bool CtOk(ReadOnlySpan<byte> cand) =>
                cand.Length == d.CtLen
                && cand[0] == 0x04
                && (ikmBytes.Length == 0
                    || FordMmcsDecryptor.BlobOpensExactWithIkm(ikmBytes, cand));

            // emptyFordGate / DecryptFordKeys: pool.lookup(gate) → Read(ctLen).
            // Se il CT è già nello spill, non richiedere GatePresentInPlan
            // (AG dump corrotti: containers da pathOffsets senza CI45 allineati).
            // Con IKM: scarta CT poison (probe: cache/mirror che non apre → fo=0).
            byte[]? ct = null;
            var how = "";
            if (ChunkFileCache.TryRead(d.Gate45, d.CtLen, out var fileCt)
                && CtOk(fileCt))
            {
                ct = fileCt;
                how = "chunkfile";
            }
            else if (ChunkFileCache.TryRead(d.Gate45, d.CtLen, out _)
                     && ikmBytes.Length > 0)
            {
                poisonSkip++;
                // Unverified early spill left a head-04 body that does not open —
                // drop it so host_open can replace with a fresh GET (+ IKM check).
                ChunkFileCache.TryDelete(d.Gate45);
            }

            if (ct is null && siblings is not null)
            {
                var gk = "gate:" + Convert.ToHexString(d.Gate45).ToLowerInvariant();
                if (siblings.TryGetValue(gk, out var ge) && CtOk(ge.Compact))
                {
                    ct = ge.Compact;
                    how = "gate-mirror";
                }
                else
                {
                    // Mirror/cache morti: togli dalla map (Books: 043A2AC4… non apre).
                    if (siblings is IDictionary<string, (byte[] Compact, long MmcsStart)> mut
                        && mut.ContainsKey(gk))
                        mut.Remove(gk);

                    if (TryReadCtLenFromPlanHosts(
                            d, plan, hosts, siblings, out var fromHost, ikmBytes))
                    {
                        ct = fromHost;
                        how = "host_open";
                        ChunkFileCache.PutOverwrite(d.Gate45, ct);
                    }
                    else if (!string.IsNullOrEmpty(d.ObjectId)
                             && ikmBytes.Length > 0
                             && OidHostBodyCache.TryPackScanOpen(
                                 d.ObjectId, d.CtLen, ikmBytes,
                                 out var fromOid, out var oidHow, out _))
                    {
                        ct = fromOid;
                        how = "oid_cache:" + oidHow;
                        ChunkFileCache.PutOverwrite(d.Gate45, ct);
                    }
                }
            }

            if (ct is null && !GatePresentInPlan(d, plan, hosts))
            {
                skipPlan++;
                continue;
            }

            AgentLog(
                "H3",
                "BindOwnedFordStorages",
                "ford_bind",
                new Dictionary<string, object?>
                {
                    ["how"] = how.Length > 0 ? how : "miss",
                    ["gateHex12"] = Convert.ToHexString(d.Gate45.AsSpan(0, 12)),
                    ["ctLen"] = d.CtLen,
                    ["gateOwns"] = UbChunkBuilder.GateOwnsPlan(d.Gate45, plan),
                    ["head8"] = ct is { Length: >= 8 }
                        ? Convert.ToHexString(ct.AsSpan(0, 8))
                        : "",
                });

            if (ct is null)
            {
                missCt++;
                // H-ORDER: registra pending — pack OID successivi possono plantare il CT.
                if (!string.IsNullOrEmpty(d.ObjectId) && ikmBytes.Length > 0)
                    OidHostBodyCache.RegisterPending(
                        d.ObjectId, d.Gate45, d.CtLen, ikmBytes, path: null);
                // #region agent log
                try
                {
                    byte[]? cand = null;
                    var candSrc = "none";
                    if (ChunkFileCache.TryRead(d.Gate45, d.CtLen, out var cacheCt))
                    {
                        cand = cacheCt;
                        candSrc = "chunkfile";
                    }
                    else if (siblings is not null)
                    {
                        var gk2 = "gate:" + Convert.ToHexString(d.Gate45).ToLowerInvariant();
                        if (siblings.TryGetValue(gk2, out var ge2) && ge2.Compact.Length > 0)
                        {
                            cand = ge2.Compact;
                            candSrc = "gate-mirror";
                        }
                    }

                    var lenOk = cand is not null && cand.Length == d.CtLen;
                    var leadOk = cand is { Length: > 0 } && cand[0] == 0x04;
                    var opens = cand is { Length: > 0 } && ikmBytes.Length > 0
                        && FordMmcsDecryptor.BlobOpensExactWithIkm(ikmBytes, cand);
                    var oidAlt = 0;
                    var oidAltOpen = 0;
                    var oidAltHead = "";
                    if (siblings is not null
                        && !string.IsNullOrEmpty(d.ObjectId)
                        && ikmBytes.Length > 0)
                    {
                        var prefix = d.ObjectId + "@";
                        foreach (var (k, (body, _)) in siblings)
                        {
                            if (!k.StartsWith(prefix, StringComparison.Ordinal))
                                continue;
                            oidAlt++;
                            if (body.Length >= d.CtLen
                                && TryMaterializeFordCt(
                                    body, body.Length, d.CtLen, 0, 0, 0,
                                    out var alt, out var altHow, ikmBytes))
                            {
                                oidAltOpen++;
                                if (oidAltHead.Length == 0)
                                    oidAltHead =
                                        Convert.ToHexString(alt.AsSpan(0, Math.Min(8, alt.Length)))
                                        + ":" + altHow;
                            }
                        }
                    }

                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "03cce7",
                        ["runId"] = RunId,
                        ["hypothesisId"] = "H-CTOK-REJECT",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "LiveFillPipeline.BindOwnedFordStorages",
                        ["message"] = "ford_ct_rejected",
                        ["data"] = new Dictionary<string, object?>
                        {
                            ["candSrc"] = candSrc,
                            ["wantCtLen"] = d.CtLen,
                            ["candLen"] = cand?.Length ?? 0,
                            ["lenOk"] = lenOk,
                            ["leadOk"] = leadOk,
                            ["ikmLen"] = ikmBytes.Length,
                            ["ikmHead8"] = ikmBytes.Length >= 8
                                ? Convert.ToHexString(ikmBytes.AsSpan(0, 8))
                                : "",
                            ["candHead8"] = cand is { Length: >= 8 }
                                ? Convert.ToHexString(cand.AsSpan(0, 8))
                                : "",
                            ["blobOpens"] = opens,
                            ["poisonSkip"] = poisonSkip,
                            ["gateHex12"] = Convert.ToHexString(d.Gate45.AsSpan(0, 12)),
                            ["oid8"] = d.ObjectId is { Length: >= 8 } o ? o[..8] : d.ObjectId,
                            ["oidAlt"] = oidAlt,
                            ["oidAltOpen"] = oidAltOpen,
                            ["oidAltHead"] = oidAltHead,
                        },
                    });
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                        line + Environment.NewLine);
                    File.AppendAllText(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line + Environment.NewLine);
                }
                catch { /* ignore */ }
                // #endregion
                continue;
            }

            var sha = Convert.ToHexString(
                System.Security.Cryptography.SHA256.HashData(ct).AsSpan(0, 8));
            if (!seen.Add(sha))
                continue;

            // HasFord ≡ emptyFordGate (+0x98==45) con CT materializzato.
            list.Add(new FileGroupFillDecrypt.BoundStorage(
                FindHostCiForGate(d, plan, hosts),
                true,
                ct,
                $"{how} ctLen={d.CtLen}"));
        }

        AgentLog(
            "H4",
            "BindOwnedFordStorages",
            "bind_summary",
            new Dictionary<string, object?>
            {
                ["descs"] = descs.Count,
                ["bound"] = list.Count,
                ["skipFc"] = skipFc,
                ["skipPlan"] = skipPlan,
                ["missCt"] = missCt,
                ["poisonSkip"] = poisonSkip,
                ["ikmLen"] = fordIkm.Length,
                ["sib"] = siblings?.Count ?? 0,
                ["hasPlanFc"] = plan.FileChecksum is { Length: 21 },
            });

        return list;
    }

    private static int PutEmptyHostExactByOid(
        byte[] body,
        string oid,
        byte[]? authBody,
        Dictionary<string, int> nestedCt,
        IDictionary<string, (byte[] Compact, long MmcsStart)> hostBodies,
        int hostIndex)
    {
        if (string.IsNullOrEmpty(oid)
            || authBody is not { Length: > 0 }
            || !UbChunkBuilder.IsPlausibleAuthFordCtLen(body.Length)
            || body[0] != 0x04)
            return 0;

        var n = 0;
        foreach (var d in UbChunkBuilder.ExtractAuthFordDescriptors(authBody))
        {
            if (d.Gate45.Length != 45 || !UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen))
                continue;
            if (body.Length != d.CtLen)
                continue;
            if (string.IsNullOrEmpty(d.ObjectId)
                || !string.Equals(d.ObjectId, oid, StringComparison.Ordinal))
                continue;

            var gateHex = Convert.ToHexString(d.Gate45).ToLowerInvariant();
            nestedCt[gateHex] = d.CtLen;
            ChunkFileCache.PutOverwrite(d.Gate45, body);
            hostBodies["gate:" + gateHex] = (body, 0L);
            n++;
            AgentLog(
                "H-IKE-SPILL",
                "PutChunksFromHostBodies",
                "spill_empty_oid_read_ctLen",
                new Dictionary<string, object?>
                {
                    ["h"] = hostIndex,
                    ["ctLen"] = d.CtLen,
                    ["oid8"] = oid.Length >= 8 ? oid[..8] : oid,
                    ["gate8"] = Convert.ToHexString(d.Gate45.AsSpan(0, 8)),
                    ["head8"] = Convert.ToHexString(
                        body.AsSpan(0, Math.Min(8, body.Length))),
                });
        }

        return n;
    }

    private static Dictionary<string, int> BuildNestedCtLenMap(byte[]? authBody)
    {
        var map = new Dictionary<string, int>(StringComparer.Ordinal);
        if (authBody is not { Length: > 0 })
            return map;
        foreach (var d in UbChunkBuilder.ExtractAuthFordDescriptors(authBody))
        {
            if (d.Gate45.Length == 45 && UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen))
                map[Convert.ToHexString(d.Gate45).ToLowerInvariant()] = d.CtLen;
        }

        return map;
    }

    private static bool GatePresentInPlan(
        UbChunkBuilder.AuthFordDescriptor d,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts)
    {
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
               && hosts.Any(h => string.Equals(
                   h.EdgeHeaders?.ObjectId, d.ObjectId, StringComparison.Ordinal));
    }

    private static int FindHostCiForGate(
        UbChunkBuilder.AuthFordDescriptor d,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts)
    {
        // Preferisci host il cui ByteRange è il FileGroup che contiene il gate.
        for (var i = 0; i < plan.Containers.Count && i < hosts.Count; i++)
        {
            foreach (var ch in plan.Containers[i])
            {
                if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                    && ch.Checksum21.Length == 45
                    && ch.Checksum21.AsSpan().SequenceEqual(d.Gate45))
                    return i;
            }
        }

        if (!string.IsNullOrEmpty(d.ObjectId))
        {
            for (var i = 0; i < hosts.Count; i++)
            {
                if (string.Equals(
                        hosts[i].EdgeHeaders?.ObjectId, d.ObjectId, StringComparison.Ordinal))
                    return i;
            }
        }

        return -1;
    }

    /// <summary>Stessa regola SpillOpen: exact / wireOff / packScan(IKM).</summary>
    private static bool TryReadCtLenFromPlanHosts(
        UbChunkBuilder.AuthFordDescriptor d,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> siblings,
        out byte[] ct,
        ReadOnlySpan<byte> fordIkm = default)
    {
        ct = [];
        for (var i = 0; i < plan.Containers.Count && i < hosts.Count; i++)
        {
            var group = plan.Containers[i];
            if (hosts[i].ByteRange is not { } br)
                continue;

            var ci = -1;
            AuthorizeGetCryptoChunk? ch = null;
            for (var j = 0; j < group.Count; j++)
            {
                if (!UbChunkBuilder.IsAuthFordDescriptorChunk(group[j])
                    || group[j].Checksum21.Length != 45
                    || !group[j].Checksum21.AsSpan().SequenceEqual(d.Gate45))
                    continue;
                ci = j;
                ch = group[j];
                break;
            }

            if (ci < 0 || ch is null)
                continue;

            var oid = hosts[i].EdgeHeaders?.ObjectId ?? "";
            byte[]? body = null;
            if (!string.IsNullOrEmpty(oid)
                && siblings.TryGetValue($"{oid}@{br.Start}", out var byOid)
                && byOid.Compact.Length >= d.CtLen)
                body = byOid.Compact;
            else if (siblings.TryGetValue($"host:{i}@{br.Start}", out var byIdx)
                     && byIdx.Compact.Length >= d.CtLen)
                body = byIdx.Compact;
            if (body is null)
                continue;

            var authLen = br.End - br.Start + 1;
            if (!TryMaterializeFordCt(
                    body, authLen, d.CtLen, ch.Offset, br.Start, ci, out ct, out _, fordIkm))
                continue;
            return true;
        }

        // Descriptor host CI45 assente nel plan container: scan tutti i sibling packed
        // con IKM (stesso recovery della probe IkeOnly su ike_run).
        if (!fordIkm.IsEmpty)
        {
            foreach (var (key, (body, _)) in siblings)
            {
                if (key.StartsWith("gate:", StringComparison.Ordinal)
                    || key.StartsWith("sig:", StringComparison.Ordinal))
                    continue;
                if (body.Length < d.CtLen) continue;
                if (TryMaterializeFordCt(
                        body, body.Length, d.CtLen, 0, 0, 0, out ct, out var how, fordIkm)
                    && how.StartsWith("pack", StringComparison.Ordinal))
                    return true;
                if (body.Length == d.CtLen
                    && TryMaterializeFordCt(
                        body, body.Length, d.CtLen, 0, 0, 0, out ct, out _, fordIkm))
                    return true;
            }

            // H-ORDER: body dello stesso OID da altri FileGroup (cache di processo).
            if (!string.IsNullOrEmpty(d.ObjectId)
                && OidHostBodyCache.TryPackScanOpen(
                    d.ObjectId, d.CtLen, fordIkm, out ct, out _, out _))
                return true;
        }

        return false;
    }

    // #region agent log
    private static void AgentLog(
        string hypothesisId,
        string location,
        string message,
        Dictionary<string, object?> data)
    {
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = RunId,
                    ["hypothesisId"] = hypothesisId,
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "LiveFillPipeline." + location,
                    ["message"] = message,
                    ["data"] = data,
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
    }
    // #endregion
}
