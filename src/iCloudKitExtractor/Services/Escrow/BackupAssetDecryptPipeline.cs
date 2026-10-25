using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Cascata unica MMCS/Ford → plaintext (o data-tail ciphertext).
/// Stadi: a=MMCS, b=split geometrico, c=interleaved/packed, d=sibling+select,
/// e=DecryptAsset SIV+MAC, f=data-tail/refs fallback.
/// </summary>
public static class BackupAssetDecryptPipeline
{
    public sealed record Result(
        byte[] Body,
        string Stage,
        string Mode,
        bool Decrypted,
        string? Note,
        string? FailReason = null);

    /// <summary>Post-decrypt: LZFSE se magic bvx*. Restituisce (body, expanded, preLen).</summary>
    public static (byte[] Body, bool Expanded, int PreLength) ApplyLzfse(byte[] plain)
    {
        var pre = plain.Length;
        if (LzfseDecompressor.TryExpand(plain, out var expanded))
            return (expanded, true, pre);
        return (plain, false, pre);
    }

    public static Result TryDecrypt(
        BackupAsset asset,
        byte[] compact,
        byte[] authBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        IReadOnlyList<SignedUrlChunk> chunks,
        IReadOnlyList<(long Start, long End)> ranges,
        byte[]? fordIkm,
        string fordIkmSource,
        bool canMmcs,
        bool usePlan,
        byte[]? mmcsKek16,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblingCompacts,
        ReadOnlyMemory<byte> impliedFord = default)
    {
        var record = asset.RecordName;
        var path = asset.RelativePath ?? asset.RecordName;
        var fordFamily = UbChunkBuilder.IsFordFamilySingleGet(plan)
                         || UbChunkBuilder.IsFordFamilyZeroKeyPlan(plan);

        // --- a: MMCS CFB (non Ford-family) ---
        if (canMmcs && !fordFamily && mmcsKek16 is { Length: 16 })
        {
            try
            {
                if (usePlan && plan.TotalCryptoBytes == compact.Length)
                {
                    var pt = MmcsChunkCrypto.DecryptAndAssemble(compact, plan, mmcsKek16);
                    StageLog("a", "ok", record, path, new { mode = "mmcs-decrypt", len = pt.Length });
                    return new Result(pt, "a", "mmcs-decrypt", true, null);
                }

                if (!usePlan)
                {
                    var cfb = MmcsChunkCrypto.DecryptCfb(mmcsKek16, compact);
                    if (LooksPlausiblePlain(cfb))
                    {
                        StageLog("a", "ok", record, path, new { mode = "mmcs-cfb-no-plan", len = cfb.Length });
                        return new Result(cfb, "a", "mmcs-cfb-no-plan", true, null);
                    }
                }
            }
            catch (Exception ex)
            {
                StageLog("a", "fail", record, path, new { err = Clip(ex.Message) });
            }
        }
        else
        {
            StageLog("a", "skip", record, path, new { canMmcs, fordFamily });
        }

        // --- b–d: build Ford split ---
        var fordCiphers = new List<byte[]>();
        var dataChunks = new List<byte[]>();
        var split = false;
        var splitVia = "";

        if (FordMmcsDecryptor.TrySplitByAuthorizeGetPlan(
                compact, orderedChunks, chunks, plan, out fordCiphers, out dataChunks))
        {
            split = true;
            splitVia = "plan";
        }
        else if (FordMmcsDecryptor.TrySplitCompactByRanges(
                     compact, ranges, out var fordCt, out dataChunks))
        {
            fordCiphers = [fordCt];
            split = true;
            splitVia = "ranges";
        }

        StageLog("b", split ? "ok" : "fail", record, path, new
        {
            splitVia,
            fordN = fordCiphers.Count,
            dataN = dataChunks.Count,
        });

        // --- c: interleaved / packed host ---
        if (!split
            && FordMmcsDecryptor.TryExtractInterleavedPackedFord(
                compact, plan, out fordCiphers, out dataChunks, fordIkm ?? []))
        {
            split = true;
            splitVia = "interleaved";
            StageLog("c", "ok", record, path, new { splitVia, fordN = fordCiphers.Count });
        }
        else if (!split
                 && FordMmcsDecryptor.TryExtractFordFamilyPackedHost(
                     compact, plan, out fordCiphers, out dataChunks, impliedFord.Span, fordIkm ?? []))
        {
            split = true;
            splitVia = "packed-host";
            StageLog("c", "ok", record, path, new { splitVia, fordN = fordCiphers.Count });
        }
        else if (!split)
        {
            StageLog("c", "fail", record, path, new { });
        }

        // Implied Ford (dataStart−112) DISABILITATO — usa solo Auth FileGroup GET exact.
        if (!split && impliedFord.Length >= 0x12)
        {
            StageLog("c", "implied_ford_disabled", record, path, new
            {
                fordLen = impliedFord.Length,
            });
        }

        // --- d: sibling Ford ---
        // MAC gate: usare i byte *owned* del file (ChunkInfo Offset/Length), non il compact
        // packed multi-tenant (gap+chunk altrui). Login Data: compact=2464 → select fail;
        // chunk0=2048 → Ford 560 B cross-OID apre (probe chrome-login-560).
        if (!split
            && fordIkm is { Length: > 0 }
            && siblingCompacts is { Count: > 0 }
            && compact.Length > 0)
        {
            var macs = FordMmcsDecryptor.ExtractChunkHeaderMacs(authBody);
            var chunkAbsStart = orderedChunks.Count > 0 && orderedChunks[0].ByteRange is { } fr
                ? fr.Start
                : 0L;
            var dataOid = FirstDataObjectId(orderedChunks, plan);
            // Singolo host packed: owned = solo i chunk del file (Login Data).
            // Multi-host concat: Offset sono relativi a ogni GET — lo slice owned fallisce;
            // DecryptAsset vuole il compact intero (PDF Deep Learning).
            var dataHosts = plan.Containers.Count(static c => c.Count > 0);
            var ownedData = dataHosts > 1
                ? compact
                : (TryBuildOwnedDataBytes(compact, plan) ?? compact);
            if (FordMmcsDecryptor.TryFindFordInSiblingCompacts(
                    fordIkm, chunkAbsStart, siblingCompacts, out var sibFord, ownedData, macs,
                    preferObjectId: dataOid))
            {
                fordCiphers = [sibFord];
                dataChunks = [ownedData];
                split = true;
                splitVia = "sibling";
                StageLog("d", "ok", record, path, new
                {
                    fordLen = sibFord.Length,
                    macN = macs.Count,
                    owned = ownedData.Length,
                });
            }
            else if (FordMmcsDecryptor.TryFindFordInSiblingCompacts(
                         fordIkm, chunkAbsStart, siblingCompacts, out sibFord,
                         preferObjectId: dataOid))
            {
                fordCiphers = [sibFord];
                dataChunks = [ownedData];
                split = true;
                splitVia = "sibling";
                StageLog("d", "ok", record, path, new { fordLen = sibFord.Length, macN = macs.Count });
            }
            else
            {
                StageLog("d", "fail", record, path, new
                {
                    siblings = siblingCompacts.Count,
                    owned = ownedData.Length,
                    compact = compact.Length,
                });
            }
        }
        else if (!split)
        {
            StageLog("d", "skip", record, path, new { hasIkm = fordIkm is { Length: > 0 } });
        }

        // Refine packed data after geometric/sibling split
        // Solo se dataChunks è ancora il compact packed intero (non già owned-slice da sibling).
        if (split
            && UbChunkBuilder.IsFordFamilyZeroKeyPlan(plan)
            && dataChunks.Count > 0
            && Concat(dataChunks).Length == compact.Length)
        {
            var packedData = Concat(dataChunks);
            var externalFord = fordCiphers.Count == 1 ? fordCiphers[0] : ReadOnlySpan<byte>.Empty;
            if (FordMmcsDecryptor.TryExtractInterleavedPackedFord(
                    packedData, plan, out var ownedFords, out var ownedData, fordIkm ?? [])
                && ownedFords.Count > 0 && ownedData.Count > 0)
            {
                fordCiphers = ownedFords;
                dataChunks = ownedData;
                splitVia += "+refine-interleaved";
            }
            else if (FordMmcsDecryptor.TryExtractFordFamilyPackedHost(
                         packedData, plan, out ownedFords, out ownedData, externalFord, fordIkm ?? [])
                     && ownedFords.Count > 0 && ownedData.Count > 0)
            {
                fordCiphers = ownedFords;
                dataChunks = ownedData;
                splitVia += "+refine-packed";
            }
        }

        // Select among many Ford candidates (IKM+MAC); reset if polluted.
        // Non sostituire Ford già aperti dal plan (es. Instagram 155+112) con un
        // sibling singolo: TrySelect confronta contro data concatenata e fallisce,
        // poi picka un Ford SIV-ok sbagliato.
        if (split && fordIkm is { Length: > 0 } && dataChunks.Count == 1)
        {
            var macs = FordMmcsDecryptor.ExtractChunkHeaderMacs(authBody);
            var data0 = dataChunks[0];
            var planFordsOpen = fordCiphers.Count > 0
                && fordCiphers.All(f => FordMmcsDecryptor.BlobOpensWithIkm(fordIkm, f));
            var needSelect = !planFordsOpen
                && (fordCiphers.Count > 1
                    || (fordCiphers.Count == 1 && fordCiphers[0].Length > 112));
            if (planFordsOpen && fordCiphers.Count > 1)
            {
                StageLog("d", "keep_plan_fords", record, path, new
                {
                    fordN = fordCiphers.Count,
                    fordLens = fordCiphers.Select(static f => f.Length).ToArray(),
                });
            }
            else if (needSelect)
            {
                if (data0.Length > 1_048_576
                    && FordMmcsDecryptor.TryExtractInterleavedPackedFord(
                        data0, plan, out var ownF, out var ownD, fordIkm ?? [])
                    && ownF.Count > 0)
                {
                    fordCiphers = ownF;
                    dataChunks = ownD;
                }
                else if (FordMmcsDecryptor.TrySelectFordCipher(
                             fordIkm, data0, macs, fordCiphers, out var picked))
                {
                    fordCiphers = [picked];
                    StageLog("d", "select_ok", record, path, new { pickedLen = picked.Length });
                }
                else
                {
                    byte[]? sibFord = null;
                    if (siblingCompacts is { Count: > 0 })
                    {
                        var abs = orderedChunks.Count > 0 && orderedChunks[^1].ByteRange is { } dr
                            ? dr.Start
                            : 0L;
                        var dataOid = FirstDataObjectId(orderedChunks, plan);
                        if (FordMmcsDecryptor.TryFindFordInSiblingCompacts(
                                fordIkm, abs, siblingCompacts, out var found, data0, macs,
                                preferObjectId: dataOid))
                            sibFord = found;
                        else if (FordMmcsDecryptor.TryFindFordInSiblingCompacts(
                                     fordIkm, abs, siblingCompacts, out found,
                                     preferObjectId: dataOid))
                            sibFord = found;
                    }

                    if (sibFord is { Length: > 0 })
                    {
                        fordCiphers = [sibFord];
                        dataChunks = [data0];
                        StageLog("d", "select_sibling_ok", record, path, new { fordLen = sibFord.Length });
                    }
                    else if (FordMmcsDecryptor.TryExtractInterleavedPackedFord(
                                 data0, plan, out ownF, out ownD, fordIkm ?? [])
                             && ownF.Count > 0 && ownD.Count > 0)
                    {
                        fordCiphers = ownF;
                        dataChunks = ownD;
                    }
                    else if (fordCiphers.Count > 8)
                    {
                        split = false;
                        fordCiphers = [];
                        dataChunks = [];
                        StageLog("d", "select_reset_polluted", record, path, new { });
                    }
                    else
                    {
                        StageLog("d", "select_fail", record, path, new { fordN = fordCiphers.Count });
                    }
                }
            }
        }

        // D: tieni solo Ford che aprono con questo IKM. Blob multi-tenant (es. empty 6850 B)
        // → estrai la finestra che apre; se nessuna apre, scarta (non forzare un tenant altrui).
        if (split && fordIkm is { Length: > 0 } && fordCiphers.Count > 0)
        {
            var before = fordCiphers.Count;
            var survivors = new List<byte[]>(fordCiphers.Count);
            var narrowed = 0;
            foreach (var f in fordCiphers)
            {
                if (!FordMmcsDecryptor.TryExtractIkmOpenFord(fordIkm, f, out var open))
                    continue;
                if (open.Length != f.Length)
                    narrowed++;
                survivors.Add(open);
            }

            fordCiphers = survivors;
            if (fordCiphers.Count != before || narrowed > 0)
            {
                StageLog("d", "drop_dead_geometric", record, path, new
                {
                    before,
                    after = fordCiphers.Count,
                    narrowed,
                    fordLens = fordCiphers.Select(static x => x.Length).ToArray(),
                });
            }
        }

        // Implied Ford recover DISABILITATO (dataStart−112 inventiva).
        _ = impliedFord;

        // Prima di DecryptAsset: empty same-OID prima del geometrico, poi resto del pool.
        // Skip se i Ford del plan sono già multipli e aperti (non collassare a 1 sibling).
        if (split
            && fordIkm is { Length: > 0 }
            && dataChunks.Count >= 1
            && siblingCompacts is { Count: > 0 }
            && !(fordCiphers.Count > 1
                 && fordCiphers.All(f => FordMmcsDecryptor.BlobOpensWithIkm(fordIkm, f))))
        {
            var macs = FordMmcsDecryptor.ExtractChunkHeaderMacs(authBody);
            var data0 = dataChunks.Count == 1 ? dataChunks[0] : Concat(dataChunks);
            var dataOid = FirstDataObjectId(orderedChunks, plan);
            var sameOid = new List<byte[]>();
            var otherOid = new List<byte[]>();
            foreach (var blob in EnumerateFordSiblingCandidates(
                         siblingCompacts, requireMacGate: macs.Count > 0, onlyObjectId: dataOid))
                sameOid.Add(blob);
            foreach (var blob in EnumerateFordSiblingCandidates(
                         siblingCompacts, requireMacGate: macs.Count > 0, excludeObjectId: dataOid))
                otherOid.Add(blob);

            var candidates = new List<byte[]>(sameOid.Count + fordCiphers.Count + otherOid.Count);
            candidates.AddRange(sameOid);
            candidates.AddRange(fordCiphers);
            candidates.AddRange(otherOid);

            if (candidates.Count > 0
                && FordMmcsDecryptor.TrySelectFordCipher(
                    fordIkm, data0, macs, candidates, out var picked))
            {
                fordCiphers = [picked];
                dataChunks = [data0];
                splitVia += "+sib-preselect";
                StageLog("d", "preselect_sibling_pool", record, path, new
                {
                    pool = candidates.Count,
                    sameOid = sameOid.Count,
                    pickedLen = picked.Length,
                    macN = macs.Count,
                });
            }
        }

        // --- e: DecryptAsset ---
        if (split && fordIkm is { Length: > 0 } && dataChunks.Count > 0)
        {
            Exception? decryptEx = null;
            var dataObjectStart = ResolveDataObjectStart(chunks, plan);
            if (fordCiphers.Count > 0)
            {
                try
                {
                    var ford = FordMmcsDecryptor.DecryptAsset(
                        fordIkm, fordCiphers, dataChunks, asset.SizeBytes, authBody,
                        dataObjectStart);
                    StageLog("e", "ok", record, path, new
                    {
                        ikmSource = fordIkmSource,
                        ford = ford.FordBytes,
                        data = ford.DataChunks,
                        note = ford.Note,
                        pt = ford.Plaintext.Length,
                        dataObjectStart,
                    });
                    return new Result(
                        ford.Plaintext,
                        "e",
                        "ford-siv",
                        true,
                        $"ford={ford.FordBytes} data={ford.DataChunks} ikm={fordIkmSource} via={splitVia}");
                }
                catch (Exception ex)
                {
                    decryptEx = ex;
                    StageLog("e", "fail", record, path, new { err = Clip(ex.Message), via = splitVia, dataObjectStart });
                }
            }
            else
            {
                StageLog("e", "skip_empty_ford", record, path, new { via = splitVia });
            }

            if (decryptEx is not null || fordCiphers.Count == 0)
            {
                // Recovery: stesso pool Ford-plausible + TrySelectFordCipher.
                var dataOnly = Concat(dataChunks);
                var macs = FordMmcsDecryptor.ExtractChunkHeaderMacs(authBody);
                var abs = orderedChunks.Count > 0 && orderedChunks[^1].ByteRange is { } dr
                    ? dr.Start
                    : (orderedChunks.Count > 0 && orderedChunks[0].ByteRange is { } fr
                        ? fr.Start
                        : 0L);

                byte[]? retryFord = null;
                List<byte[]> retryData = [dataOnly];
                var retryVia = "";

                var dataOid = FirstDataObjectId(orderedChunks, plan);
                var pool = new List<byte[]>();
                if (siblingCompacts is { Count: > 0 })
                {
                    foreach (var blob in EnumerateFordSiblingCandidates(
                                 siblingCompacts, requireMacGate: macs.Count > 0, onlyObjectId: dataOid))
                        pool.Add(blob);
                    foreach (var blob in EnumerateFordSiblingCandidates(
                                 siblingCompacts, requireMacGate: macs.Count > 0, excludeObjectId: dataOid))
                        pool.Add(blob);
                }

                if (pool.Count > 0
                    && FordMmcsDecryptor.TrySelectFordCipher(
                        fordIkm, dataOnly, macs, pool, out var poolPicked))
                {
                    retryFord = poolPicked;
                    retryVia = "e-retry-pool-select";
                }
                else if (siblingCompacts is { Count: > 0 }
                    && FordMmcsDecryptor.TryFindFordInSiblingCompacts(
                        fordIkm, abs, siblingCompacts, out var sib, dataOnly, macs,
                        preferObjectId: dataOid))
                {
                    retryFord = sib;
                    retryVia = "e-retry-sibling-mac";
                }
                else if (siblingCompacts is { Count: > 0 }
                         && FordMmcsDecryptor.TryFindFordInSiblingCompacts(
                             fordIkm, abs, siblingCompacts, out sib,
                             preferObjectId: dataOid))
                {
                    retryFord = sib;
                    retryVia = "e-retry-sibling";
                }
                else if (FordMmcsDecryptor.TryExtractInterleavedPackedFord(
                             dataOnly, plan, out var ownF, out var ownD, fordIkm ?? [])
                         && ownF.Count > 0 && ownD.Count > 0)
                {
                    retryFord = ownF[0];
                    retryData = ownD.ToList();
                    if (ownF.Count > 1
                        && FordMmcsDecryptor.TrySelectFordCipher(
                            fordIkm, Concat(ownD), macs, ownF, out var picked))
                        retryFord = picked;
                    retryVia = "e-retry-interleaved";
                }
                else if (FordMmcsDecryptor.TryExtractFordFamilyPackedHost(
                             dataOnly, plan, out ownF, out ownD, ReadOnlySpan<byte>.Empty, fordIkm ?? [])
                         && ownF.Count > 0 && ownD.Count > 0)
                {
                    retryFord = ownF[0];
                    retryData = ownD.ToList();
                    retryVia = "e-retry-packed";
                }

                if (retryFord is { Length: > 0 })
                {
                    try
                    {
                        var ford2 = FordMmcsDecryptor.DecryptAsset(
                            fordIkm, [retryFord], retryData, asset.SizeBytes, authBody,
                            dataObjectStart);
                        StageLog("e", "retry_ok", record, path, new
                        {
                            via = retryVia,
                            ford = ford2.FordBytes,
                            pt = ford2.Plaintext.Length,
                        });
                        return new Result(
                            ford2.Plaintext,
                            "e",
                            "ford-siv",
                            true,
                            $"ford={ford2.FordBytes} data={ford2.DataChunks} ikm={fordIkmSource} via={retryVia}");
                    }
                    catch (Exception ex2)
                    {
                        StageLog("e", "retry_fail", record, path, new
                        {
                            via = retryVia,
                            err = Clip(ex2.Message),
                        });
                    }
                }
                else
                {
                    StageLog("e", "retry_miss", record, path, new
                    {
                        siblings = siblingCompacts?.Count ?? 0,
                        pool = pool.Count,
                        dataLen = dataOnly.Length,
                        macN = macs.Count,
                    });
                }

                // Fallback: scrivi solo data (non ford‖data intero).
                return FinishFallback(
                    dataOnly.Length > 0 && dataOnly.Length < compact.Length ? dataOnly : compact,
                    plan,
                    usePlan,
                    canMmcs,
                    mmcsKek16,
                    record,
                    path,
                    decryptEx is null ? null : Clip(decryptEx.Message));
            }
        }

        if (split && fordIkm is not { Length: > 0 })
            StageLog("e", "skip_no_ikm", record, path, new { via = splitVia });
        else if (!split)
            StageLog("e", "skip_no_split", record, path, new { });

        // --- f: fallback data-tail / refs / compact ---
        return FinishFallback(compact, plan, usePlan, canMmcs, mmcsKek16, record, path, null);
    }

    private static Result FinishFallback(
        byte[] compact,
        AuthorizeGetDecryptPlan plan,
        bool usePlan,
        bool canMmcs,
        byte[]? mmcsKek16,
        string record,
        string path,
        string? priorFail)
    {
        if (!usePlan)
        {
            if (canMmcs && mmcsKek16 is { Length: 16 })
            {
                try
                {
                    var cfb = MmcsChunkCrypto.DecryptCfb(mmcsKek16, compact);
                    if (LooksPlausiblePlain(cfb))
                    {
                        StageLog("f", "ok", record, path, new { mode = "mmcs-cfb-no-plan" });
                        return new Result(cfb, "f", "mmcs-cfb-no-plan", true, priorFail);
                    }
                }
                catch
                {
                    // ignore
                }
            }

            StageLog("f", "ok", record, path, new { mode = "compact-no-plan", len = compact.Length });
            return new Result(compact, "f", "compact-no-plan", false, priorFail);
        }

        if (plan.TotalCryptoBytes != compact.Length)
        {
            var toWrite = compact;
            var mode = "compact-mismatch";
            if (plan.TotalCryptoBytes is > 0 and <= int.MaxValue
                && compact.Length > plan.TotalCryptoBytes
                && UbChunkBuilder.IsFordFamilyZeroKeyPlan(plan))
            {
                var dataLen = (int)plan.TotalCryptoBytes;
                toWrite = compact.AsSpan(compact.Length - dataLen, dataLen).ToArray();
                mode = "compact-mismatch-data-tail";
            }

            StageLog("f", "ok", record, path, new
            {
                mode,
                cryptoSum = plan.TotalCryptoBytes,
                compact = compact.Length,
                written = toWrite.Length,
                priorFail,
            });
            return new Result(toWrite, "f", mode, false, priorFail);
        }

        if (canMmcs && mmcsKek16 is { Length: 16 })
        {
            try
            {
                var pt = MmcsChunkCrypto.DecryptAndAssemble(compact, plan, mmcsKek16);
                StageLog("f", "ok", record, path, new { mode = "mmcs-decrypt", len = pt.Length });
                return new Result(pt, "f", "mmcs-decrypt", true, priorFail);
            }
            catch (Exception ex)
            {
                StageLog("f", "mmcs_fail_refs", record, path, new { err = Clip(ex.Message) });
            }
        }

        var refs = MmcsChunkCrypto.AssembleByReferences(compact, plan);
        StageLog("f", "ok", record, path, new { mode = "refs-ciphertext", len = refs.Length });
        return new Result(refs, "f", "refs-ciphertext", false, priorFail);
    }

    private static bool LooksPlausiblePlain(ReadOnlySpan<byte> b)
        => b.Length >= 16
           && (FileListSqliteParser.LooksLikeSqlite(b)
               || LzfseDecompressor.IsLzfseMagic(b)
               || (b.Length >= 8 && b[0] == 0x62 && b[1] == 0x70 && b[2] == 0x6C && b[3] == 0x69)); // bpli

    private static byte[] Concat(IReadOnlyList<byte[]> parts)
    {
        if (parts.Count == 1)
            return parts[0];
        var n = parts.Sum(static p => p.Length);
        var buf = new byte[n];
        var o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, buf, o, p.Length);
            o += p.Length;
        }

        return buf;
    }

    /// <summary>
    /// Sibling empty-host per Ford select. Con MAC: ogni body che può contenere una
    /// finestra standard (≤4 KiB), preferendo lunghezze esatte. Senza MAC: solo esatte.
    /// Chiavi sibling tipiche: <c>oid@start</c>.
    /// </summary>
    private static IEnumerable<byte[]> EnumerateFordSiblingCandidates(
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)> siblingCompacts,
        bool requireMacGate,
        string? onlyObjectId = null,
        string? excludeObjectId = null)
    {
        var list = new List<(int Rank, int Len, byte[] Blob)>();
        foreach (var (key, (blob, _)) in siblingCompacts)
        {
            if (blob is not { Length: > 0 })
                continue;
            var oid = ObjectIdFromSiblingKey(key);
            if (!string.IsNullOrEmpty(onlyObjectId)
                && !string.Equals(oid, onlyObjectId, StringComparison.Ordinal))
                continue;
            if (!string.IsNullOrEmpty(excludeObjectId)
                && string.Equals(oid, excludeObjectId, StringComparison.Ordinal))
                continue;
            if (requireMacGate)
            {
                if (!FordMmcsDecryptor.CanContainStandardFordWindow(blob.Length))
                    continue;
            }
            else if (!FordMmcsDecryptor.IsExactStandardFordHostLength(blob.Length))
            {
                continue;
            }

            var rank = FordMmcsDecryptor.IsExactStandardFordHostLength(blob.Length) ? 0 : 1;
            list.Add((rank, blob.Length, blob));
        }

        list.Sort(static (a, b) =>
        {
            var c = a.Rank.CompareTo(b.Rank);
            return c != 0 ? c : a.Len.CompareTo(b.Len);
        });
        foreach (var item in list)
            yield return item.Blob;
    }

    private static string ObjectIdFromSiblingKey(string key)
    {
        var at = key.IndexOf('@');
        return at > 0 ? key[..at] : key;
    }

    /// <summary>Object-id del primo host dati (ChunkInfo &gt; 0) nel plan/ordered.</summary>
    private static string? FirstDataObjectId(
        IReadOnlyList<SignedUrlChunk> orderedChunks,
        AuthorizeGetDecryptPlan plan)
    {
        for (var i = 0; i < orderedChunks.Count; i++)
        {
            if ((uint)i < (uint)plan.Containers.Count && plan.Containers[i].Count == 0)
                continue;
            var oid = orderedChunks[i].EdgeHeaders?.ObjectId;
            if (!string.IsNullOrEmpty(oid))
                return oid;
        }

        foreach (var c in orderedChunks)
        {
            var oid = c.EdgeHeaders?.ObjectId;
            if (!string.IsNullOrEmpty(oid))
                return oid;
        }

        return null;
    }

    /// <summary>
    /// ByteRange.Start del host authorizeGet che contiene i ChunkInfo del file
    /// (indice container = indice in <paramref name="authOrderChunks"/> pre-reorder).
    /// </summary>
    private static long? ResolveDataObjectStart(
        IReadOnlyList<SignedUrlChunk> authOrderChunks,
        AuthorizeGetDecryptPlan plan)
    {
        if (plan.References.Count == 0)
            return null;
        var ci = plan.References[0].ContainerIndex;
        if ((uint)ci >= (uint)authOrderChunks.Count)
            return null;
        return authOrderChunks[ci].ByteRange?.Start;
    }

    private static string Clip(string s)
        => s.Length <= 160 ? s : s[..160];

    // Former agent-debug stage tracer — kept as no-op so call sites stay readable.
    private static void StageLog(string stage, string status, string record, string path, object? data)
    {
        if (stage is not ("e" or "f"))
            return;
        if (stage == "e" && status is not ("fail" or "skip_empty_ford"))
            return;
        if (stage == "f" && status != "ok")
            return;
        if (stage == "f" && data is not null)
        {
            var mode = data.GetType().GetProperty("mode")?.GetValue(data)?.ToString() ?? "";
            if (mode is not ("refs-ciphertext" or "compact-mismatch-data-tail" or "compact-mismatch"))
                return;
        }

        // #region agent log
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["location"] = $"BackupAssetDecryptPipeline.stage_{stage}",
                ["message"] = status,
                ["data"] = new Dictionary<string, object?>
                {
                    ["record"] = record,
                    ["path"] = path,
                    ["stage"] = stage,
                    ["status"] = status,
                    ["detailJson"] = data is null ? null : JsonSerializer.Serialize(data),
                },
                ["hypothesisId"] = "H-BK2",
                ["runId"] = "bk-decrypt-v1",
            });
            File.AppendAllText(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                line + Environment.NewLine);
        }
        catch
        {
            // ignore debug log failures
        }
        // #endregion
    }

    /// <summary>
    /// Byte dati del file dentro un compact packed (solo ChunkInfo delle refs), senza gap Ford
    /// né chunk di altri tenant. Serve al MAC gate di <see cref="FordMmcsDecryptor.TrySelectFordCipher"/>.
    /// </summary>
    private static byte[]? TryBuildOwnedDataBytes(byte[] compact, AuthorizeGetDecryptPlan plan)
    {
        if (compact.Length == 0 || plan.References.Count == 0)
            return null;

        using var ms = new MemoryStream();
        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                return null;
            var group = plan.Containers[r.ContainerIndex];
            if (group.Count == 0)
                return null;
            if (!FordMmcsDecryptor.TryOwnedPackedSlice(
                    compact, group, r.ChunkIndex, out var data, out _))
                return null;
            if (data.Length == 0)
                return null;
            ms.Write(data);
        }

        return ms.Length > 0 ? ms.ToArray() : null;
    }

}
