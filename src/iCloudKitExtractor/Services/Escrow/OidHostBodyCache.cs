using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Download;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Cache di processo: body MMCS per <c>oid@start</c> (tutti i FileGroup).
/// Pending Ford è keyed per <c>gateHex</c> (pack multi-asset sullo stesso OID).
/// Seed tardivo → <see cref="Put"/> → packScan IKM → .chunks + retry assemble.
/// </summary>
public static class OidHostBodyCache
{
    private static readonly ConcurrentDictionary<string, byte[]> Bodies =
        new(StringComparer.Ordinal);

    /// <summary>Key = lowercase hex(Gate45). Un pending per gate owned (non per OID).</summary>
    private static readonly ConcurrentDictionary<string, PendingFord> Pending =
        new(StringComparer.Ordinal);

    /// <summary>Path asset recuperati dopo plant tardivo (per retry assemble).</summary>
    private static readonly ConcurrentQueue<string> RecoveredPaths = new();

    private readonly record struct PendingFord(
        byte[] Gate45, int CtLen, byte[] Ikm, string Path, string Oid);

    public static void Put(string oid, long start, byte[] body)
    {
        if (string.IsNullOrEmpty(oid) || body.Length < 0x12)
            return;
        Bodies[$"{oid}@{start}"] = body;
        TryRecoverPending(oid, body, start);
    }

    public static void RegisterPending(
        string? oid,
        byte[] gate45,
        int ctLen,
        ReadOnlySpan<byte> ikm,
        string? path)
    {
        if (string.IsNullOrEmpty(oid)
            || gate45.Length != 45
            || !UbChunkBuilder.IsPlausibleAuthFordCtLen(ctLen)
            || ikm.Length is not (16 or 32))
            return;

        var gateKey = Convert.ToHexString(gate45).ToLowerInvariant();
        var p = new PendingFord(
            gate45.ToArray(), ctLen, ikm.ToArray(), path ?? "", oid);
        Pending[gateKey] = p;

        // Pack già in cache (ordine inverso rispetto al fail).
        foreach (var (key, body) in Bodies)
        {
            if (!key.StartsWith(oid + "@", StringComparison.Ordinal))
                continue;
            if (TryRecoverOne(body, p, hostStart: -1, gateKey))
                break;
        }
    }

    public static bool TryPackScanOpen(
        string oid,
        int ctLen,
        ReadOnlySpan<byte> ikm,
        out byte[] ct,
        out string how,
        out long fromStart)
    {
        ct = [];
        how = "";
        fromStart = -1;
        if (string.IsNullOrEmpty(oid) || ikm.IsEmpty || ctLen < 0x12)
            return false;

        var prefix = oid + "@";
        foreach (var (key, body) in Bodies)
        {
            if (!key.StartsWith(prefix, StringComparison.Ordinal))
                continue;
            if (!long.TryParse(key.AsSpan(prefix.Length), out var start))
                continue;
            if (!LiveFillPipeline.TryMaterializeFordCt(
                    body, body.Length, ctLen, 0, 0, 0, out ct, out how, ikm))
                continue;
            fromStart = start;
            return true;
        }

        return false;
    }

    /// <summary>
    /// True se almeno un descriptor Ford owned dal plan ha CT materializzabile
    /// (chunkfile / gate-mirror / oid packScan con IKM).
    /// </summary>
    public static bool TryOwnedFordCtAvailable(
        byte[]? authBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? siblings,
        ReadOnlySpan<byte> fordIkm,
        byte[]? assetSignature21 = null)
    {
        if (authBody is not { Length: > 0 } || fordIkm.Length is not (16 or 32))
            return false;

        var ikm = fordIkm.ToArray();
        var anyOwned = false;
        foreach (var d in UbChunkBuilder.CollectAuthFordDescriptors(authBody, plan, hosts))
        {
            if (d.Gate45.Length != 45 || !UbChunkBuilder.IsPlausibleAuthFordCtLen(d.CtLen))
                continue;
            if (plan.FileChecksum is { Length: 21 } || assetSignature21 is { Length: 21 })
            {
                var ownsPlan = plan.FileChecksum is { Length: 21 }
                               && UbChunkBuilder.GateOwnsPlan(d.Gate45, plan);
                var ownsAsset = assetSignature21 is { Length: 21 }
                                && UbChunkBuilder.GateEmbedsFileChecksum(
                                    d.Gate45, assetSignature21);
                if (!ownsPlan && !ownsAsset)
                    continue;
            }
            anyOwned = true;

            if (ChunkFileCache.TryRead(d.Gate45, d.CtLen, out var fileCt)
                && fileCt.Length == d.CtLen
                && fileCt[0] == 0x04
                && FordMmcsDecryptor.BlobOpensExactWithIkm(ikm, fileCt))
                return true;

            if (siblings is not null)
            {
                var gk = "gate:" + Convert.ToHexString(d.Gate45).ToLowerInvariant();
                if (siblings.TryGetValue(gk, out var ge)
                    && ge.Compact.Length == d.CtLen
                    && ge.Compact[0] == 0x04
                    && FordMmcsDecryptor.BlobOpensExactWithIkm(ikm, ge.Compact))
                    return true;
            }

            if (!string.IsNullOrEmpty(d.ObjectId)
                && TryPackScanOpen(d.ObjectId, d.CtLen, ikm, out _, out _, out _))
                return true;

            // Host bodies già in sibling map (stesso seed batch).
            if (siblings is not null && !string.IsNullOrEmpty(d.ObjectId))
            {
                var prefix = d.ObjectId + "@";
                foreach (var (k, (body, _)) in siblings)
                {
                    if (!k.StartsWith(prefix, StringComparison.Ordinal))
                        continue;
                    if (LiveFillPipeline.TryMaterializeFordCt(
                            body, body.Length, d.CtLen, 0, 0, 0, out _, out _, ikm))
                        return true;
                }
            }
        }

        // Nessun Ford owned → non è un defer Ford (Pipe C / no-ford path diverso).
        return !anyOwned;
    }

    public static void RegisterOwnedPendings(
        byte[]? authBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk> hosts,
        ReadOnlySpan<byte> fordIkm,
        string? path)
    {
        if (authBody is not { Length: > 0 } || fordIkm.Length is not (16 or 32))
            return;
        foreach (var d in UbChunkBuilder.CollectAuthFordDescriptors(authBody, plan, hosts))
        {
            if (d.Gate45.Length != 45 || string.IsNullOrEmpty(d.ObjectId))
                continue;
            if (plan.FileChecksum is { Length: 21 }
                && !UbChunkBuilder.GateOwnsPlan(d.Gate45, plan))
                continue;
            RegisterPending(d.ObjectId, d.Gate45, d.CtLen, fordIkm, path);
        }
    }

    public static bool TryDequeueRecovered(out string path) =>
        RecoveredPaths.TryDequeue(out path!);

    public static int PendingCount => Pending.Count;

    private static void TryRecoverPending(string oid, byte[] body, long start)
    {
        foreach (var (gateKey, p) in Pending)
        {
            if (!string.Equals(p.Oid, oid, StringComparison.Ordinal))
                continue;
            _ = TryRecoverOne(body, p, start, gateKey);
        }
    }

    private static bool TryRecoverOne(
        byte[] body, PendingFord p, long hostStart, string gateKey)
    {
        if (!LiveFillPipeline.TryMaterializeFordCt(
                body, body.Length, p.CtLen, 0, 0, 0,
                out var ct, out var how, p.Ikm))
            return false;

        ChunkFileCache.PutOverwrite(p.Gate45, ct);
        Pending.TryRemove(gateKey, out _);
        if (!string.IsNullOrEmpty(p.Path))
            RecoveredPaths.Enqueue(p.Path);

        // #region agent log
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = "oid-order-v2",
                    ["hypothesisId"] = "H-ORDER",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "OidHostBodyCache.TryRecoverOne",
                    ["message"] = "oid_pack_recover",
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["oid8"] = p.Oid.Length >= 8 ? p.Oid[..8] : p.Oid,
                        ["bodyLen"] = body.Length,
                        ["hostStart"] = hostStart,
                        ["how"] = how,
                        ["ctLen"] = ct.Length,
                        ["head8"] = Convert.ToHexString(
                            ct.AsSpan(0, Math.Min(8, ct.Length))),
                        ["path"] = p.Path,
                        ["gate8"] = Convert.ToHexString(p.Gate45.AsSpan(0, 8)),
                        ["ikmHead8"] = Convert.ToHexString(p.Ikm.AsSpan(0, 8)),
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
        return true;
    }
}
