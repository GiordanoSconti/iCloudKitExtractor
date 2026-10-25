using System.Globalization;
using System.IO;
using System.Text.Json;
using System.Threading;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Dump temporaneo IKE in formato/x64dbg oracle
/// (<c>ag_/storage45_/ford_/ikm_/data_/mac21_/key33_</c>) per replay offline
/// con <c>IkeAgProbe --cmp-ike-ag / --cmp-mac-siv</c>.
/// <para>
/// Abilita: <c>IKE_ORACLE_DUMP=1</c> (solo fail) o <c>=all</c> (ogni decrypt).
/// Root: <c>IKE_ORACLE_DUMP_DIR</c> oppure <c>{work}/tmp/ike_oracle</c> via
/// <see cref="SetRoot"/>.
/// </para>
/// </summary>
public static class IkeOraclePairDumpWriter
{
    public const string FolderName = "ike_oracle";
    private static readonly object Gate = new();
    private static string? _root;
    private static int _nextId =
        int.TryParse(Environment.GetEnvironmentVariable("IKE_ORACLE_DUMP_START"), out var s)
            ? Math.Max(3000, s)
            : 3000;

    /// <summary>
    /// <c>1</c>/<c>true</c>/<c>fail</c> → dump solo fail; <c>all</c> → ogni TraceDecrypt.
    /// </summary>
    public static bool Enabled
    {
        get
        {
            var v = Environment.GetEnvironmentVariable("IKE_ORACLE_DUMP");
            return string.Equals(v, "1", StringComparison.Ordinal)
                   || string.Equals(v, "true", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(v, "fail", StringComparison.OrdinalIgnoreCase)
                   || string.Equals(v, "all", StringComparison.OrdinalIgnoreCase);
        }
    }

    public static bool DumpAll =>
        string.Equals(
            Environment.GetEnvironmentVariable("IKE_ORACLE_DUMP"),
            "all",
            StringComparison.OrdinalIgnoreCase);

    public static void SetRoot(string? directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
            return;
        lock (Gate)
        {
            _root = directory;
            Directory.CreateDirectory(directory);
            var nextPath = Path.Combine(directory, "_next_id.txt");
            if (File.Exists(nextPath)
                && int.TryParse(File.ReadAllText(nextPath).Trim(), out var n)
                && n >= 3000)
                _nextId = n;
        }
    }

    public static string? ResolveRoot()
    {
        var env = Environment.GetEnvironmentVariable("IKE_ORACLE_DUMP_DIR");
        if (!string.IsNullOrWhiteSpace(env))
            return env;
        return _root;
    }

    public sealed record PairMaterials(
        BackupAsset Asset,
        byte[] AuthBody,
        IReadOnlyDictionary<string, (byte[] Compact, long MmcsStart)>? HostSiblings,
        AuthorizeGetDecryptPlan Plan,
        byte[] FordIkm,
        IReadOnlyList<FileGroupFillDecrypt.BoundStorage> Storages,
        IReadOnlyList<byte[]>? DataChunks,
        byte[]? BestFordCt,
        IReadOnlyList<FordMmcsDecryptor.FordChunkKey>? BestKeys,
        string? FailReason,
        string? Note,
        int FordOpen,
        int FordSkip);

    /// <summary>
    /// Scrive il pair-compatible. Ritorna id numerico o -1 se skip.
    /// </summary>
    public static int TryDump(PairMaterials m)
    {
        if (!Enabled)
            return -1;
        var failed = !string.IsNullOrEmpty(m.FailReason)
                     || m.BestKeys is not { Count: > 0 }
                     || m.DataChunks is not { Count: > 0 };
        if (!DumpAll && !failed)
            return -1;

        var root = ResolveRoot();
        if (string.IsNullOrWhiteSpace(root))
        {
            // Fallback stabile accanto ai dump x64dbg.
            root = Path.Combine(
                Path.GetTempPath(),
                "ike_oracle_live",
                "ike_run");
        }

        int id;
        lock (Gate)
        {
            Directory.CreateDirectory(root);
            id = _nextId++;
            try
            {
                File.WriteAllText(Path.Combine(root!, "_next_id.txt"), id.ToString("D4"));
            }
            catch { /* ignore */ }
        }

        var sid = id.ToString("D4", CultureInfo.InvariantCulture);
        try
        {
            WriteAll(root!, sid, m);
            AppendIndex(root!, sid, m);
            return id;
        }
        catch
        {
            return -1;
        }
    }

    private static void WriteAll(string root, string sid, PairMaterials m)
    {
        File.WriteAllBytes(Path.Combine(root, $"ag_{sid}.bin"), m.AuthBody);

        //  un file per GET host (oid@start), niente concat compact.
        var hostKeys = new List<string>();
        var hostBytes = 0L;
        if (m.HostSiblings is { Count: > 0 })
        {
            var hi = 0;
            foreach (var (key, (body, start)) in m.HostSiblings
                         .OrderBy(static kv => kv.Key, StringComparer.Ordinal))
            {
                if (key.StartsWith("sig:", StringComparison.Ordinal)
                    || key.StartsWith("gate:", StringComparison.Ordinal)
                    || body.Length == 0)
                    continue;
                if (!key.Contains('@', StringComparison.Ordinal))
                    continue;
                var safe = key.Replace('@', '_');
                if (safe.Length > 80)
                    safe = safe[..80];
                File.WriteAllBytes(Path.Combine(root, $"host_{sid}_{hi:D2}_{safe}.bin"), body);
                hostKeys.Add(key);
                hostBytes += body.Length;
                hi++;
            }
        }

        var gate = ResolveGate45(m);
        if (gate is { Length: 45 })
            File.WriteAllBytes(Path.Combine(root, $"storage45_{sid}.bin"), gate);

        if (m.FordIkm is { Length: > 0 })
            File.WriteAllBytes(Path.Combine(root, $"ikm_{sid}.bin"), m.FordIkm);

        if (m.Asset.RecordPayload is { Length: > 32 } rp)
            File.WriteAllBytes(Path.Combine(root, $"rp_{sid}.bin"), rp);

        var ford = m.BestFordCt
                   ?? m.Storages.FirstOrDefault(static s => s.HasFord && s.FordCt is { Length: > 0 }).FordCt;
        if (ford is { Length: > 0 })
            File.WriteAllBytes(Path.Combine(root, $"ford_{sid}.bin"), ford);

        if (m.DataChunks is { Count: > 0 } data && data[0].Length > 0)
            File.WriteAllBytes(Path.Combine(root, $"data_{sid}.bin"), data[0]);

        var mac = ResolveMac21(m);
        if (mac is { Length: 21 })
            File.WriteAllBytes(Path.Combine(root, $"mac21_{sid}.bin"), mac);

        if (m.BestKeys is { Count: > 0 } keys && keys[0].Key is { Length: >= 32 } k)
        {
            // Formato dump live: lead 0x04 ‖ KEY32 (33B).
            var key33 = new byte[33];
            key33[0] = 0x04;
            k.AsSpan(0, 32).CopyTo(key33.AsSpan(1));
            File.WriteAllBytes(Path.Combine(root, $"key33_{sid}.bin"), key33);
            File.WriteAllBytes(Path.Combine(root, $"key32_{sid}.bin"), k.AsSpan(0, 32).ToArray());
        }

        // Ford CT di ogni storage HAS-Ford (noise / multi-candidate).
        for (var i = 0; i < m.Storages.Count; i++)
        {
            var s = m.Storages[i];
            if (s.FordCt is not { Length: > 0 })
                continue;
            File.WriteAllBytes(
                Path.Combine(root, $"ford_storage{i}_h{s.ContainerIndex}_{sid}.bin"),
                s.FordCt);
        }

        var meta = new Dictionary<string, object?>
        {
            ["id"] = sid,
            ["source"] = "ike",
            ["recordName"] = m.Asset.RecordName,
            ["relativePath"] = m.Asset.RelativePath,
            ["domain"] = m.Asset.Domain,
            ["failReason"] = m.FailReason,
            ["note"] = m.Note,
            ["fordOpen"] = m.FordOpen,
            ["fordSkip"] = m.FordSkip,
            ["authBytes"] = m.AuthBody.Length,
            ["hostKeys"] = hostKeys,
            ["hostBytes"] = hostBytes,
            ["hostN"] = hostKeys.Count,
            ["ikmLen"] = m.FordIkm.Length,
            ["ikmHead8"] = m.FordIkm.Length >= 8
                ? Convert.ToHexString(m.FordIkm.AsSpan(0, 8))
                : null,
            ["fordLen"] = ford?.Length ?? 0,
            ["fordHead8"] = ford is { Length: >= 8 }
                ? Convert.ToHexString(ford.AsSpan(0, 8))
                : null,
            ["ikmOpensFord"] = m.FordIkm.Length > 0 && ford is { Length: > 0 }
                && FordMmcsDecryptor.BlobOpensWithIkm(m.FordIkm, ford),
            ["wrapHex"] = m.Asset.AssetProtectionInfoHex,
            ["wrapLen"] = string.IsNullOrWhiteSpace(m.Asset.AssetProtectionInfoHex)
                ? 0
                : m.Asset.AssetProtectionInfoHex!.Length / 2,
            ["rpLen"] = m.Asset.RecordPayload?.Length ?? 0,
            ["data0Len"] = m.DataChunks is { Count: > 0 } ? m.DataChunks[0].Length : 0,
            ["mac21"] = mac is { Length: 21 } ? Convert.ToHexString(mac) : null,
            ["gate45"] = gate is { Length: 45 } ? Convert.ToHexString(gate) : null,
            ["fileChecksum"] = m.Plan.FileChecksum is { Length: 21 } fc
                ? Convert.ToHexString(fc)
                : null,
            ["assetSignature"] = m.Asset.AssetSignature is { Length: > 0 } sig
                ? Convert.ToHexString(sig)
                : null,
            ["refs"] = m.Plan.References
                .Select(static r => $"{r.ContainerIndex}:{r.ChunkIndex}")
                .ToArray(),
            ["storages"] = m.Storages.Select(static s => new
            {
                h = s.ContainerIndex,
                hasFord = s.HasFord,
                fordLen = s.FordCt?.Length ?? 0,
                note = s.Note,
            }).ToArray(),
            ["keyHints"] = m.BestKeys?.Select(static k => k.ChunkLengthHint).ToArray(),
            ["utc"] = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
        };
        File.WriteAllText(
            Path.Combine(root, $"meta_{sid}.json"),
            JsonSerializer.Serialize(meta, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static byte[]? ResolveGate45(PairMaterials m)
    {
        // Preferisci CI45 / nested gate che incorpora FileChecksum.
        byte[]? fileId = m.Plan.FileChecksum is { Length: 21 } fc
            ? fc
            : m.Asset.AssetSignature is { Length: 21 } sig ? sig : null;

        if (fileId is { Length: 21 })
        {
            foreach (var d in UbChunkBuilder.ExtractAuthFordDescriptors(m.AuthBody))
            {
                if (d.Gate45.Length == 45
                    && UbChunkBuilder.GateEmbedsFileChecksum(d.Gate45, fileId))
                    return d.Gate45;
            }

            foreach (var group in m.Plan.Containers)
            {
                foreach (var ch in group)
                {
                    if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch)
                        && ch.Checksum21.Length == 45
                        && UbChunkBuilder.GateEmbedsFileChecksum(ch.Checksum21, fileId))
                        return ch.Checksum21;
                }
            }

            // Fallback strutturale: 0C0F01 ‖ FC ‖ 21×00 (probe match-by-FC ancora utile).
            var syn = new byte[45];
            syn[0] = 0x0C;
            syn[1] = 0x0F;
            syn[2] = 0x01;
            fileId.CopyTo(syn.AsSpan(3));
            return syn;
        }

        foreach (var d in UbChunkBuilder.ExtractAuthFordDescriptors(m.AuthBody))
        {
            if (d.Gate45.Length == 45)
                return d.Gate45;
        }

        return null;
    }

    private static byte[]? ResolveMac21(PairMaterials m)
    {
        if (m.Plan.References.Count == 0)
            return null;
        var r = m.Plan.References[0];
        if ((uint)r.ContainerIndex >= (uint)m.Plan.Containers.Count)
            return null;
        var g = m.Plan.Containers[r.ContainerIndex];
        if ((uint)r.ChunkIndex >= (uint)g.Count)
            return null;
        var ch = g[r.ChunkIndex];
        return ch.Checksum21 is { Length: 21 } mac ? mac : null;
    }

    private static void AppendIndex(string root, string sid, PairMaterials m)
    {
        var line = JsonSerializer.Serialize(new Dictionary<string, object?>
        {
            ["id"] = sid,
            ["path"] = m.Asset.RelativePath ?? m.Asset.RecordName,
            ["record"] = m.Asset.RecordName,
            ["fail"] = m.FailReason,
            ["fordOpen"] = m.FordOpen,
            ["sig"] = m.Asset.AssetSignature is { Length: >= 4 } s
                ? Convert.ToHexString(s.AsSpan(0, 4))
                : null,
            ["utc"] = DateTime.UtcNow.ToString("o", CultureInfo.InvariantCulture),
        });
        lock (Gate)
            File.AppendAllText(Path.Combine(root, "index.jsonl"), line + Environment.NewLine);
    }
}
