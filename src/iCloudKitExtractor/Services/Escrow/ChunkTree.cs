using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text.Json;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Chiave stabile del nodo (FillChunks Phase A lookup/create su RB-tree).
/// </summary>
public readonly record struct ChunkNodeKey(int ContainerIndex, int ChunkIndex)
    : IComparable<ChunkNodeKey>
{
    public int CompareTo(ChunkNodeKey other)
    {
        var c = ContainerIndex.CompareTo(other.ContainerIndex);
        return c != 0 ? c : ChunkIndex.CompareTo(other.ChunkIndex);
    }

    public override string ToString() => $"{ContainerIndex}:{ChunkIndex}";
}

/// <summary>
/// Nodo chunk <c>malloc(0x78)</c> — layout logico allineato al nativo live:
/// <c>+0x28</c> dataLen, <c>+0x2C</c> length (Phase A = ChunkInfo; Phase B inject = Ford PT),
/// <c>+0x38</c> KEY33, <c>+0x58</c> signature21 / checksum21 (MAC20 = [1:21]).
/// <see cref="CipherLength"/> = ChunkInfo.Length immutabile per attach dati (ciphertext).
/// </summary>
public sealed class ChunkNode
{
    public required ChunkNodeKey Key { get; init; }

    /// <summary><c>node+0x28</c>.</summary>
    public long OffsetAt28 { get; init; }

    /// <summary>
    /// <c>node+0x2C</c>: Phase A = ChunkInfo.Length; dopo inject = Ford chunk_len (plain hint).
    /// </summary>
    public int LengthAt2c { get; private set; }

    /// <summary>Lunghezza ciphertext ChunkInfo (attach / ResolveChunkDataBuf) — non sovrascritta all'inject.</summary>
    public int CipherLength { get; private set; }

    /// <summary><c>node+0x58</c> signature21 / checksum21 (live injectLen/CD dump).</summary>
    public byte[] ChecksumAt58 { get; private set; } = [];

    /// <summary>Alias storico — preferire <see cref="ChecksumAt58"/>.</summary>
    public byte[] ChecksumAt30 => ChecksumAt58;

    /// <summary>MAC20 = checksum[1:21] per VerifyDigest / ChunkDecrypt hdr.</summary>
    public byte[] Mac20 { get; private set; } = [];

    /// <summary><c>node+0x38</c> KEY33 dopo DecryptFordKeys inject.</summary>
    public FordMmcsDecryptor.FordChunkKey? KeyAt38 { get; private set; }

    /// <summary>
    /// Auth <c>ChunkInfo.chunkEncryptionKey</c> — leaf Pipe C (DecryptChunk AES-CFB)
    /// dentro ChunkDecrypt quando presente.
    /// </summary>
    public byte[] ChunkEncryptionKey { get; private set; } = [];

    /// <summary>Body chunk (ResolveChunkDataBuf / storage) — lato MUT.</summary>
    public byte[]? DataSlice { get; private set; }

    public int RefOrdinal { get; set; } = -1;

    // Alias usati dal resto del codice.
    public long Offset => OffsetAt28;
    public int Length => CipherLength > 0 ? CipherLength : LengthAt2c;
    public byte[] Checksum21 => ChecksumAt58;
    public FordMmcsDecryptor.FordChunkKey? FordKey => KeyAt38;

    public void SetLengthAt2c(int length) => LengthAt2c = length;

    public void SetCipherLength(int length)
    {
        CipherLength = length;
        if (LengthAt2c <= 0)
            LengthAt2c = length;
    }

    public void RefreshChecksum21(ReadOnlySpan<byte> checksum21)
    {
        if (checksum21.Length == 0)
            return;
        // Solo data MAC21 sul nodo decrypt; gate45 non va in Mac20.
        if (checksum21.Length == 45)
            return;
        ChecksumAt58 = checksum21.ToArray();
        Mac20 = ChecksumAt58.Length == 21
            ? ChecksumAt58.AsSpan(1).ToArray()
            : [];
    }

    /// <summary>
    /// inject @ +0x94d9b5: KEY → +0x38; <c>mov [node+0x2C], eax</c> = Ford chunk_len (+0x40).
    /// </summary>
    public void InjectFordKey(FordMmcsDecryptor.FordChunkKey key)
    {
        KeyAt38 = key;
        if (key.ChunkLengthHint is int h && h > 0)
            LengthAt2c = h;
    }

    public void SetChunkEncryptionKey(ReadOnlySpan<byte> key)
    {
        if (key.Length > 0)
            ChunkEncryptionKey = key.ToArray();
    }

    public void AttachData(byte[] slice) => DataSlice = slice;

    public void ClearDataSlice() => DataSlice = null;

    /// <summary>Rilascia KEY/data/MAC dopo file done.</summary>
    public void ClearPayload()
    {
        KeyAt38 = null;
        DataSlice = null;
        Mac20 = [];
    }
}

/// <summary>
/// <c>chunkRecordMap</c> / RB-tree FillChunks (<c>+0x94d630</c>).
/// Mappa ordinata <see cref="ChunkNodeKey"/> → nodo (CLR <see cref="SortedDictionary{TKey,TValue}"/>
/// = albero rosso-nero, stesso modello di <c>std::map</c>).
/// <list type="number">
/// <item><b>FillChunks</b> per storage: Phase A; Phase B solo se fordSize≠0.</item>
/// <item>Pipe B: FillChunks successivo sullo stesso map — KEY già a +0x38.</item>
/// <item>MUT: per ogni nodo in ordine refs → ChunkDecrypt → VerifyDigest → append.</item>
/// </list>
/// </summary>
public sealed class ChunkTree
{
    /// <summary>RB-tree chunkRecordMap (SortedDictionary = red-black).</summary>
    private readonly SortedDictionary<ChunkNodeKey, ChunkNode> _rbMap = new();

    /// <summary>Ordine FileChecksumChunkReferences (walk MUT).</summary>
    private readonly List<ChunkNodeKey> _fillOrder = [];

    public int Count => _rbMap.Count;
    public IReadOnlyList<ChunkNodeKey> FillOrder => _fillOrder;

    public void Clear()
    {
        var n = _rbMap.Count;
        foreach (var node in _rbMap.Values)
            node.ClearPayload();
        _rbMap.Clear();
        _fillOrder.Clear();
        // #region agent log
        AgentTreeLog("H-TREE-CLR", "tree_cleared", new Dictionary<string, object?>
        {
            ["runId"] = "ike-hostwalk-v1",
            ["clearedNodes"] = n,
        });
        // #endregion
    }

    /// <summary>Su fail decrypt: drop data, tieni KEY (+0x38) per retry Pipe B.</summary>
    public void ClearDataSlicesOnly()
    {
        foreach (var node in _rbMap.Values)
            node.ClearDataSlice();
    }

    public IEnumerable<ChunkNode> NodesInFillOrder()
    {
        foreach (var k in _fillOrder)
        {
            if (_rbMap.TryGetValue(k, out var n))
                yield return n;
        }
    }

    /// <summary>Chiavi RB-tree in ordine inorder (stesso walk di Phase B inject).</summary>
    public IReadOnlyList<ChunkNodeKey> RbMapInorderKeys() => _rbMap.Keys.ToList();

    public bool TryGet(ChunkNodeKey key, out ChunkNode node) =>
        _rbMap.TryGetValue(key, out node!);

    /// <summary>
    /// <c>FillChunks</c> (+0x94d630) su <b>uno</b> storage: Phase A sempre;
    /// Phase B solo se <paramref name="fordKeys"/> non vuoto.
    /// </summary>
    public string FillChunks(
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<FordMmcsDecryptor.FordChunkKey>? fordKeys)
    {
        PhaseAEnsureNodes(plan);
        if (fordKeys is { Count: > 0 })
        {
            PhaseBInjectFordKeys(fordKeys);
            // #region agent log
            AgentTreeLog("H-STRUCT-FC", "fillchunks_pass", new Dictionary<string, object?>
            {
                ["runId"] = "ike-hostwalk-v1",
                ["pipe"] = "A",
                ["keys"] = fordKeys.Count,
                ["nodes"] = _fillOrder.Count,
                ["keyed"] = CountNodesWithFordKeys(),
            });
            // #endregion
            return "A";
        }

        var keyed = CountNodesWithFordKeys();
        // #region agent log
        AgentTreeLog("H-STRUCT-FC", "fillchunks_pass", new Dictionary<string, object?>
        {
            ["runId"] = "ike-hostwalk-v1",
            ["pipe"] = "B",
            ["keys"] = 0,
            ["nodes"] = _fillOrder.Count,
            ["keyed"] = keyed,
        });
        // #endregion
        return "B";
    }

    public int CountNodesWithFordKeys()
    {
        var n = 0;
        foreach (var node in NodesInFillOrder())
        {
            if (node.KeyAt38 is not null)
                n++;
        }

        return n;
    }

    /// <summary>Nodi con Auth <c>chunkEncryptionKey</c> (Pipe C / FL CFB).</summary>
    public int CountNodesWithChunkEncryptionKeys()
    {
        var n = 0;
        foreach (var node in NodesInFillOrder())
        {
            if (node.ChunkEncryptionKey.Length > 0)
                n++;
        }

        return n;
    }

    /// <summary>Ogni nodo ha KEY33 Ford oppure chunkEncryptionKey Pipe C.</summary>
    public bool EveryNodeHasDecryptMaterial()
    {
        foreach (var node in NodesInFillOrder())
        {
            if (node.KeyAt38 is null && node.ChunkEncryptionKey.Length == 0)
                return false;
        }

        return _fillOrder.Count > 0;
    }

    public int PhaseAEnsureNodes(AuthorizeGetDecryptPlan plan)
    {
        _fillOrder.Clear();
        var created = 0;
        var ordinal = 0;
        var skippedFord = 0;
        foreach (var r in plan.References)
        {
            if ((uint)r.ContainerIndex >= (uint)plan.Containers.Count)
                throw new CryptographicException(
                    $"FillChunks Phase A: container {r.ContainerIndex} fuori range");
            var group = plan.Containers[r.ContainerIndex];
            if ((uint)r.ChunkIndex >= (uint)group.Count)
                throw new CryptographicException(
                    $"FillChunks Phase A: chunk {r.ChunkIndex} fuori range container {r.ContainerIndex}");

            var ch = group[r.ChunkIndex];
            // Refs devono puntare a data CI. Se Auth punta a gate45, salta (non è nodo decrypt).
            if (UbChunkBuilder.IsAuthFordDescriptorChunk(ch))
            {
                skippedFord++;
                continue;
            }

            var key = new ChunkNodeKey(r.ContainerIndex, r.ChunkIndex);
            if (!_rbMap.TryGetValue(key, out var node))
            {
                node = new ChunkNode
                {
                    Key = key,
                    OffsetAt28 = ch.Offset,
                };
                node.SetCipherLength(ch.Length);
                node.SetLengthAt2c(ch.Length);
                node.RefreshChecksum21(ch.Checksum21);
                node.SetChunkEncryptionKey(ch.EncryptionKey);
                _rbMap[key] = node;
                created++;
            }
            else
            {
                if (ch.Checksum21.Length > 0)
                    node.RefreshChecksum21(ch.Checksum21);
                if (ch.EncryptionKey.Length > 0 && node.ChunkEncryptionKey.Length == 0)
                    node.SetChunkEncryptionKey(ch.EncryptionKey);
            }

            node.RefOrdinal = ordinal++;
            _fillOrder.Add(key);
        }

        // #region agent log
        AgentTreeLog("H-TREE-A", "phase_a_ensure_nodes", new Dictionary<string, object?>
        {
            ["runId"] = "ike-gate45-v1",
            ["refs"] = plan.References.Count,
            ["mapN"] = _rbMap.Count,
            ["created"] = created,
            ["lookups"] = plan.References.Count - created - skippedFord,
            ["skippedFordCi"] = skippedFord,
            ["keyed"] = CountNodesWithFordKeys(),
            ["keys"] = _fillOrder.Take(12).Select(static k => k.ToString()).ToArray(),
            ["lens"] = NodesInFillOrder().Take(12).Select(static n => n.LengthAt2c).ToArray(),
        });
        // #endregion

        return created;
    }

    public void PhaseBInjectFordKeys(IReadOnlyList<FordMmcsDecryptor.FordChunkKey> keys)
    {
        if (_fillOrder.Count == 0)
            throw new CryptographicException("FillChunks Phase B: tree vuoto (Phase A mancante)");
        if (keys.Count == 0)
            throw new CryptographicException("Cannot decrypt ford info from empty storages");

        // inject @ +0x94d9a0: zip FordKeyEntry × nodi in fill-order (= refs).
        // Nessun match per length-hint (non è).
        var nodes = NodesInFillOrder().ToList();
        if (keys.Count != nodes.Count)
        {
            throw new CryptographicException(
                $"FillChunks Phase B: keys={keys.Count} ≠ nodes={nodes.Count} (zip only)");
        }

        const string mode = "fill-order-zip";
        for (var i = 0; i < nodes.Count; i++)
            nodes[i].InjectFordKey(keys[i]);

        // #region agent log
        var distinctC = nodes.Select(static n => n.Key.ContainerIndex).Distinct().Count();
        try
        {
            var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "03cce7",
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["hypothesisId"] = "H-KEY-ORDER",
                ["runId"] = "fill-order-zip-v1",
                ["location"] = "ChunkTree.PhaseBInjectFordKeys",
                ["message"] = "phase_b_inject_keys",
                ["data"] = new Dictionary<string, object?>
                {
                    ["mode"] = mode,
                    ["keys"] = keys.Count,
                    ["nodes"] = nodes.Count,
                    ["fillOrderHead"] = _fillOrder.Take(8).Select(static k => k.ToString()).ToArray(),
                    ["injectHead"] = nodes.Take(8).Select(static x => x.Key.ToString()).ToArray(),
                    ["rbInorderHead"] = _rbMap.Keys.Take(8).Select(static k => k.ToString()).ToArray(),
                    ["injected"] = CountNodesWithFordKeys(),
                    ["containers"] = distinctC,
                },
            });
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                line + Environment.NewLine);
        }
        catch { /* ignore */ }
        // #endregion
    }

    public void AttachDataSlices(IReadOnlyList<byte[]> slices)
    {
        var nodes = NodesInFillOrder().ToList();
        if (slices.Count != nodes.Count)
        {
            throw new CryptographicException(
                $"FillChunks data attach: slices {slices.Count} != nodes {nodes.Count}");
        }

        for (var i = 0; i < nodes.Count; i++)
        {
            // Attach = ciphertext ChunkInfo.Length, NON node+0x2C post-inject (Ford PT hint).
            var cipherLen = nodes[i].CipherLength > 0 ? nodes[i].CipherLength : nodes[i].LengthAt2c;
            if (slices[i].Length != cipherLen && cipherLen > 0)
            {
                throw new CryptographicException(
                    $"FillChunks data attach: slice[{i}] len {slices[i].Length} != " +
                    $"ChunkInfo.Length {cipherLen} (ci={nodes[i].Key} node+0x2C={nodes[i].LengthAt2c})");
            }

            nodes[i].AttachData(slices[i]);
        }
    }

    /// <summary>
    /// Attacca slice dai ChunkInfo di un solo container (dopo FillChunks su quel storage).
    /// </summary>
    public int AttachDataFromContainerHost(
        int containerIndex,
        byte[] hostBody,
        AuthorizeGetDecryptPlan plan)
    {
        if ((uint)containerIndex >= (uint)plan.Containers.Count)
            return 0;
        var group = plan.Containers[containerIndex];
        if (group.Count == 0 || hostBody.Length == 0)
            return 0;

        var attached = 0;
        foreach (var node in NodesInFillOrder())
        {
            if (node.Key.ContainerIndex != containerIndex)
                continue;
            if ((uint)node.Key.ChunkIndex >= (uint)group.Count)
                continue;
            var ch = group[node.Key.ChunkIndex];
            if (ch.Length <= 0)
                continue;

            byte[] slice;
            if (ch.Offset >= 0
                && ch.Offset + ch.Length <= hostBody.Length)
            {
                slice = hostBody.AsSpan((int)ch.Offset, ch.Length).ToArray();
            }
            else if (hostBody.Length == ch.Length)
            {
                slice = hostBody.ToArray();
            }
            else
            {
                // Sequential pack: somma lunghezze dei chunk precedenti nello stesso host.
                var off = 0;
                for (var i = 0; i < node.Key.ChunkIndex; i++)
                    off += group[i].Length;
                if (off + ch.Length > hostBody.Length)
                {
                    throw new CryptographicException(
                        $"FillChunks attach host ci={containerIndex} chunk={node.Key.ChunkIndex}: " +
                        $"body={hostBody.Length} need off={off}+{ch.Length}");
                }

                slice = hostBody.AsSpan(off, ch.Length).ToArray();
            }

            node.AttachData(slice);
            if (node.CipherLength <= 0)
                node.SetCipherLength(slice.Length);
            attached++;
        }

        // #region agent log
        AgentTreeLog("H-HOST-ATT", "attach_container_host", new Dictionary<string, object?>
        {
            ["runId"] = "ike-hostwalk-v1",
            ["ci"] = containerIndex,
            ["bodyLen"] = hostBody.Length,
            ["attached"] = attached,
            ["chunkN"] = group.Count,
        });
        // #endregion

        return attached;
    }

    public bool AllNodesReadyForDecrypt()
    {
        foreach (var n in NodesInFillOrder())
        {
            if (n.KeyAt38 is null || n.DataSlice is null || n.Mac20.Length < 20)
                return false;
        }

        return _fillOrder.Count > 0;
    }

    /// <summary>
    /// Assemble  ChunkDecrypt + VerifyDigest in ordine refs
    /// (via <see cref="FordMmcsDecryptor.AssemblePlaintextFromFileRefs"/>).
    /// </summary>
    public byte[] DecryptAssemble(long? declaredPlainSize = null)
    {
        var nodes = NodesInFillOrder().ToList();
        if (nodes.Count == 0)
            throw new CryptographicException("FillChunks decrypt: nessun nodo");

        var keys = new List<FordMmcsDecryptor.FordChunkKey>(nodes.Count);
        var data = new List<byte[]>(nodes.Count);
        var macs = new List<byte[]>(nodes.Count);
        foreach (var n in nodes)
        {
            if (n.KeyAt38 is null)
                throw new CryptographicException(
                    $"FillChunks decrypt: nodo {n.Key} senza KEY@+0x38");
            if (n.DataSlice is null)
                throw new CryptographicException(
                    $"FillChunks decrypt: nodo {n.Key} senza data");
            if (n.Mac20.Length < 20)
                throw new CryptographicException(
                    $"FillChunks decrypt: nodo {n.Key} senza MAC20");

            keys.Add(n.KeyAt38);
            data.Add(n.DataSlice);
            macs.Add(n.Mac20);
        }

        return FordMmcsDecryptor.AssemblePlaintextFromFileRefs(
            keys, data, macs, declaredPlainSize, logContext: "ChunkTree.DecryptAssemble");
    }

    /// <summary>
    /// MUT esplicito per-nodo (opt-in host-walk). Default assemble usa il path batch sopra.
    /// </summary>
    /// <summary>
    /// caller MUT → ChunkDecrypt per nodo.
    /// Leaf: KEY33/SIV (Pipe A/B) oppure <c>DecryptChunk</c> AES-CFB (Pipe C)
    /// se il nodo ha <c>chunkEncryptionKey</c>.
    /// </summary>
    public byte[] DecryptAssembleMut(byte[]? mmcsKek16 = null)
    {
        var nodes = NodesInFillOrder().ToList();
        if (nodes.Count == 0)
            throw new CryptographicException("MUT ChunkDecrypt: nessun nodo");

        using var output = new MemoryStream();
        for (var i = 0; i < nodes.Count; i++)
        {
            var n = nodes[i];
            if (n.DataSlice is null)
                throw new CryptographicException(
                    $"MUT ChunkDecrypt: nodo {n.Key} senza data");

            byte[] pt;

            // Pipe C leaf (~3% / FL): chunkEncryptionKey → DecryptChunk AES-CFB.
            // type 0x01 = key già plain (no KEK); type 0x02 = AES-KW(mmcsKek).
            if (n.ChunkEncryptionKey.Length > 0)
            {
                var kek = mmcsKek16 is { Length: 16 } ? mmcsKek16 : ReadOnlySpan<byte>.Empty;
                var needsKek = n.ChunkEncryptionKey[0] == 0x02;
                if (needsKek && kek.IsEmpty)
                    throw new CryptographicException(
                        $"MUT Pipe C: manca MMCS KEK per chunkEncryptionKey type02 ({n.Key})");
                var aesKey = MmcsChunkCrypto.TryUnwrapChunkAesKey(n.ChunkEncryptionKey, kek)
                             ?? throw new CryptographicException(
                                 $"MUT Pipe C: unwrap chunkEncryptionKey fallito ({n.Key})");
                pt = MmcsChunkCrypto.DecryptCfb(aesKey, n.DataSlice);
                output.Write(pt);
                continue;
            }

            if (n.KeyAt38 is null)
                throw new CryptographicException(
                    $"MUT ChunkDecrypt: nodo {n.Key} senza KEY@+0x38 (Pipe B miss)");
            if (n.Mac20.Length < 20)
                throw new CryptographicException(
                    $"MUT ChunkDecrypt: nodo {n.Key} senza MAC20");

            var hint = n.KeyAt38.ChunkLengthHint is int h && h > 0 ? h : n.LengthAt2c;
            try
            {
                pt = FordMmcsDecryptor.ChunkDecrypt(
                    n.KeyAt38.Key, n.DataSlice, hint > 0 ? hint : null, n.Mac20);
            }
            catch (Exception ex)
            {
                // #region agent log
                AgentTreeLog("H-MUT", "chunk_decrypt_fail", new Dictionary<string, object?>
                {
                    ["runId"] = "ike-hostwalk-v1",
                    ["i"] = i,
                    ["node"] = n.Key.ToString(),
                    ["dataLen"] = n.DataSlice.Length,
                    ["hint"] = hint,
                    ["err"] = ex.Message.Length <= 120 ? ex.Message : ex.Message[..120],
                });
                // #endregion
                throw;
            }

            if (!FordMmcsDecryptor.VerifyDigestWithChunkKey(n.KeyAt38.Key, pt, n.Mac20))
            {
                // #region agent log
                AgentTreeLog("H-MUT", "verify_digest_fail", new Dictionary<string, object?>
                {
                    ["runId"] = "ike-hostwalk-v1",
                    ["i"] = i,
                    ["node"] = n.Key.ToString(),
                    ["ptLen"] = pt.Length,
                });
                // #endregion
                throw new CryptographicException(
                    "Verification of decryption has been failed (VerifyDigest)");
            }

            output.Write(pt);
        }

        return output.ToArray();
    }

    // #region agent log
    private static void AgentTreeLog(
        string hypothesisId,
        string message,
        Dictionary<string, object?> data)
    {
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "ike-hostwalk-v1",
                ["hypothesisId"] = hypothesisId,
                ["location"] = "ChunkTree",
                ["message"] = message,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = data,
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion
}
