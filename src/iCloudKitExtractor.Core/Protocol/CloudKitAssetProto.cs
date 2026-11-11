namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Parser strutturale del messaggio CloudKit/MMCS <c>Asset</c> (path).
/// Signature (<c>f2</c>) e <c>protectionInfo.protectionInfo</c> (<c>f15.f1</c>) sono
/// fratelli nello stesso messaggio — non si cerca il “primo wrap” nel payload.
/// </summary>
public static class CloudKitAssetProto
{
    /// <summary>Asset MMCS tipico in BackupAsset.contents.</summary>
    public sealed record ParsedAsset(
        byte[] Signature,
        byte[]? ProtectionWrap,
        byte[]? ReferenceSignature,
        long? SizeBytes,
        string? DownloadAuth,
        string? DownloadUrl,
        int Offset,
        int Length);

    /// <summary>
    /// Trova l'Asset il cui <c>f2</c> coincide con <paramref name="assetSignature"/>.
    /// </summary>
    public static ParsedAsset? TryFindBySignature(
        ReadOnlySpan<byte> window,
        ReadOnlySpan<byte> assetSignature)
    {
        if (assetSignature.Length < 4)
            return null;
        foreach (var asset in EnumerateAssets(window))
        {
            if (asset.Signature.AsSpan().SequenceEqual(assetSignature))
                return asset;
        }

        // H-WRAP1: flist lead 0x01 vs contents Asset.f2 lead 0x04 (stesso digest 20B).
        if (assetSignature.Length == 21)
        {
            var digest = assetSignature[1..];
            foreach (var asset in EnumerateAssets(window))
            {
                if (asset.Signature.Length == 21
                    && asset.Signature.AsSpan(1).SequenceEqual(digest))
                    return asset;
            }
        }

        return null;
    }

    /// <summary>
    /// Wrap AES-KW dallo stesso Asset della signature (strategia).
    /// Accetta anche match digest con lead diverso (flist <c>0x01</c> vs contents <c>0x04</c>).
    /// </summary>
    /// <summary>
    /// <c>FillFordIkmFromContents</c> su un CKFile/record (live x64dbg 2026-10-02):
    /// <c>map["contents"]</c> → Asset.protectionInfo → wrap40. Ordine IKE allineato:
    /// 1) field <c>contents</c> (anche se f2 lead/digest ≠ flist <c>0x01</c>),
    /// 2) f2+f15 / f17→file sul window. Mai il primo wrap di un PrivilegedBatch.
    /// </summary>
    public static byte[]? TryResolveOwnedWrap(
        ReadOnlySpan<byte> window,
        ReadOnlySpan<byte> fileSignature,
        out string source)
    {
        source = "missing";
        if (window.IsEmpty || fileSignature.Length < 4)
            return null;

        // FillFord: lookup key "contents" PRIMA — sig04 contents ≠ sig01 download.
        var fromContents = TryResolveContentsFieldWrap(window, fileSignature, out source);
        if (fromContents is { Length: 24 or 40 })
            return fromContents;

        var bySig = TryGetWrapForSignature(window, fileSignature);
        if (bySig is { Length: 24 or 40 })
        {
            source = "asset-proto";
            return bySig;
        }

        var byRef = TryGetWrapForReferenceSignature(window, fileSignature);
        if (byRef is { Length: 24 or 40 })
        {
            source = "asset-ref-sig";
            return byRef;
        }

        if (fileSignature.Length == 21)
        {
            byRef = TryGetWrapForReferenceSignature(window, fileSignature[1..]);
            if (byRef is { Length: 24 or 40 })
            {
                source = "asset-ref-digest";
                return byRef;
            }
        }

        return null;
    }

    /// <summary>
    /// True se <paramref name="wrap"/> è il wrap per il file.
    /// </summary>
    public static bool IsOwnedWrap(
        ReadOnlySpan<byte> window,
        ReadOnlySpan<byte> fileSignature,
        ReadOnlySpan<byte> wrap)
    {
        if (window.IsEmpty || fileSignature.Length < 4 || wrap.Length is not (24 or 40))
            return false;
        var owned = TryResolveOwnedWrap(window, fileSignature, out _);
        return owned is not null && owned.AsSpan().SequenceEqual(wrap);
    }

    /// <summary>
    /// Wrap dal field <c>contents</c> (map key). Live: digests sig04≠sig01 sul
    /// CKFile — non richiedere match flist. Batch-safe: solo Asset nella slice
    /// contents→extension/relativePath/…. Preferenza: match flist se c’è, altrimenti
    /// sole wrap nella slice, altrimenti Asset lead <c>0x04</c>.
    /// </summary>
    public static byte[]? TryResolveContentsFieldWrap(
        ReadOnlySpan<byte> window,
        ReadOnlySpan<byte> fileSignature,
        out string source)
    {
        source = "missing";
        if (window.IsEmpty)
            return null;

        var searchFrom = 0;
        while (searchFrom < window.Length)
        {
            var rel = IndexOf(window[searchFrom..], "contents"u8);
            if (rel < 0)
                break;
            var contentsIdx = searchFrom + rel;
            var sliceStart = contentsIdx + "contents".Length;
            if (sliceStart >= window.Length)
                break;

            var rest = window[sliceStart..];
            var end = rest.Length;
            end = CutBeforeFieldName(rest, end, "extension"u8);
            end = CutBeforeFieldName(rest, end, "relativePath"u8);
            end = CutBeforeFieldName(rest, end, "domain"u8);
            end = CutBeforeFieldName(rest, end, "encryptionKey"u8);
            end = CutBeforeFieldName(rest, end, "fileType"u8);
            end = CutBeforeFieldName(rest, end, "clonedFrom"u8);
            var nextContents = IndexOf(rest, "contents"u8);
            if (nextContents >= 64 && nextContents < end)
                end = nextContents;

            var slice = rest[..end];
            var assets = new List<ParsedAsset>();
            CollectAssets(slice, assets, baseOffset: 0);

            ParsedAsset? matched = null;
            byte[]? soleWrap = null;
            var soleOk = true;
            foreach (var a in assets)
            {
                if (a.ProtectionWrap is not { Length: 24 or 40 } w)
                    continue;

                if (fileSignature.Length >= 4 && AssetMatchesFileSignature(a, fileSignature))
                {
                    matched = a;
                    break;
                }

                if (soleWrap is null)
                    soleWrap = w;
                else if (!soleWrap.AsSpan().SequenceEqual(w))
                    soleOk = false;
            }

            //  CKFile già scoped → contents wrap (sig04 contents ≠ sig download OK).
            // Sole solo nella slice contents (mai lead04 / mai batch intero).
            byte[]? wrap = matched?.ProtectionWrap;
            if (wrap is null && soleOk && soleWrap is not null)
                wrap = soleWrap;

            if (wrap is { Length: 24 or 40 })
            {
                if (matched?.Signature is { Length: >= 1 } sig)
                    source = $"map-contents/sig{sig[0]:X2}";
                else
                    source = "map-contents/sole";
                return wrap;
            }

            searchFrom = sliceStart + Math.Max(1, end);
        }

        return null;
    }

    /// <summary>Senza file signature non si disambigua un batch → null.</summary>
    public static byte[]? TryResolveContentsFieldWrap(
        ReadOnlySpan<byte> window,
        out string source)
    {
        source = "missing";
        return null;
    }

    private static bool AssetMatchesFileSignature(
        ParsedAsset asset,
        ReadOnlySpan<byte> fileSignature)
    {
        if (fileSignature.Length < 4)
            return false;

        if (asset.Signature.AsSpan().SequenceEqual(fileSignature))
            return true;

        if (fileSignature.Length == 21 && asset.Signature.Length == 21
            && asset.Signature.AsSpan(1).SequenceEqual(fileSignature[1..]))
            return true;

        if (asset.ReferenceSignature is { Length: > 0 } refSig)
        {
            if (refSig.AsSpan().SequenceEqual(fileSignature))
                return true;
            if (fileSignature.Length == 21 && refSig.Length == 21
                && refSig.AsSpan(1).SequenceEqual(fileSignature[1..]))
                return true;
            if (fileSignature.Length == 21 && refSig.Length == 20
                && refSig.AsSpan().SequenceEqual(fileSignature[1..]))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Un solo wrap nel window intero (record multi-asset). Solo CT-gated in IKE.
    /// </summary>
    public static byte[]? TryResolveContentsSoleWrap(
        ReadOnlySpan<byte> window,
        out string source)
    {
        source = "missing";
        if (window.IsEmpty)
            return null;

        byte[]? sole = null;
        foreach (var a in EnumerateAssets(window))
        {
            if (a.ProtectionWrap is not { Length: 24 or 40 } w)
                continue;
            if (sole is null)
            {
                sole = w;
                continue;
            }

            if (!sole.AsSpan().SequenceEqual(w))
                return null;
        }

        if (sole is null)
            return null;
        source = "contents-sole-wrap";
        return sole;
    }

    /// <summary>
    /// Finestra valore del field <c>contents</c>: da dopo il nome fino al prossimo
    /// field name tipico del BackupAsset (evita Asset di altri campi nel merge globale).
    /// </summary>
    public static ReadOnlySpan<byte> SliceContentsFieldValue(ReadOnlySpan<byte> window)
    {
        var contentsIdx = IndexOf(window, "contents"u8);
        if (contentsIdx < 0)
            return ReadOnlySpan<byte>.Empty;

        var start = contentsIdx + "contents".Length;
        if (start >= window.Length)
            return ReadOnlySpan<byte>.Empty;

        var rest = window[start..];
        var end = rest.Length;
        end = CutBeforeFieldName(rest, end, "extension"u8);
        end = CutBeforeFieldName(rest, end, "relativePath"u8);
        end = CutBeforeFieldName(rest, end, "domain"u8);
        end = CutBeforeFieldName(rest, end, "encryptionKey"u8);
        end = CutBeforeFieldName(rest, end, "fileType"u8);
                end = CutBeforeFieldName(rest, end, "clonedFrom"u8);
        var nextContents = IndexOf(rest, "contents"u8);
        if (nextContents >= 64 && nextContents < end)
            end = nextContents;
        return rest[..end];
    }

    private static int CutBeforeFieldName(
        ReadOnlySpan<byte> rest,
        int end,
        ReadOnlySpan<byte> name)
    {
        var i = IndexOf(rest, name);
        // Evita tagli troppo corti (rumore binario / sottostringhe).
        if (i >= 64 && i < end)
            return i;
        return end;
    }

    /// <summary>
    /// Wrap AES-KW dall'Asset il cui <c>f2</c> coincide (stesso messaggio di <c>f15</c>).
    /// </summary>
    public static byte[]? TryGetWrapForSignature(
        ReadOnlySpan<byte> window,
        ReadOnlySpan<byte> assetSignature)
    {
        var asset = TryFindBySignature(window, assetSignature);
        if (asset?.ProtectionWrap is { Length: 24 or 40 } exact)
            return exact;

        // H-WRAP1: flist assetSignature lead 0x01, Asset.f2 in contents spesso 0x04 (stesso digest).
        if (assetSignature.Length == 21)
        {
            var digest = assetSignature[1..];
            foreach (var a in EnumerateAssets(window))
            {
                if (a.Signature.Length != 21)
                    continue;
                if (!a.Signature.AsSpan(1).SequenceEqual(digest))
                    continue;
                if (a.ProtectionWrap is { Length: 24 or 40 } w)
                    return w;
            }
        }

        return null;
    }

    /// <summary>
    /// Wrap AES-KW dall'Asset il cui <c>f17</c> (referenceSignature) coincide.
    /// CloudDocs dedup: il blob MMCS può usare reference sig distinta dalla file sig.
    /// </summary>
    public static byte[]? TryGetWrapForReferenceSignature(
        ReadOnlySpan<byte> window,
        ReadOnlySpan<byte> referenceSignature)
    {
        if (referenceSignature.Length < 4)
            return null;
        foreach (var asset in EnumerateAssets(window))
        {
            if (asset.ReferenceSignature is not { Length: > 0 } refSig)
                continue;
            if (!refSig.AsSpan().SequenceEqual(referenceSignature))
                continue;
            if (asset.ProtectionWrap is { Length: 24 or 40 } w)
                return w;
        }

        return null;
    }

    /// <summary>Tutti gli Asset riconoscibili nella finestra (contents / record / batch).</summary>
    public static List<ParsedAsset> EnumerateAssets(ReadOnlySpan<byte> window)
    {
        var list = new List<ParsedAsset>();
        if (window.IsEmpty)
            return list;

        // Preferisci il sottoalbero dopo il nome campo "contents".
        var contentsIdx = IndexOf(window, "contents"u8);
        if (contentsIdx >= 0)
            CollectAssets(window[(contentsIdx + "contents".Length)..], list, baseOffset: contentsIdx + "contents".Length);

        // Anche scan globale (batch multi-record / kalama).
        CollectAssets(window, list, baseOffset: 0);

        // Dedup per signature.
        var seen = new HashSet<string>(StringComparer.Ordinal);
        var unique = new List<ParsedAsset>(list.Count);
        foreach (var a in list)
        {
            var key = Convert.ToHexString(a.Signature);
            if (!seen.Add(key))
                continue;
            unique.Add(a);
        }

        return unique;
    }

    private static void CollectAssets(ReadOnlySpan<byte> data, List<ParsedAsset> into, int baseOffset)
    {
        // Candidati: length-delimited che contengono f2 = signature 21B (04‖…).
        for (var i = 0; i < data.Length - 4; i++)
        {
            var key = data[i];
            if ((key & 0x07) != 2)
                continue;
            var pos = i + 1;
            if (!TryReadVarint(data, ref pos, out var lenLong))
                continue;
            if (lenLong is < 40 or > 8192 or > int.MaxValue)
                continue;
            var len = (int)lenLong;
            if (pos + len > data.Length)
                continue;

            var slice = data.Slice(pos, len);
            if (!TryParseAssetMessage(slice, out var parsed))
                continue;

            into.Add(parsed with
            {
                Offset = baseOffset + pos,
                Length = len,
            });
            // Salta il messaggio per ridurre ridondanza (continua comunque per nested).
        }
    }

    /// <summary>Parse di un singolo messaggio Asset (campi f1…f21 tipici).</summary>
    public static bool TryParseAssetMessage(ReadOnlySpan<byte> msg, out ParsedAsset asset)
    {
        asset = null!;
        byte[]? signature = null;
        byte[]? wrap = null;
        byte[]? refSig = null;
        long? size = null;
        string? auth = null;
        string? url = null;

        var i = 0;
        while (i < msg.Length)
        {
            if (!TryReadVarint(msg, ref i, out var key))
                return false;
            var fn = (int)(key >> 3);
            var wt = (int)(key & 0x07);
            if (wt == 0)
            {
                if (!TryReadVarint(msg, ref i, out var v))
                    return false;
                if (fn == 4)
                    size = v;
                continue;
            }

            if (wt == 1)
            {
                if (i + 8 > msg.Length)
                    return false;
                i += 8;
                continue;
            }

            if (wt == 5)
            {
                if (i + 4 > msg.Length)
                    return false;
                i += 4;
                continue;
            }

            if (wt != 2)
                return false;

            if (!TryReadLengthDelimited(msg, ref i, out var body))
                return false;

            switch (fn)
            {
                // FileList/MMCS signatures: lead 0x04 (CSB/Ford) o 0x01 (assetSignature flist).
                case 2 when body.Length == 21 && body[0] is 0x01 or 0x04:
                    signature = body.ToArray();
                    break;
                case 5 when body.Length >= 8 && LooksAscii(body):
                    auth = System.Text.Encoding.ASCII.GetString(body);
                    break;
                case 8 when body.Length >= 8 && LooksAscii(body):
                    url = System.Text.Encoding.ASCII.GetString(body);
                    break;
                case 15:
                    // ProtectionInfo { bytes protectionInfo = 1; } → wrap 24/40
                    wrap = TryExtractProtectionInfoWrap(body) ?? wrap;
                    break;
                case 17 when body.Length == 21 && body[0] is 0x01 or 0x04:
                    refSig = body.ToArray();
                    break;
            }
        }

        if (signature is null)
            return false;

        asset = new ParsedAsset(
            signature,
            wrap,
            refSig,
            size,
            auth,
            url,
            Offset: 0,
            Length: msg.Length);
        return true;
    }

    private static byte[]? TryExtractProtectionInfoWrap(ReadOnlySpan<byte> protectionInfo)
    {
        var i = 0;
        while (i < protectionInfo.Length)
        {
            if (!TryReadVarint(protectionInfo, ref i, out var key))
                break;
            var fn = (int)(key >> 3);
            var wt = (int)(key & 0x07);
            if (wt == 0)
            {
                if (!TryReadVarint(protectionInfo, ref i, out _))
                    break;
                continue;
            }

            if (wt == 1)
            {
                i += 8;
                continue;
            }

            if (wt == 5)
            {
                i += 4;
                continue;
            }

            if (wt != 2)
                break;
            if (!TryReadLengthDelimited(protectionInfo, ref i, out var body))
                break;
            // f1 = protectionInfo bytes (AES-KW wrap)
            if (fn == 1 && body.Length is 24 or 40)
                return body.ToArray();
        }

        // Fallback pattern classico 0a28 / 0a18
        if (protectionInfo.Length >= 42
            && protectionInfo[0] == 0x0a
            && protectionInfo[1] == 0x28)
            return protectionInfo.Slice(2, 40).ToArray();
        if (protectionInfo.Length >= 26
            && protectionInfo[0] == 0x0a
            && protectionInfo[1] == 0x18)
            return protectionInfo.Slice(2, 24).ToArray();
        return null;
    }

    private static bool LooksAscii(ReadOnlySpan<byte> b)
    {
        var n = Math.Min(b.Length, 48);
        var ok = 0;
        for (var i = 0; i < n; i++)
        {
            if (b[i] is >= 32 and < 127)
                ok++;
        }

        return ok >= n * 0.85;
    }

    private static bool TryReadLengthDelimited(
        ReadOnlySpan<byte> msg,
        ref int pos,
        out ReadOnlySpan<byte> body)
    {
        body = default;
        if (!TryReadVarint(msg, ref pos, out var lenLong)
            || lenLong < 0
            || lenLong > int.MaxValue)
            return false;

        var len = (int)lenLong;
        if (pos > msg.Length - len)
            return false;

        body = msg.Slice(pos, len);
        pos += len;
        return true;
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> data, ref int pos, out long value)
    {
        value = 0;
        var shift = 0;
        while (pos < data.Length && shift <= 63)
        {
            var b = data[pos++];
            value |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
        }

        return false;
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        if (needle.IsEmpty || haystack.Length < needle.Length)
            return -1;
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.Slice(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }
}
