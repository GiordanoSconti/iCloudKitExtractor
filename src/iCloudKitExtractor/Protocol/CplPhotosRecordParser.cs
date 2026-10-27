using System.IO;
using System.Linq;
using System.Text;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Parser CPL Photos sul wire CloudKit (query/retrieve zona <c>PrimarySync</c>).
/// Ground truth: <c>capture_http_20260802_054842</c> wo 757/767/777/780.
/// </summary>
public static class CplPhotosRecordParser
{
    public const string PhotosZone = "PrimarySync";
    public const string RootFolderRecordName = "----Root-Folder----";

    private static readonly Regex UuidRegex = new(
        @"\$?([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})",
        RegexOptions.Compiled);

    private static readonly Regex RelationRegex = new(
        @"([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})-IN-([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    public sealed record CplAlbum(
        string RecordName,
        int? AlbumType,
        bool HasEncryptedName,
        bool IsRootFolder);

    public sealed record CplRelation(string ItemId, string ContainerId);

    public sealed record CplMedia(
        string RecordName,
        string RecordType,
        bool Hidden,
        bool Trashed,
        bool Favorite,
        string? MmcsAuth,
        long? SizeBytes,
        string? ContentBaseUrl,
        string? AssetProtectionInfoHex,
        string? RecordProtectionInfoDerHex,
        bool LooksOriginal,
        string? AssetRecordName = null);

    public sealed record QueryContinuation(
        string? LastRecordName,
        byte[]? Marker,
        bool MoreComing);

    public static byte[] MaybeDecompress(byte[] payload) =>
        UbChunkWscBuilder.DecompressIfGzip(payload);

    public static IReadOnlyList<CplAlbum> ParseAlbums(byte[] payload)
    {
        payload = MaybeDecompress(payload);
        var text = Encoding.Latin1.GetString(payload);
        var albums = new List<CplAlbum>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        var rootAt = text.IndexOf(RootFolderRecordName, StringComparison.Ordinal);
        if (rootAt >= 0)
        {
            var type = TryReadInt64AfterName(payload, IndexOfAscii(payload, "albumType"u8, rootAt));
            albums.Add(new CplAlbum(RootFolderRecordName, type, HasEncryptedName: false, IsRootFolder: true));
            seen.Add(RootFolderRecordName);
        }

        var searchFrom = 0;
        while (true)
        {
            var rel = text.IndexOf("CPLAlbum", searchFrom, StringComparison.Ordinal);
            if (rel < 0)
                break;

            var windowStart = Math.Max(0, rel - 160);
            var window = text.Substring(windowStart, Math.Min(900, text.Length - windowStart));
            var name = TryRecordName(window) ?? TryRecordName(text.Substring(Math.Max(0, rel - 80), Math.Min(80, rel)));
            if (!string.IsNullOrWhiteSpace(name) && seen.Add(name))
            {
                var abs = windowStart;
                var typeAt = IndexOfAscii(payload, "albumType"u8, abs);
                var type = typeAt >= 0 ? TryReadInt64AfterName(payload, typeAt) : null;
                var hasName = window.Contains("albumNameEnc", StringComparison.Ordinal);
                albums.Add(new CplAlbum(name, type, hasName, IsRootFolder: name == RootFolderRecordName));
            }

            searchFrom = rel + 8;
        }

        return albums;
    }

    public static IReadOnlyList<CplRelation> ParseRelations(byte[] payload)
    {
        payload = MaybeDecompress(payload);
        var text = Encoding.Latin1.GetString(payload);
        var list = new List<CplRelation>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (Match m in RelationRegex.Matches(text))
        {
            var item = m.Groups[1].Value.ToUpperInvariant();
            var container = m.Groups[2].Value.ToUpperInvariant();
            var key = item + ":" + container;
            if (!seen.Add(key))
                continue;
            list.Add(new CplRelation(item, container));
        }

        return list;
    }

    public static IReadOnlyList<CplMedia> ParseMedia(byte[] payload)
    {
        payload = MaybeDecompress(payload);
        var results = new List<CplMedia>();
        var seenAuth = new HashSet<string>(StringComparer.Ordinal);

        // / wire: i UUID intermedi spezzano le finestre record→prossimo-UUID,
        // quindi CPLMaster+resOriginalRes restano fuori dalla finestra (es. 866 originali
        // nel payload ma solo ~25 finestre UUID le contenevano). Ancoriamo le risorse.
        AppendMediaFromResourceField(
            payload, "resOriginalRes"u8, liveSuffix: false, results, seenAuth);
        AppendMediaFromResourceField(
            payload, "originalResource"u8, liveSuffix: false, results, seenAuth);
        AppendMediaFromResourceField(
            payload, "resOriginalVidComplRes"u8, liveSuffix: true, results, seenAuth);


        return results;
    }

    private static void AppendMediaFromResourceField(
        byte[] payload,
        ReadOnlySpan<byte> fieldName,
        bool liveSuffix,
        List<CplMedia> results,
        HashSet<string> seenAuth)
    {
        var searchFrom = 0;
        while (searchFrom < payload.Length)
        {
            var fieldAt = IndexOfAscii(payload, fieldName, searchFrom);
            if (fieldAt < 0)
                break;
            searchFrom = fieldAt + fieldName.Length;

            // Finestra ampia: PI CPLMaster può stare >8 KB prima della risorsa.
            const int lookback = 48_000;
            var winStart = Math.Max(0, fieldAt - lookback);
            var winEnd = Math.Min(payload.Length, fieldAt + 3_000);
            var window = payload.AsSpan(winStart, winEnd - winStart).ToArray();
            var fieldInWindow = fieldAt - winStart;

            var mmcsAuth = TryExtractMmcsAuthNear(window, fieldName);
            if (mmcsAuth is null)
            {
                // Fallback: cerca CAog strutturato solo nella coda dopo il field name.
                var after = window.AsSpan(fieldInWindow).ToArray();
                mmcsAuth = TryExtractMmcsAuth(after);
            }

            if (mmcsAuth is null || !seenAuth.Add(mmcsAuth))
                continue;

            // Nearest CPLMaster/CPLAsset before the resource (not first in lookback window).
            var lookStart = Math.Max(0, fieldAt - lookback);
            var lookSpan = payload.AsSpan(lookStart, fieldAt - lookStart);
            var masterRel = lookSpan.LastIndexOf("CPLMaster"u8);
            var masterMarkerAt = masterRel >= 0 ? lookStart + masterRel : -1;

            var masterName = masterMarkerAt >= 0
                ? TryExtractWireRecordNameBefore(payload, masterMarkerAt, "CPLMaster"u8)
                  ?? FindUuidBeforeMarker(payload, masterMarkerAt, "CPLMaster"u8, 256)
                : null;

            var assetRel = lookSpan.LastIndexOf("CPLAsset"u8);
            var assetMarkerAt = assetRel >= 0 ? lookStart + assetRel : -1;

            var assetName = assetMarkerAt >= 0
                ? TryExtractWireRecordNameBefore(payload, assetMarkerAt, "CPLAsset"u8)
                  ?? FindUuidBeforeMarker(payload, assetMarkerAt, "CPLAsset"u8, 256)
                : null;

            var recordName = masterName ?? assetName
                             ?? FindNearestUuidBefore(payload, fieldAt, lookback)
                             ?? $"UNKNOWN_{fieldAt:X}";
            if (liveSuffix)
                recordName += "_Live";


            var hidden = (TryReadInt64AfterName(window, IndexOfAscii(window, "hidden"u8)) ?? 0) != 0;
            var trashed = (TryReadInt64AfterName(window, IndexOfAscii(window, "trashed"u8)) ?? 0) != 0
                          || (TryReadInt64AfterName(window, IndexOfAscii(window, "isDeleted"u8)) ?? 0) != 0;
            var favorite = (TryReadInt64AfterName(window, IndexOfAscii(window, "isFavorite"u8)) ?? 0) != 0;
            byte[]? wrap = null;
            if (MmcsAuthBuilder.TrySplitMmcsAuth(mmcsAuth, out var sig21, out _, out _))
                wrap = MmcsAssetProtection.TryExtractForSignature(window, sig21);
            wrap ??= MmcsAssetProtection.TryExtract(window);
            // PI wrapping: ancora sul CPLMaster (non solo vicino a resOriginalRes).
            byte[]? recordPi = null;
            if (masterMarkerAt >= 0)
            {
                var piStart = Math.Max(0, masterMarkerAt - 512);
                var piEnd = Math.Min(payload.Length, masterMarkerAt + 2_048);
                recordPi = PcsRecordPi(payload.AsSpan(piStart, piEnd - piStart).ToArray());
            }

            recordPi ??= PcsRecordPi(window);
            var size = TryExtractSize(window);
            var url = TryExtractContentUrl(window);
            var isMaster = IndexOfAscii(window, "CPLMaster"u8) >= 0;

            results.Add(new CplMedia(
                recordName,
                isMaster ? "CPLMaster" : "CPLAsset",
                hidden,
                trashed,
                favorite,
                mmcsAuth,
                size,
                url,
                wrap is null ? null : Convert.ToHexString(wrap),
                recordPi is null ? null : Convert.ToHexString(recordPi),
                LooksOriginal: true,
                AssetRecordName: assetName));
        }
    }

    /// <summary>UUID del record CPL più vicino prima di <paramref name="before"/>.</summary>
    public static string? TryFindNearestUuidBefore(byte[] payload, int before, int maxLookback = 8_192) =>
        FindNearestUuidBefore(payload, before, maxLookback);

    /// <summary>
    /// Nome record CloudKit sul wire: CPLMaster → 28 char base64; CPLAsset → UUID.
    /// </summary>
    public static string? TryExtractWireRecordNameBefore(
        byte[] payload,
        int markerAt,
        ReadOnlySpan<byte> marker,
        int maxLookback = 256)
    {
        if (markerAt <= 0 || markerAt > payload.Length)
            return null;

        var start = Math.Max(0, markerAt - maxLookback);
        var before = payload.AsSpan(start, markerAt - start);

        // CPLMaster wire: 0x1c + 28 byte base64 (es. AZ92xGvEfw6g4pIcG+li…).
        for (var i = before.Length - 29; i >= 0; i--)
        {
            if (before[i] != 0x1c || i + 29 > before.Length)
                continue;
            var name = Encoding.ASCII.GetString(before.Slice(i + 1, 28));
            if (LooksLikeWireRecordName(name))
                return name;
        }

        // CPLAsset wire: 0x24 + UUID ASCII.
        for (var i = before.Length - 37; i >= 0; i--)
        {
            if (before[i] != 0x24 || i + 37 > before.Length)
                continue;
            var uuid = Encoding.ASCII.GetString(before.Slice(i + 1, 36));
            if (UuidRegex.IsMatch(uuid))
                return uuid.ToUpperInvariant();
        }

        _ = marker;
        return null;
    }

    /// <summary>
    /// Mappa mmcsAuth Live (<c>resOriginalVidComplRes</c>) → mmcsAuth master
    /// (<c>resOriginalRes</c> più vicino prima nel payload).
    /// </summary>
    public static Dictionary<string, string> ParseLiveToMasterAuthMap(byte[] payload)
    {
        payload = MaybeDecompress(payload);
        var map = new Dictionary<string, string>(StringComparer.Ordinal);
        var origAuthByOffset = new List<(int Offset, string Auth)>();

        void Collect(ReadOnlySpan<byte> fieldName, bool isLive)
        {
            var searchFrom = 0;
            var fieldLen = fieldName.Length;
            while (searchFrom < payload.Length)
            {
                var fieldAt = IndexOfAscii(payload, fieldName, searchFrom);
                if (fieldAt < 0)
                    break;
                searchFrom = fieldAt + fieldLen;

                var winStart = Math.Max(0, fieldAt - 8_000);
                var winEnd = Math.Min(payload.Length, fieldAt + 3_000);
                var window = payload.AsSpan(winStart, winEnd - winStart).ToArray();
                var fieldInWindow = fieldAt - winStart;
                var auth = TryExtractMmcsAuthNear(window, fieldName);
                if (auth is null)
                    auth = TryExtractMmcsAuth(window.AsSpan(fieldInWindow).ToArray());
                if (string.IsNullOrWhiteSpace(auth))
                    continue;

                if (!isLive)
                {
                    origAuthByOffset.Add((fieldAt, auth));
                    continue;
                }

                string? masterAuth = null;
                for (var i = origAuthByOffset.Count - 1; i >= 0; i--)
                {
                    if (origAuthByOffset[i].Offset < fieldAt
                        && fieldAt - origAuthByOffset[i].Offset < 4_000)
                    {
                        masterAuth = origAuthByOffset[i].Auth;
                        break;
                    }
                }

                if (string.IsNullOrWhiteSpace(masterAuth)
                    || string.Equals(masterAuth, auth, StringComparison.Ordinal))
                    continue;

                map[auth] = masterAuth;
            }
        }

        Collect("resOriginalRes"u8, isLive: false);
        Collect("resOriginalVidComplRes"u8, isLive: true);
        return map;
    }

    /// <summary>Master CPL (wire base64) in ordine di <c>resOriginalRes</c> nel payload.</summary>
    public static IReadOnlyList<string> ParseMasterWireNamesByResourceOrder(byte[] payload)
    {
        payload = MaybeDecompress(payload);
        var list = new List<string>();
        var searchFrom = 0;
        while (searchFrom < payload.Length)
        {
            var fieldAt = IndexOfAscii(payload, "resOriginalRes"u8, searchFrom);
            if (fieldAt < 0)
                break;
            searchFrom = fieldAt + 14;

            var winStart = Math.Max(0, fieldAt - 8_000);
            var win = payload.AsSpan(winStart, fieldAt - winStart);
            var relMaster = win.LastIndexOf("CPLMaster"u8);
            if (relMaster < 0)
                continue;

            var absMaster = winStart + relMaster;
            var wire = TryExtractWireRecordNameBefore(payload, absMaster, "CPLMaster"u8)
                       ?? FindUuidBeforeMarker(payload, absMaster, "CPLMaster"u8, 256);
            if (!string.IsNullOrWhiteSpace(wire))
                list.Add(wire);
        }

        return list;
    }

    /// <summary>Mappa itemId relazioni (CPLAsset UUID) → master wire base64 via <c>masterRef</c>.</summary>
    public static Dictionary<string, string> ParseAssetToMasterWireMap(byte[] payload)
    {
        payload = MaybeDecompress(payload);
        var text = Encoding.Latin1.GetString(payload);
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var searchFrom = 0;
        while (searchFrom < text.Length)
        {
            var assetAt = text.IndexOf("CPLAsset", searchFrom, StringComparison.Ordinal);
            if (assetAt < 0)
                break;
            searchFrom = assetAt + 8;

            var assetName = TryExtractWireRecordNameBefore(payload, assetAt, "CPLAsset"u8)
                            ?? FindUuidBeforeMarker(payload, assetAt, "CPLAsset"u8, 256);
            if (string.IsNullOrWhiteSpace(assetName))
                continue;

            var masterRefAt = text.IndexOf(
                "masterRef", assetAt, Math.Min(4_000, text.Length - assetAt), StringComparison.Ordinal);
            if (masterRefAt < 0)
                continue;

            var masterWire = ExtractWireNameAfterMasterRef(payload, masterRefAt);
            if (string.IsNullOrWhiteSpace(masterWire))
                continue;

            map[assetName.ToUpperInvariant()] = masterWire;
        }

        return map;
    }

    private static string? ExtractWireNameAfterMasterRef(byte[] payload, int masterRefAt)
    {
        if (masterRefAt < 0 || masterRefAt >= payload.Length)
            return null;
        var end = Math.Min(payload.Length, masterRefAt + 220);
        if (end <= masterRefAt)
            return null;
        var span = payload.AsSpan(masterRefAt, end - masterRefAt);
        var idx = span.IndexOf((byte)0x1c);
        if (idx < 0 || idx + 29 > span.Length)
            return null;

        var name = Encoding.ASCII.GetString(span.Slice(idx + 1, 28));
        return LooksLikeWireRecordName(name) ? name : null;
    }

    private static bool LooksLikeWireRecordName(string name) =>
        name.Length == 28
        && name[0] == 'A'
        && name.All(static c => char.IsAsciiLetterOrDigit(c) || c is '+' or '/');

    private static string? FindUuidBeforeMarker(
        byte[] payload,
        int before,
        ReadOnlySpan<byte> marker,
        int maxLookback)
    {
        var start = Math.Max(0, before - maxLookback);
        var slice = Encoding.Latin1.GetString(payload, start, before - start);
        var markerStr = Encoding.Latin1.GetString(marker);
        var markerAt = slice.LastIndexOf(markerStr, StringComparison.Ordinal);
        if (markerAt < 0)
            return null;

        Match? last = null;
        foreach (Match m in UuidRegex.Matches(slice[..markerAt]))
            last = m;
        return last is null ? null : last.Groups[1].Value.ToUpperInvariant();
    }

    private static string? FindNearestUuidBefore(byte[] payload, int before, int maxLookback = 8_192)
    {
        var start = Math.Max(0, before - maxLookback);
        var slice = Encoding.Latin1.GetString(payload, start, before - start);

        // Preferisci UUID immediatamente prima di CPLMaster nella finestra.
        var masterAt = slice.LastIndexOf("CPLMaster", StringComparison.Ordinal);
        if (masterAt >= 0)
        {
            Match? nearMaster = null;
            foreach (Match m in UuidRegex.Matches(slice[..masterAt]))
                nearMaster = m;
            if (nearMaster is not null)
                return nearMaster.Groups[1].Value.ToUpperInvariant();
        }

        Match? last = null;
        foreach (Match m in UuidRegex.Matches(slice))
            last = m;
        return last is null ? null : last.Groups[1].Value.ToUpperInvariant();
    }

    /// <summary>
    /// UUID record CPL per un campo cifrato: master per metadati asset, album record per albumNameEnc.
    /// </summary>
    public static string? TryFindUuidForEncryptedField(
        byte[] payload,
        int fieldOffset,
        string fieldName)
    {
        if (fieldName.Equals("albumNameEnc", StringComparison.Ordinal))
            return FindUuidBeforeMarker(payload, fieldOffset, "CPLAlbum"u8, 16_384)
                   ?? TryFindNearestUuidBefore(payload, fieldOffset, 16_384);

        // filenameEnc / bundle / app → record master (wire base64 prima di CPLMaster).
        var masterAt = IndexOfAscii(payload, "CPLMaster"u8, Math.Max(0, fieldOffset - 8_192));
        if (masterAt >= 0 && masterAt < fieldOffset)
        {
            var wire = TryExtractWireRecordNameBefore(payload, masterAt, "CPLMaster"u8);
            if (!string.IsNullOrWhiteSpace(wire))
                return wire;
        }

        return FindUuidBeforeMarker(payload, fieldOffset, "CPLMaster"u8, 8_192)
               ?? TryFindNearestUuidBefore(payload, fieldOffset, 8_192);
    }

    private static int CountAscii(byte[] data, ReadOnlySpan<byte> needle)
    {
        var count = 0;
        var start = 0;
        while (true)
        {
            var at = IndexOfAscii(data, needle, start);
            if (at < 0)
                return count;
            count++;
            start = at + needle.Length;
        }
    }

    public static QueryContinuation ExtractContinuation(byte[] payload)
    {
        payload = MaybeDecompress(payload);
        byte[]? marker = null;
        var moreComing = false;
        string? lastRecord = null;

        foreach (var message in EnumerateDelimited(payload))
        {
            // ResponseOperation: f3 often encodes moreComing (len-delimited { f1 = 1 }).
            var top = new ProtobufReader(message);
            while (top.HasMore)
            {
                int field, wire;
                try
                {
                    (field, wire) = top.ReadTag();
                }
                catch
                {
                    break;
                }

                if (wire == 2 && field == 3 && top.TryReadLengthDelimited(out var moreBlob))
                {
                    var mr = new ProtobufReader(moreBlob);
                    while (mr.HasMore)
                    {
                        try
                        {
                            var (f, w) = mr.ReadTag();
                            if (w == 0 && f == 1 && mr.ReadVarint() != 0)
                                moreComing = true;
                            else
                                mr.SkipField(w);
                        }
                        catch
                        {
                            break;
                        }
                    }

                    continue;
                }

                if (wire != 2)
                {
                    try { top.SkipField(wire); }
                    catch { break; }
                    continue;
                }

                if (!top.TryReadLengthDelimited(out var blob))
                    break;
                if (field != 220)
                    continue;

                // QueryRetrieveResponse body: many f1=records, trailing f2={query,cursor}.
                var inner = new ProtobufReader(blob);
                while (inner.HasMore)
                {
                    int f, w;
                    try
                    {
                        (f, w) = inner.ReadTag();
                    }
                    catch
                    {
                        break;
                    }

                    if (w != 2)
                    {
                        try { inner.SkipField(w); }
                        catch { break; }
                        continue;
                    }

                    if (!inner.TryReadLengthDelimited(out var b))
                        break;
                    if (f != 2)
                        continue;

                    // f2 = continuation: { f1=query, f2=cursor{ f2=marker, f3=ident{f1=uuid,f2=1} } }
                    if (TryParseQueryContinuation(b, out var contMarker, out var contRecord))
                    {
                        marker = contMarker;
                        if (!string.IsNullOrWhiteSpace(contRecord))
                            lastRecord = contRecord;
                        moreComing = true;
                    }
                }
            }
        }

        if (lastRecord is null)
        {
            var media = ParseMedia(payload);
            if (media.Count > 0)
            {
                var name = media[^1].RecordName;
                if (name.EndsWith("_Live", StringComparison.Ordinal))
                    name = name[..^5];
                lastRecord = name;
            }
        }

        // Large page without parseable cursor: do NOT force moreComing (avoids HTTP 500 on bare page+).
        if (moreComing && (marker is null || marker.Length == 0 || string.IsNullOrWhiteSpace(lastRecord)))
            moreComing = false;


        return new QueryContinuation(lastRecord, marker, moreComing);
    }

    /// <summary>
    /// page+ cursor: <c>f1=query; f2={ f2=marker(4–32); f3={ f1=recordName; f2=1 } }</c>.
    /// </summary>
    private static bool TryParseQueryContinuation(
        byte[] blob,
        out byte[]? marker,
        out string? recordName)
    {
        marker = null;
        recordName = null;
        var hasQuery = false;
        var reader = new ProtobufReader(blob);
        while (reader.HasMore)
        {
            int f, w;
            try
            {
                (f, w) = reader.ReadTag();
            }
            catch
            {
                break;
            }

            if (w != 2)
            {
                try { reader.SkipField(w); }
                catch { return false; }
                continue;
            }

            if (!reader.TryReadLengthDelimited(out var part))
                return false;

            if (f == 1)
            {
                var text = Encoding.ASCII.GetString(part);
                if (text.Contains("CPLAssetAndMaster", StringComparison.Ordinal)
                    || text.Contains("CPLRecordByType", StringComparison.Ordinal))
                    hasQuery = true;
                continue;
            }

            if (f != 2)
                continue;

            var cursor = new ProtobufReader(part);
            while (cursor.HasMore)
            {
                int cf, cw;
                try
                {
                    (cf, cw) = cursor.ReadTag();
                }
                catch
                {
                    break;
                }

                if (cw != 2)
                {
                    try { cursor.SkipField(cw); }
                    catch { break; }
                    continue;
                }

                if (!cursor.TryReadLengthDelimited(out var cb))
                    break;

                if (cf == 2 && cb.Length is >= 4 and <= 32)
                    marker = cb;
                else if (cf == 3)
                {
                    var ident = new ProtobufReader(cb);
                    while (ident.HasMore)
                    {
                        try
                        {
                            var (idf, idw) = ident.ReadTag();
                            if (idw == 2 && idf == 1 && ident.TryReadLengthDelimited(out var nameBytes))
                                recordName = Encoding.ASCII.GetString(nameBytes).Trim().ToUpperInvariant();
                            else
                                ident.SkipField(idw);
                        }
                        catch
                        {
                            break;
                        }
                    }
                }
            }
        }

        return hasQuery && marker is { Length: > 0 } && !string.IsNullOrWhiteSpace(recordName);
    }

    public static string ClassifyAlbumFolder(CplAlbum album, string? decryptedName)
    {
        if (album.IsRootFolder || album.AlbumType == 3)
            return "_Root";
        var name = decryptedName?.Trim();
        if (string.IsNullOrWhiteSpace(name))
            return SanitizeFileToken(album.RecordName);
        return SanitizeFileToken(name);
    }

    public static string GuessExtension(ReadOnlySpan<byte> data)
    {
        if (data.Length >= 3 && data[0] == 0xFF && data[1] == 0xD8 && data[2] == 0xFF)
            return ".jpg";
        if (data.Length >= 12 && data.Slice(4, 4).SequenceEqual("ftyp"u8))
        {
            var brand = Encoding.ASCII.GetString(data.Slice(8, 4));
            if (brand.StartsWith("heic", StringComparison.OrdinalIgnoreCase)
                || brand.StartsWith("mif1", StringComparison.OrdinalIgnoreCase)
                || brand.StartsWith("msf1", StringComparison.OrdinalIgnoreCase)
                || brand.StartsWith("heix", StringComparison.OrdinalIgnoreCase))
                return ".heic";
            if (brand.StartsWith("qt", StringComparison.OrdinalIgnoreCase))
                return ".mov";
            return ".mp4";
        }

        // Live Photo / QuickTime senza ftyp iniziale: atom wide/mdat/moov/free.
        if (data.Length >= 8)
        {
            var atom = Encoding.ASCII.GetString(data.Slice(4, 4));
            if (atom is "wide" or "mdat" or "moov" or "free" or "skip" or "pnot")
                return ".mov";
        }

        if (data.Length >= 8 && data[0] == 0x89 && data.Slice(1, 3).SequenceEqual("PNG"u8))
            return ".png";
        if (data.Length >= 4 && data.Slice(0, 4).SequenceEqual("RIFF"u8))
            return ".webp";
        return ".bin";
    }

    public static string SanitizeFileToken(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name.Trim())
        {
            if (char.IsLetterOrDigit(c) || c is '-' or '_' or '.' or ' ')
                sb.Append(c);
            else
                sb.Append('_');
        }

        var s = sb.ToString().Trim();
        return s.Length == 0 ? "untitled" : s.Length > 80 ? s[..80] : s;
    }

    private static string? TryExtractMmcsAuth(byte[] window)
    {
        // Prefer auth bound to resOriginalRes (Photos CPLMaster), then legacy originalResource.
        var nearOriginal = TryExtractMmcsAuthNear(window, "resOriginalRes"u8)
                           ?? TryExtractMmcsAuthNear(window, "originalResource"u8);
        if (nearOriginal is not null)
            return nearOriginal;

        var structured = MmcsAuthBuilder.ExtractStructuredAuths(window);
        if (structured.Count > 0)
            return structured[^1].Header;

        var ready = MmcsAuthBuilder.ExtractAllReadyMadeAuths(window);
        return ready.Count > 0 ? ready[^1] : null;
    }

    /// <summary>
    /// First structured/ready MMCS auth whose CAog token appears after <paramref name="fieldName"/> in the window.
    /// </summary>
    private static string? TryExtractMmcsAuthNear(byte[] window, ReadOnlySpan<byte> fieldName)
    {
        var fieldAt = IndexOfAscii(window, fieldName);
        if (fieldAt < 0)
            return null;

        var structured = MmcsAuthBuilder.ExtractStructuredAuths(window);
        string? best = null;
        var bestPos = int.MaxValue;
        foreach (var a in structured)
        {
            var tok = a.Header.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
            if (tok is null)
                continue;
            var at = IndexOfAscii(window, Encoding.ASCII.GetBytes(tok), fieldAt);
            if (at < 0 || at >= bestPos)
                continue;
            bestPos = at;
            best = a.Header;
        }

        if (best is not null)
            return best;

        foreach (var header in MmcsAuthBuilder.ExtractAllReadyMadeAuths(window))
        {
            var tok = header.Split(' ', StringSplitOptions.RemoveEmptyEntries).LastOrDefault();
            if (tok is null)
                continue;
            var at = IndexOfAscii(window, Encoding.ASCII.GetBytes(tok), fieldAt);
            if (at < 0 || at >= bestPos)
                continue;
            bestPos = at;
            best = header;
        }

        return best;
    }


    private static byte[]? PcsRecordPi(byte[] window)
    {
        try
        {
            return PcsProtectionZone.TryExtractRecordProtectionInfoDer(window);
        }
        catch
        {
            return null;
        }
    }

    private static string? TryExtractContentUrl(byte[] window)
    {
        var marker = "https://"u8;
        var idx = IndexOfAscii(window, marker);
        if (idx < 0)
            return null;
        var end = idx;
        while (end < window.Length && window[end] is >= 33 and < 127 && window[end] != '"')
            end++;
        var url = Encoding.ASCII.GetString(window, idx, end - idx);
        if (url.Contains("icloud", StringComparison.OrdinalIgnoreCase)
            && url.Contains("content", StringComparison.OrdinalIgnoreCase))
            return url.TrimEnd('/');
        return null;
    }

    private static long? TryExtractSize(byte[] window)
    {
        var idx = IndexOfAscii(window, "size"u8);
        if (idx < 0)
            return null;
        var v = TryReadInt64AfterName(window, idx);
        if (v is > 1024 and < 2_000_000_000)
            return v;
        return null;
    }

    private static string? TryRecordName(string window)
    {
        if (window.Contains(RootFolderRecordName, StringComparison.Ordinal))
            return RootFolderRecordName;
        var m = UuidRegex.Match(window);
        return m.Success ? m.Groups[1].Value.ToUpperInvariant() : null;
    }

    /// <summary>CloudKit Value INT64 type=7: <c>12 04 08 07 20 varint</c>.</summary>
    private static int? TryReadInt64AfterName(byte[] data, int nameAt)
    {
        if (nameAt < 0 || nameAt >= data.Length)
            return null;
        var nameLen = 0;
        while (nameAt + nameLen < data.Length && IsIdent(data[nameAt + nameLen]))
            nameLen++;
        var after = nameAt + nameLen;
        for (var probe = after; probe < after + 8 && probe + 5 < data.Length; probe++)
        {
            if (data[probe] != 0x12)
                continue;
            var innerLen = data[probe + 1];
            if (innerLen is >= 4 and <= 8
                && data[probe + 2] == 0x08
                && data[probe + 3] == 0x07
                && data[probe + 4] == 0x20)
            {
                return data[probe + 5];
            }
        }

        return null;
    }

    private static int IndexOfAscii(byte[] data, ReadOnlySpan<byte> needle, int start = 0)
    {
        if (start < 0)
            start = 0;
        var span = data.AsSpan(start);
        var rel = span.IndexOf(needle);
        return rel < 0 ? -1 : start + rel;
    }

    private static bool IsIdent(byte b) =>
        b is (>= (byte)'A' and <= (byte)'Z')
            or (>= (byte)'a' and <= (byte)'z')
            or (>= (byte)'0' and <= (byte)'9')
            or (byte)'_';

    private static IEnumerable<byte[]> EnumerateDelimited(byte[] payload)
    {
        var reader = new ProtobufReader(payload);
        var any = false;
        while (reader.HasMore)
        {
            if (!reader.TryReadLengthDelimited(out var message) || message.Length == 0)
                break;
            any = true;
            yield return message;
        }

        if (!any)
            yield return payload;
    }
}
