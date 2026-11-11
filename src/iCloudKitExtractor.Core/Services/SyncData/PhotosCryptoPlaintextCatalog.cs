using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Carica nomi album e metadati media dai plaintext PCS in <c>crypto/query_*</c>,
/// legati al record wire (base64 CPLMaster) via ordine <c>resOriginalRes</c> + mmcsAuth.
/// </summary>
public static class PhotosCryptoPlaintextCatalog
{
    public sealed record LoadResult(
        Dictionary<string, string> AlbumNames,
        int MediaRecords,
        int AlbumMapped);

    /// <summary>
    /// Legge crypto/ e popola cache + nomi album per l'organizer finale.
    /// </summary>
    public static LoadResult LoadInto(
        string containerDir,
        PhotosMediaMetaCache cache,
        IReadOnlyList<CplPhotosRecordParser.CplAlbum> albums,
        IProgress<string>? log = null)
    {
        var cryptoRoot = Path.Combine(containerDir, "crypto");
        var albumNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        cache.ClearRecords();
        foreach (var album in albums.Where(static a => a.IsRootFolder))
            albumNames[album.RecordName] = "Root";

        var mediaCount = 0;

        // Album: query_cplalbum
        var albumCrypto = Path.Combine(cryptoRoot, "query_cplalbum");
        var albumBin = Path.Combine(containerDir, "query_cplalbum.bin");
        var albumMapped = LoadFieldRecords(
            albumCrypto,
            albumBin,
            "albumNameEnc",
            (uuid, text) =>
            {
                if (string.IsNullOrWhiteSpace(uuid) || string.IsNullOrWhiteSpace(text))
                    return;
                albumNames[uuid] = text.Trim();
            },
            log);

        var wireToAuth = new Dictionary<string, string>(StringComparer.Ordinal);
        var authToWire = new Dictionary<string, string>(StringComparer.Ordinal);
        var authToMedia = new Dictionary<string, CplPhotosRecordParser.CplMedia>(StringComparer.Ordinal);
        var assetToMasterWire = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        var liveToMasterAuth = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var pageBin in Directory.GetFiles(containerDir, "query_cplasset_p*.bin")
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            var payload = File.ReadAllBytes(pageBin);
            foreach (var (assetId, masterWire) in CplPhotosRecordParser.ParseAssetToMasterWireMap(payload))
                assetToMasterWire[assetId] = masterWire;
            foreach (var (liveAuth, masterAuth) in CplPhotosRecordParser.ParseLiveToMasterAuthMap(payload))
                liveToMasterAuth[liveAuth] = masterAuth;
        }

        foreach (var pageBin in Directory.GetFiles(containerDir, "query_cplasset_p*.bin")
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            var payload = File.ReadAllBytes(pageBin);
            var tag = Path.GetFileNameWithoutExtension(pageBin);
            var pageCrypto = Path.Combine(cryptoRoot, tag);

            foreach (var m in CplPhotosRecordParser.ParseMedia(payload))
            {
                if (string.IsNullOrWhiteSpace(m.MmcsAuth))
                    continue;
                wireToAuth[m.RecordName] = m.MmcsAuth;
                authToWire[m.MmcsAuth] = m.RecordName;
                authToMedia[m.MmcsAuth] = m;
            }

            mediaCount += LoadWireOrderedFilenames(
                pageCrypto, pageBin, payload, cache, wireToAuth, log);
            mediaCount += LoadAllPlaintextFields(
                pageCrypto, pageBin, payload, cache, wireToAuth, assetToMasterWire, log);
        }

        ApplyAssetRecordNames(containerDir, cache, wireToAuth);
        ApplyMediaFlagsFromWire(cache, authToMedia);
        BindAssetScopedPlaintextFields(containerDir, cache, wireToAuth, assetToMasterWire);
        PropagateLiveCompanionMetaByWire(cache, wireToAuth);
        PropagateLiveExtraMetaByWire(cache, wireToAuth);
        var liveAuthPropagated = PropagateLiveCompanionMetaByAuth(cache, liveToMasterAuth);
        cache.PropagateLiveCompanionMeta();

        cache.SaveAlbumNames(albumNames);
        cache.SaveIndex();


        log?.Report(
            $"  crypto catalog: album={albumMapped}/{albums.Count(a => a.HasEncryptedName)} " +
            $"media≈{mediaCount} records={cache.Records.Count} wire={wireToAuth.Count} " +
            $"liveAuth={liveAuthPropagated}/{liveToMasterAuth.Count}");
        return new LoadResult(albumNames, mediaCount, albumMapped);
    }

    private static int LoadWireOrderedFilenames(
        string cryptoDir,
        string pageBin,
        byte[] payload,
        PhotosMediaMetaCache cache,
        IReadOnlyDictionary<string, string> wireToAuth,
        IProgress<string>? log)
    {
        var plainDir = Path.Combine(cryptoDir, "plaintext", "filenameEnc");
        if (!Directory.Exists(plainDir))
            return 0;

        // 1) Preferisci field_records (record_name da offset campo): il wire-order
        //    per indice sbaglia ~25% su CPL multi-resource / Live.
        var bound = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ok = LoadFieldRecords(cryptoDir, pageBin, "filenameEnc", (uuid, text) =>
        {
            if (string.IsNullOrWhiteSpace(uuid) || string.IsNullOrWhiteSpace(text))
                return;
            var trimmed = text.Trim();
            cache.UpsertRecord(uuid, r => r.Filename = trimmed);
            if (wireToAuth.TryGetValue(uuid, out var auth))
                cache.UpsertRecordByAuth(auth, r => r.Filename = trimmed);
            bound.Add(uuid);
        }, log);
        if (ok > 0)
            log?.Report($"    {Path.GetFileName(cryptoDir)}/filenameEnc: {ok} (field_records)");

        // 2) Wire-order solo per master ancora senza Filename.
        var decompressed = CplPhotosRecordParser.MaybeDecompress(payload);
        var masters = CplPhotosRecordParser.ParseMasterWireNamesByResourceOrder(decompressed);
        var texts = Directory.GetFiles(plainDir, "*.txt")
            .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase)
            .Select(static p => File.ReadAllText(p).Trim())
            .Where(static t => !string.IsNullOrWhiteSpace(t))
            .ToList();

        var filled = 0;
        var n = Math.Min(masters.Count, texts.Count);
        for (var i = 0; i < n; i++)
        {
            var wire = masters[i];
            if (bound.Contains(wire))
                continue;
            var text = texts[i];
            cache.UpsertRecord(wire, r => r.Filename ??= text);
            if (wireToAuth.TryGetValue(wire, out var auth))
                cache.UpsertRecordByAuth(auth, r => r.Filename ??= text);
            filled++;
        }

        if (filled > 0)
            log?.Report(
                $"    {Path.GetFileName(cryptoDir)}/filenameEnc: +{filled} (wire-order gap)");

        return ok + filled;
    }

    private static int LoadAllPlaintextFields(
        string cryptoDir,
        string pageBin,
        byte[] payload,
        PhotosMediaMetaCache cache,
        IReadOnlyDictionary<string, string> wireToAuth,
        IReadOnlyDictionary<string, string> assetToMasterWire,
        IProgress<string>? log)
    {
        var plainRoot = Path.Combine(cryptoDir, "plaintext");
        if (!Directory.Exists(plainRoot))
            return 0;

        var decompressed = CplPhotosRecordParser.MaybeDecompress(payload);
        var masters = CplPhotosRecordParser.ParseMasterWireNamesByResourceOrder(decompressed);
        var total = 0;

        foreach (var fieldDir in Directory.GetDirectories(plainRoot).OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            var fieldName = Path.GetFileName(fieldDir);
            if (fieldName.Equals("filenameEnc", StringComparison.Ordinal))
                continue;

            // Come filenameEnc: field_records prima (record_name da offset).
            // Wire-order per indice scambia metadati su CPL multi-resource / Live.
            var boundKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            var fromRecords = LoadFieldRecords(cryptoDir, pageBin, fieldName, (recordKey, text) =>
            {
                ApplyPlaintextValue(recordKey, fieldName, text, cache, wireToAuth, assetToMasterWire);
                if (!string.IsNullOrWhiteSpace(recordKey))
                    boundKeys.Add(recordKey);
            }, log);
            total += fromRecords;
            if (fromRecords > 0)
                log?.Report($"    {Path.GetFileName(cryptoDir)}/{fieldName}: {fromRecords} (field_records)");

            var texts = ReadOrderedPlaintextValues(fieldDir);
            if (texts.Count == 0 || masters.Count == 0)
                continue;

            if (texts.Count > masters.Count && texts.Count <= masters.Count * 2)
                texts = texts.Take(masters.Count).ToList();

            var filled = 0;
            var n = Math.Min(masters.Count, texts.Count);
            for (var i = 0; i < n; i++)
            {
                var wire = masters[i];
                if (boundKeys.Contains(wire))
                    continue;
                ApplyPlaintextValue(wire, fieldName, texts[i], cache, wireToAuth, assetToMasterWire);
                filled++;
            }

            if (filled > 0)
            {
                total += filled;
                log?.Report(
                    $"    {Path.GetFileName(cryptoDir)}/{fieldName}: +{filled} (wire-order gap)");
            }
        }

        return total;
    }

    private static void BindAssetScopedPlaintextFields(
        string containerDir,
        PhotosMediaMetaCache cache,
        IReadOnlyDictionary<string, string> wireToAuth,
        IReadOnlyDictionary<string, string> assetToMasterWire)
    {
        foreach (var pageBin in Directory.GetFiles(containerDir, "query_cplasset_p*.bin")
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            var tag = Path.GetFileNameWithoutExtension(pageBin);
            var pageCrypto = Path.Combine(containerDir, "crypto", tag);
            var plainRoot = Path.Combine(pageCrypto, "plaintext");
            if (!Directory.Exists(plainRoot))
                continue;

            foreach (var fieldDir in Directory.GetDirectories(plainRoot))
            {
                var fieldName = Path.GetFileName(fieldDir);
                if (fieldName is "filenameEnc" or "importedByBundleIdentifierEnc"
                    or "importedByDisplayNameEnc" or "originalFilenameEnc")
                    continue;

                LoadFieldRecords(pageCrypto, pageBin, fieldName, (recordKey, text) =>
                {
                    if (wireToAuth.ContainsKey(recordKey))
                        return;
                    ApplyPlaintextValue(recordKey, fieldName, text, cache, wireToAuth, assetToMasterWire);
                }, log: null);
            }
        }
    }

    private static void ApplyMediaFlagsFromWire(
        PhotosMediaMetaCache cache,
        IReadOnlyDictionary<string, CplPhotosRecordParser.CplMedia> authToMedia)
    {
        foreach (var entry in cache.Entries)
        {
            if (string.IsNullOrWhiteSpace(entry.MmcsAuth))
                continue;
            if (!authToMedia.TryGetValue(entry.MmcsAuth, out var media))
                continue;

            entry.Hidden = media.Hidden;
            entry.Trashed = media.Trashed;
            entry.Favorite = media.Favorite;
            if (media.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase))
                entry.IsLive = true;
        }
    }

    private static void ApplyPlaintextValue(
        string recordKey,
        string fieldName,
        string text,
        PhotosMediaMetaCache cache,
        IReadOnlyDictionary<string, string> wireToAuth,
        IReadOnlyDictionary<string, string> assetToMasterWire)
    {
        if (string.IsNullOrWhiteSpace(recordKey) || string.IsNullOrWhiteSpace(text))
            return;

        var auth = ResolveAuthForRecordKey(recordKey, wireToAuth, assetToMasterWire, cache);
        if (auth is not null)
            ApplyPlaintextValueByAuth(auth, fieldName, text, cache);
    }

    private static string? ResolveAuthForRecordKey(
        string recordKey,
        IReadOnlyDictionary<string, string> wireToAuth,
        IReadOnlyDictionary<string, string> assetToMasterWire,
        PhotosMediaMetaCache cache)
    {
        if (wireToAuth.TryGetValue(recordKey, out var auth))
            return auth;

        if (assetToMasterWire.TryGetValue(recordKey, out var masterWire)
            && wireToAuth.TryGetValue(masterWire, out auth))
            return auth;

        foreach (var entry in cache.Entries)
        {
            if (string.Equals(entry.AssetRecordName, recordKey, StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(entry.MmcsAuth))
                return entry.MmcsAuth;
        }

        return null;
    }

    private static void ApplyPlaintextValueByAuth(
        string auth,
        string fieldName,
        string text,
        PhotosMediaMetaCache cache)
    {
        switch (fieldName)
        {
            case "importedByBundleIdentifierEnc":
                cache.UpsertRecordByAuth(auth, r => r.BundleId = text.Trim());
                return;
            case "importedByDisplayNameEnc":
                cache.UpsertRecordByAuth(auth, r => r.AppDisplayName = text.Trim());
                return;
            case "originalFilenameEnc":
                cache.UpsertRecordByAuth(auth, r => r.OriginalFilename = text.Trim());
                return;
            case "filenameEnc":
                cache.UpsertRecordByAuth(auth, r => r.Filename ??= text.Trim());
                return;
            default:
                cache.UpsertExtraByAuth(auth, fieldName, text);
                return;
        }
    }

    private static List<string> ReadOrderedPlaintextValues(string fieldDir)
    {
        var values = new List<string>();
        var indices = new SortedSet<int>();
        foreach (var path in Directory.GetFiles(fieldDir))
        {
            var name = Path.GetFileNameWithoutExtension(path);
            if (int.TryParse(name, out var idx))
                indices.Add(idx);
        }

        foreach (var idx in indices)
        {
            var text = ReadPlaintextValueByIndex(fieldDir, idx);
            if (!string.IsNullOrWhiteSpace(text))
                values.Add(text);
        }

        return values;
    }

    private static string ReadPlaintextValueByIndex(string fieldDir, int idx)
    {
        var stem = $"{idx:D4}";
        var txtPath = Path.Combine(fieldDir, stem + ".txt");
        if (File.Exists(txtPath))
        {
            var t = File.ReadAllText(txtPath).Trim();
            if (t.Length > 0)
                return t;
        }

        foreach (var path in Directory.GetFiles(fieldDir, stem + ".*"))
        {
            if (path.EndsWith(".txt", StringComparison.OrdinalIgnoreCase))
                continue;
            var preview = ReadPlaintextPreview(path);
            if (!string.IsNullOrWhiteSpace(preview))
                return preview;
        }

        return "";
    }

    private static string ReadPlaintextValue(string txtPath, string binPath)
    {
        if (File.Exists(txtPath))
        {
            var t = File.ReadAllText(txtPath).Trim();
            if (t.Length > 0)
                return t;
        }

        return ReadPlaintextPreview(binPath);
    }

    private static void PropagateLiveExtraMetaByWire(
        PhotosMediaMetaCache cache,
        IReadOnlyDictionary<string, string> wireToAuth)
    {
        foreach (var (wire, liveAuth) in wireToAuth)
        {
            if (!wire.EndsWith("_Live", StringComparison.OrdinalIgnoreCase))
                continue;

            var masterWire = wire[..^5];
            if (!wireToAuth.TryGetValue(masterWire, out var masterAuth))
                continue;

            var masterExtra = cache.GetExtraForAuth(masterAuth);
            if (masterExtra is null)
                continue;

            foreach (var (field, value) in masterExtra)
                cache.UpsertExtraByAuth(liveAuth, field, value);
        }
    }

    private static int CountExtraMetaAuths(PhotosMediaMetaCache cache) =>
        cache.Entries.Count(e =>
            !string.IsNullOrWhiteSpace(e.MmcsAuth)
            && cache.GetExtraForAuth(e.MmcsAuth) is { Count: > 0 });

    private static void PropagateLiveCompanionMetaByWire(
        PhotosMediaMetaCache cache,
        IReadOnlyDictionary<string, string> wireToAuth)
    {
        foreach (var (wire, liveAuth) in wireToAuth)
        {
            if (!wire.EndsWith("_Live", StringComparison.OrdinalIgnoreCase))
                continue;

            var masterWire = wire[..^5];
            if (!wireToAuth.TryGetValue(masterWire, out var masterAuth))
                continue;

            var masterMeta = cache.GetMetaForAuth(masterAuth);
            if (masterMeta is null)
                continue;

            cache.UpsertRecordByAuth(liveAuth, live =>
            {
                live.BundleId ??= masterMeta.BundleId;
                live.AppDisplayName ??= masterMeta.AppDisplayName;
                if (string.IsNullOrWhiteSpace(live.OriginalFilename)
                    && !string.IsNullOrWhiteSpace(masterMeta.OriginalFilename))
                {
                    var baseName = Path.GetFileNameWithoutExtension(masterMeta.OriginalFilename);
                    live.OriginalFilename = baseName + "_Live.MOV";
                }

                live.Filename ??= masterMeta.Filename is { Length: > 0 } fn
                    ? Path.GetFileNameWithoutExtension(fn) + "_Live.MOV"
                    : null;
            });
        }
    }

    /// <summary>
    /// Propaga filename/bundle dal master al companion Live usando la mappa auth
    /// (funziona anche quando i record name sono UNKNOWN_* con offset diversi).
    /// </summary>
    private static int PropagateLiveCompanionMetaByAuth(
        PhotosMediaMetaCache cache,
        IReadOnlyDictionary<string, string> liveToMasterAuth)
    {
        var propagated = 0;
        foreach (var (liveAuth, masterAuth) in liveToMasterAuth)
        {
            var masterMeta = cache.GetMetaForAuth(masterAuth);
            var masterName = masterMeta?.OriginalFilename ?? masterMeta?.Filename;
            if (string.IsNullOrWhiteSpace(masterName))
            {
                // Fallback: nome già risolto / token del master entry.
                var masterEntry = cache.Entries.FirstOrDefault(e =>
                    string.Equals(e.MmcsAuth, masterAuth, StringComparison.Ordinal)
                    && !e.IsLive
                    && !e.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase));
                if (masterEntry is not null)
                {
                    masterName = cache.ResolveDisplayFileName(
                                     masterEntry.RecordName, ".jpg", masterEntry.MmcsAuth)
                                 ?? (string.IsNullOrWhiteSpace(masterEntry.PlainRelativePath)
                                     ? null
                                     : Path.GetFileName(masterEntry.PlainRelativePath));
                    if (string.IsNullOrWhiteSpace(masterName)
                        && !masterEntry.Token.StartsWith("UNKNOWN_", StringComparison.OrdinalIgnoreCase))
                        masterName = masterEntry.Token;
                }
            }

            if (string.IsNullOrWhiteSpace(masterName) && masterMeta is null)
                continue;

            var before = cache.GetMetaForAuth(liveAuth)?.OriginalFilename;
            cache.UpsertRecordByAuth(liveAuth, live =>
            {
                if (masterMeta is not null)
                {
                    live.BundleId ??= masterMeta.BundleId;
                    live.AppDisplayName ??= masterMeta.AppDisplayName;
                }

                if (string.IsNullOrWhiteSpace(live.OriginalFilename)
                    && !string.IsNullOrWhiteSpace(masterName))
                {
                    var baseName = Path.GetFileNameWithoutExtension(masterName);
                    live.OriginalFilename = baseName + "_Live.MOV";
                }

                live.Filename ??= !string.IsNullOrWhiteSpace(masterName)
                    ? Path.GetFileNameWithoutExtension(masterName) + "_Live.MOV"
                    : null;
            });

            var after = cache.GetMetaForAuth(liveAuth)?.OriginalFilename;
            if (!string.IsNullOrWhiteSpace(after)
                && !string.Equals(before, after, StringComparison.Ordinal))
                propagated++;

            var masterExtra = cache.GetExtraForAuth(masterAuth);
            if (masterExtra is null)
                continue;
            foreach (var (field, value) in masterExtra)
            {
                var liveExtra = cache.GetExtraForAuth(liveAuth);
                if (liveExtra is not null && liveExtra.ContainsKey(field))
                    continue;
                cache.UpsertExtraByAuth(liveAuth, field, value);
            }
        }

        return propagated;
    }

    private static void ApplyAssetRecordNames(
        string containerDir,
        PhotosMediaMetaCache cache,
        IReadOnlyDictionary<string, string> wireToAuth)
    {
        var authToAsset = new Dictionary<string, string>(StringComparer.Ordinal);
        foreach (var pageBin in Directory.GetFiles(containerDir, "query_cplasset_p*.bin")
                     .OrderBy(static p => p, StringComparer.OrdinalIgnoreCase))
        {
            var payload = File.ReadAllBytes(pageBin);
            var assetToMaster = CplPhotosRecordParser.ParseAssetToMasterWireMap(payload);
            foreach (var (assetId, masterWire) in assetToMaster)
            {
                if (!wireToAuth.TryGetValue(masterWire, out var auth))
                    continue;
                authToAsset[auth] = assetId;
            }
        }

        foreach (var entry in cache.Entries)
        {
            if (string.IsNullOrWhiteSpace(entry.MmcsAuth))
                continue;
            if (authToAsset.TryGetValue(entry.MmcsAuth, out var assetId))
                entry.AssetRecordName = assetId;
        }
    }

    private static int LoadFieldRecords(
        string cryptoDir,
        string? payloadBin,
        string fieldName,
        Action<string, string> apply,
        IProgress<string>? log)
    {
        var recordsPath = Path.Combine(cryptoDir, "field_records.tsv");
        var rows = File.Exists(recordsPath)
            ? ParseFieldRecordsTsv(recordsPath, fieldName)
            : RebuildFromPayload(cryptoDir, payloadBin, fieldName);

        var ok = 0;
        foreach (var (recordName, text) in rows)
        {
            if (string.IsNullOrWhiteSpace(text))
                continue;
            apply(recordName, text);
            ok++;
        }

        if (ok > 0 && fieldName is not "filenameEnc")
            log?.Report($"    {Path.GetFileName(cryptoDir)}/{fieldName}: {ok}");
        return ok;
    }

    private static List<(string RecordName, string Text)> ParseFieldRecordsTsv(
        string path,
        string fieldName)
    {
        var list = new List<(string, string)>();
        var lines = File.ReadAllLines(path);
        if (lines.Length < 2)
            return list;

        for (var i = 1; i < lines.Length; i++)
        {
            var parts = lines[i].Split('\t');
            if (parts.Length < 6 || !parts[0].Equals(fieldName, StringComparison.Ordinal))
                continue;
            var record = parts[2].Trim();
            var text = parts[5].Trim();
            if (string.IsNullOrWhiteSpace(text) && parts.Length >= 5)
            {
                var plainPath = parts[4];
                text = ReadPlaintextPreview(plainPath);
            }

            list.Add((record, text));
        }

        return list;
    }

    private static List<(string RecordName, string Text)> RebuildFromPayload(
        string cryptoDir,
        string? payloadBin,
        string fieldName)
    {
        var list = new List<(string, string)>();
        if (string.IsNullOrWhiteSpace(payloadBin) || !File.Exists(payloadBin))
            return list;

        var payload = File.ReadAllBytes(payloadBin);
        var plainDir = Path.Combine(cryptoDir, "plaintext", fieldName);
        if (!Directory.Exists(plainDir))
            return list;

        var fields = CloudKitEncryptedFieldScanner.Scan(payload, [fieldName])
            .Where(f => f.FieldName == fieldName)
            .ToList();

        for (var i = 0; i < fields.Count; i++)
        {
            var idx = i + 1;
            var text = ReadPlaintextValueByIndex(plainDir, idx);
            if (string.IsNullOrWhiteSpace(text))
                continue;

            var recordName = CplPhotosRecordParser.TryFindUuidForEncryptedField(
                payload, fields[i].Offset, fields[i].FieldName) ?? "";
            if (string.IsNullOrWhiteSpace(recordName))
                continue;
            list.Add((recordName, text));
        }

        return list;
    }

    private static string ReadPlaintextPreview(string path)
    {
        if (!File.Exists(path))
            return "";
        try
        {
            var bytes = File.ReadAllBytes(path);
            if (bytes.Length == 0)
                return "";
            if (LooksLikeUtf8Text(bytes))
                return Encoding.UTF8.GetString(bytes).Trim().Trim('\0');
            return Convert.ToBase64String(bytes);
        }
        catch
        {
            return "";
        }
    }

    private static bool LooksLikeUtf8Text(byte[] bytes)
    {
        if (bytes.Length == 0)
            return false;
        try
        {
            var text = Encoding.UTF8.GetString(bytes).Trim().Trim('\0');
            if (text.Length == 0)
                return false;
            var printable = text.Count(static c => c is >= ' ' and <= '~' or '\n' or '\r' or '\t');
            return printable >= text.Length * 0.85;
        }
        catch
        {
            return false;
        }
    }

}
