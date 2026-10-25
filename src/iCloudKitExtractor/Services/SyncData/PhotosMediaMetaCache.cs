using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Cache locale Photos Sync Data: sidecars MMCS + metadati PCS legati al record UUID,
/// usata dopo il download per decrypt media, rename e organizzazione album.
/// </summary>
public sealed class PhotosMediaMetaCache
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly string _cacheDir;
    private readonly string _indexPath;
    private readonly string _recordsPath;
    private readonly object _gate = new();
    private readonly List<MediaEntry> _entries = [];
    private readonly Dictionary<string, RecordMeta> _records =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, RecordMeta> _recordsByAuth =
        new(StringComparer.Ordinal);
    private readonly Dictionary<string, Dictionary<string, string>> _extraByAuth =
        new(StringComparer.Ordinal);

    public PhotosMediaMetaCache(string photosDir)
    {
        _cacheDir = Path.Combine(photosDir, "decrypt_cache");
        Directory.CreateDirectory(_cacheDir);
        _indexPath = Path.Combine(_cacheDir, "media_index.json");
        _recordsPath = Path.Combine(_cacheDir, "records.json");
    }

    public string CacheDirectory => _cacheDir;
    public IReadOnlyList<MediaEntry> Entries
    {
        get { lock (_gate) return _entries.ToList(); }
    }

    public IReadOnlyDictionary<string, RecordMeta> Records
    {
        get { lock (_gate) return new Dictionary<string, RecordMeta>(_records, StringComparer.OrdinalIgnoreCase); }
    }

    public void AddDownload(MediaEntry entry)
    {
        lock (_gate)
        {
            _entries.RemoveAll(e =>
                string.Equals(e.Token, entry.Token, StringComparison.OrdinalIgnoreCase)
                || (entry.MmcsAuth is not null
                    && string.Equals(e.MmcsAuth, entry.MmcsAuth, StringComparison.Ordinal)));
            _entries.Add(entry);
        }
    }

    public void SaveIndex()
    {
        lock (_gate)
        {
            File.WriteAllText(_indexPath, JsonSerializer.Serialize(_entries, JsonOpts));
            File.WriteAllText(_recordsPath, JsonSerializer.Serialize(_records, JsonOpts));
        }
    }

    public void LoadIfPresent()
    {
        lock (_gate)
        {
            _entries.Clear();
            _records.Clear();
            _recordsByAuth.Clear();
            if (File.Exists(_indexPath))
            {
                var list = JsonSerializer.Deserialize<List<MediaEntry>>(File.ReadAllText(_indexPath));
                if (list is { Count: > 0 })
                    _entries.AddRange(list);
            }

            if (File.Exists(_recordsPath))
            {
                var map = JsonSerializer.Deserialize<Dictionary<string, RecordMeta>>(File.ReadAllText(_recordsPath));
                if (map is not null)
                {
                    foreach (var kv in map)
                        _records[kv.Key] = kv.Value;
                }
            }
        }
    }

    /// <summary>
    /// Decifra filename/bundle/app dai payload CPL e li lega all'UUID record
    /// (campo type=20 → UUID più vicino prima dell'offset).
    /// </summary>
    /// <remarks>
    /// Le pagine CPL sono multi-MB con migliaia di campi criptati. Non chiamare
    /// <c>TryUnwrapAll</c> per ogni campo (ECDH × N): riusa le zone di pagina e,
    /// solo se fallisce, unwrap una sola finestra per UUID.
    /// </remarks>
    public int BuildRecordMetadata(
        ICloudSession session,
        byte[]? zonePayload,
        IReadOnlyList<byte[]> assetPages,
        IProgress<string>? log = null,
        IReadOnlyList<ProtectionZoneKeys>? precomputedZones = null,
        Action<int, int>? pageProgress = null)
    {
        if (!PcsSessionSeedKeys.HasAny(session))
            return 0;

        var seedKeys = PcsSessionSeedKeys.CollectForSyncData(session, log);
        if (seedKeys.Count == 0)
            return 0;


        List<ProtectionZoneKeys> zones;
        if (precomputedZones is { Count: > 0 })
        {
            zones = precomputedZones.ToList();
        }
        else
        {
            var pool = new List<PcsCompactPrivateKey>(seedKeys);
            zones = [];
            if (zonePayload is { Length: > 32 })
            {
                var fromZone = PcsProtectionZone.TryUnwrapAll(zonePayload, seedKeys, lightKeys: seedKeys);
                zones.AddRange(fromZone);
                pool = PcsProtectionZone.MergeKeys(seedKeys, fromZone);
            }

            for (var pi = 0; pi < assetPages.Count; pi++)
            {
                pageProgress?.Invoke(pi + 1, assetPages.Count);
                log?.Report(
                    $"  BuildRecordMetadata: unwrap pagina {pi + 1}/{assetPages.Count} " +
                    $"({assetPages[pi].Length:N0} B)…");
                var fromPage = PcsProtectionZone.TryUnwrapAll(assetPages[pi], pool, lightKeys: seedKeys);
                zones.AddRange(fromPage);
                pool = PcsProtectionZone.MergeKeys(pool, fromPage);
            }
        }

        // Per i campi type=20 basta la PI locale del record (+ poche zone),
        // non provare migliaia di master su ogni filenameEnc.
        var zoneOnly = zones
            .Where(static z => z.ProtectionInfoTag is not null || z.NestedPrivateKeys.Count > 0)
            .Take(32)
            .ToList();
        if (zoneOnly.Count == 0)
            zoneOnly = zones.Take(16).ToList();

        // zoneOnly=1 → localUnwrap ×242/page, okDelta=0, ~5min/page (troppo lento in produzione).
        // Senza zone utili il fallback locale è solo CPU morta.
        var allowLocalUnwrap = zoneOnly.Count >= 4;
        if (!allowLocalUnwrap)
        {
            log?.Report(
                $"  BuildRecordMetadata: zone utili={zoneOnly.Count}/{zones.Count} — " +
                "skip unwrap locale per-UUID (troppo lento e inefficace)");
        }

        string[] fields =
        [
            "filenameEnc", "originalFilenameEnc",
            "importedByBundleIdentifierEnc", "importedByDisplayNameEnc"
        ];

        var ok = 0;
        // Cache unwrap locale per UUID: al massimo 1 TryUnwrapAll per record, non per campo.
        var localZonesByUuid = new Dictionary<string, List<ProtectionZoneKeys>>(StringComparer.OrdinalIgnoreCase);

        for (var pageIdx = 0; pageIdx < assetPages.Count; pageIdx++)
        {
            var page = assetPages[pageIdx];
            pageProgress?.Invoke(pageIdx + 1, assetPages.Count);
            log?.Report(
                $"  BuildRecordMetadata: campi pagina {pageIdx + 1}/{assetPages.Count} " +
                $"({page.Length:N0} B, zone={zoneOnly.Count})…");
            var scanned = CloudKitEncryptedFieldScanner.Scan(page, fields);
            foreach (var field in scanned)
            {
                if (!fields.Contains(field.FieldName, StringComparer.Ordinal))
                    continue;

                var uuid = CplPhotosRecordParser.TryFindUuidForEncryptedField(
                    page, field.Offset, field.FieldName);
                if (uuid is null)
                    continue;

                // 1) Zone di pagina / zone precomputate (economico).
                var plain = TryDecryptPcsField(field.Ciphertext, field.FieldName, zoneOnly, seedKeys);

                // 2) Fallback: unwrap locale una sola volta per UUID (solo se zone utili).
                if (plain is null && allowLocalUnwrap)
                {
                    if (!localZonesByUuid.TryGetValue(uuid, out var localZones))
                    {
                        var start = Math.Max(0, field.Offset - 6144);
                        var len = Math.Min(page.Length - start, 12288);
                        localZones = PcsProtectionZone.TryUnwrapAll(
                            page.AsSpan(start, len), seedKeys, lightKeys: seedKeys);
                        localZonesByUuid[uuid] = localZones;
                    }

                    if (localZones.Count > 0)
                        plain = TryDecryptPcsField(field.Ciphertext, field.FieldName, localZones, seedKeys);
                }

                if (plain is not { Length: > 0 })
                    continue;

                var text = Encoding.UTF8.GetString(plain).Trim().Trim('\0');
                if (string.IsNullOrWhiteSpace(text) && field.FieldName is not "mediaMetaDataEnc")
                    continue;

                lock (_gate)
                {
                    if (!_records.TryGetValue(uuid, out var meta))
                    {
                        meta = new RecordMeta { RecordName = uuid };
                        _records[uuid] = meta;
                    }

                    switch (field.FieldName)
                    {
                        case "originalFilenameEnc":
                            meta.OriginalFilename = text;
                            break;
                        case "filenameEnc":
                            meta.Filename ??= text;
                            break;
                        case "importedByBundleIdentifierEnc":
                            meta.BundleId = text;
                            break;
                        case "importedByDisplayNameEnc":
                            meta.AppDisplayName = text;
                            break;
                    }

                    ok++;
                }
            }
        }

        // Live companion: riusa metadati del master senza _Live se assenti.
        lock (_gate)
        {
            foreach (var entry in _entries)
            {
                if (!entry.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase))
                    continue;
                var master = entry.RecordName[..^5];
                if (!_records.TryGetValue(entry.RecordName, out var liveMeta)
                    || string.IsNullOrWhiteSpace(liveMeta.OriginalFilename)
                       && string.IsNullOrWhiteSpace(liveMeta.Filename))
                {
                    if (_records.TryGetValue(master, out var m))
                    {
                        var copy = liveMeta ?? new RecordMeta { RecordName = entry.RecordName };
                        copy.BundleId ??= m.BundleId;
                        copy.AppDisplayName ??= m.AppDisplayName;
                        if (string.IsNullOrWhiteSpace(copy.OriginalFilename)
                            && !string.IsNullOrWhiteSpace(m.OriginalFilename))
                        {
                            var baseName = Path.GetFileNameWithoutExtension(m.OriginalFilename);
                            copy.OriginalFilename = baseName + "_Live.MOV";
                        }

                        _records[entry.RecordName] = copy;
                    }
                }
            }
        }

        log?.Report(
            $"  decrypt_cache: metadati PCS per-record ok≈{ok} records={_records.Count} " +
            $"(localUnwrapUuid={localZonesByUuid.Count})");
        SaveIndex();
        return ok;
    }


    public void ClearRecords()
    {
        lock (_gate)
        {
            _records.Clear();
            _recordsByAuth.Clear();
            _extraByAuth.Clear();
        }
    }

    public void UpsertExtraByAuth(string? mmcsAuth, string fieldName, string value)
    {
        if (string.IsNullOrWhiteSpace(mmcsAuth) || string.IsNullOrWhiteSpace(fieldName))
            return;
        var text = value.Trim();
        if (text.Length == 0)
            return;

        lock (_gate)
        {
            if (!_extraByAuth.TryGetValue(mmcsAuth, out var map))
            {
                map = new Dictionary<string, string>(StringComparer.Ordinal);
                _extraByAuth[mmcsAuth] = map;
            }

            map[fieldName] = text;
        }
    }

    public IReadOnlyDictionary<string, string>? GetExtraForAuth(string? mmcsAuth)
    {
        if (string.IsNullOrWhiteSpace(mmcsAuth))
            return null;
        lock (_gate)
            return _extraByAuth.TryGetValue(mmcsAuth, out var map)
                ? map
                : null;
    }

    public void UpsertRecordByAuth(string? mmcsAuth, Action<RecordMeta> update)
    {
        if (string.IsNullOrWhiteSpace(mmcsAuth))
            return;

        lock (_gate)
        {
            if (!_recordsByAuth.TryGetValue(mmcsAuth, out var meta))
            {
                meta = new RecordMeta();
                _recordsByAuth[mmcsAuth] = meta;
            }

            update(meta);
        }
    }

    public void UpsertRecord(string recordName, Action<RecordMeta> update)
    {
        lock (_gate)
        {
            if (!_records.TryGetValue(recordName, out var meta))
            {
                meta = new RecordMeta { RecordName = recordName };
                _records[recordName] = meta;
            }

            update(meta);
        }
    }

    public void PropagateLiveCompanionMeta()
    {
        lock (_gate)
        {
            foreach (var entry in _entries)
            {
                if (!entry.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase))
                    continue;
                var master = entry.RecordName[..^5];
                if (!_records.TryGetValue(entry.RecordName, out var liveMeta))
                {
                    liveMeta = new RecordMeta { RecordName = entry.RecordName };
                    _records[entry.RecordName] = liveMeta;
                }

                if (!_records.TryGetValue(master, out var m))
                    continue;

                liveMeta.BundleId ??= m.BundleId;
                liveMeta.AppDisplayName ??= m.AppDisplayName;
                if (string.IsNullOrWhiteSpace(liveMeta.OriginalFilename)
                    && !string.IsNullOrWhiteSpace(m.OriginalFilename))
                {
                    var baseName = Path.GetFileNameWithoutExtension(m.OriginalFilename);
                    liveMeta.OriginalFilename = baseName + "_Live.MOV";
                }

                liveMeta.Filename ??= m.Filename;
            }
        }
    }

    public void SaveAlbumNames(IReadOnlyDictionary<string, string> albumNames)
    {
        lock (_gate)
        {
            var path = Path.Combine(_cacheDir, "album_names.json");
            File.WriteAllText(path, JsonSerializer.Serialize(albumNames, JsonOpts));
        }
    }

    public Dictionary<string, string> LoadAlbumNames()
    {
        var path = Path.Combine(_cacheDir, "album_names.json");
        if (!File.Exists(path))
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            return JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(path))
                   ?? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
        catch
        {
            return new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }
    }

    public RecordMeta? GetMetaForRecord(string recordName)
    {
        lock (_gate)
            return _records.TryGetValue(recordName, out var m) ? m : null;
    }

    public RecordMeta? GetMetaForAuth(string? mmcsAuth)
    {
        if (string.IsNullOrWhiteSpace(mmcsAuth))
            return null;
        lock (_gate)
            return _recordsByAuth.TryGetValue(mmcsAuth, out var m) ? m : null;
    }

    public string? ResolveDisplayFileName(
        string recordName,
        string extensionWithDot,
        string? mmcsAuth = null)
    {
        var meta = GetMetaForAuth(mmcsAuth)
                   ?? GetMetaForRecord(recordName);
        var raw = meta?.OriginalFilename ?? meta?.Filename;
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var name = Path.GetFileName(raw.Trim());
        if (string.IsNullOrWhiteSpace(name))
            return null;

        // Se manca estensione, usa quella del plaintext.
        if (string.IsNullOrWhiteSpace(Path.GetExtension(name))
            && !string.IsNullOrWhiteSpace(extensionWithDot))
            name += extensionWithDot.StartsWith('.') ? extensionWithDot : "." + extensionWithDot;

        return CplPhotosRecordParser.SanitizeFileToken(name);
    }

    private static byte[]? TryDecryptPcsField(
        byte[] ciphertext,
        string fieldName,
        List<ProtectionZoneKeys> zones,
        List<PcsCompactPrivateKey> seedKeys)
    {
        var aad = new List<string> { fieldName };
        if (fieldName.EndsWith("Enc", StringComparison.Ordinal))
            aad.Add(fieldName[..^3]);
        if (fieldName.EndsWith("Encrypted", StringComparison.Ordinal))
            aad.Add(fieldName[..^"Encrypted".Length]);

        var aadArr = aad.ToArray();
        foreach (var zone in zones)
        {
            var plain = PcsProtectionZone.TryDecryptField(zone, ciphertext, aadArr);
            if (plain is { Length: > 0 })
                return plain;
        }

        // Evita TryUnwrapAll su ogni ciphertext campo (costoso × migliaia di field).
        return null;
    }

    public sealed class MediaEntry
    {
        public string Token { get; set; } = "";
        public string RecordName { get; set; } = "";
        public string? MmcsAuth { get; set; }
        public string? WrapHex { get; set; }
        public long? SizeBytes { get; set; }
        public bool Hidden { get; set; }
        public bool Trashed { get; set; }
        public bool Favorite { get; set; }
        public bool IsLive { get; set; }
        public string? AssetRecordName { get; set; }
        public List<string> AlbumIds { get; set; } = [];
        public string? CipherRelativePath { get; set; }
        public string? PlainRelativePath { get; set; }
    }

    public sealed class RecordMeta
    {
        public string RecordName { get; set; } = "";
        public string? Filename { get; set; }
        public string? OriginalFilename { get; set; }
        public string? BundleId { get; set; }
        public string? AppDisplayName { get; set; }
    }
}
