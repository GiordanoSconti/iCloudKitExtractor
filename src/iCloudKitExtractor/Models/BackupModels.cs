namespace iCloudKitExtractor.Models;

public sealed class BackupDevice
{
    /// <summary>
    /// Id record CloudKit <c>D:&lt;sha40&gt;</c> (hash opaco Apple), non l'UDID hardware iOS.
    /// Serve alle API CloudKit (retrieve Device, KA: prefix, keybag).
    /// </summary>
    public string DeviceUuid { get; set; } = string.Empty;
    /// <summary>UDID hardware iOS (es. <c>00008150…</c>) se noto — cartella preferita.</summary>
    public string? HardwareUdid { get; set; }
    public string? ProductType { get; set; }
    public string? HardwareModel { get; set; }
    public string? MarketingName { get; set; }
    public string? SerialNumber { get; set; }
    public string? DisplayName { get; set; }
    public List<BackupSnapshot> Snapshots { get; set; } = new();
    public List<string> Keybags { get; set; } = new();
    /// <summary>Id record <c>K:&lt;uuid16&gt;</c> trovati sul Device (prima del download blob).</summary>
    public List<string> KeybagRecordIds { get; set; } = new();
    /// <summary>Payload grezzi record/retrieve (o query) per ciascun id K:.</summary>
    public Dictionary<string, byte[]> KeybagRawPayloads { get; set; } = new(StringComparer.Ordinal);
    /// <summary>Campo <c>keybagData</c> grezzo (spesso PCS) per id K:.</summary>
    public Dictionary<string, byte[]> KeybagDataBlobs { get; set; } = new(StringComparer.Ordinal);
    public List<string> AssetHints { get; set; } = new();

    public int SnapshotCount => Snapshots.Count;

    public string ModelLabel =>
        MarketingName ?? ProductType ?? DisplayName ?? DeviceUuid;

    /// <summary>Valore da mostrare in UI: UDID hardware se noto, altrimenti hash CloudKit.</summary>
    public string DisplayDeviceId =>
        !string.IsNullOrWhiteSpace(HardwareUdid) ? HardwareUdid : DeviceUuid;
}

public sealed class BackupSnapshot
{
    public string RecordName { get; set; } = string.Empty;
    public string ZoneName { get; set; } = "mbksync";
    /// <summary>GUID del record <c>S:</c> (cartella snapshot), non confondere con <see cref="OriginalSnapshotId"/>.</summary>
    public string? BackupUuid { get; set; }

    /// <summary>Campo CloudKit <c>originalSnapshotID</c> (può differire dal GUID <c>S:</c>).</summary>
    public string? OriginalSnapshotId { get; set; }

    /// <summary>GUID snapshot da usare in path/UI (= record <c>S:</c>).</summary>
    public string? Udid => BackupUuid;
    public string? ProductVersion { get; set; }
    public string? BuildVersion { get; set; }
    public long? SizeBytes { get; set; }
    public DateTimeOffset? BackupDate { get; set; }
    public string? MmcsAuth { get; set; }
    /// <summary>Payload CloudKit S:/&amp;S: recuperato durante la lista snapshot, riusato dal download.</summary>
    public byte[]? CatalogPayload { get; set; }

    /// <summary>Campo CloudKit <c>backupProperties</c> grezzo (type=20 ENCRYPTED_BYTES).</summary>
    public byte[]? BackupPropertiesCiphertext { get; set; }

    /// <summary>Plist <c>backupProperties</c> dopo decrypt PCS (bplist/xml).</summary>
    public byte[]? BackupPropertiesPlaintext { get; set; }

    public string? BackupPropertiesStatus { get; set; }
    public string? BackupPropertiesVersion { get; set; }
    public string? SystemDomainsVersion { get; set; }
    public string? ActiveAppleId { get; set; }
    public bool? WasPasscodeSet { get; set; }
    public int? AccountType { get; set; }
    public DateTimeOffset? BackupPropertiesDate { get; set; }

    /// <summary>UDID hardware da <c>backupProperties.Lockdown.UniqueDeviceID</c> (es. <c>00008150-…</c>).</summary>
    public string? HardwareUdid { get; set; }
    public string? LockdownSerialNumber { get; set; }
    public string? LockdownProductType { get; set; }
    public string? LockdownDeviceName { get; set; }

    public string ShortUuid =>
        BackupUuid is { Length: >= 8 } uuid ? uuid[..8].ToUpperInvariant() : RecordName;

    public string SizeLabel => SizeBytes is long size and > 0
        ? FormatBytes(size)
        : "-";

    public string DateLabel => BackupDate is { Year: >= 2015 } date
        ? date.ToLocalTime().ToString("g")
        : "-";

    public string IosLabel => string.IsNullOrWhiteSpace(ProductVersion)
        ? "-"
        : string.IsNullOrWhiteSpace(BuildVersion)
            ? ProductVersion
            : $"{ProductVersion} ({BuildVersion})";

    public string PasscodeLabel => WasPasscodeSet switch
    {
        true => "sì",
        false => "no",
        null => "—"
    };

    public string BackupPropsVersionLabel =>
        string.IsNullOrWhiteSpace(BackupPropertiesVersion) ? "—" : BackupPropertiesVersion;

    public string SystemDomainsLabel =>
        string.IsNullOrWhiteSpace(SystemDomainsVersion) ? "—" : SystemDomainsVersion;

    public string AppleIdLabel =>
        string.IsNullOrWhiteSpace(ActiveAppleId) ? "—" : ActiveAppleId;

    public string BackupPropsStatusLabel =>
        string.IsNullOrWhiteSpace(BackupPropertiesStatus)
            ? (BackupPropertiesCiphertext is { Length: > 0 } ? "cifrato" : "—")
            : BackupPropertiesStatus;

    private static string FormatBytes(long bytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        double size = bytes;
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }

        return unit == 0
            ? $"{bytes:N0} {units[unit]}"
            : $"{size:0.##} {units[unit]}";
    }
}

/// <summary>
/// Asset scaricabile in <c>_defaultZone</c>.
/// Per file flist (allineato <c>CKFile+0x08</c>):
/// <see cref="RecordName"/> = <c>A:{pref4}:{uuid}:{token}:{size}</c>
/// (pref4 = zonePref = <c>DevicePrefix4</c>);
/// <see cref="RecordIdSuffix"/> = rid grezzo <c>uuid:token=:size</c>;
/// <see cref="MmcsFileId"/> = <c>F:{uuid}:{token}:{size}:</c>.
/// </summary>
public sealed class BackupAsset
{
    /// <summary>
    /// recordKey (<c>CKFile+0x08</c>): <c>A:{pref4}:{rid}</c>
    /// (pref4 ≡ zonePref ProcessFiles).
    /// Non collassare a UUID — sibling flist condividono l'UUID ma non il token.
    /// </summary>
    public string RecordName { get; set; } = string.Empty;
    public string ZoneName { get; set; } = "_defaultZone";
    /// <summary>
    /// FileID MMCS da rid flist: <c>F:{uuid}:{token}:{size}:</c>.
    /// Distinto da <see cref="FileId"/> (SHA1 domain-path per Manifest.db).
    /// </summary>
    public string? MmcsFileId { get; set; }

    /// <summary>
    /// <c>Assets.recordIDSuffix</c> grezzo: <c>uuid:token=:size</c>.
    /// </summary>
    public string? RecordIdSuffix { get; set; }

    /// <summary>
    /// <c>Assets.assetSignature</c> (21 B, tipicamente <c>0x04‖20B</c>) —
    /// field1 del body authorizeGet (verbatim).
    /// </summary>
    public byte[]? AssetSignature { get; set; }

    /// <summary>
    /// Stesso <see cref="AssetSignature"/> già scaricato: non rifare authorizeGet/edge;
    /// copia il body sul fileID SHA1(domain-path) di questo path iTunes.
    /// </summary>
    public bool ContentFromExistingSignature { get; set; }

    /// <summary><c>Assets.compressionMethod</c> (0 = nessuno).</summary>
    public long? CompressionMethod { get; set; }

    /// <summary>
    /// Companion 21 B (<c>0x01‖20B</c>) per authorizeGet field4 —
    /// DA CONFERMARE A RUNTIME: origine da CK/PreAuth mmcs-auth part1.
    /// </summary>
    public byte[]? MmcsCompanionSignature { get; set; }

    /// <summary>AuthToken CAog… (authorizeGet field2) senza i due hex del header.</summary>
    public string? MmcsAuthToken { get; set; }

    public long? SizeBytes { get; set; }
    public string? MmcsAuth { get; set; }
    /// <summary>
    /// <c>Asset.protectionInfo.protectionInfo</c> AES-KW wrap (hex):
    /// 24 B → chiave 16 B, oppure 40 B → chiave 32 B.
    /// </summary>
    public string? AssetProtectionInfoHex { get; set; }
    /// <summary>
    /// IKM Ford (CKFile[+0x160]): AES-KW unwrap di <see cref="AssetProtectionInfoHex"/>
    /// con NISTKDF(zoneMaster, "wrapping key wrap me") → tipicamente 32 B (wrap40) o 16 B (wrap24).
    /// </summary>
    public byte[]? AssetUnwrappedKey { get; set; }
    /// <summary>
    /// Hex del wrap usato per produrre <see cref="AssetUnwrappedKey"/> — invalida la cache IKM se cambia.
    /// </summary>
    public string? AssetUnwrappedKeyWrapHex { get; set; }
    /// <summary>Record ProtectionInfo DER (hex) — master per unwrap del wrap.</summary>
    public string? RecordProtectionInfoDerHex { get; set; }

    /// <summary>
    /// Twin logico CKFile (alloc 0x1F8) + FileGroup materials per questo Asset.
    /// Popolato da <c>AssetMaterialPipeline</c>.
    /// </summary>
    public AssetCkFile? CkFileAsset { get; set; }

    /// <summary>Estensione dichiarata sul BackupAsset (es. <c>plist</c>).</summary>
    public string? Extension { get; set; }

    /// <summary>
    /// Finestra/payload CloudKit del record BackupAsset (query|retrieve) —
    /// serve a isolare <c>encryptedAttributes</c> per il decrypt PCS.
    /// </summary>
    public byte[]? RecordPayload { get; set; }

    /// <summary>Domain iTunes (post metadata decrypt), es. <c>AppDomain-…</c>.</summary>
    public string? Domain { get; set; }

    /// <summary>Path relativo nel backup (post metadata decrypt).</summary>
    public string? RelativePath { get; set; }

    /// <summary>Protection class iOS (1–11) per unwrap EncryptionKey.</summary>
    public int? ProtectionClass { get; set; }

    /// <summary>Chiave file wrappata (40 B) da metadata — AES-KW con class key.</summary>
    public byte[]? EncryptionKey { get; set; }

    /// <summary>
    /// <c>SHA1(domain + "-" + relativePath)</c> hex — nome filesystem/iTunes.
    /// Null finché domain/path non sono noti.
    /// </summary>
    public string? FileId { get; set; }

    /// <summary>True se domain+relativePath sono disponibili per Manifest/xx/fileID.</summary>
    public bool HasFilesystemIdentity =>
        !string.IsNullOrWhiteSpace(Domain) && !string.IsNullOrWhiteSpace(RelativePath);

    /// <summary>Calcola e assegna <see cref="FileId"/> se domain/path presenti.</summary>
    public string? EnsureFileId()
    {
        if (!string.IsNullOrWhiteSpace(FileId))
            return FileId;
        if (!HasFilesystemIdentity)
            return null;

        FileId = ComputeFileId(Domain!, RelativePath!);
        return FileId;
    }

    /// <summary>fileID iTunes/ SHA1(domain + "-" + relativePath) hex.</summary>
    public static string ComputeFileId(string domain, string relativePath)
    {
        var input = System.Text.Encoding.UTF8.GetBytes($"{domain}-{relativePath}");
        return Convert.ToHexString(System.Security.Cryptography.SHA1.HashData(input))
            .ToLowerInvariant();
    }
}

public sealed class DownloadJob
{
    public required string OutputDirectory { get; init; }
    public required BackupSnapshot Snapshot { get; init; }
    public required BackupDevice Device { get; init; }
    /// <summary>Limite opzionale per test (null = tutti gli asset del manifest).</summary>
    public int? MaxAssets { get; init; }
    /// <summary>iCloud Security Code — usato solo se <see cref="EnableEscrowRecover"/> è true.</summary>
    public string? IcscSecurityCode { get; init; }
    /// <summary>Se true, esegue srp_init→recover con iCSC durante il download (default: off).</summary>
    public bool EnableEscrowRecover { get; init; }
    /// <summary>Se true, costruisce solo il catalogo S:→M:→files + Manifest.db locale (niente download file).</summary>
    public bool ManifestOnly { get; init; }
    /// <summary>Etichetta UI catena, es. <c>2/5 · 2024-03-01 · A1B2C3D4</c>.</summary>
    public string? ChainLabel { get; init; }
}

public sealed class DownloadProgressReport
{
    public long BytesDownloaded { get; init; }
    public long TotalBytes { get; init; }
    public string Status { get; init; } = string.Empty;
    public int AssetsCompleted { get; init; }
    public int AssetsTotal { get; init; }
    /// <summary>File con contenuto MMCS già scaricato (anche in coda decrypt o falliti dopo download).</summary>
    public int FilesDownloaded { get; init; }
    /// <summary>File scritti in Backup/ dopo decrypt riuscito (non include coda né Falliti).</summary>
    public int FilesDecrypted { get; init; }
    /// <summary>Decifratura fallita in modo definitivo (non PENDING chunk).</summary>
    public int FilesDecryptFailed { get; init; }
    /// <summary>
    /// File scritti in Backup/ ancora ciphertext (no file-AES plaintext): parity incompleta PC1/PC2
    /// oppure body CIFRATO/incompleto su fallimento MMCS.
    /// </summary>
    public int FilesCiphertextSaved { get; init; }
    /// <summary>Totale file previsti (stesso denominatore delle barre Scaricati/Decifrati).</summary>
    public int FilesTotal { get; init; }
    /// <summary>Snapshot in corso (catena o singolo), per la status bar.</summary>
    public string? SnapshotLabel { get; init; }
    /// <summary>Job decrypt in coda + in esecuzione.</summary>
    public int DecryptQueued { get; init; }
    /// <summary>Path clonati da shard già scaricato (stessa assetSignature).</summary>
    public int FilesDuplicated { get; init; }
    /// <summary>File in attesa di chunk MMCS in cache (pending assemble).</summary>
    public int FilesPendingChunks { get; init; }
    /// <summary>
    /// Sequenza monotona del report (UI ignora seq &lt; ultimo applicato: evita coda decrypt stale
    /// da BeginInvoke / race download vs worker).
    /// </summary>
    public long ReportSequence { get; init; }
    /// <summary>False per byte-progress (solo status bar), true per eventi da loggare.</summary>
    public bool AppendToLog { get; init; } = true;
}

/// <summary>
/// Unwrap wrap40/IKM o Ford decrypt fallito: interrompe il download backup.
/// Mostrato nel popup Download.
/// </summary>
public sealed class BackupCryptoAbortException : InvalidOperationException
{
    public BackupCryptoAbortException(string message) : base(message) { }

    public BackupCryptoAbortException(string message, Exception inner)
        : base(message, inner) { }
}
