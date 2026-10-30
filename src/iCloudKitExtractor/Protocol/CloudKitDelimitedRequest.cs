using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Costruzione di RequestOperation delimited per CloudKit backup, allineata
/// allo schema CloudDBClient.desc osservato nelle catture akd (iOS 12).
/// </summary>
public static class CloudKitDelimitedRequest
{
    private const int FetchRecordZonesType = 201;
    private const int FetchRecordZoneChangesType = 203;
    public const int FetchRecordsType = 211;
    private const int FetchRecordChangesType = 213;
    internal const int QueryOperationType = 220;

    public static readonly string[] BackupZones = { "_defaultZone", "mbksync" };

    public static byte[] BuildFetchRecordZones(
        string cloudKitUserId,
        IEnumerable<string> zoneNames,
        RestoreRequestContext? restore = null,
        CloudKitContainerBinding? container = null,
        string? zoneOwnerUserId = null)
    {
        var zones = zoneNames.ToList();
        if (zones.Count == 0)
            throw new ArgumentException("Nessuna zona da recuperare.");
        // Lab ACL: header identity (cloudKitUserId) may differ from zone owner.
        var owner = string.IsNullOrWhiteSpace(zoneOwnerUserId) ? cloudKitUserId : zoneOwnerUserId;

        byte[]? payload = null;
        for (var i = 0; i < zones.Count; i++)
        {
            var inner = new ProtobufWriter();
            inner.WriteString(1, Guid.NewGuid().ToString());
            inner.WriteVarint(2, FetchRecordZonesType);
            // zone/retrieve: Operation.last = 0 sul singolo retrieve "default".
            inner.WriteVarint(4, 0);

            // ZoneRetrieveRequest: proto storico InflatableDonkey = field 1;
            // CloudDocs moderno (2026) scrive SOLO field 2. Scrivere field 1 con
            // nome "default" → "Zone does not exist"; field 2 solo → tutte le zone + PI.
            var zoneId = BuildZoneIdentifier(NormalizeZoneNameForRetrieve(zones[i]), owner);
            var zoneWrap = new ProtobufWriter();
            zoneWrap.WriteBytes(2, zoneId);

            var op = new ProtobufWriter();
            if (i == 0)
            {
                op.WriteBytes(1, restore is null
                    ? BuildPlainHeader(cloudKitUserId, "CKDFetchRecordZonesOperation", container)
                    : BuildRestoreHeader(cloudKitUserId, "CKDFetchRecordZonesOperation", restore, container));
            }

            op.WriteBytes(2, inner.ToArray());
            op.WriteBytes(201, zoneWrap.ToArray());

            var chunk = WrapDelimited(op.ToArray());
            payload = payload is null ? chunk : Concat(payload, chunk);
        }

        return payload!;
    }

    /// <summary>
    /// Body <c>CKDFetchRecordZonesOperation</c> (field 201).
    /// recovery backup lo posta su <c>/record/retrieve</c>; CloudDocs spesso su <c>/zone/retrieve</c>.
    /// </summary>
    public static byte[] BuildZoneRetrieve(
        string cloudKitUserId,
        IEnumerable<string> zoneNames,
        RestoreRequestContext? restore = null,
        CloudKitContainerBinding? container = null,
        string? zoneOwnerUserId = null) =>
        BuildFetchRecordZones(cloudKitUserId, zoneNames, restore, container, zoneOwnerUserId);

    /// <summary>
    /// CloudDocs usa il nome zona <c>default</c> (non <c>_defaultZone</c>) in zone/retrieve.
    /// </summary>
    public static string NormalizeZoneNameForRetrieve(string zoneName)
    {
        if (string.IsNullOrWhiteSpace(zoneName))
            return "default";
        if (zoneName.Equals("_defaultZone", StringComparison.OrdinalIgnoreCase)
            || zoneName.Equals("defaultZone", StringComparison.OrdinalIgnoreCase))
            return "default";
        return zoneName;
    }

    public static byte[] BuildRecordRetrieve(
        string cloudKitUserId,
        string zoneName,
        IEnumerable<string> recordNames,
        RestoreRequestContext? restore = null,
        CloudKitContainerBinding? container = null)
    {
        var names = recordNames.ToList();
        if (names.Count == 0)
            throw new ArgumentException("Nessun record da recuperare.");

        byte[]? payload = null;
        for (var i = 0; i < names.Count; i++)
        {
            var inner = new ProtobufWriter();
            inner.WriteString(1, Guid.NewGuid().ToString());
            inner.WriteVarint(2, FetchRecordsType);
            inner.WriteVarint(4, 1);

            var retrieve = BuildRecordRetrieveBody(names[i], zoneName, cloudKitUserId);

            var op = new ProtobufWriter();
            if (i == 0)
            {
                op.WriteBytes(1, restore is null
                    ? BuildPlainHeader(cloudKitUserId, "CKDFetchRecordsOperation-Private", container)
                    : BuildRestoreHeader(cloudKitUserId, "CKDFetchRecordsOperation-Private", restore, container));
            }

            op.WriteBytes(2, inner.ToArray());
            op.WriteBytes(211, retrieve);

            var chunk = WrapDelimited(op.ToArray());
            payload = payload is null ? chunk : Concat(payload, chunk);
        }

        return payload!;
    }

    /// <summary>
    /// <c>CKDFetchDatabaseChangesOperation</c> — elenca zone del private DB (field 203).
    /// </summary>
    public static byte[] BuildZoneRetrieveChanges(
        string cloudKitUserId,
        byte[]? syncContinuationToken = null,
        CloudKitContainerBinding? container = null)
    {
        var inner = new ProtobufWriter();
        inner.WriteString(1, Guid.NewGuid().ToString());
        inner.WriteVarint(2, FetchRecordZoneChangesType);
        inner.WriteVarint(4, 1);

        var changes = new ProtobufWriter();
        if (syncContinuationToken is { Length: > 0 })
            changes.WriteBytes(1, syncContinuationToken);
        changes.WriteVarint(2, 200); // limit

        var op = new ProtobufWriter();
        op.WriteBytes(1, BuildPlainHeader(
            cloudKitUserId, "CKDFetchDatabaseChangesOperation", container));
        op.WriteBytes(2, inner.ToArray());
        op.WriteBytes(203, changes.ToArray());
        return WrapDelimited(op.ToArray());
    }

    /// <summary>
    /// <c>CKDFetchRecordZoneChangesOperation</c> — delta record in una zona (field 213).
    /// Token nullo = storia completa dalla creazione zona.
    /// Proto rustpush: syncContinuationToken=1, zoneIdentifier=2, …
    /// </summary>
    public static byte[] BuildRecordRetrieveChanges(
        string cloudKitUserId,
        string zoneName,
        byte[]? syncContinuationToken = null,
        CloudKitContainerBinding? container = null)
    {
        var inner = new ProtobufWriter();
        inner.WriteString(1, Guid.NewGuid().ToString());
        inner.WriteVarint(2, FetchRecordChangesType);
        inner.WriteVarint(4, 1);

        // RetrieveChangesRequest (OpenBubbles/rustpush cloudkit.proto):
        //   1 syncContinuationToken
        //   2 zoneIdentifier
        //   4 maxChanges
        //   5 requestedChangesTypes
        //   6 assetsToDownload
        //   7 newestFirst
        var changes = new ProtobufWriter();
        if (syncContinuationToken is { Length: > 0 })
            changes.WriteBytes(1, syncContinuationToken);
        changes.WriteBytes(2, BuildZoneIdentifier(zoneName, cloudKitUserId));
        changes.WriteVarint(5, 3); // requestedChangesTypes (rustpush = 3)
        var assets = new ProtobufWriter();
        assets.WriteVarint(1, 1); // allAssets
        changes.WriteBytes(6, assets.ToArray());
        changes.WriteVarint(7, 0); // newestFirst = false

        var op = new ProtobufWriter();
        op.WriteBytes(1, BuildPlainHeader(
            cloudKitUserId, "CKDFetchRecordZoneChangesOperation", container));
        op.WriteBytes(2, inner.ToArray());
        op.WriteBytes(213, changes.ToArray());
        return WrapDelimited(op.ToArray());
    }

    /// <summary>
    /// CKKS / iCloud Keychain views (appleservices <c>cloudkit.buildRecordSyncBody</c>):
    /// <c>CKDFetchRecordChangesOperation</c>, <c>requestedChangesTypes=3</c>, no requestedFields.
    /// Zone names: <c>Passwords</c>, <c>LimitedPeersAllowed</c>, …
    /// </summary>
    public static byte[] BuildCkksRecordSync(
        string cloudKitUserId,
        string zoneName,
        byte[]? syncContinuationToken = null,
        CloudKitContainerBinding? container = null,
        string? zoneOwnerUserId = null)
    {
        var owner = string.IsNullOrWhiteSpace(zoneOwnerUserId) ? cloudKitUserId : zoneOwnerUserId;
        var inner = new ProtobufWriter();
        inner.WriteString(1, Guid.NewGuid().ToString());
        inner.WriteVarint(2, FetchRecordChangesType);
        inner.WriteVarint(4, 1);

        var zid = new ProtobufWriter();
        zid.WriteBytes(1, BuildZoneName(zoneName));
        zid.WriteBytes(2, BuildUserIdentifier(owner));
        zid.WriteVarint(3, 1);

        var changes = new ProtobufWriter();
        if (syncContinuationToken is { Length: > 0 })
            changes.WriteBytes(1, syncContinuationToken);
        changes.WriteBytes(2, zid.ToArray());
        changes.WriteVarint(5, 3); // requestedChangesTypes — appleservices CKKS

        var op = new ProtobufWriter();
        op.WriteBytes(1, BuildPlainHeader(
            cloudKitUserId, "CKDFetchRecordChangesOperation", container));
        op.WriteBytes(2, inner.ToArray());
        op.WriteBytes(213, changes.ToArray());
        return WrapDelimited(op.ToArray());
    }

    /// <summary>
    /// Notes Sync Data (<c>capture_syncdata_notes_20260827_125749</c> wo 196/206):
    /// <c>CKDFetchRecordChangesOperation</c>, zona <c>Notes</c>,
    /// <c>maxChanges=1000</c>, <c>requestedChangesTypes=1</c>, no <c>newestFirst</c>.
    /// </summary>
    public static byte[] BuildNotesRecordRetrieveChanges(
        string cloudKitUserId,
        string zoneName,
        byte[]? syncContinuationToken = null,
        CloudKitContainerBinding? container = null) =>
        BuildDriveStyleRecordRetrieveChanges(cloudKitUserId, zoneName, syncContinuationToken, container);

    /// <summary>
    /// iCloud Drive / CloudDocs (<c>capture_icloud_drive_20260828_084540</c> wo 186/552):
    /// <c>CKDFetchRecordChangesOperation</c> (non ZoneChanges), zone
    /// <c>com.apple.CloudDocs</c> / <c>com.apple.CloudDocs.container-metadata</c>,
    /// <c>maxChanges=1000</c>, <c>requestedChangesTypes=1</c>, allAssets.
    /// </summary>
    public static byte[] BuildCloudDocsRecordRetrieveChanges(
        string cloudKitUserId,
        string zoneName,
        byte[]? syncContinuationToken = null,
        CloudKitContainerBinding? container = null,
        int requestedChangesTypes = 1,
        bool includeRequestedFields = true) =>
        BuildDriveStyleRecordRetrieveChanges(
            cloudKitUserId,
            zoneName,
            syncContinuationToken,
            container,
            requestedChangesTypes,
            includeRequestedFields);

    private static byte[] BuildDriveStyleRecordRetrieveChanges(
        string cloudKitUserId,
        string zoneName,
        byte[]? syncContinuationToken,
        CloudKitContainerBinding? container,
        int requestedChangesTypes = 1,
        bool includeRequestedFields = true)
    {
        var inner = new ProtobufWriter();
        inner.WriteString(1, Guid.NewGuid().ToString());
        inner.WriteVarint(2, FetchRecordChangesType);
        inner.WriteVarint(4, 1);

        var changes = new ProtobufWriter();
        if (syncContinuationToken is { Length: > 0 })
            changes.WriteBytes(1, syncContinuationToken);
        changes.WriteBytes(2, BuildZoneIdentifier(zoneName, cloudKitUserId));
        // CloudDocs/WhatsApp: field 3 = requestedFields (encryptedBasename/parent/…).
        if (includeRequestedFields)
            changes.WriteBytes(3, BuildCloudDocsRequestedFields());
        changes.WriteVarint(4, 1000); // maxChanges — CloudDocs/Notes
        changes.WriteVarint(5, (ulong)requestedChangesTypes);
        var assets = new ProtobufWriter();
        assets.WriteVarint(1, 1); // allAssets
        changes.WriteBytes(6, assets.ToArray());

        var op = new ProtobufWriter();
        op.WriteBytes(1, BuildPlainHeader(
            cloudKitUserId, "CKDFetchRecordChangesOperation", container));
        op.WriteBytes(2, inner.ToArray());
        op.WriteBytes(213, changes.ToArray());
        return WrapDelimited(op.ToArray());
    }

    /// <summary>
    /// <c>capture_icloud_drive</c> wo 552 (zona WhatsApp) / 522 (CloudDocs):
    /// <c>RetrieveChangesRequest.requestedFields</c> = lista
    /// <c>RecordField { identifier { name } }</c>.
    /// </summary>
    private static byte[] BuildCloudDocsRequestedFields()
    {
        // Ordine e nomi da cattura 00552 (WhatsApp CloudDocs).
        // Encoding: repeated field1 = RecordFieldIdentifier{ name=1 } ( 0a len 0a len name).
        string[] names =
        [
            "encryptedBasename", "extension", "parent", "target", "hiddenExt",
            "executable", "writable", "finderTags", "ftags", "size", "fileContent",
            "pkgSignature", "pkgContent", "pkgManifest", "mtime", "birthtime",
            "hiddenExt", "bounceNo",
        ];
        var fields = new ProtobufWriter();
        foreach (var name in names)
        {
            var ident = new ProtobufWriter();
            ident.WriteString(1, name);
            fields.WriteBytes(1, ident.ToArray());
        }

        return fields.ToArray();
    }

    public static string BuildMultiDPathBatchName(IEnumerable<string> dPathSpecs) =>
        string.Join(",", dPathSpecs.Where(static s => !string.IsNullOrWhiteSpace(s)));

    public static byte[] BuildPrivilegedBatchFetch(
        string cloudKitUserId,
        string zoneName,
        string recordName,
        RestoreRequestContext? restore = null) =>
        BuildPrivilegedBatchFetch(cloudKitUserId, zoneName, [recordName], restore);

    /// <summary>
    /// PrivilegedBatch multi-ref (capture 00253): Value.type=13 + <c>f11</c> ripetuto
    /// per ogni <c>TYPE:pref4:rid</c>.
    /// </summary>
    public static byte[] BuildPrivilegedBatchFetch(
        string cloudKitUserId,
        string zoneName,
        IEnumerable<string> recordNames,
        RestoreRequestContext? restore = null)
    {
        var names = recordNames
            .Where(static n => !string.IsNullOrWhiteSpace(n))
            .Select(static n => n.Trim())
            .Distinct(StringComparer.Ordinal)
            .ToList();
        if (names.Count == 0)
            throw new ArgumentException("Serve almeno un recordName.", nameof(recordNames));

        var inner = new ProtobufWriter();
        inner.WriteString(1, Guid.NewGuid().ToString().ToUpperInvariant());
        inner.WriteVarint(2, QueryOperationType);
        inner.WriteVarint(4, 1);

        var op = new ProtobufWriter();
        op.WriteBytes(1, restore is null
            ? BuildPlainHeader(cloudKitUserId, "CKDQueryOperation-Private")
            : BuildRestoreHeader(cloudKitUserId, "CKDQueryOperation-Private", restore));
        op.WriteBytes(2, inner.ToArray());
        op.WriteBytes(220, BuildPrivilegedBatchQueryBody(names, zoneName, cloudKitUserId));

        return WrapDelimited(op.ToArray());
    }

    /// <summary>
    /// Query CPL Photos (<c>capture_http_20260802_054842</c> wo 755/765/775/778):
    /// <c>CPLRecordByType</c> + filtro <c>type EQUALS</c>, oppure
    /// <c>CPLAssetAndMasterByAssetDate</c> senza filtro; zona <c>PrimarySync</c>.
    /// Pagina 2+: QueryRetrieveRequest field 2 (query + continuation marker + last record).
    /// </summary>
    public static byte[] BuildCplQueryRetrieve(
        string cloudKitUserId,
        string zoneName,
        string queryRecordType,
        CloudKitContainerBinding container,
        string? filterFieldName = null,
        string? filterEqualsValue = null,
        string? continuationRecordName = null,
        byte[]? continuationMarker = null)
    {
        if (string.IsNullOrWhiteSpace(queryRecordType))
            throw new ArgumentException("queryRecordType assente.", nameof(queryRecordType));

        var inner = new ProtobufWriter();
        inner.WriteString(1, Guid.NewGuid().ToString().ToUpperInvariant());
        inner.WriteVarint(2, QueryOperationType);
        inner.WriteVarint(4, 1);

        var op = new ProtobufWriter();
        op.WriteBytes(1, BuildPlainHeader(cloudKitUserId, "CKDQueryOperation-Private", container));
        op.WriteBytes(2, inner.ToArray());
        op.WriteBytes(220, BuildCplQueryBody(
            cloudKitUserId,
            zoneName,
            queryRecordType,
            filterFieldName,
            filterEqualsValue,
            continuationRecordName,
            continuationMarker));
        return WrapDelimited(op.ToArray());
    }

    public static byte[] BuildPreAuthQueryProbeMessage(string cloudKitUserId) =>
        BuildPreAuthForegroundRetrieveMessage(cloudKitUserId, restore: null, firstEnRecordName: null);

    public static byte[] BuildPreAuthHeaderMessage(string cloudKitUserId) =>
        BuildPreAuthForegroundRetrieveMessage(cloudKitUserId, restore: null, firstEnRecordName: null);

    public static byte[] BuildPreAuthForegroundRetrieveMessage(
        string cloudKitUserId,
        RestoreRequestContext? restore,
        string? firstEnRecordName)
    {
        // frame 0: RequestOperation { f1=header, f2=correlation, f211=retrieve(primo EN) }.
        // Nessun campo 6 top-level (i flag stanno dentro il retrieve body).
        var inner = new ProtobufWriter();
        inner.WriteString(1, Guid.NewGuid().ToString().ToUpperInvariant());
        inner.WriteVarint(2, FetchRecordsType);
        inner.WriteVarint(4, 1);

        var op = new ProtobufWriter();
        op.WriteBytes(1, restore is null
            ? BuildPlainHeader(cloudKitUserId, "CKDFetchRecordsOperation-Private")
            : BuildRestoreHeader(cloudKitUserId, "CKDFetchRecordsOperation-Private", restore));
        op.WriteBytes(2, inner.ToArray());

        if (!string.IsNullOrWhiteSpace(firstEnRecordName))
            op.WriteBytes(211, BuildRecordRetrieveBody(firstEnRecordName, "_defaultZone", cloudKitUserId));

        return op.ToArray();
    }

    public static byte[] BuildRestoreHeader(
        string cloudKitUserId,
        string operationName,
        RestoreRequestContext restore,
        CloudKitContainerBinding? container = null) =>
        BuildHeaderCore(cloudKitUserId, operationName, restore.DeviceSessionId, restore.Foreground, container);

    internal static byte[] BuildPlainHeader(
        string cloudKitUserId,
        string operationName,
        CloudKitContainerBinding? container = null) =>
        BuildCatalogHeader(cloudKitUserId, operationName, deviceSessionId: null, container);

    /// <summary>
    /// Header per elenco backup (catalogo): schema senza f30 MMCS né RestoreSessionState.
    /// </summary>
    private static byte[] BuildCatalogHeader(
        string cloudKitUserId,
        string operationName,
        string? deviceSessionId,
        CloudKitContainerBinding? container = null)
    {
        var binding = container ?? CloudKitContainerBinding.Backup;
        var header = new ProtobufWriter();
        header.WriteString(2, binding.ContainerId);
        header.WriteString(3, binding.BundleId);
        header.WriteBytes(7, BuildDeviceSession(deviceSessionId ?? Guid.NewGuid().ToString()));
        header.WriteString(8, "13.0");
        header.WriteString(9, "iPhone9,3");
        header.WriteString(10, "com.apple.cloudkit.CloudKitDaemon");
        header.WriteString(11, "829");
        header.WriteString(12, operationName);
        header.WriteVarint(13, 0);
        header.WriteVarint(14, 0);
        header.WriteFixed32(15, 0);
        header.WriteString(18, "5.0");
        header.WriteVarint(19, 1);
        header.WriteString(21, "iPhone");
        header.WriteString(22, ComputeCatalogHardwareId(cloudKitUserId));
        header.WriteVarint(23, 1);
        header.WriteVarint(25, 1);
        header.WriteString(26, "Foreground Restore");
        header.WriteVarint(29, 0);
        return header.ToArray();
    }

    private static string ComputeCatalogHardwareId(string cloudKitUserId)
    {
        var material = "catalog|" + NormalizeUserId(cloudKitUserId);
        return Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(material)));
    }

    private static string NormalizeUserId(string cloudKitUserId) =>
        cloudKitUserId.StartsWith('_') ? cloudKitUserId : $"_{cloudKitUserId.TrimStart('!')}";

    private static byte[] BuildHeaderCore(
        string cloudKitUserId,
        string operationName,
        string? deviceSessionId,
        ForegroundRestorePlist? foreground,
        CloudKitContainerBinding? container = null)
    {
        var binding = container ?? CloudKitContainerBinding.Backup;
        var header = new ProtobufWriter();
        header.WriteString(2, binding.ContainerId);
        header.WriteString(3, binding.BundleId);

        if (!string.IsNullOrWhiteSpace(deviceSessionId))
            header.WriteBytes(7, BuildDeviceSession(deviceSessionId));

        header.WriteString(8, "13.0");
        header.WriteString(9, foreground is not null ? "iPhone9,1" : "iPhone9,3");
        header.WriteString(10, "com.apple.cloudkit.CloudKitDaemon");
        header.WriteString(11, "829");
        header.WriteString(12, operationName);
        header.WriteVarint(13, 0);
        header.WriteVarint(14, 0);
        header.WriteFixed32(15, 0);

        if (foreground is not null)
        {
            header.WriteString(18, foreground.ProtoVersion);
            header.WriteVarint(19, 1);
            header.WriteString(21, "My Computer 1");
            header.WriteString(22, foreground.HardwareIdHex.ToUpperInvariant());
            header.WriteVarint(23, 1);
            header.WriteVarint(25, 1);
            header.WriteString(26, "Foreground Restore");
            header.WriteVarint(29, 0);
            header.WriteBytes(30, BuildForegroundMmcsMetadata(foreground));
        }

        return header.ToArray();
    }

    public static byte[] BuildZoneIdentifier(string zoneName, string cloudKitUserId)
    {
        var zone = new ProtobufWriter();
        zone.WriteBytes(1, BuildZoneName(zoneName));
        zone.WriteBytes(2, BuildUserIdentifier(cloudKitUserId));
        return zone.ToArray();
    }

    public static byte[] WrapDelimitedMessage(byte[] message) => WrapDelimited(message);

    private static byte[] BuildRecordRetrieveBody(
        string recordName,
        string zoneName,
        string cloudKitUserId)
    {
        var recordId = new ProtobufWriter();
        recordId.WriteString(1, recordName);
        recordId.WriteVarint(2, 1);

        var request = new ProtobufWriter();
        request.WriteBytes(1, recordId.ToArray());
        request.WriteBytes(2, BuildZoneIdentifier(zoneName, cloudKitUserId));

        var flags = new ProtobufWriter();
        flags.WriteVarint(1, 1);

        var retrieve = new ProtobufWriter();
        retrieve.WriteBytes(1, request.ToArray());
        retrieve.WriteBytes(6, flags.ToArray());
        return retrieve.ToArray();
    }

    private static byte[] BuildPrivilegedBatchQueryBody(
        string recordName,
        string zoneName,
        string cloudKitUserId) =>
        BuildPrivilegedBatchQueryBody([recordName], zoneName, cloudKitUserId);

    private static byte[] BuildPrivilegedBatchQueryBody(
        IReadOnlyList<string> recordNames,
        string zoneName,
        string cloudKitUserId)
    {
        // 20260809 query/retrieve 00253 + cloud_kit.proto:
        // Value.type = REFERENCE_LIST (13); listValues (f11) = Value{type=REFERENCE(5),
        // referenceValue=…}; Filter.type = IN (3). Un Domain ≈ 6–12 seed.

        var fetchType = new ProtobufWriter();
        fetchType.WriteString(1, "PrivilegedBatchRecordFetch");

        var fieldValue = new ProtobufWriter();
        fieldValue.WriteVarint(1, 13); // REFERENCE_LIST_TYPE
        foreach (var rawName in recordNames)
        {
            //  sempre A:pref4:rid — MA:/KA:/… sono length-byte ASCII, non TYPE.
            var recordName = CloudKitMmcsIds.ToPrivilegedBatchWireName(rawName) ?? rawName.Trim();
            var recordId = new ProtobufWriter();
            recordId.WriteString(1, recordName);
            recordId.WriteVarint(2, 1); // Identifier.Type.RECORD

            var recordAndZone = new ProtobufWriter();
            recordAndZone.WriteBytes(1, recordId.ToArray());
            recordAndZone.WriteBytes(2, BuildZoneIdentifier(zoneName, cloudKitUserId));

            // Record.Reference { type=WEAK(2), recordIdentifier }
            var reference = new ProtobufWriter();
            reference.WriteVarint(1, 2);
            reference.WriteBytes(2, recordAndZone.ToArray());

            // Value { type=REFERENCE(5), referenceValue=f9 }
            var listItem = new ProtobufWriter();
            listItem.WriteVarint(1, 5);
            listItem.WriteBytes(9, reference.ToArray());

            fieldValue.WriteBytes(11, listItem.ToArray()); // listValues
        }

        var fieldName = new ProtobufWriter();
        fieldName.WriteString(1, "___recordID");

        var filter = new ProtobufWriter();
        filter.WriteBytes(1, fieldName.ToArray());
        filter.WriteBytes(2, fieldValue.ToArray());
        filter.WriteVarint(4, 3); // Query.Filter.Type.IN

        var query = new ProtobufWriter();
        query.WriteBytes(1, fetchType.ToArray());
        query.WriteBytes(2, filter.ToArray());

        var flags = new ProtobufWriter();
        flags.WriteVarint(1, 1);

        var body = new ProtobufWriter();
        body.WriteBytes(1, query.ToArray());
        body.WriteBytes(4, BuildZoneIdentifier(zoneName, cloudKitUserId));
        body.WriteBytes(6, flags.ToArray());
        return body.ToArray();
    }

    private static byte[] BuildCplQueryBody(
        string cloudKitUserId,
        string zoneName,
        string queryRecordType,
        string? filterFieldName,
        string? filterEqualsValue,
        string? continuationRecordName,
        byte[]? continuationMarker)
    {
        var fetchType = new ProtobufWriter();
        fetchType.WriteString(1, queryRecordType);

        var query = new ProtobufWriter();
        query.WriteBytes(1, fetchType.ToArray());
        if (!string.IsNullOrWhiteSpace(filterFieldName)
            && !string.IsNullOrWhiteSpace(filterEqualsValue))
        {
            var fieldName = new ProtobufWriter();
            fieldName.WriteString(1, filterFieldName);

            // Value.type = STRING (3); stringValue = field 7. Filter.type = EQUALS (1).
            var fieldValue = new ProtobufWriter();
            fieldValue.WriteVarint(1, 3);
            fieldValue.WriteString(7, filterEqualsValue);

            var filter = new ProtobufWriter();
            filter.WriteBytes(1, fieldName.ToArray());
            filter.WriteBytes(2, fieldValue.ToArray());
            filter.WriteVarint(4, 1);
            query.WriteBytes(2, filter.ToArray());
        }

        var flags = new ProtobufWriter();
        flags.WriteVarint(1, 1);

        var body = new ProtobufWriter();
        if (!string.IsNullOrWhiteSpace(continuationRecordName))
        {
            var ident = new ProtobufWriter();
            ident.WriteString(1, continuationRecordName.Trim());
            ident.WriteVarint(2, 1);

            var cursor = new ProtobufWriter();
            if (continuationMarker is { Length: > 0 })
                cursor.WriteBytes(2, continuationMarker);
            cursor.WriteBytes(3, ident.ToArray());

            var cont = new ProtobufWriter();
            cont.WriteBytes(1, query.ToArray());
            cont.WriteBytes(2, cursor.ToArray());
            body.WriteBytes(2, cont.ToArray());
        }
        else
        {
            body.WriteBytes(1, query.ToArray());
        }

        body.WriteBytes(4, BuildZoneIdentifier(zoneName, cloudKitUserId));
        body.WriteBytes(6, flags.ToArray());
        return body.ToArray();
    }

    private static byte[] BuildForegroundMmcsMetadata(ForegroundRestorePlist foreground)
    {
        var meta = new ProtobufWriter();
        WriteMmcsHeaderPair(meta, "x-apple-mmcs-proto-version", foreground.ProtoVersion);
        WriteMmcsHeaderPair(meta, "x-apple-mmcs-plist-sha256", foreground.PlistSha256Base64);
        WriteMmcsHeaderPair(meta, "x-apple-mmcs-plist-version", foreground.PlistVersion);
        if (!string.IsNullOrWhiteSpace(foreground.MmeClientInfo))
            WriteMmcsHeaderPair(meta, "x-mme-client-info", foreground.MmeClientInfo);
        meta.WriteVarint(2, 0);
        return meta.ToArray();
    }

    private static void WriteMmcsHeaderPair(ProtobufWriter meta, string key, string value)
    {
        var pair = new ProtobufWriter();
        pair.WriteString(1, key);
        pair.WriteString(2, value);
        meta.WriteBytes(1, pair.ToArray());
    }

    private static byte[] BuildDeviceSession(string deviceSessionId)
    {
        var m = new ProtobufWriter();
        m.WriteString(1, deviceSessionId);
        m.WriteVarint(2, 2);
        return m.ToArray();
    }

    private static byte[] BuildZoneName(string zoneName)
    {
        var m = new ProtobufWriter();
        m.WriteString(1, zoneName);
        m.WriteVarint(2, 6);
        return m.ToArray();
    }

    private static byte[] BuildUserIdentifier(string cloudKitUserId)
    {
        var user = new ProtobufWriter();
        user.WriteString(1, cloudKitUserId);
        user.WriteVarint(2, 7);
        return user.ToArray();
    }

    private static byte[] WrapDelimited(byte[] message)
    {
        var len = EncodeVarint((ulong)message.Length);
        return Concat(len, message);
    }

    private static byte[] EncodeVarint(ulong value)
    {
        var bytes = new List<byte>();
        while (value >= 0x80)
        {
            bytes.Add((byte)(value | 0x80));
            value >>= 7;
        }
        bytes.Add((byte)value);
        return bytes.ToArray();
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var length = parts.Sum(p => p.Length);
        var result = new byte[length];
        var offset = 0;
        foreach (var part in parts)
        {
            Buffer.BlockCopy(part, 0, result, offset, part.Length);
            offset += part.Length;
        }
        return result;
    }
}
