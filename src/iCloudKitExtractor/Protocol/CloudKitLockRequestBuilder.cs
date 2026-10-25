using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Costruzione dinamica record/save Lock (CKDModifyRecordsOperation-Private).
/// </summary>
public static class CloudKitLockRequestBuilder
{
    private const int ModifyRecordsType = 210;
    private const ulong LockDurationSeconds = 172_800;

    public static byte[] BuildLockSave(
        RestoreRequestContext context,
        string cloudKitUserId,
        string deviceSha1,
        string lockOperationId)
    {
        var deviceSha = NormalizeDeviceSha(deviceSha1);
        // 20260721: "{sha}:Lock" senza il prefisso "-".
        var lockRecordName = $"{deviceSha}:Lock";

        var inner = new ProtobufWriter();
        inner.WriteString(1, lockOperationId);
        inner.WriteVarint(2, ModifyRecordsType);
        inner.WriteVarint(4, 1);

        var record = BuildLockRecord(lockRecordName, cloudKitUserId, deviceSha);

        var modify = new ProtobufWriter();
        modify.WriteBytes(1, record);
        modify.WriteVarint(2, 1);
        modify.WriteVarint(6, 3);

        var op = new ProtobufWriter();
        op.WriteBytes(1, CloudKitDelimitedRequest.BuildRestoreHeader(
            cloudKitUserId,
            "CKDModifyRecordsOperation-Private",
            context));
        op.WriteBytes(2, inner.ToArray());
        op.WriteBytes(ModifyRecordsType, modify.ToArray());

        return CloudKitDelimitedRequest.WrapDelimitedMessage(op.ToArray());
    }

    private static byte[] BuildLockRecord(string lockRecordName, string cloudKitUserId, string deviceSha)
    {
        //  RecordIdentifier diretto in fields.f1 (niente wrap extra).
        var recordId = new ProtobufWriter();
        recordId.WriteString(1, lockRecordName);
        recordId.WriteVarint(2, 1);

        var fields = new ProtobufWriter();
        fields.WriteBytes(1, recordId.ToArray());
        fields.WriteBytes(2, CloudKitDelimitedRequest.BuildZoneIdentifier("mbksync", cloudKitUserId));

        var typeName = new ProtobufWriter();
        typeName.WriteString(1, "Lock");

        var ownerValue = new ProtobufWriter();
        ownerValue.WriteVarint(1, 3);
        ownerValue.WriteString(7, deviceSha);

        var ownerField = BuildNamedField("owner", ownerValue.ToArray());

        var durationValue = new ProtobufWriter();
        durationValue.WriteVarint(1, 7);
        durationValue.WriteVarint(4, LockDurationSeconds);

        var durationField = BuildNamedField("duration", durationValue.ToArray());

        var record = new ProtobufWriter();
        record.WriteBytes(2, fields.ToArray());
        record.WriteBytes(3, typeName.ToArray());
        record.WriteBytes(12, ownerField);
        record.WriteBytes(12, durationField);

        return record.ToArray();
    }

    /// <summary>
    /// Campo nominato  un solo wrap sul nome (<c>0a 07 0a 05 owner</c>), non doppio.
    /// Il doppio wrap produceva Lockb9 vs Lockb7 e Invalid lock id.
    /// </summary>
    private static byte[] BuildNamedField(string name, byte[] value)
    {
        var nameLeaf = new ProtobufWriter();
        nameLeaf.WriteString(1, name);

        var field = new ProtobufWriter();
        field.WriteBytes(1, nameLeaf.ToArray());
        field.WriteBytes(2, value);
        return field.ToArray();
    }

    private static string NormalizeDeviceSha(string deviceSha1) =>
        deviceSha1.StartsWith("D:", StringComparison.OrdinalIgnoreCase)
            ? deviceSha1[2..]
            : deviceSha1;
}
