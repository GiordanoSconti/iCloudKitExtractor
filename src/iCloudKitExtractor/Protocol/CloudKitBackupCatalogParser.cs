using System.Buffers.Binary;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Estrae metadati catalogo backup da risposte CloudKit record/retrieve (D:, S:).
/// Date: CFAbsoluteTime (secondi dal 2001-01-01) in snapshotCommittedDates.
/// Dimensione: somma ricorsiva dei byte in domainQuota per snapshot.
/// </summary>
public static class CloudKitBackupCatalogParser
{
    private static readonly DateTimeOffset AppleEpoch =
        new(2001, 1, 1, 0, 0, 0, TimeSpan.Zero);

    private static readonly Regex SnapshotRecordRegex = new(
        @"&?S:[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly Regex DeviceRecordRegex = new(
        @"\*?D:[0-9a-f]{40}",
        RegexOptions.Compiled);

    private static readonly Regex PlistDateRegex = new(
        @"<date>\s*([^<]+?)\s*</date>",
        RegexOptions.IgnoreCase | RegexOptions.Compiled);

    private static readonly HashSet<string> DeviceFieldNames = new(StringComparer.Ordinal)
    {
        "marketingName",
        "productType",
        "hardwareModel",
        "serialNumber",
        "deviceName",
        "deviceClass",
    };

    private static readonly HashSet<string> SnapshotFieldNames = new(StringComparer.Ordinal)
    {
        "productVersion",
        "buildVersion",
        "deviceName",
        "backupType",
        "originalSnapshotID",
    };

    public sealed class DeviceCatalog
    {
        public string? MarketingName { get; init; }
        public string? ProductType { get; init; }
        public string? HardwareModel { get; init; }
        public string? SerialNumber { get; init; }
        public string? DeviceName { get; init; }
        public IReadOnlyList<string> SnapshotRecordNames { get; init; } = [];
        public IReadOnlyList<string> OrderedSnapshotRecordNames { get; init; } = [];
        public IReadOnlyList<DateTimeOffset> CommittedDatesOrdered { get; init; } = [];
    }

    public sealed class SnapshotCatalog
    {
        public string RecordName { get; init; } = string.Empty;
        public string? OriginalSnapshotId { get; init; }
        public string? ProductVersion { get; init; }
        public string? BuildVersion { get; init; }
        public string? DeviceName { get; init; }
        public long? SizeBytes { get; init; }
        public DateTimeOffset? BackupDate { get; init; }
        /// <summary>Campo CloudKit <c>backupProperties</c> (ENCRYPTED_BYTES) grezzo.</summary>
        public byte[]? BackupPropertiesCiphertext { get; init; }
    }

    public static DeviceCatalog ParseDeviceRecord(byte[] payload, string deviceRecordName)
    {
        var fields = ExtractNamedStringFields(payload, DeviceFieldNames);
        var orderedSnapshots = ExtractOrderedSnapshotRecordNames(payload);
        var committedDates = ExtractCommittedDatesOrdered(payload);

        return new DeviceCatalog
        {
            MarketingName = GetField(fields, "marketingName"),
            ProductType = GetField(fields, "productType"),
            HardwareModel = GetField(fields, "hardwareModel"),
            SerialNumber = GetField(fields, "serialNumber"),
            DeviceName = GetField(fields, "deviceName"),
            SnapshotRecordNames = orderedSnapshots,
            OrderedSnapshotRecordNames = orderedSnapshots,
            CommittedDatesOrdered = committedDates,
        };
    }

    /// <summary>Estrae nomi record device (*D:sha / D:sha) da qualsiasi payload CloudKit/mbs.</summary>
    public static IReadOnlyList<string> ExtractDeviceRecords(byte[]? payload)
    {
        if (payload is not { Length: > 0 })
            return [];

        var names = new HashSet<string>(StringComparer.Ordinal);
        var text = Encoding.Latin1.GetString(payload);

        foreach (Match match in DeviceRecordRegex.Matches(text))
            names.Add(CloudKitRecordNames.CanonicalDeviceRecordName(match.Value));

        foreach (var s in ProtobufStringScanner.ExtractDelimited(payload))
        {
            foreach (Match match in DeviceRecordRegex.Matches(s))
                names.Add(CloudKitRecordNames.CanonicalDeviceRecordName(match.Value));
        }

        foreach (var s in ProtobufStringScanner.ExtractAsciiRuns(payload, 8))
        {
            foreach (Match match in DeviceRecordRegex.Matches(s))
                names.Add(CloudKitRecordNames.CanonicalDeviceRecordName(match.Value));
        }

        return names.Take(32).ToList();
    }

    /// <summary>Estrae nomi record device (*D:sha / D:sha) dalla risposta BackupAccount.</summary>
    public static IReadOnlyList<string> ExtractDeviceRecordsFromBackupAccount(byte[]? payload) =>
        ExtractDeviceRecords(payload);

    public static DateTimeOffset? ResolveSnapshotDate(
        string canonicalSnapshotName,
        IReadOnlyList<string> orderedSnapshots,
        IReadOnlyList<DateTimeOffset> committedDates)
    {
        if (committedDates.Count == 0 || orderedSnapshots.Count == 0)
            return null;

        var index = orderedSnapshots
            .Select(CloudKitRecordNames.CanonicalSnapshotRecordName)
            .ToList()
            .FindIndex(n => string.Equals(n, canonicalSnapshotName, StringComparison.OrdinalIgnoreCase));

        if (index < 0 || index >= committedDates.Count)
            return null;

        return committedDates[index];
    }

    public static void ApplyToSnapshot(BackupSnapshot snapshot, SnapshotCatalog catalog)
    {
        // BackupUuid resta il GUID del record S: (layout). originalSnapshotID è un campo separato
        // e su alcuni snapshot differisce (es. catena incrementale).
        if (!string.IsNullOrWhiteSpace(catalog.OriginalSnapshotId))
            snapshot.OriginalSnapshotId = catalog.OriginalSnapshotId;
        snapshot.ProductVersion ??= catalog.ProductVersion;
        snapshot.BuildVersion ??= catalog.BuildVersion;
        snapshot.SizeBytes ??= catalog.SizeBytes;
        snapshot.BackupDate ??= catalog.BackupDate;
        if (catalog.BackupPropertiesCiphertext is { Length: > 0 })
            snapshot.BackupPropertiesCiphertext = catalog.BackupPropertiesCiphertext;
    }

    public static bool IsMetadataIncomplete(BackupSnapshot snapshot) =>
        snapshot.BackupDate is not { Year: >= 2015 }
        || string.IsNullOrWhiteSpace(snapshot.ProductVersion)
        || snapshot.SizeBytes is not > 0;

    public static IReadOnlyDictionary<string, SnapshotCatalog> ParseSnapshotBatch(byte[] payload)
    {
        var result = new Dictionary<string, SnapshotCatalog>(StringComparer.OrdinalIgnoreCase);
        foreach (var (recordName, slice) in SplitSnapshotSlices(payload))
        {
            var canonical = CloudKitRecordNames.CanonicalSnapshotRecordName(recordName);
            var fields = ExtractNamedStringFields(slice, SnapshotFieldNames);

            result[canonical] = new SnapshotCatalog
            {
                RecordName = canonical,
                OriginalSnapshotId = NormalizeSnapshotUdid(GetField(fields, "originalSnapshotID")),
                ProductVersion = GetField(fields, "productVersion"),
                BuildVersion = GetField(fields, "buildVersion"),
                DeviceName = GetField(fields, "deviceName"),
                SizeBytes = SumDomainQuotaBytes(slice),
                BackupDate = ExtractSnapshotBackupDate(slice),
                BackupPropertiesCiphertext = ExtractBackupPropertiesCiphertext(slice),
            };
        }

        return result;
    }

    private static string? GetField(IReadOnlyDictionary<string, string> fields, string name) =>
        fields.TryGetValue(name, out var value) ? value.TrimEnd(':') : null;

    /// <summary>
    /// Estrae il Value CloudKit di <c>backupProperties</c> (ENCRYPTED_BYTES) dallo slice S:.
    /// </summary>
    private static byte[]? ExtractBackupPropertiesCiphertext(byte[] slice)
    {
        var fields = CloudKitResponseParser.ExtractNamedByteFields(slice, "backupProperties");
        if (fields.TryGetValue("backupProperties", out var bytes) && bytes.Length >= 16)
            return bytes;
        return null;
    }

    /// <summary>
    /// UDID backup (campo CloudKit originalSnapshotID), senza prefisso $ e con UUID canonico.
    /// </summary>
    public static string? NormalizeSnapshotUdid(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var value = raw.Trim().TrimStart('$').TrimEnd(':').Trim();
        if (value.Length == 0)
            return null;

        return Guid.TryParse(value, out var guid)
            ? guid.ToString("D").ToUpperInvariant()
            : value.ToUpperInvariant();
    }

    private static List<string> ExtractOrderedSnapshotRecordNames(byte[] payload)
    {
        var fromSnapshotsField = ExtractSnapshotNamesFromSnapshotsField(payload);
        if (fromSnapshotsField.Count > 0)
            return fromSnapshotsField;

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ordered = new List<string>();

        foreach (Match m in SnapshotRecordRegex.Matches(Encoding.UTF8.GetString(payload)))
        {
            var canonical = CloudKitRecordNames.CanonicalSnapshotRecordName(m.Value);
            if (seen.Add(canonical))
                ordered.Add(canonical);
        }

        return ordered.Take(64).ToList();
    }

    private static List<string> ExtractSnapshotNamesFromSnapshotsField(byte[] payload)
    {
        var marker = Encoding.UTF8.GetBytes("snapshots");
        var idx = IndexOf(payload, marker);
        if (idx < 0)
            return [];

        var pos = idx + marker.Length;
        if (!TryReadLengthDelimitedAt(payload, pos, out var region, out _))
            return [];

        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var ordered = new List<string>();
        foreach (Match m in SnapshotRecordRegex.Matches(Encoding.UTF8.GetString(region)))
        {
            var canonical = CloudKitRecordNames.CanonicalSnapshotRecordName(m.Value);
            if (seen.Add(canonical))
                ordered.Add(canonical);
        }

        return ordered.Take(64).ToList();
    }

    private static List<DateTimeOffset> ExtractCommittedDatesOrdered(byte[] payload)
    {
        var marker = Encoding.UTF8.GetBytes("snapshotCommittedDates");
        var idx = IndexOf(payload, marker);
        if (idx < 0)
            return [];

        var pos = idx + marker.Length;
        if (!TryReadLengthDelimitedAt(payload, pos, out var inner, out _))
            return [];

        var dates = new List<DateTimeOffset>();
        var reader = new ProtobufReader(inner);
        while (reader.HasMore)
        {
            try
            {
                var (field, wire) = reader.ReadTag();
                if (field == 11 && wire == 2 && reader.TryReadLengthDelimited(out var entry))
                {
                    if (TryReadFirstCfAbsoluteTime(entry, out var date))
                        dates.Add(date);
                }
                else
                {
                    reader.SkipField(wire);
                }
            }
            catch
            {
                break;
            }
        }

        return dates;
    }

    private static bool TryReadLengthDelimitedAt(
        byte[] payload,
        int pos,
        out byte[] inner,
        out int consumed)
    {
        inner = Array.Empty<byte>();
        consumed = 0;
        if (pos >= payload.Length)
            return false;

        try
        {
            var slice = payload.AsSpan(pos).ToArray();
            var reader = new ProtobufReader(slice);
            var start = reader.Remaining;
            var (field, wire) = reader.ReadTag();
            if (wire != 2 || field != 2)
                return false;

            inner = reader.ReadLengthDelimited();
            consumed = start - reader.Remaining;
            return inner.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryReadFirstCfAbsoluteTime(byte[] entry, out DateTimeOffset date)
    {
        date = default;
        var reader = new ProtobufReader(entry);
        while (reader.HasMore)
        {
            try
            {
                var (_, wire) = reader.ReadTag();
                if (wire == 1)
                {
                    var offset = entry.Length - reader.Remaining;
                    if (offset + 8 <= entry.Length
                        && TryDecodeCfAbsoluteTime(entry.AsSpan(offset, 8).ToArray(), out date))
                    {
                        return true;
                    }

                    reader.SkipField(1);
                }
                else if (wire == 2 && reader.TryReadLengthDelimited(out var nested))
                {
                    if (TryReadFirstCfAbsoluteTime(nested, out date))
                        return true;
                }
                else
                {
                    reader.SkipField(wire);
                }
            }
            catch
            {
                break;
            }
        }

        return false;
    }

    private static bool TryReadLengthDelimitedField(byte[] payload, ref int pos, out byte[] inner)
    {
        var ok = TryReadLengthDelimitedAt(payload, pos, out inner, out var consumed);
        if (ok)
            pos += consumed;
        return ok;
    }

    private static bool TryDecodeCfAbsoluteTime(byte[] eightBytes, out DateTimeOffset date)
    {
        date = default;
        if (eightBytes.Length < 8)
            return false;

        var seconds = BitConverter.Int64BitsToDouble(BinaryPrimitives.ReadInt64LittleEndian(eightBytes));
        if (seconds is < 500_000_000 or > 950_000_000)
            return false;

        date = AppleEpoch.AddSeconds(seconds);
        return date.Year is >= 2015 and <= 2035;
    }

    private static Dictionary<string, string> ExtractNamedStringFields(
        byte[] payload,
        IReadOnlySet<string> allowedNames)
    {
        var fields = new Dictionary<string, string>(StringComparer.Ordinal);
        var data = payload.AsSpan();

        foreach (var name in allowedNames)
        {
            var nameBytes = Encoding.UTF8.GetBytes(name);
            var idx = IndexOf(data, nameBytes);
            while (idx >= 0)
            {
                if (TryReadTypedStringNear(data, idx + nameBytes.Length, out var value)
                    && !string.IsNullOrWhiteSpace(value))
                {
                    fields[name] = value;
                    break;
                }

                idx = IndexOf(data, nameBytes, idx + 1);
            }
        }

        return fields;
    }

    private static bool TryReadTypedStringNear(ReadOnlySpan<byte> data, int start, out string value)
    {
        value = string.Empty;
        var end = Math.Min(data.Length, start + 128);
        for (var i = start; i < end - 2; i++)
        {
            if (data[i] == 0x12 && i + 2 < end)
            {
                var wrapPos = i + 1;
                if (!TryReadVarintAt(data, wrapPos, out var wrapLen, out var wrapNext))
                    continue;

                if (wrapLen is 0 or > 4096 || wrapNext + (int)wrapLen > data.Length)
                    continue;

                if (TryReadTypedStringInSpan(data.Slice(wrapNext, (int)wrapLen), out value))
                    return true;

                i = wrapNext + (int)wrapLen - 1;
                continue;
            }

            if (TryReadTypedStringInSpan(data.Slice(i, end - i), out value))
                return true;
        }

        return false;
    }

    private static bool TryReadTypedStringInSpan(ReadOnlySpan<byte> data, out string value)
    {
        value = string.Empty;
        var limit = Math.Min(data.Length, 64);
        for (var i = 0; i < limit - 2; i++)
        {
            if (data[i] != 0x08 || data[i + 1] != 0x03)
                continue;

            var pos = i + 2;
            if (pos < limit && data[pos] == 0x3A)
                pos++;

            if (pos >= data.Length)
                continue;

            if (!TryReadVarintAt(data, pos, out var len, out var valueStart))
                continue;

            if (len is 0 or > 256 || valueStart + (int)len > data.Length)
                continue;

            try
            {
                value = Encoding.UTF8.GetString(data.Slice(valueStart, (int)len));
                return value.Length > 0 && value.All(c => !char.IsControl(c));
            }
            catch
            {
                return false;
            }
        }

        return false;
    }

    private static bool TryReadVarintAt(
        ReadOnlySpan<byte> data,
        int start,
        out ulong value,
        out int next)
    {
        value = 0;
        next = start;
        var shift = 0;
        while (next < data.Length)
        {
            var b = data[next++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
            if (shift > 63)
                return false;
        }

        return false;
    }

    private static DateTimeOffset? ExtractPlistBackupDate(ReadOnlySpan<byte> data)
    {
        var text = Encoding.UTF8.GetString(data);
        var match = PlistDateRegex.Match(text);
        if (!match.Success)
            return null;

        if (DateTimeOffset.TryParse(
                match.Groups[1].Value.Trim(),
                CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal,
                out var dto))
        {
            return dto;
        }

        return null;
    }

    private static DateTimeOffset? ExtractSnapshotBackupDate(ReadOnlySpan<byte> data)
    {
        var plistDate = ExtractPlistBackupDate(data);
        if (plistDate is { Year: >= 2015 })
            return plistDate;

        return ExtractLatestCfAbsoluteTime(data);
    }

    private static DateTimeOffset? ExtractLatestCfAbsoluteTime(ReadOnlySpan<byte> data)
    {
        DateTimeOffset? best = null;
        for (var i = 0; i + 8 <= data.Length; i++)
        {
            if (!TryDecodeCfAbsoluteTime(data.Slice(i, 8).ToArray(), out var date))
                continue;

            if (best is null || date > best)
                best = date;
        }

        return best;
    }

    private static long? SumDomainQuotaBytes(ReadOnlySpan<byte> data)
    {
        var marker = Encoding.UTF8.GetBytes("domainQuota");
        long? best = null;
        var pos = 0;
        while (pos < data.Length)
        {
            var idx = IndexOf(data, marker, pos);
            if (idx < 0)
                break;

            var after = idx + marker.Length;
            if (TryReadLengthDelimitedAt(data.ToArray(), after, out var quotaRoot, out _))
            {
                var sum = SumQuotaVarintsRecursive(quotaRoot);
                if (sum > 0 && (best is null || sum > best))
                    best = sum;
            }

            pos = idx + marker.Length;
        }

        return best;
    }

    private static long SumQuotaVarintsRecursive(ReadOnlySpan<byte> data)
    {
        long sum = 0;
        var reader = new ProtobufReader(data.ToArray());
        while (reader.HasMore)
        {
            try
            {
                var (_, wire) = reader.ReadTag();
                if (wire == 0)
                {
                    var v = (long)reader.ReadVarint();
                    if (v is >= 1024 and <= 2_000_000_000_000L)
                        sum += v;
                }
                else if (wire == 2 && reader.TryReadLengthDelimited(out var nested))
                {
                    sum += SumQuotaVarintsRecursive(nested);
                }
                else
                {
                    reader.SkipField(wire);
                }
            }
            catch
            {
                break;
            }
        }

        return sum;
    }

    private static IEnumerable<(string RecordName, byte[] Slice)> SplitSnapshotSlices(byte[] payload)
    {
        var hits = new List<(int Index, string Name)>();
        foreach (Match m in SnapshotRecordRegex.Matches(Encoding.UTF8.GetString(payload)))
        {
            var name = CloudKitRecordNames.CanonicalSnapshotRecordName(m.Value);
            var idx = IndexOf(payload, Encoding.UTF8.GetBytes($"&{name}"));
            if (idx < 0)
                idx = IndexOf(payload, Encoding.UTF8.GetBytes(name));
            if (idx >= 0)
                hits.Add((idx, name));
        }

        hits = hits
            .GroupBy(h => h.Name, StringComparer.OrdinalIgnoreCase)
            .Select(g => g.OrderBy(x => x.Index).First())
            .OrderBy(h => h.Index)
            .ToList();

        for (var i = 0; i < hits.Count; i++)
        {
            var start = hits[i].Index;
            var end = i + 1 < hits.Count ? hits[i + 1].Index : payload.Length;
            var len = end - start;
            if (len <= 0)
                continue;

            yield return (hits[i].Name, payload.AsSpan(start, len).ToArray());
        }
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle, int start = 0)
    {
        if (needle.Length == 0 || haystack.Length < needle.Length)
            return -1;

        for (var i = Math.Max(0, start); i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.Slice(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }
}
