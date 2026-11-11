namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Nomi record CloudKit backup come osservati nelle capture akd.
/// </summary>
public static class CloudKitRecordNames
{
    public static IEnumerable<string> FetchNameCandidates(string recordName)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            yield break;

        if (recordName.StartsWith("D:", StringComparison.Ordinal))
        {
            yield return $"*{recordName}";
            yield return recordName;
            yield return recordName[2..];
            yield break;
        }

        if (recordName.StartsWith("*D:", StringComparison.Ordinal))
        {
            yield return recordName;
            yield return recordName[1..];
            yield break;
        }

        if (recordName.StartsWith("S:", StringComparison.Ordinal))
        {
            // retrieve usa S:; &S: è solo riferimento in Device response.
            yield return recordName;
            yield return $"&{recordName}";
            yield return recordName[2..];
            yield break;
        }

        if (recordName.StartsWith("&S:", StringComparison.Ordinal))
        {
            yield return recordName[1..];
            yield return recordName;
            yield break;
        }

        yield return recordName;
    }

    /// <summary>Nome record preferito in fase restore/download (*D:, S:).</summary>
    public static string PrimaryFetchName(string recordName)
    {
        foreach (var candidate in RestoreFetchCandidates(recordName))
            return candidate;
        return recordName;
    }

    /// <summary>Candidati per il fetch in fase lista backup (D:, S: prima).</summary>
    public static IEnumerable<string> ListFetchCandidates(string recordName)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            yield break;

        if (recordName.StartsWith("*D:", StringComparison.Ordinal))
        {
            yield return recordName[1..];
            yield return recordName;
            yield break;
        }

        if (recordName.StartsWith("D:", StringComparison.Ordinal))
        {
            yield return recordName;
            yield return $"*{recordName}";
            yield break;
        }

        if (recordName.StartsWith("&S:", StringComparison.Ordinal))
        {
            yield return recordName[1..];
            yield return recordName;
            yield break;
        }

        if (recordName.StartsWith("S:", StringComparison.Ordinal))
        {
            yield return recordName;
            yield return $"&{recordName}";
            yield break;
        }

        yield return recordName;
    }

    /// <summary>Candidati per restore/download (prefissi prima).</summary>
    public static IEnumerable<string> RestoreFetchCandidates(string recordName) => FetchNameCandidates(recordName);

    public static string CanonicalDeviceRecordName(string recordName)
    {
        if (recordName.StartsWith("*D:", StringComparison.Ordinal))
            return recordName[1..];
        if (recordName.StartsWith("D:", StringComparison.Ordinal))
            return recordName;
        return $"D:{recordName}";
    }

    public static string CanonicalSnapshotRecordName(string recordName)
    {
        if (recordName.StartsWith("&S:", StringComparison.Ordinal))
            return recordName[1..];
        if (recordName.StartsWith("S:", StringComparison.Ordinal))
            return recordName;
        return $"S:{recordName}";
    }

    /// <summary>
    /// Nome wire batch pre-Lock  <c>S:uuid</c> (non <c>&amp;S:</c>).
    /// Il byte lunghezza 0x26 (= ASCII '&amp;') davanti a <c>S:</c> ha generato falsi positivi nelle catture.
    /// In Device response i riferimenti compaiono come <c>&amp;S:</c>, ma il retrieve batch usa <c>S:</c>.
    /// </summary>
    public static string BatchSnapshotRecordName(string recordName) =>
        CanonicalSnapshotRecordName(recordName);

    public static string StripDevicePrefix(string recordName)
    {
        if (recordName.StartsWith("*D:", StringComparison.Ordinal))
            return recordName[3..];
        if (recordName.StartsWith("D:", StringComparison.Ordinal))
            return recordName[2..];
        return recordName;
    }

    public static string StripSnapshotPrefix(string recordName)
    {
        if (recordName.StartsWith("&S:", StringComparison.Ordinal))
            return recordName[3..];
        if (recordName.StartsWith("S:", StringComparison.Ordinal))
            return recordName[2..];
        return recordName;
    }

    public static string DeviceRecord(string deviceSha1) =>
        deviceSha1.StartsWith("D:", StringComparison.Ordinal) ? deviceSha1 : $"D:{deviceSha1}";

    public static string DeviceLockRecord(string deviceSha1)
    {
        var sha = deviceSha1.StartsWith("D:", StringComparison.Ordinal) ? deviceSha1[2..] : deviceSha1;
        // Wire: "{sha}:Lock" (senza "-" iniziale).
        return $"{sha}:Lock";
    }

    public static string DevicePrefix4(string deviceSha1)
    {
        var sha = deviceSha1.StartsWith("D:", StringComparison.Ordinal) ? deviceSha1[2..] : deviceSha1;
        return sha.Length >= 4 ? sha[..4] : sha;
    }
}
