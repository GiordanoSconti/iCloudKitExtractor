using System.Globalization;
using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Sidecar a fine snapshot : <c>Info.plist</c> (XML), <c>Status.plist</c> /
/// <c>Manifest.plist</c> (bplist), costruiti da device + snapshot + Lockdown già in sessione
/// (niente fetch aggiuntivi).
/// </summary>
public static class ItunesBackupSidecarWriter
{
    public static async Task WriteAsync(
        string cleanBackupDirectory,
        BackupDevice device,
        BackupSnapshot snapshot,
        ICloudSession? session = null,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        bool isComplete = true,
        bool? isFullBackup = null)
    {
        Directory.CreateDirectory(cleanBackupDirectory);
        var date = snapshot.BackupPropertiesDate
                   ?? snapshot.BackupDate
                   ?? DateTimeOffset.UtcNow;
        var full = isFullBackup ?? isComplete;

        // Info: Build/Device/Product/Serial/UDID da device + Lockdown già sul snapshot.
        await File.WriteAllBytesAsync(
            Path.Combine(cleanBackupDirectory, "Info.plist"),
            BuildInfoPlist(device, snapshot, date),
            ct).ConfigureAwait(false);

        // Status: finished solo se Manifest flags=1 tutti presenti su disco.
        await File.WriteAllBytesAsync(
            Path.Combine(cleanBackupDirectory, "Status.plist"),
            BuildStatusPlist(snapshot, date, isComplete, full),
            ct).ConfigureAwait(false);

        // Manifest: preferisci backupProperties plaintext (include Lockdown completo);
        // altrimenti sintetizza dalle stesse chiavi già estratte in lista device/snapshot.
        var manifestPath = Path.Combine(cleanBackupDirectory, "Manifest.plist");
        if (snapshot.BackupPropertiesPlaintext is { Length: > 32 } plain)
        {
            await File.WriteAllBytesAsync(manifestPath, plain, ct).ConfigureAwait(false);
            var kind = plain.AsSpan().StartsWith("bplist"u8) ? "bplist" : "xml";
            log?.Report(
                $"  Manifest.plist ← backupProperties in sessione ({kind}, {plain.Length:N0} B)");
        }
        else
        {
            await File.WriteAllBytesAsync(
                manifestPath,
                BuildManifestPlist(device, snapshot, session, date),
                ct).ConfigureAwait(false);
            log?.Report(
                "  Manifest.plist ← device+snapshot+Lockdown (bplist sintetico)");
        }

        log?.Report(
            $"  Info.plist + Status.plist scritti da device/Lockdown " +
            $"(UDID={device.HardwareUdid ?? snapshot.HardwareUdid ?? "—"}; " +
            $"SnapshotState={(isComplete ? "finished" : "incomplete")}; " +
            $"IsFullBackup={full})");
        log?.Report(
            $"Snapshot pulito → {cleanBackupDirectory} " +
            "(Manifest.db + Info/Status/Manifest.plist + xx/fileID)");
    }

    /// <summary> XML indentato, 8 chiavi, senza DOCTYPE.</summary>
    private static byte[] BuildInfoPlist(
        BackupDevice device,
        BackupSnapshot snapshot,
        DateTimeOffset date)
    {
        var udid = device.HardwareUdid
                   ?? snapshot.HardwareUdid
                   ?? IkeBackupOutputPaths.ResolveDeviceFolderName(device);
        var target = udid.Replace("-", "", StringComparison.Ordinal).ToLowerInvariant();
        var unique = NormalizeUdidDisplay(udid);

        var sb = new StringBuilder(512);
        sb.Append("""<?xml version="1.0" encoding="UTF-8" ?>""").Append('\n');
        sb.Append("""<plist version="1.0">""").Append('\n');
        sb.Append("    <dict>\n");
        AppendXmlString(sb, "Build Version", snapshot.BuildVersion ?? "");
        AppendXmlString(sb, "Device Name",
            snapshot.LockdownDeviceName ?? device.DisplayName ?? "iPhone");
        AppendXmlString(sb, "Product Type",
            snapshot.LockdownProductType ?? device.ProductType ?? "");
        AppendXmlString(sb, "Product Version", snapshot.ProductVersion ?? "");
        AppendXmlString(sb, "Serial Number",
            snapshot.LockdownSerialNumber ?? device.SerialNumber ?? "");
        AppendXmlString(sb, "Target Identifier", target);
        AppendXmlString(sb, "Unique Identifier", unique);
        AppendXmlDate(sb, "Last Backup Date", date);
        sb.Append("    </dict>\n");
        sb.Append("</plist>\n");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    /// <summary>
    ///  bplist — BackupState, SnapshotState, Version, Date, UUID, IsFullBackup.
    ///  <paramref name="isComplete"/> false → SnapshotState=incomplete.
    ///  <paramref name="isFullBackup"/> = vista full (merge incrementale), anche se incomplete.
    /// </summary>
    private static byte[] BuildStatusPlist(
        BackupSnapshot snapshot,
        DateTimeOffset date,
        bool isComplete,
        bool isFullBackup)
    {
        var dict = new Dictionary<string, object?>
        {
            ["BackupState"] = "new",
            ["SnapshotState"] = isComplete ? "finished" : "incomplete",
            ["Version"] = "2.4",
            ["Date"] = date.ToUniversalTime(),
            ["UUID"] = IkeBackupOutputPaths.ResolveSnapshotGuid(snapshot),
            ["IsFullBackup"] = isFullBackup
        };
        return AppleBinaryPlist.Write(dict);
    }

    /// <summary>
    /// Fallback se backupProperties assente: solo chiavi top-level presenti in,
    /// senza campi inventati (niente BudyStashData / SnapshotHMACKey finti).
    /// </summary>
    private static byte[] BuildManifestPlist(
        BackupDevice device,
        BackupSnapshot snapshot,
        ICloudSession? session,
        DateTimeOffset date)
    {
        var dict = new Dictionary<string, object?>
        {
            ["AccountType"] = snapshot.AccountType ?? 1,
            ["Version"] = snapshot.BackupPropertiesVersion ?? "9.1",
            ["Date"] = date.ToUniversalTime()
        };

        if (!string.IsNullOrWhiteSpace(snapshot.SystemDomainsVersion))
            dict["SystemDomainsVersion"] = snapshot.SystemDomainsVersion;

        var appleId = snapshot.ActiveAppleId;
        if (!string.IsNullOrWhiteSpace(appleId))
        {
            var entry = new Dictionary<string, object?>();
            if (!string.IsNullOrWhiteSpace(session?.Dsid))
                entry["dsid"] = session!.Dsid!;
            dict["AppleIDs"] = new Dictionary<string, object?>
            {
                [appleId] = entry
            };
        }

        if (snapshot.WasPasscodeSet is bool pass)
            dict["WasPasscodeSet"] = pass;

        if (!string.IsNullOrWhiteSpace(appleId))
            dict["ActiveAppleID"] = appleId;

        dict["Lockdown"] = BuildLockdown(device, snapshot);

        dict["IsEncrypted"] = "BackupKeyBag";
        dict["BackupKeyBag"] = Array.Empty<byte>();

        return AppleBinaryPlist.Write(dict);
    }

    private static Dictionary<string, object?> BuildLockdown(
        BackupDevice device,
        BackupSnapshot snapshot)
    {
        var udid = NormalizeUdidDisplay(
            device.HardwareUdid ?? snapshot.HardwareUdid
            ?? IkeBackupOutputPaths.ResolveDeviceFolderName(device));
        return new Dictionary<string, object?>
        {
            ["BuildVersion"] = snapshot.BuildVersion ?? "",
            ["DeviceClass"] = "iPhone",
            ["DeviceName"] = snapshot.LockdownDeviceName ?? device.DisplayName ?? "iPhone",
            ["ProductType"] = snapshot.LockdownProductType ?? device.ProductType ?? "",
            ["ProductVersion"] = snapshot.ProductVersion ?? "",
            ["SerialNumber"] = snapshot.LockdownSerialNumber ?? device.SerialNumber ?? "",
            ["UniqueDeviceID"] = udid
        };
    }

    private static string NormalizeUdidDisplay(string udid)
    {
        var t = udid.Trim();
        if (t.Contains('-', StringComparison.Ordinal))
            return t.ToUpperInvariant();
        if (t.Length == 24 && t.All(Uri.IsHexDigit))
            return $"{t[..8]}-{t[8..]}".ToUpperInvariant();
        return t.ToUpperInvariant();
    }

    private static void AppendXmlString(StringBuilder sb, string key, string value)
    {
        sb.Append("        <key>").Append(Escape(key)).Append("</key>\n");
        sb.Append("        <string>").Append(Escape(value)).Append("</string>\n");
    }

    private static void AppendXmlDate(StringBuilder sb, string key, DateTimeOffset value)
    {
        sb.Append("        <key>").Append(Escape(key)).Append("</key>\n");
        sb.Append("        <date>")
            .Append(value.UtcDateTime.ToString(
                "yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture))
            .Append("</date>\n");
    }

    private static string Escape(string value) =>
        value.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);
}
