using System.Globalization;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// Blob <c>Files.file</c> allineato a  XML compatto con sole 9 chiavi
/// (domain, relativePath, mode, size, userID, groupID, modified, birth, statusChanged).
/// </summary>
public static class ManifestFilePlist
{
    public static byte[] Build(
        string domain,
        string relativePath,
        long mode,
        long size,
        long userId = 0,
        long groupId = 0,
        string? modified = null,
        string? birth = null,
        string? statusChanged = null)
    {
        var now = DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        modified ??= now;
        birth ??= now;
        statusChanged ??= now;

        var sb = new StringBuilder(384);
        sb.Append("""<?xml version="1.0" encoding="UTF-8"?>""");
        sb.Append('\n');
        sb.Append("""<plist version="1.0"><dict>""");
        AppendString(sb, "domain", domain);
        AppendString(sb, "relativePath", relativePath);
        AppendInt(sb, "mode", mode);
        AppendInt(sb, "size", size);
        AppendInt(sb, "userID", userId);
        AppendInt(sb, "groupID", groupId);
        AppendString(sb, "modified", modified);
        AppendString(sb, "birth", birth);
        AppendString(sb, "statusChanged", statusChanged);
        sb.Append("</dict></plist>");
        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    public static byte[] BuildFromAsset(BackupAsset asset, long sizeBytes)
    {
        var size = asset.SizeBytes is > 0 ? asset.SizeBytes.Value : sizeBytes;
        return Build(
            asset.Domain ?? "",
            asset.RelativePath ?? "",
            mode: 33152,
            size: size);
    }

    public static byte[] BuildFromInventory(string domain, FileListSqliteParser.InventoryRow row) =>
        Build(
            domain,
            row.RelativePath,
            row.Mode,
            row.Size,
            row.UserId,
            row.GroupId,
            FormatUnixUtc(row.Modified),
            FormatUnixUtc(row.Birth),
            FormatUnixUtc(row.StatusChanged));

    public static string FormatUnixUtc(long unixSeconds)
    {
        if (unixSeconds <= 0)
            return "1970-01-01T00:00:00Z";
        try
        {
            return DateTimeOffset.FromUnixTimeSeconds(unixSeconds)
                .UtcDateTime
                .ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture);
        }
        catch
        {
            return "1970-01-01T00:00:00Z";
        }
    }

    private static void AppendString(StringBuilder sb, string key, string value)
    {
        sb.Append("<key>").Append(Escape(key)).Append("</key>");
        sb.Append("<string>").Append(Escape(value)).Append("</string>");
    }

    private static void AppendInt(StringBuilder sb, string key, long value)
    {
        sb.Append("<key>").Append(Escape(key)).Append("</key>");
        sb.Append("<integer>").Append(value).Append("</integer>");
    }

    private static string Escape(string value) =>
        value.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);
}
