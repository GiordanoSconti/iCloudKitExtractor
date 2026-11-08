using System.IO;
using BackupViewer.Models;

namespace BackupViewer.Services;

/// <summary>
/// Indice path media WhatsApp nel backup.
/// In ChatStorage i path sono spesso "Media/…", negli shard "Message/Media/…".
/// </summary>
public sealed class WhatsAppMediaIndex
{
    private readonly Dictionary<string, BackupFileEntry> _byRelative =
        new(StringComparer.OrdinalIgnoreCase);
    private readonly Dictionary<string, BackupFileEntry> _byFileName =
        new(StringComparer.OrdinalIgnoreCase);

    public static WhatsAppMediaIndex Build(BackupCatalog catalog)
    {
        var idx = new WhatsAppMediaIndex();
        foreach (var f in catalog.Files)
        {
            if (f.IsDirectory || !f.ExistsOnDisk || string.IsNullOrWhiteSpace(f.AbsolutePath))
                continue;
            if (!f.Domain.Contains("whatsapp", StringComparison.OrdinalIgnoreCase))
                continue;

            var rel = f.RelativePath.Replace('\\', '/');
            idx._byRelative[rel] = f;

            var name = f.DisplayName;
            if (!string.IsNullOrWhiteSpace(name)
                && name.Contains('.')
                && !name.Equals("Photo.jpg", StringComparison.OrdinalIgnoreCase))
            {
                // Prefer Message/Media over Profile collisions
                if (!idx._byFileName.TryGetValue(name, out var existing)
                    || (!existing.RelativePath.Contains("/Media/", StringComparison.OrdinalIgnoreCase)
                        && rel.Contains("Message/Media/", StringComparison.OrdinalIgnoreCase)))
                {
                    idx._byFileName[name] = f;
                }
            }
        }

        return idx;
    }

    public BackupFileEntry? Resolve(string? mediaLocalPath)
    {
        if (string.IsNullOrWhiteSpace(mediaLocalPath))
            return null;

        var rel = mediaLocalPath.Replace('\\', '/').TrimStart('/');

        if (_byRelative.TryGetValue(rel, out var hit))
            return hit;
        if (!rel.StartsWith("Message/", StringComparison.OrdinalIgnoreCase)
            && _byRelative.TryGetValue("Message/" + rel, out hit))
            return hit;
        if (rel.StartsWith("Message/", StringComparison.OrdinalIgnoreCase)
            && _byRelative.TryGetValue(rel["Message/".Length..], out hit))
            return hit;

        var name = Path.GetFileName(rel);
        if (!string.IsNullOrWhiteSpace(name) && _byFileName.TryGetValue(name, out hit))
            return hit;

        return null;
    }
}
