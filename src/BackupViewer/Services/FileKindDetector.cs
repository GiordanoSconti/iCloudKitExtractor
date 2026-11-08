using System.IO;
using System.Text;
using BackupViewer.Models;

namespace BackupViewer.Services;

public static class FileKindDetector
{
    private static readonly HashSet<string> ImageExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".heic", ".heif", ".tif", ".tiff",
    };

    private static readonly HashSet<string> VideoExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".mov", ".mp4", ".m4v", ".avi", ".mkv", ".hevc",
    };

    private static readonly HashSet<string> AudioExt = new(StringComparer.OrdinalIgnoreCase)
    {
        ".m4a", ".mp3", ".aac", ".wav", ".caf", ".aiff", ".flac",
    };

    public static void Classify(BackupFileEntry entry)
    {
        if (entry.IsDirectory)
        {
            entry.Kind = FileKind.Directory;
            entry.CategoryKey = "dirs";
            return;
        }

        if (!entry.ExistsOnDisk)
        {
            entry.Kind = FileKind.Missing;
            entry.CategoryKey = "missing";
            return;
        }

        if (entry.SizeBytes == 0)
        {
            entry.Kind = FileKind.Empty;
            entry.CategoryKey = "empty";
            return;
        }

        var ext = Path.GetExtension(entry.RelativePath);
        if (ImageExt.Contains(ext))
        {
            entry.Kind = FileKind.Image;
            entry.CategoryKey = "media";
            return;
        }

        if (VideoExt.Contains(ext))
        {
            entry.Kind = FileKind.Video;
            entry.CategoryKey = "media";
            return;
        }

        if (AudioExt.Contains(ext))
        {
            entry.Kind = FileKind.Audio;
            entry.CategoryKey = "media";
            return;
        }

        if (ext.Equals(".json", StringComparison.OrdinalIgnoreCase))
        {
            entry.Kind = FileKind.Json;
            entry.CategoryKey = "structured";
            return;
        }

        if (ext.Equals(".xml", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".html", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".htm", StringComparison.OrdinalIgnoreCase))
        {
            entry.Kind = FileKind.Xml;
            entry.CategoryKey = "structured";
            return;
        }

        if (ext.Equals(".plist", StringComparison.OrdinalIgnoreCase))
        {
            entry.Kind = ProbePlist(entry.AbsolutePath!);
            entry.CategoryKey = "plist";
            return;
        }

        if (ext.Equals(".db", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".sqlite", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".sqlite3", StringComparison.OrdinalIgnoreCase)
            || ext.Equals(".sqlitedb", StringComparison.OrdinalIgnoreCase))
        {
            entry.Kind = FileKind.Sqlite;
            entry.CategoryKey = "databases";
            return;
        }

        if (LooksLikeSqlite(entry.AbsolutePath!))
        {
            entry.Kind = FileKind.Sqlite;
            entry.CategoryKey = "databases";
            return;
        }

        var head = ReadHead(entry.AbsolutePath!, 16);
        if (head.Length >= 8 && Encoding.ASCII.GetString(head, 0, 8) == "bplist00")
        {
            entry.Kind = FileKind.PlistBinary;
            entry.CategoryKey = "plist";
            return;
        }

        if (head.Length >= 5 && Encoding.ASCII.GetString(head, 0, 5) == "<?xml")
        {
            entry.Kind = LooksLikePlistXml(entry.AbsolutePath!)
                ? FileKind.PlistXml
                : FileKind.Xml;
            entry.CategoryKey = entry.Kind == FileKind.PlistXml ? "plist" : "structured";
            return;
        }

        if (LooksLikeText(head) || IsTextyExtension(ext))
        {
            entry.Kind = FileKind.Text;
            entry.CategoryKey = "text";
            return;
        }

        if (LooksLikeProtobuf(head, entry.SizeBytes))
        {
            entry.Kind = FileKind.Protobuf;
            entry.CategoryKey = "protobuf";
            return;
        }

        entry.Kind = FileKind.Binary;
        entry.CategoryKey = "binary";
    }

    private static FileKind ProbePlist(string path)
    {
        var head = ReadHead(path, 16);
        if (head.Length >= 8 && Encoding.ASCII.GetString(head, 0, 8) == "bplist00")
            return FileKind.PlistBinary;
        return FileKind.PlistXml;
    }

    private static bool LooksLikePlistXml(string path)
    {
        try
        {
            using var sr = new StreamReader(path, Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            var sample = sr.ReadToEnd();
            if (sample.Length > 4096)
                sample = sample[..4096];
            return sample.Contains("<plist", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    private static bool LooksLikeSqlite(string path)
    {
        var head = ReadHead(path, 16);
        return head.Length >= 15
               && Encoding.ASCII.GetString(head, 0, 15) == "SQLite format 3";
    }

    private static bool IsTextyExtension(string ext) =>
        ext is ".txt" or ".csv" or ".log" or ".md" or ".css" or ".js" or ".ts"
            or ".swift" or ".py" or ".sql" or ".strings" or ".conf" or ".ini"
            or ".yml" or ".yaml" or ".toml";

    private static bool LooksLikeText(byte[] head)
    {
        if (head.Length == 0)
            return false;
        var printable = 0;
        foreach (var b in head)
        {
            if (b is 9 or 10 or 13 || b is >= 32 and < 127)
                printable++;
            else if (b == 0)
                return false;
        }

        return printable >= head.Length * 0.85;
    }

    private static bool LooksLikeProtobuf(byte[] head, long size)
    {
        if (size is < 4 or > 8_000_000 || head.Length < 2)
            return false;
        // Very weak heuristic: first byte looks like a protobuf tag (field<<3|wire).
        var tag = head[0];
        var wire = tag & 0x07;
        return wire is 0 or 1 or 2 or 5 && tag != 0;
    }

    private static byte[] ReadHead(string path, int n)
    {
        try
        {
            using var fs = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            var buf = new byte[n];
            var read = fs.Read(buf, 0, n);
            if (read == n)
                return buf;
            return buf.AsSpan(0, read).ToArray();
        }
        catch
        {
            return [];
        }
    }
}
