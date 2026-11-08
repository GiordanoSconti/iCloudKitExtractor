using System.IO;
using System.Text;
using System.Text.Json;
using System.Xml.Linq;
using BackupViewer.Models;

namespace BackupViewer.Services;

public static class PreviewService
{
    private const int MaxTextBytes = 2_000_000;
    private const int MaxHexBytes = 64_000;

    public static async Task<PreviewResult> BuildAsync(
        BackupFileEntry entry,
        CancellationToken ct)
    {
        return await Task.Run(() => Build(entry, ct), ct).ConfigureAwait(false);
    }

    private static PreviewResult Build(BackupFileEntry entry, CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();

        if (entry.IsDirectory)
            return PreviewResult.Status("Directory", entry.RelativePath);

        if (!entry.ExistsOnDisk || string.IsNullOrWhiteSpace(entry.AbsolutePath))
            return PreviewResult.Fail(
                "Assente",
                $"Shard non trovato su disco.\nfileID={entry.FileId}\n{entry.Domain}/{entry.RelativePath}");

        var path = entry.AbsolutePath!;
        try
        {
            return entry.Kind switch
            {
                FileKind.Empty => PreviewResult.Status("Vuoto", "0 byte"),
                FileKind.Image => BuildImage(path, entry.RelativePath),
                FileKind.Video => BuildMedia(path, entry.RelativePath, PreviewMode.Video, entry.DisplayName),
                FileKind.Audio => BuildMedia(path, entry.RelativePath, PreviewMode.Audio, entry.DisplayName),
                FileKind.Sqlite => new PreviewResult
                {
                    Mode = PreviewMode.Sqlite,
                    Title = entry.DisplayName,
                    SqlitePath = path,
                },
                FileKind.PlistBinary => BuildBinaryPlist(path),
                FileKind.PlistXml => BuildXml(path, plistHint: true),
                FileKind.Json => BuildJson(path),
                FileKind.Xml => BuildXml(path, plistHint: false),
                FileKind.Protobuf => BuildProtobuf(path),
                FileKind.Text => BuildText(path),
                FileKind.Binary => BuildHex(path),
                _ => BuildAuto(path, entry.RelativePath),
            };
        }
        catch (Exception ex)
        {
            return PreviewResult.Fail(entry.DisplayName, ex.Message);
        }
    }

    private static PreviewResult BuildMedia(
        string shardPath,
        string relativePath,
        PreviewMode mode,
        string title)
    {
        var staged = MediaStaging.StageWithExtension(shardPath, relativePath);
        return new PreviewResult
        {
            Mode = mode,
            Title = title,
            MediaPath = staged,
        };
    }

    private static PreviewResult BuildImage(string shardPath, string relativePath)
    {
        // HEIC e formati estensione-dipendenti: stage con estensione reale.
        var path = MediaStaging.StageWithExtension(shardPath, relativePath);
        var bmp = ImageLoader.Load(path);
        if (bmp is null)
            return PreviewResult.Fail("Immagine", "Decodifica non riuscita (codec/formato).");
        return new PreviewResult
        {
            Mode = PreviewMode.Image,
            Title = Path.GetFileName(relativePath),
            Image = bmp,
        };
    }

    private static PreviewResult BuildBinaryPlist(string path)
    {
        var data = File.ReadAllBytes(path);
        var json = BinaryPlistParser.ToPrettyJson(data);
        return new PreviewResult
        {
            Mode = PreviewMode.Text,
            Title = "bplist → JSON",
            TextBody = json,
        };
    }

    private static PreviewResult BuildJson(string path)
    {
        var text = ReadTextCapped(path);
        try
        {
            using var doc = JsonDocument.Parse(text);
            var pretty = JsonSerializer.Serialize(
                doc.RootElement,
                new JsonSerializerOptions { WriteIndented = true });
            return new PreviewResult
            {
                Mode = PreviewMode.Text,
                Title = "JSON",
                TextBody = pretty,
            };
        }
        catch
        {
            return new PreviewResult
            {
                Mode = PreviewMode.Text,
                Title = "JSON (raw)",
                TextBody = text,
            };
        }
    }

    private static PreviewResult BuildXml(string path, bool plistHint)
    {
        var text = ReadTextCapped(path);
        try
        {
            var doc = XDocument.Parse(text, LoadOptions.PreserveWhitespace);
            return new PreviewResult
            {
                Mode = PreviewMode.Text,
                Title = plistHint ? "plist XML" : "XML",
                TextBody = doc.ToString(),
            };
        }
        catch
        {
            return new PreviewResult
            {
                Mode = PreviewMode.Text,
                Title = plistHint ? "plist XML (raw)" : "XML (raw)",
                TextBody = text,
            };
        }
    }

    private static PreviewResult BuildProtobuf(string path)
    {
        var data = ReadBytesCapped(path, MaxTextBytes);
        return new PreviewResult
        {
            Mode = PreviewMode.Text,
            Title = "Protobuf wire",
            TextBody = ProtobufWireInspector.Inspect(data),
        };
    }

    private static PreviewResult BuildText(string path) =>
        new()
        {
            Mode = PreviewMode.Text,
            Title = "Testo",
            TextBody = ReadTextCapped(path),
        };

    private static PreviewResult BuildHex(string path)
    {
        var data = ReadBytesCapped(path, MaxHexBytes);
        return new PreviewResult
        {
            Mode = PreviewMode.Text,
            Title = $"Hex ({data.Length:N0} B mostrati)",
            TextBody = ToHexDump(data),
        };
    }

    private static PreviewResult BuildAuto(string path, string relativePath)
    {
        var head = ReadBytesCapped(path, 16);
        if (head.Length >= 8 && Encoding.ASCII.GetString(head, 0, 8) == "bplist00")
            return BuildBinaryPlist(path);
        if (head.Length >= 15 && Encoding.ASCII.GetString(head, 0, 15) == "SQLite format 3")
            return new PreviewResult { Mode = PreviewMode.Sqlite, Title = Path.GetFileName(relativePath), SqlitePath = path };
        if (LooksText(head))
            return BuildText(path);
        return BuildHex(path);
    }

    private static bool LooksText(byte[] head)
    {
        if (head.Length == 0)
            return false;
        foreach (var b in head)
        {
            if (b == 0)
                return false;
            if (b is < 9 or (> 13 and < 32))
                return false;
        }

        return true;
    }

    private static string ReadTextCapped(string path)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var len = (int)Math.Min(fs.Length, MaxTextBytes);
        var buf = new byte[len];
        var read = fs.Read(buf, 0, len);
        var text = Encoding.UTF8.GetString(buf, 0, read);
        if (fs.Length > MaxTextBytes)
            text += $"\n\n… troncato ({fs.Length:N0} B totali)";
        return text;
    }

    private static byte[] ReadBytesCapped(string path, int max)
    {
        using var fs = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        var len = (int)Math.Min(fs.Length, max);
        var buf = new byte[len];
        var read = fs.Read(buf, 0, len);
        if (read == len)
            return buf;
        return buf.AsSpan(0, read).ToArray();
    }

    private static string ToHexDump(byte[] data)
    {
        var sb = new StringBuilder(data.Length * 4);
        for (var i = 0; i < data.Length; i += 16)
        {
            sb.Append(i.ToString("X8")).Append("  ");
            var lineLen = Math.Min(16, data.Length - i);
            for (var j = 0; j < 16; j++)
            {
                if (j < lineLen)
                    sb.Append(data[i + j].ToString("X2")).Append(' ');
                else
                    sb.Append("   ");
                if (j == 7)
                    sb.Append(' ');
            }

            sb.Append(' ');
            for (var j = 0; j < lineLen; j++)
            {
                var b = data[i + j];
                sb.Append(b is >= 32 and < 127 ? (char)b : '.');
            }

            sb.AppendLine();
        }

        return sb.ToString();
    }
}
