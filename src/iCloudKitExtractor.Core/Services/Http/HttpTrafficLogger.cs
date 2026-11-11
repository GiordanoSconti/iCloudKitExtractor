using System.IO;
using System.Text;

namespace iCloudKitExtractor.Services.Http;

public sealed class HttpTrafficLogger
{
    private static readonly HashSet<string> SensitiveHeaders = new(StringComparer.OrdinalIgnoreCase)
    {
        "Authorization",
        "Cookie",
        "Set-Cookie",
        "security-code",
        "X-Apple-Identity-Token",
        "X-Apple-GS-Token",
        "X-Apple-PE-Token",
        "X-Apple-HB-Token",
        "X-Apple-Session-Key",
        "X-CloudKit-AuthToken"
    };

    private readonly object _lock = new();
    private readonly string? _filePath;
    private readonly Action<string>? _lineCallback;
    private readonly int _maxBodyBytes;

    public HttpTrafficLogger(string? filePath, Action<string>? lineCallback = null, int maxBodyBytes = 16_384)
    {
        _filePath = filePath;
        _lineCallback = lineCallback;
        _maxBodyBytes = maxBodyBytes;
        if (!string.IsNullOrEmpty(filePath))
        {
            var dir = Path.GetDirectoryName(filePath);
            if (!string.IsNullOrEmpty(dir))
                Directory.CreateDirectory(dir);
        }
    }

    public void LogBlock(string block)
    {
        lock (_lock)
        {
            _lineCallback?.Invoke(TruncateForUi(block));
            if (string.IsNullOrEmpty(_filePath))
                return;
            File.AppendAllText(_filePath, block + Environment.NewLine, Encoding.UTF8);
        }
    }

    public static string FormatHeaders(IEnumerable<KeyValuePair<string, IEnumerable<string>>> headers)
    {
        var sb = new StringBuilder();
        foreach (var (name, values) in headers)
        {
            foreach (var value in values)
                sb.AppendLine(FormatHeaderLine(name, value));
        }
        return sb.ToString().TrimEnd();
    }

    public static string FormatBodyPreview(byte[]? body)
    {
        if (body is null || body.Length == 0)
            return "(empty)";
        var preview = body.Length <= 16_384 ? body : body.AsSpan(0, 16_384).ToArray();
        if (LooksLikeText(preview))
            return Encoding.UTF8.GetString(preview) + (body.Length > preview.Length ? "\n…(truncated)" : "");
        return $"[binary {body.Length} bytes] {Convert.ToHexString(preview.AsSpan(0, Math.Min(64, preview.Length)))}"
               + (body.Length > preview.Length ? " …" : "");
    }

    private static string FormatHeaderLine(string name, string value) =>
        SensitiveHeaders.Contains(name) ? $"{name}: [redacted]" : $"{name}: {value}";

    private static bool LooksLikeText(ReadOnlySpan<byte> data)
    {
        if (data.IsEmpty)
            return true;
        var printable = 0;
        foreach (var b in data)
        {
            if (b is 9 or 10 or 13 or >= 32 and < 127)
                printable++;
        }
        return printable * 100 / data.Length >= 85;
    }

    private static string TruncateForUi(string block)
    {
        const int max = 240;
        var oneLine = block.Replace('\r', ' ').Replace('\n', ' ');
        return oneLine.Length <= max ? oneLine : oneLine[..max] + "…";
    }
}
