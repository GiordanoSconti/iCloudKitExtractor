using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Services.Forensics;

/// <summary>
/// Append-only high-level operation journal under <c>{case}/ops/operations.jsonl</c>.
/// Details are scrubbed of tokens / secrets before write.
/// </summary>
public static class IkeCaseOpsJournal
{
    public const string FileName = "operations.jsonl";

    private static readonly object Gate = new();
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    private static readonly Regex Sensitive = new(
        @"(?i)(authorization|bearer|cookie|set-cookie|password|passwd|pet|gs[-_]?token|" +
        @"session[-_]?token|hb[-_]?token|identity[-_]?token|x-apple-[a-z0-9-]*token|" +
        @"x-cloudkit-authtoken|recovery[-_]?key|passcode|secret|private[-_]?key|" +
        @"-----BEGIN[^-]+-----)[^\s,;""']*",
        RegexOptions.Compiled);

    private static readonly Regex LongHex = new(
        @"\b[0-9a-fA-F]{48,}\b",
        RegexOptions.Compiled);

    public static void Append(
        IkeCaseSession? session,
        string area,
        string action,
        string? detail = null,
        string status = "ok")
    {
        if (session is null)
            return;

        try
        {
            Directory.CreateDirectory(session.OpsRoot);
            var entry = new IkeCaseOperationEntry
            {
                Utc = DateTimeOffset.UtcNow,
                Area = SanitizeShort(area),
                Action = SanitizeShort(action),
                Detail = Scrub(detail),
                Status = SanitizeShort(status),
            };
            var line = JsonSerializer.Serialize(entry, JsonOptions) + "\n";
            lock (Gate)
                File.AppendAllText(session.OperationsJsonlPath, line, Encoding.UTF8);
        }
        catch
        {
            // journal must never break acquisition
        }
    }

    public static IReadOnlyList<IkeCaseOperationEntry> ReadAll(IkeCaseSession session)
    {
        var path = session.OperationsJsonlPath;
        if (!File.Exists(path))
            return Array.Empty<IkeCaseOperationEntry>();

        var list = new List<IkeCaseOperationEntry>();
        foreach (var line in File.ReadLines(path))
        {
            if (string.IsNullOrWhiteSpace(line))
                continue;
            try
            {
                var entry = JsonSerializer.Deserialize<IkeCaseOperationEntry>(line, JsonOptions);
                if (entry is not null)
                    list.Add(entry);
            }
            catch
            {
                // skip corrupt lines
            }
        }

        return list;
    }

    public static string Scrub(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "";
        var s = Sensitive.Replace(text, "[redacted]");
        s = LongHex.Replace(s, "[redacted-hex]");
        if (s.Length > 400)
            s = s[..397] + "...";
        return s.Trim();
    }

    private static string SanitizeShort(string? value)
    {
        var s = Scrub(value);
        if (s.Length > 80)
            s = s[..77] + "...";
        return string.IsNullOrWhiteSpace(s) ? "—" : s;
    }
}

public sealed class IkeCaseOperationEntry
{
    public DateTimeOffset Utc { get; set; }
    public string Area { get; set; } = "";
    public string Action { get; set; } = "";
    public string? Detail { get; set; }
    public string Status { get; set; } = "ok";
}
