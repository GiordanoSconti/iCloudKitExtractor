using System.IO;
using System.Text;
using System.Xml.Linq;

namespace iCloudKitExtractor.Protocol;

public static class AppleXmlPlist
{
    public static Dictionary<string, object?> Parse(byte[] data)
    {
        var doc = XDocument.Parse(Encoding.UTF8.GetString(data));
        var root = doc.Root?.Element("dict") ?? throw new InvalidDataException("Plist senza dict radice.");
        return ParseDict(root);
    }

    public static byte[] BuildGsService2Request(string operation, Dictionary<string, object?> requestFields)
    {
        var request = new Dictionary<string, object?>(requestFields) { ["o"] = operation };
        var plist = new Dictionary<string, object?>
        {
            ["Header"] = new Dictionary<string, object?> { ["Version"] = "1.0.1" },
            ["Request"] = request
        };
        return Encoding.UTF8.GetBytes(BuildPlist(plist));
    }

    public static Dictionary<string, object?>? GetResponseDict(byte[] data)
    {
        var root = Parse(data);
        if (root.TryGetValue("Response", out var response) && response is Dictionary<string, object?> dict)
            return dict;
        return root;
    }

    /// <summary>
    /// Estrae <c>respBlob</c> da risposta escrow ( sempre <c>&lt;string&gt;</c> base64).
    /// </summary>
    public static byte[]? GetEscrowRespBlob(Dictionary<string, object?> parsed)
    {
        var data = GetData(parsed, "respBlob");
        if (data is { Length: > 0 })
            return data;
        var asString = GetString(parsed, "respBlob");
        if (string.IsNullOrWhiteSpace(asString))
            return null;
        return Convert.FromBase64String(CompactBase64(asString));
    }

    public static byte[]? GetData(Dictionary<string, object?> dict, string key) =>
        dict.TryGetValue(key, out var value) ? value as byte[] : null;

    public static string? GetString(Dictionary<string, object?> dict, string key) =>
        dict.TryGetValue(key, out var value) ? value as string : null;

    public static int? GetInt(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value) || value is null)
            return null;
        return value switch
        {
            int i => i,
            long l when l is >= int.MinValue and <= int.MaxValue => (int)l,
            string s when int.TryParse(s, out var n) => n,
            _ => null
        };
    }

    private static Dictionary<string, object?> ParseDict(XElement dict)
    {
        var result = new Dictionary<string, object?>(StringComparer.Ordinal);
        var elements = dict.Elements().ToList();
        for (var i = 0; i < elements.Count; i += 2)
        {
            var key = elements[i].Value;
            result[key] = ParseNode(elements[i + 1]);
        }
        return result;
    }

    private static object? ParseNode(XElement node) => node.Name.LocalName switch
    {
        "dict" => ParseDict(node),
        "array" => node.Elements().Select(ParseNode).ToList(),
        "string" => node.Value,
        "integer" => ParseInteger(node.Value),
        "true" => true,
        "false" => false,
        "data" => Convert.FromBase64String(CompactBase64(node.Value)),
        _ => node.Value
    };

    public static byte[] ToXmlBytes(Dictionary<string, object?> root) =>
        Encoding.UTF8.GetBytes(BuildPlist(root));

    /// <summary>
    /// Plist XML come escrowproxy (<c>srp_init</c>/<c>recover</c>):
    /// dichiarazione con spazio prima di <c>?&gt;</c>, indent 4 spazi, blob in <c>&lt;string&gt;</c> base64.
    /// </summary>
    public static byte[] ToEscrowProxyXmlBytes(Dictionary<string, object?> root) =>
        Encoding.UTF8.GetBytes(BuildEscrowProxyPlist(root));

    private static string BuildPlist(Dictionary<string, object?> root)
    {
        var sb = new StringBuilder();
        sb.Append("""<?xml version="1.0" encoding="UTF-8"?>""");
        sb.Append("""
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
""");
        WriteValue(sb, root, 0);
        sb.Append("</plist>");
        return sb.ToString();
    }

    private static string BuildEscrowProxyPlist(Dictionary<string, object?> root)
    {
        var sb = new StringBuilder();
        sb.Append("""<?xml version="1.0" encoding="UTF-8" ?>""");
        sb.Append('\n');
        sb.Append("""<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">""");
        sb.Append('\n');
        sb.Append("""<plist version="1.0">""");
        sb.Append('\n');
        WriteEscrowValue(sb, root, 4);
        sb.Append("</plist>\n");
        return sb.ToString();
    }

    private static void WriteEscrowValue(StringBuilder sb, object? value, int indent)
    {
        var pad = new string(' ', indent);
        switch (value)
        {
            case Dictionary<string, object?> dict:
                sb.Append(pad).Append("<dict>\n");
                foreach (var (key, entry) in dict)
                {
                    sb.Append(pad).Append("    <key>").Append(Escape(key)).Append("</key>\n");
                    WriteEscrowValue(sb, entry, indent + 4);
                }

                sb.Append(pad).Append("</dict>\n");
                break;
            case byte[] bytes:
                //  blob come <string> base64.
                sb.Append(pad).Append("<string>")
                    .Append(Convert.ToBase64String(bytes))
                    .Append("</string>\n");
                break;
            case int n:
                sb.Append(pad).Append("<integer>").Append(n).Append("</integer>\n");
                break;
            case long n:
                sb.Append(pad).Append("<integer>").Append(n).Append("</integer>\n");
                break;
            case string s:
                sb.Append(pad).Append("<string>").Append(Escape(s)).Append("</string>\n");
                break;
            case null:
                break;
            default:
                sb.Append(pad).Append("<string>").Append(Escape(value.ToString() ?? "")).Append("</string>\n");
                break;
        }
    }

    private static void WriteValue(StringBuilder sb, object? value, int indent)
    {
        var pad = new string(' ', indent);
        switch (value)
        {
            case Dictionary<string, object?> dict:
                sb.Append(pad).Append("<dict>\n");
                foreach (var (key, entry) in dict)
                {
                    sb.Append(pad).Append("  <key>").Append(Escape(key)).Append("</key>\n");
                    WriteValue(sb, entry, indent + 2);
                }
                sb.Append(pad).Append("</dict>\n");
                break;
            case IList<object?> list:
                sb.Append(pad).Append("<array>\n");
                foreach (var item in list)
                    WriteValue(sb, item, indent + 2);
                sb.Append(pad).Append("</array>\n");
                break;
            case byte[] bytes:
                sb.Append(pad).Append("<data>")
                    .Append(Convert.ToBase64String(bytes))
                    .Append("</data>\n");
                break;
            case ulong n:
                sb.Append(pad).Append("<integer>").Append(n).Append("</integer>\n");
                break;
            case long n:
                sb.Append(pad).Append("<integer>").Append(n).Append("</integer>\n");
                break;
            case int n:
                sb.Append(pad).Append("<integer>").Append(n).Append("</integer>\n");
                break;
            case bool b:
                sb.Append(pad).Append(b ? "<true/>\n" : "<false/>\n");
                break;
            case string s:
                sb.Append(pad).Append("<string>").Append(Escape(s)).Append("</string>\n");
                break;
            case null:
                break;
            default:
                sb.Append(pad).Append("<string>").Append(Escape(value.ToString() ?? "")).Append("</string>\n");
                break;
        }
    }

    private static string Escape(string value) =>
        value.Replace("&", "&amp;", StringComparison.Ordinal)
            .Replace("<", "&lt;", StringComparison.Ordinal)
            .Replace(">", "&gt;", StringComparison.Ordinal);

    private static string CompactBase64(string value) =>
        value.Replace("\n", "", StringComparison.Ordinal)
            .Replace("\r", "", StringComparison.Ordinal)
            .Replace(" ", "", StringComparison.Ordinal)
            .Replace("\t", "", StringComparison.Ordinal);

    /// <summary>dsid escrow spesso &gt; int.MaxValue → long.</summary>
    private static object? ParseInteger(string value)
    {
        if (!long.TryParse(value, out var n))
            return null;
        if (n is >= int.MinValue and <= int.MaxValue)
            return (int)n;
        return n;
    }
}
