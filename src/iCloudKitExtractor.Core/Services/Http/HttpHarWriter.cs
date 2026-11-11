using System.Collections.Generic;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace iCloudKitExtractor.Services.Http;

/// <summary>
/// HAR 1.2 writer (Chrome/Firefox compatible) for PoC wire evidence.
/// </summary>
public static class HttpHarWriter
{
    /// <summary>Body oltre questo limite: truncated + riferimento file locale.</summary>
    public const int MaxInlineBodyBytes = 8 * 1024 * 1024;

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public sealed class HarExchange
    {
        public DateTime StartedUtc { get; init; }
        public double TimeMs { get; init; }
        public string Method { get; init; } = "GET";
        public string Url { get; init; } = "";
        public Dictionary<string, List<string>> RequestHeaders { get; init; } = new();
        public byte[]? RequestBody { get; init; }
        public string? RequestMime { get; init; }
        public int Status { get; init; }
        public string? StatusText { get; init; }
        public Dictionary<string, List<string>> ResponseHeaders { get; init; } = new();
        public byte[]? ResponseBody { get; init; }
        public string? ResponseMime { get; init; }
        public string? BodyFileRequest { get; init; }
        public string? BodyFileResponse { get; init; }
        public string? CorrelationId { get; init; }
        public int Seq { get; init; }
    }

    public static string BuildHarJson(IReadOnlyList<HarExchange> exchanges, bool redactSensitiveHeaders)
    {
        var entries = new List<object>(exchanges.Count);
        foreach (var ex in exchanges)
        {
            var reqHeaders = redactSensitiveHeaders
                ? HttpSessionCapture.RedactHeadersPublic(ex.RequestHeaders)
                : ex.RequestHeaders;
            var respHeaders = redactSensitiveHeaders
                ? HttpSessionCapture.RedactHeadersPublic(ex.ResponseHeaders)
                : ex.ResponseHeaders;

            entries.Add(new Dictionary<string, object?>
            {
                ["startedDateTime"] = ex.StartedUtc.ToString("o"),
                ["time"] = ex.TimeMs,
                ["request"] = BuildRequest(ex, reqHeaders),
                ["response"] = BuildResponse(ex, respHeaders),
                ["cache"] = new { },
                ["timings"] = new Dictionary<string, object>
                {
                    ["blocked"] = -1,
                    ["dns"] = -1,
                    ["connect"] = -1,
                    ["ssl"] = -1,
                    ["send"] = 0,
                    ["wait"] = Math.Max(0, ex.TimeMs),
                    ["receive"] = 0
                },
                ["_seq"] = ex.Seq,
                ["_correlationId"] = ex.CorrelationId
            });
        }

        var doc = new Dictionary<string, object>
        {
            ["log"] = new Dictionary<string, object>
            {
                ["version"] = "1.2",
                ["creator"] = new Dictionary<string, string>
                {
                    ["name"] = "iCloudKitExtractor",
                    ["version"] = "poc-har"
                },
                ["pages"] = Array.Empty<object>(),
                ["entries"] = entries
            }
        };

        return JsonSerializer.Serialize(doc, JsonOptions);
    }

    private static Dictionary<string, object?> BuildRequest(
        HarExchange ex, Dictionary<string, List<string>> headers)
    {
        var mime = ex.RequestMime
                   ?? GuessMime(headers)
                   ?? "application/octet-stream";
        var (text, encoding, truncated, size) = EncodeBody(ex.RequestBody);
        var req = new Dictionary<string, object?>
        {
            ["method"] = ex.Method,
            ["url"] = ex.Url,
            ["httpVersion"] = "HTTP/1.1",
            ["cookies"] = Array.Empty<object>(),
            ["headers"] = ToHarHeaders(headers),
            ["queryString"] = ParseQuery(ex.Url),
            ["headersSize"] = -1,
            ["bodySize"] = size
        };
        if (size > 0 || truncated)
        {
            var post = new Dictionary<string, object?>
            {
                ["mimeType"] = mime,
                ["text"] = text,
                ["encoding"] = encoding
            };
            if (truncated)
            {
                post["_truncated"] = true;
                post["_bodyFile"] = ex.BodyFileRequest;
                post["_originalSize"] = ex.RequestBody?.Length ?? 0;
            }
            req["postData"] = post;
        }

        return req;
    }

    private static Dictionary<string, object?> BuildResponse(
        HarExchange ex, Dictionary<string, List<string>> headers)
    {
        var mime = ex.ResponseMime
                   ?? GuessMime(headers)
                   ?? "application/octet-stream";
        var (text, encoding, truncated, size) = EncodeBody(ex.ResponseBody);
        var content = new Dictionary<string, object?>
        {
            ["size"] = size,
            ["mimeType"] = mime,
            ["text"] = text,
            ["encoding"] = encoding
        };
        if (truncated)
        {
            content["_truncated"] = true;
            content["_bodyFile"] = ex.BodyFileResponse;
            content["_originalSize"] = ex.ResponseBody?.Length ?? 0;
        }

        return new Dictionary<string, object?>
        {
            ["status"] = ex.Status,
            ["statusText"] = ex.StatusText ?? "",
            ["httpVersion"] = "HTTP/1.1",
            ["cookies"] = Array.Empty<object>(),
            ["headers"] = ToHarHeaders(headers),
            ["content"] = content,
            ["redirectURL"] = "",
            ["headersSize"] = -1,
            ["bodySize"] = size
        };
    }

    private static (string? text, string? encoding, bool truncated, int size) EncodeBody(byte[]? body)
    {
        if (body is null || body.Length == 0)
            return ("", null, false, 0);

        var truncated = body.Length > MaxInlineBodyBytes;
        var slice = truncated ? body.AsSpan(0, MaxInlineBodyBytes).ToArray() : body;

        // Prefer UTF-8 text when printable; else base64 (HAR standard).
        if (TryUtf8(slice, out var utf8))
            return (utf8, truncated ? "utf8+truncated" : null, truncated, body.Length);

        return (Convert.ToBase64String(slice), "base64", truncated, body.Length);
    }

    private static bool TryUtf8(byte[] data, out string text)
    {
        text = "";
        try
        {
            text = Encoding.UTF8.GetString(data);
        }
        catch
        {
            return false;
        }

        var sample = text.Length > 4096 ? text.AsSpan(0, 4096) : text.AsSpan();
        foreach (var c in sample)
        {
            if (char.IsControl(c) && c is not '\t' and not '\n' and not '\r')
                return false;
        }

        return true;
    }

    private static List<object> ToHarHeaders(Dictionary<string, List<string>> headers)
    {
        var list = new List<object>();
        foreach (var (name, values) in headers)
        {
            foreach (var v in values)
                list.Add(new Dictionary<string, string> { ["name"] = name, ["value"] = v });
        }

        return list;
    }

    private static List<object> ParseQuery(string url)
    {
        var list = new List<object>();
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return list;
        var q = uri.Query;
        if (string.IsNullOrEmpty(q) || q.Length < 2)
            return list;
        foreach (var part in q.TrimStart('?').Split('&', StringSplitOptions.RemoveEmptyEntries))
        {
            var i = part.IndexOf('=');
            var name = i < 0 ? part : part[..i];
            var value = i < 0 ? "" : part[(i + 1)..];
            list.Add(new Dictionary<string, string>
            {
                ["name"] = Uri.UnescapeDataString(name),
                ["value"] = Uri.UnescapeDataString(value)
            });
        }

        return list;
    }

    private static string? GuessMime(Dictionary<string, List<string>> headers)
    {
        if (headers.TryGetValue("Content-Type", out var values) && values.Count > 0)
        {
            var v = values[0];
            var semi = v.IndexOf(';');
            return semi > 0 ? v[..semi].Trim() : v.Trim();
        }

        return null;
    }
}
