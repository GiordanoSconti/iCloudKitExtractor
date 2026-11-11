using System.IO;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services;

namespace iCloudKitExtractor.Services.Http;

/// <summary>
/// Scrive una capture strutturata (jsonl + body + header) per confronto con live/mitm.
/// I token completi sono in secrets/ per ripristino sessione locale.
/// </summary>
public sealed class HttpSessionCapture
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
        "X-Apple-Session-Token",
        "X-Apple-Session-Key",
        "X-Apple-Encrypted-Session-Key",
        "X-CloudKit-AuthToken"
    };

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private static readonly JsonSerializerOptions JsonlOptions = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly object _lock = new();
    private readonly string? _logsRoot;
    private readonly List<HttpHarWriter.HarExchange> _harEntries = new();
    private int _seq;
    private bool _materialized;
    public string RunId { get; private set; }
    public string RunDirectory { get; private set; }
    public string SummaryLogPath { get; private set; }
    public string ExchangeJsonlPath { get; private set; }
    public string AuthEventsPath { get; private set; }
    public string BodiesDirectory { get; private set; }
    public string SecretsDirectory { get; private set; }
    public string HarPath { get; private set; } = "";
    public string HarRedactedPath { get; private set; } = "";
    public int HarEntryCount
    {
        get { lock (_lock) return _harEntries.Count; }
    }

    /// <summary>True se al momento è consentito scrivere su disco (flag UI/env).</summary>
    public bool IsPersistEnabled => IkeLogOptions.PersistRunLogs;

    private HttpSessionCapture(string? logsRoot)
    {
        _logsRoot = logsRoot;
        RunId = "(pending)";
        RunDirectory = "(disabled)";
        SummaryLogPath = "";
        ExchangeJsonlPath = "";
        AuthEventsPath = "";
        BodiesDirectory = "";
        SecretsDirectory = "";
    }

    public static HttpSessionCapture CreateNew(string? logsRoot = null) =>
        new(logsRoot);

    /// <summary>
    /// Crea <c>run_*</c> sotto AppData solo al primo write con persist ON.
    /// </summary>
    private bool TryMaterialize()
    {
        if (!IkeLogOptions.PersistRunLogs)
            return false;
        if (_materialized)
            return true;

        lock (_lock)
        {
            if (_materialized)
                return true;
            if (!IkeLogOptions.PersistRunLogs)
                return false;

            var root = _logsRoot ?? Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                "iCloudKitExtractor",
                "logs");
            Directory.CreateDirectory(root);

            var runId = DateTime.Now.ToString("yyyyMMdd_HHmmss");
            var runDirectory = Path.Combine(root, $"run_{runId}");
            Directory.CreateDirectory(runDirectory);

            RunId = runId;
            RunDirectory = runDirectory;
            SummaryLogPath = Path.Combine(runDirectory, "http_summary.log");
            ExchangeJsonlPath = Path.Combine(runDirectory, "http_exchange.jsonl");
            AuthEventsPath = Path.Combine(runDirectory, "auth_events.log");
            BodiesDirectory = Path.Combine(runDirectory, "http_bodies");
            SecretsDirectory = Path.Combine(runDirectory, "secrets");
            HarPath = Path.Combine(runDirectory, "session.har");
            HarRedactedPath = Path.Combine(runDirectory, "session_redacted.har");
            Directory.CreateDirectory(BodiesDirectory);
            Directory.CreateDirectory(SecretsDirectory);

            File.WriteAllText(Path.Combine(runDirectory, "manifest.json"), JsonSerializer.Serialize(new
            {
                runId,
                startedAt = DateTime.UtcNow,
                summaryLog = "http_summary.log",
                exchangeJsonl = "http_exchange.jsonl",
                authEvents = "auth_events.log",
                har = "session.har",
                harRedacted = "session_redacted.har",
                bodiesDir = "http_bodies/",
                secretsDir = "secrets/",
                note = "HAR 1.2: session.har (full) + session_redacted.har (header secrets). Bodies anche in http_bodies/."
            }, JsonOptions), Encoding.UTF8);

            _materialized = true;
            return true;
        }
    }

    public void LogAuthEvent(string message)
    {
        if (!TryMaterialize())
            return;
        var line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}";
        lock (_lock)
        {
            File.AppendAllText(AuthEventsPath, line + Environment.NewLine, Encoding.UTF8);
        }
    }

    public void LogSummary(string block)
    {
        if (!TryMaterialize())
            return;
        lock (_lock)
            File.AppendAllText(SummaryLogPath, block + Environment.NewLine, Encoding.UTF8);
    }

    public void SaveSessionSnapshot(ICloudSession session, string phase, string? note = null)
    {
        if (!TryMaterialize())
            return;
        var path = Path.Combine(SecretsDirectory, $"session_{phase}_{DateTime.Now:HHmmss}.json");
        var payload = new Dictionary<string, object?>
        {
            ["capturedAtUtc"] = DateTime.UtcNow,
            ["phase"] = phase,
            ["note"] = note,
            ["appleId"] = session.AppleId,
            ["dsid"] = session.Dsid,
            ["partition"] = session.Partition,
            ["cloudKitUserId"] = session.CloudKitUserId,
            ["cloudKitAuthToken"] = session.CloudKitAuthToken,
            ["mobileMeAuthToken"] = session.MobileMeAuthToken,
            ["peToken"] = session.PeToken,
            ["gsToken"] = session.GsToken,
            ["gsICloudAuthToken"] = session.GsICloudAuthToken,
            ["identityToken"] = session.IdentityToken,
            ["adsid"] = session.Adsid,
            ["gsIdmsToken"] = session.GsIdmsToken,
            ["appleCloudKitContext"] = session.AppleCloudKitContext,
            ["cloudKitGatewayUrl"] = session.CloudKitGatewayUrl,
            ["escrowProxyUrl"] = session.EscrowProxyUrl,
            ["anisette"] = new
            {
                session.Anisette.Md,
                session.Anisette.MdM,
                session.Anisette.MdRinfo,
                session.Anisette.ClientTimeUtc,
                session.Anisette.Locale,
                session.Anisette.SerialNumber,
                session.Anisette.ClientProductType
            }
        };

        var json = JsonSerializer.Serialize(payload, JsonOptions);
        lock (_lock)
        {
            File.WriteAllText(path, json, Encoding.UTF8);
            File.WriteAllText(Path.Combine(SecretsDirectory, "session_latest.json"), json, Encoding.UTF8);
        }
    }

    public void RecordExchange(
        string correlationId,
        HttpRequestMessage request,
        byte[]? requestBody,
        HttpResponseMessage response,
        byte[] responseBody,
        DateTime? startedUtc = null,
        double? elapsedMs = null)
    {
        if (!TryMaterialize())
            return;

        var status = (int)response.StatusCode;
        // Quiet: salta OK — tranne FullHarCapture (PoC: tutte le req/resp).
        if (!IkeLogOptions.FullHarCapture
            && IkeLogOptions.Quiet
            && status is >= 200 and < 400)
            return;

        var seq = Interlocked.Increment(ref _seq);
        var timestamp = startedUtc ?? DateTime.UtcNow;
        var timeMs = elapsedMs ?? 0;
        var uri = request.RequestUri ?? new Uri("http://localhost/");
        var host = uri.Host;
        var path = string.IsNullOrEmpty(uri.AbsolutePath) ? "/" : uri.AbsolutePath;

        var reqHeaders = FlattenHeaders(request.Headers, request.Content?.Headers);
        var respHeaders = FlattenHeaders(response.Headers, response.Content.Headers);

        var reqBodyInfo = WriteBodyFiles(seq, "request", host, path, requestBody, request.Content?.Headers);
        var respBodyInfo = WriteBodyFiles(seq, "response", host, path, responseBody, response.Content.Headers);

        WriteHeaderSidecars(seq, "request", host, path, reqHeaders);
        WriteHeaderSidecars(seq, "response", host, path, respHeaders);

        var entry = new
        {
            seq,
            correlationId,
            kind = "http_exchange",
            timestamp,
            request = new
            {
                method = request.Method.Method,
                url = uri.ToString(),
                host,
                path,
                headers = RedactHeaders(reqHeaders),
                headersFile = reqBodyInfo.headersFile,
                bodyFile = reqBodyInfo.bodyFile,
                bodyLen = requestBody?.Length,
                bodyFormat = reqBodyInfo.bodyFormat
            },
            response = new
            {
                status,
                statusText = response.ReasonPhrase,
                headers = RedactHeaders(respHeaders),
                headersFile = respBodyInfo.headersFile,
                bodyFile = respBodyInfo.bodyFile,
                bodyLen = responseBody.Length,
                bodyFormat = respBodyInfo.bodyFormat
            }
        };

        var harEx = new HttpHarWriter.HarExchange
        {
            StartedUtc = timestamp,
            TimeMs = timeMs,
            Method = request.Method.Method,
            Url = uri.ToString(),
            RequestHeaders = CloneHeaders(reqHeaders),
            RequestBody = requestBody is { Length: > 0 } ? requestBody : null,
            RequestMime = request.Content?.Headers.ContentType?.MediaType,
            Status = status,
            StatusText = response.ReasonPhrase,
            ResponseHeaders = CloneHeaders(respHeaders),
            ResponseBody = responseBody.Length > 0 ? responseBody : null,
            ResponseMime = response.Content.Headers.ContentType?.MediaType,
            BodyFileRequest = reqBodyInfo.bodyFile,
            BodyFileResponse = respBodyInfo.bodyFile,
            CorrelationId = correlationId,
            Seq = seq
        };

        var summary = $"""
            ---------- [{correlationId}] seq={seq} REQUEST ----------
            {request.Method} {uri}
            {FormatHeadersForLog(RedactHeaders(reqHeaders))}
            Body: {FormatBodyPreview(requestBody)}
            ---------- [{correlationId}] seq={seq} RESPONSE {status} ----------
            {request.Method} {uri}
            {FormatHeadersForLog(RedactHeaders(respHeaders))}
            Body: {FormatBodyPreview(responseBody)}
            """;

        var flushHar = false;
        lock (_lock)
        {
            File.AppendAllText(ExchangeJsonlPath, JsonSerializer.Serialize(entry, JsonlOptions) + Environment.NewLine, Encoding.UTF8);
            File.AppendAllText(SummaryLogPath, summary + Environment.NewLine, Encoding.UTF8);
            if (IkeLogOptions.FullHarCapture || IkeLogOptions.PersistRunLogs)
            {
                _harEntries.Add(harEx);
                // Flush ogni 10 entry o subito se FullHar (PoC).
                flushHar = IkeLogOptions.FullHarCapture
                           || _harEntries.Count % 10 == 0;
            }
        }

        if (flushHar)
            FlushHarFiles();
    }

    /// <summary>Scrive/aggiorna <c>session.har</c> e <c>session_redacted.har</c>.</summary>
    public void FlushHarFiles()
    {
        if (!_materialized || string.IsNullOrEmpty(HarPath))
            return;

        List<HttpHarWriter.HarExchange> snapshot;
        lock (_lock)
            snapshot = _harEntries.ToList();

        if (snapshot.Count == 0)
            return;

        try
        {
            var full = HttpHarWriter.BuildHarJson(snapshot, redactSensitiveHeaders: false);
            var redacted = HttpHarWriter.BuildHarJson(snapshot, redactSensitiveHeaders: true);
            lock (_lock)
            {
                File.WriteAllText(HarPath, full, Encoding.UTF8);
                File.WriteAllText(HarRedactedPath, redacted, Encoding.UTF8);
            }
        }
        catch
        {
            // non bloccare il traffico HTTP se HAR fallisce
        }
    }

    /// <summary>Esporta header redatti (usato da <see cref="HttpHarWriter"/>).</summary>
    public static Dictionary<string, List<string>> RedactHeadersPublic(
        Dictionary<string, List<string>> headers) =>
        RedactHeaders(headers);

    private static Dictionary<string, List<string>> CloneHeaders(
        Dictionary<string, List<string>> src)
    {
        var d = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (k, v) in src)
            d[k] = new List<string>(v);
        return d;
    }

    private (string? bodyFile, string? headersFile, string? bodyFormat) WriteBodyFiles(
        int seq,
        string direction,
        string host,
        string path,
        byte[]? body,
        HttpContentHeaders? contentHeaders)
    {
        var stem = BuildStem(seq, direction, host, path);
        var headersFile = $"{stem}_headers.json";
        string? bodyFile = null;
        string? bodyFormat = null;

        if (body is { Length: > 0 })
        {
            bodyFormat = DetectBodyFormat(body, contentHeaders);
            var ext = bodyFormat switch
            {
                "json" => "json",
                "xml" => "xml",
                "plist" => "xml",
                "protobuf" => "pb",
                _ => "bin"
            };
            bodyFile = Path.Combine("http_bodies", $"{stem}_body.{ext}");
            var fullPath = Path.Combine(RunDirectory, bodyFile);
            File.WriteAllBytes(fullPath, body);
        }
        else
        {
            bodyFormat = "empty";
        }

        return (bodyFile, Path.Combine("http_bodies", $"{stem}_headers.json"), bodyFormat);
    }

    private void WriteHeaderSidecars(int seq, string direction, string host, string path, Dictionary<string, List<string>> headers)
    {
        var stem = BuildStem(seq, direction, host, path);
        var fullPath = Path.Combine(BodiesDirectory, $"{stem}_headers.json");
        var redactedPath = Path.Combine(BodiesDirectory, $"{stem}_headers_redacted.json");
        var allPath = Path.Combine(BodiesDirectory, $"{stem}_headers_all.json");

        var headersAll = headers.SelectMany(kv => kv.Value.Select(v => new[] { kv.Key, v })).ToList();
        File.WriteAllText(fullPath, JsonSerializer.Serialize(headers, JsonOptions), Encoding.UTF8);
        File.WriteAllText(redactedPath, JsonSerializer.Serialize(RedactHeaders(headers), JsonOptions), Encoding.UTF8);
        File.WriteAllText(allPath, JsonSerializer.Serialize(headersAll, JsonOptions), Encoding.UTF8);
    }

    private static string BuildStem(int seq, string direction, string host, string path)
    {
        var safePath = path.Trim('/').Replace('/', '_').Replace('?', '_').Replace('=', '_').Replace('%', '_');
        if (safePath.Length > 80)
            safePath = safePath[..80];
        if (string.IsNullOrEmpty(safePath))
            safePath = "root";
        return $"{seq:D5}_{direction}_{SanitizeFileName(host)}_{safePath}";
    }

    private static string SanitizeFileName(string name) =>
        string.Concat(name.Select(c => Path.GetInvalidFileNameChars().Contains(c) ? '_' : c));

    private static Dictionary<string, List<string>> FlattenHeaders(
        HttpHeaders? primary,
        HttpHeaders? secondary)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        if (primary is not null)
            MergeHeaders(result, primary);
        if (secondary is not null)
            MergeHeaders(result, secondary);
        return result;
    }

    private static void MergeHeaders(Dictionary<string, List<string>> target, HttpHeaders headers)
    {
        foreach (var header in headers)
        {
            if (!target.TryGetValue(header.Key, out var list))
            {
                list = new List<string>();
                target[header.Key] = list;
            }
            list.AddRange(header.Value);
        }
    }

    private static Dictionary<string, List<string>> RedactHeaders(Dictionary<string, List<string>> headers)
    {
        var result = new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        foreach (var (name, values) in headers)
        {
            result[name] = SensitiveHeaders.Contains(name)
                ? values.Select(_ => "[redacted]").ToList()
                : new List<string>(values);
        }
        return result;
    }

    private static string? DetectBodyFormat(byte[] body, HttpContentHeaders? headers)
    {
        var contentType = headers?.ContentType?.MediaType ?? "";
        if (contentType.Contains("octet-stream", StringComparison.OrdinalIgnoreCase))
            return "bin";
        if (contentType.Contains("json", StringComparison.OrdinalIgnoreCase))
            return "json";
        if (contentType.Contains("xml", StringComparison.OrdinalIgnoreCase)
            || contentType.Contains("plist", StringComparison.OrdinalIgnoreCase))
            return "xml";
        if (contentType.Contains("protobuf", StringComparison.OrdinalIgnoreCase)
            || contentType.Contains("ubchunk", StringComparison.OrdinalIgnoreCase))
            return "protobuf";

        var text = Encoding.UTF8.GetString(body).TrimStart();
        if (text.StartsWith('{') || text.StartsWith('['))
            return "json";
        if (text.StartsWith("<?xml", StringComparison.Ordinal) || text.StartsWith("<plist", StringComparison.Ordinal))
            return "xml";
        if (text.Length > 0 && text.All(c => !char.IsControl(c) || c is '\t' or '\n' or '\r'))
            return "text";
        return "bin";
    }

    private static string FormatHeadersForLog(Dictionary<string, List<string>> headers)
    {
        var sb = new StringBuilder();
        foreach (var (name, values) in headers)
        {
            foreach (var value in values)
                sb.AppendLine($"{name}: {value}");
        }
        return sb.ToString().TrimEnd();
    }

    private static string FormatBodyPreview(byte[]? body)
    {
        if (body is null || body.Length == 0)
            return "(empty)";
        const int max = 16_384;
        var preview = body.Length <= max ? body : body.AsSpan(0, max).ToArray();
        try
        {
            var text = Encoding.UTF8.GetString(preview);
            if (text.All(c => !char.IsControl(c) || c is '\t' or '\n' or '\r'))
                return text + (body.Length > preview.Length ? "\n…(truncated in summary)" : "");
        }
        catch
        {
            // binary
        }
        return $"[binary {body.Length} bytes] {Convert.ToHexString(preview.AsSpan(0, Math.Min(64, preview.Length)))}"
               + (body.Length > preview.Length ? " …" : "");
    }
}
