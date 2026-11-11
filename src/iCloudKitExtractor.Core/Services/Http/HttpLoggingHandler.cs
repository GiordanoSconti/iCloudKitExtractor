using System.Diagnostics;
using iCloudKitExtractor.Services;

namespace iCloudKitExtractor.Services.Http;

public sealed class HttpLoggingHandler : DelegatingHandler
{
    private readonly HttpSessionCapture? _capture;
    private readonly HttpTrafficLogger? _legacyLogger;

    public HttpLoggingHandler(HttpSessionCapture capture, HttpMessageHandler innerHandler)
        : base(innerHandler) => _capture = capture;

    public HttpLoggingHandler(HttpTrafficLogger legacyLogger, HttpMessageHandler innerHandler)
        : base(innerHandler) => _legacyLogger = legacyLogger;

    public HttpLoggingHandler(HttpSessionCapture capture, HttpTrafficLogger legacyLogger, HttpMessageHandler innerHandler)
        : base(innerHandler)
    {
        _capture = capture;
        _legacyLogger = legacyLogger;
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var persistCapture = _capture is not null
                             && (IkeLogOptions.PersistRunLogs || IkeLogOptions.FullHarCapture);
        var useLegacy = _legacyLogger is not null;
        // Senza persist: evita buffer completo request/response solo per la capture su disco.
        if (!persistCapture && !useLegacy)
            return await base.SendAsync(request, cancellationToken).ConfigureAwait(false);

        var id = Guid.NewGuid().ToString("N")[..8];
        var requestBody = request.Content is null
            ? null
            : await request.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);

        if (request.Content is not null && requestBody is not null)
            request.Content = CloneContent(requestBody, request.Content.Headers);

        var sw = Stopwatch.StartNew();
        var startedUtc = DateTime.UtcNow;
        var response = await base.SendAsync(request, cancellationToken).ConfigureAwait(false);
        sw.Stop();
        var responseBody = await response.Content.ReadAsByteArrayAsync(cancellationToken).ConfigureAwait(false);
        response.Content = CloneContent(responseBody, response.Content.Headers);

        // EN record/retrieve post-Lock: body multi-MB — non scrivere su disco sul thread caller (UI).
        var capture = persistCapture ? _capture : null;
        var legacy = _legacyLogger;
        var exchangeId = id;
        var reqBody = requestBody;
        var respBody = responseBody;
        var elapsedMs = sw.Elapsed.TotalMilliseconds;
        await Task.Run(() =>
        {
            if (capture is not null)
            {
                capture.RecordExchange(
                    exchangeId, request, reqBody, response, respBody,
                    startedUtc, elapsedMs);
            }

            if (legacy is not null)
            {
                legacy.LogBlock($"""
                    ---------- [{exchangeId}] REQUEST ----------
                    {request.Method} {request.RequestUri}
                    {HttpTrafficLogger.FormatHeaders(request.Headers.Concat(request.Content?.Headers ?? Enumerable.Empty<KeyValuePair<string, IEnumerable<string>>>()))}
                    Body: {HttpTrafficLogger.FormatBodyPreview(reqBody)}
                    ---------- [{exchangeId}] RESPONSE {(int)response.StatusCode} ----------
                    {request.Method} {request.RequestUri}
                    {HttpTrafficLogger.FormatHeaders(response.Headers.Concat(response.Content.Headers))}
                    Body: {HttpTrafficLogger.FormatBodyPreview(respBody)}
                    """);
            }
        }, cancellationToken).ConfigureAwait(false);

        return response;
    }

    private static ByteArrayContent CloneContent(byte[] body, System.Net.Http.Headers.HttpContentHeaders headers)
    {
        var content = new ByteArrayContent(body);
        foreach (var header in headers)
            content.Headers.TryAddWithoutValidation(header.Key, header.Value);
        return content;
    }
}
