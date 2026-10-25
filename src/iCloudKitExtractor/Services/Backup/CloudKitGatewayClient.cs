using System.IO;
using System.IO.Compression;
using System.Net.Http.Headers;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Backup;

public sealed class CloudKitGatewayClient
{
    private static readonly int[] RetryDelaysMs = [600, 1500, 3500, 6000];
    private static readonly int[] UnauthorizedRefreshDelaysMs = [1500, 3000, 5000];
    private const int MaxConsecutiveUnauthorized = 6;
    private const int MaxUnauthorizedRefreshPerCall = 3;

    public delegate Task UnauthorizedRefreshDelegate(ICloudSession session, CancellationToken ct);

    private readonly HttpClient _http;
    private int _consecutiveUnauthorized;
    private UnauthorizedRefreshDelegate? _onUnauthorized;

    public CloudKitGatewayClient(HttpClient http) => _http = http;

    /// <summary>
    /// Dopo refresh Anisette/token: azzera il circuit breaker 401 così KA/LA/MA possono riprendere.
    /// </summary>
    public void ClearUnauthorized() => _consecutiveUnauthorized = 0;

    public int ConsecutiveUnauthorized => _consecutiveUnauthorized;

    /// <summary>
    /// Su HTTP 401 (flood / Anisette stantia): refresh e ritenta lo stesso POST.
    /// </summary>
    public void SetUnauthorizedRefresh(UnauthorizedRefreshDelegate? refresh) =>
        _onUnauthorized = refresh;

    public Task<byte[]> RecordRetrieveAsync(
        ICloudSession session,
        byte[] body,
        CancellationToken ct,
        RestoreSessionState? restore = null,
        CloudKitContainerBinding? container = null) =>
        PostAsync(session, "https://gateway.icloud.com/ckdatabase/api/client/record/retrieve",
            "CKDFetchRecordsOperation-Private", body, ct, restoreState: restore, container: container);

    public Task<byte[]> RecordRetrieveWscPreAuthAsync(
        ICloudSession session,
        byte[] body,
        CancellationToken ct,
        RestoreSessionState? restore = null) =>
        PostAsync(session, "https://gateway.icloud.com/ckdatabase/api/client/record/retrieve",
            "CKDFetchRecordsOperation-Private-WscPreAuth", body, ct,
            decompressGzip: true, restoreState: restore, retryTransient: false);

    public Task<byte[]> RecordSaveAsync(
        ICloudSession session,
        byte[] body,
        CancellationToken ct,
        RestoreSessionState? restore = null) =>
        PostAsync(session, "https://gateway.icloud.com/ckdatabase/api/client/record/save",
            "CKDModifyRecordsOperation-Private", body, ct, restoreState: restore);

    public Task<byte[]> QueryRetrieveAsync(
        ICloudSession session,
        byte[] body,
        CancellationToken ct,
        RestoreSessionState? restore = null,
        CloudKitContainerBinding? container = null) =>
        PostAsync(session, "https://gateway.icloud.com/ckdatabase/api/client/query/retrieve",
            "CKDQueryOperation-Private", body, ct, restoreState: restore, container: container);

    public Task<byte[]> ZoneChangesAsync(
        ICloudSession session,
        byte[] body,
        CancellationToken ct,
        CloudKitContainerBinding? container = null) =>
        PostAsync(session, "https://gateway.icloud.com/ckdatabase/api/client/zone/sync",
            "CKDFetchDatabaseChangesOperation", body, ct, container: container);

    /// <summary>
    /// recovery backup: <c>CKDFetchRecordZonesOperation</c> su <c>POST /record/retrieve</c>
    /// (non <c>/zone/retrieve</c>). Qui arrivano i ProtectionInfo di zona mbksync + master PCS.
    /// </summary>
    public Task<byte[]> RecordRetrieveZonesAsync(
        ICloudSession session,
        byte[] body,
        CancellationToken ct,
        RestoreSessionState? restore = null,
        CloudKitContainerBinding? container = null) =>
        PostAsync(session, "https://gateway.icloud.com/ckdatabase/api/client/record/retrieve",
            "CKDFetchRecordZonesOperation", body, ct, restoreState: restore, container: container);

    /// <summary>
    /// <c>POST /zone/retrieve</c> — stesso body field 201; usato da CloudDocs / fallback.
    /// </summary>
    public Task<byte[]> ZoneRetrieveAsync(
        ICloudSession session,
        byte[] body,
        CancellationToken ct,
        RestoreSessionState? restore = null,
        CloudKitContainerBinding? container = null) =>
        PostAsync(session, "https://gateway.icloud.com/ckdatabase/api/client/zone/retrieve",
            "CKDFetchRecordZonesOperation", body, ct, restoreState: restore, container: container);

    public Task<byte[]> RecordChangesAsync(
        ICloudSession session,
        byte[] body,
        CancellationToken ct,
        CloudKitContainerBinding? container = null) =>
        PostAsync(session, "https://gateway.icloud.com/ckdatabase/api/client/record/sync",
            "CKDFetchRecordZoneChangesOperation", body, ct, container: container);

    /// <summary>PreAuth ubchunk su query/retrieve (risposta gzip, header X-CloudKit-PreAuth-Get).</summary>
    public Task<byte[]> QueryRetrieveWscPreAuthAsync(
        ICloudSession session,
        byte[] body,
        CancellationToken ct,
        RestoreSessionState? restore = null) =>
        PostAsync(session, "https://gateway.icloud.com/ckdatabase/api/client/query/retrieve",
            "CKDQueryOperation-Private-WscPreAuth", body, ct,
            decompressGzip: true, restoreState: restore, retryTransient: false);

    private async Task<byte[]> PostAsync(
        ICloudSession session,
        string url,
        string operationKey,
        byte[] body,
        CancellationToken ct,
        bool decompressGzip = false,
        RestoreSessionState? restoreState = null,
        bool retryTransient = true,
        CloudKitContainerBinding? container = null)
    {
        Exception? lastError = null;
        var transientAttempt = 0;
        var unauthRefresh = 0;

        while (true)
        {
            if (_onUnauthorized is null && _consecutiveUnauthorized >= MaxConsecutiveUnauthorized)
            {
                throw new InvalidOperationException(
                    $"CloudKit bloccato: {_consecutiveUnauthorized} HTTP 401 consecutivi " +
                    "(sessione/token o flood record/retrieve). Rilancia il restore dopo re-login.");
            }

            using var request = BuildRequest(session, url, body, restoreState, container);
            using var response = await _http.SendAsync(
                    request, HttpCompletionOption.ResponseContentRead, ct)
                .ConfigureAwait(false);

            if (response.IsSuccessStatusCode)
            {
                _consecutiveUnauthorized = 0;
                var payload = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
                if (!decompressGzip)
                    return payload;

                var headers = response.Headers
                    .Concat(response.Content.Headers)
                    .ToDictionary(h => h.Key, h => h.Value, StringComparer.OrdinalIgnoreCase);
                return UbChunkWscBuilder.DecompressIfGzip(payload, headers);
            }

            var status = (int)response.StatusCode;
            if (status == 401)
            {
                _consecutiveUnauthorized++;
                var err401 = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
                lastError = new InvalidOperationException(
                    $"CloudKit {operationKey} HTTP 401 (consecutivi={_consecutiveUnauthorized})"
                    + (string.IsNullOrWhiteSpace(err401) ? "" : $" body={err401.Trim()}"));

                if (_onUnauthorized is not null && unauthRefresh < MaxUnauthorizedRefreshPerCall)
                {
                    try
                    {
                        await _onUnauthorized(session, ct).ConfigureAwait(false);
                        _consecutiveUnauthorized = 0;
                        unauthRefresh++;
                        var delayIdx = Math.Min(unauthRefresh - 1, UnauthorizedRefreshDelaysMs.Length - 1);
                        await Task.Delay(UnauthorizedRefreshDelaysMs[delayIdx], ct).ConfigureAwait(false);
                        continue;
                    }
                    catch (Exception refreshEx)
                    {
                        throw new InvalidOperationException(
                            $"CloudKit {operationKey} HTTP 401 e refresh Anisette fallito: {refreshEx.Message}",
                            lastError);
                    }
                }

                throw lastError;
            }

            _consecutiveUnauthorized = 0;
            var errBody = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
            var debug = response.Headers.TryGetValues("X-Apple-Request-Debug", out var dbg)
                ? string.Join(",", dbg) : string.Empty;
            var resp = response.Headers.TryGetValues("X-Responding-Instance", out var ri)
                ? string.Join(",", ri) : string.Empty;
            lastError = new InvalidOperationException(
                $"CloudKit {operationKey} HTTP {status} url={url}"
                + (string.IsNullOrEmpty(resp) ? "" : $" resp={resp}")
                + (string.IsNullOrEmpty(debug) ? "" : $" dbg={debug}")
                + (string.IsNullOrWhiteSpace(errBody) ? "" : $" body={errBody.Trim()}"));

            if (!retryTransient || !IsRetryableStatus(status) || transientAttempt >= RetryDelaysMs.Length)
                throw lastError;

            await Task.Delay(RetryDelaysMs[transientAttempt], ct).ConfigureAwait(false);
            transientAttempt++;
        }
    }

    private static bool IsRetryableStatus(int status) =>
        status is 429 or 502 or 503 or 504;

    private static HttpRequestMessage BuildRequest(
        ICloudSession session,
        string url,
        byte[] body,
        RestoreSessionState? restoreState,
        CloudKitContainerBinding? container = null)
    {
        var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Content = new ByteArrayContent(body);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-protobuf");
        request.Content.Headers.ContentType.Parameters.Add(
            new NameValueHeaderValue("desc", "\"https://gateway.icloud.com:443/static/protobuf/CloudDB/CloudDBClient.desc\""));
        request.Content.Headers.ContentType.Parameters.Add(new NameValueHeaderValue("messageType", "RequestOperation"));
        request.Content.Headers.ContentType.Parameters.Add(new NameValueHeaderValue("delimited", "true"));
        request.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip");

        var operationId = Guid.NewGuid().ToString("N")[..16].ToUpperInvariant();
        request.ApplyCloudKitHeaders(session, operationId, container: container);

        request.Headers.Remove("x-apple-operation-group-id");
        var groupId = restoreState?.OperationGroupId ?? operationId;
        request.Headers.TryAddWithoutValidation("x-apple-operation-group-id", groupId);

        return request;
    }
}
