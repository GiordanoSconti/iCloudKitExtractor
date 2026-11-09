using System.Collections.Concurrent;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Trasporto IDS su APS: HTTP-over-APNs (id-query) e push notifiche verso peer token.
/// </summary>
public sealed class IdsApsTransport : IDisposable
{
    private readonly ApsCourierClient _courier;
    private readonly ConcurrentDictionary<Guid, TaskCompletionSource<byte[]>> _pending = new();
    private readonly Action<string>? _log;
    private bool _subscribed;

    public IdsApsTransport(ApsCourierClient courier, Action<string>? log = null)
    {
        _courier = courier ?? throw new ArgumentNullException(nameof(courier));
        _log = log;
    }

    public void Attach()
    {
        if (_subscribed)
            return;
        _courier.NotificationReceived += OnNotification;
        _subscribed = true;
    }

    public void Dispose()
    {
        if (!_subscribed)
            return;
        _courier.NotificationReceived -= OnNotification;
        _subscribed = false;
        foreach (var kv in _pending)
            kv.Value.TrySetCanceled();
        _pending.Clear();
    }

    /// <summary>
    /// Pseudo-HTTP su APS: body plist gzip con cT/U/c/u/h/v/b (Apple Wiki / rustpush).
    /// </summary>
    public async Task<byte[]> HttpOverApnsAsync(
        string url,
        IReadOnlyDictionary<string, string> headers,
        byte[] bodyGzip,
        string contentType = "application/x-apple-plist",
        TimeSpan? timeout = null,
        CancellationToken ct = default)
    {
        if (!_courier.IsConnected)
            throw new InvalidOperationException("APS non connesso — Connetti APS prima del lookup IDS.");

        Attach();
        var messageId = Guid.NewGuid();
        var tcs = new TaskCompletionSource<byte[]>(TaskCreationOptions.RunContinuationsAsynchronously);
        if (!_pending.TryAdd(messageId, tcs))
            throw new InvalidOperationException("Collision message-id HTTP-over-APNs.");

        try
        {
            var headerList = headers
                .Select(kv => (object?)new Dictionary<string, object?>
                {
                    ["name"] = kv.Key,
                    ["value"] = kv.Value,
                })
                .ToList();

            var requestDict = new Dictionary<string, object?>
            {
                ["cT"] = contentType,
                ["U"] = messageId.ToByteArray(),
                ["c"] = 96,
                ["u"] = url,
                ["h"] = headerList,
                ["v"] = 2,
                ["b"] = bodyGzip,
            };
            var payload = AppleXmlPlist.ToXmlBytes(requestDict);
            var selfToken = _courier.Token
                ?? throw new InvalidOperationException("Push token APS assente.");

            await _courier.SendNotificationAsync(
                    IdsConstants.IdsHttpOverApnsTopic,
                    selfToken,
                    payload,
                    messageId.ToByteArray(),
                    ct)
                .ConfigureAwait(false);
            _log?.Invoke($"IDS HTTP-over-APNs → {url} U={messageId:N}");

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout ?? TimeSpan.FromSeconds(45));
            await using var reg = timeoutCts.Token.Register(() =>
                tcs.TrySetException(new TimeoutException(
                    "Timeout HTTP-over-APNs (nessuna risposta IDS).")));

            var responsePayload = await tcs.Task.ConfigureAwait(false);
            return ExtractHttpResponseBody(responsePayload);
        }
        finally
        {
            _pending.TryRemove(messageId, out _);
        }
    }

    public Task SendToPeerAsync(
        string topic,
        byte[] destinationToken,
        byte[] payload,
        byte[]? messageId = null,
        CancellationToken ct = default) =>
        _courier.SendNotificationAsync(topic, destinationToken, payload, messageId, ct);

    private void OnNotification(object? sender, ApsNotificationEventArgs e)
    {
        var payload = e.Payload;
        if (payload is null || payload.Length < 8)
            return;

        try
        {
            // Risposta HTTP-over-APNs: plist con U + b
            var dict = TryParsePlist(payload);
            if (dict is null)
                return;
            if (!dict.TryGetValue("U", out var uObj))
                return;

            byte[]? uidBytes = null;
            if (uObj is byte[] b)
                uidBytes = b;
            else if (uObj is string s)
            {
                try { uidBytes = Convert.FromBase64String(s); }
                catch { /* ignore */ }
            }
            if (uidBytes is null || uidBytes.Length != 16)
                return;

            var id = new Guid(uidBytes);
            if (_pending.TryGetValue(id, out var tcs))
            {
                _log?.Invoke($"IDS HTTP-over-APNs ← response U={id:N} len={payload.Length}");
                tcs.TrySetResult(payload);
            }
        }
        catch (Exception ex)
        {
            _log?.Invoke("IDS transport parse: " + ex.Message);
        }
    }

    private static byte[] ExtractHttpResponseBody(byte[] responsePayload)
    {
        var dict = TryParsePlist(responsePayload)
                   ?? throw new InvalidOperationException("Risposta HTTP-over-APNs non plist.");
        if (dict.TryGetValue("b", out var bodyObj) && bodyObj is byte[] body)
        {
            var unzipped = IdsSigning.TryGunzip(body) ?? body;
            return unzipped;
        }

        // Alcune risposte mettono lo status nel root senza 'b'
        return responsePayload;
    }

    private static Dictionary<string, object?>? TryParsePlist(byte[] data)
    {
        try
        {
            if (data.Length >= 6 && data.AsSpan(0, 6).SequenceEqual("bplist"u8))
            {
                if (AppleBinaryPlist.TryParseDict(data, out var dict, out _) && dict is not null)
                    return dict;
                return null;
            }

            var text = System.Text.Encoding.UTF8.GetString(data);
            if (!text.Contains("<plist", StringComparison.OrdinalIgnoreCase))
                return null;
            return AppleXmlPlist.Parse(data);
        }
        catch
        {
            return null;
        }
    }
}
