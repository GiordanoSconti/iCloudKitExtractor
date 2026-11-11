using System.IO;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Ids;

namespace iCloudKitExtractor.Services.Push;

/// <summary>
/// Client device-side verso courier APS — allineato a pypush:
/// TLS client-cert + ALPN <c>apns-security-v3</c>, SNI <c>courier.push.apple.com</c>,
/// Connect con cert DER + nonce + firma RSA-SHA1.
/// </summary>
public sealed class ApsCourierClient : IAsyncDisposable
{
    public const int CourierPort = 5223;
    public const string ProductionSni = "courier.push.apple.com";
    public const string SandboxSni = "courier.sandbox.push.apple.com";

    private readonly object _gate = new();
    private TcpClient? _tcp;
    private SslStream? _ssl;
    private X509Certificate2? _clientCert;
    private RSA? _clientRsa; // tenuto vivo per firme connect
    private CancellationTokenSource? _loopCts;
    private Task? _receiveLoop;
    private Task? _keepAliveLoop;

    public byte[]? Token { get; private set; }
    public string? CourierHost { get; private set; }
    public bool IsConnected => _ssl is not null && _tcp?.Connected == true;
    public DateTimeOffset? ConnectedUtc { get; private set; }

    public event EventHandler<ApsNotificationEventArgs>? NotificationReceived;
    public event EventHandler<string>? Log;

    public async Task ConnectAsync(
        string keyPem,
        string certPem,
        byte[]? existingToken = null,
        IReadOnlyList<string>? filterTopics = null,
        CancellationToken ct = default)
    {
        await DisconnectAsync().ConfigureAwait(false);

        var attempts = new List<(string? Host, byte[]? Token, string Label)>
        {
            (null, existingToken, existingToken is null ? "bag-host, no-token" : "bag-host, saved-token"),
        };
        if (existingToken is not null)
            attempts.Add((null, null, "bag-host, no-token"));
        attempts.Add(("1-courier.push.apple.com", null, "1-courier, no-token"));
        attempts.Add(("windows.courier.push.apple.com", null, "windows.courier, no-token"));

        Exception? last = null;
        for (var i = 0; i < attempts.Count; i++)
        {
            var (hostOverride, tokenToUse, label) = attempts[i];
            try
            {
                if (i > 0)
                {
                    RaiseLog($"Retry APS ({label})…");
                    if (tokenToUse is null)
                    {
                        try { File.Delete(ApsStorage.TokenPath); } catch { /* ignore */ }
                    }

                    await DisconnectAsync().ConfigureAwait(false);
                }

                await ConnectOnceAsync(keyPem, certPem, tokenToUse, filterTopics, hostOverride, ct)
                    .ConfigureAwait(false);
                return;
            }
            catch (Exception ex) when (i < attempts.Count - 1 && IsRetryableConnectError(ex))
            {
                last = ex;
                RaiseLog($"Connect failed ({ex.Message}) — next attempt…");
            }
        }

        throw last ?? new InvalidOperationException("APS connect failed.");
    }

    private static bool IsRetryableConnectError(Exception ex) =>
        ex.Message.Contains("status non-OK", StringComparison.OrdinalIgnoreCase)
        || ex.Message.Contains("ALPN", StringComparison.OrdinalIgnoreCase)
        || ex is AuthenticationException or IOException;

    private async Task ConnectOnceAsync(
        string keyPem,
        string certPem,
        byte[]? existingToken,
        IReadOnlyList<string>? filterTopics,
        string? hostOverride,
        CancellationToken ct)
    {
        var host = hostOverride ?? await ResolveCourierHostAsync(ct).ConfigureAwait(false);
        CourierHost = host;
        var sni = host.Contains("sandbox", StringComparison.OrdinalIgnoreCase)
            ? SandboxSni
            : ProductionSni;

        using var pemCert = X509Certificate2.CreateFromPem(certPem, keyPem);
        var pfx = pemCert.Export(X509ContentType.Pkcs12);
        _clientCert?.Dispose();
        _clientRsa?.Dispose();
        _clientCert = X509CertificateLoader.LoadPkcs12(
            pfx,
            password: null,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);

        var clientCert = _clientCert;
        _clientRsa = RSA.Create();
        _clientRsa.ImportFromPem(keyPem);
        var clientRsa = _clientRsa;
        var certDer = clientCert.RawData;

        // Su Windows Schannel: bisogna OFFRIRE apns-security-v3 (senza ALPN Apple
        // rifiuta le credenziali), ma NegotiatedApplicationProtocol resta spesso
        // vuoto anche quando il connect firmato va a status 0x00. Non abortire.
        TcpClient? tcp = null;
        SslStream? ssl = null;
        try
        {
            tcp = new TcpClient();
            await tcp.ConnectAsync(host, CourierPort, ct).ConfigureAwait(false);
            tcp.NoDelay = true;
            ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                // Critico: SNI generico (pypush), non l'host numerato 27-courier…
                TargetHost = sni,
                ClientCertificates = new X509CertificateCollection { clientCert },
                LocalCertificateSelectionCallback = (_, _, _, _, _) => clientCert,
                EnabledSslProtocols = SslProtocols.Tls12,
                ApplicationProtocols = new List<SslApplicationProtocol>
                {
                    new("apns-security-v3"),
                },
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
                RemoteCertificateValidationCallback = static (_, _, _, _) => true,
            }, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            ssl?.Dispose();
            tcp?.Dispose();
            var root = ex;
            while (root.InnerException is not null)
                root = root.InnerException;
            throw new AuthenticationException(
                $"APS TLS failed on {host} SNI={sni}: {ex.Message} | {root.Message}", ex);
        }

        _tcp = tcp;
        _ssl = ssl;
        var alpnNeg = ssl.NegotiatedApplicationProtocol.ToString();
        RaiseLog(
            $"TLS OK → {host}:{CourierPort} SNI={sni} ALPN={(string.IsNullOrEmpty(alpnNeg) ? "(schannel-empty, offer=v3)" : alpnNeg)}");

        byte[] SignNonce(byte[] nonce) =>
            clientRsa.SignData(nonce, HashAlgorithmName.SHA1, RSASignaturePadding.Pkcs1);

        // iPhone Device CA certs often use richer flag bits (wiki iOS ~0x26A);
        // Albert/Windows path keeps pypush 0x41.
        var useIosFlags = IsAppleIphoneDeviceCert(certDer);
        var connectFlags = useIosFlags ? 0x26A : 65;
        var connectPayload = ApsProtocol.BuildConnect(
            existingToken,
            certDer,
            SignNonce,
            flags: connectFlags);
        RaiseLog(
            $"TX Connect type=0x07 flags=0x{connectFlags:X} "
            + $"token={(existingToken is null ? "no" : "yes")} "
            + $"cert={(useIosFlags ? "iPhone" : "Albert/other")}");
        await ssl.WriteAsync(connectPayload, ct).ConfigureAwait(false);
        await ssl.FlushAsync(ct).ConfigureAwait(false);

        using var ackCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        ackCts.CancelAfter(TimeSpan.FromSeconds(30));
        byte[]? token = null;
        while (token is null)
        {
            var msg = await ApsProtocol.ReadMessageAsync(ssl, ackCts.Token).ConfigureAwait(false);
            if (msg is null)
                throw new InvalidOperationException("APS: stream closed during connect.");
            var (type, fields) = msg.Value;
            RaiseLog($"RX type=0x{type:X2} fields={fields.Count} [{FormatFields(fields)}]");
            if (type != ApsProtocol.TypeConnectAck)
                continue;

            var status = ApsProtocol.GetField(fields, 1);
            if (status is null || status.Length < 1 || status[0] != 0x00)
            {
                throw new InvalidOperationException(
                    $"APS connect ack status non-OK: {(status is null ? "?" : Convert.ToHexString(status))}");
            }

            token = ApsProtocol.GetField(fields, 3) ?? existingToken;
            if (token is null || token.Length == 0)
                throw new InvalidOperationException("APS connect ack without token.");
        }

        Token = token;
        ApsStorage.SaveToken(token);
        ConnectedUtc = DateTimeOffset.UtcNow;
        RaiseLog($"Push token: {ApsStorage.TokenHex(token)}");

        // pypush / JJTech: filter topics FIRST, then active SetState(1).
        var topics = filterTopics
                     ?? (useIosFlags ? MadridReceiveTopics : DefaultAuthTopics);
        await ssl.WriteAsync(ApsProtocol.BuildFilter(token, topics), ct).ConfigureAwait(false);
        await ssl.WriteAsync(ApsProtocol.BuildSetState(1), ct).ConfigureAwait(false);
        await ssl.FlushAsync(ct).ConfigureAwait(false);
        RaiseLog($"Filter+SetState(1) topics: {string.Join(", ", topics)}");
        if (useIosFlags)
        {
            RaiseLog(
                "NOTE: same push token as the iPhone — put the phone in Airplane Mode "
                + "(or sign out of iMessage) or apsd will steal the courier and you only see KeepAlive.");
        }

        _loopCts = new CancellationTokenSource();
        var loopToken = _loopCts.Token;
        _receiveLoop = Task.Run(() => ReceiveLoopAsync(loopToken), CancellationToken.None);
        _keepAliveLoop = Task.Run(() => KeepAliveLoopAsync(loopToken), CancellationToken.None);
    }

    private static bool IsAppleIphoneDeviceCert(byte[] certDer)
    {
        try
        {
            using var cert = X509CertificateLoader.LoadCertificate(certDer);
            var issuer = cert.IssuerName.Name ?? "";
            var subject = cert.SubjectName.Name ?? "";
            return issuer.Contains("iPhone Device CA", StringComparison.OrdinalIgnoreCase)
                   || subject.Contains("OU=iPhone", StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    public async Task DisconnectAsync()
    {
        var cts = _loopCts;
        _loopCts = null;
        if (cts is not null)
        {
            try { cts.Cancel(); } catch { /* ignore */ }
            cts.Dispose();
        }

        var recv = _receiveLoop;
        var ka = _keepAliveLoop;
        _receiveLoop = null;
        _keepAliveLoop = null;
        if (recv is not null)
        {
            try { await recv.ConfigureAwait(false); } catch { /* ignore */ }
        }

        if (ka is not null)
        {
            try { await ka.ConfigureAwait(false); } catch { /* ignore */ }
        }

        var ssl = _ssl;
        _ssl = null;
        if (ssl is not null)
            await ssl.DisposeAsync().ConfigureAwait(false);

        var tcp = _tcp;
        _tcp = null;
        tcp?.Dispose();

        var cert = _clientCert;
        _clientCert = null;
        cert?.Dispose();

        var rsa = _clientRsa;
        _clientRsa = null;
        rsa?.Dispose();

        ConnectedUtc = null;
        CourierHost = null;
    }

    public async ValueTask DisposeAsync() => await DisconnectAsync().ConfigureAwait(false);

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        var ssl = _ssl;
        if (ssl is null)
            return;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                var msg = await ApsProtocol.ReadMessageAsync(ssl, ct).ConfigureAwait(false);
                if (msg is null)
                {
                    RaiseLog("APS stream chiuso.");
                    break;
                }

                var (type, fields) = msg.Value;
                if (type == ApsProtocol.TypeKeepAliveAck)
                    continue;

                if (type == ApsProtocol.TypeNotification)
                {
                    var payload = ApsProtocol.GetField(fields, 3);
                    var topicHash = ApsProtocol.GetField(fields, 1);
                    var messageId = ApsProtocol.GetField(fields, 4);
                    var token = Token;
                    if (token is not null && messageId is not null)
                    {
                        try
                        {
                            var ack = ApsProtocol.BuildNotificationAck(token, messageId);
                            await ssl.WriteAsync(ack, ct).ConfigureAwait(false);
                            await ssl.FlushAsync(ct).ConfigureAwait(false);
                        }
                        catch (Exception ex)
                        {
                            RaiseLog($"ACK failed: {ex.Message}");
                        }
                    }

                    // IDS HTTP-over-APNs responses (id-query) — complete waiter, don't treat as chat.
                    if (TryCompleteHttpOverApns(payload))
                        continue;

                    var text = TryDecodePayload(payload);
                    var otp = TryExtractOtp(text);
                    NotificationReceived?.Invoke(this, new ApsNotificationEventArgs
                    {
                        Type = type,
                        Fields = fields,
                        Payload = payload,
                        TopicHash = topicHash,
                        MessageId = messageId,
                        PayloadText = text,
                        ExtractedOtp = otp,
                    });
                    RaiseLog(
                        otp is null
                            ? $"NOTIF payload={text ?? Convert.ToHexString(payload ?? Array.Empty<byte>())}"
                            : $"NOTIF OTP={otp} payload={text}");
                    continue;
                }

                RaiseLog($"RX type=0x{type:X2} fields={fields.Count}");
            }
        }
        catch (OperationCanceledException)
        {
            // shutdown
        }
        catch (Exception ex)
        {
            RaiseLog($"Receive loop: {ex.Message}");
        }
    }

    private async Task KeepAliveLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested)
            {
                await Task.Delay(TimeSpan.FromSeconds(30), ct).ConfigureAwait(false);
                var ssl = _ssl;
                if (ssl is null)
                    break;
                await ssl.WriteAsync(ApsProtocol.BuildKeepAlive(), ct).ConfigureAwait(false);
                await ssl.FlushAsync(ct).ConfigureAwait(false);
                RaiseLog("KeepAlive inviato.");
            }
        }
        catch (OperationCanceledException)
        {
            // shutdown
        }
        catch (Exception ex)
        {
            RaiseLog($"KeepAlive: {ex.Message}");
        }
    }

    /// <summary>Topics for live iMessage RX when using the cloned iPhone APS identity.</summary>
    private static readonly string[] MadridReceiveTopics =
    {
        "com.apple.madrid",
        "com.apple.private.ids",
        "com.apple.private.alloy",
        "com.apple.ess",
        "com.apple.private.alloy.sms",
    };

    private static readonly string[] DefaultAuthTopics =
    {
        // 2FA / AuthKit / IDMS (OTP trusted device)
        "com.apple.gs.idms.pet",
        "com.apple.gs.idms.hb",
        "com.apple.idmsauth",
        "com.apple.idmsauthagent",
        "com.apple.aa.idms",
        "com.apple.akd",
        "com.apple.AuthKit",
        "com.apple.appleaccount",
        "com.apple.accountsd",
        "com.apple.ess",
        "com.apple.private.ids",
        "com.apple.private.alloy",
        "com.apple.private.alloy.multiplex1",
        "com.apple.private.alloy.fmf",
        "com.apple.private.alloy.fmd",
        "com.apple.private.alloy.status.keysharing",
        "com.apple.private.alloy.status.personal",
        "com.apple.madrid",
        "com.apple.icloud-container.com.apple.private.alloy",
        "com.apple.icloud-container.com.apple.icloud.searchpartyuseragent",
        "com.apple.gamed",
        "com.apple.itunesstored",
    };

    private static async Task<string> ResolveCourierHostAsync(CancellationToken ct)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(15) };
            using var resp = await http.GetAsync("http://init-p01st.push.apple.com/bag", ct)
                .ConfigureAwait(false);
            resp.EnsureSuccessStatusCode();
            var outer = await resp.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
            var outerDict = AppleXmlPlist.Parse(outer);
            if (outerDict.TryGetValue("bag", out var bagObj) && bagObj is byte[] bagBytes)
            {
                var bag = AppleXmlPlist.Parse(bagBytes);
                var hostname = AppleXmlPlist.GetString(bag, "APNSCourierHostname") ?? "courier.push.apple.com";
                var count = AppleXmlPlist.GetInt(bag, "APNSCourierHostcount") ?? 50;
                var n = Random.Shared.Next(1, Math.Max(2, count + 1));
                return $"{n}-{hostname}";
            }
        }
        catch
        {
            // fallback
        }

        return $"{Random.Shared.Next(1, 50)}-courier.push.apple.com";
    }

    private static string FormatFields(IReadOnlyList<(byte Id, byte[] Value)> fields) =>
        string.Join(", ", fields.Select(f =>
            $"id=0x{f.Id:X2} len={f.Value.Length} hex={Convert.ToHexString(f.Value.AsSpan(0, Math.Min(8, f.Value.Length)))}"));

    private static string? TryDecodePayload(byte[]? payload)
    {
        if (payload is null || payload.Length == 0)
            return null;
        try
        {
            if (payload.Length >= 6 && payload[0] == 'b' && payload[1] == 'p'
                && payload[2] == 'l' && payload[3] == 'i' && payload[4] == 's' && payload[5] == 't')
            {
                return "bplist(" + payload.Length + " bytes) hex=" + Convert.ToHexString(payload);
            }

            var text = Encoding.UTF8.GetString(payload);
            if (text.Any(ch => char.IsControl(ch) && ch is not '\n' and not '\r' and not '\t'))
                return Convert.ToHexString(payload);
            return text;
        }
        catch
        {
            return Convert.ToHexString(payload);
        }
    }

    private static string? TryExtractOtp(string? text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return null;
        var m = Regex.Match(text, @"\b(\d{6})\b");
        return m.Success ? m.Groups[1].Value : null;
    }

    /// <summary>Publish a notification to a recipient push token on the given topic.</summary>
    public async Task SendNotificationAsync(
        string topic,
        byte[] recipientToken,
        byte[] payload,
        byte[]? messageId = null,
        CancellationToken ct = default)
    {
        var ssl = _ssl;
        if (ssl is null || !IsConnected)
            throw new InvalidOperationException("APS courier is not connected.");
        if (recipientToken is null || recipientToken.Length == 0)
            throw new ArgumentException("Recipient push token required.", nameof(recipientToken));

        var frame = ApsProtocol.BuildNotification(topic, recipientToken, payload, messageId);
        await ssl.WriteAsync(frame, ct).ConfigureAwait(false);
        await ssl.FlushAsync(ct).ConfigureAwait(false);
        RaiseLog($"TX NOTIF topic={topic} tokenLen={recipientToken.Length} payload={payload.Length} B");
    }

    /// <summary>Best-effort topic name from hash (filter map not kept in Madrid courier path).</summary>
    public string? ResolveTopic(byte[]? topicHash) => null;

    /// <summary>
    /// IDS HTTP-over-APNs (pypush <c>ids/query.py</c>): send binary plist envelope on
    /// <paramref name="topic"/> and wait for a matching response notification (<c>U</c>).
    /// </summary>
    public async Task<byte[]> HttpOverApnsAsync(
        string topic,
        string url,
        IReadOnlyDictionary<string, string> headers,
        byte[] gzippedBody,
        CancellationToken ct = default,
        TimeSpan? timeout = null)
    {
        var ssl = _ssl;
        var token = Token;
        if (ssl is null || !IsConnected || token is null || token.Length == 0)
            throw new InvalidOperationException("APS courier is not connected (needed for id-query).");

        var msgId = RandomNumberGenerator.GetBytes(16);
        var envelope = new Dictionary<string, object?>
        {
            ["cT"] = "application/x-apple-plist",
            ["U"] = msgId,
            ["c"] = 96,
            ["u"] = url,
            ["h"] = headers.ToDictionary(kv => kv.Key, kv => (object?)kv.Value),
            ["v"] = 2,
            ["b"] = gzippedBody,
        };
        var payload = AppleBinaryPlist.Write(envelope);

        var tcs = new TaskCompletionSource<byte[]>(
            TaskCreationOptions.RunContinuationsAsynchronously);
        lock (_pendingHttp)
            _pendingHttp[Convert.ToHexString(msgId)] = tcs;

        try
        {
            var frame = ApsProtocol.BuildNotification(topic, token, payload);
            await ssl.WriteAsync(frame, ct).ConfigureAwait(false);
            await ssl.FlushAsync(ct).ConfigureAwait(false);
            RaiseLog(
                $"TX HTTP-over-APNs topic={topic} U={Convert.ToHexString(msgId)[..8]}… "
                + $"url={url} body={gzippedBody.Length} B");

            using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            timeoutCts.CancelAfter(timeout ?? TimeSpan.FromSeconds(30));
            await using var reg = timeoutCts.Token.Register(
                () => tcs.TrySetException(new TimeoutException("IDS HTTP-over-APNs timed out.")));
            return await tcs.Task.ConfigureAwait(false);
        }
        finally
        {
            lock (_pendingHttp)
                _pendingHttp.Remove(Convert.ToHexString(msgId));
        }
    }

    private readonly Dictionary<string, TaskCompletionSource<byte[]>> _pendingHttp = new(StringComparer.Ordinal);

    private bool TryCompleteHttpOverApns(byte[]? payload)
    {
        if (payload is null || payload.Length < 8)
            return false;
        try
        {
            if (!AppleBinaryPlist.TryParseDict(payload, out var dict, out _) || dict is null)
                return false;
            if (!dict.TryGetValue("U", out var uObj) || uObj is not byte[] u || u.Length == 0)
                return false;
            if (!dict.TryGetValue("b", out var bObj) || bObj is not byte[] body || body.Length == 0)
                return false;

            var key = Convert.ToHexString(u);
            TaskCompletionSource<byte[]>? tcs;
            lock (_pendingHttp)
                _pendingHttp.TryGetValue(key, out tcs);
            if (tcs is null)
                return false;

            var unzipped = IdsSigning.TryGunzip(body) ?? body;
            tcs.TrySetResult(unzipped);
            RaiseLog($"RX HTTP-over-APNs U={key[..Math.Min(8, key.Length)]}… body={unzipped.Length} B");
            return true;
        }
        catch
        {
            return false;
        }
    }

    private void RaiseLog(string message)
    {
        lock (_gate)
            Log?.Invoke(this, message);
    }
}
