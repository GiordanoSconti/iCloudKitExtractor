using System.Text;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>Send/recv messaggi Alloy su topic multiplex (payload grezzo + NGM).</summary>
public sealed class IdsMessagingClient
{
    private readonly IdsApsTransport _transport;
    private readonly IdsIdentityCache _cache;
    private readonly IdsIdentity _identity;
    private readonly Action<string>? _log;

    public IdsMessagingClient(
        IdsApsTransport transport,
        IdsIdentityCache cache,
        IdsIdentity identity,
        Action<string>? log = null)
    {
        _transport = transport;
        _cache = cache;
        _identity = identity;
        _log = log;
    }

    public event EventHandler<IdsMessageReceivedEventArgs>? MessageReceived;

    public async Task SendAsync(IdsSendRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);
        if (request.Targets.Count == 0)
            throw new ArgumentException("Nessun target.", nameof(request));

        var messageId = request.MessageId ?? Guid.NewGuid().ToString("D").ToUpperInvariant();
        var sent = 0;
        foreach (var target in request.Targets)
        {
            if (target.PushToken is null || target.PushToken.Length == 0)
            {
                _log?.Invoke($"IDS send skip {target.Uri}: push-token assente");
                continue;
            }

            var preKey = IdsNgmCrypto.TryParsePreKeyPublic(target.NgmPreKeyData)
                         ?? target.NgmDevicePublicKey;
            var devicePub = target.NgmDevicePublicKey ?? preKey;
            byte[] wirePayload;
            if (preKey is { Length: 32 } && devicePub is { Length: 32 })
            {
                var counter = IdsNgmCrypto.NextCounter(_identity, preKey, devicePub);
                var encrypted = IdsNgmCrypto.Encrypt(
                    _identity, preKey, devicePub, request.Payload, counter);
                wirePayload = BuildIdsEnvelope(
                    request, messageId, target, encrypted, encryptedPayload: true);
            }
            else
            {
                // Fallback: payload in chiaro nell'envelope (lab / peer senza NGM).
                wirePayload = BuildIdsEnvelope(
                    request, messageId, target, request.Payload, encryptedPayload: false);
                _log?.Invoke($"IDS send {target.Uri}: senza prekey NGM — payload non cifrato");
            }

            await _transport.SendToPeerAsync(
                    request.Topic, target.PushToken, wirePayload, ct: ct)
                .ConfigureAwait(false);
            sent++;
            _log?.Invoke(
                $"IDS send OK topic={request.Topic} → {target.Uri} cmd={request.Command} id={messageId}");
        }

        if (sent == 0)
            throw new InvalidOperationException("Nessun target con push-token inviabile.");
    }

    /// <summary>App-ack Find My style (command 244) rispondendo a un messaggio ricevuto.</summary>
    public async Task SendAppAckAsync(
        string topic,
        string selfHandle,
        IdsReceivedMessage incoming,
        CancellationToken ct = default)
    {
        if (incoming.Sender is null || incoming.Uuid is null || incoming.SenderToken is null)
            throw new InvalidOperationException("Messaggio incompleto per app-ack.");

        var targets = _cache.GetTargets(topic, selfHandle, [incoming.Sender]);
        var peer = targets.FirstOrDefault()
                   ?? new IdsPeerIdentity
                   {
                       Uri = incoming.Sender,
                       PushToken = incoming.SenderToken,
                   };

        var extras = new Dictionary<string, object?>
        {
            ["rI"] = incoming.Uuid.Value.ToByteArray(),
        };
        await SendAsync(new IdsSendRequest
        {
            Topic = topic,
            SenderHandle = selfHandle,
            Targets = [peer],
            Payload = [],
            Command = 244,
            NoResponse = true,
            Extras = extras,
        }, ct).ConfigureAwait(false);
    }

    public bool TryHandleIncoming(ApsNotificationEventArgs e, out IdsReceivedMessage? message)
    {
        message = null;
        var topic = e.Topic;
        if (topic is null
            || !(topic.Contains("alloy", StringComparison.OrdinalIgnoreCase)
                 || topic.Contains("multiplex", StringComparison.OrdinalIgnoreCase)
                 || topic.Equals(IdsConstants.IdsHttpOverApnsTopic, StringComparison.Ordinal)))
        {
            return false;
        }

        // Non trattare risposte HTTP-over-APNs come messaggi Alloy.
        if (topic.Equals(IdsConstants.IdsHttpOverApnsTopic, StringComparison.Ordinal))
            return false;

        var payload = e.Payload;
        if (payload is null || payload.Length == 0)
            return false;

        try
        {
            var dict = TryParsePlist(payload);
            string? sender = null;
            string? target = null;
            int? command = null;
            Guid? uuid = null;
            byte[]? inner = null;
            byte[]? senderToken = e.Fields.FirstOrDefault(f => f.Id == 2).Value;

            if (dict is not null)
            {
                sender = AppleXmlPlist.GetString(dict, "sP")
                         ?? AppleXmlPlist.GetString(dict, "sender");
                target = AppleXmlPlist.GetString(dict, "tP")
                         ?? AppleXmlPlist.GetString(dict, "target");
                command = AppleXmlPlist.GetInt(dict, "c")
                          ?? AppleXmlPlist.GetInt(dict, "command");
                if (dict.TryGetValue("U", out var uObj) && uObj is byte[] uid && uid.Length == 16)
                    uuid = new Guid(uid);
                inner = AppleXmlPlist.GetData(dict, "P")
                        ?? AppleXmlPlist.GetData(dict, "p")
                        ?? AppleXmlPlist.GetData(dict, "raw");
            }

            byte[]? plaintext = null;
            var decrypted = false;
            string? note = null;
            var rawInner = inner ?? payload;
            if (rawInner.Length > 0)
            {
                plaintext = IdsNgmCrypto.TryDecrypt(_identity, rawInner, out var err);
                if (plaintext is not null)
                {
                    decrypted = true;
                }
                else
                {
                    note = err;
                    // forse già plaintext bplist/xml
                    if (LooksLikePlist(rawInner) || LooksLikeText(rawInner))
                        plaintext = rawInner;
                }
            }

            message = new IdsReceivedMessage
            {
                Topic = topic,
                Sender = sender,
                Target = target,
                SenderToken = senderToken,
                Uuid = uuid,
                Command = command,
                Plaintext = plaintext,
                RawPayload = payload,
                Decrypted = decrypted,
                ParseNote = note,
                ReceivedUtc = e.ReceivedUtc,
            };
            MessageReceived?.Invoke(this, new IdsMessageReceivedEventArgs { Message = message });
            _log?.Invoke(
                $"IDS recv topic={topic} cmd={command?.ToString() ?? "?"} from={sender ?? "?"} " +
                $"decrypted={decrypted} plain={(plaintext?.Length ?? 0)} B");
            return true;
        }
        catch (Exception ex)
        {
            _log?.Invoke("IDS recv parse: " + ex.Message);
            return false;
        }
    }

    private static byte[] BuildIdsEnvelope(
        IdsSendRequest request,
        string messageId,
        IdsPeerIdentity target,
        byte[] payload,
        bool encryptedPayload)
    {
        var dict = new Dictionary<string, object?>
        {
            ["c"] = request.Command,
            ["E"] = encryptedPayload ? "pair-ec" : "plain",
            ["sP"] = request.SenderHandle,
            ["tP"] = target.Uri,
            ["U"] = Guid.TryParse(messageId, out var g) ? g.ToByteArray() : Encoding.UTF8.GetBytes(messageId),
            ["P"] = payload,
        };
        if (request.Extras is not null)
        {
            foreach (var (k, v) in request.Extras)
                dict[k] = v;
        }

        if (target.SessionToken is { Length: > 0 })
            dict["t"] = target.SessionToken;

        return AppleXmlPlist.ToXmlBytes(dict);
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

            var text = Encoding.UTF8.GetString(data);
            if (!text.Contains("<plist", StringComparison.OrdinalIgnoreCase))
                return null;
            return AppleXmlPlist.Parse(data);
        }
        catch
        {
            return null;
        }
    }

    private static bool LooksLikePlist(byte[] data) =>
        data.Length >= 6 && (data.AsSpan(0, 6).SequenceEqual("bplist"u8)
                             || Encoding.UTF8.GetString(data).Contains("<plist", StringComparison.OrdinalIgnoreCase));

    private static bool LooksLikeText(byte[] data)
    {
        try
        {
            var t = Encoding.UTF8.GetString(data);
            return t.All(c => !char.IsControl(c) || c is '\n' or '\r' or '\t');
        }
        catch
        {
            return false;
        }
    }
}
