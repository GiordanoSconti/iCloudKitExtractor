using System.IO;
using System.Text;
using iCloudKitExtractor.Services.Ids;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.IMessage;

/// <summary>
/// Orchestrates Madrid iMessage receive/send over the existing APS courier.
/// Phase MVP: parse APS payloads, decrypt when possible, persist text, and publish
/// encrypted envelopes via courier send when identities are available.
/// </summary>
public sealed class MadridClient
{
    private readonly MadridMessageStore _store = new();
    private readonly IdsUserDirectory _directory = new();
    private readonly HttpClient _http;
    private ApsCourierClient? _courier;

    public MadridClient(HttpClient http)
    {
        _http = http;
        _store.Load();
        _store.Changed += (_, _) => Changed?.Invoke(this, EventArgs.Empty);
    }

    public MadridMessageStore Store => _store;
    public IdsUserDirectory Directory => _directory;

    public event EventHandler? Changed;
    public event EventHandler<string>? Log;

    public void BindCourier(ApsCourierClient courier) => _courier = courier;

    public void HandleApsNotification(ApsNotificationEventArgs e)
    {
        var payload = e.Payload ?? Array.Empty<byte>();
        if (payload.Length == 0 && string.IsNullOrEmpty(e.PayloadText))
            return;

        // Topic arrives as SHA-1 hash; treat non-OTP notifications as candidate chat payloads.
        if (e.ExtractedOtp is not null && (e.PayloadText?.Length ?? 0) < 24)
            return;

        var raw = payload.Length > 0
            ? payload
            : Encoding.UTF8.GetBytes(e.PayloadText ?? "");

        var peer = TryExtractPeer(e.PayloadText, raw) ?? "unknown";
        var identity = IdsIdentity.LoadOrCreate();
        string body;
        if (MadridMessageCrypto.TryDecrypt(raw, identity, out var clear))
            body = clear;
        else if (!string.IsNullOrWhiteSpace(e.PayloadText))
            body = e.PayloadText!;
        else
            body = $"[binary {raw.Length} B]";

        _store.Append(peer, body, outgoing: false);
        Log?.Invoke(this, $"Madrid RX {peer}: {Truncate(body, 120)}");
    }

    public async Task<IdsLookupResult> LookupHandleAsync(
        string handle,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        if (!IdsStorage.HasMadridRegistration() && !IdsStorage.HasRegistration())
            throw new InvalidOperationException("Enroll Madrid / IDS first (ID cert required).");
        var (push, pushKey, pushCert, pushSrc) = MadridPushMaterial.ResolveForMadrid();
        log?.Invoke("Madrid lookup push: " + pushSrc);
        var meta = IdsStorage.TryLoadMadridMeta() ?? IdsStorage.TryLoadMeta();
        var profileId = meta?.ProfileId
                        ?? throw new InvalidOperationException("IDS profile id missing — re-enroll.");
        // ID cert is bound to the auth CSR — always sign with auth key (never a stale ids-id.key).
        var idKey = await File.ReadAllTextAsync(IdsStorage.AuthKeyPemPath, ct).ConfigureAwait(false);
        var idCertPath = IdsStorage.HasMadridRegistration()
            ? IdsStorage.MadridIdCertPemPath
            : IdsStorage.IdCertPemPath;
        var idCert = await File.ReadAllTextAsync(idCertPath, ct).ConfigureAwait(false);
        var selfUri = meta?.Handles?.FirstOrDefault(h =>
                          h.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                      ?? meta?.Handles?.FirstOrDefault();

        if (_courier is null || !_courier.IsConnected)
            throw new InvalidOperationException(
                "Connect APS (iPhone push) before IDS lookup — id-query is HTTP-over-APNs.");

        var bag = new IdsBag(_http);
        var lookup = new IdsLookupClient(_http, bag, _directory);
        return await lookup
            .LookupAsync(
                handle, profileId, idKey, idCert, push,
                pushKey, pushCert,
                _courier, selfUri,
                m =>
                {
                    log?.Invoke(m);
                    Log?.Invoke(this, m);
                }, ct)
            .ConfigureAwait(false);
    }

    public async Task<MadridMessage> SendTextAsync(
        string peerHandle,
        string text,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(text))
            throw new ArgumentException("Empty message.", nameof(text));
        var peer = IdsLookupClient.NormalizeHandle(peerHandle);
        if (!_directory.TryGet(peer, out var looked) || !looked.Success || looked.Identities.Count == 0)
        {
            log?.Invoke("Lookup required before send…");
            looked = await LookupHandleAsync(peer, log, ct).ConfigureAwait(false);
            if (!looked.Success || looked.Identities.Count == 0)
                throw new InvalidOperationException(looked.Error ?? "IDS lookup returned no identities.");
        }

        var local = IdsIdentity.LoadOrCreate();
        var remote = looked.Identities[0];
        if (string.IsNullOrWhiteSpace(remote.SessionToken))
        {
            log?.Invoke("Session token missing/expired — re-lookup…");
            looked = await LookupHandleAsync(peer, log, ct).ConfigureAwait(false);
            if (!looked.Success || looked.Identities.Count == 0)
                throw new InvalidOperationException(looked.Error ?? "Re-lookup returned no identities.");
            remote = looked.Identities[0];
        }

        var cipher = MadridMessageCrypto.EncryptForRemote(text, remote, local);

        // Publish via APS when courier exposes send; otherwise persist locally and log.
        if (_courier is not null
            && !string.IsNullOrWhiteSpace(remote.PushTokenHex)
            && remote.PushTokenHex!.Length >= 16)
        {
            try
            {
                var token = Convert.FromHexString(remote.PushTokenHex);
                await _courier
                    .SendNotificationAsync("com.apple.madrid", token, cipher, ct: ct)
                    .ConfigureAwait(false);
                log?.Invoke($"Madrid TX via APS to {peer} ({cipher.Length} B)");
            }
            catch (Exception ex)
            {
                // Expired session tokens often surface as courier/server rejection — re-lookup once.
                log?.Invoke("APS send failed, re-lookup + retry: " + ex.Message);
                looked = await LookupHandleAsync(peer, log, ct).ConfigureAwait(false);
                if (looked.Success && looked.Identities.Count > 0)
                {
                    remote = looked.Identities[0];
                    cipher = MadridMessageCrypto.EncryptForRemote(text, remote, local);
                    if (!string.IsNullOrWhiteSpace(remote.PushTokenHex))
                    {
                        var token2 = Convert.FromHexString(remote.PushTokenHex!);
                        await _courier
                            .SendNotificationAsync("com.apple.madrid", token2, cipher, ct: ct)
                            .ConfigureAwait(false);
                        log?.Invoke($"Madrid TX retry OK to {peer} ({cipher.Length} B)");
                    }
                }
                else
                {
                    log?.Invoke("APS send failed (message stored locally): " + ex.Message);
                }
            }
        }
        else
        {
            log?.Invoke(
                "APS send skipped (missing courier/push token) — stored as outgoing locally.");
        }

        var msg = _store.Append(peer, text, outgoing: true);
        Log?.Invoke(this, $"Madrid TX {peer}: {Truncate(text, 120)}");
        return msg;
    }

    private static string? TryExtractPeer(string? text, byte[] raw)
    {
        if (!string.IsNullOrWhiteSpace(text))
        {
            // Heuristic: mailto:/tel: in JSON-ish payload text
            var m = System.Text.RegularExpressions.Regex.Match(
                text, @"(mailto:[^\s""']+|tel:\+?\d+)");
            if (m.Success)
                return m.Groups[1].Value;
        }

        try
        {
            var s = Encoding.UTF8.GetString(raw);
            var m = System.Text.RegularExpressions.Regex.Match(
                s, @"(mailto:[^\s""']+|tel:\+?\d+)");
            if (m.Success)
                return m.Groups[1].Value;
        }
        catch
        {
            // ignore
        }

        return null;
    }

    /// <summary>Phase 6: attachments not in text MVP.</summary>
    public Task SendAttachmentAsync(string peerHandle, string filePath, CancellationToken ct = default) =>
        throw new NotSupportedException(
            "Attachments are not implemented yet (Phase 6). Text MVP only.");

    /// <summary>Phase 6: typing / read receipts not in text MVP.</summary>
    public Task SendReceiptAsync(string peerHandle, string kind, CancellationToken ct = default) =>
        throw new NotSupportedException(
            "Typing/read receipts are not implemented yet (Phase 6).");

    /// <summary>Phase 6: group chats not in text MVP.</summary>
    public Task SendGroupTextAsync(IReadOnlyList<string> handles, string text, CancellationToken ct = default) =>
        throw new NotSupportedException(
            "Group chats are not implemented yet (Phase 6). Text 1:1 MVP only.");

    /// <summary>
    /// Optional CloudKit Messages history uses existing Manatee/PCS probes
    /// (<c>MessagesPcsProbe</c>) — not a substitute for live APNs.
    /// </summary>
    public static string CloudKitHistoryHint =>
        "CloudKit Messages history: use Sync Data → Messages / MessagesPcsProbe. Live chat requires APS + Madrid enroll.";

    private static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) ? "" : (s.Length <= n ? s : s[..n] + "…");
}
