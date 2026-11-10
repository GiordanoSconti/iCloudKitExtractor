using iCloudKitExtractor.Services.Ids;

namespace iCloudKitExtractor.Services.Push;

/// <summary>
/// Orchestrazione Albert + sessione APS + stato/token per UI e GSA <c>ptkn</c>.
/// </summary>
public sealed class ApsSessionService : IAsyncDisposable
{
    private readonly HttpClient _http;
    private readonly ApsCourierClient _courier = new();
    private string? _lastError;

    public ApsSessionService(HttpClient http)
    {
        _http = http;
        _courier.Log += (_, msg) => Log?.Invoke(this, msg);
        _courier.NotificationReceived += (_, e) => NotificationReceived?.Invoke(this, e);
    }

    public event EventHandler<string>? Log;
    public event EventHandler<ApsNotificationEventArgs>? NotificationReceived;

    /// <summary>Underlying courier (for Madrid send / topic binding).</summary>
    public ApsCourierClient Courier => _courier;

    public bool IsConnected => _courier.IsConnected;

    public ApsPushState Snapshot() => new()
    {
        HasCertificate = ApsStorage.HasCertificate(),
        IsConnected = _courier.IsConnected,
        CourierHost = _courier.CourierHost,
        Token = _courier.Token ?? ApsStorage.TryLoadToken(),
        LastError = _lastError,
        ConnectedUtc = _courier.ConnectedUtc,
    };

    /// <summary>Token hex uppercase per GSA cpd <c>ptkn</c> (o null).</summary>
    public static string? TryGetPushTokenHex()
    {
        var tok = ApsStorage.TryLoadToken();
        if (tok is null || tok.Length == 0)
            return null;
        return ApsStorage.TokenHex(tok);
    }

    public async Task<string> EnsureActivatedAsync(bool forceRenew = false, CancellationToken ct = default)
    {
        if (!forceRenew && ApsStorage.HasCertificate())
        {
            var msg = "APS certificate already present in " + ApsStorage.DirectoryPath;
            Log?.Invoke(this, msg);
            return msg;
        }

        if (forceRenew)
        {
            try { System.IO.File.Delete(ApsStorage.KeyPemPath); } catch { /* ignore */ }
            try { System.IO.File.Delete(ApsStorage.CertPemPath); } catch { /* ignore */ }
            try { System.IO.File.Delete(ApsStorage.TokenPath); } catch { /* ignore */ }
        }

        Log?.Invoke(this, "Albert Windows activation (deviceservices, RSA-1024)…");
        try
        {
            var certPem = await new AlbertPushActivation(_http)
                .ActivateAsync(ct)
                .ConfigureAwait(false);
            _lastError = null;
            var msg = $"Albert OK — DeviceCertificate ({certPem.Length} char) salvato.";
            Log?.Invoke(this, msg);
            return msg;
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            throw;
        }
    }

    public async Task ConnectAsync(CancellationToken ct = default)
    {
        // After Madrid enroll with Frida iPhone push, courier MUST use that identity
        // or incoming iMessage stays on the phone (different push token).
        if (IdsStorage.HasMadridRegistration()
            && MadridPushMaterial.TryResolveIphone(out var phoneTok, out var phoneKey, out var phoneCert, out var detail))
        {
            Log?.Invoke(this, "APS Connect: Madrid → " + detail);
            await ConnectWithMaterialAsync(phoneKey, phoneCert, phoneTok, allowAlbertRenew: false, ct)
                .ConfigureAwait(false);
            return;
        }

        if (!ApsStorage.HasCertificate())
            await EnsureActivatedAsync(forceRenew: false, ct).ConfigureAwait(false);

        var (keyPem, certPem) = ApsStorage.LoadCertificate();
        var existing = ApsStorage.TryLoadToken();
        await ConnectWithMaterialAsync(keyPem, certPem, existing, allowAlbertRenew: true, ct)
            .ConfigureAwait(false);
    }

    /// <summary>Force courier onto Frida iPhone APS identity (after Madrid enroll OK).</summary>
    public async Task ConnectMadridIphoneAsync(CancellationToken ct = default)
    {
        if (!MadridPushMaterial.TryResolveIphone(out var tok, out var key, out var cert, out var detail))
            throw new InvalidOperationException(
                "iPhone APS material missing — run fetch_aps_push_identity.py + fetch_ids_validation.py");

        Log?.Invoke(this, "APS Connect (Madrid iPhone): " + detail);
        await ConnectWithMaterialAsync(key, cert, tok, allowAlbertRenew: false, ct).ConfigureAwait(false);
    }

    private async Task ConnectWithMaterialAsync(
        string keyPem,
        string certPem,
        byte[]? existingToken,
        bool allowAlbertRenew,
        CancellationToken ct)
    {
        Log?.Invoke(this, "Connessione courier APS…");
        try
        {
            await _courier.ConnectAsync(keyPem, certPem, existingToken, ct: ct).ConfigureAwait(false);
            _lastError = null;
            if (_courier.Token is { Length: > 0 } live)
                ApsStorage.SaveToken(live);
        }
        catch (Exception ex) when (
            allowAlbertRenew
            && (ex.Message.Contains("status non-OK: 02", StringComparison.OrdinalIgnoreCase)
                || ex.Message.Contains("ALPN non negoziato", StringComparison.OrdinalIgnoreCase)))
        {
            // Cert da Albert vecchio (ALUnbrick / RSA-2048) spesso → 0x02. Rinnova come pypush.
            Log?.Invoke(this,
                "Connect 0x02/ALPN — rinnovo Albert (deviceservices + RSA-1024) e riprovo…");
            try
            {
                try { System.IO.File.Delete(ApsStorage.TokenPath); } catch { /* ignore */ }
                await EnsureActivatedAsync(forceRenew: true, ct).ConfigureAwait(false);
                var (k2, c2) = ApsStorage.LoadCertificate();
                await _courier.ConnectAsync(k2, c2, existingToken: null, ct: ct).ConfigureAwait(false);
                _lastError = null;
                if (_courier.Token is { Length: > 0 } live2)
                    ApsStorage.SaveToken(live2);
            }
            catch (Exception ex2)
            {
                _lastError = ex2.Message;
                throw;
            }
        }
        catch (Exception ex)
        {
            _lastError = ex.Message;
            throw;
        }
    }

    public Task DisconnectAsync() => _courier.DisconnectAsync();

    public ValueTask DisposeAsync() => _courier.DisposeAsync();
}
