using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Auth;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Download;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services;

public sealed class ICloudBackupOrchestrator
{
    private readonly HttpClient _http;
    private readonly AuthAnisetteProviders _anisette;
    private readonly bool _useFullIphoneAuth;
    private readonly string _windowsDeviceUuid;
    private readonly SemaphoreSlim _reloginGate = new(1, 1);
    /// <summary>Evita deadlock: Relogin → Bootstrap → ckAppInit 401 non richiama Relogin.</summary>
    private int _insideRelogin;
    /// <summary>Soft refresh 401: ckAppInit reminta solo, senza Relogin (lo decide il caller).</summary>
    private int _softRefreshOnly;

    /// <summary>Credenziali in RAM per re-login mid-download (mmeAuthToken scaduto → 401).</summary>
    private string? _storedAppleId;
    private string? _storedPassword;

    /// <summary>
    /// Invocato quando Relogin mid-download richiede 2FA o la password è rifiutata (-22406).
    /// Deve completare Accesso/2FA in UI, assorbire i token nella <paramref name="liveSession"/>
    /// (es. <see cref="ApplyAuthenticatedSessionAsync"/>) e restituire true se riprendere.
    /// </summary>
    public Func<ICloudSession, SessionReloginException, IProgress<string>?, CancellationToken, Task<bool>>?
        InteractiveSessionRecovery
    { get; set; }

    public ICloudBackupOrchestrator(HttpClient http, AuthAnisetteProviders anisette, bool useFullIphoneAuth = false)
    {
        _http = http;
        _anisette = anisette;
        _useFullIphoneAuth = useFullIphoneAuth;
        _windowsDeviceUuid = new AnisetteDeviceStore(AdiDeviceProfile.Windows).GetOrCreateDeviceUuid();
    }

    public GsaGrandSlamAuthService CreateAuthService() => new(_http, _anisette, _useFullIphoneAuth);

    public bool HasStoredCredentials =>
        !string.IsNullOrWhiteSpace(_storedAppleId) && !string.IsNullOrEmpty(_storedPassword);

    public async Task<ICloudSession> CompleteSignInAsync(
        string appleId,
        string password,
        string? twoFactorCode,
        ICloudSession? partialSession,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var auth = CreateAuthService();
        auth.Progress += p => log?.Report($"{p.Step}: {p.Message}");

        AuthResult result;
        if (partialSession is not null && !string.IsNullOrWhiteSpace(twoFactorCode))
        {
            result = partialSession.TwoFactorMethod == TwoFactorMethod.Sms
                ? await auth.SubmitSmsCodeAsync(appleId, password, twoFactorCode, partialSession, ct)
                : await auth.SubmitTrustedDeviceCodeAsync(appleId, twoFactorCode, partialSession, ct);
        }
        else
        {
            result = await auth.SignInAsync(appleId, password, ct);
            if (result.Requires2Fa)
                throw new TwoFactorRequiredException(
                    result.Session!,
                    result.Error ?? "2FA richiesto.",
                    result.VerificationOptions);
        }

        if (!result.Success || result.Session is null)
            throw new InvalidOperationException(result.Error ?? "Autenticazione fallita.");

        RememberCredentials(appleId, password);
        var session = result.Session;
        await RefreshAnisetteAsync(session, ct);
        try
        {
            await BootstrapCloudKitAsync(session, log, ct);
        }
        catch (Exception ex)
        {
            throw new CloudKitBootstrapException(session, ex.Message, ex);
        }

        return session;
    }

    public async Task RequestSmsTwoFactorAsync(
        ICloudSession partialSession,
        int? phoneId = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var auth = CreateAuthService();
        auth.Progress += p => log?.Report($"{p.Step}: {p.Message}");
        await auth.RequestSmsCodeAsync(
            partialSession,
            phoneId ?? partialSession.SelectedPhoneId,
            ct);
    }

    public async Task<IReadOnlyList<BackupDevice>> ListBackupsAsync(
        ICloudSession session, IProgress<string>? log = null, CancellationToken ct = default)
    {
        await RefreshAnisetteAsync(session, ct);
        if (string.IsNullOrEmpty(session.CloudKitAuthToken))
            await FetchAccountSettingsAsync(session, null, ct);

        // Escrow KeySet e/o Manatee Octagon già su disco → seed per decrypt backupProperties.
        // Non forza recover live in fase lista.
        if (!PcsSessionSeedKeys.HasAny(session)
            && (!string.IsNullOrWhiteSpace(session.PcsKeysDirectory)
                || !string.IsNullOrWhiteSpace(session.OctagonKeysDirectory)))
        {
            try
            {
                var pcsDir = EscrowPcsSession.ResolvePcsKeysDirectory(
                    session.PcsKeysDirectory,
                    session.OctagonKeysDirectory);
                var ensure = await EscrowPcsSession.EnsureKeySetAsync(
                    session, _http, pcsDir, iCloudSecurityCode: null, sms: null, log, ct);
                if (!ensure.Success)
                    log?.Report($"PCS KeySet (lista): {ensure.Message} — backupProperties resterà cifrato");
            }
            catch (Exception ex)
            {
                log?.Report($"PCS KeySet (lista): {ex.Message}");
            }
        }

        var ck = new CloudKitBackupService(_http);
        byte[]? mbsManifest = null;
        try
        {
            mbsManifest = await new MobileBackupService(_http).GetAccountManifestAsync(session, ct);
        }
        catch (Exception ex)
        {
            log?.Report($"mbs manifest (pre-lista): {ex.Message}");
        }

        var devices = await ck.ListDevicesAsync(session, log, mbsManifest, ct);
        _lastBackupListService = ck;
        log?.Report($"CloudKit: trovati {devices.Count} dispositivi con backup");
        foreach (var d in devices)
        {
            log?.Report($"  {d.DisplayName ?? d.DeviceUuid} ({d.ProductType ?? "?"}) — {d.Snapshots.Count} snapshot");
        }

        try
        {
            if (mbsManifest is { Length: > 0 })
                LogMbsManifest(mbsManifest, log);
            else
                log?.Report("mbs manifest (post-lista): non disponibile");
        }
        catch (Exception ex)
        {
            log?.Report($"mbs manifest (post-lista): {ex.Message}");
        }

        return devices;
    }

    private CloudKitBackupService? _lastBackupListService;

    /// <summary>
    /// Decrypt <c>backupProperties</c> in background dopo la lista (PCS, thread pool).
    /// </summary>
    public Task<SnapshotBackupPropertiesDecryptor.DecryptSummary> DecryptListedBackupPropertiesAsync(
        ICloudSession session,
        IEnumerable<BackupDevice> devices,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        var ck = _lastBackupListService ?? new CloudKitBackupService(_http);
        return ck.DecryptBackupPropertiesAsync(session, devices, log, ct);
    }

    private static void LogMbsManifest(byte[]? manifest, IProgress<string>? log)
    {
        if (log is null)
            return;
        if (manifest is not { Length: > 0 })
        {
            log.Report("mbs manifest: (vuoto)");
            return;
        }

        log.Report($"mbs manifest: {manifest.Length} byte");
        if (manifest.Length <= 32)
        {
            var text = System.Text.Encoding.UTF8.GetString(manifest).Trim();
            if (!string.IsNullOrEmpty(text))
                log.Report($"  mbs> (minimale) {text}");
            return;
        }
        var strings = Protocol.ProtobufStringScanner.ExtractAsciiRuns(manifest, 3)
            .Where(s => s.Length is >= 3 and <= 200)
            .Distinct(StringComparer.Ordinal)
            .ToList();

        foreach (var s in strings.Where(s =>
                     s.StartsWith("A:", StringComparison.Ordinal) ||
                     s.StartsWith("MA:", StringComparison.Ordinal) ||
                     s.StartsWith("S:", StringComparison.Ordinal) ||
                     s.StartsWith("D:", StringComparison.Ordinal) ||
                     s.Contains("Zone", StringComparison.Ordinal) ||
                     s.Contains("Backup", StringComparison.Ordinal) ||
                     System.Text.RegularExpressions.Regex.IsMatch(s, "^[0-9A-Fa-f-]{36}$")))
            log.Report($"  mbs> {s}");
    }

    public async Task DownloadSnapshotAsync(
        ICloudSession session,
        DownloadJob job,
        IProgress<DownloadProgressReport>? progress = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        // Remint pesante (Frida) solo se OTP assente/stallo lungo; altrimenti Touch + retry su 401.
        var hardStale = !session.Anisette.HasMachineData
            || session.Anisette.IsClientTimeStale(TimeSpan.FromMinutes(12));
        if (hardStale)
        {
            log?.Report("  remint Anisette prima di ckAppInit (OTP assente/stallo)…");
            await RefreshAnisetteAsync(session, ct, forceRemint: true);
        }
        else
        {
            log?.Report("  reuse Anisette sessione prima di ckAppInit…");
            await RefreshAnisetteAsync(session, ct, forceRemint: false);
        }

        await EnsureCloudKitSessionAsync(session, log, ct);

        // Mid-download: soft = Anisette touch; 401 = re-login GrandSlam + ckAppInit (se password in RAM).
        var downloader = new BackupDownloadService(_http, RefreshAnisetteOnlyAsync);
        await downloader.DownloadSnapshotAsync(session, job, progress, log, ct)
            .ConfigureAwait(false);
    }

    /// <summary>
    /// Refresh mid-download. Soft: Client-Time. Su 401 (<paramref name="forceRemint"/>):
    /// 1) remint Anisette + ckAppInit (senza GrandSlam);
    /// 2) Relogin GrandSlam se soft fallisce e password in RAM;
    /// 3) <see cref="InteractiveSessionRecovery"/> se Relogin chiede 2FA / -22406.
    /// </summary>
    public async Task RefreshAnisetteOnlyAsync(
        ICloudSession session,
        IProgress<string>? log = null,
        CancellationToken ct = default,
        bool forceRemint = false)
    {
        if (!forceRemint)
        {
            log?.Report("  reuse Anisette sessione (no ckAppInit)…");
            await RefreshAnisetteAsync(session, ct, forceRemint: false).ConfigureAwait(false);
            return;
        }

        // Soft first: remint OTP + ckAppInit con token già in sessione (no SRP).
        try
        {
            log?.Report("  soft refresh 401: remint Anisette + ckAppInit…");
            Interlocked.Exchange(ref _softRefreshOnly, 1);
            try
            {
                await RefreshAnisetteAsync(session, ct, forceRemint: true).ConfigureAwait(false);
                await BootstrapCloudKitAsync(session, log, ct).ConfigureAwait(false);
            }
            finally
            {
                Interlocked.Exchange(ref _softRefreshOnly, 0);
            }

            log?.Report("  soft refresh 401 OK.");
            return;
        }
        catch (Exception softEx)
        {
            log?.Report($"  soft refresh 401 fallito: {softEx.Message}");
        }

        if (!HasStoredCredentials)
        {
            throw new InvalidOperationException(
                "Refresh 401: soft fallito e password non in RAM — rifare Accesso dalla UI.");
        }

        try
        {
            await ReloginIntoSessionAsync(session, log, ct).ConfigureAwait(false);
        }
        catch (SessionReloginException reloginEx)
            when (reloginEx.Kind is SessionReloginKind.Requires2Fa
                or SessionReloginKind.PasswordRejected)
        {
            var handler = InteractiveSessionRecovery;
            if (handler is null)
                throw;

            log?.Report($"  Relogin richiede intervento UI ({reloginEx.Kind})…");
            var ok = await handler(session, reloginEx, log, ct).ConfigureAwait(false);
            if (!ok)
            {
                throw new InvalidOperationException(
                    "Recupero sessione mid-download annullato o fallito.",
                    reloginEx);
            }
        }
    }

    /// <summary>
    /// Dopo Escrow recover (bottle PIN / iCDP) il <c>mmeAuthToken</c> spesso non è più
    /// accettato da <c>ckAppInit</c> (HTTP 401 su <c>com.apple.security.keychain</c>)
    /// finché non si rifà GrandSlam. Preferire Relogin proattivo invece di attendere il 401.
    /// Preserva campi Octagon/PCS già in sessione (<see cref="AbsorbAuthIntoSession"/>).
    /// </summary>
    public async Task EnsureFreshCloudKitAfterEscrowAsync(
        ICloudSession session,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (HasStoredCredentials)
        {
            log?.Report(
                "  refresh sessione post-Escrow (GrandSlam) — evita ckAppInit 401 su Cuttlefish…");
            await ReloginIntoSessionAsync(session, log, ct).ConfigureAwait(false);
            return;
        }

        log?.Report(
            "  WARN: password non in RAM dopo Escrow — ckAppInit può rispondere 401; " +
            "se fallisce, rifai Accesso e poi «OTBottle / Peer».");
        await RefreshAnisetteAsync(session, ct, forceRemint: false).ConfigureAwait(false);
    }

    /// <summary>
    /// GsService2 + authenticate + ckAppInit sulla stessa istanza sessione
    /// (preserva PCS/Octagon/Manatee). Usato quando Apple risponde 401 mid-download.
    /// </summary>
    public async Task ReloginIntoSessionAsync(
        ICloudSession session,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (!HasStoredCredentials)
            throw new InvalidOperationException(
                "Re-login mid-download: password non in RAM — rifare Accesso dalla UI.");

        await _reloginGate.WaitAsync(ct).ConfigureAwait(false);
        Interlocked.Exchange(ref _insideRelogin, 1);
        try
        {
            log?.Report("  re-login GrandSlam (sessione scaduta / 401)…");
            var auth = CreateAuthService();
            auth.Progress += p => log?.Report($"  {p.Step}: {p.Message}");

            var result = await auth.SignInAsync(_storedAppleId!, _storedPassword!, ct)
                .ConfigureAwait(false);

            if (result.Requires2Fa && result.Session is not null)
            {
                throw new SessionReloginException(
                    SessionReloginKind.Requires2Fa,
                    result.Error ?? "Re-login mid-download richiede 2FA.",
                    result.Session,
                    result.VerificationOptions);
            }

            if (!result.Success || result.Session is null)
            {
                var msg = result.Error ?? "Re-login mid-download fallito.";
                throw new SessionReloginException(
                    LooksLikePasswordRejected(msg)
                        ? SessionReloginKind.PasswordRejected
                        : SessionReloginKind.Other,
                    msg);
            }

            AbsorbAuthIntoSession(session, result.Session);
            log?.Report(
                "  re-login OK — token aggiornati (PCS/Octagon invariati), ckAppInit…");
            await BootstrapCloudKitAsync(session, log, ct).ConfigureAwait(false);
            log?.Report("  sessione CloudKit rinnovata.");
        }
        finally
        {
            Interlocked.Exchange(ref _insideRelogin, 0);
            _reloginGate.Release();
        }
    }

    /// <summary>
    /// Dopo Accesso/2FA interattivo mid-download: assorbe i token freschi nella sessione live
    /// e rifà ckAppInit (PCS/Octagon invariati).
    /// </summary>
    public async Task ApplyAuthenticatedSessionAsync(
        ICloudSession liveSession,
        ICloudSession authenticated,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        AbsorbAuthIntoSession(liveSession, authenticated);
        log?.Report("  sessione live aggiornata da Accesso/2FA — ckAppInit…");
        await BootstrapCloudKitAsync(liveSession, log, ct).ConfigureAwait(false);
        log?.Report("  sessione CloudKit rinnovata (UI).");
    }

    private static bool LooksLikePasswordRejected(string message) =>
        message.Contains("-22406", StringComparison.Ordinal)
        || message.Contains("incorrect", StringComparison.OrdinalIgnoreCase);

    private void RememberCredentials(string appleId, string password)
    {
        _storedAppleId = appleId.Trim();
        _storedPassword = password;
    }

    /// <summary>
    /// Copia token/auth da un login fresco nella sessione live del download.
    /// Non tocca KeySet PCS, Manatee, Octagon, preferred KeyId.
    /// </summary>
    internal static void AbsorbAuthIntoSession(ICloudSession live, ICloudSession fresh)
    {
        live.AppleId = fresh.AppleId;
        if (!string.IsNullOrEmpty(fresh.Dsid))
            live.Dsid = fresh.Dsid;
        if (!string.IsNullOrEmpty(fresh.Partition))
            live.Partition = fresh.Partition;

        live.Anisette = fresh.Anisette;
        live.MobileMeAuthToken = fresh.MobileMeAuthToken;
        live.CloudKitAuthToken = fresh.CloudKitAuthToken;
        live.CloudKitUserId = fresh.CloudKitUserId;
        live.CloudKitGsToken = fresh.CloudKitGsToken;
        live.PeToken = fresh.PeToken;
        live.GsToken = fresh.GsToken;
        live.GsICloudAuthToken = fresh.GsICloudAuthToken;
        live.IdentityToken = fresh.IdentityToken;
        live.Adsid = fresh.Adsid;
        live.GsIdmsToken = fresh.GsIdmsToken;
        live.AppleCloudKitContext = fresh.AppleCloudKitContext;
        live.CloudKitGatewayUrl = fresh.CloudKitGatewayUrl;
        live.EscrowProxyUrl = fresh.EscrowProxyUrl;
        live.MmeFmfAppToken = fresh.MmeFmfAppToken;
        live.MmeFmfToken = fresh.MmeFmfToken;
        live.MmeFmipToken = fresh.MmeFmipToken;
        live.SearchPartyToken = fresh.SearchPartyToken;
        live.IdmsaTrustToken = fresh.IdmsaTrustToken ?? live.IdmsaTrustToken;

        if (fresh.GsServiceTokens.Count > 0)
            live.GsServiceTokens = new Dictionary<string, string>(fresh.GsServiceTokens);
        if (fresh.AvailableDataclasses.Count > 0)
            live.AvailableDataclasses = fresh.AvailableDataclasses;
        if (fresh.DataclassServiceUrls.Count > 0)
        {
            live.DataclassServiceUrls =
                new Dictionary<string, string>(fresh.DataclassServiceUrls, StringComparer.OrdinalIgnoreCase);
        }
    }

    /// <summary>Rinfresca ckAppInit prima del restore (token CloudKit per gateway).</summary>
    public async Task EnsureCloudKitSessionAsync(
        ICloudSession session,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        await BootstrapCloudKitAsync(session, log, ct);
    }

    /// <summary>
    /// Policy Anisette post-login:
    /// <list type="bullet">
    /// <item>forceRemint=false → riusa MD/MD-M in sessione, aggiorna solo Client-Time se stallo</item>
    /// <item>forceRemint=true → mint fresco (ForceFresh) — anti -22410 / OTP morto</item>
    /// </list>
    /// </summary>
    private async Task RefreshAnisetteAsync(
        ICloudSession session,
        CancellationToken ct,
        bool forceRemint = false)
    {
        if (!forceRemint && session.Anisette.TryReuseTouchingClientTime())
            return;

        var opts = forceRemint
            ? AnisetteFetchOptions.ForGrandSlamLogin(session.AppleId)
            : AnisetteFetchOptions.ForAppleId(session.AppleId);
        session.Anisette = await _anisette.Ios
            .FetchAsync(opts, ct)
            .ConfigureAwait(false);
    }

    private async Task BootstrapCloudKitAsync(ICloudSession session, IProgress<string>? log, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(session.CloudKitAuthToken))
            await FetchAccountSettingsAsync(session, log, ct);

        if (string.IsNullOrEmpty(session.CloudKitAuthToken))
        {
            throw new InvalidOperationException(
                "Manca cloudKitToken per ckAppInit. " +
                "In hybrid serve get_account_settings dopo authenticate; " +
                "in flow iPhone arriva da GsService2/validate (X-Apple-GS-Token cloudkit.auth).");
        }

        static string Prefix(string? t) => string.IsNullOrEmpty(t)
            ? "(vuoto)"
            : $"{t[..Math.Min(4, t.Length)]}…(len={t.Length})";
        log?.Report($"ckAppInit container={CloudKitContainerBinding.Backup.ContainerId}… dsid={session.Dsid} "
                    + $"mmeToken={Prefix(session.MobileMeAuthToken)} ckGs={Prefix(session.CloudKitGsToken)} "
                    + $"ckToken={Prefix(session.CloudKitAuthToken)} ckUser={(string.IsNullOrEmpty(session.CloudKitUserId) ? "(vuoto)" : "presente")}");
        await SendCkAppInitAsync(session, CloudKitContainerBinding.Backup.ContainerId, log, ct);

        if (string.IsNullOrEmpty(session.CloudKitUserId))
            throw new InvalidOperationException("ckAppInit senza cloudKitUserId.");
    }

    /// <summary>
    /// ckAppInit per un container arbitrario. Sovrascrive <see cref="ICloudSession.CloudKitAuthToken"/> /
    /// <see cref="ICloudSession.CloudKitUserId"/> con valori scoped al container.
    /// </summary>
    public Task CkAppInitAsync(
        ICloudSession session,
        string containerId,
        IProgress<string>? log = null,
        CancellationToken ct = default) =>
        SendCkAppInitAsync(session, containerId, log, ct);

    private async Task SendCkAppInitAsync(
        ICloudSession session,
        string containerId,
        IProgress<string>? log,
        CancellationToken ct)
    {
        for (var attempt = 0; attempt < 2; attempt++)
        {
            var status = await TrySendCkAppInitAsync(session, containerId, log, ct)
                .ConfigureAwait(false);
            if (status == 200)
                return;

            if (status == 401 && attempt == 0)
            {
                // Soft refresh / Relogin interno: solo remint (il caller gestisce Relogin/UI).
                // Non richiamare Relogin da dentro Relogin (gate → deadlock).
                if (HasStoredCredentials
                    && Volatile.Read(ref _insideRelogin) == 0
                    && Volatile.Read(ref _softRefreshOnly) == 0)
                {
                    log?.Report(
                        $"ckAppInit({containerId}) HTTP 401 — re-login GrandSlam e retry…");
                    await ReloginIntoSessionAsync(session, log, ct).ConfigureAwait(false);
                    // Relogin ha già fatto ckAppInit: se OK siamo a posto al continue.
                    continue;
                }

                log?.Report(
                    $"ckAppInit({containerId}) HTTP 401 — remint Anisette (OTP) e retry…");
                await RefreshAnisetteAsync(session, ct, forceRemint: true).ConfigureAwait(false);
                continue;
            }

            throw new InvalidOperationException(
                status == 401
                    ? $"ckAppInit({containerId}) HTTP 401 dopo recovery. "
                      + "mmeAuthToken scaduto — rifare Accesso (login)."
                    : $"ckAppInit({containerId}) HTTP {status}.");
        }
    }

    /// <returns>200 ok, altrimenti status HTTP (nessuna exception su 4xx/5xx).</returns>
    private async Task<int> TrySendCkAppInitAsync(
        ICloudSession session,
        string containerId,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var encoded = Uri.EscapeDataString(containerId);
        using var request = new HttpRequestMessage(HttpMethod.Post,
            $"https://setup.icloud.com/setup/ck/v1/ckAppInit?container={encoded}");
        request.Content = new ByteArrayContent(Array.Empty<byte>());
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-protobuf");
        // akd: ckAppInit e getQuotaInfo usano lo STESSO token dsid:mmeAuthToken
        // (blob \x10\x00… che incorpora gs.icloud.auth). Non il cloudKitToken né cloudkit.auth.
        var ckAuthToken = !string.IsNullOrEmpty(session.MobileMeAuthToken)
            ? session.MobileMeAuthToken
            : !string.IsNullOrEmpty(session.CloudKitGsToken)
                ? session.CloudKitGsToken
                : session.CloudKitAuthToken;
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            AppleHttpExtensions.BasicAuth(session.Dsid, ckAuthToken));
        request.ApplyAuthKitIphoneGsHeaders(session.Anisette);
        request.Headers.TryAddWithoutValidation("Accept", "*/*");

        using var response = await _http.SendAsync(request, ct);
        if (!response.IsSuccessStatusCode)
        {
            var errorBody = await response.Content.ReadAsStringAsync(ct);
            var debug = response.Headers.TryGetValues("X-Apple-Request-Debug", out var dbg)
                ? string.Join(",", dbg)
                : string.Empty;
            log?.Report($"ckAppInit({containerId}) HTTP {(int)response.StatusCode}"
                        + (string.IsNullOrEmpty(debug) ? "" : $" ({debug})")
                        + (string.IsNullOrWhiteSpace(errorBody) ? "" : $" body={errorBody.Trim()}"));
            return (int)response.StatusCode;
        }

        if (response.Headers.TryGetValues("x-apple-user-partition", out var partitionValues))
        {
            var partition = partitionValues.First();
            session.Partition = partition.StartsWith('p') ? partition : $"p{partition}";
        }

        var body = await response.Content.ReadAsByteArrayAsync(ct);
        if (!TryParseCkAppInitJson(session, body))
            CloudKitBackupService.ParseCkAppInitProtobuf(session, body);
        return 200;
    }

    private async Task FetchAccountSettingsAsync(
        ICloudSession session,
        IProgress<string>? log,
        CancellationToken ct)
    {
        if (string.IsNullOrEmpty(session.Dsid))
            throw new InvalidOperationException("Manca dsid per get_account_settings.");

        var mmeSecret = session.MobileMeAuthToken;
        if (string.IsNullOrEmpty(mmeSecret) && !string.IsNullOrEmpty(session.GsICloudAuthToken))
            mmeSecret = GsaGrandSlamAuthService.ExtractGsICloudAuthPasswordForBootstrap(session.GsICloudAuthToken);
        if (string.IsNullOrEmpty(mmeSecret) && !string.IsNullOrEmpty(session.CloudKitGsToken))
            mmeSecret = session.CloudKitGsToken;
        if (string.IsNullOrEmpty(mmeSecret))
            throw new InvalidOperationException("Manca mmeAuthToken / gs.icloud.auth per get_account_settings.");

        log?.Report("get_account_settings…");

        var auth = new AccountSettingsAuth(session.Dsid, mmeSecret, "dsid:mmeAuthToken");

        if (!_useFullIphoneAuth)
        {
            var windowsAnisette = await _anisette.Windows.FetchAsync(ct);
            if (await TryAccountSettingsRequestAsync(
                    session,
                    HttpMethod.Get,
                    "https://setup.icloud.com/setup/get_account_settings",
                    useCloudKitDaemon: false,
                    auth,
                    windowsAnisette,
                    authKitWin: true,
                    ct,
                    log))
            {
                if (!string.IsNullOrEmpty(session.CloudKitAuthToken))
                    log?.Report("get_account_settings OK — cloudKitToken ricevuto (AuthKitWin).");
                else
                    log?.Report("get_account_settings OK — senza cloudKitToken nel plist.");
                if (!string.IsNullOrWhiteSpace(session.EscrowProxyUrl))
                    log?.Report($"  escrowProxyUrl → {session.EscrowProxyUrl}");
                return;
            }
        }

        if (await TryAccountSettingsRequestAsync(
                session,
                HttpMethod.Get,
                "https://setup.icloud.com/setup/get_account_settings",
                useCloudKitDaemon: _useFullIphoneAuth,
                auth,
                session.Anisette,
                authKitWin: false,
                ct,
                log))
        {
            if (!string.IsNullOrEmpty(session.CloudKitAuthToken))
                log?.Report("get_account_settings OK — cloudKitToken ricevuto.");
            else
                log?.Report("get_account_settings OK — senza cloudKitToken nel plist.");
            if (!string.IsNullOrWhiteSpace(session.EscrowProxyUrl))
                log?.Report($"  escrowProxyUrl → {session.EscrowProxyUrl}");
            return;
        }

        if (!string.IsNullOrEmpty(session.PeToken))
        {
            var pe = DecodePeToken(session.PeToken);
            if (!string.IsNullOrEmpty(pe)
                && await TryAccountSettingsRequestAsync(
                    session,
                    HttpMethod.Get,
                    "https://setup.icloud.com/setup/get_account_settings",
                    useCloudKitDaemon: _useFullIphoneAuth,
                    new AccountSettingsAuth(session.Dsid, pe, "dsid:peToken"),
                    session.Anisette,
                    authKitWin: false,
                    ct,
                    log))
            {
                if (!string.IsNullOrWhiteSpace(session.EscrowProxyUrl))
                    log?.Report($"  escrowProxyUrl → {session.EscrowProxyUrl}");
                return;
            }
        }

        throw new InvalidOperationException("get_account_settings fallito — impossibile ottenere cloudKitToken.");
    }

    private async Task<bool> TryAccountSettingsRequestAsync(
        ICloudSession session,
        HttpMethod method,
        string url,
        bool useCloudKitDaemon,
        AccountSettingsAuth auth,
        AnisetteHeaders anisette,
        bool authKitWin,
        CancellationToken ct,
        IProgress<string>? log = null)
    {
        using var request = new HttpRequestMessage(method, url);
        if (method == HttpMethod.Post)
            request.Content = new ByteArrayContent(Array.Empty<byte>());

        request.Headers.Authorization = new AuthenticationHeaderValue("Basic",
            AppleHttpExtensions.BasicAuth(auth.User, auth.Secret));
        request.Headers.TryAddWithoutValidation("Accept",
            useCloudKitDaemon ? "*/*" : "application/xml, text/xml, */*");
        if (useCloudKitDaemon)
        {
            request.ApplyCloudKitDaemon(acceptStar: true);
            // setup.icloud.com risponde 409 MISS_HDR_ANISETTE senza header OTP.
            request.ApplyAnisetteHeaders(anisette, iosRouting: _useFullIphoneAuth);
            if (!string.IsNullOrEmpty(anisette.MdLu))
                request.Headers.TryAddWithoutValidation("X-Apple-I-MD-LU", anisette.MdLu);
        }
        else if (authKitWin)
        {
            request.ApplyWindowsAuthKitHeaders(anisette, _windowsDeviceUuid);
        }
        else
        {
            request.ApplyAuthKitIphoneGsHeaders(anisette);
        }

        if (!string.IsNullOrEmpty(session.AppleCloudKitContext))
            request.Headers.TryAddWithoutValidation("X-Apple-I-CK", session.AppleCloudKitContext);

        using var response = await _http.SendAsync(request, ct);
        if (response.Headers.TryGetValues("x-apple-user-partition", out var partitionValues))
        {
            var partition = partitionValues.First();
            session.Partition = partition.StartsWith('p') ? partition : $"p{partition}";
        }

        var body = await response.Content.ReadAsByteArrayAsync(ct);
        if (!response.IsSuccessStatusCode)
        {
            var debug = response.Headers.TryGetValues("X-Apple-Request-Debug", out var dbg)
                ? string.Join(",", dbg)
                : string.Empty;
            log?.Report($"get_account_settings [{auth.Label}] HTTP {(int)response.StatusCode}"
                        + (string.IsNullOrEmpty(debug) ? "" : $" ({debug})"));
            return false;
        }

        ParseAccountSettingsPlist(session, body);
        return true;
    }

    private readonly record struct AccountSettingsAuth(string User, string Secret, string Label);

    private static void ParseAccountSettingsPlist(ICloudSession session, byte[] body)
    {
        if (body.Length == 0 || !LooksLikeXml(body))
            return;

        var root = AppleXmlPlist.Parse(body);
        if (root.TryGetValue("tokens", out var tokens) && tokens is Dictionary<string, object?> tokenDict)
            ApplyTokenDict(session, tokenDict);

        if (root.TryGetValue("com.apple.mobileme", out var mobileMe)
            && mobileMe is Dictionary<string, object?> mobileMeDict)
        {
            if (mobileMeDict.TryGetValue("tokens", out var mmeTokens)
                && mmeTokens is Dictionary<string, object?> mmeTokenDict)
            {
                ApplyTokenDict(session, mmeTokenDict);
            }

            AccountSettingsApply.ApplyMobileMeDict(session, mobileMeDict);
            TryExtractEscrowProxyUrl(session, mobileMeDict);
        }

        // A volte KeychainSync è top-level, non sotto mobileme.
        TryExtractEscrowProxyUrl(session, root);
        // Dataclass top-level (raro): unisci URL se non già sotto mobileme.
        CollectTopLevelDataclassUrls(session, root);
        ExtractCloudKitTokensRecursive(session, root);
    }

    private static void CollectTopLevelDataclassUrls(
        ICloudSession session,
        Dictionary<string, object?> root)
    {
        var extra = AccountSettingsApply.CollectServiceUrls(root);
        if (extra.Count == 0)
            return;
        foreach (var (k, v) in extra)
            session.DataclassServiceUrls.TryAdd(k, v);

        if (session.AvailableDataclasses.Count == 0)
        {
            session.AvailableDataclasses =
                AccountSettingsApply.CollectAvailableDataclasses(root);
        }
    }

    private static void TryExtractEscrowProxyUrl(ICloudSession session, Dictionary<string, object?> root)
    {
        if (!string.IsNullOrWhiteSpace(session.EscrowProxyUrl))
            return;

        if (root.TryGetValue("com.apple.Dataclass.KeychainSync", out var keychain)
            && keychain is Dictionary<string, object?> keychainDict
            && keychainDict.TryGetValue("escrowProxyUrl", out var urlObj)
            && urlObj is string url
            && !string.IsNullOrWhiteSpace(url))
        {
            session.EscrowProxyUrl = url.TrimEnd('/');
            return;
        }

        // Fallback: qualsiasi stringa *escrowproxy.icloud.com*
        FindEscrowUrlRecursive(session, root);
    }

    private static void FindEscrowUrlRecursive(ICloudSession session, object? node)
    {
        if (!string.IsNullOrWhiteSpace(session.EscrowProxyUrl))
            return;

        switch (node)
        {
            case Dictionary<string, object?> dict:
                foreach (var value in dict.Values)
                    FindEscrowUrlRecursive(session, value);
                break;
            case IList<object?> list:
                foreach (var item in list)
                    FindEscrowUrlRecursive(session, item);
                break;
            case string text
                when text.Contains("escrowproxy.icloud.com", StringComparison.OrdinalIgnoreCase):
                session.EscrowProxyUrl = text.TrimEnd('/');
                break;
        }
    }

    private static void ExtractCloudKitTokensRecursive(ICloudSession session, object? node)
    {
        if (string.IsNullOrEmpty(session.CloudKitAuthToken) && node is Dictionary<string, object?> dict)
        {
            foreach (var value in dict.Values)
            {
                if (value is string text && (text.StartsWith("EAM", StringComparison.Ordinal)
                                             || text.StartsWith("EAAr", StringComparison.Ordinal)))
                {
                    session.CloudKitAuthToken = text;
                    return;
                }
            }

            foreach (var value in dict.Values)
                ExtractCloudKitTokensRecursive(session, value);
        }
        else if (node is List<object?> list)
        {
            foreach (var item in list)
                ExtractCloudKitTokensRecursive(session, item);
        }
    }

    private static void ApplyTokenDict(ICloudSession session, Dictionary<string, object?> tokenDict)
    {
        if (tokenDict.TryGetValue("cloudKitToken", out var ck)
            && ck is string ckToken
            && !string.IsNullOrEmpty(ckToken))
        {
            session.CloudKitAuthToken = ckToken;
        }

        if (tokenDict.TryGetValue("mmeAuthToken", out var mme)
            && mme is string mmeToken
            && !string.IsNullOrEmpty(mmeToken))
        {
            session.MobileMeAuthToken = mmeToken;
        }

        if (tokenDict.TryGetValue("mmeFMFAppToken", out var fmfApp)
            && fmfApp is string fmfAppTok
            && !string.IsNullOrEmpty(fmfAppTok))
        {
            session.MmeFmfAppToken = fmfAppTok;
        }

        if (tokenDict.TryGetValue("mmeFMFToken", out var fmf)
            && fmf is string fmfTok
            && !string.IsNullOrEmpty(fmfTok))
        {
            session.MmeFmfToken = fmfTok;
        }

        if (tokenDict.TryGetValue("mmeFMIPToken", out var fmip)
            && fmip is string fmipTok
            && !string.IsNullOrEmpty(fmipTok))
        {
            session.MmeFmipToken = fmipTok;
        }
    }

    private static bool TryParseCkAppInitJson(ICloudSession session, byte[] body)
    {
        if (!LooksLikeJson(body))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(body);
            var root = doc.RootElement;
            if (root.TryGetProperty("cloudKitUserId", out var userId))
                session.CloudKitUserId = userId.GetString() ?? session.CloudKitUserId;
            if (root.TryGetProperty("cloudKitToken", out var token))
                session.CloudKitAuthToken = token.GetString() ?? session.CloudKitAuthToken;
            if (root.TryGetProperty("cloudKitDatabaseGatewayUrl", out var gateway))
                session.CloudKitGatewayUrl = gateway.GetString() ?? session.CloudKitGatewayUrl;
            // appleservices / cuttlefish: cloudKitDatabaseUrl
            if (root.TryGetProperty("cloudKitDatabaseUrl", out var dbUrl)
                && dbUrl.GetString() is { Length: > 0 } url)
            {
                session.CloudKitGatewayUrl = url;
            }

            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool LooksLikeJson(ReadOnlySpan<byte> body)
    {
        var text = Encoding.UTF8.GetString(body).TrimStart();
        return text.StartsWith('{') || text.StartsWith('[');
    }

    private static bool LooksLikeXml(ReadOnlySpan<byte> body)
    {
        var text = Encoding.UTF8.GetString(body).TrimStart();
        return text.StartsWith("<?xml", StringComparison.Ordinal)
               || text.StartsWith("<plist", StringComparison.Ordinal)
               || text.StartsWith("<dict", StringComparison.Ordinal);
    }

    private static string DecodePeToken(string? encoded)
    {
        if (string.IsNullOrEmpty(encoded))
            return string.Empty;
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
            var colon = decoded.IndexOf(':');
            return colon >= 0 ? decoded[(colon + 1)..] : decoded;
        }
        catch
        {
            return encoded;
        }
    }
}

public sealed class TwoFactorRequiredException : Exception
{
    public ICloudSession PartialSession { get; }
    public PhoneVerificationOptions? VerificationOptions { get; }

    public TwoFactorRequiredException(
        ICloudSession partialSession,
        string message,
        PhoneVerificationOptions? verificationOptions = null) : base(message)
    {
        PartialSession = partialSession;
        VerificationOptions = verificationOptions;
    }
}

public enum SessionReloginKind
{
    Requires2Fa,
    PasswordRejected,
    Other
}

/// <summary>Esito tipizzato di <see cref="ICloudBackupOrchestrator.ReloginIntoSessionAsync"/>.</summary>
public sealed class SessionReloginException : Exception
{
    public SessionReloginKind Kind { get; }
    public ICloudSession? PartialSession { get; }
    public PhoneVerificationOptions? VerificationOptions { get; }

    public SessionReloginException(
        SessionReloginKind kind,
        string message,
        ICloudSession? partialSession = null,
        PhoneVerificationOptions? verificationOptions = null,
        Exception? inner = null)
        : base(message, inner)
    {
        Kind = kind;
        PartialSession = partialSession;
        VerificationOptions = verificationOptions;
    }
}
