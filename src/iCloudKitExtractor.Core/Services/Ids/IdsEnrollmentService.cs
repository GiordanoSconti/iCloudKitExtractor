using System.IO;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Auth;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Pipeline enroll IDS: delegate → authenticateDS → handles → id-register
/// (multiplex1/FMF and/or Madrid).
/// </summary>
public sealed class IdsEnrollmentService
{
    private readonly HttpClient _http;
    private readonly IAnisetteProvider _anisette;

    public IdsEnrollmentService(HttpClient http, IAnisetteProvider anisette)
    {
        _http = http;
        _anisette = anisette;
    }

    public Task<string> EnrollAsync(ICloudSession session, CancellationToken ct = default) =>
        EnrollCoreAsync(session, IdsRegisterServiceKind.FindMyMultiplex, ct);

    /// <summary>Register <c>com.apple.madrid</c> IDS identity for iMessage.</summary>
    public Task<string> EnrollMadridAsync(ICloudSession session, CancellationToken ct = default) =>
        EnrollCoreAsync(session, IdsRegisterServiceKind.Madrid, ct);

    private async Task<string> EnrollCoreAsync(
        ICloudSession session,
        IdsRegisterServiceKind serviceKind,
        CancellationToken ct)
    {
        var logLines = new List<string>();
        void Log(string msg)
        {
            logLines.Add(msg);
            Progress?.Invoke(this, msg);
        }

        try
        {
            var pushToken = ApsStorage.TryLoadToken();
            if (pushToken is null || pushToken.Length == 0)
                throw new InvalidOperationException(
                    "APS push token missing — run Albert activation + Connect APS before IDS enroll.");
            if (!ApsStorage.HasCertificate())
                throw new InvalidOperationException("APS certificate missing — run Albert activation.");

            string? overridePushKey = null;
            string? overridePushCert = null;
            if (serviceKind == IdsRegisterServiceKind.Madrid)
            {
                Log(IphoneApsPushStore.FormatStatusSummary());
                var iphone = IphoneIdsIdentityStore.TryLoad();
                var iphonePush = IphoneApsPushStore.TryLoad();
                Log(
                    $"Madrid push resolve: identity={(iphone is null ? "no" : "yes")} "
                    + $"pushPem={(iphonePush is null ? "no" : "yes")} "
                    + $"tokenHexLen={iphone?.PushTokenHex?.Length ?? 0} "
                    + $"certExists={File.Exists(IphoneApsPushStore.CertPemPath)} "
                    + $"keyExists={File.Exists(IphoneApsPushStore.KeyPemPath)}");
                if (iphonePush is not null
                    && iphone?.PushTokenHex is { Length: >= 32 } hex)
                {
                    try
                    {
                        var phoneTok = Convert.FromHexString(hex.Trim());
                        if (phoneTok.Length >= 16)
                        {
                            pushToken = phoneTok;
                            overridePushKey = iphonePush.Value.KeyPem;
                            overridePushCert = iphonePush.Value.CertPem;
                            Log(
                                "APS: using Frida iPhone push token + APSClientIdentity "
                                + $"(hex={ApsStorage.TokenHex(pushToken)[..Math.Min(16, ApsStorage.TokenHex(pushToken).Length)]}…)");
                        }
                    }
                    catch (Exception ex)
                    {
                        Log("APS: iPhone push token parse failed — " + ex.Message);
                    }
                }
            }

            if (overridePushKey is null)
            {
                Log(
                    $"APS token (Albert) len={pushToken.Length} hex={ApsStorage.TokenHex(pushToken)[..Math.Min(16, ApsStorage.TokenHex(pushToken).Length)]}…");
            }

            Log($"IDS enroll target: {serviceKind}");

            var bag = new IdsBag(_http);
            await bag.EnsureLoadedAsync(ct).ConfigureAwait(false);
            var snap = await bag.SnapshotAsync(ct).ConfigureAwait(false);
            Log($"IDS bag id-get-handles={snap.GetValueOrDefault("id-get-handles")}");

            var delegateLogin = new IdsDelegateLogin(_http, _anisette);
            var del = await delegateLogin.ObtainAsync(session, Log, ct).ConfigureAwait(false);
            Log($"Delegate OK via {del.Source}: profile={del.ProfileId}");

            var auth = new IdsAuthenticateDs(_http, bag);
            var (authKeyPem, authCertPem) = await auth
                .AuthenticateAsync(del.ProfileId, del.AuthToken, Log, ct)
                .ConfigureAwait(false);

            var register = new IdsRegisterClient(_http, bag);
            var handles = await register
                .GetHandlesAsync(
                    del.ProfileId, authKeyPem, authCertPem, pushToken, Log, ct,
                    overridePushKey, overridePushCert)
                .ConfigureAwait(false);
            Log($"Handles: {string.Join(", ", handles)}");

            var identity = IdsIdentity.LoadOrCreate();
            var anisette = await _anisette.FetchAsync(ct).ConfigureAwait(false);
            anisette.TouchClientTimeUtc();

            Log(MadridDevicePersona.FormatStatusSummary());
            Log(IphoneIdsIdentityStore.FormatStatusSummary());
            Log(IphoneApsPushStore.FormatStatusSummary());
            Log(IdsValidationDataStore.FormatStatusSummary());
            if (serviceKind == IdsRegisterServiceKind.Madrid
                && !MadridDevicePersona.HasPersona()
                && !IdsValidationDataStore.HasBlob())
            {
                Log("WARNING: Madrid without Mac persona or Frida validation-data — Apple often returns 6009.");
            }

            if (serviceKind == IdsRegisterServiceKind.Madrid
                && IdsValidationDataStore.HasBlob()
                && !IphoneApsPushStore.HasCredentials())
            {
                Log(
                    "WARNING: Frida validation-data without iPhone APS cert/key — "
                    + "x-push-sig stays Albert → likely 6009. Run fetch_aps_push_identity.py");
            }

            if (serviceKind == IdsRegisterServiceKind.Madrid)
            {
                var fridaId = IphoneIdsIdentityStore.TryLoad();
                if (fridaId is not null)
                {
                    if (fridaId.HasMadrid is not true)
                    {
                        Log(
                            "WARNING: Frida register had NO com.apple.madrid "
                            + $"(services={string.Join(",", fridaId.Services ?? [])}). "
                            + "That validation-data is FaceTime/alloy — Apple often returns 6009 for Madrid.");
                    }

                    var fridaMail = (fridaId.Uris ?? [])
                        .Where(u => u.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                        .Select(u => u["mailto:".Length..].Trim())
                        .Where(s => s.Length > 0)
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);
                    var winMail = handles
                        .Where(u => u.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                        .Select(u => u["mailto:".Length..].Trim())
                        .ToHashSet(StringComparer.OrdinalIgnoreCase);
                    if (fridaMail.Count > 0 && winMail.Count > 0 && !fridaMail.Overlaps(winMail))
                    {
                        Log(
                            "WARNING: Frida Apple ID uris=["
                            + string.Join(", ", fridaMail)
                            + "] but Windows handles=["
                            + string.Join(", ", winMail)
                            + "] — different accounts → 6009. Sign Windows into the SAME iCloud as the phone, "
                            + "or abandon Frida and import a Mac data.plist for this Windows account.");
                    }
                }
            }

            byte[] validation;
            var captured = IdsValidationDataStore.TryLoad(out var captureDetail);
            if (captured is { Length: > 0 })
            {
                Log("NAC: using Frida-captured validation-data — " + captureDetail);
                if (NacValidationService.IsRelayConfigured)
                {
                    Log(
                        "WARNING: Frida blob overrides NAC relay ("
                        + NacValidationService.ResolveRelayUrl()
                        + "). Delete madrid-persona/validation-data.b64 to use Mac Mini relay.");
                }

                if (overridePushKey is null)
                    Log("NOTE: iPhone-bound blob + Windows Albert token may still get 6009.");
                else
                    Log("NAC: push identity matched to iPhone APSClientIdentity.");
                validation = captured;
            }
            else
            {
                var nac = new NacValidationService();
                if (NacValidationService.IsRelayConfigured)
                    Log("NAC: requesting validation-data via relay…");
                else
                    Log("NAC: generating validation-data (pypush IMDAppleServices)…");
                validation = await nac.GenerateAsync(Log, ct).ConfigureAwait(false);
            }

            var (idCert, status) = await register
                .RegisterAsync(
                    del.ProfileId, handles, authKeyPem, authCertPem, pushToken,
                    identity, validation, anisette, serviceKind, Log, ct)
                .ConfigureAwait(false);

            var meta = new IdsEnrollmentMeta
            {
                ProfileId = del.ProfileId,
                AppleId = session.AppleId,
                Handles = handles.ToList(),
                RegisteredUtc = DateTime.UtcNow.ToString("O"),
                LastStatus = status,
                LastError = null,
            };
            if (serviceKind == IdsRegisterServiceKind.Madrid)
                IdsStorage.SaveMadridMeta(meta);
            else
                IdsStorage.SaveMeta(meta);

            // Keep a shared profile id on Find My meta when Madrid-only enroll runs first.
            if (serviceKind == IdsRegisterServiceKind.Madrid && IdsStorage.TryLoadMeta() is null)
                IdsStorage.SaveMeta(meta);

            Log($"{serviceKind} enroll completed.");
            Log(IdsStorage.FormatStatusSummary());
            _ = idCert;
            return string.Join(Environment.NewLine, logLines);
        }
        catch (Exception ex)
        {
            if (serviceKind == IdsRegisterServiceKind.Madrid)
            {
                var meta = IdsStorage.TryLoadMadridMeta()
                           ?? new IdsEnrollmentMeta { AppleId = session.AppleId };
                meta.LastError = ex.Message;
                meta.RegisteredUtc = null;
                IdsStorage.SaveMadridMeta(meta);
            }
            else
            {
                var meta = IdsStorage.TryLoadMeta() ?? new IdsEnrollmentMeta { AppleId = session.AppleId };
                meta.LastError = ex.Message;
                meta.RegisteredUtc = null;
                IdsStorage.SaveMeta(meta);
            }

            Log("ERROR: " + ex.Message);
            throw new InvalidOperationException(
                ex.Message + Environment.NewLine + Environment.NewLine + string.Join(Environment.NewLine, logLines),
                ex);
        }
    }

    public event EventHandler<string>? Progress;
}
