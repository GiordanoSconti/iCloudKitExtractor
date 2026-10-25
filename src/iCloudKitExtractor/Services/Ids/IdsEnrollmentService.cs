using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Auth;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Pipeline enroll IDS: delegate → authenticateDS → handles → id-register (multiplex1/FMF).
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

    public async Task<string> EnrollAsync(ICloudSession session, CancellationToken ct = default)
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
                    "Push token APS assente — Attiva Albert + Connetti APS prima dell'enroll IDS.");
            if (!ApsStorage.HasCertificate())
                throw new InvalidOperationException("Certificato APS assente — Attiva Albert.");

            Log($"APS token len={pushToken.Length} hex={ApsStorage.TokenHex(pushToken)[..Math.Min(16, ApsStorage.TokenHex(pushToken).Length)]}…");

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
                .GetHandlesAsync(del.ProfileId, authKeyPem, authCertPem, pushToken, Log, ct)
                .ConfigureAwait(false);
            Log($"Handles: {string.Join(", ", handles)}");

            var identity = IdsIdentity.LoadOrCreate();
            var anisette = await _anisette.FetchAsync(ct).ConfigureAwait(false);
            anisette.TouchClientTimeUtc();

            Log("NAC: generazione validation-data (pypush IMDAppleServices)…");
            var nac = new NacValidationService();
            var validation = await nac.GenerateAsync(Log, ct).ConfigureAwait(false);

            var (idCert, status) = await register
                .RegisterAsync(
                    del.ProfileId, handles, authKeyPem, authCertPem, pushToken,
                    identity, validation, anisette, Log, ct)
                .ConfigureAwait(false);

            IdsStorage.SaveMeta(new IdsEnrollmentMeta
            {
                ProfileId = del.ProfileId,
                AppleId = session.AppleId,
                Handles = handles.ToList(),
                RegisteredUtc = DateTime.UtcNow.ToString("O"),
                LastStatus = status,
                LastError = null,
            });

            Log("Enroll IDS completato.");
            Log(IdsStorage.FormatStatusSummary());
            _ = idCert;
            return string.Join(Environment.NewLine, logLines);
        }
        catch (Exception ex)
        {
            var meta = IdsStorage.TryLoadMeta() ?? new IdsEnrollmentMeta { AppleId = session.AppleId };
            meta.LastError = ex.Message;
            meta.RegisteredUtc = null;
            IdsStorage.SaveMeta(meta);
            Log("ERRORE: " + ex.Message);
            throw new InvalidOperationException(
                ex.Message + Environment.NewLine + Environment.NewLine + string.Join(Environment.NewLine, logLines),
                ex);
        }
    }

    public event EventHandler<string>? Progress;
}
