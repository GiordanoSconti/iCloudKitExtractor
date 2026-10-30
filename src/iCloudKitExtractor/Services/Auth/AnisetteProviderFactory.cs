namespace iCloudKitExtractor.Services.Auth;

using iCloudKitExtractor.Models;

public static class AnisetteProviderFactory
{
    public const string DefaultServerUrl = "http://127.0.0.1:6971";

    public static string ResolveServerUrl()
    {
        var env = Environment.GetEnvironmentVariable("ANISETTE_SERVER_URL")?.Trim();
        if (!string.IsNullOrEmpty(env))
            return env;

        var settings = AnisetteUserSettings.Load();
        if (settings.IsRemoteServerEnabled())
        {
            var file = settings.ServerUrl?.Trim();
            if (!string.IsNullOrEmpty(file))
                return file;
        }

        return DefaultServerUrl;
    }

    /// <summary>
    /// License Bearer: env <c>ANISETTE_LICENSE</c>, altrimenti JSON UI.
    /// </summary>
    public static string? ResolveLicenseBearer()
    {
        var fromEnv = RemoteAnisetteProvider.ResolveLicenseBearerFromEnv();
        if (!string.IsNullOrEmpty(fromEnv))
            return fromEnv;

        var fromFile = AnisetteUserSettings.Load().License?.Trim();
        return string.IsNullOrEmpty(fromFile) ? null : fromFile;
    }

    public static bool IsServerUrlOverriddenByEnvironment() =>
        !string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("ANISETTE_SERVER_URL"));

    /// <summary>
    /// iphone = AuthKit iPhone end-to-end (Frida/akd device o worker ADI emulato).
    /// hybrid = legacy AuthKitWin SRP + anisette remota post-login (solo se esplicito in config).
    /// </summary>
    public static string ResolveAuthMode()
    {
        var env = Environment.GetEnvironmentVariable("ICLOUD_AUTH_MODE")?.Trim().ToLowerInvariant();
        if (!string.IsNullOrEmpty(env))
            return env;

        var file = AnisetteUserSettings.Load().AuthMode?.Trim().ToLowerInvariant();
        if (!string.IsNullOrEmpty(file))
            return file;

        return "iphone";
    }

    public static string SettingsFilePath => AnisetteUserSettings.SettingsPath;

    public static AuthAnisetteProviders CreateAuth(HttpClient http) =>
        new(
            new CoreAdiAnisetteProvider(http, AdiDeviceProfile.Windows),
            new RemoteAnisetteProvider(http, ResolveServerUrl(), ResolveLicenseBearer()));

    public static async Task<AnisetteAuthProfile> ProbeAsync(HttpClient http, CancellationToken ct = default)
    {
        var providers = CreateAuth(http);
        var url = ResolveServerUrl();
        var mode = ResolveAuthMode();

        // Test diagnostico: identità coerente stile Provision (client-info Xcode/Mac ma
        // ADI Android). La remota sembra "docker Mac" ma è voluta → forza il full-iphone auth.
        var provisionMode = AdiDeviceProfile.ResolveIdentityMode() == "provision";

        // Frida: health senza mint pesante; prova un GET / se possibile.
        if (providers.Ios is RemoteAnisetteProvider remoteProv)
        {
            var backend = await remoteProv.TryGetBackendAsync(ct).ConfigureAwait(false);
            if (AnisetteCapability.IsFridaIphoneBackend(backend))
            {
                AnisetteHeaders probeRemote;
                try
                {
                    // Un mint reale così il log mostra MD-M (non stub vuoto).
                    probeRemote = await remoteProv.FetchAsync(ct).ConfigureAwait(false);
                }
                catch
                {
                    probeRemote = new AnisetteHeaders
                    {
                        ClientMmeInfo =
                            "<iPhone10,4> <iPhone OS;16.7;20H19> <com.apple.AuthKit/1 (com.apple.akd/1.0)>",
                        MdRinfo = "33883392",
                    };
                }

                var useFull = mode == "iphone" || provisionMode;
                return new AnisetteAuthProfile(
                    url, mode,
                    LocalCoreAdiSpoof: false,
                    DockerMacAnisette: false,
                    UseFullIphoneAuth: useFull,
                    new AnisetteHeaders(),
                    probeRemote,
                    Backend: backend);
            }
        }

        AnisetteHeaders remote;
        AnisetteHeaders windows;

        if (mode == "iphone")
        {
            remote = await providers.Ios.FetchAsync(ct).ConfigureAwait(false);
            var emulatedAkd = AnisetteCapability.IsEmulatedAkdAnisette(remote);
            var dockerMac = AnisetteCapability.IsDockerMacAnisette(remote);
            if (provisionMode || emulatedAkd || dockerMac)
                windows = new AnisetteHeaders();
            else
                windows = await providers.Windows.FetchAsync(ct).ConfigureAwait(false);
        }
        else
        {
            windows = await providers.Windows.FetchAsync(ct).ConfigureAwait(false);
            remote = await providers.Ios.FetchAsync(ct).ConfigureAwait(false);
        }

        var localSpoof = mode != "iphone"
            && AnisetteCapability.IsLocalServerUrl(url)
            && !AnisetteCapability.IsBridgeServerUrl(url)
            && AnisetteCapability.IsLocalCoreAdiSpoof(windows, remote);
        var dockerMacAnisette = !provisionMode && AnisetteCapability.IsDockerMacAnisette(remote);
        var emulatedAkdRemote = AnisetteCapability.IsEmulatedAkdAnisette(remote);
        var useFullIphone = mode == "iphone"
            && (provisionMode || (!dockerMacAnisette && (emulatedAkdRemote || !localSpoof)));

        return new AnisetteAuthProfile(
            url, mode, localSpoof, dockerMacAnisette, useFullIphone, windows, remote, Backend: null);
    }
}

public sealed record AnisetteAuthProfile(
    string ServerUrl,
    string Mode,
    bool LocalCoreAdiSpoof,
    bool DockerMacAnisette,
    bool UseFullIphoneAuth,
    AnisetteHeaders WindowsAnisette,
    AnisetteHeaders RemoteAnisette,
    string? Backend = null);
