namespace iCloudKitExtractor.Services.Auth;

using iCloudKitExtractor.Models;

/// <summary>
/// CoreADI su Windows genera lo stesso MD-M per profilo "ios" e "windows".
/// Apple rifiuta GsService2 init akd (-22410) se header iPhone + OTP Windows.
/// </summary>
public static class AnisetteCapability
{
    public static bool IsLocalServerUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return true;

        return uri.Host is "127.0.0.1" or "localhost" or "::1";
    }

    /// <summary>
    /// Bridge HTTP locale (6970) non è CoreADI Windows — anisette arriva dal Mac via tunnel.
    /// </summary>
    public static bool IsBridgeServerUrl(string url)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out var uri))
            return false;

        if (!IsLocalServerUrl(url))
            return false;

        var bridgePort = ResolveBridgeHttpPort();
        return uri.Port == bridgePort;
    }

    public static int ResolveBridgeHttpPort() =>
        int.TryParse(Environment.GetEnvironmentVariable("ANISETTE_BRIDGE_HTTP_PORT"), out var p) ? p : 6970;

    /// <summary>
    /// true se l'anisette remota sembra provenire da CoreADI locale (spoof iOS).
    /// </summary>
    public static bool IsLocalCoreAdiSpoof(AnisetteHeaders windows, AnisetteHeaders remote)
    {
        // Frida/akd e worker emulato: Client-Info akd → non confrontare MD-M con CoreADI Windows.
        if (IsEmulatedAkdAnisette(remote))
            return false;

        if (string.IsNullOrEmpty(windows.MdM) || string.IsNullOrEmpty(remote.MdM))
            return false;

        return string.Equals(windows.MdM, remote.MdM, StringComparison.Ordinal);
    }

    public static bool IsDockerMacAnisette(AnisetteHeaders remote) =>
        AnisetteIdentity.IsMacProvisioning(remote.ClientMmeInfo);

    public static bool IsEmulatedAkdAnisette(AnisetteHeaders remote) =>
        AnisetteIdentity.IsAkdProvisioning(remote.ClientMmeInfo);

    public static bool IsFridaIphoneBackend(string? backend) =>
        backend is "frida" or "iphone-frida" or "jb-frida";

    public static int ResolveEmulatedIosPort() =>
        int.TryParse(Environment.GetEnvironmentVariable("ANISETTE_EMULATED_IOS_PORT"), out var p) ? p : 6971;

    public static string DescribeForLogin(
        string serverUrl,
        bool localSpoof,
        AnisetteHeaders? remote = null,
        string? backend = null)
    {
        if (localSpoof)
        {
            return "AnisetteServer :6969 usa CoreADI Windows (non emulazione akd). " +
                   "Per flusso iPhone interno: Anisette.py su :6971 — vedi docs/IPHONE_INTERNAL_FLOW.md.";
        }

        if (IsFridaIphoneBackend(backend))
        {
            return $"Anisette iPhone Frida/akd ({serverUrl}) — OTP da AuthKit sul device jailbroken, " +
                   $"MD-M {SummarizeMdM(remote?.MdM)}. Nessun worker Android.";
        }

        if (remote is not null && IsDockerMacAnisette(remote))
        {
            return $"Anisette remota ({serverUrl}) è Mac/Xcode (dadoum docker), non akd. " +
                   "Avvia setup-emulated-akd.ps1 (worker Android ADI su :6971) oppure --backend frida.";
        }

        // Client-Info con akd ma backend frida già gestito sopra; qui = emulato Android classico
        if (remote is not null && IsEmulatedAkdAnisette(remote) && !IsFridaIphoneBackend(backend))
        {
            return $"Anisette akd emulato ({serverUrl}) — worker Android ADI, MD-M {SummarizeMdM(remote.MdM)}. " +
                   "Flow iPhone end-to-end (vedi docs/EMULATED_AKD.md).";
        }

        return $"Anisette remota ({serverUrl}) — backend={backend ?? "?"}.";
    }

    public static string SummarizeMdM(string? mdM)
    {
        if (string.IsNullOrEmpty(mdM))
            return "(vuoto — mint su GET / al login)";
        return mdM.Length <= 16 ? mdM : mdM[..16] + "…";
    }
}
