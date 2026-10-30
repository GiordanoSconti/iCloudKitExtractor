using System.Net.NetworkInformation;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Win32;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>Static machine fingerprint headers for first-connection license issuance.</summary>
public static class IkeClientIdentity
{
    public const string HeaderMachineId = "X-IKE-Machine-Id";
    public const string HeaderHostname = "X-IKE-Hostname";
    public const string HeaderOs = "X-IKE-Os";
    public const string HeaderAppInstance = "X-IKE-App-Instance";
    public const string ResponseBundleHeader = "X-Anisette-License-Bundle";

    private static string? _machineId;
    private static string? _appInstance;

    public static string MachineId => _machineId ??= ResolveMachineId();
    public static string Hostname => Environment.MachineName;
    public static string Os => $"{Environment.OSVersion.Platform} {Environment.OSVersion.Version}";
    public static string AppInstance => _appInstance ??= Guid.NewGuid().ToString("N")[..16];

    public static void ApplyFingerprintHeaders(HttpRequestMessage request)
    {
        request.Headers.TryAddWithoutValidation(HeaderMachineId, MachineId);
        request.Headers.TryAddWithoutValidation(HeaderHostname, Hostname);
        request.Headers.TryAddWithoutValidation(HeaderOs, Os);
        request.Headers.TryAddWithoutValidation(HeaderAppInstance, AppInstance);
    }

    private static string ResolveMachineId()
    {
        try
        {
            using var key = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Cryptography");
            var guid = key?.GetValue("MachineGuid") as string;
            if (!string.IsNullOrWhiteSpace(guid))
                return guid.Trim();
        }
        catch
        {
            // fall through
        }

        try
        {
            var mac = NetworkInterface.GetAllNetworkInterfaces()
                .Where(n => n.OperationalStatus == OperationalStatus.Up
                            && n.NetworkInterfaceType != NetworkInterfaceType.Loopback)
                .Select(n => n.GetPhysicalAddress()?.ToString())
                .FirstOrDefault(a => !string.IsNullOrEmpty(a));
            if (!string.IsNullOrEmpty(mac))
                return "mac:" + mac;
        }
        catch
        {
            // fall through
        }

        var raw = Hostname + "|" + Environment.UserName + "|" + Os;
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return "hash:" + Convert.ToHexString(hash)[..32].ToLowerInvariant();
    }
}
