using System.Security.Cryptography;
using System.Text;

namespace iCloudKitExtractor.AnisetteLicense;

public static class ClientFingerprint
{
    public const string HeaderMachineId = "X-IKE-Machine-Id";
    public const string HeaderHostname = "X-IKE-Hostname";
    public const string HeaderOs = "X-IKE-Os";
    public const string HeaderAppInstance = "X-IKE-App-Instance";
    public const string ResponseBundleHeader = "X-Anisette-License-Bundle";

    public static string Compute(
        string? machineId,
        string? hostname,
        string? os,
        string? appInstance)
    {
        var raw = string.Join('|',
            (machineId ?? "").Trim().ToLowerInvariant(),
            (hostname ?? "").Trim().ToLowerInvariant(),
            (os ?? "").Trim().ToLowerInvariant(),
            (appInstance ?? "").Trim().ToLowerInvariant());
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public static string SubjectFromFingerprint(string fingerprint, string? hostname) =>
        string.IsNullOrWhiteSpace(hostname)
            ? "auto:" + Truncate(fingerprint, 16)
            : "auto:" + hostname.Trim() + ":" + Truncate(fingerprint, 12);

    private static string Truncate(string s, int n) =>
        s.Length <= n ? s : s[..n];
}
