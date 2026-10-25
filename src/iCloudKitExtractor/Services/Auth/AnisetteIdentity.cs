namespace iCloudKitExtractor.Services.Auth;

internal static class AnisetteIdentity
{
    /// <summary>
    /// dadoum/anisette-v3-server provisiona come Mac/Xcode, non come iPhone/akd .
    /// </summary>
    public static bool IsMacProvisioning(string? clientMmeInfo)
    {
        if (string.IsNullOrEmpty(clientMmeInfo))
            return false;

        return clientMmeInfo.Contains("MacBook", StringComparison.OrdinalIgnoreCase)
               || clientMmeInfo.Contains("macOS", StringComparison.OrdinalIgnoreCase)
               || clientMmeInfo.Contains("com.apple.dt.Xcode", StringComparison.OrdinalIgnoreCase)
               || clientMmeInfo.Contains("iMac", StringComparison.OrdinalIgnoreCase);
    }

    public static bool IsAkdProvisioning(string? clientMmeInfo) =>
        !string.IsNullOrEmpty(clientMmeInfo)
        && clientMmeInfo.Contains("com.apple.akd", StringComparison.OrdinalIgnoreCase);
}
