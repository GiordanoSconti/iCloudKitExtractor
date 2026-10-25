using System.Text;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Patch di template  sostituisce stringhe UTF-8 a lunghezza fissa nei body protobuf.
/// </summary>
public static class CloudKitTemplatePatcher
{
    private const string TemplateUserId = "_11df099a63349d1d43c84ef3080a50fa";
    private const string TemplateDeviceSha = "fd775295c1f92068478484a91e7322bb74acd200";
    private const string TemplateLockRecord = $"{TemplateDeviceSha}:Lock";

    public static byte[] PatchUserId(ReadOnlySpan<byte> template, string cloudKitUserId)
    {
        var body = template.ToArray();
        ReplaceUtf8(body, TemplateUserId, NormalizeUserId(cloudKitUserId));
        return body;
    }

    public static byte[] PatchRecordSaveLock(ReadOnlySpan<byte> template, string cloudKitUserId, string deviceSha1)
    {
        var body = template.ToArray();
        ReplaceUtf8(body, TemplateUserId, NormalizeUserId(cloudKitUserId));
        ReplaceUtf8(body, TemplateDeviceSha, NormalizeDeviceSha(deviceSha1));
        ReplaceUtf8(body, TemplateLockRecord, $"{NormalizeDeviceSha(deviceSha1)}:Lock");
        ReplaceUtf8(body, "8F3C7FDA-8F2A-4FDF-C9A0-8021EC620158", Guid.NewGuid().ToString().ToUpperInvariant());
        ReplaceUtf8(body, "9a60ee6e-c02b-2152-1e08-625a33a36ecb", Guid.NewGuid().ToString());
        return body;
    }

    private static string NormalizeUserId(string cloudKitUserId) =>
        cloudKitUserId.StartsWith('_') ? cloudKitUserId : $"_{cloudKitUserId.TrimStart('!')}";

    private static string NormalizeDeviceSha(string deviceSha1) =>
        deviceSha1.StartsWith("D:", StringComparison.OrdinalIgnoreCase)
            ? deviceSha1[2..]
            : deviceSha1;

    private static void ReplaceUtf8(byte[] body, string oldText, string newText)
    {
        var oldBytes = Encoding.UTF8.GetBytes(oldText);
        var newBytes = Encoding.UTF8.GetBytes(newText);
        if (oldBytes.Length != newBytes.Length)
            throw new ArgumentException($"Replacement length mismatch: '{oldText}' -> '{newText}'");

        var index = IndexOf(body, oldBytes);
        if (index < 0)
            throw new InvalidOperationException($"Template placeholder not found: {oldText}");
        Buffer.BlockCopy(newBytes, 0, body, index, newBytes.Length);
    }

    private static int IndexOf(byte[] haystack, byte[] needle)
    {
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            var match = true;
            for (var j = 0; j < needle.Length; j++)
            {
                if (haystack[i + j] != needle[j])
                {
                    match = false;
                    break;
                }
            }
            if (match)
                return i;
        }
        return -1;
    }
}
