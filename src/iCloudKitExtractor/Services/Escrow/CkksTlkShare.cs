using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Estrae blob ECIES da TLKShare <c>wrappedkey</c> (NSKeyedArchive bplist).
/// appleservices <c>ckks/tlkshare.go</c>.
/// </summary>
public static class CkksTlkShare
{
    private const int EphPubLen = 97;
    private const int IesTagLen = 16;

    // Typo Apple: "Externa" senza 'l'.
    private const string EphPubKey = "SFEphemeralSenderPublicKeyExternaRepresentation";
    private const string CiphertextKey = "SFCiphertext";
    private const string TagKey = "SFIESAuthenticationCode";

    public static bool TryExtractEciesBlob(string wrappedKeyB64, out byte[] blob, out string? error)
    {
        blob = [];
        error = null;
        byte[] raw;
        try
        {
            raw = Convert.FromBase64String(wrappedKeyB64);
        }
        catch (Exception ex)
        {
            error = $"wrappedkey base64: {ex.Message}";
            return false;
        }

        return TryExtractEciesBlob(raw, out blob, out error);
    }

    public static bool TryExtractEciesBlob(ReadOnlySpan<byte> wrappedKey, out byte[] blob, out string? error)
    {
        blob = [];
        error = null;
        if (!AppleBinaryPlist.TryParse(wrappedKey, out var root, out var parseErr))
        {
            error = $"tlkshare bplist: {parseErr}";
            return false;
        }

        if (root is not Dictionary<string, object?> arch)
        {
            error = "tlkshare: radice non dict";
            return false;
        }

        if (!arch.TryGetValue("$objects", out var objectsObj) || objectsObj is not object?[] objects)
        {
            error = "tlkshare: $objects assente";
            return false;
        }

        if (!arch.TryGetValue("$top", out var topObj) || topObj is not Dictionary<string, object?> top)
        {
            error = "tlkshare: $top assente";
            return false;
        }

        var ephPub = ArchiveBytes(ResolveTop(top, objects, EphPubKey));
        var ct = ArchiveBytes(ResolveTop(top, objects, CiphertextKey));
        var tag = ArchiveBytes(ResolveTop(top, objects, TagKey));

        // Trim trailing zeros sul ciphertext (layout SecureFoundation).
        var ctLen = ct.Length;
        while (ctLen > 0 && ct[ctLen - 1] == 0)
            ctLen--;
        ct = ct.AsSpan(0, ctLen).ToArray();

        if (ephPub.Length != EphPubLen || ct.Length == 0 || tag.Length != IesTagLen)
        {
            error = $"tlkshare ECIES parts: ephPub={ephPub.Length} ct={ct.Length} tag={tag.Length}";
            return false;
        }

        blob = new byte[ephPub.Length + ct.Length + tag.Length];
        Buffer.BlockCopy(ephPub, 0, blob, 0, ephPub.Length);
        Buffer.BlockCopy(ct, 0, blob, ephPub.Length, ct.Length);
        Buffer.BlockCopy(tag, 0, blob, ephPub.Length + ct.Length, tag.Length);
        return true;
    }

    private static object? ResolveTop(
        Dictionary<string, object?> top, object?[] objects, string key)
    {
        if (!top.TryGetValue(key, out var v) || v is null)
            return null;
        if (v is PlistUid uid)
        {
            if (uid.Value >= (ulong)objects.Length)
                return null;
            return objects[(int)uid.Value];
        }

        // Alcuni parser risolvono già l'UID.
        return v;
    }

    private static byte[] ArchiveBytes(object? v) => v switch
    {
        byte[] b => b,
        Dictionary<string, object?> d when d.TryGetValue("NS.data", out var nd) && nd is byte[] nb => nb,
        string s => Encoding.UTF8.GetBytes(s),
        _ => []
    };
}
