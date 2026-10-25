using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Auth;

namespace iCloudKitExtractor.Services;

/// <summary>
/// Secret dinamico sessione per endpoint MobileMe/Quota/SharedStreams/KVS/Contacts
/// (<c>MobileMeAuthToken</c> / <c>UAEA…</c> / fallback gs.icloud.auth).
/// </summary>
public static class SessionMmeAuth
{
    public static string? ResolveSecret(ICloudSession session) =>
        ResolveSecretCandidates(session).FirstOrDefault();

    /// <summary>
    /// Candidati in ordine di preferenza (dedup). Utile quando il primo token
    /// (es. EAA scaduto) dà 401/434 e un UAEA di sessione è ancora valido.
    /// </summary>
    public static IReadOnlyList<string> ResolveSecretCandidates(ICloudSession session)
    {
        var list = new List<string>();
        void Add(string? raw)
        {
            var n = NormalizeSecret(raw, session.Dsid);
            if (string.IsNullOrWhiteSpace(n))
                return;
            if (list.Any(x => string.Equals(x, n, StringComparison.Ordinal)))
                return;
            list.Add(n);
        }

        Add(session.MobileMeAuthToken);
        Add(session.AppleCloudKitContext);
        Add(session.CloudKitAuthToken);

        if (!string.IsNullOrWhiteSpace(session.GsICloudAuthToken))
        {
            Add(GsaGrandSlamAuthService.ExtractGsICloudAuthPasswordForBootstrap(
                session.GsICloudAuthToken));
        }

        if (session.GsServiceTokens.TryGetValue("com.apple.gs.icloud.auth", out var gs)
            && !string.IsNullOrWhiteSpace(gs))
        {
            Add(GsaGrandSlamAuthService.ExtractGsICloudAuthPasswordForBootstrap(gs));
        }

        // Preferisci UAEA/EAA “freschi” in testa se MME non sembra un token iCloud.
        return PreferIcloudAuthTokens(list);
    }

    internal static string? NormalizeSecret(string? secret, string? dsid)
    {
        if (string.IsNullOrWhiteSpace(secret))
            return null;

        secret = secret.Trim();

        // Già "dsid:token" in chiaro
        if (!string.IsNullOrWhiteSpace(dsid)
            && secret.StartsWith(dsid + ":", StringComparison.Ordinal))
            return secret[(dsid.Length + 1)..].Trim();

        // Base64(dsid:token) come nel header Authorization PE
        try
        {
            var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(secret));
            var colon = decoded.IndexOf(':');
            if (colon > 0)
            {
                var user = decoded[..colon];
                var pass = decoded[(colon + 1)..].Trim();
                if (pass.Length > 8
                    && (string.IsNullOrWhiteSpace(dsid)
                        || string.Equals(user, dsid, StringComparison.Ordinal)
                        || LooksLikeIcloudAuthToken(pass)))
                {
                    return pass;
                }
            }
        }
        catch (FormatException)
        {
            // non era base64
        }

        return secret;
    }

    private static IReadOnlyList<string> PreferIcloudAuthTokens(List<string> list)
    {
        if (list.Count <= 1)
            return list;

        var preferred = list.Where(LooksLikeIcloudAuthToken).ToList();
        if (preferred.Count == 0)
            return list;

        var rest = list.Where(s => !LooksLikeIcloudAuthToken(s)).ToList();
        // UAEA prima di EAA (quota/contacts spesso usano UAEA di sessione)
        preferred.Sort(static (a, b) =>
        {
            var score = TokenRank(b).CompareTo(TokenRank(a));
            return score != 0 ? score : 0;
        });
        preferred.AddRange(rest);
        return preferred;
    }

    private static int TokenRank(string t)
    {
        if (t.StartsWith("UAEA", StringComparison.Ordinal)) return 3;
        if (t.StartsWith("EAA", StringComparison.Ordinal)) return 2;
        if (t.StartsWith("EAM", StringComparison.Ordinal)) return 1;
        return 0;
    }

    private static bool LooksLikeIcloudAuthToken(string t) =>
        t.StartsWith("UAEA", StringComparison.Ordinal)
        || t.StartsWith("EAA", StringComparison.Ordinal)
        || t.StartsWith("EAM", StringComparison.Ordinal);
}
