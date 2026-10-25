using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.FindMy;

/// <summary>
/// Stato trust / GrandSlam / APS per la UI «Dispositivi fidati».
/// Il flusso lista 2FA è HSA2/GSA (<c>Hsa2TrustedDeviceService</c>), non TrustToken web idmsa.
/// </summary>
public sealed class TrustedDevicesService
{
    public string FormatSessionTrustStatus(ICloudSession session)
    {
        var fromDisk = TryLoadTrustTokenFile(session);

        var sb = new StringBuilder();
        sb.AppendLine("=== Trust / GrandSlam (sessione corrente) ===");
        sb.AppendLine($"Apple ID: {session.AppleId}");
        sb.AppendLine($"DSID: {session.Dsid}");
        sb.AppendLine($"ADSID: {(string.IsNullOrWhiteSpace(session.Adsid) ? "(assente)" : "presente")}");
        sb.AppendLine($"PET: {(string.IsNullOrWhiteSpace(session.PeToken) ? "(assente)" : "presente")}");

        if (string.IsNullOrWhiteSpace(session.IdmsaTrustToken))
            sb.AppendLine("Idmsa TrustToken (cache/sessione): (assente)");
        else
            sb.AppendLine(
                $"Idmsa TrustToken (cache/sessione): presente{(fromDisk ? " — da file ~/.icloud" : "")}");

        if (session.IdmsaMfa is not null)
        {
            var hasLiveTrust = !string.IsNullOrWhiteSpace(session.IdmsaMfa.TrustToken);
            var complete = session.IdmsaMfa.LastSignInCompleteStatus;
            string completeHint;
            if (hasLiveTrust)
            {
                completeHint = " — sessione trusted (TrustToken live)";
                if (complete == 409)
                    completeHint += " [signin/complete era 409, poi OTP]";
            }
            else if (complete is 200 or 204)
                completeHint = " (signin/complete OK, TrustToken ancora assente)";
            else if (complete == 409)
                completeHint = " (signin/complete 409 — flusso web idmsa non più esposto in UI)";
            else if (complete is null)
                completeHint = "";
            else
                completeHint = $" (signin/complete HTTP {complete})";

            sb.AppendLine(
                $"IdmsaMfa live: sessionId={(string.IsNullOrWhiteSpace(session.IdmsaMfa.SessionId) ? "?" : "ok")} " +
                $"trustToken={(hasLiveTrust ? "sì" : "no")}" +
                completeHint);
            if (hasLiveTrust)
                sb.AppendLine($"  TrustToken live: {session.IdmsaMfa.TrustToken}");
        }
        else
        {
            sb.AppendLine("IdmsaMfa live: (nessuna — non usata dal flusso lista 2FA HSA2)");
        }

        sb.AppendLine();
        sb.AppendLine("=== Token Find My / FMF (da get_account_settings) ===");
        sb.AppendLine($"mmeFMFAppToken: {(string.IsNullOrWhiteSpace(session.MmeFmfAppToken) ? "NO" : "OK")}");
        sb.AppendLine($"mmeFMFToken: {(string.IsNullOrWhiteSpace(session.MmeFmfToken) ? "NO" : "OK")}");
        sb.AppendLine($"mmeFMIPToken: {(string.IsNullOrWhiteSpace(session.MmeFmipToken) ? "NO" : "OK")}");
        sb.AppendLine($"searchPartyToken: {(string.IsNullOrWhiteSpace(session.SearchPartyToken) ? "NO" : "OK")}");
        sb.AppendLine($"mmeAuthToken: {(string.IsNullOrWhiteSpace(session.MobileMeAuthToken) ? "NO" : "OK")}");
        sb.AppendLine($"PCS KeySet Escrow: {(session.PcsEscrowedKeySet is { Length: > 32 } ? $"OK ({session.PcsEscrowedKeySet.Length} B)" : "NO")}");

        sb.AppendLine();
        sb.AppendLine("Telefoni 2FA noti in sessione:");
        if (session.TrustedPhoneNumbers.Count == 0)
        {
            sb.AppendLine("  (nessuno)");
            sb.AppendLine("  Origine: challenge GSA (login HSA2).");
        }
        else
        {
            foreach (var p in session.TrustedPhoneNumbers)
                sb.AppendLine($"  · {p.DisplayLabel} (id={p.Id})");
        }

        sb.AppendLine();
        sb.AppendLine("=== APS push (Albert / courier) ===");
        sb.AppendLine(
            $"Certificato: {(ApsStorage.HasCertificate() ? "OK (" + ApsStorage.DirectoryPath + ")" : "NO")}");
        var pushTok = ApsSessionService.TryGetPushTokenHex();
        if (string.IsNullOrEmpty(pushTok))
            sb.AppendLine("Push token: (assente — Attiva Albert + Connetti APS)");
        else
            sb.AppendLine($"Push token: {pushTok}");

        sb.AppendLine();
        sb.AppendLine("Nota:");
        sb.AppendLine(
            "  · «Registra in lista 2FA» (HSA2/GSA) usa password + ptkn APS, poi OTP dal device già fidato.");
        sb.AppendLine(
            "  · Il TrustToken web (idmsa) non è usato da questo flusso.");
        return sb.ToString();
    }

    /// <returns>true se il token è stato appena caricato da disco (non già in memoria).</returns>
    public static bool TryLoadTrustTokenFile(ICloudSession session)
    {
        if (!string.IsNullOrWhiteSpace(session.IdmsaTrustToken)
            || string.IsNullOrWhiteSpace(session.AppleId))
            return false;

        try
        {
            var path = TrustTokenPath(session.AppleId);
            if (!File.Exists(path))
                return false;
            var tok = File.ReadAllText(path).Trim();
            if (string.IsNullOrWhiteSpace(tok))
                return false;
            session.IdmsaTrustToken = tok;
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static string TrustTokenPath(string appleId)
    {
        var b64 = Convert.ToBase64String(Encoding.UTF8.GetBytes(appleId.ToLowerInvariant()));
        return Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.UserProfile),
            ".icloud",
            ".trust-token-" + b64);
    }
}
