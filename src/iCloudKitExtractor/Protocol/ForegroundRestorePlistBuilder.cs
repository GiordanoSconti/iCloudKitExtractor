using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Metadati Foreground Restore per header CloudKit f18/f22/f26/f30.
/// hw + plist-sha256 sono stabili su tutte le catture dello stesso account
/// (13 sessioni, 02–21/07/2026, 227 request); mme-client-info invece varia.
/// </summary>
public static class ForegroundRestorePlistBuilder
{
    /// <summary>Hardware-id (campo 22), invariato in tutte le catture analizzate.</summary>
    public const string HardwareIdHex =
        "69A01E7605308B82DC2D16C2EE5708EBF809D270A77C4C001C080FB95E10A7FA";

    /// <summary>x-apple-mmcs-plist-sha256, invariato in tutte le catture analizzate.</summary>
    public const string PlistSha256Base64 =
        "T4puFGiGd8+Ps3UvjxZcJvUpp8qKADTniDwLwlDqaD0=";

    public const string IkeProtoVersion = "5.0";
    public const string IkePlistVersion = "v1.0";

    /// <summary>Default mme-client-info (cattura 20260721); può essere sostituito da risposte.</summary>
    public const string DefaultMmeClientInfo =
        "<D10AP> <iPhone OS;13.4.1;17E262> <com.apple.icloud.content/471 (com.apple.CloudKit/17A577)>";

    public static ForegroundRestorePlist BuildFromSession(ICloudSession session, BackupDevice device) =>
        BuildCapturedAuth(session.Anisette);

    /// <summary>Foreground per elenco backup (pre-device): stessi hw/sha stabili.</summary>
    public static ForegroundRestorePlist BuildForCatalog(ICloudSession session) =>
        BuildCapturedAuth(session.Anisette);

    /// <summary>
    /// Identità restore catturata: hw + sha statici; mme da anisette (formato icloud.content)
    /// o default dell'ultima cattura.
    /// </summary>
    public static ForegroundRestorePlist BuildCapturedAuth(
        AnisetteHeaders? anisette = null,
        string? mmeClientInfoFromResponse = null)
    {
        var mme = FirstNonEmpty(
            mmeClientInfoFromResponse,
            BuildMmcsForegroundClientInfo(anisette),
            DefaultMmeClientInfo);

        return new ForegroundRestorePlist(
            ProtoVersion: IkeProtoVersion,
            PlistSha256Base64: PlistSha256Base64,
            PlistVersion: IkePlistVersion,
            HardwareIdHex: HardwareIdHex,
            MmeClientInfo: mme);
    }

    /// <summary>
    /// Unisce FG statico con campi opzionali assorbiti da risposte precedenti
    /// (solo mme-client-info è risultato variabile nelle catture).
    /// </summary>
    public static ForegroundRestorePlist MergeWithAbsorbed(
        ForegroundRestorePlist fillBase,
        ForegroundRestorePlist? absorbed)
    {
        if (absorbed is null)
            return fillBase;

        return fillBase with
        {
            MmeClientInfo = FirstNonEmpty(absorbed.MmeClientInfo, fillBase.MmeClientInfo),
            // hw/sha restano quelli stabili anche se una risposta ne riportasse altri
            HardwareIdHex = HardwareIdHex,
            PlistSha256Base64 = PlistSha256Base64,
            ProtoVersion = string.IsNullOrWhiteSpace(absorbed.ProtoVersion)
                ? fillBase.ProtoVersion
                : absorbed.ProtoVersion,
            PlistVersion = string.IsNullOrWhiteSpace(absorbed.PlistVersion)
                ? fillBase.PlistVersion
                : absorbed.PlistVersion
        };
    }

    /// <summary>Client-info per f30 MMCS (usa icloud.content, non AuthKit/akd).</summary>
    public static string BuildMmcsForegroundClientInfo(AnisetteHeaders? anisette)
    {
        if (anisette is null)
            return DefaultMmeClientInfo;

        // Se anisette espone già un client-info stile icloud.content, riusalo.
        var existing = anisette.ClientMmeInfo;
        if (!string.IsNullOrWhiteSpace(existing)
            && existing.Contains("icloud.content", StringComparison.OrdinalIgnoreCase))
            return existing.Trim();

        var product = string.IsNullOrWhiteSpace(anisette.ClientProductType)
            ? "D10AP"
            : anisette.ClientProductType.Trim();

        // Anisette tipicamente dà iPhone9,3 — nelle catture usa board-id (D10AP/N71AP/…).
        if (product.StartsWith("iPhone", StringComparison.OrdinalIgnoreCase)
            || product.StartsWith("iPad", StringComparison.OrdinalIgnoreCase))
            return DefaultMmeClientInfo;

        return $"<{product}> <iPhone OS;13.4.1;17E262> <com.apple.icloud.content/471 (com.apple.CloudKit/17A577)>";
    }

    private static string FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values)
        {
            if (!string.IsNullOrWhiteSpace(v))
                return v.Trim();
        }

        return DefaultMmeClientInfo;
    }
}
