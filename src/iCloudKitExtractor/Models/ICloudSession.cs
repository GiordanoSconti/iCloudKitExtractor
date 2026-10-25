using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Models;

public sealed class ICloudSession
{
    public string AppleId { get; set; } = string.Empty;
    public string Dsid { get; set; } = string.Empty;
    public string Partition { get; set; } = "p178";
    public string CloudKitUserId { get; set; } = string.Empty;
    public string CloudKitAuthToken { get; set; } = string.Empty;
    public string MobileMeAuthToken { get; set; } = string.Empty;

    /// <summary>Token FMF app da get_account_settings (<c>mmeFMFAppToken</c>) — friends mobile.</summary>
    public string? MmeFmfAppToken { get; set; }

    /// <summary>Token FMF legacy (<c>mmeFMFToken</c>).</summary>
    public string? MmeFmfToken { get; set; }

    /// <summary>Token Find My iPhone (<c>mmeFMIPToken</c>).</summary>
    public string? MmeFmipToken { get; set; }

    /// <summary>
    /// Token Search Party / AirTag (<c>searchPartyToken</c>) da get_account_settings
    /// con Client-Info Find My — usato da <c>acsnservice/fetch</c>.
    /// </summary>
    public string? SearchPartyToken { get; set; }

    /// <summary>Trust token idmsa (<c>X-Apple-TwoSV-Trust-Token</c>) se ottenuto in sessione.</summary>
    public string? IdmsaTrustToken { get; set; }

    public string? PeToken { get; set; }
    public string? GsToken { get; set; }
    /// <summary>Token da X-Apple-GS-Token com.apple.gs.icloud.auth (password setup/authenticate).</summary>
    public string? GsICloudAuthToken { get; set; }
    /// <summary>JWT com.apple.gs.icloud.cloudkit.auth (password ckAppInit, equivalente moderno di gs.icloud.auth).</summary>
    public string? CloudKitGsToken { get; set; }
    public string? IdentityToken { get; set; }
    public string? Adsid { get; set; }
    public string? GsIdmsToken { get; set; }

    /// <summary>
    /// Mappa completa <c>spd.t</c> (servizio → secret grezzo). Account Info usa un
    /// secret ~476 in Basic/X-Apple-GS-Token; non sempre è solo <c>icloud.auth</c>.
    /// </summary>
    public Dictionary<string, string> GsServiceTokens { get; set; } =
        new(StringComparer.Ordinal);

    public string? AppleCloudKitContext { get; set; }
    public string? CloudKitGatewayUrl { get; set; }

    /// <summary>
    /// Da get_account_settings → com.apple.Dataclass.KeychainSync.escrowProxyUrl
    /// (es. https://p178-escrowproxy.icloud.com:443). PCS identity / keychain recovery.
    /// </summary>
    public string? EscrowProxyUrl { get; set; }

    /// <summary>
    /// Dataclass presenti in <c>get_account_settings</c>
    /// (<c>com.apple.mobileme</c> + <c>availableFeatures</c>) — usate per le checkbox Sync Data.
    /// </summary>
    public IReadOnlyList<string> AvailableDataclasses { get; set; } = [];

    /// <summary>
    /// Endpoint servizi da <c>get_account_settings</c> → ogni
    /// <c>com.apple.Dataclass.*</c> (<c>url</c>, <c>escrowProxyUrl</c>, …).
    /// Chiave = dataclass oppure <c>dataclass.campoUrl</c>.
    /// </summary>
    public Dictionary<string, string> DataclassServiceUrls { get; set; } =
        new(StringComparer.OrdinalIgnoreCase);

    /// <summary>
    /// KeySet PCS escrowed sbloccato in questa sessione (plaintext <c>appl[2]</c>).
    /// Usato dinamicamente da CloudDocs senza rileggere dump storici.
    /// </summary>
    public byte[]? PcsEscrowedKeySet { get; set; }

    /// <summary>Cartella dove Escrow ha scritto gli artifact PCS in questa sessione.</summary>
    public string? PcsKeysDirectory { get; set; }

    /// <summary>
    /// BottledPeerEntropy (72 B) da Unlock Octagon/iCDP — base HKDF per OTBottle/Manatee.
    /// </summary>
    public byte[]? OctagonBottledPeerEntropy { get; set; }

    /// <summary>Label <c>com.apple.icdp.record.*</c> dell’ultima bottle sbloccata.</summary>
    public string? OctagonBottleLabel { get; set; }

    /// <summary>Serial device della bottle Escrow appena sbloccata (match fetchViableBottles).</summary>
    public string? OctagonBottleSerial { get; set; }

    /// <summary>Cartella artifact Octagon (entropy, EscrowBottle plist, meta).</summary>
    public string? OctagonKeysDirectory { get; set; }

    /// <summary>Sponsor peer ID (post fetchViableBottles + OTBottle decrypt).</summary>
    public string? OctagonPeerId { get; set; }

    /// <summary>Peer encryption private key PKCS#8 (P-384) — apre vault CKKS/Manatee.</summary>
    public byte[]? OctagonPeerEncryptionPkcs8 { get; set; }

    /// <summary>Peer signing private key PKCS#8 (P-384).</summary>
    public byte[]? OctagonPeerSigningPkcs8 { get; set; }

    /// <summary>
    /// TLK CKKS per view (es. LimitedPeersAllowed, Passwords) dopo OpenVault.
    /// </summary>
    public Dictionary<string, byte[]>? CkksTlkByView { get; set; }

    /// <summary>
    /// Chiavi PCS compact da CKKS OpenVault (Manatee / ProtectedCloudStorage).
    /// SyncData e Backup le uniscono al KeySet Escrow (pool seed PCS).
    /// Con ADP spesso sono l’unica fonte utilizzabile.
    /// </summary>
    public List<PcsCompactPrivateKey>? PcsManateeCompactKeys { get; set; }

    /// <summary>
    /// KeyId (hex) che hanno già unwrap-ato zone/keybag in questa sessione — provati per primi.
    /// </summary>
    public HashSet<string>? PcsPreferredKeyIds { get; set; }

    public AnisetteHeaders Anisette { get; set; } = new();

    /// <summary>Canale 2FA scelto dopo login parziale.</summary>
    public TwoFactorMethod TwoFactorMethod { get; set; } = TwoFactorMethod.TrustedDevice;

    public int SelectedPhoneId { get; set; } = 1;

    public bool SmsCodeRequested { get; set; }

    public SmsSendChannel SmsSendChannel { get; set; } = SmsSendChannel.None;

    public IReadOnlyList<TrustedPhoneNumber> TrustedPhoneNumbers { get; set; } = [];

    /// <summary>Sessione idmsa parallela (non usata nel flusso SMS GSA-only).</summary>
    public IdmsaMfaState? IdmsaMfa { get; set; }
}
