using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Categorie Sync Data (<c>SelectSyncDataWidget</c> / <c>chk*</c>).
/// Allineate a  Photos, Account Info, Apple Maps, Calendars, Contacts, Calls,
/// FileVault2 token, Health, iBooks, Keychain, Messages, Notes, Safari, Screen Time,
/// Voice Memos, Wallet, Wi-Fi.
/// Visibilità = presenza dataclass in <c>get_account_settings</c>
/// (oppure CKDatabaseService per categorie solo-CloudKit).
/// </summary>
public static class SyncDataCategoryCatalog
{
    public const string PhotosId = "photos";
    public const string AccountInfoId = "accountinfo";

    public const string CallsId = "calls";
    public const string MessagesId = "messages";
    public const string VoiceMemosId = "voicememos";

    public sealed record Category(
        string Id,
        string DisplayName,
        /// <summary>Dataclass richiesta (null = CloudKit generico se CKDatabaseService disponibile).</summary>
        string? RequiredDataclass,
        IReadOnlyList<CloudKitContainerBinding> Containers,
        bool IncludeAccountInfo = false,
        bool DefaultChecked = false,
        /// <summary>False = checkbox disabilitata in UI (es. Calls, feature off / ckm4qn70).</summary>
        bool UiEnabled = true);

    /// <summary>Ordine UI: Photos, Account Info, Messages, Voice Memos, Notes, poi il resto.</summary>
    public static IReadOnlyList<Category> All { get; } =
    [
        new(PhotosId, "Photos", "com.apple.Dataclass.CloudPhotos",
            [new("com.apple.photos.cloud", "com.apple.Photos")],
            DefaultChecked: true),
        new(AccountInfoId, "Account Info", null,
            [], IncludeAccountInfo: true),
        new(MessagesId, "Messages", null,
            [new("com.apple.messages.cloud", "com.apple.imagent")]),
        new(VoiceMemosId, "Voice Memos", null,
            [new("com.apple.VoiceMemosContainer", "com.apple.voicememod")]),
        new("notes", "Notes", "com.apple.Dataclass.Notes",
            [new("com.apple.notes", "com.apple.Notes")]),
        new("maps", "Apple Maps", null,
            [new("com.apple.Maps.Sync", "com.apple.Maps")],
            UiEnabled: false),
        // Container sotto = candidati da entitlement / reverse-DNS Apple (da validare con
        // ckAppInit + zone/sync). Non sono tutti pubblicati; probe runtime conferma.
        new("calendars", "Calendars", "com.apple.Dataclass.Calendars",
        [
            new("com.apple.mobilecal", "com.apple.mobilecal"),
            new("com.apple.Calendar", "com.apple.mobilecal"),
        ], UiEnabled: false),
        new("contacts", "Contacts", "com.apple.Dataclass.Contacts",
        [
            // Path principale UI Exploratory = CardDAV; questi sono candidati CloudKit.
            new("com.apple.contacts", "com.apple.MobileAddressBook"),
            new("com.apple.AddressBook", "com.apple.MobileAddressBook"),
        ], UiEnabled: false),
        new(CallsId, "Calls", null,
        [
            // Prefer cloud-storage (CallHistorySyncHelper entitlement map). Legacy
            // com.apple.CallHistory often returns ckm4qn70 «optional feature disabled».
            new("com.apple.callhistory.cloud-storage", "com.apple.callhistory.sync-helper"),
            new("com.apple.CallHistory", "com.apple.callhistory.sync-helper"),
        ], UiEnabled: false),
        // FileVault2 token: tipicamente KVS/sbd o Keychain, non un container CK dedicato.
        // Nessun candidati CK qui — usare KeyValue / Keychain; dataclass non espone FV2 CK.
        new("filevault", "FileVault2 token", null,
            []),
        new("health", "Health", "com.apple.Dataclass.Health",
            [new("com.apple.health.sync", "com.apple.healthd")],
            UiEnabled: false),
        new("ibooks", "iBooks", null,
            [new("com.apple.iBooks", "com.apple.iBooks")],
            UiEnabled: false),
        new("keychain", "Keychain", "com.apple.Dataclass.KeychainSync",
            [new("com.apple.security.keychain", "com.apple.securityd")],
            UiEnabled: false),
        new("safari", "Safari", "com.apple.Dataclass.Bookmarks",
        [
            new("com.apple.SafariShared.WBSCloudBookmarksStore", "com.apple.SafariBookmarksSyncAgent"),
            new("com.apple.SafariShared.CloudTabs", "com.apple.SafariBookmarksSyncAgent"),
            new("com.apple.SafariShared.WBSCloudHistoryStore", "com.apple.Safari"),
        ], UiEnabled: false),
        new("screentime", "Screen Time", null,
        [
            new("com.apple.ScreenTimeAgent", "com.apple.ScreenTimeAgent"),
            new("com.apple.screentime.cloudkit", "com.apple.ScreenTimeAgent"),
        ], UiEnabled: false),
        new("wallet", "Wallet", null,
        [
            new("com.apple.Passbook", "com.apple.Passbook"),
            new("com.apple.passd", "com.apple.passd"),
        ], UiEnabled: false),
        new("wifi", "Wi-Fi", null,
        [
            new("com.apple.wifi", "com.apple.wifi"),
            new("com.apple.wifid.sync", "com.apple.wifid"),
        ], UiEnabled: false),
    ];

    public static IReadOnlyList<Category> ResolveAvailable(IReadOnlyCollection<string> availableDataclasses)
    {
        var set = new HashSet<string>(availableDataclasses, StringComparer.OrdinalIgnoreCase);
        var hasCk = set.Contains("com.apple.Dataclass.CKDatabaseService");
        var list = new List<Category>();
        foreach (var cat in All)
        {
            // Account Info: login-gated (IdentityToken/MME), non dipende da CK dataclass.
            if (cat.IncludeAccountInfo)
            {
                list.Add(cat);
                continue;
            }

            if (cat.RequiredDataclass is null)
            {
                if (hasCk)
                    list.Add(cat);
                continue;
            }

            if (set.Contains(cat.RequiredDataclass))
                list.Add(cat);
        }

        return list;
    }

    public static IReadOnlyList<CloudKitContainerBinding> ContainersForSelection(
        IEnumerable<string> selectedIds)
    {
        var ids = new HashSet<string>(selectedIds, StringComparer.OrdinalIgnoreCase);
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<CloudKitContainerBinding>();
        foreach (var cat in All)
        {
            if (!ids.Contains(cat.Id))
                continue;
            foreach (var c in cat.Containers)
            {
                if (seen.Add(c.ContainerId))
                    list.Add(c);
            }
        }

        return list;
    }

    public static bool SelectionIncludesAccountInfo(IEnumerable<string> selectedIds) =>
        selectedIds.Any(id => string.Equals(id, AccountInfoId, StringComparison.OrdinalIgnoreCase));

    /// <summary>PCS/Escrow necessario solo se c'è almeno un container CloudKit.</summary>
    public static bool SelectionRequiresPcs(IEnumerable<string> selectedIds) =>
        ContainersForSelection(selectedIds).Count > 0;

    /// <summary>
    /// Categorie selezionabili in UI per test runtime.
    /// Abilitate se hanno almeno un container CloudKit candidato, oppure Account Info.
    /// FileVault2 resta fuori (path KVS/Keychain, non CK).
    /// Flusso generico: zone/retrieve → zone/sync → record/sync sulle zone trovate
    /// (non record/retrieve: serve quando conosci già i record name).
    /// </summary>
    public static bool IsRecoverable(Category cat) =>
        cat.UiEnabled && (cat.IncludeAccountInfo || cat.Containers.Count > 0);

    /// <summary>True se la categoria è in catalogo ma ancora senza container CK candidato.</summary>
    public static bool NeedsContainerDiscovery(Category cat) =>
        !cat.IncludeAccountInfo && cat.Containers.Count == 0;

    /// <summary>
    /// Candidati probe da dataclass account + entitlement-style container già in catalogo.
    /// Usato da CloudKit Containers probe / Sync Data discovery.
    /// </summary>
    public static IReadOnlyList<CloudKitContainerBinding> DiscoveryCandidatesForDataclasses(
        IReadOnlyCollection<string> availableDataclasses)
    {
        var set = new HashSet<string>(availableDataclasses, StringComparer.OrdinalIgnoreCase);
        var hasCk = set.Contains("com.apple.Dataclass.CKDatabaseService");
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var list = new List<CloudKitContainerBinding>();

        foreach (var cat in All)
        {
            if (cat.Containers.Count == 0)
                continue;
            if (cat.RequiredDataclass is not null && !set.Contains(cat.RequiredDataclass))
                continue;
            if (cat.RequiredDataclass is null && !hasCk)
                continue;
            foreach (var c in cat.Containers)
            {
                if (seen.Add(c.ContainerId))
                    list.Add(c);
            }
        }

        return list;
    }
}
