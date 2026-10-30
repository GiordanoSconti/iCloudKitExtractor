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

    public sealed record Category(
        string Id,
        string DisplayName,
        /// <summary>Dataclass richiesta (null = CloudKit generico se CKDatabaseService disponibile).</summary>
        string? RequiredDataclass,
        IReadOnlyList<CloudKitContainerBinding> Containers,
        bool IncludeAccountInfo = false,
        bool DefaultChecked = false);

    /// <summary>Ordine UI allineato all’elenco Sync Data (Photos prima).</summary>
    public static IReadOnlyList<Category> All { get; } =
    [
        new(PhotosId, "Photos", "com.apple.Dataclass.CloudPhotos",
            [new("com.apple.photos.cloud", "com.apple.Photos")],
            DefaultChecked: true),
        new(AccountInfoId, "Account Info", null,
            [], IncludeAccountInfo: true),
        new("maps", "Apple Maps", null,
            [new("com.apple.Maps.Sync", "com.apple.Maps")]),
        new("calendars", "Calendars", "com.apple.Dataclass.Calendars",
            []),
        new("contacts", "Contacts", "com.apple.Dataclass.Contacts",
            []),
        new("calls", "Calls", null,
        [
            new("com.apple.CallHistory", "com.apple.callhistory.sync-helper"),
            // CallHistorySyncHelper entitlement: service map → cloud-storage.
            new("com.apple.callhistory.cloud-storage", "com.apple.callhistory.sync-helper"),
        ]),
        new("filevault", "FileVault2 token", null,
            []),
        new("health", "Health", "com.apple.Dataclass.Health",
            [new("com.apple.health.sync", "com.apple.healthd")]),
        new("ibooks", "iBooks", null,
            [new("com.apple.iBooks", "com.apple.iBooks")]),
        new("keychain", "Keychain", "com.apple.Dataclass.KeychainSync",
            [new("com.apple.security.keychain", "com.apple.securityd")]),
        new("messages", "Messages", null,
            [new("com.apple.messages.cloud", "com.apple.imagent")]),
        new("notes", "Notes", "com.apple.Dataclass.Notes",
            [new("com.apple.notes", "com.apple.Notes")]),
        new("safari", "Safari", "com.apple.Dataclass.Bookmarks",
        [
            new("com.apple.SafariShared.WBSCloudBookmarksStore", "com.apple.SafariBookmarksSyncAgent"),
            new("com.apple.SafariShared.CloudTabs", "com.apple.SafariBookmarksSyncAgent"),
            new("com.apple.SafariShared.WBSCloudHistoryStore", "com.apple.Safari"),
        ]),
        new("screentime", "Screen Time", null,
            []),
        new("voicememos", "Voice Memos", null,
            [new("com.apple.VoiceMemosContainer", "com.apple.voicememod")]),
        new("wallet", "Wallet", null,
            []),
        new("wifi", "Wi-Fi", null,
            []),
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
    /// Categorie recuperabili in UI. Photos, Account Info, Voice Memos.
    /// Le altre restano «(presto)» disabilitate.
    /// </summary>
    public static bool IsRecoverable(Category cat) =>
        string.Equals(cat.Id, PhotosId, StringComparison.OrdinalIgnoreCase)
        || string.Equals(cat.Id, AccountInfoId, StringComparison.OrdinalIgnoreCase)
        || string.Equals(cat.Id, "voicememos", StringComparison.OrdinalIgnoreCase);
}
