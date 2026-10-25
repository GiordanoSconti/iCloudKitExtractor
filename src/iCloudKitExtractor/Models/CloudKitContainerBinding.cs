namespace iCloudKitExtractor.Models;

/// <summary>Identificatori CloudKit (container + bundle) per header HTTP e protobuf.</summary>
public sealed record CloudKitContainerBinding(string ContainerId, string BundleId)
{
    public static CloudKitContainerBinding Backup { get; } =
        new("com.apple.backup.ios", "com.apple.backupd");

    /// <summary>
    /// Container iCloud WhatsApp (entitlement <c>icloud-container-identifiers</c>).
    /// </summary>
    public static CloudKitContainerBinding WhatsApp { get; } =
        new("57T9237FN3.net.whatsapp.WhatsApp", "net.whatsapp.WhatsApp");

    /// <summary>iCloud Drive / CloudDocuments ( container <c>com.apple.clouddocs</c>, bundle <c>com.apple.CloudDocs</c>).</summary>
    public static CloudKitContainerBinding CloudDocs { get; } =
        new("com.apple.clouddocs", "com.apple.CloudDocs");

    /// <summary>
    /// Find My Items / AirTag (OpenBubbles rustpush):
    /// container <c>com.apple.icloud.searchparty</c>, bundle <c>com.apple.icloud.searchpartyd</c>,
    /// zona privata <c>BeaconStore</c> (PCS Manatee).
    /// </summary>
    public static CloudKitContainerBinding SearchParty { get; } =
        new("com.apple.icloud.searchparty", "com.apple.icloud.searchpartyd");

    /// <summary>
    /// Octagon / Cuttlefish code/invoke (appleservices):
    /// container <c>com.apple.security.keychain</c>, bundle <c>com.apple.security.cuttlefish</c>.
    /// </summary>
    public static CloudKitContainerBinding Cuttlefish { get; } =
        new("com.apple.security.keychain", "com.apple.security.cuttlefish");

    /// <summary>
    /// Container Sync Data (capture <c>capture_http_20260802_054842</c>):
    /// dopo Escrow → ckAppInit → zone/retrieve → record/sync.
    /// </summary>
    public static IReadOnlyList<CloudKitContainerBinding> SyncDataContainers { get; } =
    [
        new("com.apple.photos.cloud", "com.apple.Photos"),
        new("com.apple.Maps.Sync", "com.apple.Maps"),
        new("com.apple.CallHistory", "com.apple.callhistory.sync-helper"),
        new("com.apple.health.sync", "com.apple.healthd"),
        new("com.apple.iBooks", "com.apple.iBooks"),
        new("com.apple.security.keychain", "com.apple.securityd"),
        new("com.apple.messages.cloud", "com.apple.imagent"),
        new("com.apple.notes", "com.apple.Notes"),
        new("com.apple.SafariShared.WBSCloudBookmarksStore", "com.apple.SafariBookmarksSyncAgent"),
        new("com.apple.SafariShared.CloudTabs", "com.apple.SafariBookmarksSyncAgent"),
        new("com.apple.SafariShared.WBSCloudHistoryStore", "com.apple.Safari"),
        new("com.apple.VoiceMemosContainer", "com.apple.voicememod"),
    ];
}
