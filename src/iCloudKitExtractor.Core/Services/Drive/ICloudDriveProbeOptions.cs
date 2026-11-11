namespace iCloudKitExtractor.Services.Drive;

/// <summary>
/// Opzioni probe CloudDocs. Modalità <see cref="ICloudFiles"/> allinea
/// <c>capture_icloud_drive_20260905_072447</c>: tutte le zone (CloudDocs + WhatsApp + app),
/// path rebuild Directory, output <c>icloud_files_*</c>.
/// </summary>
public sealed class ICloudDriveProbeOptions
{
    /// <summary>Solo Drive utente (+ checkbox app legacy).</summary>
    public static ICloudDriveProbeOptions Drive(bool includeAppZones) => new()
    {
        Mode = ICloudDriveProbeMode.Drive,
        IncludeAppZones = includeAppZones,
        IncludeWhatsAppZones = false,
        RebuildDirectoryPaths = true,
        OutputFolderPrefix = "icloud_drive",
    };

    /// <summary>iCloud Files  tutte le zone documenti + metadati + path tree.</summary>
    public static ICloudDriveProbeOptions ICloudFiles() => new()
    {
        Mode = ICloudDriveProbeMode.Files,
        IncludeAppZones = true,
        IncludeWhatsAppZones = true,
        RebuildDirectoryPaths = true,
        OutputFolderPrefix = "icloud_files",
    };

    public ICloudDriveProbeMode Mode { get; init; } = ICloudDriveProbeMode.Drive;
    public bool IncludeAppZones { get; init; }
    public bool IncludeWhatsAppZones { get; init; }
    public bool RebuildDirectoryPaths { get; init; } = true;
    public string OutputFolderPrefix { get; init; } = "icloud_drive";
}

public enum ICloudDriveProbeMode
{
    Drive,
    Files,
}
