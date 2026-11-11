using System.IO;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace iCloudKitExtractor.Services.Forensics;

/// <summary>
/// Case package root: <c>case.json</c> + acquisition subfolders under a chosen destination.
/// </summary>
public sealed class IkeCaseSession
{
    public const string CaseFileName = "case.json";

    public const string LogsFolder = "logs";
    public const string BackupFolder = "backup";
    public const string EscrowFolder = "escrow";
    public const string WhatsAppFolder = "whatsapp";
    public const string DriveFolder = "drive";
    public const string FilesFolder = "files";
    public const string SyncDataFolder = "syncdata";
    public const string MailFolder = "mail";
    public const string ReportFolder = "report";
    public const string OpsFolder = "ops";

    private static readonly string[] Subfolders =
    [
        LogsFolder,
        BackupFolder,
        EscrowFolder,
        WhatsAppFolder,
        DriveFolder,
        FilesFolder,
        SyncDataFolder,
        MailFolder,
        ReportFolder,
        OpsFolder,
    ];

    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public IkeCaseInfo Info { get; private set; }

    public string RootPath => Info.RootPath;

    public string LogsRoot => Path.Combine(RootPath, LogsFolder);
    public string BackupRoot => Path.Combine(RootPath, BackupFolder);
    public string EscrowRoot => Path.Combine(RootPath, EscrowFolder);
    public string WhatsAppRoot => Path.Combine(RootPath, WhatsAppFolder);
    public string DriveRoot => Path.Combine(RootPath, DriveFolder);
    public string FilesRoot => Path.Combine(RootPath, FilesFolder);
    public string SyncDataRoot => Path.Combine(RootPath, SyncDataFolder);
    public string MailRoot => Path.Combine(RootPath, MailFolder);
    public string ReportRoot => Path.Combine(RootPath, ReportFolder);
    public string OpsRoot => Path.Combine(RootPath, OpsFolder);

    public string CaseJsonPath => Path.Combine(RootPath, CaseFileName);
    public string OperationsJsonlPath => Path.Combine(OpsRoot, IkeCaseOpsJournal.FileName);

    private IkeCaseSession(IkeCaseInfo info) => Info = info;

    public static IkeCaseSession Create(string destinationRoot, IkeCaseInfoDraft draft)
    {
        if (string.IsNullOrWhiteSpace(destinationRoot))
            throw new ArgumentException("Destination folder is required.", nameof(destinationRoot));
        if (string.IsNullOrWhiteSpace(draft.CaseId))
            throw new ArgumentException("Case ID is required.", nameof(draft));
        if (string.IsNullOrWhiteSpace(draft.CaseName))
            throw new ArgumentException("Case name is required.", nameof(draft));
        if (string.IsNullOrWhiteSpace(draft.Examiner))
            throw new ArgumentException("Examiner is required.", nameof(draft));

        var root = Path.GetFullPath(destinationRoot.Trim());
        Directory.CreateDirectory(root);
        EnsureSubfolders(root);

        var now = DateTimeOffset.UtcNow;
        var info = new IkeCaseInfo
        {
            CaseId = draft.CaseId.Trim(),
            CaseName = draft.CaseName.Trim(),
            Examiner = draft.Examiner.Trim(),
            Agency = NullIfWhiteSpace(draft.Agency),
            Notes = NullIfWhiteSpace(draft.Notes),
            CreatedAt = now,
            UpdatedAt = now,
            RootPath = root,
            SchemaVersion = 1,
        };

        var session = new IkeCaseSession(info);
        session.Save();
        return session;
    }

    public static IkeCaseSession Open(string destinationRoot)
    {
        if (string.IsNullOrWhiteSpace(destinationRoot))
            throw new ArgumentException("Destination folder is required.", nameof(destinationRoot));

        var root = Path.GetFullPath(destinationRoot.Trim());
        var path = Path.Combine(root, CaseFileName);
        if (!File.Exists(path))
            throw new FileNotFoundException($"No {CaseFileName} in the selected folder.", path);

        var json = File.ReadAllText(path);
        var info = JsonSerializer.Deserialize<IkeCaseInfo>(json, JsonOptions)
                   ?? throw new InvalidDataException($"{CaseFileName} is empty or invalid.");
        if (string.IsNullOrWhiteSpace(info.CaseId)
            || string.IsNullOrWhiteSpace(info.CaseName)
            || string.IsNullOrWhiteSpace(info.Examiner))
            throw new InvalidDataException($"{CaseFileName} is missing required fields.");

        info.RootPath = root;
        EnsureSubfolders(root);
        return new IkeCaseSession(info);
    }

    public static bool TryFindCaseJson(string destinationRoot, out string caseJsonPath)
    {
        caseJsonPath = "";
        if (string.IsNullOrWhiteSpace(destinationRoot))
            return false;
        try
        {
            var path = Path.Combine(Path.GetFullPath(destinationRoot.Trim()), CaseFileName);
            if (!File.Exists(path))
                return false;
            caseJsonPath = path;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public void UpdateMetadata(IkeCaseInfoDraft draft)
    {
        if (string.IsNullOrWhiteSpace(draft.CaseId))
            throw new ArgumentException("Case ID is required.", nameof(draft));
        if (string.IsNullOrWhiteSpace(draft.CaseName))
            throw new ArgumentException("Case name is required.", nameof(draft));
        if (string.IsNullOrWhiteSpace(draft.Examiner))
            throw new ArgumentException("Examiner is required.", nameof(draft));

        Info.CaseId = draft.CaseId.Trim();
        Info.CaseName = draft.CaseName.Trim();
        Info.Examiner = draft.Examiner.Trim();
        Info.Agency = NullIfWhiteSpace(draft.Agency);
        Info.Notes = NullIfWhiteSpace(draft.Notes);
        Info.UpdatedAt = DateTimeOffset.UtcNow;
        Save();
    }

    public void Save()
    {
        Directory.CreateDirectory(RootPath);
        EnsureSubfolders(RootPath);
        var json = JsonSerializer.Serialize(Info, JsonOptions);
        File.WriteAllText(CaseJsonPath, json);
    }

    public bool IsUnderCaseRoot(string? path)
    {
        if (string.IsNullOrWhiteSpace(path))
            return false;
        try
        {
            var full = Path.GetFullPath(path.Trim());
            var root = Path.GetFullPath(RootPath);
            if (!root.EndsWith(Path.DirectorySeparatorChar)
                && !root.EndsWith(Path.AltDirectorySeparatorChar))
                root += Path.DirectorySeparatorChar;
            return full.StartsWith(root, StringComparison.OrdinalIgnoreCase)
                   || string.Equals(
                       full.TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                       Path.GetFullPath(RootPath).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar),
                       StringComparison.OrdinalIgnoreCase);
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Deletes all files under <see cref="EscrowRoot"/> (keys / bottles / CKKS exports)
    /// and recreates an empty <c>escrow/</c> folder. Called after CloudKit Report generation.
    /// </summary>
    public int PurgeEscrowSensitiveData()
    {
        var root = EscrowRoot;
        var deleted = 0;
        if (Directory.Exists(root))
        {
            foreach (var f in Directory.EnumerateFiles(root, "*", SearchOption.AllDirectories))
            {
                try
                {
                    File.SetAttributes(f, FileAttributes.Normal);
                    File.Delete(f);
                    deleted++;
                }
                catch
                {
                    // best-effort purge
                }
            }

            try
            {
                Directory.Delete(root, recursive: true);
            }
            catch
            {
                // leftover locked dirs — EnsureSubfolders recreates as needed
            }
        }

        Directory.CreateDirectory(root);
        return deleted;
    }

    private static void EnsureSubfolders(string root)
    {
        foreach (var name in Subfolders)
            Directory.CreateDirectory(Path.Combine(root, name));
    }

    private static string? NullIfWhiteSpace(string? value) =>
        string.IsNullOrWhiteSpace(value) ? null : value.Trim();
}

public sealed class IkeCaseInfo
{
    public int SchemaVersion { get; set; } = 1;
    public string CaseId { get; set; } = "";
    public string CaseName { get; set; } = "";
    public string Examiner { get; set; } = "";
    public string? Agency { get; set; }
    public string? Notes { get; set; }
    public DateTimeOffset CreatedAt { get; set; }
    public DateTimeOffset UpdatedAt { get; set; }
    /// <summary>Absolute case root; rewritten on Open to the folder that contains case.json.</summary>
    public string RootPath { get; set; } = "";
}

public sealed class IkeCaseInfoDraft
{
    public string CaseId { get; set; } = "";
    public string CaseName { get; set; } = "";
    public string Examiner { get; set; } = "";
    public string? Agency { get; set; }
    public string? Notes { get; set; }
}
