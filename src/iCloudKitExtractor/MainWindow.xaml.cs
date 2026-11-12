using System.IO;
using System.Threading;
using System.Text.Json;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Documents;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Threading;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services;
using iCloudKitExtractor.Services.Auth;
using iCloudKitExtractor.Services.Backup;
using iCloudKitExtractor.Services.Http;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.WhatsApp;
using iCloudKitExtractor.Services.Drive;
using iCloudKitExtractor.Services.SyncData;
using iCloudKitExtractor.Services.Quota;
using iCloudKitExtractor.Services.SharedStreams;
using iCloudKitExtractor.Services.Contacts;
using iCloudKitExtractor.Services.FindMy;
using iCloudKitExtractor.Services.Mail;
using iCloudKitExtractor.Services.Push;
using iCloudKitExtractor.Services.Ids;
using iCloudKitExtractor.Services.IMessage;
using iCloudKitExtractor.Services.CloudKit;
using iCloudKitExtractor.Services.Forensics;
using MailKit;
using Microsoft.Win32;
using System.Diagnostics;



namespace iCloudKitExtractor;



public partial class MainWindow : Window

{

    private readonly AppleHttpClientFactory _httpFactory = new();

    private readonly HttpSessionCapture _capture = HttpSessionCapture.CreateNew();

    private HttpClient? _http;

    private ICloudSession? _session;

    private ICloudBackupOrchestrator? _orchestrator;

    private ApsSessionService? _apsSession;

    /// <summary>Live Madrid / iMessage client bound to APS (Trusted devices tab).</summary>
    private MadridClient? _madridClient;

    /// <summary>Partial GSA session waiting for HSA2 OTP (2FA list).</summary>
    private ICloudSession? _hsa2PartialSession;

    private AnisetteAuthProfile? _authProfile;

    private bool _licenseOverlayShown;

    private List<BackupDevice> _devices = new();

    /// <summary>True mentre è in corso Aggiorna elenco (lista e/o decrypt backupProperties).</summary>
    private bool _backupListBusy;

    /// <summary>True mentre è in corso Scarica backup (HTTP GET/POST vanno nel log Backup).</summary>
    private bool _downloadBusy;

    /// <summary>Sessione live del download in attesa di Sign In/2FA mid-download.</summary>
    private ICloudSession? _midDownloadLiveSession;
    private TaskCompletionSource<bool>? _midDownloadAuthTcs;

    /// <summary>Ultimo stato progresso download (per ripristino dopo “copia log”).</summary>
    private string _lastDownloadProgressStatus = "";

    /// <summary>Generazione flash status “copia log” (click ripetuti annullano il restore precedente).</summary>
    private int _downloadStatusFlashGeneration;

    /// <summary>Peak contatori UI (BeginInvoke out-of-order non deve regressare Decifrati/Scaricati).</summary>
    private int _uiPeakFilesDownloaded;
    private int _uiPeakFilesDecrypted;
    private int _uiPeakFilesDecryptFailed;
    private int _uiPeakFilesCiphertextSaved;
    private int _uiPeakFilesDuplicated;
    /// <summary>Ultimo ReportSequence applicato (scarta report stale).</summary>
    private long _uiLastProgressSeq;
    /// <summary>Coalesce: un solo BeginInvoke in volo con l’ultimo report.</summary>
    private DownloadProgressReport? _uiPendingProgress;
    private int _uiProgressFlushScheduled;
    private int _uiStatusLogCount;
    private int _uiErrorLogCount;

    /// <summary>Avvio download backup (UTC) per tempo trascorso + progress byte.</summary>
    private DateTime? _backupDownloadStartedUtc;
    private DispatcherTimer? _downloadTimingTimer;
    private int _timingFilesDone;
    private int _timingFilesTotal;
    private long _timingBytesDone;
    private long _timingBytesTotal;
    /// <summary>Traffico HTTP cumulato (WireBytes) per la riga Rete.</summary>
    private long _timingWireBytes;
    private int _uiBytesProgressLogCount;
    /// <summary>Ultima <see cref="DownloadProgressReport.SnapshotLabel"/> applicata ai byte UI (reset cross-snapshot).</summary>
    private string? _uiLastBytesSnapshotLabel;

    /// <summary>
    /// True dopo che backupProperties è stato elaborato e la griglia Snapshot è stata riaggiornata.
    /// </summary>
    private bool _backupPropertiesReady;

    private ImapMailClient? _imapMail;
    private string? _imapSelectedFolder;
    private CancellationTokenSource? _imapCts;
    private ImapMessageFilter? _imapFilter;

    /// <summary>Active forensic case package (required before Sign in).</summary>
    private IkeCaseSession? _case;
    private bool _suppressPathWarn;
    private string? _lastReportPath;

    public MainWindow()

    {

        InitializeComponent();
        WireOutputPathLostFocus();
        UpdateDownloadButtonLabel();
        RemoteAnisetteProvider.AnyLicenseBundleIssued += OnAnisetteLicenseBundleIssued;
        RemoteAnisetteProvider.AnyLicenseReplicaSynced += OnAnisetteLicenseReplicaSynced;

        OutputFolderTextBox.Text = "";
        DecryptOutputTextBox.Text = "";
        WhatsAppOutputTextBox.Text = "";
        ICloudDriveOutputTextBox.Text = "";
        ICloudFilesOutputTextBox.Text = "";
        SyncDataOutputTextBox.Text = "";

        _httpFactory.Capture = _capture;

        // BeginInvoke: Invoke sincrono durante authorizeGet/edge blocca UI e download.
        // Durante elenco/download backup → scheda Backup (Informazioni/Avvisi/Errori); altrimenti Sign In.
        _httpFactory.HttpLogLine += line =>
        {
            var msg = $"[HTTP] {line}";
            if (IkeLogOptions.Quiet && !IkeLogOptions.IsErrorLine(msg))
                return;
            Dispatcher.BeginInvoke(() => AppendHttpTrafficLog(line));
        };

        SyncQuietLogFromUi();
        SyncPersistRunLogsFromUi();
        SyncFullHarCaptureFromUi();
        if (IkeLogOptions.FullHarCapture)
        {
            LogAuth(
                "Full HAR: ON → session.har / session_redacted.har in " +
                "%AppData%\\iCloudKitExtractor\\logs\\run_*");
        }
        else if (IkeLogOptions.PersistRunLogs)
        {
            LogAuth("Capture run: enabled (folder created on first event → %AppData%\\iCloudKitExtractor\\logs\\run_*)");
        }
        else
        {
            LogAuth("Capture run: disabled (no logs in %AppData%\\iCloudKitExtractor\\logs)");
        }
        LoadAnisetteSettingsUi();
        LogAuth($"Anisette: {AnisetteProviderFactory.ResolveServerUrl()} | mode: {AnisetteProviderFactory.ResolveAuthMode()}");
        LogAuth($"  config: {AnisetteProviderFactory.SettingsFilePath}");
        Loaded += MainWindow_Loaded;
        ApplyResponsiveLayout(ActualWidth, ActualHeight);
        HookRichLogResize(DownloadInfoLogBox);
        HookRichLogResize(DownloadWarningLogBox);
        HookRichLogResize(DownloadErrorLogBox);
        HookRichLogResize(SyncDataInfoLogBox);
        HookRichLogResize(SyncDataErrorLogBox);

        SyncDiskDumpFromUi();
        UpdateSessionUi(false);
        ApplyUiWizardStage(UiWizardStage.CaseOnly);
    }

    private enum UiWizardStage
    {
        /// <summary>Solo scheda Case (nessun login finché il caso non è aperto).</summary>
        CaseOnly = 0,
        /// <summary>Caso aperto → Sign In (e tab sempre-on post-caso).</summary>
        LoginOnly = 1,
        /// <summary>Login OK → Escrow abilitata e selezionata.</summary>
        AfterLogin = 2,
        /// <summary>Escrow OK → tutte le schede abilitate (resta su Escrow se già lì).</summary>
        AfterEscrow = 3,
    }

    private void ApplyUiWizardStage(UiWizardStage stage, bool selectTab = true)
    {
        if (MainTabControl is null || CaseTab is null || AccessTab is null)
            return;

        CaseTab.IsEnabled = true;
        var hasCase = stage >= UiWizardStage.LoginOnly;
        AccessTab.IsEnabled = hasCase;
        if (ReportTab is not null)
            ReportTab.IsEnabled = hasCase;
        EscrowTab.IsEnabled = stage >= UiWizardStage.AfterLogin;
        if (ExploratoryServicesTab is not null)
            ExploratoryServicesTab.IsEnabled = stage >= UiWizardStage.AfterLogin;
        if (TrustedDevicesTab is not null)
            TrustedDevicesTab.IsEnabled = hasCase;
        if (ImapMailTab is not null)
            ImapMailTab.IsEnabled = hasCase;
        PrefillImapUserFromSession();
        PrefillEscrowRecoverySaltFromSession();
        var rest = stage >= UiWizardStage.AfterEscrow;
        BackupTab.IsEnabled = rest;
        WhatsAppTab.IsEnabled = rest;
        ICloudDriveTab.IsEnabled = rest;
        ICloudFilesTab.IsEnabled = rest;
        SyncDataTab.IsEnabled = rest;

        if (stage == UiWizardStage.AfterLogin)
            RecordCaseOp("auth", "signed-in", "wizard → Escrow");
        else if (stage == UiWizardStage.AfterEscrow)
            RecordCaseOp("escrow", "unlocked", "wizard → acquisition tabs");

        if (!selectTab)
            return;

        MainTabControl.SelectedItem = stage switch
        {
            UiWizardStage.CaseOnly => CaseTab,
            UiWizardStage.AfterLogin => EscrowTab,
            UiWizardStage.AfterEscrow => EscrowTab,
            _ => AccessTab,
        };
    }

    private void WireOutputPathLostFocus()
    {
        void Hook(TextBox? box)
        {
            if (box is null)
                return;
            box.LostFocus += (_, _) => OnOutputPathLostFocus(box);
        }

        Hook(OutputFolderTextBox);
        Hook(DecryptOutputTextBox);
        Hook(WhatsAppOutputTextBox);
        Hook(ICloudDriveOutputTextBox);
        Hook(ICloudFilesOutputTextBox);
        Hook(SyncDataOutputTextBox);
    }

    private void AppendCaseLog(string line) =>
        AppendBoundedLog(CaseLogTextBox, line, "case");

    private IkeCaseInfoDraft ReadCaseDraftFromUi() =>
        new()
        {
            CaseId = CaseIdTextBox?.Text?.Trim() ?? "",
            CaseName = CaseNameTextBox?.Text?.Trim() ?? "",
            Examiner = CaseExaminerTextBox?.Text?.Trim() ?? "",
            Agency = CaseAgencyTextBox?.Text?.Trim(),
            Notes = CaseNotesTextBox?.Text?.Trim(),
        };

    private void FillCaseUiFromSession(IkeCaseSession session)
    {
        _suppressPathWarn = true;
        try
        {
            CaseIdTextBox.Text = session.Info.CaseId;
            CaseNameTextBox.Text = session.Info.CaseName;
            CaseExaminerTextBox.Text = session.Info.Examiner;
            CaseAgencyTextBox.Text = session.Info.Agency ?? "";
            CaseNotesTextBox.Text = session.Info.Notes ?? "";
            CaseDestinationTextBox.Text = session.RootPath;
            OutputFolderTextBox.Text = session.BackupRoot;
            DecryptOutputTextBox.Text = session.EscrowRoot;
            WhatsAppOutputTextBox.Text = session.WhatsAppRoot;
            ICloudDriveOutputTextBox.Text = session.DriveRoot;
            ICloudFilesOutputTextBox.Text = session.FilesRoot;
            SyncDataOutputTextBox.Text = session.SyncDataRoot;
        }
        finally
        {
            _suppressPathWarn = false;
        }

        if (SaveCaseMetadataButton is not null)
            SaveCaseMetadataButton.IsEnabled = true;
        CaseStatusText.Text =
            $"Case open: {session.Info.CaseId} — {session.Info.CaseName} @ {session.RootPath}";
        CaseLayoutHintText.Text =
            $"Root: {session.RootPath}\n" +
            $"logs/ · backup/ · escrow/ · whatsapp/ · drive/ · files/ · syncdata/ · mail/ · ops/ · report/\n" +
            $"case.json · createdUtc={session.Info.CreatedAt:O}";
    }

    private void ActivateCaseSession(IkeCaseSession session)
    {
        _case = session;
        FillCaseUiFromSession(session);
        IkeUiSessionLog.RelocateToLogsRoot(session.LogsRoot);
        _capture.TrySetLogsRoot(session.LogsRoot);
        var uiDir = IkeUiSessionLog.SessionDirectory;
        AppendCaseLog($"Case ready → {session.RootPath}");
        AppendCaseLog($"  id={session.Info.CaseId} examiner={session.Info.Examiner}");
        if (uiDir is not null)
            AppendCaseLog($"UI logs → {uiDir}");
        LogAuth($"Case open: {session.Info.CaseId} @ {session.RootPath}");
        IkeCaseOpsJournal.Append(session, "case", "opened",
            $"id={session.Info.CaseId}; examiner={session.Info.Examiner}");
        ApplyUiWizardStage(UiWizardStage.LoginOnly);
    }

    private void AppendReportLog(string line) =>
        AppendBoundedLog(ReportLogTextBox, line, "report");

    private void RecordCaseOp(string area, string action, string? detail = null, string status = "ok") =>
        IkeCaseOpsJournal.Append(_case, area, action, detail, status);

    private byte[]? TryLoadReportLogoPng()
    {
        try
        {
            var uri = new Uri("pack://application:,,,/Assets/app-icon.png");
            var info = System.Windows.Application.GetResourceStream(uri);
            if (info?.Stream is null)
                return null;
            using var ms = new MemoryStream();
            info.Stream.CopyTo(ms);
            return ms.ToArray();
        }
        catch
        {
            return null;
        }
    }

    private void GenerateReportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_case is null)
        {
            MessageBox.Show(this, "Create or open a case first.", "LE Report",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            AppendReportLog("Building CloudKit Report…");
            var model = IkeCaseReportBuilder.Build(_case, TryLoadReportLogoPng());
            var path = IkeCaseReportHtmlWriter.Write(_case, model);
            _lastReportPath = path;
            if (model.LogoPng is { Length: > 0 })
            {
                try
                {
                    File.WriteAllBytes(Path.Combine(_case.ReportRoot, "logo.png"), model.LogoPng);
                }
                catch { /* optional companion */ }
            }

            ReportStatusText.Text =
                $"Report ready · {model.Operations.Count} ops · " +
                $"{model.IntegrityManifests.Count} integrity manifests · {path}";
            AppendReportLog($"Wrote {path}");
            AppendReportLog(
                $"  areas with data: {model.Areas.Count(a => a.FileCount > 0)} · " +
                $"files={model.Areas.Sum(a => a.FileCount):N0}");
            RecordCaseOp("report", "generated", Path.GetFileName(path));

            var purged = _case.PurgeEscrowSensitiveData();
            RecordCaseOp("escrow", "purged",
                purged > 0 ? $"{purged} file(s) removed after report" : "escrow/ cleared after report");
            AppendReportLog($"Escrow purged ({purged} file(s)) — sensitive material removed.");

            MessageBox.Show(this,
                "CloudKit Report generated.\n\n" + path +
                "\n\nEscrow data was purged. The case will now close and the UI will reset.",
                "LE Report",
                MessageBoxButton.OK, MessageBoxImage.Information);

            CloseCaseAndResetUi($"report generated → {Path.GetFileName(path)}");
        }
        catch (Exception ex)
        {
            AppendReportLog($"Generate failed: {ex.Message}");
            MessageBox.Show(this, ex.Message, "LE Report",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    /// <summary>
    /// Closes the active case, clears auth/session state, and returns every tab to Case-only.
    /// </summary>
    private void CloseCaseAndResetUi(string? reason = null)
    {
        if (_case is not null)
        {
            try
            {
                IkeCaseOpsJournal.Append(_case, "case", "closed",
                    string.IsNullOrWhiteSpace(reason) ? null : reason);
            }
            catch { /* journal best-effort */ }
        }

        _case = null;
        _session = null;
        _orchestrator = null;
        _madridClient = null;
        _lastReportPath = null;
        _imapMail = null;
        _imapSelectedFolder = null;
        try { _imapCts?.Cancel(); } catch { /* ignore */ }
        _imapCts = null;

        _suppressPathWarn = true;
        try
        {
            if (CaseIdTextBox is not null) CaseIdTextBox.Text = "";
            if (CaseNameTextBox is not null) CaseNameTextBox.Text = "";
            if (CaseExaminerTextBox is not null) CaseExaminerTextBox.Text = "";
            if (CaseAgencyTextBox is not null) CaseAgencyTextBox.Text = "";
            if (CaseNotesTextBox is not null) CaseNotesTextBox.Text = "";
            if (CaseDestinationTextBox is not null) CaseDestinationTextBox.Text = "";
            if (CaseStatusText is not null) CaseStatusText.Text = "No case open — create or open a case to continue.";
            if (CaseLayoutHintText is not null)
                CaseLayoutHintText.Text =
                    "A case package creates logs/, backup/, escrow/, whatsapp/, drive/, files/, syncdata/, mail/, ops/, report/ under the destination.";

            OutputFolderTextBox.Text = "";
            DecryptOutputTextBox.Text = "";
            WhatsAppOutputTextBox.Text = "";
            ICloudDriveOutputTextBox.Text = "";
            ICloudFilesOutputTextBox.Text = "";
            SyncDataOutputTextBox.Text = "";

            if (AppleIdTextBox is not null) AppleIdTextBox.Text = "";
            if (PasswordBox is not null) PasswordBox.Password = "";
            if (EscrowPasswordBox is not null) EscrowPasswordBox.Password = "";
            if (EscrowRecoverySaltBox is not null) EscrowRecoverySaltBox.Text = "";
            if (Hsa2AppleIdTextBox is not null) Hsa2AppleIdTextBox.Text = "";
            if (Hsa2PasswordBox is not null) Hsa2PasswordBox.Password = "";
            if (ImapAppPasswordBox is not null) ImapAppPasswordBox.Password = "";

            if (ReportStatusText is not null) ReportStatusText.Text = "";
            ClearLogTextBox(CaseLogTextBox);
            ClearLogTextBox(ReportLogTextBox);
        }
        finally
        {
            _suppressPathWarn = false;
        }

        if (SaveCaseMetadataButton is not null)
            SaveCaseMetadataButton.IsEnabled = false;

        UpdateSessionUi(false);
        ApplyUiWizardStage(UiWizardStage.CaseOnly);
        LogAuth(string.IsNullOrWhiteSpace(reason)
            ? "Case closed — UI reset to Case tab."
            : $"Case closed ({reason}) — UI reset to Case tab.");
    }

    private static void ClearLogTextBox(System.Windows.Controls.TextBox? box)
    {
        if (box is null) return;
        box.Clear();
    }

    private void OpenReportButton_Click(object sender, RoutedEventArgs e)
    {
        var path = _lastReportPath;
        if (string.IsNullOrWhiteSpace(path) && _case is not null)
            path = Path.Combine(_case.ReportRoot, IkeCaseReportHtmlWriter.DefaultFileName);
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            MessageBox.Show(this, "Generate the report first.", "LE Report",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            Process.Start(new ProcessStartInfo
            {
                FileName = path,
                UseShellExecute = true,
            });
            AppendReportLog($"Opened {path}");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "LE Report",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void RevealReportFolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (_case is null)
        {
            MessageBox.Show(this, "Create or open a case first.", "LE Report",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            Directory.CreateDirectory(_case.ReportRoot);
            Process.Start(new ProcessStartInfo
            {
                FileName = _case.ReportRoot,
                UseShellExecute = true,
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "LE Report",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void BrowseCaseDestination_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            CaseDestinationTextBox.Text = dlg.FolderName;
    }

    private void CreateCaseButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var root = CaseDestinationTextBox?.Text?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(root))
            {
                MessageBox.Show(this, "Select a destination folder for the case package.", "Case",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            if (IkeCaseSession.TryFindCaseJson(root, out _))
            {
                MessageBox.Show(this,
                    "A case.json already exists in that folder.\nUse \"Open existing\" instead of Create.",
                    "Case", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            var draft = ReadCaseDraftFromUi();
            var session = IkeCaseSession.Create(root, draft);
            IkeCaseOpsJournal.Append(session, "case", "created",
                $"id={session.Info.CaseId}; name={session.Info.CaseName}");
            ActivateCaseSession(session);
            AppendCaseLog("Created case.json and acquisition subfolders.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Case", MessageBoxButton.OK, MessageBoxImage.Error);
            AppendCaseLog($"Create failed: {ex.Message}");
        }
    }

    private void OpenCaseButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var root = CaseDestinationTextBox?.Text?.Trim() ?? "";
            if (string.IsNullOrWhiteSpace(root))
            {
                MessageBox.Show(this, "Select the folder that contains case.json.", "Case",
                    MessageBoxButton.OK, MessageBoxImage.Information);
                return;
            }

            var session = IkeCaseSession.Open(root);
            ActivateCaseSession(session);
            AppendCaseLog("Opened existing case.json.");
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Case", MessageBoxButton.OK, MessageBoxImage.Error);
            AppendCaseLog($"Open failed: {ex.Message}");
        }
    }

    private void SaveCaseMetadataButton_Click(object sender, RoutedEventArgs e)
    {
        if (_case is null)
        {
            MessageBox.Show(this, "Create or open a case first.", "Case",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        try
        {
            _case.UpdateMetadata(ReadCaseDraftFromUi());
            FillCaseUiFromSession(_case);
            AppendCaseLog("case.json metadata updated.");
            MessageBox.Show(this, "Case metadata saved.", "Case",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Case", MessageBoxButton.OK, MessageBoxImage.Error);
            AppendCaseLog($"Save metadata failed: {ex.Message}");
        }
    }

    private bool ConfirmOutsideCase(string? path)
    {
        if (_suppressPathWarn || _case is null || string.IsNullOrWhiteSpace(path))
            return true;
        if (_case.IsUnderCaseRoot(path))
            return true;

        var confirm = MessageBox.Show(this,
            "The selected path is outside the case folder.\n" +
            "Data saved there will not be part of the case package.\n\n" +
            $"Case root: {_case.RootPath}\n" +
            $"Selected: {path}\n\nContinue?",
            "Path outside case",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm == MessageBoxResult.Yes)
        {
            AppendCaseLog($"WARNING: path outside case → {path}");
            LogAuth($"WARNING: path outside case → {path}");
            return true;
        }

        return false;
    }

    private void OnOutputPathLostFocus(TextBox box)
    {
        if (_suppressPathWarn || _case is null)
            return;
        var path = box.Text?.Trim() ?? "";
        if (string.IsNullOrEmpty(path) || _case.IsUnderCaseRoot(path))
            return;
        if (ConfirmOutsideCase(path))
            return;

        _suppressPathWarn = true;
        try
        {
            box.Text = ResolveCaseDefaultForBox(box);
        }
        finally
        {
            _suppressPathWarn = false;
        }
    }

    private string ResolveCaseDefaultForBox(TextBox box)
    {
        if (_case is null)
            return box.Text ?? "";
        if (ReferenceEquals(box, OutputFolderTextBox))
            return _case.BackupRoot;
        if (ReferenceEquals(box, DecryptOutputTextBox))
            return _case.EscrowRoot;
        if (ReferenceEquals(box, WhatsAppOutputTextBox))
            return _case.WhatsAppRoot;
        if (ReferenceEquals(box, ICloudDriveOutputTextBox))
            return _case.DriveRoot;
        if (ReferenceEquals(box, ICloudFilesOutputTextBox))
            return _case.FilesRoot;
        if (ReferenceEquals(box, SyncDataOutputTextBox))
            return _case.SyncDataRoot;
        return _case.RootPath;
    }

    private void ApplyBrowsedFolder(TextBox box, string? folder)
    {
        if (string.IsNullOrEmpty(folder))
            return;
        if (!ConfirmOutsideCase(folder))
            return;
        box.Text = folder;
    }

    private static bool LooksLikeHttp401(string? message)
    {
        if (string.IsNullOrWhiteSpace(message))
            return false;
        if (message.Contains("401", StringComparison.Ordinal))
            return true;
        return message.Contains("Unauthorized", StringComparison.OrdinalIgnoreCase);
    }

    private void ResetWizardToLoginAfterEscrowAuthFailure(string detail)
    {
        AppendDecryptLog($"Escrow auth failed (401) — returning to login. {detail}");
        _session = null;
        _orchestrator = null;
        UpdateSessionUi(false);
        ApplyUiWizardStage(UiWizardStage.LoginOnly);
        LogAuth("Session invalidated after 401 Escrow — repeat Sign In.");
    }

    private void QuietLogCheckBox_Changed(object sender, RoutedEventArgs e) =>
        SyncQuietLogFromUi();

    private void PersistRunLogsCheckBox_Changed(object sender, RoutedEventArgs e) =>
        SyncPersistRunLogsFromUi();

    private void FullHarCaptureCheckBox_Changed(object sender, RoutedEventArgs e) =>
        SyncFullHarCaptureFromUi();

    private void SyncQuietLogFromUi()
    {
        // Checkbox ha priorità sull'env dopo il load UI.
        if (QuietLogCheckBox is not null)
            IkeLogOptions.SetQuiet(QuietLogCheckBox.IsChecked == true);
    }

    private void SyncPersistRunLogsFromUi()
    {
        if (PersistRunLogsCheckBox is not null)
            IkeLogOptions.SetPersistRunLogs(PersistRunLogsCheckBox.IsChecked == true);
    }

    private void SyncFullHarCaptureFromUi()
    {
        if (FullHarCaptureCheckBox is null)
            return;
        var on = FullHarCaptureCheckBox.IsChecked == true;
        IkeLogOptions.SetFullHarCapture(on);
        if (on && PersistRunLogsCheckBox is not null && PersistRunLogsCheckBox.IsChecked != true)
            PersistRunLogsCheckBox.IsChecked = true;
        if (on)
        {
            LogAuth(
                "HAR completo: ON → %AppData%\\iCloudKitExtractor\\logs\\run_*\\session.har " +
                "(+ session_redacted.har). Also captures HTTP 2xx in Quiet.");
        }
    }

    private void SyncDiskDumpFromUi()
    {
        if (DumpAuthCheckBox is null)
            return;
        IkeDiskDumpOptions.SetFromUi(
            DumpAuthCheckBox.IsChecked == true,
            DumpEdgeCheckBox.IsChecked == true,
            DumpKalamaCheckBox.IsChecked == true);
    }

    private void HookRichLogResize(RichTextBox box)
    {
        box.SizeChanged += (_, _) => FitRichLogPageWidth(box, box.Document);
    }



    private HttpClient Http => _http ??= _httpFactory.Create();

    private TrustedDevicesService CreateTrustedDevicesService() => new();



    private ICloudBackupOrchestrator Orchestrator
    {
        get
        {
            if (_orchestrator is null)
            {
                _orchestrator = new ICloudBackupOrchestrator(
                    Http,
                    AnisetteProviderFactory.CreateAuth(Http),
                    _authProfile?.UseFullIphoneAuth ?? false);
                WireOrchestratorCallbacks(_orchestrator);
            }

            return _orchestrator;
        }
    }

    private void WireOrchestratorCallbacks(ICloudBackupOrchestrator orchestrator)
    {
        orchestrator.InteractiveSessionRecovery = RecoverSessionMidDownloadAsync;
    }

    /// <summary>
    /// Pausa download: mostra Sign In/2FA; dopo login OK assorbe token nella sessione live e riprende.
    /// </summary>
    private async Task<bool> RecoverSessionMidDownloadAsync(
        ICloudSession liveSession,
        SessionReloginException ex,
        IProgress<string>? log,
        CancellationToken ct)
    {
        var tcs = new TaskCompletionSource<bool>(TaskCreationOptions.RunContinuationsAsynchronously);
        _midDownloadLiveSession = liveSession;
        _midDownloadAuthTcs = tcs;

        using var reg = ct.Register(() =>
        {
            tcs.TrySetCanceled(ct);
            _midDownloadLiveSession = null;
            _midDownloadAuthTcs = null;
        });

        await Dispatcher.InvokeAsync(() =>
        {
            if (MainTabControl is not null && AccessTab is not null)
                MainTabControl.SelectedItem = AccessTab;

            LogAuth($"Download paused — session recovery ({ex.Kind}): {ex.Message}");
            _lastDownloadProgressStatus = "Paused — complete Sign In/2FA…";
            if (DownloadStatusText is not null)
                DownloadStatusText.Text = _lastDownloadProgressStatus;

            if (ex.Kind == SessionReloginKind.Requires2Fa && ex.PartialSession is not null)
            {
                _session = ex.PartialSession;
                ConfigureTwoFactorUi(ex.VerificationOptions);
                TwoFactorPanel.Visibility = Visibility.Visible;
                MessageBox.Show(
                    this,
                    "Session expired during download. Complete two-factor verification to resume.",
                    "2FA required",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else
            {
                TwoFactorPanel.Visibility = Visibility.Collapsed;
                MessageBox.Show(
                    this,
                    "Apple rejected the in-memory password or a new sign-in is required.\n" +
                    "Re-enter the password on the Sign In tab and click Sign In to resume the download.",
                    "Sign-in required",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                try { PasswordBox.Focus(); }
                catch { /* ignore */ }
            }
        });

        try
        {
            return await tcs.Task.ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            return false;
        }
    }

    private async Task FinishMidDownloadAuthAsync(
        ICloudSession authenticated,
        IProgress<string>? progress)
    {
        var live = _midDownloadLiveSession;
        var tcs = _midDownloadAuthTcs;
        if (live is null || tcs is null)
            return;

        await Orchestrator
            .ApplyAuthenticatedSessionAsync(live, authenticated, progress)
            .ConfigureAwait(true);

        _session = live;
        UpdateSessionUi(true);
        TwoFactorPanel.Visibility = Visibility.Collapsed;

        _midDownloadLiveSession = null;
        _midDownloadAuthTcs = null;
        tcs.TrySetResult(true);

        LogAuth("Mid-download session restored — resuming download.");
        _lastDownloadProgressStatus = "Session restored — resuming…";
        if (DownloadStatusText is not null)
            DownloadStatusText.Text = _lastDownloadProgressStatus;
    }

    private bool _workAreaStacked;

    private void MainWindow_SizeChanged(object sender, SizeChangedEventArgs e)
    {
        ApplyResponsiveLayout(e.NewSize.Width, e.NewSize.Height);
    }

    /// <summary>
    /// Adatta layout a larghezze/altezze ridotte: pannello sessione sotto le tab,
    /// blob di sfondo e tipografia header.
    /// </summary>
    private void ApplyResponsiveLayout(double width, double height)
    {
        if (WorkAreaGrid is null || SideSessionPanel is null)
            return;

        // Stack side panel under tabs when the content area is too narrow for both.
        var stack = width < 1120;
        if (stack != _workAreaStacked)
        {
            _workAreaStacked = stack;
            if (stack)
            {
                WorkGapCol.Width = new GridLength(0);
                WorkSideCol.Width = new GridLength(0);
                WorkStackGapRow.Height = new GridLength(10);
                Grid.SetRow(MainTabControl, 0);
                Grid.SetColumn(MainTabControl, 0);
                Grid.SetColumnSpan(MainTabControl, 3);
                Grid.SetRow(SideSessionPanel, 2);
                Grid.SetColumn(SideSessionPanel, 0);
                Grid.SetColumnSpan(SideSessionPanel, 3);
            }
            else
            {
                WorkGapCol.Width = new GridLength(12);
                WorkSideCol.Width = new GridLength(320);
                WorkStackGapRow.Height = new GridLength(0);
                WorkSideRow.Height = new GridLength(0);
                Grid.SetRow(MainTabControl, 0);
                Grid.SetColumn(MainTabControl, 0);
                Grid.SetColumnSpan(MainTabControl, 1);
                Grid.SetRow(SideSessionPanel, 0);
                Grid.SetColumn(SideSessionPanel, 2);
                Grid.SetColumnSpan(SideSessionPanel, 1);
            }
        }

        if (_workAreaStacked)
            WorkSideRow.Height = new GridLength(height < 700 ? 180 : 220);

        if (HeaderTitleText is not null)
            HeaderTitleText.FontSize = width < 980 ? 20 : 26;
        if (HeaderSubtitleText is not null)
            HeaderSubtitleText.Visibility = width < 900 ? Visibility.Collapsed : Visibility.Visible;

        LayoutBackgroundBlobs(width, height);
    }

    private void LayoutBackgroundBlobs(double width, double height)
    {
        if (BlobA is null)
            return;

        var w = Math.Max(width, 640);
        var h = Math.Max(height, 480);
        Canvas.SetLeft(BlobA, -80);
        Canvas.SetTop(BlobA, -120);
        Canvas.SetLeft(BlobB, Math.Max(40, w - 420));
        Canvas.SetTop(BlobB, 20);
        Canvas.SetLeft(BlobC, w * 0.18);
        Canvas.SetTop(BlobC, Math.Max(120, h - 340));
        Canvas.SetLeft(BlobD, w * 0.48);
        Canvas.SetTop(BlobD, Math.Max(80, h * 0.52));
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        ApplyResponsiveLayout(ActualWidth, ActualHeight);
        var uiLogPath = IkeUiSessionLog.TryTakeSessionAnnouncement();
        if (uiLogPath is not null)
            LogAuth(uiLogPath);
        try
        {
            await EnsureAuthProfileAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            LogAuth($"Anisette probe failed: {ex.Message}");
        }
    }

    private async Task EnsureAuthProfileAsync()
    {
        if (_authProfile is not null)
            return;

        _authProfile = await AnisetteProviderFactory.ProbeAsync(Http).ConfigureAwait(true);
        LogAuthProfile(_authProfile);
    }

    private void LoadAnisetteSettingsUi()
    {
        if (AnisetteLocalRadio is null)
            return;

        var settings = AnisetteUserSettings.Load();
        var remote = settings.IsRemoteServerEnabled();
        AnisetteLocalRadio.IsChecked = !remote;
        AnisetteRemoteRadio.IsChecked = remote;
        AnisetteServerUrlTextBox.Text = string.IsNullOrWhiteSpace(settings.ServerUrl)
            ? (AnisetteUserSettings.ExampleMacUrl ?? "")
            : settings.ServerUrl.Trim();
        AnisetteLicenseTextBox.Text = settings.License?.Trim() ?? "";

        var mode = (settings.AuthMode ?? AnisetteProviderFactory.ResolveAuthMode())
            .Trim().ToLowerInvariant();
        AnisetteAuthModeCombo.SelectedIndex = mode == "hybrid" ? 1 : 0;

        UpdateAnisetteRemoteFieldsEnabled();
        if (AnisetteProviderFactory.IsServerUrlOverriddenByEnvironment())
        {
            AnisetteEnvOverrideText.Visibility = Visibility.Visible;
            AnisetteEnvOverrideText.Text =
                "ANISETTE_SERVER_URL set: overrides the UI (" +
                AnisetteProviderFactory.ResolveServerUrl() + ").";
        }
        else
        {
            AnisetteEnvOverrideText.Visibility = Visibility.Collapsed;
        }

        AnisetteSettingsStatusText.Text =
            "Active: " + AnisetteProviderFactory.ResolveServerUrl();
    }

    private void UpdateAnisetteRemoteFieldsEnabled()
    {
        if (AnisetteRemoteFieldsPanel is null)
            return;
        var remote = AnisetteRemoteRadio?.IsChecked == true;
        AnisetteRemoteFieldsPanel.IsEnabled = remote;
    }

    private void AnisetteServerModeRadio_Changed(object sender, RoutedEventArgs e) =>
        UpdateAnisetteRemoteFieldsEnabled();

    private void OnAnisetteLicenseBundleIssued(string bundleBase64)
    {
        if (string.IsNullOrWhiteSpace(bundleBase64))
            return;
        Dispatcher.BeginInvoke(() => ApplyIssuedLicenseBundle(bundleBase64));
    }

    private void OnAnisetteLicenseReplicaSynced(string detail)
    {
        Dispatcher.BeginInvoke(() =>
        {
            var msg = string.IsNullOrWhiteSpace(detail)
                ? AnisetteLicenseReplicaSyncedException.UserMessage
                : detail.Trim();
            LogAuth("Anisette license replica sync: " + msg);
            if (AnisetteSettingsStatusText is not null)
                AnisetteSettingsStatusText.Text = "License synced on server — please reconnect.";
            MessageBox.Show(
                this,
                msg,
                "Anisette license",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        });
    }

    private void ApplyIssuedLicenseBundle(string bundleBase64)
    {
        var existing = AnisetteLicenseTextBox?.Text?.Trim();
        if (!string.IsNullOrWhiteSpace(existing))
            return;
        if (_licenseOverlayShown)
            return;

        if (AnisetteLicenseTextBox is not null)
            AnisetteLicenseTextBox.Text = bundleBase64;
        var settings = ReadAnisetteSettingsFromUi();
        settings.License = bundleBase64;
        AnisetteUserSettings.Save(settings);

        if (LicenseIssuedValueBox is not null)
            LicenseIssuedValueBox.Text = bundleBase64;
        if (LicenseIssuedOverlay is not null)
            LicenseIssuedOverlay.Visibility = Visibility.Visible;
        _licenseOverlayShown = true;
        LogAuth("Anisette license (Package C) received on first connection — saved to anisette.json.");
        AnisetteSettingsStatusText.Text = "New license received — copy and store it.";
    }

    private void LicenseOverlayCopy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(LicenseIssuedValueBox.Text ?? "");
            AnisetteSettingsStatusText.Text = "License copied to clipboard.";
        }
        catch (Exception ex)
        {
            LogAuth("Copy license failed: " + ex.Message);
        }
    }

    private void LicenseOverlayDismiss_Click(object sender, RoutedEventArgs e)
    {
        LicenseIssuedOverlay.Visibility = Visibility.Collapsed;
    }

    private AnisetteUserSettings ReadAnisetteSettingsFromUi()
    {
        var remote = AnisetteRemoteRadio?.IsChecked == true;
        var url = AnisetteServerUrlTextBox?.Text?.Trim();
        var modeTag = (AnisetteAuthModeCombo?.SelectedItem as ComboBoxItem)?.Tag?.ToString()
                      ?? "iphone";
        var license = AnisetteLicenseTextBox?.Text?.Trim();
        return new AnisetteUserSettings
        {
            UseRemoteServer = remote,
            ServerUrl = string.IsNullOrWhiteSpace(url) ? null : url,
            AuthMode = modeTag,
            License = string.IsNullOrWhiteSpace(license) ? null : license,
        };
    }

    private void InvalidateAnisetteSession()
    {
        _authProfile = null;
        _orchestrator = null;
    }

    private async void AnisetteSaveButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            var settings = ReadAnisetteSettingsFromUi();
            if (settings.UseRemoteServer == true)
            {
                if (string.IsNullOrWhiteSpace(settings.ServerUrl))
                {
                    AnisetteSettingsStatusText.Text = "Remote URL required.";
                    return;
                }

                if (!Uri.TryCreate(settings.ServerUrl, UriKind.Absolute, out var uri)
                    || uri.Scheme is not ("http" or "https"))
                {
                    AnisetteSettingsStatusText.Text = "Invalid URL (http/https).";
                    return;
                }
            }

            AnisetteUserSettings.Save(settings);
            InvalidateAnisetteSession();
            var resolved = AnisetteProviderFactory.ResolveServerUrl();
            AnisetteSettingsStatusText.Text = "Saved → " + resolved;
            LogAuth($"Anisette saved: {resolved} | mode: {AnisetteProviderFactory.ResolveAuthMode()}");
            LogAuth($"  config: {AnisetteProviderFactory.SettingsFilePath}");

            await EnsureAuthProfileAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            AnisetteSettingsStatusText.Text = "Save error: " + ex.Message;
            LogAuth($"Saving Anisette failed: {ex.Message}");
        }
    }

    private async void AnisetteTestButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            AnisetteTestButton.IsEnabled = false;
            AnisetteSettingsStatusText.Text = "Test in progress…";

            // Prova l'URL selezionato in UI senza obbligatoriamente salvare.
            var draft = ReadAnisetteSettingsFromUi();
            var url = draft.UseRemoteServer == true
                && !string.IsNullOrWhiteSpace(draft.ServerUrl)
                    ? draft.ServerUrl!.TrimEnd('/')
                    : AnisetteProviderFactory.DefaultServerUrl;
            if (AnisetteProviderFactory.IsServerUrlOverriddenByEnvironment())
                url = AnisetteProviderFactory.ResolveServerUrl().TrimEnd('/');

            if (!Uri.TryCreate(url, UriKind.Absolute, out _))
            {
                AnisetteSettingsStatusText.Text = "Invalid URL.";
                return;
            }

            var license = string.IsNullOrWhiteSpace(draft.License)
                ? AnisetteProviderFactory.ResolveLicenseBearer()
                : draft.License;
            var remote = new RemoteAnisetteProvider(AnisetteRemoteHttp.Create(url), url, license);
            var backend = await remote.TryGetBackendAsync().ConfigureAwait(true);
            var headers = await remote.FetchAsync().ConfigureAwait(true);
            var md = AnisetteCapability.SummarizeMdM(headers.MdM);
            AnisetteSettingsStatusText.Text =
                $"OK {url}" +
                (string.IsNullOrEmpty(backend) ? "" : $" · backend={backend}") +
                $" · MD-M {md}";
            LogAuth($"Test Anisette OK: {url}" +
                    (string.IsNullOrEmpty(backend) ? "" : $" backend={backend}") +
                    $" MD-M={md}");
        }
        catch (Exception ex)
        {
            AnisetteSettingsStatusText.Text = "Test failed: " + ex.Message;
            LogAuth($"Anisette test failed: {ex.Message}");
        }
        finally
        {
            AnisetteTestButton.IsEnabled = true;
        }
    }

    private void LogAuthProfile(AnisetteAuthProfile profile)
    {
        LogAuth(AnisetteCapability.DescribeForLogin(
            profile.ServerUrl, profile.LocalCoreAdiSpoof, profile.RemoteAnisette, profile.Backend));
        LogAuth($"  remote MD-M:  {AnisetteCapability.SummarizeMdM(profile.RemoteAnisette.MdM)}");
        if (AnisetteCapability.IsFridaIphoneBackend(profile.Backend))
            LogAuth("Flow iPhone: Frida → AuthKit/akd on device + SRP GSA.");
        else if (profile.UseFullIphoneAuth)
            LogAuth("Flow iPhone: remote Anisette (RAD/emulated/Frida) + SRP GSA.");
        else if (profile.Mode == "iphone" && profile.DockerMacAnisette)
            LogAuth("authMode=iphone but anisette = Mac/Xcode (docker). Use --backend frida or setup-emulated-akd.");
        else if (profile.Mode == "iphone" && profile.LocalCoreAdiSpoof)
            LogAuth("authMode=iphone but anisette = CoreADI Windows (:6969). Use --backend frida (:6971).");
        else if (profile.Mode == "hybrid")
            LogAuth("Flow hybrid (legacy): SRP AuthKitWin → ckAppInit iPhone.");
        else
            LogAuth("authMode=iphone not active — check AnisetteServer on :6971 (backend=frida).");
    }



    /// <summary>Oltre questa soglia il TextBox log viene ridotto (UI non risponde / RAM).</summary>
    private const int LogLineLimit = 500;
    private const int LogLinesToKeep = 80;
    /// <summary>Max Info/s sul RichTextBox (Quiet off). Error/Warning sempre ammessi.</summary>
    private const int MaxInfoLogLinesPerSecond = 15;
    /// <summary>Max BeginInvoke Info in coda (evita flood dispatcher prima del throttle UI).</summary>
    private const int MaxPendingInfoLogPosts = 24;
    private long _infoLogWindowStartMs;
    private int _infoLogInWindow;
    private int _infoLogDropped;
    private int _pendingInfoLogPosts;
    private int _richLogScrollDebt;
    private double _richLogLastPageWidth;

    private static readonly SolidColorBrush LogInfoBrush =
        CreateFrozenBrush(0x1B, 0x1C, 0x1F);
    private static readonly SolidColorBrush LogWarningBrush =
        CreateFrozenBrush(0xB5, 0x86, 0x00);
    private static readonly SolidColorBrush LogErrorBrush =
        CreateFrozenBrush(0xC5, 0x22, 0x1F);
    private static readonly SolidColorBrush LogTimestampBrush =
        CreateFrozenBrush(0x5F, 0x63, 0x68);

    private enum DownloadLogKind
    {
        Info,
        Warning,
        Error,
    }

    private static SolidColorBrush CreateFrozenBrush(byte r, byte g, byte b)
    {
        var brush = new SolidColorBrush(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }

    private void AppendAuthLog(string line) =>
        AppendBoundedLog(AuthLogTextBox, line, "auth");

    /// <summary>
    /// Traffico HTTP condiviso: in operazioni Backup → log Informazioni/Avvisi/Errori;
    /// durante login/2FA/altro → log Sign In.
    /// </summary>
    private void AppendHttpTrafficLog(string line)
    {
        var msg = $"[HTTP] {line}";
        if (_backupListBusy || _downloadBusy)
            AppendDownloadLog(msg);
        else
            AppendAuthLog(msg);
    }

    private void LogAuth(string message)
    {
        _capture.LogAuthEvent(message);
        AppendAuthLog(message);
    }

    private void SaveSessionSnapshot(string phase, string? note = null)
    {
        if (_session is null)
            return;
        _capture.SaveSessionSnapshot(_session, phase, note);
        LogAuth($"Session snapshot saved ({phase})");
    }

    /// <summary>
    /// NDJSON agent: mai File.Append sul thread UI (debug-*.log multi-GB → freeze dispatcher).
    /// </summary>
    private static void QueueAgentNdjson(string absolutePath, string jsonLine)
    {
        _ = Task.Run(() =>
        {
            try
            {
                File.AppendAllText(absolutePath, jsonLine + Environment.NewLine);
            }
            catch { /* ignore */ }
        });
    }

    // #region agent log
    private static void NoteUiStall(string location, string message, long elapsedMs, object? data = null)
    {
        if (elapsedMs < 40)
            return;
        try
        {
            var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "9a5651",
                ["runId"] = "ui-freeze-v1",
                ["hypothesisId"] = "H-UI-DISK",
                ["location"] = location,
                ["message"] = message,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                ["data"] = new Dictionary<string, object?>
                {
                    ["elapsedMs"] = elapsedMs,
                    ["onUiThread"] = true,
                    ["extra"] = data,
                },
            });
            QueueAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                payload);
        }
        catch { /* ignore */ }
    }
    // #endregion

    private void AppendDownloadLog(string line)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        var kind = ClassifyDownloadLog(line);
        var isFgProbe = IsForegroundMmcsProbeLog(line);
        if (isFgProbe)
            UpdateForegroundMmcsUiFromLog(line);

        if (IkeLogOptions.Quiet
            && kind is not DownloadLogKind.Error
            && !isFgProbe)
            return;

        // Quiet off: senza cap il FlowDocument + ScrollToEnd congela il dispatcher
        // (diagnostica: ~36k ui_append_log_stall Info, non File.Copy).
        // FG probe: sempre ammessi (pochi) anche se Quiet off + info throttle.
        if (kind == DownloadLogKind.Info && !isFgProbe && !TryAdmitInfoLogLine())
            return;

        // #region agent log
        if (kind == DownloadLogKind.Error
            || line.Contains("decrypt failed", StringComparison.OrdinalIgnoreCase)
            || line.Contains("decrypt fallito", StringComparison.OrdinalIgnoreCase)
            || line.Contains("MmcsAuth", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var n = Interlocked.Increment(ref _uiErrorLogCount);
                if (n <= 60 || n % 25 == 0)
                {
                    var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["runId"] = "errlog-v1",
                        ["hypothesisId"] = "H-ERRLOG",
                        ["location"] = "MainWindow.AppendDownloadLog",
                        ["message"] = "ui_error_log_line",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            n,
                            kind = kind.ToString(),
                            quiet = IkeLogOptions.Quiet,
                            preview = line.Length > 160 ? line[..160] : line,
                        },
                    });
                    // Off UI: stesso file dei worker → Append sync bloccava il dispatcher.
                    QueueAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        payload);
                }
            }
            catch { /* ignore */ }
        }
        // #endregion

        var box = kind switch
        {
            DownloadLogKind.Error => DownloadErrorLogBox,
            DownloadLogKind.Warning => DownloadWarningLogBox,
            _ => DownloadInfoLogBox,
        };
        var bodyBrush = kind switch
        {
            DownloadLogKind.Error => LogErrorBrush,
            DownloadLogKind.Warning => LogWarningBrush,
            _ => LogInfoBrush,
        };
        AppendRichLogLine(box, line, bodyBrush, "download");
        // #region agent log
        NoteUiStall(
            "MainWindow.AppendDownloadLog",
            "ui_append_log_stall",
            sw.ElapsedMilliseconds,
            new
            {
                kind = kind.ToString(),
                len = line.Length,
                droppedInfo = Volatile.Read(ref _infoLogDropped),
            });
        // #endregion
    }

    /// <summary>
    /// Worker → UI: gate Quiet + cap coda BeginInvoke (senza questo il dispatcher
    /// si riempie di decine di migliaia di append anche prima del throttle Info).
    /// </summary>
    private void PostDownloadLogFromWorker(string msg)
    {
        if (IkeLogOptions.Quiet && !IkeLogOptions.ShouldEmitUi(msg))
            return;

        // Errori + probe FG: sempre in coda. Info/warnings: drop se già troppi post pendenti.
        // In Quiet ShouldEmitUi lascia passare errors e linee FG observe/seed.
        var bypassInfoCap = IkeLogOptions.IsErrorLine(msg)
                            || IkeLogOptions.IsForegroundMmcsProbeLine(msg);
        if (!bypassInfoCap)
        {
            var pending = Interlocked.Increment(ref _pendingInfoLogPosts);
            if (pending > MaxPendingInfoLogPosts)
            {
                Interlocked.Decrement(ref _pendingInfoLogPosts);
                Interlocked.Increment(ref _infoLogDropped);
                return;
            }
        }

        Dispatcher.BeginInvoke(() =>
        {
            try
            {
                AppendDownloadLog(msg);
            }
            finally
            {
                if (!bypassInfoCap)
                    Interlocked.Decrement(ref _pendingInfoLogPosts);
            }
        });
    }

    /// <summary>True = ammetti questa riga Info sul RichTextBox.</summary>
    private bool TryAdmitInfoLogLine()
    {
        var now = Environment.TickCount64;
        if (now - _infoLogWindowStartMs >= 1000)
        {
            _infoLogWindowStartMs = now;
            _infoLogInWindow = 0;
        }

        if (_infoLogInWindow >= MaxInfoLogLinesPerSecond)
        {
            var dropped = Interlocked.Increment(ref _infoLogDropped);
            // #region agent log
            if (dropped <= 5 || dropped % 500 == 0)
            {
                try
                {
                    var payload = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "9a5651",
                        ["runId"] = "ui-freeze-v2",
                        ["hypothesisId"] = "H-UI-LOG-FLOOD",
                        ["location"] = "MainWindow.TryAdmitInfoLogLine",
                        ["message"] = "ui_info_log_throttled",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new { dropped, capPerSec = MaxInfoLogLinesPerSecond },
                    });
                    QueueAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-9a5651.log",
                        payload);
                }
                catch { /* ignore */ }
            }
            // #endregion
            return false;
        }

        _infoLogInWindow++;
        return true;
    }

    private static int _classifySelfTestDone;

    private static bool IsForegroundMmcsProbeLog(string line) =>
        IkeLogOptions.IsForegroundMmcsProbeLine(line);

    private void ResetForegroundMmcsUi()
    {
        if (ForegroundMmcsText is null)
            return;
        ForegroundMmcsText.Text = "FG MMCS: in probe… (wait for zones / D: / S: / mbs)";
    }

    private void UpdateForegroundMmcsUiFromLog(string line)
    {
        if (ForegroundMmcsText is null)
            return;

        var text = line.Trim();
        if (text.StartsWith("FG observe summary:", StringComparison.Ordinal))
        {
            ForegroundMmcsText.Text = text;
            return;
        }

        // FG observe [source]: HIT|MISS …
        var hitIdx = text.IndexOf("FG observe [", StringComparison.Ordinal);
        if (hitIdx >= 0)
        {
            var after = text[hitIdx..];
            var srcStart = after.IndexOf('[') + 1;
            var srcEnd = after.IndexOf(']');
            var src = srcStart > 0 && srcEnd > srcStart
                ? after[srcStart..srcEnd]
                : "?";

            if (after.Contains(": HIT ", StringComparison.Ordinal))
            {
                var hw = ExtractFgToken(after, "hw=");
                var sha = ExtractFgToken(after, "sha=");
                var matchHw = after.Contains("matchStaticHw=True", StringComparison.OrdinalIgnoreCase);
                var matchSha = after.Contains("matchStaticSha=True", StringComparison.OrdinalIgnoreCase);
                ForegroundMmcsText.Text =
                    $"FG MMCS HIT [{src}]: hw={hw ?? "?"}  sha={sha ?? "?"}  " +
                    $"static={(matchHw && matchSha ? "match" : "DIFF")}";
                return;
            }

            if (after.Contains(": MISS", StringComparison.Ordinal))
            {
                ForegroundMmcsText.Text =
                    $"FG MMCS: MISS [{src}] — no hw/sha in this response";
                return;
            }
        }

        if (text.Contains("FG seed", StringComparison.Ordinal))
        {
            var hw = ExtractFgToken(text, "hw=");
            var sha = ExtractFgToken(text, "sha=");
            ForegroundMmcsText.Text =
                $"FG MMCS seed (request): hw={hw ?? "?"}  sha={sha ?? "?"} — listening for responses…";
        }
    }

    private static string? ExtractFgToken(string text, string key)
    {
        var i = text.IndexOf(key, StringComparison.Ordinal);
        if (i < 0)
            return null;
        var start = i + key.Length;
        var end = start;
        while (end < text.Length)
        {
            var c = text[end];
            if (char.IsWhiteSpace(c))
                break;
            end++;
        }

        return end > start ? text[start..end] : null;
    }

    private static DownloadLogKind ClassifyDownloadLog(string line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return DownloadLogKind.Info;

        // #region agent log
        if (Interlocked.CompareExchange(ref _classifySelfTestDone, 1, 0) == 0)
        {
            try
            {
                var samples = new (string id, string text, string expect)[]
                {
                    ("H-path-critical",
                        "  PENDING Library/Preferences/com.apple.messages.critical-messaging.storage.plist: missing 1 chunk in cache (data:H-x9VSABnTfvZeEKqSge:816-1215(400B)) — download continues",
                        "Warning"),
                    ("H-path-exception",
                        "  plan SysSharedContainerDomain-systemgroup.com.apple.ReportMemoryException: 0 files to download (FileMetadata=2 incl. dir/link=2, Assets=0, empty=0, noSig=0, size0=0, dup=0)",
                        "Info"),
                    ("H-path-errorview",
                        "  Library/FLXViewRepository/44-39238115d66481635db86ab4746ca9c65d27a6fc-p-D6223F352E5B0396/pom/views/carrier-error-view.tml → ..\\Backup\\6e\\6e2b80faefaab5ec9049fe30f74646534d570d3b edge=8 storages=2 fordN=1 fill pipeA=1 pipeB=1 fordOpen=1 fordSkip=0 keyed=1 nodes=1 ford=[gate-mirror ctLen=112] pipes=[A,B] MMCS (+27.520 B)",
                        "Info"),
                    ("H-real-error",
                        "  decrypt failed: Invalid nonce",
                        "Error"),
                };
                var logPath = @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-b3df71.log";
                foreach (var (id, text, expect) in samples)
                {
                    var got = ClassifyDownloadLogCore(text);
                    var payload = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "b3df71",
                        ["runId"] = "path-false-error",
                        ["hypothesisId"] = id,
                        ["location"] = "MainWindow.ClassifyDownloadLog",
                        ["message"] = "classify_self_test",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["data"] = new
                        {
                            expect,
                            got = got.ToString(),
                            pass = string.Equals(got.ToString(), expect, StringComparison.Ordinal),
                            preview = text.Length > 120 ? text[..120] : text,
                        },
                    });
                    System.IO.File.AppendAllText(logPath, payload + Environment.NewLine);
                }
            }
            catch { /* ignore */ }
        }
        // #endregion

        return ClassifyDownloadLogCore(line);
    }

    private static DownloadLogKind ClassifyDownloadLogCore(string line)
    {
        // Progress file N/total — mai errors (anche se N è 401/403/404).
        if (System.Text.RegularExpressions.Regex.IsMatch(
                line,
                @"^\s*File\s+\d+\s*/\s*\d+\s*:",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase
                | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
            return DownloadLogKind.Info;

        // PrivilegedBatch progresso … abort=0 — campo contatore, non token ABORT.
        if (line.Contains("PrivilegedBatch progress", StringComparison.OrdinalIgnoreCase)
            || line.Contains("PrivilegedBatch progresso", StringComparison.OrdinalIgnoreCase))
            return DownloadLogKind.Info;

        // Successi / traffico normale (path tipo ApiErrors.bundle NON sono errors).
        if (ContainsAny(line,
                "verifyDigest=ok",
                "chunk OK",
                "decryptFord",
                "decrypt in coda", "decrypt queued",
                "mmcs_cache: rilasciati",
                "fordOpen=",
                "fill pipeA="))
            return DownloadLogKind.Info;

        // Piano dominio (anche ReportMemoryException nel nome) = info, non errore.
        if ((line.Contains("plan ", StringComparison.OrdinalIgnoreCase)
                 || line.Contains("piano ", StringComparison.OrdinalIgnoreCase))
            && (line.Contains("files to download", StringComparison.OrdinalIgnoreCase)
                || line.Contains("file da scaricare", StringComparison.OrdinalIgnoreCase)))
            return DownloadLogKind.Info;

        // Log tracer HTTP: REQUEST senza status di risposta → Informazioni (non Errori).
        if (line.Contains("[HTTP]", StringComparison.OrdinalIgnoreCase)
            && line.Contains("REQUEST", StringComparison.OrdinalIgnoreCase)
            && !IkeLogOptions.HasHttpResponseStatusError(line))
            return DownloadLogKind.Info;

        // "fail=0" / "abort=0" (contatori progresso) non sono token ERROR/ABORT.
        var scan = System.Text.RegularExpressions.Regex.Replace(
            line,
            @"fail\s*=\s*0(?:/\d+)?",
            "okcount",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);
        scan = System.Text.RegularExpressions.Regex.Replace(
            scan,
            @"\babort\s*=\s*\d+",
            "abortcount",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        // Errori: token interi (evita ApiErrors / ErrorHandler / RevolutErrors).
        // HTTP 401/403/404/5xx → solo da status di risposta (RESPONSE/HTTP …), non da testo libero.
        // Path Apple: ReportMemoryException, carrier-error-view, critical-messaging.storage.plist
        // non devono finire in Errori (lookaround: niente match dentro id con . / - _).
        if (HasLogErrorToken(scan)
            || IkeLogOptions.HasHttpResponseStatusError(scan)
            || HasLogClrExceptionToken(scan)
            || ContainsAny(scan,
                "NullReference", "Unauthorized",
                "decrypt fail", "decrypt failed", "decrypt fallito", "crypto abort", "Invalid nonce",
                "≠ assetSize", "size_mismatch", "no-ikm", "no-resolve",
                "decrypt_failures", "MmcsAuth missing", "MmcsAuth assente"))
            return DownloadLogKind.Error;

        // Avvisi
        if (ContainsAny(scan,
                "WARN", "avvis", "PENDING", "pending", "skip", "SKIP",
                "assente", "absent", "missing", "mancano", "manca ", "fallback", "degrad",
                "prosegue", "continues", "warning", "attenzion", "notice", "stub", "orfan",
                "non ancora", "not yet", "senza auth", "without auth", "debole", "weak"))
            return DownloadLogKind.Warning;

        return DownloadLogKind.Info;
    }

    /// <summary>
    /// Match solo token ERROR/FAIL/… — non id path (carrier-error-view, critical-messaging).
    /// </summary>
    private static bool HasLogErrorToken(string line) =>
        System.Text.RegularExpressions.Regex.IsMatch(
            line,
            @"(?<![\w.-])(?:ERROR|FAIL|FATAL|CRITICAL|CRITIC|ABORT|Errore|Error|abortito|aborted|interrotto|interrupted)(?![\w-])",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
            | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// CLR <c>Exception:</c> / <c>System.*.Exception</c> / tipi noti — non DNS/path
    /// (<c>ReportMemoryException</c>, <c>exception_reset_counter.plist</c>).
    /// </summary>
    private static bool HasLogClrExceptionToken(string line) =>
        System.Text.RegularExpressions.Regex.IsMatch(
            line,
            @"\bException\s*:|(?<![\w./-])System(?:\.\w+)*Exception\b|(?<![\w./-])(?:NullReference|InvalidOperation|Argument(?:Null|OutOfRange)?|IO|Cryptographic|Aggregate|Timeout|HttpRequest|TaskCanceled|OperationCanceled|ObjectDisposed|UnauthorizedAccess|NotImplemented|NotSupported|FileNotFound|DirectoryNotFound|Json|Xml)Exception\b",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
            | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    private static bool ContainsAny(string haystack, params string[] needles)
    {
        foreach (var n in needles)
        {
            if (haystack.Contains(n, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private void AppendRichLogLine(RichTextBox box, string line, SolidColorBrush bodyBrush, string channel)
    {
        IkeUiSessionLog.Append(channel, line);
        var doc = box.Document;
        FitRichLogPageWidth(box, doc);
        var stamp = $"[{DateTime.Now:HH:mm:ss}] ";
        var para = new Paragraph
        {
            Margin = new Thickness(0, 0, 0, 2),
            LineHeight = 18,
        };
        para.Inlines.Add(new Run(stamp)
        {
            Foreground = LogTimestampBrush,
            FontWeight = FontWeights.Normal,
        });
        para.Inlines.Add(new Run(line)
        {
            Foreground = bodyBrush,
            FontWeight = FontWeights.Bold,
        });
        doc.Blocks.Add(para);

        if (doc.Blocks.Count > LogLineLimit)
            TrimRichLog(doc, LogLinesToKeep);

        // ScrollToEnd a ogni riga = layout completo → stall secondi/decine di s.
        if (++_richLogScrollDebt >= 8)
        {
            _richLogScrollDebt = 0;
            box.ScrollToEnd();
        }
    }

    /// <summary>
    /// FlowDocument senza PageWidth taglia le righe lunghe; allinea alla viewport (wrap).
    /// PagePadding lascia aria su testo e scrollbar (Padding sul RTB le clippa).
    /// </summary>
    private void FitRichLogPageWidth(RichTextBox box, FlowDocument doc)
    {
        const double padL = 12, padT = 10, padR = 12, padB = 10;
        if (doc.PagePadding.Left != padL)
            doc.PagePadding = new Thickness(padL, padT, padR, padB);

        var w = box.ViewportWidth;
        if (w <= 1)
            w = box.ActualWidth;
        if (w <= 40)
            return;

        var scroll = SystemParameters.VerticalScrollBarWidth + 4;
        var pageW = Math.Max(120, w - padL - padR - scroll);
        if (Math.Abs(pageW - _richLogLastPageWidth) < 0.5)
            return;
        _richLogLastPageWidth = pageW;
        doc.PageWidth = pageW;
    }

    private static void TrimRichLog(FlowDocument doc, int keepLines)
    {
        // Niente paragraph “log ridotto” a ogni trim: con flood Info
        // insert+remove ripetuti sul FlowDocument congelavano l’UI.
        var remove = doc.Blocks.Count - keepLines;
        for (var i = 0; i < remove; i++)
            doc.Blocks.Remove(doc.Blocks.FirstBlock);
    }

    private static string GetRichTextPlain(RichTextBox box)
    {
        var range = new TextRange(box.Document.ContentStart, box.Document.ContentEnd);
        return range.Text.TrimEnd();
    }

    private void AppendDecryptLog(string line) =>
        AppendBoundedLog(DecryptLogTextBox, line, "escrow");

    private void AppendBoundedLog(TextBox box, string line, string channel)
    {
        IkeUiSessionLog.Append(channel, line);
        box.AppendText($"[{DateTime.Now:HH:mm:ss}] {line}{Environment.NewLine}");
        if (box.LineCount > LogLineLimit)
            TrimLogTextBox(box, LogLinesToKeep);
        // ScrollToEnd → ScrollToLine(LineCount-1): con LineCount 0 esplode.
        if (box.LineCount > 0)
            box.ScrollToEnd();
    }

    private static void TrimLogTextBox(TextBox box, int keepLines)
    {
        var text = box.Text;
        if (string.IsNullOrEmpty(text) || keepLines <= 0)
        {
            box.Clear();
            return;
        }

        var idx = text.Length;
        var kept = 0;
        while (idx > 0 && kept < keepLines)
        {
            idx = text.LastIndexOf('\n', idx - 1);
            if (idx < 0)
            {
                idx = 0;
                break;
            }

            kept++;
        }

        var start = idx <= 0 ? 0 : idx + 1;
        if (start > text.Length)
            start = 0;
        box.Text = $"[{DateTime.Now:HH:mm:ss}] … log trimmed (last {keepLines} lines){Environment.NewLine}"
                   + text[start..];
    }



    private void BrowseDecryptOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            ApplyBrowsedFolder(DecryptOutputTextBox, dlg.FolderName);
    }

    private void EscrowSmsVariantCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        var on = EscrowSmsVariantCheckBox.IsChecked == true;
        EscrowSmsCodeLabel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        EscrowSmsCodeBox.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        EscrowRequestSmsCheckBox.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        EscrowSecretLabel.Text = "iCSC:";
        EscrowSecretHint.Text = on
            ? "(SMS — empty = DSID; SRP uses dsid)"
            : "(empty = DSID)";
    }

    /// <summary>iCSC dal campo Escrow; se vuoto → DSID (default).</summary>
    private string ResolveEscrowIcsc()
    {
        var typed = EscrowPasswordBox.Password.Trim();
        if (!string.IsNullOrEmpty(typed))
            return typed;
        return _session?.Dsid?.Trim() ?? "";
    }

    /// <summary>
    /// Remint Anisette dopo operazioni lunghe Escrow/Octagon (OTP spesso morto).
    /// Best-effort: non maschera l'esito dell'unlock.
    /// </summary>
    private async Task RemintAnisetteAfterSensitiveOpAsync(string reason)
    {
        if (_session is null)
            return;
        try
        {
            AppendDecryptLog($"  remint Anisette post-{reason}…");
            var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendDecryptLog(msg)));
            await Orchestrator
                .RefreshAnisetteOnlyAsync(_session, log, CancellationToken.None, forceRemint: true)
                .ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            AppendDecryptLog($"  remint Anisette failed: {ex.Message}");
        }
    }

    private async void EscrowPcsUnlockButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "Unlock EscrowedKeys",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(_session.Dsid))
        {
            MessageBox.Show(this, "Session without dsid.", "Unlock EscrowedKeys",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var useSms = EscrowSmsVariantCheckBox.IsChecked == true;
        var iCsc = ResolveEscrowIcsc();
        var iCscFromField = !string.IsNullOrWhiteSpace(EscrowPasswordBox.Password);

        var outputDir = DecryptOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Select an output folder.", "Unlock EscrowedKeys",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);

        var resetLoginAfter401 = false;
        string? resetDetail = null;
        try
        {
            EscrowPcsUnlockButton.IsEnabled = false;
            AppendDecryptLog($"Unlock EscrowedKeys (SRP recover + PCS) → {outputDir}");
            AppendDecryptLog(
                $"SRP: inner=SHA256(\"{_session.Dsid}:\" + dsid), x=SHA256(salt||inner)");
            AppendDecryptLog("Post-K: PBKDF2(dsid)+AES(sec3) → BackupBagPassword → RFC6637+GCM");
            if (useSms)
                AppendDecryptLog("SMS variant (securebackup) active");
            AppendDecryptLog(
                iCscFromField
                    ? $"iCSC from field ({iCsc.Length} char)"
                    : $"iCSC empty → default DSID ({iCsc})");

            var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendDecryptLog(msg)));
            var recovery = new EscrowRecoveryService(Http);
            EscrowSmsOptions? sms = useSms
                ? new EscrowSmsOptions(
                    Enabled: true,
                    SmsChallengeCode: EscrowSmsCodeBox.Text,
                    RequestSmsChallenge: EscrowRequestSmsCheckBox.IsChecked == true)
                : null;
            var result = await recovery.FetchEncryptedKeyBagKeyAsync(
                _session, iCsc, outputDir, log, sms);

            AppendDecryptLog(result.Success ? $"OK: {result.Message}" : $"FAIL: {result.Message}");
            if (!string.IsNullOrEmpty(result.EncryptedKeyBagKeyPath))
                AppendDecryptLog($"Blob: {result.EncryptedKeyBagKeyPath}");
            if (!string.IsNullOrEmpty(result.KeybagKeyPath))
                AppendDecryptLog($"BackupBagPassword: {result.KeybagKeyPath} ({result.PcsUnwrapMethod})");

            if (result.Success)
            {
                // Sempre: materializza KeySet in sessione (file già scritto da recover/unlock).
                var ensure = await EscrowPcsSession.EnsureKeySetAsync(
                    _session, Http, outputDir, iCsc, sms, log);
                AppendDecryptLog(
                    ensure.Success
                        ? $"PCS KeySet in session: {ensure.KeySet?.Length ?? 0} B ← {ensure.Source}"
                        : $"PCS KeySet NOT in session: {ensure.Message}");
                AppendDecryptLog($"OK unlock: {result.Message}");
                // Abilita Backup/Drive/… senza lasciare la scheda Escrow.
                ApplyUiWizardStage(UiWizardStage.AfterEscrow, selectTab: false);
            }
            else if (LooksLikeHttp401(result.Message))
            {
                MessageBox.Show(this, result.Message, "Unlock EscrowedKeys",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                resetLoginAfter401 = true;
                resetDetail = result.Message;
            }
            else
            {
                MessageBox.Show(this, result.Message, "Unlock EscrowedKeys",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            AppendDecryptLog($"Unlock error: {ex.Message}");
            MessageBox.Show(this, ex.Message, "Unlock EscrowedKeys",
                MessageBoxButton.OK, MessageBoxImage.Error);
            if (LooksLikeHttp401(ex.Message))
            {
                resetLoginAfter401 = true;
                resetDetail = ex.Message;
            }
        }
        finally
        {
            await RemintAnisetteAfterSensitiveOpAsync("Escrow Unlock").ConfigureAwait(true);
            if (resetLoginAfter401)
                ResetWizardToLoginAfterEscrowAuthFailure(resetDetail ?? "HTTP 401");
            EscrowPcsUnlockButton.IsEnabled = true;
        }
    }

    private async void EscrowOctagonListButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "Lista bottle iCDP",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = DecryptOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Select an output folder.", "Lista bottle iCDP",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);
        try
        {
            EscrowOctagonListButton.IsEnabled = false;
            AppendDecryptLog($"List iCDP bottles (get_records, non-destructive) → {outputDir}");
            var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendDecryptLog(msg)));
            var svc = new OctagonBottleRecoveryService(Http);
            var (bottles, error) = await svc.ListBottlesLiveAsync(_session, outputDir, log);
            if (error is not null)
            {
                AppendDecryptLog("FAIL: " + error);
                MessageBox.Show(this, error, "Lista bottle iCDP",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            EscrowOctagonBottleCombo.ItemsSource = bottles;
            if (bottles.Count > 0)
                EscrowOctagonBottleCombo.SelectedIndex = 0;
            AppendDecryptLog($"Bottle iCDP in combo: {bottles.Count}");
        }
        catch (Exception ex)
        {
            AppendDecryptLog($"iCDP list error: {ex.Message}");
            MessageBox.Show(this, ex.Message, "Lista bottle iCDP",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            EscrowOctagonListButton.IsEnabled = true;
        }
    }

    private async void EscrowOctagonUnlockButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "Unlock Octagon",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (EscrowOctagonBottleCombo.SelectedItem is not OctagonBottleListItem bottle)
        {
            MessageBox.Show(this,
                "Select an iCDP bottle (run \"List iCDP bottles\" first).",
                "Unlock Octagon", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var passcode = EscrowPasswordBox.Password.Trim();
        if (string.IsNullOrEmpty(passcode))
        {
            MessageBox.Show(this,
                "Enter the passcode of the device that created the bottle\n" +
                $"(serial={bottle.Serial}, build={bottle.Build}).\n" +
                "Do not use DSID: Octagon requires the device passcode / iCSC.",
                "Unlock Octagon", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = DecryptOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Select an output folder.", "Unlock Octagon",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var confirm = MessageBox.Show(this,
            "WARNING: Octagon unlock consumes one irreversible attempt on this bottle\n" +
            $"(attempts remaining ≈ {bottle.RemainingAttempts?.ToString() ?? "?"}/10).\n" +
            "On the 10th failure the HSM destroys the record.\n\n" +
            $"{bottle.Display}\n\nContinue?",
            "Unlock Octagon — confirm",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
            return;

        Directory.CreateDirectory(outputDir);
        try
        {
            EscrowOctagonUnlockButton.IsEnabled = false;
            AppendDecryptLog($"Unlock Octagon bottle → {outputDir}");
            AppendDecryptLog($"  {bottle.Display}");
            var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendDecryptLog(msg)));
            var svc = new OctagonBottleRecoveryService(Http);
            var result = await svc.RecoverBottleAsync(
                _session, bottle.Label, passcode, outputDir,
                confirmIrreversible: true, log);

            AppendDecryptLog(result.Success ? $"OK: {result.Message}" : $"FAIL: {result.Message}");
            if (result.EntropyPath is not null)
                AppendDecryptLog($"Entropy: {result.EntropyPath}");
            if (result.Success)
            {
                if (!string.IsNullOrWhiteSpace(bottle.Serial))
                    _session.OctagonBottleSerial = bottle.Serial;
                AppendDecryptLog(
                    $"Octagon entropy in session: {_session.OctagonBottledPeerEntropy?.Length ?? 0} B" +
                    (string.IsNullOrWhiteSpace(bottle.Serial) ? "" : $" (serial={bottle.Serial})"));
                await RunOctagonPeerRecoveryAsync(outputDir).ConfigureAwait(true);
                // Stesso gate di Unlock EscrowProxy: Backup / Drive / Sync / …
                ApplyUiWizardStage(UiWizardStage.AfterEscrow, selectTab: false);
            }
            else
            {
                MessageBox.Show(this, result.Message, "Unlock Octagon",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }
        }
        catch (Exception ex)
        {
            AppendDecryptLog($"Octagon unlock error: {ex.Message}");
            MessageBox.Show(this, ex.Message, "Unlock Octagon",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            await RemintAnisetteAfterSensitiveOpAsync("Octagon bottle unlock")
                .ConfigureAwait(true);
            EscrowOctagonUnlockButton.IsEnabled = true;
        }
    }

    private async void EscrowOctagonRkButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "Octagon RK",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var rk = EscrowRecoveryKeyBox.Password;
        if (string.IsNullOrWhiteSpace(rk))
        {
            MessageBox.Show(this,
                "Enter the iCloud Recovery Key (XXXX-XXXX-…).",
                "Octagon RK", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = DecryptOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Select an output folder.", "Octagon RK",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var salt = EscrowRecoverySaltBox.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(salt))
            salt = _session.Adsid?.Trim() ?? "";
        if (!string.IsNullOrWhiteSpace(salt))
            EscrowRecoverySaltBox.Text = salt;

        var rkDir = Path.Combine(outputDir, "octagon_rk");
        try
        {
            EscrowOctagonRkButton.IsEnabled = false;
            AppendDecryptLog($"Unlock Octagon via Recovery Key → {rkDir}");
            AppendDecryptLog(
                "Path: HKDF(RK,altDSID) → peer RK → fetchRecoverableTLKShares → CKKS Manatee/PCS " +
                "(no RECOVER HSM / bottle attempt).");
            var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendDecryptLog(msg)));
            var svc = new OctagonRecoveryKeyUnlockService(
                new OctagonCuttlefishService(Http, Orchestrator),
                new CkksVaultService(Http, Orchestrator),
                Orchestrator);
            var result = await svc.UnlockAsync(_session, rk, salt, rkDir, log)
                .ConfigureAwait(true);
            AppendDecryptLog(result.Success ? $"OK: {result.Message}" : $"FAIL: {result.Message}");
            if (result.PeerId is not null)
                AppendDecryptLog($"Peer RK: {result.PeerId}");
            if (result.PcsKeys > 0)
            {
                AppendDecryptLog(
                    $"PCS ManateeCompact in session: {_session.PcsManateeCompactKeys?.Count ?? 0}");
            }

            if (result.Success)
            {
                // Stesso gate di Unlock EscrowProxy: Backup / Drive / Sync / …
                ApplyUiWizardStage(UiWizardStage.AfterEscrow, selectTab: false);
                MessageBox.Show(this, result.Message, "Octagon RK",
                    MessageBoxButton.OK, MessageBoxImage.Information);
            }
            else
            {
                MessageBox.Show(this, result.Message, "Octagon RK",
                    MessageBoxButton.OK, MessageBoxImage.Warning);
            }

            FlushHttpHarIfEnabled();
        }
        catch (Exception ex)
        {
            AppendDecryptLog($"Octagon RK error: {ex.Message}");
            MessageBox.Show(this, ex.Message, "Octagon RK",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            await RemintAnisetteAfterSensitiveOpAsync("Octagon RK unlock")
                .ConfigureAwait(true);
            EscrowOctagonRkButton.IsEnabled = true;
        }
    }

    private async void EscrowOctagonPeerButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "OTBottle / Peer",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var outputDir = _session.OctagonKeysDirectory;
        if (string.IsNullOrWhiteSpace(outputDir))
        {
            outputDir = DecryptOutputTextBox.Text.Trim();
            if (string.IsNullOrEmpty(outputDir))
                outputDir = OutputFolderTextBox.Text.Trim();
        }

        if (_session.OctagonBottledPeerEntropy is not { Length: > 0 })
        {
            var entropyPath = string.IsNullOrWhiteSpace(outputDir)
                ? null
                : Path.Combine(outputDir, OctagonBottleRecoveryService.EntropyFileName);
            if (entropyPath is not null && File.Exists(entropyPath))
            {
                _session.OctagonBottledPeerEntropy = await File.ReadAllBytesAsync(entropyPath);
                _session.OctagonKeysDirectory ??= outputDir;
                AppendDecryptLog($"Entropy reloaded from disk ({_session.OctagonBottledPeerEntropy.Length} B)");
            }
            else
            {
                MessageBox.Show(this,
                    "BottledPeerEntropy required: run Unlock Octagon bottle first.",
                    "OTBottle / Peer", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        if (string.IsNullOrWhiteSpace(outputDir))
        {
            MessageBox.Show(this, "Select an output folder.", "OTBottle / Peer",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            EscrowOctagonPeerButton.IsEnabled = false;
            await RunOctagonPeerRecoveryAsync(outputDir).ConfigureAwait(true);
        }
        finally
        {
            EscrowOctagonPeerButton.IsEnabled = true;
        }
    }

    private async Task RunOctagonPeerRecoveryAsync(string outputDir)
    {
        if (_session is null)
            return;
        AppendDecryptLog($"OTBottle / Peer keys → {outputDir}");
        var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendDecryptLog(msg)));
        // Escrow recover (PIN bottle) lascia spesso mmeAuthToken rifiutato da ckAppInit
        // finché non si rifà GrandSlam — evita il 401 su com.apple.security.keychain.
        await Orchestrator
            .EnsureFreshCloudKitAfterEscrowAsync(_session, log, CancellationToken.None)
            .ConfigureAwait(true);
        var svc = new OctagonCuttlefishService(Http, Orchestrator);
        var peer = await svc.FetchAndDecryptPeerAsync(_session, outputDir, log)
            .ConfigureAwait(true);
        AppendDecryptLog(peer.Success ? $"OK: {peer.Message}" : $"FAIL: {peer.Message}");
        if (peer.PeerEncryptionPkcs8Path is not null)
            AppendDecryptLog($"Peer enc: {peer.PeerEncryptionPkcs8Path}");
        if (peer.Success)
        {
            AppendDecryptLog(
                "Auto-start CKKS OpenVault (Manatee + PCS + Passwords + WiFi)…");
            var ckks = new CkksVaultService(Http, Orchestrator);
            var vault = await ckks.OpenViewsAsync(_session, outputDir, log: log)
                .ConfigureAwait(true);
            AppendDecryptLog(vault.Success ? $"CKKS: {vault.Message}" : $"CKKS FAIL: {vault.Message}");
            if (vault.PcsKeysFound > 0)
                AppendDecryptLog($"Manatee PCS keys in session: {vault.PcsKeysFound}");
            AppendDecryptLog(
                "Export: ckks_passwords.csv + notes/OTP + wifi/certs/keys (se TLK OK)");
            if (OctagonAuthzProbeRunner.IsEnabled)
            {
                AppendDecryptLog("AUTHZ probes (IKE_AUTHZ_PROBES=1)…");
                await OctagonAuthzProbeRunner.RunRecoverableForPeerMatrixAsync(
                        new OctagonCuttlefishService(Http, Orchestrator),
                        _session, outputDir, log)
                    .ConfigureAwait(true);
            }

            FlushHttpHarIfEnabled();
        }
    }

    private void FlushHttpHarIfEnabled()
    {
        if (!IkeLogOptions.PersistRunLogs && !IkeLogOptions.FullHarCapture)
            return;
        try
        {
            _capture.FlushHarFiles();
            if (!string.IsNullOrEmpty(_capture.HarPath) && File.Exists(_capture.HarPath))
            {
                AppendDecryptLog(
                    $"HAR: {_capture.HarPath} ({_capture.HarEntryCount} entry) | " +
                    $"redacted: {Path.GetFileName(_capture.HarRedactedPath)}");
            }
        }
        catch (Exception ex)
        {
            AppendDecryptLog($"HAR flush: {ex.Message}");
        }
    }

    private async void EscrowCkksVaultButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "CKKS OpenVault",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = _session.OctagonKeysDirectory;
        if (string.IsNullOrWhiteSpace(outputDir))
        {
            outputDir = DecryptOutputTextBox.Text.Trim();
            if (string.IsNullOrEmpty(outputDir))
                outputDir = OutputFolderTextBox.Text.Trim();
        }

        if (string.IsNullOrWhiteSpace(outputDir))
        {
            MessageBox.Show(this, "Select an output folder (Escrow).", "CKKS OpenVault",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);

        if (_session.OctagonPeerEncryptionPkcs8 is not { Length: > 0 })
        {
            var encPath = Path.Combine(outputDir, "octagon_peer_encryption.pkcs8");
            if (File.Exists(encPath))
            {
                _session.OctagonPeerEncryptionPkcs8 = await File.ReadAllBytesAsync(encPath);
                AppendDecryptLog($"Peer enc reloaded from disk ({_session.OctagonPeerEncryptionPkcs8.Length} B)");
            }
        }

        if (string.IsNullOrWhiteSpace(_session.OctagonPeerId))
        {
            var metaPath = Path.Combine(outputDir, "octagon_peer_unlock_meta.json");
            if (File.Exists(metaPath))
            {
                try
                {
                    using var doc = System.Text.Json.JsonDocument.Parse(
                        await File.ReadAllTextAsync(metaPath));
                    if (doc.RootElement.TryGetProperty("peerId", out var p))
                        _session.OctagonPeerId = p.GetString();
                }
                catch
                {
                    // ignore
                }
            }
        }

        if (_session.OctagonPeerEncryptionPkcs8 is not { Length: > 0 }
            || string.IsNullOrWhiteSpace(_session.OctagonPeerId))
        {
            MessageBox.Show(this,
                "Peer encryption + peerId required: run OTBottle / Peer keys first.",
                "CKKS OpenVault", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            EscrowCkksVaultButton.IsEnabled = false;
            AppendDecryptLog($"CKKS OpenVault → {outputDir}");
            var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendDecryptLog(msg)));
            var svc = new CkksVaultService(Http, Orchestrator);
            var result = await svc.OpenViewsAsync(_session, outputDir, log: log)
                .ConfigureAwait(true);
            AppendDecryptLog(result.Success ? $"OK: {result.Message}" : $"FAIL: {result.Message}");
            if (result.PcsKeysFound > 0)
                AppendDecryptLog($"Manatee PCS keys in session: {result.PcsKeysFound}");
            if (result.ItemsJsonPath is not null)
                AppendDecryptLog($"Items: {result.ItemsJsonPath}");
            foreach (var name in new[]
                     {
                         "ckks_passwords.csv", "ckks_notes_otp.csv", "ckks_wifi.csv",
                         "ckks_certs.csv", "ckks_keys.csv", "ckks_credit_cards.csv",
                         "ckks_catalog.csv", "ckks_passkeys.csv", "ckks_subsystem.csv"
                     })
            {
                var p = Path.Combine(outputDir, name);
                if (File.Exists(p))
                    AppendDecryptLog($"{name}: {p}");
            }
            if (OctagonAuthzProbeRunner.IsEnabled && _session is not null)
            {
                AppendDecryptLog("AUTHZ probes (IKE_AUTHZ_PROBES=1)…");
                await OctagonAuthzProbeRunner.RunRecoverableForPeerMatrixAsync(
                        new OctagonCuttlefishService(Http, Orchestrator),
                        _session, outputDir, log)
                    .ConfigureAwait(true);
            }

            FlushHttpHarIfEnabled();
            MessageBox.Show(this, result.Message, "CKKS OpenVault",
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            AppendDecryptLog($"CKKS OpenVault error: {ex.Message}");
            MessageBox.Show(this, ex.Message, "CKKS OpenVault",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            EscrowCkksVaultButton.IsEnabled = true;
        }
    }

    private void AttachPcsKeysToSession(byte[]? keySet, string directory)
    {
        if (_session is null)
            return;
        if (keySet is { Length: > 0 })
            _session.PcsEscrowedKeySet = keySet;
        _session.PcsKeysDirectory = directory;
        AppendDecryptLog(
            $"PCS KeySet in session: {_session.PcsEscrowedKeySet?.Length ?? 0} B ← {directory}");
    }

    private async Task AttachPcsKeysFromDirectoryAsync(string directory)
    {
        if (_session is null)
            return;
        _session.PcsKeysDirectory = directory;
        var unlocked = Path.Combine(directory, EscrowPcsUnlock.UnlockedKeysFileName);
        if (!File.Exists(unlocked))
        {
            // Recover può aver già fatto unlock: se manca, prova ora.
            var unlock = await new EscrowRecoveryService(Http)
                .CompletePcsUnlockOfflineAsync(directory);
            if (unlock.Success && unlock.Plaintext is { Length: > 0 })
            {
                AttachPcsKeysToSession(unlock.Plaintext, directory);
                return;
            }
        }

        if (File.Exists(unlocked))
        {
            AttachPcsKeysToSession(await File.ReadAllBytesAsync(unlocked), directory);
            return;
        }

        AppendDecryptLog("PCS KeySet not yet in session — use Unlock EscrowedKeys.");
    }

    private void AppendWhatsAppLog(string line) =>
        AppendBoundedLog(WhatsAppLogTextBox, line, "whatsapp");

    private void BrowseWhatsAppOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            ApplyBrowsedFolder(WhatsAppOutputTextBox, dlg.FolderName);
    }

    private async void WhatsAppProbeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "WhatsApp CloudKit",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = WhatsAppOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Select an output folder.", "WhatsApp CloudKit",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);

        try
        {
            WhatsAppProbeButton.IsEnabled = false;
            AppendWhatsAppLog($"Probe WhatsApp (CK + Documents) → {outputDir}");

            var pcsDir = EscrowPcsSession.ResolvePcsKeysDirectory(
                DecryptOutputTextBox.Text.Trim(),
                _session.OctagonKeysDirectory,
                _session.PcsKeysDirectory,
                outputDir);
            Directory.CreateDirectory(pcsDir);
            _ = EscrowPcsSession.TryLoadManateeFromDisk(_session, pcsDir, null);

            // Seed PCS (Escrow KeySet o Manatee) obbligatorio per basename + MMCS decrypt.
            var iCsc = ResolveEscrowIcsc();
            if (string.IsNullOrEmpty(EscrowPasswordBox.Password.Trim()) && !string.IsNullOrEmpty(iCsc))
                AppendWhatsAppLog($"iCSC empty → default DSID ({iCsc})");
            EscrowSmsOptions? sms = EscrowSmsVariantCheckBox.IsChecked == true
                ? new EscrowSmsOptions(
                    Enabled: true,
                    SmsChallengeCode: EscrowSmsCodeBox.Text,
                    RequestSmsChallenge: EscrowRequestSmsCheckBox.IsChecked == true)
                : null;
            var ensureLog = new Progress<string>(msg => Dispatcher.Invoke(() => AppendWhatsAppLog(msg)));
            var ensure = await EscrowPcsSession.EnsureKeySetAsync(
                _session, Http, pcsDir, iCsc, sms, ensureLog);
            if (!ensure.Success || !PcsSessionSeedKeys.HasAny(_session))
            {
                AppendWhatsAppLog($"FAIL PCS: {ensure.Message}");
                MessageBox.Show(this,
                    ensure.Message
                    ?? "PCS missing — Unlock EscrowedKeys or Octagon/CKKS OpenVault (Manatee).",
                    "WhatsApp CloudKit",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            AppendWhatsAppLog(PcsSessionSeedKeys.DescribeSeed(_session, ensure.Source));

            var session = _session;
            var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendWhatsAppLog(msg)));
            var ckResult = await Task.Run(async () =>
            {
                var ckProbe = new WhatsAppCloudKitProbeService(Http, Orchestrator);
                var ck = await ckProbe.ProbePrivateDatabaseAsync(session, outputDir, log)
                    .ConfigureAwait(false);
                var docsProbe = new WhatsAppDocumentsProbeService(Http, Orchestrator);
                await docsProbe.ProbeAsync(session, outputDir, log, pcsKeysDirectory: pcsDir)
                    .ConfigureAwait(false);
                return ck;
            }).ConfigureAwait(true);

            AppendWhatsAppLog($"CK probe OK: {ckResult.OutputDirectory}");
            AppendWhatsAppLog("Documents probe finished.");
            MessageBox.Show(this,
                $"Probe completed (live values from this run only).\n" +
                $"CK: {ckResult.OutputDirectory}\n" +
                "Documents: whatsapp_docs_* folder (artifact, not input).\n" +
                "Crypto: zone/retrieve + FetchRecords + PCS KeySet in session.",
                "WhatsApp CloudKit",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AppendWhatsAppLog($"Error: {ex.Message}");
            MessageBox.Show(this, ex.Message, "WhatsApp CloudKit",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            WhatsAppProbeButton.IsEnabled = true;
        }
    }

    private void AppendICloudDriveLog(string line) =>
        AppendBoundedLog(ICloudDriveLogTextBox, line, "drive");

    private void BrowseICloudDriveOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            ApplyBrowsedFolder(ICloudDriveOutputTextBox, dlg.FolderName);
    }

    private async void ICloudDriveProbeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "iCloud Drive",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = ICloudDriveOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Select an output folder.", "iCloud Drive",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);

        try
        {
            ICloudDriveProbeButton.IsEnabled = false;
            ICloudDriveProgressBar.Value = 0;
            ICloudDriveStatusText.Text = "Starting…";
            AppendICloudDriveLog($"iCloud Drive → {outputDir}");

            var pcsDir = EscrowPcsSession.ResolvePcsKeysDirectory(
                DecryptOutputTextBox.Text.Trim(),
                _session.OctagonKeysDirectory,
                _session.PcsKeysDirectory,
                outputDir);
            Directory.CreateDirectory(pcsDir);
            _ = EscrowPcsSession.TryLoadManateeFromDisk(_session, pcsDir, null);

            var iCsc = ResolveEscrowIcsc();
            EscrowSmsOptions? sms = EscrowSmsVariantCheckBox.IsChecked == true
                ? new EscrowSmsOptions(
                    Enabled: true,
                    SmsChallengeCode: EscrowSmsCodeBox.Text,
                    RequestSmsChallenge: EscrowRequestSmsCheckBox.IsChecked == true)
                : null;
            var ensureLog = new Progress<string>(msg => Dispatcher.Invoke(() => AppendICloudDriveLog(msg)));
            var ensure = await EscrowPcsSession.EnsureKeySetAsync(
                _session, Http, pcsDir, iCsc, sms, ensureLog);
            if (!ensure.Success || !PcsSessionSeedKeys.HasAny(_session))
            {
                AppendICloudDriveLog($"FAIL PCS: {ensure.Message}");
                ICloudDriveStatusText.Text = "PCS missing";
                MessageBox.Show(this,
                    ensure.Message
                    ?? "PCS missing — Unlock EscrowedKeys or Octagon/CKKS OpenVault (Manatee).",
                    "iCloud Drive",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            AppendICloudDriveLog(PcsSessionSeedKeys.DescribeSeed(_session, ensure.Source));

            var includeApps = ICloudDriveIncludeAppZonesCheckBox.IsChecked == true;
            var session = _session;
            var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendICloudDriveLog(msg)));
            var progress = new Progress<ICloudDriveProgress>(p => Dispatcher.Invoke(() =>
            {
                ICloudDriveProgressBar.Value = p.Percent;
                ICloudDriveStatusText.Text = $"{p.Phase}: {p.Detail}";
            }));

            var probe = new ICloudDriveProbeService(Http, Orchestrator);
            var result = await Task.Run(
                    () => probe.ProbeAsync(
                        session,
                        outputDir,
                        includeApps,
                        log,
                        progress,
                        pcsKeysDirectory: pcsDir),
                    CancellationToken.None)
                .ConfigureAwait(true);

            ICloudDriveProgressBar.Value = 100;
            ICloudDriveStatusText.Text = result.Success ? "Completed" : "Error";
            AppendICloudDriveLog(
                $"Fine: zone={result.ZonesProcessed} record={result.RecordsFetched} → {result.OutputDirectory}");

            MessageBox.Show(this,
                result.Success
                    ? $"iCloud Drive download completed.\n{result.OutputDirectory}\n" +
                      $"Zone: {result.ZonesProcessed}, record: {result.RecordsFetched}\n" +
                      "Decrypted files in clouddocs_ck/fetch_*/crypto/plaintext/"
                    : result.Error ?? "Probe failed.",
                "iCloud Drive",
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            AppendICloudDriveLog($"Error: {ex.Message}");
            ICloudDriveStatusText.Text = "Error";
            MessageBox.Show(this, ex.Message, "iCloud Drive",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ICloudDriveProbeButton.IsEnabled = true;
        }
    }

    private void AppendICloudFilesLog(string line) =>
        AppendBoundedLog(ICloudFilesLogTextBox, line, "files");

    private void BrowseICloudFilesOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            ApplyBrowsedFolder(ICloudFilesOutputTextBox, dlg.FolderName);
    }

    private async void ICloudFilesProbeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "iCloud Files",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = ICloudFilesOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Select an output folder.", "iCloud Files",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);

        try
        {
            ICloudFilesProbeButton.IsEnabled = false;
            ICloudFilesProgressBar.Value = 0;
            ICloudFilesStatusText.Text = "Starting…";
            AppendICloudFilesLog($"iCloud Files  → {outputDir}");

            var pcsDir = EscrowPcsSession.ResolvePcsKeysDirectory(
                DecryptOutputTextBox.Text.Trim(),
                _session.OctagonKeysDirectory,
                _session.PcsKeysDirectory,
                outputDir);
            Directory.CreateDirectory(pcsDir);
            _ = EscrowPcsSession.TryLoadManateeFromDisk(_session, pcsDir, null);

            var iCsc = ResolveEscrowIcsc();
            EscrowSmsOptions? sms = EscrowSmsVariantCheckBox.IsChecked == true
                ? new EscrowSmsOptions(
                    Enabled: true,
                    SmsChallengeCode: EscrowSmsCodeBox.Text,
                    RequestSmsChallenge: EscrowRequestSmsCheckBox.IsChecked == true)
                : null;
            var ensureLog = new Progress<string>(msg => Dispatcher.Invoke(() => AppendICloudFilesLog(msg)));
            var ensure = await EscrowPcsSession.EnsureKeySetAsync(
                _session, Http, pcsDir, iCsc, sms, ensureLog);
            if (!ensure.Success || !PcsSessionSeedKeys.HasAny(_session))
            {
                AppendICloudFilesLog($"FAIL PCS: {ensure.Message}");
                ICloudFilesStatusText.Text = "PCS missing";
                MessageBox.Show(this,
                    ensure.Message
                    ?? "PCS missing — Unlock EscrowedKeys or Octagon/CKKS OpenVault (Manatee).",
                    "iCloud Files",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            AppendICloudFilesLog(PcsSessionSeedKeys.DescribeSeed(_session, ensure.Source));

            var session = _session;
            var log = new Progress<string>(msg => Dispatcher.Invoke(() => AppendICloudFilesLog(msg)));
            var progress = new Progress<ICloudDriveProgress>(p => Dispatcher.Invoke(() =>
            {
                ICloudFilesProgressBar.Value = p.Percent;
                ICloudFilesStatusText.Text = $"{p.Phase}: {p.Detail}";
            }));

            var probe = new ICloudDriveProbeService(Http, Orchestrator);
            var result = await Task.Run(
                    () => probe.ProbeAsync(
                        session,
                        outputDir,
                        ICloudDriveProbeOptions.ICloudFiles(),
                        log,
                        progress,
                        pcsKeysDirectory: pcsDir),
                    CancellationToken.None)
                .ConfigureAwait(true);

            ICloudFilesProgressBar.Value = 100;
            ICloudFilesStatusText.Text = result.Success ? "Completed" : "Error";
            AppendICloudFilesLog(
                $"Fine: zone={result.ZonesProcessed} record={result.RecordsFetched} → {result.OutputDirectory}");

            MessageBox.Show(this,
                result.Success
                    ? $"iCloud Files download completed.\n{result.OutputDirectory}\n" +
                      $"Zone: {result.ZonesProcessed}, record: {result.RecordsFetched}\n" +
                      "Manifest: icloud_files_manifest.json\n" +
                      "Plaintext: clouddocs_ck/fetch_*/crypto/plaintext/"
                    : result.Error ?? "Probe failed.",
                "iCloud Files",
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            AppendICloudFilesLog($"Error: {ex.Message}");
            ICloudFilesStatusText.Text = "Error";
            MessageBox.Show(this, ex.Message, "iCloud Files",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ICloudFilesProbeButton.IsEnabled = true;
        }
    }

    private void BrowseSyncDataOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            ApplyBrowsedFolder(SyncDataOutputTextBox, dlg.FolderName);
    }

    private void AppendSyncDataLog(string line)
    {
        var kind = ClassifyDownloadLog(line);
        var box = kind == DownloadLogKind.Error
            ? SyncDataErrorLogBox
            : SyncDataInfoLogBox;
        var bodyBrush = kind switch
        {
            DownloadLogKind.Error => LogErrorBrush,
            DownloadLogKind.Warning => LogWarningBrush,
            _ => LogInfoBrush,
        };
        AppendRichLogLine(box, line, bodyBrush, "syncdata");
    }

    private void CopySyncDataLog_Click(object sender, RoutedEventArgs e)
    {
        var active = SyncDataLogTabs.SelectedIndex == 1
            ? SyncDataErrorLogBox
            : SyncDataInfoLogBox;
        var text = GetRichTextPlain(active);
        if (string.IsNullOrEmpty(text))
            return;

        try
        {
            Clipboard.SetText(text);
        }
        catch (Exception ex)
        {
            AppendSyncDataLog($"Copy log failed: {ex.Message}");
        }
    }


    private async void SyncDataProbeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "iCloud Sync Data",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = SyncDataOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Select an output folder.", "iCloud Sync Data",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);

        try
        {
            SyncDataProbeButton.IsEnabled = false;
            SyncDataProgressBar.IsIndeterminate = false;
            SyncDataProgressBar.Value = 0;
            SyncDataPhasePanel.Visibility = Visibility.Collapsed;
            SyncDataPhaseProgressBar.IsIndeterminate = false;
            SyncDataPhaseProgressBar.Value = 0;
            SyncDataPhaseStatusText.Text = "";
            SyncDataStatusText.Text = "Starting…";
            AppendSyncDataLog($"Sync Data → {outputDir}");


            var pcsDir = DecryptOutputTextBox.Text.Trim();
            if (string.IsNullOrEmpty(pcsDir))
                pcsDir = outputDir;
            Directory.CreateDirectory(pcsDir);

            var iCsc = ResolveEscrowIcsc();
            if (string.IsNullOrEmpty(EscrowPasswordBox.Password.Trim()) && !string.IsNullOrEmpty(iCsc))
                AppendSyncDataLog($"iCSC empty → default DSID ({iCsc})");
            EscrowSmsOptions? sms = EscrowSmsVariantCheckBox.IsChecked == true
                ? new EscrowSmsOptions(
                    Enabled: true,
                    SmsChallengeCode: EscrowSmsCodeBox.Text,
                    RequestSmsChallenge: EscrowRequestSmsCheckBox.IsChecked == true)
                : null;

            // Progress non bloccante: BeginInvoke evita che il worker aspetti il thread UI.
            var uiLog = new Progress<string>(msg =>
                Dispatcher.BeginInvoke(() => AppendSyncDataLog(msg)));
            var uiProgress = new Progress<SyncDataProgressReport>(r =>
                Dispatcher.BeginInvoke(() => ApplySyncDataProgress(r)));

            var selected = GetSelectedSyncDataCategoryIds();
            if (selected.Count == 0)
            {
                MessageBox.Show(this,
                    "Select at least one Sync Data category (Photos / Account Info).",
                    "iCloud Sync Data",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            AppendSyncDataLog($"Selected categories: {string.Join(", ", selected)}");
            var buildPhotosRecordMetadata = IsPhotosBuildRecordMetadataEnabled();
            if (selected.Any(static id =>
                    string.Equals(id, SyncDataCategoryCatalog.PhotosId, StringComparison.OrdinalIgnoreCase)))
            {
                AppendSyncDataLog(
                    buildPhotosRecordMetadata
                        ? "Photos: BuildRecordMetadata ON (nomi file PCS)"
                        : "Photos: BuildRecordMetadata OFF (crypto/Album/MMCS only)");
            }

            var needsPcs = SyncDataCategoryCatalog.SelectionRequiresPcs(selected);
            var session = _session!;

            if (needsPcs)
            {
                await Dispatcher.InvokeAsync(() =>
                {
                    SyncDataProgressBar.IsIndeterminate = true;
                    SyncDataStatusText.Text = "PCS (Escrow / Manatee)…";
                });

                // Preferisci Manatee Octagon/CKKS già su disco (ADP) prima del recover Escrow.
                pcsDir = EscrowPcsSession.ResolvePcsKeysDirectory(
                    session.OctagonKeysDirectory,
                    session.PcsKeysDirectory,
                    pcsDir,
                    outputDir);
                _ = EscrowPcsSession.TryLoadManateeFromDisk(session, pcsDir, uiLog);

                if (!PcsSessionSeedKeys.HasAny(session))
                {
                    var ensure = await Task.Run(
                        () => EscrowPcsSession.EnsureKeySetAsync(
                            session, Http, pcsDir, iCsc, sms, uiLog),
                        CancellationToken.None).ConfigureAwait(false);

                    if (!ensure.Success || !PcsSessionSeedKeys.HasAny(session))
                    {
                        await Dispatcher.InvokeAsync(() =>
                        {
                            AppendSyncDataLog($"FAIL PCS: {ensure.Message}");
                            MessageBox.Show(this,
                                ensure.Message
                                ?? "PCS missing — Unlock EscrowedKeys or Octagon/CKKS OpenVault (Manatee).",
                                "iCloud Sync Data",
                                MessageBoxButton.OK,
                                MessageBoxImage.Warning);
                        });
                        return;
                    }

                    await Dispatcher.InvokeAsync(() => AppendSyncDataLog(
                        PcsSessionSeedKeys.DescribeSeed(session, ensure.Source)));
                }
                else
                {
                    // Escrow già in sessione: Ensure ricarica comunque Manatee da disco.
                    if (session.PcsManateeCompactKeys is not { Count: > 0 })
                    {
                        await Task.Run(
                                () => EscrowPcsSession.EnsureKeySetAsync(
                                    session, Http, pcsDir, iCsc, sms, uiLog),
                                CancellationToken.None)
                            .ConfigureAwait(false);
                    }

                    await Dispatcher.InvokeAsync(() => AppendSyncDataLog(
                        PcsSessionSeedKeys.DescribeSeed(session, "session")));
                }
            }
            else
            {
                AppendSyncDataLog("PCS — skip (category without KeySet/Manatee)");
            }

            var probe = new ICloudSyncDataProbeService(Http, Orchestrator);

            var result = await Task.Run(
                () => probe.ProbeAsync(
                    session, outputDir, uiLog,
                    selectedCategoryIds: selected,
                    progress: uiProgress,
                    buildPhotosRecordMetadata: buildPhotosRecordMetadata),
                CancellationToken.None).ConfigureAwait(false);


            var ok = result.Containers.Count(static c => c.Ok);
            await Dispatcher.InvokeAsync(() =>
            {
                AppendSyncDataLog($"Done: {ok}/{result.Containers.Count} containers → {result.OutputDirectory}");
                if (!string.IsNullOrEmpty(result.RunLogPath))
                    AppendSyncDataLog($"Log run: {result.RunLogPath}");
                SyncDataProgressBar.Value = 100;
                SyncDataPhasePanel.Visibility = Visibility.Collapsed;
                SyncDataPhaseProgressBar.Value = 100;
                SyncDataStatusText.Text = result.Containers.Count == 0
                    ? $"Completed → {Path.GetFileName(result.OutputDirectory)}"
                    : $"Completed: {ok}/{result.Containers.Count} OK";
                MessageBox.Show(this,
                    $"Sync Data completed.\n{result.OutputDirectory}\n" +
                    (result.Containers.Count == 0
                        ? "accountinfo/ senza container CloudKit.\n"
                        : $"Container OK: {ok}/{result.Containers.Count}\n") +
                    (string.IsNullOrEmpty(result.RunLogPath) ? "" : $"Log: {result.RunLogPath}\n") +
                    "accountinfo/ + ck/<container>/.",
                    "iCloud Sync Data",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            });
        }
        catch (Exception ex)
        {
            await Dispatcher.InvokeAsync(() =>
            {
                AppendSyncDataLog($"Error: {ex.Message}");
                SyncDataProgressBar.IsIndeterminate = false;
                SyncDataStatusText.Text = $"Error: {ex.Message}";
                MessageBox.Show(this, ex.Message, "iCloud Sync Data",
                    MessageBoxButton.OK, MessageBoxImage.Error);
            });
        }
        finally
        {
            await Dispatcher.InvokeAsync(() =>
            {
                SyncDataProbeButton.IsEnabled = true;
                SyncDataProgressBar.IsIndeterminate = false;
            });
        }
    }

    private void ApplySyncDataProgress(SyncDataProgressReport r)
    {
        SyncDataStatusText.Text = r.Status;
        if (r.IsIndeterminate)
        {
            SyncDataProgressBar.IsIndeterminate = true;
        }
        else
        {
            SyncDataProgressBar.IsIndeterminate = false;
            if (r.Percent is { } pct && double.IsFinite(pct))
            {
                var lo = SyncDataProgressBar.Minimum;
                var hi = SyncDataProgressBar.Maximum;
                SyncDataProgressBar.Value = Math.Clamp(pct, lo, hi);
            }
        }

        if (r.ClearPhase)
        {
            SyncDataPhasePanel.Visibility = Visibility.Collapsed;
            SyncDataPhaseProgressBar.IsIndeterminate = false;
            SyncDataPhaseProgressBar.Value = 0;
            SyncDataPhaseStatusText.Text = "";
            return;
        }

        if (r.PhaseLabel is null && r.PhasePercent is null && !r.PhaseIndeterminate)
            return;

        SyncDataPhasePanel.Visibility = Visibility.Visible;
        if (r.PhaseLabel is { Length: > 0 })
            SyncDataPhaseLabel.Text = r.PhaseLabel;

        // Dettaglio fase: riusa Status se non c'è etichetta dedicata oltre PhaseLabel.
        if (r.PhaseLabel is not null)
            SyncDataPhaseStatusText.Text = r.Status;

        if (r.PhaseIndeterminate)
        {
            SyncDataPhaseProgressBar.IsIndeterminate = true;
            return;
        }

        SyncDataPhaseProgressBar.IsIndeterminate = false;
        if (r.PhasePercent is { } phasePct && double.IsFinite(phasePct))
        {
            var lo = SyncDataPhaseProgressBar.Minimum;
            var hi = SyncDataPhaseProgressBar.Maximum;
            SyncDataPhaseProgressBar.Value = Math.Clamp(phasePct, lo, hi);
        }
    }

    private void UpdateSessionUi(bool connected)
    {
        SessionStatusText.Text = connected
            ? $"Connected — DSID {_session?.Dsid}"
            : "Not authenticated";

        SessionIndicator.Fill = new SolidColorBrush(connected
            ? Color.FromRgb(0x1E, 0x8E, 0x3E)
            : Color.FromRgb(0xBD, 0xC1, 0xC6));
        SessionStatusText.Foreground = new SolidColorBrush(connected
            ? Color.FromRgb(0x1E, 0x8E, 0x3E)
            : Color.FromRgb(0x42, 0x85, 0xF4));

        RefreshSessionInventoryPanel();
        PrefillEscrowRecoverySaltFromSession();
        RefreshSyncDataServiceCheckboxes();
        _ = RefreshCloudQuotaPanelAsync();
    }

    /// <summary>
    /// Come OctagonLab: altDSID Escrow = <see cref="ICloudSession.Adsid"/> SPD.
    /// Sempre allineato al login corrente (non lasciare il valore del account precedente).
    /// </summary>
    private void PrefillEscrowRecoverySaltFromSession()
    {
        if (EscrowRecoverySaltBox is null)
            return;
        var adsid = _session?.Adsid?.Trim();
        if (!string.IsNullOrWhiteSpace(adsid))
            EscrowRecoverySaltBox.Text = adsid;
        else if (_session is null)
            EscrowRecoverySaltBox.Text = "";
    }

    /// <summary>
    /// Pannello destro (sempre visibile): token promossi + spd.t + dataclass, valori completi.
    /// </summary>
    private void RefreshSessionInventoryPanel()
    {
        if (SessionTokensTextBox is null || SessionServicesTextBox is null)
            return;

        if (_session is null)
        {
            SessionTokensTextBox.Text = "Sign in to see recovered tokens.";
            SessionServicesTextBox.Text = "Sign in to see available services.";
            if (CloudQuotaTextBox is not null)
                CloudQuotaTextBox.Text = "Sign in to load iCloud storage.";
            return;
        }

        var s = _session;
        var tokens = new System.Text.StringBuilder();
        tokens.AppendLine($"Apple ID: {s.AppleId}");
        tokens.AppendLine($"DSID: {NullDash(s.Dsid)}");
        tokens.AppendLine($"adsid: {NullDash(s.Adsid)}");
        tokens.AppendLine($"Partition: {NullDash(s.Partition)}");
        tokens.AppendLine($"CloudKitUserId: {NullDash(s.CloudKitUserId)}");
        tokens.AppendLine();
        AppendFullSecret(tokens, "IdentityToken", s.IdentityToken);
        AppendFullSecret(tokens, "GsIdmsToken", s.GsIdmsToken);
        AppendFullSecret(tokens, "PeToken", s.PeToken);
        AppendFullSecret(tokens, "GsToken", s.GsToken);
        AppendFullSecret(tokens, "GsICloudAuthToken", s.GsICloudAuthToken);
        AppendFullSecret(tokens, "CloudKitGsToken", s.CloudKitGsToken);
        AppendFullSecret(tokens, "MobileMeAuthToken", s.MobileMeAuthToken);
        AppendFullSecret(tokens, "CloudKitAuthToken", s.CloudKitAuthToken);
        tokens.AppendLine();
        AppendFullSecret(tokens, "AppleCloudKitContext", s.AppleCloudKitContext);
        tokens.AppendLine($"CloudKitGatewayUrl: {NullDash(s.CloudKitGatewayUrl)}");
        tokens.AppendLine($"EscrowProxyUrl: {NullDash(s.EscrowProxyUrl)}");
        SessionTokensTextBox.Text = tokens.ToString().TrimEnd();

        var services = new System.Text.StringBuilder();
        var gs = s.GsServiceTokens;
        services.AppendLine($"=== GsServiceTokens (spd.t) — {gs.Count} ===");
        if (gs.Count == 0)
        {
            services.AppendLine("(empty — SPD did not populate t, or login incomplete)");
        }
        else
        {
            foreach (var kv in gs.OrderBy(static x => x.Key, StringComparer.OrdinalIgnoreCase))
                AppendFullSecret(services, kv.Key, kv.Value);
        }

        services.AppendLine();
        var urls = s.DataclassServiceUrls;
        services.AppendLine($"=== Endpoint servizi (get_account_settings) — {urls.Count} ===");
        if (urls.Count == 0)
        {
            services.AppendLine("(no urls — dataclass without url/escrowProxyUrl field)");
        }
        else
        {
            foreach (var kv in urls.OrderBy(static x => x.Key, StringComparer.OrdinalIgnoreCase))
            {
                var shortName = kv.Key.StartsWith("com.apple.Dataclass.", StringComparison.OrdinalIgnoreCase)
                    ? kv.Key["com.apple.Dataclass.".Length..]
                    : kv.Key;
                services.AppendLine($"{shortName}");
                services.AppendLine($"  {kv.Value}");
            }
        }

        services.AppendLine();
        var dc = s.AvailableDataclasses;
        services.AppendLine($"=== Dataclass abilitate — {dc.Count} ===");
        if (dc.Count == 0)
        {
            services.AppendLine("(none — get_account_settings did not return com.apple.Dataclass.*)");
        }
        else
        {
            foreach (var name in dc.OrderBy(static x => x, StringComparer.OrdinalIgnoreCase))
            {
                var shortName = name.StartsWith("com.apple.Dataclass.", StringComparison.OrdinalIgnoreCase)
                    ? name["com.apple.Dataclass.".Length..]
                    : name;
                var hasUrl = urls.ContainsKey(name)
                             || urls.Keys.Any(k => k.StartsWith(name + ".", StringComparison.OrdinalIgnoreCase));
                services.AppendLine(hasUrl ? $"{shortName}  ✓ url" : shortName);
            }
        }

        SessionServicesTextBox.Text = services.ToString().TrimEnd();
    }

    private void CopySessionTokensButton_Click(object sender, RoutedEventArgs e) =>
        CopyTextBoxToClipboard(SessionTokensTextBox, "Session tokens");

    private void CopySessionServicesButton_Click(object sender, RoutedEventArgs e) =>
        CopyTextBoxToClipboard(SessionServicesTextBox, "Services / dataclass");

    private void CopyCloudQuotaButton_Click(object sender, RoutedEventArgs e) =>
        CopyTextBoxToClipboard(CloudQuotaTextBox, "Cloud storage details");

    private void RefreshCloudQuotaButton_Click(object sender, RoutedEventArgs e) =>
        _ = RefreshCloudQuotaPanelAsync();

    private void CopyExploratoryServicesResult_Click(object sender, RoutedEventArgs e) =>
        CopyTextBoxToClipboard(ExploratoryServicesResultTextBox, "Services response");

    private void TrustedDevicesRefreshButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshApsTokenLabel();
        if (_session is null)
        {
            if (TrustedDevicesResultTextBox is not null)
            {
                TrustedDevicesResultTextBox.Text =
                    "Not signed in.\n\n" +
                    $"APS cert: {(ApsStorage.HasCertificate() ? "OK" : "NO")}\n" +
                    $"Push token: {ApsSessionService.TryGetPushTokenHex() ?? "(missing)"}";
            }

            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "APS status (no iCloud session).";
            return;
        }

        SyncIdmsaTrustFromSession(_session);
        var text = CreateTrustedDevicesService().FormatSessionTrustStatus(_session);
        if (TrustedDevicesResultTextBox is not null)
            TrustedDevicesResultTextBox.Text = text;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "Status updated from current session.";
        RefreshMadridUi();
        LogAuth("TrustedDevices: refresh status OK.");
    }

    private ApsSessionService GetApsSession()
    {
        if (_apsSession is not null)
            return _apsSession;
        _apsSession = new ApsSessionService(Http);
        _apsSession.Log += (_, msg) => Dispatcher.BeginInvoke(() =>
        {
            AppendApsLog(msg);
            LogAuth("APS: " + msg);
        });
        _apsSession.NotificationReceived += (_, e) => Dispatcher.BeginInvoke(() =>
        {
            var line = e.ExtractedOtp is not null
                ? $"[APS NOTIF] OTP={e.ExtractedOtp} {e.PayloadText}"
                : $"[APS NOTIF] {e.PayloadText ?? Convert.ToHexString(e.Payload ?? Array.Empty<byte>())}";
            AppendApsLog(line);
            if (e.ExtractedOtp is not null && IdmsaOtpCodeTextBox is not null
                && string.IsNullOrWhiteSpace(IdmsaOtpCodeTextBox.Text))
            {
                IdmsaOtpCodeTextBox.Text = e.ExtractedOtp;
            }

            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = e.ExtractedOtp is not null
                    ? $"APS: OTP received ({e.ExtractedOtp})"
                    : "APS: notification received";

            // Auto-submit HSA2 OTP when panel is open and trusted-device path is selected.
            if (e.ExtractedOtp is not null
                && _hsa2PartialSession is not null
                && IdmsaOtpPanel?.Visibility == Visibility.Visible
                && IdmsaOtpDeviceRadio?.IsChecked == true
                && IdmsaOtpSmsRadio?.IsChecked != true)
            {
                _ = SubmitHsa2OtpAsync(e.ExtractedOtp);
            }

            // Forward madrid / IDS payloads to the live message client when present.
            try
            {
                EnsureMadridClient().HandleApsNotification(e);
                RefreshMadridUi();
            }
            catch (Exception ex)
            {
                AppendApsLog("Madrid APS handler: " + ex.Message);
            }
        });
        return _apsSession;
    }

    private void AppendApsLog(string line)
    {
        if (TrustedDevicesResultTextBox is null)
            return;
        IkeUiSessionLog.Append("trusted", line);
        var stamp = DateTime.Now.ToString("HH:mm:ss");
        TrustedDevicesResultTextBox.AppendText(
            (TrustedDevicesResultTextBox.Text.Length > 0 ? Environment.NewLine : "")
            + $"[{stamp}] {line}");
        TrustedDevicesResultTextBox.ScrollToEnd();
    }

    private void RefreshApsTokenLabel()
    {
        if (ApsTokenText is null)
            return;
        var snap = _apsSession?.Snapshot() ?? new ApsPushState
        {
            HasCertificate = ApsStorage.HasCertificate(),
            Token = ApsStorage.TryLoadToken(),
        };
        var tok = snap.TokenHex;
        ApsTokenText.Text = string.IsNullOrEmpty(tok)
            ? $"Push token APS: (missing) cert={(snap.HasCertificate ? "OK" : "NO")} connected={snap.IsConnected}"
            : $"Push token APS: {tok}"
              + (snap.IsConnected ? $" | connected {snap.CourierHost}" : " | offline");
    }

    private async void ApsActivateButton_Click(object sender, RoutedEventArgs e)
    {
        if (ApsActivateButton is not null)
            ApsActivateButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "Albert activation…";
        try
        {
            var aps = GetApsSession();
            // Sempre rinnova: Albert ora usa deviceservices + RSA-1024 (pypush).
            var msg = await Task.Run(async () =>
                await aps.EnsureActivatedAsync(forceRenew: true).ConfigureAwait(false))
                .ConfigureAwait(true);
            AppendApsLog(msg);
            RefreshApsTokenLabel();
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "Albert: OK";
        }
        catch (Exception ex)
        {
            AppendApsLog("Albert error: " + ex.Message);
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "Albert: error";
            LogAuth("APS Albert: " + ex.Message);
        }
        finally
        {
            if (ApsActivateButton is not null)
                ApsActivateButton.IsEnabled = true;
        }
    }

    private async void ApsConnectButton_Click(object sender, RoutedEventArgs e)
    {
        if (ApsConnectButton is not null)
            ApsConnectButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "Connecting APS…";
        try
        {
            var aps = GetApsSession();
            await Task.Run(async () => await aps.ConnectAsync().ConfigureAwait(false))
                .ConfigureAwait(true);
            RefreshApsTokenLabel();
            EnsureMadridClient().BindCourier(aps.Courier);
            RefreshMadridUi();
            var snap = aps.Snapshot();
            AppendApsLog("APS connected. Token=" + (snap.TokenHex.Length > 0 ? snap.TokenHex : "?"));
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "APS: connected";
            if (_session is not null)
            {
                var text = CreateTrustedDevicesService().FormatSessionTrustStatus(_session);
                if (TrustedDevicesResultTextBox is not null)
                    TrustedDevicesResultTextBox.Text = text + Environment.NewLine + Environment.NewLine
                        + TrustedDevicesResultTextBox.Text;
            }
        }
        catch (Exception ex)
        {
            AppendApsLog("APS connect error: " + ex.Message);
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "APS: connect error";
            LogAuth("APS connect: " + ex.Message);
            RefreshApsTokenLabel();
        }
        finally
        {
            if (ApsConnectButton is not null)
                ApsConnectButton.IsEnabled = true;
        }
    }

    private async void ApsDisconnectButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            if (_apsSession is not null)
                await _apsSession.DisconnectAsync().ConfigureAwait(true);
            RefreshApsTokenLabel();
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "APS: disconnected";
            AppendApsLog("APS disconnected.");
        }
        catch (Exception ex)
        {
            AppendApsLog("APS disconnect: " + ex.Message);
        }
    }

    private async void Hsa2NewAdiButton_Click(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            "Delete the current ADI identity (device-iphone-coherent.json + worker session) " +
            "and create a new one via MidService.\n\n" +
            "Use when GSA no longer prompts for 2FA (ADI already trusted).\n" +
            "Do not abuse: Apple may respond HTTP 433 / 'ptm'.\n\n" +
            "Continue?",
            "New ADI identity",
            MessageBoxButton.YesNo,
            MessageBoxImage.Warning);
        if (confirm != MessageBoxResult.Yes)
            return;

        if (Hsa2NewAdiButton is not null)
            Hsa2NewAdiButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "ADI: newIdentity MidService…";

        try
        {
            var baseUrl = AnisetteProviderFactory.ResolveServerUrl().TrimEnd('/');
            AppendApsLog($"HSA2: POST {baseUrl}/provision?newIdentity=1…");
            using var provisionReq = new HttpRequestMessage(HttpMethod.Post, $"{baseUrl}/provision?newIdentity=1");
            RemoteAnisetteProvider.ApplyLicenseHeader(provisionReq);
            using var response = await Http
                .SendAsync(provisionReq)
                .ConfigureAwait(true);
            var body = await response.Content.ReadAsStringAsync().ConfigureAwait(true);
            if (!response.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"POST /provision?newIdentity=1 HTTP {(int)response.StatusCode}: {TrimUiBody(body)}");
            }

            // Verifica OTP sulla nuova macchina.
            using var probeReq = new HttpRequestMessage(HttpMethod.Get, baseUrl + "/");
            RemoteAnisetteProvider.ApplyLicenseHeader(probeReq);
            using var probe = await Http.SendAsync(probeReq).ConfigureAwait(true);
            var probeBody = await probe.Content.ReadAsStringAsync().ConfigureAwait(true);
            if (!probe.IsSuccessStatusCode)
            {
                throw new InvalidOperationException(
                    $"New ADI created but GET / failed HTTP {(int)probe.StatusCode}: {TrimUiBody(probeBody)}");
            }

            AppendApsLog("HSA2: new ADI OK — " + TrimUiBody(body));
            if (TrustedDevicesResultTextBox is not null)
                TrustedDevicesResultTextBox.Text = body + Environment.NewLine + Environment.NewLine + probeBody;
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "ADI: new identity OK — now Register for 2FA list";
            LogAuth("HSA2: newIdentity ADI OK.");
        }
        catch (Exception ex)
        {
            AppendApsLog("HSA2 newIdentity error: " + ex.Message);
            if (TrustedDevicesResultTextBox is not null)
                TrustedDevicesResultTextBox.Text = ex.Message;
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "ADI: newIdentity failed";
            LogAuth("HSA2 newIdentity: " + ex.Message);
            MessageBox.Show(this, ex.Message, "New ADI identity",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            if (Hsa2NewAdiButton is not null)
                Hsa2NewAdiButton.IsEnabled = true;
        }
    }

    private static string TrimUiBody(string body)
    {
        var t = body.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return t.Length <= 400 ? t : t[..400] + "…";
    }

    private async void Hsa2RegisterButton_Click(object sender, RoutedEventArgs e)
    {
        var appleId = Hsa2AppleIdTextBox?.Text?.Trim() ?? "";
        var password = Hsa2PasswordBox?.Password?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(appleId) || string.IsNullOrWhiteSpace(password))
        {
            MessageBox.Show(this,
                "Enter email and password in the HSA2 fields on this tab.\n" +
                "The Sign In tab Apple ID/password (and session PET) are not used.",
                "Lista 2FA", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var aps = GetApsSession();
        if (!aps.Snapshot().IsConnected)
        {
            MessageBox.Show(this,
                "Connect APS and keep the session active (ptkn in GSA CPD).",
                "Lista 2FA", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (Hsa2RegisterButton is not null)
            Hsa2RegisterButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "HSA2: SignIn GSA…";

        var log = new System.Text.StringBuilder();
        void Log(string m)
        {
            lock (log)
                log.AppendLine(m);
            Dispatcher.BeginInvoke(() => AppendApsLog("HSA2: " + m));
        }

        try
        {
            var useIphone = _authProfile?.UseFullIphoneAuth ?? true;
            var svc = new Hsa2TrustedDeviceService(
                Http, AnisetteProviderFactory.CreateAuth(Http), useIphone);

            var begin = await Task.Run(async () =>
                    await svc.BeginAsync(appleId, password, Log).ConfigureAwait(false))
                .ConfigureAwait(true);

            if (TrustedDevicesResultTextBox is not null)
            {
                string logText;
                lock (log)
                    logText = log.ToString();
                TrustedDevicesResultTextBox.Text = logText + Environment.NewLine + begin.DeviceSummary;
            }

            if (begin.NeedsOtp && begin.PartialSession is not null)
            {
                _hsa2PartialSession = begin.PartialSession;
                await ConfigureIdmsaOtpUiAsync(begin.Verification).ConfigureAwait(true);
                if (IdmsaOtpTitleText is not null)
                    IdmsaOtpTitleText.Text = "HSA2 OTP — code from your trusted Apple device";
                if (IdmsaOtpPanel is not null)
                    IdmsaOtpPanel.Visibility = Visibility.Visible;
                if (IdmsaOtpDeviceRadio is not null)
                    IdmsaOtpDeviceRadio.IsChecked = true;
                if (TrustedDevicesStatusText is not null)
                    TrustedDevicesStatusText.Text =
                        "HSA2: enter OTP from your iPhone, then Submit OTP";
                LogAuth("HSA2: waiting for OTP for 2FA list.");
                return;
            }

            _hsa2PartialSession = null;
            if (begin.CompletedSession is not null)
                _session = begin.CompletedSession;
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "HSA2: no challenge (see log)";
        }
        catch (Exception ex)
        {
            AppendApsLog("HSA2 error: " + ex.Message);
            if (TrustedDevicesResultTextBox is not null)
            {
                string logText;
                lock (log)
                    logText = log.ToString();
                TrustedDevicesResultTextBox.Text = logText + Environment.NewLine + ex.Message;
            }
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "HSA2: error";
            LogAuth("HSA2: " + ex.Message);
        }
        finally
        {
            if (Hsa2RegisterButton is not null)
                Hsa2RegisterButton.IsEnabled = true;
        }
    }

    private async void IdsEnrollButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null || string.IsNullOrWhiteSpace(_session.AppleId))
        {
            MessageBox.Show(this, "Sign in to iCloud first (PET required).", "Enroll IDS",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (string.IsNullOrWhiteSpace(ApsSessionService.TryGetPushTokenHex()))
        {
            MessageBox.Show(this,
                "An APS push token is required.\nActivate Albert → Connect APS, then retry Enroll IDS.",
                "Enroll IDS", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (IdsEnrollButton is not null)
            IdsEnrollButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "IDS enroll…";

        try
        {
            var anisette = AnisetteProviderFactory.CreateAuth(Http).Ios;
            var svc = new IdsEnrollmentService(Http, anisette);
            svc.Progress += (_, msg) => Dispatcher.Invoke(() => AppendApsLog("IDS: " + msg));

            var report = await Task.Run(async () =>
                    await svc.EnrollAsync(_session, CancellationToken.None).ConfigureAwait(false))
                .ConfigureAwait(true);

            if (TrustedDevicesResultTextBox is not null)
            {
                TrustedDevicesResultTextBox.Text =
                    report + Environment.NewLine + Environment.NewLine
                    + IdsStorage.FormatStatusSummary()
                    + Environment.NewLine + Environment.NewLine
                    + TrustedDevicesResultTextBox.Text;
            }

            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "IDS: enroll OK";
            LogAuth("IDS enroll completed.");
        }
        catch (Exception ex)
        {
            AppendApsLog("IDS enroll error: " + ex.Message);
            if (TrustedDevicesResultTextBox is not null)
            {
                TrustedDevicesResultTextBox.Text =
                    ex.Message + Environment.NewLine + Environment.NewLine
                    + IdsStorage.FormatStatusSummary()
                    + Environment.NewLine + Environment.NewLine
                    + TrustedDevicesResultTextBox.Text;
            }

            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "IDS: error";
            LogAuth("IDS enroll: " + ex.Message);
        }
        finally
        {
            if (IdsEnrollButton is not null)
                IdsEnrollButton.IsEnabled = true;
        }
    }

    private async Task ConfigureIdmsaOtpUiAsync(PhoneVerificationOptions? options)
    {
        if (IdmsaOtpPhoneComboBox is null)
            return;

        var phones = (options?.TrustedPhoneNumbers
                      ?? _hsa2PartialSession?.TrustedPhoneNumbers
                      ?? _session?.TrustedPhoneNumbers
                      ?? Array.Empty<TrustedPhoneNumber>()).ToList();

        // When GSA challenge has no SMS numbers, try Apple ID security/devices list.
        if (phones.Count == 0)
        {
            var sessionForPhones = _hsa2PartialSession ?? _session;
            if (sessionForPhones is not null)
            {
                try
                {
                    var useIphone = _authProfile?.UseFullIphoneAuth ?? true;
                    var svc = new Hsa2TrustedDeviceService(
                        Http, AnisetteProviderFactory.CreateAuth(Http), useIphone);
                    var associated = await Task.Run(async () =>
                            await svc.FetchAssociatedPhonesAsync(sessionForPhones, m => AppendApsLog("HSA2: " + m))
                                .ConfigureAwait(false))
                        .ConfigureAwait(true);
                    var mapped = associated
                        .Select((p, i) => new TrustedPhoneNumber
                        {
                            Id = i + 1,
                            ObfuscatedNumber = p.Obfuscated,
                            NumberWithDialCode = p.RawWithDialCode ?? p.Number,
                            LastTwoDigits = p.LastTwoDigits,
                        })
                        .Where(p => !string.IsNullOrWhiteSpace(p.DisplayLabel))
                        .ToList();
                    if (mapped.Count > 0)
                    {
                        phones = mapped;
                        AppendApsLog($"HSA2: phone list from security/devices ({phones.Count}).");
                    }
                }
                catch (Exception ex)
                {
                    AppendApsLog("HSA2: associated phones failed: " + ex.Message);
                }
            }
        }

        IdmsaOtpPhoneComboBox.ItemsSource = phones;
        if (phones.Count > 0)
            IdmsaOtpPhoneComboBox.SelectedIndex = 0;

        var hasSms = phones.Count > 0;
        if (IdmsaOtpSmsRadio is not null)
            IdmsaOtpSmsRadio.IsEnabled = hasSms;
        if (!hasSms && IdmsaOtpDeviceRadio is not null)
            IdmsaOtpDeviceRadio.IsChecked = true;

        IdmsaOtpMethodRadio_Changed(this, new RoutedEventArgs());
    }

    private MadridClient EnsureMadridClient()
    {
        if (_madridClient is not null)
            return _madridClient;
        _madridClient = new MadridClient(Http);
        _madridClient.Log += (_, msg) => Dispatcher.BeginInvoke(() => AppendApsLog(msg));
        _madridClient.Changed += (_, _) => Dispatcher.BeginInvoke(RefreshMadridUi);
        if (_apsSession?.IsConnected == true)
            _madridClient.BindCourier(_apsSession.Courier);
        return _madridClient;
    }

    private void RefreshMadridUi()
    {
        var madridOk = IdsStorage.HasMadridRegistration();
        var meta = IdsStorage.TryLoadMadridMeta();
        var persona = MadridDevicePersona.TryLoadMeta();
        if (MadridStatusText is not null)
        {
            var personaBit = MadridDevicePersona.HasPersona()
                ? $"persona={persona?.SerialNumber ?? "?"}"
                : "persona=missing";
            string nacBit;
            if (IdsValidationDataStore.HasBlob())
                nacBit = NacValidationService.IsRelayConfigured ? "nac=frida(overrides-relay)" : "nac=frida";
            else if (NacValidationService.IsRelayConfigured)
                nacBit = "nac=relay";
            else
                nacBit = "nac=local";
            var valBit = IdsValidationDataStore.HasBlob() ? "valdata=Frida" : "valdata=missing";
            var pushBit = IphoneApsPushStore.HasCredentials() ? "pushAPS=iPhone" : "pushAPS=Albert";
            personaBit = $"{personaBit}; {nacBit}; {valBit}; {pushBit}";
            if (madridOk)
            {
                var handles = meta?.Handles is { Count: > 0 }
                    ? string.Join(", ", meta.Handles)
                    : "(handles n/a)";
                MadridStatusText.Text =
                    $"Madrid: enrolled ({meta?.RegisteredUtc ?? "?"}) — {handles} | {personaBit}";
            }
            else
            {
                MadridStatusText.Text = IdsStorage.HasRegistration()
                    ? $"Madrid: not enrolled (Find My IDS present). {personaBit}"
                    : $"Madrid: not enrolled. {personaBit}";
            }
        }

        var client = _madridClient ?? EnsureMadridClient();
        if (MadridConversationsListBox is not null)
        {
            var selected = MadridConversationsListBox.SelectedItem as MadridConversation;
            MadridConversationsListBox.ItemsSource = client.Store.Conversations.ToList();
            if (selected is not null)
            {
                var match = client.Store.Conversations
                    .FirstOrDefault(c => string.Equals(
                        c.PeerHandle, selected.PeerHandle, StringComparison.OrdinalIgnoreCase));
                if (match is not null)
                    MadridConversationsListBox.SelectedItem = match;
            }
        }

        RefreshMadridThread();
    }

    private void RefreshMadridThread()
    {
        if (MadridThreadTextBox is null)
            return;
        var conv = MadridConversationsListBox?.SelectedItem as MadridConversation;
        if (conv is null)
        {
            MadridThreadTextBox.Text = "Select a conversation or look up a handle, then compose.";
            return;
        }

        var sb = new System.Text.StringBuilder();
        foreach (var m in conv.Messages)
        {
            var dir = m.Outgoing ? "→" : "←";
            var stamp = DateTime.TryParse(m.Utc, null, System.Globalization.DateTimeStyles.RoundtripKind, out var dt)
                ? dt.ToLocalTime().ToString("HH:mm:ss")
                : m.Utc;
            sb.AppendLine($"{stamp} {dir} {m.Body}");
        }

        MadridThreadTextBox.Text = sb.Length > 0 ? sb.ToString() : "(empty thread)";
    }

    private void MadridLoadPersonaButton_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Import Mac NAC data.plist",
            Filter = "Property list (*.plist)|*.plist|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        if (dlg.ShowDialog(this) != true)
            return;

        try
        {
            var info = MadridDevicePersona.ImportDataPlist(dlg.FileName, note: "UI import");
            AppendApsLog("Madrid persona imported: " + MadridDevicePersona.FormatStatusSummary());
            RefreshMadridUi();
            MessageBox.Show(this,
                "Imported Mac persona for NAC / Madrid register.\n\n"
                + $"Serial: {info.SerialNumber}\n"
                + $"Hardware: {info.HardwareVersion}\n"
                + $"Saved: {MadridDevicePersona.DataPlistPath}\n\n"
                + "Re-run Enroll Madrid. Capture on macOS:\n"
                + "  python3 scripts/nac-pypush/capture_mac_persona.py -o data.plist\n"
                + "Full dumps (encrypted IOKit keys) from nacserver extractor work better than partial ioreg.",
                "Load Mac persona", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Load Mac persona", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void MadridLoadValidationButton_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFileDialog
        {
            Title = "Import Frida IDS validation-data",
            Filter = "Base64 / JSON (*.b64;*.json;*.txt)|*.b64;*.json;*.txt|All files (*.*)|*.*",
            CheckFileExists = true,
        };
        if (dlg.ShowDialog(this) != true)
            return;

        try
        {
            var text = File.ReadAllText(dlg.FileName);
            IdsValidationDataStore.SaveBase64(text, source: dlg.FileName);
            AppendApsLog(IdsValidationDataStore.FormatStatusSummary());
            RefreshMadridUi();
            MessageBox.Show(this,
                "Saved Frida validation-data.\n\n"
                + IdsValidationDataStore.FormatStatusSummary() + "\n\n"
                + "Capture:\n"
                + "  python scripts/ios_akd_probe/fetch_aps_push_identity.py -H PHONE_IP:27042\n"
                + "  python scripts/ios_akd_probe/fetch_ids_validation.py -H PHONE_IP:27042\n"
                + "Toggle iMessage while attached, then Enroll Madrid within 1–2 minutes.\n"
                + "Without iPhone APS cert/key, Albert x-push-sig → 6009.",
                "Load validation-data", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Load validation-data", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void MadridEnrollButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first (PET required).", "Enroll Madrid",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (!MadridDevicePersona.HasPersona())
        {
            var cont = MessageBox.Show(this,
                "No Mac persona imported.\n\n"
                + "NAC validation-data needs Mac IOKit (serial/MLB/ROM), not iPhone Frida Anisette.\n"
                + "On a Mac with working iMessage:\n"
                + "  python3 scripts/nac-pypush/capture_mac_persona.py -o data.plist\n"
                + "Then Load Mac persona here.\n\n"
                + "Continue anyway with bundled spoofed data.plist? (likely 6009)",
                "Enroll Madrid", MessageBoxButton.YesNo, MessageBoxImage.Warning);
            if (cont != MessageBoxResult.Yes)
                return;
        }

        if (string.IsNullOrWhiteSpace(ApsSessionService.TryGetPushTokenHex()))
        {
            MessageBox.Show(this,
                "An APS push token is required.\nActivate Albert → Connect APS, then retry Enroll Madrid.",
                "Enroll Madrid", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MadridEnrollButton is not null)
            MadridEnrollButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "Madrid enroll…";

        try
        {
            var anisette = AnisetteProviderFactory.CreateAuth(Http).Ios;
            var svc = new IdsEnrollmentService(Http, anisette);
            svc.Progress += (_, msg) => Dispatcher.BeginInvoke(() => AppendApsLog("Madrid: " + msg));
            var body = await Task.Run(async () =>
                    await svc.EnrollMadridAsync(_session, CancellationToken.None).ConfigureAwait(false))
                .ConfigureAwait(true);

            if (TrustedDevicesResultTextBox is not null)
            {
                TrustedDevicesResultTextBox.Text =
                    body + Environment.NewLine + Environment.NewLine
                    + IdsStorage.FormatStatusSummary() + Environment.NewLine + Environment.NewLine
                    + TrustedDevicesResultTextBox.Text;
            }

            EnsureMadridClient();
            RefreshMadridUi();
            if (MadridMessagesExpander is not null)
                MadridMessagesExpander.IsExpanded = true;

            // Live iMessage is delivered to the push token used in id-register.
            // Reconnect courier on iPhone APS identity (not Albert) so RX works here.
            try
            {
                var aps = GetApsSession();
                AppendApsLog("Madrid OK — reconnecting APS on iPhone push token for live RX…");
                await Task.Run(async () =>
                        await aps.ConnectMadridIphoneAsync().ConfigureAwait(false))
                    .ConfigureAwait(true);
                EnsureMadridClient().BindCourier(aps.Courier);
                RefreshApsTokenLabel();
                var tok = aps.Snapshot().TokenHex;
                AppendApsLog(
                    "APS Madrid/iPhone connected. Token="
                    + (tok.Length > 0 ? tok : "?")
                    + " — ask friend to resend (phone may drop APS).");
                if (TrustedDevicesStatusText is not null)
                    TrustedDevicesStatusText.Text = "Madrid: enroll OK + APS iPhone";
            }
            catch (Exception apsEx)
            {
                AppendApsLog("APS iPhone reconnect after Madrid: " + apsEx.Message);
                if (TrustedDevicesStatusText is not null)
                    TrustedDevicesStatusText.Text = "Madrid: enroll OK (APS iPhone failed — Connect APS)";
            }

            LogAuth("Madrid enroll OK.");
        }
        catch (Exception ex)
        {
            AppendApsLog("Madrid enroll error: " + ex.Message);
            if (TrustedDevicesResultTextBox is not null)
            {
                TrustedDevicesResultTextBox.Text =
                    ex.Message + Environment.NewLine + Environment.NewLine
                    + IdsStorage.FormatStatusSummary() + Environment.NewLine + Environment.NewLine
                    + TrustedDevicesResultTextBox.Text;
            }

            RefreshMadridUi();
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "Madrid: enroll error";
            MessageBox.Show(this, ex.Message, "Enroll Madrid", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            if (MadridEnrollButton is not null)
                MadridEnrollButton.IsEnabled = true;
        }
    }

    private async void MadridLookupButton_Click(object sender, RoutedEventArgs e)
    {
        var handle = MadridLookupHandleTextBox?.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(handle))
        {
            MessageBox.Show(this, "Enter a handle (email or phone).", "IDS lookup",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MadridLookupButton is not null)
            MadridLookupButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "IDS lookup…";

        try
        {
            var client = EnsureMadridClient();
            var result = await Task.Run(async () =>
                    await client.LookupHandleAsync(handle, m => Dispatcher.BeginInvoke(() => AppendApsLog(m)))
                        .ConfigureAwait(false))
                .ConfigureAwait(true);

            AppendApsLog(result.Success
                ? $"Lookup OK {result.Handle}: {result.Identities.Count} device(s)"
                : $"Lookup failed {result.Handle}: {result.Error}");
            foreach (var id in result.Identities)
            {
                AppendApsLog(
                    $"  device={id.DeviceName ?? "?"} push={(id.PushTokenHex is { Length: > 8 } t ? t[..8] + "…" : "?")} session={(id.SessionToken is { Length: > 0 } ? "yes" : "no")}");
            }

            if (result.Success)
            {
                client.Store.GetOrCreate(result.Handle);
                if (MadridLookupHandleTextBox is not null)
                    MadridLookupHandleTextBox.Text = result.Handle;
                RefreshMadridUi();
                if (MadridConversationsListBox is not null)
                {
                    var match = client.Store.Conversations
                        .FirstOrDefault(c => string.Equals(
                            c.PeerHandle, result.Handle, StringComparison.OrdinalIgnoreCase));
                    if (match is not null)
                        MadridConversationsListBox.SelectedItem = match;
                }

                if (MadridMessagesExpander is not null)
                    MadridMessagesExpander.IsExpanded = true;
            }

            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = result.Success
                    ? $"IDS lookup OK ({result.Identities.Count})"
                    : "IDS lookup: no identities";
        }
        catch (Exception ex)
        {
            AppendApsLog("IDS lookup error: " + ex.Message);
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "IDS lookup: error";
            MessageBox.Show(this, ex.Message, "IDS lookup", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            if (MadridLookupButton is not null)
                MadridLookupButton.IsEnabled = true;
        }
    }

    private void MadridConversationsListBox_SelectionChanged(object sender, SelectionChangedEventArgs e) =>
        RefreshMadridThread();

    private async void MadridSendButton_Click(object sender, RoutedEventArgs e)
    {
        var text = MadridComposeTextBox?.Text?.Trim() ?? "";
        if (string.IsNullOrWhiteSpace(text))
            return;

        var peer = (MadridConversationsListBox?.SelectedItem as MadridConversation)?.PeerHandle
                   ?? MadridLookupHandleTextBox?.Text?.Trim()
                   ?? "";
        if (string.IsNullOrWhiteSpace(peer))
        {
            MessageBox.Show(this, "Select a conversation or enter a handle first.", "Send",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (MadridSendButton is not null)
            MadridSendButton.IsEnabled = false;
        try
        {
            var client = EnsureMadridClient();
            await Task.Run(async () =>
                    await client.SendTextAsync(peer, text, m => Dispatcher.BeginInvoke(() => AppendApsLog(m)))
                        .ConfigureAwait(false))
                .ConfigureAwait(true);
            if (MadridComposeTextBox is not null)
                MadridComposeTextBox.Text = "";
            RefreshMadridUi();
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "Madrid: message sent (local + APS attempt)";
        }
        catch (Exception ex)
        {
            AppendApsLog("Madrid send error: " + ex.Message);
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "Madrid send: error";
            MessageBox.Show(this, ex.Message, "Send", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            if (MadridSendButton is not null)
                MadridSendButton.IsEnabled = true;
        }
    }

    private void IdmsaOtpMethodRadio_Changed(object sender, RoutedEventArgs e)
    {
        if (IdmsaOtpSmsPhonePanel is null || IdmsaOtpSmsRadio is null)
            return;
        var showSms = IdmsaOtpSmsRadio.IsChecked == true && IdmsaOtpSmsRadio.IsEnabled;
        IdmsaOtpSmsPhonePanel.Visibility = showSms ? Visibility.Visible : Visibility.Collapsed;
    }

    private async void IdmsaOtpRequestSmsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_hsa2PartialSession is null)
        {
            MessageBox.Show(this,
                "No HSA2 session waiting for OTP.\nStart \"Register on 2FA list\" first.",
                "2FA list", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var phone = IdmsaOtpPhoneComboBox?.SelectedItem as TrustedPhoneNumber
                    ?? _hsa2PartialSession.TrustedPhoneNumbers.FirstOrDefault();
        if (phone is null || phone.Id <= 0)
        {
            MessageBox.Show(this,
                "No trusted phone number available for SMS.",
                "2FA list", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (IdmsaOtpRequestSmsButton is not null)
            IdmsaOtpRequestSmsButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = $"HSA2: requesting SMS to {phone.DisplayLabel}…";

        var log = new System.Text.StringBuilder();
        void Log(string m)
        {
            lock (log)
                log.AppendLine(m);
            Dispatcher.BeginInvoke(() => AppendApsLog("HSA2: " + m));
        }

        try
        {
            var useIphone = _authProfile?.UseFullIphoneAuth ?? true;
            var svc = new Hsa2TrustedDeviceService(
                Http, AnisetteProviderFactory.CreateAuth(Http), useIphone);
            var partial = _hsa2PartialSession;
            await Task.Run(async () =>
                    await svc.RequestSmsForPartialAsync(partial, phone.Id, Log)
                        .ConfigureAwait(false))
                .ConfigureAwait(true);

            if (IdmsaOtpSmsRadio is not null)
                IdmsaOtpSmsRadio.IsChecked = true;
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text =
                    $"HSA2: SMS sent to {phone.DisplayLabel} — enter code, then Submit OTP";
            LogAuth($"HSA2: SMS requested for {phone.DisplayLabel}");
        }
        catch (Exception ex)
        {
            AppendApsLog("HSA2 SMS error: " + ex.Message);
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "HSA2 SMS: error";
            MessageBox.Show(this, ex.Message, "2FA SMS", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
        finally
        {
            if (IdmsaOtpRequestSmsButton is not null)
                IdmsaOtpRequestSmsButton.IsEnabled = true;
        }
    }

    private async Task SubmitHsa2OtpAsync(string code)
    {
        if (_hsa2PartialSession is null)
            return;

        var appleId = Hsa2AppleIdTextBox?.Text?.Trim()
                      ?? _hsa2PartialSession.AppleId?.Trim()
                      ?? "";
        if (string.IsNullOrWhiteSpace(appleId))
        {
            MessageBox.Show(this,
                "Apple ID missing in the HSA2 fields on this tab.",
                "2FA list", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var useSms = IdmsaOtpSmsRadio?.IsChecked == true
                     || _hsa2PartialSession.TwoFactorMethod == TwoFactorMethod.Sms
                     || _hsa2PartialSession.SmsCodeRequested;
        var password = Hsa2PasswordBox?.Password?.Trim() ?? "";
        if (useSms && string.IsNullOrWhiteSpace(password))
        {
            MessageBox.Show(this,
                "Password required in the HSA2 fields to complete SMS 2FA.",
                "2FA list", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (IdmsaOtpSubmitButton is not null)
            IdmsaOtpSubmitButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = useSms
                ? "HSA2: verifying SMS OTP…"
                : "HSA2: verifying GSA OTP…";

        var log = new System.Text.StringBuilder();
        void Log(string m)
        {
            lock (log)
                log.AppendLine(m);
            Dispatcher.BeginInvoke(() => AppendApsLog("HSA2: " + m));
        }

        try
        {
            var useIphone = _authProfile?.UseFullIphoneAuth ?? true;
            var svc = new Hsa2TrustedDeviceService(
                Http, AnisetteProviderFactory.CreateAuth(Http), useIphone);
            var partial = _hsa2PartialSession;

            Hsa2CompleteResult done;
            if (useSms)
            {
                done = await Task.Run(async () =>
                        await svc.CompleteWithSmsAsync(appleId, password, code, partial, Log)
                            .ConfigureAwait(false))
                    .ConfigureAwait(true);
            }
            else
            {
                done = await Task.Run(async () =>
                        await svc.CompleteWithOtpAsync(appleId, code, partial, Log)
                            .ConfigureAwait(false))
                    .ConfigureAwait(true);
            }

            _session = done.Session;
            _hsa2PartialSession = null;
            if (IdmsaOtpPanel is not null)
                IdmsaOtpPanel.Visibility = Visibility.Collapsed;
            if (IdmsaOtpTitleText is not null)
                IdmsaOtpTitleText.Text = "HSA2 OTP — code from your trusted Apple device";

            if (TrustedDevicesResultTextBox is not null)
            {
                string logText;
                lock (log)
                    logText = log.ToString();
                TrustedDevicesResultTextBox.Text =
                    logText + Environment.NewLine + done.DeviceSummary + Environment.NewLine
                    + Environment.NewLine
                    + CreateTrustedDevicesService().FormatSessionTrustStatus(_session);
            }

            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "HSA2: OTP OK — check device count above";
            LogAuth("HSA2: 2FA list registration completed.");
        }
        catch (Exception ex)
        {
            AppendApsLog("HSA2 OTP error: " + ex.Message);
            if (TrustedDevicesResultTextBox is not null)
            {
                string logText;
                lock (log)
                    logText = log.ToString();
                TrustedDevicesResultTextBox.Text = logText + Environment.NewLine + ex.Message;
            }
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "HSA2 OTP: error";
            LogAuth("HSA2 OTP: " + ex.Message);
        }
        finally
        {
            if (IdmsaOtpSubmitButton is not null)
                IdmsaOtpSubmitButton.IsEnabled = true;
        }
    }

    private async void IdmsaOtpSubmitButton_Click(object sender, RoutedEventArgs e)
    {
        var code = IdmsaOtpCodeTextBox?.Text?.Trim() ?? "";
        if (code.Length < 4)
        {
            MessageBox.Show(this, "Enter the OTP code.", "Lista 2FA",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_hsa2PartialSession is not null)
        {
            await SubmitHsa2OtpAsync(code).ConfigureAwait(true);
            return;
        }

        MessageBox.Show(this,
            "No HSA2 session waiting for OTP.\n" +
            "Start \"Register for 2FA list\" and wait for the challenge before Submit OTP.",
            "Lista 2FA", MessageBoxButton.OK, MessageBoxImage.Information);
    }

    private static void SyncIdmsaTrustFromSession(ICloudSession session)
    {
        if (session.IdmsaMfa is not null
            && !string.IsNullOrWhiteSpace(session.IdmsaMfa.TrustToken))
        {
            session.IdmsaTrustToken = session.IdmsaMfa.TrustToken;
        }
    }

    private void PrefillImapUserFromSession()
    {
        if (ImapUserTextBox is null)
            return;
        if (!string.IsNullOrWhiteSpace(ImapUserTextBox.Text))
            return;
        var id = _session?.AppleId?.Trim();
        if (!string.IsNullOrWhiteSpace(id))
            ImapUserTextBox.Text = id;
    }

    private void ImapAppPasswordLink_RequestNavigate(
        object sender, System.Windows.Navigation.RequestNavigateEventArgs e)
    {
        try
        {
            Process.Start(new ProcessStartInfo(e.Uri.AbsoluteUri) { UseShellExecute = true });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, ex.Message, "Open link", MessageBoxButton.OK, MessageBoxImage.Warning);
        }

        e.Handled = true;
    }

    private sealed class ImapFolderRowVm
    {
        public string FullName { get; init; } = "";
        public string Label { get; init; } = "";
        public override string ToString() => Label;
    }

    private sealed class ImapMessageRowVm
    {
        public UniqueId Uid { get; init; }
        public string Subject { get; init; } = "";
        public string From { get; init; } = "";
        public string DateLabel { get; init; } = "";
        public string AttachLabel { get; init; } = "";
    }

    private async void ImapConnectButton_Click(object sender, RoutedEventArgs e)
    {
        var user = ImapUserTextBox?.Text?.Trim() ?? "";
        var pass = ImapAppPasswordBox?.Password ?? "";
        var host = ImapHostTextBox?.Text?.Trim() ?? ImapMailClient.DefaultHost;
        if (string.IsNullOrWhiteSpace(user) || string.IsNullOrWhiteSpace(pass))
        {
            MessageBox.Show(this,
                "Enter iCloud user and app-specific password.",
                "IMAP Mail", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SetImapBusy(true, "Connecting IMAP…");
        _imapCts?.Cancel();
        _imapCts = new CancellationTokenSource();
        var ct = _imapCts.Token;

        try
        {
            var client = new ImapMailClient();
            await client.ConnectAsync(host, ImapMailClient.DefaultPort, user, pass, ct)
                .ConfigureAwait(true);
            if (_imapMail is not null)
                await _imapMail.DisposeAsync().ConfigureAwait(true);
            _imapMail = client;

            if (ImapDisconnectButton is not null)
                ImapDisconnectButton.IsEnabled = true;
            if (ImapRefreshButton is not null)
                ImapRefreshButton.IsEnabled = true;
            SetImapExportEnabled(true);
            SetImapFilterControlsEnabled(true);

            await ReloadImapFoldersAsync(ct).ConfigureAwait(true);
            SetImapBusy(false, $"Connected to {host} as {user}");
            LogAuth($"IMAP: connected {host} user={user}");
        }
        catch (Exception ex)
        {
            await ClearImapUiAsync().ConfigureAwait(true);
            SetImapBusy(false, "Connection error");
            ShowImapPreviewStatus($"Error IMAP: {ex.Message}");
            MessageBox.Show(this, ex.Message, "IMAP Mail", MessageBoxButton.OK, MessageBoxImage.Warning);
            LogAuth($"IMAP: {ex.Message}");
        }
        finally
        {
            if (ImapConnectButton is not null)
                ImapConnectButton.IsEnabled = true;
        }
    }

    private async void ImapDisconnectButton_Click(object sender, RoutedEventArgs e)
    {
        _imapCts?.Cancel();
        await ClearImapUiAsync().ConfigureAwait(true);
        SetImapBusy(false, "Disconnected.");
    }

    private async void ImapRefreshFoldersButton_Click(object sender, RoutedEventArgs e)
    {
        if (_imapMail is not { IsConnected: true })
            return;
        SetImapBusy(true, "Refreshing folders…");
        try
        {
            _imapCts?.Cancel();
            _imapCts = new CancellationTokenSource();
            await ReloadImapFoldersAsync(_imapCts.Token).ConfigureAwait(true);
            SetImapBusy(false, "Folders updated.");
        }
        catch (Exception ex)
        {
            SetImapBusy(false, "Folder error");
            MessageBox.Show(this, ex.Message, "IMAP Mail", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async Task ReloadImapFoldersAsync(CancellationToken ct)
    {
        if (_imapMail is null)
            return;
        var folders = await _imapMail.ListFoldersAsync(ct).ConfigureAwait(true);
        var rows = folders.Select(f => new ImapFolderRowVm
        {
            FullName = f.FullName,
            Label = $"{f.DisplayName} ({f.TotalMessages})",
        }).ToList();
        if (ImapFoldersListBox is not null)
            ImapFoldersListBox.ItemsSource = rows;
        if (ImapMessagesGrid is not null)
            ImapMessagesGrid.ItemsSource = null;
        ShowImapPreviewStatus("Select a folder.");
        _imapSelectedFolder = null;

        var inbox = rows.FirstOrDefault(r =>
            r.FullName.Equals("INBOX", StringComparison.OrdinalIgnoreCase));
        if (inbox is not null && ImapFoldersListBox is not null)
            ImapFoldersListBox.SelectedItem = inbox;
    }

    private async void ImapFoldersListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ImapFoldersListBox?.SelectedItem is not ImapFolderRowVm folder)
            return;
        if (_imapMail is not { IsConnected: true })
            return;

        _imapSelectedFolder = folder.FullName;
        await ReloadImapMessagesAsync().ConfigureAwait(true);
    }

    private async void ImapFilterApplyButton_Click(object sender, RoutedEventArgs e)
    {
        _imapFilter = ReadImapFilterFromUi();
        if (_imapFilter is { IsEmpty: true })
            _imapFilter = null;
        UpdateImapMessagesHeader();
        await ReloadImapMessagesAsync().ConfigureAwait(true);
    }

    private async void ImapFilterClearButton_Click(object sender, RoutedEventArgs e)
    {
        _imapFilter = null;
        if (ImapFilterFromDate is not null)
            ImapFilterFromDate.SelectedDate = null;
        if (ImapFilterToDate is not null)
            ImapFilterToDate.SelectedDate = null;
        if (ImapFilterKeywordsTextBox is not null)
            ImapFilterKeywordsTextBox.Text = "";
        UpdateImapMessagesHeader();
        await ReloadImapMessagesAsync().ConfigureAwait(true);
    }

    private ImapMessageFilter ReadImapFilterFromUi()
    {
        DateTime? from = ImapFilterFromDate?.SelectedDate?.Date;
        DateTime? to = ImapFilterToDate?.SelectedDate?.Date;
        var keywords = ImapFilterKeywordsTextBox?.Text?.Trim();
        if (from is not null && to is not null && from > to)
            (from, to) = (to, from);
        return new ImapMessageFilter(from, to, string.IsNullOrWhiteSpace(keywords) ? null : keywords);
    }

    private void UpdateImapMessagesHeader()
    {
        if (ImapMessagesHeaderText is null)
            return;
        if (_imapFilter is { IsEmpty: false } f)
            ImapMessagesHeaderText.Text = $"Messages (filter: {f.Describe()})";
        else
            ImapMessagesHeaderText.Text = "Messages (last 100)";
    }

    private async Task ReloadImapMessagesAsync()
    {
        if (_imapMail is not { IsConnected: true })
            return;
        if (string.IsNullOrWhiteSpace(_imapSelectedFolder))
            return;

        var folder = _imapSelectedFolder;
        var filter = _imapFilter is { IsEmpty: false } ? _imapFilter : null;
        var busy = filter is null
            ? $"Loading {folder}…"
            : $"Searching {folder}…";
        SetImapBusy(true, busy);
        _imapCts?.Cancel();
        _imapCts = new CancellationTokenSource();
        var ct = _imapCts.Token;
        try
        {
            var max = filter is null ? 100 : 500;
            var msgs = await _imapMail.ListMessagesAsync(folder, max, filter, ct)
                .ConfigureAwait(true);
            var rows = msgs.Select(m => new ImapMessageRowVm
            {
                Uid = m.Uid,
                Subject = m.Subject,
                From = m.From,
                DateLabel = m.Date?.ToLocalTime().ToString("yyyy-MM-dd HH:mm") ?? "",
                AttachLabel = m.HasAttachments ? "●" : "",
            }).ToList();
            if (ImapMessagesGrid is not null)
                ImapMessagesGrid.ItemsSource = rows;
            ShowImapPreviewStatus(
                rows.Count == 0
                    ? (filter is null ? "(empty folder)" : "(no messages matching these filters)")
                    : "Select a message.");

            UpdateImapMessagesHeader();
            var status = filter is null
                ? $"{folder}: {rows.Count} messages"
                : $"{folder}: {rows.Count} results ({filter.Describe()})";
            SetImapBusy(false, status);
        }
        catch (OperationCanceledException)
        {
            SetImapBusy(false, "Canceled.");
        }
        catch (Exception ex)
        {
            SetImapBusy(false, "List error");
            ShowImapPreviewStatus(ex.Message);
        }
    }

    private async void ImapMessagesGrid_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ImapMessagesGrid?.SelectedItem is not ImapMessageRowVm row)
            return;
        if (_imapMail is not { IsConnected: true })
            return;
        if (string.IsNullOrWhiteSpace(_imapSelectedFolder))
            return;

        SetImapBusy(true, "Downloading message…");
        _imapCts?.Cancel();
        _imapCts = new CancellationTokenSource();
        try
        {
            var body = await _imapMail.FetchMessageAsync(_imapSelectedFolder, row.Uid, _imapCts.Token)
                .ConfigureAwait(true);
            ShowImapHtmlDocument(body.HtmlDocument);
            SetImapBusy(false,
                body.IsHtml ? "HTML message (read-only)." : "Plain-text message (read-only).");
        }
        catch (OperationCanceledException)
        {
            SetImapBusy(false, "Canceled.");
        }
        catch (Exception ex)
        {
            SetImapBusy(false, "Message error");
            ShowImapPreviewStatus(ex.Message);
        }
    }

    private void ShowImapPreviewStatus(string message) =>
        ShowImapHtmlDocument(ImapMailClient.BuildStatusHtmlDocument(message));

    private void ShowImapHtmlDocument(string html)
    {
        if (ImapMessageBrowser is null)
            return;
        try
        {
            ImapMessageBrowser.NavigateToString(html);
        }
        catch (Exception ex)
        {
            // IE engine a volte rifiuta documenti molto grandi: fallback minimale.
            try
            {
                ImapMessageBrowser.NavigateToString(
                    ImapMailClient.BuildStatusHtmlDocument("Preview unavailable: " + ex.Message));
            }
            catch
            {
                // ignore
            }
        }
    }

    /// <summary>
    /// Sola lettura: blocca navigazione verso http(s)/mailto (niente pixel/redirect).
    /// </summary>
    private void ImapMessageBrowser_Navigating(
        object sender, System.Windows.Navigation.NavigatingCancelEventArgs e)
    {
        if (e.Uri is null)
            return;
        var scheme = e.Uri.Scheme;
        if (scheme.Equals("http", StringComparison.OrdinalIgnoreCase)
            || scheme.Equals("https", StringComparison.OrdinalIgnoreCase)
            || scheme.Equals("mailto", StringComparison.OrdinalIgnoreCase)
            || scheme.Equals("file", StringComparison.OrdinalIgnoreCase))
        {
            e.Cancel = true;
        }
    }

    private void SetImapBusy(bool busy, string status)
    {
        if (ImapMailStatusText is not null)
            ImapMailStatusText.Text = status;
        if (ImapConnectButton is not null && busy)
            ImapConnectButton.IsEnabled = false;
        if (ImapConnectButton is not null && !busy && _imapMail is not { IsConnected: true })
            ImapConnectButton.IsEnabled = true;
        if (ImapConnectButton is not null && !busy && _imapMail is { IsConnected: true })
            ImapConnectButton.IsEnabled = true;
        if (busy)
        {
            SetImapExportEnabled(false);
            SetImapFilterControlsEnabled(false);
        }
        else if (_imapMail is { IsConnected: true })
        {
            SetImapExportEnabled(true);
            SetImapFilterControlsEnabled(true);
        }
    }

    private void SetImapExportEnabled(bool enabled)
    {
        if (ImapExportSelectedButton is not null)
            ImapExportSelectedButton.IsEnabled = enabled;
        if (ImapExportFolderButton is not null)
            ImapExportFolderButton.IsEnabled = enabled;
        if (ImapExportAllButton is not null)
            ImapExportAllButton.IsEnabled = enabled;
    }

    private void SetImapFilterControlsEnabled(bool enabled)
    {
        if (ImapFilterFromDate is not null)
            ImapFilterFromDate.IsEnabled = enabled;
        if (ImapFilterToDate is not null)
            ImapFilterToDate.IsEnabled = enabled;
        if (ImapFilterKeywordsTextBox is not null)
            ImapFilterKeywordsTextBox.IsEnabled = enabled;
        if (ImapFilterApplyButton is not null)
            ImapFilterApplyButton.IsEnabled = enabled;
        if (ImapFilterClearButton is not null)
            ImapFilterClearButton.IsEnabled = enabled;
    }

    private string? PickImapExportParentDirectory()
    {
        var dlg = new OpenFolderDialog
        {
            Title = "Destination folder for mail export (.eml)",
        };
        var hint = _case?.MailRoot ?? OutputFolderTextBox?.Text?.Trim();
        if (!string.IsNullOrWhiteSpace(hint) && Directory.Exists(hint))
            dlg.InitialDirectory = hint;
        else if (_case is not null)
            dlg.InitialDirectory = _case.MailRoot;
        else
        {
            dlg.InitialDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "iCloudBackups");
        }

        if (dlg.ShowDialog(this) != true)
            return null;
        var folder = dlg.FolderName;
        if (!ConfirmOutsideCase(folder))
            return _case?.MailRoot;
        return folder;
    }

    private async void ImapExportSelectedButton_Click(object sender, RoutedEventArgs e)
    {
        if (_imapMail is not { IsConnected: true })
            return;
        if (string.IsNullOrWhiteSpace(_imapSelectedFolder))
        {
            MessageBox.Show(this, "Select an IMAP folder first.", "IMAP Mail",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (ImapMessagesGrid?.SelectedItem is not ImapMessageRowVm row)
        {
            MessageBox.Show(this, "Select a message to export.", "IMAP Mail",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var parent = PickImapExportParentDirectory();
        if (parent is null)
            return;

        await RunImapExportAsync(
            "Exporting message…",
            async (client, progress, ct) =>
                await ImapMailExportService.ExportAsync(
                    client, parent, _imapSelectedFolder!, [row.Uid], progress, ct)
                    .ConfigureAwait(true)).ConfigureAwait(true);
    }

    private async void ImapExportFolderButton_Click(object sender, RoutedEventArgs e)
    {
        if (_imapMail is not { IsConnected: true })
            return;
        if (string.IsNullOrWhiteSpace(_imapSelectedFolder))
        {
            MessageBox.Show(this, "Select an IMAP folder first.", "IMAP Mail",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var parent = PickImapExportParentDirectory();
        if (parent is null)
            return;

        var folder = _imapSelectedFolder!;
        var filter = _imapFilter is { IsEmpty: false } ? _imapFilter : null;
        var label = filter is null
            ? $"Exporting folder {folder}…"
            : $"Exporting folder {folder} (filter)…";
        await RunImapExportAsync(
            label,
            async (client, progress, ct) =>
            {
                progress.Report($"Listing UIDs {folder}…");
                var uids = await client.ListAllUidsAsync(folder, filter, ct).ConfigureAwait(true);
                if (uids.Count == 0)
                {
                    throw new InvalidOperationException(
                        filter is null
                            ? $"Folder «{folder}» has no messages."
                            : $"No messages in «{folder}» matching active filters.");
                }

                return await ImapMailExportService.ExportAsync(
                        client, parent, folder, uids, progress, ct)
                    .ConfigureAwait(true);
            }).ConfigureAwait(true);
    }

    private async void ImapExportAllButton_Click(object sender, RoutedEventArgs e)
    {
        if (_imapMail is not { IsConnected: true })
            return;

        var filter = _imapFilter is { IsEmpty: false } ? _imapFilter : null;
        var confirmMsg = filter is null
            ? "Export all messages from all IMAP folders?\n" +
              "This can take a long time on large mailboxes."
            : "Export from all folders only messages matching the active filters?\n" +
              $"Filtro: {filter.Describe()}";
        var confirm = MessageBox.Show(this, confirmMsg, "IMAP Mail",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes)
            return;

        var parent = PickImapExportParentDirectory();
        if (parent is null)
            return;

        await RunImapExportAsync(
            filter is null ? "Exporting all folders…" : "Exporting all folders (filter)…",
            async (client, progress, ct) =>
                await ImapMailExportService.ExportAllFoldersAsync(
                        client, parent, filter, progress, ct)
                    .ConfigureAwait(true)).ConfigureAwait(true);
    }

    private async Task RunImapExportAsync(
        string busyLabel,
        Func<ImapMailClient, IProgress<string>, CancellationToken, Task<ImapMailExportService.ExportResult>> work)
    {
        if (_imapMail is not { IsConnected: true } client)
            return;

        SetImapBusy(true, busyLabel);
        _imapCts?.Cancel();
        _imapCts = new CancellationTokenSource();
        var ct = _imapCts.Token;
        var progress = new Progress<string>(msg =>
        {
            if (ImapMailStatusText is not null)
                ImapMailStatusText.Text = msg;
        });

        try
        {
            var result = await work(client, progress, ct).ConfigureAwait(true);
            SetImapBusy(false,
                $"Export: {result.Written} .eml" +
                (result.Failed > 0 ? $", fail={result.Failed}" : ""));
            LogAuth($"IMAP export: ok={result.Written} fail={result.Failed} → {result.RootDirectory}");
            MessageBox.Show(this,
                $"Exported {result.Written} messages (.eml)" +
                (result.Failed > 0 ? $"\nFailed: {result.Failed}" : "") +
                $"\n\n{result.RootDirectory}",
                "IMAP Mail",
                MessageBoxButton.OK,
                result.Failed > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            SetImapBusy(false, "Export canceled.");
        }
        catch (Exception ex)
        {
            SetImapBusy(false, "Error export");
            MessageBox.Show(this, ex.Message, "IMAP Mail", MessageBoxButton.OK, MessageBoxImage.Warning);
            LogAuth($"IMAP export: {ex.Message}");
        }
    }

    private async Task ClearImapUiAsync()
    {
        if (_imapMail is not null)
        {
            await _imapMail.DisposeAsync().ConfigureAwait(true);
            _imapMail = null;
        }

        _imapSelectedFolder = null;
        _imapFilter = null;
        if (ImapFoldersListBox is not null)
            ImapFoldersListBox.ItemsSource = null;
        if (ImapMessagesGrid is not null)
            ImapMessagesGrid.ItemsSource = null;
        ShowImapPreviewStatus("Select a message to read the body (read-only).");
        if (ImapFilterFromDate is not null)
            ImapFilterFromDate.SelectedDate = null;
        if (ImapFilterToDate is not null)
            ImapFilterToDate.SelectedDate = null;
        if (ImapFilterKeywordsTextBox is not null)
            ImapFilterKeywordsTextBox.Text = "";
        UpdateImapMessagesHeader();
        if (ImapDisconnectButton is not null)
            ImapDisconnectButton.IsEnabled = false;
        if (ImapRefreshButton is not null)
            ImapRefreshButton.IsEnabled = false;
        SetImapExportEnabled(false);
        SetImapFilterControlsEnabled(false);
        if (ImapConnectButton is not null)
            ImapConnectButton.IsEnabled = true;
        if (ImapAppPasswordBox is not null)
            ImapAppPasswordBox.Password = "";
    }

    private async void FindMyPeopleQueryButton_Click(object sender, RoutedEventArgs e)
    {
        await RunExploratoryQueryAsync(
            "FindMyPeople",
            FindMyPeopleQueryButton,
            async session =>
            {
                await TryRefreshAnisetteForExploratoryAsync(session).ConfigureAwait(false);
                return await new FindMyFriendsClient(Http)
                    .FetchFriendsTextAsync(session)
                    .ConfigureAwait(false);
            });
    }

    private async void FindMyItemsQueryButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "Find My Items",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var hasEscrow = _session.PcsEscrowedKeySet is { Length: > 32 };
        var hasManatee = _session.PcsManateeCompactKeys is { Count: > 0 };
        if (!hasEscrow && !hasManatee)
        {
            MessageBox.Show(this,
                "PCS Manatee/Escrow required: \"Unlock EscrowedKeys\" and/or \"CKKS OpenVault\".\n" +
                "Then retry Find My Items.",
                "Find My Items", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        HideContactsExplorer();
        _contactsSnapshot = null;
        ClearFindMyDevicesGrid();

        if (FindMyItemsQueryButton is not null)
            FindMyItemsQueryButton.IsEnabled = false;
        if (ExploratoryServicesStatusText is not null)
            ExploratoryServicesStatusText.Text = "FindMyItems: request in progress…";
        if (ExploratoryServicesResultTextBox is not null)
            ExploratoryServicesResultTextBox.Text = "Loading FindMyItems…";

        var progress = new Progress<string>(msg =>
        {
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = "FindMyItems: " + TrimUiStatus(msg, 120);
        });

        try
        {
            var session = _session;
            var result = await Task.Run(async () =>
            {
                await TryRefreshAnisetteForExploratoryAsync(session).ConfigureAwait(false);
                return await new SearchPartyBeaconStoreService(Http, Orchestrator)
                    .FetchBeaconStoreAsync(session, progress)
                    .ConfigureAwait(false);
            }).ConfigureAwait(true);

            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = result.LogText;
            BindFindMyDevicesGrid(result.Devices);
            if (ExploratoryServicesStatusText is not null)
            {
                ExploratoryServicesStatusText.Text =
                    $"FindMyItems: OK — {result.Devices.Count} devices " +
                    $"({result.LogText.Length:N0} log chars)";
            }

            LogAuth($"FindMyItems: OK, devices={result.Devices.Count}, out={result.OutputDirectory}");
        }
        catch (Exception ex)
        {
            ClearFindMyDevicesGrid();
            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = $"Error FindMyItems: {ex.Message}";
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = "FindMyItems: error";
            LogAuth($"FindMyItems: {ex.Message}");
        }
        finally
        {
            if (FindMyItemsQueryButton is not null)
                FindMyItemsQueryButton.IsEnabled = true;
        }
    }

    /// <summary>Riga UI per DataGrid Find My Items (BeaconStore).</summary>
    private sealed class FindMyDeviceRowVm
    {
        public string DisplayName { get; init; } = "";
        public string Kind { get; init; } = "";
        public string Model { get; init; } = "";
        public string Serial { get; init; } = "";
        public string PairingDate { get; init; } = "";
        public string SystemVersion { get; init; } = "";
        public string BatteryLevel { get; init; } = "";
        public string KeysLabel { get; init; } = "";
        public string RecordId { get; init; } = "";

        public static FindMyDeviceRowVm From(BeaconDeviceInventory.DeviceRow d)
        {
            var name = string.IsNullOrWhiteSpace(d.Emoji)
                ? d.Name
                : $"{d.Emoji} {d.Name}";
            var keys = (d.HasPrivateKey ? "P" : "")
                       + (d.HasSharedSecret ? "S" : "")
                       + (d.HasPublicKey ? "U" : "");
            return new FindMyDeviceRowVm
            {
                DisplayName = name,
                Kind = d.Kind,
                Model = d.Model,
                Serial = d.Serial,
                PairingDate = d.PairingDate,
                SystemVersion = d.SystemVersion,
                BatteryLevel = d.BatteryLevel,
                KeysLabel = string.IsNullOrEmpty(keys) ? "—" : keys,
                RecordId = d.RecordId,
            };
        }
    }

    private void BindFindMyDevicesGrid(IReadOnlyList<BeaconDeviceInventory.DeviceRow> devices)
    {
        if (FindMyDevicesGrid is null || FindMyDevicesPanel is null)
            return;

        var rows = devices.Select(FindMyDeviceRowVm.From).ToList();
        FindMyDevicesGrid.ItemsSource = rows;
        FindMyDevicesPanel.Visibility = rows.Count > 0 ? Visibility.Visible : Visibility.Collapsed;
        if (FindMyDevicesCountText is not null)
        {
            FindMyDevicesCountText.Text = rows.Count == 0
                ? ""
                : $"{rows.Count} record · P=privateKey S=sharedSecret U=publicKey";
        }
    }

    private void ClearFindMyDevicesGrid()
    {
        if (FindMyDevicesGrid is not null)
            FindMyDevicesGrid.ItemsSource = null;
        if (FindMyDevicesPanel is not null)
            FindMyDevicesPanel.Visibility = Visibility.Collapsed;
        if (FindMyDevicesCountText is not null)
            FindMyDevicesCountText.Text = "";
    }

    private static string TrimUiStatus(string s, int max) =>
        string.IsNullOrEmpty(s) ? s : (s.Length <= max ? s : s[..max] + "…");

    private async void CloudKitContainerProbeButton_Click(object sender, RoutedEventArgs e)
    {
        var extrasRaw = CloudKitContainerProbeExtraTextBox?.Text;
        await RunExploratoryQueryAsync(
            "CloudKitContainers",
            CloudKitContainerProbeButton,
            async session =>
            {
                await TryRefreshAnisetteForExploratoryAsync(session).ConfigureAwait(false);
                var candidates = BuildCloudKitProbeCandidates(extrasRaw);
                var progress = new Progress<string>(msg =>
                    Dispatcher.BeginInvoke(() =>
                    {
                        if (ExploratoryServicesStatusText is not null)
                            ExploratoryServicesStatusText.Text =
                                "CloudKitContainers: " + TrimUiStatus(msg, 120);
                    }));
                return await new CloudKitContainerProbeService(Orchestrator, Http)
                    .ProbeAsync(session, candidates, progress)
                    .ConfigureAwait(false);
            });
    }

    private static List<CloudKitContainerProbeService.Candidate> BuildCloudKitProbeCandidates(
        string? extrasRaw)
    {
        var list = new List<CloudKitContainerProbeService.Candidate>(
            CloudKitContainerProbeService.DefaultCandidates);
        if (string.IsNullOrWhiteSpace(extrasRaw))
            return list;

        foreach (var line in extrasRaw.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
        {
            var id = line.Trim();
            if (id.Length == 0 || id.StartsWith('#'))
                continue;
            list.Add(new CloudKitContainerProbeService.Candidate(id, "custom", InCatalog: false));
        }

        return list;
    }

    private async void SharedStreamsQueryButton_Click(object sender, RoutedEventArgs e)
    {
        await RunExploratoryQueryAsync(
            "SharedStreams",
            SharedStreamsQueryButton,
            async session =>
            {
                await TryRefreshAnisetteForExploratoryAsync(session).ConfigureAwait(false);
                return await new SharedStreamsClient(Http)
                    .FetchAlbumListTextAsync(session)
                    .ConfigureAwait(false);
            });
    }

    private async void KeyValueQueryButton_Click(object sender, RoutedEventArgs e)
    {
        await RunExploratoryQueryAsync(
            "KeyValue",
            KeyValueQueryButton,
            async session =>
            {
                await TryRefreshAnisetteForExploratoryAsync(session).ConfigureAwait(false);
                return await new KeyValueSyncClient(Http)
                    .FetchDefaultAppsTextAsync(session)
                    .ConfigureAwait(false);
            });
    }

    private async Task TryRefreshAnisetteForExploratoryAsync(ICloudSession session)
    {
        if (_orchestrator is null)
            return;
        try
        {
            await _orchestrator.RefreshAnisetteOnlyAsync(session, log: null).ConfigureAwait(false);
        }
        catch
        {
            // best-effort: le query usano comunque Anisette in sessione
        }
    }

    private AddressbookSnapshot? _contactsSnapshot;

    private async void ContactsQueryButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "iCloud services",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (ContactsQueryButton is not null)
            ContactsQueryButton.IsEnabled = false;
        if (ExploratoryServicesStatusText is not null)
            ExploratoryServicesStatusText.Text = "Contacts: request in progress…";
        if (ExploratoryServicesResultTextBox is not null)
            ExploratoryServicesResultTextBox.Text = "Loading Contacts…";
        ClearFindMyDevicesGrid();
        ClearContactsExplorer(keepPanelVisible: true);

        try
        {
            var session = _session;
            var snap = await Task.Run(async () =>
                await new ContactsCardDavClient(Http)
                    .FetchAddressbookAsync(session)
                    .ConfigureAwait(false)).ConfigureAwait(true);
            _contactsSnapshot = snap;
            var text = ContactsCardDavClient.FormatSnapshot(snap);
            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = text;
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text =
                    $"Contacts: OK — {snap.Contacts.Count} contact(s)";
            PopulateContactsExplorer(snap);
            LogAuth($"Contacts: query OK ({snap.Contacts.Count}).");
        }
        catch (Exception ex)
        {
            _contactsSnapshot = null;
            HideContactsExplorer();
            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = $"Error Contacts: {ex.Message}";
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = "Contacts: error";
            LogAuth($"Contacts: {ex.Message}");
        }
        finally
        {
            if (ContactsQueryButton is not null)
                ContactsQueryButton.IsEnabled = true;
        }
    }

    private void PopulateContactsExplorer(AddressbookSnapshot snap)
    {
        if (ContactsExplorerPanel is null || ContactsListBox is null)
            return;

        ContactsExplorerPanel.Visibility = Visibility.Visible;
        if (ContactsExplorerColumn is not null)
            ContactsExplorerColumn.Width = new GridLength(300);
        ContactsListBox.ItemsSource = snap.Contacts;
        ContactsListBox.SelectedIndex = snap.Contacts.Count > 0 ? 0 : -1;
        UpdateContactsDetailButtons();
    }

    private void HideContactsExplorer()
    {
        ClearContactsExplorer(keepPanelVisible: false);
        if (ContactsExplorerPanel is not null)
            ContactsExplorerPanel.Visibility = Visibility.Collapsed;
        if (ContactsExplorerColumn is not null)
            ContactsExplorerColumn.Width = new GridLength(0);
    }

    private void ClearContactsExplorer(bool keepPanelVisible)
    {
        if (ContactsListBox is not null && !keepPanelVisible)
            ContactsListBox.ItemsSource = null;
        if (ContactsVcardTextBox is not null)
            ContactsVcardTextBox.Text = "vCard for selected contact…";
        if (ContactsPhotoImage is not null)
            ContactsPhotoImage.Source = null;
        if (ContactsLoadVcardButton is not null)
            ContactsLoadVcardButton.IsEnabled = false;
        if (ContactsLoadPhotoButton is not null)
            ContactsLoadPhotoButton.IsEnabled = false;
    }

    private ContactEntry? SelectedContact() =>
        ContactsListBox?.SelectedItem as ContactEntry;

    private void ContactsListBox_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ContactsVcardTextBox is not null)
            ContactsVcardTextBox.Text = "vCard for selected contact…";
        if (ContactsPhotoImage is not null)
            ContactsPhotoImage.Source = null;
        UpdateContactsDetailButtons();
    }

    private void UpdateContactsDetailButtons()
    {
        var c = SelectedContact();
        if (ContactsLoadVcardButton is not null)
            ContactsLoadVcardButton.IsEnabled = c is not null && !string.IsNullOrWhiteSpace(c.Url);
        if (ContactsLoadPhotoButton is not null)
            ContactsLoadPhotoButton.IsEnabled =
                c is not null && !string.IsNullOrWhiteSpace(c.PhotoUrl);
    }

    private async void ContactsLoadVcardButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
            return;
        var contact = SelectedContact();
        if (contact is null || string.IsNullOrWhiteSpace(contact.Url))
            return;

        if (ContactsLoadVcardButton is not null)
            ContactsLoadVcardButton.IsEnabled = false;
        if (ExploratoryServicesStatusText is not null)
            ExploratoryServicesStatusText.Text = $"Contacts: GET vCard «{contact}»…";

        try
        {
            var session = _session;
            var url = contact.Url;
            var vcard = await Task.Run(async () =>
                await new ContactsCardDavClient(Http)
                    .FetchVcardAsync(session, url)
                    .ConfigureAwait(false)).ConfigureAwait(true);
            if (ContactsVcardTextBox is not null)
                ContactsVcardTextBox.Text = vcard;
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text =
                    $"Contacts: vCard OK ({vcard.Length:N0} characters)";
            LogAuth($"Contacts: vCard OK {contact.Href}");
        }
        catch (Exception ex)
        {
            if (ContactsVcardTextBox is not null)
                ContactsVcardTextBox.Text = $"vCard error: {ex.Message}";
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = "Contacts: error vCard";
            LogAuth($"Contacts vCard: {ex.Message}");
        }
        finally
        {
            UpdateContactsDetailButtons();
        }
    }

    private async void ContactsLoadPhotoButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
            return;
        var contact = SelectedContact();
        if (contact is null || string.IsNullOrWhiteSpace(contact.PhotoUrl))
            return;

        if (ContactsLoadPhotoButton is not null)
            ContactsLoadPhotoButton.IsEnabled = false;
        if (ExploratoryServicesStatusText is not null)
            ExploratoryServicesStatusText.Text = $"Contacts: GET photo «{contact}»…";

        try
        {
            var session = _session;
            var photoUrl = contact.PhotoUrl!;
            var (bytes, contentType) = await Task.Run(async () =>
                await new ContactsCardDavClient(Http)
                    .FetchPhotoAsync(session, photoUrl)
                    .ConfigureAwait(false)).ConfigureAwait(true);

            var bitmap = new BitmapImage();
            using (var ms = new MemoryStream(bytes))
            {
                bitmap.BeginInit();
                bitmap.CacheOption = BitmapCacheOption.OnLoad;
                bitmap.StreamSource = ms;
                bitmap.EndInit();
            }
            bitmap.Freeze();

            if (ContactsPhotoImage is not null)
                ContactsPhotoImage.Source = bitmap;
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text =
                    $"Contacts: photo OK ({bytes.Length:N0} bytes, {contentType})";
            LogAuth($"Contacts: foto OK {bytes.Length} byte");
        }
        catch (Exception ex)
        {
            if (ContactsPhotoImage is not null)
                ContactsPhotoImage.Source = null;
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = $"Contacts: error foto — {ex.Message}";
            LogAuth($"Contacts foto: {ex.Message}");
        }
        finally
        {
            UpdateContactsDetailButtons();
        }
    }

    private async Task RunExploratoryQueryAsync(
        string serviceName,
        Button? button,
        Func<ICloudSession, Task<string>> query)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in to iCloud first.", "iCloud services",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        // Altre query nascondono i pannelli dedicati (Contacts / Find My devices).
        HideContactsExplorer();
        _contactsSnapshot = null;
        ClearFindMyDevicesGrid();

        if (button is not null)
            button.IsEnabled = false;
        if (ExploratoryServicesStatusText is not null)
            ExploratoryServicesStatusText.Text = $"{serviceName}: request in progress…";
        if (ExploratoryServicesResultTextBox is not null)
            ExploratoryServicesResultTextBox.Text = $"Loading {serviceName}…";

        try
        {
            var session = _session;
            var text = await Task.Run(async () =>
                await query(session).ConfigureAwait(false)).ConfigureAwait(true);
            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = text;
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = $"{serviceName}: OK ({text.Length:N0} characters)";
            LogAuth($"{serviceName}: query OK.");
        }
        catch (Exception ex)
        {
            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = $"Error {serviceName}: {ex.Message}";
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = $"{serviceName}: error";
            LogAuth($"{serviceName}: {ex.Message}");
        }
        finally
        {
            if (button is not null)
                button.IsEnabled = true;
        }
    }

    private int _cloudQuotaFetchGen;

    private async Task RefreshCloudQuotaPanelAsync()
    {
        if (CloudQuotaTextBox is null)
            return;

        if (_session is null)
        {
            CloudQuotaTextBox.Text = "Sign in to load iCloud storage.";
            return;
        }

        var gen = Interlocked.Increment(ref _cloudQuotaFetchGen);
        CloudQuotaTextBox.Text = "Loading iCloud storage…";
        try
        {
            // Anisette aggiornata dalla sessione corrente (token dinamici già in _session).
            var session = _session;
            var text = await Task.Run(async () =>
            {
                var svc = new ICloudQuotaService(Http);
                return await svc.FetchDetailsTextAsync(session!).ConfigureAwait(false);
            }).ConfigureAwait(true);

            if (gen != Volatile.Read(ref _cloudQuotaFetchGen))
                return;
            CloudQuotaTextBox.Text = text;
            LogAuth("iCloud quota: storage details updated.");
        }
        catch (Exception ex)
        {
            if (gen != Volatile.Read(ref _cloudQuotaFetchGen))
                return;
            CloudQuotaTextBox.Text = $"Error Quota: {ex.Message}";
            LogAuth($"Quota iCloud: {ex.Message}");
        }
    }

    private void CopyTextBoxToClipboard(TextBox? box, string label)
    {
        if (box is null)
            return;
        var text = box.Text ?? "";
        if (string.IsNullOrWhiteSpace(text))
            return;
        try
        {
            Clipboard.SetText(text);
            LogAuth($"{label}: copied to clipboard ({text.Length} characters).");
        }
        catch (Exception ex)
        {
            LogAuth($"{label}: copy failed — {ex.Message}");
        }
    }

    private static string NullDash(string? value) =>
        string.IsNullOrWhiteSpace(value) ? "—" : value.Trim();

    /// <summary>Token/secret completi in UI (label + len + valore intero).</summary>
    private static void AppendFullSecret(System.Text.StringBuilder sb, string label, string? value)
    {
        if (string.IsNullOrEmpty(value))
        {
            sb.AppendLine($"{label}: —");
            return;
        }

        sb.AppendLine($"{label} (len={value.Length}):");
        sb.AppendLine(value);
    }

    private void RefreshSyncDataServiceCheckboxes()
    {
        SyncDataServicesPanel.Children.Clear();
        if (_session is null)
        {
            SyncDataServicesHintText.Text =
                "Sync Data services — sign in to load available dataclasses.";
            SyncDataPhotosOptionsPanel.Visibility = Visibility.Collapsed;
            return;
        }

        // Elenco: recuperabili vs «(presto)».
        SyncDataServicesHintText.Text =
            "Enabled: Photos, Account Info, Voice Memos, Calls, Messages; others coming soon. " +
            "Calls: Phone & FaceTime in iCloud + Escrow/Octagon. " +
            "Messages: CloudKit sync + MMCS attempt on content.icloud.com (like Voice Memos) when ckAsset present.";

        foreach (var cat in SyncDataCategoryCatalog.All)
        {
            var canRecover = SyncDataCategoryCatalog.IsRecoverable(cat);
            var cb = new CheckBox
            {
                Content = cat.DisplayName + (canRecover ? "" : " (presto)"),
                Tag = cat.Id,
                IsChecked = cat.DefaultChecked && canRecover,
                IsEnabled = canRecover,
                Margin = new Thickness(0, 0, 16, 8),
                VerticalAlignment = VerticalAlignment.Center,
                ToolTip = canRecover
                    ? (cat.IncludeAccountInfo
                        ? "GSA Account Info (profilo, payment, security, devices)"
                        : (cat.RequiredDataclass ?? "CloudKit (CKDatabaseService)"))
                    : "Recovery not yet implemented (coming soon)"
            };
            if (string.Equals(cat.Id, SyncDataCategoryCatalog.PhotosId, StringComparison.OrdinalIgnoreCase))
            {
                cb.Checked += (_, _) => UpdateSyncDataPhotosOptionsVisibility();
                cb.Unchecked += (_, _) => UpdateSyncDataPhotosOptionsVisibility();
            }

            SyncDataServicesPanel.Children.Add(cb);
        }

        UpdateSyncDataPhotosOptionsVisibility();
    }

    private void UpdateSyncDataPhotosOptionsVisibility()
    {
        var photosOn = false;
        foreach (var child in SyncDataServicesPanel.Children)
        {
            if (child is CheckBox { IsChecked: true, Tag: string id }
                && string.Equals(id, SyncDataCategoryCatalog.PhotosId, StringComparison.OrdinalIgnoreCase))
            {
                photosOn = true;
                break;
            }
        }

        SyncDataPhotosOptionsPanel.Visibility = photosOn ? Visibility.Visible : Visibility.Collapsed;
    }

    private bool IsPhotosBuildRecordMetadataEnabled() =>
        SyncDataPhotosOptionsPanel.Visibility == Visibility.Visible
        && SyncDataBuildRecordMetadataCheckBox.IsChecked == true;

    private IReadOnlyList<string> GetSelectedSyncDataCategoryIds()
    {
        var ids = new List<string>();
        foreach (var child in SyncDataServicesPanel.Children)
        {
            if (child is CheckBox { IsChecked: true, Tag: string id })
                ids.Add(id);
        }

        return ids;
    }



    private async void LoginButton_Click(object sender, RoutedEventArgs e)

    {

        try

        {

            LoginButton.IsEnabled = false;

            var recoveringMidDownload = _midDownloadAuthTcs is not null;

            // Nuovo login: scarta sessione 2FA/SMS parziale precedente.
            // Mid-download: conserva orchestrator/callback e la sessione live in attesa.
            if (!recoveringMidDownload)
            {
                _session = null;
                _orchestrator = null;
                TwoFactorPanel.Visibility = Visibility.Collapsed;
                ApplyUiWizardStage(UiWizardStage.LoginOnly);
            }
            else
            {
                TwoFactorPanel.Visibility = Visibility.Collapsed;
            }

            var appleId = AppleIdTextBox.Text.Trim();

            var password = PasswordBox.Password;

            if (string.IsNullOrWhiteSpace(appleId) || string.IsNullOrWhiteSpace(password))

            {

                MessageBox.Show(this, "Enter Apple ID and password.", "Sign In", MessageBoxButton.OK, MessageBoxImage.Warning);

                return;

            }



            await EnsureAuthProfileAsync().ConfigureAwait(true);

            if (!recoveringMidDownload)
            {
                _orchestrator = new ICloudBackupOrchestrator(
                    Http,
                    AnisetteProviderFactory.CreateAuth(Http),
                    _authProfile!.UseFullIphoneAuth);
            }

            WireOrchestratorCallbacks(Orchestrator);

            var progress = new Progress<string>(msg => Dispatcher.Invoke(() => LogAuth(msg)));



            try

            {

                var authenticated = await Orchestrator.CompleteSignInAsync(
                    appleId, password, null, null, progress);

                if (recoveringMidDownload)
                {
                    await FinishMidDownloadAuthAsync(authenticated, progress).ConfigureAwait(true);
                    return;
                }

                _session = authenticated;

                UpdateSessionUi(true);

                TwoFactorPanel.Visibility = Visibility.Collapsed;

                SaveSessionSnapshot("login_ok");
                ApplyUiWizardStage(UiWizardStage.AfterLogin);

            }

            catch (CloudKitBootstrapException ex)

            {

                if (recoveringMidDownload)
                {
                    await FinishMidDownloadAuthAsync(ex.Session, progress).ConfigureAwait(true);
                    return;
                }

                _session = ex.Session;

                UpdateSessionUi(true);

                TwoFactorPanel.Visibility = Visibility.Collapsed;

                SaveSessionSnapshot("login_ok_bootstrap_failed", ex.Message);

                LogAuth($"Login OK — bootstrap CloudKit: {ex.Message}");
                ApplyUiWizardStage(UiWizardStage.AfterLogin);

            }

            catch (TwoFactorRequiredException ex)

            {

                _session = ex.PartialSession;

                SaveSessionSnapshot("2fa_required");
                RefreshSessionInventoryPanel();
                _ = RefreshCloudQuotaPanelAsync();

                ConfigureTwoFactorUi(ex.VerificationOptions);

                TwoFactorPanel.Visibility = Visibility.Visible;

                LogAuth(ex.Message);

                MessageBox.Show(this, ex.Message, "Two-factor verification", MessageBoxButton.OK, MessageBoxImage.Information);

            }

        }

        catch (Exception ex)

        {

            LogAuth($"Error: {ex.Message}");

            MessageBox.Show(this, ex.Message, "Sign In", MessageBoxButton.OK, MessageBoxImage.Error);

        }

        finally

        {

            LoginButton.IsEnabled = true;

        }

    }



    private async void Verify2FaButton_Click(object sender, RoutedEventArgs e)

    {

        if (_session is null)

        {

            MessageBox.Show(this, "Sign in first.", "2FA", MessageBoxButton.OK, MessageBoxImage.Warning);

            return;

        }



        var code = TwoFactorCodeTextBox.Text.Trim();

        if (code.Length < 6)

        {

            MessageBox.Show(this, "Enter the 6-digit code.", "2FA", MessageBoxButton.OK, MessageBoxImage.Warning);

            return;

        }



        var progress = new Progress<string>(msg => Dispatcher.Invoke(() => LogAuth(msg)));

        try

        {

            Verify2FaButton.IsEnabled = false;

            var appleId = AppleIdTextBox.Text.Trim();

            if (_session is not null)
            {
                _session.TwoFactorMethod = TwoFactorSmsRadio.IsChecked == true
                    ? TwoFactorMethod.Sms
                    : TwoFactorMethod.TrustedDevice;
                if (_session.TwoFactorMethod == TwoFactorMethod.Sms
                    && SmsPhoneComboBox.SelectedItem is TrustedPhoneNumber phone)
                {
                    _session.SelectedPhoneId = phone.Id;
                }
            }

            var authenticated = await Orchestrator.CompleteSignInAsync(

                appleId, PasswordBox.Password, code, _session, progress);

            if (_midDownloadAuthTcs is not null)
            {
                await FinishMidDownloadAuthAsync(authenticated, progress).ConfigureAwait(true);
                return;
            }

            _session = authenticated;

            UpdateSessionUi(true);

            TwoFactorPanel.Visibility = Visibility.Collapsed;

            SaveSessionSnapshot("2fa_ok");

            LogAuth("2FA completed.");
            ApplyUiWizardStage(UiWizardStage.AfterLogin);

        }

        catch (CloudKitBootstrapException ex)

        {

            if (_midDownloadAuthTcs is not null)
            {
                await FinishMidDownloadAuthAsync(ex.Session, progress).ConfigureAwait(true);
                return;
            }

            _session = ex.Session;

            UpdateSessionUi(true);

            TwoFactorPanel.Visibility = Visibility.Collapsed;

            SaveSessionSnapshot("2fa_ok_bootstrap_failed", ex.Message);

            LogAuth($"Login OK — bootstrap CloudKit: {ex.Message}");

            MessageBox.Show(this,

                $"Authentication succeeded, but CloudKit initialization failed:\n{ex.Message}",

                "CloudKit",

                MessageBoxButton.OK,

                MessageBoxImage.Warning);
            ApplyUiWizardStage(UiWizardStage.AfterLogin);

        }

        catch (Exception ex)

        {

            LogAuth($"2FA failed: {ex.Message}");

            MessageBox.Show(this, ex.Message, "2FA", MessageBoxButton.OK, MessageBoxImage.Error);

        }

        finally

        {

            Verify2FaButton.IsEnabled = true;

        }

    }



    private async void RefreshBackupsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in before listing backups.", "Backup", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _backupListBusy = true;
        _backupPropertiesReady = false;
        RefreshBackupsButton.IsEnabled = false;
        UpdateDownloadButtonState();

        // Tempo: parte subito su Aggiorna (lista + backupProperties), non al download.
        StartDownloadTiming();
        _lastDownloadProgressStatus = "Fetching snapshot list…";
        DownloadStatusText.Text = _lastDownloadProgressStatus;
        DownloadProgressBar.IsIndeterminate = true;
        // #region agent log
        AgentListLog("H-REFRESH-UI", "refresh_ui_timing_start", new
        {
            status = DownloadStatusText.Text,
            timingStarted = _backupDownloadStartedUtc is not null,
        });
        // #endregion

        try
        {
            // #region agent log
            AgentListLog("H-HANG3", "refresh_backups_start", new { hasKeySet = _session.PcsEscrowedKeySet is { Length: > 32 } });
            // #endregion
            var listLog = new Progress<string>(PostDownloadLogFromWorker);
            var devices = await Orchestrator.ListBackupsAsync(_session, listLog);
            _devices = devices.ToList();
            // #region agent log
            AgentListLog(
                "H-HANG3",
                "refresh_list_done",
                new
                {
                    devices = _devices.Count,
                    snaps = _devices.Sum(d => d.Snapshots.Count),
                    withCipher = _devices.SelectMany(d => d.Snapshots)
                        .Count(s => s.BackupPropertiesCiphertext is { Length: > 16 }),
                });
            // #endregion
            DevicesGrid.ItemsSource = null;
            DevicesGrid.ItemsSource = _devices;
            if (_devices.Count > 0)
            {
                DevicesGrid.SelectedIndex = 0;
                BindSnapshotsForSelectedDevice();
            }
            else
            {
                SnapshotsGrid.ItemsSource = null;
                SnapshotsGrid.SelectedItem = null;
                UpdateDownloadButtonState();
            }

            SaveSessionSnapshot("backup_list_ok", $"{_devices.Count} devices");
            AppendDownloadLog($"Found {_devices.Count} devices with backups.");

            // Decrypt PCS di backupProperties: attende il fine e solo dopo riabilita Scarica.
            var needsProps = _devices.SelectMany(d => d.Snapshots)
                .Any(s => s.BackupPropertiesCiphertext is { Length: > 16 });
            if (needsProps)
            {
                _lastDownloadProgressStatus = "Decrypting snapshot fields…";
                DownloadStatusText.Text = _lastDownloadProgressStatus;
                AppendDownloadLog("Decrypting backupProperties…");
                // #region agent log
                AgentListLog("H-REFRESH-UI", "refresh_decrypt_status", new
                {
                    status = DownloadStatusText.Text,
                    needsProps,
                });
                AgentListLog("H-HANG3", "refresh_decrypt_begin", new { needsProps });
                // #endregion
                await DecryptBackupPropertiesAndRefreshGridAsync(listLog);
                // #region agent log
                AgentListLog("H-HANG3", "refresh_decrypt_end", new { });
                // #endregion
            }
            else
            {
                BindSnapshotsForSelectedDevice();
            }

            _backupPropertiesReady = true;
            var snapCount = _devices.Sum(d => d.Snapshots.Count);
            var deviceWord = _devices.Count == 1 ? "device" : "devices";
            _lastDownloadProgressStatus =
                $"List ready ({_devices.Count} {deviceWord}, {snapCount} snapshots)";
            DownloadStatusText.Text = _lastDownloadProgressStatus;
        }
        catch (Exception ex)
        {
            SaveSessionSnapshot("backup_list_failed", ex.Message);
            AppendDownloadLog($"Backup list error: {ex.Message}");
            // #region agent log
            AgentListLog("H-HANG3", "refresh_backups_exception", new { err = ex.GetType().Name, msg = ex.Message });
            // #endregion
            MessageBox.Show(this, ex.Message, "Backup", MessageBoxButton.OK, MessageBoxImage.Error);
            _backupPropertiesReady = false;
            _lastDownloadProgressStatus = "List failed";
            DownloadStatusText.Text = _lastDownloadProgressStatus;
        }
        finally
        {
            DownloadProgressBar.IsIndeterminate = false;
            DownloadProgressBar.Value = 0;
            StopDownloadTiming();
            _backupListBusy = false;
            RefreshBackupsButton.IsEnabled = true;
            UpdateDownloadButtonState();
            // #region agent log
            AgentListLog("H-REFRESH-UI", "refresh_ui_timing_end", new
            {
                status = DownloadStatusText.Text,
                elapsedText = DownloadElapsedText.Text,
            });
            // #endregion
        }
    }

    // #region agent log
    private static void AgentListLog(string hypothesisId, string message, object data)
    {
        try
        {
            var line = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["sessionId"] = "7dabb5",
                ["runId"] = "backup-pcs1",
                ["hypothesisId"] = hypothesisId,
                ["location"] = "MainWindow.RefreshBackups",
                ["message"] = message,
                ["data"] = data,
                ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
            });
            IkeLogOptions.AppendAgentNdjson(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                line);
        }
        catch
        {
            // ignore
        }
    }
    // #endregion

    private async Task DecryptBackupPropertiesAndRefreshGridAsync(IProgress<string> listLog)
    {
        if (_session is null || _devices.Count == 0)
            return;

        try
        {
            var summary = await Orchestrator.DecryptListedBackupPropertiesAsync(
                _session, _devices, listLog).ConfigureAwait(true);
            // HardwareUdid arriva dal decrypt: ri-bind della griglia dispositivi.
            DevicesGrid.ItemsSource = null;
            DevicesGrid.ItemsSource = _devices;
            BindSnapshotsForSelectedDevice();
            AppendDownloadLog($"backupProperties: {summary.Message}");
            var udid = _devices.FirstOrDefault(d => !string.IsNullOrWhiteSpace(d.HardwareUdid))?.HardwareUdid;
            if (udid is not null)
                AppendDownloadLog($"HardwareUdid (Lockdown.UniqueDeviceID): {udid}");
        }
        catch (Exception ex)
        {
            AppendDownloadLog($"backupProperties: {ex.Message}");
            BindSnapshotsForSelectedDevice();
        }
    }

    private void DevicesGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        BindSnapshotsForSelectedDevice();
    }

    private void SnapshotsGrid_SelectionChanged(object sender, System.Windows.Controls.SelectionChangedEventArgs e)
    {
        UpdateDownloadButtonState();
    }

    private void ChainSnapshotsCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        UpdateDownloadButtonLabel();
    }

    private void UpdateDownloadButtonLabel()
    {
        if (DownloadButton is null || ChainSnapshotsCheckBox is null)
            return;
        DownloadButton.Content = ChainSnapshotsCheckBox.IsChecked == true
            ? "Download backup (chain)"
            : "Download selected snapshot";
    }

    private void BindSnapshotsForSelectedDevice()
    {
        if (DevicesGrid.SelectedItem is not BackupDevice device || device.Snapshots.Count == 0)
        {
            SnapshotsGrid.ItemsSource = null;
            SnapshotsGrid.SelectedItem = null;
            UpdateDownloadButtonState();
            return;
        }

        SnapshotsGrid.ItemsSource = device.Snapshots.OrderByDescending(s => s.BackupDate).ToList();
        SnapshotsGrid.SelectedIndex = 0;
        UpdateDownloadButtonState();
    }

    private void UpdateDownloadButtonState()
    {
        DownloadButton.IsEnabled = !_backupListBusy
            && _backupPropertiesReady
            && SnapshotsGrid.SelectedItem is BackupSnapshot;
    }

    /// <summary>
    /// Coalesce progress: un solo BeginInvoke in volo, applica sempre l’ultimo report
    /// (coda decrypt non resta “congelata” sul backlog dispatcher).
    /// </summary>
    private void EnqueueDownloadProgressReport(DownloadProgressReport r)
    {
        Volatile.Write(ref _uiPendingProgress, r);
        if (Interlocked.CompareExchange(ref _uiProgressFlushScheduled, 1, 0) != 0)
            return;

        Dispatcher.BeginInvoke(FlushDownloadProgressReports);
    }

    private void FlushDownloadProgressReports()
    {
        try
        {
            while (true)
            {
                var latest = Volatile.Read(ref _uiPendingProgress);
                Volatile.Write(ref _uiProgressFlushScheduled, 0);
                if (latest is null)
                    return;

                ApplyDownloadProgressReport(latest);

                // Report più fresco arrivato dopo il clear del flag → ripeti senza nuovo post.
                var again = Volatile.Read(ref _uiPendingProgress);
                if (again is null || ReferenceEquals(again, latest))
                    return;
                if (Interlocked.CompareExchange(ref _uiProgressFlushScheduled, 1, 0) != 0)
                    return; // un altro flush è già schedulato
            }
        }
        catch (Exception ex)
        {
            Volatile.Write(ref _uiProgressFlushScheduled, 0);
            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "MainWindow.FlushDownloadProgressReports",
                    ["message"] = "progressbar_value_fail",
                    ["data"] = new { type = ex.GetType().FullName, msg = ex.Message },
                    ["hypothesisId"] = "H-UI-QUEUE",
                    ["runId"] = "queue-coalesce-v1",
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion
        }
    }

    private readonly System.Diagnostics.Stopwatch _uiProgressApplySw = new();

    private void ApplyDownloadProgressReport(DownloadProgressReport r)
    {
        _uiProgressApplySw.Restart();
        // Scarta snapshot più vecchi (race download vs worker: coda stale alta).
        if (r.ReportSequence > 0 && r.ReportSequence < _uiLastProgressSeq)
        {
            // #region agent log
            try
            {
                var n = Interlocked.Increment(ref _uiStaleProgressDropCount);
                if (n <= 30 || n % 50 == 0)
                {
                    var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "MainWindow.ApplyDownloadProgressReport",
                        ["message"] = "progress_stale_dropped",
                        ["hypothesisId"] = "H-UI-QUEUE",
                        ["runId"] = "queue-coalesce-v1",
                        ["data"] = new
                        {
                            n,
                            seq = r.ReportSequence,
                            last = _uiLastProgressSeq,
                            decryptQueued = r.DecryptQueued,
                            filesDecrypted = r.FilesDecrypted,
                        },
                    });
                    IkeLogOptions.AppendAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
                }
            }
            catch { /* ignore */ }
            // #endregion
            return;
        }

        if (r.ReportSequence > _uiLastProgressSeq)
            _uiLastProgressSeq = r.ReportSequence;

        // ETA byte: per-snapshot (service azzera a ogni DownloadSnapshotAsync).
        // NON usare solo-max: in catena incrementale i picchi del job precedente
        // facevano restare done/total sullo snapshot vecchio e “sommare” i totali.
        var labelChanged = !string.IsNullOrWhiteSpace(r.SnapshotLabel)
            && !string.Equals(r.SnapshotLabel, _uiLastBytesSnapshotLabel, StringComparison.Ordinal);
        if (labelChanged)
        {
            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "MainWindow.ApplyDownloadProgressReport",
                    ["message"] = "bytes_snapshot_rebind",
                    ["hypothesisId"] = "H-BYTES-RESET",
                    ["runId"] = "bytes-snap-reset-v1",
                    ["data"] = new
                    {
                        prevLabel = _uiLastBytesSnapshotLabel,
                        nextLabel = r.SnapshotLabel,
                        prevDone = _timingBytesDone,
                        prevTotal = _timingBytesTotal,
                        reportDone = r.BytesDownloaded,
                        reportTotal = r.TotalBytes,
                        reportSeq = r.ReportSequence,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion
            _uiLastBytesSnapshotLabel = r.SnapshotLabel;
            _timingBytesDone = 0;
            _timingBytesTotal = r.TotalBytes > 0 ? r.TotalBytes : 0;
            _timingWireBytes = 0;
            _uiBytesProgressLogCount = 0;
        }

        if (r.ReportSequence > 0)
        {
            // ReportFilesDoneProgress: cumulativo ufficiale del job corrente.
            _timingBytesDone = Math.Max(0L, r.BytesDownloaded);
            if (r.TotalBytes > 0)
                _timingBytesTotal = r.TotalBytes;
            if (r.WireBytes > 0)
                _timingWireBytes = r.WireBytes;
        }
        else
        {
            // Report “leggeri” (solo Status): non regredire.
            if (r.BytesDownloaded > _timingBytesDone)
                _timingBytesDone = r.BytesDownloaded;
            if (r.TotalBytes > _timingBytesTotal)
                _timingBytesTotal = r.TotalBytes;
            if (r.WireBytes > _timingWireBytes)
                _timingWireBytes = r.WireBytes;
        }

        var filesHint = r.FilesTotal > 0 ? r.FilesTotal : r.AssetsTotal;
        var doneHint = Math.Max(r.FilesDecrypted, _uiPeakFilesDecrypted)
                       + Math.Max(r.FilesDecryptFailed, _uiPeakFilesDecryptFailed);
        // Solo a fine run, e solo se non abbiamo un totale snapshot dichiarato più piccolo.
        if (_timingBytesTotal < _timingBytesDone
            && (filesHint <= 0 || doneHint >= filesHint)
            && !(r.TotalBytes > 0 && _timingBytesDone > r.TotalBytes * 11 / 10))
            _timingBytesTotal = _timingBytesDone;
        // Se done ha superato il totale dichiarato (credito MMCS legacy), clamp visuale.
        if (_timingBytesTotal > 0 && _timingBytesDone > _timingBytesTotal)
            _timingBytesDone = _timingBytesTotal;

        var filesTotal = r.FilesTotal > 0 ? r.FilesTotal : r.AssetsTotal;
        var downloaded = Math.Max(r.FilesDownloaded, _uiPeakFilesDownloaded);
        var decrypted = Math.Max(r.FilesDecrypted, _uiPeakFilesDecrypted);
        var decryptFailed = Math.Max(r.FilesDecryptFailed, _uiPeakFilesDecryptFailed);
        var ciphertextSaved = Math.Max(r.FilesCiphertextSaved, _uiPeakFilesCiphertextSaved);
        var duplicated = Math.Max(r.FilesDuplicated, _uiPeakFilesDuplicated);

        // Pipeline report (anche coda→0 / solo Falliti): aggiorna picchi e testi dedicati.
        if (r.FilesTotal > 0 || r.FilesDownloaded > 0 || r.FilesDecrypted > 0
            || r.DecryptQueued > 0 || r.FilesDecryptFailed > 0 || r.FilesCiphertextSaved > 0
            || r.FilesDuplicated > 0 || r.FilesPendingChunks > 0
            || r.ReportSequence > 0)
        {
            _uiPeakFilesDownloaded = downloaded;
            _uiPeakFilesDecrypted = decrypted;
            _uiPeakFilesDecryptFailed = decryptFailed;
            _uiPeakFilesCiphertextSaved = ciphertextSaved;
            _uiPeakFilesDuplicated = duplicated;

            if (filesTotal > 0)
            {
                var dlPct = 100.0 * downloaded / filesTotal;
                var dcPct = 100.0 * decrypted / filesTotal;
                if (double.IsFinite(dlPct))
                    DownloadFilesProgressBar.Value = Math.Clamp(
                        dlPct, DownloadFilesProgressBar.Minimum, DownloadFilesProgressBar.Maximum);
                if (double.IsFinite(dcPct))
                    DecryptFilesProgressBar.Value = Math.Clamp(
                        dcPct, DecryptFilesProgressBar.Minimum, DecryptFilesProgressBar.Maximum);
                DownloadFilesCountText.Text = $"{downloaded:N0} / {filesTotal:N0}";
                DecryptFilesCountText.Text = $"{decrypted:N0} / {filesTotal:N0}";
            }

            // Coda: applica SEMPRE il valore del report (anche 0) — non restare su picco stale.
            DecryptQueueText.Text = $"Decrypt queue: {r.DecryptQueued:N0}";
            PendingChunksText.Text = $"Pending: {r.FilesPendingChunks:N0}";
            DuplicatedFilesText.Text = $"Duplicates: {duplicated:N0}";
            CiphertextFilesText.Text = $"Ciphertext: {ciphertextSaved:N0}";
            DecryptFailedText.Text = $"Decrypt failed: {decryptFailed:N0}";

            _timingFilesDone = decrypted + decryptFailed;
            if (filesTotal > 0)
                _timingFilesTotal = filesTotal;
            DownloadProgressBar.IsIndeterminate = false;
            RefreshDownloadTimingTexts();
        }
        else if (r.BytesDownloaded > 0 || r.TotalBytes > 0)
        {
            RefreshDownloadTimingTexts();
        }

        // Barra stato complessiva: SOLO successi (= Decifrati). Mai Falliti, mai Scaricati-in-coda.
        if (filesTotal > 0 && (r.ReportSequence > 0 || r.FilesTotal > 0 || r.FilesDecrypted > 0
                               || r.FilesDownloaded > 0 || r.AssetsTotal > 0
                               || _uiPeakFilesDecrypted > 0))
        {
            DownloadProgressBar.IsIndeterminate = false;
            var successDone = decrypted;

            var pct = 100.0 * successDone / filesTotal;
            if (double.IsFinite(pct))
                DownloadProgressBar.Value = Math.Clamp(
                    pct, DownloadProgressBar.Minimum, DownloadProgressBar.Maximum);
            var snapPrefix = string.IsNullOrWhiteSpace(r.SnapshotLabel)
                ? ""
                : $"[{r.SnapshotLabel}] ";
            var progressStatus =
                $"{snapPrefix}{successDone:N0} / {filesTotal:N0} files decrypted";
            _lastDownloadProgressStatus = progressStatus;
            DownloadStatusText.Text = progressStatus;

            // #region agent log
            // Prima: AppendAllText sync sul dispatcher + trigger DecryptQueued==0 →
            // decine di migliaia di write su debug-7dabb5.log (= freeze UI).
            try
            {
                var n = Interlocked.Increment(ref _uiStatusLogCount);
                if (n <= 20 || n % 200 == 0 || decryptFailed > 0)
                {
                    var line = JsonSerializer.Serialize(new Dictionary<string, object?>
                    {
                        ["sessionId"] = "7dabb5",
                        ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                        ["location"] = "MainWindow.ApplyDownloadProgressReport",
                        ["message"] = "status_eq_decrypted",
                        ["hypothesisId"] = "H-STATUS-GAP",
                        ["runId"] = "count-semantics-v2",
                        ["data"] = new
                        {
                            n,
                            successDone,
                            downloaded,
                            decrypted,
                            decryptFailed,
                            ciphertextSaved,
                            reportCipher = r.FilesCiphertextSaved,
                            queue = r.DecryptQueued,
                            filesTotal,
                            assetsCompleted = r.AssetsCompleted,
                            statusEqualsDecrypted = successDone == decrypted,
                            failedWouldInflate = successDone == decrypted + decryptFailed
                                                 && decryptFailed > 0,
                            hypothesis = "H-CIPHER-UI",
                        },
                    });
                    QueueAgentNdjson(
                        @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                        line);
                }
            }
            catch { /* ignore */ }
            // #endregion
        }
        else if (!string.IsNullOrWhiteSpace(r.Status) && r.AssetsTotal <= 0 && r.FilesTotal <= 0)
        {
            // Mai «Decifratura campi Backup…» / backupProperties sulla progressbar (solo log).
            if (!IsBackupFieldDecryptStatus(r.Status))
            {
                _lastDownloadProgressStatus = r.Status;
                DownloadStatusText.Text = r.Status;
            }
            RefreshDownloadTimingTexts();
        }

        if (r.AppendToLog && !string.IsNullOrWhiteSpace(r.Status))
            AppendDownloadLog(r.Status);

        // #region agent log
        NoteUiStall(
            "MainWindow.ApplyDownloadProgressReport",
            "ui_progress_apply_stall",
            _uiProgressApplySw.ElapsedMilliseconds,
            new { seq = r.ReportSequence, files = r.FilesDecrypted });
        // #endregion
    }

    private static bool IsBackupFieldDecryptStatus(string status) =>
        status.Contains("Decrypting fields", StringComparison.OrdinalIgnoreCase)
        || status.Contains("Decifratura campi", StringComparison.OrdinalIgnoreCase)
        || status.Contains("backupProperties", StringComparison.OrdinalIgnoreCase)
        || status.Contains("Decrypt backupProperties", StringComparison.OrdinalIgnoreCase);

    private void StartDownloadTiming()
    {
        _backupDownloadStartedUtc = DateTime.UtcNow;
        _timingFilesDone = 0;
        _timingFilesTotal = 0;
        _timingBytesDone = 0;
        _timingBytesTotal = 0;
        _timingWireBytes = 0;
        _uiBytesProgressLogCount = 0;
        _uiLastBytesSnapshotLabel = null;
        DownloadElapsedText.Text = "Time: 0:00";
        DownloadBytesText.Text = "Backup: — / —";
        if (DownloadWireBytesText is not null)
            DownloadWireBytesText.Text = "Network: —";

        _downloadTimingTimer?.Stop();
        _downloadTimingTimer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(1) };
        _downloadTimingTimer.Tick += (_, _) => RefreshDownloadTimingTexts();
        _downloadTimingTimer.Start();
    }

    private void StopDownloadTiming()
    {
        _downloadTimingTimer?.Stop();
        _downloadTimingTimer = null;
        RefreshDownloadTimingTexts();
        _backupDownloadStartedUtc = null;
        if (DownloadProgressBar.IsIndeterminate)
        {
            DownloadProgressBar.IsIndeterminate = false;
            DownloadProgressBar.Value = 0;
        }
    }

    private void DownloadBytesScaleCombo_SelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        // Scala scelta a runtime: ricalcola subito il testo Dati senza attendere il tick.
        if (IsLoaded)
            RefreshDownloadTimingTexts();
    }

    private void RefreshDownloadTimingTexts()
    {
        if (_backupDownloadStartedUtc is not { } started)
            return;

        var elapsed = DateTime.UtcNow - started;
        if (elapsed < TimeSpan.Zero)
            elapsed = TimeSpan.Zero;
        DownloadElapsedText.Text = $"Time: {FormatDownloadDuration(elapsed)}";

        var bytesDone = Math.Max(0L, _timingBytesDone);
        var bytesTotal = Math.Max(0L, _timingBytesTotal);
        var wireBytes = Math.Max(0L, _timingWireBytes);
        // Niente estrapolazione file-ratio in UI: il totale arriva da Snapshot.SizeBytes
        // (ReportFilesDoneProgress). Gonfiava 9GB → decine di GB.

        var scaleIdx = DownloadBytesScaleCombo?.SelectedIndex ?? 0;
        var text = FormatDownloadBytesProgress(bytesDone, bytesTotal, scaleIdx);
        DownloadBytesText.Text = text;
        if (DownloadWireBytesText is not null)
            DownloadWireBytesText.Text = FormatWireBytesProgress(wireBytes, scaleIdx);

        // #region agent log
        try
        {
            var n = Interlocked.Increment(ref _uiBytesProgressLogCount);
            if (n <= 30 || n % 20 == 0 || scaleIdx != 0)
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "MainWindow.RefreshDownloadTimingTexts",
                    ["message"] = "bytes_progress_tick",
                    ["hypothesisId"] = "H-BYTES-SNAP",
                    ["runId"] = "bytes-snap-v1",
                    ["data"] = new
                    {
                        n,
                        bytesDone,
                        bytesTotal,
                        scaleIdx,
                        text,
                        elapsedSec = (int)elapsed.TotalSeconds,
                        noExtrapolate = true,
                    },
                });
                QueueAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
        }
        catch { /* ignore */ }
        // #endregion
    }

    /// <summary>
    /// <paramref name="scaleIdx"/>: 0=Auto, 1=B … 5=TB.
    /// </summary>
    private static string FormatDownloadBytesProgress(long done, long total, int scaleIdx)
    {
        var unit = ResolveBytesUnit(scaleIdx, total > 0 ? total : done);
        var div = Math.Pow(1024, unit.Index);
        string Fmt(long b)
        {
            if (unit.Index == 0)
                return b.ToString("N0");
            return (b / div).ToString("0.##");
        }

        if (total <= 0)
            return done <= 0
                ? $"Backup: — / — {unit.Name}"
                : $"Backup: {Fmt(done)} / — {unit.Name}";

        return $"Backup: {Fmt(done)} / {Fmt(total)} {unit.Name}";
    }

    private static string FormatWireBytesProgress(long wireBytes, int scaleIdx)
    {
        if (wireBytes <= 0)
            return "Network: —";

        var unit = ResolveBytesUnit(scaleIdx, wireBytes);
        var div = Math.Pow(1024, unit.Index);
        if (unit.Index == 0)
            return $"Network: {wireBytes:N0} {unit.Name}";
        return $"Network: {(wireBytes / div):0.##} {unit.Name}";
    }

    private static (int Index, string Name) ResolveBytesUnit(int scaleIdx, long referenceBytes)
    {
        string[] units = ["B", "KB", "MB", "GB", "TB"];
        if (scaleIdx >= 1 && scaleIdx <= units.Length)
            return (scaleIdx - 1, units[scaleIdx - 1]);

        // Auto: adatta alla grandezza del totale (o dei done se totale ancora ignoto).
        double size = Math.Max(referenceBytes, 0);
        var unit = 0;
        while (size >= 1024 && unit < units.Length - 1)
        {
            size /= 1024;
            unit++;
        }

        return (unit, units[unit]);
    }

    private static string FormatDownloadDuration(TimeSpan t)
    {
        if (t.TotalHours >= 1)
            return $"{(int)t.TotalHours}:{t.Minutes:D2}:{t.Seconds:D2}";
        return $"{t.Minutes}:{t.Seconds:D2}";
    }

    private int _uiStaleProgressDropCount;

    private void BrowseOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            ApplyBrowsedFolder(OutputFolderTextBox, dlg.FolderName);
    }

    private void CopyDownloadLog_Click(object sender, RoutedEventArgs e)
    {
        var (active, label) = DownloadLogTabs.SelectedIndex switch
        {
            1 => (DownloadWarningLogBox, "warnings"),
            2 => (DownloadErrorLogBox, "errors"),
            _ => (DownloadInfoLogBox, "information"),
        };
        var text = GetRichTextPlain(active);
        if (string.IsNullOrEmpty(text))
        {
            FlashDownloadStatusThenRestore("Log empty");
            return;
        }

        try
        {
            Clipboard.SetText(text);
            FlashDownloadStatusThenRestore($"Log {label} copied to clipboard");
        }
        catch (Exception ex)
        {
            FlashDownloadStatusThenRestore($"Copy log failed: {ex.Message}");
        }
    }

    private async void FlashDownloadStatusThenRestore(string flashMessage, int restoreAfterMs = 2500)
    {
        var gen = ++_downloadStatusFlashGeneration;
        DownloadStatusText.Text = flashMessage;
        try
        {
            await Task.Delay(restoreAfterMs).ConfigureAwait(true);
        }
        catch
        {
            return;
        }

        if (gen != _downloadStatusFlashGeneration)
            return;
        if (!string.IsNullOrWhiteSpace(_lastDownloadProgressStatus))
            DownloadStatusText.Text = _lastDownloadProgressStatus;
    }

    private async void DownloadButton_Click(object sender, RoutedEventArgs e)

    {

        if (_session is null)

        {

            MessageBox.Show(this, "Session not active.", "Download", MessageBoxButton.OK, MessageBoxImage.Warning);

            return;

        }



        if (DevicesGrid.SelectedItem is not BackupDevice device || device.Snapshots.Count == 0)
        {
            MessageBox.Show(this, "Select a device with at least one snapshot.", "Download", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (SnapshotsGrid.SelectedItem is not BackupSnapshot selectedSnapshot)
        {
            MessageBox.Show(this, "Select a snapshot to download.", "Download", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var chainAll = ChainSnapshotsCheckBox.IsChecked == true;
        var snapshotsToDownload = chainAll
            ? device.Snapshots
                .OrderBy(static s => s.BackupDate ?? DateTimeOffset.MinValue)
                .ThenBy(static s => s.RecordName, StringComparer.Ordinal)
                .ToList()
            : [selectedSnapshot];

        if (snapshotsToDownload.Count == 0)
        {
            MessageBox.Show(this, "No snapshot to download.", "Download", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputRoot = OutputFolderTextBox.Text.Trim();
        AppendDownloadLog(
            chainAll
                ? $"Snapshot chain: {snapshotsToDownload.Count} (oldest to newest)"
                : $"Single snapshot: {selectedSnapshot.DateLabel} ({selectedSnapshot.ShortUuid})");

        try
        {
            _downloadBusy = true;
            DownloadButton.IsEnabled = false;
            DownloadProgressBar.Value = 0;
            DownloadFilesProgressBar.Value = 0;
            DecryptFilesProgressBar.Value = 0;
            DownloadFilesCountText.Text = "0 / 0";
            DecryptFilesCountText.Text = "0 / 0";
            DecryptQueueText.Text = "Decrypt queue: 0";
            PendingChunksText.Text = "Pending: 0";
            DuplicatedFilesText.Text = "Duplicates: 0";
            CiphertextFilesText.Text = "Ciphertext: 0";
            DecryptFailedText.Text = "Decrypt failed: 0";
            StartDownloadTiming();
            ResetForegroundMmcsUi();
            _lastDownloadProgressStatus = "Escrow / PCS KeySet…";
            DownloadStatusText.Text = _lastDownloadProgressStatus;
            DownloadProgressBar.IsIndeterminate = true;
            _uiPeakFilesDownloaded = 0;
            _uiPeakFilesDecrypted = 0;
            _uiPeakFilesDecryptFailed = 0;
            _uiPeakFilesCiphertextSaved = 0;
            _uiPeakFilesDuplicated = 0;
            _uiLastProgressSeq = 0;
            _uiStatusLogCount = 0;
            _uiErrorLogCount = 0;
            _uiPendingProgress = null;
            Volatile.Write(ref _uiProgressFlushScheduled, 0);

            var progress = new Progress<DownloadProgressReport>(EnqueueDownloadProgressReport);

            var downloadLog = new Progress<string>(PostDownloadLogFromWorker);

            IkeLogOptions.SetQuiet(QuietLogCheckBox.IsChecked == true);
            SyncPersistRunLogsFromUi();
            SyncDiskDumpFromUi();
            WireOrchestratorCallbacks(Orchestrator);
            var maxAssets = int.TryParse(MaxAssetsTextBox.Text.Trim(), out var max) && max > 0 ? max : (int?)null;
            var manifestOnly = ManifestOnlyCheckBox.IsChecked == true;

            // KeySet PCS: una sola volta per tutta la catena.
            var firstOut = IkeBackupOutputPaths.ResolveSnapshotDirectory(
                outputRoot, device, snapshotsToDownload[0]);
            Directory.CreateDirectory(firstOut);
            var pcsDir = EscrowPcsSession.ResolvePcsKeysDirectory(
                DecryptOutputTextBox.Text.Trim(),
                _session.PcsKeysDirectory,
                firstOut,
                OutputFolderTextBox.Text.Trim());
            Directory.CreateDirectory(pcsDir);
            var iCsc = ResolveEscrowIcsc();
            if (string.IsNullOrEmpty(EscrowPasswordBox.Password.Trim()) && !string.IsNullOrEmpty(iCsc))
                AppendDownloadLog($"iCSC empty → default DSID ({iCsc})");
            EscrowSmsOptions? sms = EscrowSmsVariantCheckBox.IsChecked == true
                ? new EscrowSmsOptions(
                    Enabled: true,
                    SmsChallengeCode: EscrowSmsCodeBox.Text,
                    RequestSmsChallenge: EscrowRequestSmsCheckBox.IsChecked == true)
                : null;

            IProgress<string> downloadLogProgress = downloadLog;
            var completedDirs = new List<string>();
            await Task.Run(
                async () =>
                {
                    var ensure = await EscrowPcsSession.EnsureKeySetAsync(
                        _session, Http, pcsDir, iCsc, sms, downloadLogProgress).ConfigureAwait(false);
                    if (ensure.Success)
                    {
                        downloadLogProgress.Report(
                            $"PCS KeySet: presente ({_session.PcsEscrowedKeySet?.Length ?? 0} B) ← {ensure.Source}");
                    }
                    else
                    {
                        downloadLogProgress.Report(
                            $"PCS KeySet: missing — {ensure.Message} (download continues; MMCS decrypt skip)");
                    }

                    // #region agent log
                    try
                    {
                        var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                        {
                            ["sessionId"] = "7dabb5",
                            ["runId"] = "chain-snap-v1",
                            ["hypothesisId"] = "H-COPY-SNAP",
                            ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                            ["location"] = "MainWindow.DownloadButton_Click",
                            ["message"] = "snapshot_chain_plan",
                            ["data"] = new
                            {
                                chainAll,
                                count = snapshotsToDownload.Count,
                                order = snapshotsToDownload.Select(static s => new
                                {
                                    s.ShortUuid,
                                    date = s.BackupDate?.ToString("o"),
                                    s.RecordName,
                                }).ToArray(),
                            },
                        });
                        IkeLogOptions.AppendAgentNdjson(
                            @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                            line);
                    }
                    catch { /* ignore */ }
                    // #endregion

                    for (var i = 0; i < snapshotsToDownload.Count; i++)
                    {
                        var snap = snapshotsToDownload[i];
                        var outputDir = IkeBackupOutputPaths.ResolveSnapshotDirectory(
                            outputRoot, device, snap);
                        Directory.CreateDirectory(outputDir);
                        downloadLogProgress.Report(
                            $"── Snapshot {i + 1}/{snapshotsToDownload.Count}: " +
                            $"{snap.DateLabel} ({snap.ShortUuid}) → {outputDir}");

                        await Dispatcher.InvokeAsync(() =>
                        {
                            _uiPeakFilesDownloaded = 0;
                            _uiPeakFilesDecrypted = 0;
                            _uiPeakFilesDecryptFailed = 0;
                            _uiPeakFilesCiphertextSaved = 0;
                            _uiPeakFilesDuplicated = 0;
                            _uiLastProgressSeq = 0;
                            _uiPendingProgress = null;
                            Volatile.Write(ref _uiProgressFlushScheduled, 0);
                            // Rebind Dati allo snapshot corrente (catena incrementale).
                            var declared = snap.SizeBytes is > 0 ? snap.SizeBytes.Value : 0L;
                            // #region agent log
                            try
                            {
                                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                                {
                                    ["sessionId"] = "7dabb5",
                                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                                    ["location"] = "MainWindow.DownloadButton_Click",
                                    ["message"] = "bytes_chain_snapshot_reset",
                                    ["hypothesisId"] = "H-BYTES-RESET",
                                    ["runId"] = "bytes-snap-reset-v1",
                                    ["data"] = new
                                    {
                                        index = i + 1,
                                        count = snapshotsToDownload.Count,
                                        shortUuid = snap.ShortUuid,
                                        dateLabel = snap.DateLabel,
                                        declaredSize = declared,
                                        prevDone = _timingBytesDone,
                                        prevTotal = _timingBytesTotal,
                                    },
                                });
                                IkeLogOptions.AppendAgentNdjson(
                                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                                    line);
                            }
                            catch { /* ignore */ }
                            // #endregion
                            _timingBytesDone = 0;
                            _timingBytesTotal = declared;
                            _timingWireBytes = 0;
                            _uiBytesProgressLogCount = 0;
                            _uiLastBytesSnapshotLabel = null;
                            var scaleIdx = DownloadBytesScaleCombo?.SelectedIndex ?? 0;
                            DownloadBytesText.Text = FormatDownloadBytesProgress(0, declared, scaleIdx);
                            if (DownloadWireBytesText is not null)
                                DownloadWireBytesText.Text = FormatWireBytesProgress(0, scaleIdx);
                            DownloadFilesCountText.Text = "0 / 0";
                            DecryptFilesCountText.Text = "0 / 0";
                            DecryptQueueText.Text = "Decrypt queue: 0";
                            PendingChunksText.Text = "Pending: 0";
                            DuplicatedFilesText.Text = "Duplicates: 0";
                            CiphertextFilesText.Text = "Ciphertext: 0";
                            DecryptFailedText.Text = "Decrypt failed: 0";
                            _lastDownloadProgressStatus =
                                $"Snapshot {i + 1}/{snapshotsToDownload.Count}: preparing…";
                            DownloadStatusText.Text = _lastDownloadProgressStatus;
                        });

                        await Orchestrator.DownloadSnapshotAsync(
                            _session,
                            new DownloadJob
                            {
                                Device = device,
                                Snapshot = snap,
                                OutputDirectory = outputDir,
                                MaxAssets = maxAssets,
                                EnableEscrowRecover = false,
                                ManifestOnly = manifestOnly,
                                ChainLabel =
                                    $"{i + 1}/{snapshotsToDownload.Count} · {snap.DateLabel} · {snap.ShortUuid}",
                            },
                            progress,
                            downloadLogProgress).ConfigureAwait(false);

                        completedDirs.Add(outputDir);
                        downloadLogProgress.Report(
                            $"── Completed {i + 1}/{snapshotsToDownload.Count}: {snap.ShortUuid}");
                    }
                }).ConfigureAwait(false);

            var summary = completedDirs.Count == 1
                ? $"Download saved to {completedDirs[0]}"
                : $"Chain completed: {completedDirs.Count} snapshots under {outputRoot}";
            RecordCaseOp("backup", "download-completed",
                IkeCaseOpsJournal.Scrub($"{completedDirs.Count} snapshot(s) under {outputRoot}"));
            await Dispatcher.InvokeAsync(() =>
                MessageBox.Show(this, summary, "Download", MessageBoxButton.OK, MessageBoxImage.Information));

        }

        catch (Exception ex)

        {
            var shown = FlattenDownloadException(ex);

            // #region agent log
            try
            {
                var line = System.Text.Json.JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "7dabb5",
                    ["runId"] = "aor-v1",
                    ["hypothesisId"] = "H-AOR1",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "MainWindow.DownloadSnapshot",
                    ["message"] = "download_fatal",
                    ["data"] = new
                    {
                        type = shown.GetType().FullName,
                        msg = shown.Message,
                        param = (shown as ArgumentOutOfRangeException)?.ParamName,
                        stack = shown.StackTrace?.Split('\n').Take(20).Select(static l => l.Trim()).ToArray(),
                        innerType = shown.InnerException?.GetType().FullName,
                        innerMsg = shown.InnerException?.Message,
                        outerType = ex.GetType().FullName,
                    },
                });
                IkeLogOptions.AppendAgentNdjson(
                    @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log",
                    line);
            }
            catch { /* ignore */ }
            // #endregion

            await Dispatcher.InvokeAsync(() =>
            {
                AppendDownloadLog($"Error: {shown.GetType().Name}: {shown.Message}");
                if (shown is ArgumentOutOfRangeException aor && !string.IsNullOrEmpty(aor.ParamName))
                    AppendDownloadLog($"  param: {aor.ParamName}");
                if (shown.InnerException is not null)
                    AppendDownloadLog($"  inner: {shown.InnerException.GetType().Name}: {shown.InnerException.Message}");
                var marks = shown.StackTrace?.Split('\n')
                    .Where(static l => l.Contains("iCloudKitExtractor", StringComparison.Ordinal))
                    .Take(5)
                    .Select(static l => l.Trim())
                    .ToList() ?? [];
                foreach (var mark in marks)
                    AppendDownloadLog($"  at {mark}");
                MessageBox.Show(this, shown.Message, "Download", MessageBoxButton.OK, MessageBoxImage.Error);
            });

        }

        finally
        {
            _downloadBusy = false;
            await Dispatcher.InvokeAsync(() =>
            {
                StopDownloadTiming();
                UpdateDownloadButtonState();
            });
        }

    }

    private static Exception FlattenDownloadException(Exception ex)
    {
        while (true)
        {
            if (ex is AggregateException { InnerException: { } aggInner })
            {
                ex = aggInner;
                continue;
            }

            if (ex is not BackupCryptoAbortException
                && ex.InnerException is BackupCryptoAbortException abort)
            {
                ex = abort;
                continue;
            }

            return ex;
        }
    }

    private void ConfigureTwoFactorUi(PhoneVerificationOptions? options)
    {
        var phones = options?.TrustedPhoneNumbers ?? _session?.TrustedPhoneNumbers ?? [];
        var hasSms = phones.Count > 0;
        var deviceCount = options?.TrustedDeviceCount ?? 0;
        // Solo SMS (nessun trusted device): seleziona radio SMS e mostra il combo.
        var smsOnly = hasSms && deviceCount <= 0;
        TwoFactorSmsRadio.IsEnabled = hasSms;
        SmsPhoneComboBox.ItemsSource = phones;
        if (hasSms)
            SmsPhoneComboBox.SelectedIndex = 0;
        if (smsOnly)
        {
            TwoFactorSmsRadio.IsChecked = true;
            TwoFactorDeviceRadio.IsChecked = false;
            if (_session is not null)
                _session.TwoFactorMethod = TwoFactorMethod.Sms;
        }
        else
        {
            TwoFactorDeviceRadio.IsChecked = true;
            TwoFactorSmsRadio.IsChecked = false;
        }
        UpdateSmsPanelVisibility();
    }

    private void TwoFactorMethodRadio_Changed(object sender, RoutedEventArgs e) =>
        UpdateSmsPanelVisibility();

    private void UpdateSmsPanelVisibility()
    {
        if (SmsPhonePanel is null || TwoFactorSmsRadio is null)
            return;
        var showPhones = TwoFactorSmsRadio.IsChecked == true
            && SmsPhoneComboBox.Items.Count > 0;
        SmsPhonePanel.Visibility = showPhones ? Visibility.Visible : Visibility.Collapsed;
        RequestSmsButton.IsEnabled = showPhones;
    }

    private async void RequestSmsButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Sign in first.", "2FA SMS", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (SmsPhoneComboBox.SelectedItem is not TrustedPhoneNumber phone)
        {
            MessageBox.Show(this, "No SMS number available for this account.", "2FA SMS",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        try
        {
            RequestSmsButton.IsEnabled = false;
            _session.TwoFactorMethod = TwoFactorMethod.Sms;
            _session.SelectedPhoneId = phone.Id;
            var progress = new Progress<string>(msg => Dispatcher.Invoke(() => LogAuth(msg)));
            await Orchestrator.RequestSmsTwoFactorAsync(_session, phone.Id, progress);
            TwoFactorSmsRadio.IsChecked = true;
            MessageBox.Show(this, $"SMS code sent to {phone.DisplayLabel}.", "2FA SMS",
                MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            LogAuth($"SMS 2FA: {ex.Message}");
            MessageBox.Show(this, ex.Message, "2FA SMS", MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            RequestSmsButton.IsEnabled = true;
        }
    }
}

