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

    /// <summary>Sessione GSA parziale in attesa OTP per registrazione HSA2 (lista 2FA).</summary>
    private ICloudSession? _hsa2PartialSession;

    private AnisetteAuthProfile? _authProfile;

    private bool _licenseOverlayShown;

    private List<BackupDevice> _devices = new();

    /// <summary>True mentre è in corso Aggiorna elenco (lista e/o decrypt backupProperties).</summary>
    private bool _backupListBusy;

    /// <summary>True mentre è in corso Scarica backup (HTTP GET/POST vanno nel log Backup).</summary>
    private bool _downloadBusy;

    /// <summary>Sessione live del download in attesa di Accesso/2FA mid-download.</summary>
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

    public MainWindow()

    {

        InitializeComponent();
        UpdateDownloadButtonLabel();
        RemoteAnisetteProvider.AnyLicenseBundleIssued += OnAnisetteLicenseBundleIssued;

        OutputFolderTextBox.Text = Path.Combine(

            Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),

            "iCloudBackups");

        DecryptOutputTextBox.Text = OutputFolderTextBox.Text;
        WhatsAppOutputTextBox.Text = OutputFolderTextBox.Text;
        ICloudDriveOutputTextBox.Text = OutputFolderTextBox.Text;
        ICloudFilesOutputTextBox.Text = OutputFolderTextBox.Text;
        SyncDataOutputTextBox.Text = OutputFolderTextBox.Text;

        _httpFactory.Capture = _capture;

        // BeginInvoke: Invoke sincrono durante authorizeGet/edge blocca UI e download.
        // Durante elenco/download backup → scheda Backup (Informazioni/Avvisi/Errori); altrimenti Accesso.
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
                "HAR completo: ON → session.har / session_redacted.har in " +
                "%AppData%\\iCloudKitExtractor\\logs\\run_*");
        }
        else if (IkeLogOptions.PersistRunLogs)
        {
            LogAuth("Capture run: attiva (cartella creata al primo evento → %AppData%\\iCloudKitExtractor\\logs\\run_*)");
        }
        else
        {
            LogAuth("Capture run: disattivata (nessun log in %AppData%\\iCloudKitExtractor\\logs)");
        }
        LoadAnisetteSettingsUi();
        LogAuth($"Anisette: {AnisetteProviderFactory.ResolveServerUrl()} | mode: {AnisetteProviderFactory.ResolveAuthMode()}");
        LogAuth($"  config: {AnisetteProviderFactory.SettingsFilePath}");
        Loaded += MainWindow_Loaded;
        HookRichLogResize(DownloadInfoLogBox);
        HookRichLogResize(DownloadWarningLogBox);
        HookRichLogResize(DownloadErrorLogBox);
        HookRichLogResize(SyncDataInfoLogBox);
        HookRichLogResize(SyncDataErrorLogBox);

        SyncDiskDumpFromUi();
        UpdateSessionUi(false);
        ApplyUiWizardStage(UiWizardStage.LoginOnly);
    }

    private enum UiWizardStage
    {
        /// <summary>Solo scheda Accesso.</summary>
        LoginOnly = 0,
        /// <summary>Login OK → Escrow abilitata e selezionata.</summary>
        AfterLogin = 1,
        /// <summary>Escrow OK → tutte le schede abilitate (resta su Escrow se già lì).</summary>
        AfterEscrow = 2,
    }

    private void ApplyUiWizardStage(UiWizardStage stage, bool selectTab = true)
    {
        if (MainTabControl is null || AccessTab is null)
            return;

        AccessTab.IsEnabled = true;
        EscrowTab.IsEnabled = stage >= UiWizardStage.AfterLogin;
        // SharedStreams / KeyValue / Contacts / Find My People: post-login.
        if (ExploratoryServicesTab is not null)
            ExploratoryServicesTab.IsEnabled = stage >= UiWizardStage.AfterLogin;
        // Dispositivi fidati / IMAP Posta: sempre (credenziali dedicate, anche senza Escrow).
        if (TrustedDevicesTab is not null)
            TrustedDevicesTab.IsEnabled = true;
        if (ImapMailTab is not null)
            ImapMailTab.IsEnabled = true;
        PrefillImapUserFromSession();
        PrefillEscrowRecoverySaltFromSession();
        var rest = stage >= UiWizardStage.AfterEscrow;
        BackupTab.IsEnabled = rest;
        WhatsAppTab.IsEnabled = rest;
        ICloudDriveTab.IsEnabled = rest;
        ICloudFilesTab.IsEnabled = rest;
        SyncDataTab.IsEnabled = rest;

        if (!selectTab)
            return;

        MainTabControl.SelectedItem = stage switch
        {
            UiWizardStage.AfterLogin => EscrowTab,
            UiWizardStage.AfterEscrow => EscrowTab,
            _ => AccessTab,
        };
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
        AppendDecryptLog($"Auth Escrow fallita (401) — ritorno al login. {detail}");
        _session = null;
        _orchestrator = null;
        UpdateSessionUi(false);
        ApplyUiWizardStage(UiWizardStage.LoginOnly);
        LogAuth("Sessione invalidata dopo 401 Escrow — ripetere Accesso.");
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
                "(+ session_redacted.har). Cattura anche HTTP 2xx in Quiet.");
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
    /// Pausa download: mostra Accesso/2FA; dopo login OK assorbe token nella sessione live e riprende.
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

            LogAuth($"Download in pausa — recupero sessione ({ex.Kind}): {ex.Message}");
            _lastDownloadProgressStatus = "In pausa — completa Accesso/2FA…";
            if (DownloadStatusText is not null)
                DownloadStatusText.Text = _lastDownloadProgressStatus;

            if (ex.Kind == SessionReloginKind.Requires2Fa && ex.PartialSession is not null)
            {
                _session = ex.PartialSession;
                ConfigureTwoFactorUi(ex.VerificationOptions);
                TwoFactorPanel.Visibility = Visibility.Visible;
                MessageBox.Show(
                    this,
                    "Sessione scaduta durante il download. Completa la verifica a due fattori per riprendere.",
                    "2FA richiesto",
                    MessageBoxButton.OK,
                    MessageBoxImage.Information);
            }
            else
            {
                TwoFactorPanel.Visibility = Visibility.Collapsed;
                MessageBox.Show(
                    this,
                    "Apple ha rifiutato la password in memoria o serve un nuovo accesso.\n" +
                    "Reinserisci la password nella scheda Accesso e clicca Accedi per riprendere il download.",
                    "Accesso richiesto",
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

        LogAuth("Sessione mid-download ripristinata — ripresa download.");
        _lastDownloadProgressStatus = "Sessione ripristinata — ripresa…";
        if (DownloadStatusText is not null)
            DownloadStatusText.Text = _lastDownloadProgressStatus;
    }

    private async void MainWindow_Loaded(object sender, RoutedEventArgs e)
    {
        try
        {
            await EnsureAuthProfileAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            LogAuth($"Probe anisette fallita: {ex.Message}");
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
                "ANISETTE_SERVER_URL impostata: ha priorità sulla UI (" +
                AnisetteProviderFactory.ResolveServerUrl() + ").";
        }
        else
        {
            AnisetteEnvOverrideText.Visibility = Visibility.Collapsed;
        }

        AnisetteSettingsStatusText.Text =
            "Attivo: " + AnisetteProviderFactory.ResolveServerUrl();
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
        LogAuth("Licenza Anisette (Package C) ricevuta alla prima connessione — salvata in anisette.json.");
        AnisetteSettingsStatusText.Text = "Nuova licenza ricevuta — copiala e conservala.";
    }

    private void LicenseOverlayCopy_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            Clipboard.SetText(LicenseIssuedValueBox.Text ?? "");
            AnisetteSettingsStatusText.Text = "Licenza copiata negli appunti.";
        }
        catch (Exception ex)
        {
            LogAuth("Copia licenza fallita: " + ex.Message);
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
                    AnisetteSettingsStatusText.Text = "URL remoto obbligatorio.";
                    return;
                }

                if (!Uri.TryCreate(settings.ServerUrl, UriKind.Absolute, out var uri)
                    || uri.Scheme is not ("http" or "https"))
                {
                    AnisetteSettingsStatusText.Text = "URL non valido (http/https).";
                    return;
                }
            }

            AnisetteUserSettings.Save(settings);
            InvalidateAnisetteSession();
            var resolved = AnisetteProviderFactory.ResolveServerUrl();
            AnisetteSettingsStatusText.Text = "Salvato → " + resolved;
            LogAuth($"Anisette salvata: {resolved} | mode: {AnisetteProviderFactory.ResolveAuthMode()}");
            LogAuth($"  config: {AnisetteProviderFactory.SettingsFilePath}");

            await EnsureAuthProfileAsync().ConfigureAwait(true);
        }
        catch (Exception ex)
        {
            AnisetteSettingsStatusText.Text = "Errore salvataggio: " + ex.Message;
            LogAuth($"Salvataggio Anisette fallito: {ex.Message}");
        }
    }

    private async void AnisetteTestButton_Click(object sender, RoutedEventArgs e)
    {
        try
        {
            AnisetteTestButton.IsEnabled = false;
            AnisetteSettingsStatusText.Text = "Test in corso…";

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
                AnisetteSettingsStatusText.Text = "URL non valido.";
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
            AnisetteSettingsStatusText.Text = "Test fallito: " + ex.Message;
            LogAuth($"Test Anisette fallito: {ex.Message}");
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
        LogAuth($"  MD-M remoto:  {AnisetteCapability.SummarizeMdM(profile.RemoteAnisette.MdM)}");
        if (AnisetteCapability.IsFridaIphoneBackend(profile.Backend))
            LogAuth("Flow iPhone: Frida → AuthKit/akd sul device + SRP GSA.");
        else if (profile.UseFullIphoneAuth)
            LogAuth("Flow iPhone: Anisette remota (RAD/emulato/Frida) + SRP GSA.");
        else if (profile.Mode == "iphone" && profile.DockerMacAnisette)
            LogAuth("authMode=iphone ma anisette = Mac/Xcode (docker). Usa --backend frida o setup-emulated-akd.");
        else if (profile.Mode == "iphone" && profile.LocalCoreAdiSpoof)
            LogAuth("authMode=iphone ma anisette = CoreADI Windows (:6969). Usa --backend frida (:6971).");
        else if (profile.Mode == "hybrid")
            LogAuth("Flow hybrid (legacy): SRP AuthKitWin → ckAppInit iPhone.");
        else
            LogAuth("authMode=iphone non attivo — verifica AnisetteServer su :6971 (backend=frida).");
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
        AppendBoundedLog(AuthLogTextBox, line);

    /// <summary>
    /// Traffico HTTP condiviso: in operazioni Backup → log Informazioni/Avvisi/Errori;
    /// durante login/2FA/altro → log Accesso.
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
        LogAuth($"Snapshot sessione salvato ({phase})");
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
        if (IkeLogOptions.Quiet
            && kind is not DownloadLogKind.Error)
            return;

        // Quiet off: senza cap il FlowDocument + ScrollToEnd congela il dispatcher
        // (diagnostica: ~36k ui_append_log_stall Info, non File.Copy).
        if (kind == DownloadLogKind.Info && !TryAdmitInfoLogLine())
            return;

        // #region agent log
        if (kind == DownloadLogKind.Error
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
        AppendRichLogLine(box, line, bodyBrush);
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

        // Errori: sempre in coda. Info/avvisi: drop se già troppi post pendenti.
        // In Quiet qui arrivano solo errori (ShouldEmitUi); niente cap.
        var likelyError = IkeLogOptions.Quiet || IkeLogOptions.IsErrorLine(msg);
        if (!likelyError)
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
                if (!likelyError)
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
                        "  PENDING Library/Preferences/com.apple.messages.critical-messaging.storage.plist: mancano 1 chunk in cache (data:H-x9VSABnTfvZeEKqSge:816-1215(400B)) — download continua",
                        "Warning"),
                    ("H-path-exception",
                        "  piano SysSharedContainerDomain-systemgroup.com.apple.ReportMemoryException: 0 file da scaricare (FileMetadata=2 incl. dir/link=2, Assets=0, empty=0, noSig=0, size0=0, dup=0)",
                        "Info"),
                    ("H-path-errorview",
                        "  Library/FLXViewRepository/44-39238115d66481635db86ab4746ca9c65d27a6fc-p-D6223F352E5B0396/pom/views/carrier-error-view.tml → ..\\Backup\\6e\\6e2b80faefaab5ec9049fe30f74646534d570d3b edge=8 storages=2 fordN=1 fill pipeA=1 pipeB=1 fordOpen=1 fordSkip=0 keyed=1 nodes=1 ford=[gate-mirror ctLen=112] pipes=[A,B] MMCS (+27.520 B)",
                        "Info"),
                    ("H-real-error",
                        "  decrypt fallito: Invalid nonce",
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
        // Progress file N/total — mai errori (anche se N è 401/403/404).
        if (System.Text.RegularExpressions.Regex.IsMatch(
                line,
                @"^\s*File\s+\d+\s*/\s*\d+\s*:",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase
                | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
            return DownloadLogKind.Info;

        // Successi / traffico normale (path tipo ApiErrors.bundle NON sono errori).
        if (ContainsAny(line,
                "verifyDigest=ok",
                "chunk OK",
                "decryptFord",
                "decrypt in coda",
                "mmcs_cache: rilasciati",
                "fordOpen=",
                "fill pipeA="))
            return DownloadLogKind.Info;

        // Piano dominio (anche ReportMemoryException nel nome) = info, non errore.
        if (line.Contains("piano ", StringComparison.OrdinalIgnoreCase)
            && line.Contains("file da scaricare", StringComparison.OrdinalIgnoreCase))
            return DownloadLogKind.Info;

        // Log tracer HTTP: REQUEST senza status di risposta → Informazioni (non Errori).
        if (line.Contains("[HTTP]", StringComparison.OrdinalIgnoreCase)
            && line.Contains("REQUEST", StringComparison.OrdinalIgnoreCase)
            && !IkeLogOptions.HasHttpResponseStatusError(line))
            return DownloadLogKind.Info;

        // "fail=0" / "fail=0/1296" non sono errori (es. MMCS ok=1296 fail=0/1296).
        var scan = System.Text.RegularExpressions.Regex.Replace(
            line,
            @"fail\s*=\s*0(?:/\d+)?",
            "okcount",
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
                "decrypt fail", "decrypt fallito", "crypto abort", "Invalid nonce",
                "≠ assetSize", "size_mismatch", "no-ikm", "no-resolve",
                "decrypt_failures", "MmcsAuth assente"))
            return DownloadLogKind.Error;

        // Avvisi
        if (ContainsAny(scan,
                "WARN", "avvis", "PENDING", "pending", "skip", "SKIP",
                "assente", "mancano", "manca ", "fallback", "degrad",
                "prosegue", "warning", "attenzion", "stub", "orfan",
                "non ancora", "senza auth", "debole"))
            return DownloadLogKind.Warning;

        return DownloadLogKind.Info;
    }

    /// <summary>
    /// Match solo token ERROR/FAIL/… — non id path (carrier-error-view, critical-messaging).
    /// </summary>
    private static bool HasLogErrorToken(string line) =>
        System.Text.RegularExpressions.Regex.IsMatch(
            line,
            @"(?<![\w.-])(?:ERROR|FAIL|FATAL|CRITICAL|CRITIC|ABORT|Errore|abortito|interrotto)(?![\w-])",
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

    private void AppendRichLogLine(RichTextBox box, string line, SolidColorBrush bodyBrush)
    {
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
        AppendBoundedLog(DecryptLogTextBox, line);

    private static void AppendBoundedLog(TextBox box, string line)
    {
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
        box.Text = $"[{DateTime.Now:HH:mm:ss}] … log ridotto (ultime {keepLines} righe){Environment.NewLine}"
                   + text[start..];
    }



    private void BrowseDecryptOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            DecryptOutputTextBox.Text = dlg.FolderName;
    }

    private void EscrowSmsVariantCheckBox_Changed(object sender, RoutedEventArgs e)
    {
        var on = EscrowSmsVariantCheckBox.IsChecked == true;
        EscrowSmsCodeLabel.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        EscrowSmsCodeBox.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        EscrowRequestSmsCheckBox.Visibility = on ? Visibility.Visible : Visibility.Collapsed;
        EscrowSecretLabel.Text = "iCSC:";
        EscrowSecretHint.Text = on
            ? "(SMS — vuoto = DSID; SRP usa dsid)"
            : "(vuoto = DSID)";
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
            AppendDecryptLog($"  remint Anisette fallito: {ex.Message}");
        }
    }

    private async void EscrowPcsUnlockButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Effettua prima il login iCloud.", "Unlock EscrowedKeys",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (string.IsNullOrWhiteSpace(_session.Dsid))
        {
            MessageBox.Show(this, "Sessione senza dsid.", "Unlock EscrowedKeys",
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
            MessageBox.Show(this, "Seleziona una cartella output.", "Unlock EscrowedKeys",
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
                AppendDecryptLog("Variante SMS (securebackup) attiva");
            AppendDecryptLog(
                iCscFromField
                    ? $"iCSC dal campo ({iCsc.Length} char)"
                    : $"iCSC vuoto → default DSID ({iCsc})");

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
                        ? $"PCS KeySet in sessione: {ensure.KeySet?.Length ?? 0} B ← {ensure.Source}"
                        : $"PCS KeySet NON in sessione: {ensure.Message}");
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
            AppendDecryptLog($"Errore unlock: {ex.Message}");
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
            MessageBox.Show(this, "Effettua prima il login iCloud.", "Lista bottle iCDP",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = DecryptOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Seleziona una cartella output.", "Lista bottle iCDP",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);
        try
        {
            EscrowOctagonListButton.IsEnabled = false;
            AppendDecryptLog($"Lista bottle iCDP (get_records, non distruttivo) → {outputDir}");
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
            AppendDecryptLog($"Errore lista iCDP: {ex.Message}");
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
            MessageBox.Show(this, "Effettua prima il login iCloud.", "Unlock Octagon",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (EscrowOctagonBottleCombo.SelectedItem is not OctagonBottleListItem bottle)
        {
            MessageBox.Show(this,
                "Seleziona una bottle iCDP (prima «Lista bottle iCDP»).",
                "Unlock Octagon", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var passcode = EscrowPasswordBox.Password.Trim();
        if (string.IsNullOrEmpty(passcode))
        {
            MessageBox.Show(this,
                "Inserisci il passcode del dispositivo che ha creato la bottle\n" +
                $"(serial={bottle.Serial}, build={bottle.Build}).\n" +
                "Non usare il DSID: per Octagon serve il passcode device / iCSC.",
                "Unlock Octagon", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = DecryptOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Seleziona una cartella output.", "Unlock Octagon",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var confirm = MessageBox.Show(this,
            "ATTENZIONE: unlock Octagon consuma 1 tentativo irreversibile su questa bottle\n" +
            $"(tentativi rimasti ≈ {bottle.RemainingAttempts?.ToString() ?? "?"}/10).\n" +
            "Al 10° fallimento HSM distrugge il record.\n\n" +
            $"{bottle.Display}\n\nProcedere?",
            "Unlock Octagon — conferma",
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
                    $"Octagon entropy in sessione: {_session.OctagonBottledPeerEntropy?.Length ?? 0} B" +
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
            AppendDecryptLog($"Errore Octagon unlock: {ex.Message}");
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
            MessageBox.Show(this, "Effettua prima il login iCloud.", "Octagon RK",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var rk = EscrowRecoveryKeyBox.Password;
        if (string.IsNullOrWhiteSpace(rk))
        {
            MessageBox.Show(this,
                "Inserisci la iCloud Recovery Key (XXXX-XXXX-…).",
                "Octagon RK", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = DecryptOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Seleziona una cartella output.", "Octagon RK",
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
                "(nessun RECOVER HSM / tentativo bottle).");
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
                    $"PCS ManateeCompact in sessione: {_session.PcsManateeCompactKeys?.Count ?? 0}");
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
            AppendDecryptLog($"Errore Octagon RK: {ex.Message}");
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
            MessageBox.Show(this, "Effettua prima il login iCloud.", "OTBottle / Peer",
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
                AppendDecryptLog($"Entropy ricaricata da disco ({_session.OctagonBottledPeerEntropy.Length} B)");
            }
            else
            {
                MessageBox.Show(this,
                    "Serve BottledPeerEntropy: esegui prima Unlock Octagon bottle.",
                    "OTBottle / Peer", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }
        }

        if (string.IsNullOrWhiteSpace(outputDir))
        {
            MessageBox.Show(this, "Seleziona una cartella output.", "OTBottle / Peer",
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
                "Avvio automatico CKKS OpenVault (Manatee + PCS + Passwords)…");
            var ckks = new CkksVaultService(Http, Orchestrator);
            var vault = await ckks.OpenViewsAsync(_session, outputDir, log: log)
                .ConfigureAwait(true);
            AppendDecryptLog(vault.Success ? $"CKKS: {vault.Message}" : $"CKKS FAIL: {vault.Message}");
            if (vault.PcsKeysFound > 0)
                AppendDecryptLog($"Manatee PCS keys in sessione: {vault.PcsKeysFound}");
            AppendDecryptLog("Export password (se view Passwords OK): ckks_passwords.csv");
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
            MessageBox.Show(this, "Effettua prima il login iCloud.", "CKKS OpenVault",
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
            MessageBox.Show(this, "Seleziona una cartella output (Escrow).", "CKKS OpenVault",
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
                AppendDecryptLog($"Peer enc ricaricata da disco ({_session.OctagonPeerEncryptionPkcs8.Length} B)");
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
                "Serve peer encryption + peerId: esegui prima OTBottle / Peer keys.",
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
                AppendDecryptLog($"Manatee PCS keys in sessione: {result.PcsKeysFound}");
            if (result.ItemsJsonPath is not null)
                AppendDecryptLog($"Items: {result.ItemsJsonPath}");
            var pwdCsv = Path.Combine(outputDir, "ckks_passwords.csv");
            if (File.Exists(pwdCsv))
                AppendDecryptLog($"Passwords CSV: {pwdCsv}");
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
            AppendDecryptLog($"Errore CKKS OpenVault: {ex.Message}");
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
            $"PCS KeySet in sessione: {_session.PcsEscrowedKeySet?.Length ?? 0} B ← {directory}");
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

        AppendDecryptLog("PCS KeySet non ancora in sessione — usa Unlock EscrowedKeys.");
    }

    private void AppendWhatsAppLog(string line) =>
        AppendBoundedLog(WhatsAppLogTextBox, line);

    private void BrowseWhatsAppOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            WhatsAppOutputTextBox.Text = dlg.FolderName;
    }

    private async void WhatsAppProbeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Effettua prima il login iCloud.", "WhatsApp CloudKit",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = WhatsAppOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Seleziona una cartella output.", "WhatsApp CloudKit",
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
                AppendWhatsAppLog($"iCSC vuoto → default DSID ({iCsc})");
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
                    ?? "PCS assente — Unlock EscrowedKeys oppure Octagon/CKKS OpenVault (Manatee).",
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
            AppendWhatsAppLog("Documents probe finito.");
            MessageBox.Show(this,
                $"Probe completato (solo valori live di questa run).\n" +
                $"CK: {ckResult.OutputDirectory}\n" +
                "Documents: cartella whatsapp_docs_* (artifact, non input).\n" +
                "Crypto: zone/retrieve + FetchRecords + KeySet PCS in sessione.",
                "WhatsApp CloudKit",
                MessageBoxButton.OK,
                MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            AppendWhatsAppLog($"Errore: {ex.Message}");
            MessageBox.Show(this, ex.Message, "WhatsApp CloudKit",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            WhatsAppProbeButton.IsEnabled = true;
        }
    }

    private void AppendICloudDriveLog(string line) =>
        AppendBoundedLog(ICloudDriveLogTextBox, line);

    private void BrowseICloudDriveOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            ICloudDriveOutputTextBox.Text = dlg.FolderName;
    }

    private async void ICloudDriveProbeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Effettua prima il login iCloud.", "iCloud Drive",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = ICloudDriveOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Seleziona una cartella output.", "iCloud Drive",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);

        try
        {
            ICloudDriveProbeButton.IsEnabled = false;
            ICloudDriveProgressBar.Value = 0;
            ICloudDriveStatusText.Text = "Avvio…";
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
                ICloudDriveStatusText.Text = "PCS assente";
                MessageBox.Show(this,
                    ensure.Message
                    ?? "PCS assente — Unlock EscrowedKeys oppure Octagon/CKKS OpenVault (Manatee).",
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
            ICloudDriveStatusText.Text = result.Success ? "Completato" : "Errore";
            AppendICloudDriveLog(
                $"Fine: zone={result.ZonesProcessed} record={result.RecordsFetched} → {result.OutputDirectory}");

            MessageBox.Show(this,
                result.Success
                    ? $"Download iCloud Drive completato.\n{result.OutputDirectory}\n" +
                      $"Zone: {result.ZonesProcessed}, record: {result.RecordsFetched}\n" +
                      "File decifrati in clouddocs_ck/fetch_*/crypto/plaintext/"
                    : result.Error ?? "Probe fallito.",
                "iCloud Drive",
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            AppendICloudDriveLog($"Errore: {ex.Message}");
            ICloudDriveStatusText.Text = "Errore";
            MessageBox.Show(this, ex.Message, "iCloud Drive",
                MessageBoxButton.OK, MessageBoxImage.Error);
        }
        finally
        {
            ICloudDriveProbeButton.IsEnabled = true;
        }
    }

    private void AppendICloudFilesLog(string line) =>
        AppendBoundedLog(ICloudFilesLogTextBox, line);

    private void BrowseICloudFilesOutput_Click(object sender, RoutedEventArgs e)
    {
        var dlg = new OpenFolderDialog();
        if (dlg.ShowDialog(this) == true)
            ICloudFilesOutputTextBox.Text = dlg.FolderName;
    }

    private async void ICloudFilesProbeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Effettua prima il login iCloud.", "iCloud Files",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = ICloudFilesOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Seleziona una cartella output.", "iCloud Files",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        Directory.CreateDirectory(outputDir);

        try
        {
            ICloudFilesProbeButton.IsEnabled = false;
            ICloudFilesProgressBar.Value = 0;
            ICloudFilesStatusText.Text = "Avvio…";
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
                ICloudFilesStatusText.Text = "PCS assente";
                MessageBox.Show(this,
                    ensure.Message
                    ?? "PCS assente — Unlock EscrowedKeys oppure Octagon/CKKS OpenVault (Manatee).",
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
            ICloudFilesStatusText.Text = result.Success ? "Completato" : "Errore";
            AppendICloudFilesLog(
                $"Fine: zone={result.ZonesProcessed} record={result.RecordsFetched} → {result.OutputDirectory}");

            MessageBox.Show(this,
                result.Success
                    ? $"Download iCloud Files completato.\n{result.OutputDirectory}\n" +
                      $"Zone: {result.ZonesProcessed}, record: {result.RecordsFetched}\n" +
                      "Manifest: icloud_files_manifest.json\n" +
                      "Plaintext: clouddocs_ck/fetch_*/crypto/plaintext/"
                    : result.Error ?? "Probe fallito.",
                "iCloud Files",
                MessageBoxButton.OK,
                result.Success ? MessageBoxImage.Information : MessageBoxImage.Warning);
        }
        catch (Exception ex)
        {
            AppendICloudFilesLog($"Errore: {ex.Message}");
            ICloudFilesStatusText.Text = "Errore";
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
            SyncDataOutputTextBox.Text = dlg.FolderName;
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
        AppendRichLogLine(box, line, bodyBrush);
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
            AppendSyncDataLog($"Copia log fallita: {ex.Message}");
        }
    }


    private async void SyncDataProbeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_session is null)
        {
            MessageBox.Show(this, "Effettua prima il login iCloud.", "iCloud Sync Data",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputDir = SyncDataOutputTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
            outputDir = OutputFolderTextBox.Text.Trim();
        if (string.IsNullOrEmpty(outputDir))
        {
            MessageBox.Show(this, "Seleziona una cartella output.", "iCloud Sync Data",
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
            SyncDataStatusText.Text = "Avvio…";
            AppendSyncDataLog($"Sync Data → {outputDir}");


            var pcsDir = DecryptOutputTextBox.Text.Trim();
            if (string.IsNullOrEmpty(pcsDir))
                pcsDir = outputDir;
            Directory.CreateDirectory(pcsDir);

            var iCsc = ResolveEscrowIcsc();
            if (string.IsNullOrEmpty(EscrowPasswordBox.Password.Trim()) && !string.IsNullOrEmpty(iCsc))
                AppendSyncDataLog($"iCSC vuoto → default DSID ({iCsc})");
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
                    "Seleziona almeno una categoria Sync Data (Photos / Account Info).",
                    "iCloud Sync Data",
                    MessageBoxButton.OK,
                    MessageBoxImage.Warning);
                return;
            }

            AppendSyncDataLog($"Categorie selezionate: {string.Join(", ", selected)}");
            var buildPhotosRecordMetadata = IsPhotosBuildRecordMetadataEnabled();
            if (selected.Any(static id =>
                    string.Equals(id, SyncDataCategoryCatalog.PhotosId, StringComparison.OrdinalIgnoreCase)))
            {
                AppendSyncDataLog(
                    buildPhotosRecordMetadata
                        ? "Photos: BuildRecordMetadata ON (nomi file PCS)"
                        : "Photos: BuildRecordMetadata OFF (solo crypto/Album/MMCS)");
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
                                ?? "PCS assente — Unlock EscrowedKeys oppure Octagon/CKKS OpenVault (Manatee).",
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
                AppendSyncDataLog("PCS — skip (categoria senza KeySet/Manatee)");
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
                AppendSyncDataLog($"Fatto: {ok}/{result.Containers.Count} container → {result.OutputDirectory}");
                if (!string.IsNullOrEmpty(result.RunLogPath))
                    AppendSyncDataLog($"Log run: {result.RunLogPath}");
                SyncDataProgressBar.Value = 100;
                SyncDataPhasePanel.Visibility = Visibility.Collapsed;
                SyncDataPhaseProgressBar.Value = 100;
                SyncDataStatusText.Text = result.Containers.Count == 0
                    ? $"Completato → {Path.GetFileName(result.OutputDirectory)}"
                    : $"Completato: {ok}/{result.Containers.Count} OK";
                MessageBox.Show(this,
                    $"Sync Data completato.\n{result.OutputDirectory}\n" +
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
                AppendSyncDataLog($"Errore: {ex.Message}");
                SyncDataProgressBar.IsIndeterminate = false;
                SyncDataStatusText.Text = $"Errore: {ex.Message}";
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
            ? $"Connesso — DSID {_session?.Dsid}"
            : "Non autenticato";

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
            SessionTokensTextBox.Text = "Effettua il login per vedere i token recuperati.";
            SessionServicesTextBox.Text = "Effettua il login per vedere i servizi disponibili.";
            if (CloudQuotaTextBox is not null)
                CloudQuotaTextBox.Text = "Effettua il login per caricare lo spazio iCloud.";
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
            services.AppendLine("(vuoto — SPD non ha popolato t, oppure login incompleto)");
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
            services.AppendLine("(nessun url — dataclass senza campo url/escrowProxyUrl)");
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
            services.AppendLine("(nessuna — get_account_settings non ha restituito com.apple.Dataclass.*)");
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
        CopyTextBoxToClipboard(SessionTokensTextBox, "Token sessione");

    private void CopySessionServicesButton_Click(object sender, RoutedEventArgs e) =>
        CopyTextBoxToClipboard(SessionServicesTextBox, "Servizi / dataclass");

    private void CopyCloudQuotaButton_Click(object sender, RoutedEventArgs e) =>
        CopyTextBoxToClipboard(CloudQuotaTextBox, "Dettagli Spazio Cloud");

    private void RefreshCloudQuotaButton_Click(object sender, RoutedEventArgs e) =>
        _ = RefreshCloudQuotaPanelAsync();

    private void CopyExploratoryServicesResult_Click(object sender, RoutedEventArgs e) =>
        CopyTextBoxToClipboard(ExploratoryServicesResultTextBox, "Risposta servizi");

    private void TrustedDevicesRefreshButton_Click(object sender, RoutedEventArgs e)
    {
        RefreshApsTokenLabel();
        if (_session is null)
        {
            if (TrustedDevicesResultTextBox is not null)
            {
                TrustedDevicesResultTextBox.Text =
                    "Login non effettuato.\n\n" +
                    $"APS cert: {(ApsStorage.HasCertificate() ? "OK" : "NO")}\n" +
                    $"Push token: {ApsSessionService.TryGetPushTokenHex() ?? "(assente)"}";
            }

            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "Stato APS (senza sessione iCloud).";
            return;
        }

        SyncIdmsaTrustFromSession(_session);
        var text = CreateTrustedDevicesService().FormatSessionTrustStatus(_session);
        if (TrustedDevicesResultTextBox is not null)
            TrustedDevicesResultTextBox.Text = text;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "Stato aggiornato dalla sessione corrente.";
        LogAuth("TrustedDevices: refresh stato OK.");
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
                    ? $"APS: OTP ricevuto ({e.ExtractedOtp})"
                    : "APS: notifica ricevuta";
        });
        return _apsSession;
    }

    private void AppendApsLog(string line)
    {
        if (TrustedDevicesResultTextBox is null)
            return;
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
            ? $"Push token APS: (assente) cert={(snap.HasCertificate ? "OK" : "NO")} connected={snap.IsConnected}"
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
            AppendApsLog("Albert errore: " + ex.Message);
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "Albert: errore";
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
            TrustedDevicesStatusText.Text = "Connessione APS…";
        try
        {
            var aps = GetApsSession();
            await Task.Run(async () => await aps.ConnectAsync().ConfigureAwait(false))
                .ConfigureAwait(true);
            RefreshApsTokenLabel();
            var snap = aps.Snapshot();
            AppendApsLog("APS connesso. Token=" + (snap.TokenHex.Length > 0 ? snap.TokenHex : "?"));
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "APS: connesso";
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
            AppendApsLog("APS connect errore: " + ex.Message);
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "APS: errore connect";
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
                TrustedDevicesStatusText.Text = "APS: disconnesso";
            AppendApsLog("APS disconnesso.");
        }
        catch (Exception ex)
        {
            AppendApsLog("APS disconnect: " + ex.Message);
        }
    }

    private async void Hsa2NewAdiButton_Click(object sender, RoutedEventArgs e)
    {
        var confirm = MessageBox.Show(this,
            "Cancella l’identità ADI attuale (device-iphone-coherent.json + sessione worker) " +
            "e ne crea una nuova via MidService.\n\n" +
            "Serve quando GSA non chiede più 2FA (ADI già trusted).\n" +
            "Non abusare: Apple può rispondere HTTP 433 / 'ptm'.\n\n" +
            "Continuo?",
            "Nuova identità ADI",
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
                    $"Nuova ADI creata ma GET / fallisce HTTP {(int)probe.StatusCode}: {TrimUiBody(probeBody)}");
            }

            AppendApsLog("HSA2: nuova ADI OK — " + TrimUiBody(body));
            if (TrustedDevicesResultTextBox is not null)
                TrustedDevicesResultTextBox.Text = body + Environment.NewLine + Environment.NewLine + probeBody;
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "ADI: nuova identità OK — ora Registra in lista 2FA";
            LogAuth("HSA2: newIdentity ADI OK.");
        }
        catch (Exception ex)
        {
            AppendApsLog("HSA2 newIdentity errore: " + ex.Message);
            if (TrustedDevicesResultTextBox is not null)
                TrustedDevicesResultTextBox.Text = ex.Message;
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "ADI: newIdentity fallita";
            LogAuth("HSA2 newIdentity: " + ex.Message);
            MessageBox.Show(this, ex.Message, "Nuova identità ADI",
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
                "Inserisci e-mail e password nei campi HSA2 di questa scheda.\n" +
                "Non vengono usati Apple ID/password della scheda Accesso (né PET di sessione).",
                "Lista 2FA", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var aps = GetApsSession();
        if (!aps.Snapshot().IsConnected)
        {
            MessageBox.Show(this,
                "Connetti APS e lascia la sessione attiva (ptkn nel CPD GSA).",
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
                ConfigureIdmsaOtpUi(begin.Verification);
                if (IdmsaOtpTitleText is not null)
                    IdmsaOtpTitleText.Text = "OTP HSA2 — codice dal dispositivo Apple già fidato";
                if (IdmsaOtpPanel is not null)
                    IdmsaOtpPanel.Visibility = Visibility.Visible;
                if (IdmsaOtpDeviceRadio is not null)
                    IdmsaOtpDeviceRadio.IsChecked = true;
                if (TrustedDevicesStatusText is not null)
                    TrustedDevicesStatusText.Text =
                        "HSA2: inserisci OTP dal tuo iPhone, poi Invia OTP";
                LogAuth("HSA2: in attesa OTP per lista 2FA.");
                return;
            }

            _hsa2PartialSession = null;
            if (begin.CompletedSession is not null)
                _session = begin.CompletedSession;
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "HSA2: nessun challenge (vedi log)";
        }
        catch (Exception ex)
        {
            AppendApsLog("HSA2 errore: " + ex.Message);
            if (TrustedDevicesResultTextBox is not null)
            {
                string logText;
                lock (log)
                    logText = log.ToString();
                TrustedDevicesResultTextBox.Text = logText + Environment.NewLine + ex.Message;
            }
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "HSA2: errore";
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
            MessageBox.Show(this, "Effettua prima il login iCloud (serve PET).", "Enroll IDS",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (string.IsNullOrWhiteSpace(ApsSessionService.TryGetPushTokenHex()))
        {
            MessageBox.Show(this,
                "Serve un push token APS.\nAttiva Albert → Connetti APS, poi riprova Enroll IDS.",
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
            LogAuth("IDS enroll completato.");
        }
        catch (Exception ex)
        {
            AppendApsLog("IDS enroll errore: " + ex.Message);
            if (TrustedDevicesResultTextBox is not null)
            {
                TrustedDevicesResultTextBox.Text =
                    ex.Message + Environment.NewLine + Environment.NewLine
                    + IdsStorage.FormatStatusSummary()
                    + Environment.NewLine + Environment.NewLine
                    + TrustedDevicesResultTextBox.Text;
            }

            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "IDS: errore";
            LogAuth("IDS enroll: " + ex.Message);
        }
        finally
        {
            if (IdsEnrollButton is not null)
                IdsEnrollButton.IsEnabled = true;
        }
    }

    private void ConfigureIdmsaOtpUi(PhoneVerificationOptions? options)
    {
        if (IdmsaOtpPhoneComboBox is null)
            return;

        var phones = options?.TrustedPhoneNumbers ?? _session?.TrustedPhoneNumbers
                     ?? Array.Empty<TrustedPhoneNumber>();
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

    private void IdmsaOtpMethodRadio_Changed(object sender, RoutedEventArgs e)
    {
        if (IdmsaOtpSmsPhonePanel is null || IdmsaOtpSmsRadio is null)
            return;
        var showSms = IdmsaOtpSmsRadio.IsChecked == true && IdmsaOtpSmsRadio.IsEnabled;
        IdmsaOtpSmsPhonePanel.Visibility = showSms ? Visibility.Visible : Visibility.Collapsed;
    }

    private void IdmsaOtpRequestSmsButton_Click(object sender, RoutedEventArgs e)
    {
        MessageBox.Show(this,
            "Per la lista 2FA usa il codice sul dispositivo Apple già fidato.\n" +
            "Avvia «Registra in lista 2FA», poi Invia OTP.",
            "Lista 2FA", MessageBoxButton.OK, MessageBoxImage.Information);
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
                "Manca l’Apple ID nei campi HSA2 di questa scheda.",
                "Lista 2FA", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (IdmsaOtpSubmitButton is not null)
            IdmsaOtpSubmitButton.IsEnabled = false;
        if (TrustedDevicesStatusText is not null)
            TrustedDevicesStatusText.Text = "HSA2: verifica OTP GSA…";

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

            var done = await Task.Run(async () =>
                    await svc.CompleteWithOtpAsync(appleId, code, partial, Log)
                        .ConfigureAwait(false))
                .ConfigureAwait(true);

            _session = done.Session;
            _hsa2PartialSession = null;
            if (IdmsaOtpPanel is not null)
                IdmsaOtpPanel.Visibility = Visibility.Collapsed;
            if (IdmsaOtpTitleText is not null)
                IdmsaOtpTitleText.Text = "OTP HSA2 — codice dal dispositivo Apple già fidato";

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
                TrustedDevicesStatusText.Text = "HSA2: OTP OK — controlla conteggio device sopra";
            LogAuth("HSA2: registrazione lista 2FA completata.");
        }
        catch (Exception ex)
        {
            AppendApsLog("HSA2 OTP errore: " + ex.Message);
            if (TrustedDevicesResultTextBox is not null)
            {
                string logText;
                lock (log)
                    logText = log.ToString();
                TrustedDevicesResultTextBox.Text = logText + Environment.NewLine + ex.Message;
            }
            if (TrustedDevicesStatusText is not null)
                TrustedDevicesStatusText.Text = "HSA2 OTP: errore";
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
            MessageBox.Show(this, "Inserisci il codice OTP.", "Lista 2FA",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (_hsa2PartialSession is not null)
        {
            await SubmitHsa2OtpAsync(code).ConfigureAwait(true);
            return;
        }

        MessageBox.Show(this,
            "Nessuna sessione HSA2 in attesa di OTP.\n" +
            "Avvia «Registra in lista 2FA» e attendi il challenge prima di Invia OTP.",
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
            MessageBox.Show(this, ex.Message, "Apertura link", MessageBoxButton.OK, MessageBoxImage.Warning);
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
                "Inserisci utente iCloud e password per le app.",
                "IMAP Posta", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        SetImapBusy(true, "Connessione IMAP…");
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
            SetImapBusy(false, $"Connesso a {host} come {user}");
            LogAuth($"IMAP: connesso {host} user={user}");
        }
        catch (Exception ex)
        {
            await ClearImapUiAsync().ConfigureAwait(true);
            SetImapBusy(false, "Errore connessione");
            ShowImapPreviewStatus($"Errore IMAP: {ex.Message}");
            MessageBox.Show(this, ex.Message, "IMAP Posta", MessageBoxButton.OK, MessageBoxImage.Warning);
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
        SetImapBusy(false, "Disconnesso.");
    }

    private async void ImapRefreshFoldersButton_Click(object sender, RoutedEventArgs e)
    {
        if (_imapMail is not { IsConnected: true })
            return;
        SetImapBusy(true, "Aggiornamento cartelle…");
        try
        {
            _imapCts?.Cancel();
            _imapCts = new CancellationTokenSource();
            await ReloadImapFoldersAsync(_imapCts.Token).ConfigureAwait(true);
            SetImapBusy(false, "Cartelle aggiornate.");
        }
        catch (Exception ex)
        {
            SetImapBusy(false, "Errore cartelle");
            MessageBox.Show(this, ex.Message, "IMAP Posta", MessageBoxButton.OK, MessageBoxImage.Warning);
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
        ShowImapPreviewStatus("Seleziona una cartella.");
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
            ImapMessagesHeaderText.Text = $"Messaggi (filtro: {f.Describe()})";
        else
            ImapMessagesHeaderText.Text = "Messaggi (ultimi 100)";
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
            ? $"Carico {folder}…"
            : $"Cerco in {folder}…";
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
                    ? (filter is null ? "(cartella vuota)" : "(nessun messaggio con questi filtri)")
                    : "Seleziona un messaggio.");

            UpdateImapMessagesHeader();
            var status = filter is null
                ? $"{folder}: {rows.Count} messaggi"
                : $"{folder}: {rows.Count} risultati ({filter.Describe()})";
            SetImapBusy(false, status);
        }
        catch (OperationCanceledException)
        {
            SetImapBusy(false, "Annullato.");
        }
        catch (Exception ex)
        {
            SetImapBusy(false, "Errore elenco");
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

        SetImapBusy(true, "Scarico messaggio…");
        _imapCts?.Cancel();
        _imapCts = new CancellationTokenSource();
        try
        {
            var body = await _imapMail.FetchMessageAsync(_imapSelectedFolder, row.Uid, _imapCts.Token)
                .ConfigureAwait(true);
            ShowImapHtmlDocument(body.HtmlDocument);
            SetImapBusy(false,
                body.IsHtml ? "Messaggio HTML (sola lettura)." : "Messaggio testo (sola lettura).");
        }
        catch (OperationCanceledException)
        {
            SetImapBusy(false, "Annullato.");
        }
        catch (Exception ex)
        {
            SetImapBusy(false, "Errore messaggio");
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
                    ImapMailClient.BuildStatusHtmlDocument("Anteprima non disponibile: " + ex.Message));
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
            Title = "Cartella di destinazione per l’export posta (.eml)",
        };
        var hint = OutputFolderTextBox?.Text?.Trim();
        if (!string.IsNullOrWhiteSpace(hint) && Directory.Exists(hint))
            dlg.InitialDirectory = hint;
        else
        {
            dlg.InitialDirectory = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "iCloudBackups");
        }

        return dlg.ShowDialog(this) == true ? dlg.FolderName : null;
    }

    private async void ImapExportSelectedButton_Click(object sender, RoutedEventArgs e)
    {
        if (_imapMail is not { IsConnected: true })
            return;
        if (string.IsNullOrWhiteSpace(_imapSelectedFolder))
        {
            MessageBox.Show(this, "Seleziona prima una cartella IMAP.", "IMAP Posta",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        if (ImapMessagesGrid?.SelectedItem is not ImapMessageRowVm row)
        {
            MessageBox.Show(this, "Seleziona un messaggio da esportare.", "IMAP Posta",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var parent = PickImapExportParentDirectory();
        if (parent is null)
            return;

        await RunImapExportAsync(
            "Esporto messaggio…",
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
            MessageBox.Show(this, "Seleziona prima una cartella IMAP.", "IMAP Posta",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var parent = PickImapExportParentDirectory();
        if (parent is null)
            return;

        var folder = _imapSelectedFolder!;
        var filter = _imapFilter is { IsEmpty: false } ? _imapFilter : null;
        var label = filter is null
            ? $"Esporto cartella {folder}…"
            : $"Esporto cartella {folder} (filtro)…";
        await RunImapExportAsync(
            label,
            async (client, progress, ct) =>
            {
                progress.Report($"Elenco UID {folder}…");
                var uids = await client.ListAllUidsAsync(folder, filter, ct).ConfigureAwait(true);
                if (uids.Count == 0)
                {
                    throw new InvalidOperationException(
                        filter is null
                            ? $"La cartella «{folder}» non contiene messaggi."
                            : $"Nessun messaggio in «{folder}» con i filtri attivi.");
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
            ? "Esportare tutti i messaggi di tutte le cartelle IMAP?\n" +
              "Può richiedere molto tempo su caselle grandi."
            : "Esportare da tutte le cartelle solo i messaggi che rispettano i filtri attivi?\n" +
              $"Filtro: {filter.Describe()}";
        var confirm = MessageBox.Show(this, confirmMsg, "IMAP Posta",
            MessageBoxButton.YesNo, MessageBoxImage.Question);
        if (confirm != MessageBoxResult.Yes)
            return;

        var parent = PickImapExportParentDirectory();
        if (parent is null)
            return;

        await RunImapExportAsync(
            filter is null ? "Esporto tutte le cartelle…" : "Esporto tutte le cartelle (filtro)…",
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
                $"Esportati {result.Written} messaggi (.eml)" +
                (result.Failed > 0 ? $"\nFalliti: {result.Failed}" : "") +
                $"\n\n{result.RootDirectory}",
                "IMAP Posta",
                MessageBoxButton.OK,
                result.Failed > 0 ? MessageBoxImage.Warning : MessageBoxImage.Information);
        }
        catch (OperationCanceledException)
        {
            SetImapBusy(false, "Export annullato.");
        }
        catch (Exception ex)
        {
            SetImapBusy(false, "Errore export");
            MessageBox.Show(this, ex.Message, "IMAP Posta", MessageBoxButton.OK, MessageBoxImage.Warning);
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
        ShowImapPreviewStatus("Seleziona un messaggio per leggere il corpo (sola lettura).");
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
            MessageBox.Show(this, "Effettua prima il login iCloud.", "Find My Items",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var hasEscrow = _session.PcsEscrowedKeySet is { Length: > 32 };
        var hasManatee = _session.PcsManateeCompactKeys is { Count: > 0 };
        if (!hasEscrow && !hasManatee)
        {
            MessageBox.Show(this,
                "Serve PCS Manatee/Escrow: «Unlock EscrowedKeys» e/o «CKKS OpenVault».\n" +
                "Poi riprova Find My Items.",
                "Find My Items", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        HideContactsExplorer();
        _contactsSnapshot = null;
        ClearFindMyDevicesGrid();

        if (FindMyItemsQueryButton is not null)
            FindMyItemsQueryButton.IsEnabled = false;
        if (ExploratoryServicesStatusText is not null)
            ExploratoryServicesStatusText.Text = "FindMyItems: richiesta in corso…";
        if (ExploratoryServicesResultTextBox is not null)
            ExploratoryServicesResultTextBox.Text = "Caricamento FindMyItems…";

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
                    $"FindMyItems: OK — {result.Devices.Count} dispositivi " +
                    $"({result.LogText.Length:N0} car. log)";
            }

            LogAuth($"FindMyItems: OK, devices={result.Devices.Count}, out={result.OutputDirectory}");
        }
        catch (Exception ex)
        {
            ClearFindMyDevicesGrid();
            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = $"Errore FindMyItems: {ex.Message}";
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = "FindMyItems: errore";
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
            MessageBox.Show(this, "Effettua prima il login iCloud.", "Servizi iCloud",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (ContactsQueryButton is not null)
            ContactsQueryButton.IsEnabled = false;
        if (ExploratoryServicesStatusText is not null)
            ExploratoryServicesStatusText.Text = "Contacts: richiesta in corso…";
        if (ExploratoryServicesResultTextBox is not null)
            ExploratoryServicesResultTextBox.Text = "Caricamento Contacts…";
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
                    $"Contacts: OK — {snap.Contacts.Count} contatto/i";
            PopulateContactsExplorer(snap);
            LogAuth($"Contacts: query OK ({snap.Contacts.Count}).");
        }
        catch (Exception ex)
        {
            _contactsSnapshot = null;
            HideContactsExplorer();
            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = $"Errore Contacts: {ex.Message}";
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = "Contacts: errore";
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
            ContactsVcardTextBox.Text = "vCard del contatto selezionato…";
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
            ContactsVcardTextBox.Text = "vCard del contatto selezionato…";
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
                    $"Contacts: vCard OK ({vcard.Length:N0} caratteri)";
            LogAuth($"Contacts: vCard OK {contact.Href}");
        }
        catch (Exception ex)
        {
            if (ContactsVcardTextBox is not null)
                ContactsVcardTextBox.Text = $"Errore vCard: {ex.Message}";
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = "Contacts: errore vCard";
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
            ExploratoryServicesStatusText.Text = $"Contacts: GET foto «{contact}»…";

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
                    $"Contacts: foto OK ({bytes.Length:N0} byte, {contentType})";
            LogAuth($"Contacts: foto OK {bytes.Length} byte");
        }
        catch (Exception ex)
        {
            if (ContactsPhotoImage is not null)
                ContactsPhotoImage.Source = null;
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = $"Contacts: errore foto — {ex.Message}";
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
            MessageBox.Show(this, "Effettua prima il login iCloud.", "Servizi iCloud",
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
            ExploratoryServicesStatusText.Text = $"{serviceName}: richiesta in corso…";
        if (ExploratoryServicesResultTextBox is not null)
            ExploratoryServicesResultTextBox.Text = $"Caricamento {serviceName}…";

        try
        {
            var session = _session;
            var text = await Task.Run(async () =>
                await query(session).ConfigureAwait(false)).ConfigureAwait(true);
            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = text;
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = $"{serviceName}: OK ({text.Length:N0} caratteri)";
            LogAuth($"{serviceName}: query OK.");
        }
        catch (Exception ex)
        {
            if (ExploratoryServicesResultTextBox is not null)
                ExploratoryServicesResultTextBox.Text = $"Errore {serviceName}: {ex.Message}";
            if (ExploratoryServicesStatusText is not null)
                ExploratoryServicesStatusText.Text = $"{serviceName}: errore";
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
            CloudQuotaTextBox.Text = "Effettua il login per caricare lo spazio iCloud.";
            return;
        }

        var gen = Interlocked.Increment(ref _cloudQuotaFetchGen);
        CloudQuotaTextBox.Text = "Caricamento spazio iCloud…";
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
            LogAuth("Quota iCloud: dettagli spazio aggiornati.");
        }
        catch (Exception ex)
        {
            if (gen != Volatile.Read(ref _cloudQuotaFetchGen))
                return;
            CloudQuotaTextBox.Text = $"Errore Quota: {ex.Message}";
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
            LogAuth($"{label}: copiati negli appunti ({text.Length} caratteri).");
        }
        catch (Exception ex)
        {
            LogAuth($"{label}: copia fallita — {ex.Message}");
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
                "Servizi Sync Data — effettua il login per caricare le dataclass disponibili.";
            SyncDataPhotosOptionsPanel.Visibility = Visibility.Collapsed;
            return;
        }

        // Elenco completo: solo Photos + Account Info selezionabili; resto «(presto)».
        SyncDataServicesHintText.Text =
            "Attivi: Photos, Account Info, Voice Memos; le altre sono in arrivo (presto).";

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
                    : "Recupero non ancora implementato (presto)"
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

                MessageBox.Show(this, "Inserisci Apple ID e password.", "Accesso", MessageBoxButton.OK, MessageBoxImage.Warning);

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

                MessageBox.Show(this, ex.Message, "Verifica a due fattori", MessageBoxButton.OK, MessageBoxImage.Information);

            }

        }

        catch (Exception ex)

        {

            LogAuth($"Errore: {ex.Message}");

            MessageBox.Show(this, ex.Message, "Accesso", MessageBoxButton.OK, MessageBoxImage.Error);

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

            MessageBox.Show(this, "Esegui prima il login.", "2FA", MessageBoxButton.OK, MessageBoxImage.Warning);

            return;

        }



        var code = TwoFactorCodeTextBox.Text.Trim();

        if (code.Length < 6)

        {

            MessageBox.Show(this, "Inserisci il codice a 6 cifre.", "2FA", MessageBoxButton.OK, MessageBoxImage.Warning);

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

            LogAuth("2FA completata.");
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

                $"Autenticazione riuscita, ma l'inizializzazione CloudKit è fallita:\n{ex.Message}",

                "CloudKit",

                MessageBoxButton.OK,

                MessageBoxImage.Warning);
            ApplyUiWizardStage(UiWizardStage.AfterLogin);

        }

        catch (Exception ex)

        {

            LogAuth($"2FA fallita: {ex.Message}");

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
            MessageBox.Show(this, "Autenticati prima di elencare i backup.", "Backup", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        _backupListBusy = true;
        _backupPropertiesReady = false;
        RefreshBackupsButton.IsEnabled = false;
        UpdateDownloadButtonState();

        // Tempo: parte subito su Aggiorna (lista + backupProperties), non al download.
        StartDownloadTiming();
        _lastDownloadProgressStatus = "Recupero elenco snapshot…";
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

            SaveSessionSnapshot("backup_list_ok", $"{_devices.Count} dispositivi");
            AppendDownloadLog($"Trovati {_devices.Count} dispositivi con backup.");

            // Decrypt PCS di backupProperties: attende il fine e solo dopo riabilita Scarica.
            var needsProps = _devices.SelectMany(d => d.Snapshots)
                .Any(s => s.BackupPropertiesCiphertext is { Length: > 16 });
            if (needsProps)
            {
                _lastDownloadProgressStatus = "Decifratura campi snapshot in corso…";
                DownloadStatusText.Text = _lastDownloadProgressStatus;
                AppendDownloadLog("Decrypt backupProperties in corso…");
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
            var deviceWord = _devices.Count == 1 ? "dispositivo" : "dispositivi";
            _lastDownloadProgressStatus =
                $"Elenco pronto ({_devices.Count} {deviceWord}, {snapCount} snapshot)";
            DownloadStatusText.Text = _lastDownloadProgressStatus;
        }
        catch (Exception ex)
        {
            SaveSessionSnapshot("backup_list_failed", ex.Message);
            AppendDownloadLog($"Errore elenco backup: {ex.Message}");
            // #region agent log
            AgentListLog("H-HANG3", "refresh_backups_exception", new { err = ex.GetType().Name, msg = ex.Message });
            // #endregion
            MessageBox.Show(this, ex.Message, "Backup", MessageBoxButton.OK, MessageBoxImage.Error);
            _backupPropertiesReady = false;
            _lastDownloadProgressStatus = "Elenco fallito";
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
            ? "Scarica backup (catena)"
            : "Scarica snapshot selezionato";
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
            _uiBytesProgressLogCount = 0;
        }

        if (r.ReportSequence > 0)
        {
            // ReportFilesDoneProgress: cumulativo ufficiale del job corrente.
            _timingBytesDone = Math.Max(0L, r.BytesDownloaded);
            if (r.TotalBytes > 0)
                _timingBytesTotal = r.TotalBytes;
        }
        else
        {
            // Report “leggeri” (solo Status): non regredire.
            if (r.BytesDownloaded > _timingBytesDone)
                _timingBytesDone = r.BytesDownloaded;
            if (r.TotalBytes > _timingBytesTotal)
                _timingBytesTotal = r.TotalBytes;
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
            DecryptQueueText.Text = $"Coda decrypt: {r.DecryptQueued:N0}";
            PendingChunksText.Text = $"Pending: {r.FilesPendingChunks:N0}";
            DuplicatedFilesText.Text = $"Duplicati: {duplicated:N0}";
            CiphertextFilesText.Text = $"Cifrati: {ciphertextSaved:N0}";
            DecryptFailedText.Text = $"Falliti decrypt: {decryptFailed:N0}";

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
                $"{snapPrefix}{successDone:N0} / {filesTotal:N0} file decifrati";
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
        status.Contains("Decifratura campi", StringComparison.OrdinalIgnoreCase)
        || status.Contains("backupProperties", StringComparison.OrdinalIgnoreCase)
        || status.Contains("Decrypt backupProperties", StringComparison.OrdinalIgnoreCase);

    private void StartDownloadTiming()
    {
        _backupDownloadStartedUtc = DateTime.UtcNow;
        _timingFilesDone = 0;
        _timingFilesTotal = 0;
        _timingBytesDone = 0;
        _timingBytesTotal = 0;
        _uiBytesProgressLogCount = 0;
        _uiLastBytesSnapshotLabel = null;
        DownloadElapsedText.Text = "Tempo: 0:00";
        DownloadBytesText.Text = "Dati: — / —";

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
        DownloadElapsedText.Text = $"Tempo: {FormatDownloadDuration(elapsed)}";

        var bytesDone = Math.Max(0L, _timingBytesDone);
        var bytesTotal = Math.Max(0L, _timingBytesTotal);
        // Niente estrapolazione file-ratio in UI: il totale arriva da Snapshot.SizeBytes
        // (ReportFilesDoneProgress). Gonfiava 9GB → decine di GB.

        var scaleIdx = DownloadBytesScaleCombo?.SelectedIndex ?? 0;
        var text = FormatDownloadBytesProgress(bytesDone, bytesTotal, scaleIdx);
        DownloadBytesText.Text = text;

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
                ? $"Dati: — / — {unit.Name}"
                : $"Dati: {Fmt(done)} / — {unit.Name}";

        return $"Dati: {Fmt(done)} / {Fmt(total)} {unit.Name}";
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

        if (dlg.ShowDialog() == true)

            OutputFolderTextBox.Text = dlg.FolderName;

    }

    private void CopyDownloadLog_Click(object sender, RoutedEventArgs e)
    {
        var (active, label) = DownloadLogTabs.SelectedIndex switch
        {
            1 => (DownloadWarningLogBox, "avvisi"),
            2 => (DownloadErrorLogBox, "errori"),
            _ => (DownloadInfoLogBox, "informazioni"),
        };
        var text = GetRichTextPlain(active);
        if (string.IsNullOrEmpty(text))
        {
            FlashDownloadStatusThenRestore("Log vuoto");
            return;
        }

        try
        {
            Clipboard.SetText(text);
            FlashDownloadStatusThenRestore($"Log {label} copiato negli appunti");
        }
        catch (Exception ex)
        {
            FlashDownloadStatusThenRestore($"Copia log fallita: {ex.Message}");
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

            MessageBox.Show(this, "Sessione non attiva.", "Download", MessageBoxButton.OK, MessageBoxImage.Warning);

            return;

        }



        if (DevicesGrid.SelectedItem is not BackupDevice device || device.Snapshots.Count == 0)
        {
            MessageBox.Show(this, "Seleziona un dispositivo con almeno uno snapshot.", "Download", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (SnapshotsGrid.SelectedItem is not BackupSnapshot selectedSnapshot)
        {
            MessageBox.Show(this, "Seleziona uno snapshot da scaricare.", "Download", MessageBoxButton.OK, MessageBoxImage.Warning);
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
            MessageBox.Show(this, "Nessuno snapshot da scaricare.", "Download", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        var outputRoot = OutputFolderTextBox.Text.Trim();
        AppendDownloadLog(
            chainAll
                ? $"Catena snapshot: {snapshotsToDownload.Count} (dal più vecchio al più recente)"
                : $"Snapshot singolo: {selectedSnapshot.DateLabel} ({selectedSnapshot.ShortUuid})");

        try
        {
            _downloadBusy = true;
            DownloadButton.IsEnabled = false;
            DownloadProgressBar.Value = 0;
            DownloadFilesProgressBar.Value = 0;
            DecryptFilesProgressBar.Value = 0;
            DownloadFilesCountText.Text = "0 / 0";
            DecryptFilesCountText.Text = "0 / 0";
            DecryptQueueText.Text = "Coda decrypt: 0";
            PendingChunksText.Text = "Pending: 0";
            DuplicatedFilesText.Text = "Duplicati: 0";
            CiphertextFilesText.Text = "Cifrati: 0";
            DecryptFailedText.Text = "Falliti decrypt: 0";
            StartDownloadTiming();
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
                AppendDownloadLog($"iCSC vuoto → default DSID ({iCsc})");
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
                            $"PCS KeySet: assente — {ensure.Message} (download prosegue; MMCS decrypt skip)");
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
                            _uiBytesProgressLogCount = 0;
                            _uiLastBytesSnapshotLabel = null;
                            DownloadBytesText.Text = FormatDownloadBytesProgress(
                                0, declared, DownloadBytesScaleCombo?.SelectedIndex ?? 0);
                            DownloadFilesCountText.Text = "0 / 0";
                            DecryptFilesCountText.Text = "0 / 0";
                            DecryptQueueText.Text = "Coda decrypt: 0";
                            PendingChunksText.Text = "Pending: 0";
                            DuplicatedFilesText.Text = "Duplicati: 0";
                            CiphertextFilesText.Text = "Cifrati: 0";
                            DecryptFailedText.Text = "Falliti decrypt: 0";
                            _lastDownloadProgressStatus =
                                $"Snapshot {i + 1}/{snapshotsToDownload.Count}: preparazione…";
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
                            $"── Completato {i + 1}/{snapshotsToDownload.Count}: {snap.ShortUuid}");
                    }
                }).ConfigureAwait(false);

            var summary = completedDirs.Count == 1
                ? $"Download salvato in {completedDirs[0]}"
                : $"Catena completata: {completedDirs.Count} snapshot sotto {outputRoot}";
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
                AppendDownloadLog($"Errore: {shown.GetType().Name}: {shown.Message}");
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
            MessageBox.Show(this, "Esegui prima il login.", "2FA SMS", MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }

        if (SmsPhoneComboBox.SelectedItem is not TrustedPhoneNumber phone)
        {
            MessageBox.Show(this, "Nessun numero SMS disponibile per questo account.", "2FA SMS",
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
            MessageBox.Show(this, $"Codice SMS inviato a {phone.DisplayLabel}.", "2FA SMS",
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

