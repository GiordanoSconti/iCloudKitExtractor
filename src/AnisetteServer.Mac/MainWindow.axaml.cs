using AnisetteServer.Mac.Services;
using Avalonia.Controls;
using Avalonia.Interactivity;
using Avalonia.Threading;
using iCloudKitExtractor.AnisetteLicense;

namespace AnisetteServer.Mac;

public partial class MainWindow : Window
{
    private readonly MiddlewareHost _host = new();
    private MiddlewareSettings _settings = MiddlewareSettings.Load();

    public MainWindow()
    {
        InitializeComponent();
        _host.Changed += () => Dispatcher.UIThread.Post(RefreshStatus);
        LoadSettingsIntoUi();
        RefreshStatus();
        RefreshLicenses();
    }

    private void LoadSettingsIntoUi()
    {
        FridaHostBox.Text = _settings.FridaHost;
        FridaProcessBox.Text = _settings.FridaProcess;
        PythonBox.Text = _settings.Python;
        FetchScriptBox.Text = _settings.FetchScript ?? "";
        LiteCheck.IsChecked = _settings.Lite;
        TimeoutBox.Value = _settings.TimeoutSec;
        ListenBox.Text = _settings.ListenUrls;
        DataRootBox.Text = string.IsNullOrWhiteSpace(_settings.DataRoot)
            ? MiddlewareSettings.DefaultDataRoot()
            : _settings.DataRoot;
    }

    private void CaptureSettingsFromUi()
    {
        _settings.FridaHost = FridaHostBox.Text?.Trim() ?? "";
        _settings.FridaProcess = FridaProcessBox.Text?.Trim() ?? "akd";
        _settings.Python = PythonBox.Text?.Trim() ?? "python3";
        _settings.FetchScript = string.IsNullOrWhiteSpace(FetchScriptBox.Text) ? null : FetchScriptBox.Text.Trim();
        _settings.Lite = LiteCheck.IsChecked == true;
        _settings.TimeoutSec = (int)(TimeoutBox.Value ?? 60);
        _settings.ListenUrls = ListenBox.Text?.Trim() ?? "http://0.0.0.0:6971";
        _settings.DataRoot = DataRootBox.Text?.Trim();
    }

    private void RefreshStatus()
    {
        StatusText.Text = _host.StatusText;
        MintText.Text = _host.LastMintSummary;
        ErrorText.Text = _host.LastError;
        StartBtn.IsEnabled = !_host.IsRunning;
        StopBtn.IsEnabled = _host.IsRunning;
    }

    private async void StartBtn_OnClick(object? sender, RoutedEventArgs e)
    {
        try
        {
            CaptureSettingsFromUi();
            await _host.StartAsync(_settings);
            RefreshLicenses();
        }
        catch (Exception ex)
        {
            ErrorText.Text = ex.Message;
        }
        RefreshStatus();
    }

    private async void StopBtn_OnClick(object? sender, RoutedEventArgs e)
    {
        await _host.StopAsync();
        RefreshStatus();
    }

    private void SaveBtn_OnClick(object? sender, RoutedEventArgs e)
    {
        CaptureSettingsFromUi();
        _settings.EnsureKeys();
        _settings.Save();
        StatusText.Text = "Config saved · " + MiddlewareSettings.DefaultConfigPath();
    }

    private void RefreshLicenses_OnClick(object? sender, RoutedEventArgs e) => RefreshLicenses();

    private void RefreshLicenses()
    {
        try
        {
            CaptureSettingsFromUi();
            _settings.ApplyToEnvironment();
            using var db = new LicenseDatabase(LicensePaths.DatabasePath);
            _licenseRows = db.ListAll().ToList();
            LicenseList.ItemsSource = _licenseRows
                .Select(FormatRow)
                .ToList();
        }
        catch (Exception ex)
        {
            ErrorText.Text = ex.Message;
        }
    }

    private List<LicenseRow> _licenseRows = new();

    private static string FormatRow(LicenseRow r)
    {
        var status = !string.IsNullOrEmpty(r.RevokedAt)
            ? "REVOKED"
            : (r.Enabled ? "ON" : "OFF");
        var fp = string.IsNullOrEmpty(r.Fingerprint) ? "-" : Truncate(r.Fingerprint, 16);
        return $"{r.LicenseId[..8]}…  {r.Subject}  ip={r.ClientIp ?? "-"}  fp={fp}  emitted={r.EmittedOnce}  [{status}]";
    }

    private static string Truncate(string s, int n) => s.Length <= n ? s : s[..n] + "…";

    private LicenseRow? SelectedRow()
    {
        var i = LicenseList.SelectedIndex;
        if (i < 0 || i >= _licenseRows.Count)
            return null;
        return _licenseRows[i];
    }

    private void DisableLicense_OnClick(object? sender, RoutedEventArgs e) =>
        MutateSelected((db, id) => db.SetEnabled(id, false));

    private void EnableLicense_OnClick(object? sender, RoutedEventArgs e) =>
        MutateSelected((db, id) => db.SetEnabled(id, true));

    private void DeleteLicense_OnClick(object? sender, RoutedEventArgs e) =>
        MutateSelected((db, id) => db.Delete(id));

    private void MutateSelected(Func<LicenseDatabase, string, bool> action)
    {
        var row = SelectedRow();
        if (row is null)
            return;
        CaptureSettingsFromUi();
        _settings.ApplyToEnvironment();
        using var db = new LicenseDatabase(LicensePaths.DatabasePath);
        action(db, row.LicenseId);
        RefreshLicenses();
    }

    private void IssueManual_OnClick(object? sender, RoutedEventArgs e)
    {
        var sub = ManualSubBox.Text?.Trim();
        if (string.IsNullOrWhiteSpace(sub))
        {
            ErrorText.Text = "Subject required";
            return;
        }

        CaptureSettingsFromUi();
        _settings.EnsureKeys();
        using var db = new LicenseDatabase(LicensePaths.DatabasePath);
        var issuer = new LicenseIssuer(
            LicensePaths.PrivateKeyPath,
            LicensePaths.PublicKeyPath,
            db);
        var daysVal = (int)(ManualDaysBox.Value ?? 0);
        int? days = daysVal <= 0 ? null : daysVal;
        issuer.IssueManual(
            sub,
            days,
            note: "manual (Mac UI)",
            fingerprint: string.IsNullOrWhiteSpace(ManualFpBox.Text) ? null : ManualFpBox.Text.Trim(),
            clientIp: null,
            out _,
            out var bundle);
        IssuedBundleBox.Text = bundle;
        RefreshLicenses();
    }

    private void CopyBundle_OnClick(object? sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(IssuedBundleBox.Text))
            return;
        IssuedBundleBox.Focus();
        IssuedBundleBox.SelectionStart = 0;
        IssuedBundleBox.SelectionEnd = IssuedBundleBox.Text?.Length ?? 0;
    }

    protected override async void OnClosed(EventArgs e)
    {
        await _host.DisposeAsync();
        base.OnClosed(e);
    }
}
