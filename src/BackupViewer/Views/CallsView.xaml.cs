using System.Windows.Controls;
using BackupViewer.Models;
using BackupViewer.Services;

namespace BackupViewer.Views;

public partial class CallsView : UserControl
{
    private IReadOnlyList<CallRecord> _all = [];
    private string _search = "";

    public CallsView()
    {
        InitializeComponent();
    }

    public void Bind(CoreDataService core)
    {
        _all = core.Snapshot.Calls;
        var apps = _all.Select(static c => c.App).Distinct(StringComparer.OrdinalIgnoreCase)
            .OrderBy(static a => a).ToList();
        AppFilter.Items.Clear();
        AppFilter.Items.Add(new ComboBoxItem { Content = "Tutte", Tag = "", IsSelected = true });
        foreach (var app in apps)
            AppFilter.Items.Add(new ComboBoxItem { Content = app, Tag = app });
        ApplyFilter();
    }

    public void ApplySearch(string query)
    {
        _search = query ?? "";
        ApplyFilter();
    }

    private void Filter_OnChanged(object sender, SelectionChangedEventArgs e)
    {
        if (!IsLoaded || CallList is null || EmptyLabel is null)
            return;
        ApplyFilter();
    }

    private void ApplyFilter()
    {
        if (CallList is null || EmptyLabel is null)
            return;

        IEnumerable<CallRecord> q = _all;
        if (AppFilter.SelectedItem is ComboBoxItem appItem
            && appItem.Tag is string app
            && !string.IsNullOrWhiteSpace(app))
            q = q.Where(c => string.Equals(c.App, app, StringComparison.OrdinalIgnoreCase));

        if (OutcomeFilter.SelectedItem is ComboBoxItem outItem
            && outItem.Tag is string outcome
            && Enum.TryParse<CallOutcome>(outcome, out var oc))
            q = q.Where(c => c.Outcome == oc);

        if (!string.IsNullOrWhiteSpace(_search))
            q = q.Where(c =>
                c.Peer.Contains(_search, StringComparison.OrdinalIgnoreCase)
                || c.App.Contains(_search, StringComparison.OrdinalIgnoreCase));

        var list = q.ToList();
        CallList.ItemsSource = list;
        EmptyLabel.Text = list.Count == 0
            ? "Nessuna chiamata con i filtri correnti."
            : $"{list.Count:N0} chiamate";
    }
}
