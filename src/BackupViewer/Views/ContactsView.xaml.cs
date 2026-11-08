using System.Windows.Controls;
using BackupViewer.Models;
using BackupViewer.Services;

namespace BackupViewer.Views;

public partial class ContactsView : UserControl
{
    private IReadOnlyList<ContactRecord> _all = [];

    public ContactsView()
    {
        InitializeComponent();
    }

    public void Bind(CoreDataService core)
    {
        _all = core.Snapshot.Contacts;
        ApplySearch("");
        if (ContactList.Items.Count > 0)
            ContactList.SelectedIndex = 0;
    }

    public void ApplySearch(string query)
    {
        query ??= "";
        IEnumerable<ContactRecord> q = _all;
        if (!string.IsNullOrWhiteSpace(query))
        {
            q = q.Where(c =>
                c.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase)
                || (c.Organization?.Contains(query, StringComparison.OrdinalIgnoreCase) ?? false)
                || c.Phones.Any(p => p.Value.Contains(query, StringComparison.OrdinalIgnoreCase))
                || c.Emails.Any(p => p.Value.Contains(query, StringComparison.OrdinalIgnoreCase)));
        }

        var list = q
            .OrderBy(static c => c.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
        ContactList.ItemsSource = list;
        ListHeader.Text = $"CONTATTI · {list.Count:N0}";
    }

    private void ContactList_OnSelectionChanged(object sender, SelectionChangedEventArgs e)
    {
        if (ContactList.SelectedItem is not ContactRecord c)
            return;
        NameText.Text = c.DisplayName;
        OrgText.Text = c.Organization ?? "";
        JobText.Text = c.JobTitle ?? "";
        PhoneList.ItemsSource = c.Phones;
        EmailList.ItemsSource = c.Emails;
        OtherList.ItemsSource = c.Other;
        NoteText.Text = c.Note ?? "";
    }
}
