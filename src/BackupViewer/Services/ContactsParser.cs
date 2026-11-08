using BackupViewer.Models;
using Microsoft.Data.Sqlite;

namespace BackupViewer.Services;

public static class ContactsParser
{
    // CNContact property IDs commonly used in AddressBook.sqlitedb
    private const int PropPhone = 3;
    private const int PropEmail = 4;

    public static IReadOnlyList<ContactRecord> Parse(string dbPath)
    {
        using var con = SqliteOpen.OpenReadonly(dbPath);
        if (!SqliteOpen.TableExists(con, "ABPerson"))
            return [];

        var labels = LoadLabels(con);
        var fields = LoadFields(con, labels);

        var list = new List<ContactRecord>();
        using var cmd = con.CreateCommand();
        cmd.CommandText =
            """
            SELECT ROWID, First, Last, Middle, Organization, JobTitle, Note,
                   Nickname, DisplayName, Birthday, ModificationDate
            FROM ABPerson;
            """;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var id = r.GetInt64(0);
            var first = GetStr(r, 1);
            var last = GetStr(r, 2);
            var middle = GetStr(r, 3);
            var org = GetStr(r, 4);
            var job = GetStr(r, 5);
            var note = GetStr(r, 6);
            var nick = GetStr(r, 7);
            var display = GetStr(r, 8);
            var birthday = ParseBirthday(GetStr(r, 9));
            var modified = AppleTime.FromCocoa(GetLong(r, 10));

            var name = BuildName(display, first, middle, last, nick, org);
            fields.TryGetValue(id, out var bag);
            bag ??= new FieldBag();

            list.Add(new ContactRecord
            {
                Id = id,
                DisplayName = name,
                Organization = org,
                JobTitle = job,
                Note = note,
                Birthday = birthday,
                Modified = modified,
                Phones = bag.Phones,
                Emails = bag.Emails,
                Other = bag.Other,
            });
        }

        return list
            .OrderBy(static c => c.DisplayName, StringComparer.CurrentCultureIgnoreCase)
            .ToList();
    }

    private static Dictionary<long, FieldBag> LoadFields(
        SqliteConnection con,
        IReadOnlyDictionary<long, string> labels)
    {
        var map = new Dictionary<long, FieldBag>();
        if (!SqliteOpen.TableExists(con, "ABMultiValue"))
            return map;

        using var cmd = con.CreateCommand();
        cmd.CommandText =
            """
            SELECT record_id, property, label, value
            FROM ABMultiValue
            WHERE value IS NOT NULL AND TRIM(value) <> '';
            """;
        using var r = cmd.ExecuteReader();
        while (r.Read())
        {
            var recordId = r.GetInt64(0);
            var prop = r.IsDBNull(1) ? 0 : r.GetInt32(1);
            var labelId = r.IsDBNull(2) ? -1 : r.GetInt64(2);
            var value = r.GetString(3).Trim();
            if (value.Length == 0)
                continue;

            if (!map.TryGetValue(recordId, out var bag))
            {
                bag = new FieldBag();
                map[recordId] = bag;
            }

            var label = labels.TryGetValue(labelId, out var lab)
                ? FriendlyLabel(lab)
                : DefaultLabel(prop);
            var field = new ContactField { Label = label, Value = value };
            switch (prop)
            {
                case PropPhone:
                    bag.Phones.Add(field);
                    break;
                case PropEmail:
                    bag.Emails.Add(field);
                    break;
                default:
                    bag.Other.Add(field);
                    break;
            }
        }

        return map;
    }

    private static Dictionary<long, string> LoadLabels(SqliteConnection con)
    {
        var map = new Dictionary<long, string>();
        if (!SqliteOpen.TableExists(con, "ABMultiValueLabel"))
            return map;
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT ROWID, value FROM ABMultiValueLabel;";
        using var r = cmd.ExecuteReader();
        while (r.Read())
            map[r.GetInt64(0)] = r.IsDBNull(1) ? "" : r.GetString(1);
        return map;
    }

    private static string BuildName(
        string? display,
        string? first,
        string? middle,
        string? last,
        string? nick,
        string? org)
    {
        if (!string.IsNullOrWhiteSpace(display))
            return display.Trim();
        var parts = new[] { first, middle, last }
            .Where(static s => !string.IsNullOrWhiteSpace(s))
            .Select(static s => s!.Trim());
        var name = string.Join(' ', parts);
        if (!string.IsNullOrWhiteSpace(name))
            return name;
        if (!string.IsNullOrWhiteSpace(nick))
            return nick.Trim();
        if (!string.IsNullOrWhiteSpace(org))
            return org.Trim();
        return "(senza nome)";
    }

    private static string FriendlyLabel(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return "";
        // _$!<Mobile>!$_ → Mobile
        if (raw.StartsWith("_$!<", StringComparison.Ordinal) && raw.EndsWith(">!$_", StringComparison.Ordinal))
            return raw[4..^4];
        return raw.Trim().TrimStart('\u200e', '\u200f');
    }

    private static string DefaultLabel(int prop) => prop switch
    {
        PropPhone => "Telefono",
        PropEmail => "Email",
        _ => "Altro",
    };

    private static DateTimeOffset? ParseBirthday(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        // Often stored as YYYY-MM-DD or Cocoa timestamp string
        if (double.TryParse(raw, System.Globalization.NumberStyles.Float,
                System.Globalization.CultureInfo.InvariantCulture, out var cocoa))
            return AppleTime.FromCocoa(cocoa);
        if (DateTimeOffset.TryParse(raw, out var dto))
            return dto;
        return null;
    }

    private static string? GetStr(SqliteDataReader r, int i) =>
        r.IsDBNull(i) ? null : r.GetString(i);

    private static long? GetLong(SqliteDataReader r, int i) =>
        r.IsDBNull(i) ? null : Convert.ToInt64(r.GetValue(i));

    private sealed class FieldBag
    {
        public List<ContactField> Phones { get; } = [];
        public List<ContactField> Emails { get; } = [];
        public List<ContactField> Other { get; } = [];
    }
}
