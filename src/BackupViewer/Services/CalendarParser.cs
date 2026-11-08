using BackupViewer.Models;
using Microsoft.Data.Sqlite;

namespace BackupViewer.Services;

public static class CalendarParser
{
    public static (IReadOnlyList<CalendarInfo> Calendars, IReadOnlyList<CalendarEventItem> Events)
        Parse(string dbPath)
    {
        using var con = SqliteOpen.OpenReadonly(dbPath);
        if (!SqliteOpen.TableExists(con, "Calendar"))
            return ([], []);

        var calendars = new Dictionary<long, CalendarInfo>();
        using (var cmd = con.CreateCommand())
        {
            cmd.CommandText = "SELECT ROWID, title, color FROM Calendar ORDER BY title COLLATE NOCASE;";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var id = r.GetInt64(0);
                calendars[id] = new CalendarInfo
                {
                    Id = id,
                    Title = r.IsDBNull(1) || string.IsNullOrWhiteSpace(r.GetString(1))
                        ? $"Calendario {id}"
                        : r.GetString(1).Trim(),
                    ColorHex = NormalizeColor(r.IsDBNull(2) ? null : r.GetString(2)),
                };
            }
        }

        var locations = new Dictionary<long, string>();
        if (SqliteOpen.TableExists(con, "Location"))
        {
            using var cmd = con.CreateCommand();
            cmd.CommandText =
                """
                SELECT ROWID,
                       COALESCE(NULLIF(TRIM(title), ''), NULLIF(TRIM(address), ''))
                FROM Location;
                """;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                if (r.IsDBNull(1))
                    continue;
                locations[r.GetInt64(0)] = r.GetString(1);
            }
        }

        var events = new List<CalendarEventItem>();
        if (SqliteOpen.TableExists(con, "CalendarItem"))
        {
            using var cmd = con.CreateCommand();
            cmd.CommandText =
                """
                SELECT ROWID, summary, description, start_date, end_date, all_day,
                       calendar_id, location_id, url, entity_type, hidden
                FROM CalendarItem
                WHERE (hidden IS NULL OR hidden = 0)
                ORDER BY start_date DESC;
                """;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var calId = r.IsDBNull(6) ? 0L : r.GetInt64(6);
                calendars.TryGetValue(calId, out var cal);
                string? loc = null;
                if (!r.IsDBNull(7))
                    locations.TryGetValue(r.GetInt64(7), out loc);

                var summary = r.IsDBNull(1) ? null : r.GetString(1);
                if (string.IsNullOrWhiteSpace(summary))
                    summary = "(senza titolo)";

                var entityType = r.IsDBNull(9) ? 0 : r.GetInt32(9);
                var item = new CalendarEventItem
                {
                    Id = r.GetInt64(0),
                    CalendarId = calId,
                    CalendarTitle = cal?.Title ?? "Calendario",
                    ColorHex = cal?.ColorHex,
                    Summary = summary.Trim(),
                    Description = r.IsDBNull(2) ? null : NullIfEmpty(r.GetString(2)),
                    Start = AppleTime.FromCocoa(GetDouble(r, 3)),
                    End = AppleTime.FromCocoa(GetDouble(r, 4)),
                    AllDay = !r.IsDBNull(5) && r.GetInt32(5) != 0,
                    Location = loc,
                    Url = r.IsDBNull(8) ? null : NullIfEmpty(r.GetString(8)),
                    IsTask = entityType == 1,
                };
                events.Add(item);
                if (cal is not null)
                    cal.EventCount++;
            }
        }

        return (calendars.Values.OrderBy(static c => c.Title, StringComparer.OrdinalIgnoreCase).ToList(),
            events);
    }

    private static string? NormalizeColor(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        raw = raw.Trim();
        if (!raw.StartsWith('#'))
            raw = "#" + raw;
        // #RRGGBBAA → #RRGGBB for WPF simplicity when alpha last
        if (raw.Length == 9)
            return raw[..7];
        return raw.Length is 7 or 4 ? raw : null;
    }

    private static double? GetDouble(SqliteDataReader r, int i)
    {
        if (r.IsDBNull(i))
            return null;
        return Convert.ToDouble(r.GetValue(i), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static string? NullIfEmpty(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Trim();
}
