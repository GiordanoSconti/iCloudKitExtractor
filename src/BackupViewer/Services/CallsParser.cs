using BackupViewer.Models;
using Microsoft.Data.Sqlite;

namespace BackupViewer.Services;

public static class CallsParser
{
    public static IReadOnlyList<CallRecord> ParseWhatsApp(string dbPath)
    {
        using var con = SqliteOpen.OpenReadonly(dbPath);
        if (!SqliteOpen.TableExists(con, "ZWACDCALLEVENT"))
            return [];

        var peers = new Dictionary<long, string>();
        if (SqliteOpen.TableExists(con, "ZWACDCALLEVENTPARTICIPANT"))
        {
            using var cmd = con.CreateCommand();
            // Z1PARTICIPANTS → parent call event PK
            cmd.CommandText =
                """
                SELECT Z1PARTICIPANTS, GROUP_CONCAT(ZJIDSTRING, ', ')
                FROM ZWACDCALLEVENTPARTICIPANT
                WHERE ZJIDSTRING IS NOT NULL
                GROUP BY Z1PARTICIPANTS;
                """;
            try
            {
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    if (r.IsDBNull(0) || r.IsDBNull(1))
                        continue;
                    var peer = FriendlyPeers(r.GetString(1));
                    if (!string.IsNullOrWhiteSpace(peer))
                        peers[r.GetInt64(0)] = peer;
                }
            }
            catch
            {
                // schema variants
            }
        }

        var list = new List<CallRecord>();
        using (var cmd = con.CreateCommand())
        {
            cmd.CommandText =
                """
                SELECT Z_PK, ZOUTCOME, ZDATE, ZDURATION, ZGROUPJIDSTRING, ZCALLIDSTRING,
                       ZISBOTGROUPCALL
                FROM ZWACDCALLEVENT
                ORDER BY ZDATE DESC;
                """;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var pk = r.GetInt64(0);
                var outcomeRaw = r.IsDBNull(1) ? -1 : r.GetInt32(1);
                var groupJid = r.IsDBNull(4) ? null : r.GetString(4);
                peers.TryGetValue(pk, out var peer);
                if (string.IsNullOrWhiteSpace(peer))
                    peer = FriendlyPeers(groupJid);
                if (string.IsNullOrWhiteSpace(peer))
                    peer = "WhatsApp";

                list.Add(new CallRecord
                {
                    Id = pk,
                    App = "WhatsApp",
                    Peer = peer,
                    Direction = CallDirection.Unknown,
                    Outcome = MapWaOutcome(outcomeRaw),
                    StartedAt = AppleTime.FromCocoa(GetDouble(r, 2)),
                    DurationSeconds = GetDouble(r, 3),
                    IsGroup = !string.IsNullOrWhiteSpace(groupJid)
                              || (!r.IsDBNull(6) && r.GetInt32(6) != 0),
                });
            }
        }

        return list;
    }

    public static IReadOnlyList<CallRecord> ParseAppleCallHistory(string dbPath)
    {
        using var con = SqliteOpen.OpenReadonly(dbPath);
        // CallHistory.storedata uses ZCALLRECORD
        if (!SqliteOpen.TableExists(con, "ZCALLRECORD"))
            return [];

        var list = new List<CallRecord>();
        using var cmd = con.CreateCommand();
        var hasVideo = SqliteOpen.ColumnExists(con, "ZCALLRECORD", "ZVIDEO");
        var hasOriginated = SqliteOpen.ColumnExists(con, "ZCALLRECORD", "ZORIGINATED");
        var hasAnswered = SqliteOpen.ColumnExists(con, "ZCALLRECORD", "ZANSWERED");
        var hasName = SqliteOpen.ColumnExists(con, "ZCALLRECORD", "ZNAME");
        cmd.CommandText =
            $"""
             SELECT Z_PK,
                    ZADDRESS,
                    {(hasName ? "ZNAME" : "NULL")},
                    ZDATE,
                    ZDURATION,
                    {(hasOriginated ? "ZORIGINATED" : "NULL")},
                    {(hasAnswered ? "ZANSWERED" : "NULL")},
                    {(hasVideo ? "ZVIDEO" : "NULL")},
                    ZCALLTYPE
             FROM ZCALLRECORD
             ORDER BY ZDATE DESC;
             """;
        try
        {
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var address = r.IsDBNull(1) ? null : r.GetString(1);
                var name = r.IsDBNull(2) ? null : r.GetString(2);
                var originated = !r.IsDBNull(5) && Convert.ToInt32(r.GetValue(5)) != 0;
                var answered = r.IsDBNull(6) || Convert.ToInt32(r.GetValue(6)) != 0;
                var video = !r.IsDBNull(7) && Convert.ToInt32(r.GetValue(7)) != 0;
                var duration = GetDouble(r, 4);
                var peer = !string.IsNullOrWhiteSpace(name) ? name.Trim() : address ?? "Sconosciuto";

                CallOutcome outcome;
                if (!answered && (duration is null or <= 0))
                    outcome = originated ? CallOutcome.Cancelled : CallOutcome.Missed;
                else if (!answered)
                    outcome = CallOutcome.Missed;
                else
                    outcome = CallOutcome.Answered;

                list.Add(new CallRecord
                {
                    Id = r.GetInt64(0),
                    App = "Telefono",
                    Peer = peer,
                    Direction = originated ? CallDirection.Outgoing : CallDirection.Incoming,
                    Outcome = outcome,
                    StartedAt = AppleTime.FromCocoa(GetDouble(r, 3)),
                    DurationSeconds = duration,
                    IsVideo = video,
                });
            }
        }
        catch
        {
            return [];
        }

        return list;
    }

    private static CallOutcome MapWaOutcome(int raw) => raw switch
    {
        0 => CallOutcome.Answered,
        1 => CallOutcome.Missed,
        2 => CallOutcome.Rejected,
        3 => CallOutcome.Cancelled,
        4 => CallOutcome.Rejected,
        _ => CallOutcome.Other,
    };

    private static string? FriendlyPeers(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var parts = raw.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Select(static j =>
            {
                var at = j.IndexOf('@');
                return at > 0 ? j[..at] : j;
            });
        return string.Join(", ", parts);
    }

    private static double? GetDouble(SqliteDataReader r, int i)
    {
        if (r.IsDBNull(i))
            return null;
        return Convert.ToDouble(r.GetValue(i), System.Globalization.CultureInfo.InvariantCulture);
    }
}
