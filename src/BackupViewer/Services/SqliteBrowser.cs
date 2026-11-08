using System.Data;
using Microsoft.Data.Sqlite;

namespace BackupViewer.Services;

public sealed class SqliteTableInfo
{
    public required string Name { get; init; }
    public long RowCount { get; init; }
    public string Caption => $"{Name} ({RowCount:N0})";
}

public static class SqliteBrowser
{
    public static IReadOnlyList<SqliteTableInfo> ListTables(string path)
    {
        SQLitePCL.Batteries_V2.Init();
        using var con = Open(path);
        var tables = new List<string>();
        using (var cmd = con.CreateCommand())
        {
            cmd.CommandText =
                """
                SELECT name FROM sqlite_master
                WHERE type='table' AND name NOT LIKE 'sqlite_%'
                ORDER BY name;
                """;
            using var r = cmd.ExecuteReader();
            while (r.Read())
                tables.Add(r.GetString(0));
        }

        var result = new List<SqliteTableInfo>(tables.Count);
        foreach (var table in tables)
        {
            long count = 0;
            try
            {
                using var cmd = con.CreateCommand();
                cmd.CommandText = $"SELECT COUNT(*) FROM \"{EscapeIdent(table)}\";";
                count = Convert.ToInt64(cmd.ExecuteScalar() ?? 0L);
            }
            catch
            {
                count = -1;
            }

            result.Add(new SqliteTableInfo { Name = table, RowCount = count });
        }

        return result;
    }

    public static DataView LoadTable(string path, string table, int maxRows = 500)
    {
        SQLitePCL.Batteries_V2.Init();
        using var con = Open(path);
        using var cmd = con.CreateCommand();
        cmd.CommandText = $"SELECT * FROM \"{EscapeIdent(table)}\" LIMIT {maxRows};";
        using var r = cmd.ExecuteReader();

        var dt = new DataTable(table);
        for (var i = 0; i < r.FieldCount; i++)
        {
            var name = r.GetName(i);
            if (string.IsNullOrWhiteSpace(name))
                name = $"col{i}";
            if (dt.Columns.Contains(name))
                name += "_" + i;
            dt.Columns.Add(name, typeof(string));
        }

        while (r.Read())
        {
            var row = dt.NewRow();
            for (var i = 0; i < r.FieldCount; i++)
                row[i] = FormatCell(r, i);
            dt.Rows.Add(row);
        }

        return dt.DefaultView;
    }

    private static SqliteConnection Open(string path)
    {
        var cs = new SqliteConnectionStringBuilder
        {
            DataSource = path,
            Mode = SqliteOpenMode.ReadOnly,
            Pooling = false,
        }.ToString();
        var con = new SqliteConnection(cs);
        con.Open();
        return con;
    }

    private static string EscapeIdent(string name) =>
        name.Replace("\"", "\"\"", StringComparison.Ordinal);

    private static string FormatCell(SqliteDataReader r, int i)
    {
        if (r.IsDBNull(i))
            return "NULL";
        var v = r.GetValue(i);
        return v switch
        {
            byte[] blob => $"BLOB({blob.Length})",
            DateTime dt => dt.ToString("O"),
            _ => Convert.ToString(v) ?? "",
        };
    }
}
