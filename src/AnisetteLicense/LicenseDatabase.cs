using Microsoft.Data.Sqlite;

namespace iCloudKitExtractor.AnisetteLicense;

public sealed class LicenseDatabase : IDisposable
{
    private readonly SqliteConnection _conn;

    public LicenseDatabase(string path)
    {
        Directory.CreateDirectory(System.IO.Path.GetDirectoryName(System.IO.Path.GetFullPath(path))!);
        _conn = new SqliteConnection($"Data Source={path}");
        _conn.Open();
        EnsureSchema();
    }

    public string DatabasePath => _conn.DataSource;

    private void EnsureSchema()
    {
        using (var cmd = _conn.CreateCommand())
        {
            cmd.CommandText =
                """
                CREATE TABLE IF NOT EXISTS licenses (
                  license_id   TEXT PRIMARY KEY NOT NULL,
                  subject      TEXT NOT NULL,
                  issued_at    TEXT NOT NULL,
                  expires_at   TEXT NULL,
                  revoked_at   TEXT NULL,
                  note         TEXT NULL,
                  token_hint   TEXT NULL,
                  fingerprint  TEXT NULL,
                  client_ip    TEXT NULL,
                  enabled      INTEGER NOT NULL DEFAULT 1,
                  emitted_once INTEGER NOT NULL DEFAULT 0
                );
                """;
            cmd.ExecuteNonQuery();
        }

        EnsureColumn("fingerprint", "TEXT NULL");
        EnsureColumn("client_ip", "TEXT NULL");
        EnsureColumn("enabled", "INTEGER NOT NULL DEFAULT 1");
        EnsureColumn("emitted_once", "INTEGER NOT NULL DEFAULT 0");
    }

    private void EnsureColumn(string name, string decl)
    {
        using var check = _conn.CreateCommand();
        check.CommandText = "PRAGMA table_info(licenses);";
        using var r = check.ExecuteReader();
        while (r.Read())
        {
            if (string.Equals(r.GetString(1), name, StringComparison.OrdinalIgnoreCase))
                return;
        }

        using var alter = _conn.CreateCommand();
        alter.CommandText = $"ALTER TABLE licenses ADD COLUMN {name} {decl};";
        alter.ExecuteNonQuery();
    }

    public void Insert(LicensePayload payload, string? tokenHint = null, bool emittedOnce = false)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO licenses (
              license_id, subject, issued_at, expires_at, note, token_hint,
              fingerprint, client_ip, enabled, emitted_once)
            VALUES (
              $id, $sub, $iat, $exp, $note, $hint,
              $fp, $ip, 1, $emitted);
            """;
        cmd.Parameters.AddWithValue("$id", payload.LicenseId);
        cmd.Parameters.AddWithValue("$sub", payload.Subject);
        cmd.Parameters.AddWithValue("$iat", DateTimeOffset.FromUnixTimeSeconds(payload.IssuedAtUnix).UtcDateTime.ToString("o"));
        cmd.Parameters.AddWithValue("$exp", payload.ExpiresAtUnix is long e
            ? DateTimeOffset.FromUnixTimeSeconds(e).UtcDateTime.ToString("o")
            : DBNull.Value);
        cmd.Parameters.AddWithValue("$note", (object?)payload.Note ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$hint", (object?)tokenHint ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$fp", (object?)payload.Fingerprint ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ip", (object?)payload.ClientIp ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$emitted", emittedOnce ? 1 : 0);
        cmd.ExecuteNonQuery();
    }

    public bool TryGetActive(string licenseId, out LicenseRow? row, out string error)
    {
        row = null;
        error = "";
        if (!TryGet(licenseId, out row, out error) || row is null)
            return false;

        if (!row.Enabled)
        {
            error = "license disabled";
            return false;
        }

        if (!string.IsNullOrEmpty(row.RevokedAt))
        {
            error = "license revoked";
            return false;
        }

        if (row.ExpiresAt is string expRaw
            && DateTimeOffset.TryParse(expRaw, out var exp)
            && exp < DateTimeOffset.UtcNow)
        {
            error = "license expired (db)";
            return false;
        }

        return true;
    }

    public bool TryGet(string licenseId, out LicenseRow? row, out string error)
    {
        row = null;
        error = "";
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT license_id, subject, issued_at, expires_at, revoked_at, note,
                   fingerprint, client_ip, enabled, emitted_once
            FROM licenses WHERE license_id = $id LIMIT 1;
            """;
        cmd.Parameters.AddWithValue("$id", licenseId);
        using var r = cmd.ExecuteReader();
        if (!r.Read())
        {
            error = "license_id not registered";
            return false;
        }

        row = ReadRow(r);
        return true;
    }

    public LicenseRow? FindByFingerprint(string fingerprint)
    {
        if (string.IsNullOrWhiteSpace(fingerprint))
            return null;
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT license_id, subject, issued_at, expires_at, revoked_at, note,
                   fingerprint, client_ip, enabled, emitted_once
            FROM licenses
            WHERE fingerprint = $fp
            ORDER BY issued_at DESC
            LIMIT 1;
            """;
        cmd.Parameters.AddWithValue("$fp", fingerprint.Trim());
        using var r = cmd.ExecuteReader();
        return r.Read() ? ReadRow(r) : null;
    }

    public bool Revoke(string licenseId)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            UPDATE licenses SET revoked_at = $ts
            WHERE license_id = $id AND revoked_at IS NULL;
            """;
        cmd.Parameters.AddWithValue("$ts", DateTimeOffset.UtcNow.ToString("o"));
        cmd.Parameters.AddWithValue("$id", licenseId);
        return cmd.ExecuteNonQuery() > 0;
    }

    public bool SetEnabled(string licenseId, bool enabled)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            UPDATE licenses SET enabled = $en WHERE license_id = $id;
            """;
        cmd.Parameters.AddWithValue("$en", enabled ? 1 : 0);
        cmd.Parameters.AddWithValue("$id", licenseId);
        return cmd.ExecuteNonQuery() > 0;
    }

    public bool Delete(string licenseId)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText = "DELETE FROM licenses WHERE license_id = $id;";
        cmd.Parameters.AddWithValue("$id", licenseId);
        return cmd.ExecuteNonQuery() > 0;
    }

    public bool MarkEmitted(string licenseId)
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            UPDATE licenses SET emitted_once = 1 WHERE license_id = $id;
            """;
        cmd.Parameters.AddWithValue("$id", licenseId);
        return cmd.ExecuteNonQuery() > 0;
    }

    public IReadOnlyList<LicenseRow> ListAll()
    {
        using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            SELECT license_id, subject, issued_at, expires_at, revoked_at, note,
                   fingerprint, client_ip, enabled, emitted_once
            FROM licenses ORDER BY issued_at DESC;
            """;
        var list = new List<LicenseRow>();
        using var r = cmd.ExecuteReader();
        while (r.Read())
            list.Add(ReadRow(r));
        return list;
    }

    private static LicenseRow ReadRow(SqliteDataReader r) =>
        new(
            r.GetString(0),
            r.GetString(1),
            r.GetString(2),
            r.IsDBNull(3) ? null : r.GetString(3),
            r.IsDBNull(4) ? null : r.GetString(4),
            r.IsDBNull(5) ? null : r.GetString(5),
            r.IsDBNull(6) ? null : r.GetString(6),
            r.IsDBNull(7) ? null : r.GetString(7),
            !r.IsDBNull(8) && r.GetInt64(8) != 0,
            !r.IsDBNull(9) && r.GetInt64(9) != 0);

    public void Dispose() => _conn.Dispose();
}

public sealed record LicenseRow(
    string LicenseId,
    string Subject,
    string IssuedAt,
    string? ExpiresAt,
    string? RevokedAt,
    string? Note,
    string? Fingerprint = null,
    string? ClientIp = null,
    bool Enabled = true,
    bool EmittedOnce = false);
