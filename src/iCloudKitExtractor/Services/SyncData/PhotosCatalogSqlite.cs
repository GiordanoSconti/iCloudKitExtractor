using System.IO;
using Microsoft.Data.Sqlite;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>Catalogo SQLite Photos Sync Data (<c>photos/Photos.db</c>).</summary>
public sealed class PhotosCatalogSqlite : IAsyncDisposable
{
    private readonly SqliteConnection _conn;
    private bool _opened;

    private PhotosCatalogSqlite(SqliteConnection conn) => _conn = conn;

    public static async Task<PhotosCatalogSqlite> OpenAsync(string photosDir, CancellationToken ct = default)
    {
        Directory.CreateDirectory(photosDir);
        var dbPath = Path.Combine(photosDir, "Photos.db");
        var conn = new SqliteConnection($"Data Source={dbPath}");
        await conn.OpenAsync(ct);
        await EnsureSchemaAsync(conn, ct);
        return new PhotosCatalogSqlite(conn) { _opened = true };
    }

    private static async Task EnsureSchemaAsync(SqliteConnection conn, CancellationToken ct)
    {
        // Migra schema legacy (PK record_name) → PK token.
        var pkColumn = await ReadMediaPkColumnAsync(conn, ct);
        if (pkColumn is "record_name")
        {
            await using var drop = conn.CreateCommand();
            drop.CommandText = "DROP TABLE IF EXISTS AlbumMedia; DROP TABLE IF EXISTS Media;";
            await drop.ExecuteNonQueryAsync(ct);
        }

        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS Albums (
              record_name TEXT PRIMARY KEY,
              name TEXT,
              album_type INTEGER,
              is_root INTEGER NOT NULL DEFAULT 0,
              folder TEXT
            );
            CREATE TABLE IF NOT EXISTS Media (
              token TEXT PRIMARY KEY,
              record_name TEXT NOT NULL,
              asset_record_name TEXT,
              file_name TEXT,
              relative_path TEXT,
              extension TEXT,
              size_bytes INTEGER,
              hidden INTEGER NOT NULL DEFAULT 0,
              trashed INTEGER NOT NULL DEFAULT 0,
              favorite INTEGER NOT NULL DEFAULT 0,
              is_live INTEGER NOT NULL DEFAULT 0,
              bundle_id TEXT,
              app_display_name TEXT,
              mmcs_auth TEXT,
              sha256 TEXT
            );
            CREATE TABLE IF NOT EXISTS AlbumMedia (
              album_record_name TEXT NOT NULL,
              media_token TEXT NOT NULL,
              PRIMARY KEY (album_record_name, media_token)
            );
            CREATE INDEX IF NOT EXISTS ix_media_record ON Media(record_name);
            CREATE INDEX IF NOT EXISTS ix_media_asset ON Media(asset_record_name);
            CREATE INDEX IF NOT EXISTS ix_media_sha256 ON Media(sha256);
            CREATE INDEX IF NOT EXISTS ix_album_media_token ON AlbumMedia(media_token);
            CREATE TABLE IF NOT EXISTS MediaMetadata (
              media_token TEXT NOT NULL,
              field_name TEXT NOT NULL,
              text_value TEXT NOT NULL,
              PRIMARY KEY (media_token, field_name),
              FOREIGN KEY (media_token) REFERENCES Media(token) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS ix_media_metadata_field ON MediaMetadata(field_name);
            """;
        await cmd.ExecuteNonQueryAsync(ct);

        // Colonne aggiunte su DB creati prima di questa versione.
        await TryAddColumnAsync(conn, "Media", "asset_record_name", "TEXT", ct);
        await TryAddColumnAsync(conn, "Media", "sha256", "TEXT", ct);
        await using var ix = conn.CreateCommand();
        ix.CommandText = "CREATE INDEX IF NOT EXISTS ix_media_sha256 ON Media(sha256);";
        await ix.ExecuteNonQueryAsync(ct);
    }

    private static async Task EnsureMediaMetadataTableAsync(SqliteConnection conn, CancellationToken ct)
    {
        await using var check = conn.CreateCommand();
        check.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name='MediaMetadata';";
        if (await check.ExecuteScalarAsync(ct) is not null)
            return;

        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS MediaMetadata (
              media_token TEXT NOT NULL,
              field_name TEXT NOT NULL,
              text_value TEXT NOT NULL,
              PRIMARY KEY (media_token, field_name),
              FOREIGN KEY (media_token) REFERENCES Media(token) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS ix_media_metadata_field ON MediaMetadata(field_name);
            """;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    private static async Task<string?> ReadMediaPkColumnAsync(SqliteConnection conn, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' AND name='Media';";
        if (await cmd.ExecuteScalarAsync(ct) is null)
            return null;

        await using var info = conn.CreateCommand();
        info.CommandText = "PRAGMA table_info(Media);";
        await using var reader = await info.ExecuteReaderAsync(ct);
        while (await reader.ReadAsync(ct))
        {
            var name = reader.GetString(1);
            var pk = reader.GetInt32(5);
            if (pk == 1)
                return name;
        }

        return null;
    }

    private static async Task TryAddColumnAsync(
        SqliteConnection conn,
        string table,
        string column,
        string type,
        CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText = $"ALTER TABLE {table} ADD COLUMN {column} {type};";
        try { await cmd.ExecuteNonQueryAsync(ct); }
        catch (SqliteException ex) when (ex.Message.Contains("duplicate column", StringComparison.OrdinalIgnoreCase)) { }
    }

    public async Task ClearAsync(CancellationToken ct = default)
    {
        await EnsureMediaMetadataTableAsync(_conn, ct);
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText = "DELETE FROM MediaMetadata; DELETE FROM AlbumMedia; DELETE FROM Media; DELETE FROM Albums;";
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpsertAlbumAsync(
        string recordName,
        string? name,
        int? albumType,
        bool isRoot,
        string? folder,
        CancellationToken ct = default)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO Albums(record_name, name, album_type, is_root, folder)
            VALUES ($r, $n, $t, $root, $f)
            ON CONFLICT(record_name) DO UPDATE SET
              name=excluded.name,
              album_type=excluded.album_type,
              is_root=excluded.is_root,
              folder=excluded.folder;
            """;
        cmd.Parameters.AddWithValue("$r", recordName);
        cmd.Parameters.AddWithValue("$n", (object?)name ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$t", (object?)albumType ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$root", isRoot ? 1 : 0);
        cmd.Parameters.AddWithValue("$f", (object?)folder ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpsertMediaAsync(
        string token,
        string recordName,
        string? assetRecordName,
        string? fileName,
        string? relativePath,
        string? extension,
        long? sizeBytes,
        bool hidden,
        bool trashed,
        bool favorite,
        bool isLive,
        string? bundleId,
        string? appDisplayName,
        string? mmcsAuth,
        string? sha256 = null,
        CancellationToken ct = default)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO Media(
              token, record_name, asset_record_name, file_name, relative_path, extension, size_bytes,
              hidden, trashed, favorite, is_live, bundle_id, app_display_name, mmcs_auth, sha256)
            VALUES (
              $tok, $r, $asset, $fn, $rp, $ext, $sz,
              $h, $tr, $fav, $live, $bid, $app, $auth, $sha)
            ON CONFLICT(token) DO UPDATE SET
              record_name=excluded.record_name,
              asset_record_name=excluded.asset_record_name,
              file_name=excluded.file_name,
              relative_path=excluded.relative_path,
              extension=excluded.extension,
              size_bytes=excluded.size_bytes,
              hidden=excluded.hidden,
              trashed=excluded.trashed,
              favorite=excluded.favorite,
              is_live=excluded.is_live,
              bundle_id=excluded.bundle_id,
              app_display_name=excluded.app_display_name,
              mmcs_auth=excluded.mmcs_auth,
              sha256=excluded.sha256;
            """;
        cmd.Parameters.AddWithValue("$tok", token);
        cmd.Parameters.AddWithValue("$r", recordName);
        cmd.Parameters.AddWithValue("$asset", (object?)assetRecordName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$fn", (object?)fileName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$rp", (object?)relativePath ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$ext", (object?)extension ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$sz", (object?)sizeBytes ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$h", hidden ? 1 : 0);
        cmd.Parameters.AddWithValue("$tr", trashed ? 1 : 0);
        cmd.Parameters.AddWithValue("$fav", favorite ? 1 : 0);
        cmd.Parameters.AddWithValue("$live", isLive ? 1 : 0);
        cmd.Parameters.AddWithValue("$bid", (object?)bundleId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$app", (object?)appDisplayName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$auth", (object?)mmcsAuth ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$sha", (object?)sha256 ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpsertMediaMetadataAsync(
        string mediaToken,
        IReadOnlyDictionary<string, string> fields,
        CancellationToken ct = default)
    {
        if (fields.Count == 0)
            return;

        await EnsureMediaMetadataTableAsync(_conn, ct);
        await using var tx = (SqliteTransaction)await _conn.BeginTransactionAsync(ct);
        foreach (var (fieldName, textValue) in fields)
        {
            if (string.IsNullOrWhiteSpace(fieldName) || string.IsNullOrWhiteSpace(textValue))
                continue;

            await using var cmd = _conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText =
                """
                INSERT INTO MediaMetadata(media_token, field_name, text_value)
                VALUES ($tok, $field, $val)
                ON CONFLICT(media_token, field_name) DO UPDATE SET
                  text_value=excluded.text_value;
                """;
            cmd.Parameters.AddWithValue("$tok", mediaToken);
            cmd.Parameters.AddWithValue("$field", fieldName);
            cmd.Parameters.AddWithValue("$val", textValue.Trim());
            await cmd.ExecuteNonQueryAsync(ct);
        }

        await tx.CommitAsync(ct);
    }

    public async Task LinkAlbumMediaAsync(
        string albumRecordName,
        string mediaToken,
        CancellationToken ct = default)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT OR IGNORE INTO AlbumMedia(album_record_name, media_token)
            VALUES ($a, $tok);
            """;
        cmd.Parameters.AddWithValue("$a", albumRecordName);
        cmd.Parameters.AddWithValue("$tok", mediaToken);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async ValueTask DisposeAsync()
    {
        if (_opened)
            await _conn.DisposeAsync();
        _opened = false;
    }
}
