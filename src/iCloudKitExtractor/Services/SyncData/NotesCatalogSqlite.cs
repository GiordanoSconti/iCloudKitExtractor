using System.IO;
using Microsoft.Data.Sqlite;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>Catalogo SQLite Notes Sync Data (<c>Notes.db</c>).</summary>
public sealed class NotesCatalogSqlite : IAsyncDisposable
{
    private readonly SqliteConnection _conn;
    private bool _opened;

    private NotesCatalogSqlite(SqliteConnection conn) => _conn = conn;

    public static async Task<NotesCatalogSqlite> OpenAsync(string notesDir, CancellationToken ct = default)
    {
        Directory.CreateDirectory(notesDir);
        var dbPath = Path.Combine(notesDir, "Notes.db");
        var conn = new SqliteConnection($"Data Source={dbPath}");
        await conn.OpenAsync(ct);
        await EnsureSchemaAsync(conn, ct);
        return new NotesCatalogSqlite(conn) { _opened = true };
    }

    private static async Task EnsureSchemaAsync(SqliteConnection conn, CancellationToken ct)
    {
        await using var cmd = conn.CreateCommand();
        cmd.CommandText =
            """
            CREATE TABLE IF NOT EXISTS folders (
              record_name TEXT PRIMARY KEY,
              name TEXT,
              folder_key TEXT,
              folder_hash_id TEXT,
              is_system INTEGER NOT NULL DEFAULT 0,
              sync_tag TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_folders_key ON folders(folder_key);

            CREATE TABLE IF NOT EXISTS notes (
              record_name TEXT PRIMARY KEY,
              title TEXT,
              snippet TEXT,
              folder_key TEXT,
              folder_record_name TEXT,
              record_type TEXT NOT NULL DEFAULT 'Note',
              deleted INTEGER NOT NULL DEFAULT 0,
              sync_tag TEXT
            );
            CREATE INDEX IF NOT EXISTS ix_notes_folder_key ON notes(folder_key);
            CREATE INDEX IF NOT EXISTS ix_notes_folder_rec ON notes(folder_record_name);

            CREATE TABLE IF NOT EXISTS note_plaintext (
              record_name TEXT NOT NULL,
              field_name TEXT NOT NULL,
              plain_path TEXT NOT NULL,
              text_preview TEXT,
              PRIMARY KEY (record_name, field_name, plain_path)
            );
            CREATE INDEX IF NOT EXISTS ix_note_plaintext_field ON note_plaintext(field_name);
            """;
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task ClearAsync(CancellationToken ct = default)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText = "DELETE FROM note_plaintext; DELETE FROM notes; DELETE FROM folders;";
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpsertFolderAsync(
        string recordName,
        string? name,
        string? folderKey,
        string? folderHashId,
        bool isSystem,
        string? syncTag,
        CancellationToken ct = default)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO folders(record_name, name, folder_key, folder_hash_id, is_system, sync_tag)
            VALUES ($r, $n, $k, $h, $sys, $tag)
            ON CONFLICT(record_name) DO UPDATE SET
              name=COALESCE(excluded.name, folders.name),
              folder_key=COALESCE(excluded.folder_key, folders.folder_key),
              folder_hash_id=COALESCE(excluded.folder_hash_id, folders.folder_hash_id),
              is_system=excluded.is_system,
              sync_tag=excluded.sync_tag;
            """;
        cmd.Parameters.AddWithValue("$r", recordName);
        cmd.Parameters.AddWithValue("$n", (object?)name ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$k", (object?)folderKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$h", (object?)folderHashId ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$sys", isSystem ? 1 : 0);
        cmd.Parameters.AddWithValue("$tag", (object?)syncTag ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpsertNoteAsync(
        string recordName,
        string? title,
        string? snippet,
        string? folderKey,
        string? folderRecordName,
        string recordType,
        bool deleted,
        string? syncTag,
        CancellationToken ct = default)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO notes(
              record_name, title, snippet, folder_key, folder_record_name,
              record_type, deleted, sync_tag)
            VALUES ($r, $t, $s, $fk, $fr, $rt, $del, $tag)
            ON CONFLICT(record_name) DO UPDATE SET
              title=COALESCE(excluded.title, notes.title),
              snippet=COALESCE(excluded.snippet, notes.snippet),
              folder_key=COALESCE(excluded.folder_key, notes.folder_key),
              folder_record_name=COALESCE(excluded.folder_record_name, notes.folder_record_name),
              record_type=excluded.record_type,
              deleted=excluded.deleted,
              sync_tag=excluded.sync_tag;
            """;
        cmd.Parameters.AddWithValue("$r", recordName);
        cmd.Parameters.AddWithValue("$t", (object?)title ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$s", (object?)snippet ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$fk", (object?)folderKey ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$fr", (object?)folderRecordName ?? DBNull.Value);
        cmd.Parameters.AddWithValue("$rt", recordType);
        cmd.Parameters.AddWithValue("$del", deleted ? 1 : 0);
        cmd.Parameters.AddWithValue("$tag", (object?)syncTag ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task UpsertPlaintextAsync(
        string recordName,
        string fieldName,
        string plainPath,
        string? textPreview,
        CancellationToken ct = default)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText =
            """
            INSERT INTO note_plaintext(record_name, field_name, plain_path, text_preview)
            VALUES ($r, $f, $p, $txt)
            ON CONFLICT(record_name, field_name, plain_path) DO UPDATE SET
              text_preview=COALESCE(excluded.text_preview, note_plaintext.text_preview);
            """;
        cmd.Parameters.AddWithValue("$r", recordName);
        cmd.Parameters.AddWithValue("$f", fieldName);
        cmd.Parameters.AddWithValue("$p", plainPath);
        cmd.Parameters.AddWithValue("$txt", (object?)textPreview ?? DBNull.Value);
        await cmd.ExecuteNonQueryAsync(ct);
    }

    public async Task<int> CountAsync(string table, CancellationToken ct = default)
    {
        await using var cmd = _conn.CreateCommand();
        cmd.CommandText = $"SELECT COUNT(*) FROM {table};";
        var scalar = await cmd.ExecuteScalarAsync(ct);
        return scalar switch
        {
            long l => (int)l,
            int i => i,
            _ => Convert.ToInt32(scalar)
        };
    }

    public async ValueTask DisposeAsync()
    {
        if (_opened)
            await _conn.DisposeAsync();
        _opened = false;
    }
}
