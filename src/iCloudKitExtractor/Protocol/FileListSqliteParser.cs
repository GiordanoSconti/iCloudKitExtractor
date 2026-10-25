using System.IO;
using Microsoft.Data.Sqlite;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// <c>ParseFileListDb</c> / <c>icloud::ReadIos26FileList</c> (+0x8fbc50):
/// blob MMCS+PCS (+ LZFSE/bzip2) → magic <c>SQLite format 3</c> → query Assets⋈FileMetadata.
/// Le righe alimentano <c>GatherFilesToDownload</c> (rid/ek/rp/…).
/// </summary>
public static class FileListSqliteParser
{
    /// <summary>SQL ReadIos26FileList (+ colonne signature/size usate in download).</summary>
    public const string JoinSql =
        """
        SELECT a.recordIDSuffix AS rid, a.encryptionKey AS ek,
               f.relativePath AS rp, f.size AS sz, f.mode AS md,
               f.protectionClass AS pc, f.modified AS mt, f.birth AS bt,
               f.statusChanged AS sc, a.assetSignature AS sig, a.assetSize AS asz
        FROM Assets a
        JOIN FileMetadata f ON a.inode = f.inode
        """;

    /// <summary>
    /// Inventario completo per Manifest: tutte le <c>FileMetadata</c> (dir incluse),
    /// con campi Asset se presenti.
    /// </summary>
    public const string InventorySql =
        """
        SELECT f.inode, f.relativePath, f.size, f.birth, f.modified, f.statusChanged,
               f.userID, f.groupID, f.mode, f.flags, f.protectionClass, f.xattrs,
               a.recordIDSuffix, a.encryptionKey, a.assetSignature, a.assetSize,
               a.assetType, a.compressionMethod
        FROM FileMetadata f
        LEFT JOIN Assets a ON a.inode = f.inode
        ORDER BY f.relativePath
        """;

    public sealed record Entry(
        string RecordIdSuffix,
        byte[]? EncryptionKey,
        string RelativePath,
        long Size,
        long Mode,
        int ProtectionClass,
        long Modified,
        long Birth,
        long StatusChanged,
        byte[]? AssetSignature,
        long? AssetSize);

    public sealed record InventoryRow(
        long Inode,
        string RelativePath,
        long Size,
        long Birth,
        long Modified,
        long StatusChanged,
        long UserId,
        long GroupId,
        long Mode,
        long Flags,
        int ProtectionClass,
        byte[]? Xattrs,
        string? RecordIdSuffix,
        byte[]? EncryptionKey,
        byte[]? AssetSignature,
        long? AssetSize,
        long? AssetType,
        long? CompressionMethod);

    public sealed record ParseResult(
        bool Ok,
        string? Error,
        IReadOnlyList<string> Tables,
        int AssetRows,
        int FileMetadataRows,
        IReadOnlyList<Entry> Entries);

    public sealed record InventoryResult(
        bool Ok,
        string? Error,
        int AssetRows,
        int FileMetadataRows,
        IReadOnlyList<InventoryRow> Rows);

    public static bool LooksLikeSqlite(ReadOnlySpan<byte> data) =>
        data.Length >= 16 && data.StartsWith("SQLite format 3\0"u8);

    public static ParseResult Parse(byte[] sqliteDb, int sampleLimit = int.MaxValue)
    {
        if (!LooksLikeSqlite(sqliteDb))
            return new ParseResult(false, "magic non SQLite", [], 0, 0, []);

        var tmp = Path.Combine(Path.GetTempPath(), $"flist_{Guid.NewGuid():N}.db");
        try
        {
            File.WriteAllBytes(tmp, sqliteDb);
            return ParseFile(tmp, sampleLimit);
        }
        finally
        {
            try { File.Delete(tmp); } catch { /* ignore */ }
        }
    }

    public static ParseResult ParseFile(string dbPath, int sampleLimit = int.MaxValue)
    {
        try
        {
            using var con = OpenReadOnly(dbPath);
            var tables = ReadTables(con);
            var assetRows = Count(con, "Assets");
            var metaRows = Count(con, "FileMetadata");

            var entries = new List<Entry>();
            using (var cmd = con.CreateCommand())
            {
                cmd.CommandText = sampleLimit < int.MaxValue
                    ? JoinSql + $" LIMIT {sampleLimit}"
                    : JoinSql;
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    entries.Add(new Entry(
                        RecordIdSuffix: r.IsDBNull(0) ? "" : r.GetString(0),
                        EncryptionKey: ReadBlob(r, 1),
                        RelativePath: r.IsDBNull(2) ? "" : r.GetString(2),
                        Size: r.IsDBNull(3) ? 0 : r.GetInt64(3),
                        Mode: r.IsDBNull(4) ? 0 : r.GetInt64(4),
                        ProtectionClass: r.IsDBNull(5) ? 0 : r.GetInt32(5),
                        Modified: r.IsDBNull(6) ? 0 : r.GetInt64(6),
                        Birth: r.IsDBNull(7) ? 0 : r.GetInt64(7),
                        StatusChanged: r.IsDBNull(8) ? 0 : r.GetInt64(8),
                        AssetSignature: ReadBlob(r, 9),
                        AssetSize: r.IsDBNull(10) ? null : r.GetInt64(10)));
                }
            }

            return new ParseResult(true, null, tables, assetRows, metaRows, entries);
        }
        catch (Exception ex)
        {
            return new ParseResult(false, ex.Message, [], 0, 0, []);
        }
    }

    public static InventoryResult ParseInventory(string dbPath)
    {
        try
        {
            using var con = OpenReadOnly(dbPath);
            var assetRows = Count(con, "Assets");
            var metaRows = Count(con, "FileMetadata");
            var rows = new List<InventoryRow>(Math.Max(metaRows, 16));

            using var cmd = con.CreateCommand();
            cmd.CommandText = InventorySql;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                rows.Add(new InventoryRow(
                    Inode: r.IsDBNull(0) ? 0 : r.GetInt64(0),
                    RelativePath: r.IsDBNull(1) ? "" : r.GetString(1),
                    Size: r.IsDBNull(2) ? 0 : r.GetInt64(2),
                    Birth: r.IsDBNull(3) ? 0 : r.GetInt64(3),
                    Modified: r.IsDBNull(4) ? 0 : r.GetInt64(4),
                    StatusChanged: r.IsDBNull(5) ? 0 : r.GetInt64(5),
                    UserId: r.IsDBNull(6) ? 0 : r.GetInt64(6),
                    GroupId: r.IsDBNull(7) ? 0 : r.GetInt64(7),
                    Mode: r.IsDBNull(8) ? 0 : r.GetInt64(8),
                    Flags: r.IsDBNull(9) ? 0 : r.GetInt64(9),
                    ProtectionClass: r.IsDBNull(10) ? 0 : r.GetInt32(10),
                    Xattrs: ReadBlob(r, 11),
                    RecordIdSuffix: r.IsDBNull(12) ? null : r.GetString(12),
                    EncryptionKey: ReadBlob(r, 13),
                    AssetSignature: ReadBlob(r, 14),
                    AssetSize: r.IsDBNull(15) ? null : r.GetInt64(15),
                    AssetType: r.IsDBNull(16) ? null : r.GetInt64(16),
                    CompressionMethod: r.IsDBNull(17) ? null : r.GetInt64(17)));
            }

            return new InventoryResult(true, null, assetRows, metaRows, rows);
        }
        catch (Exception ex)
        {
            return new InventoryResult(false, ex.Message, 0, 0, []);
        }
    }

    private static SqliteConnection OpenReadOnly(string dbPath)
    {
        var cs = new SqliteConnectionStringBuilder
        {
            DataSource = dbPath,
            Mode = SqliteOpenMode.ReadOnly,
            Cache = SqliteCacheMode.Shared
        }.ToString();
        var con = new SqliteConnection(cs);
        con.Open();
        return con;
    }

    private static List<string> ReadTables(SqliteConnection con)
    {
        var tables = new List<string>();
        using var cmd = con.CreateCommand();
        cmd.CommandText = "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name";
        using var r = cmd.ExecuteReader();
        while (r.Read())
            tables.Add(r.GetString(0));
        return tables;
    }

    private static int Count(SqliteConnection con, string table)
    {
        try
        {
            using var cmd = con.CreateCommand();
            cmd.CommandText = $"SELECT COUNT(*) FROM \"{table}\"";
            return Convert.ToInt32(cmd.ExecuteScalar());
        }
        catch
        {
            return 0;
        }
    }

    private static byte[]? ReadBlob(SqliteDataReader r, int ordinal)
    {
        if (r.IsDBNull(ordinal))
            return null;
        using var s = r.GetStream(ordinal);
        using var ms = new MemoryStream();
        s.CopyTo(ms);
        return ms.Length == 0 ? null : ms.ToArray();
    }
}
