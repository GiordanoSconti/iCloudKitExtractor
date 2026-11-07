namespace iCloudKitExtractor.Services.Forensics;

/// <summary>
/// Inizializza il provider nativo SQLitePCL (e_sqlite3) una sola volta.
/// Senza questo, <c>SqliteConnection</c> può fallire nel type initializer
/// (provider non configurato / native DLL non caricata).
/// </summary>
public static class SqliteBootstrap
{
    private static readonly object Gate = new();
    private static bool _ready;
    private static Exception? _initError;

    public static void EnsureInitialized()
    {
        if (_ready)
            return;

        lock (Gate)
        {
            if (_ready)
                return;

            try
            {
                SQLitePCL.Batteries_V2.Init();
                _ready = true;
            }
            catch (Exception ex)
            {
                _initError = ex;
                throw new InvalidOperationException(
                    "SQLitePCL Batteries_V2.Init fallito — manca e_sqlite3 nativo " +
                    "o bundle SQLitePCLRaw.bundle_e_sqlite3 non copiato nell'output. " +
                    $"Dettaglio: {Flatten(ex)}",
                    ex);
            }
        }
    }

    public static string? LastInitError => _initError is null ? null : Flatten(_initError);

    private static string Flatten(Exception ex)
    {
        var parts = new List<string>();
        for (Exception? e = ex; e is not null; e = e.InnerException)
            parts.Add($"{e.GetType().Name}: {e.Message}");
        return string.Join(" → ", parts);
    }
}
