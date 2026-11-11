using System.IO;

namespace iCloudKitExtractor.Services;

/// <summary>
/// Dump opzionali su disco durante il backup download (perf).
/// Di default <b>spenti</b>: non servono al decrypt live (auth/body restano in RAM;
/// wrap kalama vengono indicizzati in memoria via <c>AbsorbWrapsFromPayload</c>).
/// <list type="bullet">
/// <item><c>IKE_DUMP_AUTH=1</c> — <c>AUTH_BATCH_*.bin</c></item>
/// <item><c>IKE_DUMP_EDGE=1</c> — <c>.edge_compact.bin</c> / <c>.ciphertext</c> (non lo staging OBJ)</item>
/// <item><c>IKE_DUMP_KALAMA=1</c> — cartella <c>kalama_records/</c> (query_*.bin, solo offline/debug;
/// wrap live restano in RAM via AbsorbWraps + indice multi-candidate)</item>
/// </list>
/// Lo staging <c>OBJ_*.bin</c> sul path flist con <c>prebuiltCompact</c> è skippato
/// (body in RAM → solo <c>Backup/</c>). Resta per path monofile / dump edge.
/// </summary>
public static class IkeDiskDumpOptions
{
    private static int _auth = -1;
    private static int _edge = -1;
    private static int _kalama = -1;

    public static bool DumpAuthBatch
    {
        get => ReadFlag(ref _auth, "IKE_DUMP_AUTH");
        set => Volatile.Write(ref _auth, value ? 1 : 0);
    }

    public static bool DumpEdgeSidecars
    {
        get => ReadFlag(ref _edge, "IKE_DUMP_EDGE");
        set => Volatile.Write(ref _edge, value ? 1 : 0);
    }

    public static bool DumpKalamaRecords
    {
        get => ReadFlag(ref _kalama, "IKE_DUMP_KALAMA");
        set => Volatile.Write(ref _kalama, value ? 1 : 0);
    }

    public static void SetFromUi(bool auth, bool edge, bool kalama)
    {
        DumpAuthBatch = auth;
        DumpEdgeSidecars = edge;
        DumpKalamaRecords = kalama;
    }

    private static bool ReadFlag(ref int field, string envName)
    {
        var v = Volatile.Read(ref field);
        if (v >= 0)
            return v != 0;
        var env = Environment.GetEnvironmentVariable(envName);
        var on = IsTruthy(env);
        Volatile.Write(ref field, on ? 1 : 0);
        return on;
    }

    private static bool IsTruthy(string? env) =>
        env is "1" or "true" or "TRUE" or "yes" or "YES" or "on" or "ON";
}
