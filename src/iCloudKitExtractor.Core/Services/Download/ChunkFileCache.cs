using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Download;

/// <summary>
/// Cache file <c>CChunkCache</c> / <c>Downloads\.chunks\&lt;hex(sig)&gt;</c>.
/// Nome = hex minuscolo della signature (21 → 42, 45 → 90).
/// DecryptFord: open + <c>Read(ctLen)</c> — non slice RAM del pack.
/// </summary>
public static class ChunkFileCache
{
    private static string? _root;

    public static string? RootDirectory => _root;

    public static void Bind(string directory)
    {
        if (string.IsNullOrWhiteSpace(directory))
            return;
        _root = directory;
        Directory.CreateDirectory(directory);
    }

    /// <summary>Probe/test: punta a una cartella temp (o svuota i file signature se già bound).</summary>
    public static void ClearForTests(string? tempDirectory = null)
    {
        if (!string.IsNullOrWhiteSpace(tempDirectory))
        {
            _root = tempDirectory;
            Directory.CreateDirectory(tempDirectory);
        }

        if (_root is null || !Directory.Exists(_root))
            return;
        try
        {
            foreach (var f in Directory.EnumerateFiles(_root))
            {
                var name = Path.GetFileName(f);
                if (IsSignatureFileName(name))
                    File.Delete(f);
            }
        }
        catch
        {
            /* ignore */
        }
    }

    public static string FileName(ReadOnlySpan<byte> signature) =>
        Convert.ToHexString(signature).ToLowerInvariant();

    public static bool IsSignatureFileName(string name) =>
        name.Length is 42 or 90 && name.All(static c =>
            c is >= '0' and <= '9' or >= 'a' and <= 'f');

    public static void Put(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> body) =>
        PutCore(signature, body, overwrite: false);

    /// <summary>Sostituisce entry head-04 (plant IKM-validated che corregge Offset sbagliato).</summary>
    public static void PutOverwrite(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> body) =>
        PutCore(signature, body, overwrite: true);

    /// <summary>
    /// Ford gate (45): body ≤ sanità; bound reale = ByteRange host a valle.
    /// Data sig (21): può superare 64 KiB (es. Categories 73728) — cap MMCS-pratico.
    /// </summary>
    private static bool BodyLenOk(int sigLen, int bodyLen) =>
        bodyLen >= 0x12
        && (sigLen == 45
            ? UbChunkBuilder.IsPlausibleAuthFordCtLen(bodyLen)
            : bodyLen <= 32 * 1024 * 1024);

    private static void PutCore(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> body, bool overwrite)
    {
        if (_root is null
            || signature.Length is not (21 or 45)
            || !BodyLenOk(signature.Length, body.Length))
            return;

        // Data CI21: spill `.chunks/<hex(checksum21)>` accetta qualsiasi lead
        // (live 2026-10-09: head C4D2… len 73728). Lead 0x04 è tipico Ford CT, non
        // requisito data. Anti-poison Ford resta in PlantAuth / IsFordPrefixPoison.
        if (signature.Length == 21 && body.Length == 0)
            return;

        var name = FileName(signature);
        var path = Path.Combine(_root, name);
        try
        {
            //  un file = body di QUEL gate/sig. Non sovrascrivere con pack più lungo.
            // Eccezione: entry stessa len ma head≠0x04 (plant avvelenato) → sostituisci con Ford.
            // overwrite=true: IKM-open correttivo (3029 pad/scan vs Offset chiuso).
            if (!overwrite && File.Exists(path))
            {
                var existing = new FileInfo(path).Length;
                if (existing == body.Length)
                {
                    if (body.Length > 0 && body[0] == 0x04)
                    {
                        try
                        {
                            var head = new byte[1];
                            using (var fs = new FileStream(
                                       path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                            {
                                if (fs.Read(head, 0, 1) == 1 && head[0] == 0x04)
                                    return;
                            }
                        }
                        catch
                        {
                            return;
                        }
                    }
                    else
                        return;
                }
                else if (existing > 0 && existing < body.Length)
                    return;
            }

            File.WriteAllBytes(path, body.ToArray());
            // #region agent log
            AgentLog(overwrite ? "chunkfile_put_ow" : "chunkfile_put", name, body.Length, body.Length, 0);
            // #endregion
        }
        catch
        {
            // non bloccare il download
        }
    }

    /// <summary><c>stream.Read(ctLen)</c> sul file <c>.chunks/hex(sig)</c>.</summary>
    public static bool TryRead(ReadOnlySpan<byte> signature, int ctLen, out byte[] body)
    {
        body = [];
        if (_root is null
            || signature.Length is not (21 or 45)
            || !BodyLenOk(signature.Length, ctLen))
            return false;
        var path = Path.Combine(_root, FileName(signature));
        if (!File.Exists(path))
            return false;

        try
        {
            using var fs = new FileStream(
                path, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            if (fs.Length < ctLen)
            {
                // #region agent log
                AgentLog("chunkfile_short", FileName(signature), ctLen, (int)fs.Length, 0);
                // #endregion
                return false;
            }

            body = new byte[ctLen];
            var n = fs.Read(body, 0, ctLen);
            if (n != ctLen)
            {
                body = [];
                return false;
            }

            // #region agent log
            AgentLog("chunkfile_read", FileName(signature), ctLen, (int)fs.Length, 1);
            // #endregion
            return true;
        }
        catch
        {
            body = [];
            return false;
        }
    }

    public static bool HasExact(ReadOnlySpan<byte> signature, int ctLen)
    {
        if (_root is null || signature.Length is not (21 or 45) || ctLen <= 0)
            return false;
        var path = Path.Combine(_root, FileName(signature));
        try
        {
            return File.Exists(path) && new FileInfo(path).Length == ctLen;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>Rimuove entry poison (CT che non apre con IKM) prima di un re-GET.</summary>
    public static bool TryDelete(ReadOnlySpan<byte> signature)
    {
        if (_root is null || signature.Length is not (21 or 45))
            return false;
        var path = Path.Combine(_root, FileName(signature));
        try
        {
            if (!File.Exists(path))
                return false;
            File.Delete(path);
            // #region agent log
            AgentLog("chunkfile_delete", FileName(signature), 0, 0, 1);
            // #endregion
            return true;
        }
        catch
        {
            return false;
        }
    }

    // #region agent log
    private static int _logN;
    private static void AgentLog(string message, string name, int ctLen, int fileLen, int ok)
    {
        if (Interlocked.Increment(ref _logN) > 40)
            return;
        try
        {
            File.AppendAllText(
                @"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-03cce7.log",
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = "ike-chunkfile-v1",
                    ["hypothesisId"] = "H-CHUNKFILE",
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "ChunkFileCache",
                    ["message"] = message,
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["name12"] = name.Length >= 12 ? name[..12] : name,
                        ["nameLen"] = name.Length,
                        ["ctLen"] = ctLen,
                        ["fileLen"] = fileLen,
                        ["ok"] = ok,
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
    }
    // #endregion
}
