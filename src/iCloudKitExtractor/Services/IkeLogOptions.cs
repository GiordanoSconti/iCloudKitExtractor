using System.IO;

namespace iCloudKitExtractor.Services;

/// <summary>
/// Gate log info/warning (UI + disco). Errori restano sempre attivi.
/// <list type="bullet">
/// <item>UI: checkbox «Solo errori» oppure <c>IKE_QUIET=1</c> (default se var assente: vedi <see cref="Quiet"/>).</item>
/// <item>Disco: salta journal <c>pending_chunks</c> / fallback rumorosi; niente NDJSON agent su hot path.</item>
/// <item>UI: checkbox «Salva log run» / <c>IKE_PERSIST_RUN_LOGS</c> → %AppData%/iCloudKitExtractor/logs/run_*.</item>
/// </list>
/// Disattiva quiet con checkbox off o <c>IKE_QUIET=0</c>.
/// </summary>
public static class IkeLogOptions
{
    private static int _quiet = -1; // -1 = lazy from env
    private static int _persistRunLogs = -1; // -1 = lazy from env
    private static int _fullHarCapture = -1; // -1 = lazy from env

    /// <summary>
    /// True = solo errori (veloce). Override UI tramite <see cref="SetQuiet"/>.
    /// Env: <c>IKE_QUIET=1</c> on, <c>=0</c> off; se assente default <c>true</c> (perf).
    /// </summary>
    public static bool Quiet
    {
        get
        {
            var v = Volatile.Read(ref _quiet);
            if (v >= 0)
                return v != 0;
            var env = Environment.GetEnvironmentVariable("IKE_QUIET");
            var on = string.IsNullOrWhiteSpace(env)
                     || IsTruthy(env);
            Volatile.Write(ref _quiet, on ? 1 : 0);
            return on;
        }
    }

    public static void SetQuiet(bool quiet) =>
        Volatile.Write(ref _quiet, quiet ? 1 : 0);

    /// <summary>
    /// True = scrivi capture HTTP/auth in
    /// <c>%AppData%/iCloudKitExtractor/logs/run_*</c>.
    /// Override UI tramite <see cref="SetPersistRunLogs"/>.
    /// Env: <c>IKE_PERSIST_RUN_LOGS=1</c> on, <c>=0</c> off; se assente default <c>false</c>.
    /// </summary>
    public static bool PersistRunLogs
    {
        get
        {
            var v = Volatile.Read(ref _persistRunLogs);
            if (v >= 0)
                return v != 0;
            var env = Environment.GetEnvironmentVariable("IKE_PERSIST_RUN_LOGS");
            // Default off: capture HTTP (body+headers) può superare 2× lo snapshot.
            var on = !string.IsNullOrWhiteSpace(env) && IsTruthy(env);
            Volatile.Write(ref _persistRunLogs, on ? 1 : 0);
            return on;
        }
    }

    public static void SetPersistRunLogs(bool persist) =>
        Volatile.Write(ref _persistRunLogs, persist ? 1 : 0);

    /// <summary>
    /// True = HAR 1.2 di <b>tutte</b> le req/resp (anche HTTP OK in Quiet).
    /// Implica persist run logs. Env: <c>IKE_FULL_HAR=1</c>.
    /// Output: <c>session.har</c> + <c>session_redacted.har</c> nella run.
    /// </summary>
    public static bool FullHarCapture
    {
        get
        {
            var v = Volatile.Read(ref _fullHarCapture);
            if (v >= 0)
                return v != 0;
            var env = Environment.GetEnvironmentVariable("IKE_FULL_HAR");
            var on = !string.IsNullOrWhiteSpace(env) && IsTruthy(env);
            Volatile.Write(ref _fullHarCapture, on ? 1 : 0);
            return on;
        }
    }

    public static void SetFullHarCapture(bool enabled)
    {
        Volatile.Write(ref _fullHarCapture, enabled ? 1 : 0);
        if (enabled)
            SetPersistRunLogs(true);
    }

    /// <summary>UI / <c>IProgress&lt;string&gt;</c>: emetti solo se errore, o se non-quiet.</summary>
    public static bool ShouldEmitUi(string? line)
    {
        if (!Quiet)
            return true;
        return IsErrorLine(line);
    }

    /// <summary>
    /// Journal <c>decrypt_failures</c>: in quiet solo stage “hard fail”.
    /// </summary>
    public static bool ShouldJournal(string stage)
    {
        if (!Quiet)
            return true;
        if (string.IsNullOrWhiteSpace(stage))
            return false;
        return stage switch
        {
            "pending_chunks" => false,
            "ford_fallback" => false,
            "file_aes_not_decrypted" => false,
            _ => true, // size_mismatch, mmcs_not_decrypted, batch_error, skip_crypto, …
        };
    }

    /// <summary>NDJSON agent / diag hot-path: mai in quiet (usa <c>IKE_AGENT_DIAG=1</c> + quiet off).</summary>
    public static bool ShouldWriteAgentDiag =>
        !Quiet
        && string.Equals(
            Environment.GetEnvironmentVariable("IKE_AGENT_DIAG"),
            "1",
            StringComparison.Ordinal);

    /// <summary>Append NDJSON solo se non-quiet (hot path download).</summary>
    public static void AppendAgentNdjson(string absolutePath, string jsonLine)
    {
        if (Quiet)
            return;
        try
        {
            File.AppendAllText(absolutePath, jsonLine + Environment.NewLine);
        }
        catch
        {
            // ignore
        }
    }

    public static bool IsErrorLine(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return false;

        // Progress "File 401/N:" — mai errore HTTP.
        if (System.Text.RegularExpressions.Regex.IsMatch(
                line,
                @"^\s*File\s+\d+\s*/\s*\d+\s*:",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase
                | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
            return false;

        if (ContainsAny(line,
                "verifyDigest=ok",
                "chunk OK",
                "decryptFord",
                "decrypt in coda",
                "mmcs_cache: rilasciati"))
            return false;

        if (line.Contains("[HTTP]", StringComparison.OrdinalIgnoreCase)
            && line.Contains("REQUEST", StringComparison.OrdinalIgnoreCase)
            && !HasHttpResponseStatusError(line))
            return false;

        var scan = System.Text.RegularExpressions.Regex.Replace(
            line,
            @"fail\s*=\s*0(?:/\d+)?",
            "okcount",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase);

        return HasLogErrorToken(scan)
               || HasHttpResponseStatusError(scan)
               || ContainsAny(scan,
                   "Exception", "NullReference", "Unauthorized",
                   "decrypt fail", "decrypt fallito", "crypto abort", "Invalid nonce",
                   "≠ assetSize", "size_mismatch", "no-ikm", "no-resolve",
                   "Stream was too long", "OutOfMemory",
                   "batch fail", "Collection was modified",
                   "decrypt_failures", "MmcsAuth assente");
    }

    private static bool IsTruthy(string env) =>
        env is "1" or "true" or "TRUE" or "yes" or "YES" or "on" or "ON";

    private static bool ContainsAny(string line, params string[] needles)
    {
        foreach (var n in needles)
        {
            if (line.Contains(n, StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    private static bool HasLogErrorToken(string line) =>
        System.Text.RegularExpressions.Regex.IsMatch(
            line,
            @"\b(?:ERROR|FAIL|FATAL|CRITIC(?:AL)?|ABORT|Errore|abortito|interrotto)\b",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
            | System.Text.RegularExpressions.RegexOptions.CultureInvariant);

    /// <summary>
    /// Solo status di <b>risposta HTTP</b> (es. <c>RESPONSE 401</c>, <c>HTTP 403</c>).
    /// Non matcha progress tipo <c>File 401/56279</c>.
    /// </summary>
    public static bool HasHttpResponseStatusError(string? line)
    {
        if (string.IsNullOrWhiteSpace(line))
            return false;

        // Contatori progresso: "File 401/56279: path" — non sono HTTP.
        if (System.Text.RegularExpressions.Regex.IsMatch(
                line,
                @"^\s*File\s+\d+\s*/\s*\d+\s*:",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase
                | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
            return false;

        // Tracer HTTP / blocchi capture: "RESPONSE 401".
        if (System.Text.RegularExpressions.Regex.IsMatch(
                line,
                @"\bRESPONSE\s+(?:401|403|404|408|429|5\d{2})\b",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase
                | System.Text.RegularExpressions.RegexOptions.CultureInvariant))
            return true;

        // Messaggi layer HTTP espliciti: "HTTP 401", "HTTP/1.1 403".
        return System.Text.RegularExpressions.Regex.IsMatch(
            line,
            @"\bHTTP(?:/\d\.\d)?\s+(?:401|403|404|408|429|5\d{2})\b",
            System.Text.RegularExpressions.RegexOptions.IgnoreCase
            | System.Text.RegularExpressions.RegexOptions.CultureInvariant);
    }

    private static bool HasHttpStatusError(string line) =>
        HasHttpResponseStatusError(line);
}
