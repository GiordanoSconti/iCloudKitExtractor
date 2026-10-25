using System.Net;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Download;

/// <summary>Edge GET fallito: URL/header firmati scaduti (tipico 403/503).</summary>
public sealed class EdgeUrlExpiredException : Exception
{
    public HttpStatusCode StatusCode { get; }

    public EdgeUrlExpiredException(HttpStatusCode status, string message)
        : base(message)
    {
        StatusCode = status;
    }
}

/// <summary>
/// Stato authorizeGet per un download edge: su 403/503 riesegue authorizeGet
/// e rimappa i chunk per object-id + byte range.
/// </summary>
public sealed class EdgeDownloadAuthState
{
    /// <summary>
    /// Oltre questa età (ms) le URL edge si considerano a rischio scadenza:
    /// refresh proattivo prima del GET. Abbassato 30s→15s: con gate pieno le URL
    /// invecchiano in coda (log 403 expired=true edgeInFlight=8).
    /// </summary>
    public const int MaxAuthAgeMsBeforeRefresh = 15_000;

    /// <summary>
    /// Se il GET ha atteso il gate edge oltre questa soglia, rinnova auth
    /// prima di usare le URL (coda lunga = scadenza tipica).
    /// </summary>
    public const int GateWaitMsBeforeRefresh = 2_000;

    private readonly Func<CancellationToken, Task<(byte[] AuthBody, IReadOnlyList<SignedUrlChunk> Chunks)>>
        _refreshAsync;
    private readonly IReadOnlyList<SignedUrlChunk> _template;
    private readonly SemaphoreSlim _refreshGate = new(1, 1);
    private int _refreshCount;
    private long _lastRefreshTicks;
    private long _authIssuedTicks;

    public byte[] AuthBody { get; private set; }
    public IReadOnlyList<SignedUrlChunk> Chunks { get; private set; }

    private EdgeDownloadAuthState(
        byte[] authBody,
        IReadOnlyList<SignedUrlChunk> chunks,
        IReadOnlyList<SignedUrlChunk> template,
        Func<CancellationToken, Task<(byte[] AuthBody, IReadOnlyList<SignedUrlChunk> Chunks)>> refreshAsync)
    {
        AuthBody = authBody;
        Chunks = chunks;
        _template = template;
        _refreshAsync = refreshAsync;
        _authIssuedTicks = Environment.TickCount64;
    }

    public static EdgeDownloadAuthState ForAsset(
        byte[] authBody,
        IReadOnlyList<SignedUrlChunk> chunks,
        Func<CancellationToken, Task<(byte[] AuthBody, IReadOnlyList<SignedUrlChunk> Chunks)>> refreshAsync) =>
        new(authBody, chunks, chunks, refreshAsync);

    public int RefreshCount => _refreshCount;

    /// <summary>Ms dall'ultimo authorizeGet (iniziale o refresh) che ha prodotto le URL correnti.</summary>
    public long AuthAgeMs
    {
        get
        {
            var age = Environment.TickCount64 - Volatile.Read(ref _authIssuedTicks);
            return age < 0 ? 0 : age;
        }
    }

    public bool ShouldRefreshProactively(long gateWaitMs) =>
        AuthAgeMs >= MaxAuthAgeMsBeforeRefresh
        || gateWaitMs >= GateWaitMsBeforeRefresh;

    public SignedUrlChunk RemapChunk(SignedUrlChunk chunk) =>
        EdgeChunkRemap.RemapByObjectRange([chunk], Chunks)[0];

    public async Task<SignedUrlChunk> RefreshAndRemapChunkAsync(
        SignedUrlChunk chunk,
        CancellationToken ct,
        bool force = false)
    {
        await RefreshAsync(ct, force).ConfigureAwait(false);
        return RemapChunk(chunk);
    }

    /// <param name="force">
    /// True = ignora debounce 10s (obbligatorio dopo 403 o attesa gate lunga).
    /// </param>
    public async Task RefreshAsync(CancellationToken ct, bool force = false)
    {
        await _refreshGate.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            var now = Environment.TickCount64;
            // Debounce solo su refresh "soft": dopo 403/gate-wait serve sempre un wire nuovo.
            if (!force && _refreshCount > 0 && now - _lastRefreshTicks < 10_000)
                return;

            var (auth, fresh) = await _refreshAsync(ct).ConfigureAwait(false);
            AuthBody = auth;
            Chunks = EdgeChunkRemap.RemapByObjectRange(_template, fresh);
            _refreshCount++;
            _lastRefreshTicks = now;
            Volatile.Write(ref _authIssuedTicks, now);
        }
        finally
        {
            _refreshGate.Release();
        }
    }
}

internal static class EdgeChunkRemap
{
    /// <summary>
    /// Status ritentabili con refresh URL / nuovo tentativo GET.
    /// Include 500: errore tipico CDN/edge Apple (lato server), non abort snapshot.
    /// </summary>
    internal static bool IsExpiredEdgeStatus(HttpStatusCode status) =>
        status is HttpStatusCode.Forbidden
            or HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;

    /// <summary>5xx edge = fallimento lato server (non bug client / URL scaduta sola).</summary>
    internal static bool IsServerSideEdgeStatus(HttpStatusCode status) =>
        status is HttpStatusCode.InternalServerError
            or HttpStatusCode.BadGateway
            or HttpStatusCode.ServiceUnavailable
            or HttpStatusCode.GatewayTimeout;

    internal static List<SignedUrlChunk> RemapByObjectRange(
        IReadOnlyList<SignedUrlChunk> template,
        IReadOnlyList<SignedUrlChunk> freshPool)
    {
        var lookup = new Dictionary<(string Oid, long Start, long End), SignedUrlChunk>();
        foreach (var c in freshPool)
        {
            if (c.ByteRange is not { } br)
                continue;
            var oid = c.EdgeHeaders?.ObjectId ?? string.Empty;
            lookup[(oid, br.Start, br.End)] = c;
        }

        var result = new List<SignedUrlChunk>(template.Count);
        for (var i = 0; i < template.Count; i++)
        {
            var t = template[i];
            if (t.ByteRange is not { } tbr)
            {
                result.Add(i < freshPool.Count ? freshPool[i] : t);
                continue;
            }

            var key = (t.EdgeHeaders?.ObjectId ?? string.Empty, tbr.Start, tbr.End);
            if (!lookup.TryGetValue(key, out var match))
            {
                throw new InvalidOperationException(
                    $"edge refresh: chunk assente oid={key.Item1} range={key.Start}-{key.End}");
            }

            result.Add(match);
        }

        return result;
    }
}
