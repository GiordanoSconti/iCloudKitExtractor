using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using AnisetteBridge;

var tcpBind = Environment.GetEnvironmentVariable("ANISETTE_BRIDGE_TCP_BIND") ?? "0.0.0.0";
var tcpPort = ResolveInt("ANISETTE_BRIDGE_TCP_PORT", 6971);
var httpBind = Environment.GetEnvironmentVariable("ANISETTE_BRIDGE_HTTP_BIND") ?? "127.0.0.1";
var httpPort = ResolveInt("ANISETTE_BRIDGE_HTTP_PORT", 6970);
var token = Environment.GetEnvironmentVariable("ANISETTE_BRIDGE_TOKEN")
    ?? throw new InvalidOperationException("Imposta ANISETTE_BRIDGE_TOKEN (segreto condiviso con il client Mac).");

var session = new BridgeClientSession(token);
_ = Task.Run(() => RunTcpAcceptLoopAsync(session, tcpBind, tcpPort));

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseUrls($"http://{httpBind}:{httpPort}");
var app = builder.Build();

app.MapGet("/health", () =>
{
    var connected = session.IsConnected;
    return Results.Json(new
    {
        ok = connected,
        clientConnected = connected,
        lastError = session.LastError,
        lastFetchUtc = session.LastFetchUtc
    }, statusCode: connected ? 200 : 503);
});

app.MapGet("/", async (CancellationToken ct) =>
{
    if (!session.IsConnected)
    {
        return Results.Json(new { error = "Nessun client Mac connesso al bridge." }, statusCode: 503);
    }

    try
    {
        var body = await session.FetchAsync(ct).ConfigureAwait(false);
        return Results.Content(body, "application/json");
    }
    catch (Exception ex)
    {
        return Results.Json(new { error = ex.Message }, statusCode: 502);
    }
});

Console.WriteLine("AnisetteBridge SERVER");
Console.WriteLine($"  TCP client Mac: {tcpBind}:{tcpPort}  (port-forward su router → questo host)");
Console.WriteLine($"  HTTP app locale: http://{httpBind}:{httpPort}/");
Console.WriteLine($"  Token: {token[..Math.Min(6, token.Length)]}… (ANISETTE_BRIDGE_TOKEN)");
Console.WriteLine("  anisette.json → \"serverUrl\": \"http://127.0.0.1:6970\", \"authMode\": \"iphone\"");

await app.RunAsync();

static int ResolveInt(string name, int fallback) =>
    int.TryParse(Environment.GetEnvironmentVariable(name), out var value) ? value : fallback;

static async Task RunTcpAcceptLoopAsync(BridgeClientSession session, string bind, int port)
{
    var listener = new TcpListener(IPAddress.Parse(bind), port);
    listener.Start();
    Console.WriteLine($"[tcp] In ascolto su {bind}:{port}");

    while (true)
    {
        TcpClient client;
        try
        {
            client = await listener.AcceptTcpClientAsync().ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"[tcp] Accept error: {ex.Message}");
            continue;
        }

        _ = Task.Run(() => session.HandleClientAsync(client));
    }
}

sealed class BridgeClientSession
{
    private readonly string _expectedToken;
    private readonly SemaphoreSlim _writeLock = new(1, 1);
    private readonly ConcurrentDictionary<string, TaskCompletionSource<BridgeFetchResultMessage>> _pending = new();
    private readonly object _gate = new();

    private StreamReader? _reader;
    private StreamWriter? _writer;
    private CancellationTokenSource? _readLoopCts;

    public BridgeClientSession(string expectedToken) => _expectedToken = expectedToken;

    public bool IsConnected
    {
        get { lock (_gate) return _writer is not null; }
    }

    public string? LastError { get; private set; }
    public DateTimeOffset? LastFetchUtc { get; private set; }

    public async Task HandleClientAsync(TcpClient tcp)
    {
        var endpoint = tcp.Client.RemoteEndPoint?.ToString() ?? "?";
        Console.WriteLine($"[tcp] Connessione da {endpoint}");

        tcp.NoDelay = true;
        using var network = tcp;
        using var stream = tcp.GetStream();
        using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
        using var writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };

        var registerLine = await LineJsonProtocol.ReadLineAsync(reader, CancellationToken.None).ConfigureAwait(false);
        if (registerLine is null)
        {
            Console.WriteLine($"[tcp] {endpoint}: chiusura prima del register");
            return;
        }

        BridgeRegisterMessage? register;
        try
        {
            register = JsonSerializer.Deserialize<BridgeRegisterMessage>(registerLine, BridgeJson.Options);
        }
        catch
        {
            register = null;
        }

        if (register is null || !string.Equals(register.Token, _expectedToken, StringComparison.Ordinal))
        {
            await LineJsonProtocol.WriteAsync(writer, new BridgeRegisteredMessage
            {
                Ok = false,
                Error = "Token non valido"
            }, CancellationToken.None).ConfigureAwait(false);
            Console.WriteLine($"[tcp] {endpoint}: register rifiutato");
            return;
        }

        lock (_gate)
        {
            _readLoopCts?.Cancel();
            _reader = reader;
            _writer = writer;
            _readLoopCts = new CancellationTokenSource();
        }

        await LineJsonProtocol.WriteAsync(writer, new BridgeRegisteredMessage { Ok = true }, CancellationToken.None)
            .ConfigureAwait(false);
        Console.WriteLine($"[tcp] Client registrato ({endpoint}) anisette={register.AnisetteUrl}");

        try
        {
            await ReadLoopAsync(reader, _readLoopCts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // sostituito da nuova connessione
        }
        catch (Exception ex)
        {
            LastError = ex.Message;
            Console.WriteLine($"[tcp] Read loop: {ex.Message}");
        }
        finally
        {
            lock (_gate)
            {
                if (ReferenceEquals(_reader, reader))
                {
                    _reader = null;
                    _writer = null;
                }
            }

            FailPending($"Client disconnesso ({endpoint})");
            Console.WriteLine($"[tcp] Client disconnesso {endpoint}");
        }
    }

    private async Task ReadLoopAsync(StreamReader reader, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var line = await LineJsonProtocol.ReadLineAsync(reader, ct).ConfigureAwait(false);
            if (line is null)
                break;

            BridgeFetchResultMessage? result;
            try
            {
                result = JsonSerializer.Deserialize<BridgeFetchResultMessage>(line, BridgeJson.Options);
            }
            catch
            {
                continue;
            }

            if (result is null || result.Type != "fetchResult" || string.IsNullOrEmpty(result.Id))
                continue;

            if (_pending.TryRemove(result.Id, out var tcs))
                tcs.TrySetResult(result);
        }
    }

    public async Task<string> FetchAsync(CancellationToken ct)
    {
        StreamWriter? writer;
        lock (_gate)
        {
            writer = _writer;
        }

        if (writer is null)
            throw new InvalidOperationException("Client Mac non connesso.");

        var id = Guid.NewGuid().ToString("N");
        var tcs = new TaskCompletionSource<BridgeFetchResultMessage>(TaskCreationOptions.RunContinuationsAsynchronously);
        _pending[id] = tcs;

        await _writeLock.WaitAsync(ct).ConfigureAwait(false);
        try
        {
            await LineJsonProtocol.WriteAsync(writer, new BridgeFetchMessage { Id = id }, ct).ConfigureAwait(false);
        }
        finally
        {
            _writeLock.Release();
        }

        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeout.CancelAfter(TimeSpan.FromSeconds(30));
        BridgeFetchResultMessage result;
        try
        {
            result = await tcs.Task.WaitAsync(timeout.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            _pending.TryRemove(id, out _);
            throw new TimeoutException("Timeout in attesa del client Mac (30s).");
        }

        LastFetchUtc = DateTimeOffset.UtcNow;

        if (!result.Ok || string.IsNullOrEmpty(result.Body))
        {
            LastError = result.Error ?? $"fetch fallito HTTP {result.Status}";
            throw new InvalidOperationException(LastError);
        }

        LastError = null;
        return result.Body;
    }

    private void FailPending(string reason)
    {
        foreach (var kv in _pending)
        {
            if (_pending.TryRemove(kv.Key, out var tcs))
                tcs.TrySetException(new IOException(reason));
        }
    }
}
