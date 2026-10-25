using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using AnisetteBridge;

var host = Environment.GetEnvironmentVariable("ANISETTE_BRIDGE_SERVER_HOST")
    ?? throw new InvalidOperationException("Imposta ANISETTE_BRIDGE_SERVER_HOST (IP pubblico Windows).");
var port = ResolveInt("ANISETTE_BRIDGE_SERVER_PORT", 6971);
var token = Environment.GetEnvironmentVariable("ANISETTE_BRIDGE_TOKEN")
    ?? throw new InvalidOperationException("Imposta ANISETTE_BRIDGE_TOKEN (stesso valore del server Windows).");
var anisetteUrl = Environment.GetEnvironmentVariable("ANISETTE_LOCAL_URL") ?? "http://127.0.0.1:6969/";
var reconnectSec = ResolveInt("ANISETTE_BRIDGE_RECONNECT_SEC", 5);

using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(25) };

Console.WriteLine("AnisetteBridge CLIENT (Mac)");
Console.WriteLine($"  Server: {host}:{port}");
Console.WriteLine($"  Anisette locale: {anisetteUrl}");

while (true)
{
    try
    {
        await RunSessionAsync(host, port, token, anisetteUrl, http).ConfigureAwait(false);
    }
    catch (Exception ex)
    {
        Console.WriteLine($"[client] Sessione terminata: {ex.Message}");
    }

    Console.WriteLine($"[client] Riconnessione tra {reconnectSec}s…");
    await Task.Delay(TimeSpan.FromSeconds(reconnectSec)).ConfigureAwait(false);
}

static int ResolveInt(string name, int fallback) =>
    int.TryParse(Environment.GetEnvironmentVariable(name), out var value) ? value : fallback;

static async Task RunSessionAsync(
    string host,
    int port,
    string token,
    string anisetteUrl,
    HttpClient http)
{
    using var tcp = new TcpClient();
    Console.WriteLine($"[client] Connessione a {host}:{port}…");
    await tcp.ConnectAsync(host, port).ConfigureAwait(false);
    tcp.NoDelay = true;

    using var stream = tcp.GetStream();
    using var reader = new StreamReader(stream, Encoding.UTF8, leaveOpen: true);
    using var writer = new StreamWriter(stream, new UTF8Encoding(false)) { AutoFlush = true, NewLine = "\n" };

    await LineJsonProtocol.WriteAsync(writer, new BridgeRegisterMessage
    {
        Token = token,
        AnisetteUrl = anisetteUrl
    }, CancellationToken.None).ConfigureAwait(false);

    var regLine = await LineJsonProtocol.ReadLineAsync(reader, CancellationToken.None).ConfigureAwait(false);
    if (regLine is null)
        throw new IOException("Server chiuso durante register.");

    var registered = JsonSerializer.Deserialize<BridgeRegisteredMessage>(regLine, BridgeJson.Options);
    if (registered is null || !registered.Ok)
        throw new InvalidOperationException(registered?.Error ?? "Register rifiutato dal server.");

    Console.WriteLine("[client] Registrato — in attesa di comandi fetch…");

    while (true)
    {
        var line = await LineJsonProtocol.ReadLineAsync(reader, CancellationToken.None).ConfigureAwait(false);
        if (line is null)
            break;

        using var doc = JsonDocument.Parse(line);
        var type = doc.RootElement.GetProperty("type").GetString();
        if (type == "ping")
        {
            await LineJsonProtocol.WriteAsync(writer, new BridgePongMessage(), CancellationToken.None).ConfigureAwait(false);
            continue;
        }

        if (type != "fetch")
            continue;

        var id = doc.RootElement.GetProperty("id").GetString() ?? string.Empty;
        var fetched = await FetchLocalAnisetteAsync(http, anisetteUrl).ConfigureAwait(false);
        fetched.Id = id;
        await LineJsonProtocol.WriteAsync(writer, fetched, CancellationToken.None).ConfigureAwait(false);
    }
}

static async Task<BridgeFetchResultMessage> FetchLocalAnisetteAsync(HttpClient http, string anisetteUrl)
{
    try
    {
        using var response = await http.GetAsync(anisetteUrl).ConfigureAwait(false);
        var body = await response.Content.ReadAsStringAsync().ConfigureAwait(false);
        return new BridgeFetchResultMessage
        {
            Ok = response.IsSuccessStatusCode,
            Status = (int)response.StatusCode,
            Body = response.IsSuccessStatusCode ? body : null,
            Error = response.IsSuccessStatusCode ? null : Trim(body)
        };
    }
    catch (Exception ex)
    {
        return new BridgeFetchResultMessage
        {
            Ok = false,
            Status = 0,
            Error = ex.Message
        };
    }
}

static string Trim(string s) => s.Length <= 300 ? s : s[..300] + "…";
