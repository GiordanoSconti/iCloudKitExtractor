using System.IO;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Push;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Facade runtime IDS multiplex1: open su enroll+APS, lookup, send/recv.
/// </summary>
public sealed class IdsSession : IDisposable
{
    private readonly HttpClient _http;
    private readonly ApsSessionService _aps;
    private readonly Action<string>? _log;
    private IdsBag? _bag;
    private IdsApsTransport? _transport;
    private IdsLookupClient? _lookup;
    private IdsMessagingClient? _messaging;
    private EventHandler<ApsNotificationEventArgs>? _apsHandler;
    private bool _open;

    public IdsSession(HttpClient http, ApsSessionService aps, Action<string>? log = null)
    {
        _http = http;
        _aps = aps;
        _log = log;
    }

    public bool IsOpen => _open;
    public IdsIdentity? Identity { get; private set; }
    public IdsIdentityCache Cache { get; } = new();
    public IdsServiceDefinition Service { get; private set; } = IdsServiceCatalog.MultiplexFindMy;
    public string? ProfileId { get; private set; }
    public IReadOnlyList<string> Handles { get; private set; } = Array.Empty<string>();
    public string? SelfHandle => Handles.FirstOrDefault();

    public event EventHandler<IdsMessageReceivedEventArgs>? MessageReceived;

    public async Task OpenAsync(ICloudSession? cloudSession = null, CancellationToken ct = default)
    {
        if (!IdsStorage.HasRegistration())
            throw new InvalidOperationException(
                "IDS non registrato — esegui Enroll IDS prima di aprire la sessione.");
        if (!_aps.IsConnected)
            throw new InvalidOperationException(
                "APS non connesso — Connetti APS prima della sessione IDS.");

        var meta = IdsStorage.TryLoadMeta()
                   ?? throw new InvalidOperationException("ids-meta.json assente dopo enroll.");
        if (string.IsNullOrWhiteSpace(meta.ProfileId))
            throw new InvalidOperationException("ProfileId IDS assente in meta.");
        if (meta.Handles is not { Count: > 0 })
            throw new InvalidOperationException("Nessun handle IDS in meta.");

        ProfileId = meta.ProfileId;
        Handles = meta.Handles.ToList();
        Identity = IdsIdentity.LoadOrCreate();
        Service = IdsServiceCatalog.MultiplexFindMy;

        _bag = new IdsBag(_http);
        await _bag.EnsureLoadedAsync(ct).ConfigureAwait(false);

        _transport?.Dispose();
        _transport = new IdsApsTransport(_aps.Courier, _log);
        _transport.Attach();

        _lookup = new IdsLookupClient(_bag, _transport, _http, _log);
        _messaging = new IdsMessagingClient(_transport, Cache, Identity, _log);
        _messaging.MessageReceived += (_, e) => MessageReceived?.Invoke(this, e);

        if (_apsHandler is not null)
            _aps.NotificationReceived -= _apsHandler;
        _apsHandler = (_, e) =>
        {
            _ = _messaging?.TryHandleIncoming(e, out IdsReceivedMessage? _);
        };
        _aps.NotificationReceived += _apsHandler;

        _open = true;
        _log?.Invoke(
            $"IDS session open profile={ProfileId} handles={string.Join(", ", Handles)} " +
            $"service={Service.Name} subs={Service.SubServices.Count}");
        await Task.CompletedTask.ConfigureAwait(false);
    }

    public void Close()
    {
        if (_apsHandler is not null)
        {
            _aps.NotificationReceived -= _apsHandler;
            _apsHandler = null;
        }

        _transport?.Dispose();
        _transport = null;
        _lookup = null;
        _messaging = null;
        Cache.Clear();
        _open = false;
        _log?.Invoke("IDS session closed.");
    }

    public void Dispose() => Close();

    public async Task<IdsLookupResult> LookupAsync(
        string topic,
        IReadOnlyList<string> uris,
        CancellationToken ct = default)
    {
        EnsureOpen();
        var self = SelfHandle
                   ?? throw new InvalidOperationException("Self handle assente.");
        var pushToken = _aps.Courier.Token
                        ?? ApsStorage.TryLoadToken()
                        ?? throw new InvalidOperationException("Push token assente.");

        var idKey = File.Exists(IdsStorage.IdKeyPemPath)
            ? await File.ReadAllTextAsync(IdsStorage.IdKeyPemPath, ct).ConfigureAwait(false)
            : await File.ReadAllTextAsync(IdsStorage.AuthKeyPemPath, ct).ConfigureAwait(false);
        var idCert = await File.ReadAllTextAsync(IdsStorage.IdCertPemPath, ct).ConfigureAwait(false);

        var result = await _lookup!.QueryAsync(
                topic, self, uris, idKey, idCert, pushToken, preferHttpOverApns: true, ct)
            .ConfigureAwait(false);
        Cache.PutAll(topic, self, result.Identities);
        _log?.Invoke($"IDS lookup done: {result.RawSummary}");
        return result;
    }

    public Task SendAsync(IdsSendRequest request, CancellationToken ct = default)
    {
        EnsureOpen();
        return _messaging!.SendAsync(request, ct);
    }

    public Task SendAppAckAsync(IdsReceivedMessage incoming, CancellationToken ct = default)
    {
        EnsureOpen();
        var self = SelfHandle ?? throw new InvalidOperationException("Self handle assente.");
        return _messaging!.SendAppAckAsync(incoming.Topic, self, incoming, ct);
    }

    public string FormatStatus()
    {
        var lines = new List<string>
        {
            IdsStorage.FormatStatusSummary(),
            $"Session open: {_open}",
            $"APS connected: {_aps.IsConnected}",
            $"Cache identities: {Cache.Count}",
            $"Service: {Service.Name} (runtime={Service.RuntimeSupported})",
        };
        if (Handles.Count > 0)
            lines.Add("Handles: " + string.Join(", ", Handles));
        lines.Add("Catalog:");
        foreach (var s in IdsServiceCatalog.All)
            lines.Add($"  - {s.Name} runtime={s.RuntimeSupported} subs={s.SubServices.Count}");
        return string.Join(Environment.NewLine, lines);
    }

    private void EnsureOpen()
    {
        if (!_open || _lookup is null || _messaging is null || Identity is null)
            throw new InvalidOperationException("Sessione IDS non aperta — Apri sessione IDS.");
    }
}
