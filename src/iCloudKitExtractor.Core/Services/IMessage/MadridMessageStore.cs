using System.Collections.Concurrent;
using System.IO;
using System.Text.Json;

namespace iCloudKitExtractor.Services.IMessage;

/// <summary>Local JSON-backed store for Madrid iMessage conversations (text MVP).</summary>
public sealed class MadridMessageStore
{
    private readonly ConcurrentDictionary<string, MadridConversation> _byPeer =
        new(StringComparer.OrdinalIgnoreCase);

    public static string DirectoryPath { get; } = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "iCloudKitExtractor",
        "imessage");

    public static string StorePath => Path.Combine(DirectoryPath, "messages.json");

    public IReadOnlyList<MadridConversation> Conversations =>
        _byPeer.Values.OrderByDescending(c => c.LastUtc).ToList();

    public event EventHandler? Changed;

    public void Load()
    {
        _byPeer.Clear();
        if (!File.Exists(StorePath))
            return;
        try
        {
            var root = JsonSerializer.Deserialize<MadridStoreFile>(File.ReadAllText(StorePath));
            if (root?.Conversations is null)
                return;
            foreach (var c in root.Conversations)
            {
                if (!string.IsNullOrWhiteSpace(c.PeerHandle))
                    _byPeer[c.PeerHandle] = c;
            }
        }
        catch
        {
            // Corrupt store — start empty.
        }
    }

    public void Save()
    {
        Directory.CreateDirectory(DirectoryPath);
        var file = new MadridStoreFile { Conversations = Conversations.ToList() };
        File.WriteAllText(StorePath, JsonSerializer.Serialize(file, new JsonSerializerOptions
        {
            WriteIndented = true
        }));
    }

    public MadridConversation GetOrCreate(string peerHandle)
    {
        var key = peerHandle.Trim();
        return _byPeer.GetOrAdd(key, h => new MadridConversation { PeerHandle = h });
    }

    public MadridMessage Append(
        string peerHandle,
        string body,
        bool outgoing,
        string? messageId = null)
    {
        var conv = GetOrCreate(peerHandle);
        var msg = new MadridMessage
        {
            Id = messageId ?? Guid.NewGuid().ToString("N"),
            PeerHandle = conv.PeerHandle,
            Body = body,
            Outgoing = outgoing,
            Utc = DateTime.UtcNow.ToString("O"),
        };
        conv.Messages.Add(msg);
        conv.LastUtc = msg.Utc;
        conv.LastPreview = Truncate(body, 80);
        Save();
        Changed?.Invoke(this, EventArgs.Empty);
        return msg;
    }

    private static string Truncate(string s, int n) =>
        string.IsNullOrEmpty(s) ? "" : (s.Length <= n ? s : s[..n] + "…");
}

public sealed class MadridStoreFile
{
    public List<MadridConversation> Conversations { get; set; } = [];
}

public sealed class MadridConversation
{
    public string PeerHandle { get; set; } = "";
    public string? LastUtc { get; set; }
    public string? LastPreview { get; set; }
    public List<MadridMessage> Messages { get; set; } = [];
}

public sealed class MadridMessage
{
    public string Id { get; set; } = "";
    public string PeerHandle { get; set; } = "";
    public string Body { get; set; } = "";
    public bool Outgoing { get; set; }
    public string Utc { get; set; } = "";
}
