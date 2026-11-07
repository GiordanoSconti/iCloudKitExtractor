using System.Globalization;
using System.IO;
using System.Text.Json;

namespace iCloudKitExtractor.Services.SyncData;

public sealed record MessagesLibrary(
    string InventoryPath,
    IReadOnlyList<ChatThread> Chats,
    int TotalMessages,
    int WithText);

public sealed record ChatThread(
    string Key,
    string Title,
    string Subtitle,
    string Preview,
    string? LastTimeUtc,
    long LastSortTicks,
    int MessageCount,
    string? Service,
    IReadOnlyList<ChatMessage> Messages)
{
    public string Initials
    {
        get
        {
            var t = Title.Trim();
            if (t.Length == 0)
                return "?";
            if (t.StartsWith('+') || t.Count(char.IsDigit) >= 6)
                return "#";
            var parts = t.Split(' ', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length >= 2)
                return string.Concat(parts[0].AsSpan(0, 1), parts[1].AsSpan(0, 1)).ToUpperInvariant();
            return t[..1].ToUpperInvariant();
        }
    }

    public string LastTimeDisplay => MessagesChatCatalog.FormatShortTimePublic(LastTimeUtc);
}

public sealed record ChatMessage(
    string RecordName,
    string Kind,
    string? Guid,
    string? ChatId,
    string? Sender,
    string? Service,
    string? TimeUtc,
    long SortTicks,
    string? BodyText,
    string DisplayText,
    bool IsFromMe,
    bool IsSystem,
    string? Effect,
    string? BalloonBundleId,
    string? Reply,
    string? AssociatedEmoji,
    string? GroupId)
{
    public string TimeDisplay => MessagesChatCatalog.FormatShortTimePublic(TimeUtc);
    public string SenderLabel =>
        IsSystem ? "" :
        IsFromMe ? "Tu" :
        string.IsNullOrWhiteSpace(Sender) ? "Sconosciuto" : Sender!;
}

/// <summary>
/// Carica <c>messages_inventory.json</c> e raggruppa per chat (stile Messaggi/WhatsApp).
/// </summary>
public static class MessagesChatCatalog
{
    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNameCaseInsensitive = true,
        ReadCommentHandling = JsonCommentHandling.Skip,
        AllowTrailingCommas = true,
    };

    public static string? FindInventoryPath(string syncDataRootOrContainer)
    {
        if (string.IsNullOrWhiteSpace(syncDataRootOrContainer))
            return null;

        var direct = Path.Combine(syncDataRootOrContainer, "messages_inventory.json");
        if (File.Exists(direct))
            return direct;

        var ck = Path.Combine(syncDataRootOrContainer, "ck", "apple.messages.cloud", "messages_inventory.json");
        if (File.Exists(ck))
            return ck;

        try
        {
            // Cartella output padre con sync_data_*/ck/...
            if (Directory.Exists(syncDataRootOrContainer))
            {
                foreach (var run in Directory.GetDirectories(syncDataRootOrContainer, "sync_data_*")
                             .OrderByDescending(d => d, StringComparer.OrdinalIgnoreCase))
                {
                    var nested = Path.Combine(run, "ck", "apple.messages.cloud", "messages_inventory.json");
                    if (File.Exists(nested))
                        return nested;
                }
            }

            foreach (var hit in Directory.EnumerateFiles(
                         syncDataRootOrContainer, "messages_inventory.json", SearchOption.AllDirectories)
                         .OrderByDescending(p => p, StringComparer.OrdinalIgnoreCase))
                return hit;
        }
        catch
        {
            /* ignore */
        }

        return null;
    }

    public static MessagesLibrary Load(
        string inventoryJsonPath,
        IEnumerable<string>? ownHandles = null)
    {
        var json = File.ReadAllText(inventoryJsonPath);
        var rows = JsonSerializer.Deserialize<List<MessageRow>>(json, JsonOpts) ?? [];
        var own = NormalizeHandles(ownHandles);
        InferOwnHandles(rows, own);

        var messages = rows
            .Select(r => ToMessage(r, own))
            .OrderBy(m => m.SortTicks)
            .ThenBy(m => m.Guid ?? m.RecordName, StringComparer.OrdinalIgnoreCase)
            .ToList();

        var chats = messages
            .GroupBy(m => ChatKey(m), StringComparer.OrdinalIgnoreCase)
            .Select(g =>
            {
                var list = g.ToList();
                var last = list[^1];
                var title = ResolveChatTitle(g.Key, list);
                var preview = list.LastOrDefault(m => !string.IsNullOrWhiteSpace(m.DisplayText))
                              ?? last;
                return new ChatThread(
                    Key: g.Key,
                    Title: title,
                    Subtitle: BuildSubtitle(list),
                    Preview: Truncate(preview.DisplayText, 80),
                    LastTimeUtc: last.TimeUtc,
                    LastSortTicks: last.SortTicks,
                    MessageCount: list.Count,
                    Service: list.Select(m => m.Service).FirstOrDefault(s => !string.IsNullOrWhiteSpace(s)),
                    Messages: list);
            })
            .OrderByDescending(c => c.LastSortTicks)
            .ThenBy(c => c.Title, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new MessagesLibrary(
            InventoryPath: inventoryJsonPath,
            Chats: chats,
            TotalMessages: messages.Count,
            WithText: messages.Count(m => !string.IsNullOrWhiteSpace(m.BodyText)));
    }

    private static ChatMessage ToMessage(MessageRow r, HashSet<string> own)
    {
        var kind = string.IsNullOrWhiteSpace(r.Kind) ? "message" : r.Kind!;
        var text = FirstNonEmpty(r.Text, r.Subject, r.EventDetail);
        var isSystem = !string.Equals(kind, "message", StringComparison.OrdinalIgnoreCase);
        var fromMe = !isSystem && InferFromMe(r, own);
        var display = isSystem
            ? (text ?? kind)
            : (text ?? (r.HasAttributedBody == true || r.HasPayloadData == true
                ? "(allegato / rich content)"
                : "(senza testo)"));

        return new ChatMessage(
            RecordName: r.RecordName ?? "",
            Kind: kind,
            Guid: r.Guid,
            ChatId: r.ChatId,
            Sender: r.Sender,
            Service: r.Service,
            TimeUtc: r.TimeUtc,
            SortTicks: ParseSortTicks(r.TimeUtc),
            BodyText: text,
            DisplayText: display!,
            IsFromMe: fromMe,
            IsSystem: isSystem,
            Effect: r.Effect,
            BalloonBundleId: r.BalloonBundleId,
            Reply: r.Reply,
            AssociatedEmoji: r.AssociatedEmoji,
            GroupId: r.GroupId);
    }

    private static bool InferFromMe(MessageRow r, HashSet<string> own)
    {
        var sender = NormalizeHandle(r.Sender);
        if (string.IsNullOrEmpty(sender))
            return true; // spesso i messaggi inviati non hanno sender valorizzato

        if (own.Contains(sender))
            return true;

        var chat = NormalizeHandle(r.ChatId);
        if (!string.IsNullOrEmpty(chat) && LooksLikeHandle(chat))
        {
            // 1:1 — se sender == chatId è l'altro; altrimenti tipicamente self.
            if (string.Equals(sender, chat, StringComparison.Ordinal))
                return false;
            if (!own.Contains(chat))
                return true;
        }

        return false;
    }

    private static void InferOwnHandles(List<MessageRow> rows, HashSet<string> own)
    {
        // Heuristica: in chat 1:1, il sender che NON coincide col chatId è spesso self.
        var votes = new Dictionary<string, int>(StringComparer.Ordinal);
        foreach (var r in rows)
        {
            var sender = NormalizeHandle(r.Sender);
            var chat = NormalizeHandle(r.ChatId);
            if (string.IsNullOrEmpty(sender) || string.IsNullOrEmpty(chat))
                continue;
            if (!LooksLikeHandle(chat))
                continue;
            if (string.Equals(sender, chat, StringComparison.Ordinal))
                continue;
            votes[sender] = votes.GetValueOrDefault(sender) + 1;
        }

        foreach (var (handle, count) in votes.OrderByDescending(kv => kv.Value).Take(3))
        {
            if (count >= 3)
                own.Add(handle);
        }
    }

    private static string ChatKey(ChatMessage m)
    {
        if (!string.IsNullOrWhiteSpace(m.ChatId))
            return m.ChatId.Trim();
        if (!string.IsNullOrWhiteSpace(m.GroupId))
            return "group:" + m.GroupId.Trim();
        if (!string.IsNullOrWhiteSpace(m.Sender))
            return "sender:" + m.Sender.Trim();
        return "unknown:" + (m.RecordName.Length >= 8 ? m.RecordName[..8] : m.RecordName);
    }

    private static string ResolveChatTitle(string key, List<ChatMessage> messages)
    {
        if (key.StartsWith("group:", StringComparison.OrdinalIgnoreCase))
        {
            var named = messages.FirstOrDefault(m =>
                string.Equals(m.Kind, "group_title", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(m.BodyText));
            if (named?.BodyText is { Length: > 0 })
                return named.BodyText;
            return "Gruppo";
        }

        if (key.StartsWith("sender:", StringComparison.OrdinalIgnoreCase))
            return key["sender:".Length..];
        if (key.StartsWith("unknown:", StringComparison.OrdinalIgnoreCase))
            return "Chat senza ID";

        return key;
    }

    private static string BuildSubtitle(List<ChatMessage> list)
    {
        var svc = list.Select(m => m.Service).FirstOrDefault(s => !string.IsNullOrWhiteSpace(s));
        var n = list.Count;
        return string.IsNullOrWhiteSpace(svc) ? $"{n} messaggi" : $"{svc} · {n}";
    }

    private static HashSet<string> NormalizeHandles(IEnumerable<string>? handles)
    {
        var set = new HashSet<string>(StringComparer.Ordinal);
        if (handles is null)
            return set;
        foreach (var h in handles)
        {
            var n = NormalizeHandle(h);
            if (!string.IsNullOrEmpty(n))
                set.Add(n);
        }

        return set;
    }

    private static string NormalizeHandle(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        var s = value.Trim();
        if (s.StartsWith("tel:", StringComparison.OrdinalIgnoreCase))
            s = s[4..];
        if (s.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
            s = s[7..];
        s = s.Trim();
        if (s.Contains('@', StringComparison.Ordinal))
            return s.ToLowerInvariant();

        // Telefono: tieni cifre e +
        var digits = new string(s.Where(c => char.IsDigit(c) || c == '+').ToArray());
        return digits.Length >= 6 ? digits : s.ToLowerInvariant();
    }

    private static bool LooksLikeHandle(string normalized) =>
        normalized.Contains('@', StringComparison.Ordinal)
        || normalized.Count(char.IsDigit) >= 6
        || normalized.StartsWith('+');

    private static long ParseSortTicks(string? timeUtc)
    {
        if (string.IsNullOrWhiteSpace(timeUtc))
            return long.MaxValue / 4;
        if (DateTimeOffset.TryParse(
                timeUtc, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var dto))
            return dto.UtcTicks;
        return long.MaxValue / 4;
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values)
        {
            if (!string.IsNullOrWhiteSpace(v))
                return v.Trim();
        }

        return null;
    }

    private static string Truncate(string? text, int max)
    {
        if (string.IsNullOrWhiteSpace(text))
            return "";
        var t = text.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return t.Length <= max ? t : t[..(max - 1)] + "…";
    }

    internal static string FormatShortTimePublic(string? timeUtc)
    {
        if (string.IsNullOrWhiteSpace(timeUtc))
            return "";
        if (!DateTimeOffset.TryParse(
                timeUtc, CultureInfo.InvariantCulture,
                DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal,
                out var dto))
            return timeUtc;

        var local = dto.ToLocalTime();
        var today = DateTime.Now.Date;
        if (local.Date == today)
            return local.ToString("HH:mm", CultureInfo.CurrentCulture);
        if (local.Date == today.AddDays(-1))
            return "Ieri";
        if (local.Year == today.Year)
            return local.ToString("d MMM", CultureInfo.CurrentCulture);
        return local.ToString("dd/MM/yy", CultureInfo.CurrentCulture);
    }

    private sealed class MessageRow
    {
        public string? RecordName { get; set; }
        public string? Kind { get; set; }
        public string? Guid { get; set; }
        public string? ChatId { get; set; }
        public string? Sender { get; set; }
        public string? DcId { get; set; }
        public string? Service { get; set; }
        public string? TimeUtc { get; set; }
        public string? Text { get; set; }
        public string? Subject { get; set; }
        public string? Effect { get; set; }
        public string? BalloonBundleId { get; set; }
        public string? Reply { get; set; }
        public string? GroupId { get; set; }
        public string? AssociatedEmoji { get; set; }
        public string? EventDetail { get; set; }
        public bool? HasAttributedBody { get; set; }
        public bool? HasPayloadData { get; set; }
    }
}
