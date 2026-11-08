using System.IO;
using BackupViewer.Models;

namespace BackupViewer.Services;

public sealed class CoreDataService
{
    private readonly BackupCatalog _catalog;
    private CoreDataSnapshot? _snapshot;
    private readonly Dictionary<string, string> _chatDbPaths = new(StringComparer.Ordinal);
    private WhatsAppMediaIndex? _waMedia;

    public CoreDataService(BackupCatalog catalog) => _catalog = catalog;

    public CoreDataSnapshot Snapshot =>
        _snapshot ?? throw new InvalidOperationException("Core data non ancora caricato.");

    public bool IsLoaded => _snapshot is not null;

    public CoreDataSnapshot Load()
    {
        var notes = new List<string>();
        var contacts = Array.Empty<ContactRecord>();
        var calendars = Array.Empty<CalendarInfo>();
        var events = Array.Empty<CalendarEventItem>();
        var chatSources = new List<ChatSource>();
        var calls = new List<CallRecord>();
        _chatDbPaths.Clear();

        var ab = FindPresent(
            static e => e.RelativePath.EndsWith("AddressBook.sqlitedb", StringComparison.OrdinalIgnoreCase)
                        && e.Domain.Contains("HomeDomain", StringComparison.Ordinal));
        if (ab?.AbsolutePath is { } abPath)
        {
            try { contacts = ContactsParser.Parse(abPath).ToArray(); }
            catch (Exception ex) { notes.Add("Contatti: " + ex.Message); }
        }
        else
        {
            notes.Add("AddressBook.sqlitedb non presente nel backup.");
        }

        var cal = FindPresent(
            static e => e.RelativePath.EndsWith("Calendar.sqlitedb", StringComparison.OrdinalIgnoreCase));
        if (cal?.AbsolutePath is { } calPath)
        {
            try
            {
                var (cals, evs) = CalendarParser.Parse(calPath);
                calendars = cals.ToArray();
                events = evs.ToArray();
            }
            catch (Exception ex)
            {
                notes.Add("Calendario: " + ex.Message);
            }
        }
        else
        {
            notes.Add("Calendar.sqlitedb non presente nel backup.");
        }

        var waChat = FindPresent(
            static e => e.RelativePath.Equals("ChatStorage.sqlite", StringComparison.OrdinalIgnoreCase)
                        || e.RelativePath.EndsWith("/ChatStorage.sqlite", StringComparison.OrdinalIgnoreCase));
        if (waChat?.AbsolutePath is { } waPath)
        {
            try
            {
                _waMedia = WhatsAppMediaIndex.Build(_catalog);
                var src = ChatParser.ParseWhatsApp(waPath);
                if (src is not null)
                {
                    chatSources.Add(src);
                    _chatDbPaths[src.Id] = waPath;
                }
            }
            catch (Exception ex)
            {
                notes.Add("WhatsApp chat: " + ex.Message);
            }
        }

        var sms = FindPresent(
            static e => e.RelativePath.Equals("Library/SMS/sms.db", StringComparison.OrdinalIgnoreCase)
                        || e.RelativePath.EndsWith("/sms.db", StringComparison.OrdinalIgnoreCase));
        if (sms?.AbsolutePath is { } smsPath)
        {
            try
            {
                var src = ChatParser.ParseSms(smsPath);
                if (src is not null)
                {
                    chatSources.Add(src);
                    _chatDbPaths[src.Id] = smsPath;
                }
            }
            catch (Exception ex)
            {
                notes.Add("Messaggi: " + ex.Message);
            }
        }
        else
        {
            notes.Add("sms.db non presente (Messaggi iOS assenti o solo su iCloud).");
        }

        var waCalls = FindPresent(
            static e => e.RelativePath.Equals("CallHistory.sqlite", StringComparison.OrdinalIgnoreCase)
                        && e.Domain.Contains("whatsapp", StringComparison.OrdinalIgnoreCase));
        if (waCalls?.AbsolutePath is { } waCallPath)
        {
            try { calls.AddRange(CallsParser.ParseWhatsApp(waCallPath)); }
            catch (Exception ex) { notes.Add("Chiamate WhatsApp: " + ex.Message); }
        }

        var phoneCalls = FindPresent(
            static e =>
                e.RelativePath.EndsWith("CallHistory.storedata", StringComparison.OrdinalIgnoreCase)
                || e.RelativePath.EndsWith("CallHistoryDB/CallHistory.storedata", StringComparison.OrdinalIgnoreCase)
                || (e.RelativePath.Contains("CallHistoryDB", StringComparison.OrdinalIgnoreCase)
                    && e.RelativePath.EndsWith(".storedata", StringComparison.OrdinalIgnoreCase)));
        if (phoneCalls?.AbsolutePath is { } phonePath)
        {
            try { calls.AddRange(CallsParser.ParseAppleCallHistory(phonePath)); }
            catch (Exception ex) { notes.Add("Cronologia telefono: " + ex.Message); }
        }
        else
        {
            notes.Add("CallHistory.storedata non presente (cronologia Telefono assente).");
        }

        calls = calls
            .OrderByDescending(static c => c.StartedAt ?? DateTimeOffset.MinValue)
            .ToList();

        _snapshot = new CoreDataSnapshot
        {
            Contacts = contacts,
            Calendars = calendars,
            Events = events,
            ChatSources = chatSources,
            Calls = calls,
            Notes = notes,
        };
        return _snapshot;
    }

    public IReadOnlyList<ChatMessage> LoadMessages(string sourceId, string conversationId)
    {
        if (!_chatDbPaths.TryGetValue(sourceId, out var path) || !File.Exists(path))
            return [];

        return sourceId switch
        {
            "whatsapp" => ChatParser.LoadWhatsAppMessages(path, conversationId, _waMedia),
            "messages" => ChatParser.LoadSmsMessages(path, conversationId),
            _ => [],
        };
    }

    private BackupFileEntry? FindPresent(Func<BackupFileEntry, bool> pred) =>
        _catalog.Files.FirstOrDefault(e =>
            !e.IsDirectory && e.ExistsOnDisk && !string.IsNullOrWhiteSpace(e.AbsolutePath) && pred(e));
}
