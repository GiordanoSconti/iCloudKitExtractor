using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using iCloudKitExtractor.Services.Forensics;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Pubblica un visualizzatore Messages HTML portatile (lista chat + bolle)
/// sotto <c>messages_viewer/</c>, con <c>HASHES.sha256</c> + <c>integrity.json</c>
/// dedicati alla cartella viewer.
/// </summary>
public static class MessagesHtmlViewerPublisher
{
    public const string ViewerFolderName = "messages_viewer";
    public const string IndexFileName = "index.html";
    public const string DataFileName = "chats.json";
    public const string LauncherFileName = "Apri Messaggi.html";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static async Task<string?> PublishAsync(
        string containerDirectory,
        IEnumerable<string>? ownHandles = null,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(containerDirectory) || !Directory.Exists(containerDirectory))
            return null;

        var inventory = Path.Combine(containerDirectory, "messages_inventory.json");
        if (!File.Exists(inventory))
        {
            log?.Report("  Messages HTML viewer skip: messages_inventory.json assente");
            return null;
        }

        MessagesLibrary library;
        try
        {
            library = MessagesChatCatalog.Load(inventory, ownHandles);
        }
        catch (Exception ex)
        {
            log?.Report($"  Messages HTML viewer skip: {ex.Message}");
            return null;
        }

        if (library.Chats.Count == 0)
        {
            log?.Report("  Messages HTML viewer skip: nessuna chat");
            return null;
        }

        var viewerDir = Path.Combine(containerDirectory, ViewerFolderName);
        Directory.CreateDirectory(viewerDir);

        var payload = BuildPayload(library);
        var dataJson = JsonSerializer.Serialize(payload, JsonOpts);
        var dataPath = Path.Combine(viewerDir, DataFileName);
        await File.WriteAllTextAsync(dataPath, dataJson, Encoding.UTF8, ct).ConfigureAwait(false);

        var html = BuildIndexHtml(dataJson);
        var indexPath = Path.Combine(viewerDir, IndexFileName);
        await File.WriteAllTextAsync(indexPath, html, Encoding.UTF8, ct).ConfigureAwait(false);

        var launcherPath = Path.Combine(containerDirectory, LauncherFileName);
        await File.WriteAllTextAsync(
            launcherPath,
            BuildLauncherHtml(),
            Encoding.UTF8,
            ct).ConfigureAwait(false);

        try
        {
            await OutputHashManifest.WriteForDirectoryAsync(viewerDir, log, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log?.Report($"  Messages viewer HASH: {ex.Message}");
        }

        log?.Report(
            $"  Messages HTML viewer: {library.Chats.Count} chat, {library.TotalMessages} msg → " +
            $"{ViewerFolderName}/{IndexFileName} (+ {LauncherFileName})");
        return indexPath;
    }

    public static string? Publish(
        string containerDirectory,
        IEnumerable<string>? ownHandles = null,
        IProgress<string>? log = null) =>
        PublishAsync(containerDirectory, ownHandles, log).GetAwaiter().GetResult();

    private static ViewerPayload BuildPayload(MessagesLibrary library) =>
        new(
            GeneratedAt: DateTimeOffset.UtcNow,
            SourceInventory: Path.GetFileName(library.InventoryPath),
            ChatCount: library.Chats.Count,
            MessageCount: library.TotalMessages,
            WithText: library.WithText,
            Chats: library.Chats.Select(c => new ViewerChat(
                Key: c.Key,
                Title: c.Title,
                Subtitle: c.Subtitle,
                Preview: c.Preview,
                Initials: c.Initials,
                LastTimeDisplay: c.LastTimeDisplay,
                MessageCount: c.MessageCount,
                Service: c.Service,
                Messages: c.Messages.Select(m => new ViewerMessage(
                    Kind: m.Kind,
                    Guid: m.Guid,
                    Sender: m.Sender,
                    SenderLabel: m.SenderLabel,
                    Service: m.Service,
                    TimeUtc: m.TimeUtc,
                    TimeDisplay: m.TimeDisplay,
                    Text: m.DisplayText,
                    IsFromMe: m.IsFromMe,
                    IsSystem: m.IsSystem,
                    Reply: m.Reply,
                    AssociatedEmoji: m.AssociatedEmoji)).ToList())).ToList());

    private static string BuildLauncherHtml() =>
        """
        <!DOCTYPE html>
        <html lang="it">
        <head>
          <meta charset="utf-8"/>
          <meta http-equiv="refresh" content="0; url=messages_viewer/index.html"/>
          <title>Apri Messaggi</title>
        </head>
        <body>
          <p><a href="messages_viewer/index.html">Apri visualizzatore Messaggi</a></p>
        </body>
        </html>
        """;

    private static string BuildIndexHtml(string dataJson)
    {
        // Evita chiusura accidentale di <script> se un messaggio contiene la sequenza.
        var safeJson = dataJson.Replace("</", "<\\/", StringComparison.Ordinal);

        var sb = new StringBuilder(safeJson.Length + 12_000);
        sb.Append(
            """
            <!DOCTYPE html>
            <html lang="it">
            <head>
            <meta charset="utf-8"/>
            <meta name="viewport" content="width=device-width, initial-scale=1"/>
            <title>Messaggi — iCloud Sync Data</title>
            <style>
            :root {
              --bg: #f2f2f7;
              --paper: #fffffff2;
              --ink: #1b1c1f;
              --muted: #6b6b70;
              --line: #14000000;
              --accent: #007aff;
              --me: #007aff;
              --them: #ffffff;
              --sys: #6b6b70;
              --sel: #1a007aff;
              --avatar: #d1d1d6;
            }
            * { box-sizing: border-box; }
            html, body { height: 100%; margin: 0; }
            body {
              font-family: "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
              background: var(--bg); color: var(--ink);
              display: flex; flex-direction: column;
            }
            header {
              height: 52px; display: flex; align-items: center; justify-content: space-between;
              padding: 0 18px; background: var(--paper); border-bottom: 1px solid var(--line);
              flex-shrink: 0;
            }
            header h1 { font-size: 18px; font-weight: 600; margin: 0; }
            header .meta { font-size: 12px; color: var(--muted); margin-left: 14px; }
            header input {
              width: min(280px, 40vw); height: 30px; border: 1px solid #d0d0d5; border-radius: 8px;
              padding: 0 10px; font-size: 13px; background: #fff;
            }
            .shell { flex: 1; display: grid; grid-template-columns: minmax(240px, 320px) 1fr; min-height: 0; }
            .chats {
              background: var(--paper); border-right: 1px solid var(--line);
              overflow: auto; min-height: 0;
            }
            .chats h2 {
              margin: 12px 16px 6px; font-size: 12px; font-weight: 500; color: var(--muted);
            }
            .chat-item {
              display: grid; grid-template-columns: 44px 1fr auto; gap: 10px;
              padding: 10px 14px; border-bottom: 1px solid var(--line); cursor: pointer;
            }
            .chat-item:hover { background: #0d000000; }
            .chat-item.active { background: var(--sel); }
            .avatar {
              width: 40px; height: 40px; border-radius: 50%; background: var(--avatar);
              display: grid; place-items: center; font-weight: 600; font-size: 13px; color: #3a3a3c;
            }
            .chat-item .title { font-weight: 600; font-size: 13px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .chat-item .preview { font-size: 12px; color: var(--muted); margin-top: 2px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .chat-item .when { font-size: 11px; color: #8e8e93; text-align: right; }
            .thread { display: flex; flex-direction: column; min-height: 0; min-width: 0; }
            .thread-head {
              height: 56px; padding: 0 18px; display: flex; flex-direction: column; justify-content: center;
              background: var(--paper); border-bottom: 1px solid var(--line); flex-shrink: 0;
            }
            .thread-head .t { font-size: 16px; font-weight: 600; }
            .thread-head .s { font-size: 11px; color: #8e8e93; }
            .messages {
              flex: 1; overflow: auto; padding: 14px 18px; min-height: 0;
            }
            .bubble-row { display: flex; margin: 3px 0; }
            .bubble-row.me { justify-content: flex-end; }
            .bubble-row.sys { justify-content: center; }
            .bubble {
              max-width: min(520px, 85%); padding: 8px 12px; border-radius: 16px;
              background: var(--them); border: 1px solid var(--line); font-size: 14px;
              white-space: pre-wrap; word-break: break-word;
            }
            .bubble.me { background: var(--me); color: #fff; border: 0; }
            .bubble.sys { background: transparent; border: 0; color: var(--sys); font-size: 12px; text-align: center; max-width: 440px; }
            .bubble .who { font-size: 11px; font-weight: 600; color: var(--accent); margin-bottom: 2px; }
            .bubble.me .who { display: none; }
            .bubble .reply {
              font-size: 11px; font-style: italic; opacity: .85; margin-bottom: 6px;
              padding: 4px 8px; border-radius: 8px; background: #14000000;
            }
            .bubble.me .reply { background: #22ffffff; }
            .bubble .meta { margin-top: 4px; font-size: 10px; color: #8e8e93; display: flex; justify-content: space-between; gap: 8px; }
            .bubble.me .meta { color: #ccffffff; }
            .bubble.sys .meta { justify-content: center; }
            .empty {
              flex: 1; display: grid; place-items: center; color: #8e8e93; font-size: 14px;
            }
            @media (max-width: 720px) {
              .shell { grid-template-columns: 1fr; }
              .chats { max-height: 40vh; }
            }
            </style>
            </head>
            <body>
            <header>
              <div style="display:flex;align-items:center;min-width:0">
                <h1>Messaggi</h1>
                <span class="meta" id="summary"></span>
              </div>
              <input id="search" type="search" placeholder="Filtra chat e messaggi" autocomplete="off"/>
            </header>
            <div class="shell">
              <aside class="chats">
                <h2>Chat</h2>
                <div id="chatList"></div>
              </aside>
              <section class="thread">
                <div class="thread-head">
                  <div class="t" id="threadTitle">Seleziona una chat</div>
                  <div class="s" id="threadSub"></div>
                </div>
                <div class="messages" id="messages"></div>
              </section>
            </div>
            <script type="application/json" id="msg-data">
            """);
        sb.Append(safeJson);
        sb.Append(
            """

            </script>
            <script>
            const DATA = JSON.parse(document.getElementById('msg-data').textContent);
            const chatListEl = document.getElementById('chatList');
            const messagesEl = document.getElementById('messages');
            const summaryEl = document.getElementById('summary');
            const titleEl = document.getElementById('threadTitle');
            const subEl = document.getElementById('threadSub');
            const searchEl = document.getElementById('search');
            let activeKey = null;

            summaryEl.textContent =
              `${DATA.chatCount} chat · ${DATA.messageCount} msg (${DATA.withText} con testo)`;

            function esc(s) {
              return String(s ?? '').replace(/[&<>"']/g, c => ({
                '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
              }[c]));
            }

            function filterChats(q) {
              q = (q || '').trim().toLowerCase();
              if (!q) return DATA.chats;
              return DATA.chats.filter(c =>
                (c.title || '').toLowerCase().includes(q) ||
                (c.preview || '').toLowerCase().includes(q) ||
                (c.key || '').toLowerCase().includes(q) ||
                (c.messages || []).some(m =>
                  (m.text || '').toLowerCase().includes(q) ||
                  (m.sender || '').toLowerCase().includes(q)));
            }

            function renderChatList() {
              const chats = filterChats(searchEl.value);
              chatListEl.innerHTML = chats.map(c => `
                <div class="chat-item ${c.key === activeKey ? 'active' : ''}" data-key="${esc(c.key)}">
                  <div class="avatar">${esc(c.initials || '?')}</div>
                  <div style="min-width:0">
                    <div class="title">${esc(c.title)}</div>
                    <div class="preview">${esc(c.preview)}</div>
                  </div>
                  <div class="when">${esc(c.lastTimeDisplay || '')}<div style="margin-top:4px;font-size:10px;color:#aeaeb2">${c.messageCount}</div></div>
                </div>`).join('');
              chatListEl.querySelectorAll('.chat-item').forEach(el => {
                el.addEventListener('click', () => openChat(el.getAttribute('data-key')));
              });
              if (!chats.length) {
                messagesEl.innerHTML = '<div class="empty">Nessuna chat da mostrare</div>';
                titleEl.textContent = 'Nessuna chat';
                subEl.textContent = '';
              } else if (!chats.some(c => c.key === activeKey)) {
                openChat(chats[0].key);
              }
            }

            function openChat(key) {
              activeKey = key;
              const chat = DATA.chats.find(c => c.key === key);
              if (!chat) return;
              titleEl.textContent = chat.title || 'Chat';
              subEl.textContent = `${chat.subtitle || ''} · ${chat.messageCount} messaggi`;
              const q = (searchEl.value || '').trim().toLowerCase();
              let msgs = chat.messages || [];
              if (q && !(chat.title || '').toLowerCase().includes(q) && !(chat.key || '').toLowerCase().includes(q)) {
                const filtered = msgs.filter(m =>
                  (m.text || '').toLowerCase().includes(q) ||
                  (m.sender || '').toLowerCase().includes(q));
                if (filtered.length) msgs = filtered;
              }
              messagesEl.innerHTML = msgs.map(m => {
                const row = m.isSystem ? 'sys' : (m.isFromMe ? 'me' : '');
                const bub = m.isSystem ? 'sys' : (m.isFromMe ? 'me' : '');
                const who = (!m.isFromMe && !m.isSystem) ? `<div class="who">${esc(m.senderLabel || m.sender || '')}</div>` : '';
                const reply = m.reply ? `<div class="reply">${esc(m.reply)}</div>` : '';
                const emoji = m.associatedEmoji ? `<span>${esc(m.associatedEmoji)}</span>` : '<span></span>';
                return `<div class="bubble-row ${row}"><div class="bubble ${bub}">${who}${reply}<div>${esc(m.text)}</div><div class="meta">${emoji}<span>${esc(m.timeDisplay || '')}</span></div></div></div>`;
              }).join('');
              messagesEl.scrollTop = messagesEl.scrollHeight;
              renderChatListActiveOnly();
            }

            function renderChatListActiveOnly() {
              chatListEl.querySelectorAll('.chat-item').forEach(el => {
                el.classList.toggle('active', el.getAttribute('data-key') === activeKey);
              });
            }

            searchEl.addEventListener('input', renderChatList);
            renderChatList();
            </script>
            </body>
            </html>
            """);
        return sb.ToString();
    }

    private sealed record ViewerPayload(
        DateTimeOffset GeneratedAt,
        string SourceInventory,
        int ChatCount,
        int MessageCount,
        int WithText,
        IReadOnlyList<ViewerChat> Chats);

    private sealed record ViewerChat(
        string Key,
        string Title,
        string Subtitle,
        string Preview,
        string Initials,
        string LastTimeDisplay,
        int MessageCount,
        string? Service,
        IReadOnlyList<ViewerMessage> Messages);

    private sealed record ViewerMessage(
        string Kind,
        string? Guid,
        string? Sender,
        string SenderLabel,
        string? Service,
        string? TimeUtc,
        string TimeDisplay,
        string Text,
        bool IsFromMe,
        bool IsSystem,
        string? Reply,
        string? AssociatedEmoji);
}
