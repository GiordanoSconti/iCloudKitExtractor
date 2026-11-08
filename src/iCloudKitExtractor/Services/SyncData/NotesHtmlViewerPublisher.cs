using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Forensics;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Pubblica un visualizzatore Notes HTML stile Apple Notes sotto <c>notes_viewer/</c>,
/// con <c>HASHES.sha256</c> + <c>integrity.json</c> dedicati.
/// </summary>
public static class NotesHtmlViewerPublisher
{
    public const string ViewerFolderName = "notes_viewer";
    public const string IndexFileName = "index.html";
    public const string DataFileName = "notes.json";
    public const string LauncherFileName = "Apri Note.html";

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
    };

    public static async Task<string?> PublishAsync(
        string containerDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(containerDirectory) || !Directory.Exists(containerDirectory))
            return null;

        var dbPath = Path.Combine(containerDirectory, "Notes.db");
        if (!File.Exists(dbPath))
        {
            log?.Report("  Notes HTML viewer skip: Notes.db assente");
            return null;
        }

        ViewerPayload payload;
        try
        {
            payload = await BuildPayloadFromDbAsync(containerDirectory, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log?.Report($"  Notes HTML viewer skip: {ex.Message}");
            return null;
        }

        if (payload.Notes.Count == 0)
        {
            log?.Report("  Notes HTML viewer skip: nessuna nota");
            return null;
        }

        var viewerDir = Path.Combine(containerDirectory, ViewerFolderName);
        Directory.CreateDirectory(viewerDir);

        var dataJson = JsonSerializer.Serialize(payload, JsonOpts);
        await File.WriteAllTextAsync(
            Path.Combine(viewerDir, DataFileName), dataJson, Encoding.UTF8, ct).ConfigureAwait(false);

        var indexPath = Path.Combine(viewerDir, IndexFileName);
        await File.WriteAllTextAsync(
            indexPath, BuildIndexHtml(dataJson), Encoding.UTF8, ct).ConfigureAwait(false);

        await File.WriteAllTextAsync(
            Path.Combine(containerDirectory, LauncherFileName),
            BuildLauncherHtml(),
            Encoding.UTF8,
            ct).ConfigureAwait(false);

        try
        {
            await OutputHashManifest.WriteForDirectoryAsync(viewerDir, log, ct).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            log?.Report($"  Notes viewer HASH: {ex.Message}");
        }

        log?.Report(
            $"  Notes HTML viewer: {payload.FolderCount} cartelle, {payload.NoteCount} note → " +
            $"{ViewerFolderName}/{IndexFileName} (+ {LauncherFileName})");
        return indexPath;
    }

    public static string? Publish(string containerDirectory, IProgress<string>? log = null) =>
        PublishAsync(containerDirectory, log).GetAwaiter().GetResult();

    private static async Task<ViewerPayload> BuildPayloadFromDbAsync(
        string containerDirectory,
        CancellationToken ct)
    {
        var db = await NotesCatalogSqlite.OpenAsync(containerDirectory, ct);
        try
        {
        var folders = await db.ListFoldersAsync(ct);
        var notes = await db.ListNotesAsync(ct);

        var folderDtos = folders.Select(f => new ViewerFolder(
            Id: f.RecordName,
            Key: f.FolderKey ?? f.RecordName,
            Name: ResolveFolderName(f),
            IsSystem: f.IsSystem,
            IsTrash: IsTrash(f.FolderKey))).ToList();

        // Assicura cartelle virtuali se mancano nel DB.
        EnsureVirtualFolder(folderDtos, "DefaultFolder-CloudKit", "Note", isSystem: true, isTrash: false);
        EnsureVirtualFolder(folderDtos, "TrashFolder-CloudKit", "Eliminate di recente", isSystem: true, isTrash: true);

        var noteDtos = new List<ViewerNote>();
        foreach (var n in notes)
        {
            ct.ThrowIfCancellationRequested();
            var plains = await db.ListPlaintextForNoteAsync(n.RecordName, ct);
            var body = await ResolveBodyAsync(plains, ct).ConfigureAwait(false);
            var titleFromDb = NotesPlaintextDecoder.IsReplicaMapPreview(n.Title) ? null : n.Title;
            var snippetFromDb = NotesPlaintextDecoder.IsReplicaMapPreview(n.Snippet) ? null : n.Snippet;
            var titleFromFile = await ResolveTitleAsync(plains, ct).ConfigureAwait(false);
            var title = FirstNonEmpty(
                titleFromDb,
                titleFromFile,
                FirstLine(body),
                "Senza titolo")!;
            var snippet = FirstNonEmpty(snippetFromDb, Truncate(body, 160)) ?? "";
            var folderKey = string.IsNullOrWhiteSpace(n.FolderKey)
                ? (n.Deleted ? "TrashFolder-CloudKit" : "DefaultFolder-CloudKit")
                : n.FolderKey!;

            if (string.IsNullOrWhiteSpace(body) && string.Equals(title, "Senza titolo", StringComparison.Ordinal))
                continue;

            noteDtos.Add(new ViewerNote(
                Id: n.RecordName,
                Title: title,
                Snippet: snippet,
                Body: body ?? "",
                FolderKey: folderKey,
                FolderRecordName: n.FolderRecordName,
                Deleted: n.Deleted || IsTrash(folderKey),
                RecordType: n.RecordType));
        }

        // Conta note per cartella (chiave folder_key).
        var counts = noteDtos
            .GroupBy(static n => n.FolderKey, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(g => g.Key, g => g.Count(), StringComparer.OrdinalIgnoreCase);

        folderDtos = folderDtos
            .Select(f => f with { NoteCount = counts.GetValueOrDefault(f.Key) })
            .OrderByDescending(static f => f.IsSystem && !f.IsTrash)
            .ThenBy(static f => f.IsTrash)
            .ThenBy(static f => f.Name, StringComparer.OrdinalIgnoreCase)
            .ToList();

        return new ViewerPayload(
            GeneratedAt: DateTimeOffset.UtcNow,
            SourceDb: "Notes.db",
            FolderCount: folderDtos.Count,
            NoteCount: noteDtos.Count,
            Folders: folderDtos,
            Notes: noteDtos);
        }
        finally
        {
            await db.CloseForHashingAsync(ct).ConfigureAwait(false);
        }
    }

    private static void EnsureVirtualFolder(
        List<ViewerFolder> folders,
        string key,
        string name,
        bool isSystem,
        bool isTrash)
    {
        if (folders.Any(f => string.Equals(f.Key, key, StringComparison.OrdinalIgnoreCase)))
            return;
        folders.Add(new ViewerFolder(
            Id: "system:" + key,
            Key: key,
            Name: name,
            IsSystem: isSystem,
            IsTrash: isTrash,
            NoteCount: 0));
    }

    private static string ResolveFolderName(NotesCatalogSqlite.FolderRow f)
    {
        if (!string.IsNullOrWhiteSpace(f.Name))
            return f.Name!;
        if (IsTrash(f.FolderKey))
            return "Eliminate di recente";
        if (string.Equals(f.FolderKey, "DefaultFolder-CloudKit", StringComparison.OrdinalIgnoreCase))
            return "Note";
        if (!string.IsNullOrWhiteSpace(f.FolderKey))
        {
            var sep = f.FolderKey!.LastIndexOf("::", StringComparison.Ordinal);
            if (sep >= 0 && sep + 2 < f.FolderKey.Length)
                return f.FolderKey[(sep + 2)..];
            return f.FolderKey;
        }

        return "Cartella";
    }

    private static bool IsTrash(string? folderKey) =>
        !string.IsNullOrWhiteSpace(folderKey)
        && folderKey.Contains("TrashFolder", StringComparison.OrdinalIgnoreCase);

    private static async Task<string?> ResolveBodyAsync(
        IReadOnlyList<NotesCatalogSqlite.PlaintextRow> plains,
        CancellationToken ct)
    {
        static bool Prefer(string field) =>
            field.Equals("TextDataEncrypted", StringComparison.OrdinalIgnoreCase)
            || field.Equals("StandardizedContentEncrypted", StringComparison.OrdinalIgnoreCase)
            || field.Equals("DisplayTextEncrypted", StringComparison.OrdinalIgnoreCase);

        static bool IsMeta(string field) =>
            field.Contains("ReplicaID", StringComparison.OrdinalIgnoreCase)
            || field.Contains("MergeablePreferredViewSize", StringComparison.OrdinalIgnoreCase);

        foreach (var row in plains.Where(r => Prefer(r.FieldName) && !IsMeta(r.FieldName)))
        {
            ct.ThrowIfCancellationRequested();
            var decoded = await DecodePlainFileAsync(row.FieldName, row.PlainPath, ct)
                .ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(decoded)
                && !NotesPlaintextDecoder.IsReplicaMapPreview(decoded))
                return decoded;

            if (!string.IsNullOrWhiteSpace(row.TextPreview)
                && !NotesPlaintextDecoder.IsReplicaMapPreview(row.TextPreview))
                return row.TextPreview.Trim();
        }

        return null;
    }

    private static async Task<string?> DecodePlainFileAsync(
        string fieldName,
        string path,
        CancellationToken ct)
    {
        try
        {
            if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
                return null;
            var bytes = await File.ReadAllBytesAsync(path, ct).ConfigureAwait(false);
            if (bytes.Length == 0)
                return null;
            return NotesPlaintextDecoder.DecodeField(fieldName, bytes).TextPreview;
        }
        catch
        {
            return null;
        }
    }

    private static async Task<string?> ResolveTitleAsync(
        IReadOnlyList<NotesCatalogSqlite.PlaintextRow> plains,
        CancellationToken ct)
    {
        foreach (var row in plains.Where(static r =>
                     r.FieldName.Equals("TitleEncrypted", StringComparison.OrdinalIgnoreCase)))
        {
            var decoded = await DecodePlainFileAsync(row.FieldName, row.PlainPath, ct)
                .ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(decoded)
                && !NotesPlaintextDecoder.IsReplicaMapPreview(decoded))
                return decoded;
        }

        return null;
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

    private static string? FirstLine(string? body)
    {
        if (string.IsNullOrWhiteSpace(body))
            return null;
        var line = body.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries)
            .FirstOrDefault();
        return string.IsNullOrWhiteSpace(line) ? null : Truncate(line, 80);
    }

    private static string Truncate(string? value, int max)
    {
        if (string.IsNullOrWhiteSpace(value))
            return "";
        var t = value.Replace('\r', ' ').Replace('\n', ' ').Trim();
        return t.Length <= max ? t : t[..(max - 1)].TrimEnd() + "…";
    }

    private static string BuildLauncherHtml() =>
        """
        <!DOCTYPE html>
        <html lang="it">
        <head>
          <meta charset="utf-8"/>
          <meta http-equiv="refresh" content="0; url=notes_viewer/index.html"/>
          <title>Apri Note</title>
        </head>
        <body>
          <p><a href="notes_viewer/index.html">Apri visualizzatore Note</a></p>
        </body>
        </html>
        """;

    private static string BuildIndexHtml(string dataJson)
    {
        var safeJson = dataJson.Replace("</", "<\\/", StringComparison.Ordinal);
        var sb = new StringBuilder(safeJson.Length + 14_000);
        sb.Append(
            """
            <!DOCTYPE html>
            <html lang="it">
            <head>
            <meta charset="utf-8"/>
            <meta name="viewport" content="width=device-width, initial-scale=1"/>
            <title>Note — iCloud Sync Data</title>
            <style>
            :root {
              --sidebar: #f7f7f7;
              --list: #ffffff;
              --paper: #fffdf6;
              --ink: #1d1d1f;
              --muted: #6e6e73;
              --line: #d2d2d7;
              --yellow: #f7ce46;
              --yellow-soft: #fff4c2;
              --accent: #d6a700;
              --sel: #ffe58a;
              --trash: #ff3b30;
              --folder: #ffcc00;
            }
            * { box-sizing: border-box; }
            html, body { height: 100%; margin: 0; }
            body {
              font-family: "SF Pro Text", "Segoe UI Variable Text", "Segoe UI", system-ui, sans-serif;
              color: var(--ink); background: #e8e8ed;
              display: flex; flex-direction: column;
            }
            header {
              height: 52px; display: flex; align-items: center; justify-content: space-between;
              padding: 0 16px; background: linear-gradient(#fffef8, #faf6e8);
              border-bottom: 1px solid var(--line); flex-shrink: 0;
            }
            header h1 {
              margin: 0; font-size: 18px; font-weight: 700;
              display: flex; align-items: center; gap: 8px;
            }
            header h1::before {
              content: ""; width: 14px; height: 14px; border-radius: 3px;
              background: var(--yellow); box-shadow: inset 0 0 0 1px #00000022;
            }
            header .meta { font-size: 12px; color: var(--muted); margin-left: 12px; }
            header input {
              width: min(260px, 38vw); height: 30px; border: 1px solid var(--line);
              border-radius: 8px; padding: 0 10px; font-size: 13px; background: #fff;
            }
            .shell {
              flex: 1; min-height: 0;
              display: grid; grid-template-columns: 220px minmax(240px, 320px) 1fr;
            }
            .folders, .notes {
              overflow: auto; min-height: 0; border-right: 1px solid var(--line);
            }
            .folders { background: var(--sidebar); padding: 10px 8px; }
            .notes { background: var(--list); }
            .editor { background: var(--paper); display: flex; flex-direction: column; min-width: 0; min-height: 0; }
            .sec {
              font-size: 11px; font-weight: 600; letter-spacing: .04em; text-transform: uppercase;
              color: var(--muted); padding: 8px 10px 4px;
            }
            .folder-item, .note-item {
              display: flex; align-items: center; gap: 8px;
              padding: 8px 10px; border-radius: 8px; cursor: pointer; margin: 1px 4px;
            }
            .folder-item:hover, .note-item:hover { background: #0000000a; }
            .folder-item.active, .note-item.active { background: var(--sel); }
            .folder-item .ico {
              width: 18px; height: 18px; border-radius: 3px; background: var(--folder);
              box-shadow: inset 0 0 0 1px #00000018; flex-shrink: 0;
            }
            .folder-item.trash .ico { background: var(--trash); }
            .folder-item .name { flex: 1; font-size: 13px; font-weight: 500; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
            .folder-item .count { font-size: 12px; color: var(--muted); }
            .note-item {
              flex-direction: column; align-items: stretch; gap: 2px;
              border-bottom: 1px solid #0000000d; border-radius: 0; margin: 0; padding: 12px 14px;
            }
            .note-item.active { background: var(--yellow-soft); }
            .note-item .title { font-size: 14px; font-weight: 600; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
            .note-item .snippet { font-size: 12px; color: var(--muted); display: -webkit-box; -webkit-line-clamp: 2; -webkit-box-orient: vertical; overflow: hidden; }
            .editor-head {
              padding: 18px 28px 8px; border-bottom: 1px solid #0000000d; flex-shrink: 0;
            }
            .editor-head .folder-tag {
              font-size: 11px; color: var(--accent); font-weight: 600; margin-bottom: 6px;
            }
            .editor-head h2 {
              margin: 0; font-size: 28px; font-weight: 700; line-height: 1.2;
              font-family: "Segoe UI Variable Display", "SF Pro Display", "Segoe UI", sans-serif;
            }
            .editor-body {
              flex: 1; overflow: auto; padding: 16px 28px 40px;
              font-size: 16px; line-height: 1.55; white-space: pre-wrap; word-break: break-word;
            }
            .empty {
              flex: 1; display: grid; place-items: center; color: var(--muted); font-size: 14px;
              padding: 24px; text-align: center;
            }
            @media (max-width: 900px) {
              .shell { grid-template-columns: 180px 1fr; }
              .editor { grid-column: 1 / -1; min-height: 45vh; }
            }
            @media (max-width: 640px) {
              .shell { grid-template-columns: 1fr; }
              .folders { max-height: 28vh; }
              .notes { max-height: 32vh; }
            }
            </style>
            </head>
            <body>
            <header>
              <div style="display:flex;align-items:center;min-width:0">
                <h1>Note</h1>
                <span class="meta" id="summary"></span>
              </div>
              <input id="search" type="search" placeholder="Cerca note" autocomplete="off"/>
            </header>
            <div class="shell">
              <aside class="folders" id="folderList"></aside>
              <section class="notes" id="noteList"></section>
              <section class="editor" id="editor">
                <div class="empty">Seleziona una nota</div>
              </section>
            </div>
            <script type="application/json" id="notes-data">
            """);
        sb.Append(safeJson);
        sb.Append(
            """

            </script>
            <script>
            const DATA = JSON.parse(document.getElementById('notes-data').textContent);
            const folderListEl = document.getElementById('folderList');
            const noteListEl = document.getElementById('noteList');
            const editorEl = document.getElementById('editor');
            const summaryEl = document.getElementById('summary');
            const searchEl = document.getElementById('search');
            let activeFolder = null;
            let activeNote = null;

            summaryEl.textContent = `${DATA.folderCount} cartelle · ${DATA.noteCount} note`;

            function esc(s) {
              return String(s ?? '').replace(/[&<>"']/g, c => ({
                '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'
              }[c]));
            }

            function folderByKey(key) {
              return DATA.folders.find(f => f.key === key);
            }

            function notesInFolder(folderKey, q) {
              q = (q || '').trim().toLowerCase();
              return DATA.notes.filter(n => {
                if (folderKey && n.folderKey !== folderKey) return false;
                if (!q) return true;
                return (n.title || '').toLowerCase().includes(q)
                    || (n.snippet || '').toLowerCase().includes(q)
                    || (n.body || '').toLowerCase().includes(q);
              });
            }

            function renderFolders() {
              const q = searchEl.value;
              const system = DATA.folders.filter(f => f.isSystem && !f.isTrash);
              const custom = DATA.folders.filter(f => !f.isSystem && !f.isTrash);
              const trash = DATA.folders.filter(f => f.isTrash);
              const blocks = [];
              function block(title, items) {
                if (!items.length) return;
                blocks.push(`<div class="sec">${esc(title)}</div>`);
                items.forEach(f => {
                  const count = notesInFolder(f.key, q).length;
                  blocks.push(`
                    <div class="folder-item ${f.isTrash ? 'trash' : ''} ${f.key === activeFolder ? 'active' : ''}" data-key="${esc(f.key)}">
                      <div class="ico"></div>
                      <div class="name">${esc(f.name)}</div>
                      <div class="count">${count}</div>
                    </div>`);
                });
              }
              block('iCloud', system.concat(custom));
              block('Eliminate', trash);
              folderListEl.innerHTML = blocks.join('');
              folderListEl.querySelectorAll('.folder-item').forEach(el => {
                el.addEventListener('click', () => selectFolder(el.getAttribute('data-key')));
              });
            }

            function selectFolder(key) {
              activeFolder = key;
              renderFolders();
              renderNotes();
            }

            function renderNotes() {
              const notes = notesInFolder(activeFolder, searchEl.value);
              if (!notes.length) {
                noteListEl.innerHTML = '<div class="empty">Nessuna nota</div>';
                activeNote = null;
                editorEl.innerHTML = '<div class="empty">Nessuna nota in questa cartella</div>';
                return;
              }
              noteListEl.innerHTML = notes.map(n => `
                <div class="note-item ${n.id === activeNote ? 'active' : ''}" data-id="${esc(n.id)}">
                  <div class="title">${esc(n.title)}</div>
                  <div class="snippet">${esc(n.snippet || '')}</div>
                </div>`).join('');
              noteListEl.querySelectorAll('.note-item').forEach(el => {
                el.addEventListener('click', () => openNote(el.getAttribute('data-id')));
              });
              if (!notes.some(n => n.id === activeNote))
                openNote(notes[0].id);
              else
                highlightNote();
            }

            function highlightNote() {
              noteListEl.querySelectorAll('.note-item').forEach(el => {
                el.classList.toggle('active', el.getAttribute('data-id') === activeNote);
              });
            }

            function openNote(id) {
              activeNote = id;
              const note = DATA.notes.find(n => n.id === id);
              if (!note) return;
              const folder = folderByKey(note.folderKey);
              editorEl.innerHTML = `
                <div class="editor-head">
                  <div class="folder-tag">${esc(folder ? folder.name : 'Note')}</div>
                  <h2>${esc(note.title)}</h2>
                </div>
                <div class="editor-body">${esc(note.body || note.snippet || '')}</div>`;
              highlightNote();
            }

            searchEl.addEventListener('input', () => {
              renderFolders();
              renderNotes();
            });

            const first = DATA.folders.find(f => !f.isTrash) || DATA.folders[0];
            if (first) selectFolder(first.key);
            else {
              folderListEl.innerHTML = '<div class="empty">Nessuna cartella</div>';
              noteListEl.innerHTML = '';
              editorEl.innerHTML = '<div class="empty">Nessuna nota</div>';
            }
            </script>
            </body>
            </html>
            """);
        return sb.ToString();
    }

    private sealed record ViewerPayload(
        DateTimeOffset GeneratedAt,
        string SourceDb,
        int FolderCount,
        int NoteCount,
        IReadOnlyList<ViewerFolder> Folders,
        IReadOnlyList<ViewerNote> Notes);

    private sealed record ViewerFolder(
        string Id,
        string Key,
        string Name,
        bool IsSystem,
        bool IsTrash,
        int NoteCount = 0);

    private sealed record ViewerNote(
        string Id,
        string Title,
        string Snippet,
        string Body,
        string FolderKey,
        string? FolderRecordName,
        bool Deleted,
        string RecordType);
}
