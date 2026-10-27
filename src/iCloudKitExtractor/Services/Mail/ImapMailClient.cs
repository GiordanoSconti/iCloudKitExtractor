using System.IO;
using System.Text;
using System.Text.RegularExpressions;
using MailKit;
using MailKit.Net.Imap;
using MailKit.Search;
using MailKit.Security;
using MimeKit;

namespace iCloudKitExtractor.Services.Mail;

/// <summary>Cartella IMAP (sola lettura).</summary>
public sealed record ImapFolderInfo(string FullName, string DisplayName, int TotalMessages);

/// <summary>Riga elenco messaggi (envelope, senza body).</summary>
public sealed record ImapMessageInfo(
    UniqueId Uid,
    string Subject,
    string From,
    DateTimeOffset? Date,
    bool IsSeen,
    bool HasAttachments,
    long Size);

/// <summary>Corpo messaggio: testo + HTML pronto per preview client-like.</summary>
public sealed record ImapMessageBody(
    UniqueId Uid,
    string Subject,
    string From,
    string To,
    DateTimeOffset? Date,
    string TextBody,
    /// <summary>Documento HTML completo (header + corpo) per WebBrowser.</summary>
    string HtmlDocument,
    bool IsHtml);

/// <summary>
/// Filtro IMAP SEARCH: periodo (Date header / sent) e parole chiave
/// (oggetto ∪ mittente ∪ corpo, AND tra token).
/// </summary>
public sealed record ImapMessageFilter(
    DateTime? FromDateInclusive = null,
    DateTime? ToDateInclusive = null,
    string? Keywords = null)
{
    public bool IsEmpty =>
        FromDateInclusive is null
        && ToDateInclusive is null
        && string.IsNullOrWhiteSpace(Keywords);

    public string Describe()
    {
        var parts = new List<string>();
        if (FromDateInclusive is DateTime from)
            parts.Add($"dal {from:yyyy-MM-dd}");
        if (ToDateInclusive is DateTime to)
            parts.Add($"al {to:yyyy-MM-dd}");
        if (!string.IsNullOrWhiteSpace(Keywords))
            parts.Add($"«{Keywords.Trim()}»");
        return parts.Count == 0 ? "" : string.Join(", ", parts);
    }
}

/// <summary>
/// Client IMAP iCloud sola lettura (LIST / SELECT / FETCH).
/// Auth: Apple ID + <b>app-specific password</b> (non il token MME/UAEA).
/// </summary>
public sealed class ImapMailClient : IAsyncDisposable
{
    public const string DefaultHost = "imap.mail.me.com";
    public const int DefaultPort = 993;
    public const string AppPasswordSettingsUrl =
        "https://account.apple.com/account/manage/section/security";
    public const string AppPasswordHelpUrl =
        "https://support.apple.com/102654";

    private ImapClient? _client;
    private string? _selectedFolder;

    public bool IsConnected => _client is { IsConnected: true, IsAuthenticated: true };
    public string? SelectedFolder => _selectedFolder;

    public async Task ConnectAsync(
        string host,
        int port,
        string username,
        string password,
        CancellationToken ct = default)
    {
        await DisconnectAsync().ConfigureAwait(false);

        host = string.IsNullOrWhiteSpace(host) ? DefaultHost : host.Trim();
        username = username.Trim();
        password = password.Trim();
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrWhiteSpace(password))
            throw new InvalidOperationException("Utente e password per app sono obbligatori.");

        var client = new ImapClient();
        try
        {
            await client.ConnectAsync(host, port, SecureSocketOptions.SslOnConnect, ct)
                .ConfigureAwait(false);
            await client.AuthenticateAsync(username, password, ct).ConfigureAwait(false);
            _client = client;
        }
        catch
        {
            client.Dispose();
            throw;
        }
    }

    public async Task<IReadOnlyList<ImapFolderInfo>> ListFoldersAsync(CancellationToken ct = default)
    {
        var client = RequireClient();
        var list = new List<ImapFolderInfo>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        async Task AddFolderAsync(IMailFolder folder)
        {
            if (!seen.Add(folder.FullName))
                return;
            try
            {
                if ((folder.Attributes & FolderAttributes.NoSelect) != 0)
                    return;
                await folder.StatusAsync(StatusItems.Count, ct).ConfigureAwait(false);
                list.Add(new ImapFolderInfo(
                    folder.FullName,
                    string.IsNullOrWhiteSpace(folder.Name) ? folder.FullName : folder.Name,
                    folder.Count));
            }
            catch
            {
                // ignore
            }
        }

        await AddFolderAsync(client.Inbox).ConfigureAwait(false);
        if (client.PersonalNamespaces.Count > 0)
        {
            var personal = client.GetFolder(client.PersonalNamespaces[0]);
            await WalkFoldersAsync(personal, list, seen, ct).ConfigureAwait(false);
        }

        list.Sort(static (a, b) =>
        {
            var ai = a.FullName.Equals("INBOX", StringComparison.OrdinalIgnoreCase) ? 0 : 1;
            var bi = b.FullName.Equals("INBOX", StringComparison.OrdinalIgnoreCase) ? 0 : 1;
            var c = ai.CompareTo(bi);
            return c != 0
                ? c
                : string.Compare(a.DisplayName, b.DisplayName, StringComparison.OrdinalIgnoreCase);
        });
        return list;
    }

    public async Task<IReadOnlyList<ImapMessageInfo>> ListMessagesAsync(
        string folderFullName,
        int maxCount = 100,
        ImapMessageFilter? filter = null,
        CancellationToken ct = default)
    {
        var folder = await OpenFolderReadOnlyAsync(folderFullName, ct).ConfigureAwait(false);
        if (folder.Count == 0)
            return [];

        maxCount = Math.Clamp(maxCount, 1, 500);
        IList<IMessageSummary> summaries;

        if (filter is { IsEmpty: false })
        {
            var uids = await SearchUidsInOpenFolderAsync(folder, filter, ct).ConfigureAwait(false);
            if (uids.Count == 0)
                return [];

            // Più recenti prima: UniqueId confrontabile; poi taglia a maxCount.
            var ordered = uids.OrderByDescending(static u => u.Id).Take(maxCount).ToList();
            summaries = await folder.FetchAsync(
                    ordered,
                    MessageSummaryItems.UniqueId
                    | MessageSummaryItems.Envelope
                    | MessageSummaryItems.Flags
                    | MessageSummaryItems.Size
                    | MessageSummaryItems.BodyStructure,
                    ct)
                .ConfigureAwait(false);
        }
        else
        {
            var start = Math.Max(0, folder.Count - maxCount);
            summaries = await folder.FetchAsync(
                    start,
                    -1,
                    MessageSummaryItems.UniqueId
                    | MessageSummaryItems.Envelope
                    | MessageSummaryItems.Flags
                    | MessageSummaryItems.Size
                    | MessageSummaryItems.BodyStructure,
                    ct)
                .ConfigureAwait(false);
        }

        var rows = new List<ImapMessageInfo>(summaries.Count);
        foreach (var s in summaries.OrderByDescending(static x => x.UniqueId.Id))
        {
            var env = s.Envelope;
            var subject = env?.Subject?.Trim() ?? "(senza oggetto)";
            var from = FormatAddresses(env?.From);
            var seen = s.Flags?.HasFlag(MessageFlags.Seen) == true;
            var attach = s.BodyParts?.Any(static p => p.IsAttachment) == true;

            rows.Add(new ImapMessageInfo(
                s.UniqueId,
                subject,
                from,
                env?.Date,
                seen,
                attach,
                s.Size ?? 0));
        }

        return rows;
    }

    public async Task<ImapMessageBody> FetchMessageAsync(
        string folderFullName,
        UniqueId uid,
        CancellationToken ct = default)
    {
        var message = await FetchMimeMessageAsync(folderFullName, uid, ct).ConfigureAwait(false);
        var subject = message.Subject?.Trim() ?? "(senza oggetto)";
        var from = FormatAddresses(message.From);
        var to = FormatAddresses(message.To);
        var text = PreferTextBody(message, out var isHtml);
        var htmlDoc = BuildHtmlPreviewDocument(message, subject, from, to);
        return new ImapMessageBody(
            uid,
            subject,
            from,
            to,
            message.Date,
            text,
            htmlDoc,
            isHtml);
    }

    /// <summary>Scarica il MIME completo (per export .eml).</summary>
    public async Task<MimeMessage> FetchMimeMessageAsync(
        string folderFullName,
        UniqueId uid,
        CancellationToken ct = default)
    {
        var client = RequireClient();
        var folder = await OpenFolderReadOnlyAsync(folderFullName, ct).ConfigureAwait(false);
        return await folder.GetMessageAsync(uid, ct).ConfigureAwait(false);
    }

    /// <summary>
    /// Tutti gli UID della cartella (ordine cronologico inverso: più recenti prima),
    /// opzionalmente filtrati con IMAP SEARCH.
    /// </summary>
    public async Task<IReadOnlyList<UniqueId>> ListAllUidsAsync(
        string folderFullName,
        ImapMessageFilter? filter = null,
        CancellationToken ct = default)
    {
        var folder = await OpenFolderReadOnlyAsync(folderFullName, ct).ConfigureAwait(false);
        if (folder.Count == 0)
            return [];

        if (filter is { IsEmpty: false })
        {
            var matched = await SearchUidsInOpenFolderAsync(folder, filter, ct).ConfigureAwait(false);
            return matched.OrderByDescending(static u => u.Id).ToList();
        }

        var summaries = await folder.FetchAsync(
                0,
                -1,
                MessageSummaryItems.UniqueId,
                ct)
            .ConfigureAwait(false);
        return summaries.OrderByDescending(static s => s.UniqueId.Id)
            .Select(static s => s.UniqueId)
            .ToList();
    }

    private static async Task<IList<UniqueId>> SearchUidsInOpenFolderAsync(
        IMailFolder folder,
        ImapMessageFilter filter,
        CancellationToken ct)
    {
        var query = BuildSearchQuery(filter);
        if (query is null)
            return [];
        return await folder.SearchAsync(query, ct).ConfigureAwait(false);
    }

    private static SearchQuery? BuildSearchQuery(ImapMessageFilter filter)
    {
        SearchQuery? q = null;

        if (filter.FromDateInclusive is DateTime from)
        {
            // SentSince = Date header on/after midnight of that day (locale → date-only).
            var since = from.Date;
            q = And(q, SearchQuery.SentSince(since));
        }

        if (filter.ToDateInclusive is DateTime to)
        {
            // SentBefore = strictly before midnight of the day after To (include whole To day).
            var before = to.Date.AddDays(1);
            q = And(q, SearchQuery.SentBefore(before));
        }

        if (!string.IsNullOrWhiteSpace(filter.Keywords))
        {
            foreach (var token in filter.Keywords.Split(
                         [' ', '\t', ',', ';'],
                         StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
            {
                if (token.Length == 0)
                    continue;
                // Oggetto ∪ mittente ∪ corpo (IMAP BODY include testo, non sempre allegati).
                var part = SearchQuery.SubjectContains(token)
                    .Or(SearchQuery.FromContains(token))
                    .Or(SearchQuery.BodyContains(token));
                q = And(q, part);
            }
        }

        return q;
    }

    private static SearchQuery And(SearchQuery? left, SearchQuery right) =>
        left is null ? right : left.And(right);

    private async Task<IMailFolder> OpenFolderReadOnlyAsync(
        string folderFullName,
        CancellationToken ct)
    {
        var client = RequireClient();
        var folder = await client.GetFolderAsync(folderFullName, ct).ConfigureAwait(false);
        if (!folder.IsOpen || folder.Access != FolderAccess.ReadOnly)
            await folder.OpenAsync(FolderAccess.ReadOnly, ct).ConfigureAwait(false);
        _selectedFolder = folder.FullName;
        return folder;
    }

    public async Task DisconnectAsync()
    {
        var client = _client;
        _client = null;
        _selectedFolder = null;
        if (client is null)
            return;
        try
        {
            if (client.IsConnected)
                await client.DisconnectAsync(true).ConfigureAwait(false);
        }
        catch
        {
            // ignore
        }
        finally
        {
            client.Dispose();
        }
    }

    public async ValueTask DisposeAsync() => await DisconnectAsync().ConfigureAwait(false);

    private ImapClient RequireClient() =>
        _client is { IsConnected: true, IsAuthenticated: true } c
            ? c
            : throw new InvalidOperationException("Non connesso a IMAP. Premi Connetti.");

    private static async Task WalkFoldersAsync(
        IMailFolder folder,
        List<ImapFolderInfo> sink,
        HashSet<string> seen,
        CancellationToken ct)
    {
        ct.ThrowIfCancellationRequested();
        if (folder.Exists && (folder.Attributes & FolderAttributes.NoSelect) == 0
            && seen.Add(folder.FullName))
        {
            try
            {
                await folder.StatusAsync(StatusItems.Count, ct).ConfigureAwait(false);
                sink.Add(new ImapFolderInfo(
                    folder.FullName,
                    string.IsNullOrWhiteSpace(folder.Name) ? folder.FullName : folder.Name,
                    folder.Count));
            }
            catch
            {
                // alcune cartelle speciali non accettano STATUS
            }
        }

        IList<IMailFolder> children;
        try
        {
            children = await folder.GetSubfoldersAsync(false, ct).ConfigureAwait(false);
        }
        catch
        {
            return;
        }

        foreach (var child in children)
            await WalkFoldersAsync(child, sink, seen, ct).ConfigureAwait(false);
    }

    private static string FormatAddresses(InternetAddressList? list)
    {
        if (list is null || list.Count == 0)
            return "";
        var sb = new StringBuilder();
        foreach (var a in list)
        {
            if (sb.Length > 0)
                sb.Append(", ");
            sb.Append(a.ToString());
        }

        return sb.ToString();
    }

    private static string PreferTextBody(MimeMessage message, out bool isHtml)
    {
        isHtml = false;
        var text = message.TextBody;
        if (!string.IsNullOrWhiteSpace(text))
            return text.TrimEnd();

        var html = message.HtmlBody;
        if (!string.IsNullOrWhiteSpace(html))
        {
            isHtml = true;
            return StripHtmlRough(html);
        }

        return "(nessun corpo testo)";
    }

    /// <summary>
    /// Anteprima stile client mail: HTML nativo con <c>cid:</c> → data URI,
    /// altrimenti testo in <c>&lt;pre&gt;</c>.
    /// </summary>
    public static string BuildHtmlPreviewDocument(
        MimeMessage message,
        string subject,
        string from,
        string to)
    {
        string bodyHtml;
        var rawHtml = message.HtmlBody;
        if (!string.IsNullOrWhiteSpace(rawHtml))
        {
            bodyHtml = RewriteCidToDataUris(message, rawHtml);
        }
        else
        {
            var text = message.TextBody;
            if (string.IsNullOrWhiteSpace(text))
                text = "(nessun corpo testo)";
            bodyHtml =
                "<pre style=\"white-space:pre-wrap;font-family:Segoe UI,Calibri,sans-serif;" +
                "font-size:14px;margin:0;color:#1a1a1a;\">" +
                System.Net.WebUtility.HtmlEncode(text.TrimEnd()) +
                "</pre>";
        }

        var date = message.Date != default
            ? message.Date.ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            : "";

        return
            "<!DOCTYPE html><html><head><meta charset=\"utf-8\"/>" +
            "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"/>" +
            "<style>" +
            "body{margin:0;padding:0;background:#fff;color:#1a1a1a;" +
            "font-family:Segoe UI,Calibri,Arial,sans-serif;font-size:14px;}" +
            ".hdr{padding:12px 14px;border-bottom:1px solid #e2e5e9;background:#f7f8fa;}" +
            ".hdr .row{margin:0 0 4px 0;line-height:1.35;}" +
            ".hdr .k{color:#667;min-width:4.5em;display:inline-block;}" +
            ".hdr .subj{font-size:16px;font-weight:600;margin:0 0 8px 0;}" +
            ".body{padding:14px;}" +
            "img{max-width:100%;height:auto;}" +
            "a{color:#0b57d0;}" +
            "</style></head><body>" +
            "<div class=\"hdr\">" +
            "<div class=\"subj\">" + H(subject) + "</div>" +
            "<div class=\"row\"><span class=\"k\">Da</span> " + H(from) + "</div>" +
            "<div class=\"row\"><span class=\"k\">A</span> " + H(to) + "</div>" +
            (string.IsNullOrEmpty(date)
                ? ""
                : "<div class=\"row\"><span class=\"k\">Data</span> " + H(date) + "</div>") +
            "</div>" +
            "<div class=\"body\">" + bodyHtml + "</div>" +
            "</body></html>";

        static string H(string? s) => System.Net.WebUtility.HtmlEncode(s ?? "");
    }

    private static readonly Regex CidUrlRegex = new(
        @"cid:(?<cid>[^""'\s>]+)",
        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

    /// <summary>Sostituisce riferimenti <c>cid:</c> con data URI dalle parti MIME collegate.</summary>
    private static string RewriteCidToDataUris(MimeMessage message, string html)
    {
        var byCid = new Dictionary<string, MimePart>(StringComparer.OrdinalIgnoreCase);
        foreach (var part in message.BodyParts.OfType<MimePart>())
        {
            if (string.IsNullOrWhiteSpace(part.ContentId))
                continue;
            var id = part.ContentId.Trim().Trim('<', '>');
            if (id.Length == 0)
                continue;
            byCid.TryAdd(id, part);
        }

        if (byCid.Count == 0)
            return html;

        return CidUrlRegex.Replace(html, m =>
        {
            var cid = m.Groups["cid"].Value.Trim().Trim('<', '>');
            if (!byCid.TryGetValue(cid, out var part) || part.Content is null)
                return m.Value;
            try
            {
                using var ms = new MemoryStream();
                part.Content.DecodeTo(ms);
                var bytes = ms.ToArray();
                if (bytes.Length == 0)
                    return m.Value;
                var mime = string.IsNullOrWhiteSpace(part.ContentType?.MimeType)
                    ? "application/octet-stream"
                    : part.ContentType.MimeType;
                return "data:" + mime + ";base64," + Convert.ToBase64String(bytes);
            }
            catch
            {
                return m.Value;
            }
        });
    }

    /// <summary>Pagina HTML minimale per stati/errori nella preview.</summary>
    public static string BuildStatusHtmlDocument(string message) =>
        "<!DOCTYPE html><html><head><meta charset=\"utf-8\"/>" +
        "<meta http-equiv=\"X-UA-Compatible\" content=\"IE=edge\"/>" +
        "<style>body{font-family:Segoe UI,Calibri,sans-serif;font-size:14px;" +
        "color:#445;padding:16px;margin:0;background:#fafbfc;}</style></head><body>" +
        "<p>" + System.Net.WebUtility.HtmlEncode(message) + "</p></body></html>";

    private static string StripHtmlRough(string html)
    {
        var sb = new StringBuilder(html.Length);
        var inTag = false;
        foreach (var c in html)
        {
            if (c == '<')
            {
                inTag = true;
                continue;
            }

            if (c == '>')
            {
                inTag = false;
                continue;
            }

            if (!inTag)
                sb.Append(c);
        }

        return System.Net.WebUtility.HtmlDecode(sb.ToString()).Trim();
    }

}
