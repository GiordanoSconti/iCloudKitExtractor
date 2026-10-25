using System.Text;
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

/// <summary>Corpo messaggio già decodificato (testo preferito).</summary>
public sealed record ImapMessageBody(
    UniqueId Uid,
    string Subject,
    string From,
    string To,
    DateTimeOffset? Date,
    string TextBody,
    bool IsHtml);

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
        CancellationToken ct = default)
    {
        var client = RequireClient();
        var folder = await client.GetFolderAsync(folderFullName, ct).ConfigureAwait(false);
        await folder.OpenAsync(FolderAccess.ReadOnly, ct).ConfigureAwait(false);
        _selectedFolder = folder.FullName;

        if (folder.Count == 0)
            return [];

        maxCount = Math.Clamp(maxCount, 1, 500);
        var start = Math.Max(0, folder.Count - maxCount);
        var summaries = await folder.FetchAsync(
                start,
                -1,
                MessageSummaryItems.UniqueId
                | MessageSummaryItems.Envelope
                | MessageSummaryItems.Flags
                | MessageSummaryItems.Size
                | MessageSummaryItems.BodyStructure,
                ct)
            .ConfigureAwait(false);

        var rows = new List<ImapMessageInfo>(summaries.Count);
        foreach (var s in summaries.Reverse())
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
        var client = RequireClient();
        var folder = await client.GetFolderAsync(folderFullName, ct).ConfigureAwait(false);
        if (!folder.IsOpen || folder.Access != FolderAccess.ReadOnly)
            await folder.OpenAsync(FolderAccess.ReadOnly, ct).ConfigureAwait(false);
        _selectedFolder = folder.FullName;

        var message = await folder.GetMessageAsync(uid, ct).ConfigureAwait(false);
        var text = PreferTextBody(message, out var isHtml);
        return new ImapMessageBody(
            uid,
            message.Subject?.Trim() ?? "(senza oggetto)",
            FormatAddresses(message.From),
            FormatAddresses(message.To),
            message.Date,
            text,
            isHtml);
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
