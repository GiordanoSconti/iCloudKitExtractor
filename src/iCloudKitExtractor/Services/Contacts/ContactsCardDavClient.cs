using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml.Linq;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Contacts;

/// <summary>Voce addressbook CardDAV (sola lettura).</summary>
public sealed record ContactEntry(
    string Href,
    string Url,
    string? Fn,
    string? Uid,
    string? Etag,
    string? PhotoUrl,
    string? Rev)
{
    public override string ToString() =>
        string.IsNullOrWhiteSpace(Fn) ? (Uid ?? Href) : Fn!;
}

/// <summary>Snapshot discovery + elenco contatti da addressbook-query.</summary>
public sealed record AddressbookSnapshot(
    string Host,
    string PrincipalUrl,
    string HomeUrl,
    string BookUrl,
    string? DisplayName,
    string? Ctag,
    IReadOnlyList<ContactEntry> Contacts);

/// <summary>
/// Contacts CardDAV (sola lettura): discovery, elenco, GET vCard singolo, GET foto.
/// Auth <c>Basic {dsid}:{MobileMe/UAEA}</c>.
/// </summary>
public sealed class ContactsCardDavClient
{
    private static readonly HttpMethod PropFindMethod = new("PROPFIND");
    private static readonly HttpMethod ReportMethod = new("REPORT");

    private static readonly XNamespace Dav = "DAV:";
    private static readonly XNamespace CardDav = "urn:ietf:params:xml:ns:carddav";
    private static readonly XNamespace Cs = "http://calendarserver.org/ns/";

    private const string PropPrincipal = """
        <?xml version="1.0" encoding="UTF-8"?>
        <d:propfind xmlns:d="DAV:">
          <d:prop><d:current-user-principal/></d:prop>
        </d:propfind>
        """;

    private const string PropHome = """
        <?xml version="1.0" encoding="UTF-8"?>
        <d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
          <d:prop><card:addressbook-home-set/><d:displayname/></d:prop>
        </d:propfind>
        """;

    private const string PropCollections = """
        <?xml version="1.0" encoding="UTF-8"?>
        <d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav"
                    xmlns:cs="http://calendarserver.org/ns/">
          <d:prop>
            <d:displayname/>
            <d:resourcetype/>
            <cs:getctag/>
            <d:getetag/>
          </d:prop>
        </d:propfind>
        """;

    private const string ReportAddressbookQuery = """
        <?xml version="1.0" encoding="UTF-8"?>
        <card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
          <d:prop>
            <d:getetag/>
            <card:address-data/>
          </d:prop>
        </card:addressbook-query>
        """;

    private readonly HttpClient _http;

    public ContactsCardDavClient(HttpClient http) => _http = http;

    public async Task<AddressbookSnapshot> FetchAddressbookAsync(
        ICloudSession session,
        CancellationToken ct = default)
    {
        var (auth, host, dsid) = Begin(session);

        var rootXml = await DavAsync(
            PropFindMethod, $"{host}/", "0", PropPrincipal, auth, session, ct).ConfigureAwait(false);
        var principalHref = FirstHref(rootXml, Dav + "current-user-principal")
            ?? $"/{dsid}/principal/";
        var principalUrl = Absolutize(host, principalHref);

        var homeXml = await DavAsync(
            PropFindMethod, EnsureTrailingSlash(principalUrl), "0", PropHome, auth, session, ct)
            .ConfigureAwait(false);
        var homeHref = FirstHref(homeXml, CardDav + "addressbook-home-set")
            ?? throw new InvalidOperationException("CardDAV: addressbook-home-set assente.");
        var homeUrl = EnsureTrailingSlash(Absolutize(host, homeHref));
        var displayName = FirstElementValue(homeXml, Dav + "displayname");

        var colXml = await DavAsync(
            PropFindMethod, homeUrl, "1", PropCollections, auth, session, ct).ConfigureAwait(false);
        var bookHref = FindAddressbookHref(colXml)
            ?? throw new InvalidOperationException("CardDAV: nessuna collection addressbook.");
        var bookUrl = EnsureTrailingSlash(Absolutize(host, bookHref));
        var ctag = FirstElementValue(colXml, Cs + "getctag");

        var reportXml = await DavAsync(
            ReportMethod, bookUrl, "1", ReportAddressbookQuery, auth, session, ct)
            .ConfigureAwait(false);

        var contacts = ParseContacts(host, reportXml);
        return new AddressbookSnapshot(host, principalUrl, homeUrl, bookUrl, displayName, ctag, contacts);
    }

    public async Task<string> FetchAddressbookTextAsync(
        ICloudSession session,
        CancellationToken ct = default)
    {
        var snap = await FetchAddressbookAsync(session, ct).ConfigureAwait(false);
        return FormatSnapshot(snap);
    }

    /// <summary>GET della risorsa <c>.vcf</c> del singolo contatto.</summary>
    public async Task<string> FetchVcardAsync(
        ICloudSession session,
        string contactUrl,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(contactUrl))
            throw new ArgumentException("URL contatto mancante.", nameof(contactUrl));

        var (auth, _, _) = Begin(session);
        var (bytes, contentType, code) = await GetBytesAsync(contactUrl.Trim(), auth, session, ct)
            .ConfigureAwait(false);
        if (code is < 200 or >= 300)
        {
            var preview = Encoding.UTF8.GetString(bytes.AsSpan(0, Math.Min(bytes.Length, 240)));
            throw new InvalidOperationException($"Contacts GET vCard HTTP {code}: {preview}");
        }

        var text = Encoding.UTF8.GetString(bytes);
        if (string.IsNullOrWhiteSpace(text))
            throw new InvalidOperationException($"Contacts GET vCard vuoto (ct={contentType}).");
        return text;
    }

    /// <summary>GET immagine da URL PHOTO (gateway.icloud.com/contacts/…).</summary>
    public async Task<(byte[] Bytes, string ContentType)> FetchPhotoAsync(
        ICloudSession session,
        string photoUrl,
        CancellationToken ct = default)
    {
        if (string.IsNullOrWhiteSpace(photoUrl))
            throw new ArgumentException("URL foto mancante.", nameof(photoUrl));

        var (auth, _, _) = Begin(session);
        var (bytes, contentType, code) = await GetBytesAsync(photoUrl.Trim(), auth, session, ct)
            .ConfigureAwait(false);
        if (code is < 200 or >= 300 || bytes.Length == 0)
        {
            var preview = Encoding.UTF8.GetString(bytes.AsSpan(0, Math.Min(bytes.Length, 240)));
            throw new InvalidOperationException($"Contacts GET foto HTTP {code}: {preview}");
        }

        return (bytes, string.IsNullOrWhiteSpace(contentType) ? "image/jpeg" : contentType);
    }

    internal static string ResolveHost(ICloudSession session)
    {
        foreach (var key in new[]
                 {
                     "Contacts",
                     "com.apple.Dataclass.Contacts",
                     "com.apple.Dataclass.Contacts.url",
                 })
        {
            if (session.DataclassServiceUrls.TryGetValue(key, out var url)
                && !string.IsNullOrWhiteSpace(url)
                && Uri.TryCreate(url.Replace(":443", "", StringComparison.Ordinal), UriKind.Absolute, out var uri))
                return $"{uri.Scheme}://{uri.Host}";
        }

        var partition = string.IsNullOrWhiteSpace(session.Partition) ? "p116" : session.Partition.Trim();
        if (!partition.StartsWith('p'))
            partition = "p" + partition;
        return $"https://{partition}-contacts.icloud.com";
    }

    internal static string? ExtractPhotoUrl(string vcard)
    {
        var unfolded = UnfoldVcard(vcard);
        var m = Regex.Match(
            unfolded,
            @"(?im)^PHOTO(?:;[^:\r\n]*)?:(.*)$");
        if (!m.Success)
            return null;

        var value = m.Groups[1].Value.Trim();
        var uriMatch = Regex.Match(
            m.Value,
            @"VALUE=uri:(\S+)",
            RegexOptions.IgnoreCase);
        if (uriMatch.Success)
            return uriMatch.Groups[1].Value.Trim().TrimEnd('\r');

        if (value.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            return value.TrimEnd('\r');

        return null;
    }

    internal static string FormatSnapshot(AddressbookSnapshot snap)
    {
        var sb = new StringBuilder();
        sb.AppendLine("=== Contacts — CardDAV addressbook-query ===");
        sb.AppendLine($"Host: {snap.Host}");
        sb.AppendLine($"Principal: {snap.PrincipalUrl}");
        sb.AppendLine($"Home-set: {snap.HomeUrl}");
        sb.AppendLine($"Addressbook: {snap.BookUrl}");
        if (!string.IsNullOrWhiteSpace(snap.DisplayName))
            sb.AppendLine($"DisplayName: {snap.DisplayName}");
        if (!string.IsNullOrWhiteSpace(snap.Ctag))
            sb.AppendLine($"getctag: {snap.Ctag}");
        sb.AppendLine();
        sb.AppendLine($"Contatti: {snap.Contacts.Count}");
        var i = 0;
        foreach (var c in snap.Contacts)
        {
            i++;
            sb.AppendLine($"--- [{i}] ---");
            sb.AppendLine($"  href: {c.Href}");
            if (!string.IsNullOrEmpty(c.Etag))
                sb.AppendLine($"  etag: {c.Etag}");
            if (!string.IsNullOrEmpty(c.Fn))
                sb.AppendLine($"  FN: {c.Fn}");
            if (!string.IsNullOrEmpty(c.Uid))
                sb.AppendLine($"  UID: {c.Uid}");
            if (!string.IsNullOrEmpty(c.Rev))
                sb.AppendLine($"  REV: {c.Rev}");
            sb.AppendLine($"  PHOTO: {(string.IsNullOrEmpty(c.PhotoUrl) ? "no" : c.PhotoUrl)}");
        }

        if (snap.Contacts.Count == 0)
            sb.AppendLine("(nessun contatto nell'addressbook)");
        sb.AppendLine();
        sb.AppendLine("Seleziona un contatto nel pannello a destra per caricare vCard o foto.");
        return sb.ToString().TrimEnd();
    }

    private (string Auth, string Host, string Dsid) Begin(ICloudSession session)
    {
        if (string.IsNullOrWhiteSpace(session.Dsid))
            throw new InvalidOperationException("Sessione senza DSID.");

        var secret = SessionMmeAuth.ResolveSecret(session);
        if (string.IsNullOrWhiteSpace(secret))
            throw new InvalidOperationException("Manca secret sessione (MobileMeAuthToken / UAEA…).");

        var dsid = session.Dsid.Trim();
        var auth = $"Basic {AppleHttpExtensions.BasicAuth(dsid, secret)}";
        return (auth, ResolveHost(session), dsid);
    }

    private async Task<string> DavAsync(
        HttpMethod method,
        string url,
        string depth,
        string body,
        string authorization,
        ICloudSession session,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(method, url);
        request.Content = new StringContent(body, Encoding.UTF8, "application/xml");
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        request.Headers.TryAddWithoutValidation("Depth", depth);
        ApplySessionHeaders(request, session);

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        var code = (int)response.StatusCode;
        if (code != 207 && !response.IsSuccessStatusCode)
        {
            var preview = text.Length > 240 ? text[..240] : text;
            throw new InvalidOperationException(
                $"Contacts {method.Method} {url} HTTP {code}: {preview}");
        }

        return text;
    }

    private async Task<(byte[] Bytes, string ContentType, int Code)> GetBytesAsync(
        string url,
        string authorization,
        ICloudSession session,
        CancellationToken ct)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.TryAddWithoutValidation("Authorization", authorization);
        ApplySessionHeaders(request, session);

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        var ctHeader = response.Content.Headers.ContentType?.ToString() ?? "";
        return (bytes, ctHeader, (int)response.StatusCode);
    }

    private static void ApplySessionHeaders(HttpRequestMessage request, ICloudSession session)
    {
        session.Anisette.TouchClientTimeUtc();
        request.ApplyAnisetteHeaders(session.Anisette, iosRouting: true);
        if (!string.IsNullOrEmpty(session.Anisette.MdLu))
            request.Headers.TryAddWithoutValidation("X-Apple-I-MD-LU", session.Anisette.MdLu);
        request.Headers.Accept.Clear();
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));
    }

    private static List<ContactEntry> ParseContacts(string host, string reportXml)
    {
        var list = new List<ContactEntry>();
        XDocument doc;
        try
        {
            doc = XDocument.Parse(reportXml);
        }
        catch
        {
            return list;
        }

        foreach (var resp in doc.Descendants(Dav + "response"))
        {
            var href = resp.Element(Dav + "href")?.Value?.Trim() ?? "";
            if (string.IsNullOrEmpty(href) || href.EndsWith('/'))
                continue;

            var etag = resp.Descendants(Dav + "getetag").FirstOrDefault()?.Value?.Trim();
            var rawData = resp.Descendants(CardDav + "address-data").FirstOrDefault()?.Value ?? "";
            var vcard = DecodeXmlText(rawData);
            list.Add(new ContactEntry(
                Href: href,
                Url: Absolutize(host, href),
                Fn: MatchVcardLine(vcard, "FN"),
                Uid: MatchVcardLine(vcard, "UID"),
                Etag: etag,
                PhotoUrl: ExtractPhotoUrl(vcard),
                Rev: MatchVcardLine(vcard, "REV")));
        }

        return list;
    }

    private static string? FindAddressbookHref(string xml)
    {
        XDocument doc;
        try
        {
            doc = XDocument.Parse(xml);
        }
        catch
        {
            return null;
        }

        foreach (var resp in doc.Descendants(Dav + "response"))
        {
            var href = resp.Element(Dav + "href")?.Value?.Trim();
            if (string.IsNullOrEmpty(href))
                continue;
            var rt = resp.Descendants(Dav + "resourcetype").FirstOrDefault();
            if (rt is null)
                continue;
            var isCollection = rt.Element(Dav + "collection") is not null;
            var isAddressbook = rt.Element(CardDav + "addressbook") is not null
                || href.Contains("/carddavhome/card", StringComparison.OrdinalIgnoreCase)
                || href.TrimEnd('/').EndsWith("/card", StringComparison.OrdinalIgnoreCase);
            if (isCollection && isAddressbook
                && !href.TrimEnd('/').EndsWith("carddavhome", StringComparison.OrdinalIgnoreCase))
                return href;
        }

        foreach (var href in doc.Descendants(Dav + "href").Select(e => e.Value.Trim()))
        {
            if (href.Contains("/carddavhome/card", StringComparison.OrdinalIgnoreCase))
                return href;
        }

        return null;
    }

    private static string? FirstHref(string xml, XName container)
    {
        try
        {
            var doc = XDocument.Parse(xml);
            var el = doc.Descendants(container).FirstOrDefault();
            return el?.Descendants(Dav + "href").FirstOrDefault()?.Value?.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static string? FirstElementValue(string xml, XName name)
    {
        try
        {
            return XDocument.Parse(xml).Descendants(name).FirstOrDefault()?.Value?.Trim();
        }
        catch
        {
            return null;
        }
    }

    private static string Absolutize(string host, string href)
    {
        if (href.StartsWith("http", StringComparison.OrdinalIgnoreCase))
            return href.Replace(":443", "", StringComparison.Ordinal);
        if (!href.StartsWith('/'))
            href = "/" + href;
        return host.TrimEnd('/') + href;
    }

    private static string EnsureTrailingSlash(string url) =>
        url.EndsWith('/') ? url : url + "/";

    private static string DecodeXmlText(string raw)
    {
        if (string.IsNullOrEmpty(raw))
            return "";
        return raw
            .Replace("&#13;", "\r", StringComparison.Ordinal)
            .Replace("&#10;", "\n", StringComparison.Ordinal)
            .Replace("&amp;", "&", StringComparison.Ordinal)
            .Replace("&lt;", "<", StringComparison.Ordinal)
            .Replace("&gt;", ">", StringComparison.Ordinal)
            .Replace("&quot;", "\"", StringComparison.Ordinal);
    }

    private static string UnfoldVcard(string vcard)
    {
        if (string.IsNullOrEmpty(vcard))
            return "";
        return Regex.Replace(vcard, @"\r?\n[ \t]", "");
    }

    private static string? MatchVcardLine(string vcard, string key)
    {
        var unfolded = UnfoldVcard(vcard);
        var m = Regex.Match(
            unfolded,
            $@"(?im)^{Regex.Escape(key)}(?:;[^:\r\n]*)?:(.*)$");
        if (!m.Success)
            return null;
        var v = m.Groups[1].Value.Trim().TrimEnd('\r');
        return string.IsNullOrWhiteSpace(v) ? null : v;
    }
}
