using System.IO;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// <c>authenticateDS</c>: CSR RSA-2048 SHA-1, XML plist + gzip → cert auth IDS.
/// </summary>
public sealed class IdsAuthenticateDs
{
    private readonly HttpClient _http;
    private readonly IdsBag _bag;

    public IdsAuthenticateDs(HttpClient http, IdsBag bag)
    {
        _http = http;
        _bag = bag;
    }

    public async Task<(string KeyPem, string CertPem)> AuthenticateAsync(
        string profileId,
        string authToken,
        Action<string>? log = null,
        CancellationToken ct = default)
    {
        var url = await _bag.GetAsync("id-authenticate-ds-id", ct).ConfigureAwait(false);
        var (keyPem, csrDer) = GenerateSha1Csr(profileId);

        var bodyDict = new Dictionary<string, object?>
        {
            ["authentication-data"] = new Dictionary<string, object?>
            {
                ["auth-token"] = authToken,
            },
            ["csr"] = csrDer,
            ["realm-user-id"] = profileId,
        };
        var xml = AppleXmlPlist.ToXmlBytes(bodyDict);
        var gzipped = IdsSigning.GzipMtime0(xml);
        log?.Invoke($"authenticateDS: CSR={csrDer.Length} B, body gzip={gzipped.Length} B → {url}");

        using var request = new HttpRequestMessage(HttpMethod.Post, url);
        request.Headers.TryAddWithoutValidation("User-Agent", IdsConstants.InvitationUserAgent);
        request.Headers.TryAddWithoutValidation("x-protocol-version", IdsConstants.ProtocolVersion);
        request.Headers.TryAddWithoutValidation("Accept-Encoding", "gzip");
        request.Headers.TryAddWithoutValidation("Accept", "*/*");
        request.Content = new ByteArrayContent(gzipped);
        request.Content.Headers.ContentType = new MediaTypeHeaderValue("application/x-apple-plist");
        request.Content.Headers.ContentEncoding.Add("gzip");

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var bytes = await response.Content.ReadAsByteArrayAsync(ct).ConfigureAwait(false);
        var unzipped = IdsSigning.TryGunzip(bytes) ?? bytes;
        log?.Invoke($"authenticateDS HTTP {(int)response.StatusCode}, resp={unzipped.Length} B");

        Dictionary<string, object?> root;
        try
        {
            root = AppleXmlPlist.Parse(unzipped);
        }
        catch (Exception ex)
        {
            var preview = Encoding.UTF8.GetString(unzipped);
            if (preview.Length > 300)
                preview = preview[..300] + "…";
            throw new InvalidOperationException($"authenticateDS: plist non valido: {ex.Message} — {preview}");
        }

        var status = AppleXmlPlist.GetInt(root, "status");
        if (status is not 0)
        {
            var msg = AppleXmlPlist.GetString(root, "message") ?? "";
            throw new InvalidOperationException($"authenticateDS status={status} {msg}".Trim());
        }

        var certDer = AppleXmlPlist.GetData(root, "cert")
                      ?? throw new InvalidOperationException(
                          "authenticateDS: cert assente. Chiavi: " + string.Join(", ", root.Keys));

        var certPem = IdsSigning.ArmourCertDer(certDer);
        // valida parse
        _ = new X509CertificateParser().ReadCertificate(certDer);
        IdsStorage.SaveAuthKeyPair(keyPem, certPem);
        log?.Invoke($"authenticateDS OK — cert DER={certDer.Length} B salvato.");
        return (keyPem, certPem);
    }

    private static (string KeyPem, byte[] CsrDer) GenerateSha1Csr(string profileId)
    {
        var cn = Convert.ToHexString(SHA1.HashData(Encoding.UTF8.GetBytes(profileId)));
        var gen = new RsaKeyPairGenerator();
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = gen.GenerateKeyPair();

        var subject = new X509Name("CN=" + cn);
        var csr = new Pkcs10CertificationRequest(
            "SHA1WITHRSA",
            subject,
            keyPair.Public,
            null,
            keyPair.Private);

        string keyPem;
        using (var sw = new StringWriter())
        {
            new PemWriter(sw).WriteObject(keyPair.Private);
            keyPem = sw.ToString();
        }

        return (keyPem, csr.GetEncoded());
    }
}
