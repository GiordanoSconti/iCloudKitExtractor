using System.IO;
using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Protocol;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace iCloudKitExtractor.Services.Push;

/// <summary>
/// Attivazione Albert Windows → DeviceCertificate per APS (schema pypush).
/// </summary>
public sealed class AlbertPushActivation
{
    // pypush: deviceservices/deviceActivation (non WebObjects/ALUnbrick).
    private const string ActivationUrl =
        "https://albert.apple.com/deviceservices/deviceActivation?device=Windows";

    private readonly HttpClient _http;

    public AlbertPushActivation(HttpClient http) => _http = http;

    /// <summary>
    /// Genera CSR, attiva su Albert, persiste key+cert. Ritorna PEM cert.
    /// </summary>
    public async Task<string> ActivateAsync(CancellationToken ct = default)
    {
        var (serial, udid) = ApsStorage.ResolveWindowsIdentity();
        var (keyPair, keyPem, csrPem) = GenerateKeyAndCsr();

        var activationInfo = new Dictionary<string, object?>
        {
            ["ActivationRandomness"] = Guid.NewGuid().ToString().ToUpperInvariant(),
            ["ActivationState"] = "Unactivated",
            ["BuildVersion"] = "10.6.4",
            ["DeviceCertRequest"] = Encoding.UTF8.GetBytes(csrPem),
            ["DeviceClass"] = "Windows",
            ["ProductType"] = "windows1,1",
            ["ProductVersion"] = "10.6.4",
            ["SerialNumber"] = serial,
            ["UniqueDeviceID"] = udid,
        };
        var activationInfoXml = AppleXmlPlist.ToXmlBytes(activationInfo);

        var fairplayKey = LoadFairPlayPrivateKey();
        var signature = SignDataSha1Rsa(fairplayKey, activationInfoXml);

        var body = new Dictionary<string, object?>
        {
            ["ActivationInfoComplete"] = true,
            ["ActivationInfoXML"] = activationInfoXml,
            ["FairPlayCertChain"] = FairPlayActivationMaterial.CertChainDer,
            ["FairPlaySignature"] = signature,
        };
        var activationPlist = AppleXmlPlist.ToXmlBytes(body);

        using var form = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            ["activation-info"] = Encoding.UTF8.GetString(activationPlist),
        });
        using var request = new HttpRequestMessage(HttpMethod.Post, ActivationUrl) { Content = form };
        request.Headers.TryAddWithoutValidation("User-Agent", "iTunes/12.6.2 (Windows; N; Windows 10)");
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("*/*"));

        using var response = await _http.SendAsync(request, ct).ConfigureAwait(false);
        var text = await response.Content.ReadAsStringAsync(ct).ConfigureAwait(false);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Albert HTTP {(int)response.StatusCode}: {Trim(text, 400)}");

        var certPem = ExtractDeviceCertificatePem(text);
        // Non usiamo keyPair oltre generazione — keyPem è la private key.
        _ = keyPair;
        ApsStorage.SaveCertificate(keyPem, certPem, serial, udid);
        return certPem;
    }

    private static (AsymmetricCipherKeyPair KeyPair, string KeyPem, string CsrPem) GenerateKeyAndCsr()
    {
        var gen = new RsaKeyPairGenerator();
        // pypush albert.py: RSA 1024 (Albert Windows lo richiede così).
        gen.Init(new KeyGenerationParameters(new SecureRandom(), 1024));
        var keyPair = gen.GenerateKeyPair();

        var subject = new X509Name(
            $"C=US, ST=CA, L=Cupertino, O=Apple Inc., OU=iPhone, CN={Guid.NewGuid()}");
        var csr = new Pkcs10CertificationRequest(
            "SHA256WITHRSA",
            subject,
            keyPair.Public,
            null,
            keyPair.Private);

        string keyPem;
        using (var sw = new StringWriter())
        {
            var pw = new PemWriter(sw);
            pw.WriteObject(keyPair.Private);
            pw.Writer.Flush();
            keyPem = sw.ToString();
        }

        string csrPem;
        using (var sw = new StringWriter())
        {
            var pw = new PemWriter(sw);
            pw.WriteObject(csr);
            pw.Writer.Flush();
            csrPem = sw.ToString();
        }

        return (keyPair, keyPem, csrPem);
    }

    private static AsymmetricKeyParameter LoadFairPlayPrivateKey()
    {
        using var reader = new StringReader(FairPlayActivationMaterial.PrivateKeyPem);
        var pem = new PemReader(reader).ReadObject();
        if (pem is AsymmetricCipherKeyPair pair)
            return pair.Private;
        if (pem is AsymmetricKeyParameter key)
            return key;
        throw new InvalidOperationException($"FairPlay key tipo inatteso: {pem?.GetType().Name}");
    }

    private static byte[] SignDataSha1Rsa(AsymmetricKeyParameter privateKey, byte[] data)
    {
        var signer = SignerUtilities.GetSigner("SHA1withRSA");
        signer.Init(true, privateKey);
        signer.BlockUpdate(data, 0, data.Length);
        return signer.GenerateSignature();
    }

    private static string ExtractDeviceCertificatePem(string responseText)
    {
        // Risposta Albert: HTML/XML con plist innestato.
        var plistXml = TryExtractPlistXml(responseText)
                       ?? throw new InvalidOperationException(
                           "Albert: nessun plist nella risposta: " + Trim(responseText, 300));

        Dictionary<string, object?> root;
        try
        {
            root = AppleXmlPlist.Parse(Encoding.UTF8.GetBytes(plistXml));
        }
        catch (Exception ex)
        {
            throw new InvalidOperationException("Albert: plist non valido: " + ex.Message, ex);
        }

        if (!TryGetPath(root, out var certObj, "device-activation", "activation-record", "DeviceCertificate")
            && !TryGetPath(root, out certObj, "DeviceCertificate"))
        {
            throw new InvalidOperationException(
                "Albert: DeviceCertificate assente. Chiavi: " + string.Join(", ", root.Keys));
        }

        return certObj switch
        {
            byte[] data => Encoding.UTF8.GetString(data).Trim(),
            string s when s.Contains("BEGIN CERTIFICATE", StringComparison.Ordinal) => s.Trim(),
            string s => Encoding.UTF8.GetString(Convert.FromBase64String(CompactB64(s))).Trim(),
            _ => throw new InvalidOperationException(
                $"Albert: DeviceCertificate tipo {certObj?.GetType().Name}"),
        };
    }

    private static string? TryExtractPlistXml(string text)
    {
        var m = Regex.Match(
            text,
            @"<\?xml[^>]*>\s*<plist[\s\S]*?</plist>",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (m.Success)
            return m.Value;

        m = Regex.Match(
            text,
            @"<plist[\s\S]*?</plist>",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (m.Success)
            return m.Value;

        // Alcune risposte wrappano in <Protocol>…base64…</Protocol>
        m = Regex.Match(
            text,
            @"<Protocol[^>]*>([\s\S]*?)</Protocol>",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        if (m.Success)
        {
            var inner = m.Groups[1].Value.Trim();
            if (inner.Contains("<plist", StringComparison.OrdinalIgnoreCase))
                return TryExtractPlistXml(inner);
            try
            {
                var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(CompactB64(inner)));
                return TryExtractPlistXml(decoded) ?? decoded;
            }
            catch
            {
                // ignore
            }
        }

        if (text.TrimStart().StartsWith('<'))
            return text;
        return null;
    }

    private static bool TryGetPath(
        Dictionary<string, object?> root,
        out object? value,
        params string[] path)
    {
        object? cur = root;
        foreach (var p in path)
        {
            if (cur is not Dictionary<string, object?> dict
                || !dict.TryGetValue(p, out cur))
            {
                value = null;
                return false;
            }
        }

        value = cur;
        return true;
    }

    private static string CompactB64(string s) =>
        Regex.Replace(s, @"\s+", "");

    private static string Trim(string s, int max) =>
        s.Length <= max ? s : s[..max] + "…";
}
