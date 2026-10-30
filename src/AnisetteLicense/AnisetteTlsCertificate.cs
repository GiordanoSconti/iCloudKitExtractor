using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace iCloudKitExtractor.AnisetteLicense;

/// <summary>
/// HTTPS material for Anisette middleware: auto-create a lab self-signed PFX/CER,
/// or load operator-supplied PFX / PEM (Let's Encrypt, etc.).
/// Auto certs include localhost, 127.0.0.1, and the machine's current NIC IPs.
/// </summary>
public static class AnisetteTlsCertificate
{
    public static string TlsDirectory =>
        Environment.GetEnvironmentVariable("ANISETTE_TLS_DIR")?.Trim() is { Length: > 0 } d
            ? Path.GetFullPath(d)
            : Path.Combine(LicensePaths.DataDir, "tls");

    public static string PfxPath =>
        Environment.GetEnvironmentVariable("ANISETTE_TLS_PFX")?.Trim() is { Length: > 0 } p
            ? Path.GetFullPath(p)
            : Path.Combine(TlsDirectory, "anisette-https.pfx");

    public static string CerPath =>
        Path.Combine(TlsDirectory, "anisette-https.cer");

    public static string ThumbprintPath =>
        Path.Combine(TlsDirectory, "anisette-https.thumbprint");

    public static string SanListPath =>
        Path.Combine(TlsDirectory, "anisette-https.san.txt");

    public static string? PfxPassword =>
        Environment.GetEnvironmentVariable("ANISETTE_TLS_PFX_PASSWORD");

    /// <summary>
    /// Load existing TLS material or generate a 5-year self-signed server certificate.
    /// Extra DNS/IP names: <c>ANISETTE_TLS_DNS</c> (comma-separated) + <paramref name="extraNames"/>.
    /// </summary>
    public static X509Certificate2 LoadOrCreate(params string[] extraNames)
    {
        Directory.CreateDirectory(TlsDirectory);

        var certPem = Environment.GetEnvironmentVariable("ANISETTE_TLS_CERT")?.Trim();
        var keyPem = Environment.GetEnvironmentVariable("ANISETTE_TLS_KEY")?.Trim();
        if (!string.IsNullOrEmpty(certPem)
            && !string.IsNullOrEmpty(keyPem)
            && File.Exists(certPem)
            && File.Exists(keyPem))
        {
            var fromPem = X509Certificate2.CreateFromPemFile(certPem, keyPem);
            return EnsurePrivateKeyExportable(fromPem);
        }

        if (File.Exists(PfxPath))
        {
            try
            {
                var existing = LoadPfx(PfxPath, PfxPassword);
                // Regenerate if a current LAN/host IP is missing from SAN (DHCP / new NIC).
                if (CertificateCoversLocalAddresses(existing))
                    return existing;
                existing.Dispose();
            }
            catch
            {
                // Corrupt / wrong password → regenerate below.
            }
        }

        return CreateAndPersist(extraNames);
    }

    public static X509Certificate2 CreateAndPersist(params string[] extraNames)
    {
        Directory.CreateDirectory(TlsDirectory);

        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=AnisetteServer",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: true));
        req.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.1") },
                critical: true));

        var sanNames = new List<string>();
        var san = new SubjectAlternativeNameBuilder();
        AddSanDns(san, sanNames, "localhost");
        AddSanIp(san, sanNames, IPAddress.Loopback);
        AddSanIp(san, sanNames, IPAddress.IPv6Loopback);
        try
        {
            var host = Environment.MachineName?.Trim();
            if (!string.IsNullOrEmpty(host))
                AddSanDns(san, sanNames, host);
        }
        catch
        {
            // ignore
        }

        foreach (var ip in EnumerateLocalAddresses())
            AddSanIp(san, sanNames, ip);

        foreach (var name in CollectNames(extraNames))
        {
            if (IPAddress.TryParse(name, out var ip))
                AddSanIp(san, sanNames, ip);
            else
                AddSanDns(san, sanNames, name);
        }

        req.CertificateExtensions.Add(san.Build());

        using var created = req.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddDays(-1),
            DateTimeOffset.UtcNow.AddYears(5));

        var password = PfxPassword ?? "";
        var pfxBytes = created.Export(X509ContentType.Pfx, password);
        File.WriteAllBytes(PfxPath, pfxBytes);
        File.WriteAllBytes(CerPath, created.Export(X509ContentType.Cert));
        File.WriteAllText(SanListPath, string.Join(Environment.NewLine, sanNames) + Environment.NewLine);

        var loaded = LoadPfx(PfxPath, string.IsNullOrEmpty(password) ? null : password);
        File.WriteAllText(ThumbprintPath, loaded.Thumbprint + Environment.NewLine);
        Console.WriteLine(
            $"[anisette-tls] issued self-signed cert SANs: {string.Join(", ", sanNames)}");
        return loaded;
    }

    /// <summary>Unicast IPv4/IPv6 on up NICs (excludes loopback / link-local IPv6 clutter optional).</summary>
    public static IReadOnlyList<IPAddress> EnumerateLocalAddresses()
    {
        // NetworkInterface enumeration has hung on some macOS setups; bound the wait.
        try
        {
            var task = Task.Run(EnumerateLocalAddressesCore);
            return task.Wait(TimeSpan.FromSeconds(3)) ? task.Result : Array.Empty<IPAddress>();
        }
        catch
        {
            return Array.Empty<IPAddress>();
        }
    }

    private static IReadOnlyList<IPAddress> EnumerateLocalAddressesCore()
    {
        var list = new List<IPAddress>();
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up)
                    continue;
                if (nic.NetworkInterfaceType is NetworkInterfaceType.Loopback
                    or NetworkInterfaceType.Tunnel)
                    continue;

                foreach (var ua in nic.GetIPProperties().UnicastAddresses)
                {
                    var ip = ua.Address;
                    if (IPAddress.IsLoopback(ip))
                        continue;
                    if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.IsIPv6LinkLocal)
                        continue;
                    if (ip.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
                        continue;
                    if (!seen.Add(ip.ToString()))
                        continue;
                    list.Add(ip);
                }
            }
        }
        catch
        {
            // ignore enumeration failures
        }

        try
        {
            var entry = Dns.GetHostEntry(Dns.GetHostName());
            foreach (var ip in entry.AddressList)
            {
                if (IPAddress.IsLoopback(ip))
                    continue;
                if (ip.AddressFamily == AddressFamily.InterNetworkV6 && ip.IsIPv6LinkLocal)
                    continue;
                if (ip.AddressFamily is not (AddressFamily.InterNetwork or AddressFamily.InterNetworkV6))
                    continue;
                if (!seen.Add(ip.ToString()))
                    continue;
                list.Add(ip);
            }
        }
        catch
        {
            // ignore
        }

        return list;
    }

    private static X509Certificate2 LoadPfx(string path, string? password)
    {
        // EphemeralKeySet is fine on Windows; on macOS it can break Kestrel HTTPS
        // (cert loads but SSL handshake / server start stalls).
        var flags = X509KeyStorageFlags.Exportable;
        if (OperatingSystem.IsWindows())
            flags |= X509KeyStorageFlags.EphemeralKeySet;
#if NET9_0_OR_GREATER
        return X509CertificateLoader.LoadPkcs12FromFile(path, password, flags);
#else
        return new X509Certificate2(path, password, flags);
#endif
    }

    private static X509Certificate2 EnsurePrivateKeyExportable(X509Certificate2 cert)
    {
        if (cert.HasPrivateKey)
            return cert;
        throw new InvalidOperationException(
            "ANISETTE_TLS_CERT/KEY loaded without a usable private key.");
    }

    private static bool CertificateCoversLocalAddresses(X509Certificate2 cert)
    {
        var local = EnumerateLocalAddresses();
        if (local.Count == 0)
            return true;

        var sanText = BuildSanInventory(cert);
        foreach (var ip in local)
        {
            if (ip.AddressFamily != AddressFamily.InterNetwork)
                continue; // require at least all current IPv4 LAN addresses
            if (!sanText.Contains(ip.ToString(), StringComparison.OrdinalIgnoreCase))
                return false;
        }

        return true;
    }

    private static string BuildSanInventory(X509Certificate2 cert)
    {
        var sb = new StringBuilder();
        sb.Append(cert.Subject).Append(' ').Append(cert.FriendlyName);
        foreach (var ext in cert.Extensions)
        {
            try
            {
                sb.Append(' ').Append(ext.Format(false));
            }
            catch
            {
                // ignore
            }
        }

        if (File.Exists(SanListPath))
        {
            try
            {
                sb.Append(' ').Append(File.ReadAllText(SanListPath));
            }
            catch
            {
                // ignore
            }
        }

        return sb.ToString();
    }

    private static void AddSanDns(SubjectAlternativeNameBuilder san, List<string> names, string dns)
    {
        san.AddDnsName(dns);
        if (!names.Contains(dns, StringComparer.OrdinalIgnoreCase))
            names.Add(dns);
    }

    private static void AddSanIp(SubjectAlternativeNameBuilder san, List<string> names, IPAddress ip)
    {
        san.AddIpAddress(ip);
        var s = ip.ToString();
        if (!names.Contains(s, StringComparer.OrdinalIgnoreCase))
            names.Add(s);
    }

    private static IEnumerable<string> CollectNames(string[] extraNames)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var n in extraNames)
            TryAdd(seen, n);

        var env = Environment.GetEnvironmentVariable("ANISETTE_TLS_DNS");
        if (!string.IsNullOrWhiteSpace(env))
        {
            foreach (var part in env.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                TryAdd(seen, part);
        }

        return seen;
    }

    private static void TryAdd(HashSet<string> seen, string? name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return;
        seen.Add(name.Trim());
    }
}
