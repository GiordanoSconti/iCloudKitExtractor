using System.IO;
using System.Text;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Export Keychain material oltre le password: Wi‑Fi, certificati, keys/identity.
/// </summary>
public static class CkksKeychainMaterialExport
{
    public sealed record WifiRow(
        string View,
        string Name,
        string? Agrp,
        string? Ssid,
        string? Password,
        string? Label,
        string? Desc,
        string? Svce);

    public sealed record CertRow(
        string View,
        string Name,
        string? Class,
        string? Agrp,
        string? Label,
        string? Subject,
        string? Issuer,
        string? Serial,
        string? NotBefore,
        string? NotAfter,
        string? Algorithm,
        int? KeySizeBits,
        string? PemFile);

    public sealed record KeyRow(
        string View,
        string Name,
        string? Class,
        string? Agrp,
        string? Label,
        string? Algorithm,
        int? KeySizeBits,
        string DataKind,
        int DataLen,
        string? PemFile);

    public sealed record ExportCounts(
        int Wifi,
        int Certs,
        int Keys);

    public static async Task<ExportCounts> WriteAsync(
        IReadOnlyList<CkksVaultItem> items,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var certDir = Path.Combine(outputDirectory, "ckks_certs");
        var keyDir = Path.Combine(outputDirectory, "ckks_keys");

        var wifi = new List<WifiRow>();
        var certs = new List<CertRow>();
        var keys = new List<KeyRow>();
        var certIndex = 0;
        var keyIndex = 0;

        foreach (var item in items)
        {
            ct.ThrowIfCancellationRequested();
            var decoded = CkksSecItemPayload.Decode(item);
            var cls = item.Class ?? CkksSecItemPayload.AttrString(item, "class") ?? "";
            var agrp = item.Agrp ?? "";
            var desc = CkksSecItemPayload.AttrString(item, "desc");
            var svce = CkksSecItemPayload.AttrString(item, "svce");

            if (decoded.Kind == CkksSecItemPayload.Kind.Wifi
                || (CkksSecItemPayload.IsWifiItem(item) && !string.IsNullOrEmpty(decoded.Utf8Secret)))
            {
                wifi.Add(new WifiRow(
                    item.View,
                    item.Name,
                    agrp,
                    decoded.WifiSsid
                    ?? item.Acct
                    ?? item.Labl,
                    decoded.WifiPassword ?? decoded.Utf8Secret,
                    item.Labl,
                    desc,
                    svce));
                continue;
            }

            if (decoded.Kind == CkksSecItemPayload.Kind.Certificate
                || cls.Equals("cert", StringComparison.OrdinalIgnoreCase))
            {
                string? pemFile = null;
                if (!string.IsNullOrEmpty(decoded.CertPem))
                {
                    Directory.CreateDirectory(certDir);
                    pemFile = $"cert_{certIndex:D4}.pem";
                    await File.WriteAllTextAsync(
                            Path.Combine(certDir, pemFile), decoded.CertPem, ct)
                        .ConfigureAwait(false);
                    certIndex++;
                }

                certs.Add(new CertRow(
                    item.View,
                    item.Name,
                    cls,
                    agrp,
                    item.Labl,
                    decoded.CertSubject,
                    decoded.CertIssuer,
                    decoded.CertSerial,
                    decoded.CertNotBefore,
                    decoded.CertNotAfter,
                    decoded.KeyAlgorithm,
                    decoded.KeySizeBits,
                    pemFile));
                continue;
            }

            if (decoded.Kind == CkksSecItemPayload.Kind.KeyMaterial
                || cls.Equals("keys", StringComparison.OrdinalIgnoreCase)
                || cls.Equals("idnt", StringComparison.OrdinalIgnoreCase))
            {
                string? pemFile = null;
                if (!string.IsNullOrEmpty(decoded.KeyPem))
                {
                    Directory.CreateDirectory(keyDir);
                    pemFile = $"key_{keyIndex:D4}.pem";
                    await File.WriteAllTextAsync(
                            Path.Combine(keyDir, pemFile), decoded.KeyPem, ct)
                        .ConfigureAwait(false);
                    keyIndex++;
                }
                else if (!string.IsNullOrEmpty(decoded.CertPem))
                {
                    Directory.CreateDirectory(certDir);
                    pemFile = $"idnt_{certIndex:D4}.pem";
                    await File.WriteAllTextAsync(
                            Path.Combine(certDir, pemFile), decoded.CertPem, ct)
                        .ConfigureAwait(false);
                    certIndex++;
                    certs.Add(new CertRow(
                        item.View,
                        item.Name,
                        cls,
                        agrp,
                        item.Labl,
                        decoded.CertSubject,
                        decoded.CertIssuer,
                        decoded.CertSerial,
                        decoded.CertNotBefore,
                        decoded.CertNotAfter,
                        decoded.KeyAlgorithm,
                        decoded.KeySizeBits,
                        pemFile));
                    continue;
                }

                keys.Add(new KeyRow(
                    item.View,
                    item.Name,
                    cls,
                    agrp,
                    item.Labl,
                    decoded.KeyAlgorithm,
                    decoded.KeySizeBits,
                    decoded.DataKind,
                    decoded.DataLen,
                    pemFile));
            }
        }

        await WriteWifiCsvAsync(Path.Combine(outputDirectory, "ckks_wifi.csv"), wifi, ct)
            .ConfigureAwait(false);
        await WriteCertCsvAsync(Path.Combine(outputDirectory, "ckks_certs.csv"), certs, ct)
            .ConfigureAwait(false);
        await WriteKeyCsvAsync(Path.Combine(outputDirectory, "ckks_keys.csv"), keys, ct)
            .ConfigureAwait(false);

        var jsonOpts = new JsonSerializerOptions { WriteIndented = true };
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "ckks_wifi.json"),
            JsonSerializer.Serialize(wifi, jsonOpts), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "ckks_certs.json"),
            JsonSerializer.Serialize(certs, jsonOpts), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "ckks_keys.json"),
            JsonSerializer.Serialize(keys, jsonOpts), ct).ConfigureAwait(false);

        log?.Report(
            $"  Keychain material: wifi={wifi.Count} certs={certs.Count} keys={keys.Count} " +
            "→ ckks_wifi.csv / ckks_certs.csv / ckks_keys.csv");

        return new ExportCounts(wifi.Count, certs.Count, keys.Count);
    }

    private static async Task WriteWifiCsvAsync(
        string path, IReadOnlyList<WifiRow> rows, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine("view,agrp,ssid,password,labl,desc,svce,name");
        foreach (var r in rows)
        {
            sb.Append(Csv(r.View)).Append(',')
                .Append(Csv(r.Agrp)).Append(',')
                .Append(Csv(r.Ssid)).Append(',')
                .Append(Csv(r.Password)).Append(',')
                .Append(Csv(r.Label)).Append(',')
                .Append(Csv(r.Desc)).Append(',')
                .Append(Csv(r.Svce)).Append(',')
                .Append(Csv(r.Name))
                .AppendLine();
        }

        await File.WriteAllTextAsync(path, sb.ToString(), ct).ConfigureAwait(false);
    }

    private static async Task WriteCertCsvAsync(
        string path, IReadOnlyList<CertRow> rows, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine(
            "view,class,agrp,labl,subject,issuer,serial,notBefore,notAfter,algorithm,keySizeBits,pemFile,name");
        foreach (var r in rows)
        {
            sb.Append(Csv(r.View)).Append(',')
                .Append(Csv(r.Class)).Append(',')
                .Append(Csv(r.Agrp)).Append(',')
                .Append(Csv(r.Label)).Append(',')
                .Append(Csv(r.Subject)).Append(',')
                .Append(Csv(r.Issuer)).Append(',')
                .Append(Csv(r.Serial)).Append(',')
                .Append(Csv(r.NotBefore)).Append(',')
                .Append(Csv(r.NotAfter)).Append(',')
                .Append(Csv(r.Algorithm)).Append(',')
                .Append(r.KeySizeBits?.ToString() ?? "").Append(',')
                .Append(Csv(r.PemFile)).Append(',')
                .Append(Csv(r.Name))
                .AppendLine();
        }

        await File.WriteAllTextAsync(path, sb.ToString(), ct).ConfigureAwait(false);
    }

    private static async Task WriteKeyCsvAsync(
        string path, IReadOnlyList<KeyRow> rows, CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine("view,class,agrp,labl,algorithm,keySizeBits,dataKind,dataLen,pemFile,name");
        foreach (var r in rows)
        {
            sb.Append(Csv(r.View)).Append(',')
                .Append(Csv(r.Class)).Append(',')
                .Append(Csv(r.Agrp)).Append(',')
                .Append(Csv(r.Label)).Append(',')
                .Append(Csv(r.Algorithm)).Append(',')
                .Append(r.KeySizeBits?.ToString() ?? "").Append(',')
                .Append(Csv(r.DataKind)).Append(',')
                .Append(r.DataLen).Append(',')
                .Append(Csv(r.PemFile)).Append(',')
                .Append(Csv(r.Name))
                .AppendLine();
        }

        await File.WriteAllTextAsync(path, sb.ToString(), ct).ConfigureAwait(false);
    }

    private static string Csv(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        if (value.Contains('"') || value.Contains(',') || value.Contains('\n')
            || value.Contains('\r'))
            return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
        return value;
    }
}
