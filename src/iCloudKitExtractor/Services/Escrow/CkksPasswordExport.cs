using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Esporta item CKKS view <c>Passwords</c> (e affini) in CSV/JSON leggibile:
/// <c>srvr</c> / <c>acct</c> / <c>v_Data</c> (password).
/// </summary>
public static class CkksPasswordExport
{
    private static readonly Regex NonPrintable = new(
        @"[\x00-\x08\x0B\x0C\x0E-\x1F]",
        RegexOptions.Compiled);

    public sealed record PasswordRow(
        string View,
        string Name,
        string? Class,
        string? Agrp,
        string? Srvr,
        string? Acct,
        string? Labl,
        string? Password,
        string DataKind,
        int DataLen);

    public static async Task<int> WriteAsync(
        IReadOnlyList<CkksVaultItem> items,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var rows = new List<PasswordRow>();
        foreach (var item in items)
        {
            if (!IsPasswordLike(item))
                continue;
            rows.Add(ToRow(item));
        }

        var csvPath = Path.Combine(outputDirectory, "ckks_passwords.csv");
        var jsonPath = Path.Combine(outputDirectory, "ckks_passwords.json");
        var sb = new StringBuilder();
        sb.AppendLine("view,class,agrp,srvr,acct,labl,password,dataKind,dataLen,name");
        foreach (var r in rows)
        {
            sb.Append(Csv(r.View)).Append(',')
                .Append(Csv(r.Class)).Append(',')
                .Append(Csv(r.Agrp)).Append(',')
                .Append(Csv(r.Srvr)).Append(',')
                .Append(Csv(r.Acct)).Append(',')
                .Append(Csv(r.Labl)).Append(',')
                .Append(Csv(r.Password)).Append(',')
                .Append(Csv(r.DataKind)).Append(',')
                .Append(r.DataLen).Append(',')
                .Append(Csv(r.Name))
                .AppendLine();
        }

        await File.WriteAllTextAsync(csvPath, sb.ToString(), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(
            jsonPath,
            JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true }),
            ct).ConfigureAwait(false);

        var withSecret = rows.Count(r => !string.IsNullOrEmpty(r.Password));
        log?.Report(
            $"  Passwords export: {rows.Count} item (password UTF-8={withSecret}) → " +
            Path.GetFileName(csvPath));
        if (rows.Count == 0)
        {
            log?.Report(
                "  Nessun item Passwords — OpenVault ora chiama fetchRecoverableTLKShares; " +
                "verifica log «recoverable TLK» / view Passwords.");
        }

        return rows.Count;
    }

    /// <summary>Riesporta da <c>ckks_items.json</c> già su disco (senza rete).</summary>
    public static async Task<int> WriteFromItemsJsonAsync(
        string ckksItemsJsonPath,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (!File.Exists(ckksItemsJsonPath))
            return 0;

        await using var stream = File.OpenRead(ckksItemsJsonPath);
        using var doc = await JsonDocument.ParseAsync(stream, cancellationToken: ct)
            .ConfigureAwait(false);
        if (doc.RootElement.ValueKind != JsonValueKind.Array)
            return 0;

        var synthetic = new List<CkksVaultItem>();
        foreach (var el in doc.RootElement.EnumerateArray())
        {
            byte[]? data = null;
            if (el.TryGetProperty("dataB64", out var b64)
                && b64.ValueKind == JsonValueKind.String
                && !string.IsNullOrEmpty(b64.GetString()))
            {
                try { data = Convert.FromBase64String(b64.GetString()!); }
                catch { /* ignore */ }
            }

            synthetic.Add(new CkksVaultItem(
                el.TryGetProperty("View", out var v) ? v.GetString() ?? "" : "",
                el.TryGetProperty("Name", out var n) ? n.GetString() ?? "" : "",
                Etag: null,
                Class: el.TryGetProperty("Class", out var c) ? c.GetString() : null,
                Agrp: el.TryGetProperty("Agrp", out var a) ? a.GetString() : null,
                Srvr: el.TryGetProperty("Srvr", out var s) ? s.GetString() : null,
                Acct: el.TryGetProperty("Acct", out var ac) ? ac.GetString() : null,
                Labl: el.TryGetProperty("Labl", out var l) ? l.GetString() : null,
                Data: data,
                Attrs: new Dictionary<string, object?>()));
        }

        return await WriteAsync(synthetic, outputDirectory, log, ct).ConfigureAwait(false);
    }

    public static bool IsPasswordLike(CkksVaultItem item)
    {
        var view = item.View ?? "";
        if (view.Equals("Passwords", StringComparison.OrdinalIgnoreCase)
            || view.Equals("Password", StringComparison.OrdinalIgnoreCase)
            || view.Equals("CreditCards", StringComparison.OrdinalIgnoreCase)
            || view.Equals("AutoFillPasskey", StringComparison.OrdinalIgnoreCase))
            return true;

        var agrp = item.Agrp ?? "";
        if (agrp.Contains("cfnetwork", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("password", StringComparison.OrdinalIgnoreCase)
            || agrp.Equals("com.apple.security.sos", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("Safari", StringComparison.OrdinalIgnoreCase))
            return true;

        // inet/genp con v_Data UTF-8 corto = tipico password item
        var cls = item.Class ?? "";
        if ((cls.Equals("inet", StringComparison.OrdinalIgnoreCase)
             || cls.Equals("genp", StringComparison.OrdinalIgnoreCase))
            && TryUtf8Password(item.Data, out _)
            && !IsPcsAgrp(agrp))
            return true;

        return false;
    }

    private static bool IsPcsAgrp(string agrp) =>
        agrp.Contains("ProtectedCloudStorage", StringComparison.OrdinalIgnoreCase);

    private static PasswordRow ToRow(CkksVaultItem item)
    {
        var kind = "empty";
        string? password = null;
        var len = item.Data?.Length ?? 0;
        if (item.Data is { Length: > 0 } data)
        {
            if (TryUtf8Password(data, out var utf8))
            {
                kind = "utf8";
                password = utf8;
            }
            else if (data.Length >= 8 && data.AsSpan(0, 8).SequenceEqual("bplist00"u8))
            {
                kind = "bplist";
            }
            else if (data[0] == 0x30)
            {
                kind = "asn1";
            }
            else
            {
                kind = "binary";
            }
        }

        return new PasswordRow(
            item.View,
            item.Name,
            item.Class,
            item.Agrp,
            item.Srvr,
            item.Acct,
            item.Labl,
            password,
            kind,
            len);
    }

    private static bool TryUtf8Password(byte[]? data, out string text)
    {
        text = "";
        if (data is not { Length: > 0 and < 4096 })
            return false;
        try
        {
            text = Encoding.UTF8.GetString(data);
        }
        catch
        {
            return false;
        }

        if (string.IsNullOrEmpty(text))
            return false;
        if (NonPrintable.IsMatch(text))
            return false;
        // Evita di etichettare DER/XML come password.
        if (text.StartsWith("<?xml", StringComparison.Ordinal)
            || text.StartsWith("<plist", StringComparison.Ordinal))
            return false;
        return true;
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
