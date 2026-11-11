using System.IO;
using System.Text;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Esporta item CKKS view <c>Passwords</c> (e affini) in CSV/JSON leggibile:
/// <c>srvr</c> / <c>acct</c> / <c>v_Data</c> (password), più note/TOTP da sidecar.
/// </summary>
public static class CkksPasswordExport
{
    public sealed record PasswordRow(
        string View,
        string Name,
        string? Class,
        string? Agrp,
        string? Srvr,
        string? Acct,
        string? Labl,
        string? Password,
        string? Notes,
        string? OtpAuth,
        string DataKind,
        int DataLen);

    public sealed record NoteOtpRow(
        string View,
        string Name,
        string? Agrp,
        string? Srvr,
        string? Acct,
        string? Title,
        string? Notes,
        string? OtpAuth,
        string? TotpIssuer,
        string? TotpAccount);

    public static async Task<int> WriteAsync(
        IReadOnlyList<CkksVaultItem> items,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var rows = new List<PasswordRow>();
        var noteRows = new List<NoteOtpRow>();
        var cardRows = new List<PasswordRow>();

        foreach (var item in items)
        {
            var decoded = CkksSecItemPayload.Decode(item);

            if (decoded.Kind == CkksSecItemPayload.Kind.PasswordManagerSidecar
                || !string.IsNullOrEmpty(decoded.Notes)
                || !string.IsNullOrEmpty(decoded.OtpAuth))
            {
                if (CkksSecItemPayload.IsPasswordManagerAgrp(item.Agrp ?? "")
                    || decoded.Kind == CkksSecItemPayload.Kind.PasswordManagerSidecar
                    || !string.IsNullOrEmpty(decoded.OtpAuth))
                {
                    noteRows.Add(new NoteOtpRow(
                        item.View,
                        item.Name,
                        item.Agrp,
                        item.Srvr,
                        item.Acct,
                        decoded.Title ?? item.Labl,
                        decoded.Notes,
                        decoded.OtpAuth,
                        decoded.TotpIssuer,
                        decoded.TotpAccount));
                }
            }

            if (decoded.Kind == CkksSecItemPayload.Kind.CreditCard)
            {
                cardRows.Add(new PasswordRow(
                    item.View,
                    item.Name,
                    item.Class,
                    item.Agrp,
                    item.Srvr,
                    item.Acct,
                    decoded.Title ?? item.Labl,
                    FormatCardSecret(decoded),
                    decoded.Notes,
                    null,
                    decoded.DataKind,
                    decoded.DataLen));
                continue;
            }

            if (!IsPasswordLike(item))
                continue;

            // Wi‑Fi / cert / keys handled by material export.
            if (decoded.Kind is CkksSecItemPayload.Kind.Wifi
                or CkksSecItemPayload.Kind.Certificate
                or CkksSecItemPayload.Kind.KeyMaterial)
                continue;
            if (CkksSecItemPayload.IsPasswordManagerAgrp(item.Agrp ?? "")
                && decoded.Kind == CkksSecItemPayload.Kind.PasswordManagerSidecar
                && string.IsNullOrEmpty(decoded.Utf8Secret))
                continue;

            rows.Add(ToRow(item, decoded));
        }

        // Merge sidecar notes/OTP onto login rows by (srvr, acct).
        MergeSidecars(rows, noteRows);

        var csvPath = Path.Combine(outputDirectory, "ckks_passwords.csv");
        var jsonPath = Path.Combine(outputDirectory, "ckks_passwords.json");
        var sb = new StringBuilder();
        sb.AppendLine("view,class,agrp,srvr,acct,labl,password,notes,otpauth,dataKind,dataLen,name");
        foreach (var r in rows)
        {
            sb.Append(Csv(r.View)).Append(',')
                .Append(Csv(r.Class)).Append(',')
                .Append(Csv(r.Agrp)).Append(',')
                .Append(Csv(r.Srvr)).Append(',')
                .Append(Csv(r.Acct)).Append(',')
                .Append(Csv(r.Labl)).Append(',')
                .Append(Csv(r.Password)).Append(',')
                .Append(Csv(r.Notes)).Append(',')
                .Append(Csv(r.OtpAuth)).Append(',')
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

        await WriteNotesOtpAsync(outputDirectory, noteRows, ct).ConfigureAwait(false);
        if (cardRows.Count > 0)
            await WriteCardsAsync(outputDirectory, cardRows, ct).ConfigureAwait(false);

        var withSecret = rows.Count(r => !string.IsNullOrEmpty(r.Password));
        var withOtp = rows.Count(r => !string.IsNullOrEmpty(r.OtpAuth))
                      + noteRows.Count(r => !string.IsNullOrEmpty(r.OtpAuth));
        var withNotes = rows.Count(r => !string.IsNullOrEmpty(r.Notes))
                        + noteRows.Count(r => !string.IsNullOrEmpty(r.Notes));
        log?.Report(
            $"  Passwords export: {rows.Count} item (password UTF-8={withSecret}, " +
            $"notes={withNotes}, otp={withOtp}, cards={cardRows.Count}) → " +
            Path.GetFileName(csvPath));
        if (rows.Count == 0)
        {
            log?.Report(
                "  No Passwords items — OpenVault now calls fetchRecoverableTLKShares; " +
                "check log «recoverable TLK» / view Passwords.");
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
            || agrp.Contains("Safari", StringComparison.OrdinalIgnoreCase)
            || CkksSecItemPayload.IsPasswordManagerAgrp(agrp)
            || CkksSecItemPayload.IsCreditCardAgrp(agrp))
            return true;

        // inet/genp con v_Data UTF-8 corto = tipico password item
        var cls = item.Class ?? "";
        if ((cls.Equals("inet", StringComparison.OrdinalIgnoreCase)
             || cls.Equals("genp", StringComparison.OrdinalIgnoreCase))
            && CkksSecItemPayload.TryUtf8Secret(item.Data, out _)
            && !IsPcsAgrp(agrp)
            && !CkksSecItemPayload.IsWifiItem(item))
            return true;

        return false;
    }

    private static bool IsPcsAgrp(string agrp) =>
        agrp.Contains("ProtectedCloudStorage", StringComparison.OrdinalIgnoreCase);

    private static PasswordRow ToRow(CkksVaultItem item, CkksSecItemPayload.Decoded decoded)
    {
        var password = decoded.Utf8Secret;
        var kind = decoded.DataKind;
        var len = decoded.DataLen;

        if (password is null && item.Data is { Length: > 0 })
        {
            kind = decoded.Kind switch
            {
                CkksSecItemPayload.Kind.BinaryPlist => "bplist",
                CkksSecItemPayload.Kind.Asn1 => "asn1",
                CkksSecItemPayload.Kind.Binary => "binary",
                CkksSecItemPayload.Kind.Empty => "empty",
                _ => kind
            };
            len = item.Data.Length;
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
            decoded.Notes,
            decoded.OtpAuth,
            kind,
            len);
    }

    private static void MergeSidecars(List<PasswordRow> rows, List<NoteOtpRow> sidecars)
    {
        if (rows.Count == 0 || sidecars.Count == 0)
            return;

        for (var i = 0; i < rows.Count; i++)
        {
            var r = rows[i];
            var match = sidecars.FirstOrDefault(s =>
                string.Equals(s.Srvr ?? "", r.Srvr ?? "", StringComparison.OrdinalIgnoreCase)
                && string.Equals(s.Acct ?? "", r.Acct ?? "", StringComparison.OrdinalIgnoreCase)
                && (!string.IsNullOrEmpty(s.Srvr) || !string.IsNullOrEmpty(s.Acct)));
            if (match is null)
                continue;

            rows[i] = r with
            {
                Notes = FirstNonEmpty(r.Notes, match.Notes),
                OtpAuth = FirstNonEmpty(r.OtpAuth, match.OtpAuth),
                Labl = FirstNonEmpty(r.Labl, match.Title)
            };
        }
    }

    private static async Task WriteNotesOtpAsync(
        string outputDirectory, List<NoteOtpRow> rows, CancellationToken ct)
    {
        var csvPath = Path.Combine(outputDirectory, "ckks_notes_otp.csv");
        var jsonPath = Path.Combine(outputDirectory, "ckks_notes_otp.json");
        var sb = new StringBuilder();
        sb.AppendLine("view,agrp,srvr,acct,title,notes,otpauth,totpIssuer,totpAccount,name");
        foreach (var r in rows)
        {
            sb.Append(Csv(r.View)).Append(',')
                .Append(Csv(r.Agrp)).Append(',')
                .Append(Csv(r.Srvr)).Append(',')
                .Append(Csv(r.Acct)).Append(',')
                .Append(Csv(r.Title)).Append(',')
                .Append(Csv(r.Notes)).Append(',')
                .Append(Csv(r.OtpAuth)).Append(',')
                .Append(Csv(r.TotpIssuer)).Append(',')
                .Append(Csv(r.TotpAccount)).Append(',')
                .Append(Csv(r.Name))
                .AppendLine();
        }

        await File.WriteAllTextAsync(csvPath, sb.ToString(), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(
            jsonPath,
            JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true }),
            ct).ConfigureAwait(false);
    }

    private static async Task WriteCardsAsync(
        string outputDirectory, List<PasswordRow> cards, CancellationToken ct)
    {
        var csvPath = Path.Combine(outputDirectory, "ckks_credit_cards.csv");
        var sb = new StringBuilder();
        sb.AppendLine("view,class,agrp,srvr,acct,labl,card,notes,dataKind,dataLen,name");
        foreach (var r in cards)
        {
            sb.Append(Csv(r.View)).Append(',')
                .Append(Csv(r.Class)).Append(',')
                .Append(Csv(r.Agrp)).Append(',')
                .Append(Csv(r.Srvr)).Append(',')
                .Append(Csv(r.Acct)).Append(',')
                .Append(Csv(r.Labl)).Append(',')
                .Append(Csv(r.Password)).Append(',')
                .Append(Csv(r.Notes)).Append(',')
                .Append(Csv(r.DataKind)).Append(',')
                .Append(r.DataLen).Append(',')
                .Append(Csv(r.Name))
                .AppendLine();
        }

        await File.WriteAllTextAsync(csvPath, sb.ToString(), ct).ConfigureAwait(false);
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "ckks_credit_cards.json"),
            JsonSerializer.Serialize(cards, new JsonSerializerOptions { WriteIndented = true }),
            ct).ConfigureAwait(false);
    }

    private static string FormatCardSecret(CkksSecItemPayload.Decoded d)
    {
        var parts = new List<string>();
        if (!string.IsNullOrEmpty(d.CardNumber))
            parts.Add("pan=" + d.CardNumber);
        if (!string.IsNullOrEmpty(d.CardName))
            parts.Add("name=" + d.CardName);
        if (!string.IsNullOrEmpty(d.CardExpiry))
            parts.Add("exp=" + d.CardExpiry);
        if (!string.IsNullOrEmpty(d.CardCvv))
            parts.Add("cvv=" + d.CardCvv);
        return string.Join("; ", parts);
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values)
        {
            if (!string.IsNullOrWhiteSpace(v))
                return v;
        }

        return null;
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
