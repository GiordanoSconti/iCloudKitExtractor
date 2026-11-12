using System.IO;
using System.Text;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Catalogo forense di tutti gli item CKKS: classificazione agrp, passkey,
/// subsystem (HomeKit/rapport/sos/…), e decode v_Data (bplist JSON / ASN.1 sniff / hex).
/// </summary>
public static class CkksKeychainCatalogExport
{
    public sealed record CatalogCounts(
        int Total,
        int Passkeys,
        int Subsystem,
        int BplistDecoded,
        int Asn1Sniffed,
        int WithSummary);

    public static async Task<CatalogCounts> WriteAsync(
        IReadOnlyList<CkksVaultItem> items,
        string outputDirectory,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        Directory.CreateDirectory(outputDirectory);
        var vdataDir = Path.Combine(outputDirectory, "ckks_vdata");
        Directory.CreateDirectory(vdataDir);

        var catalogCsv = new StringBuilder();
        catalogCsv.AppendLine(
            "view,class,agrp,category,kind,dataKind,dataLen,srvr,acct,labl,svce,desc,hasSummary,hexPreview,name");

        var passkeyCsv = new StringBuilder();
        passkeyCsv.AppendLine(
            "view,agrp,labl,srvr,acct,dataLen,keyBits,hexPreview,summaryFile,name");

        var subsystemCsv = new StringBuilder();
        subsystemCsv.AppendLine(
            "view,class,agrp,category,kind,dataKind,dataLen,labl,acct,svce,summaryFile,hexPreview,name");

        var catalogJson = new List<object>();
        var passkeyN = 0;
        var subsystemN = 0;
        var bplistN = 0;
        var asn1N = 0;
        var summaryN = 0;
        var fileIndex = 0;

        foreach (var item in items)
        {
            ct.ThrowIfCancellationRequested();
            var decoded = CkksSecItemPayload.Decode(item);
            var cls = item.Class ?? CkksSecItemPayload.AttrString(item, "class") ?? "";
            var agrp = item.Agrp ?? "";
            var category = decoded.Category
                           ?? CkksSecItemPayload.ClassifyAgrp(agrp, cls, item);
            var svce = CkksSecItemPayload.AttrString(item, "svce");
            var desc = CkksSecItemPayload.AttrString(item, "desc");

            string? summaryFile = null;
            if (!string.IsNullOrEmpty(decoded.SummaryJson))
            {
                summaryN++;
                if (decoded.DataKind.StartsWith("bplist", StringComparison.OrdinalIgnoreCase)
                    || decoded.Kind == CkksSecItemPayload.Kind.BinaryPlist)
                    bplistN++;
                if (decoded.DataKind.Equals("asn1", StringComparison.OrdinalIgnoreCase)
                    || decoded.Kind == CkksSecItemPayload.Kind.Asn1)
                    asn1N++;

                summaryFile = $"vdata_{fileIndex:D5}_{Sanitize(category)}.json";
                await File.WriteAllTextAsync(
                        Path.Combine(vdataDir, summaryFile), decoded.SummaryJson, ct)
                    .ConfigureAwait(false);

                // Also keep raw bytes for binary / passkey / asn1 lab follow-up.
                if (item.Data is { Length: > 0 and <= 65536 }
                    && decoded.Kind is CkksSecItemPayload.Kind.Passkey
                        or CkksSecItemPayload.Kind.HomeKitPairing
                        or CkksSecItemPayload.Kind.Rapport
                        or CkksSecItemPayload.Kind.Sos
                        or CkksSecItemPayload.Kind.AppToken
                        or CkksSecItemPayload.Kind.Subsystem
                        or CkksSecItemPayload.Kind.Asn1
                        or CkksSecItemPayload.Kind.Binary)
                {
                    var binName = Path.ChangeExtension(summaryFile, ".bin");
                    await File.WriteAllBytesAsync(
                            Path.Combine(vdataDir, binName), item.Data, ct)
                        .ConfigureAwait(false);
                }

                fileIndex++;
            }
            else if (item.Data is { Length: > 0 }
                     && decoded.Kind is CkksSecItemPayload.Kind.BinaryPlist
                         or CkksSecItemPayload.Kind.Asn1
                         or CkksSecItemPayload.Kind.Binary
                         or CkksSecItemPayload.Kind.Passkey
                         or CkksSecItemPayload.Kind.HomeKitPairing
                         or CkksSecItemPayload.Kind.Rapport
                         or CkksSecItemPayload.Kind.Sos
                         or CkksSecItemPayload.Kind.AppToken
                         or CkksSecItemPayload.Kind.Subsystem)
            {
                // No JSON summary — still dump raw for lab.
                summaryFile = $"vdata_{fileIndex:D5}_{Sanitize(category)}.bin";
                await File.WriteAllBytesAsync(
                        Path.Combine(vdataDir, summaryFile), item.Data, ct)
                    .ConfigureAwait(false);
                fileIndex++;
            }

            catalogCsv.Append(Csv(item.View)).Append(',')
                .Append(Csv(cls)).Append(',')
                .Append(Csv(agrp)).Append(',')
                .Append(Csv(category)).Append(',')
                .Append(Csv(decoded.Kind.ToString())).Append(',')
                .Append(Csv(decoded.DataKind)).Append(',')
                .Append(decoded.DataLen).Append(',')
                .Append(Csv(item.Srvr)).Append(',')
                .Append(Csv(item.Acct)).Append(',')
                .Append(Csv(item.Labl)).Append(',')
                .Append(Csv(svce)).Append(',')
                .Append(Csv(desc)).Append(',')
                .Append(string.IsNullOrEmpty(decoded.SummaryJson) ? "0" : "1").Append(',')
                .Append(Csv(decoded.HexPreview)).Append(',')
                .Append(Csv(item.Name))
                .AppendLine();

            catalogJson.Add(new
            {
                item.View,
                Class = cls,
                Agrp = agrp,
                category,
                kind = decoded.Kind.ToString(),
                decoded.DataKind,
                decoded.DataLen,
                item.Srvr,
                item.Acct,
                item.Labl,
                svce,
                desc,
                summaryFile,
                decoded.HexPreview,
                item.Name
            });

            if (decoded.Kind == CkksSecItemPayload.Kind.Passkey || category == "passkey")
            {
                passkeyN++;
                passkeyCsv.Append(Csv(item.View)).Append(',')
                    .Append(Csv(agrp)).Append(',')
                    .Append(Csv(item.Labl)).Append(',')
                    .Append(Csv(item.Srvr)).Append(',')
                    .Append(Csv(item.Acct)).Append(',')
                    .Append(decoded.DataLen).Append(',')
                    .Append(decoded.KeySizeBits?.ToString() ?? "").Append(',')
                    .Append(Csv(decoded.HexPreview)).Append(',')
                    .Append(Csv(summaryFile)).Append(',')
                    .Append(Csv(item.Name))
                    .AppendLine();
            }

            if (decoded.Kind is CkksSecItemPayload.Kind.HomeKitPairing
                    or CkksSecItemPayload.Kind.Rapport
                    or CkksSecItemPayload.Kind.Sos
                    or CkksSecItemPayload.Kind.AppToken
                    or CkksSecItemPayload.Kind.Subsystem
                || category is "homekit" or "rapport" or "sos" or "app-token" or "subsystem")
            {
                subsystemN++;
                subsystemCsv.Append(Csv(item.View)).Append(',')
                    .Append(Csv(cls)).Append(',')
                    .Append(Csv(agrp)).Append(',')
                    .Append(Csv(category)).Append(',')
                    .Append(Csv(decoded.Kind.ToString())).Append(',')
                    .Append(Csv(decoded.DataKind)).Append(',')
                    .Append(decoded.DataLen).Append(',')
                    .Append(Csv(item.Labl)).Append(',')
                    .Append(Csv(item.Acct)).Append(',')
                    .Append(Csv(svce)).Append(',')
                    .Append(Csv(summaryFile)).Append(',')
                    .Append(Csv(decoded.HexPreview)).Append(',')
                    .Append(Csv(item.Name))
                    .AppendLine();
            }
        }

        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "ckks_catalog.csv"), catalogCsv.ToString(), ct)
            .ConfigureAwait(false);
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "ckks_passkeys.csv"), passkeyCsv.ToString(), ct)
            .ConfigureAwait(false);
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "ckks_subsystem.csv"), subsystemCsv.ToString(), ct)
            .ConfigureAwait(false);

        var jsonOpts = new JsonSerializerOptions { WriteIndented = true };
        await File.WriteAllTextAsync(
            Path.Combine(outputDirectory, "ckks_catalog.json"),
            JsonSerializer.Serialize(catalogJson, jsonOpts), ct).ConfigureAwait(false);

        log?.Report(
            $"  Keychain catalog: total={items.Count} passkeys={passkeyN} subsystem={subsystemN} " +
            $"bplistJson={bplistN} asn1={asn1N} summaries={summaryN} → " +
            "ckks_catalog.csv / ckks_passkeys.csv / ckks_subsystem.csv / ckks_vdata/");

        return new CatalogCounts(items.Count, passkeyN, subsystemN, bplistN, asn1N, summaryN);
    }

    private static string Sanitize(string category)
    {
        var s = string.IsNullOrWhiteSpace(category) ? "unknown" : category;
        foreach (var c in Path.GetInvalidFileNameChars())
            s = s.Replace(c, '_');
        return s.Length > 32 ? s[..32] : s;
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
