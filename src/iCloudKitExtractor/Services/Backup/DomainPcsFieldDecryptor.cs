using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Services.Backup;

/// <summary>
/// DecryptFields PCS sui record Domain (EN/N:): campi type=20
/// (<c>domain</c>, <c>fileList</c>, <c>newAssets</c>, …) prima del parse inventario.
/// </summary>
public static class DomainPcsFieldDecryptor
{
    public static readonly string[] PreferredFields =
    [
        "domain",
        "fileList",
        "newAssets",
        "deletedAssets",
        "encryptedAttributes",
        "EncryptedAttributes",
        "domainName",
    ];

    public sealed record DecryptSummary(
        int DomainsIn,
        int DomainsOut,
        int FieldsSeen,
        int FieldsDecrypted,
        int FileListsFilled,
        int NewAssetsFilled,
        int ZoneKeys,
        string Message);

    /// <summary>
    /// Parse Domain dal wire + arricchimento da campi PCS decryptati.
    /// </summary>
    public static (IReadOnlyList<DomainFileListParser.DomainRecord> Domains, DecryptSummary Summary)
        ParseDomainsDecrypted(
            ICloudSession session,
            byte[]? zonesPayload,
            IReadOnlyList<byte[]> payloads,
            string? outputDirectory = null,
            IProgress<string>? log = null)
    {
        var wireDomains = DomainFileListParser.ParseDomains(payloads.ToArray());
        if (!PcsSessionSeedKeys.HasAny(session))
        {
            return (wireDomains, new DecryptSummary(
                wireDomains.Count, wireDomains.Count, 0, 0, 0, 0, 0,
                "PCS KeySet assente — solo parse wire"));
        }

        var manateeFast = PcsSessionSeedKeys.IsManateePrimary(session);
        // Escrow = ParseKeySet (HEAD). Manatee = Collect. Light solo Escrow (manateeFast→no-light BP-style).
        var seedKeys = PcsSessionSeedKeys.HasEscrowKeySet(session)
            ? PcsDer.ParseKeySetPrivateKeys(session.PcsEscrowedKeySet!)
            : PcsSessionSeedKeys.Collect(session, log);
        if (seedKeys.Count == 0)
        {
            return (wireDomains, new DecryptSummary(
                wireDomains.Count, wireDomains.Count, 0, 0, 0, 0, 0,
                "KeySet senza chiavi private"));
        }

        var poolKeys = new List<PcsCompactPrivateKey>(seedKeys);
        var zones = new List<ProtectionZoneKeys>();
        if (zonesPayload is { Length: > 32 })
        {
            var fromZones = PcsProtectionZone.TryUnwrapAll(
                zonesPayload, seedKeys, includeLight: !manateeFast);
            if (fromZones.Count > 0)
            {
                zones.AddRange(fromZones);
                poolKeys = PcsProtectionZone.MergeKeys(seedKeys, fromZones);
                if (manateeFast)
                    PcsSessionSeedKeys.RememberFromZones(session, fromZones, seedKeys);
            }
        }

        foreach (var payload in payloads)
        {
            if (payload is not { Length: > 64 })
                continue;
            var fromRecords = PcsProtectionZone.TryUnwrapAll(
                payload, poolKeys, includeLight: !manateeFast);
            if (fromRecords.Count == 0)
                continue;
            zones.AddRange(fromRecords);
            poolKeys = PcsProtectionZone.MergeKeys(poolKeys, fromRecords);
        }

        // Domain PI spesso 96–512 B (sotto filtro CloudDocs 200–900).
        foreach (var d in wireDomains)
        {
            if (d.RecordWindow is not { Length: > 32 })
                continue;
            foreach (var der in PcsProtectionZone.TryExtractProtectionInfoCandidates(d.RecordWindow))
            {
                if (der.Length is < 64 or > 1200)
                    continue;
                var z = PcsProtectionZone.TryUnwrap(der, poolKeys);
                if (z is null)
                    continue;
                zones.Add(z);
                poolKeys = PcsProtectionZone.MergeKeys(poolKeys, [z]);
            }
        }

        string? plainRoot = null;
        if (!string.IsNullOrWhiteSpace(outputDirectory))
        {
            plainRoot = Path.Combine(outputDirectory, "en_pcs_plaintext");
            Directory.CreateDirectory(plainRoot);
        }

        var fieldsSeen = 0;
        var fieldsOk = 0;
        var fileListsFilled = 0;
        var newAssetsFilled = 0;
        var enriched = new List<DomainFileListParser.DomainRecord>(wireDomains.Count);

        foreach (var domain in wireDomains)
        {
            var window = domain.RecordWindow;
            if (window is not { Length: > 32 })
            {
                enriched.Add(domain);
                continue;
            }

            // Zone locali dal PI del record (prioritarie sul decrypt del Domain).
            var localZones = new List<ProtectionZoneKeys>(zones);
            foreach (var der in PcsProtectionZone.TryExtractProtectionInfoCandidates(window))
            {
                if (der.Length is < 64 or > 1200)
                    continue;
                var z = PcsProtectionZone.TryUnwrap(der, poolKeys);
                if (z is not null)
                    localZones.Insert(0, z);
            }

            var fileList = domain.FileList;
            var newAssets = domain.NewAssetRecordNames.ToList();
            var deletedAssets = domain.DeletedAssetRecordNames.ToList();
            var domainName = domain.DomainName;
            var encoding = domain.FileListEncoding ?? DomainFileListParser.FileListEncodingSqlite;

            // 1) Campo domain (EncryptedDomain): spesso 57 B DataA senza PI record
            //    (non contiene fileList/newAssets — inventario già in chiaro sul wire).
            if (domain.EncryptedDomain is { Length: > 80 } encDom)
            {
                fieldsSeen++;
                var ct = BackupKeybagPcsUnlock.ExtractEncryptedBytesValue(encDom);
                var plain = TryDecrypt(ct, "domain", localZones, seedKeys)
                            ?? TryDecrypt(encDom, "domain", localZones, seedKeys);
                if (plain is { Length: > 0 })
                {
                    fieldsOk++;
                    SavePlain(plainRoot, domain, "domain", plain);
                    ApplyDomainPlain(
                        plain, domain.RecordName, ref domainName, ref encoding,
                        ref fileList, newAssets, deletedAssets, ref fileListsFilled, ref newAssetsFilled);
                }
            }

            // 2) Altri type=20 nella finestra record.
            var scanned = CloudKitEncryptedFieldScanner.Scan(window, PreferredFields);
            fieldsSeen += scanned.Count;
            var idx = 0;
            foreach (var field in scanned)
            {
                idx++;
                var plain = TryDecrypt(field.Ciphertext, field.FieldName, localZones, seedKeys);
                if (plain is not { Length: > 0 })
                    continue;
                fieldsOk++;
                SavePlain(plainRoot, domain, $"{Sanitize(field.FieldName)}_{idx:D3}", plain);

                var name = field.FieldName;
                if (name.Equals("fileList", StringComparison.OrdinalIgnoreCase))
                {
                    var fl = DomainFileListParser.TryParseFileListFromDecrypted(
                        plain, domainName, encoding, domain.RecordName);
                    if (fl is not null && fileList is null)
                    {
                        fileList = fl;
                        fileListsFilled++;
                    }
                }
                else if (name.Equals("newAssets", StringComparison.OrdinalIgnoreCase))
                {
                    var n = MergeNames(newAssets, DomainFileListParser.ExtractAssetRecordNamesFromBytes(plain));
                    if (n > 0)
                        newAssetsFilled += n;
                }
                else if (name.Equals("deletedAssets", StringComparison.OrdinalIgnoreCase))
                {
                    MergeNames(deletedAssets, DomainFileListParser.ExtractAssetRecordNamesFromBytes(plain));
                }
                else if (name.Equals("domain", StringComparison.OrdinalIgnoreCase)
                         || name.Equals("encryptedAttributes", StringComparison.OrdinalIgnoreCase)
                         || name.Equals("EncryptedAttributes", StringComparison.OrdinalIgnoreCase))
                {
                    ApplyDomainPlain(
                        plain, domain.RecordName, ref domainName, ref encoding,
                        ref fileList, newAssets, deletedAssets, ref fileListsFilled, ref newAssetsFilled);
                }
                else if (name.Equals("domainName", StringComparison.OrdinalIgnoreCase)
                         && LooksLikeDomainName(plain))
                {
                    domainName = Encoding.UTF8.GetString(plain).Trim('\0', ' ');
                }
            }

            enriched.Add(domain with
            {
                DomainName = domainName,
                FileListEncoding = encoding,
                FileList = fileList,
                NewAssetRecordNames = newAssets,
                DeletedAssetRecordNames = deletedAssets
            });
        }

        // Domain senza finestra: resta il wire parse.
        if (enriched.Count < wireDomains.Count)
        {
            var seen = new HashSet<string>(
                enriched.Select(static d => d.FileList?.SignatureHex ?? $"{d.RecordName}|{d.DomainName}"),
                StringComparer.Ordinal);
            foreach (var d in wireDomains)
            {
                var key = d.FileList?.SignatureHex ?? $"{d.RecordName}|{d.DomainName}";
                if (seen.Add(key))
                    enriched.Add(d);
            }
        }

        var msg = fieldsOk > 0
            ? $"PCS Domain ok {fieldsOk}/{fieldsSeen} campi → +FL={fileListsFilled} +new={newAssetsFilled} (zoneKeys={zones.Count})"
            : fieldsSeen == 0
                ? $"nessun type=20 Domain (zoneKeys={zones.Count}) — solo wire"
                : $"PCS Domain 0/{fieldsSeen} decrypt (zoneKeys={zones.Count})";
        log?.Report($"  {msg}");

        return (enriched, new DecryptSummary(
            wireDomains.Count, enriched.Count, fieldsSeen, fieldsOk,
            fileListsFilled, newAssetsFilled, zones.Count, msg));
    }

    private static void ApplyDomainPlain(
        byte[] plain,
        string? recordName,
        ref string domainName,
        ref int encoding,
        ref DomainFileListParser.FileListAsset? fileList,
        List<string> newAssets,
        List<string> deletedAssets,
        ref int fileListsFilled,
        ref int newAssetsFilled)
    {
        // domainName in chiaro dentro il blob.
        var nameTag = Encoding.ASCII.GetBytes("domainName");
        // Scan grezzo: se compare un AppDomain/… usalo.
        foreach (var s in ProtobufStringScanner.ExtractUtf8Strings(plain))
        {
            if (s.StartsWith("AppDomain", StringComparison.Ordinal)
                || s.StartsWith("HomeDomain", StringComparison.Ordinal)
                || s.StartsWith("KeychainDomain", StringComparison.Ordinal)
                || s.StartsWith("CameraRollDomain", StringComparison.Ordinal)
                || s.StartsWith("MediaDomain", StringComparison.Ordinal)
                || s.StartsWith("RootDomain", StringComparison.Ordinal)
                || s.StartsWith("DatabaseDomain", StringComparison.Ordinal)
                || s.StartsWith("SysContainer", StringComparison.Ordinal)
                || s.StartsWith("SysSharedContainer", StringComparison.Ordinal)
                || s.StartsWith("HealthDomain", StringComparison.Ordinal)
                || s.Contains("Domain-", StringComparison.Ordinal))
            {
                if (s.Length is >= 4 and <= 200)
                    domainName = s.TrimEnd(':');
                break;
            }
        }

        _ = nameTag;

        if (fileList is null)
        {
            var fl = DomainFileListParser.TryParseFileListFromDecrypted(
                plain, domainName, encoding, recordName);
            if (fl is not null)
            {
                fileList = fl;
                fileListsFilled++;
            }
        }

        var addedNew = MergeNames(
            newAssets, DomainFileListParser.ExtractAssetRecordNamesFromBytes(plain));
        if (addedNew > 0)
            newAssetsFilled += addedNew;

        // deletedAssets: stessi pattern TYPE: — distinguere è difficile dallo scan solo;
        // se il blob ha il tag, ExtractAssetRecordNamesFromBytes sul sotto-campo è già
        // gestito dallo scanner per-field. Qui non doppio-conteggio deleted.
        _ = deletedAssets;
    }

    private static int MergeNames(List<string> target, IReadOnlyList<string> add)
    {
        var n = 0;
        var seen = new HashSet<string>(target, StringComparer.Ordinal);
        foreach (var a in add)
        {
            if (seen.Add(a))
            {
                target.Add(a);
                n++;
            }
        }

        return n;
    }

    private static byte[]? TryDecrypt(
        byte[] ciphertext,
        string fieldName,
        List<ProtectionZoneKeys> zones,
        List<PcsCompactPrivateKey> seedKeys)
    {
        var aad = AadCandidates(fieldName);
        foreach (var zone in zones)
        {
            var plain = PcsProtectionZone.TryDecryptField(zone, ciphertext, aad);
            if (plain is { Length: > 0 })
                return plain;
        }

        var embedded = PcsProtectionZone.TryUnwrapAll(ciphertext, seedKeys);
        foreach (var zone in embedded)
        {
            var plain = PcsProtectionZone.TryDecryptField(zone, ciphertext, aad);
            if (plain is { Length: > 0 })
                return plain;
        }

        return null;
    }

    private static string[] AadCandidates(string fieldName)
    {
        var list = new List<string> { fieldName };
        if (fieldName.Equals("domain", StringComparison.OrdinalIgnoreCase))
        {
            list.Add("Domain");
            list.Add("encryptedDomain");
            list.Add("EncryptedDomain");
        }

        if (fieldName.EndsWith("Encrypted", StringComparison.Ordinal))
            list.Add(fieldName[..^"Encrypted".Length]);
        return list.Distinct(StringComparer.Ordinal).ToArray();
    }

    private static bool LooksLikeDomainName(byte[] plain)
    {
        if (plain.Length is < 4 or > 200)
            return false;
        var s = Encoding.UTF8.GetString(plain).Trim('\0', ' ');
        return s.Contains("Domain", StringComparison.Ordinal)
               || s.StartsWith("AppDomain", StringComparison.Ordinal);
    }

    private static void SavePlain(
        string? root,
        DomainFileListParser.DomainRecord domain,
        string tag,
        byte[] plain)
    {
        if (root is null)
            return;
        try
        {
            var dir = Path.Combine(
                root,
                Sanitize(domain.DomainName) + "_" + Sanitize(domain.RecordName ?? "n"));
            Directory.CreateDirectory(dir);
            File.WriteAllBytes(Path.Combine(dir, tag + ".bin"), plain);
        }
        catch
        {
            // ignore IO
        }
    }

    private static string Sanitize(string? s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return "_";
        var chars = s.Trim();
        if (chars.Length > 80)
            chars = chars[..80];
        foreach (var c in Path.GetInvalidFileNameChars())
            chars = chars.Replace(c, '_');
        return chars;
    }
}
