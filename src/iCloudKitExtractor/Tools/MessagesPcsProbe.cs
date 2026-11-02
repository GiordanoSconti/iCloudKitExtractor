using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;

namespace iCloudKitExtractor.Tools;

/// <summary>Offline Messages PCS field decrypt probe (CLI: msgs-probe).</summary>
public static class MessagesPcsProbe
{
    public static int Run(string[] args)
    {
        var backups = args.Length > 1
            ? args[1]
            : Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                "iCloudBackups");
        var outLog = Path.Combine(backups, "msgs_pcs_probe.log");
        using var log = new StreamWriter(outLog, append: false) { AutoFlush = true };
        void L(string s)
        {
            log.WriteLine(s);
            try { Console.WriteLine(s); } catch { /* WinExe may have no console */ }
        }

        var sync = Directory.GetDirectories(backups, "sync_data_*")
            .OrderByDescending(Directory.GetLastWriteTimeUtc)
            .First();
        var container = Path.Combine(sync, "ck", "apple.messages.cloud");
        var keysDir = Path.Combine(backups, "manatee_pcs_keys");
        var payloadPath = Path.Combine(container, "record_sync_chatManateeZone_p1.bin");
        var zonesPath = Directory.GetFiles(container, "zones_*.bin").FirstOrDefault();

        L($"log={outLog}");
        L($"sync={sync}");
        L($"payload={payloadPath} exists={File.Exists(payloadPath)}");

        var session = new ICloudSession
        {
            PcsManateeCompactKeys = LoadKeys(keysDir)
        };
        L($"loaded keys={session.PcsManateeCompactKeys.Count}");

        var payload = File.ReadAllBytes(payloadPath);
        byte[]? zonesPayload = zonesPath is null ? null : File.ReadAllBytes(zonesPath);
        var fields = CloudKitEncryptedFieldScanner.Scan(payload, ["svc", "guid", "msgProto"]);
        L($"fields={fields.Count}");
        if (fields.Count == 0)
            return 2;

        var seed = PcsSessionSeedKeys.CollectForSyncData(session);
        var zones = new List<ProtectionZoneKeys>();
        if (zonesPayload is { Length: > 0 })
            zones.AddRange(PcsProtectionZone.TryUnwrapAll(zonesPayload, seed));
        L($"from zones_*: {zones.Count}");
        zones.AddRange(PcsProtectionZone.TryUnwrapAllIterative(payload, seed));
        L(
            $"zoneKeys={zones.Count} nestedSum={zones.Sum(z => z.NestedPrivateKeys.Count)} " +
            $"withNestedBlob={zones.Count(z => z.NestedProtectionObject is { Length: > 0 })}");

        foreach (var z in zones.Take(8))
        {
            L(
                $"  zone id={Trim(z.MasterKeyIdHex, 16)} masterLen={z.MasterKey.Length} " +
                $"decLen={z.DecryptKey.Length} tag={z.ProtectionInfoTag ?? "-"} " +
                $"nestedKeys={z.NestedPrivateKeys.Count} nestBlob={z.NestedProtectionObject?.Length ?? 0}");
        }

        var sample = fields.First(f => f.FieldName == "svc");
        var record = ResolveMessagesRecord(payload, sample.Offset);
        L(
            $"sample svc ctLen={sample.Ciphertext.Length} " +
            $"head={Convert.ToHexString(sample.Ciphertext.AsSpan(0, Math.Min(8, sample.Ciphertext.Length)))} " +
            $"record={record ?? "(null)"}");
        DumpGcmLayout(sample.Ciphertext, L);

        var aads = BuildAads("svc", "chatManateeZone", record);
        L($"aad×{aads.Count}: {string.Join(" | ", aads)}");

        var keysToTry = new List<(string Label, byte[] Key)>();
        foreach (var z in zones)
        {
            var id = Trim(z.MasterKeyIdHex, 8);
            keysToTry.Add(($"dec:{id}", z.DecryptKey));
            if (z.MasterKey.Length >= 16)
                keysToTry.Add(($"master16:{id}", z.MasterKey.AsSpan(0, 16).ToArray()));
            if (z.MasterKey.Length >= 32)
                keysToTry.Add(($"master32:{id}", z.MasterKey.AsSpan(0, 32).ToArray()));
            // KDF variants already in DecryptKey; also try raw nested blob prefixes.
            if (z.NestedProtectionObject is { Length: >= 16 } nest)
            {
                keysToTry.Add(($"nest16:{id}", nest.AsSpan(0, 16).ToArray()));
                if (nest.Length >= 32)
                    keysToTry.Add(($"nest32:{id}", nest.AsSpan(0, 32).ToArray()));
                // If nested is itself GCMDataA, try decrypt with zone keys then use result
                try
                {
                    var inner = PcsGcmDataA.Decrypt(z.DecryptKey, nest);
                    if (inner.Length >= 16)
                        keysToTry.Add(($"nestDec16:{id}", inner.AsSpan(0, 16).ToArray()));
                }
                catch
                {
                    // ignore
                }
            }

            foreach (var nk in z.NestedPrivateKeys)
            {
                var nMaster = nk.PrivateD.Length >= 16 ? nk.PrivateD.AsSpan(0, 16).ToArray() : nk.PrivateD;
                keysToTry.Add(($"nestedD:{Trim(Convert.ToHexString(nk.KeyId), 8)}", nMaster));
            }
        }

        var hits = 0;
        foreach (var (label, key) in keysToTry)
        {
            if (key.Length is not (16 or 32))
                continue;
            foreach (var aad in aads.Append(""))
            {
                try
                {
                    var plain = aad.Length == 0
                        ? PcsGcmDataA.Decrypt(key, sample.Ciphertext)
                        : PcsGcmDataA.Decrypt(key, sample.Ciphertext, Encoding.UTF8.GetBytes(aad));
                    L($"HIT {label} aad='{aad}' plainLen={plain.Length} plain={Preview(plain)}");
                    hits++;
                    if (hits >= 8)
                        return 0;
                }
                catch
                {
                    // next
                }
            }
        }

        L($"no hits after keys={keysToTry.Count} aads={aads.Count + 1}");

        var windowStart = Math.Max(0, sample.Offset - 48 * 1024);
        var window = payload.AsSpan(
            windowStart,
            Math.Min(payload.Length - windowStart, 60 * 1024)).ToArray();
        var local = PcsProtectionZone.TryUnwrapAll(window, seed);
        L($"localZones={local.Count}");
        foreach (var z in local)
        {
            foreach (var key in new[] { z.DecryptKey, z.MasterKey.Length >= 16 ? z.MasterKey.AsSpan(0, 16).ToArray() : z.MasterKey })
            {
                foreach (var aad in aads.Append(""))
                {
                    try
                    {
                        var plain = aad.Length == 0
                            ? PcsGcmDataA.Decrypt(key, sample.Ciphertext)
                            : PcsGcmDataA.Decrypt(key, sample.Ciphertext, Encoding.UTF8.GetBytes(aad));
                        L(
                            $"LOCAL HIT id={Trim(z.MasterKeyIdHex, 8)} aad='{aad}' " +
                            $"plainLen={plain.Length} {Preview(plain)}");
                        return 0;
                    }
                    catch
                    {
                        // next
                    }
                }
            }
        }

        return 1;
    }

    private static void DumpGcmLayout(byte[] ct, Action<string> log)
    {
        if (ct.Length < 4)
            return;
        var ver = ct[0];
        var headerLen = ver switch
        {
            0 or 1 => 1,
            2 => 3,
            3 => 4 + ct[3],
            _ => -1
        };
        if (headerLen < 0 || ct.Length < headerLen)
        {
            log($"gcm: ver={ver} headerLen=? rawLen={ct.Length}");
            return;
        }

        var nonceLen = ver == 0 ? 8 : 12;
        var tagLen = ver == 0 ? 8 : 12;
        var encLen = ct.Length - headerLen - nonceLen - tagLen;
        log(
            $"gcm: ver={ver} headerLen={headerLen} header={Convert.ToHexString(ct.AsSpan(0, headerLen))} " +
            $"nonceLen={nonceLen} tagLen={tagLen} encLen={encLen}");
    }

    private static List<PcsCompactPrivateKey> LoadKeys(string dir)
    {
        var list = new List<PcsCompactPrivateKey>();
        if (!Directory.Exists(dir))
            return list;
        foreach (var xPath in Directory.GetFiles(dir, "pcs_*_x.bin"))
        {
            var dPath = xPath.Replace("_x.bin", "_d.bin");
            if (!File.Exists(dPath))
                continue;
            var x = File.ReadAllBytes(xPath);
            var d = File.ReadAllBytes(dPath);
            if (x.Length < 32 || d.Length < 32)
                continue;
            var pub = x.AsSpan(0, 32).ToArray();
            var priv = d.AsSpan(0, 32).ToArray();
            list.Add(new PcsCompactPrivateKey(pub, priv, PcsDer.KeyIdOf(pub), null));
        }

        return list;
    }

    private static List<string> BuildAads(string field, string zone, string? record)
    {
        var list = new List<string>();
        void Add(string s)
        {
            if (!string.IsNullOrEmpty(s) && !list.Contains(s, StringComparer.Ordinal))
                list.Add(s);
        }

        if (record is not null)
        {
            Add($"{zone}-{record}-{field}");
            if (record.StartsWith('_'))
                Add($"{zone}-{record[1..]}-{field}");
            Add($"{record}-{field}");
            if (record.StartsWith('_'))
                Add($"{record[1..]}-{field}");
            Add($"BeaconStore-{record}-{field}");
            // Alternate separators seen in some Apple stacks
            Add($"{zone}/{record}/{field}");
            Add($"{zone}:{record}:{field}");
        }

        Add(field);
        Add($"{zone}-{field}");
        return list;
    }

    private static string? ResolveMessagesRecord(byte[] payload, int fieldOffset)
    {
        var windowStart = Math.Max(0, fieldOffset - 1500);
        var text = Encoding.ASCII.GetString(
            payload, windowStart,
            Math.Min(payload.Length - windowStart, fieldOffset - windowStart + 64));
        string? best = null;
        var bestDist = int.MaxValue;
        for (var i = 0; i + 33 <= text.Length; i++)
        {
            if (text[i] != '_')
                continue;
            var ok = true;
            for (var j = 1; j <= 32; j++)
            {
                var c = text[i + j];
                if (c is not ((>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F')))
                {
                    ok = false;
                    break;
                }
            }

            if (!ok)
                continue;
            var abs = windowStart + i;
            var dist = fieldOffset - abs;
            if (dist < 0 || dist >= bestDist)
                continue;
            bestDist = dist;
            best = text.Substring(i, 33);
        }

        return best;
    }

    private static string Preview(byte[] plain)
    {
        if (plain.Length == 0)
            return "(empty)";
        var ascii = Encoding.ASCII.GetString(plain);
        if (ascii.All(c => c is >= ' ' and <= '~' or '\n' or '\r' or '\t'))
            return ascii.Length > 60 ? ascii[..60] + "…" : ascii;
        return Convert.ToHexString(plain.AsSpan(0, Math.Min(24, plain.Length)));
    }

    private static string Trim(string s, int n) => s.Length <= n ? s : s[..n];
}
