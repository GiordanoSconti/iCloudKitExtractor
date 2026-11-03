using System.IO;
using System.Text;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Escrow;
using iCloudKitExtractor.Services.SyncData;

namespace iCloudKitExtractor.Tools;

/// <summary>
/// rustpush <c>PCSKey::key_id</c>:
/// HMAC-SHA256(KDF(master,"master key id labell"), "M key input data 2 u").
/// GCMDataA v3 header embeds key_id[0..4].
/// </summary>
internal static class PcsKeyId
{
    private static readonly byte[] Label =
        Encoding.ASCII.GetBytes("master key id labell");
    private static readonly byte[] Step2 =
        Encoding.ASCII.GetBytes("M key input data 2 u");

    public static byte[] FromMaster(ReadOnlySpan<byte> master)
    {
        var labelKey = PcsNistKdf.CtrHmacSha256(master, Label, master.Length);
        using var h = new System.Security.Cryptography.HMACSHA256(labelKey);
        return h.ComputeHash(Step2);
    }
}

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
            try { Console.WriteLine(s); } catch { /* WinExe */ }
        }

        L($"log={outLog}");
        var sync = Directory.GetDirectories(backups, "sync_data_*")
            .OrderByDescending(Directory.GetLastWriteTimeUtc)
            .First();
        var container = Path.Combine(sync, "ck", "apple.messages.cloud");
        var keysDir = Path.Combine(backups, "manatee_pcs_keys");
        // messageManateeZone: dominant key_id4=288B9022 (already in zone masters).
        var payloadPath = Path.Combine(container, "record_sync_messageManateeZone_p1.bin");
        var zonesPath = Directory.GetFiles(container, "zones_*.bin").FirstOrDefault();
        L($"sync={sync}");
        L($"payload={payloadPath} exists={File.Exists(payloadPath)}");

        var session = new ICloudSession { PcsManateeCompactKeys = LoadKeys(keysDir) };
        L($"loaded keys={session.PcsManateeCompactKeys.Count}");
        var seed = PcsSessionSeedKeys.CollectForSyncData(session);
        var payload = File.ReadAllBytes(payloadPath);
        byte[]? zonesPayload = zonesPath is null ? null : File.ReadAllBytes(zonesPath);

        var fields = CloudKitEncryptedFieldScanner.Scan(payload, ["svc", "guid"]);
        L($"fields={fields.Count}");
        if (fields.Count == 0)
            return 2;

        // Prefer ciphertext whose key_id4 matches an unwrapped PCSKey (after zones load).
        var sample = fields.First(f => f.FieldName == "svc");
        // Owner id "_"+32hex is NOT the record name — Messages uses 64-hex record names.
        var owner = ResolveMessagesRecord(payload, sample.Offset);
        var record = ResolveMessagesRecordHex64(payload, sample.Offset) ?? owner;
        L($"sample svc offset={sample.Offset} ctLen={sample.Ciphertext.Length} " +
          $"head={Convert.ToHexString(sample.Ciphertext.AsSpan(0, Math.Min(8, sample.Ciphertext.Length)))} " +
          $"record={record ?? "(null)"} owner={owner ?? "(null)"}");
        DumpGcmLayout(sample.Ciphertext, L);

        var zones = new List<ProtectionZoneKeys>();
        var pool = new List<PcsCompactPrivateKey>(seed);
        // rustpush: zone PI → nested EC (zone_keys); then record_protection_info
        // decode(zone_keys) → default_record_keys (PCSKey) for field GCM.
        if (zonesPayload is { Length: > 0 })
        {
            var round0 = PcsProtectionZone.TryUnwrapAll(zonesPayload, seed);
            zones.AddRange(round0);
            pool = PcsProtectionZone.MergeKeys(seed, round0);
            L($"zones round0 (seed): {round0.Count} pool={pool.Count}");

            // Re-scan with nested MasterKeySet → record_protection_info.
            for (var round = 1; round <= 3; round++)
            {
                var more = PcsProtectionZone.TryUnwrapAll(zonesPayload, pool);
                var added = 0;
                foreach (var z in more)
                {
                    var id = Convert.ToHexString(z.MasterKey);
                    if (zones.Any(x => Convert.ToHexString(x.MasterKey) == id))
                        continue;
                    zones.Add(z);
                    added++;
                }

                pool = PcsProtectionZone.MergeKeys(pool, more);
                L($"zones round{round} (nested): +{added} totalZones={zones.Count} pool={pool.Count}");
                if (added == 0)
                    break;
            }

            // GCM v3 header embeds PCSKey.key_id[0..4] as 03 | id0..1 | 02 | id2..3.
            var wantKeyId4 = sample.Ciphertext.Length >= 6 && sample.Ciphertext[0] == 3
                ? new byte[]
                {
                    sample.Ciphertext[1], sample.Ciphertext[2],
                    sample.Ciphertext[4], sample.Ciphertext[5],
                }
                : null;
            if (wantKeyId4 is not null)
                L($"ciphertext key_id4={Convert.ToHexString(wantKeyId4)}");

            foreach (var z in zones)
            {
                var kid = PcsKeyId.FromMaster(z.MasterKey);
                var kid4 = kid.AsSpan(0, Math.Min(4, kid.Length)).ToArray();
                var match = wantKeyId4 is not null
                            && kid4.AsSpan().SequenceEqual(wantKeyId4);
                L($"  master id={Trim(z.MasterKeyIdHex, 12)} nest={z.NestedPrivateKeys.Count} " +
                  $"pcsKeyId4={Convert.ToHexString(kid4)}{(match ? " ★MATCH header" : "")} " +
                  $"master={Convert.ToHexString(z.MasterKey.AsSpan(0, Math.Min(8, z.MasterKey.Length)))}…");
            }

            // Collect symm keys (04 10) from all nestBlobs as PCSKey candidates.
            var pcsCandidates = new List<(string Label, byte[] Master)>();
            foreach (var z in zones)
            {
                pcsCandidates.Add(($"master:{Trim(z.MasterKeyIdHex, 8)}", z.MasterKey));
                if (z.NestedProtectionObject is not { Length: > 0 } nb)
                    continue;
                for (var i = 0; i + 18 <= nb.Length; i++)
                {
                    if (nb[i] != 0x04 || nb[i + 1] != 0x10)
                        continue;
                    pcsCandidates.Add(($"symm@{i}", nb.AsSpan(i + 2, 16).ToArray()));
                }
            }

            // Prefer first svc; if no PCSKey for its key_id4, repick.
            byte[]? FindMaster(byte[] id4) =>
                pcsCandidates
                    .Select(c => (c, kid: PcsKeyId.FromMaster(c.Master)))
                    .Where(t => t.kid.Length >= 4 && t.kid.AsSpan(0, 4).SequenceEqual(id4))
                    .Select(t => t.c.Master)
                    .FirstOrDefault();

            if (wantKeyId4 is not null && FindMaster(wantKeyId4) is null)
            {
                foreach (var f in fields.Where(f => f.FieldName == "svc" && f.Ciphertext.Length >= 6))
                {
                    var id4 = new byte[]
                    {
                        f.Ciphertext[1], f.Ciphertext[2], f.Ciphertext[4], f.Ciphertext[5],
                    };
                    if (FindMaster(id4) is null)
                        continue;
                    sample = f;
                    record = ResolveMessagesRecord(payload, sample.Offset);
                    wantKeyId4 = id4;
                    L($"REPICK svc@{sample.Offset} key_id4={Convert.ToHexString(id4)} " +
                      $"head={Convert.ToHexString(sample.Ciphertext.AsSpan(0, 8))}");
                    break;
                }
            }

            if (wantKeyId4 is not null)
            {
                foreach (var (label, master) in pcsCandidates)
                {
                    var kid = PcsKeyId.FromMaster(master);
                    if (kid.Length < 4 || !kid.AsSpan(0, 4).SequenceEqual(wantKeyId4))
                        continue;
                    L($"PCSKey candidate {label} master={Convert.ToHexString(master)} " +
                      $"kid={Convert.ToHexString(kid)}");
                }
            }
        }

        L($"payloadLen={payload.Length}");

        zones = zones
            .GroupBy(z => Convert.ToHexString(z.MasterKey), StringComparer.Ordinal)
            .Select(g => g.First())
            .ToList();
        L($"zoneKeys dedup={zones.Count}");

        var aads = BuildAads("svc", "messageManateeZone", record);
        foreach (var extra in new[]
                 {
                     "messageManateeZone-_1f765d7f431869eb5832d3d65fc3eadd-svc",
                     "chatManateeZone-_1f765d7f431869eb5832d3d65fc3eadd-svc",
                     "MessageEncryptedV3-svc",
                 })
        {
            if (!aads.Contains(extra, StringComparer.Ordinal))
                aads.Add(extra);
        }

        L($"aad×{aads.Count}: {string.Join(" | ", aads)}");

        var keysToTry = new List<(string Label, byte[] Key)>();
        var want4 = sample.Ciphertext.Length >= 6 && sample.Ciphertext[0] == 3
            ? new byte[]
            {
                sample.Ciphertext[1], sample.Ciphertext[2],
                sample.Ciphertext[4], sample.Ciphertext[5],
            }
            : null;

        void AddPcs(string label, byte[] master)
        {
            var m16 = master.Length == 16 ? master : master.AsSpan(0, 16).ToArray();
            keysToTry.Add(($"★{label} nist",
                PcsNistKdf.CtrHmacSha256(m16, Encoding.ASCII.GetBytes("encryption key key m"), 16)));
            keysToTry.Add(($"★{label} hmacPad", PcsHmacKdf.DeriveAes128Key(m16)));
            keysToTry.Add(($"★{label} raw", m16));
            var share = PcsNistKdf.CtrHmacSha256(
                m16, Encoding.ASCII.GetBytes("MsaeEooevaX fooo 012"), 16);
            keysToTry.Add(($"★{label} shareNist",
                PcsNistKdf.CtrHmacSha256(share, Encoding.ASCII.GetBytes("encryption key key m"), 16)));
            L($"try PCSKey {label}={Convert.ToHexString(m16)} " +
              $"nist={Convert.ToHexString(keysToTry[^4].Key)}");
        }

        if (want4 is not null)
        {
            foreach (var z in zones)
            {
                if (PcsKeyId.FromMaster(z.MasterKey).AsSpan(0, 4).SequenceEqual(want4))
                    AddPcs("master", z.MasterKey);
                if (z.NestedProtectionObject is not { Length: > 0 } nb)
                    continue;
                for (var i = 0; i + 18 <= nb.Length; i++)
                {
                    if (nb[i] != 0x04 || nb[i + 1] != 0x10)
                        continue;
                    var slice = nb.AsSpan(i + 2, 16).ToArray();
                    if (PcsKeyId.FromMaster(slice).AsSpan(0, 4).SequenceEqual(want4))
                        AddPcs($"symm@{i}", slice);
                }
            }
        }

        keysToTry = keysToTry
            .GroupBy(k => Convert.ToHexString(k.Key), StringComparer.Ordinal)
            .Select(g => g.First())
            .ToList();
        L($"keysToTry={keysToTry.Count} want4={(want4 is null ? "-" : Convert.ToHexString(want4))}");

        var priority = keysToTry.Where(k => k.Label.StartsWith('★')).ToList();
        if (priority.Count == 0)
            priority = keysToTry;
        foreach (var (label, key) in priority)
        {
            if (key.Length is not (16 or 32))
                continue;
            foreach (var aad in aads)
            {
                try
                {
                    var plain = PcsGcmDataA.Decrypt(key, sample.Ciphertext, Encoding.UTF8.GetBytes(aad));
                    L($"HIT {label} aad='{aad}' plainLen={plain.Length} plain={Preview(plain)}");

                    // Production path smoke: SyncDataPcsDecryptor on this payload.
                    var outDir = Path.Combine(Path.GetDirectoryName(payloadPath)!, "crypto", "_msgs_probe_verify");
                    var progress = new Progress<string>(L);
                    var sum = SyncDataPcsDecryptor.DecryptPayload(
                        session, zonesPayload, payload, outDir,
                        containerHint: "apple.messages.cloud",
                        log: progress,
                        zoneNameHint: "messageManateeZone");
                    L($"SyncDataPcsDecryptor: {sum.Message} decrypted={sum.DecryptedCount}/{sum.FieldCount} zones={sum.ZoneKeys}");
                    return sum.DecryptedCount > 0 ? 0 : 1;
                }
                catch
                {
                    // next
                }
            }
        }

        L($"no hits after priority={priority.Count} × aads={aads.Count}");
        return 1;
    }

    private static int IndexOf(byte[] hay, byte[] needle)
    {
        if (needle.Length == 0 || hay.Length < needle.Length)
            return -1;
        var span = hay.AsSpan();
        for (var i = 0; i <= span.Length - needle.Length; i++)
        {
            if (span.Slice(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }

    private static bool TrySliceAppl(byte[] data, int offset, out byte[] der)
    {
        der = [];
        try
        {
            if (offset >= data.Length || data[offset] != 0x61)
                return false;
            var pos = offset + 1;
            if (!TryReadLen(data, ref pos, out var len))
                return false;
            if (pos + len > data.Length || len < 4)
                return false;
            der = data.AsSpan(offset, (pos - offset) + len).ToArray();
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static bool TryReadLen(byte[] data, ref int pos, out int len)
    {
        len = 0;
        if (pos >= data.Length)
            return false;
        var b = data[pos++];
        if (b < 0x80)
        {
            len = b;
            return true;
        }

        var n = b & 0x7F;
        if (n is 0 or > 3 || pos + n > data.Length)
            return false;
        for (var i = 0; i < n; i++)
            len = (len << 8) | data[pos++];
        return len > 0;
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
        log($"gcm: ver={ver} headerLen={headerLen} header={Convert.ToHexString(ct.AsSpan(0, headerLen))} " +
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
            Add($"Manatee-{record}-{field}");
            Add($"MessageEncryptedV3-{record}-{field}");
            Add($"ChatEncryptedV3-{record}-{field}");
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

    /// <summary>Messages record name: 64 lowercase hex (not owner <c>_</c>+32hex).</summary>
    private static string? ResolveMessagesRecordHex64(byte[] payload, int fieldOffset)
    {
        var windowStart = Math.Max(0, fieldOffset - 2500);
        var text = Encoding.ASCII.GetString(
            payload, windowStart,
            Math.Min(payload.Length - windowStart, fieldOffset - windowStart + 8));
        string? best = null;
        var bestDist = int.MaxValue;
        for (var i = 0; i + 64 <= text.Length; i++)
        {
            var ok = true;
            for (var j = 0; j < 64; j++)
            {
                var c = text[i + j];
                if (c is not ((>= '0' and <= '9') or (>= 'a' and <= 'f')))
                {
                    ok = false;
                    break;
                }
            }

            if (!ok)
                continue;
            // Prefer standalone hex (not mid-string): prev not hex.
            if (i > 0 && IsAsciiHex(text[i - 1]))
                continue;
            if (i + 64 < text.Length && IsAsciiHex(text[i + 64]))
                continue;
            var abs = windowStart + i;
            var dist = fieldOffset - abs;
            if (dist < 0 || dist >= bestDist)
                continue;
            bestDist = dist;
            best = text.Substring(i, 64);
        }

        return best;
    }

    private static bool IsAsciiHex(char c) =>
        c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');

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
