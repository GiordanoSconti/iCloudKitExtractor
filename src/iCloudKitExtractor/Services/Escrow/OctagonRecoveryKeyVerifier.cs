using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Offline + live verifier for Octagon Recovery Key against harvested
/// <c>RK-…</c> peer IDs and recoverable TLKShare dumps (B5b/B10).
/// </summary>
public static class OctagonRecoveryKeyVerifier
{
    private static readonly Regex RkPeerRegex = new(
        @"RK-[A-Za-z0-9+/]{64}",
        RegexOptions.Compiled);

    public sealed record Result(
        bool DerivedOk,
        string PeerId,
        bool MatchedHarvestedPeer,
        IReadOnlyList<string> HarvestedPeers,
        string? MatchedPeer,
        int OfflineUnwrapViews,
        IReadOnlyDictionary<string, int> OfflineTlkBytesByView,
        string Summary);

    /// <summary>
    /// Derive RK keys, compare peerID to harvested receivers in dump dirs,
    /// attempt ECIES unwrap of recoverable bins with the encryption private key.
    /// </summary>
    public static Result VerifyOffline(
        string recoveryKeyString,
        string recoverySalt,
        params string[] dumpDirectories)
    {
        var derived = OctagonRecoveryKey.Derive(recoveryKeyString, recoverySalt);
        var want = OctagonRecoveryKey.NormalizeRkPeerId(derived.PeerId);

        var harvested = new SortedSet<string>(StringComparer.Ordinal);
        foreach (var dir in dumpDirectories)
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                continue;
            foreach (var f in Directory.EnumerateFiles(dir, "*.bin", SearchOption.AllDirectories))
            {
                var ascii = Encoding.ASCII.GetString(File.ReadAllBytes(f));
                foreach (Match m in RkPeerRegex.Matches(ascii))
                    harvested.Add(OctagonRecoveryKey.NormalizeRkPeerId(m.Value));
            }
        }

        string? matched = null;
        foreach (var h in harvested)
        {
            if (string.Equals(h, want, StringComparison.Ordinal))
            {
                matched = h;
                break;
            }
        }

        var tlkByView = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var dir in dumpDirectories)
        {
            if (string.IsNullOrWhiteSpace(dir) || !Directory.Exists(dir))
                continue;
            foreach (var f in Directory.EnumerateFiles(dir, "*.bin", SearchOption.AllDirectories))
            {
                if (!f.Contains("fetchRecoverable", StringComparison.OrdinalIgnoreCase)
                    && !f.Contains("recoverable", StringComparison.OrdinalIgnoreCase)
                    && !Path.GetDirectoryName(f)!.Contains("B5b", StringComparison.OrdinalIgnoreCase))
                    continue;
                TryUnwrapBin(File.ReadAllBytes(f), derived.EncryptionPkcs8, tlkByView, want);
            }
        }

        var sizes = tlkByView.ToDictionary(
            kv => kv.Key, kv => kv.Value.Length, StringComparer.OrdinalIgnoreCase);

        var summary =
            matched is not null
                ? $"MATCH peer {matched} — offline unwrap views={tlkByView.Count}"
                : tlkByView.Count > 0
                    ? $"peerID non in harvest, ma unwrap OK views={tlkByView.Count} (KDF usable)"
                    : $"peerID={want} non tra i {harvested.Count} RK harvest; unwrap=0 " +
                      "(RK non enrolled, salt errato, o dump senza share per questo RK)";

        return new Result(
            true,
            want,
            matched is not null,
            harvested.ToList(),
            matched,
            tlkByView.Count,
            sizes,
            summary);
    }

    /// <summary>
    /// Persist derived key material (PKCS#8) + report under <paramref name="outputDirectory"/>.
    /// Does not write the recovery key string.
    /// </summary>
    public static void WriteArtifacts(
        string recoveryKeyString,
        string recoverySalt,
        string outputDirectory,
        Result result)
    {
        Directory.CreateDirectory(outputDirectory);
        var derived = OctagonRecoveryKey.Derive(recoveryKeyString, recoverySalt);
        File.WriteAllBytes(
            Path.Combine(outputDirectory, "rk_signing.pkcs8"), derived.SigningPkcs8);
        File.WriteAllBytes(
            Path.Combine(outputDirectory, "rk_encryption.pkcs8"), derived.EncryptionPkcs8);
        File.WriteAllBytes(
            Path.Combine(outputDirectory, "rk_signing_pub.bin"), derived.SigningPublicKeyData);
        File.WriteAllBytes(
            Path.Combine(outputDirectory, "rk_encryption_pub.bin"), derived.EncryptionPublicKeyData);

        var report = new
        {
            peerId = result.PeerId,
            matchedHarvestedPeer = result.MatchedHarvestedPeer,
            matchedPeer = result.MatchedPeer,
            harvestedPeers = result.HarvestedPeers,
            offlineUnwrapViews = result.OfflineUnwrapViews,
            offlineTlkBytesByView = result.OfflineTlkBytesByView,
            summary = result.Summary,
            saltLen = recoverySalt.Length,
            rkLen = recoveryKeyString.Length,
            note =
                "KDF = HKDF-SHA384(ikm=UTF8(rk), salt=UTF8(altDSID), info, 56) + " +
                "ccec_generate_key_deterministic(P-384, FIPS extrabits). " +
                "peerID = RK- + b64(SHA384(signingPub X9.63)). Recovery string not stored."
        };
        File.WriteAllText(
            Path.Combine(outputDirectory, "rk_verifier_report.json"),
            JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));

        var tlkDir = Path.Combine(outputDirectory, "tlk");
        Directory.CreateDirectory(tlkDir);
        var tlkByView = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        var parent = Directory.GetParent(outputDirectory)?.FullName;
        if (parent is not null)
        {
            foreach (var sub in new[] { "B10_recoverable_RK", "B5_recoverable_bypass", "B12_other_angles" })
            {
                var d = Path.Combine(parent, sub);
                if (!Directory.Exists(d))
                    continue;
                foreach (var f in Directory.EnumerateFiles(d, "*.bin", SearchOption.AllDirectories))
                {
                    if (!f.Contains("fetchRecoverable", StringComparison.OrdinalIgnoreCase)
                        && !f.Contains("recoverable", StringComparison.OrdinalIgnoreCase)
                        && !f.Contains("B5b", StringComparison.OrdinalIgnoreCase))
                        continue;
                    TryUnwrapBin(
                        File.ReadAllBytes(f), derived.EncryptionPkcs8, tlkByView, result.PeerId);
                }
            }
        }

        foreach (var (view, tlk) in tlkByView)
        {
            var safe = string.Join("_", view.Split(Path.GetInvalidFileNameChars()));
            File.WriteAllBytes(Path.Combine(tlkDir, $"ckks_{safe}_tlk_rk.bin"), tlk);
        }
    }

    /// <summary>
    /// Stock parser + wire heuristic for B5b (NSKeyedArchive wrappedkey as b64 near peer name).
    /// </summary>
    public static int TryUnwrapBin(
        byte[] raw,
        byte[] encryptionPkcs8,
        IDictionary<string, byte[]> tlkByView,
        string? peerIdFilter = null)
    {
        var added = 0;
        var needle = string.IsNullOrWhiteSpace(peerIdFilter)
            ? null
            : OctagonRecoveryKey.NormalizeRkPeerId(peerIdFilter);

        try
        {
            var (shares, _) = OctagonCuttlefishService.ParseRecoverableResponse(raw);
            added += TryUnwrapRecords(shares, encryptionPkcs8, tlkByView, needle);
        }
        catch
        {
            // ignore
        }

        // B5b: record name embeds receiver peerID; wrappedkey follows as b64(bplist).
        added += TryUnwrapWireHeuristic(raw, encryptionPkcs8, tlkByView, needle);
        return added;
    }

    /// <summary>
    /// Locate <c>tlkshare-…::RK-…</c> (or SHA256) names and the following bplist wrappedkey.
    /// </summary>
    private static int TryUnwrapWireHeuristic(
        byte[] raw,
        byte[] encryptionPkcs8,
        IDictionary<string, byte[]> tlkByView,
        string? needle)
    {
        var added = 0;
        var ascii = Encoding.ASCII.GetString(raw);
        var nameRegex = new Regex(
            @"tlkshare-[0-9A-Fa-f-]{36}::(RK-[A-Za-z0-9+/]{64}|SHA256:[A-Za-z0-9+/=]{20,})",
            RegexOptions.Compiled);

        foreach (Match nameMatch in nameRegex.Matches(ascii))
        {
            var receiver = nameMatch.Groups[1].Value;
            if (needle is not null)
            {
                var norm = receiver.StartsWith("RK-", StringComparison.Ordinal)
                    ? OctagonRecoveryKey.NormalizeRkPeerId(receiver)
                    : receiver;
                if (!string.Equals(norm, needle, StringComparison.Ordinal)
                    && !receiver.Contains(needle.Length > 16 ? needle[3..19] : needle, StringComparison.Ordinal))
                    continue;
            }

            var from = nameMatch.Index;
            var windowLen = Math.Min(6000, raw.Length - from);
            var after = Encoding.ASCII.GetString(raw, from, windowLen);
            var wkAt = after.IndexOf("wrappedkey", StringComparison.Ordinal);
            if (wkAt < 0)
                continue;

            var afterWk = after[(wkAt + "wrappedkey".Length)..];
            // Prefer NSKeyedArchive bplist (YnBsaXN0…); fallback any long b64.
            var bm = Regex.Match(afterWk, @"(YnBsaXN0[A-Za-z0-9+/]{200,}={0,3})");
            if (!bm.Success)
                bm = Regex.Match(afterWk, @"([A-Za-z0-9+/]{200,}={0,3})");
            if (!bm.Success)
                continue;

            var b64 = bm.Groups[1].Value;
            // Trim trailing junk past first non-b64 run (protobuf may glue next field).
            var cut = 0;
            for (; cut < b64.Length; cut++)
            {
                var c = b64[cut];
                if (c is >= 'A' and <= 'Z' or >= 'a' and <= 'z' or >= '0' and <= '9' or '+' or '/' or '=')
                    continue;
                break;
            }

            b64 = b64[..cut].TrimEnd('=');
            while (b64.Length % 4 != 0)
                b64 += "=";

            if (!CkksTlkShare.TryExtractEciesBlob(b64, out var ecies, out _))
                continue;

            try
            {
                var pt = CkksEcies.Unwrap(encryptionPkcs8, ecies);
                var tlk = CkksKeys.TlkFromCkksKeyPlaintext(pt);
                var zone = CkksKeys.ZoneNameFromCkksKeyPlaintext(pt) ?? "unknown";
                if (tlkByView.TryAdd(zone, tlk))
                    added++;
            }
            catch
            {
                // not for this key
            }
        }

        return added;
    }

    private static int TryUnwrapRecords(
        IEnumerable<CkksRecord> shares,
        byte[] encryptionPkcs8,
        IDictionary<string, byte[]> tlkByView,
        string? needle)
    {
        var added = 0;
        foreach (var rec in shares)
        {
            var name = rec.Name ?? "";
            if (needle is not null
                && !name.Contains(needle, StringComparison.Ordinal)
                && !name.Contains(needle.Length > 16 ? needle[3..19] : needle, StringComparison.Ordinal))
                continue;

            var wrapped = rec.FieldString("wrappedkey");
            if (string.IsNullOrEmpty(wrapped))
                continue;
            if (!CkksTlkShare.TryExtractEciesBlob(wrapped, out var ecies, out _))
                continue;
            try
            {
                var pt = CkksEcies.Unwrap(encryptionPkcs8, ecies);
                var tlk = CkksKeys.TlkFromCkksKeyPlaintext(pt);
                var zone = CkksKeys.ZoneNameFromCkksKeyPlaintext(pt) ?? "unknown";
                if (tlkByView.TryAdd(zone, tlk))
                    added++;
            }
            catch
            {
                // not for this RK
            }
        }

        return added;
    }
}
