using System.Text;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Estrae / costruisce l'header HTTP <c>x-apple-mmcs-auth</c>.
/// Formato  <c>{hex21_f2} {hex21_f17} {CAog…}</c> dove f2/f17 sono checksum
/// (21 byte) e CAog è il protobuf firmato "Foreground Restore" (base64url).
/// In PreAuth i tre pezzi sono campi protobuf sibling 2 / 5 / 17.
/// </summary>
public static class MmcsAuthBuilder
{
    private static readonly Regex ReadyAuthRegex = new(
        @"((?:01|04)[0-9a-fA-F]{40})\s+((?:01|04)[0-9a-fA-F]{40})\s+([A-Za-z0-9_-]{16,})",
        RegexOptions.Compiled);

    public static string? BuildFromRecordPayload(ReadOnlySpan<byte> payload, string recordName)
    {
        if (recordName.StartsWith("S:", StringComparison.Ordinal)
            || recordName.StartsWith("&S:", StringComparison.Ordinal))
        {
            var snapAuth = BuildSnapshotAuth(payload, recordName);
            if (!string.IsNullOrWhiteSpace(snapAuth))
                return snapAuth;
        }

        var data = payload.ToArray();

        var structured = ExtractStructuredAuths(data);
        if (structured.Count == 1)
            return structured[0].Header;

        if (structured.Count > 1)
        {
            var match = structured.FirstOrDefault(a =>
                a.RecordName is not null &&
                RecordNameLookupCandidates(recordName).Contains(a.RecordName, StringComparer.Ordinal));
            if (match is not null)
                return match.Header;
        }

        var ready = ExtractAllReadyMadeAuths(data);
        if (ready.Count == 1)
            return ready[0];
        foreach (var auth in ready)
        {
            if (auth.Contains(recordName, StringComparison.Ordinal) || AuthMatchesRecord(auth, recordName))
                return auth;
        }

        return null;
    }

    /// <summary>
    /// Auth MMCS per record snapshot (S:/&amp;S:). Il proto spesso non ripete il nome S: ma
    /// contiene l'UUID snapshot nel blob base64 del terzo campo.
    /// </summary>
    public static string? BuildSnapshotAuth(ReadOnlySpan<byte> payload, string snapshotRecordName)
    {
        var canonical = CloudKitRecordNames.CanonicalSnapshotRecordName(snapshotRecordName);
        var uuid = CloudKitRecordNames.StripSnapshotPrefix(canonical);
        var compactUuid = uuid.Replace("-", "", StringComparison.Ordinal);
        var data = payload.ToArray();

        var structured = ExtractStructuredAuths(data);
        if (structured.Count == 1)
            return structured[0].Header;

        foreach (var auth in structured)
        {
            if (AuthReferencesSnapshot(auth.Header, uuid, compactUuid))
                return auth.Header;
        }

        var ready = ExtractAllReadyMadeAuths(data);
        if (ready.Count == 1)
            return ready[0];

        foreach (var auth in ready)
        {
            if (AuthReferencesSnapshot(auth, uuid, compactUuid))
                return auth;
        }

        if (structured.Count == 0 && ready.Count == 1)
            return ready[0];

        return null;
    }

    private static bool AuthReferencesSnapshot(string authHeader, string uuid, string compactUuid)
    {
        if (AuthMatchesRecord(authHeader, CloudKitRecordNames.CanonicalSnapshotRecordName($"S:{uuid}")))
            return true;

        if (authHeader.Contains(uuid, StringComparison.OrdinalIgnoreCase))
            return true;

        var parts = authHeader.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
            return false;

        try
        {
            var padded = parts[2].Replace('-', '+').Replace('_', '/');
            padded += (padded.Length % 4) switch
            {
                2 => "==",
                3 => "=",
                _ => string.Empty
            };
            var bytes = Convert.FromBase64String(padded);
            var text = Encoding.UTF8.GetString(bytes);
            if (text.Contains(uuid, StringComparison.OrdinalIgnoreCase)
                || text.Contains(compactUuid, StringComparison.OrdinalIgnoreCase))
                return true;

            return IndexOf(bytes, Encoding.UTF8.GetBytes(uuid)) >= 0
                   || IndexOf(bytes, Encoding.UTF8.GetBytes(compactUuid)) >= 0;
        }
        catch
        {
            return false;
        }
    }

    public static IReadOnlyList<string> RecordNameLookupCandidates(string recordName)
    {
        var names = new List<string>();
        void Add(string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return;
            if (!names.Contains(name, StringComparer.Ordinal))
                names.Add(name);
        }

        Add(recordName);
        foreach (var candidate in CloudKitRecordNames.FetchNameCandidates(recordName))
            Add(candidate);

        // Wire canonico A:… ↔ illusione length-byte XA:… (capture ASCII).
        if (CloudKitMmcsIds.ToPrivilegedBatchWireName(recordName) is { } wire)
        {
            Add(wire);
            foreach (var letter in new[] { 'K', 'M', 'L', 'N', 'J', 'O', 'P', 'Q' })
                Add($"{letter}{wire}");
        }

        if (recordName.Length > 2
            && recordName[1] == ':'
            && "KMLNJ".Contains(recordName[0]))
        {
            Add(recordName[1..]);
        }

        if (recordName.StartsWith("A:", StringComparison.Ordinal))
            Add($"K{recordName}");

        // F:{uuid}:{token}:{size}: ↔ UUID (flist rid).
        if (recordName.StartsWith("F:", StringComparison.Ordinal))
        {
            var uuid = CloudKitMmcsIds.CkRecordNameFromRid(recordName);
            Add(uuid);
        }
        else if (CloudKitMmcsIds.IsUuidRecordName(recordName))
        {
            // Il payload può citare il FileID completo accanto all'UUID.
            Add($"F:{recordName}");
        }
        else
        {
            var asFileId = CloudKitMmcsIds.ToMmcsFileId(recordName);
            Add(asFileId);
            Add(CloudKitMmcsIds.CkRecordNameFromRid(recordName));
        }

        return names;
    }

    /// <summary>Auth strutturato + regex, come lista di header pronti.</summary>
    public static IReadOnlyList<string> ExtractAllReadyMadeAuths(ReadOnlySpan<byte> payload)
    {
        var auths = new List<string>();
        foreach (var structured in ExtractStructuredAuths(payload.ToArray()))
        {
            if (!auths.Contains(structured.Header, StringComparer.Ordinal))
                auths.Add(structured.Header);
        }

        var text = Encoding.Latin1.GetString(payload);
        foreach (Match match in ReadyAuthRegex.Matches(text))
        {
            var auth =
                $"{match.Groups[1].Value.ToLowerInvariant()} {match.Groups[2].Value.ToLowerInvariant()} {match.Groups[3].Value}";
            if (!auths.Contains(auth, StringComparer.Ordinal))
                auths.Add(auth);
        }

        return auths;
    }

    public static string? ExtractReadyMadeAuth(ReadOnlySpan<byte> payload)
    {
        var all = ExtractAllReadyMadeAuths(payload);
        return all.Count > 0 ? all[0] : null;
    }

    public static bool AuthMatchesRecord(string auth, string recordName)
    {
        var parts = auth.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
            return false;

        try
        {
            var padded = parts[2].Replace('-', '+').Replace('_', '/');
            padded += (padded.Length % 4) switch
            {
                2 => "==",
                3 => "=",
                _ => string.Empty
            };
            var bytes = Convert.FromBase64String(padded);
            return IndexOf(bytes, Encoding.UTF8.GetBytes(recordName)) >= 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Record <c>MA:udid:uuid:checksumB64:size</c> o catalogo moderno
    /// <c>:CN:uuid:checksumB64</c> → SHA1 hex del checksum (20 B),
    /// confrontabile con i token f2/f17 di <c>x-apple-mmcs-auth</c> (senza prefisso 01/04).
    /// </summary>
    public static string? TryExtractAssetChecksumHex(string recordName)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            return null;

        // Moderno: :CN:uuid:checksum (nessun size suffix) — non usare la logica …:checksum:size.
        if (recordName.StartsWith(":CN:", StringComparison.OrdinalIgnoreCase)
            || recordName.StartsWith("CN:", StringComparison.OrdinalIgnoreCase))
        {
            var lastColon = recordName.LastIndexOf(':');
            if (lastColon <= 0 || lastColon >= recordName.Length - 1)
                return null;
            return TryDecodeChecksumToHex(recordName[(lastColon + 1)..]);
        }

        // TYPE:prefix4:…:checksum:size
        var sizeColon = recordName.LastIndexOf(':');
        if (sizeColon <= 0)
            return null;
        var beforeSize = recordName[..sizeColon];
        var checksumColon = beforeSize.LastIndexOf(':');
        if (checksumColon <= 0)
            return null;

        var checksumRaw = beforeSize[(checksumColon + 1)..];
        return TryDecodeChecksumToHex(checksumRaw);
    }

    /// <summary>SHA1 hex (40 char) dal token f2 (file checksum) di un header mmcs-auth.</summary>
    public static string? TryExtractFileChecksumHex(string authHeader)
    {
        var parts = authHeader.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 1)
            return null;
        return NormalizeAuthTokenChecksumHex(parts[0]);
    }

    /// <summary>
    /// Split <c>x-apple-mmcs-auth</c> → (sig21, companion21, CAog token).
    /// Per flist authorizeGet: sostituire sig21 con <c>Assets.assetSignature</c>.
    /// </summary>
    public static bool TrySplitMmcsAuth(
        string? mmcsAuth,
        out byte[] signature21,
        out byte[] companion21,
        out string authToken)
    {
        signature21 = [];
        companion21 = [];
        authToken = "";
        if (string.IsNullOrWhiteSpace(mmcsAuth))
            return false;

        var parts = mmcsAuth.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 3)
            return false;

        try
        {
            signature21 = FromAuthHexToken(parts[0]);
            companion21 = FromAuthHexToken(parts[1]);
            authToken = parts[2].Trim();
            return signature21.Length == 21
                   && companion21.Length == 21
                   && authToken.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>
    /// Entry authorizeGet flist: f1 = <c>Assets.assetSignature</c> verbatim
    /// (post-fileList: tipicamente <c>0x04‖20B</c>), f2/f4 da CK mmcs-auth
    /// (CAog + companion <c>0x01‖20B</c>). Non usare mai CK part0 come f1.
    /// </summary>
    public static UbChunkBuilder.AuthorizeGetFileEntry? TryBuildFlistAuthorizeEntry(
        byte[] assetSignature21,
        string? mmcsAuth)
    {
        if (assetSignature21 is not { Length: 21 })
            return null;
        if (!TrySplitMmcsAuth(mmcsAuth, out _, out var companion, out var token))
            return null;
        return new UbChunkBuilder.AuthorizeGetFileEntry(assetSignature21, token, companion);
    }

    /// <summary>
    /// SHA-1 hex (40 char) di una signature 21B — ignora il type-byte
    /// (<c>0x01</c>/<c>0x04</c>) per join flist↔CK.
    /// </summary>
    public static string? SignatureDigestHex(ReadOnlySpan<byte> signature21)
    {
        if (signature21.Length != 21)
            return null;
        return Convert.ToHexString(signature21[1..]).ToLowerInvariant();
    }

    /// <summary>
    /// True se due signature 21B condividono lo stesso digest 20B
    /// (type-byte <c>01</c>/<c>04</c> può differire).
    /// </summary>
    public static bool SameSignatureDigest(ReadOnlySpan<byte> a, ReadOnlySpan<byte> b) =>
        a.Length == 21 && b.Length == 21 && a[1..].SequenceEqual(b[1..]);

    private static byte[] FromAuthHexToken(string token)
    {
        if (token.Length % 2 == 0 && token.All(static c =>
                c is >= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F'))
            return Convert.FromHexString(token);
        return Encoding.UTF8.GetBytes(token);
    }

    /// <summary>
    /// Indice auth per hex completo del token f1/part0 (42 char, es. <c>04…</c> =
    /// <c>Assets.assetSignature</c>) e per digest 40 char (type-byte-agnostic).
    /// </summary>
    public static Dictionary<string, string> IndexAuthsBySignatureHex(
        IEnumerable<string> authHeaders)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var auth in authHeaders)
        {
            if (!TrySplitMmcsAuth(auth, out var sig, out _, out _))
                continue;
            if (sig.Length != 21)
                continue;
            var hex = Convert.ToHexString(sig).ToLowerInvariant();
            map.TryAdd(hex, auth);
            var digest = SignatureDigestHex(sig);
            if (digest is not null)
                map.TryAdd(digest, auth);
        }

        return map;
    }

    /// <summary>SHA1 hex (40 char) dai token f2/f17 di un header mmcs-auth.</summary>
    public static IReadOnlyList<string> ExtractAuthChecksumHexes(string authHeader)
    {
        var parts = authHeader.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length < 2)
            return [];

        var list = new List<string>(2);
        for (var i = 0; i < 2; i++)
        {
            var hex = NormalizeAuthTokenChecksumHex(parts[i]);
            if (hex is not null && !list.Contains(hex, StringComparer.OrdinalIgnoreCase))
                list.Add(hex);
        }

        return list;
    }

    /// <summary>True se f2 (file checksum) dell'auth coincide col checksum nel nome record.</summary>
    public static bool AuthChecksumMatchesRecord(string authHeader, string recordName)
    {
        var recordHex = TryExtractAssetChecksumHex(recordName);
        if (recordHex is null)
            return false;

        var f2 = TryExtractFileChecksumHex(authHeader);
        return f2 is not null && f2.Equals(recordHex, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>Primo auth il cui f2 matcha il checksum del record (o CAog contiene il nome).</summary>
    public static string? TryFindAuthForRecord(IEnumerable<string> authHeaders, string recordName)
    {
        string? caogHit = null;
        foreach (var auth in authHeaders)
        {
            if (string.IsNullOrWhiteSpace(auth))
                continue;
            if (AuthChecksumMatchesRecord(auth, recordName))
                return auth;
            if (caogHit is null && AuthMatchesRecord(auth, recordName))
                caogHit = auth;
        }

        return caogHit;
    }

    /// <summary>
    /// Indice f2 (file checksum) → auth per join PreAuth orfani ↔ catalogo MA:/KA:.
    /// Usa solo f2, non f17 (reference), per evitare false associazioni.
    /// </summary>
    public static Dictionary<string, string> IndexAuthsByChecksum(IEnumerable<string> authHeaders)
    {
        var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var auth in authHeaders)
        {
            if (string.IsNullOrWhiteSpace(auth))
                continue;
            var f2 = TryExtractFileChecksumHex(auth);
            if (f2 is null || map.ContainsKey(f2))
                continue;
            map[f2] = auth;
        }

        return map;
    }

    private static string? NormalizeAuthTokenChecksumHex(string token)
    {
        if (string.IsNullOrWhiteSpace(token))
            return null;

        var t = token.Trim();
        if (t.Length == 42 && (t.StartsWith("01", StringComparison.OrdinalIgnoreCase)
                               || t.StartsWith("04", StringComparison.OrdinalIgnoreCase)))
            t = t[2..];

        if (t.Length != 40 || !IsHexString(t))
            return null;
        return t.ToLowerInvariant();
    }

    private static string? TryDecodeChecksumToHex(string raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;

        var cleaned = CloudKitManifestChecksumParser.CleanCnChecksum(raw);
        foreach (var candidate in new[] { raw.Trim(), cleaned, cleaned + "=", cleaned + "==" })
        {
            if (string.IsNullOrEmpty(candidate))
                continue;

            // Già hex SHA1?
            if (candidate.Length == 40 && IsHexString(candidate))
                return candidate.ToLowerInvariant();

            try
            {
                var padded = candidate.Replace('-', '+').Replace('_', '/');
                padded += (padded.Length % 4) switch
                {
                    2 => "==",
                    3 => "=",
                    _ => string.Empty
                };
                var bytes = Convert.FromBase64String(padded);
                if (bytes.Length == 20)
                    return Convert.ToHexString(bytes).ToLowerInvariant();
            }
            catch
            {
                // try next form
            }
        }

        return null;
    }

    private static bool IsHexString(string value)
    {
        foreach (var c in value)
        {
            if (c is not (>= '0' and <= '9' or >= 'a' and <= 'f' or >= 'A' and <= 'F'))
                return false;
        }

        return true;
    }

    public static string Build(string recordName, string fileChecksum, string referenceChecksum, byte[]? authProtobuf = null)
    {
        authProtobuf ??= BuildAuthProtobuf(recordName, fileChecksum);
        return $"01{fileChecksum} 01{referenceChecksum} {Base64Url(authProtobuf)}";
    }

    public sealed record StructuredAuth(string Header, string? RecordName);

    /// <summary>
    /// Estrae header <c>x-apple-mmcs-auth</c> = <c>hex(f2) hex(f17) f5</c>
    /// (f2/f17 = token 21 byte, f5 = CAog Foreground Restore firmato).
    /// </summary>
    public static IReadOnlyList<StructuredAuth> ExtractStructuredAuths(byte[] payload)
    {
        var results = new List<StructuredAuth>();
        foreach (var frame in EnumerateDelimitedFrames(payload))
            WalkForAuth(frame, results, 0);

        if (results.Count == 0)
            WalkForAuth(payload, results, 0);

        // PreAuth: f2/f5/f17 sono sibling ma il tree-walk spesso non li vede insieme.
        ScanSequentialAuths(payload, results);
        return results;
    }

    private static IEnumerable<byte[]> EnumerateDelimitedFrames(byte[] data)
    {
        var index = 0;
        var yielded = false;
        while (index < data.Length)
        {
            var save = index;
            if (!TryReadVarint(data, ref index, out var len)
                || len == 0
                || len > (ulong)(data.Length - index))
            {
                index = save;
                break;
            }

            yield return data.AsSpan(index, (int)len).ToArray();
            index += (int)len;
            yielded = true;
        }

        if (!yielded)
            yield break;
    }

    /// <summary>
    /// Wire scan: <c>12 15 01…</c> (f2) → <c>2a … CAog</c> (f5) → <c>8a 01 15 01…</c> (f17).
    /// </summary>
    private static void ScanSequentialAuths(byte[] data, List<StructuredAuth> results)
    {
        for (var i = 0; i + 24 < data.Length; i++)
        {
            if (data[i] != 0x12 || data[i + 1] != 0x15)
                continue;
            if (data[i + 2] is not (0x01 or 0x04))
                continue;

            var f2 = data.AsSpan(i + 2, 21).ToArray();
            var caogTag = IndexOfCaogTag(data, i + 23, i + 23 + 96);
            if (caogTag < 0)
                continue;

            if (!TryReadLengthDelimited(data, caogTag, out var f5Start, out var f5Len)
                || f5Len is < 160 or > 300
                || f5Start + f5Len > data.Length)
                continue;

            var f5 = data.AsSpan(f5Start, f5Len).ToArray();
            if (f5.Length < 4
                || f5[0] != (byte)'C' || f5[1] != (byte)'A'
                || f5[2] != (byte)'o' || f5[3] != (byte)'g'
                || !LooksBase64Url(f5)
                || !CaogLooksForegroundSigned(f5))
                continue;

            var f17Value = IndexOfField17Token(data, f5Start + f5Len, f5Start + f5Len + 160);
            if (f17Value < 0)
                continue;

            var f17 = data.AsSpan(f17Value, 21).ToArray();
            var header = $"{Convert.ToHexString(f2).ToLowerInvariant()} " +
                         $"{Convert.ToHexString(f17).ToLowerInvariant()} " +
                         $"{Encoding.Latin1.GetString(f5)}";
            if (results.Any(r => r.Header == header))
                continue;

            var windowStart = Math.Max(0, i - 2048);
            var windowEnd = Math.Min(data.Length, f17Value + 21 + 2048);
            var recordName = FindRecordName(data[windowStart..windowEnd], preferMa: true);
            results.Add(new StructuredAuth(header, recordName));
        }
    }

    private static int IndexOfCaogTag(byte[] data, int from, int to)
    {
        to = Math.Min(to, data.Length - 4);
        for (var i = from; i < to; i++)
        {
            if (data[i] != 0x2A)
                continue;

            var idx = i + 1;
            if (!TryReadVarint(data, ref idx, out var len) || len is < 160 or > 300)
                continue;

            if (idx + 4 <= data.Length
                && data[idx] == (byte)'C'
                && data[idx + 1] == (byte)'A'
                && data[idx + 2] == (byte)'o'
                && data[idx + 3] == (byte)'g')
                return i;
        }

        return -1;
    }

    private static int IndexOfField17Token(byte[] data, int from, int to)
    {
        to = Math.Min(to, data.Length - 24);
        for (var i = from; i < to; i++)
        {
            if (data[i] == 0x8A && data[i + 1] == 0x01 && data[i + 2] == 0x15
                && data[i + 3] is 0x01 or 0x04)
                return i + 3;
        }

        return -1;
    }

    private static bool TryReadLengthDelimited(byte[] data, int tagIndex, out int valueStart, out int valueLen)
    {
        valueStart = 0;
        valueLen = 0;
        var idx = tagIndex + 1;
        if (!TryReadVarint(data, ref idx, out var len))
            return false;
        valueStart = idx;
        valueLen = (int)len;
        return true;
    }

    /// <summary>CAog FG firmati: decode → <c>08 0a 20</c>… + stringa Foreground Restore.</summary>
    private static bool CaogLooksForegroundSigned(byte[] base64Url)
    {
        try
        {
            var padded = Encoding.Latin1.GetString(base64Url).Replace('-', '+').Replace('_', '/');
            padded += (padded.Length % 4) switch
            {
                2 => "==",
                3 => "=",
                _ => string.Empty
            };
            var raw = Convert.FromBase64String(padded);
            return raw.Length >= 40
                   && raw[0] == 0x08 && raw[1] == 0x0A && raw[2] == 0x20
                   && IndexOf(raw, "Foreground Restore"u8) >= 0;
        }
        catch
        {
            return false;
        }
    }

    private static void WalkForAuth(byte[] message, List<StructuredAuth> results, int depth)
    {
        if (depth > 16)
            return;

        var fields = ReadFields(message);

        if (fields.TryGetValue(2, out var f2)
            && fields.TryGetValue(5, out var f5)
            && fields.TryGetValue(17, out var f17)
            && f2.Length == 21 && f17.Length == 21
            && LooksBase64Url(f5))
        {
            var header = $"{Convert.ToHexString(f2).ToLowerInvariant()} " +
                         $"{Convert.ToHexString(f17).ToLowerInvariant()} " +
                         $"{Encoding.Latin1.GetString(f5)}";
            var recordName = FindRecordName(message);
            if (!results.Any(r => r.Header == header))
                results.Add(new StructuredAuth(header, recordName));
        }

        foreach (var child in ReadSubMessages(message))
            WalkForAuth(child, results, depth + 1);
    }

    /// <summary>Legge i campi length-delimited diretti (primo valore per numero).</summary>
    private static Dictionary<int, byte[]> ReadFields(byte[] buffer)
    {
        var fields = new Dictionary<int, byte[]>();
        var index = 0;
        while (index < buffer.Length)
        {
            if (!TryReadVarint(buffer, ref index, out var tag))
                break;

            var fieldNumber = (int)(tag >> 3);
            var wire = (int)(tag & 7);
            switch (wire)
            {
                case 0:
                    if (!TryReadVarint(buffer, ref index, out _))
                        return fields;
                    break;
                case 1:
                    index += 8;
                    break;
                case 2:
                    if (!TryReadVarint(buffer, ref index, out var len)
                        || len > (ulong)(buffer.Length - index))
                        return fields;
                    if (!fields.ContainsKey(fieldNumber))
                        fields[fieldNumber] = buffer.AsSpan(index, (int)len).ToArray();
                    index += (int)len;
                    break;
                case 5:
                    index += 4;
                    break;
                default:
                    return fields;
            }
        }

        return fields;
    }

    private static IEnumerable<byte[]> ReadSubMessages(byte[] buffer)
    {
        var children = new List<byte[]>();
        var index = 0;
        while (index < buffer.Length)
        {
            if (!TryReadVarint(buffer, ref index, out var tag))
                break;

            var wire = (int)(tag & 7);
            switch (wire)
            {
                case 0:
                    if (!TryReadVarint(buffer, ref index, out _))
                        return children;
                    break;
                case 1:
                    index += 8;
                    break;
                case 2:
                    if (!TryReadVarint(buffer, ref index, out var len)
                        || len > (ulong)(buffer.Length - index))
                        return children;
                    if (len >= 4)
                        children.Add(buffer.AsSpan(index, (int)len).ToArray());
                    index += (int)len;
                    break;
                case 5:
                    index += 4;
                    break;
                default:
                    return children;
            }
        }

        return children;
    }

    private static readonly Regex AssetNameRegex = new(
        @"(?:KA|MA|LA|NA|JA|A):[0-9a-f]{4}:[^\s\x00-\x1f""]{8,200}",
        RegexOptions.Compiled);

    private static string? FindRecordName(byte[] message, bool preferMa = false)
    {
        var text = Encoding.Latin1.GetString(message);
        var matches = AssetNameRegex.Matches(text);
        if (matches.Count == 0)
            return null;

        if (preferMa)
        {
            foreach (Match m in matches)
            {
                if (m.Value.StartsWith("MA:", StringComparison.Ordinal))
                    return m.Value;
            }
        }

        return matches[0].Value;
    }

    private static bool LooksBase64Url(byte[] data)
    {
        if (data.Length < 20)
            return false;

        var ok = 0;
        foreach (var b in data)
        {
            var c = (char)b;
            if (c is (>= 'A' and <= 'Z') or (>= 'a' and <= 'z') or (>= '0' and <= '9') or '-' or '_' or '=')
                ok++;
        }

        return (double)ok / data.Length > 0.95;
    }

    private static bool TryReadVarint(byte[] data, ref int index, out ulong value)
    {
        value = 0;
        var shift = 0;
        while (index < data.Length)
        {
            var b = data[index++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
            if (shift > 63)
                break;
        }

        return false;
    }

    private static byte[] BuildAuthProtobuf(string recordName, string checksum)
    {
        var writer = new ProtobufWriter();
        writer.WriteVarint(1, 10);
        writer.WriteBytes(4, Encoding.UTF8.GetBytes(recordName));
        writer.WriteVarint(6, 1);
        writer.WriteBytes(10, Encoding.UTF8.GetBytes(checksum));
        return writer.ToArray();
    }

    private static int IndexOf(ReadOnlySpan<byte> haystack, ReadOnlySpan<byte> needle)
    {
        for (var i = 0; i <= haystack.Length - needle.Length; i++)
        {
            if (haystack.Slice(i, needle.Length).SequenceEqual(needle))
                return i;
        }

        return -1;
    }

    private static string Base64Url(byte[] data) =>
        Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}
