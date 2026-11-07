using System.Buffers.Binary;
using System.IO;
using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

public static class CloudKitResponseParser
{
    private static readonly Regex AssetRecordRegex = new(
        @"(?:^|[^\w])(?:[A-Z])?(A:[0-9a-f]{4}:[^\s\x00-\x1f]{8,320})",
        RegexOptions.Compiled | RegexOptions.IgnoreCase);

    private static readonly Regex AssetRecordLineRegex = new(
        @"^(?:[A-Z]A|A):[^\s\x00-\x1f]{8,320}$",
        RegexOptions.Compiled);

    private static readonly Regex KeybagRegex = new(
        @"^K:[A-Za-z0-9+/=]{8,120}$",
        RegexOptions.Compiled);

    public static IReadOnlyList<string> ExtractAssetRecordNames(byte[]? payload, int maxRecords = 50_000)
    {
        if (payload is not { Length: > 0 })
            return [];

        var names = new HashSet<string>(StringComparer.Ordinal);
        void AddName(string? raw)
        {
            var name = CloudKitMmcsIds.ToPrivilegedBatchWireName(raw) ?? raw;
            if (!string.IsNullOrWhiteSpace(name))
                names.Add(name);
        }

        foreach (var s in CollectStrings(payload))
        {
            if (AssetRecordLineRegex.IsMatch(s))
                AddName(s);
            if (names.Count >= maxRecords)
                break;
        }

        foreach (Match m in AssetRecordRegex.Matches(System.Text.Encoding.UTF8.GetString(payload)))
        {
            AddName(m.Groups[1].Value);
            if (names.Count >= maxRecords)
                break;
        }

        return names
            .OrderBy(static n => AssetPriority(n))
            .ThenBy(static n => n, StringComparer.Ordinal)
            .ToList();
    }

    /// <summary>
    /// Motivo leggibile da payload errore CloudKit (es. «Optional feature disabled…»).
    /// Preferisce frasi umane rispetto a UUID / errorKey <c>ck…</c>.
    /// </summary>
    public static string? TryGetCloudKitReason(byte[]? payload)
    {
        if (payload is not { Length: > 0 })
            return null;

        string? bestHuman = null;
        string? bestCk = null;
        foreach (var s in CollectStrings(payload))
        {
            if (string.IsNullOrWhiteSpace(s) || s.Length < 5)
                continue;
            if (LooksLikeUuidOrOwner(s))
                continue;

            if (IsHumanCloudKitError(s))
            {
                if (bestHuman is null || s.Length > bestHuman.Length)
                    bestHuman = s;
                continue;
            }

            if (s.Length is >= 5 and <= 16
                && s.StartsWith("ck", StringComparison.OrdinalIgnoreCase)
                && s.Skip(2).All(char.IsLetterOrDigit))
                bestCk ??= s;
        }

        if (bestHuman is not null)
        {
            var msg = bestHuman.Length > 160 ? bestHuman[..160] + "…" : bestHuman;
            return bestCk is null ? msg : $"{msg} ({bestCk})";
        }

        return bestCk;
    }

    /// <summary>Diagnostica risposte CloudKit troppo piccole (stub/error).</summary>
    public static string? DescribeCompactPayload(byte[]? payload)
    {
        if (payload is not { Length: > 0 and < 512 })
            return TryGetCloudKitReason(payload);

        var reason = TryGetCloudKitReason(payload);
        if (reason is not null)
            return reason;

        var runs = CollectStrings(payload)
            .Where(static s => s.Length >= 6 && !LooksLikeUuidOrOwner(s))
            .Take(4)
            .ToList();
        return runs.Count > 0 ? string.Join(" | ", runs) : $"binary {payload.Length} byte";
    }

    /// <summary>
    /// True se il payload è una ResponseOperation di errore (FAILURE / missing filter / not found).
    /// </summary>
    public static bool IsCloudKitErrorPayload(byte[]? payload, out string? description)
    {
        description = null;
        if (payload is not { Length: > 0 })
            return false;

        var reason = TryGetCloudKitReason(payload);
        if (reason is not null && IsHumanCloudKitError(reason.Split('(')[0].TrimEnd()))
        {
            description = reason;
            return true;
        }

        foreach (var s in CollectStrings(payload))
        {
            if (s.Contains("missing filter", StringComparison.OrdinalIgnoreCase)
                || s.Contains("Record not found", StringComparison.OrdinalIgnoreCase)
                || s.Contains("BAD_SYNTAX", StringComparison.OrdinalIgnoreCase)
                || s.Equals("notFound", StringComparison.OrdinalIgnoreCase)
                || s.Equals("FAILURE", StringComparison.OrdinalIgnoreCase))
            {
                description = s.Length > 160 ? s[..160] + "…" : s;
                return true;
            }
        }

        // Errori tipici: body &lt; 200 B con "ck" errorKey.
        if (payload.Length < 200)
        {
            description = DescribeCompactPayload(payload) ?? reason;
            if (description is not null
                && (description.Contains("ck", StringComparison.OrdinalIgnoreCase)
                    || description.Contains("error", StringComparison.OrdinalIgnoreCase)
                    || description.Contains("fail", StringComparison.OrdinalIgnoreCase)
                    || description.Contains("disabled", StringComparison.OrdinalIgnoreCase)
                    || description.Contains("not exist", StringComparison.OrdinalIgnoreCase)
                    || description.Contains("not support", StringComparison.OrdinalIgnoreCase)))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Nomi header HTTP/MMCS spesso embedded nei template edge (es. nel body
    /// PrivilegedBatch OK compare la stringa <c>X-Apple-Error-Info</c> come
    /// chiave header da inviare a content, non come errore CloudKit).
    /// </summary>
    private static bool IsAppleHttpHeaderName(string s)
    {
        if (string.IsNullOrWhiteSpace(s) || s.Length > 64 || s.Contains(' '))
            return false;
        return s.StartsWith("X-Apple-", StringComparison.OrdinalIgnoreCase)
               || s.StartsWith("x-apple-", StringComparison.OrdinalIgnoreCase)
               || s.StartsWith("x-cloudkit-", StringComparison.OrdinalIgnoreCase)
               || s.Equals("Accept", StringComparison.OrdinalIgnoreCase)
               || s.Equals("Range", StringComparison.OrdinalIgnoreCase)
               || s.Equals("Host", StringComparison.OrdinalIgnoreCase)
               || s.Equals("Date", StringComparison.OrdinalIgnoreCase)
               || s.Equals("Server", StringComparison.OrdinalIgnoreCase);
    }

    private static bool IsHumanCloudKitError(string s)
    {
        if (s.Length < 8)
            return false;
        // Mai trattare il solo nome header come reason (falso positivo PB/MMCS).
        if (IsAppleHttpHeaderName(s))
            return false;
        // Bundle ID / dominio backup (es. com.apple.askpermissiond) NON sono errori:
        // "permission" da solo faceva scartare M: validi come payload vuoto.
        if (LooksLikeAppleBundleOrDomain(s))
            return false;
        return s.Contains("error", StringComparison.OrdinalIgnoreCase)
            || s.Contains("notFound", StringComparison.OrdinalIgnoreCase)
            || s.Contains("not found", StringComparison.OrdinalIgnoreCase)
            || s.Contains("permission denied", StringComparison.OrdinalIgnoreCase)
            || s.Contains("PERMISSION_DENIED", StringComparison.OrdinalIgnoreCase)
            || s.Contains("insufficient permissions", StringComparison.OrdinalIgnoreCase)
            || s.Contains("retry", StringComparison.OrdinalIgnoreCase)
            || s.Contains("missing filter", StringComparison.OrdinalIgnoreCase)
            || s.Contains("BAD_SYNTAX", StringComparison.OrdinalIgnoreCase)
            || s.Contains("disabled", StringComparison.OrdinalIgnoreCase)
            || s.Contains("not exist", StringComparison.OrdinalIgnoreCase)
            || s.Contains("does not exist", StringComparison.OrdinalIgnoreCase)
            || s.Contains("not support", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Only custom zones", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Optional feature", StringComparison.OrdinalIgnoreCase)
            || s.Contains("Feature not", StringComparison.OrdinalIgnoreCase)
            || s.Contains("unauthorized", StringComparison.OrdinalIgnoreCase)
            || s.Contains("unauthenticated", StringComparison.OrdinalIgnoreCase)
            || s.Contains("forbidden", StringComparison.OrdinalIgnoreCase)
            || s.Contains("quota", StringComparison.OrdinalIgnoreCase)
            || s.Contains("throttl", StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Bundle ID / entitlement / domain tipici nei record Manifest (files),
    /// non messaggi di errore CloudKit.
    /// </summary>
    private static bool LooksLikeAppleBundleOrDomain(string s)
    {
        if (string.IsNullOrWhiteSpace(s))
            return false;
        var t = s.TrimStart('-', '+', ' ', '\t');
        return t.StartsWith("com.apple.", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("group.com.apple.", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("systemgroup.", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("AppDomain-", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("AppDomainGroup-", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("HomeDomain", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("CameraRollDomain", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("MediaDomain", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("WirelessDomain", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("DatabaseDomain", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("KeychainDomain", StringComparison.OrdinalIgnoreCase)
               || t.StartsWith("RootDomain", StringComparison.OrdinalIgnoreCase)
               || t.Contains("CanModifyAppLinkPermissions", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksLikeUuidOrOwner(string s)
    {
        if (s.Length is >= 32 and <= 40 && s.TrimStart('_', '$', '!').All(Uri.IsHexDigit))
            return true;
        if (s.Length == 36
            && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-')
            return true;
        if (s.StartsWith('_') && s.Length >= 20 && s[1..].All(Uri.IsHexDigit))
            return true;
        return false;
    }

    public static IReadOnlyList<string> ExtractKeybags(byte[]? payload)
    {
        if (payload is not { Length: > 0 })
            return [];

        var bags = new HashSet<string>(StringComparer.Ordinal);
        foreach (var s in CollectStrings(payload))
        {
            if (KeybagRegex.IsMatch(s))
                bags.Add(s);
        }

        foreach (var blob in ExtractEmbeddedKeybagBlobs(payload))
            bags.Add("K:" + Convert.ToBase64String(blob));

        return bags.OrderBy(static s => s, StringComparer.Ordinal).ToList();
    }

    /// <summary>
    /// <c>K:</c> + UUID 16 byte in base64 (riferimento record), non il TLV completo.
    /// </summary>
    public static bool IsKeybagRecordId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value) || !value.StartsWith("K:", StringComparison.Ordinal))
            return false;

        try
        {
            var data = Convert.FromBase64String(value[2..]);
            return data.Length == 16;
        }
        catch
        {
            return false;
        }
    }

    /// <summary>True se <paramref name="value"/> è un blob TLV TYPE/SALT/WPKY parsabile.</summary>
    public static bool IsFullKeybagBlob(string? value) =>
        !string.IsNullOrWhiteSpace(value)
        && IosKeybag.TryParse(value, out var kb, out _)
        && kb is not null;

    /// <summary>
    /// Estrae campi bytes nominati (es. <c>keybagData</c>, <c>secret</c>) dal wire CloudKit.
    /// </summary>
    public static IReadOnlyDictionary<string, byte[]> ExtractNamedByteFields(
        byte[] payload,
        params string[] fieldNames)
    {
        var result = new Dictionary<string, byte[]>(StringComparer.Ordinal);
        if (payload.Length == 0 || fieldNames.Length == 0)
            return result;

        foreach (var name in fieldNames)
        {
            if (string.IsNullOrEmpty(name) || result.ContainsKey(name))
                continue;

            var key = System.Text.Encoding.ASCII.GetBytes(name);
            var searchFrom = 0;
            while (searchFrom < payload.Length)
            {
                var rel = payload.AsSpan(searchFrom).IndexOf(key);
                if (rel < 0)
                    break;

                var after = searchFrom + rel + key.Length;
                if (TryReadNextLengthDelimitedBytes(payload, after, out var bytes)
                    && bytes.Length >= 16
                    && !result.ContainsKey(name))
                {
                    result[name] = bytes;
                    break;
                }

                searchFrom += rel + 1;
            }
        }

        return result;
    }

    private static bool TryReadNextLengthDelimitedBytes(byte[] data, int offset, out byte[] value)
    {
        value = [];
        for (var probe = offset; probe < offset + 6 && probe < data.Length; probe++)
        {
            var pos = probe;
            try
            {
                var tag = ReadVarintLocal(data, ref pos);
                if ((tag & 0x7) != 2)
                    continue;

                var len = (int)ReadVarintLocal(data, ref pos);
                if (len is < 1 or > 1_048_576 || pos + len > data.Length)
                    continue;

                value = data.AsSpan(pos, len).ToArray();
                return true;
            }
            catch
            {
                // next probe
            }
        }

        return false;
    }

    private static ulong ReadVarintLocal(byte[] data, ref int pos)
    {
        ulong result = 0;
        var shift = 0;
        while (pos < data.Length)
        {
            var b = data[pos++];
            result |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return result;
            shift += 7;
            if (shift > 63)
                throw new InvalidDataException("Varint troppo lungo.");
        }

        throw new InvalidDataException("Varint troncato.");
    }

    /// <summary>Cerca keybag TLV binari (TYPE/SALT/WPKY) embedded nel payload protobuf.</summary>
    public static IReadOnlyList<byte[]> ExtractEmbeddedKeybagBlobs(byte[] payload)
    {
        var results = new List<byte[]>();
        for (var i = 0; i <= payload.Length - 48; i++)
        {
            if (payload[i] != (byte)'T' || payload[i + 1] != (byte)'Y'
                || payload[i + 2] != (byte)'P' || payload[i + 3] != (byte)'E')
                continue;

            if (!TryMeasureKeybagBlob(payload, i, out var end))
                continue;

            var slice = payload[i..end];
            if (slice.Length is >= 64 and <= 65536
                && !results.Any(b => b.AsSpan().SequenceEqual(slice)))
            {
                results.Add(slice);
            }
        }

        return results;
    }

    private static bool TryMeasureKeybagBlob(byte[] data, int start, out int end)
    {
        end = start;
        var offset = start;
        var hasSalt = false;
        var hasWpky = false;

        while (offset + 8 <= data.Length)
        {
            if (data[offset] < 0x20 || data[offset + 1] < 0x20)
                break;

            var tag = System.Text.Encoding.ASCII.GetString(data, offset, 4);
            if (tag.Any(c => c < 32 || c >= 127))
                break;

            var len = BinaryPrimitives.ReadInt32BigEndian(data.AsSpan(offset + 4, 4));
            if (len < 0 || len > 65536 || offset + 8 + len > data.Length)
                break;

            if (tag == "SALT")
                hasSalt = true;
            if (tag == "WPKY")
                hasWpky = true;

            offset += 8 + len;
            end = offset;

            if (hasSalt && hasWpky && offset - start >= 64)
                return true;
        }

        return hasSalt && hasWpky && end > start;
    }

    public static bool ResponseIndicatesMoreResults(byte[]? payload)
    {
        if (payload is null || payload.Length == 0)
            return false;

        var cont = TryExtractRecordSyncContinuation(payload);
        if (cont.MoreComing)
            return true;

        foreach (var s in CollectStrings(payload))
        {
            if (s.Contains("moreComing", StringComparison.OrdinalIgnoreCase))
                return true;
        }

        return false;
    }

    /// <summary>
    /// Estrae <c>syncContinuationToken</c> + <c>moreComing</c> da
    /// <c>ResponseOperation.recordRetrieveChangesResponse</c> (field 213).
    /// Schema tipico: f1=changes*, f2=token, f3=moreComing.
    /// </summary>
    public static RecordSyncContinuation TryExtractRecordSyncContinuation(byte[]? payload)
    {
        if (payload is not { Length: > 8 })
            return default;

        byte[]? token = null;
        var moreComing = false;
        var found213 = false;

        // Le risposte record/sync sono messaggi *delimited*: varint(len) ‖ message.
        // Senza rimuovere il prefisso, il walker interpreta il varint iniziale come
        // tag e si desincronizza (token mai estratto).
        var message = StripDelimitedLengthPrefix(payload);

        try
        {
            WalkRecordSyncResponse(message, depth: 0, ref token, ref moreComing, ref found213);
        }
        catch
        {
            /* payload malformato / troncato */
        }

        _ = found213;
        return new RecordSyncContinuation(token, moreComing);
    }

    /// <summary>
    /// Paginazione record/sync (CloudDocs, Notes, …): continua se moreComing, oppure se il server
    /// restituisce un sync token ma zero record nella pagina corrente (handshake pre-batch).
    /// </summary>
    public static bool ShouldContinueRecordSyncPagination(
        RecordSyncContinuation cont,
        ReadOnlySpan<byte> sentToken,
        int pageRecordCount,
        bool stringMore)
    {
        if (cont.SyncContinuationToken is not { Length: > 0 })
            return false;
        if (cont.MoreComing || stringMore)
            return true;
        if (pageRecordCount > 0)
            return false;
        return sentToken.Length == 0
               || !sentToken.SequenceEqual(cont.SyncContinuationToken);
    }

    /// <summary>
    /// Rimuove il prefisso di lunghezza varint dei messaggi CloudKit <c>delimited=true</c>
    /// (<c>varint(len) ‖ message</c>). Se il varint iniziale corrisponde alla lunghezza
    /// del resto del payload, restituisce solo il messaggio; altrimenti il payload intero.
    /// </summary>
    private static byte[] StripDelimitedLengthPrefix(byte[] payload)
    {
        if (payload.Length < 2)
            return payload;

        var shift = 0;
        var value = 0L;
        var i = 0;
        while (i < payload.Length && i < 10)
        {
            var b = payload[i++];
            value |= (long)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
            {
                var remaining = payload.Length - i;
                if (value == remaining && remaining > 0)
                    return payload[i..];
                return payload;
            }
            shift += 7;
        }

        return payload;
    }

    private static void WalkRecordSyncResponse(
        byte[] data,
        int depth,
        ref byte[]? token,
        ref bool moreComing,
        ref bool found213)
    {
        if (depth > 6 || data.Length == 0)
            return;

        var reader = new ProtobufReader(data);
        while (reader.HasMore)
        {
            int field;
            int wire;
            try
            {
                (field, wire) = reader.ReadTag();
            }
            catch
            {
                break;
            }

            if (wire == 2)
            {
                if (!reader.TryReadLengthDelimited(out var slice))
                    break;

                // f4 vuoto precede spesso f213 (recordRetrieveChangesResponse) — non interrompere.
                if (slice.Length == 0)
                    continue;

                if (field == 213)
                {
                    found213 = true;
                    ParseRetrieveChangesResponse(slice, ref token, ref moreComing);
                }
                else if (depth < 4)
                {
                    WalkRecordSyncResponse(slice, depth + 1, ref token, ref moreComing, ref found213);
                }
            }
            else
            {
                try
                {
                    reader.SkipField(wire);
                }
                catch
                {
                    break;
                }
            }
        }
    }

    private static void ParseRetrieveChangesResponse(
        byte[] body,
        ref byte[]? token,
        ref bool moreComing)
    {
        var reader = new ProtobufReader(body);
        while (reader.HasMore)
        {
            int field;
            int wire;
            try
            {
                (field, wire) = reader.ReadTag();
            }
            catch
            {
                break;
            }

            if (wire == 2 && field == 2)
            {
                if (reader.TryReadLengthDelimited(out var t) && t.Length is >= 8 and <= 512)
                    token = t;
            }
            else if (wire == 0 && field == 3)
            {
                try
                {
                    // Schema CK classico: f3 = moreComing bool.
                    moreComing = reader.ReadVarint() != 0;
                }
                catch
                {
                    break;
                }
            }
            else if (wire == 0 && field == 4)
            {
                try
                {
                    // CloudDocs client RetrieveChangesResponse: niente f3;
                    // f4=1 ⇒ moreComing (00514 handshake + live WA sync),
                    // f4=3 ⇒ pagina completa / stop (light zone syncs).
                    var status = reader.ReadVarint();
                    if (status == 1)
                        moreComing = true;
                }
                catch
                {
                    break;
                }
            }
            else if (wire == 2 && field == 1)
            {
                // change record — skip
                if (!reader.TryReadLengthDelimited(out _))
                    break;
            }
            else
            {
                try
                {
                    reader.SkipField(wire);
                }
                catch
                {
                    break;
                }
            }
        }
    }

    public readonly record struct RecordSyncContinuation(byte[]? SyncContinuationToken, bool MoreComing);

    private static int AssetPriority(string recordName)
    {
        if (recordName.StartsWith("KA:", StringComparison.Ordinal)) return 0;
        if (recordName.StartsWith("MA:", StringComparison.Ordinal)) return 1;
        if (recordName.StartsWith("LA:", StringComparison.Ordinal)) return 2;
        if (recordName.StartsWith("NA:", StringComparison.Ordinal)) return 3;
        if (recordName.StartsWith("JA:", StringComparison.Ordinal)) return 4;
        return 5;
    }

    /// <summary>Stringhe UTF-8 stampabili dal payload (diagnostica container generici).</summary>
    public static IReadOnlyList<string> ExtractDiagnosticStrings(byte[]? payload, int max = 200)
    {
        if (payload is not { Length: > 0 })
            return [];

        return CollectStrings(payload)
            .Where(static s => s.Length >= 4)
            .Distinct(StringComparer.Ordinal)
            .Take(max)
            .ToList();
    }

    /// <summary>
    /// Diagnostica errori opachi (X-Apple-Error-Info): size, hex, chiavi <c>ck*</c>,
    /// tutte le stringhe ASCII/UTF-8 utili. Per capire se c’è reason/id oltre al nome header.
    /// </summary>
    public static string FormatErrorPayloadDiagnostics(byte[]? payload, int maxStrings = 48)
    {
        if (payload is not { Length: > 0 })
            return "payload=vuoto";

        var strings = ExtractDiagnosticStrings(payload, maxStrings);
        var ckKeys = strings
            .Where(static s =>
                s.Length is >= 5 and <= 24
                && s.StartsWith("ck", StringComparison.OrdinalIgnoreCase)
                && s.Skip(2).All(char.IsLetterOrDigit))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .Take(12)
            .ToList();
        var interesting = strings
            .Where(static s =>
                s.Contains("error", StringComparison.OrdinalIgnoreCase)
                || s.Contains("throttl", StringComparison.OrdinalIgnoreCase)
                || s.Contains("retry", StringComparison.OrdinalIgnoreCase)
                || s.Contains("rate", StringComparison.OrdinalIgnoreCase)
                || s.Contains("limit", StringComparison.OrdinalIgnoreCase)
                || s.Contains("quota", StringComparison.OrdinalIgnoreCase)
                || s.Contains("fail", StringComparison.OrdinalIgnoreCase)
                || s.Contains("denied", StringComparison.OrdinalIgnoreCase)
                || s.Contains("forbidden", StringComparison.OrdinalIgnoreCase)
                || s.Contains("Apple", StringComparison.OrdinalIgnoreCase)
                || s.Contains("CloudKit", StringComparison.OrdinalIgnoreCase)
                || s.Contains("try again", StringComparison.OrdinalIgnoreCase))
            .Take(16)
            .ToList();
        var hexLen = Math.Min(payload.Length, 96);
        var hex = Convert.ToHexString(payload.AsSpan(0, hexLen));
        if (payload.Length > hexLen)
            hex += "…";

        static string JoinClip(IReadOnlyList<string> items, int maxItem = 96)
        {
            if (items.Count == 0)
                return "—";
            return string.Join(" | ", items.Select(s =>
                s.Length <= maxItem ? s : s[..maxItem] + "…"));
        }

        return
            $"len={payload.Length} " +
            $"ck=[{JoinClip(ckKeys, 32)}] " +
            $"hit=[{JoinClip(interesting, 120)}] " +
            $"all=[{JoinClip(strings.Take(24).ToList(), 80)}] " +
            $"hex={hex}";
    }

    private static IEnumerable<string> CollectStrings(byte[] payload)
    {
        foreach (var s in ProtobufStringScanner.ExtractDelimited(payload))
            yield return s;
        foreach (var s in ProtobufStringScanner.ExtractAsciiRuns(payload, 8))
            yield return s;
    }
}
