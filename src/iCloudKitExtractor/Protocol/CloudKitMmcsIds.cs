using System.Text.RegularExpressions;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Identità file da flist <c>Assets.recordIDSuffix</c> (rid):
/// <list type="bullet">
/// <item>CloudKit PrivilegedBatch wire: <c>A:{pref4}:{rid}</c> (UUID nudo → NOT_FOUND)</item>
/// <item>FileID/MMCS: <c>F:{uuid}:{token}:{size}:</c></item>
/// <item>
/// Apparenze <c>KA:/MA:/LA:/NA:</c> nelle capture ASCII sono illusorie: il byte di
/// length protobuf (0x4B/4D/4C/4E…) precede <c>A:</c>. manda sempre <c>A:</c>.
/// </item>
/// </list>
/// </summary>
public static class CloudKitMmcsIds
{
    private static readonly Regex GuidHeadRegex = new(
        @"^([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12})\b",
        RegexOptions.Compiled);

    /// <summary>Wire <c>A:pref4:uuid:</c> oppure illusione <c>XA:pref4:uuid:</c>.</summary>
    private static readonly Regex TypePrefixedAssetRegex = new(
        @"^(?:[A-Z]A|A):[a-z0-9]{4}:([0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}):",
        RegexOptions.Compiled);

    /// <summary>True se è un UUID record CloudKit (senza TYPE:pref4:).</summary>
    public static bool IsUuidRecordName(string? recordName)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            return false;
        return Guid.TryParse(recordName.Trim(), out _);
    }

    /// <summary>
    /// Nome record asset su wire PrivilegedBatch: sempre <c>A:{pref4}:{rid}</c>.
    /// Converte <c>MA:/KA:/LA:…</c> (illusione length-byte) → <c>A:…</c>.
    /// </summary>
    public static string? ToPrivilegedBatchWireName(string? nameOrRid)
    {
        if (string.IsNullOrWhiteSpace(nameOrRid))
            return null;
        var s = nameOrRid.Trim();

        // Illusione XA:pref4:… → A:pref4:… (togli solo la lettera length-byte).
        if (s.Length > 3
            && s[1] == 'A'
            && s[2] == ':'
            && char.IsAsciiLetterUpper(s[0])
            && s[0] != 'A')
            s = s[1..];

        if (s.StartsWith("A:", StringComparison.Ordinal)
            && TypePrefixedAssetRegex.IsMatch(s))
            return s;

        return null;
    }

    /// <summary>True se il nome è (o normalizza a) un record asset <c>A:pref4:…</c>.</summary>
    public static bool IsAssetRecordName(string? recordName) =>
        ToPrivilegedBatchWireName(recordName) is not null;

    /// <summary>
    /// Seed PrivilegedBatch  <c>A:{pref4}:{rid}</c>.
    /// UUID nudo → NOT_FOUND. Il parametro <paramref name="type"/> è ignorato (solo <c>A</c>).
    /// </summary>
    public static string? ToPrivilegedBatchSeed(
        string devicePrefix4,
        string? recordIdSuffix,
        string type = "A")
    {
        if (string.IsNullOrWhiteSpace(recordIdSuffix))
            return null;
        var rid = recordIdSuffix.Trim();
        if (ToPrivilegedBatchWireName(rid) is { } wire)
            return wire;

        var pref = devicePrefix4.Length >= 4 ? devicePrefix4[..4].ToLowerInvariant() : devicePrefix4;
        if (string.IsNullOrWhiteSpace(pref))
            return null;
        _ = type; // storico KA/MA/LA: illusione; wire = sempre A
        return ToPrivilegedBatchWireName($"A:{pref}:{rid}");
    }

    /// <summary>
    /// Classe size storica (solo log/UI). Non usata sul wire — manda sempre <c>A:</c>.
    /// </summary>
    public static string InferAssetTypeFromSize(long sizeBytes)
    {
        if (sizeBytes <= 16) return "JA";
        if (sizeBytes <= 100) return "KA";
        if (sizeBytes <= 1024) return "LA";
        if (sizeBytes <= 10240) return "MA";
        if (sizeBytes <= 100_000) return "NA";
        if (sizeBytes <= 1_048_576) return "OA";
        return "PA";
    }

    /// <summary>
    /// Size dichiarata in <c>uuid:token=:size</c> / <c>A:pref4:…=:size</c>, oppure null.
    /// </summary>
    public static long? TryExtractSizeFromRid(string? ridOrName)
    {
        if (string.IsNullOrWhiteSpace(ridOrName))
            return null;
        var s = ridOrName.Trim();
        var sep = s.LastIndexOf("=:", StringComparison.Ordinal);
        if (sep < 0 || sep + 2 >= s.Length)
            return null;
        var sizeText = s[(sep + 2)..].TrimEnd(':');
        return long.TryParse(sizeText, out var n) && n >= 0 ? n : null;
    }

    /// <summary>
    /// Token base64 in <c>uuid:token=:size</c> (tra il primo <c>:</c> dopo l'UUID e <c>=:</c>).
    /// Accetta anche wire <c>A:pref4:…</c>.
    /// </summary>
    public static string? TryExtractRidToken(string? ridOrName)
    {
        if (string.IsNullOrWhiteSpace(ridOrName))
            return null;
        var rid = ToRecordIdSuffix(ridOrName.Trim()) ?? ridOrName.Trim();
        var uuidEnd = rid.IndexOf(':');
        if (uuidEnd <= 0 || uuidEnd >= rid.Length - 1)
            return null;
        var rest = rid[(uuidEnd + 1)..];
        var sep = rest.LastIndexOf("=:", StringComparison.Ordinal);
        if (sep <= 0)
            return null;
        var token = rest[..sep];
        return token.Length > 0 ? token : null;
    }

    /// <summary>
    /// Garantisce suffisso <c>=:size</c> sul seed PrivilegedBatch (CK NOT_FOUND senza size).
    /// </summary>
    public static string EnsurePrivilegedBatchSeedSize(string seed, long sizeBytes)
    {
        if (string.IsNullOrWhiteSpace(seed) || sizeBytes < 0)
            return seed;
        if (TryExtractSizeFromRid(seed) is not null)
            return seed;
        var s = seed.TrimEnd(':');
        if (s.EndsWith('='))
            return s + ":" + sizeBytes;
        return s + "=:" + sizeBytes;
    }

    /// <summary>
    /// Allinea <c>A:{pref4}:…</c> al prefisso dispositivo (EN stale con pref sbagliato).
    /// </summary>
    public static string RewritePrivilegedBatchPref4(string seed, string devicePrefix4)
    {
        if (string.IsNullOrWhiteSpace(seed) || string.IsNullOrWhiteSpace(devicePrefix4))
            return seed;
        var pref = devicePrefix4.Length >= 4
            ? devicePrefix4[..4].ToLowerInvariant()
            : devicePrefix4.ToLowerInvariant();
        var wire = ToPrivilegedBatchWireName(seed) ?? seed.Trim();
        if (!wire.StartsWith("A:", StringComparison.Ordinal) || wire.Length < 7)
            return seed;
        // A:xxxx:…
        var third = wire.IndexOf(':', 2);
        if (third != 6) // "A:" + 4 pref + ":"
            return seed;
        var oldPref = wire[2..6];
        if (string.Equals(oldPref, pref, StringComparison.OrdinalIgnoreCase))
            return wire;
        return "A:" + pref + wire[6..];
    }

    /// <summary>
    /// Varianti wire per lookup payload: size flist vs CK, base64 <c>+</c>/<c>-</c>.
    /// Mai UUID nudo (collisioni Domain).
    /// </summary>
    public static IEnumerable<string> EnumerateAssetRecordNameVariants(
        string recordName,
        long? alternateSizeBytes = null)
    {
        if (string.IsNullOrWhiteSpace(recordName))
            yield break;

        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var raw in ExpandBase64PlusMinus(recordName.Trim()))
        {
            if (!seen.Add(raw))
                continue;
            yield return raw;

            if (alternateSizeBytes is long sz and >= 0)
            {
                var resized = EnsurePrivilegedBatchSeedSize(
                    StripSizeSuffixForRewrite(raw), sz);
                if (seen.Add(resized))
                    yield return resized;
            }
        }
    }

    private static string StripSizeSuffixForRewrite(string seed)
    {
        var sep = seed.LastIndexOf("=:", StringComparison.Ordinal);
        if (sep <= 0)
            return seed.TrimEnd(':');
        // uuid:token=:size → uuid:token=
        return seed[..(sep + 1)];
    }

    private static IEnumerable<string> ExpandBase64PlusMinus(string name)
    {
        yield return name;
        if (name.Contains('+', StringComparison.Ordinal))
            yield return name.Replace('+', '-');
        if (name.Contains('-', StringComparison.Ordinal)
            && name.Contains(':', StringComparison.Ordinal))
        {
            // Solo segmento token (tra uuid e =:) — evita di toccare UUID.
            var rid = ToRecordIdSuffix(name) ?? name;
            var uuidEnd = rid.IndexOf(':');
            if (uuidEnd <= 0)
                yield break;
            var rest = rid[(uuidEnd + 1)..];
            var sep = rest.LastIndexOf("=:", StringComparison.Ordinal);
            if (sep <= 0)
                yield break;
            var token = rest[..sep];
            if (!token.Contains('-', StringComparison.Ordinal))
                yield break;
            var flipped = token.Replace('-', '+');
            var newRid = rid[..(uuidEnd + 1)] + flipped + rest[sep..];
            if (ToPrivilegedBatchWireName(name) is { } wire
                && wire.StartsWith("A:", StringComparison.Ordinal)
                && wire.Length >= 7)
                yield return "A:" + wire[2..6] + ":" + newRid;
            else
                yield return newRid;
        }
    }

    /// <summary>
    /// Etichetta size-class (log). Wire name è sempre <c>A</c>.
    /// </summary>
    public static string ResolveAssetType(
        string? enTypedName,
        long? sizeBytes,
        string? recordIdSuffix)
    {
        if (!string.IsNullOrWhiteSpace(enTypedName)
            && ToPrivilegedBatchWireName(enTypedName) is not null)
            return "A";

        var size = sizeBytes ?? TryExtractSizeFromRid(recordIdSuffix);
        return size is long sz ? InferAssetTypeFromSize(sz) : "A";
    }

    /// <summary>Nessun TYPE alternativo sul wire (sempre <c>A:</c>).</summary>
    public static IEnumerable<string> EnumerateAlternateTypes(string primaryType)
    {
        _ = primaryType;
        yield break;
    }

    /// <summary>Estrae <c>uuid:token=:size</c> da nome A:/XA:pref4:… o F:….</summary>
    public static string? ToRecordIdSuffix(string? nameOrRid)
    {
        if (string.IsNullOrWhiteSpace(nameOrRid))
            return null;
        var s = ridTrim(nameOrRid);
        if (s.StartsWith("F:", StringComparison.Ordinal))
        {
            s = s[2..];
            return s.TrimEnd(':');
        }

        if (ToPrivilegedBatchWireName(s) is { } wire)
            s = wire;

        var typePref = TypePrefixedAssetRegex.Match(s);
        if (typePref.Success)
        {
            // A:pref4:uuid:token=:size → uuid:token=:size
            var parts = s.Split(':', 3);
            return parts.Length >= 3 ? parts[2] : null;
        }

        return GuidHeadRegex.IsMatch(s) ? s : null;

        static string ridTrim(string x) => x.Trim();
    }

    /// <summary>
    /// Nome record CK da rid flist: primo segmento se UUID, altrimenti UUID da
    /// <c>TYPE:pref4:uuid:…</c> / <c>F:uuid:…</c>.
    /// </summary>
    public static string? CkRecordNameFromRid(string? rid)
    {
        if (string.IsNullOrWhiteSpace(rid))
            return null;

        var s = rid.Trim();
        if (s.StartsWith("F:", StringComparison.Ordinal))
            s = s[2..];
        if (ToPrivilegedBatchWireName(s) is { } wire)
            s = wire;

        var typePref = TypePrefixedAssetRegex.Match(s);
        if (typePref.Success)
            return typePref.Groups[1].Value;

        var head = GuidHeadRegex.Match(s);
        return head.Success ? head.Groups[1].Value : null;
    }

    /// <summary>
    /// FileID MMCS: <c>F:{uuid}:{token}:{size}:</c> dal rid flist
    /// (<c>uuid:token=:size</c> o già <c>F:…</c>).
    /// </summary>
    public static string? ToMmcsFileId(string? rid)
    {
        if (string.IsNullOrWhiteSpace(rid))
            return null;

        var s = rid.Trim();
        if (s.StartsWith("F:", StringComparison.Ordinal))
            return s.EndsWith(':') ? s : s + ":";

        if (ToPrivilegedBatchWireName(s) is { } wire)
            s = wire;

        var typePref = TypePrefixedAssetRegex.Match(s);
        if (typePref.Success)
        {
            // A:pref4:uuid:token=:size → uuid:token=:size
            var parts = s.Split(':', 3);
            if (parts.Length < 3)
                return null;
            s = parts[2];
        }

        if (CkRecordNameFromRid(s) is null)
            return null;

        return "F:" + s.TrimEnd(':') + ":";
    }
}
