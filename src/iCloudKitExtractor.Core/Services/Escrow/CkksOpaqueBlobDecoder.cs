using System.Globalization;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Decode strutturato di <c>v_Data</c> ancora “opachi”: NSKeyedArchive,
/// HomeKit LTPK/LTSK, passkey EC, protobuf sniff, nested bplist.
/// </summary>
public static class CkksOpaqueBlobDecoder
{
    private static readonly Regex HomeKitKeyPair = new(
        @"^(?<ltpk>[0-9a-fA-F]{64})\+(?<ltsk>[0-9a-fA-F]{64})$",
        RegexOptions.Compiled);
    private static readonly Regex HomeKitLtpkOnly = new(
        @"^(?<ltpk>[0-9a-fA-F]{64})$",
        RegexOptions.Compiled);
    private static readonly Regex UuidLike = new(
        @"^[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}$",
        RegexOptions.Compiled);

    public sealed record Result(
        string Format,
        string? SummaryJson,
        string? Utf8Secret = null,
        IReadOnlyDictionary<string, string?>? Fields = null);

    public static Result? TryDecode(
        CkksVaultItem item,
        byte[] data,
        string category)
    {
        if (data.Length == 0)
            return null;

        // 1) HomeKit pairing strings (most common cleartext in hap.pairing).
        if (category is "homekit" or "subsystem"
            && TryDecodeHomeKit(item, data, out var hk))
            return hk;

        // 2) Passkey / WebAuthn raw EC point or CBOR-ish prefix.
        if (category == "passkey" && TryDecodePasskey(item, data, out var pk))
            return pk;

        // 3) UTF-8 that is JSON / base64(bplist) / base64(DER).
        if (CkksSecItemPayload.TryUtf8Secret(data, out var text))
        {
            if (TryDecodeUtf8Structured(text, category, item, out var utfStruct))
                return utfStruct;
        }

        // 4) bplist / NSKeyedArchive.
        if (data.Length >= 8 && data.AsSpan(0, 8).SequenceEqual("bplist00"u8))
        {
            if (TryDecodeBplist(data, category, item, out var bp))
                return bp;
        }

        // 5) ASN.1 SEQUENCE — richer than OID sniff alone.
        if (data[0] == 0x30 && TryDecodeAsn1(data, out var asn))
            return asn;

        // 6) Length-prefixed protobuf-ish inventory.
        if (TryDecodeProtobufSniff(data, out var pb))
            return pb;

        return null;
    }

    private static bool TryDecodeHomeKit(
        CkksVaultItem item, byte[] data, out Result result)
    {
        result = null!;
        string? text = null;
        if (CkksSecItemPayload.TryUtf8Secret(data, out var utf))
            text = utf.Trim().Trim('"');
        else if (data.Length is 32 or 64)
            text = Convert.ToHexString(data).ToLowerInvariant();

        if (string.IsNullOrEmpty(text))
            return false;

        var labl = item.Labl ?? CkksSecItemPayload.AttrString(item, "labl") ?? "";
        var svce = CkksSecItemPayload.AttrString(item, "svce") ?? "";
        var acct = item.Acct ?? "";
        var isIdentity = labl.Contains("Pairing Identity", StringComparison.OrdinalIgnoreCase)
                         || svce.Contains("Pairing Identity", StringComparison.OrdinalIgnoreCase);
        var isAccessory = labl.Contains("Paired HomeKit Accessory", StringComparison.OrdinalIgnoreCase)
                          || svce.Contains("Paired HomeKit Accessory", StringComparison.OrdinalIgnoreCase)
                          || Regex.IsMatch(acct, @"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");

        var mPair = HomeKitKeyPair.Match(text);
        if (mPair.Success)
        {
            var ltpk = mPair.Groups["ltpk"].Value.ToLowerInvariant();
            var ltsk = mPair.Groups["ltsk"].Value.ToLowerInvariant();
            var fields = new Dictionary<string, string?>
            {
                ["role"] = isIdentity ? "controller-identity" : "homekit-key-pair",
                ["pairingId"] = UuidLike.IsMatch(acct) ? acct.ToUpperInvariant() : acct,
                ["ltpk"] = ltpk,
                ["ltsk"] = ltsk,
                ["curve"] = "Ed25519",
            };
            result = new Result(
                "homekit-ltpk+ltsk",
                JsonSerializer.Serialize(fields, Pretty),
                Utf8Secret: text,
                Fields: fields);
            return true;
        }

        var mPub = HomeKitLtpkOnly.Match(text);
        if (mPub.Success || data.Length == 32)
        {
            var ltpk = mPub.Success
                ? mPub.Groups["ltpk"].Value.ToLowerInvariant()
                : Convert.ToHexString(data).ToLowerInvariant();
            var fields = new Dictionary<string, string?>
            {
                ["role"] = isAccessory ? "paired-accessory" : "homekit-ltpk",
                ["accessoryId"] = isAccessory ? acct : null,
                ["pairingId"] = UuidLike.IsMatch(acct) ? acct.ToUpperInvariant() : acct,
                ["ltpk"] = ltpk,
                ["curve"] = "Ed25519",
                ["label"] = labl,
            };
            result = new Result(
                "homekit-ltpk",
                JsonSerializer.Serialize(fields, Pretty),
                Utf8Secret: text ?? ltpk,
                Fields: fields);
            return true;
        }

        return false;
    }

    private static bool TryDecodePasskey(
        CkksVaultItem item, byte[] data, out Result result)
    {
        result = null!;
        var rp = First(item.Srvr, item.Labl, CkksSecItemPayload.AttrString(item, "svce"));
        if (data.Length is 65 or 97 && data[0] == 0x04)
        {
            var fields = new Dictionary<string, string?>
            {
                ["kind"] = "ec-x963-public",
                ["curveBits"] = (data.Length == 65 ? 256 : 384).ToString(CultureInfo.InvariantCulture),
                ["pointHex"] = Convert.ToHexString(data),
                ["rpHint"] = rp,
                ["acct"] = item.Acct,
            };
            result = new Result("passkey-ec-pub", JsonSerializer.Serialize(fields, Pretty), Fields: fields);
            return true;
        }

        // CBOR map often starts with 0xa1..0xbf; credential id may be embedded.
        if (data[0] is >= 0xa0 and <= 0xbf || data[0] == 0x58 || data[0] == 0x59)
        {
            var fields = new Dictionary<string, string?>
            {
                ["kind"] = "cbor-ish",
                ["len"] = data.Length.ToString(CultureInfo.InvariantCulture),
                ["headHex"] = Convert.ToHexString(data.AsSpan(0, Math.Min(16, data.Length))),
                ["rpHint"] = rp,
                ["fullHex"] = data.Length <= 512
                    ? Convert.ToHexString(data)
                    : Convert.ToHexString(data.AsSpan(0, 128)) + "…",
            };
            // Pull ASCII/UTF-8 rp id fragments if present.
            var ascii = ExtractPrintableRuns(data, minLen: 4);
            if (ascii.Count > 0)
                fields["asciiRuns"] = string.Join(" | ", ascii.Take(8));
            result = new Result("passkey-cbor", JsonSerializer.Serialize(fields, Pretty), Fields: fields);
            return true;
        }

        if (data.Length >= 16)
        {
            var fields = new Dictionary<string, string?>
            {
                ["kind"] = "passkey-raw",
                ["len"] = data.Length.ToString(CultureInfo.InvariantCulture),
                ["sha256"] = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)),
                ["rpHint"] = rp,
                ["hexPreview"] = CkksSecItemPayload.TruncHex(data, 64),
            };
            var ascii = ExtractPrintableRuns(data, minLen: 4);
            if (ascii.Count > 0)
                fields["asciiRuns"] = string.Join(" | ", ascii.Take(8));
            result = new Result("passkey-raw", JsonSerializer.Serialize(fields, Pretty), Fields: fields);
            return true;
        }

        return false;
    }

    private static bool TryDecodeUtf8Structured(
        string text, string category, CkksVaultItem item, out Result result)
    {
        result = null!;
        var t = text.Trim();
        if (t.StartsWith('{') || t.StartsWith('['))
        {
            result = new Result(
                "json-text",
                JsonSerializer.Serialize(new { category, json = t }, Pretty),
                Utf8Secret: t);
            return true;
        }

        // base64 → nested bplist / DER
        if (t.Length >= 16 && t.Length % 4 == 0 && IsBase64ish(t))
        {
            try
            {
                var raw = Convert.FromBase64String(t);
                if (raw.Length >= 8 && raw.AsSpan(0, 8).SequenceEqual("bplist00"u8)
                    && TryDecodeBplist(raw, category, item, out var nested))
                {
                    result = nested with { Format = "b64-" + nested.Format };
                    return true;
                }

                if (raw.Length > 0 && raw[0] == 0x30 && TryDecodeAsn1(raw, out var asn))
                {
                    result = asn with { Format = "b64-" + asn.Format };
                    return true;
                }
            }
            catch
            {
                // not b64
            }
        }

        if (category is "app-token" or "rapport" or "sos" or "subsystem")
        {
            result = new Result(
                "utf8-token",
                JsonSerializer.Serialize(new
                {
                    category,
                    text = t.Length <= 4096 ? t : t[..4096] + "…",
                    length = t.Length,
                    acct = item.Acct,
                    labl = item.Labl,
                    svce = CkksSecItemPayload.AttrString(item, "svce")
                }, Pretty),
                Utf8Secret: t);
            return true;
        }

        return false;
    }

    private static bool TryDecodeBplist(
        byte[] data, string category, CkksVaultItem item, out Result result)
    {
        result = null!;
        if (!AppleBinaryPlist.TryParse(data, out var root, out _) || root is null)
            return false;

        if (root is Dictionary<string, object?> dict
            && dict.ContainsKey("$archiver")
            && dict.ContainsKey("$objects"))
        {
            var resolved = TryResolveKeyedArchive(dict);
            var payload = resolved ?? CkksSecItemPayload.ToJsonable(root, 0);
            // HomeKit sometimes archives a string key.
            if (resolved is string s
                && TryDecodeHomeKit(item, Encoding.UTF8.GetBytes(s), out var hkFromArch))
            {
                result = hkFromArch with { Format = "nskeyed-homekit" };
                return true;
            }

            result = new Result(
                "nskeyedarchive",
                JsonSerializer.Serialize(new
                {
                    category,
                    archiver = dict.GetValueOrDefault("$archiver")?.ToString(),
                    version = dict.GetValueOrDefault("$version")?.ToString(),
                    top = CkksSecItemPayload.ToJsonable(dict.GetValueOrDefault("$top"), 0),
                    resolved = payload
                }, Pretty));
            return true;
        }

        result = new Result(
            "bplist",
            CkksSecItemPayload.FlattenToJson(root));
        return true;
    }

    private static object? TryResolveKeyedArchive(Dictionary<string, object?> arch)
    {
        if (arch.GetValueOrDefault("$objects") is not object?[] objects)
            return null;
        if (arch.GetValueOrDefault("$top") is not Dictionary<string, object?> top)
            return null;

        var resolvedTop = new Dictionary<string, object?>(StringComparer.Ordinal);
        foreach (var (k, v) in top)
            resolvedTop[k] = ResolveArchiveValue(v, objects, depth: 0);

        // Common pattern: $top.root → real object
        if (resolvedTop.TryGetValue("root", out var root) && root is not null)
            return root;
        return resolvedTop;
    }

    private static object? ResolveArchiveValue(object? v, object?[] objects, int depth)
    {
        if (depth > 24 || v is null)
            return null;
        if (v is PlistUid uid)
        {
            if (uid.Value >= (ulong)objects.Length)
                return null;
            return ResolveArchiveValue(objects[(int)uid.Value], objects, depth + 1);
        }

        if (v is Dictionary<string, object?> d)
        {
            // NS.objects / NS.keys arrays, NS.string, NS.data, …
            if (d.TryGetValue("NS.string", out var ns) && ns is string s)
                return s;
            if (d.TryGetValue("NS.data", out var nd) && nd is byte[] nb)
                return nb.Length <= 256
                    ? Convert.ToHexString(nb)
                    : Convert.ToHexString(nb.AsSpan(0, 64)) + $"…({nb.Length}B)";
            if (d.TryGetValue("$class", out _))
            {
                var className = ResolveClassName(d, objects);
                var fields = new Dictionary<string, object?>();
                if (!string.IsNullOrEmpty(className))
                    fields["$class"] = className;
                foreach (var (fk, fv) in d)
                {
                    if (fk is "$class" or "NS.keys")
                        continue;
                    if (fk == "NS.objects" && fv is object?[] arr
                        && d.TryGetValue("NS.keys", out var keysObj))
                    {
                        var keys = ResolveArchiveValue(keysObj, objects, depth + 1) as object?[]
                                   ?? keysObj as object?[];
                        var map = new Dictionary<string, object?>();
                        if (keys is not null)
                        {
                            for (var i = 0; i < Math.Min(keys.Length, arr.Length); i++)
                            {
                                var key = ResolveArchiveValue(keys[i], objects, depth + 1)?.ToString()
                                          ?? $"#{i}";
                                map[key] = ResolveArchiveValue(arr[i], objects, depth + 1);
                            }

                            fields["dict"] = map;
                            continue;
                        }
                    }

                    fields[fk] = ResolveArchiveValue(fv, objects, depth + 1);
                }

                return fields;
            }

            return d.ToDictionary(
                kv => kv.Key,
                kv => ResolveArchiveValue(kv.Value, objects, depth + 1));
        }

        if (v is object?[] list)
            return list.Select(x => ResolveArchiveValue(x, objects, depth + 1)).ToArray();

        return CkksSecItemPayload.ToJsonable(v, depth);
    }

    private static string? ResolveClassName(Dictionary<string, object?> d, object?[] objects)
    {
        if (!d.TryGetValue("$class", out var c) || c is null)
            return null;
        var cls = ResolveArchiveValue(c, objects, 0);
        if (cls is Dictionary<string, object?> cd
            && cd.TryGetValue("$classname", out var name))
            return name?.ToString();
        return cls?.ToString();
    }

    private static bool TryDecodeAsn1(byte[] data, out Result result)
    {
        result = null!;
        var desc = CkksSecItemPayload.DescribeAsn1(data);
        var printable = ExtractPrintableRuns(data, minLen: 6);
        // Certs already handled upstream; here PKCS#8 / SPKI hints from OID sniff.
        string? hint = null;
        if (desc.Contains("1.2.840.10045", StringComparison.Ordinal))
            hint = "ec-oid";
        else if (desc.Contains("1.2.840.113549", StringComparison.Ordinal))
            hint = "rsa/pkcs-oid";

        // Also try exporting as SPKI/PKCS8 via existing key path
        var fields = new Dictionary<string, object?>
        {
            ["asn1"] = desc,
            ["hint"] = hint,
            ["len"] = data.Length,
            ["sha256"] = Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(data)),
            ["asciiRuns"] = printable.Count == 0 ? null : printable.Take(12).ToArray(),
            ["hexPreview"] = CkksSecItemPayload.TruncHex(data, 64),
        };
        result = new Result("asn1", JsonSerializer.Serialize(fields, Pretty));
        return true;
    }

    private static bool TryDecodeProtobufSniff(byte[] data, out Result result)
    {
        result = null!;
        // Heuristic: many small length-delimited / varint fields, no bplist magic.
        if (data.Length < 8 || data[0] == 0x30 || data.AsSpan(0, Math.Min(6, data.Length)).SequenceEqual("bplist"u8))
            return false;

        var fields = new List<object>();
        var i = 0;
        var okTags = 0;
        while (i < data.Length && fields.Count < 40)
        {
            var tag = data[i];
            var fieldNo = tag >> 3;
            var wire = tag & 0x7;
            if (fieldNo == 0 || wire > 5)
                break;
            i++;
            try
            {
                switch (wire)
                {
                    case 0: // varint
                    {
                        ulong v = 0;
                        var shift = 0;
                        while (i < data.Length)
                        {
                            var b = data[i++];
                            v |= (ulong)(b & 0x7F) << shift;
                            if ((b & 0x80) == 0)
                                break;
                            shift += 7;
                            if (shift > 63)
                                return false;
                        }

                        fields.Add(new { field = fieldNo, wire = "varint", value = v });
                        okTags++;
                        break;
                    }
                    case 2: // len-delimited
                    {
                        var len = 0;
                        var shift = 0;
                        while (i < data.Length)
                        {
                            var b = data[i++];
                            len |= (b & 0x7F) << shift;
                            if ((b & 0x80) == 0)
                                break;
                            shift += 7;
                            if (shift > 28)
                                return false;
                        }

                        if (len < 0 || i + len > data.Length)
                            return false;
                        var slice = data.AsSpan(i, len).ToArray();
                        i += len;
                        string? asText = null;
                        if (CkksSecItemPayload.TryUtf8Secret(slice, out var t) && t.Length <= 256)
                            asText = t;
                        fields.Add(new
                        {
                            field = fieldNo,
                            wire = "bytes",
                            len,
                            text = asText,
                            hex = slice.Length <= 32
                                ? Convert.ToHexString(slice)
                                : Convert.ToHexString(slice.AsSpan(0, 16)) + "…"
                        });
                        okTags++;
                        break;
                    }
                    case 5: // 32-bit
                        if (i + 4 > data.Length)
                            return false;
                        fields.Add(new
                        {
                            field = fieldNo,
                            wire = "fixed32",
                            hex = Convert.ToHexString(data.AsSpan(i, 4))
                        });
                        i += 4;
                        okTags++;
                        break;
                    case 1: // 64-bit
                        if (i + 8 > data.Length)
                            return false;
                        fields.Add(new
                        {
                            field = fieldNo,
                            wire = "fixed64",
                            hex = Convert.ToHexString(data.AsSpan(i, 8))
                        });
                        i += 8;
                        okTags++;
                        break;
                    default:
                        return false;
                }
            }
            catch
            {
                return false;
            }
        }

        if (okTags < 2)
            return false;

        result = new Result(
            "protobuf-sniff",
            JsonSerializer.Serialize(new
            {
                tags = okTags,
                consumed = i,
                totalLen = data.Length,
                fields
            }, Pretty));
        return true;
    }

    private static List<string> ExtractPrintableRuns(byte[] data, int minLen)
    {
        var runs = new List<string>();
        var sb = new StringBuilder();
        foreach (var b in data)
        {
            if (b is >= 0x20 and <= 0x7E)
            {
                sb.Append((char)b);
            }
            else
            {
                if (sb.Length >= minLen)
                    runs.Add(sb.ToString());
                sb.Clear();
            }
        }

        if (sb.Length >= minLen)
            runs.Add(sb.ToString());
        return runs;
    }

    private static bool IsBase64ish(string s)
    {
        foreach (var c in s)
        {
            if (char.IsLetterOrDigit(c) || c is '+' or '/' or '=' or '-' or '_')
                continue;
            return false;
        }

        return true;
    }

    private static string? First(params string?[] values)
    {
        foreach (var v in values)
        {
            if (!string.IsNullOrWhiteSpace(v))
                return v;
        }

        return null;
    }

    private static readonly JsonSerializerOptions Pretty = new() { WriteIndented = true };
}
