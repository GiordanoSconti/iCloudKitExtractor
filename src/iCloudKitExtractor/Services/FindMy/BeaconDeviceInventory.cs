using System.Globalization;
using System.IO;
using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.FindMy;

/// <summary>
/// Tabella dispositivi da plaintext BeaconStore:
/// MasterBeacon (stableIdentifier / pairingDate / …) ⋈ Naming (associatedBeacon → name).
/// </summary>
public static class BeaconDeviceInventory
{
    public sealed record DeviceRow(
        string Name,
        string Emoji,
        string Kind,
        string Model,
        string Serial,
        string StableIdentifier,
        string PairingDate,
        string SystemVersion,
        string BatteryLevel,
        string VendorId,
        string RoleId,
        string RecordId,
        bool HasPrivateKey,
        bool HasSharedSecret,
        bool HasPublicKey);

    public sealed record BuildResult(
        IReadOnlyList<DeviceRow> Devices,
        string TsvPath,
        string Message);

    /// <summary>
    /// Legge <c>crypto/**/field_records.tsv</c> + <c>plaintext/</c> e scrive
    /// <c>devices.tsv</c> nella root del run BeaconStore.
    /// </summary>
    public static BuildResult BuildFromRunDirectory(string outDir)
    {
        var crypto = Path.Combine(outDir, "crypto");
        if (!Directory.Exists(crypto))
            return new BuildResult([], "", "crypto/ assente");

        var byRecord = new Dictionary<string, Dictionary<string, string>>(
            StringComparer.OrdinalIgnoreCase);

        foreach (var tsv in Directory.EnumerateFiles(
                     crypto, "field_records.tsv", SearchOption.AllDirectories))
        {
            var plainRoot = Path.Combine(Path.GetDirectoryName(tsv)!, "plaintext");
            foreach (var line in File.ReadLines(tsv).Skip(1))
            {
                var parts = line.Split('\t');
                if (parts.Length < 5)
                    continue;

                var field = parts[0];
                if (field.StartsWith("type20", StringComparison.OrdinalIgnoreCase))
                    continue;
                if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var idx))
                    continue;

                var recordId = parts[2].Trim();
                if (string.IsNullOrWhiteSpace(recordId))
                    continue;

                var preview = parts.Length > 5 ? parts[5] : "";
                var value = ReadPlaintextValue(plainRoot, field, idx)
                            ?? CleanString(preview);
                if (string.IsNullOrEmpty(value) && string.IsNullOrEmpty(preview))
                    continue;

                if (!byRecord.TryGetValue(recordId, out var map))
                {
                    map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                    byRecord[recordId] = map;
                }

                map[field] = value;
            }
        }

        var masters = byRecord
            .Where(static kv =>
                kv.Value.ContainsKey("stableIdentifier")
                || kv.Value.ContainsKey("pairingDate")
                || kv.Value.ContainsKey("sharedSecret"))
            .ToDictionary(static kv => kv.Key, static kv => kv.Value, StringComparer.OrdinalIgnoreCase);

        var namings = byRecord
            .Where(static kv => kv.Value.ContainsKey("associatedBeacon"))
            .ToList();

        var devices = new List<DeviceRow>();
        foreach (var (recordId, fields) in masters)
        {
            string name = "", emoji = "", roleId = "";
            foreach (var (_, naming) in namings)
            {
                var assoc = CleanString(naming.GetValueOrDefault("associatedBeacon", ""));
                if (!RecordIdsMatch(assoc, recordId))
                    continue;
                name = CleanString(naming.GetValueOrDefault("name", ""));
                emoji = CleanString(naming.GetValueOrDefault("emoji", ""));
                roleId = CleanString(naming.GetValueOrDefault("roleId", ""));
                break;
            }

            var stable = CleanString(fields.GetValueOrDefault("stableIdentifier", ""));
            ClassifyStable(stable, out var kind, out var serial);

            var model = CleanString(fields.GetValueOrDefault("model", ""));
            if (string.IsNullOrEmpty(model) || model is "\0" or "2")
                model = kind.Equals("AirTag", StringComparison.OrdinalIgnoreCase) ? "AirTag" : "";

            var pairing = CleanString(fields.GetValueOrDefault("pairingDate", ""));
            if (pairing.StartsWith("2a09", StringComparison.OrdinalIgnoreCase)
                || pairing.Length is > 0 and < 20 && pairing.All(Uri.IsHexDigit))
            {
                // leftover hex — already should be ISO from decoder; leave as-is
            }

            devices.Add(new DeviceRow(
                string.IsNullOrWhiteSpace(name) ? "(senza nome)" : name,
                emoji,
                kind,
                model,
                serial,
                stable,
                pairing,
                CleanString(fields.GetValueOrDefault("systemVersion", "")),
                FormatBattery(fields.GetValueOrDefault("batteryLevel", "")),
                FormatVendor(fields.GetValueOrDefault("vendorId", "")),
                roleId,
                recordId,
                fields.ContainsKey("privateKey"),
                fields.ContainsKey("sharedSecret"),
                fields.ContainsKey("publicKey")));
        }

        devices.Sort(static (a, b) =>
        {
            var ka = a.Kind.Equals("AirTag", StringComparison.OrdinalIgnoreCase) ? 0 : 1;
            var kb = b.Kind.Equals("AirTag", StringComparison.OrdinalIgnoreCase) ? 0 : 1;
            var c = ka.CompareTo(kb);
            return c != 0
                ? c
                : string.Compare(a.Name, b.Name, StringComparison.OrdinalIgnoreCase);
        });

        var tsvPath = Path.Combine(outDir, "devices.tsv");
        WriteTsv(tsvPath, devices);
        var msg = devices.Count == 0
            ? "nessun MasterBeacon decifrato"
            : $"{devices.Count} dispositivi → {tsvPath}";
        return new BuildResult(devices, tsvPath, msg);
    }

    public static IEnumerable<string> FormatLogLines(IReadOnlyList<DeviceRow> devices)
    {
        if (devices.Count == 0)
        {
            yield return "(tabella dispositivi vuota)";
            yield break;
        }

        yield return $"{"Nome",-28} {"Tipo",-12} {"Modello",-12} {"Seriale/ID",-28} {"Paired (UTC)",-22}";
        yield return new string('-', 110);
        foreach (var d in devices)
        {
            var label = string.IsNullOrEmpty(d.Emoji) ? d.Name : $"{d.Emoji} {d.Name}";
            if (label.Length > 28)
                label = label[..27] + "…";
            var serial = d.Serial.Length > 28 ? d.Serial[..27] + "…" : d.Serial;
            var pair = d.PairingDate.Length > 22 ? d.PairingDate[..22] : d.PairingDate;
            yield return $"{label,-28} {d.Kind,-12} {d.Model,-12} {serial,-28} {pair,-22}";
        }
    }

    private static void WriteTsv(string path, IReadOnlyList<DeviceRow> devices)
    {
        var sb = new StringBuilder();
        sb.AppendLine(
            "name\temoji\tkind\tmodel\tserial\tstableIdentifier\tpairingDate\t" +
            "systemVersion\tbatteryLevel\tvendorId\troleId\trecordId\t" +
            "privateKey\tsharedSecret\tpublicKey");
        foreach (var d in devices)
        {
            sb.Append(Escape(d.Name)).Append('\t')
                .Append(Escape(d.Emoji)).Append('\t')
                .Append(Escape(d.Kind)).Append('\t')
                .Append(Escape(d.Model)).Append('\t')
                .Append(Escape(d.Serial)).Append('\t')
                .Append(Escape(d.StableIdentifier)).Append('\t')
                .Append(Escape(d.PairingDate)).Append('\t')
                .Append(Escape(d.SystemVersion)).Append('\t')
                .Append(Escape(d.BatteryLevel)).Append('\t')
                .Append(Escape(d.VendorId)).Append('\t')
                .Append(Escape(d.RoleId)).Append('\t')
                .Append(Escape(d.RecordId)).Append('\t')
                .Append(d.HasPrivateKey ? "yes" : "no").Append('\t')
                .Append(d.HasSharedSecret ? "yes" : "no").Append('\t')
                .Append(d.HasPublicKey ? "yes" : "no").Append('\n');
        }

        File.WriteAllText(path, sb.ToString(), Encoding.UTF8);
    }

    private static string Escape(string s) =>
        (s ?? "").Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');

    private static string? ReadPlaintextValue(string plainRoot, string field, int idx)
    {
        var dir = Path.Combine(plainRoot, Sanitize(field));
        var bin = Path.Combine(dir, $"{idx:D4}.bin");
        var txt = Path.Combine(dir, $"{idx:D4}.txt");

        if (File.Exists(bin))
        {
            var bytes = File.ReadAllBytes(bin);
            if (field.Equals("pairingDate", StringComparison.OrdinalIgnoreCase)
                && NotesPlaintextDecoder.TryDecodePairingDate(bytes, out var iso)
                && !string.IsNullOrEmpty(iso))
            {
                return iso;
            }

            if (TryDecodeCkString(bytes, out var s) && !string.IsNullOrEmpty(s))
                return s;

            if (field.Equals("batteryLevel", StringComparison.OrdinalIgnoreCase))
                return FormatBatteryBytes(bytes);
            if (field.Equals("vendorId", StringComparison.OrdinalIgnoreCase))
                return FormatVendorBytes(bytes);
            if (field.Equals("productId", StringComparison.OrdinalIgnoreCase) && bytes.Length > 0)
                return bytes.Length == 1 ? bytes[0].ToString(CultureInfo.InvariantCulture) : Convert.ToHexString(bytes);
        }

        if (File.Exists(txt))
        {
            var t = CleanString(File.ReadAllText(txt));
            if (!string.IsNullOrEmpty(t))
                return t;
        }

        return null;
    }

    /// <summary>Protobuf length-delimited string: tipico tag 0x32 ‖ len ‖ utf8.</summary>
    internal static bool TryDecodeCkString(ReadOnlySpan<byte> data, out string text)
    {
        text = "";
        if (data.Length < 2)
            return false;

        if (data[0] is 0x0a or 0x12 or 0x1a or 0x22 or 0x2a or 0x32)
        {
            var i = 1;
            if (!TryReadVarint(data, ref i, out var len))
                return false;
            if (len == 0)
            {
                text = "";
                return true;
            }

            if (len > (ulong)(data.Length - i) || len > 512)
                return false;
            text = CleanString(Encoding.UTF8.GetString(data.Slice(i, (int)len)));
            return true;
        }

        // già plaintext UTF-8
        var direct = Encoding.UTF8.GetString(data);
        if (direct.Any(char.IsControl) && !direct.Any(char.IsLetter))
            return false;
        text = CleanString(direct);
        return text.Length > 0;
    }

    private static void ClassifyStable(string stable, out string kind, out string serial)
    {
        kind = "Beacon";
        serial = stable;
        if (string.IsNullOrEmpty(stable))
        {
            serial = "";
            return;
        }

        if (stable.StartsWith("me:", StringComparison.OrdinalIgnoreCase))
        {
            kind = "Me / Owner";
            serial = stable;
            return;
        }

        if (stable.StartsWith("l:", StringComparison.OrdinalIgnoreCase))
        {
            kind = "Apple device";
            serial = stable[2..].TrimStart('/');
            return;
        }

        // $2006~#…~#SERIAL  oppure  2006~#…~#SERIAL
        var s = stable.TrimStart('$');
        if (s.Contains("~#", StringComparison.Ordinal))
        {
            var parts = s.Split("~#", StringSplitOptions.RemoveEmptyEntries);
            var product = parts[0];
            serial = parts.Length >= 2 ? parts[^1] : s;
            kind = product.StartsWith("2006", StringComparison.Ordinal)
                ? "AirTag"
                : $"Product {product}";
        }
    }

    private static bool RecordIdsMatch(string assoc, string recordId)
    {
        if (string.IsNullOrEmpty(assoc) || string.IsNullOrEmpty(recordId))
            return false;
        var a = assoc.Trim().TrimStart('$');
        var b = recordId.Trim().TrimStart('$');
        return a.Equals(b, StringComparison.OrdinalIgnoreCase)
               || a.Contains(b, StringComparison.OrdinalIgnoreCase)
               || b.Contains(a, StringComparison.OrdinalIgnoreCase);
    }

    private static string CleanString(string? s)
    {
        if (string.IsNullOrEmpty(s))
            return "";
        s = s.Trim().Trim('"');
        if (s.StartsWith("2$", StringComparison.Ordinal))
            s = s[2..];
        else if (s.StartsWith('$'))
            s = s[1..];
        // .txt legacy: "2\niPhone14,4" o "22me:/…"
        if (s.Contains('\n') || s.Contains('\r'))
        {
            var lines = s.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries);
            s = lines.LastOrDefault(static l => l.Any(char.IsLetterOrDigit)) ?? s;
        }

        // prefisso cifra lunghezza protobuf finito nel testo (es. "22me:/…")
        if (s.Length > 2
            && char.IsDigit(s[0])
            && (s.StartsWith("me:", StringComparison.Ordinal)
                || s.Contains("me:/", StringComparison.Ordinal)
                || s.StartsWith("l:", StringComparison.Ordinal)))
        {
            var i = 0;
            while (i < s.Length && char.IsDigit(s[i]))
                i++;
            if (i > 0 && i < s.Length)
                s = s[i..];
        }

        return s.Trim('\0').Trim();
    }

    private static string FormatBattery(string raw)
    {
        if (string.IsNullOrEmpty(raw))
            return "";
        if (raw is "0" or "00" or "\u0018\0")
            return "0";
        if (raw is "1" or "01")
            return "1";
        if (raw.Length == 2 && raw[0] == '\u0018')
            return ((int)raw[1]).ToString(CultureInfo.InvariantCulture);
        return raw;
    }

    private static string FormatBatteryBytes(ReadOnlySpan<byte> b)
    {
        // protobuf field3 varint: 18 <value>
        if (b.Length >= 2 && b[0] == 0x18)
            return b[1].ToString(CultureInfo.InvariantCulture);
        return b.Length == 1 ? b[0].ToString(CultureInfo.InvariantCulture) : Convert.ToHexString(b);
    }

    private static string FormatVendor(string raw)
    {
        if (string.IsNullOrEmpty(raw))
            return "";
        if (raw.Length == 2 && raw[0] == '\u0018')
            return raw[1] == 0x4c ? "Apple (0x4C)" : $"0x{((int)raw[1]):X2}";
        return raw;
    }

    private static string FormatVendorBytes(ReadOnlySpan<byte> b)
    {
        if (b.Length >= 2 && b[0] == 0x18)
        {
            if (b[1] == 0x4c)
                return "Apple (0x4C)";
            // zigzag / negative sentinel
            if (b.Length >= 3)
                return Convert.ToHexString(b);
            return $"0x{b[1]:X2}";
        }

        return Convert.ToHexString(b);
    }

    private static string Sanitize(string name)
    {
        var sb = new StringBuilder(name.Length);
        foreach (var c in name)
            sb.Append(char.IsLetterOrDigit(c) || c is '-' or '_' ? c : '_');
        return sb.ToString();
    }

    private static bool TryReadVarint(ReadOnlySpan<byte> data, ref int pos, out ulong value)
    {
        value = 0;
        var shift = 0;
        while (pos < data.Length && shift <= 63)
        {
            var b = data[pos++];
            value |= (ulong)(b & 0x7F) << shift;
            if ((b & 0x80) == 0)
                return true;
            shift += 7;
        }

        return false;
    }
}
