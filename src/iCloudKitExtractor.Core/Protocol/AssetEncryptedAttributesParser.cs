using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Plaintext post-PCS di <c>encryptedAttributes</c> —
/// InflatableDonkey <c>AssetEncryptedAttributesFactory</c> (bplist o protobuf).
/// </summary>
public static class AssetEncryptedAttributesParser
{
    public sealed record Attributes(
        string? Domain,
        string? RelativePath,
        byte[]? EncryptionKey,
        long? Size,
        int? Mode);

    public static bool TryParse(byte[] plain, out Attributes? attributes, out string? error)
    {
        attributes = null;
        error = null;
        if (plain is not { Length: > 0 })
        {
            error = "plaintext vuoto";
            return false;
        }

        if (plain.Length >= 6 && plain.AsSpan(0, 6).SequenceEqual("bplist"u8))
            return TryParseBplist(plain, out attributes, out error);

        if (TryParseProtobuf(plain, out attributes, out error) && attributes is not null)
            return true;

        // XML plist raro.
        var xml = IndexOf(plain, "<?xml"u8);
        if (xml >= 0)
            return TryParseXmlPlist(plain.AsSpan(xml).ToArray(), out attributes, out error);

        error ??= "né bplist né EncryptedAttributes protobuf";
        return false;
    }

    private static bool TryParseBplist(byte[] plain, out Attributes? attributes, out string? error)
    {
        attributes = null;
        if (!AppleBinaryPlist.TryParseDict(plain, out var dict, out error) || dict is null)
            return false;

        attributes = new Attributes(
            TryString(dict, "domain"),
            TryString(dict, "relativePath"),
            TryBytes(dict, "encryptionKey"),
            TryLong(dict, "size"),
            TryInt(dict, "mode"));
        return !string.IsNullOrWhiteSpace(attributes.RelativePath)
               || !string.IsNullOrWhiteSpace(attributes.Domain)
               || attributes.EncryptionKey is { Length: > 0 };
    }

    private static bool TryParseXmlPlist(byte[] plain, out Attributes? attributes, out string? error)
    {
        attributes = null;
        error = null;
        try
        {
            var dict = AppleXmlPlist.Parse(plain);
            attributes = new Attributes(
                TryString(dict, "domain"),
                TryString(dict, "relativePath"),
                TryBytes(dict, "encryptionKey"),
                TryLong(dict, "size"),
                TryInt(dict, "mode"));
            return !string.IsNullOrWhiteSpace(attributes.RelativePath)
                   || !string.IsNullOrWhiteSpace(attributes.Domain)
                   || attributes.EncryptionKey is { Length: > 0 };
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }
    }

    /// <summary>
    /// <c>CloudKit.EncryptedAttributes</c>: 1=relativePath, 2=domain, 6=size, 9=mode, 12=encryptionKey.
    /// </summary>
    private static bool TryParseProtobuf(byte[] plain, out Attributes? attributes, out string? error)
    {
        attributes = null;
        error = null;
        string? domain = null;
        string? relativePath = null;
        byte[]? encryptionKey = null;
        long? size = null;
        int? mode = null;

        try
        {
            var reader = new ProtobufReader(plain);
            while (reader.HasMore)
            {
                var (field, wire) = reader.ReadTag();
                switch (field)
                {
                    case 1 when wire == 2:
                        relativePath = Encoding.UTF8.GetString(reader.ReadLengthDelimited());
                        break;
                    case 2 when wire == 2:
                        domain = Encoding.UTF8.GetString(reader.ReadLengthDelimited());
                        break;
                    case 6 when wire == 0:
                        size = (long)reader.ReadVarint();
                        break;
                    case 9 when wire == 0:
                        mode = (int)reader.ReadVarint();
                        break;
                    case 12 when wire == 2:
                        encryptionKey = reader.ReadLengthDelimited();
                        break;
                    default:
                        reader.SkipField(wire);
                        break;
                }
            }
        }
        catch (Exception ex)
        {
            error = ex.Message;
            return false;
        }

        if (string.IsNullOrWhiteSpace(relativePath)
            && string.IsNullOrWhiteSpace(domain)
            && encryptionKey is not { Length: > 0 })
        {
            error = "protobuf senza path/domain/key";
            return false;
        }

        attributes = new Attributes(domain, relativePath, encryptionKey, size, mode);
        return true;
    }

    private static string? TryString(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value) || value is null)
            return null;
        return value switch
        {
            string s => s.Trim(),
            byte[] b => Encoding.UTF8.GetString(b).Trim(),
            _ => value.ToString()?.Trim()
        };
    }

    private static byte[]? TryBytes(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value) || value is null)
            return null;
        return value switch
        {
            byte[] b => b,
            string s when s.Length > 0 => Encoding.UTF8.GetBytes(s),
            _ => null
        };
    }

    private static long? TryLong(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value) || value is null)
            return null;
        return value switch
        {
            long l => l,
            int i => i,
            string s when long.TryParse(s, out var n) => n,
            _ => null
        };
    }

    private static int? TryInt(Dictionary<string, object?> dict, string key)
    {
        if (!dict.TryGetValue(key, out var value) || value is null)
            return null;
        return value switch
        {
            int i => i,
            long l when l is >= int.MinValue and <= int.MaxValue => (int)l,
            string s when int.TryParse(s, out var n) => n,
            _ => null
        };
    }

    private static int IndexOf(byte[] data, ReadOnlySpan<byte> needle)
    {
        var span = data.AsSpan();
        return span.IndexOf(needle);
    }
}
