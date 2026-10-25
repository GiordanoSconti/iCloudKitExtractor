using System.Globalization;
using System.Text.Json;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

internal static class AnisetteJsonParser
{
    public static bool TryParseHeaders(string json, out AnisetteHeaderPayload payload)
    {
        payload = default;
        if (string.IsNullOrWhiteSpace(json))
            return false;

        try
        {
            using var doc = JsonDocument.Parse(json);
            return TryParseElement(doc.RootElement, out payload);
        }
        catch (JsonException)
        {
            return false;
        }
    }

    private static bool TryParseElement(JsonElement root, out AnisetteHeaderPayload payload)
    {
        payload = default;

        if (root.ValueKind == JsonValueKind.Object)
        {
            if (TryReadHeaderObject(root, out payload))
                return true;

            foreach (var key in new[] { "headers", "header", "data", "result" })
            {
                if (root.TryGetProperty(key, out var nested) && TryParseElement(nested, out payload))
                    return true;
            }
        }

        return false;
    }

    private static bool TryReadHeaderObject(JsonElement obj, out AnisetteHeaderPayload payload)
    {
        payload = default;
        var md = ReadString(obj, "X-Apple-I-MD");
        var mdM = ReadString(obj, "X-Apple-I-MD-M");
        if (string.IsNullOrEmpty(md) || string.IsNullOrEmpty(mdM))
            return false;

        payload = new AnisetteHeaderPayload
        {
            Md = md,
            MdM = mdM,
            MdLu = ReadString(obj, "X-Apple-I-MD-LU"),
            MdRinfo = ReadString(obj, "X-Apple-I-MD-RINFO"),
            ClientTime = ReadString(obj, "X-Apple-I-Client-Time"),
            SerialNumber = ReadString(obj, "serialNumber", "X-Apple-I-SRL-NO"),
            ClientMmeInfo = ReadString(obj, "X-MMe-Client-Info"),
            MmeDeviceId = ReadString(obj, "X-Mme-Device-Id", "X-MMe-Device-Id"),
            ClientProductType = ReadString(obj, "clientProductType"),
            Locale = ReadString(obj, "locale", "X-Apple-I-Locale", "X-Apple-Locale"),
            TimeZone = ReadString(obj, "timeZone", "X-Apple-I-TimeZone"),
            CountryCode = ReadString(obj, "countryCode", "cou")
        };
        return true;
    }

    private static string? ReadString(JsonElement obj, params string[] names)
    {
        foreach (var name in names)
        {
            if (!obj.TryGetProperty(name, out var value))
                continue;
            if (value.ValueKind == JsonValueKind.String)
            {
                var text = value.GetString();
                if (!string.IsNullOrEmpty(text))
                    return text;
            }
        }

        return null;
    }

    internal readonly record struct AnisetteHeaderPayload
    {
        public required string Md { get; init; }
        public required string MdM { get; init; }
        public string? MdLu { get; init; }
        public string? MdRinfo { get; init; }
        public string? ClientTime { get; init; }
        public string? SerialNumber { get; init; }
        public string? ClientMmeInfo { get; init; }
        public string? MmeDeviceId { get; init; }
        public string? ClientProductType { get; init; }
        public string? Locale { get; init; }
        public string? TimeZone { get; init; }
        public string? CountryCode { get; init; }

        public AnisetteHeaders ToHeaders()
        {
            var rinfo = string.IsNullOrEmpty(MdRinfo) || MdRinfo == "84215040"
                ? GrandSlamCpdBuilder.IosMdRinfo.ToString(CultureInfo.InvariantCulture)
                : MdRinfo;

            return new AnisetteHeaders
            {
                Md = Md,
                MdM = MdM,
                MdLu = MdLu ?? string.Empty,
                MdRinfo = rinfo,
                ClientTimeUtc = string.IsNullOrEmpty(ClientTime)
                    ? DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
                    : ClientTime,
                SerialNumber = SerialNumber ?? string.Empty,
                ClientMmeInfo = ClientMmeInfo ?? string.Empty,
                MmeDeviceId = MmeDeviceId ?? string.Empty,
                ClientProductType = ClientProductType ?? string.Empty,
                Locale = string.IsNullOrEmpty(Locale) ? "en_US" : Locale,
                TimeZone = TimeZone ?? TimeZoneInfo.Local.Id,
                CountryCode = CountryCode ?? "US"
            };
        }
    }
}
