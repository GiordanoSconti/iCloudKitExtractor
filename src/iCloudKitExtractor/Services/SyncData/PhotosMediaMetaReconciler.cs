using System.Globalization;
using System.IO;
using System.Text.RegularExpressions;
using MetadataExtractor;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Riallinea <c>mediaMetaDataEnc</c> ai file reali: il binding CloudKit per UUID
/// a volte attacca il bplist GPS/data di un altro master (~25% mismatch osservati).
/// Matching per fingerprint EXIF/QuickTime (data + lat/lon).
/// </summary>
public static class PhotosMediaMetaReconciler
{
    private const string MediaMetaField = "mediaMetaDataEnc";
    private const double MatchKm = 0.15;

    private static readonly Regex QuickTimeGps = new(
        @"([+-]\d+\.?\d*)([+-]\d+\.?\d*)",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public static int RebindByFileExif(
        PhotosMediaMetaCache cache,
        IReadOnlyList<PhotosMediaMetaCache.MediaEntry> entries,
        Func<PhotosMediaMetaCache.MediaEntry, string?> resolvePlainPath,
        IProgress<string>? log = null)
    {
        var pool = BuildMetaPool(cache);
        if (pool.Count == 0)
        {
            log?.Report("  mediaMeta rebind: pool vuoto (nessun GPS in mediaMetaDataEnc)");
            return 0;
        }

        var rebound = 0;
        var unmatched = 0;
        var alreadyOk = 0;

        foreach (var entry in entries)
        {
            if (string.IsNullOrWhiteSpace(entry.MmcsAuth))
                continue;

            var path = resolvePlainPath(entry);
            if (path is null || !File.Exists(path))
                continue;

            if (!TryReadFileFingerprint(path, out var fileFp))
                continue;

            var current = cache.GetExtraForAuth(entry.MmcsAuth);
            string? currentRaw = null;
            current?.TryGetValue(MediaMetaField, out currentRaw);

            if (!string.IsNullOrWhiteSpace(currentRaw)
                && TryFingerprintFromMediaMeta(currentRaw, out var curFp)
                && FingerprintsMatch(curFp, fileFp))
            {
                alreadyOk++;
                continue;
            }

            if (!TryFindDonor(pool, fileFp, out var donorRaw))
            {
                unmatched++;
                // Metadati CloudKit sul record sbagliato e nessun donor: togli GPS errato
                // (il Viewer userà EXIF del file).
                if (!string.IsNullOrWhiteSpace(currentRaw)
                    && TryFingerprintFromMediaMeta(currentRaw, out var badFp)
                    && !FingerprintsMatch(badFp, fileFp))
                    cache.RemoveExtraByAuth(entry.MmcsAuth, MediaMetaField);
                continue;
            }

            if (string.Equals(currentRaw, donorRaw, StringComparison.Ordinal))
            {
                alreadyOk++;
                continue;
            }

            cache.UpsertExtraByAuth(entry.MmcsAuth, MediaMetaField, donorRaw);
            rebound++;
        }

        // Live companion: copia mediaMeta dal master (dopo rebind) se assente o mismatched.
        var liveCopied = PropagateLiveMediaMeta(cache, entries);

        if (rebound > 0 || unmatched > 0 || liveCopied > 0)
        {
            log?.Report(
                $"  mediaMeta rebind: corretti={rebound}, già-ok={alreadyOk}, " +
                $"senza-donor={unmatched}, live-copy={liveCopied}, pool={pool.Count}");
        }

        return rebound;
    }

    private static int PropagateLiveMediaMeta(
        PhotosMediaMetaCache cache,
        IReadOnlyList<PhotosMediaMetaCache.MediaEntry> entries)
    {
        var byRecord = entries
            .Where(static e => !string.IsNullOrWhiteSpace(e.RecordName))
            .GroupBy(static e => e.RecordName, StringComparer.OrdinalIgnoreCase)
            .ToDictionary(static g => g.Key, static g => g.First(), StringComparer.OrdinalIgnoreCase);

        var copied = 0;
        foreach (var live in entries)
        {
            if (!live.RecordName.EndsWith("_Live", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(live.MmcsAuth))
                continue;

            var masterName = live.RecordName[..^5];
            if (!byRecord.TryGetValue(masterName, out var master)
                || string.IsNullOrWhiteSpace(master.MmcsAuth))
                continue;

            var masterExtra = cache.GetExtraForAuth(master.MmcsAuth);
            if (masterExtra is null
                || !masterExtra.TryGetValue(MediaMetaField, out var raw)
                || string.IsNullOrWhiteSpace(raw))
                continue;

            cache.UpsertExtraByAuth(live.MmcsAuth, MediaMetaField, raw);
            copied++;
        }

        return copied;
    }

    private static List<(GpsFingerprint Fp, string Raw)> BuildMetaPool(PhotosMediaMetaCache cache)
    {
        var pool = new List<(GpsFingerprint, string)>();
        var seen = new HashSet<string>(StringComparer.Ordinal);

        foreach (var entry in cache.Entries)
        {
            if (string.IsNullOrWhiteSpace(entry.MmcsAuth))
                continue;
            var extra = cache.GetExtraForAuth(entry.MmcsAuth);
            if (extra is null || !extra.TryGetValue(MediaMetaField, out var raw)
                || string.IsNullOrWhiteSpace(raw))
                continue;
            if (!seen.Add(raw))
                continue;
            if (!TryFingerprintFromMediaMeta(raw, out var fp))
                continue;
            pool.Add((fp, raw));
        }

        return pool;
    }

    private static bool TryFindDonor(
        List<(GpsFingerprint Fp, string Raw)> pool,
        GpsFingerprint fileFp,
        out string donorRaw)
    {
        donorRaw = "";
        (GpsFingerprint Fp, string Raw)? best = null;
        var bestDist = double.MaxValue;

        foreach (var item in pool)
        {
            if (!DatesCompatible(item.Fp.Date, fileFp.Date))
                continue;
            var dist = HaversineKm(item.Fp.Lat, item.Fp.Lon, fileFp.Lat, fileFp.Lon);
            if (dist > MatchKm)
                continue;
            if (dist < bestDist)
            {
                bestDist = dist;
                best = item;
            }
        }

        if (best is null)
            return false;
        donorRaw = best.Value.Raw;
        return true;
    }

    private static bool FingerprintsMatch(GpsFingerprint a, GpsFingerprint b) =>
        DatesCompatible(a.Date, b.Date)
        && HaversineKm(a.Lat, a.Lon, b.Lat, b.Lon) <= MatchKm;

    private static bool DatesCompatible(string? a, string? b)
    {
        if (string.IsNullOrWhiteSpace(a) || string.IsNullOrWhiteSpace(b))
            return true; // GPS alone
        var na = NormalizeDate(a);
        var nb = NormalizeDate(b);
        // Stesso giorno (GPS già filtra i casi ambigui).
        return na.Length >= 10 && nb.Length >= 10
            && string.Equals(na[..10], nb[..10], StringComparison.Ordinal);
    }

    private static string NormalizeDate(string raw)
    {
        // EXIF "2025:09:29 09:00:34" or QuickTime "lun set 29 09:00:34 +02:00 2025"
        raw = raw.Trim();
        if (raw.Length >= 19 && raw[4] == ':' && raw[10] == ' ')
            return raw;

        if (DateTime.TryParse(raw, CultureInfo.InvariantCulture, DateTimeStyles.AllowWhiteSpaces, out var dt)
            || DateTime.TryParse(raw, new CultureInfo("it-IT"), DateTimeStyles.AllowWhiteSpaces, out dt))
            return dt.ToString("yyyy:MM:dd HH:mm:ss", CultureInfo.InvariantCulture);

        return raw;
    }

    private static bool TryFingerprintFromMediaMeta(string rawOrB64, out GpsFingerprint fp)
    {
        fp = default;
        var decoded = MediaMetaBplist.TryDecode(rawOrB64);
        if (decoded is not Dictionary<string, object?> dict)
            return false;

        if (!dict.TryGetValue("{GPS}", out var gpsObj) && !dict.TryGetValue("GPS", out gpsObj))
            return false;
        if (gpsObj is not Dictionary<string, object?> gps)
            return false;

        var lat = MediaMetaBplist.TryDouble(gps.GetValueOrDefault("Latitude"));
        var lon = MediaMetaBplist.TryDouble(gps.GetValueOrDefault("Longitude"));
        if (lat is null || lon is null)
            return false;
        if (IsSouthWest(gps.GetValueOrDefault("LatitudeRef")))
            lat = -lat;
        if (IsSouthWest(gps.GetValueOrDefault("LongitudeRef")))
            lon = -lon;

        string? date = null;
        if (dict.TryGetValue("{Exif}", out var exifObj) && exifObj is Dictionary<string, object?> exif)
            date = exif.GetValueOrDefault("DateTimeOriginal")?.ToString();

        fp = new GpsFingerprint(lat.Value, lon.Value, date);
        return true;
    }

    private static bool TryReadFileFingerprint(string path, out GpsFingerprint fp)
    {
        fp = default;
        try
        {
            double? lat = null, lon = null;
            string? latRef = null, lonRef = null, date = null;

            foreach (var dir in ImageMetadataReader.ReadMetadata(path))
            {
                foreach (var tag in dir.Tags)
                {
                    var name = tag.Name ?? "";
                    var desc = tag.Description;
                    if (string.IsNullOrWhiteSpace(desc))
                        continue;

                    if (name is "GPS Latitude" or "Latitude")
                        lat = ParseGpsComponent(desc);
                    else if (name is "GPS Longitude" or "Longitude")
                        lon = ParseGpsComponent(desc);
                    else if (name is "GPS Latitude Ref")
                        latRef = desc;
                    else if (name is "GPS Longitude Ref")
                        lonRef = desc;
                    else if (name is "GPS Location")
                        ParseQuickTimeLocation(desc, ref lat, ref lon);
                    else if (name is "Date/Time Original")
                        date ??= desc;
                    else if (name is "Creation Date" && date is null)
                        date = desc;
                }
            }

            if (lat is null || lon is null)
                return false;
            if (latRef is not null && latRef.StartsWith("S", StringComparison.OrdinalIgnoreCase))
                lat = -lat;
            if (lonRef is not null && lonRef.StartsWith("W", StringComparison.OrdinalIgnoreCase))
                lon = -lon;

            fp = new GpsFingerprint(lat.Value, lon.Value, date);
            return true;
        }
        catch
        {
            return false;
        }
    }

    private static void ParseQuickTimeLocation(string loc, ref double? lat, ref double? lon)
    {
        var m = QuickTimeGps.Match(loc);
        if (!m.Success)
            return;
        if (double.TryParse(m.Groups[1].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var a)
            && double.TryParse(m.Groups[2].Value, NumberStyles.Float, CultureInfo.InvariantCulture, out var b))
        {
            lat = a;
            lon = b;
        }
    }

    private static double? ParseGpsComponent(string desc)
    {
        desc = desc.Trim().Replace(',', '.');
        if (desc.Contains('°', StringComparison.Ordinal))
        {
            var parts = desc.Split(['°', '\'', '"', ' '], StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0
                || !double.TryParse(parts[0], NumberStyles.Float, CultureInfo.InvariantCulture, out var deg))
                return null;
            double min = 0, sec = 0;
            if (parts.Length > 1)
                double.TryParse(parts[1], NumberStyles.Float, CultureInfo.InvariantCulture, out min);
            if (parts.Length > 2)
                double.TryParse(parts[2], NumberStyles.Float, CultureInfo.InvariantCulture, out sec);
            return deg + min / 60.0 + sec / 3600.0;
        }

        return double.TryParse(desc, NumberStyles.Float, CultureInfo.InvariantCulture, out var d) ? d : null;
    }

    private static bool IsSouthWest(object? refValue) =>
        refValue is string s && s.Length > 0 && s[0] is 'S' or 's' or 'W' or 'w';

    private static double HaversineKm(double lat1, double lon1, double lat2, double lon2)
    {
        const double r = 6371.0;
        var dLat = (lat2 - lat1) * Math.PI / 180.0;
        var dLon = (lon2 - lon1) * Math.PI / 180.0;
        var a = Math.Sin(dLat / 2) * Math.Sin(dLat / 2)
                + Math.Cos(lat1 * Math.PI / 180.0) * Math.Cos(lat2 * Math.PI / 180.0)
                  * Math.Sin(dLon / 2) * Math.Sin(dLon / 2);
        return 2 * r * Math.Asin(Math.Min(1, Math.Sqrt(a)));
    }

    private readonly record struct GpsFingerprint(double Lat, double Lon, string? Date);
}
