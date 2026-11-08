namespace BackupViewer.Services;

public static class AppleTime
{
    private static readonly DateTimeOffset CocoaEpoch =
        new(2001, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public static DateTimeOffset? FromCocoa(double? seconds)
    {
        if (seconds is null || double.IsNaN(seconds.Value) || double.IsInfinity(seconds.Value))
            return null;
        if (Math.Abs(seconds.Value) < 0.0001)
            return null;
        try
        {
            return CocoaEpoch.AddSeconds(seconds.Value);
        }
        catch
        {
            return null;
        }
    }

    public static DateTimeOffset? FromCocoa(long? seconds) =>
        seconds is null ? null : FromCocoa((double)seconds.Value);

    public static string Format(DateTimeOffset? dt, bool includeTime = true)
    {
        if (dt is null)
            return "—";
        var local = dt.Value.ToLocalTime();
        return includeTime
            ? local.ToString("dd/MM/yyyy HH:mm")
            : local.ToString("dd/MM/yyyy");
    }

    public static string FormatDuration(double? seconds)
    {
        if (seconds is null || seconds <= 0)
            return "—";
        var t = TimeSpan.FromSeconds(seconds.Value);
        if (t.TotalHours >= 1)
            return $"{(int)t.TotalHours}:{t.Minutes:D2}:{t.Seconds:D2}";
        return $"{t.Minutes}:{t.Seconds:D2}";
    }
}
