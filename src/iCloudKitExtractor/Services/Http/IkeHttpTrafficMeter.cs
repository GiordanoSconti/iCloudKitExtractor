namespace iCloudKitExtractor.Services.Http;

/// <summary>
/// Contatore HTTP di sessione: body request + response (wire) distinti dai byte Backup UI.
/// Attivo solo tra <see cref="ResetAndEnable"/> e <see cref="Disable"/> (download snapshot).
/// </summary>
public static class IkeHttpTrafficMeter
{
    private static int _enabled;
    private static long _requestBytes;
    private static long _responseBytes;
    private static long _requestCount;
    private static long _responseCount;

    public static bool IsEnabled => Volatile.Read(ref _enabled) != 0;

    public static long RequestBytes => Volatile.Read(ref _requestBytes);

    public static long ResponseBytes => Volatile.Read(ref _responseBytes);

    /// <summary>Somma body HTTP request + response dal Reset.</summary>
    public static long TotalBytes => RequestBytes + ResponseBytes;

    public static long RequestCount => Volatile.Read(ref _requestCount);

    public static long ResponseCount => Volatile.Read(ref _responseCount);

    public static void ResetAndEnable()
    {
        Interlocked.Exchange(ref _requestBytes, 0);
        Interlocked.Exchange(ref _responseBytes, 0);
        Interlocked.Exchange(ref _requestCount, 0);
        Interlocked.Exchange(ref _responseCount, 0);
        Volatile.Write(ref _enabled, 1);
    }

    public static void Disable() => Volatile.Write(ref _enabled, 0);

    public static void AddRequest(long bytes)
    {
        if (Volatile.Read(ref _enabled) == 0 || bytes <= 0)
            return;
        Interlocked.Add(ref _requestBytes, bytes);
        Interlocked.Increment(ref _requestCount);
    }

    public static void AddResponse(long bytes)
    {
        if (Volatile.Read(ref _enabled) == 0 || bytes <= 0)
            return;
        Interlocked.Add(ref _responseBytes, bytes);
        Interlocked.Increment(ref _responseCount);
    }
}
