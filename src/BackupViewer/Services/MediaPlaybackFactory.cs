using System.IO;
using System.Windows.Controls;

namespace BackupViewer.Services;

/// <summary>
/// Crea il player VLC solo se Windows consente di caricare LibVLCSharp
/// (Smart App Control / WDAC possono bloccare la DLL).
/// </summary>
public static class MediaPlaybackFactory
{
    private static string? _loadError;

    public static string? LastLoadError => _loadError;

    public static bool IsBlockedByPolicy(Exception ex) =>
        ex is FileLoadException
            or FileNotFoundException
            or DllNotFoundException
            or BadImageFormatException
            or TypeLoadException
        || (ex.InnerException is not null && IsBlockedByPolicy(ex.InnerException));

    public static IMediaPlayback? TryCreate(Border host, out string? error)
    {
        error = null;
        try
        {
            var vlc = new VlcPlayback();
            vlc.AttachHost(host);
            _loadError = null;
            return vlc;
        }
        catch (Exception ex) when (IsBlockedByPolicy(ex))
        {
            error = FormatPolicyError(ex);
            _loadError = error;
            return null;
        }
        catch (Exception ex)
        {
            error = ex.Message;
            _loadError = error;
            return null;
        }
    }

    public static async Task WarmupSafeAsync(CancellationToken ct = default)
    {
        try
        {
            await VlcPlayback.WarmupAsync(ct).ConfigureAwait(false);
            _loadError = null;
        }
        catch (Exception ex) when (IsBlockedByPolicy(ex))
        {
            _loadError = FormatPolicyError(ex);
        }
        catch (Exception ex)
        {
            _loadError = ex.Message;
        }
    }

    public static string FormatPolicyError(Exception ex)
    {
        var detail = ex.GetBaseException().Message;
        if (detail.Contains("criterio di controllo", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("application control", StringComparison.OrdinalIgnoreCase)
            || detail.Contains("App Control", StringComparison.OrdinalIgnoreCase)
            || ex is FileLoadException)
        {
            return "Windows ha bloccato LibVLCSharp (Smart App Control / WDAC). "
                   + "Firma locale: ricostruisci Release senza SkipLocalSign, "
                   + "oppure disattiva Smart App Control per i build di lab. "
                   + "Dettaglio: " + detail;
        }

        return "Motore media non disponibile: " + detail;
    }
}
