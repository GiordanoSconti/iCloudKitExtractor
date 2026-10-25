using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Fallback Anisette via AOSKit (Microsoft Store iCloud: cartella iCloud del pacchetto).
/// </summary>
public sealed class WindowsAosKitAnisetteProvider : IAnisetteProvider
{
    private readonly AnisetteDeviceStore _deviceStore = new();
    private readonly AppleRuntimeLocator _runtime = new();

    public async Task<AnisetteHeaders> FetchAsync(CancellationToken ct = default)
    {
        var supportDir = await _runtime.EnsureAosKitRuntimeAsync(ct).ConfigureAwait(false);

        var bridgePath = ResolveBridgeExecutable()
            ?? throw new InvalidOperationException(
                "CoreAdiBridge.exe non trovato. Esegui scripts/build-coreadi-bridge.ps1.");

        var psi = new ProcessStartInfo
        {
            FileName = bridgePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        psi.ArgumentList.Add("--command");
        psi.ArgumentList.Add("aoskit-otp");
        psi.ArgumentList.Add("--support-dir");
        psi.ArgumentList.Add(supportDir);

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Impossibile avviare CoreAdiBridge.exe.");

        var stdout = await process.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
        var stderr = await process.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
        await process.WaitForExitAsync(ct).ConfigureAwait(false);

        if (process.ExitCode != 0)
        {
            var detail = string.IsNullOrWhiteSpace(stderr) ? $"exit code {process.ExitCode}" : stderr.Trim();
            throw new InvalidOperationException($"AOSKit non disponibile ({detail}).");
        }

        using var json = JsonDocument.Parse(stdout);
        var root = json.RootElement;
        if (!root.TryGetProperty("ok", out var ok) || ok.ValueKind != JsonValueKind.True)
        {
            var error = root.TryGetProperty("error", out var err) ? err.GetString() : "errore sconosciuto";
            throw new InvalidOperationException($"AOSKit: {error}");
        }

        var md = GetString(root, "X-Apple-I-MD");
        var mdM = GetString(root, "X-Apple-I-MD-M");
        var mdRinfo = GetString(root, "X-Apple-I-MD-RINFO");
        var clientTime = GetString(root, "X-Apple-I-ClientTime");

        if (string.IsNullOrEmpty(md) || string.IsNullOrEmpty(mdM))
            throw new InvalidOperationException("AOSKit non ha restituito X-Apple-I-MD / X-Apple-I-MD-M.");

        if (string.IsNullOrEmpty(mdRinfo))
            throw new InvalidOperationException("X-Apple-I-MD-RINFO mancante da AOSKit.");

        var culture = CultureInfo.CurrentUICulture;
        RegionInfo region;
        try
        {
            region = new RegionInfo(culture.Name);
        }
        catch
        {
            region = new RegionInfo("US");
        }

        return new AnisetteHeaders
        {
            Md = md,
            MdM = mdM,
            MdRinfo = mdRinfo,
            ClientTimeUtc = string.IsNullOrEmpty(clientTime)
                ? DateTime.UtcNow.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'", CultureInfo.InvariantCulture)
                : clientTime,
            SerialNumber = _deviceStore.GetOrCreateSerialNumber(),
            ClientProductType = _deviceStore.GetOrCreateClientProductType(),
            Locale = culture.Name.Replace('-', '_'),
            TimeZone = TimeZoneInfo.Local.Id,
            CountryCode = region.TwoLetterISORegionName
        };
    }

    private static string? ResolveBridgeExecutable()
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, "CoreAdiBridge.exe"),
            Path.Combine(AppContext.BaseDirectory, "native", "CoreAdiBridge", "out", "CoreAdiBridge.exe"),
            Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "native", "CoreAdiBridge", "out", "CoreAdiBridge.exe"))
        };

        foreach (var path in candidates)
        {
            if (File.Exists(path))
                return path;
        }

        return null;
    }

    private static string GetString(JsonElement root, string name) =>
        root.TryGetProperty(name, out var value) && value.ValueKind == JsonValueKind.String
            ? value.GetString() ?? string.Empty
            : string.Empty;
}
