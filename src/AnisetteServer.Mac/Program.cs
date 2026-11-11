using AnisetteServer.Mac.Services;
using Avalonia;
using System;
using System.Threading;
using System.Threading.Tasks;

namespace AnisetteServer.Mac;

class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        // Platform data root → ANISETTE_LICENSE_ROOT before UI / LicensePaths resolve keys+DB.
        MiddlewareSettings.EnsureLicenseEnvironment(
            MiddlewareSettings.Load().DataRoot);

        if (args.Any(a => string.Equals(a, "--headless", StringComparison.OrdinalIgnoreCase)))
        {
            RunHeadlessAsync(args).GetAwaiter().GetResult();
            return;
        }

        BuildAvaloniaApp().StartWithClassicDesktopLifetime(args);
    }

    private static async Task RunHeadlessAsync(string[] args)
    {
        var settings = MiddlewareSettings.Load();
        // Allow CLI overrides: --listen URL --nac-script PATH --nac-plist PATH
        for (var i = 0; i < args.Length; i++)
        {
            if (string.Equals(args[i], "--listen", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                settings.ListenUrls = args[++i];
            else if (string.Equals(args[i], "--nac-script", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                settings.NacScriptRoot = args[++i];
            else if (string.Equals(args[i], "--nac-plist", StringComparison.OrdinalIgnoreCase) && i + 1 < args.Length)
                settings.NacDataPlist = args[++i];
        }

        if (string.IsNullOrWhiteSpace(settings.ListenUrls)
            || settings.ListenUrls.Contains("0.0.0.0", StringComparison.Ordinal))
            settings.ListenUrls = "http://127.0.0.1:6971";

        await using var host = new MiddlewareHost();
        Console.WriteLine($"Headless Anisette middleware → {settings.ListenUrls}");
        await host.StartAsync(settings).ConfigureAwait(false);
        Console.WriteLine(host.StatusText);
        if (!string.IsNullOrEmpty(host.LastError))
        {
            Console.Error.WriteLine(host.LastError);
            Environment.ExitCode = 1;
            return;
        }

        var cts = new CancellationTokenSource();
        Console.CancelKeyPress += (_, e) =>
        {
            e.Cancel = true;
            cts.Cancel();
        };
        try
        {
            await Task.Delay(Timeout.Infinite, cts.Token).ConfigureAwait(false);
        }
        catch (OperationCanceledException)
        {
            // Ctrl+C
        }

        await host.StopAsync().ConfigureAwait(false);
        Console.WriteLine("Stopped.");
    }

    public static AppBuilder BuildAvaloniaApp()
        => AppBuilder.Configure<App>()
            .UsePlatformDetect()
#if DEBUG
            .WithDeveloperTools()
#endif
            .WithInterFont()
            .LogToTrace();
}
