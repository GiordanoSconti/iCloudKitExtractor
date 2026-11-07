using System.IO;
using System.Windows;
using iCloudKitExtractor.Services.Forensics;
using iCloudKitExtractor.Services.SyncData;
using iCloudKitExtractor.Tools;

namespace iCloudKitExtractor;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        try { SqliteBootstrap.EnsureInitialized(); }
        catch { /* Notes/Photos aprono SQLite al bisogno con errore dettagliato */ }

        if (e.Args is { Length: > 0 }
            && e.Args[0].Equals("msgs-probe", StringComparison.OrdinalIgnoreCase))
        {
            var code = MessagesPcsProbe.Run(e.Args);
            Shutdown(code);
            return;
        }

        if (e.Args is { Length: > 0 }
            && e.Args[0].Equals("msgs-inventory", StringComparison.OrdinalIgnoreCase))
        {
            var dir = e.Args.Length > 1
                ? e.Args[1]
                : Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.MyDocuments),
                    "iCloudBackups");
            // Se passano la root backups, prendi sync_data_* più recente / apple.messages.cloud
            if (!Directory.Exists(Path.Combine(dir, "crypto"))
                && !File.Exists(Path.Combine(dir, "session.txt")))
            {
                var sync = Directory.GetDirectories(dir, "sync_data_*")
                    .OrderByDescending(Directory.GetLastWriteTimeUtc)
                    .FirstOrDefault();
                if (sync is not null)
                    dir = Path.Combine(sync, "ck", "apple.messages.cloud");
            }

            var log = new Progress<string>(s =>
            {
                try { Console.WriteLine(s); } catch { /* WinExe */ }
                System.Diagnostics.Debug.WriteLine(s);
            });
            var summary = MessagesInventoryBuilder.Build(dir, log);
            var html = MessagesHtmlViewerPublisher.Publish(dir, log: log);
            try
            {
                Console.WriteLine(
                    $"messages={summary.Messages} chats={summary.Chats} " +
                    $"withText={summary.WithText}\n{summary.TsvPath}");
                if (html is not null)
                    Console.WriteLine($"html={html}");
            }
            catch { /* WinExe */ }
            Shutdown(summary.Messages > 0 ? 0 : 2);
            return;
        }

        base.OnStartup(e);
    }
}

