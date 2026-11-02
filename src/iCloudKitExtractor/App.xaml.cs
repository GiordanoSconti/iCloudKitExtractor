using System.Windows;
using iCloudKitExtractor.Tools;

namespace iCloudKitExtractor;

/// <summary>
/// Interaction logic for App.xaml
/// </summary>
public partial class App : Application
{
    protected override void OnStartup(StartupEventArgs e)
    {
        if (e.Args is { Length: > 0 }
            && e.Args[0].Equals("msgs-probe", StringComparison.OrdinalIgnoreCase))
        {
            var code = MessagesPcsProbe.Run(e.Args);
            Shutdown(code);
            return;
        }

        base.OnStartup(e);
    }
}

