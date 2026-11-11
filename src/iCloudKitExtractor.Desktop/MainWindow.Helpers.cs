using Avalonia;
using Avalonia.Controls;
using Avalonia.Input.Platform;
using Avalonia.Layout;
using Avalonia.Media;
using Avalonia.Platform.Storage;
using Avalonia.Threading;
using Avalonia.VisualTree;

namespace iCloudKitExtractor;

internal enum MessageBoxResult
{
    OK,
    Yes,
    No,
}

public partial class MainWindow
{
    /// <summary>Non-blocking info/warning dialog (WPF MessageBox.Show OK replacement).</summary>
    private void ShowMessage(string title, string message)
    {
        try { Console.Error.WriteLine($"[{title}] {message}"); }
        catch { /* ignore */ }

        Dispatcher.UIThread.Post(async () =>
        {
            try
            {
                await ShowDialogAsync(title, message, yesNo: false).ConfigureAwait(true);
            }
            catch
            {
                /* ignore */
            }
        });
    }

    /// <summary>Yes/No confirmation (WPF MessageBox YesNo replacement).</summary>
    private async Task<MessageBoxResult> ShowYesNoAsync(string message, string title)
    {
        var yes = await ShowDialogAsync(title, message, yesNo: true).ConfigureAwait(true);
        return yes ? MessageBoxResult.Yes : MessageBoxResult.No;
    }

    private async Task<bool> ShowDialogAsync(string title, string message, bool yesNo)
    {
        var result = false;
        var dlg = new Window
        {
            Title = title,
            Width = 520,
            MinWidth = 360,
            SizeToContent = SizeToContent.Height,
            WindowStartupLocation = WindowStartupLocation.CenterOwner,
            CanResize = false,
            ShowInTaskbar = false,
        };

        var okButton = new Button
        {
            Content = yesNo ? "Yes" : "OK",
            MinWidth = 80,
            HorizontalContentAlignment = HorizontalAlignment.Center,
        };
        okButton.Click += (_, _) =>
        {
            result = true;
            dlg.Close();
        };

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right,
            Spacing = 8,
            Margin = new Thickness(0, 16, 0, 0),
        };
        buttons.Children.Add(okButton);
        if (yesNo)
        {
            var noButton = new Button
            {
                Content = "No",
                MinWidth = 80,
                HorizontalContentAlignment = HorizontalAlignment.Center,
            };
            noButton.Click += (_, _) =>
            {
                result = false;
                dlg.Close();
            };
            buttons.Children.Add(noButton);
        }

        dlg.Content = new StackPanel
        {
            Margin = new Thickness(20),
            Children =
            {
                new TextBox
                {
                    Text = message,
                    IsReadOnly = true,
                    TextWrapping = TextWrapping.Wrap,
                    BorderThickness = new Thickness(0),
                    Background = Brushes.Transparent,
                    MaxHeight = 360,
                },
                buttons,
            },
        };

        await dlg.ShowDialog(this).ConfigureAwait(true);
        return result;
    }

    /// <summary>Folder picker; null when cancelled.</summary>
    private async Task<string?> PickFolderAsync(string? title = null, string? startFolder = null)
    {
        var options = new FolderPickerOpenOptions
        {
            Title = title ?? "Select folder",
            AllowMultiple = false,
        };
        if (!string.IsNullOrWhiteSpace(startFolder) && Directory.Exists(startFolder))
        {
            try { options.SuggestedStartLocation = await StorageProvider.TryGetFolderFromPathAsync(startFolder); }
            catch { /* ignore */ }
        }

        var folders = await StorageProvider.OpenFolderPickerAsync(options).ConfigureAwait(true);
        return folders.Count > 0 ? folders[0].TryGetLocalPath() : null;
    }

    /// <summary>File picker; null when cancelled. <paramref name="patterns"/> e.g. "*.plist".</summary>
    private async Task<string?> PickFileAsync(string? title = null, params string[] patterns)
    {
        var options = new FilePickerOpenOptions
        {
            Title = title ?? "Select file",
            AllowMultiple = false,
        };
        if (patterns is { Length: > 0 })
        {
            options.FileTypeFilter =
            [
                new FilePickerFileType("Supported") { Patterns = patterns },
                FilePickerFileTypes.All,
            ];
        }

        var files = await StorageProvider.OpenFilePickerAsync(options).ConfigureAwait(true);
        return files.Count > 0 ? files[0].TryGetLocalPath() : null;
    }

    private void SetClipboardText(string text)
    {
        var clipboard = TopLevel.GetTopLevel(this)?.Clipboard;
        if (clipboard is null)
            return;
        _ = clipboard.SetTextAsync(text);
    }

    /// <summary>TextBox.Password replacement helper (PasswordChar TextBox).</summary>
    private static string GetPassword(TextBox? box) => box?.Text ?? "";
}

internal static class TextBoxExtensions
{
    public static void AppendText(this TextBox box, string text) =>
        box.Text = (box.Text ?? "") + text;

    public static int GetLineCount(this TextBox box)
    {
        var t = box.Text;
        if (string.IsNullOrEmpty(t))
            return 0;
        var n = 1;
        foreach (var c in t)
        {
            if (c == '\n')
                n++;
        }

        return n;
    }

    public static void ScrollToEnd(this TextBox box)
    {
        var sv = box.GetVisualDescendants().OfType<ScrollViewer>().FirstOrDefault();
        if (sv is not null)
        {
            sv.ScrollToEnd();
            return;
        }

        box.CaretIndex = box.Text?.Length ?? 0;
    }
}
