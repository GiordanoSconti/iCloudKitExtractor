using System.IO;
using System.Runtime.InteropServices;
using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using System.Windows.Media.Imaging;

namespace PhotosViewer.Services;

/// <summary>Thumbnail Shell Windows (foto + video) via IShellItemImageFactory.</summary>
internal static class ShellThumbnail
{
    private static readonly Guid IidShellItemImageFactory = new("bcc18b79-ba16-442f-80c4-8a59c30c463b");

    public static ImageSource? TryGet(string path, int edgePx)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
            return null;

        IntPtr hbitmap = IntPtr.Zero;
        try
        {
            var iid = IidShellItemImageFactory;
            var hr = SHCreateItemFromParsingName(path, IntPtr.Zero, ref iid, out var factory);
            if (hr != 0 || factory is null)
                return null;

            var size = new SIZE
            {
                cx = Math.Clamp(edgePx, 32, 512),
                cy = Math.Clamp(edgePx, 32, 512)
            };
            factory.GetImage(size, SIIGBF.SIIGBF_RESIZETOFIT | SIIGBF.SIIGBF_BIGGERSIZEOK, out hbitmap);
            if (hbitmap == IntPtr.Zero)
                return null;

            var src = Imaging.CreateBitmapSourceFromHBitmap(
                hbitmap, IntPtr.Zero, Int32Rect.Empty, BitmapSizeOptions.FromEmptyOptions());
            src.Freeze();
            return src;
        }
        catch
        {
            return null;
        }
        finally
        {
            if (hbitmap != IntPtr.Zero)
                DeleteObject(hbitmap);
        }
    }

    [DllImport("shell32.dll", CharSet = CharSet.Unicode, PreserveSig = true)]
    private static extern int SHCreateItemFromParsingName(
        string pszPath, IntPtr pbc, ref Guid riid, out IShellItemImageFactory ppv);

    [DllImport("gdi32.dll")]
    private static extern bool DeleteObject(IntPtr hObject);

    [StructLayout(LayoutKind.Sequential)]
    private struct SIZE
    {
        public int cx;
        public int cy;
    }

    [Flags]
    private enum SIIGBF
    {
        SIIGBF_RESIZETOFIT = 0,
        SIIGBF_BIGGERSIZEOK = 0x01
    }

    [ComImport]
    [Guid("bcc18b79-ba16-442f-80c4-8a59c30c463b")]
    [InterfaceType(ComInterfaceType.InterfaceIsIUnknown)]
    private interface IShellItemImageFactory
    {
        void GetImage(SIZE size, SIIGBF flags, out IntPtr phbm);
    }
}
