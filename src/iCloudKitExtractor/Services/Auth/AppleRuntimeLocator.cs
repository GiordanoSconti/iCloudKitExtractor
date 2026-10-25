using System.Diagnostics;
using System.IO;
using Microsoft.Win32;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Individua e copia le DLL Apple (CoreADI/AOSKit) in AppData.
/// WindowsApps consente File.Copy ma blocca LoadLibrary per app esterne.
/// </summary>
public sealed class AppleRuntimeLocator
{
    private static readonly string[] KnownDllNames =
    [
        "CoreADI64.dll",
        "CoreADI32.dll",
        "CoreADI.dll",
        "AOSKit.dll",
        "objc.dll",
        "CoreFoundation.dll",
        "Foundation.dll",
        "libdispatch.dll",
        "pthreadVC2.dll",
        "zlib1.dll",
        "icudt62.dll",
        "libicuuc.dll",
        "libicuin.dll",
        "libxml2.dll",
        "CFNetwork.dll",
        "SQLite3.dll",
        "ASL.dll"
    ];

    private static readonly string RuntimeRoot = Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "iCloudKitExtractor",
        "runtime");

    public string RuntimeDirectory => RuntimeRoot;

    public string ProvisioningDirectory => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "iCloudKitExtractor",
        "adi");

    public string GetProvisioningDirectory(AdiDeviceProfile profile) => Path.Combine(
        Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
        "iCloudKitExtractor",
        profile.ProvisioningSubdir);

    public void EnsureProvisioningDirectory(AdiDeviceProfile profile) =>
        Directory.CreateDirectory(GetProvisioningDirectory(profile));

    public Task<string> EnsureRuntimeAsync(CancellationToken ct = default) =>
        EnsureStagedRuntimeAsync(requireCoreAdi: true, requireAosKit: false, requireWin32Foundation: false, ct);

    public Task<string> EnsureAosKitRuntimeAsync(CancellationToken ct = default) =>
        EnsureStagedRuntimeAsync(requireCoreAdi: false, requireAosKit: true, requireWin32Foundation: true, ct);

    public void EnsureProvisioningDirectory() => Directory.CreateDirectory(ProvisioningDirectory);

    private async Task<string> EnsureStagedRuntimeAsync(
        bool requireCoreAdi,
        bool requireAosKit,
        bool requireWin32Foundation,
        CancellationToken ct)
    {
        Directory.CreateDirectory(RuntimeRoot);

        if (IsStagedRuntimeReady(RuntimeRoot, requireCoreAdi, requireAosKit))
            return RuntimeRoot;

        foreach (var source in await DiscoverSourceDirectoriesAsync(requireWin32Foundation, ct).ConfigureAwait(false))
        {
            ct.ThrowIfCancellationRequested();
            if (!IsValidSource(source, requireCoreAdi, requireAosKit, requireWin32Foundation))
                continue;

            if (TryCopyRuntime(source, RuntimeRoot)
                && IsStagedRuntimeReady(RuntimeRoot, requireCoreAdi, requireAosKit))
            {
                return RuntimeRoot;
            }
        }

        throw new InvalidOperationException(
            requireWin32Foundation
                ? "AOSKit Win32 non trovato (iTunes/iCloud dal sito Apple). Con iCloud Microsoft Store usa solo CoreADI."
                : "DLL Apple non accessibili. Installa iCloud dal Microsoft Store, tienilo in esecuzione, " +
                  "poi riprova (le DLL verranno copiate in AppData).");
    }

    private static bool HasCoreAdi(string directory) =>
        File.Exists(Path.Combine(directory, "CoreADI64.dll"))
        || File.Exists(Path.Combine(directory, "CoreADI.dll"));

    private static bool HasAosKit(string directory) =>
        File.Exists(Path.Combine(directory, "AOSKit.dll"));

    private static bool HasObjc(string directory) =>
        File.Exists(Path.Combine(directory, "objc.dll"));

    private static bool IsAppleRuntimeDirectory(string directory) =>
        HasCoreAdi(directory) || HasAosKit(directory);

    private static bool IsStagedRuntimeReady(string directory, bool requireCoreAdi, bool requireAosKit) =>
        (!requireCoreAdi || HasCoreAdi(directory))
        && (!requireAosKit || (HasAosKit(directory) && HasObjc(directory)));

    private static bool HasWin32Foundation(string directory) =>
        File.Exists(Path.Combine(directory, "Foundation.dll"));

    private static bool IsValidSource(string directory, bool requireCoreAdi, bool requireAosKit, bool requireWin32Foundation) =>
        (!requireCoreAdi || HasCoreAdi(directory))
        && (!requireAosKit || HasAosKit(directory))
        && (!requireWin32Foundation || HasWin32Foundation(directory));

    private static async Task<IReadOnlyList<string>> DiscoverSourceDirectoriesAsync(bool requireWin32Foundation, CancellationToken ct)
    {
        var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        void AddCandidate(string? path)
        {
            if (string.IsNullOrWhiteSpace(path)) return;
            try
            {
                var full = Path.GetFullPath(path);
                if (IsAppleRuntimeDirectory(full))
                    seen.Add(full);

                var iCloud = Path.Combine(full, "iCloud");
                if (IsAppleRuntimeDirectory(iCloud))
                    seen.Add(iCloud);
            }
            catch
            {
                // Percorso non valido.
            }
        }

        AddCandidate(ReadRegistryInstallDir());
        AddCandidate(@"C:\Program Files (x86)\Common Files\Apple\Apple Application Support");
        AddCandidate(@"C:\Program Files\Common Files\Apple\Apple Application Support");

        foreach (var dir in FindFromRunningAppleProcesses())
            seen.Add(dir);

        foreach (var dir in FindFromProcessModules())
            seen.Add(dir);

        foreach (var dir in await QueryAppxInstallLocationsAsync(ct).ConfigureAwait(false))
            AddCandidate(dir);

        if (requireWin32Foundation)
        {
            var installDir = ReadRegistryInstallDir();
            if (!string.IsNullOrWhiteSpace(installDir))
            {
                var internetServices = Path.Combine(Path.GetDirectoryName(installDir.TrimEnd('\\')) ?? installDir, "Internet Services");
                AddCandidate(internetServices);
            }
        }

        return seen.ToList();
    }

    private static IEnumerable<string> FindFromRunningAppleProcesses()
    {
        var results = new List<string>();
        var processNames = new[] { "iCloudHome", "iCloudCKKS", "ApplePhotoStreams", "iCloudOutlookConfig64", "iTunes" };
        foreach (var name in processNames)
        {
            foreach (var process in Process.GetProcessesByName(name))
            {
                try
                {
                    var exePath = process.MainModule?.FileName;
                    if (string.IsNullOrWhiteSpace(exePath)) continue;
                    var dir = Path.GetDirectoryName(exePath);
                    if (dir is null) continue;

                    if (IsAppleRuntimeDirectory(dir))
                        results.Add(dir);
                }
                catch
                {
                    // Accesso al processo negato.
                }
                finally
                {
                    process.Dispose();
                }
            }
        }

        return results;
    }

    private static IEnumerable<string> FindFromProcessModules()
    {
        var results = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var process in Process.GetProcesses())
        {
            try
            {
                var name = process.ProcessName;
                if (!name.StartsWith("iCloud", StringComparison.OrdinalIgnoreCase)
                    && !name.Equals("ApplePhotoStreams", StringComparison.OrdinalIgnoreCase)
                    && !name.Equals("iTunes", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                foreach (ProcessModule module in process.Modules)
                {
                    var fileName = module.FileName;
                    if (string.IsNullOrWhiteSpace(fileName)) continue;

                    var baseName = Path.GetFileName(fileName);
                    if (!baseName.Equals("AOSKit.dll", StringComparison.OrdinalIgnoreCase)
                        && !baseName.Equals("CoreADI64.dll", StringComparison.OrdinalIgnoreCase)
                        && !baseName.Equals("objc.dll", StringComparison.OrdinalIgnoreCase)
                        && !baseName.Equals("CoreFoundation.dll", StringComparison.OrdinalIgnoreCase))
                    {
                        continue;
                    }

                    var dir = Path.GetDirectoryName(fileName);
                    if (!string.IsNullOrWhiteSpace(dir))
                        results.Add(dir);
                }
            }
            catch
            {
                // Moduli non accessibili senza privilegi elevati.
            }
            finally
            {
                process.Dispose();
            }
        }

        return results;
    }

    private static async Task<IEnumerable<string>> QueryAppxInstallLocationsAsync(CancellationToken ct)
    {
        var results = new List<string>();
        try
        {
            var psi = new ProcessStartInfo
            {
                FileName = "powershell",
                Arguments = "-NoProfile -Command \"Get-AppxPackage -Name 'AppleInc.*' | Select-Object -ExpandProperty InstallLocation\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process is null) return results;

            var stdout = await process.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
            await process.WaitForExitAsync(ct).ConfigureAwait(false);

            foreach (var line in stdout.Split(['\r', '\n'], StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = line.Trim();
                if (trimmed.Length > 0)
                    results.Add(trimmed);
            }
        }
        catch
        {
            // PowerShell/Appx non disponibile.
        }

        return results;
    }

    private static string? ReadRegistryInstallDir()
    {
        foreach (var view in new[] { RegistryView.Registry64, RegistryView.Registry32 })
        {
            try
            {
                using var baseKey = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, view);
                using var key = baseKey.OpenSubKey(@"SOFTWARE\Apple Inc.\Apple Application Support");
                var installDir = key?.GetValue("InstallDir") as string;
                if (!string.IsNullOrWhiteSpace(installDir))
                    return installDir;
            }
            catch
            {
                // Ignora errori di accesso al registro.
            }
        }

        return null;
    }

    private static bool TryCopyRuntime(string source, string destination)
    {
        Directory.CreateDirectory(destination);

        if (TryCopyAllDllsViaPowerShell(source, destination))
            return true;

        var copiedAny = false;

        foreach (var dllName in KnownDllNames)
        {
            var srcPath = Path.Combine(source, dllName);
            if (!File.Exists(srcPath))
                continue;

            try
            {
                File.Copy(srcPath, Path.Combine(destination, dllName), overwrite: true);
                copiedAny = true;
            }
            catch (UnauthorizedAccessException)
            {
                return false;
            }
            catch (IOException)
            {
                // Singola DLL non copiabile.
            }
        }

        return copiedAny;
    }

    private static bool TryCopyAllDllsViaPowerShell(string source, string destination)
    {
        try
        {
            var escapedSource = source.Replace("'", "''");
            var escapedDest = destination.Replace("'", "''");
            var psi = new ProcessStartInfo
            {
                FileName = "powershell",
                Arguments = $"-NoProfile -Command \"Copy-Item -LiteralPath '{escapedSource}\\*.dll' -Destination '{escapedDest}' -Force -ErrorAction Stop\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            using var process = Process.Start(psi);
            if (process is null) return false;

            process.WaitForExit();
            return process.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }
}
