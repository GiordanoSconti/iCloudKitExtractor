using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Text.Json;

namespace iCloudKitExtractor.Services.Auth;

public sealed class CoreAdiBridgeClient : IAdiCryptoClient
{
    public bool RequiresWindowsCoreAdiRuntime => true;
    public bool OwnsMidServiceHttp => false;

    public Task WipeLibraryProvisioningAsync(
        string runtimeDir, string provisioningDir, string adiId, CancellationToken ct = default) =>
        Task.CompletedTask;

    public Task ProvisionViaLibraryAsync(
        string runtimeDir, string provisioningDir, string adiId, long dsId = -2, CancellationToken ct = default) =>
        throw new NotSupportedException("CoreADI usa MidService HTTP in AdiProvisioningService, non ProvisionViaLibrary.");
    public async Task<bool> IsProvisionedAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        long dsId = -2,
        CancellationToken ct = default)
    {
        using var json = await RunAsync(runtimeDir, provisioningDir, adiId, "is-provisioned", new Dictionary<string, string>
        {
            ["--dsid"] = dsId.ToString(CultureInfo.InvariantCulture)
        }, ct).ConfigureAwait(false);

        return json.RootElement.TryGetProperty("provisioned", out var value)
               && value.ValueKind == JsonValueKind.True;
    }

    public async Task<AdiStartProvisioningResult> StartProvisioningAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        byte[] spim,
        long dsId = -2,
        CancellationToken ct = default)
    {
        using var json = await RunAsync(runtimeDir, provisioningDir, adiId, "start-provisioning", new Dictionary<string, string>
        {
            ["--dsid"] = dsId.ToString(CultureInfo.InvariantCulture),
            ["--spim"] = Convert.ToBase64String(spim)
        }, ct).ConfigureAwait(false);

        var root = json.RootElement;
        var session = root.TryGetProperty("session", out var sessionEl) ? sessionEl.GetUInt32() : 0;
        var cpim = root.TryGetProperty("cpim", out var cpimEl) ? cpimEl.GetString() ?? "" : "";
        return new AdiStartProvisioningResult(session, Convert.FromBase64String(cpim));
    }

    public async Task EndProvisioningAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        uint session,
        byte[] ptm,
        byte[] tk,
        CancellationToken ct = default)
    {
        await RunCommandAsync(runtimeDir, provisioningDir, adiId, "end-provisioning", new Dictionary<string, string>
        {
            ["--session"] = session.ToString(CultureInfo.InvariantCulture),
            ["--ptm"] = Convert.ToBase64String(ptm),
            ["--tk"] = Convert.ToBase64String(tk)
        }, ct).ConfigureAwait(false);
    }

    public Task DestroySessionAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        uint session,
        CancellationToken ct = default) =>
        RunCommandAsync(runtimeDir, provisioningDir, adiId, "destroy-session", new Dictionary<string, string>
        {
            ["--session"] = session.ToString(CultureInfo.InvariantCulture)
        }, ct);

    public Task SetRoutingAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        ulong routingInfo,
        long dsId = -2,
        CancellationToken ct = default) =>
        RunCommandAsync(runtimeDir, provisioningDir, adiId, "set-routing", new Dictionary<string, string>
        {
            ["--dsid"] = dsId.ToString(CultureInfo.InvariantCulture),
            ["--routing"] = routingInfo.ToString(CultureInfo.InvariantCulture)
        }, ct);

    public async Task<AdiOtpHeaderResult> RequestOtpAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        long dsId = -2,
        CancellationToken ct = default)
    {
        using var json = await RunAsync(runtimeDir, provisioningDir, adiId, "request-otp", new Dictionary<string, string>
        {
            ["--dsid"] = dsId.ToString(CultureInfo.InvariantCulture)
        }, ct).ConfigureAwait(false);

        var root = json.RootElement;
        return new AdiOtpHeaderResult(
            GetString(root, "X-Apple-I-MD"),
            GetString(root, "X-Apple-I-MD-M"),
            GetString(root, "X-Apple-I-MD-RINFO"));
    }

    private static async Task RunCommandAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        string command,
        IReadOnlyDictionary<string, string> extraArgs,
        CancellationToken ct)
    {
        using var _ = await RunAsync(runtimeDir, provisioningDir, adiId, command, extraArgs, ct).ConfigureAwait(false);
    }

    private static async Task<JsonDocument> RunAsync(
        string runtimeDir,
        string provisioningDir,
        string adiId,
        string command,
        IReadOnlyDictionary<string, string> extraArgs,
        CancellationToken ct)
    {
        var bridgePath = ResolveBridgeExecutable()
            ?? throw new InvalidOperationException(
                "CoreAdiBridge.exe non trovato. Esegui scripts/build-coreadi-bridge.ps1.");

        var args = new List<string>
        {
            $"--runtime", runtimeDir,
            $"--provision", provisioningDir,
            $"--adi-id", adiId,
            $"--command", command
        };
        foreach (var pair in extraArgs)
        {
            args.Add(pair.Key);
            args.Add(pair.Value);
        }

        var psi = new ProcessStartInfo
        {
            FileName = bridgePath,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true
        };
        foreach (var arg in args)
            psi.ArgumentList.Add(arg);

        using var process = Process.Start(psi)
            ?? throw new InvalidOperationException("Impossibile avviare CoreAdiBridge.exe.");

        var stdout = await process.StandardOutput.ReadToEndAsync(ct).ConfigureAwait(false);
        var stderr = await process.StandardError.ReadToEndAsync(ct).ConfigureAwait(false);
        await process.WaitForExitAsync(ct).ConfigureAwait(false);

        if (string.IsNullOrWhiteSpace(stdout))
            throw new InvalidOperationException($"CoreAdiBridge senza output: {stderr.Trim()}");

        var json = JsonDocument.Parse(stdout);
        if (json.RootElement.TryGetProperty("ok", out var ok) && ok.ValueKind == JsonValueKind.True)
            return json;

        var error = json.RootElement.TryGetProperty("error", out var errEl)
            ? errEl.GetString() ?? $"exit {process.ExitCode}"
            : $"exit {process.ExitCode}";
        throw new InvalidOperationException($"CoreADI: {error}");
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
