using System.Net;
using System.Net.Http;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Services;
using iCloudKitExtractor.Services.Auth;
using iCloudKitExtractor.Services.Escrow;

if (args.Length == 0 || HasFlag(args, "-h") || HasFlag(args, "--help"))
{
    PrintHelp();
    return args.Length == 0 ? 1 : 0;
}

try
{
    var sessionPath = Require(args, "--session");
    var sponsorDir = Require(args, "--sponsor-dir");
    var outDir = GetOpt(args, "--out")
                 ?? Path.Combine(Directory.GetCurrentDirectory(), "octagon_join_out");
    var model = GetOpt(args, "--model") ?? "MacBookPro18,1";
    var serial = GetOpt(args, "--serial") ?? "IKEJOIN000000";
    var name = GetOpt(args, "--name") ?? "IKE OctagonJoin";
    var os = GetOpt(args, "--os") ?? "macOS 15.0 (24A335)";
    var machineId = GetOpt(args, "--machine-id");
    var skipBottle = HasFlag(args, "--skip-bottle");

    Console.WriteLine("OctagonJoin — joinWithVoucher only (mutates Octagon trust).");
    Console.WriteLine($"  session : {sessionPath}");
    Console.WriteLine($"  sponsor : {sponsorDir}");
    Console.WriteLine($"  out     : {outDir}");

    var session = LoadSession(sessionPath);
    LoadSponsorKeys(session, sponsorDir);

    machineId ??= FirstNonEmpty(
        session.Anisette.MdM,
        session.Anisette.MmeDeviceId,
        Guid.NewGuid().ToString("N"));

    using var http = CreateHttp();
    var orchestrator = new ICloudBackupOrchestrator(
        http,
        AnisetteProviderFactory.CreateAuth(http));
    var log = new Progress<string>(m => Console.WriteLine(m));
    var svc = new OctagonJoinService(http, orchestrator);

    var result = await svc.JoinNewDeviceAsync(
            session,
            outDir,
            new OctagonJoinService.JoinOptions(
                MachineId: machineId!,
                ModelId: model,
                SerialNumber: serial,
                DeviceName: name,
                OsVersion: os,
                SkipBottle: skipBottle),
            log)
        .ConfigureAwait(false);

    Console.WriteLine(result.Success ? "OK: " + result.Message : "FAIL: " + result.Message);
    return result.Success ? 0 : 2;
}
catch (Exception ex)
{
    Console.Error.WriteLine("ERROR: " + ex.Message);
    return 3;
}

static void PrintHelp()
{
    Console.WriteLine(
        """
        OctagonJoin — join a NEW device peer into the account Octagon circle.

        Prerequisites (from IKE Escrow tab):
          1. Sign in, Unlock Octagon bottle, OTBottle / Peer keys
          2. Keep octagon_peer_signing.pkcs8 + octagon_peer_encryption.pkcs8
             + octagon_peer_unlock_meta.json
          3. Export / capture session_latest.json (IKE logs secrets) OR pass a
             session JSON with dsid, tokens, adsid, anisette

        Usage:
          dotnet run --project src/OctagonJoin -- \
            --session /path/session_latest.json \
            --sponsor-dir /path/octagon_keys \
            --out /path/join_out

        Options:
          --session PATH       ICloud session JSON (required)
          --sponsor-dir PATH   Dir with sponsor PKCS#8 + meta (required)
          --out PATH           Output directory (default: ./octagon_join_out)
          --machine-id ID      Octagon machineId (default: anisette MD-M)
          --model ID           Hardware model (default: MacBookPro18,1)
          --serial S           Serial (default: IKEJOIN000000)
          --name N             Device name
          --os S               OS version string
          --skip-bottle        Omit Bottle from joinWithVoucher (lab)

        Warning: this MUTATES the Apple ID Octagon trust graph. Lab / owned
        accounts only. Escrow ENROLL of the new bottle is NOT performed.
        """);
}

static ICloudSession LoadSession(string path)
{
    using var doc = JsonDocument.Parse(File.ReadAllText(path));
    var root = doc.RootElement;
    var s = new ICloudSession
    {
        AppleId = Str(root, "appleId") ?? "",
        Dsid = Str(root, "dsid") ?? throw new InvalidDataException("session.dsid missing"),
        Partition = Str(root, "partition") ?? "p178",
        CloudKitUserId = Str(root, "cloudKitUserId") ?? "",
        CloudKitAuthToken = Str(root, "cloudKitAuthToken") ?? "",
        MobileMeAuthToken = Str(root, "mobileMeAuthToken") ?? "",
        PeToken = Str(root, "peToken"),
        GsToken = Str(root, "gsToken"),
        GsICloudAuthToken = Str(root, "gsICloudAuthToken"),
        IdentityToken = Str(root, "identityToken"),
        Adsid = Str(root, "adsid") ?? Str(root, "altDSID"),
        GsIdmsToken = Str(root, "gsIdmsToken"),
        AppleCloudKitContext = Str(root, "appleCloudKitContext"),
        CloudKitGatewayUrl = Str(root, "cloudKitGatewayUrl"),
        EscrowProxyUrl = Str(root, "escrowProxyUrl"),
    };

    if (root.TryGetProperty("anisette", out var a) && a.ValueKind == JsonValueKind.Object)
    {
        s.Anisette.Md = Str(a, "md") ?? Str(a, "Md") ?? "";
        s.Anisette.MdM = Str(a, "mdM") ?? Str(a, "MdM") ?? "";
        s.Anisette.MdRinfo = Str(a, "mdRinfo") ?? Str(a, "MdRinfo") ?? "";
        s.Anisette.ClientTimeUtc = Str(a, "clientTimeUtc") ?? Str(a, "ClientTimeUtc") ?? "";
        s.Anisette.Locale = Str(a, "locale") ?? "en_US";
        s.Anisette.SerialNumber = Str(a, "serialNumber") ?? Str(a, "SerialNumber") ?? "";
        s.Anisette.ClientProductType =
            Str(a, "clientProductType") ?? Str(a, "ClientProductType") ?? "";
        s.Anisette.MmeDeviceId = Str(a, "mmeDeviceId") ?? Str(a, "MmeDeviceId") ?? "";
        s.Anisette.TouchClientTimeUtc();
    }

    if (string.IsNullOrWhiteSpace(s.MobileMeAuthToken)
        && string.IsNullOrWhiteSpace(s.CloudKitAuthToken))
        throw new InvalidDataException("session needs mobileMeAuthToken and/or cloudKitAuthToken");

    return s;
}

static void LoadSponsorKeys(ICloudSession session, string dir)
{
    if (!Directory.Exists(dir))
        throw new DirectoryNotFoundException(dir);

    var enc = Path.Combine(dir, "octagon_peer_encryption.pkcs8");
    var sig = Path.Combine(dir, "octagon_peer_signing.pkcs8");
    var meta = Path.Combine(dir, "octagon_peer_unlock_meta.json");
    if (!File.Exists(enc) || !File.Exists(sig))
        throw new FileNotFoundException(
            "Need octagon_peer_encryption.pkcs8 + octagon_peer_signing.pkcs8 in " + dir);

    session.OctagonPeerEncryptionPkcs8 = File.ReadAllBytes(enc);
    session.OctagonPeerSigningPkcs8 = File.ReadAllBytes(sig);
    session.OctagonKeysDirectory = dir;

    if (File.Exists(meta))
    {
        using var doc = JsonDocument.Parse(File.ReadAllText(meta));
        if (doc.RootElement.TryGetProperty("peerId", out var p)
            && p.ValueKind == JsonValueKind.String)
            session.OctagonPeerId = p.GetString();
    }

    if (string.IsNullOrWhiteSpace(session.OctagonPeerId))
    {
        var env = Environment.GetEnvironmentVariable("IKE_SPONSOR_PEER_ID");
        if (!string.IsNullOrWhiteSpace(env))
            session.OctagonPeerId = env.Trim();
    }

    if (string.IsNullOrWhiteSpace(session.OctagonPeerId))
        throw new InvalidDataException(
            "Sponsor peerId missing — set in octagon_peer_unlock_meta.json or IKE_SPONSOR_PEER_ID");
}

static HttpClient CreateHttp()
{
    var handler = new HttpClientHandler
    {
        AutomaticDecompression = DecompressionMethods.All,
        // Lab: Apple endpoints; do not weaken for arbitrary hosts.
        CheckCertificateRevocationList = false
    };
    return new HttpClient(handler)
    {
        Timeout = TimeSpan.FromMinutes(5)
    };
}

static string Require(string[] args, string name)
{
    var v = GetOpt(args, name);
    if (string.IsNullOrWhiteSpace(v))
        throw new ArgumentException($"Missing {name}");
    return v;
}

static string? GetOpt(string[] args, string name)
{
    for (var i = 0; i < args.Length - 1; i++)
    {
        if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase))
            return args[i + 1];
    }

    return null;
}

static bool HasFlag(string[] args, string name) =>
    args.Any(a => string.Equals(a, name, StringComparison.OrdinalIgnoreCase));

static string? Str(JsonElement el, string name) =>
    el.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
        ? v.GetString()
        : null;

static string? FirstNonEmpty(params string?[] values)
{
    foreach (var v in values)
    {
        if (!string.IsNullOrWhiteSpace(v))
            return v;
    }

    return null;
}
