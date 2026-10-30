using iCloudKitExtractor.AnisetteLicense;

if (args.Length == 0)
{
    PrintHelp();
    return 1;
}

var cmd = args[0].Trim().ToLowerInvariant();
try
{
    return cmd switch
    {
        "init-keys" => CmdInitKeys(),
        "issue" => CmdIssue(args.Skip(1).ToArray()),
        "revoke" => CmdRevoke(args.Skip(1).ToArray()),
        "disable" => CmdSetEnabled(args.Skip(1).ToArray(), enabled: false),
        "enable" => CmdSetEnabled(args.Skip(1).ToArray(), enabled: true),
        "delete" => CmdDelete(args.Skip(1).ToArray()),
        "list" => CmdList(),
        "help" or "-h" or "--help" => PrintHelp(),
        _ => Fail($"Unknown command: {cmd}"),
    };
}
catch (Exception ex)
{
    Console.Error.WriteLine("ERROR: " + ex.Message);
    return 2;
}

static int CmdInitKeys()
{
    var priv = LicensePaths.PrivateKeyPath;
    var pub = LicensePaths.PublicKeyPath;
    if (File.Exists(priv) || File.Exists(pub))
    {
        Console.Error.WriteLine($"Keys already exist:\n  {priv}\n  {pub}");
        Console.Error.WriteLine("Delete them first if you intend to rotate.");
        return 3;
    }

    LicenseCrypto.GenerateKeyPair(priv, pub);
    Console.WriteLine("Created Ed25519 key pair:");
    Console.WriteLine("  private: " + priv);
    Console.WriteLine("  public:  " + pub);
    Console.WriteLine("Keep the private key offline / on the Mac middleware only.");
    return 0;
}

static int CmdIssue(string[] args)
{
    string? sub = null;
    string? note = null;
    string? outPath = null;
    string? fingerprint = null;
    int? days = 30;

    for (var i = 0; i < args.Length; i++)
    {
        switch (args[i])
        {
            case "--sub" when i + 1 < args.Length:
                sub = args[++i];
                break;
            case "--note" when i + 1 < args.Length:
                note = args[++i];
                break;
            case "--days" when i + 1 < args.Length:
                days = int.Parse(args[++i]);
                break;
            case "--no-expiry":
                days = null;
                break;
            case "--fingerprint" when i + 1 < args.Length:
                fingerprint = args[++i];
                break;
            case "--out" when i + 1 < args.Length:
                outPath = args[++i];
                break;
        }
    }

    if (string.IsNullOrWhiteSpace(sub))
        return Fail("issue requires --sub \"name or email\"");

    if (!File.Exists(LicensePaths.PrivateKeyPath) || !File.Exists(LicensePaths.PublicKeyPath))
        return Fail("Missing keys. Run: AnisetteLicenseGen init-keys");

    using var db = new LicenseDatabase(LicensePaths.DatabasePath);
    var issuer = new LicenseIssuer(
        LicensePaths.PrivateKeyPath,
        LicensePaths.PublicKeyPath,
        db);
    issuer.IssueManual(sub!, days, note, fingerprint, clientIp: null, out var payload, out var bundleB64);

    outPath ??= Path.Combine(
        LicensePaths.DataDir,
        "licenses",
        $"{payload.Subject.Replace('@', '_').Replace(' ', '_')}-{payload.LicenseId[..8]}.license");
    Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(outPath))!);
    File.WriteAllText(outPath, bundleB64 + Environment.NewLine);

    Console.WriteLine("Issued license package C (Base64 bundle):");
    Console.WriteLine("  id:      " + payload.LicenseId);
    Console.WriteLine("  subject: " + payload.Subject);
    Console.WriteLine("  expires: " + (payload.ExpiresAtUnix is long e
        ? DateTimeOffset.FromUnixTimeSeconds(e).UtcDateTime.ToString("u")
        : "(none)"));
    Console.WriteLine("  db:      " + LicensePaths.DatabasePath);
    Console.WriteLine("  file:    " + outPath);
    Console.WriteLine();
    Console.WriteLine("License bundle Base64 (paste into IKE License field):");
    Console.WriteLine(bundleB64);
    return 0;
}

static int CmdRevoke(string[] args)
{
    string? id = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--id" && i + 1 < args.Length)
            id = args[++i];
    }

    if (string.IsNullOrWhiteSpace(id))
        return Fail("revoke requires --id <license_id>");

    using var db = new LicenseDatabase(LicensePaths.DatabasePath);
    if (!db.Revoke(id.Trim()))
    {
        Console.Error.WriteLine("No active license updated (missing or already revoked).");
        return 4;
    }

    Console.WriteLine("Revoked: " + id.Trim());
    return 0;
}

static int CmdSetEnabled(string[] args, bool enabled)
{
    string? id = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--id" && i + 1 < args.Length)
            id = args[++i];
    }

    if (string.IsNullOrWhiteSpace(id))
        return Fail((enabled ? "enable" : "disable") + " requires --id <license_id>");

    using var db = new LicenseDatabase(LicensePaths.DatabasePath);
    if (!db.SetEnabled(id.Trim(), enabled))
    {
        Console.Error.WriteLine("License not found.");
        return 4;
    }

    Console.WriteLine((enabled ? "Enabled: " : "Disabled: ") + id.Trim());
    return 0;
}

static int CmdDelete(string[] args)
{
    string? id = null;
    for (var i = 0; i < args.Length; i++)
    {
        if (args[i] is "--id" && i + 1 < args.Length)
            id = args[++i];
    }

    if (string.IsNullOrWhiteSpace(id))
        return Fail("delete requires --id <license_id>");

    using var db = new LicenseDatabase(LicensePaths.DatabasePath);
    if (!db.Delete(id.Trim()))
    {
        Console.Error.WriteLine("License not found.");
        return 4;
    }

    Console.WriteLine("Deleted: " + id.Trim());
    return 0;
}

static int CmdList()
{
    using var db = new LicenseDatabase(LicensePaths.DatabasePath);
    var rows = db.ListAll();
    if (rows.Count == 0)
    {
        Console.WriteLine("(empty) " + LicensePaths.DatabasePath);
        return 0;
    }

    Console.WriteLine($"{"id",-34} {"subject",-24} {"fp",-14} enabled emitted status");
    foreach (var r in rows)
    {
        var status = !string.IsNullOrEmpty(r.RevokedAt) ? "REVOKED" : (r.Enabled ? "active" : "disabled");
        var fp = string.IsNullOrEmpty(r.Fingerprint) ? "-" : Truncate(r.Fingerprint, 14);
        Console.WriteLine(
            $"{r.LicenseId,-34} {Truncate(r.Subject, 24),-24} {fp,-14} {(r.Enabled ? "yes" : "no"),-7} {(r.EmittedOnce ? "yes" : "no"),-7} {status}");
    }
    return 0;
}

static string Truncate(string s, int n) =>
    s.Length <= n ? s : s[..(n - 1)] + "…";

static int PrintHelp()
{
    Console.WriteLine(
        """
        AnisetteLicenseGen — Forensis-Lab private Anisette licenses (Ed25519 + SQLite + Package C)

        Commands:
          init-keys
          issue --sub "tester@…" [--days 30|--no-expiry] [--note "…"] [--fingerprint hex] [--out path]
          revoke --id <license_id>
          disable --id <license_id>
          enable --id <license_id>
          delete --id <license_id>
          list

        Paths (override with env):
          ANISETTE_LICENSE_ROOT / keys/ / data/
          ANISETTE_LICENSE_PRIVATE_KEY, ANISETTE_LICENSE_PUBLIC_KEY, ANISETTE_LICENSE_DB
        """);
    return 0;
}

static int Fail(string msg)
{
    Console.Error.WriteLine(msg);
    return 1;
}
