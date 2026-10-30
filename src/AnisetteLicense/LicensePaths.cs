namespace iCloudKitExtractor.AnisetteLicense;

/// <summary>Resolve keys/DB under the lab tree (or env overrides).</summary>
public static class LicensePaths
{
    public static string LabRoot
    {
        get
        {
            var env = Environment.GetEnvironmentVariable("ANISETTE_LICENSE_ROOT")?.Trim();
            if (!string.IsNullOrEmpty(env))
                return Path.GetFullPath(env);

            // src/AnisetteLicense → ../../ = lab root when running from project;
            // fall back to cwd when published beside keys/.
            var fromAsm = Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", ".."));
            if (Directory.Exists(Path.Combine(fromAsm, "src", "AnisetteServer")))
                return fromAsm;

            var cwd = Path.GetFullPath(Directory.GetCurrentDirectory());
            if (Directory.Exists(Path.Combine(cwd, "keys")) || Directory.Exists(Path.Combine(cwd, "src")))
                return cwd;

            return cwd;
        }
    }

    public static string KeysDir =>
        Environment.GetEnvironmentVariable("ANISETTE_LICENSE_KEYS_DIR")?.Trim() is { Length: > 0 } d
            ? Path.GetFullPath(d)
            : Path.Combine(LabRoot, "keys");

    public static string DataDir =>
        Environment.GetEnvironmentVariable("ANISETTE_LICENSE_DATA_DIR")?.Trim() is { Length: > 0 } d
            ? Path.GetFullPath(d)
            : Path.Combine(LabRoot, "data");

    public static string PrivateKeyPath =>
        Environment.GetEnvironmentVariable("ANISETTE_LICENSE_PRIVATE_KEY")?.Trim() is { Length: > 0 } p
            ? Path.GetFullPath(p)
            : Path.Combine(KeysDir, "anisette_ed25519_private.pem");

    public static string PublicKeyPath =>
        Environment.GetEnvironmentVariable("ANISETTE_LICENSE_PUBLIC_KEY")?.Trim() is { Length: > 0 } p
            ? Path.GetFullPath(p)
            : Path.Combine(KeysDir, "anisette_ed25519_public.pem");

    public static string DatabasePath =>
        Environment.GetEnvironmentVariable("ANISETTE_LICENSE_DB")?.Trim() is { Length: > 0 } p
            ? Path.GetFullPath(p)
            : Path.Combine(DataDir, "anisette-licenses.db");
}
