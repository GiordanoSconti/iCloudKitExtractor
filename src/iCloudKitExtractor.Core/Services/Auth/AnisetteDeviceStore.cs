using System.IO;
using System.Text;
using System.Text.Json;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Services.Auth;

/// <summary>
/// Identità dispositivo locale persistente per cpd GrandSlam e provisioning ADI.
/// </summary>
public sealed class AnisetteDeviceStore
{
    private readonly AdiDeviceProfile _profile;
    private readonly string _storePath;
    private DeviceIdentity? _cached;

    public AnisetteDeviceStore(AdiDeviceProfile? profile = null)
    {
        _profile = profile ?? AdiDeviceProfile.Windows;
        _storePath = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
            "iCloudKitExtractor",
            _profile.DeviceStoreFileName);
    }

    public AdiDeviceProfile Profile => _profile;

    public string StorePath => _storePath;

    /// <summary>
    /// Cancella UUID/serial/ADI persistiti per questo profilo (nuovo device verso Apple).
    /// </summary>
    public void ResetIdentity()
    {
        _cached = null;
        try
        {
            if (File.Exists(_storePath))
                File.Delete(_storePath);
        }
        catch
        {
            // best-effort: Load() ricrea se il delete fallisce
        }
    }

    /// <summary>Invalida la cache in-memory; il prossimo GetOrCreate rilegge da disco.</summary>
    public void InvalidateCache() => _cached = null;

    public string GetOrCreateSerialNumber()
    {
        var identity = Load();
        if (!string.IsNullOrEmpty(identity.SerialNumber))
            return identity.SerialNumber;

        identity.SerialNumber = _profile.IsIosClass
            ? GenerateIosSerialNumber()
            : GeneratePcSerialNumber();
        Save(identity);
        return identity.SerialNumber;
    }

    public string GetOrCreateClientProductType()
    {
        var identity = Load();
        if (!string.IsNullOrEmpty(identity.ClientProductType))
            return identity.ClientProductType;

        identity.ClientProductType = _profile.ClientProductType;
        Save(identity);
        return identity.ClientProductType;
    }

    public string GetOrCreateDeviceUuid()
    {
        var identity = Load();
        if (!string.IsNullOrEmpty(identity.DeviceUuid))
            return identity.DeviceUuid;

        identity.DeviceUuid = Guid.NewGuid().ToString().ToUpperInvariant();
        Save(identity);
        return identity.DeviceUuid;
    }

    public string GetOrCreateAdiIdentifier()
    {
        var identity = Load();
        if (!string.IsNullOrEmpty(identity.AdiIdentifier) && identity.AdiIdentifier.Length == 16)
            return identity.AdiIdentifier;

        Span<byte> bytes = stackalloc byte[8];
        Random.Shared.NextBytes(bytes);
        identity.AdiIdentifier = Convert.ToHexString(bytes).ToLowerInvariant();
        Save(identity);
        return identity.AdiIdentifier;
    }

    /// <summary>
    /// iOS/ hex 32 byte (64 char minuscoli). Windows AuthKit: base64(UTF-8 device UUID).
    /// </summary>
    public string GetOrCreateLocalUserUuid()
    {
        var identity = Load();
        if (_profile.IdentityStyle == AdiIdentityStyle.IosAkd)
        {
            if (!string.IsNullOrEmpty(identity.LocalUserUuid) && IsIosMdLuFormat(identity.LocalUserUuid))
                return identity.LocalUserUuid;

            identity.LocalUserUuid = GenerateIosLocalUserUuid();
            Save(identity);
            return identity.LocalUserUuid;
        }

        // Windows + ProvisionCompat: base64(UUID) come dadoum/Provision.
        var deviceUuid = GetOrCreateDeviceUuid();
        var expected = FormatWindowsLocalUserUuid(deviceUuid);
        if (identity.LocalUserUuid == expected)
            return identity.LocalUserUuid;

        identity.LocalUserUuid = expected;
        Save(identity);
        return identity.LocalUserUuid;
    }

    /// <summary>Allinea identità profilo; ritorna true se serve ri-provisioning ADI.</summary>
    public bool EnsureIdentityConsistency()
    {
        var identity = Load();
        var changed = false;

        if (string.IsNullOrEmpty(identity.ClientProductType)
            || identity.ClientProductType != _profile.ClientProductType)
        {
            identity.ClientProductType = _profile.ClientProductType;
            changed = true;
        }

        if (_profile.IdentityStyle == AdiIdentityStyle.IosAkd)
        {
            if (string.IsNullOrEmpty(identity.LocalUserUuid) || !IsIosMdLuFormat(identity.LocalUserUuid))
            {
                identity.LocalUserUuid = GenerateIosLocalUserUuid();
                changed = true;
            }
        }
        else
        {
            var deviceUuid = GetOrCreateDeviceUuid();
            var expectedLu = FormatWindowsLocalUserUuid(deviceUuid);
            if (identity.LocalUserUuid != expectedLu)
            {
                identity.LocalUserUuid = expectedLu;
                changed = true;
            }
        }

        if (identity.ProvisioningClientInfo != _profile.ProvisioningClientInfo)
        {
            identity.ProvisioningClientInfo = _profile.ProvisioningClientInfo;
            changed = true;
        }

        if (changed)
            Save(identity);

        return changed;
    }

    public string GetProvisioningClientInfo()
    {
        EnsureIdentityConsistency();
        return Load().ProvisioningClientInfo;
    }

  public static string FormatWindowsLocalUserUuid(string deviceUuid) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(deviceUuid));

    public static string GenerateIosLocalUserUuid()
    {
        Span<byte> bytes = stackalloc byte[32];
        Random.Shared.NextBytes(bytes);
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }

    public static bool IsIosMdLuFormat(string value)
    {
        if (value.Length != 64)
            return false;
        foreach (var c in value)
        {
            if (!char.IsAsciiHexDigit(c) || char.IsAsciiLetterUpper(c))
                return false;
        }
        return true;
    }

    public static string BuildAuthKitWinClientInfo(string productType)
    {
        var v = Environment.OSVersion.Version;
        var build = v.Build > 0 ? v.Build : 26100;
        return $"<{productType}> <Windows;{v.Major}.{v.Minor}(0,0);{build}> <com.apple.AuthKitWin/1 (com.apple.iCloud/15.0)>";
    }

    private DeviceIdentity Load()
    {
        if (_cached is not null)
            return _cached;

        try
        {
            if (File.Exists(_storePath))
            {
                var json = File.ReadAllText(_storePath);
                _cached = JsonSerializer.Deserialize<DeviceIdentity>(json) ?? new DeviceIdentity();
                return _cached;
            }
        }
        catch
        {
            // Ricrea su errore di lettura.
        }

        _cached = new DeviceIdentity();
        return _cached;
    }

    private void Save(DeviceIdentity identity)
    {
        _cached = identity;
        var dir = Path.GetDirectoryName(_storePath)!;
        Directory.CreateDirectory(dir);
        File.WriteAllText(_storePath, JsonSerializer.Serialize(identity, new JsonSerializerOptions { WriteIndented = true }));
    }

    private static string GeneratePcSerialNumber()
    {
        const string alphabet = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        Span<char> chars = stackalloc char[12];
        chars[0] = 'C';
        chars[1] = (char)('A' + Random.Shared.Next(26));
        chars[2] = (char)('A' + Random.Shared.Next(26));
        for (var i = 3; i < chars.Length; i++)
            chars[i] = alphabet[Random.Shared.Next(alphabet.Length)];
        return new string(chars);
    }

    private static string GenerateIosSerialNumber()
    {
        const string alphabet = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZ";
        Span<char> chars = stackalloc char[12];
        chars[0] = 'F';
        chars[1] = (char)('2' + Random.Shared.Next(8));
        chars[2] = (char)('A' + Random.Shared.Next(26));
        for (var i = 3; i < chars.Length; i++)
            chars[i] = alphabet[Random.Shared.Next(alphabet.Length)];
        return new string(chars);
    }

    private sealed class DeviceIdentity
    {
        public string SerialNumber { get; set; } = string.Empty;
        public string ClientProductType { get; set; } = string.Empty;
        public string DeviceUuid { get; set; } = string.Empty;
        public string AdiIdentifier { get; set; } = string.Empty;
        public string LocalUserUuid { get; set; } = string.Empty;
        public string ProvisioningClientInfo { get; set; } = string.Empty;
    }
}
