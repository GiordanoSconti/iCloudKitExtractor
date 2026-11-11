namespace iCloudKitExtractor.Models;

public enum TwoFactorMethod
{
    TrustedDevice,
    Sms
}

/// <summary>Invio SMS: idmsa PUT con identity token GSA (macless-haystack).</summary>
public enum SmsSendChannel
{
    None,
    IdmsaPut,
}

public sealed class TrustedPhoneNumber
{
    public int Id { get; init; }
    public string? ObfuscatedNumber { get; init; }
    public string? NumberWithDialCode { get; init; }
    public string? LastTwoDigits { get; init; }
    public string PushMode { get; init; } = "sms";
    public bool NonFteu { get; init; }

    public string DisplayLabel =>
        !string.IsNullOrWhiteSpace(NumberWithDialCode)
            ? NumberWithDialCode
            : !string.IsNullOrWhiteSpace(ObfuscatedNumber)
                ? ObfuscatedNumber
                : LastTwoDigits is { Length: > 0 } d
                    ? $"••• {d}"
                    : $"Numero #{Id}";
}

public sealed class PhoneVerificationOptions
{
    public IReadOnlyList<TrustedPhoneNumber> TrustedPhoneNumbers { get; init; } = [];
    public int TrustedDeviceCount { get; init; }
    public int SecurityCodeLength { get; init; } = 6;
}
