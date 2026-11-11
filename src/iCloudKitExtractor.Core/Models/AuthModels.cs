namespace iCloudKitExtractor.Models;

public enum AuthStep
{
    Idle,
    Lookup,
    Init,
    SrpExchange,
    TrustedDevicePrompt,
    SmsCodeRequest,
    ValidateCode,
    Authenticate,
    Complete,
    Failed
}

public sealed class AuthProgress
{
    public AuthStep Step { get; init; }
    public string Message { get; init; } = string.Empty;
}

public sealed class AuthResult
{
    public bool Success { get; init; }
    public string? Error { get; init; }
    public ICloudSession? Session { get; init; }
    public bool Requires2Fa { get; init; }
    public PhoneVerificationOptions? VerificationOptions { get; init; }
}
