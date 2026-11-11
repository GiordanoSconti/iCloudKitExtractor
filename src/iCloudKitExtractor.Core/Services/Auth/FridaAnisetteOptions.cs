namespace iCloudKitExtractor.Services.Auth;

/// <summary>Explicit Frida → jailbroken iPhone settings (Mac middleware / tests).</summary>
public sealed class FridaAnisetteOptions
{
    public string? Host { get; init; }
    public string? ProcessName { get; init; }
    public string? Python { get; init; }
    public string? FetchScript { get; init; }
    public bool? Lite { get; init; }
    public int? TimeoutSec { get; init; }
}
