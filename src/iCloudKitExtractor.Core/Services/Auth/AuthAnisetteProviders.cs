namespace iCloudKitExtractor.Services.Auth;



/// <summary>

/// Windows CoreADI solo per SRP GSA; AnisetteServer iOS per 2FA+ (AuthKit iPhone, come).

/// </summary>

public sealed record AuthAnisetteProviders(IAnisetteProvider Windows, IAnisetteProvider Ios);

