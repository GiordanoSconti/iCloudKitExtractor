namespace iCloudKitExtractor.Services.Push;

public sealed class ApsPushState
{
    public bool HasCertificate { get; init; }
    public bool IsConnected { get; init; }
    public string? CourierHost { get; init; }
    public byte[]? Token { get; init; }
    public string TokenHex => ApsStorage.TokenHex(Token);
    public string? LastError { get; init; }
    public DateTimeOffset? ConnectedUtc { get; init; }
}

public sealed class ApsNotificationEventArgs : EventArgs
{
    public required byte Type { get; init; }
    public required IReadOnlyList<(byte Id, byte[] Value)> Fields { get; init; }
    public byte[]? Payload { get; init; }
    public byte[]? TopicHash { get; init; }
    public byte[]? MessageId { get; init; }
    public string? PayloadText { get; init; }
    public string? ExtractedOtp { get; init; }
    public DateTimeOffset ReceivedUtc { get; init; } = DateTimeOffset.UtcNow;
}
