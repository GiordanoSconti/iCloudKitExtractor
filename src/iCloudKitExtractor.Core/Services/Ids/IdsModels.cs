namespace iCloudKitExtractor.Services.Ids;

/// <summary>Definizione di un albero servizio IDS (register / runtime).</summary>
public sealed class IdsServiceDefinition
{
    public required string Name { get; init; }
    public required string CapabilitiesName { get; init; }
    public required int CapabilityFlags { get; init; }
    public required IReadOnlyList<string> SubServices { get; init; }
    public IReadOnlyDictionary<string, object?> ClientDataFlags { get; init; } =
        new Dictionary<string, object?>();
    /// <summary>true = enroll/runtime supportati in IKE; false = solo catalogo.</summary>
    public bool RuntimeSupported { get; init; }
}

public sealed class IdsPeerIdentity
{
    public required string Uri { get; init; }
    public byte[]? PushToken { get; init; }
    public byte[]? SessionToken { get; init; }
    public int? SessionTokenExpiresSeconds { get; init; }
    public int? SessionTokenRefreshSeconds { get; init; }
    public Dictionary<string, object?>? ClientData { get; init; }
    public byte[]? NgmPreKeyData { get; init; }
    public byte[]? NgmDevicePublicKey { get; init; }
    public byte[]? LegacyIdentityKey { get; init; }
    public string PushTokenHex =>
        PushToken is { Length: > 0 } ? Convert.ToHexString(PushToken) : "";
    public string SessionTokenHex =>
        SessionToken is { Length: > 0 } ? Convert.ToHexString(SessionToken) : "";
}

public sealed class IdsLookupResult
{
    public required string Topic { get; init; }
    public required string SelfHandle { get; init; }
    public required IReadOnlyList<string> QueriedUris { get; init; }
    public required IReadOnlyList<IdsPeerIdentity> Identities { get; init; }
    public int Status { get; init; }
    public string? RawSummary { get; init; }
}

public sealed class IdsSendRequest
{
    public required string Topic { get; init; }
    public required string SenderHandle { get; init; }
    public required IReadOnlyList<IdsPeerIdentity> Targets { get; init; }
    public required byte[] Payload { get; init; }
    public int Command { get; init; } = 242;
    public bool SendDelivered { get; init; }
    public bool NoResponse { get; init; } = true;
    public string? MessageId { get; init; }
    public Dictionary<string, object?>? Extras { get; init; }
}

public sealed class IdsReceivedMessage
{
    public required string Topic { get; init; }
    public string? Sender { get; init; }
    public string? Target { get; init; }
    public byte[]? SenderToken { get; init; }
    public Guid? Uuid { get; init; }
    public int? Command { get; init; }
    public byte[]? Plaintext { get; init; }
    public byte[]? RawPayload { get; init; }
    public bool Decrypted { get; init; }
    public string? ParseNote { get; init; }
    public DateTimeOffset ReceivedUtc { get; init; } = DateTimeOffset.UtcNow;
}

public sealed class IdsMessageReceivedEventArgs : EventArgs
{
    public required IdsReceivedMessage Message { get; init; }
}
