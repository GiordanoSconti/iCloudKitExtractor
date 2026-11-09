namespace iCloudKitExtractor.Services.Ids;

/// <summary>
/// Catalogo alberi servizio IDS. Solo <see cref="MultiplexFindMy"/> ha runtime IKE completo;
/// Madrid/FaceTime restano definizioni estendibili.
/// </summary>
public static class IdsServiceCatalog
{
    public static IdsServiceDefinition MultiplexFindMy { get; } = new()
    {
        Name = IdsConstants.MultiplexService,
        CapabilitiesName = "com.apple.private.alloy",
        CapabilityFlags = 1,
        SubServices = IdsConstants.FindMySubServices,
        RuntimeSupported = true,
        ClientDataFlags = new Dictionary<string, object?>
        {
            ["supports-fmd-v2"] = true,
            ["supports-incoming-fmd-v1"] = true,
            ["supports-findmy-plugin-messages"] = true,
            ["supports-beacon-sharing-v3"] = true,
            ["supports-beacon-sharing-v2"] = true,
        },
    };

    public static IdsServiceDefinition Madrid { get; } = new()
    {
        Name = "com.apple.madrid",
        CapabilitiesName = "Messenger",
        CapabilityFlags = 17,
        SubServices =
        [
            "com.apple.private.alloy.sms",
            "com.apple.private.alloy.gelato",
            "com.apple.private.alloy.biz",
            "com.apple.private.alloy.gamecenter.imessage",
        ],
        RuntimeSupported = false,
    };

    public static IdsServiceDefinition FaceTimeMulti { get; } = new()
    {
        Name = "com.apple.private.alloy.facetime.multi",
        CapabilitiesName = "com.apple.private.alloy",
        CapabilityFlags = 1,
        SubServices = ["com.apple.private.alloy.facetime.multi"],
        RuntimeSupported = false,
    };

    public static IdsServiceDefinition Nearby { get; } = new()
    {
        Name = "com.apple.private.alloy.nearby",
        CapabilitiesName = "com.apple.private.alloy",
        CapabilityFlags = 1,
        SubServices = ["com.apple.private.alloy.nearby"],
        RuntimeSupported = false,
    };

    public static IReadOnlyList<IdsServiceDefinition> All { get; } =
    [
        MultiplexFindMy,
        Madrid,
        FaceTimeMulti,
        Nearby,
    ];

    public static IReadOnlyList<string> MultiplexTopics =>
        new[] { IdsConstants.MultiplexService }
            .Concat(IdsConstants.FindMySubServices)
            .Distinct(StringComparer.Ordinal)
            .ToArray();

    public static IdsServiceDefinition? FindByName(string name) =>
        All.FirstOrDefault(s =>
            s.Name.Equals(name, StringComparison.OrdinalIgnoreCase)
            || s.SubServices.Any(sub => sub.Equals(name, StringComparison.OrdinalIgnoreCase)));
}
