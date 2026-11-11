namespace iCloudKitExtractor.Models;

/// <summary>
/// Twin logico del <c>CKFile</c> (alloc <c>0x1F8</c>) + materiali FileGroup
/// per <b>un</b> Asset. Unità strutturale = 1 Asset = 1 CKFile + 1 FileGroup.
/// Riferimento: <c>ckfile_asset_bind_full_chain.md</c>.
/// </summary>
public sealed class AssetCkFile
{
    /// <summary>CKFile+0x08 — <c>A:{pref4}:{rid}</c>.</summary>
    public string RecordKey { get; init; } = "";

    /// <summary>CKFile+0x28 — finestra payload del parent BackupAsset Record.</summary>
    public byte[]? ParentRecordPayload { get; set; }

    /// <summary>CKFile+0x100 — FileChecksum / contents sig lead <c>0x04</c>.</summary>
    public byte[]? SigContents04 { get; set; }

    /// <summary>CKFile+0x120 — companion / AG twin lead <c>0x01</c>.</summary>
    public byte[]? SigCompanion01 { get; set; }

    /// <summary>map["contents"].protectionInfo — wrap24/40.</summary>
    public byte[]? Wrap { get; set; }

    public string WrapSource { get; set; } = "missing";

    /// <summary>CKFile+0x160 — IKM16/32 da FillFord (wrap × zoneMaster).</summary>
    public byte[]? Ikm { get; set; }

    public string IkmSource { get; set; } = "missing";

    // --- FileGroup (dopo authorizeGet dello stesso Asset) ---

    /// <summary>storage+0x88 — gate45 = <c>0C0F01 ‖ +0x100 ‖ +0x120</c>.</summary>
    public byte[]? Gate45 { get; set; }

    /// <summary>storage+0x58 — Auth nested ctLen.</summary>
    public int CtLen { get; set; }

    public string? FordObjectId { get; set; }

    public int RefCount { get; set; }

    public int DataChunkCount { get; set; }

    public int HostCount { get; set; }

    public bool HasFord =>
        Gate45 is { Length: 45 }
        && Protocol.UbChunkBuilder.IsPlausibleAuthFordCtLen(CtLen);

    public bool HasIkm => Ikm is { Length: 16 or 32 };

    public bool GateMatchesCkFileSigs()
    {
        if (Gate45 is not { Length: 45 }
            || SigContents04 is not { Length: 21 }
            || SigCompanion01 is not { Length: 21 })
            return false;
        if (Gate45[0] != 0x0C || Gate45[1] != 0x0F || Gate45[2] != 0x01)
            return false;
        return Gate45.AsSpan(3, 21).SequenceEqual(SigContents04)
               && Gate45.AsSpan(24, 21).SequenceEqual(SigCompanion01);
    }
}
