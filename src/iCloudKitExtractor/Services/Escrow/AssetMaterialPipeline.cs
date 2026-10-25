using System.IO;
using System.Text.Json;
using iCloudKitExtractor.Models;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Pipeline per-Asset, ordine obbligatorio:
/// <c>owned Record → FillFord(wrap×ZM→IKM) → AG FileGroup → plant chunk → FillChunks</c>.
/// CKFile twin: <see cref="AssetCkFile"/>.
/// <para>
/// Parità offline (_tmp_ikm_parity_probe): 965/965 ike_run + live ff_wrap40→ikm
/// (map-contents / asset-proto × NISTKDF(ZM,"wrapping key wrap me") → AES-KW).
/// </para>
/// </summary>
public static class AssetMaterialPipeline
{
    public const string RunId = "ike-fillford-parity-v1";

    /// <summary>
    /// <c>FillFordIkmFromContents</c> (+0xA32930):
    /// 1) wrap = map["contents"].protectionInfo (owned Record + sig)
    /// 2) IKM = AES-KW(NISTKDF(ZM, "wrapping key wrap me"), wrap) → CKFile+0x160
    /// </summary>
    public static AssetCkFile FillFordIkmFromContents(
        BackupAsset asset,
        Func<BackupAsset, byte[]?, byte[]?> tryUnwrapWithZoneMaster)
    {
        var ck = asset.CkFileAsset ?? new AssetCkFile
        {
            RecordKey = asset.RecordName ?? "",
        };
        ck.ParentRecordPayload = asset.RecordPayload;
        ck.SigContents04 = asset.AssetSignature is { Length: 21 } s04
            ? s04
            : asset.AssetSignature is { Length: >= 4 } sAny ? sAny : null;
        ck.SigCompanion01 = asset.MmcsCompanionSignature is { Length: 21 } s01
            ? s01
            : null;

        // 1) wrap = map["contents"].protectionInfo (owned Record only).
        byte[]? wrap = null;
        var wrapSrc = "missing";
        if (!string.IsNullOrWhiteSpace(asset.AssetProtectionInfoHex))
        {
            try
            {
                var w = Convert.FromHexString(asset.AssetProtectionInfoHex);
                if (w.Length is 24 or 40)
                {
                    wrap = w;
                    wrapSrc = "asset.AssetProtectionInfoHex";
                }
            }
            catch { /* ignore */ }
        }

        if (wrap is null
            && asset.RecordPayload is { Length: > 32 } rp
            && ck.SigContents04 is { Length: >= 4 } sig)
        {
            wrap = CloudKitAssetProto.TryResolveOwnedWrap(rp, sig, out wrapSrc);
        }

        ck.Wrap = wrap;
        ck.WrapSource = wrapSrc;
        if (wrap is { Length: 24 or 40 })
            asset.AssetProtectionInfoHex = Convert.ToHexString(wrap);

        // 2) IKM = AES-KW(NISTKDF(ZM,"wrapping key wrap me"), wrap).
        if (asset.AssetUnwrappedKey is { Length: 16 or 32 } existing
            && !string.IsNullOrWhiteSpace(asset.AssetUnwrappedKeyWrapHex)
            && string.Equals(
                asset.AssetUnwrappedKeyWrapHex,
                asset.AssetProtectionInfoHex,
                StringComparison.OrdinalIgnoreCase))
        {
            ck.Ikm = existing;
            ck.IkmSource = "cached-AssetUnwrappedKey";
        }
        else if (wrap is { Length: 24 or 40 })
        {
            var ikm = tryUnwrapWithZoneMaster(asset, wrap);
            if (ikm is { Length: 16 or 32 })
            {
                ck.Ikm = ikm;
                ck.IkmSource = "FillFord-unwrap";
                asset.AssetUnwrappedKey = ikm;
                asset.AssetUnwrappedKeyWrapHex = Convert.ToHexString(wrap);
            }
            else
            {
                ck.Ikm = null;
                ck.IkmSource = "unwrap-failed";
                asset.AssetUnwrappedKey = null;
                asset.AssetUnwrappedKeyWrapHex = null;
            }
        }
        else
        {
            ck.Ikm = null;
            ck.IkmSource = "no-wrap";
        }

        asset.CkFileAsset = ck;
        AgentLog("H-CKFILE-FILL", "FillFordIkmFromContents", "ckfile_fillford", ck, asset);
        return ck;
    }

    /// <summary>
    /// Dopo authorizeGet: attacca gate/ctLen/refs/companion dal FileGroup di
    /// <b>questo</b> Asset (FileChecksum = CKFile+0x100).
    /// </summary>
    public static AssetCkFile AttachFileGroupMaterials(
        BackupAsset asset,
        byte[] authBody,
        AuthorizeGetDecryptPlan plan,
        IReadOnlyList<SignedUrlChunk>? hosts = null)
    {
        var ck = asset.CkFileAsset ?? FillFordIkmFromContents(asset, static (_, _) => null);
        ck.HostCount = plan.Containers.Count;
        ck.RefCount = plan.References.Count;
        ck.DataChunkCount = plan.TotalCryptoChunks;

        // FileChecksum da AG refs — deve coincidere con flist sig04.
        if (plan.FileChecksum is { Length: 21 } fc)
            ck.SigContents04 ??= fc;

        if (plan.CompanionChecksum is { Length: 21 } comp)
            ck.SigCompanion01 ??= comp;

        // Gate owned: embed FC (= CKFile+0x100).
        var fc21 = ck.SigContents04 is { Length: 21 } s ? s : plan.FileChecksum;
        UbChunkBuilder.AuthFordDescriptor? owned = null;
        foreach (var d in UbChunkBuilder.CollectAuthFordDescriptors(authBody, plan, hosts))
        {
            if (d.Gate45.Length != 45 || d.CtLen is < 0x12 or > 65_536)
                continue;
            if (fc21 is { Length: 21 }
                && !UbChunkBuilder.GateEmbedsFileChecksum(d.Gate45, fc21))
                continue;
            owned = d;
            break;
        }

        if (owned is not null)
        {
            ck.Gate45 = owned.Gate45;
            ck.CtLen = owned.CtLen;
            ck.FordObjectId = owned.ObjectId;
            // Companion da gate[24:45] se non già noto.
            if (ck.SigCompanion01 is null && owned.Gate45.Length == 45)
                ck.SigCompanion01 = owned.Gate45.AsSpan(24, 21).ToArray();
            if (ck.SigContents04 is null && owned.Gate45.Length == 45)
                ck.SigContents04 = owned.Gate45.AsSpan(3, 21).ToArray();
        }

        asset.CkFileAsset = ck;
        if (ck.SigCompanion01 is { Length: 21 }
            && asset.MmcsCompanionSignature is not { Length: 21 })
            asset.MmcsCompanionSignature = ck.SigCompanion01;

        AgentLog("H-CKFILE-FG", "AttachFileGroupMaterials", "ckfile_filegroup", ck, asset);
        return ck;
    }

    // #region agent log
    private static void AgentLog(
        string hypothesisId,
        string location,
        string message,
        AssetCkFile ck,
        BackupAsset asset)
    {
        try
        {
            File.AppendAllText(
                System.IO.Path.Combine(System.IO.Path.GetTempPath(), "ike-debug.log"),
                JsonSerializer.Serialize(new Dictionary<string, object?>
                {
                    ["sessionId"] = "03cce7",
                    ["runId"] = RunId,
                    ["hypothesisId"] = hypothesisId,
                    ["timestamp"] = DateTimeOffset.UtcNow.ToUnixTimeMilliseconds(),
                    ["location"] = "AssetMaterialPipeline." + location,
                    ["message"] = message,
                    ["data"] = new Dictionary<string, object?>
                    {
                        ["path"] = asset.RelativePath ?? asset.RecordName,
                        ["recordKey8"] = ck.RecordKey.Length >= 8
                            ? ck.RecordKey[..Math.Min(24, ck.RecordKey.Length)]
                            : ck.RecordKey,
                        ["rpLen"] = ck.ParentRecordPayload?.Length ?? 0,
                        ["sig04"] = ck.SigContents04 is { Length: >= 4 } a
                            ? Convert.ToHexString(a.AsSpan(0, 4))
                            : "",
                        ["sig01"] = ck.SigCompanion01 is { Length: >= 4 } b
                            ? Convert.ToHexString(b.AsSpan(0, 4))
                            : "",
                        ["wrapLen"] = ck.Wrap?.Length ?? 0,
                        ["wrapSrc"] = ck.WrapSource,
                        ["ikmLen"] = ck.Ikm?.Length ?? 0,
                        ["ikmSrc"] = ck.IkmSource,
                        ["ikmHead8"] = ck.Ikm is { Length: >= 8 } ik
                            ? Convert.ToHexString(ik.AsSpan(0, 8))
                            : "",
                        ["gateHex12"] = ck.Gate45 is { Length: >= 12 } g
                            ? Convert.ToHexString(g.AsSpan(0, 12))
                            : "",
                        ["ctLen"] = ck.CtLen,
                        ["refs"] = ck.RefCount,
                        ["dataChunks"] = ck.DataChunkCount,
                        ["hosts"] = ck.HostCount,
                        ["gateMatchesSigs"] = ck.GateMatchesCkFileSigs(),
                        ["hasFord"] = ck.HasFord,
                        ["hasIkm"] = ck.HasIkm,
                        ["oid8"] = ck.FordObjectId is { Length: >= 8 } o
                            ? o[..8]
                            : ck.FordObjectId ?? "",
                    },
                }) + Environment.NewLine);
        }
        catch { /* ignore */ }
    }
    // #endregion
}
