using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Nuovo peer Octagon (P-384 signing + encryption) con permanent / stable / dynamic
/// signed info — allineato a rustpush <c>KeychainUserIdentity::new</c> / Sank6.
/// </summary>
public static class OctagonPeerIdentity
{
    public const string PermanentSigType = "TPPB.PeerPermanentInfo";
    public const string StableSigType = "TPPB.PeerStableInfo";
    public const string DynamicSigType = "TPPB.PeerDynamicInfo";
    public const string VoucherSigType = "TPPB.Voucher";

    // Policy hash pinning (rustpush generate_stable_info).
    public const string FrozenPolicyHash =
        "SHA256:O/ECQlWhvNlLmlDNh2+nal/yekUC87bXpV3k+6kznSo=";
    public const string FlexiblePolicyHash =
        "SHA256:OIzjC3WyLGrM8GAd/EyIfVzTJdYmcGoKPFdQeWeRZTY=";

    public sealed record SignedBlob(byte[] Data, byte[] Signature)
    {
        public byte[] ToProtobuf()
        {
            var w = new ProtobufWriter();
            w.WriteBytes(1, Data);
            w.WriteBytes(2, Signature);
            return w.ToArray();
        }
    }

    public sealed record PeerKeys(
        string PeerId,
        byte[] SigningPkcs8,
        byte[] EncryptionPkcs8,
        byte[] SigningSpki,
        byte[] EncryptionSpki,
        byte[] SigningPublicX963,
        byte[] EncryptionPublicX963,
        SignedBlob PermanentInfo,
        SignedBlob StableInfo,
        SignedBlob DynamicInfo);

    public static PeerKeys Create(
        string machineId,
        string modelId,
        string serialNumber,
        string deviceName,
        string osVersion,
        IReadOnlyList<string> includedPeerIds,
        ulong stableClock = 1,
        ulong dynamicClock = 1,
        ulong epoch = 1)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(machineId);
        ArgumentException.ThrowIfNullOrWhiteSpace(modelId);

        using var signing = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var encryption = ECDsa.Create(ECCurve.NamedCurves.nistP384);

        var signingPkcs8 = signing.ExportPkcs8PrivateKey();
        var encryptionPkcs8 = encryption.ExportPkcs8PrivateKey();
        var signingSpki = signing.ExportSubjectPublicKeyInfo();
        var encryptionSpki = encryption.ExportSubjectPublicKeyInfo();
        var signingPubX963 = ExportUncompressedPoint(signing);
        var encryptionPubX963 = ExportUncompressedPoint(encryption);

        var creationMs = (ulong)DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();
        var permanentData = EncodePermanentInfo(
            epoch, signingSpki, encryptionSpki, machineId.Trim(), MungeModelId(modelId), creationMs);
        var permanentSig = SignTyped(signing, PermanentSigType, permanentData);
        var peerId = "SHA256:" + Convert.ToBase64String(
            SHA256.HashData(Concat(permanentData, permanentSig)));

        var includeds = new List<string> { peerId };
        foreach (var id in includedPeerIds)
        {
            if (string.IsNullOrWhiteSpace(id))
                continue;
            if (!includeds.Contains(id, StringComparer.Ordinal))
                includeds.Add(id);
        }

        var stableData = EncodeStableInfo(
            stableClock,
            frozenPolicyVersion: 5,
            FrozenPolicyHash,
            osVersion,
            deviceName ?? "",
            serialNumber ?? "",
            flexiblePolicyVersion: 20,
            FlexiblePolicyHash,
            userControllableViewStatus: 1);
        var stableSig = SignTyped(signing, StableSigType, stableData);

        var dynamicData = EncodeDynamicInfo(dynamicClock, includeds);
        var dynamicSig = SignTyped(signing, DynamicSigType, dynamicData);

        return new PeerKeys(
            peerId,
            signingPkcs8,
            encryptionPkcs8,
            signingSpki,
            encryptionSpki,
            signingPubX963,
            encryptionPubX963,
            new SignedBlob(permanentData, permanentSig),
            new SignedBlob(stableData, stableSig),
            new SignedBlob(dynamicData, dynamicSig));
    }

    /// <summary>Sponsor firma un voucher per il beneficiary (nuovo peer).</summary>
    public static SignedBlob CreateVoucher(
        byte[] sponsorSigningPkcs8,
        string sponsorPeerId,
        string beneficiaryPeerId,
        uint reason = 1)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(sponsorPeerId);
        ArgumentException.ThrowIfNullOrWhiteSpace(beneficiaryPeerId);

        var w = new ProtobufWriter();
        w.WriteVarint(1, reason);
        w.WriteString(2, beneficiaryPeerId);
        w.WriteString(3, sponsorPeerId);
        var data = w.ToArray();

        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(sponsorSigningPkcs8, out _);
        var sig = SignTyped(ecdsa, VoucherSigType, data);
        return new SignedBlob(data, sig);
    }

    public static byte[] EncodeCuttlefishPeer(
        PeerKeys peer,
        SignedBlob voucher)
    {
        var w = new ProtobufWriter();
        w.WriteString(1, peer.PeerId);
        w.WriteBytes(2, peer.PermanentInfo.ToProtobuf());
        w.WriteBytes(3, peer.StableInfo.ToProtobuf());
        w.WriteBytes(4, peer.DynamicInfo.ToProtobuf());
        w.WriteBytes(5, voucher.ToProtobuf());
        return w.ToArray();
    }

    public static byte[] SignTyped(ECDsa key, string typeName, byte[] data)
    {
        var prefixed = Concat(Encoding.UTF8.GetBytes(typeName), data);
        return key.SignData(
            prefixed,
            HashAlgorithmName.SHA384,
            DSASignatureFormat.Rfc3279DerSequence);
    }

    public static string MungeModelId(string modelId)
    {
        // TrustedPeersHelper munge: keep Apple model tokens as-is for lab.
        return modelId.Trim();
    }

    public static byte[] ExportUncompressedPoint(ECDsa key)
    {
        var p = key.ExportParameters(false);
        var x = Pad48(p.Q.X!);
        var y = Pad48(p.Q.Y!);
        var point = new byte[97];
        point[0] = 0x04;
        Buffer.BlockCopy(x, 0, point, 1, 48);
        Buffer.BlockCopy(y, 0, point, 49, 48);
        return point;
    }

    public static byte[] Pkcs8ToAppleKeyData(byte[] pkcs8)
    {
        using var ecdsa = ECDsa.Create();
        ecdsa.ImportPkcs8PrivateKey(pkcs8, out _);
        var p = ecdsa.ExportParameters(true);
        var x = Pad48(p.Q.X!);
        var y = Pad48(p.Q.Y!);
        var d = Pad48(p.D!);
        var keyData = new byte[145];
        keyData[0] = 0x04;
        Buffer.BlockCopy(x, 0, keyData, 1, 48);
        Buffer.BlockCopy(y, 0, keyData, 49, 48);
        Buffer.BlockCopy(d, 0, keyData, 97, 48);
        return keyData;
    }

    private static byte[] EncodePermanentInfo(
        ulong epoch,
        byte[] signingSpki,
        byte[] encryptionSpki,
        string machineId,
        string modelId,
        ulong creationTimeMs)
    {
        var w = new ProtobufWriter();
        w.WriteVarint(1, epoch);
        w.WriteBytes(2, signingSpki);
        w.WriteBytes(3, encryptionSpki);
        w.WriteString(4, machineId);
        w.WriteString(5, modelId);
        w.WriteVarint(6, creationTimeMs);
        return w.ToArray();
    }

    private static byte[] EncodeStableInfo(
        ulong clock,
        ulong frozenPolicyVersion,
        string frozenPolicyHash,
        string osVersion,
        string deviceName,
        string serialNumber,
        ulong flexiblePolicyVersion,
        string flexiblePolicyHash,
        uint userControllableViewStatus)
    {
        var w = new ProtobufWriter();
        w.WriteVarint(1, clock);
        w.WriteVarint(2, frozenPolicyVersion);
        w.WriteString(3, frozenPolicyHash);
        w.WriteString(5, osVersion);
        w.WriteString(6, deviceName);
        w.WriteString(9, serialNumber);
        w.WriteVarint(10, flexiblePolicyVersion);
        w.WriteString(11, flexiblePolicyHash);
        w.WriteVarint(12, userControllableViewStatus);
        w.WriteVarint(18, 0); // isInheritedAccount = false
        return w.ToArray();
    }

    private static byte[] EncodeDynamicInfo(ulong clock, IReadOnlyList<string> includeds)
    {
        var w = new ProtobufWriter();
        w.WriteVarint(1, clock);
        foreach (var id in includeds)
            w.WriteString(2, id);
        return w.ToArray();
    }

    private static byte[] Pad48(byte[] n)
    {
        if (n.Length == 48)
            return n;
        if (n.Length > 48)
            return n[^48..];
        var p = new byte[48];
        Buffer.BlockCopy(n, 0, p, 48 - n.Length, n.Length);
        return p;
    }

    private static byte[] Concat(params byte[][] parts)
    {
        var len = parts.Sum(p => p.Length);
        var buf = new byte[len];
        var o = 0;
        foreach (var p in parts)
        {
            Buffer.BlockCopy(p, 0, buf, o, p.Length);
            o += p.Length;
        }

        return buf;
    }
}
