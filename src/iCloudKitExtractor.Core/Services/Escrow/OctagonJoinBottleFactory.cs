using System.Security.Cryptography;
using iCloudKitExtractor.Protocol;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Costruisce il messaggio Cuttlefish <c>Bottle</c> (OTBottle AES-GCM) per
/// <c>joinWithVoucher</c> — reverse di <see cref="OctagonBottleCrypto"/>.
/// </summary>
public static class OctagonJoinBottleFactory
{
    public sealed record BuiltBottle(
        string BottleId,
        byte[] BottleMessage,
        byte[] Entropy,
        byte[] EscrowSigningSpki,
        byte[] OtBottleBytes);

    public static BuiltBottle Build(
        OctagonPeerIdentity.PeerKeys peer,
        string adsid)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(adsid);

        var entropy = RandomNumberGenerator.GetBytes(72);
        var bottleId = Guid.NewGuid().ToString("D").ToUpperInvariant();

        using var escrowSigning = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        using var escrowEncryption = ECDsa.Create(ECCurve.NamedCurves.nistP384);
        var escrowSigningSpki = escrowSigning.ExportSubjectPublicKeyInfo();
        var escrowEncryptionSpki = escrowEncryption.ExportSubjectPublicKeyInfo();

        // OTInternalBottle { signingKey=3, encryptionKey=4 } each OTPrivateKey{type=1, keyData}.
        var internalBottle = EncodeInternalBottle(
            OctagonPeerIdentity.Pkcs8ToAppleKeyData(peer.SigningPkcs8),
            OctagonPeerIdentity.Pkcs8ToAppleKeyData(peer.EncryptionPkcs8));

        var sym = OctagonBottleCrypto.DeriveSymmetricKey(entropy, adsid);
        var iv = RandomNumberGenerator.GetBytes(32);
        var (ct, tag) = AesGcmSeal(sym, iv, internalBottle);

        var auth = new ProtobufWriter();
        auth.WriteBytes(1, ct);
        auth.WriteBytes(2, tag);
        auth.WriteBytes(3, iv);

        var ot = new ProtobufWriter();
        ot.WriteString(1, peer.PeerId);
        ot.WriteString(2, bottleId);
        ot.WriteBytes(8, escrowSigningSpki);
        ot.WriteBytes(9, escrowEncryptionSpki);
        ot.WriteBytes(10, peer.SigningPublicX963);
        ot.WriteBytes(11, peer.EncryptionPublicX963);
        ot.WriteBytes(12, auth.ToArray());
        var otBytes = ot.ToArray();

        using var peerSign = ECDsa.Create();
        peerSign.ImportPkcs8PrivateKey(peer.SigningPkcs8, out _);
        var peerSig = peerSign.SignData(
            otBytes,
            HashAlgorithmName.SHA384,
            DSASignatureFormat.Rfc3279DerSequence);
        var escrowSig = escrowSigning.SignData(
            otBytes,
            HashAlgorithmName.SHA384,
            DSASignatureFormat.Rfc3279DerSequence);

        var bottle = new ProtobufWriter();
        bottle.WriteBytes(2, otBytes);
        bottle.WriteBytes(3, escrowSigningSpki);
        bottle.WriteBytes(4, escrowSig);
        bottle.WriteBytes(5, peerSig);
        bottle.WriteString(6, peer.PeerId);
        bottle.WriteString(7, bottleId);

        return new BuiltBottle(
            bottleId,
            bottle.ToArray(),
            entropy,
            escrowSigningSpki,
            otBytes);
    }

    private static byte[] EncodeInternalBottle(byte[] signingKeyData, byte[] encryptionKeyData)
    {
        static byte[] PrivateKey(byte[] keyData)
        {
            var w = new ProtobufWriter();
            w.WriteVarint(1, 1);
            w.WriteBytes(2, keyData);
            return w.ToArray();
        }

        var w = new ProtobufWriter();
        w.WriteBytes(3, PrivateKey(signingKeyData));
        w.WriteBytes(4, PrivateKey(encryptionKeyData));
        return w.ToArray();
    }

    private static (byte[] Ciphertext, byte[] Tag) AesGcmSeal(
        byte[] key, byte[] iv, byte[] plaintext)
    {
        const int tagBits = 128;
        var cipher = new GcmBlockCipher(new AesEngine());
        cipher.Init(true, new AeadParameters(new KeyParameter(key), tagBits, iv));
        var output = new byte[cipher.GetOutputSize(plaintext.Length)];
        var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, output, 0);
        len += cipher.DoFinal(output, len);
        var tagLen = tagBits / 8;
        var ctLen = len - tagLen;
        var ct = output.AsSpan(0, ctLen).ToArray();
        var tag = output.AsSpan(ctLen, tagLen).ToArray();
        return (ct, tag);
    }
}
