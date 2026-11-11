using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Costruisce materiale wSc PreAuth round 1 (201505): prefisso 126 B + blob sessione 2940 B.
/// Template binari da capture; parti variabili derivate dalla sessione (non asset stale monolitico).
/// </summary>
public static class UbChunkWscSessionBuilder
{
    private const int SessionUnitsPerBlob = 15;
    private const int SessionUnitSize = 192;
    private const int PrefixFrame3Size = 97;
    private const int PrefixFrame2NonceOffset = 19;
    private const int PrefixFrame2NonceLength = 8;
    private const int SessionUnitNNameMaxLength = 69;
    private const int SessionUnitCorrelationOffset = 141;
    private const int SessionUnitCorrelationLength = 36;

    private static readonly Lazy<byte[]> PrefixFrame1 = new(() => LoadAsset("wsc_prefix_frame1.bin"));
    private static readonly Lazy<byte[]> PrefixFrame2Template = new(() => LoadAsset("wsc_prefix_frame2_template.bin"));
    private static readonly Lazy<byte[]> SessionBlobHeader = new(() => LoadAsset("wsc_session_blob_header.bin"));
    private static readonly Lazy<byte[]> SessionUnitTemplate = new(() => LoadAsset("wsc_session_unit_template.bin"));

    public static void TryPopulatePreAuthMaterial(
        RestoreSessionState restore,
        ICloudSession session,
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries)
    {
        if (cnEntries.Count == 0)
            return;

        if (restore.ResolvePreAuthWscPrefix() is null)
            restore.CapturePreAuthWscPrefix(BuildPrefix(restore, session));

        if (restore.PreAuthSessionBlob is null)
            restore.CapturePreAuthSessionBlob(BuildSessionBlob(cnEntries, session.CloudKitUserId));
    }

    public static byte[] BuildPrefix(RestoreSessionState restore, ICloudSession session)
    {
        var frame1 = PrefixFrame1.Value;
        var frame2 = (byte[])PrefixFrame2Template.Value.Clone();
        PatchNonce(frame2, PrefixFrame2NonceOffset, Hmac(
            restore.DeviceSessionId, restore.OperationGroupId, session.CloudKitUserId, "wsc-f2"));

        var frame3 = DerivePrefixFrame3(restore, session);
        return UbChunkDelimitedCodec.ConcatFrames([frame1, frame2, frame3]);
    }

    public static byte[] BuildSessionBlob(
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries,
        string cloudKitUserId)
    {
        using var ms = new MemoryStream();
        ms.Write(SessionBlobHeader.Value);

        var count = Math.Min(SessionUnitsPerBlob, cnEntries.Count);
        for (var i = 0; i < count; i++)
        {
            var entry = cnEntries[i];
            var nName = UbChunkCatalogParser.BuildNRecordName(entry.FileUuid, entry.ChecksumBase64);
            var correlation = DeriveCorrelationId(cloudKitUserId, nName, i);
            ms.Write(BuildSessionUnit(nName, correlation));
        }

        var partial = BuildPartialTailUnit(cnEntries, cloudKitUserId, count);
        if (partial is { Length: > 0 })
            ms.Write(partial);

        var payload = ms.ToArray();
        return payload.Length switch
        {
            2940 => payload,
            < 2940 => PadToLength(payload, 2940),
            _ => payload.AsSpan(0, 2940).ToArray()
        };
    }

    private static byte[] BuildSessionUnit(string nRecordName, string correlationId)
    {
        var unit = (byte[])SessionUnitTemplate.Value.Clone();
        PatchAscii(unit, 0, nRecordName, SessionUnitNNameMaxLength);
        PatchAscii(unit, SessionUnitCorrelationOffset, correlationId, SessionUnitCorrelationLength);
        return unit;
    }

    private static byte[]? BuildPartialTailUnit(
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries,
        string cloudKitUserId,
        int consumed)
    {
        if (consumed >= cnEntries.Count)
            return null;

        var entry = cnEntries[consumed];
        var nName = UbChunkCatalogParser.BuildNRecordName(entry.FileUuid, entry.ChecksumBase64);
        var correlation = DeriveCorrelationId(cloudKitUserId, nName, consumed);
        var full = BuildSessionUnit(nName, correlation);
        return full.AsSpan(0, 2940 - SessionBlobHeader.Value.Length - consumed * SessionUnitSize).ToArray();
    }

    private static byte[] DerivePrefixFrame3(RestoreSessionState restore, ICloudSession session)
    {
        var frame = new byte[PrefixFrame3Size];
        var written = 0;
        var round = 0;
        while (written < PrefixFrame3Size)
        {
            var block = Hmac(
                restore.DeviceSessionId,
                restore.OperationGroupId,
                session.CloudKitUserId,
                restore.Foreground?.HardwareIdHex ?? "foreground",
                $"wsc-f3|{round}");
            var take = Math.Min(block.Length, PrefixFrame3Size - written);
            Buffer.BlockCopy(block, 0, frame, written, take);
            written += take;
            round++;
        }

        return frame;
    }

    private static byte[] DeriveNonce(string seed, string salt, params string[] parts) =>
        Hmac(new[] { seed, salt }.Concat(parts).ToArray());

    private static byte[] Hmac(params string[] parts)
    {
        var payload = string.Join('|', parts);
        return HMACSHA256.HashData(
            "icloudkit|wsc"u8,
            Encoding.UTF8.GetBytes(payload));
    }

    private static string DeriveCorrelationId(string cloudKitUserId, string enRecordName, int index)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes($"{cloudKitUserId}|{enRecordName}|{index}"));
        return new Guid(hash.AsSpan(0, 16)).ToString();
    }

    private static void PatchNonce(byte[] buffer, int offset, byte[] nonce)
    {
        var length = Math.Min(PrefixFrame2NonceLength, nonce.Length);
        Buffer.BlockCopy(nonce, 0, buffer, offset, length);
    }

    private static void PatchAscii(byte[] buffer, int offset, string value, int maxLength)
    {
        var bytes = Encoding.ASCII.GetBytes(value);
        var length = Math.Min(maxLength, bytes.Length);
        Array.Clear(buffer, offset, maxLength);
        Buffer.BlockCopy(bytes, 0, buffer, offset, length);
    }

    private static byte[] PadToLength(byte[] data, int length)
    {
        if (data.Length >= length)
            return data;

        var padded = new byte[length];
        Buffer.BlockCopy(data, 0, padded, 0, data.Length);
        return padded;
    }

    private static byte[] LoadAsset(string fileName)
    {
        var assembly = Assembly.GetExecutingAssembly();
        var name = $"iCloudKitExtractor.Assets.ike.{fileName}";
        using var stream = assembly.GetManifestResourceStream(name);
        if (stream is null)
            throw new InvalidOperationException($"Risorsa embedded mancante: {name}");

        using var ms = new MemoryStream();
        stream.CopyTo(ms);
        return ms.ToArray();
    }
}
