using System.IO;
using iCloudKitExtractor.Models;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Costruisce richieste PreAuth ubchunk: magic XB, sessione Foreground Restore,
/// frame N: da manifestChecksums (:CN:) e path firmati dalla risposta precedente.
/// </summary>
public static class UbChunkPreAuthRequestBuilder
{
    /// <summary>201505/20260721 round 1: ~391 frame N:; round 2: ~247.</summary>
    public const int MaxEnFramesFirstRound = 392;

    public const int MaxEnFramesPerRound = 248;

    /// <summary>
    /// Body ubchunk  prefisso wSc (se presente) + frame Foreground + frame N: delimited.
    /// </summary>
    public static byte[] BuildPreAuthBody(
        RestoreRequestContext context,
        string cloudKitUserId,
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries,
        int skipEntries,
        int takeEntries,
        byte[]? wscPrefix,
        bool includeForegroundHeader,
        string? firstEnInForeground = null)
    {
        using var ms = new MemoryStream();
        if (wscPrefix is { Length: > 0 })
            ms.Write(wscPrefix);

        var frames = new List<byte[]>();
        if (includeForegroundHeader)
        {
            frames.Add(CloudKitDelimitedRequest.BuildPreAuthForegroundRetrieveMessage(
                cloudKitUserId, context, firstEnInForeground));
        }

        foreach (var entry in cnEntries.Skip(skipEntries).Take(takeEntries))
            frames.Add(BuildManifestEntryFrame(cloudKitUserId, entry));

        if (frames.Count > 0)
            ms.Write(UbChunkDelimitedCodec.ConcatFrames(frames));

        return ms.ToArray();
    }

    public static byte[] BuildRound1WithoutSession(
        RestoreRequestContext context,
        string cloudKitUserId,
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries) =>
        BuildRound1(context, cloudKitUserId, cnEntries, wscPrefix: null, sessionBlob: null);

    /// <summary>
    /// Round 1 (req 52): prefisso wSc + blob sessione ~2940 B + primo EN compatto (141 B) + EN standard (190 B).
    /// </summary>
    public static byte[] BuildRound1(
        RestoreRequestContext context,
        string cloudKitUserId,
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries,
        byte[]? wscPrefix,
        byte[]? sessionBlob,
        int skipEntries = 0,
        int? maxEntries = null)
    {
        var limit = maxEntries ?? MaxEnFramesFirstRound;
        var batch = cnEntries.Skip(skipEntries).Take(limit).ToList();
        if (batch.Count == 0)
            return [];

        using var ms = new MemoryStream();
        if (wscPrefix is { Length: > 0 })
            ms.Write(wscPrefix);

        if (sessionBlob is { Length: > 0 })
            ms.Write(UbChunkDelimitedCodec.WriteFrame(sessionBlob));

        var frames = new List<byte[]>
        {
            BuildCompactEnFrame(
                cloudKitUserId,
                UbChunkCatalogParser.BuildNRecordName(batch[0].FileUuid, batch[0].ChecksumBase64))
        };

        foreach (var entry in batch.Skip(1))
            frames.Add(BuildManifestEntryFrame(cloudKitUserId, entry));

        ms.Write(UbChunkDelimitedCodec.ConcatFrames(frames));
        return ms.ToArray();
    }

    /// <summary>Primo N: round 1  f1=retrieve, f6=flags (141 B), non RequestOperation.</summary>
    public static byte[] BuildCompactEnFrame(string cloudKitUserId, string enRecordName)
    {
        var retrieve = BuildRecordRetrieveInner(cloudKitUserId, enRecordName);

        var flags = new ProtobufWriter();
        flags.WriteVarint(1, 1);

        var frame = new ProtobufWriter();
        frame.WriteBytes(1, retrieve);
        frame.WriteBytes(6, flags.ToArray());
        return frame.ToArray();
    }

    private static byte[] BuildRecordRetrieveInner(string cloudKitUserId, string enRecordName)
    {
        var recordId = new ProtobufWriter();
        recordId.WriteString(1, enRecordName);
        recordId.WriteVarint(2, 1);

        var request = new ProtobufWriter();
        request.WriteBytes(1, recordId.ToArray());
        request.WriteBytes(2, CloudKitDelimitedRequest.BuildZoneIdentifier("_defaultZone", cloudKitUserId));
        return request.ToArray();
    }

    public static byte[] BuildRound2(
        RestoreRequestContext context,
        string cloudKitUserId,
        IReadOnlyList<CloudKitManifestChecksumParser.CnEntry> cnEntries,
        int skipEntries = 0,
        int? maxEntries = null)
    {
        var limit = maxEntries ?? MaxEnFramesPerRound;
        var batch = cnEntries.Skip(skipEntries).Take(limit).ToList();
        if (batch.Count == 0)
            return [];

        var firstN = UbChunkCatalogParser.BuildNRecordName(batch[0].FileUuid, batch[0].ChecksumBase64);

        // ConcatFrames aggiunge già il varint di lunghezza: non wrapparare prima
        // (doppio wrap → 503 sul gateway).
        var frames = new List<byte[]>
        {
            CloudKitDelimitedRequest.BuildPreAuthForegroundRetrieveMessage(
                cloudKitUserId, context, firstN)
        };

        //  il primo N: è solo nel frame header (f211), i frame successivi partono dal secondo.
        foreach (var entry in batch.Skip(1))
            frames.Add(BuildManifestEntryFrame(cloudKitUserId, entry));

        return UbChunkDelimitedCodec.ConcatFrames(frames);
    }

    public static byte[] BuildManifestEntryFrame(
        string cloudKitUserId,
        CloudKitManifestChecksumParser.CnEntry entry)
    {
        var nName = UbChunkCatalogParser.BuildNRecordName(entry.FileUuid, entry.ChecksumBase64);
        return BuildManifestEntryFrame(cloudKitUserId, nName);
    }

    public static byte[] BuildManifestEntryFrame(string cloudKitUserId, string enRecordName)
    {
        var correlationId = new ProtobufWriter();
        correlationId.WriteString(1, Guid.NewGuid().ToString());
        correlationId.WriteVarint(2, CloudKitDelimitedRequest.FetchRecordsType);
        correlationId.WriteVarint(4, 1);

        var recordId = new ProtobufWriter();
        recordId.WriteString(1, enRecordName);
        recordId.WriteVarint(2, 1);

        var request = new ProtobufWriter();
        request.WriteBytes(1, recordId.ToArray());
        request.WriteBytes(2, CloudKitDelimitedRequest.BuildZoneIdentifier("_defaultZone", cloudKitUserId));

        var flags = new ProtobufWriter();
        flags.WriteVarint(1, 1);

        var retrieve = new ProtobufWriter();
        retrieve.WriteBytes(1, request.ToArray());
        retrieve.WriteBytes(6, flags.ToArray());

        var opInner = new ProtobufWriter();
        opInner.WriteBytes(2, correlationId.ToArray());
        opInner.WriteBytes(211, retrieve.ToArray());

        return opInner.ToArray();
    }
}
