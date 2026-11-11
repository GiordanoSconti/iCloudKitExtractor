using System.IO;
using System.IO.Compression;
using System.Text;

namespace iCloudKitExtractor.Protocol;

/// <summary>
/// Parser campi Messages Manatee + body <c>msgProto*</c>
/// (OpenBubbles/rustpush <c>cloud_messages.proto</c>).
/// </summary>
public static class MessageProtoParser
{
    private static readonly DateTimeOffset AppleEpoch =
        new(2001, 1, 1, 0, 0, 0, TimeSpan.Zero);

    public sealed record ParsedMessageProto(
        uint? Version,
        string? Subject,
        string? Text,
        string? BalloonBundleId,
        string? Effect,
        string? AssociatedMessageGuid,
        uint? AssociatedMessageType,
        uint? AssociatedMessageRangeLocation,
        uint? AssociatedMessageRangeLength,
        ulong? DateRead,
        ulong? DateDelivered,
        uint? TimePlayed,
        uint? TimeExpressiveSentPlayed,
        uint? ExpireState,
        bool HasAttributedBody,
        bool HasPayloadData,
        bool HasMessageSummaryInfo,
        string? DateReadUtc,
        string? DateDeliveredUtc);

    public sealed record ParsedMessageProto2(
        uint? Version,
        string? Reply);

    public sealed record ParsedMessageProto3(
        uint? Version,
        uint? CmmState,
        uint? CmmAssetOffset);

    public sealed record ParsedMessageProto4(
        uint? Version,
        string? AssociatedMessageEmoji,
        string? Service,
        string? GroupId,
        uint? ScheduleType,
        uint? ScheduleState,
        uint? SentOrReceivedOffGrid);

    public sealed record ParsedChatProto(
        uint? Version,
        uint? IsRecovered);

    public sealed record ParsedGroupTitleChange(
        uint? Version,
        string? GroupTitle,
        string? OtherHandle);

    public sealed record ParsedLocationShareStatusChange(
        uint? Version,
        long? ShareStatus,
        long? ShareDirection,
        string? OtherHandle);

    public sealed record ParsedMessageAction(
        uint? Version,
        long? MessageActionType,
        string? OtherHandle,
        string? OriginalMessageGuid);

    public sealed record ParsedParticipantChange(
        uint? Version,
        long? ParticipantChangeType,
        string? OtherHandle);

    public sealed record ParsedGroupAction(
        uint? Version,
        long? GroupActionType,
        string? OtherHandle);

    /// <summary>
    /// Classificazione del body dopo gunzip: messaggio testo, evento chat, o sconosciuto.
    /// </summary>
    public sealed record ParsedBody(
        string Kind,
        ParsedMessageProto? Message,
        ParsedGroupTitleChange? GroupTitle,
        ParsedLocationShareStatusChange? LocationShare,
        ParsedMessageAction? MessageAction,
        ParsedParticipantChange? ParticipantChange,
        ParsedGroupAction? GroupAction,
        string? DisplayText);

    /// <summary>Gunzip se necessario, poi parse MessageProto (corpo tipico).</summary>
    public static ParsedMessageProto? TryParseMessageProto(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        string? subject = null;
        string? text = null;
        string? balloon = null;
        string? effect = null;
        string? assocGuid = null;
        uint? assocType = null;
        uint? assocLoc = null;
        uint? assocLen = null;
        ulong? dateRead = null;
        ulong? dateDelivered = null;
        uint? timePlayed = null;
        uint? timeExpressive = null;
        uint? expireState = null;
        var hasAttr = false;
        var hasPayload = false;
        var hasSummary = false;

        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 2:
                        subject = ReadUtf8(r);
                        break;
                    case 3 when wt == 2:
                        text = ReadUtf8(r);
                        break;
                    case 4 when wt == 2:
                        _ = r.ReadLengthDelimited();
                        hasAttr = true;
                        break;
                    case 5 when wt == 2:
                        balloon = ReadUtf8(r);
                        break;
                    case 6 when wt == 2:
                        _ = r.ReadLengthDelimited();
                        hasPayload = true;
                        break;
                    case 7 when wt == 2:
                        _ = r.ReadLengthDelimited();
                        hasSummary = true;
                        break;
                    case 8 when wt == 2:
                        effect = ReadUtf8(r);
                        break;
                    case 9 when wt == 0:
                        dateRead = r.ReadVarint();
                        break;
                    case 10 when wt == 0:
                        timePlayed = (uint)r.ReadVarint();
                        break;
                    case 11 when wt == 0:
                        timeExpressive = (uint)r.ReadVarint();
                        break;
                    case 13 when wt == 0:
                        dateDelivered = r.ReadVarint();
                        break;
                    case 14 when wt == 0:
                        expireState = (uint)r.ReadVarint();
                        break;
                    case 15 when wt == 0:
                        assocType = (uint)r.ReadVarint();
                        break;
                    case 16 when wt == 2:
                        assocGuid = ReadUtf8(r);
                        break;
                    case 17 when wt == 0:
                        assocLoc = (uint)r.ReadVarint();
                        break;
                    case 18 when wt == 0:
                        assocLen = (uint)r.ReadVarint();
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            if (LooksLikeUtf8(body))
            {
                return new ParsedMessageProto(
                    null, null, Encoding.UTF8.GetString(body).Trim(),
                    null, null, null, null, null, null,
                    null, null, null, null, null,
                    false, false, false, null, null);
            }

            return null;
        }

        // Heuristica: MessageProto “vero” ha version==1 e/o text/subject/attr.
        if (version is null or 0
            && text is null
            && subject is null
            && !hasAttr
            && !hasPayload
            && balloon is null)
            return null;

        return new ParsedMessageProto(
            version, subject, text, balloon, effect, assocGuid, assocType,
            assocLoc, assocLen, dateRead, dateDelivered, timePlayed, timeExpressive,
            expireState, hasAttr, hasPayload, hasSummary,
            FormatAppleNanos(dateRead), FormatAppleNanos(dateDelivered));
    }

    public static ParsedMessageProto2? TryParseMessageProto2(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        string? reply = null;
        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 2:
                        reply = ReadUtf8(r);
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            return null;
        }

        return new ParsedMessageProto2(version, reply);
    }

    public static ParsedMessageProto3? TryParseMessageProto3(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        uint? cmmState = null;
        uint? cmmAsset = null;
        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 0:
                        cmmState = (uint)r.ReadVarint();
                        break;
                    case 3 when wt == 0:
                        cmmAsset = (uint)r.ReadVarint();
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            return null;
        }

        return new ParsedMessageProto3(version, cmmState, cmmAsset);
    }

    public static ParsedMessageProto4? TryParseMessageProto4(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        string? emoji = null;
        string? service = null;
        string? groupId = null;
        uint? scheduleType = null;
        uint? scheduleState = null;
        uint? offGrid = null;

        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 2:
                        emoji = ReadUtf8(r);
                        break;
                    case 4 when wt == 2:
                        service = ReadUtf8(r);
                        break;
                    case 5 when wt == 0:
                        scheduleType = (uint)r.ReadVarint();
                        break;
                    case 6 when wt == 0:
                        scheduleState = (uint)r.ReadVarint();
                        break;
                    case 7 when wt == 2:
                        groupId = ReadUtf8(r);
                        break;
                    case 8 when wt == 0:
                        offGrid = (uint)r.ReadVarint();
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            return null;
        }

        return new ParsedMessageProto4(
            version, emoji, service, groupId, scheduleType, scheduleState, offGrid);
    }

    public static ParsedChatProto? TryParseChatProto(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        uint? recovered = null;
        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 0:
                        recovered = (uint)r.ReadVarint();
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            return null;
        }

        return new ParsedChatProto(version, recovered);
    }

    public static ParsedGroupTitleChange? TryParseGroupTitleChange(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        string? title = null;
        string? other = null;
        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 2:
                        title = ReadUtf8(r);
                        break;
                    case 3 when wt == 2:
                        other = ReadUtf8(r);
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            return null;
        }

        if (title is null && other is null)
            return null;
        return new ParsedGroupTitleChange(version, title, other);
    }

    public static ParsedLocationShareStatusChange? TryParseLocationShareStatusChange(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        long? status = null;
        long? direction = null;
        string? other = null;
        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 0:
                        status = (long)r.ReadVarint();
                        break;
                    case 3 when wt == 0:
                        direction = (long)r.ReadVarint();
                        break;
                    case 4 when wt == 2:
                        other = ReadUtf8(r);
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            return null;
        }

        if (status is null && other is null)
            return null;
        return new ParsedLocationShareStatusChange(version, status, direction, other);
    }

    public static ParsedMessageAction? TryParseMessageAction(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        long? actionType = null;
        string? other = null;
        string? original = null;
        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 0:
                        actionType = (long)r.ReadVarint();
                        break;
                    case 3 when wt == 2:
                        other = ReadUtf8(r);
                        break;
                    case 4 when wt == 2:
                        original = ReadUtf8(r);
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            return null;
        }

        if (actionType is null && original is null)
            return null;
        return new ParsedMessageAction(version, actionType, other, original);
    }

    public static ParsedParticipantChange? TryParseParticipantChange(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        long? changeType = null;
        string? other = null;
        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 0:
                        changeType = (long)r.ReadVarint();
                        break;
                    case 3 when wt == 2:
                        other = ReadUtf8(r);
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            return null;
        }

        if (changeType is null && other is null)
            return null;
        return new ParsedParticipantChange(version, changeType, other);
    }

    public static ParsedGroupAction? TryParseGroupAction(byte[]? data)
    {
        var body = MaybeGunzip(data);
        if (body is not { Length: > 0 })
            return null;

        uint? version = null;
        long? actionType = null;
        string? other = null;
        try
        {
            var r = new ProtobufReader(body);
            while (r.HasMore)
            {
                var (fn, wt) = r.ReadTag();
                switch (fn)
                {
                    case 1 when wt == 0:
                        version = (uint)r.ReadVarint();
                        break;
                    case 2 when wt == 0:
                        actionType = (long)r.ReadVarint();
                        break;
                    case 3 when wt == 2:
                        other = ReadUtf8(r);
                        break;
                    default:
                        r.SkipField(wt);
                        break;
                }
            }
        }
        catch (InvalidDataException)
        {
            return null;
        }

        if (actionType is null && other is null)
            return null;
        return new ParsedGroupAction(version, actionType, other);
    }

    /// <summary>
    /// Prova MessageProto, poi tipi evento (rename gruppo, partecipanti, location, …).
    /// </summary>
    public static ParsedBody ParseBody(byte[]? data)
    {
        var msg = TryParseMessageProto(data);
        if (msg is not null
            && (msg.Text is { Length: > 0 }
                || msg.Subject is { Length: > 0 }
                || msg.HasAttributedBody
                || msg.Version is 1))
        {
            var display = msg.Text ?? msg.Subject;
            return new ParsedBody("message", msg, null, null, null, null, null, display);
        }

        var title = TryParseGroupTitleChange(data);
        if (title is not null)
        {
            var display = string.IsNullOrWhiteSpace(title.GroupTitle)
                ? null
                : $"group_title:{title.GroupTitle}";
            return new ParsedBody("group_title", null, title, null, null, null, null, display);
        }

        var loc = TryParseLocationShareStatusChange(data);
        if (loc is not null)
        {
            var display = $"location_share status={loc.ShareStatus} dir={loc.ShareDirection}";
            return new ParsedBody("location_share", null, null, loc, null, null, null, display);
        }

        var action = TryParseMessageAction(data);
        if (action is not null)
        {
            var display = $"message_action type={action.MessageActionType} orig={action.OriginalMessageGuid}";
            return new ParsedBody("message_action", null, null, null, action, null, null, display);
        }

        var part = TryParseParticipantChange(data);
        if (part is not null)
        {
            var display = $"participant_change type={part.ParticipantChangeType} other={part.OtherHandle}";
            return new ParsedBody("participant_change", null, null, null, null, part, null, display);
        }

        var group = TryParseGroupAction(data);
        if (group is not null)
        {
            var display = $"group_action type={group.GroupActionType} other={group.OtherHandle}";
            return new ParsedBody("group_action", null, null, null, null, null, group, display);
        }

        if (msg is not null)
            return new ParsedBody("message", msg, null, null, null, null, null, msg.Text ?? msg.Subject);

        return new ParsedBody("unknown", null, null, null, null, null, null, null);
    }

    /// <summary>
    /// Campo stringa Manatee: protobuf length-delimited oppure UTF-8 grezzo.
    /// </summary>
    public static string? TryDecodeStringField(byte[]? data)
    {
        if (data is not { Length: > 0 })
            return null;

        if (NotesPlaintextDecoder.DecodeField("x", data).TextPreview is { Length: > 0 } preview)
            return preview.Trim();

        if (LooksLikeUtf8(data))
            return Encoding.UTF8.GetString(data).TrimEnd('\0').Trim();

        return null;
    }

    /// <summary>
    /// <c>time</c>/<c>flags</c>: tipicamente tag varint protobuf (field 3 = <c>0x18</c>).
    /// </summary>
    public static ulong? TryDecodeVarintField(byte[]? data)
    {
        if (data is not { Length: > 0 })
            return null;

        try
        {
            var r = new ProtobufReader(data);
            while (r.HasMore)
            {
                var (_, wt) = r.ReadTag();
                if (wt == 0)
                    return r.ReadVarint();
                r.SkipField(wt);
            }
        }
        catch (InvalidDataException)
        {
            // fall through
        }

        try
        {
            var r = new ProtobufReader(data);
            return r.ReadVarint();
        }
        catch
        {
            return null;
        }
    }

    /// <summary>
    /// Timestamp Messages CloudKit: nanosecondi da epoch Apple (2001-01-01).
    /// </summary>
    public static string? FormatAppleNanos(ulong? nanos)
    {
        if (nanos is null or 0)
            return null;
        try
        {
            var seconds = nanos.Value / 1_000_000_000d;
            return AppleEpoch.AddSeconds(seconds)
                .ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        }
        catch
        {
            return null;
        }
    }

    public static byte[]? MaybeGunzip(byte[]? data)
    {
        if (data is not { Length: > 0 })
            return data;
        if (data.Length >= 2 && data[0] == 0x1f && data[1] == 0x8b)
        {
            try
            {
                using var ms = new MemoryStream(data);
                using var gz = new GZipStream(ms, CompressionMode.Decompress);
                using var outMs = new MemoryStream();
                gz.CopyTo(outMs);
                return outMs.ToArray();
            }
            catch
            {
                return data;
            }
        }

        return data;
    }

    private static string ReadUtf8(ProtobufReader r) =>
        Encoding.UTF8.GetString(r.ReadLengthDelimited());

    private static bool LooksLikeUtf8(byte[] data)
    {
        if (data.Length == 0 || data.Length > 64_000)
            return false;
        var printable = 0;
        foreach (var b in data)
        {
            if (b is 9 or 10 or 13 || b is >= 32 and < 127 || b >= 128)
                printable++;
            else
                return false;
        }

        return printable >= data.Length * 0.85;
    }
}
