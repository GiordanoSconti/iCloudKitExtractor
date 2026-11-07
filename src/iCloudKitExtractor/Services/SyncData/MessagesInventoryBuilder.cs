using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.SyncData;

/// <summary>
/// Ricostruisce messaggi da <c>crypto/**/field_records.tsv</c> + plaintext PCS.
/// Associa i campi dello stesso record CloudKit (64-hex) e collega
/// <c>chatID</c> → chatManateeZone. Corpo da <c>msgProto*</c> (gzip+protobuf rustpush).
/// </summary>
public static class MessagesInventoryBuilder
{
    private static readonly Regex Hex64 = new(
        @"\b([0-9a-fA-F]{64})\b",
        RegexOptions.CultureInvariant | RegexOptions.Compiled);

    public sealed record InventorySummary(
        int Messages,
        int Chats,
        int WithText,
        string TsvPath,
        string JsonPath);

    private sealed record FieldHit(
        string Field,
        int Idx,
        string RecordName,
        int Offset,
        string PlainPath,
        string? Text,
        string SyncTag);

    private sealed class MsgAccum
    {
        public string RecordName = "";
        public string SyncTag = "";
        public string Kind = "message";
        public string? Guid;
        public string? ChatId;
        public string? Sender;
        public string? Service;
        public string? DcId;
        public ulong? TimeRaw;
        public ulong? Flags;
        public string? Text;
        public string? Subject;
        public string? Effect;
        public string? BalloonBundleId;
        public string? AssociatedGuid;
        public uint? AssociatedType;
        public uint? AssociatedRangeLocation;
        public uint? AssociatedRangeLength;
        public string? Reply;
        public string? GroupId;
        public string? Proto4Service;
        public string? AssociatedEmoji;
        public uint? ScheduleType;
        public uint? ScheduleState;
        public uint? ExpireState;
        public uint? CmmState;
        public string? DateReadUtc;
        public string? DateDeliveredUtc;
        public string? TimeUtc;
        public string? EventOtherHandle;
        public string? EventDetail;
        public bool HasAttributedBody;
        public bool HasPayloadData;
        public readonly HashSet<string> Fields = new(StringComparer.Ordinal);
    }

    public static InventorySummary Build(
        string containerDirectory,
        IProgress<string>? log = null)
    {
        Directory.CreateDirectory(containerDirectory);
        var cryptoRoot = Path.Combine(containerDirectory, "crypto");
        if (!Directory.Exists(cryptoRoot))
        {
            log?.Report("  Messages inventory skip: crypto/ assente");
            var emptyTsv = Path.Combine(containerDirectory, "messages_inventory.tsv");
            var emptyJson = Path.Combine(containerDirectory, "messages_inventory.json");
            File.WriteAllText(emptyTsv, "guid\tchat_id\tsender\tservice\ttime_utc\ttext\n");
            File.WriteAllText(emptyJson, "[]");
            return new InventorySummary(0, 0, 0, emptyTsv, emptyJson);
        }

        var syncPayloads = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var bin in Directory.GetFiles(containerDirectory, "record_sync_*.bin"))
        {
            var tag = Path.GetFileNameWithoutExtension(bin);
            try { syncPayloads[tag] = File.ReadAllBytes(bin); }
            catch { /* ignore */ }
        }

        var hits = LoadFieldHits(cryptoRoot, syncPayloads);
        log?.Report($"  Messages fields: {hits.Count} (rebind record_name da offset)");

        var messages = new Dictionary<string, MsgAccum>(StringComparer.OrdinalIgnoreCase);
        var chats = new Dictionary<string, MsgAccum>(StringComparer.OrdinalIgnoreCase);

        foreach (var hit in hits)
        {
            var isChat = hit.SyncTag.Contains("chatManatee", StringComparison.OrdinalIgnoreCase);
            var bag = isChat ? chats : messages;
            if (!bag.TryGetValue(hit.RecordName, out var acc))
            {
                acc = new MsgAccum { RecordName = hit.RecordName, SyncTag = hit.SyncTag };
                bag[hit.RecordName] = acc;
            }

            acc.Fields.Add(hit.Field);
            ApplyField(acc, hit);
        }

        var rows = new List<object>();
        var tsv = new StringBuilder();
        tsv.AppendLine(
            "record_name\tkind\tguid\tchat_id\tsender\tdc_id\tservice\ttime_utc\t" +
            "date_read_utc\tdate_delivered_utc\tflags\texpire_state\t" +
            "text\tsubject\teffect\tballoon\treply\tgroup_id\t" +
            "assoc_guid\tassoc_type\tassoc_emoji\tassoc_range\t" +
            "schedule_type\tschedule_state\tcmm_state\t" +
            "event_other\tevent_detail\thas_attr\thas_payload\t" +
            "fields\tsync_tag");

        var withText = 0;
        foreach (var m in messages.Values
                     .OrderBy(static x => x.TimeRaw ?? ulong.MaxValue)
                     .ThenBy(static x => x.Guid ?? x.RecordName, StringComparer.OrdinalIgnoreCase))
        {
            if (!string.IsNullOrWhiteSpace(m.Text))
                withText++;

            var assocRange = m.AssociatedRangeLocation is null && m.AssociatedRangeLength is null
                ? ""
                : $"{m.AssociatedRangeLocation ?? 0}:{m.AssociatedRangeLength ?? 0}";

            tsv.Append(Escape(m.RecordName)).Append('\t')
                .Append(Escape(m.Kind)).Append('\t')
                .Append(Escape(m.Guid)).Append('\t')
                .Append(Escape(m.ChatId)).Append('\t')
                .Append(Escape(m.Sender)).Append('\t')
                .Append(Escape(m.DcId)).Append('\t')
                .Append(Escape(m.Service ?? m.Proto4Service)).Append('\t')
                .Append(Escape(m.TimeUtc)).Append('\t')
                .Append(Escape(m.DateReadUtc)).Append('\t')
                .Append(Escape(m.DateDeliveredUtc)).Append('\t')
                .Append(m.Flags?.ToString(CultureInfo.InvariantCulture) ?? "").Append('\t')
                .Append(m.ExpireState?.ToString(CultureInfo.InvariantCulture) ?? "").Append('\t')
                .Append(Escape(m.Text)).Append('\t')
                .Append(Escape(m.Subject)).Append('\t')
                .Append(Escape(m.Effect)).Append('\t')
                .Append(Escape(m.BalloonBundleId)).Append('\t')
                .Append(Escape(m.Reply)).Append('\t')
                .Append(Escape(m.GroupId)).Append('\t')
                .Append(Escape(m.AssociatedGuid)).Append('\t')
                .Append(m.AssociatedType?.ToString(CultureInfo.InvariantCulture) ?? "").Append('\t')
                .Append(Escape(m.AssociatedEmoji)).Append('\t')
                .Append(Escape(assocRange)).Append('\t')
                .Append(m.ScheduleType?.ToString(CultureInfo.InvariantCulture) ?? "").Append('\t')
                .Append(m.ScheduleState?.ToString(CultureInfo.InvariantCulture) ?? "").Append('\t')
                .Append(m.CmmState?.ToString(CultureInfo.InvariantCulture) ?? "").Append('\t')
                .Append(Escape(m.EventOtherHandle)).Append('\t')
                .Append(Escape(m.EventDetail)).Append('\t')
                .Append(m.HasAttributedBody ? "1" : "0").Append('\t')
                .Append(m.HasPayloadData ? "1" : "0").Append('\t')
                .Append(Escape(string.Join(',', m.Fields.OrderBy(x => x)))).Append('\t')
                .Append(Escape(m.SyncTag))
                .AppendLine();

            rows.Add(new
            {
                m.RecordName,
                m.Kind,
                m.Guid,
                m.ChatId,
                m.Sender,
                m.DcId,
                service = m.Service ?? m.Proto4Service,
                m.TimeUtc,
                m.DateReadUtc,
                m.DateDeliveredUtc,
                m.Flags,
                m.ExpireState,
                m.Text,
                m.Subject,
                m.Effect,
                m.BalloonBundleId,
                m.Reply,
                m.GroupId,
                m.AssociatedGuid,
                m.AssociatedType,
                m.AssociatedEmoji,
                associatedRangeLocation = m.AssociatedRangeLocation,
                associatedRangeLength = m.AssociatedRangeLength,
                m.ScheduleType,
                m.ScheduleState,
                m.CmmState,
                m.EventOtherHandle,
                m.EventDetail,
                m.HasAttributedBody,
                m.HasPayloadData,
                fields = m.Fields.OrderBy(x => x).ToArray(),
                m.SyncTag,
            });
        }

        var tsvPath = Path.Combine(containerDirectory, "messages_inventory.tsv");
        var jsonPath = Path.Combine(containerDirectory, "messages_inventory.json");
        File.WriteAllText(tsvPath, tsv.ToString(), Encoding.UTF8);
        File.WriteAllText(
            jsonPath,
            JsonSerializer.Serialize(rows, new JsonSerializerOptions { WriteIndented = true }),
            Encoding.UTF8);

        var chatTsv = new StringBuilder();
        chatTsv.AppendLine("record_name\tguid\tchat_id\tservice\tis_recovered\tfields\tsync_tag");
        foreach (var c in chats.Values.OrderBy(x => x.Guid ?? x.RecordName, StringComparer.Ordinal))
        {
            chatTsv.Append(Escape(c.RecordName)).Append('\t')
                .Append(Escape(c.Guid)).Append('\t')
                .Append(Escape(c.ChatId)).Append('\t')
                .Append(Escape(c.Service)).Append('\t')
                .Append(Escape(c.EventDetail)).Append('\t')
                .Append(Escape(string.Join(',', c.Fields.OrderBy(x => x)))).Append('\t')
                .Append(Escape(c.SyncTag))
                .AppendLine();
        }

        File.WriteAllText(
            Path.Combine(containerDirectory, "chats_inventory.tsv"),
            chatTsv.ToString(),
            Encoding.UTF8);

        var kindCounts = messages.Values
            .GroupBy(m => m.Kind, StringComparer.Ordinal)
            .Select(g => $"{g.Key}={g.Count()}")
            .OrderBy(s => s, StringComparer.Ordinal);
        log?.Report(
            $"  Messages inventory: {messages.Count} msg ({withText} con testo), " +
            $"{chats.Count} chat [{string.Join(", ", kindCounts)}] → {Path.GetFileName(tsvPath)}");

        return new InventorySummary(messages.Count, chats.Count, withText, tsvPath, jsonPath);
    }

    private static void ApplyField(MsgAccum acc, FieldHit hit)
    {
        byte[]? bytes = null;
        try
        {
            if (File.Exists(hit.PlainPath))
                bytes = File.ReadAllBytes(hit.PlainPath);
        }
        catch
        {
            bytes = null;
        }

        switch (hit.Field)
        {
            case "guid":
                acc.Guid ??= MessageProtoParser.TryDecodeStringField(bytes) ?? hit.Text;
                if (hit.SyncTag.Contains("chatManatee", StringComparison.OrdinalIgnoreCase))
                    acc.ChatId ??= acc.Guid;
                break;
            case "chatID":
                acc.ChatId ??= MessageProtoParser.TryDecodeStringField(bytes) ?? hit.Text;
                break;
            case "sender":
                acc.Sender ??= MessageProtoParser.TryDecodeStringField(bytes) ?? hit.Text;
                break;
            case "svc":
                acc.Service ??= MessageProtoParser.TryDecodeStringField(bytes) ?? hit.Text;
                break;
            case "dcId":
                acc.DcId ??= MessageProtoParser.TryDecodeStringField(bytes) ?? hit.Text;
                break;
            case "time":
                acc.TimeRaw ??= MessageProtoParser.TryDecodeVarintField(bytes);
                acc.TimeUtc ??= MessageProtoParser.FormatAppleNanos(acc.TimeRaw);
                break;
            case "flags":
                acc.Flags ??= MessageProtoParser.TryDecodeVarintField(bytes);
                break;
            case "msgProto":
            {
                var body = MessageProtoParser.ParseBody(bytes);
                acc.Kind = body.Kind;
                if (body.Message is { } p)
                {
                    acc.Text ??= p.Text;
                    acc.Subject ??= p.Subject;
                    acc.Effect ??= p.Effect;
                    acc.BalloonBundleId ??= p.BalloonBundleId;
                    acc.AssociatedGuid ??= p.AssociatedMessageGuid;
                    acc.AssociatedType ??= p.AssociatedMessageType;
                    acc.AssociatedRangeLocation ??= p.AssociatedMessageRangeLocation;
                    acc.AssociatedRangeLength ??= p.AssociatedMessageRangeLength;
                    acc.ExpireState ??= p.ExpireState;
                    acc.DateReadUtc ??= p.DateReadUtc;
                    acc.DateDeliveredUtc ??= p.DateDeliveredUtc;
                    acc.HasAttributedBody |= p.HasAttributedBody;
                    acc.HasPayloadData |= p.HasPayloadData;
                }

                if (body.GroupTitle is { } gt)
                {
                    acc.Text ??= gt.GroupTitle;
                    acc.EventOtherHandle ??= gt.OtherHandle;
                    acc.EventDetail ??= $"group_title version={gt.Version}";
                }

                if (body.LocationShare is { } loc)
                {
                    acc.Text ??= body.DisplayText;
                    acc.EventOtherHandle ??= loc.OtherHandle;
                    acc.EventDetail ??= $"status={loc.ShareStatus};dir={loc.ShareDirection}";
                }

                if (body.MessageAction is { } ma)
                {
                    acc.Text ??= body.DisplayText;
                    acc.EventOtherHandle ??= ma.OtherHandle;
                    acc.AssociatedGuid ??= ma.OriginalMessageGuid;
                    acc.EventDetail ??= $"action_type={ma.MessageActionType}";
                }

                if (body.ParticipantChange is { } pc)
                {
                    acc.Text ??= body.DisplayText;
                    acc.EventOtherHandle ??= pc.OtherHandle;
                    acc.EventDetail ??= $"participant_type={pc.ParticipantChangeType}";
                }

                if (body.GroupAction is { } ga)
                {
                    acc.Text ??= body.DisplayText;
                    acc.EventOtherHandle ??= ga.OtherHandle;
                    acc.EventDetail ??= $"group_action_type={ga.GroupActionType}";
                }

                if (string.IsNullOrWhiteSpace(acc.Text) && !string.IsNullOrWhiteSpace(body.DisplayText))
                    acc.Text = body.DisplayText;
                break;
            }
            case "msgProto2":
            {
                var p2 = MessageProtoParser.TryParseMessageProto2(bytes);
                if (p2 is not null)
                    acc.Reply ??= p2.Reply;
                break;
            }
            case "msgProto3":
            {
                var p3 = MessageProtoParser.TryParseMessageProto3(bytes);
                if (p3 is not null)
                    acc.CmmState ??= p3.CmmState;
                break;
            }
            case "msgProto4":
            {
                var p4 = MessageProtoParser.TryParseMessageProto4(bytes);
                if (p4 is null)
                    break;
                acc.GroupId ??= p4.GroupId;
                acc.Proto4Service ??= p4.Service;
                acc.AssociatedEmoji ??= p4.AssociatedMessageEmoji;
                acc.ScheduleType ??= p4.ScheduleType;
                acc.ScheduleState ??= p4.ScheduleState;
                break;
            }
            default:
            {
                // Chat zone: eventuali blob arch/prop con ChatProto minimale.
                if (hit.SyncTag.Contains("chatManatee", StringComparison.OrdinalIgnoreCase)
                    && bytes is { Length: > 0 })
                {
                    var chat = MessageProtoParser.TryParseChatProto(bytes);
                    if (chat?.IsRecovered is not null)
                        acc.EventDetail ??= chat.IsRecovered.Value.ToString(CultureInfo.InvariantCulture);
                }

                break;
            }
        }
    }

    private static List<FieldHit> LoadFieldHits(
        string cryptoRoot,
        IReadOnlyDictionary<string, byte[]> syncPayloads)
    {
        var hits = new List<FieldHit>();
        foreach (var tsv in Directory.GetFiles(cryptoRoot, "field_records.tsv", SearchOption.AllDirectories))
        {
            var cryptoDir = Path.GetDirectoryName(tsv)!;
            var syncTag = Path.GetFileName(cryptoDir);
            syncPayloads.TryGetValue(syncTag, out var payload);

            string[] lines;
            try { lines = File.ReadAllLines(tsv); }
            catch { continue; }

            for (var i = 1; i < lines.Length; i++)
            {
                var parts = lines[i].Split('\t');
                if (parts.Length < 5)
                    continue;
                var field = parts[0];
                if (!int.TryParse(parts[1], NumberStyles.Integer, CultureInfo.InvariantCulture, out var idx))
                    continue;
                var record = parts[2];
                if (!int.TryParse(parts[3], NumberStyles.Integer, CultureInfo.InvariantCulture, out var offset))
                    continue;
                var plainPath = parts[4];
                var text = parts.Length > 5 ? parts[5] : null;

                if (payload is { Length: > 0 })
                {
                    var rebound = NearestHex64(payload, offset);
                    if (!string.IsNullOrWhiteSpace(rebound))
                        record = rebound;
                }

                if (string.IsNullOrWhiteSpace(record))
                    continue;

                hits.Add(new FieldHit(field, idx, record, offset, plainPath, text, syncTag));
            }
        }

        return hits;
    }

    private static string? NearestHex64(byte[] payload, int fieldOffset, int lookback = 12_000)
    {
        var start = Math.Max(0, fieldOffset - lookback);
        var len = Math.Min(payload.Length - start, fieldOffset - start + 64);
        if (len < 64)
            return null;

        var text = Encoding.ASCII.GetString(payload, start, len);
        string? best = null;
        var bestDist = int.MaxValue;
        foreach (Match m in Hex64.Matches(text))
        {
            var abs = start + m.Index;
            var dist = fieldOffset - abs;
            if (dist < 0 || dist >= bestDist)
                continue;
            if (m.Index > 0 && IsHex(text[m.Index - 1]))
                continue;
            if (m.Index + 64 < text.Length && IsHex(text[m.Index + 64]))
                continue;
            bestDist = dist;
            best = m.Groups[1].Value.ToLowerInvariant();
        }

        return best;
    }

    private static bool IsHex(char c) =>
        c is (>= '0' and <= '9') or (>= 'a' and <= 'f') or (>= 'A' and <= 'F');

    private static string Escape(string? value)
    {
        if (string.IsNullOrEmpty(value))
            return "";
        return value.Replace('\t', ' ').Replace('\r', ' ').Replace('\n', ' ');
    }
}
