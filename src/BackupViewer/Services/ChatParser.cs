using System.IO;
using BackupViewer.Models;
using Microsoft.Data.Sqlite;

namespace BackupViewer.Services;

public static class ChatParser
{
    public static ChatSource? ParseWhatsApp(string dbPath, string sourceId = "whatsapp")
    {
        using var con = SqliteOpen.OpenReadonly(dbPath);
        if (!SqliteOpen.TableExists(con, "ZWACHATSESSION") || !SqliteOpen.TableExists(con, "ZWAMESSAGE"))
            return null;

        var counts = new Dictionary<long, int>();
        using (var cmd = con.CreateCommand())
        {
            cmd.CommandText =
                """
                SELECT ZCHATSESSION, COUNT(*)
                FROM ZWAMESSAGE
                WHERE ZCHATSESSION IS NOT NULL
                GROUP BY ZCHATSESSION;
                """;
            using var r = cmd.ExecuteReader();
            while (r.Read())
                counts[r.GetInt64(0)] = r.GetInt32(1);
        }

        var conversations = new List<ChatConversation>();
        using (var cmd = con.CreateCommand())
        {
            cmd.CommandText =
                """
                SELECT Z_PK, ZPARTNERNAME, ZCONTACTJID, ZSESSIONTYPE, ZLASTMESSAGETEXT,
                       ZLASTMESSAGEDATE, ZARCHIVED, ZHIDDEN, ZMESSAGECOUNTER
                FROM ZWACHATSESSION
                WHERE (ZHIDDEN IS NULL OR ZHIDDEN = 0)
                ORDER BY ZLASTMESSAGEDATE DESC;
                """;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var pk = r.GetInt64(0);
                var partner = r.IsDBNull(1) ? null : r.GetString(1);
                var jid = r.IsDBNull(2) ? null : r.GetString(2);
                var sessionType = r.IsDBNull(3) ? 0 : r.GetInt32(3);
                var lastText = r.IsDBNull(4) ? null : SanitizePreview(r.GetString(4));
                var lastDate = AppleTime.FromCocoa(GetDouble(r, 5));
                var archived = !r.IsDBNull(6) && r.GetInt32(6) != 0;
                var isStatus = sessionType == 3;
                var isGroup = sessionType == 1 || (jid?.Contains("@g.us", StringComparison.Ordinal) ?? false);
                var title = string.IsNullOrWhiteSpace(partner)
                    ? FriendlyJid(jid) ?? $"Chat {pk}"
                    : partner.Trim().TrimStart('\u200e', '\u200f');

                counts.TryGetValue(pk, out var msgCount);
                if (msgCount == 0 && !r.IsDBNull(8))
                    msgCount = r.GetInt32(8);

                conversations.Add(new ChatConversation
                {
                    Id = pk.ToString(),
                    SourceId = sourceId,
                    Title = title,
                    Subtitle = jid,
                    LastPreview = lastText,
                    LastDate = lastDate,
                    MessageCount = msgCount,
                    IsGroup = isGroup,
                    IsStatus = isStatus,
                    IsArchived = archived,
                });
            }
        }

        return new ChatSource
        {
            Id = sourceId,
            Title = "WhatsApp",
            App = ChatAppKind.WhatsApp,
            Conversations = conversations
                .OrderBy(static c => c.Title, StringComparer.CurrentCultureIgnoreCase)
                .ToList(),
        };
    }

    public static IReadOnlyList<ChatMessage> LoadWhatsAppMessages(
        string dbPath,
        string conversationId,
        WhatsAppMediaIndex? mediaIndex = null)
    {
        if (!long.TryParse(conversationId, out var chatPk))
            return [];

        using var con = SqliteOpen.OpenReadonly(dbPath);

        string? partnerName = null;
        string? partnerJid = null;
        var sessionType = 0;
        using (var cmd = con.CreateCommand())
        {
            cmd.CommandText =
                """
                SELECT ZSESSIONTYPE, ZPARTNERNAME, ZCONTACTJID
                FROM ZWACHATSESSION WHERE Z_PK=$id LIMIT 1;
                """;
            cmd.Parameters.AddWithValue("$id", chatPk);
            using var r = cmd.ExecuteReader();
            if (r.Read())
            {
                sessionType = r.IsDBNull(0) ? 0 : r.GetInt32(0);
                partnerName = r.IsDBNull(1) ? null : CleanName(r.GetString(1));
                partnerJid = r.IsDBNull(2) ? null : r.GetString(2);
            }
        }

        var isStatusSession = sessionType == 3;
        var isGroup = sessionType == 1
                      || (partnerJid?.Contains("@g.us", StringComparison.Ordinal) ?? false);

        // JID → display name from all chat sessions (best nickname source for LID)
        var jidNames = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        using (var cmd = con.CreateCommand())
        {
            cmd.CommandText =
                """
                SELECT ZCONTACTJID, ZPARTNERNAME
                FROM ZWACHATSESSION
                WHERE ZCONTACTJID IS NOT NULL AND ZPARTNERNAME IS NOT NULL AND TRIM(ZPARTNERNAME) <> '';
                """;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var jid = r.GetString(0);
                var name = CleanName(r.GetString(1));
                if (name is null)
                    continue;
                jidNames[jid] = name;
                var bare = FriendlyJid(jid);
                if (!string.IsNullOrWhiteSpace(bare))
                    jidNames.TryAdd(bare, name);
            }
        }

        // groupMemberPk → (jid, name)
        var members = new Dictionary<long, (string? Jid, string? Name)>();
        if (SqliteOpen.TableExists(con, "ZWAGROUPMEMBER"))
        {
            using var cmd = con.CreateCommand();
            cmd.CommandText =
                """
                SELECT Z_PK, ZMEMBERJID, ZCONTACTNAME, ZFIRSTNAME
                FROM ZWAGROUPMEMBER;
                """;
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var pk = r.GetInt64(0);
                var jid = r.IsDBNull(1) ? null : r.GetString(1);
                var contact = r.IsDBNull(2) ? null : CleanName(r.GetString(2));
                var first = r.IsDBNull(3) ? null : CleanName(r.GetString(3));
                string? name = contact ?? first;
                if (name is null && jid is not null)
                {
                    if (jidNames.TryGetValue(jid, out var mapped))
                        name = mapped;
                    else if (FriendlyJid(jid) is { } bare && jidNames.TryGetValue(bare, out mapped))
                        name = mapped;
                }

                members[pk] = (jid, name);
            }
        }

        var hasGroupEvent = SqliteOpen.ColumnExists(con, "ZWAMESSAGE", "ZGROUPEVENTTYPE");
        var list = new List<ChatMessage>();
        using (var cmd = con.CreateCommand())
        {
            var hasMediaTable = SqliteOpen.TableExists(con, "ZWAMEDIAITEM");
            var groupEventCol = hasGroupEvent ? "m.ZGROUPEVENTTYPE" : "NULL";
            cmd.CommandText = hasMediaTable
                ? $"""
                  SELECT m.Z_PK, m.ZISFROMME, m.ZMESSAGETYPE, m.ZMESSAGESTATUS, m.ZTEXT,
                         m.ZMESSAGEDATE, m.ZFROMJID, m.ZPUSHNAME, m.ZGROUPMEMBER,
                         mi.ZMEDIALOCALPATH, mi.ZTITLE, mi.ZFILESIZE, mi.ZMOVIEDURATION,
                         mi.ZXMPPTHUMBPATH, {groupEventCol}
                  FROM ZWAMESSAGE m
                  LEFT JOIN ZWAMEDIAITEM mi ON mi.Z_PK = m.ZMEDIAITEM
                  WHERE m.ZCHATSESSION = $id
                  ORDER BY COALESCE(m.ZSORT, m.Z_PK), m.Z_PK;
                  """
                : $"""
                  SELECT Z_PK, ZISFROMME, ZMESSAGETYPE, ZMESSAGESTATUS, ZTEXT,
                         ZMESSAGEDATE, ZFROMJID, ZPUSHNAME, ZGROUPMEMBER,
                         NULL, NULL, NULL, NULL, NULL,
                         {(hasGroupEvent ? "ZGROUPEVENTTYPE" : "NULL")}
                  FROM ZWAMESSAGE
                  WHERE ZCHATSESSION = $id
                  ORDER BY COALESCE(ZSORT, Z_PK), Z_PK;
                  """;
            cmd.Parameters.AddWithValue("$id", chatPk);
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var type = r.IsDBNull(2) ? 0 : r.GetInt32(2);
                var fromMe = !r.IsDBNull(1) && r.GetInt32(1) != 0;
                var text = r.IsDBNull(4) ? null : r.GetString(4);
                var status = r.IsDBNull(3) ? 0 : r.GetInt32(3);
                var groupEvent = r.IsDBNull(14) ? 0 : Convert.ToInt32(r.GetValue(14));
                var kind = ClassifyWa(type, fromMe, text, isStatusSession);
                var mediaKind = MapMediaKind(type);
                var mediaLocal = r.IsDBNull(9) ? null : r.GetString(9);
                var caption = r.IsDBNull(10) ? null : NullIfEmpty(r.GetString(10));
                var fileSize = r.IsDBNull(11) ? (long?)null : Convert.ToInt64(r.GetValue(11));
                var duration = r.IsDBNull(12) ? (int?)null : Convert.ToInt32(r.GetValue(12));
                if (duration is 0)
                    duration = null;

                var fileName = string.IsNullOrWhiteSpace(mediaLocal)
                    ? null
                    : Path.GetFileName(mediaLocal.Replace('\\', '/'));
                BackupFileEntry? mediaFile = null;
                if (mediaIndex is not null && !string.IsNullOrWhiteSpace(mediaLocal))
                    mediaFile = mediaIndex.Resolve(mediaLocal);
                // Prefer full media over thumb if missing
                if (mediaFile is null && mediaIndex is not null && !r.IsDBNull(13))
                    mediaFile = mediaIndex.Resolve(r.GetString(13));

                var mediaMissing = mediaKind != ChatMediaKind.None
                                   && !string.IsNullOrWhiteSpace(mediaLocal)
                                   && mediaFile is null;

                string? senderName = null;
                string? senderId = null;
                if (fromMe)
                {
                    senderName = "Tu";
                    senderId = ExtractJidFromPushName(r.IsDBNull(7) ? null : r.GetString(7));
                }
                else if (isGroup)
                {
                    if (!r.IsDBNull(8) && members.TryGetValue(r.GetInt64(8), out var mem))
                    {
                        senderId = mem.Jid;
                        senderName = mem.Name ?? FriendlyJid(mem.Jid);
                    }

                    if (senderId is null && !r.IsDBNull(6))
                    {
                        var from = r.GetString(6);
                        // In gruppi moderni ZFROMJID è il gruppo; member jid è preferibile
                        if (!from.Contains("@g.us", StringComparison.Ordinal))
                            senderId = from;
                    }

                    if (senderName is null && senderId is not null
                        && jidNames.TryGetValue(senderId, out var mapped))
                        senderName = mapped;

                    senderName ??= FriendlyJid(senderId) ?? "Sconosciuto";
                }
                else
                {
                    senderName = partnerName
                                 ?? (!r.IsDBNull(6) && jidNames.TryGetValue(r.GetString(6), out var n)
                                     ? n
                                     : null)
                                 ?? FriendlyJid(r.IsDBNull(6) ? partnerJid : r.GetString(6))
                                 ?? "Sconosciuto";
                    senderId = r.IsDBNull(6) ? partnerJid : r.GetString(6);
                    if (string.IsNullOrWhiteSpace(senderId))
                        senderId = partnerJid;
                }

                var body = BuildBody(kind, text, caption, mediaKind, fileName, type, fromMe, groupEvent);

                list.Add(new ChatMessage
                {
                    Id = r.GetInt64(0),
                    ConversationId = conversationId,
                    Kind = kind,
                    Body = body,
                    MediaHint = MediaHint(type, groupEvent, fromMe),
                    SentAt = AppleTime.FromCocoa(GetDouble(r, 5)),
                    Sender = fromMe ? null : senderName,
                    SenderId = fromMe ? null : FriendlyJid(senderId) ?? senderId,
                    StatusLabel = WaStatusLabel(status, fromMe),
                    MediaKind = mediaKind,
                    FileName = fileName,
                    MediaRelativePath = mediaFile?.RelativePath ?? mediaLocal,
                    MediaShardPath = mediaFile?.AbsolutePath,
                    Caption = caption,
                    DurationSeconds = duration,
                    FileSizeBytes = fileSize,
                    MediaMissing = mediaMissing,
                });
            }
        }

        return list;
    }

    public static ChatSource? ParseSms(string dbPath, string sourceId = "messages")
    {
        using var con = SqliteOpen.OpenReadonly(dbPath);
        if (!SqliteOpen.TableExists(con, "chat") || !SqliteOpen.TableExists(con, "message"))
            return null;

        var handleNames = new Dictionary<long, string>();
        if (SqliteOpen.TableExists(con, "handle"))
        {
            using var cmd = con.CreateCommand();
            cmd.CommandText = "SELECT ROWID, id FROM handle;";
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                if (!r.IsDBNull(1))
                    handleNames[r.GetInt64(0)] = r.GetString(1);
            }
        }

        var conversations = new List<ChatConversation>();
        using (var cmd = con.CreateCommand())
        {
            cmd.CommandText =
                """
                SELECT c.ROWID,
                       c.chat_identifier,
                       c.display_name,
                       c.style,
                       (SELECT COUNT(*) FROM chat_message_join j WHERE j.chat_id = c.ROWID),
                       (SELECT m.text FROM message m
                          JOIN chat_message_join j ON j.message_id = m.ROWID
                         WHERE j.chat_id = c.ROWID
                         ORDER BY m.date DESC LIMIT 1),
                       (SELECT m.date FROM message m
                          JOIN chat_message_join j ON j.message_id = m.ROWID
                         WHERE j.chat_id = c.ROWID
                         ORDER BY m.date DESC LIMIT 1)
                FROM chat c
                ORDER BY 7 DESC;
                """;
            try
            {
                using var r = cmd.ExecuteReader();
                while (r.Read())
                {
                    var id = r.GetInt64(0);
                    var identifier = r.IsDBNull(1) ? null : r.GetString(1);
                    var display = r.IsDBNull(2) ? null : r.GetString(2);
                    var style = r.IsDBNull(3) ? 0 : r.GetInt32(3);
                    var count = r.IsDBNull(4) ? 0 : r.GetInt32(4);
                    var preview = r.IsDBNull(5) ? null : SanitizePreview(r.GetString(5));
                    var lastDate = FromSmsDate(GetLong(r, 6));
                    var title = !string.IsNullOrWhiteSpace(display)
                        ? display.Trim()
                        : identifier ?? $"Chat {id}";
                    conversations.Add(new ChatConversation
                    {
                        Id = id.ToString(),
                        SourceId = sourceId,
                        Title = title,
                        Subtitle = identifier,
                        LastPreview = preview,
                        LastDate = lastDate,
                        MessageCount = count,
                        IsGroup = style == 43 || style == 45,
                    });
                }
            }
            catch
            {
                return null;
            }
        }

        _ = handleNames;

        return new ChatSource
        {
            Id = sourceId,
            Title = "Messaggi",
            App = ChatAppKind.Messages,
            Conversations = conversations
                .OrderBy(static c => c.Title, StringComparer.CurrentCultureIgnoreCase)
                .ToList(),
        };
    }

    public static IReadOnlyList<ChatMessage> LoadSmsMessages(string dbPath, string conversationId)
    {
        if (!long.TryParse(conversationId, out var chatId))
            return [];

        using var con = SqliteOpen.OpenReadonly(dbPath);
        var list = new List<ChatMessage>();
        using var cmd = con.CreateCommand();
        cmd.CommandText =
            """
            SELECT m.ROWID, m.is_from_me, m.text, m.date, m.service,
                   m.is_system_message, m.handle_id
            FROM message m
            JOIN chat_message_join j ON j.message_id = m.ROWID
            WHERE j.chat_id = $id
            ORDER BY m.date, m.ROWID;
            """;
        cmd.Parameters.AddWithValue("$id", chatId);
        try
        {
            using var r = cmd.ExecuteReader();
            while (r.Read())
            {
                var fromMe = !r.IsDBNull(1) && Convert.ToInt32(r.GetValue(1)) != 0;
                var text = r.IsDBNull(2) ? null : r.GetString(2);
                var isSystem = !r.IsDBNull(5) && Convert.ToInt32(r.GetValue(5)) != 0;
                var kind = isSystem
                    ? ChatMessageKind.System
                    : IsDeletedText(text)
                        ? ChatMessageKind.Deleted
                        : fromMe ? ChatMessageKind.Sent : ChatMessageKind.Received;

                list.Add(new ChatMessage
                {
                    Id = r.GetInt64(0),
                    ConversationId = conversationId,
                    Kind = kind,
                    Body = string.IsNullOrWhiteSpace(text)
                        ? (kind == ChatMessageKind.Deleted ? "Messaggio eliminato" : "(allegato / vuoto)")
                        : text.Trim(),
                    SentAt = FromSmsDate(GetLong(r, 3)),
                    StatusLabel = r.IsDBNull(4) ? "" : r.GetString(4),
                });
            }
        }
        catch
        {
            return [];
        }

        return list;
    }

    private static ChatMessageKind ClassifyWa(int type, bool fromMe, string? text, bool statusSession)
    {
        if (statusSession)
            return ChatMessageKind.Status;
        // 14 = revoked/deleted; 15 = sticker (not deleted)
        if (type == 14 || IsDeletedText(text))
            return ChatMessageKind.Deleted;
        // 10 = missed call notification (centered system-style)
        if (type is 6 or 10 or 11)
            return ChatMessageKind.System;
        // 59 = call event in-thread (outgoing/incoming bubbles)
        return fromMe ? ChatMessageKind.Sent : ChatMessageKind.Received;
    }

    private static bool IsDeletedText(string? text) =>
        !string.IsNullOrWhiteSpace(text)
        && (text.Contains("This message was deleted", StringComparison.OrdinalIgnoreCase)
            || text.Contains("Messaggio eliminato", StringComparison.OrdinalIgnoreCase)
            || text.Contains("hai eliminato", StringComparison.OrdinalIgnoreCase)
            || text.Contains("ha eliminato", StringComparison.OrdinalIgnoreCase));

    private static bool IsWaCallType(int type) => type is 10 or 59;

    /// <summary>
    /// Heuristic video flag for call rows. Type 10 often pairs ge 56/58 with video;
    /// type 59 uses ge 5 for incoming and 0 for outgoing (voice in observed samples).
    /// </summary>
    private static bool IsWaVideoCall(int type, int groupEventType) =>
        type == 10 && groupEventType is 38 or 56 or 58;

    private static string? MediaHint(int type, int groupEventType, bool fromMe) => type switch
    {
        1 => "Immagine",
        2 => "Video",
        3 => "Audio",
        4 => "Contatto",
        5 => "Posizione",
        7 => "Link",
        8 or 9 => "Documento",
        10 => IsWaVideoCall(type, groupEventType) ? "Chiamata video persa" : "Chiamata vocale persa",
        13 => "GIF",
        15 => "Sticker",
        59 => fromMe
            ? (IsWaVideoCall(type, groupEventType) ? "Chiamata video effettuata" : "Chiamata vocale effettuata")
            : (IsWaVideoCall(type, groupEventType) ? "Chiamata video in entrata" : "Chiamata vocale in entrata"),
        _ => null,
    };

    private static ChatMediaKind MapMediaKind(int type) => type switch
    {
        1 => ChatMediaKind.Image,
        2 => ChatMediaKind.Video,
        3 => ChatMediaKind.Audio,
        8 or 9 => ChatMediaKind.Document,
        13 => ChatMediaKind.Image,
        15 => ChatMediaKind.Other,
        _ => ChatMediaKind.None,
    };

    private static string BuildBody(
        ChatMessageKind kind,
        string? text,
        string? caption,
        ChatMediaKind mediaKind,
        string? fileName,
        int type,
        bool fromMe,
        int groupEventType)
    {
        if (kind == ChatMessageKind.Deleted)
            return "Messaggio eliminato";

        if (IsWaCallType(type))
            return FormatWaCallBody(type, fromMe, groupEventType);

        if (!string.IsNullOrWhiteSpace(text))
            return text.Trim();
        if (!string.IsNullOrWhiteSpace(caption))
            return caption.Trim();
        if (type == 15)
            return "[Sticker]";
        if (type == 4)
            return "[Contatto]";
        if (type == 5)
            return "[Posizione]";
        if (mediaKind != ChatMediaKind.None)
        {
            var label = mediaKind switch
            {
                ChatMediaKind.Image => type == 13 ? "GIF" : "Immagine",
                ChatMediaKind.Video => "Video",
                ChatMediaKind.Audio => "Audio",
                ChatMediaKind.Document => "Documento",
                _ => "Media",
            };
            return string.IsNullOrWhiteSpace(fileName) ? $"[{label}]" : $"[{label}] {fileName}";
        }

        if (kind == ChatMessageKind.System)
            return FormatWaSystemBody(type, groupEventType, text);
        if (type is 28 or 66 or 54 or 38 or 46)
            return $"[Evento WhatsApp · tipo {type}]";
        return "(vuoto)";
    }

    private static string FormatWaCallBody(int type, bool fromMe, int groupEventType)
    {
        var video = IsWaVideoCall(type, groupEventType);
        var channel = video ? "video" : "vocale";
        if (type == 10)
            return $"Chiamata {channel} persa";
        // type 59
        if (fromMe)
            return $"Chiamata {channel} effettuata";
        // Incoming call event in-thread (ringing / unanswered log when type 10 absent)
        return $"Chiamata {channel} in entrata";
    }

    private static string FormatWaSystemBody(int type, int groupEventType, string? text)
    {
        if (!string.IsNullOrWhiteSpace(text))
            return text.Trim();
        if (type == 10)
            return FormatWaCallBody(10, fromMe: false, groupEventType);
        if (type == 6)
            return groupEventType switch
            {
                1 => "Partecipante aggiunto al gruppo",
                2 => "Partecipante rimosso dal gruppo",
                3 => "Hai lasciato il gruppo",
                4 => "Nome del gruppo aggiornato",
                5 => "Icona del gruppo aggiornata",
                6 => "Admin del gruppo aggiornato",
                _ => $"[Evento di gruppo · {groupEventType}]",
            };
        return $"[Evento di sistema · tipo {type}]";
    }

    private static string? CleanName(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var t = raw.Trim().TrimStart('\u200e', '\u200f');
        // Skip opaque protobuf/base64 push blobs mistakenly stored as names
        if (t.Length >= 20 && t.All(static c => char.IsLetterOrDigit(c) || c is '+' or '/' or '='))
            return null;
        return t;
    }

    private static string? ExtractJidFromPushName(string? push)
    {
        if (string.IsNullOrWhiteSpace(push))
            return null;
        try
        {
            // Often base64 protobuf containing ASCII "…@lid" / "…@s.whatsapp.net"
            byte[] bytes;
            try { bytes = Convert.FromBase64String(push); }
            catch { bytes = System.Text.Encoding.UTF8.GetBytes(push); }

            var ascii = System.Text.Encoding.ASCII.GetString(bytes);
            var match = System.Text.RegularExpressions.Regex.Match(
                ascii,
                @"[0-9A-Za-z._\-]+@(?:lid|s\.whatsapp\.net|g\.us)");
            return match.Success ? match.Value : null;
        }
        catch
        {
            return null;
        }
    }

    private static string? NullIfEmpty(string? s) =>
        string.IsNullOrWhiteSpace(s) ? null : s.Trim();

    private static string WaStatusLabel(int status, bool fromMe)
    {
        if (!fromMe)
            return status switch
        {
            8 or 13 => "Letto",
            _ => "Ricevuto",
        };
        return status switch
        {
            0 or 1 => "In coda",
            4 or 5 => "Consegnato",
            6 or 8 or 13 => "Letto",
            _ => $"Stato {status}",
        };
    }

    private static string? FriendlyJid(string? jid)
    {
        if (string.IsNullOrWhiteSpace(jid))
            return null;
        var at = jid.IndexOf('@');
        return at > 0 ? jid[..at] : jid;
    }

    private static string? SanitizePreview(string? raw)
    {
        if (string.IsNullOrWhiteSpace(raw))
            return null;
        var t = raw.Trim();
        // Skip opaque base64-ish blobs used as placeholders
        if (t.Length > 80 && t.All(static c => char.IsLetterOrDigit(c) || c is '+' or '/' or '=' or '\n'))
            return null;
        if (t.Length > 140)
            t = t[..140] + "…";
        return t.Replace('\n', ' ');
    }

    private static DateTimeOffset? FromSmsDate(long? raw)
    {
        if (raw is null or 0)
            return null;
        // Modern iOS: nanoseconds since 2001
        if (raw > 10_000_000_000_000)
            return AppleTime.FromCocoa(raw.Value / 1_000_000_000d);
        if (raw > 10_000_000_000)
            return AppleTime.FromCocoa(raw.Value / 1_000_000d);
        return AppleTime.FromCocoa((double)raw.Value);
    }

    private static double? GetDouble(SqliteDataReader r, int i)
    {
        if (r.IsDBNull(i))
            return null;
        return Convert.ToDouble(r.GetValue(i), System.Globalization.CultureInfo.InvariantCulture);
    }

    private static long? GetLong(SqliteDataReader r, int i)
    {
        if (r.IsDBNull(i))
            return null;
        return Convert.ToInt64(r.GetValue(i));
    }
}
