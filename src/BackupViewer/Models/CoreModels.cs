namespace BackupViewer.Models;

public enum ChatAppKind
{
    WhatsApp,
    Messages,
    Other,
}

public enum ChatMessageKind
{
    Sent,
    Received,
    System,
    Status,
    Deleted,
}

public enum CallDirection
{
    Incoming,
    Outgoing,
    Unknown,
}

public enum CallOutcome
{
    Answered,
    Missed,
    Rejected,
    Cancelled,
    Other,
}

public sealed class ContactRecord
{
    public long Id { get; init; }
    public string DisplayName { get; init; } = "";
    public string? Organization { get; init; }
    public string? JobTitle { get; init; }
    public string? Note { get; init; }
    public DateTimeOffset? Birthday { get; init; }
    public DateTimeOffset? Modified { get; init; }
    public IReadOnlyList<ContactField> Phones { get; init; } = [];
    public IReadOnlyList<ContactField> Emails { get; init; } = [];
    public IReadOnlyList<ContactField> Other { get; init; } = [];

    public string PhonesSummary =>
        Phones.Count == 0 ? "" : string.Join(" · ", Phones.Select(static p => p.Value));

    public string EmailsSummary =>
        Emails.Count == 0 ? "" : string.Join(" · ", Emails.Select(static p => p.Value));
}

public sealed class ContactField
{
    public required string Label { get; init; }
    public required string Value { get; init; }
}

public sealed class CalendarInfo
{
    public long Id { get; init; }
    public string Title { get; init; } = "";
    public string? ColorHex { get; init; }
    public int EventCount { get; set; }
}

public sealed class CalendarEventItem
{
    public long Id { get; init; }
    public long CalendarId { get; init; }
    public string CalendarTitle { get; init; } = "";
    public string? ColorHex { get; init; }
    public string Summary { get; init; } = "";
    public string? Description { get; init; }
    public string? Location { get; init; }
    public string? Url { get; init; }
    public DateTimeOffset? Start { get; init; }
    public DateTimeOffset? End { get; init; }
    public bool AllDay { get; init; }
    public bool IsTask { get; init; }

    public string WhenLabel
    {
        get
        {
            if (Start is null)
                return "—";
            if (AllDay)
                return AppleTimeFmt(Start, false);
            var s = AppleTimeFmt(Start, true);
            if (End is null)
                return s;
            return s + " – " + End.Value.ToLocalTime().ToString("HH:mm");
        }
    }

    private static string AppleTimeFmt(DateTimeOffset? dt, bool withTime) =>
        Services.AppleTime.Format(dt, withTime);
}

public sealed class ChatSource
{
    public required string Id { get; init; }
    public required string Title { get; init; }
    public ChatAppKind App { get; init; }
    public IReadOnlyList<ChatConversation> Conversations { get; init; } = [];
}

public sealed class ChatConversation
{
    public required string Id { get; init; }
    public required string SourceId { get; init; }
    public required string Title { get; init; }
    public string? Subtitle { get; init; }
    public string? LastPreview { get; init; }
    public DateTimeOffset? LastDate { get; init; }
    public int MessageCount { get; init; }
    public bool IsGroup { get; init; }
    public bool IsStatus { get; init; }
    public bool IsArchived { get; init; }
}

public enum ChatMediaKind
{
    None,
    Image,
    Video,
    Audio,
    Document,
    Other,
}

public sealed class ChatMessage
{
    public long Id { get; init; }
    public required string ConversationId { get; init; }
    public ChatMessageKind Kind { get; init; }
    public string Body { get; init; } = "";
    public string? MediaHint { get; init; }
    public DateTimeOffset? SentAt { get; init; }
    public string? Sender { get; init; }
    public string? SenderId { get; init; }
    public string StatusLabel { get; init; } = "";

    public ChatMediaKind MediaKind { get; init; }
    public string? FileName { get; init; }
    public string? MediaRelativePath { get; init; }
    public string? MediaShardPath { get; init; }
    public string? Caption { get; init; }
    public int? DurationSeconds { get; init; }
    public long? FileSizeBytes { get; init; }
    public bool MediaMissing { get; init; }

    public string SenderLabel
    {
        get
        {
            var name = Sender?.Trim();
            var id = SenderId?.Trim();
            if (!string.IsNullOrWhiteSpace(name) && !string.IsNullOrWhiteSpace(id)
                && !string.Equals(name, id, StringComparison.OrdinalIgnoreCase))
                return $"{name} · {id}";
            if (!string.IsNullOrWhiteSpace(name))
                return name!;
            if (!string.IsNullOrWhiteSpace(id))
                return id!;
            return "";
        }
    }

    public string MediaLabel
    {
        get
        {
            if (MediaKind == ChatMediaKind.None)
                return "";
            var kind = MediaKind switch
            {
                ChatMediaKind.Image => "Immagine",
                ChatMediaKind.Video => "Video",
                ChatMediaKind.Audio => "Audio",
                ChatMediaKind.Document => "Documento",
                _ => "Media",
            };
            var name = FileName ?? MediaHint ?? kind;
            var dur = DurationSeconds is > 0
                ? " · " + Services.AppleTime.FormatDuration(DurationSeconds)
                : "";
            var miss = MediaMissing ? " · non nel backup" : "";
            return $"{kind}: {name}{dur}{miss}";
        }
    }

    public bool CanPreviewImage =>
        MediaKind == ChatMediaKind.Image && !string.IsNullOrWhiteSpace(MediaShardPath);

    public bool CanPlayMedia =>
        MediaKind is ChatMediaKind.Video or ChatMediaKind.Audio
        && !string.IsNullOrWhiteSpace(MediaShardPath);
}

public sealed class CallRecord
{
    public long Id { get; init; }
    public required string App { get; init; }
    public string Peer { get; init; } = "";
    public CallDirection Direction { get; init; }
    public CallOutcome Outcome { get; init; }
    public DateTimeOffset? StartedAt { get; init; }
    public double? DurationSeconds { get; init; }
    public bool IsVideo { get; init; }
    public bool IsGroup { get; init; }

    public string DurationLabel => Services.AppleTime.FormatDuration(DurationSeconds);
    public string WhenLabel => Services.AppleTime.Format(StartedAt);
    public string OutcomeLabel => Outcome switch
    {
        CallOutcome.Answered => "Risposta",
        CallOutcome.Missed => "Persa",
        CallOutcome.Rejected => "Rifiutata",
        CallOutcome.Cancelled => "Annullata",
        _ => "Altro",
    };
    public string DirectionLabel => Direction switch
    {
        CallDirection.Incoming => "In entrata",
        CallDirection.Outgoing => "In uscita",
        _ => "—",
    };
}

public sealed class CoreDataSnapshot
{
    public IReadOnlyList<ContactRecord> Contacts { get; init; } = [];
    public IReadOnlyList<CalendarInfo> Calendars { get; init; } = [];
    public IReadOnlyList<CalendarEventItem> Events { get; init; } = [];
    public IReadOnlyList<ChatSource> ChatSources { get; init; } = [];
    public IReadOnlyList<CallRecord> Calls { get; init; } = [];
    public IReadOnlyList<string> Notes { get; init; } = [];
}
