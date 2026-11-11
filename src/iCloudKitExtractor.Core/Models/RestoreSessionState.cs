using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Models;

/// <summary>
/// Stato restore CloudKit per sessione: valori propagati tra richieste e assorbiti dalle risposte.
/// Foreground hw/sha da identità catturata (stabile); altri campi da risposte/anisette.
/// <see cref="ObservedForeground"/> tiene l'identità vista in rete (probe), distinta da quella usata in request.
/// </summary>
public sealed class RestoreSessionState
{
    private static readonly Regex UuidRegex = new(
        @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        RegexOptions.Compiled);

    private readonly List<string> _observedForegroundSources = new();

    public string DeviceSessionId { get; private set; }
    public string OperationGroupId { get; private set; }
    public ForegroundRestorePlist? Foreground { get; private set; }
    public UbChunkCatalog PreAuthCatalog { get; private set; } = UbChunkCatalog.Empty;
    public byte[]? PreAuthSessionBlob { get; private set; }
    public byte[]? PreAuthWscPrefix { get; private set; }
    public bool ForegroundIsSynthetic { get; private set; }

    /// <summary>Ultima identità FG estratta da una risposta (null = mai vista in rete).</summary>
    public ForegroundRestorePlist? ObservedForeground { get; private set; }

    /// <summary>Sorgente dell'ultimo HIT (es. <c>zones</c>, <c>batch S:</c>, <c>mbs</c>).</summary>
    public string? ObservedForegroundSource { get; private set; }

    public int ObservedForegroundHitCount { get; private set; }
    public int ObservedForegroundMissCount { get; private set; }

    public IReadOnlyList<string> ObservedForegroundSources => _observedForegroundSources;

    private RestoreSessionState(string deviceSessionId, string operationGroupId)
    {
        DeviceSessionId = deviceSessionId;
        OperationGroupId = operationGroupId;
    }

    public static RestoreSessionState Create(ICloudSession session)
    {
        var deviceSessionId = ResolveDeviceSessionId(session);
        var compact = deviceSessionId
            .Replace("-", "", StringComparison.Ordinal)
            .ToUpperInvariant();
        // UUID senza dash = 32 hex; non fare [..16] su stringhe corte (ArgumentOutOfRange).
        var operationGroupId = compact.Length >= 16
            ? compact[..16]
            : (compact + Guid.NewGuid().ToString("N").ToUpperInvariant())[..16];
        return new RestoreSessionState(deviceSessionId, operationGroupId);
    }

    /// <summary>Stato per restore: Foreground assorbito da mbs/batch , non sintetico pre-bootstrap.</summary>
    public static RestoreSessionState CreateForCatalog(ICloudSession session) => Create(session);

    public RestoreRequestContext ToRequestContext()
    {
        if (Foreground is null)
            throw new InvalidOperationException(
                "Foreground Restore non disponibile: completa il bootstrap o fornisci metadati sessione.");

        return new RestoreRequestContext(DeviceSessionId, Foreground);
    }

    /// <summary>
    /// Assorbe metadati Foreground e device-session da payload di risposta.
    /// Con <paramref name="source"/> + <paramref name="log"/> registra HIT/MISS hw+sha osservati in rete
    /// (senza sostituire l'hw/sha statico usato nelle request).
    /// </summary>
    public bool TryAbsorbFromPayload(
        byte[]? payload,
        string? source = null,
        IProgress<string>? log = null,
        bool logMisses = true)
    {
        if (payload is not { Length: > 64 })
        {
            if (logMisses && log is not null && !string.IsNullOrWhiteSpace(source))
            {
                ObservedForegroundMissCount++;
                log.Report($"  FG observe [{source}]: MISS (payload vuoto/corto)");
            }
            else if (!string.IsNullOrWhiteSpace(source))
            {
                ObservedForegroundMissCount++;
            }

            return false;
        }

        var extracted = ForegroundRestorePlistExtractor.Extract(payload);
        if (extracted is not null)
        {
            NoteObservedForeground(extracted, source, log);
            var captured = ForegroundRestorePlistBuilder.BuildCapturedAuth(
                anisette: null,
                mmeClientInfoFromResponse: extracted.MmeClientInfo);
            Foreground = ForegroundRestorePlistBuilder.MergeWithAbsorbed(
                captured,
                Foreground ?? extracted);
            ForegroundIsSynthetic = false;
        }
        else if (!string.IsNullOrWhiteSpace(source))
        {
            ObservedForegroundMissCount++;
            if (logMisses && log is not null)
                log.Report($"  FG observe [{source}]: MISS ({payload.Length:N0} B) — no hw/sha MMCS");
        }

        var sessionId = ForegroundRestorePlistExtractor.ExtractDeviceSessionId(payload);
        if (!string.IsNullOrWhiteSpace(sessionId))
            DeviceSessionId = sessionId;

        return extracted is not null;
    }

    /// <summary>
    /// Garantisce Foreground: hw/sha statici (invariati in tutte le catture) +
    /// mme-client-info da risposte precedenti o anisette.
    /// </summary>
    public void EnsureForeground(
        ICloudSession session,
        BackupDevice? device = null,
        IProgress<string>? log = null)
    {
        _ = device; // device non entra in hw/sha (stabili per account/host restore)
        var captured = ForegroundRestorePlistBuilder.BuildCapturedAuth(session.Anisette);

        if (Foreground is null)
        {
            Foreground = captured;
            // Identità catturata (non hash sintetico locale).
            ForegroundIsSynthetic = false;
        }
        else
        {
            // Arricchisce mme/proto da quanto già assorbito, mantiene hw/sha.
            Foreground = ForegroundRestorePlistBuilder.MergeWithAbsorbed(captured, Foreground);
            ForegroundIsSynthetic = false;
        }

        log?.Report(
            $"  FG seed (IKE static → request): hw={Foreground.HardwareIdHex} " +
            $"sha={Foreground.PlistSha256Base64}");
    }

    /// <summary>Riga di riepilogo probe FG (HIT/MISS sulle risposte early).</summary>
    public string FormatObservedSummary()
    {
        if (ObservedForeground is null)
        {
            return $"FG observe summary: hits=0 misses={ObservedForegroundMissCount} " +
                   "(nessun Hardware-Id / plist-sha256 nelle risposte)";
        }

        var matchHw = string.Equals(
            ObservedForeground.HardwareIdHex,
            ForegroundRestorePlistBuilder.HardwareIdHex,
            StringComparison.OrdinalIgnoreCase);
        var matchSha = string.Equals(
            ObservedForeground.PlistSha256Base64,
            ForegroundRestorePlistBuilder.PlistSha256Base64,
            StringComparison.Ordinal);
        var sources = _observedForegroundSources.Count == 0
            ? "?"
            : string.Join(", ", _observedForegroundSources);

        return $"FG observe summary: hits={ObservedForegroundHitCount} " +
               $"misses={ObservedForegroundMissCount} sources=[{sources}] " +
               $"hw={ObservedForeground.HardwareIdHex} sha={ObservedForeground.PlistSha256Base64} " +
               $"matchStaticHw={matchHw} matchStaticSha={matchSha}";
    }

    private void NoteObservedForeground(
        ForegroundRestorePlist extracted,
        string? source,
        IProgress<string>? log)
    {
        ObservedForegroundHitCount++;
        ObservedForeground = extracted;
        if (!string.IsNullOrWhiteSpace(source))
        {
            ObservedForegroundSource = source.Trim();
            if (!_observedForegroundSources.Contains(ObservedForegroundSource, StringComparer.Ordinal))
                _observedForegroundSources.Add(ObservedForegroundSource);
        }

        var matchHw = string.Equals(
            extracted.HardwareIdHex,
            ForegroundRestorePlistBuilder.HardwareIdHex,
            StringComparison.OrdinalIgnoreCase);
        var matchSha = string.Equals(
            extracted.PlistSha256Base64,
            ForegroundRestorePlistBuilder.PlistSha256Base64,
            StringComparison.Ordinal);
        var label = string.IsNullOrWhiteSpace(source) ? "?" : source.Trim();
        log?.Report(
            $"  FG observe [{label}]: HIT hw={extracted.HardwareIdHex} " +
            $"sha={extracted.PlistSha256Base64} " +
            $"matchStaticHw={matchHw} matchStaticSha={matchSha}");
    }

    public void MergePreAuthCatalog(UbChunkCatalog catalog) =>
        PreAuthCatalog = PreAuthCatalog.Merge(catalog);

    /// <summary>Memorizza header delimited PreAuth per round successivi (stato client).</summary>
    public void CapturePreAuthHeader(byte[] delimitedHeaderMessage)
    {
        if (delimitedHeaderMessage is { Length: > 64 })
            PreAuthSessionBlob = delimitedHeaderMessage;
    }

    public void CapturePreAuthWscPrefix(byte[]? prefix)
    {
        if (prefix is { Length: > 8 })
            PreAuthWscPrefix = prefix;
    }

    public void CapturePreAuthSessionBlob(byte[]? sessionBlob)
    {
        if (sessionBlob is { Length: >= 2800 and <= 3200 })
            PreAuthSessionBlob = sessionBlob;
    }

    /// <summary>Prefisso wSc solo se assorbito dalla sessione (mai template stale).</summary>
    public byte[]? ResolvePreAuthWscPrefix() => PreAuthWscPrefix;

    private static string ResolveDeviceSessionId(ICloudSession session)
    {
        if (TryNormalizeUuid(session.Anisette.MdLu, out var fromAnisette))
            return fromAnisette;

        if (!string.IsNullOrWhiteSpace(session.AppleCloudKitContext))
        {
            var match = UuidRegex.Match(session.AppleCloudKitContext);
            if (match.Success && TryNormalizeUuid(match.Value, out var fromContext))
                return fromContext;
        }

        if (!string.IsNullOrWhiteSpace(session.CloudKitUserId))
            return DeriveSessionUuid(session.CloudKitUserId);

        throw new InvalidOperationException(
            "device-session UUID assente: servono Anisette Md-LU, AppleCloudKitContext o CloudKitUserId.");
    }

    /// <summary>UUID deterministico da CloudKitUserId (stabile per sessione, non random).</summary>
    private static string DeriveSessionUuid(string cloudKitUserId)
    {
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes("device-session|" + cloudKitUserId));
        var bytes = hash.AsSpan(0, 16);
        return new Guid(bytes).ToString().ToLowerInvariant();
    }

    private static bool TryNormalizeUuid(string? value, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(value))
            return false;

        var match = UuidRegex.Match(value);
        if (!match.Success)
            return false;

        normalized = match.Value.ToLowerInvariant();
        return true;
    }
}

/// <summary>Contesto protobuf restore: device-session stabile + metadati Foreground.</summary>
public sealed record RestoreRequestContext(
    string DeviceSessionId,
    ForegroundRestorePlist Foreground);
