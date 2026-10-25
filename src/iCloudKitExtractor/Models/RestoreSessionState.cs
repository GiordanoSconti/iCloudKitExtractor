using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Protocol;
using iCloudKitExtractor.Services.Http;

namespace iCloudKitExtractor.Models;

/// <summary>
/// Stato restore CloudKit per sessione: valori propagati tra richieste e assorbiti dalle risposte.
/// Foreground hw/sha da identità catturata (stabile); altri campi da risposte/anisette.
/// </summary>
public sealed class RestoreSessionState
{
    private static readonly Regex UuidRegex = new(
        @"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
        RegexOptions.Compiled);

    public string DeviceSessionId { get; private set; }
    public string OperationGroupId { get; private set; }
    public ForegroundRestorePlist? Foreground { get; private set; }
    public UbChunkCatalog PreAuthCatalog { get; private set; } = UbChunkCatalog.Empty;
    public byte[]? PreAuthSessionBlob { get; private set; }
    public byte[]? PreAuthWscPrefix { get; private set; }
    public bool ForegroundIsSynthetic { get; private set; }

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

    /// <summary>Assorbe metadati Foreground e device-session da payload di risposta.</summary>
    public void TryAbsorbFromPayload(byte[]? payload)
    {
        if (payload is not { Length: > 64 })
            return;

        var extracted = ForegroundRestorePlistExtractor.Extract(payload);
        if (extracted is not null)
        {
            var captured = ForegroundRestorePlistBuilder.BuildCapturedAuth(
                anisette: null,
                mmeClientInfoFromResponse: extracted.MmeClientInfo);
            Foreground = ForegroundRestorePlistBuilder.MergeWithAbsorbed(
                captured,
                Foreground ?? extracted);
            ForegroundIsSynthetic = false;
        }

        var sessionId = ForegroundRestorePlistExtractor.ExtractDeviceSessionId(payload);
        if (!string.IsNullOrWhiteSpace(sessionId))
            DeviceSessionId = sessionId;
    }

    /// <summary>
    /// Garantisce Foreground: hw/sha statici (invariati in tutte le catture) +
    /// mme-client-info da risposte precedenti o anisette.
    /// </summary>
    public void EnsureForeground(ICloudSession session, BackupDevice? device = null)
    {
        _ = device; // device non entra in hw/sha (stabili per account/host restore)
        var captured = ForegroundRestorePlistBuilder.BuildCapturedAuth(session.Anisette);

        if (Foreground is null)
        {
            Foreground = captured;
            // Identità catturata (non hash sintetico locale).
            ForegroundIsSynthetic = false;
            return;
        }

        // Arricchisce mme/proto da quanto già assorbito, mantiene hw/sha.
        Foreground = ForegroundRestorePlistBuilder.MergeWithAbsorbed(captured, Foreground);
        ForegroundIsSynthetic = false;
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
