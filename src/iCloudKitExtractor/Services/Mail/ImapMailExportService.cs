using System.IO;
using System.Text;
using MailKit;
using MimeKit;

namespace iCloudKitExtractor.Services.Mail;

/// <summary>
/// Esporta messaggi IMAP in cartelle di file <c>.eml</c> (RFC822).
/// </summary>
public static class ImapMailExportService
{
    public sealed record ExportResult(
        string RootDirectory,
        int Written,
        int Failed,
        IReadOnlyList<string> Errors);

    /// <summary>
    /// Esporta i messaggi indicati sotto
    /// <c>{parent}/mail_export_{stamp}/{folder}/…eml</c>.
    /// </summary>
    public static async Task<ExportResult> ExportAsync(
        ImapMailClient client,
        string parentDirectory,
        string folderFullName,
        IReadOnlyList<UniqueId> uids,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (string.IsNullOrWhiteSpace(parentDirectory))
            throw new ArgumentException("Cartella destinazione obbligatoria.", nameof(parentDirectory));
        if (string.IsNullOrWhiteSpace(folderFullName))
            throw new ArgumentException("Cartella IMAP obbligatoria.", nameof(folderFullName));
        if (uids is null || uids.Count == 0)
            throw new ArgumentException("Nessun messaggio da esportare.", nameof(uids));

        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var root = Path.Combine(parentDirectory, $"mail_export_{stamp}");
        var folderDir = Path.Combine(root, SanitizePathSegment(folderFullName));
        Directory.CreateDirectory(folderDir);

        var errors = new List<string>();
        var written = 0;
        var failed = 0;
        var total = uids.Count;
        var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        for (var i = 0; i < uids.Count; i++)
        {
            ct.ThrowIfCancellationRequested();
            var uid = uids[i];
            progress?.Report($"Esporto {i + 1}/{total} ({folderFullName})…");
            try
            {
                var mime = await client.FetchMimeMessageAsync(folderFullName, uid, ct)
                    .ConfigureAwait(false);
                var fileName = BuildEmlFileName(mime, uid, usedNames);
                var path = Path.Combine(folderDir, fileName);
                await using (var fs = File.Create(path))
                    await mime.WriteToAsync(fs, ct).ConfigureAwait(false);
                written++;
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                failed++;
                if (errors.Count < 40)
                    errors.Add($"uid={uid} {folderFullName}: {ex.Message}");
            }
        }

        await WriteLogAsync(root, folderFullName, written, failed, errors, ct).ConfigureAwait(false);
        return new ExportResult(root, written, failed, errors);
    }

    /// <summary>
    /// Esporta tutte le cartelle IMAP (ogni messaggio, o filtro IMAP SEARCH)
    /// sotto un’unica <c>mail_export_{stamp}/</c>.
    /// </summary>
    public static async Task<ExportResult> ExportAllFoldersAsync(
        ImapMailClient client,
        string parentDirectory,
        ImapMessageFilter? filter = null,
        IProgress<string>? progress = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        if (string.IsNullOrWhiteSpace(parentDirectory))
            throw new ArgumentException("Cartella destinazione obbligatoria.", nameof(parentDirectory));

        var stamp = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var root = Path.Combine(parentDirectory, $"mail_export_{stamp}");
        Directory.CreateDirectory(root);

        var folders = await client.ListFoldersAsync(ct).ConfigureAwait(false);
        var errors = new List<string>();
        var written = 0;
        var failed = 0;

        foreach (var folder in folders)
        {
            ct.ThrowIfCancellationRequested();
            progress?.Report($"Cartella {folder.DisplayName}…");
            IReadOnlyList<UniqueId> uids;
            try
            {
                uids = await client.ListAllUidsAsync(folder.FullName, filter, ct)
                    .ConfigureAwait(false);
            }
            catch (Exception ex)
            {
                failed++;
                if (errors.Count < 40)
                    errors.Add($"list {folder.FullName}: {ex.Message}");
                continue;
            }

            if (uids.Count == 0)
                continue;

            var folderDir = Path.Combine(root, SanitizePathSegment(folder.FullName));
            Directory.CreateDirectory(folderDir);
            var usedNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            for (var i = 0; i < uids.Count; i++)
            {
                ct.ThrowIfCancellationRequested();
                var uid = uids[i];
                progress?.Report(
                    $"Esporto {folder.DisplayName}: {i + 1}/{uids.Count} " +
                    $"(tot ok={written} fail={failed})…");
                try
                {
                    var mime = await client.FetchMimeMessageAsync(folder.FullName, uid, ct)
                        .ConfigureAwait(false);
                    var fileName = BuildEmlFileName(mime, uid, usedNames);
                    var path = Path.Combine(folderDir, fileName);
                    await using (var fs = File.Create(path))
                        await mime.WriteToAsync(fs, ct).ConfigureAwait(false);
                    written++;
                }
                catch (OperationCanceledException)
                {
                    throw;
                }
                catch (Exception ex)
                {
                    failed++;
                    if (errors.Count < 40)
                        errors.Add($"uid={uid} {folder.FullName}: {ex.Message}");
                }
            }
        }

        await WriteLogAsync(root, "(all folders)", written, failed, errors, ct).ConfigureAwait(false);
        return new ExportResult(root, written, failed, errors);
    }

    private static async Task WriteLogAsync(
        string root,
        string scope,
        int written,
        int failed,
        IReadOnlyList<string> errors,
        CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.AppendLine($"scope={scope}");
        sb.AppendLine($"written={written}");
        sb.AppendLine($"failed={failed}");
        sb.AppendLine($"utc={DateTime.UtcNow:O}");
        foreach (var err in errors)
            sb.AppendLine(err);
        await File.WriteAllTextAsync(
                Path.Combine(root, "export.log"),
                sb.ToString(),
                ct)
            .ConfigureAwait(false);
    }

    private static string BuildEmlFileName(
        MimeMessage mime,
        UniqueId uid,
        HashSet<string> usedNames)
    {
        var date = mime.Date != default
            ? mime.Date.ToLocalTime().ToString("yyyy-MM-dd_HHmmss")
            : "nodate";
        var subject = SanitizeFileName(mime.Subject?.Trim() ?? "no-subject");
        if (subject.Length > 60)
            subject = subject[..60].TrimEnd();
        var baseName = $"{date}_uid{uid.Id}_{subject}.eml";
        if (usedNames.Add(baseName))
            return baseName;

        var n = 2;
        string alt;
        do
        {
            alt = $"{date}_uid{uid.Id}_{subject}_{n}.eml";
            n++;
        } while (!usedNames.Add(alt));

        return alt;
    }

    private static string SanitizePathSegment(string folderFullName)
    {
        var parts = folderFullName.Split(['/', '\\'], StringSplitOptions.RemoveEmptyEntries);
        if (parts.Length == 0)
            return "INBOX";
        return Path.Combine(parts.Select(SanitizeFileName).ToArray());
    }

    private static string SanitizeFileName(string name)
    {
        if (string.IsNullOrWhiteSpace(name))
            return "unnamed";
        var invalid = Path.GetInvalidFileNameChars();
        var sb = new StringBuilder(name.Length);
        foreach (var c in name.Trim())
        {
            if (invalid.Contains(c) || c < 32)
                sb.Append('_');
            else
                sb.Append(c);
        }

        var s = sb.ToString().Trim(' ', '.');
        return string.IsNullOrWhiteSpace(s) ? "unnamed" : s;
    }
}
