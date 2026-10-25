using System.IO;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Restore;

public sealed record PasscodeCrackResult(
    string Passcode,
    IosKeybag Keybag,
    IReadOnlyDictionary<int, byte[]> ClassKeys);

/// <summary>
/// Brute-force del passcode dispositivo sul keybag (PIN numerico).
/// Il passcode è il codice di sblocco del dispositivo (tipicamente 4–6 cifre).
/// </summary>
public static class KeybagPasscodeBruteforcer
{
    public static PasscodeCrackResult? TryPasscodes(
        IReadOnlyList<string> keybagRecords,
        IEnumerable<string> candidates,
        IProgress<string>? log = null)
    {
        foreach (var record in keybagRecords)
        {
            if (!IosKeybag.TryParse(record, out var keybag, out var err) || keybag is null)
            {
                log?.Report($"  keybag skip: {err}");
                continue;
            }

            log?.Report($"  keybag TYPE={keybag.KeybagType} iter={keybag.DetectedIterationCount?.ToString() ?? "?"}");

            foreach (var passcode in candidates)
            {
                if (keybag.TryUnlock(passcode))
                {
                    log?.Report($"  passcode trovato: {MaskPasscode(passcode)} ({keybag.UnwrappedClassKeys.Count} class keys)");
                    return new PasscodeCrackResult(passcode, keybag, keybag.UnwrappedClassKeys);
                }
            }
        }

        return null;
    }

    public static PasscodeCrackResult? BruteforceNumericPin(
        IReadOnlyList<string> keybagRecords,
        int minDigits = 4,
        int maxDigits = 6,
        IProgress<string>? log = null,
        CancellationToken ct = default)
    {
        if (minDigits < 1 || maxDigits < minDigits || maxDigits > 10)
            throw new ArgumentOutOfRangeException(nameof(maxDigits));

        foreach (var record in keybagRecords)
        {
            if (!IosKeybag.TryParse(record, out var keybag, out var err) || keybag is null)
            {
                log?.Report($"  keybag skip: {err}");
                continue;
            }

            var iterations = keybag.DetectedIterationCount ?? 10_000_000;
            log?.Report($"  brute PIN {minDigits}-{maxDigits} cifre (ITER≈{iterations:N0})…");

            for (var digits = minDigits; digits <= maxDigits; digits++)
            {
                var max = (int)Math.Pow(10, digits);
                for (var pin = 0; pin < max; pin++)
                {
                    ct.ThrowIfCancellationRequested();
                    var passcode = pin.ToString($"D{digits}");
                    if (keybag.TryUnlock(passcode))
                    {
                        log?.Report($"  PIN trovato: {MaskPasscode(passcode)}");
                        return new PasscodeCrackResult(passcode, keybag, keybag.UnwrappedClassKeys);
                    }

                    if (pin > 0 && pin % 500 == 0)
                        log?.Report($"  …provati {pin}/{max} ({digits} cifre)");
                }
            }
        }

        return null;
    }

    public static IEnumerable<string> LoadWordlist(string path)
    {
        if (!File.Exists(path))
            yield break;
        foreach (var line in File.ReadLines(path))
        {
            var p = line.Trim();
            if (p.Length > 0)
                yield return p;
        }
    }

    private static string MaskPasscode(string passcode) =>
        passcode.Length <= 2 ? new string('*', passcode.Length) : $"{passcode[0]}{new string('*', passcode.Length - 2)}{passcode[^1]}";
}
