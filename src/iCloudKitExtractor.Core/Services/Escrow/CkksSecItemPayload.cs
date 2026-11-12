using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using iCloudKitExtractor.Protocol;

namespace iCloudKitExtractor.Services.Escrow;

/// <summary>
/// Decodifica <c>v_Data</c> (e attributi SecItem) da item CKKS già in chiaro:
/// password UTF-8, sidecar Password Manager (notes / TOTP), Wi‑Fi, cert X.509, chiavi.
/// </summary>
public static class CkksSecItemPayload
{
    private static readonly Regex NonPrintable = new(
        @"[\x00-\x08\x0B\x0C\x0E-\x1F]",
        RegexOptions.Compiled);

    public enum Kind
    {
        Empty,
        Utf8Secret,
        PasswordManagerSidecar,
        CreditCard,
        Wifi,
        Certificate,
        KeyMaterial,
        Passkey,
        HomeKitPairing,
        Rapport,
        Sos,
        AppToken,
        Subsystem,
        BinaryPlist,
        Asn1,
        Binary,
    }

    public sealed record Decoded(
        Kind Kind,
        string? Utf8Secret,
        string? Notes,
        string? Title,
        string? OtpAuth,
        string? TotpIssuer,
        string? TotpAccount,
        string? CardNumber,
        string? CardName,
        string? CardExpiry,
        string? CardCvv,
        string? WifiSsid,
        string? WifiPassword,
        string? CertSubject,
        string? CertIssuer,
        string? CertSerial,
        string? CertNotBefore,
        string? CertNotAfter,
        string? CertPem,
        string? KeyAlgorithm,
        int? KeySizeBits,
        string? KeyPem,
        string DataKind,
        int DataLen,
        string? Category = null,
        string? SummaryJson = null,
        string? HexPreview = null);

    public static Decoded Decode(CkksVaultItem item)
    {
        var data = item.Data;
        var len = data?.Length ?? 0;
        if (data is null || len == 0)
            return Empty("empty", 0);

        var agrp = item.Agrp ?? AttrString(item, "agrp") ?? "";
        var cls = item.Class ?? AttrString(item, "class") ?? "";
        var desc = AttrString(item, "desc") ?? "";
        var svce = AttrString(item, "svce") ?? "";
        var labl = item.Labl ?? AttrString(item, "labl") ?? "";

        var cert = TryLoadCert(data);
        if (cert is not null
            || cls.Equals("cert", StringComparison.OrdinalIgnoreCase))
        {
            if (cert is not null)
            {
                return new Decoded(
                    Kind.Certificate,
                    Utf8Secret: null,
                    Notes: null,
                    Title: labl,
                    OtpAuth: null,
                    TotpIssuer: null,
                    TotpAccount: null,
                    CardNumber: null,
                    CardName: null,
                    CardExpiry: null,
                    CardCvv: null,
                    WifiSsid: null,
                    WifiPassword: null,
                    CertSubject: cert.Subject,
                    CertIssuer: cert.Issuer,
                    CertSerial: cert.SerialNumber,
                    CertNotBefore: cert.NotBefore.ToUniversalTime().ToString("O"),
                    CertNotAfter: cert.NotAfter.ToUniversalTime().ToString("O"),
                    CertPem: ToPem("CERTIFICATE", cert.RawData),
                    KeyAlgorithm: cert.GetKeyAlgorithm(),
                    KeySizeBits: TryCertKeyBits(cert),
                    KeyPem: null,
                    DataKind: "x509",
                    DataLen: len);
            }

            // class=cert ma DER non parsabile — resta binary/asn1 più sotto.
        }

        if (cls.Equals("keys", StringComparison.OrdinalIgnoreCase)
            || cls.Equals("idnt", StringComparison.OrdinalIgnoreCase))
        {
            var key = TryDecodeKey(data, cls);
            if (key is not null)
                return key with { DataLen = len, Title = string.IsNullOrEmpty(key.Title) ? labl : key.Title };
        }

        if (IsWifiItem(item, agrp, desc, svce, labl)
            && TryUtf8Secret(data, out var wifiPwd))
        {
            var ssid = FirstNonEmpty(item.Acct, item.Labl, svce, AttrString(item, "srvr"));
            return new Decoded(
                Kind.Wifi,
                Utf8Secret: wifiPwd,
                Notes: null,
                Title: labl,
                OtpAuth: null,
                TotpIssuer: null,
                TotpAccount: null,
                CardNumber: null,
                CardName: null,
                CardExpiry: null,
                CardCvv: null,
                WifiSsid: ssid,
                WifiPassword: wifiPwd,
                CertSubject: null,
                CertIssuer: null,
                CertSerial: null,
                CertNotBefore: null,
                CertNotAfter: null,
                CertPem: null,
                KeyAlgorithm: null,
                KeySizeBits: null,
                KeyPem: null,
                DataKind: "utf8",
                DataLen: len);
        }

        if (IsPasswordManagerAgrp(agrp) && TryParseBplistDict(data, out var side))
        {
            var notes = AsUtf8Field(side, "notes");
            var title = AsUtf8Field(side, "title") ?? labl;
            string? otpAuth = null;
            string? issuer = null;
            string? account = null;
            if (side.TryGetValue("totp", out var totpObj) && totpObj is Dictionary<string, object?> totp)
            {
                otpAuth = BuildOtpAuth(totp);
                issuer = AsString(totp, "issuer");
                account = AsString(totp, "accountName");
            }

            return new Decoded(
                Kind.PasswordManagerSidecar,
                Utf8Secret: null,
                Notes: notes,
                Title: title,
                OtpAuth: otpAuth,
                TotpIssuer: issuer,
                TotpAccount: account,
                CardNumber: null,
                CardName: null,
                CardExpiry: null,
                CardCvv: null,
                WifiSsid: null,
                WifiPassword: null,
                CertSubject: null,
                CertIssuer: null,
                CertSerial: null,
                CertNotBefore: null,
                CertNotAfter: null,
                CertPem: null,
                KeyAlgorithm: null,
                KeySizeBits: null,
                KeyPem: null,
                DataKind: "bplist-sidecar",
                DataLen: len);
        }

        if (IsCreditCardAgrp(agrp) && TryParseBplistDict(data, out var card))
        {
            return new Decoded(
                Kind.CreditCard,
                Utf8Secret: null,
                Notes: AsUtf8Field(card, "notes"),
                Title: AsUtf8Field(card, "cardName")
                       ?? AsString(card, "cardName")
                       ?? labl,
                OtpAuth: null,
                TotpIssuer: null,
                TotpAccount: null,
                CardNumber: AsString(card, "cardNumber") ?? AsUtf8Field(card, "cardNumber"),
                CardName: AsString(card, "cardName") ?? AsUtf8Field(card, "cardName"),
                CardExpiry: FormatCardExpiry(card),
                CardCvv: AsString(card, "cardSecurityCode")
                         ?? AsString(card, "cvv")
                         ?? AsUtf8Field(card, "cardSecurityCode"),
                WifiSsid: null,
                WifiPassword: null,
                CertSubject: null,
                CertIssuer: null,
                CertSerial: null,
                CertNotBefore: null,
                CertNotAfter: null,
                CertPem: null,
                KeyAlgorithm: null,
                KeySizeBits: null,
                KeyPem: null,
                DataKind: "bplist-card",
                DataLen: len,
                Category: "credit-card",
                SummaryJson: FlattenToJson(card),
                HexPreview: null);
        }

        var category = ClassifyAgrp(agrp, cls, item);
        if (IsPasskeyAgrp(agrp) || category == "passkey")
        {
            var opaquePk = CkksOpaqueBlobDecoder.TryDecode(item, data, "passkey");
            return Empty(opaquePk?.Format ?? "passkey", len) with
            {
                Kind = Kind.Passkey,
                Title = labl,
                Category = "passkey",
                SummaryJson = opaquePk?.SummaryJson,
                HexPreview = TruncHex(data, 64),
                KeyAlgorithm = data.Length is 65 or 97 && data[0] == 0x04 ? "EC-pub" : null,
                KeySizeBits = data.Length == 65 ? 256 : data.Length == 97 ? 384 : null,
                DataKind = opaquePk?.Format ?? "passkey"
            };
        }

        if (category is "homekit" or "rapport" or "sos" or "app-token" or "subsystem")
        {
            var kind = category switch
            {
                "homekit" => Kind.HomeKitPairing,
                "rapport" => Kind.Rapport,
                "sos" => Kind.Sos,
                "app-token" => Kind.AppToken,
                _ => Kind.Subsystem
            };
            var opaque = CkksOpaqueBlobDecoder.TryDecode(item, data, category);
            if (opaque is not null)
            {
                return Empty(opaque.Format, len) with
                {
                    Kind = kind,
                    Title = labl,
                    Utf8Secret = opaque.Utf8Secret,
                    Category = category,
                    SummaryJson = opaque.SummaryJson,
                    HexPreview = TruncHex(data, 48),
                    DataKind = opaque.Format
                };
            }

            return Empty("binary", len) with
            {
                Kind = kind,
                Title = labl,
                Category = category,
                SummaryJson = null,
                HexPreview = TruncHex(data, 48),
                DataKind = "binary"
            };
        }

        if (TryUtf8Secret(data, out var utf8))
        {
            return new Decoded(
                Kind.Utf8Secret,
                Utf8Secret: utf8,
                Notes: AttrString(item, "icmt"),
                Title: labl,
                OtpAuth: null,
                TotpIssuer: null,
                TotpAccount: null,
                CardNumber: null,
                CardName: null,
                CardExpiry: null,
                CardCvv: null,
                WifiSsid: null,
                WifiPassword: null,
                CertSubject: null,
                CertIssuer: null,
                CertSerial: null,
                CertNotBefore: null,
                CertNotAfter: null,
                CertPem: null,
                KeyAlgorithm: null,
                KeySizeBits: null,
                KeyPem: null,
                DataKind: "utf8",
                DataLen: len,
                Category: category,
                SummaryJson: null,
                HexPreview: null);
        }

        if (data.Length >= 8 && data.AsSpan(0, 8).SequenceEqual("bplist00"u8))
        {
            if (AppleBinaryPlist.TryParse(data, out var root, out _) && root is not null)
            {
                // Generic bplist — surface notes/totp if present even outside password-manager agrp.
                if (root is Dictionary<string, object?> any
                    && (any.ContainsKey("notes") || any.ContainsKey("totp") || any.ContainsKey("title")))
                {
                    var notes = AsUtf8Field(any, "notes");
                    var title = AsUtf8Field(any, "title") ?? labl;
                    string? otpAuth = null;
                    string? issuer = null;
                    string? account = null;
                    if (any.TryGetValue("totp", out var totpObj) && totpObj is Dictionary<string, object?> totp)
                    {
                        otpAuth = BuildOtpAuth(totp);
                        issuer = AsString(totp, "issuer");
                        account = AsString(totp, "accountName");
                    }

                    return new Decoded(
                        Kind.PasswordManagerSidecar,
                        Utf8Secret: null,
                        Notes: notes,
                        Title: title,
                        OtpAuth: otpAuth,
                        TotpIssuer: issuer,
                        TotpAccount: account,
                        CardNumber: null,
                        CardName: null,
                        CardExpiry: null,
                        CardCvv: null,
                        WifiSsid: null,
                        WifiPassword: null,
                        CertSubject: null,
                        CertIssuer: null,
                        CertSerial: null,
                        CertNotBefore: null,
                        CertNotAfter: null,
                        CertPem: null,
                        KeyAlgorithm: null,
                        KeySizeBits: null,
                        KeyPem: null,
                        DataKind: "bplist-sidecar",
                        DataLen: len,
                        Category: category,
                        SummaryJson: FlattenToJson(root),
                        HexPreview: null);
                }

                // Prefer NSKeyedArchive / nested resolve over shallow flatten.
                var opaqueBp = CkksOpaqueBlobDecoder.TryDecode(item, data, category);
                return Empty(opaqueBp?.Format ?? "bplist", len) with
                {
                    Kind = Kind.BinaryPlist,
                    Title = labl,
                    Category = category,
                    SummaryJson = opaqueBp?.SummaryJson ?? FlattenToJson(root),
                    HexPreview = TruncHex(data, 32),
                    DataKind = opaqueBp?.Format ?? "bplist"
                };
            }

            return Empty("bplist", len) with { Kind = Kind.BinaryPlist, Category = category };
        }

        if (data[0] == 0x30)
        {
            var opaqueAsn = CkksOpaqueBlobDecoder.TryDecode(item, data, category);
            return Empty(opaqueAsn?.Format ?? "asn1", len) with
            {
                Kind = Kind.Asn1,
                Title = labl,
                Category = category,
                SummaryJson = opaqueAsn?.SummaryJson
                              ?? JsonSerializer.Serialize(new { asn1 = DescribeAsn1(data) }),
                HexPreview = TruncHex(data, 48),
                DataKind = opaqueAsn?.Format ?? "asn1"
            };
        }

        var opaqueBin = CkksOpaqueBlobDecoder.TryDecode(item, data, category);
        return Empty(opaqueBin?.Format ?? "binary", len) with
        {
            Kind = Kind.Binary,
            Title = labl,
            Category = category,
            SummaryJson = opaqueBin?.SummaryJson,
            HexPreview = TruncHex(data, 48),
            DataKind = opaqueBin?.Format ?? "binary"
        };
    }

    /// <summary>Classifica item per <c>agrp</c> / class (catalogo forense).</summary>
    public static string ClassifyAgrp(string? agrp, string? cls = null, CkksVaultItem? item = null)
    {
        agrp ??= "";
        cls ??= item?.Class ?? "";
        if (IsPasskeyAgrp(agrp)
            || (item is not null
                && (item.View?.Equals("AutoFillPasskey", StringComparison.OrdinalIgnoreCase) ?? false)))
            return "passkey";
        if (IsCreditCardAgrp(agrp))
            return "credit-card";
        if (IsPasswordManagerAgrp(agrp))
            return "password-manager";
        if (agrp.Contains("cfnetwork", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("Safari", StringComparison.OrdinalIgnoreCase))
            return "web-password";
        if (item is not null && IsWifiItem(item))
            return "wifi";
        if (agrp.Contains("hap", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("HomeKit", StringComparison.OrdinalIgnoreCase)
            || agrp.Equals("hap.pairing", StringComparison.OrdinalIgnoreCase))
            return "homekit";
        if (agrp.Contains("rapport", StringComparison.OrdinalIgnoreCase))
            return "rapport";
        if (agrp.Contains("security.sos", StringComparison.OrdinalIgnoreCase)
            || agrp.Equals("com.apple.security.sos", StringComparison.OrdinalIgnoreCase)
            || agrp.Equals("com.apple.sbd", StringComparison.OrdinalIgnoreCase))
            return "sos";
        if (agrp.Contains("ProtectedCloudStorage", StringComparison.OrdinalIgnoreCase))
            return "pcs";
        if (agrp.Contains("bluetooth", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("continuity", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("sharing", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("apsd", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("FinanceKit", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("photos", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("Passbook", StringComparison.OrdinalIgnoreCase)
            || agrp.Contains("networkserviceproxy", StringComparison.OrdinalIgnoreCase))
            return "subsystem";
        if (cls.Equals("cert", StringComparison.OrdinalIgnoreCase))
            return "certificate";
        if (cls.Equals("keys", StringComparison.OrdinalIgnoreCase)
            || cls.Equals("idnt", StringComparison.OrdinalIgnoreCase))
            return "key-material";
        // Third-party / app access groups often look like TEAMID.* or group.*
        if (agrp.StartsWith("group.", StringComparison.OrdinalIgnoreCase)
            || (agrp.Length > 12 && char.IsDigit(agrp[0]) && agrp.Contains('.', StringComparison.Ordinal)))
            return "app-token";
        if (agrp.Equals("apple", StringComparison.OrdinalIgnoreCase))
            return "apple-generic";
        if (!string.IsNullOrEmpty(agrp) && agrp.StartsWith("com.apple.", StringComparison.OrdinalIgnoreCase))
            return "subsystem";
        if (!string.IsNullOrEmpty(agrp))
            return "app-token";
        return "unknown";
    }

    public static bool IsPasskeyAgrp(string agrp) =>
        agrp.Contains("webauthn", StringComparison.OrdinalIgnoreCase)
        || agrp.Contains("passkey", StringComparison.OrdinalIgnoreCase)
        || agrp.Equals("com.apple.webkit.webauthn", StringComparison.OrdinalIgnoreCase);

    public static bool IsWifiItem(
        CkksVaultItem item,
        string? agrp = null,
        string? desc = null,
        string? svce = null,
        string? labl = null)
    {
        agrp ??= item.Agrp ?? AttrString(item, "agrp") ?? "";
        desc ??= AttrString(item, "desc") ?? "";
        svce ??= AttrString(item, "svce") ?? "";
        labl ??= item.Labl ?? AttrString(item, "labl") ?? "";
        var view = item.View ?? "";

        if (view.Equals("WiFi", StringComparison.OrdinalIgnoreCase)
            || view.Equals("Wifi", StringComparison.OrdinalIgnoreCase))
            return true;

        if (desc.Contains("AirPort", StringComparison.OrdinalIgnoreCase)
            || desc.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase)
            || desc.Contains("WiFi", StringComparison.OrdinalIgnoreCase)
            || desc.Contains("wireless", StringComparison.OrdinalIgnoreCase))
            return true;

        if (svce.Equals("AirPort", StringComparison.OrdinalIgnoreCase)
            || svce.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase)
            || svce.Contains("WiFi", StringComparison.OrdinalIgnoreCase)
            || svce.Equals("wifi", StringComparison.OrdinalIgnoreCase))
            return true;

        // agrp apple = generici + AirPort: solo se desc/svce/labl tipici rete.
        if (agrp.Equals("apple", StringComparison.OrdinalIgnoreCase)
            && (labl.Contains("AirPort", StringComparison.OrdinalIgnoreCase)
                || labl.Contains("Wi-Fi", StringComparison.OrdinalIgnoreCase)
                || labl.Contains("WiFi", StringComparison.OrdinalIgnoreCase)))
            return true;

        return false;
    }

    public static bool IsPasswordManagerAgrp(string agrp) =>
        agrp.StartsWith("com.apple.password-manager", StringComparison.OrdinalIgnoreCase);

    public static bool IsCreditCardAgrp(string agrp) =>
        agrp.Contains("credit-card", StringComparison.OrdinalIgnoreCase)
        || agrp.Equals("com.apple.safari.credit-cards", StringComparison.OrdinalIgnoreCase);

    public static string? AttrString(CkksVaultItem item, string key)
    {
        if (item.Attrs is null || !item.Attrs.TryGetValue(key, out var v) || v is null)
            return null;
        return v switch
        {
            string s => s,
            byte[] b when TryUtf8Secret(b, out var t) => t,
            _ => v.ToString()
        };
    }

    public static bool TryUtf8Secret(byte[]? data, out string text)
    {
        text = "";
        if (data is not { Length: > 0 and < 4096 })
            return false;
        try
        {
            text = Encoding.UTF8.GetString(data);
        }
        catch
        {
            return false;
        }

        if (string.IsNullOrEmpty(text))
            return false;
        if (NonPrintable.IsMatch(text))
            return false;
        if (text.StartsWith("<?xml", StringComparison.Ordinal)
            || text.StartsWith("<plist", StringComparison.Ordinal)
            || text.StartsWith("bplist", StringComparison.Ordinal))
            return false;
        return true;
    }

    public static string BuildOtpAuth(Dictionary<string, object?> totp)
    {
        if (AsString(totp, "originalURL") is { Length: > 0 } original
            && original.StartsWith("otpauth://", StringComparison.OrdinalIgnoreCase))
            return original;

        byte[]? secretBytes = null;
        if (totp.TryGetValue("secret", out var sec))
        {
            secretBytes = sec switch
            {
                byte[] b => b,
                string s => TryFromB64OrUtf8(s),
                _ => null
            };
        }

        if (secretBytes is not { Length: > 0 })
            return "";

        var b32 = Base32Encode(secretBytes);
        var issuer = AsString(totp, "issuer") ?? "";
        var account = AsString(totp, "accountName") ?? "";
        var label = string.IsNullOrEmpty(issuer)
            ? account
            : $"{issuer}:{account}";
        if (string.IsNullOrEmpty(label))
            label = "token";

        var digits = AsInt(totp, "digits") ?? 6;
        var period = AsInt(totp, "period") ?? 30;
        var alg = AsInt(totp, "algorithm") switch
        {
            1 => "SHA256",
            2 => "SHA512",
            _ => "SHA1"
        };

        var sb = new StringBuilder();
        sb.Append("otpauth://totp/")
            .Append(Uri.EscapeDataString(label))
            .Append("?secret=").Append(b32)
            .Append("&algorithm=").Append(alg)
            .Append("&digits=").Append(digits)
            .Append("&period=").Append(period);
        if (!string.IsNullOrEmpty(issuer))
            sb.Append("&issuer=").Append(Uri.EscapeDataString(issuer));
        return sb.ToString();
    }

    public static string Base32Encode(ReadOnlySpan<byte> data)
    {
        const string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
        if (data.IsEmpty)
            return "";
        var sb = new StringBuilder((data.Length * 8 + 4) / 5);
        int buffer = data[0], next = 1, bitsLeft = 8;
        while (bitsLeft > 0 || next < data.Length)
        {
            if (bitsLeft < 5)
            {
                if (next < data.Length)
                {
                    buffer <<= 8;
                    buffer |= data[next++] & 0xff;
                    bitsLeft += 8;
                }
                else
                {
                    var pad = 5 - bitsLeft;
                    buffer <<= pad;
                    bitsLeft += pad;
                }
            }

            var index = (buffer >> (bitsLeft - 5)) & 0x1f;
            bitsLeft -= 5;
            sb.Append(alphabet[index]);
        }

        return sb.ToString();
    }

    private static Decoded? TryDecodeKey(byte[] data, string cls)
    {
        // Identity blobs sometimes embed a cert first.
        if (cls.Equals("idnt", StringComparison.OrdinalIgnoreCase)
            && TryDecodeCertificate(data, out var cert) && cert is not null)
        {
            return new Decoded(
                Kind.Certificate,
                null, null, null, null, null, null, null, null, null, null, null, null,
                cert.Subject, cert.Issuer, cert.SerialNumber,
                cert.NotBefore.ToUniversalTime().ToString("O"),
                cert.NotAfter.ToUniversalTime().ToString("O"),
                ToPem("CERTIFICATE", cert.RawData),
                cert.GetKeyAlgorithm(), TryCertKeyBits(cert), null,
                "x509-idnt", data.Length);
        }

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportPkcs8PrivateKey(data, out _);
            var pem = ecdsa.ExportPkcs8PrivateKeyPem();
            return new Decoded(
                Kind.KeyMaterial,
                null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null,
                "EC", ecdsa.KeySize, pem, "pkcs8-ec", data.Length);
        }
        catch
        {
            // next
        }

        try
        {
            using var rsa = RSA.Create();
            rsa.ImportPkcs8PrivateKey(data, out _);
            var pem = rsa.ExportPkcs8PrivateKeyPem();
            return new Decoded(
                Kind.KeyMaterial,
                null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null,
                "RSA", rsa.KeySize, pem, "pkcs8-rsa", data.Length);
        }
        catch
        {
            // next
        }

        try
        {
            using var ecdsa = ECDsa.Create();
            ecdsa.ImportECPrivateKey(data, out _);
            var pem = ecdsa.ExportPkcs8PrivateKeyPem();
            return new Decoded(
                Kind.KeyMaterial,
                null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null,
                "EC", ecdsa.KeySize, pem, "sec1-ec", data.Length);
        }
        catch
        {
            // next
        }

        // X9.63 uncompressed P-256/P-384 public (0x04||X||Y) — common for passkeys / WebAuthn.
        if (data.Length is 65 or 97 && data[0] == 0x04)
        {
            return new Decoded(
                Kind.KeyMaterial,
                null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null,
                "EC-pub", data.Length == 65 ? 256 : 384, null, "x963-pub", data.Length);
        }

        if (data[0] == 0x30)
        {
            return new Decoded(
                Kind.KeyMaterial,
                null, null, null, null, null, null, null, null, null, null, null, null,
                null, null, null, null, null, null,
                null, null, null, "asn1-key", data.Length);
        }

        return new Decoded(
            Kind.KeyMaterial,
            null, null, null, null, null, null, null, null, null, null, null, null,
            null, null, null, null, null, null,
            null, null, null, "binary-key", data.Length);
    }

    private static bool TryDecodeCertificate(byte[] data, out X509Certificate2? cert)
    {
        cert = TryLoadCert(data);
        return cert is not null;
    }

    private static X509Certificate2? TryLoadCert(byte[] data)
    {
        try
        {
            return X509CertificateLoader.LoadCertificate(data);
        }
        catch
        {
            // Some items wrap DER in a length-prefixed or PKCS#7 bag — try skip tiny headers.
            for (var skip = 1; skip <= 4 && skip < data.Length; skip++)
            {
                try
                {
                    return X509CertificateLoader.LoadCertificate(data.AsSpan(skip).ToArray());
                }
                catch
                {
                    // next
                }
            }

            return null;
        }
    }

    private static int? TryCertKeyBits(X509Certificate2 cert)
    {
        try
        {
            using var rsa = cert.GetRSAPublicKey();
            if (rsa is not null)
                return rsa.KeySize;
            using var ecdsa = cert.GetECDsaPublicKey();
            if (ecdsa is not null)
                return ecdsa.KeySize;
        }
        catch
        {
            // ignore
        }

        return null;
    }

    private static bool TryParseBplistDict(byte[] data, out Dictionary<string, object?> dict)
    {
        dict = new Dictionary<string, object?>(StringComparer.Ordinal);
        if (data.Length < 8 || !data.AsSpan(0, 6).SequenceEqual("bplist"u8))
            return false;
        if (!AppleBinaryPlist.TryParseDict(data, out var d, out _) || d is null)
            return false;
        dict = d;
        return true;
    }

    private static string? AsUtf8Field(Dictionary<string, object?> d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v is null)
            return null;
        return v switch
        {
            string s => s,
            byte[] b when TryUtf8Secret(b, out var t) => t,
            byte[] b => Encoding.UTF8.GetString(b),
            _ => v.ToString()
        };
    }

    private static string? AsString(Dictionary<string, object?> d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v is null)
            return null;
        return v switch
        {
            string s => s,
            byte[] b when TryUtf8Secret(b, out var t) => t,
            _ => v.ToString()
        };
    }

    private static int? AsInt(Dictionary<string, object?> d, string key)
    {
        if (!d.TryGetValue(key, out var v) || v is null)
            return null;
        return v switch
        {
            int i => i,
            long l => (int)l,
            byte b => b,
            string s when int.TryParse(s, out var n) => n,
            _ => null
        };
    }

    private static string? FormatCardExpiry(Dictionary<string, object?> card)
    {
        var exp = AsString(card, "expirationDate")
                  ?? AsString(card, "expiry")
                  ?? AsString(card, "cardExpiryDate");
        if (!string.IsNullOrEmpty(exp))
            return exp;
        var month = AsString(card, "expirationMonth") ?? AsString(card, "expMonth");
        var year = AsString(card, "expirationYear") ?? AsString(card, "expYear");
        if (!string.IsNullOrEmpty(month) && !string.IsNullOrEmpty(year))
            return $"{month}/{year}";
        return null;
    }

    private static byte[]? TryFromB64OrUtf8(string s)
    {
        try
        {
            return Convert.FromBase64String(s);
        }
        catch
        {
            return Encoding.UTF8.GetBytes(s);
        }
    }

    private static string ToPem(string label, byte[] der)
    {
        var b64 = Convert.ToBase64String(der);
        var sb = new StringBuilder();
        sb.Append("-----BEGIN ").Append(label).AppendLine("-----");
        for (var i = 0; i < b64.Length; i += 64)
            sb.AppendLine(b64.Substring(i, Math.Min(64, b64.Length - i)));
        sb.Append("-----END ").Append(label).AppendLine("-----");
        return sb.ToString();
    }

    private static string? FirstNonEmpty(params string?[] values)
    {
        foreach (var v in values)
        {
            if (!string.IsNullOrWhiteSpace(v))
                return v;
        }

        return null;
    }

    public static string TruncHex(byte[] data, int maxBytes)
    {
        if (data.Length <= maxBytes)
            return Convert.ToHexString(data);
        return Convert.ToHexString(data.AsSpan(0, maxBytes)) + "…";
    }

    public static string? FlattenToJson(object? root)
    {
        try
        {
            return JsonSerializer.Serialize(
                ToJsonable(root, depth: 0),
                new JsonSerializerOptions { WriteIndented = true });
        }
        catch
        {
            return null;
        }
    }

    public static object? ToJsonable(object? value, int depth)
    {
        if (depth > 12 || value is null)
            return null;
        return value switch
        {
            string s => s,
            bool b => b,
            byte[] b => b.Length <= 256
                ? Convert.ToHexString(b)
                : Convert.ToHexString(b.AsSpan(0, 64)) + $"…({b.Length}B)",
            sbyte or byte or short or ushort or int or uint or long or ulong or float or double
                or decimal => value,
            DateTime dt => dt.ToUniversalTime().ToString("O"),
            DateTimeOffset dto => dto.ToUniversalTime().ToString("O"),
            PlistUid uid => $"UID({uid.Value})",
            Dictionary<string, object?> dict => dict.ToDictionary(
                kv => kv.Key,
                kv => ToJsonable(kv.Value, depth + 1)),
            IDictionary<string, object?> idict => idict.ToDictionary(
                kv => kv.Key,
                kv => ToJsonable(kv.Value, depth + 1)),
            object?[] arr => arr.Select(x => ToJsonable(x, depth + 1)).ToArray(),
            System.Collections.IList list => list.Cast<object?>()
                .Select(x => ToJsonable(x, depth + 1)).ToArray(),
            _ => value.ToString()
        };
    }

    public static string DescribeAsn1(byte[] data)
    {
        // Lightweight sniff: SEQUENCE + optional OID peek (not a full decoder).
        if (data.Length < 2 || data[0] != 0x30)
            return $"not-sequence len={data.Length}";
        var oid = TryFindOidString(data);
        return string.IsNullOrEmpty(oid)
            ? $"SEQUENCE len={data.Length}"
            : $"SEQUENCE len={data.Length} oid≈{oid}";
    }

    private static string? TryFindOidString(byte[] data)
    {
        // Look for tag 0x06 (OID) in the first 128 bytes.
        var lim = Math.Min(data.Length - 2, 128);
        for (var i = 0; i < lim; i++)
        {
            if (data[i] != 0x06)
                continue;
            var n = data[i + 1];
            if (n is < 1 or > 32 || i + 2 + n > data.Length)
                continue;
            try
            {
                return FormatOid(data.AsSpan(i + 2, n));
            }
            catch
            {
                // next
            }
        }

        return null;
    }

    private static string FormatOid(ReadOnlySpan<byte> body)
    {
        if (body.IsEmpty)
            return "";
        var first = body[0];
        var parts = new List<int> { first / 40, first % 40 };
        ulong acc = 0;
        for (var i = 1; i < body.Length; i++)
        {
            var b = body[i];
            acc = (acc << 7) | (b & 0x7Fu);
            if ((b & 0x80) == 0)
            {
                parts.Add((int)acc);
                acc = 0;
            }
        }

        return string.Join('.', parts);
    }

    private static Decoded Empty(string kind, int len) => new(
        Kind.Empty,
        null, null, null, null, null, null, null, null, null, null, null, null,
        null, null, null, null, null, null, null, null, null, kind, len);
}
