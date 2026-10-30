# Licensed remote Anisette (self-host)

Host your own Anisette HTTP/HTTPS gate with **Package-C** licenses (Ed25519 + SQLite). Useful when friends or lab machines need OTP from **your** jailbroken iPhone Frida stack without sharing the phone. **HTTP remains the default** (no certificates required); HTTPS is optional.

Generate **your own** keys and database. Never commit `keys/` or `data/licenses/`.

## Pieces

| Project | Role |
|---------|------|
| `src/AnisetteLicense` | Ed25519 token + Package-C Base64 bundle + SQLite allowlist |
| `src/AnisetteLicenseGen` | CLI: init-keys / issue / revoke / disable / enable / delete / list |
| `src/AnisetteServer.Licensed` | Anisette HTTP API + Bearer gate (headless) |
| `src/AnisetteServer.Mac` | Avalonia **desktop UI for Windows and macOS** (folder name is historical; output = `AnisetteMiddleware`): Frida host + license panel + Start/Stop |

Unsigned local server remains `src/AnisetteServer` (no license gate).

## Package C (IKE License field)

JSON then standard Base64:

```json
{
  "token": "<payload.sig Ed25519>",
  "public_key": "<Ed25519 public key raw Base64>",
  "license_id": "…",
  "issued_at": 0
}
```

iCloudKit Extractor stores the **entire Base64 blob** in `%AppData%\iCloudKitExtractor\anisette.json` → `license` and sends `Authorization: Bearer <blob>`. The server unwraps `token`, verifies the signature, and checks the SQLite row (`enabled`, not revoked).

## First connection (auto-issue)

1. Client has empty License → sends `X-IKE-Machine-Id`, `X-IKE-Hostname`, `X-IKE-Os`, `X-IKE-App-Instance`.
2. Middleware sees a remote request without Bearer → issues **once** per fingerprint (`emitted_once=1`).
3. Response includes `X-Anisette-License-Bundle` + JSON `license_bundle` **only this once**.
4. IKE fills the License field, saves settings, shows an overlay (copy + “won’t be sent again”).
5. Later requests from the same fingerprint without Bearer → `401 license_already_issued` (no re-send).

## Quick start (keys + issue)

```powershell
dotnet run --project src/AnisetteLicenseGen -- init-keys
dotnet run --project src/AnisetteLicenseGen -- issue --sub "tester@example.com" --days 30
# prints Package-C Base64 — paste into IKE License, or leave empty for auto-issue

dotnet run --project src/AnisetteLicenseGen -- list
dotnet run --project src/AnisetteLicenseGen -- disable --id <license_id>
dotnet run --project src/AnisetteLicenseGen -- enable --id <license_id>
dotnet run --project src/AnisetteLicenseGen -- revoke --id <license_id>
dotnet run --project src/AnisetteLicenseGen -- delete --id <license_id>
```

Paths (override with env): `ANISETTE_LICENSE_ROOT`, `ANISETTE_LICENSE_PRIVATE_KEY`, `ANISETTE_LICENSE_PUBLIC_KEY`, `ANISETTE_LICENSE_DB`.

## Desktop Avalonia middleware (Windows / macOS — Frida → iPhone)

Project path is still `src/AnisetteServer.Mac` for history; the app title and binary are **Anisette Middleware** and run on **both** Windows and macOS.

```bash
dotnet run --project src/AnisetteServer.Mac -c Release
# publish examples:
dotnet publish src/AnisetteServer.Mac -c Release -r win-x64 --self-contained false
dotnet publish src/AnisetteServer.Mac -c Release -r osx-arm64 --self-contained false
```

UI:

- **Server**: Frida host (`192.168.x.y:27042`), process `akd`, Python, listen URLs (`http://0.0.0.0:6971` by default; `https://…` optional), Start/Stop
- **Licenses**: list / disable / enable / remove / manual Package-C issue

Default data root: `%AppData%\ForensisLab\AnisetteMiddleware` on Windows, or `~/Library/Application Support/ForensisLab/AnisetteMiddleware/` on macOS.  
TLS files land in `data/tls/` only when you enable HTTPS.

### HTTP (default) vs HTTPS (optional)

| Mode | How |
|------|-----|
| **HTTP (default)** | `http://0.0.0.0:6971` — no certificates |
| **HTTPS auto** | Listen `https://0.0.0.0:6971` or `ANISETTE_TLS_ENABLE=1` → self-signed under `data/tls/` (SAN: localhost, 127.0.0.1, hostname, **all current machine IPv4/IPv6**) |
| **Custom PFX** | `ANISETTE_TLS_PFX` (+ optional `ANISETTE_TLS_PFX_PASSWORD`) |
| **PEM** | `ANISETTE_TLS_CERT` + `ANISETTE_TLS_KEY` (e.g. Let's Encrypt) |
| **Extra SAN names** | `ANISETTE_TLS_DNS=www.example.com,203.0.113.10` |

Prepare the phone: see [Preparing a jailbroken iPhone](../README.md#preparing-a-jailbroken-iphone) in the README.

## Headless Licensed server

```powershell
$env:ANISETTE_SERVER_BACKEND = "frida"
# default listen = http://0.0.0.0:6971
$env:FRIDA_ANISETTE_HOST = "192.168.x.y:27042"
dotnet run --project src/AnisetteServer.Licensed -- --port 6971

# Optional TLS:
# $env:ANISETTE_TLS_ENABLE = "1"
# or: $env:ANISETTE_SERVER_URLS = "https://0.0.0.0:6971"
```

Auth rules:

- Loopback (`127.0.0.1` / `::1`) → no license
- `GET /health` → public
- Remote mint → Bearer Package-C / token **or** first-connection auto-issue

## Client (IKE)

```powershell
$env:ANISETTE_SERVER_URL = "http://YOUR_HOST:6971"
# Leave License empty once for auto-issue overlay, then keep the Base64
# or: $env:ANISETTE_LICENSE = "<Package-C Base64>"

# If the middleware uses HTTPS:
# $env:ANISETTE_SERVER_URL = "https://YOUR_HOST:6971"
# Public hostname + self-signed: install the .cer, or:
# $env:ANISETTE_TLS_INSECURE = "1"
# $env:ANISETTE_TLS_THUMBPRINT = "<from data/tls/anisette-https.thumbprint>"
# $env:ANISETTE_TLS_CA = "C:\path\to\anisette-https.cer"
```

IKE accepts both `http://` and `https://` server URLs. Loopback / private LAN IPs accept lab self-signed certs automatically when using HTTPS.

## Security notes

- Treat the **private key** and **TLS PFX** like passwords; only the host that issues licenses needs them.
- Do not publish your `keys/` folder, `data/tls/`, SQLite DB, or issued `.license` files.
- Disable or revoke licenses from the Mac UI or `AnisetteLicenseGen` when a tester should lose access.
