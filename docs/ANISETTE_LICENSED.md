# Licensed remote Anisette (self-host)

Host your own Anisette HTTP gate with **Package-C** licenses (Ed25519 + SQLite). Useful when friends or lab machines need OTP from **your** jailbroken iPhone Frida stack without sharing the phone.

Generate **your own** keys and database. Never commit `keys/` or `data/licenses/`.

## Pieces

| Project | Role |
|---------|------|
| `src/AnisetteLicense` | Ed25519 token + Package-C Base64 bundle + SQLite allowlist |
| `src/AnisetteLicenseGen` | CLI: init-keys / issue / revoke / disable / enable / delete / list |
| `src/AnisetteServer.Licensed` | Anisette HTTP API + Bearer gate (headless) |
| `src/AnisetteServer.Mac` | Avalonia UI (macOS-friendly): Frida host config + license panel + Start/Stop |

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

## Mac Avalonia middleware (Frida → iPhone)

```bash
dotnet run --project src/AnisetteServer.Mac -c Release
# publish example:
dotnet publish src/AnisetteServer.Mac -c Release -r osx-arm64 --self-contained false
```

UI:

- **Server**: Frida host (`192.168.x.y:27042`), process `akd`, Python, listen URLs (`http://0.0.0.0:6971`), Start/Stop
- **Licenses**: list / disable / enable / remove / manual Package-C issue

Default data root: `~/Library/Application Support/ForensisLab/AnisetteMiddleware/` (or `%AppData%\ForensisLab\AnisetteMiddleware` on Windows).

Prepare the phone: see [Preparing a jailbroken iPhone](../README.md#preparing-a-jailbroken-iphone) in the README.

## Headless Licensed server

```powershell
$env:ANISETTE_SERVER_BACKEND = "frida"
$env:ANISETTE_SERVER_URLS = "http://0.0.0.0:6971"
$env:FRIDA_ANISETTE_HOST = "192.168.x.y:27042"
dotnet run --project src/AnisetteServer.Licensed -- --port 6971
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
```

## Security notes

- Treat the **private key** like a password; only the host that issues licenses needs it.
- Do not publish your `keys/` folder, SQLite DB, or issued `.license` files.
- Disable or revoke licenses from the Mac UI or `AnisetteLicenseGen` when a tester should lose access.
