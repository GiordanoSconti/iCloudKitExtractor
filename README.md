# iCloudKit Extractor

**Public experimental phase** — a WPF (.NET 10) app for iCloud sign-in, device backup listing, and download via CloudKit/MMCS.

> Research / lab software. Not a finished product: undocumented Apple APIs, account-ban risk, no warranty. Use only with **your own** Apple ID and at your own risk.

## About me

My name is **Giordano Sconti**. I collaborate with the forensic laboratory **Forensis-Lab**, and I work as a software researcher as well as a technical consultant (Consulente Tecnico).

This software is released under the **MIT** license, but it **belongs to the Forensis-Lab forensic laboratory**.

This project should be considered **highly experimental**, because Apple’s internal APIs can change overnight.

I am making this project available because it is valuable for forensic work when we must recover—in extreme cases—backups and CloudKit data that are not accessible except through the devices themselves.

Unlike commercial tools I have used, I achieved a **stable and complete download** of my own personal backups both with **ADP enabled and disabled** (of course knowing the device Octagon PIN or the Recovery Key when activated).

It also works when protections such as **Lockdown Mode** are enabled and **iCloud.com** is turned off.

## What’s included

- Main app: `src/iCloudKitExtractor`
- Photo library viewer: `src/PhotosViewer` (copied into `viewer-payload` when IKE builds)
- `AnisetteServer` (+ optional bridge projects) for OTP / ADI
- Setup scripts for emulated akd / bridge
- Docs under `docs/`

## What’s intentionally excluded

- Apple binary dumps / `ios-adi-split`
- Third-party commercial anisette backends
- Lab build artifacts, probes, and capture corpora

## Requirements

- Windows + .NET 10 SDK
- iCloud / Apple Music / iTunes where CoreADI is needed
- A test Apple ID you control

## Build

```powershell
dotnet build src/iCloudKitExtractor/iCloudKitExtractor.csproj -c Release
dotnet run --project src/iCloudKitExtractor/iCloudKitExtractor.csproj -c Release
```

## Anisette with Frida (jailbroken iPhone)

Preferred path for a coherent **iPhone/akd** identity: OTP is minted on-device via Frida → AuthKit/`akd`, then served by `AnisetteServer`.

### 1. Prerequisites (device + PC)

- Jailbroken iPhone with **frida-server** running (USB or Wi‑Fi)
- Matching **frida-tools** version on the PC (`pip install frida-tools`)
- Python 3 available as `python` (or set `FRIDA_ANISETTE_PYTHON`)
- `fetch_anisette.py` (Frida attach script). Set its path with `FRIDA_ANISETTE_FETCH_PY`

> Jailbreak install steps: see **[Preparing a jailbroken iPhone](#preparing-a-jailbroken-iphone)** below (details TBA).

### 2. Environment variables

| Variable | Required | Default | Meaning |
|----------|----------|---------|---------|
| `ANISETTE_SERVER_BACKEND` | **yes** | `coreadi` | Must be `frida` (aliases: `iphone-frida`, `jb-frida`) |
| `ANISETTE_SERVER_URL` / `ANISETTE_SERVER_URLS` | no | `http://127.0.0.1:6969` | URL(s) where AnisetteServer listens |
| `ANISETTE_SERVER_PORT` | no | `6969` | Port if URLs not set |
| `ICLOUD_AUTH_MODE` | recommended | `iphone` (via config) | Use `iphone` for full AuthKit iPhone SRP |
| `FRIDA_ANISETTE_HOST` | no | `127.0.0.1:27042` | frida-server host:port (USB often via `iproxy 27042 27042`) |
| `FRIDA_ANISETTE_PROCESS` | no | `akd` | Process to attach |
| `FRIDA_ANISETTE_FETCH_PY` | **yes*** | heuristic path | Absolute path to `fetch_anisette.py` |
| `FRIDA_ANISETTE_PYTHON` | no | `python` | Python executable |
| `FRIDA_ANISETTE_LITE` | no | `1` / true | Lite attach mode |
| `FRIDA_ANISETTE_TIMEOUT` | no | `60` | Seconds before aborting a mint |

\*Without `FRIDA_ANISETTE_FETCH_PY`, the app only searches a few legacy sibling paths; set the env var explicitly.

Optional app config file: `%AppData%\iCloudKitExtractor\anisette.json` (`authMode`, `serverUrl`). Env vars override the file.

### 3. Start AnisetteServer (Frida backend)

```powershell
$env:ANISETTE_SERVER_BACKEND = "frida"
$env:ANISETTE_SERVER_PORT = "6971"
$env:FRIDA_ANISETTE_HOST = "127.0.0.1:27042"
$env:FRIDA_ANISETTE_PROCESS = "akd"
$env:FRIDA_ANISETTE_FETCH_PY = "C:\path\to\fetch_anisette.py"
$env:FRIDA_ANISETTE_PYTHON = "python"
$env:FRIDA_ANISETTE_LITE = "1"
$env:FRIDA_ANISETTE_TIMEOUT = "60"

dotnet run --project src/AnisetteServer/AnisetteServer.csproj -c Release -- --backend frida --port 6971
```

CLI `--backend` / `--port` override the environment.

Smoke test:

```powershell
curl http://127.0.0.1:6971/health
curl http://127.0.0.1:6971/
```

Expect JSON with machine data (`X-Apple-I-MD-M`, `X-MMe-Client-Info` containing `com.apple.akd`).

### 4. Point IKE at the server

```powershell
$env:ANISETTE_SERVER_URL = "http://127.0.0.1:6971/"
$env:ICLOUD_AUTH_MODE = "iphone"
dotnet run --project src/iCloudKitExtractor/iCloudKitExtractor.csproj -c Release
```

## Preparing a jailbroken iPhone

> **Placeholder** — step-by-step jailbreak / frida-server / USB forwarding instructions will be added here in a follow-up. Until then, ensure frida-server is reachable at `FRIDA_ANISETTE_HOST` and that `akd` is running on the device.

## Other anisette backends

| Backend | Use case | Docs |
|---------|----------|------|
| `frida` | Real iPhone/akd OTP (recommended when available) | This README |
| `akd-emulated` | Software ADI worker (Android libs today; iOS target) | [docs/EMULATED_AKD.md](docs/EMULATED_AKD.md) |
| `coreadi` | Windows CoreADI / AuthKitWin hybrid | [docs/MAC_ANISETTE.md](docs/MAC_ANISETTE.md) |
| Mac Docker + bridge | CGNAT / remote Mac anisette | [docs/ANISETTE_BRIDGE.md](docs/ANISETTE_BRIDGE.md) |

Emulated akd example:

```powershell
.\scripts\setup-emulated-akd.ps1
```

Also see [docs/IPHONE_INTERNAL_FLOW.md](docs/IPHONE_INTERNAL_FLOW.md) and [docs/APPLE_MIDSERVICE_PROVISIONING.md](docs/APPLE_MIDSERVICE_PROVISIONING.md).

## License

MIT — see `LICENSE`. Copyright notice names Giordano Sconti / Forensis-Lab; the project belongs to **Forensis-Lab**.

## Disclaimer

This software talks to Apple services in unofficial ways. Apple may change endpoints at any time. The authors are not responsible for data loss, account suspension, or other damages.
