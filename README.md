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

This project took roughly **seven months of research**. Without Cursor coding-agent models it would have taken far longer: the only time I had was during work hours when possible, or late at night. I tried to keep a **modular** code organization—I hope I succeeded.

If you would like to buy me a coffee, I would rather you **thank Forensis-Lab** or offer some other form of recognition instead.

## Contributing & contact

Anyone who wants to try the software, suggest improvements, or help finish the remaining features is **welcome**.

You may use paid coding-agent models (please avoid free ones—they are often unreliable for code correctness). What matters is that you **always review** the generated code and that there is **no unauthorized appropriation of third-party code** without consent. Pull requests will be reviewed **very carefully**.

Contact: [giordano.sconti@gruppoinformaticiforensi.it](mailto:giordano.sconti@gruppoinformaticiforensi.it)

Every line of code in this project belongs to **Forensis-Lab**, under my direct grant. Any use or modification must remain attributable to **Forensis-Lab**.

## Preview access to Anisette Server

If you want to try the software before running your own anisette stack, contact me **privately** to request access to my Anisette Server.

## Github Page

https://giordanosconti.github.io/iCloudKitExtractor/

## Important note: Recovery Key & Octagon

Recovery Key unlock uses an **Octagon** endpoint that can dump the full set of **encrypted TLKShares**. From those shares it is also possible to recover the ones associated with Recovery Key peers (SHA-384 of the public key that signs the Recovery Key). That allows verifying whether a given Recovery Key is among those present and, if it is, recovering the Manatee/PCS KeySet for CloudKit zones—including **ADP-protected backups** and **Keychain**.

## What’s included

- Main app: `src/iCloudKitExtractor`
- Photo library viewer: `src/PhotosViewer` (copied into `viewer-payload` when IKE builds)
- `AnisetteServer` (+ optional bridge projects) for OTP / ADI
- Setup scripts for emulated akd / bridge
- Docs under `docs/`

## What’s intentionally excluded

- Lab build artifacts, probes, and capture corpora

## Requirements

- Windows + .NET 10 SDK
- A phisical Anisette server (emulated ones not work anymore)
- A test Apple ID you control

## Build

```powershell
dotnet build src/iCloudKitExtractor/iCloudKitExtractor.csproj -c Release
dotnet run --project src/iCloudKitExtractor/iCloudKitExtractor.csproj -c Release
```

## GitHub Pages

A project site lives under [`docs/`](docs/) (`index.html` + `site.css`).

1. Push `main` to GitHub.
2. Repo **Settings → Pages**.
3. Source: **Deploy from a branch**.
4. Branch: `main` / folder: `/docs`.
5. Save — site URL will be similar to `https://giordanosconti.github.io/iCloudKitExtractor/`.

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

Install **Frida** (frida-server) and **OpenSSH** from **Sileo** on the device first.

Assumes a **rootless** jailbreak (`/var/jb/...`). Over SSH as **root**:

```sh
ls -l /var/jb/usr/sbin/frida-server
```

Recreate the LaunchDaemon plist (LF endings, rootless)—no editor needed:

```sh
cat > /var/jb/Library/LaunchDaemons/re.frida.server.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>Label</key>
	<string>re.frida.server</string>
	<key>ProgramArguments</key>
	<array>
		<string>/var/jb/usr/sbin/frida-server</string>
		<string>-l</string>
		<string>0.0.0.0:27042</string>
	</array>
	<key>RunAtLoad</key>
	<true/>
	<key>KeepAlive</key>
	<true/>
	<key>ThrottleInterval</key>
	<integer>3</integer>
</dict>
</plist>
EOF
```

Normalize line endings, convert the plist to binary, then (re)load the daemon:

```sh
tr -d '\r' < /var/jb/Library/LaunchDaemons/re.frida.server.plist > /tmp/frida.plist
mv /tmp/frida.plist /var/jb/Library/LaunchDaemons/re.frida.server.plist
plutil -convert binary1 /var/jb/Library/LaunchDaemons/re.frida.server.plist
killall frida-server 2>/dev/null
launchctl bootout system /var/jb/Library/LaunchDaemons/re.frida.server.plist 2>/dev/null
launchctl bootstrap system /var/jb/Library/LaunchDaemons/re.frida.server.plist
launchctl enable system/re.frida.server
launchctl kickstart -k system/re.frida.server
ps aux | grep '[f]rida-server'
```

This binds **frida-server** on `0.0.0.0:27042` (all interfaces), starts at boot, and keeps it alive. From the PC set e.g. `FRIDA_ANISETTE_HOST=127.0.0.1:27042` after USB port-forward (`iproxy 27042 27042`) or use the device LAN IP.

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

## License & attribution

Released under the **MIT** license (see `LICENSE`). Ownership and attribution remain with **Forensis-Lab** (Giordano Sconti). Downstream use or modification must keep clear attribution to **Forensis-Lab**.

## Disclaimer

This software talks to Apple services in unofficial ways. Apple may change endpoints at any time. The authors are not responsible for data loss, account suspension, or other damages.
