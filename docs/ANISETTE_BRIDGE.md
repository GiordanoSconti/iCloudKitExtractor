# Anisette Bridge (CGNAT → public Windows IP)

When the Mac is behind **CGNAT** (e.g. Vodafone Station) and Windows has a **public IP + port forwarding**, the Mac cannot receive inbound connections. The **bridge client** on the Mac connects **outbound** to the bridge server on Windows; the app only talks to `http://127.0.0.1:6970` locally.

```
iCloudKitExtractor ──HTTP──► Bridge Server (Windows :6970 local)
                                    │
                              TCP :6971 (public IP, port-forward)
                                    │
                                    ▼ (outbound connection)
                            Bridge Client (Mac)
                                    │
                              HTTP :6969
                                    ▼
                         Docker anisette-v3
```

Windows does **not** use CoreADI or a local AnisetteServer in this scenario.

## 1. On the Mac — Docker anisette

```bash
sed -i '' $'s/\r$//' setup-anisette-v3.sh   # if copied from Windows
bash ./setup-anisette-v3.sh
curl -s http://127.0.0.1:6969/ | head -c 200
```

## 2. On Windows — bridge server

```powershell
.\scripts\start-anisette-bridge-server.ps1
```

On first run this creates `%AppData%\iCloudKitExtractor\bridge-token.txt`.

**Router (port forwarding):**

| External | Internal | Protocol |
|---------|---------|------------|
| `6971` | Windows PC IP `:6971` | TCP |

Windows Firewall: allow inbound TCP **6971**.

The server exposes:

| Port | Bind | Use |
|-------|------|-----|
| `6971` | `0.0.0.0` | Mac client (internet) |
| `6970` | `127.0.0.1` | Local app only |

## 3. On the Mac — bridge client

Copy the token from Windows (`%AppData%\iCloudKitExtractor\bridge-token.txt`).

**If you copied scripts from the PC (`bash\r` or `pipefail^M` errors):**

```bash
sed -i '' $'s/\r$//' setup-anisette-v3.sh start-anisette-bridge-client.sh
chmod +x *.sh
```

Or: `bash fix-line-endings.sh setup-anisette-v3.sh start-anisette-bridge-client.sh`

```bash
export ANISETTE_BRIDGE_SERVER_HOST="STATIC_PUBLIC_WINDOWS_IP"
export ANISETTE_BRIDGE_TOKEN="paste-token-from-bridge-token.txt"
bash start-anisette-bridge-client.sh
```

Expected output: `Registered — waiting for fetch commands…`

## 4. Configure the app

```powershell
.\scripts\configure-bridge-anisette.ps1 -AuthMode iphone
```

Or edit `%AppData%\iCloudKitExtractor\anisette.json`:

```json
{
  "serverUrl": "http://127.0.0.1:6970",
  "authMode": "iphone"
}
```

## 5. Verify

```powershell
Invoke-RestMethod http://127.0.0.1:6970/health
# clientConnected: true

.\scripts\configure-bridge-anisette.ps1 -TestOnly
```

When starting iCloudKitExtractor: remote `MD-M` differs from Windows `MD-M`, iPhone flow active.

## Protocol (TCP newline JSON)

1. Mac → `register` + token + `anisetteUrl`
2. Windows → `registered` ok
3. Windows → `fetch` + id (on HTTP GET `/` request)
4. Mac → GET local docker → `fetchResult` + anisette JSON body

## Troubleshooting

| Problem | Solution |
|----------|-----------|
| `No Mac client connected` | Client not running, wrong token, port-forward 6971 |
| `Invalid token` | Align `ANISETTE_BRIDGE_TOKEN` on Mac/Windows |
| `Timeout 30s` | Docker anisette stopped on Mac |
| MD-M probe same as Windows | Still using local `:6969`, use bridge `:6970` |

## Environment variables

**Server (Windows):**

- `ANISETTE_BRIDGE_TOKEN` — required
- `ANISETTE_BRIDGE_TCP_PORT` — default `6971`
- `ANISETTE_BRIDGE_HTTP_PORT` — default `6970`

**Client (Mac):**

- `ANISETTE_BRIDGE_SERVER_HOST` — Windows public IP
- `ANISETTE_BRIDGE_SERVER_PORT` — default `6971`
- `ANISETTE_BRIDGE_TOKEN` — same as server
- `ANISETTE_LOCAL_URL` — default `http://127.0.0.1:6969/`

## Publishing Mac client (optional)

```bash
dotnet publish src/AnisetteBridge.Client/AnisetteBridge.Client.csproj -c Release -r osx-arm64 --self-contained
# output in src/AnisetteBridge.Client/bin/Release/net10.0/osx-arm64/publish/
```
