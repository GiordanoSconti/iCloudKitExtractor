# Anisette and auth modes (reference iPhone vs Docker)

> **Mac behind CGNAT?** See [ANISETTE_BRIDGE.md](ANISETTE_BRIDGE.md) for the bridge tunnel.  
> **Goal: emulated internal akd flow:** [IPHONE_INTERNAL_FLOW.md](IPHONE_INTERNAL_FLOW.md).  
> **Apple MidService protocol:** [APPLE_MIDSERVICE_PROVISIONING.md](APPLE_MIDSERVICE_PROVISIONING.md).

## What real iPhone/akd provisioning looks like

Official Apple provisioning with a consistent **iPhone / akd** identity end-to-end (as seen in live device or MITM reference traffic):

| Field | Reference (example capture) |
|-------|-------------------------|
| `X-MMe-Client-Info` | `<iPhone9,3> … com.apple.akd/1.0>` |
| `X-Apple-I-MD-M` | `SzhEUGjn…` (bound to iOS provisioning) |
| `cpd.capp` | `com.apple.akd` |
| `cpd.prtn` | `iPhone9,3` |

`MD-M`, `MD-LU`, `cpd`, and HTTP headers must **all** belong to the same provisioned iOS identity.

## What dadoum/anisette-v3-server (Docker) does

The Docker container on Mac does **not** replicate iPhone/akd provisioning. It provisions as **Mac / Xcode**:

```json
"X-MMe-Client-Info": "<MacBookPro13,2> <macOS;…> <com.apple.dt.Xcode/…>",
"X-Apple-I-MD-M": "KxBNsHBG…"
```

It is real Apple anisette, but a **Mac** identity, not iPhone/akd.

### Why `authMode: iphone` fails with Docker

With `authMode: iphone` the app sends **akd iPhone** `cpd` and headers, but `MD-M` comes from **Mac** Docker.  
`GsService2 init` may succeed; **`GsService2 complete` → ec=-22410** because Apple checks identity consistency.

**This is not a bridge bug** — it is a mismatch between provisioned identity (Mac) and declared identity (iPhone).

## What works today on Windows

### `hybrid` (default, recommended)

| Step | Profile |
|------|---------|
| SRP init/complete | **AuthKitWin** + CoreADI Windows |
| 2FA validate / authenticate | AuthKitWin |
| ckAppInit | Remote anisette (including Docker) for iPhone headers |

Login and backup work without real iPhone anisette for SRP.

### `iphone` (end-to-end like real akd)

Requires anisette with **iPhone/akd provisioning**, not dadoum docker:

- Omnisette / server exposing `X-MMe-Client-Info` with `com.apple.akd`
- `MD-M` different from Windows **and** identity consistent with akd in the JSON

If the probe detects Mac/Xcode in remote JSON, the app does **not** enable the iphone flow and suggests hybrid.

## Docker setup (hybrid post-login / CloudKit headers only)

```bash
bash scripts/mac/setup-anisette-v3.sh
```

Bridge (CGNAT):

```powershell
.\scripts\start-anisette-bridge-server.ps1
.\scripts\configure-bridge-anisette.ps1 -AuthMode hybrid
```

## Startup verification

```
MD-M Windows: x5VRHo8M…
MD-M remote:  KxBNsHBG…   (≠ Windows, OK for hybrid)
Flow hybrid: SRP/2FA AuthKitWin → ckAppInit iPhone
```

If you see:

```
authMode=iphone but anisette = Mac/Xcode (docker) → not iPhone/akd provisioning
```

→ switch to `authMode: hybrid` in `anisette.json`.

## Troubleshooting

| Symptom | Cause |
|---------|--------|
| `ec=-22410` complete with docker + `authMode: iphone` | Mac MD-M + akd iPhone cpd — use **hybrid** |
| `ec=-22410` init with local `:6969` | CoreADI Windows spoof — use bridge or hybrid |
| Reference iPhone flow works, ours fails in iphone mode | Real akd has integrated iOS provisioning; docker does not |
| Login OK hybrid, backup fails | Check `ckAppInit` and `get_account_settings` / `cloudKitToken` |
