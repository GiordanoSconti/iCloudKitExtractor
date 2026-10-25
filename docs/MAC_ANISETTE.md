# Anisette e modalità auth (EPB vs Docker)

> **Mac dietro CGNAT?** Vedi [ANISETTE_BRIDGE.md](ANISETTE_BRIDGE.md) per il tunnel bridge.  
> **Obiettivo EPB (emulazione flusso interno akd):** [IPHONE_INTERNAL_FLOW.md](IPHONE_INTERNAL_FLOW.md) · [EPB_IOS_ADI.md](EPB_IOS_ADI.md).  
> **Protocollo Apple MidService:** [APPLE_MIDSERVICE_PROVISIONING.md](APPLE_MIDSERVICE_PROVISIONING.md).

## Cosa fa EPB (reale)

EPB usa **provisioning Apple ufficiale** con identità **iPhone / akd** coerente end-to-end:

| Campo | EPB (esempio capture) |
|-------|-------------------------|
| `X-MMe-Client-Info` | `<iPhone9,3> … com.apple.akd/1.0>` |
| `X-Apple-I-MD-M` | `SzhEUGjn…` (legato al provisioning iOS) |
| `cpd.capp` | `com.apple.akd` |
| `cpd.prtn` | `iPhone9,3` |

`MD-M`, `MD-LU`, `cpd` e header HTTP devono essere **tutti** della stessa identità iOS provisionata.

## Cosa fa dadoum/anisette-v3-server (Docker)

Il container Docker su Mac **non** replica EPB. Provisiona come **Mac / Xcode**:

```json
"X-MMe-Client-Info": "<MacBookPro13,2> <macOS;…> <com.apple.dt.Xcode/…>",
"X-Apple-I-MD-M": "KxBNsHBG…"
```

È anisette Apple reale, ma identità **Mac**, non iPhone/akd.

### Perché `authMode: iphone` fallisce con Docker

Con `authMode: iphone` l'app invia `cpd` e header **akd iPhone**, ma `MD-M` arriva dal Docker **Mac**.  
`GsService2 init` può passare; **`GsService2 complete` → ec=-22410** perché Apple verifica la coerenza identità.

**Non è un bug del bridge** — è un mismatch tra identità provisionata (Mac) e identità dichiarata (iPhone).

## Cosa funziona oggi su Windows

### `hybrid` (default, consigliato)

| Step | Profilo |
|------|---------|
| SRP init/complete | **AuthKitWin** + CoreADI Windows |
| 2FA validate / authenticate | AuthKitWin |
| ckAppInit | Anisette remota (anche Docker) per header iPhone |

Login e backup funzionano senza anisette iPhone reale per il SRP.

### `iphone` (come EPB end-to-end)

Richiede anisette con **provisioning iPhone/akd**, non dadoum docker:

- Omnisette / server che espone `X-MMe-Client-Info` con `com.apple.akd`
- `MD-M` diverso da Windows **e** identità coerente con akd nel JSON

Se il probe rileva Mac/Xcode nel JSON remoto, l'app **non** attiva il flow iphone e suggerisce hybrid.

## Setup Docker (solo per hybrid post-login / header CloudKit)

```bash
bash scripts/mac/setup-anisette-v3.sh
```

Bridge (CGNAT):

```powershell
.\scripts\start-anisette-bridge-server.ps1
.\scripts\configure-bridge-anisette.ps1 -AuthMode hybrid
```

## Verifica all'avvio

```
MD-M Windows: x5VRHo8M…
MD-M remoto:  KxBNsHBG…   (≠ Windows, OK per hybrid)
Flow hybrid: SRP/2FA AuthKitWin → ckAppInit iPhone
```

Se vedi:

```
authMode=iphone ma anisette = Mac/Xcode (docker) → non è EPB
```

→ passa a `authMode: hybrid` in `anisette.json`.

## Troubleshooting

| Sintomo | Causa |
|---------|--------|
| `ec=-22410` complete con docker + `authMode: iphone` | MD-M Mac + cpd akd iPhone — usa **hybrid** |
| `ec=-22410` init con `:6969` locale | CoreADI Windows spoof — usa bridge o hybrid |
| EPB funziona, noi no in iphone | EPB ha provisioning iOS integrato; docker no |
| Login OK hybrid, backup fallisce | Controlla `ckAppInit` e `get_account_settings` / `cloudKitToken` |
