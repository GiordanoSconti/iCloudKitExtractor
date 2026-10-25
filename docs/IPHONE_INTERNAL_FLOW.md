# Flusso interno iPhone/akd (emulazione software)

EPB e iOS reale **non** tengono un iPhone collegato in permanenza. Eseguono in locale:

1. **MidService** — HTTP verso `gsa.apple.com` (lookup, start/finish provisioning)
2. **ADI** — crypto `spim→cpim→ptm/tk` e OTP periodico
3. **Anisette** — espone `X-Apple-I-MD` / `X-Apple-I-MD-M` al SRP e CloudKit

Su iPhone tutto gira in `akd` + `StoreServices` + container `adi.pb`. Su Windows dobbiamo **replicare le stesse fasi** con stack emulato.

---

## Mappa fasi akd → componenti

| Fase akd (iOS) | Cosa fa | Emulazione iCloudKitExtractor |
|----------------|---------|-------------------------------|
| Identità device | `X-MMe-Client-Info`, UUID, MD-LU hex, serial | `AnisetteDeviceConfig` / `device-ios.json` |
| Lookup | `GET GsService2/lookup` | `AdiProvisioningService.LoadUrlBagAsync` |
| Start provision | `POST startMachineProvisioning` → `spim` | `AdiProvisioningService.FetchSpimAsync` |
| ADI start | `ADIProvisioningStart(spim)` → `cpim` | CoreAdiBridge **oppure** Anisette.py Unicorn |
| Finish provision | `POST finishMachineProvisioning(cpim)` → `ptm`,`tk` | `AdiProvisioningService.FinishProvisioningAsync` |
| ADI end | `ADIProvisioningEnd(ptm,tk)` → `adi.pb` | CoreAdiBridge **oppure** Anisette.py |
| OTP | `ADIOTPRequest` ogni ~30s | `RequestOtpAsync` / `get_data()` |
| SRP cpd | `capp=com.apple.akd`, `prtn=iPhone9,3`, RINFO `17106176` | `GrandSlamCpdBuilder` + `AdiDeviceProfile.Ios` |
| GsService2 | init/complete con cpd coerente | `GsaGrandSlamAuthService` (`authMode: iphone`) |

**Regola:** header HTTP MidService, stato ADI (`MD-M`) e `cpd` devono essere **la stessa identità**.

---

## Tre backend ADI (scegline uno)

| Backend | Porta tipica | Identità ADI | Uso |
|---------|--------------|--------------|-----|
| **CoreADI Windows** (`AnisetteServer`) | 6969 | PC / AuthKitWin | `hybrid` SRP — **non** EPB akd |
| **Anisette.py iOS/akd** (emulato) | **6971** | akd + ARM emulato | `authMode: iphone` (da testare) |
| **dadoum Docker** | 6969 Mac | Mac/Xcode | solo post-login hybrid |

---

## Setup consigliato: Anisette.py profilo akd

Emula provisioning + ADI + server HTTP come EPB (software-only):

```powershell
# Terminale 1 — server emulato (prima esecuzione: download lib ~3 MB + provision)
.\scripts\setup-emulated-ios-anisette.ps1 -Port 6971

# Terminale 2 — config app
.\scripts\configure-emulated-ios-anisette.ps1 -Port 6971

# Test
curl http://127.0.0.1:6971/
```

Controlla:

- `X-MMe-Client-Info` contiene `com.apple.akd`
- `X-Apple-I-MD-M` **≠** MD-M da CoreADI Windows (`AnisetteCapability` probe)
- `X-Apple-I-MD-RINFO` = `17106176`
- `X-Apple-I-MD-LU` = 16 caratteri hex

Poi login con `authMode: iphone` e verifica `GsService2 complete` → `ec=0`.

### Re-provisioning

```powershell
.\scripts\setup-emulated-ios-anisette.ps1 -Port 6971 -Reset
```

Oppure `POST http://127.0.0.1:6971/provision`.

Stato persistente: `%AppData%\iCloudKitExtractor\anisette-py-ios\`.

---

## Architettura split (come SideStore v3)

```
┌─────────────────────────────────────────┐
│ iCloudKitExtractor                       │
│  AdiProvisioningService (Ios) — HTTP     │  ← opzionale se worker fa tutto
│  GsaGrandSlamAuthService (iphone)        │
│  RemoteAnisetteProvider → :6971         │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│ ios_akd_server.py (Anisette.py)          │
│  ProvisioningSession (header akd)        │
│  Unicorn → libCoreADI.so (ARM64)        │
│  GET / → MD, MD-M, clientInfo            │
└─────────────────────────────────────────┘
```

Anisette.py implementa **tutto il flusso interno** in un processo (come Dadoum/Provision), con `AnisetteDeviceConfig` personalizzabile per akd.

---

## Perché CoreADI Windows non basta

`CoreADI64.dll` (iCloud Store) provisiona come **PC**. Anche con header akd su MidService, `MD-M` resta legato a Windows → `ec=-22410` su complete.

L’emulazione ARM (Anisette.py) usa le **stesse** `.so` dell’APK Apple Music di Dadoum, ma con `clientInfo` **iPhone/akd** prima del primo provision — più vicino al flusso EPB.

**Limite noto:** non è garantito identico a EPB (binari proprietari). Va validato con probe MD-M e SRP complete.

---

## Riferimenti

- [APPLE_MIDSERVICE_PROVISIONING.md](APPLE_MIDSERVICE_PROVISIONING.md) — protocollo HTTP
- [EPB_IOS_ADI.md](EPB_IOS_ADI.md) — obiettivo EPB
- [Anisette.py](https://github.com/malmeloo/Anisette.py) — `AnisetteDeviceConfig`, `ProvisioningSession`
- Capture EPB: `MD-M` `SzhEUGjn…`, `com.apple.akd/1.0`
