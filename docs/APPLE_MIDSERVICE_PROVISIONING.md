# Apple GrandSlam — MidService provisioning (anisette reale)

Riferimenti: [Dadoum/Provision](https://github.com/Dadoum/Provision) (`lib/provision/adi.d`), capture EPB/MITM, [TCD privacy paper](https://www.scss.tcd.ie/Doug.Leith/pubs/apple_google_additional_material.pdf) (iPhone `akd`).

EPB e iOS reale usano questo flusso **prima** di generare `X-Apple-I-MD` / `X-Apple-I-MD-M`. Non è documentazione ufficiale Apple; è ricostruita da traffico e da `libstoreservicescore` (ADI).

---

## Panoramica

```
lookup (url bag)
    → startMachineProvisioning  → spim
    → [locale] ADIProvisioningStart(spim) → cpim + session
    → finishMachineProvisioning(cpim) → ptm, tk, X-Apple-I-MD-RINFO
    → [locale] ADIProvisioningEnd(ptm, tk)
    → [locale] ADIOTPRequest → X-Apple-I-MD (OTP) + machine id bytes
```

Dopo il provisioning, `MD-M` è **stabile** (machine identifier); `MD` cambia a ogni `ADIOTPRequest` (~30s).

**dsId** per GrandSlam / iCloud: `-2` (`GrandSlamDsId` nel codice).

---

## 1. `GET` `GsService2/lookup`

Ottiene il **url bag** (`urls` nel plist).

### Request headers (es. iPhone akd — TCD / EPB)

| Header | Esempio iPhone reale |
|--------|----------------------|
| `User-Agent` | `akd/1.0 CFNetwork/1128.0.1 Darwin/19.6.0` |
| `X-MMe-Client-Info` | `<iPhone10,4> <…> <com.apple.akd/1.0 (com.apple.akd/1.0)>` |
| `X-Mme-Device-Id` | UUID persistente dispositivo |
| `X-Apple-I-MD-LU` | Local user UUID (hex su iOS, base64 su Windows AuthKit) |
| `X-Apple-Client-App-Name` | `Setup` |
| `X-Apple-I-Client-Time` | ISO8601 UTC |

### Response (`urls` rilevanti)

| Chiave bag | URL |
|------------|-----|
| `midStartProvisioning` | `https://gsa.apple.com/grandslam/MidService/startMachineProvisioning` |
| `midFinishProvisioning` | `https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning` |
| `syncMachine` | `https://gsa.apple.com/grandslam/MidService/syncMachine` |

---

## 2. `POST` `startMachineProvisioning`

**Metodo: POST** (non GET). Body plist con `Request` vuoto.

### Request body

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Header</key>
  <dict/>
  <key>Request</key>
  <dict/>
</dict>
</plist>
```

### Request headers (iPhone reale)

Come lookup, più:

| Header | Note |
|--------|------|
| `X-Apple-I-SRL-NO` | **Serial hardware** (es. `C8PVCB1HJC67`) — presente su device iOS reali |
| `Content-Type` | `application/x-www-form-urlencoded` (AuthKit; body resta plist XML) |

### Response (`Response` dict)

| Chiave | Tipo | Uso |
|--------|------|-----|
| `spim` | string (base64) | Server Provisioning Intermediate Metadata → `ADIProvisioningStart` |

---

## 3. Locale — `ADIProvisioningStart`

Input: `spim` (bytes), `dsId` (-2).

Output:

| Campo | Uso |
|-------|-----|
| `cpim` | Client Provisioning Intermediate Metadata (base64 in finish) |
| `session` | Handle sessione ADI (uint) |

Implementazione: `CoreAdiBridge.exe start-provisioning` / `libstoreservicescore.so` su Linux.

---

## 4. `POST` `finishMachineProvisioning`

### Request body

```xml
<plist version="1.0">
<dict>
  <key>Header</key>
  <dict/>
  <key>Request</key>
  <dict>
    <key>cpim</key>
    <string>{base64(cpim)}</string>
  </dict>
</dict>
</plist>
```

### Response (`Response` dict)

| Chiave | Tipo | Uso |
|--------|------|-----|
| `ptm` | string (base64) | Persistent Token Metadata → `ADIProvisioningEnd` |
| `tk` | string (base64) | Trust Key → `ADIProvisioningEnd` |
| `X-Apple-I-MD-RINFO` | string | Routing info (es. `17106176` iOS, `84215040` Windows) |

### Errori ADI comuni

| Codice | Significato |
|--------|-------------|
| `-45061` | Non provisionato |
| `-45063` | Sessione pending |
| `-45066` | Sessione già completata |

---

## 5. Locale — `ADIProvisioningEnd` + OTP

Dopo `endProvisioning`, opzionale `set-routing` con `X-Apple-I-MD-RINFO`.

`ADIOTPRequest(dsId)` restituisce bytes OTP + machine identifier; il bridge li espone come:

| Header HTTP | Ruolo |
|-------------|--------|
| `X-Apple-I-MD` | OTP (cambia spesso) |
| `X-Apple-I-MD-M` | Machine ID (stabile, base64) |
| `X-Apple-I-MD-RINFO` | Routing |

Su iOS reale, `X-Apple-I-MD-M` in HTTP è la codifica base64 del machine identifier ADI (≈60 byte).

---

## 6. `syncMachine` (ri-sincronizzazione)

Per dispositivi già provisionati (es. dopo reset parziale). Flusso:

1. `POST syncMachine` → `sim` (server intermediate metadata)
2. `ADISynchronize(dsId, sim)` → `srm` + machine id
3. Eventuale nuovo ciclo finish con metadata aggiornato

EPB referenzia `syncMachine` e `finishMachineProvisioning` nel binario; il traffico HTTP MITM di EPB non sempre li cattura (provisioning può avvenire prima del login visibile).

---

## Identità EPB vs Docker

| | EPB / iPhone akd | dadoum docker |
|--|------------------|---------------|
| `X-MMe-Client-Info` | `<iPhone9,x> … akd` | `<MacBookPro…> … Xcode` |
| Provisioning headers | `akd/1.0 CFNetwork…` | stesso stack Mac |
| `MD-M` | Coerente con akd | Coerente con Mac/Xcode |
| Uso in `cpd` GsService2 akd | ✓ | ✗ (mismatch su complete) |

Per **flow EPB** serve provisioning con **client info akd** e libreria ADI che accetta quell’identità. Il progetto espone:

- `AdiProvisioningService` — chiamate HTTP Apple + `CoreAdiBridge`
- profilo `AdiDeviceProfile.Ios` — header akd su MidService
- `AnisetteServer` profilo iOS — `POST /provision` per forzare re-provisioning

---

## In questo repo

| File | Ruolo |
|------|--------|
| `AdiProvisioningService.cs` | lookup → start → finish → bridge |
| `CoreAdiBridgeClient.cs` | start/end/otp via `CoreAdiBridge.exe` |
| `AdiDeviceProfile.cs` | Windows vs iOS (akd) client info |
| `%AppData%\iCloudKitExtractor\adi-ios\` | Stato provisioning iOS |

### Re-provisioning iOS (test)

```powershell
# Rimuovi stato iOS e riavvia AnisetteServer
Remove-Item -Recurse -Force "$env:APPDATA\iCloudKitExtractor\adi-ios" -ErrorAction SilentlyContinue
dotnet run --project src\AnisetteServer\iCloudKitExtractor.AnisetteServer.csproj -c Release
# POST http://127.0.0.1:6969/provision
```

Verifica JSON `GET /`: `X-MMe-Client-Info` deve contenere `akd`, non `Xcode`.

---

## GsService2 (login) — dopo anisette

Separate dal MidService; usano lo stesso `cpd` con `MD`/`MD-M`/`MD-LU`:

| Step | `o` | Campi principali |
|------|-----|------------------|
| init | `init` | `A2k`, `u`, `cpd`, `ps` |
| complete | `complete` | `M1`, `c`, `cpd` (+ opz. `M2`) |

`cpd` akd EPB: `capp=com.apple.akd`, `prtn=iPhone9,3`, `X-Apple-I-MD-RINFO=17106176`.

Riferimento implementazione: `GsaGrandSlamAuthService.cs`, capture `epb_http_*`.
