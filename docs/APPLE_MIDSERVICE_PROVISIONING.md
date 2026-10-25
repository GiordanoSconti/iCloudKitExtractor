# Apple GrandSlam — MidService provisioning (real anisette)

References: [Dadoum/Provision](https://github.com/Dadoum/Provision) (`lib/provision/adi.d`), live device / MITM reference captures, [TCD privacy paper](https://www.scss.tcd.ie/Doug.Leith/pubs/apple_google_additional_material.pdf) (iPhone `akd`).

Real iOS and reference traffic use this flow **before** generating `X-Apple-I-MD` / `X-Apple-I-MD-M`. This is not official Apple documentation; it is reconstructed from traffic and from `libstoreservicescore` (ADI).

---

## Overview

```
lookup (url bag)
    → startMachineProvisioning  → spim
    → [local] ADIProvisioningStart(spim) → cpim + session
    → finishMachineProvisioning(cpim) → ptm, tk, X-Apple-I-MD-RINFO
    → [local] ADIProvisioningEnd(ptm, tk)
    → [local] ADIOTPRequest → X-Apple-I-MD (OTP) + machine id bytes
```

After provisioning, `MD-M` is **stable** (machine identifier); `MD` changes on each `ADIOTPRequest` (~30s).

**dsId** for GrandSlam / iCloud: `-2` (`GrandSlamDsId` in code).

---

## 1. `GET` `GsService2/lookup`

Fetches the **url bag** (`urls` in the plist).

### Request headers (e.g. iPhone akd — TCD / reference traffic)

| Header | Real iPhone example |
|--------|----------------------|
| `User-Agent` | `akd/1.0 CFNetwork/1128.0.1 Darwin/19.6.0` |
| `X-MMe-Client-Info` | `<iPhone10,4> <…> <com.apple.akd/1.0 (com.apple.akd/1.0)>` |
| `X-Mme-Device-Id` | Persistent device UUID |
| `X-Apple-I-MD-LU` | Local user UUID (hex on iOS, base64 on Windows AuthKit) |
| `X-Apple-Client-App-Name` | `Setup` |
| `X-Apple-I-Client-Time` | ISO8601 UTC |

### Response (relevant `urls`)

| Bag key | URL |
|------------|-----|
| `midStartProvisioning` | `https://gsa.apple.com/grandslam/MidService/startMachineProvisioning` |
| `midFinishProvisioning` | `https://gsa.apple.com/grandslam/MidService/finishMachineProvisioning` |
| `syncMachine` | `https://gsa.apple.com/grandslam/MidService/syncMachine` |

---

## 2. `POST` `startMachineProvisioning`

**Method: POST** (not GET). Plist body with empty `Request`.

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

### Request headers (real iPhone)

Same as lookup, plus:

| Header | Notes |
|--------|------|
| `X-Apple-I-SRL-NO` | **Hardware serial** (e.g. `C8PVCB1HJC67`) — present on real iOS devices |
| `Content-Type` | `application/x-www-form-urlencoded` (AuthKit; body remains plist XML) |

### Response (`Response` dict)

| Key | Type | Use |
|--------|------|-----|
| `spim` | string (base64) | Server Provisioning Intermediate Metadata → `ADIProvisioningStart` |

---

## 3. Local — `ADIProvisioningStart`

Input: `spim` (bytes), `dsId` (-2).

Output:

| Field | Use |
|-------|-----|
| `cpim` | Client Provisioning Intermediate Metadata (base64 in finish) |
| `session` | ADI session handle (uint) |

Implementation: `CoreAdiBridge.exe start-provisioning` / `libstoreservicescore.so` on Linux.

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

| Key | Type | Use |
|--------|------|-----|
| `ptm` | string (base64) | Persistent Token Metadata → `ADIProvisioningEnd` |
| `tk` | string (base64) | Trust Key → `ADIProvisioningEnd` |
| `X-Apple-I-MD-RINFO` | string | Routing info (e.g. `17106176` iOS, `84215040` Windows) |

### Common ADI errors

| Code | Meaning |
|--------|-------------|
| `-45061` | Not provisioned |
| `-45063` | Session pending |
| `-45066` | Session already completed |

---

## 5. Local — `ADIProvisioningEnd` + OTP

After `endProvisioning`, optional `set-routing` with `X-Apple-I-MD-RINFO`.

`ADIOTPRequest(dsId)` returns OTP bytes + machine identifier; the bridge exposes them as:

| HTTP header | Role |
|-------------|--------|
| `X-Apple-I-MD` | OTP (changes often) |
| `X-Apple-I-MD-M` | Machine ID (stable, base64) |
| `X-Apple-I-MD-RINFO` | Routing |

On real iOS, `X-Apple-I-MD-M` in HTTP is the base64 encoding of the ADI machine identifier (~60 bytes).

---

## 6. `syncMachine` (re-synchronization)

For already provisioned devices (e.g. after partial reset). Flow:

1. `POST syncMachine` → `sim` (server intermediate metadata)
2. `ADISynchronize(dsId, sim)` → `srm` + machine id
3. Optional new finish cycle with updated metadata

Reference binaries mention `syncMachine` and `finishMachineProvisioning`; MITM captures do not always include them (provisioning may occur before visible login).

---

## iPhone/akd reference vs Docker

| | iPhone akd (reference) | dadoum docker |
|--|------------------|---------------|
| `X-MMe-Client-Info` | `<iPhone9,x> … akd` | `<MacBookPro…> … Xcode` |
| Provisioning headers | `akd/1.0 CFNetwork…` | same Mac stack |
| `MD-M` | Consistent with akd | Consistent with Mac/Xcode |
| Use in akd GsService2 `cpd` | ✓ | ✗ (mismatch on complete) |

For an **end-to-end akd flow** you need provisioning with **akd client info** and an ADI library that accepts that identity. The project provides:

- `AdiProvisioningService` — Apple HTTP calls + `CoreAdiBridge`
- `AdiDeviceProfile.Ios` profile — akd headers on MidService
- `AnisetteServer` iOS profile — `POST /provision` to force re-provisioning

---

## In this repo

| File | Role |
|------|--------|
| `AdiProvisioningService.cs` | lookup → start → finish → bridge |
| `CoreAdiBridgeClient.cs` | start/end/otp via `CoreAdiBridge.exe` |
| `AdiDeviceProfile.cs` | Windows vs iOS (akd) client info |
| `%AppData%\iCloudKitExtractor\adi-ios\` | iOS provisioning state |

### iOS re-provisioning (test)

```powershell
# Remove iOS state and restart AnisetteServer
Remove-Item -Recurse -Force "$env:APPDATA\iCloudKitExtractor\adi-ios" -ErrorAction SilentlyContinue
dotnet run --project src\AnisetteServer\iCloudKitExtractor.AnisetteServer.csproj -c Release
# POST http://127.0.0.1:6969/provision
```

Verify JSON from `GET /`: `X-MMe-Client-Info` must contain `akd`, not `Xcode`.

---

## GsService2 (login) — after anisette

Separate from MidService; uses the same `cpd` with `MD`/`MD-M`/`MD-LU`:

| Step | `o` | Main fields |
|------|-----|------------------|
| init | `init` | `A2k`, `u`, `cpd`, `ps` |
| complete | `complete` | `M1`, `c`, `cpd` (+ optional `M2`) |

akd reference `cpd`: `capp=com.apple.akd`, `prtn=iPhone9,3`, `X-Apple-I-MD-RINFO=17106176`.

Implementation reference: `GsaGrandSlamAuthService.cs`, reference captures `epb_http_*` (filename prefix retained in tooling).
