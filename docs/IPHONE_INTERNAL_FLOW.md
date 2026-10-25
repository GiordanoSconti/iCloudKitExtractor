# Internal iPhone/akd flow (software emulation)

Real iOS and commercial forensic tools **do not** keep an iPhone permanently tethered. They run locally:

1. **MidService** — HTTP to `gsa.apple.com` (lookup, start/finish provisioning)
2. **ADI** — crypto `spim→cpim→ptm/tk` and periodic OTP
3. **Anisette** — exposes `X-Apple-I-MD` / `X-Apple-I-MD-M` to SRP and CloudKit

On iPhone everything runs in `akd` + `StoreServices` + the `adi.pb` container. On Windows we **replicate the same phases** with an emulated stack.

---

## akd phase map → components

| akd phase (iOS) | What it does | iCloudKitExtractor emulation |
|----------------|---------|-------------------------------|
| Device identity | `X-MMe-Client-Info`, UUID, MD-LU hex, serial | `AnisetteDeviceConfig` / `device-ios.json` |
| Lookup | `GET GsService2/lookup` | `AdiProvisioningService.LoadUrlBagAsync` |
| Start provision | `POST startMachineProvisioning` → `spim` | `AdiProvisioningService.FetchSpimAsync` |
| ADI start | `ADIProvisioningStart(spim)` → `cpim` | CoreAdiBridge **or** Anisette.py Unicorn |
| Finish provision | `POST finishMachineProvisioning(cpim)` → `ptm`,`tk` | `AdiProvisioningService.FinishProvisioningAsync` |
| ADI end | `ADIProvisioningEnd(ptm,tk)` → `adi.pb` | CoreAdiBridge **or** Anisette.py |
| OTP | `ADIOTPRequest` every ~30s | `RequestOtpAsync` / `get_data()` |
| SRP cpd | `capp=com.apple.akd`, `prtn=iPhone9,3`, RINFO `17106176` | `GrandSlamCpdBuilder` + `AdiDeviceProfile.Ios` |
| GsService2 | init/complete with consistent cpd | `GsaGrandSlamAuthService` (`authMode: iphone`) |

**Rule:** MidService HTTP headers, ADI state (`MD-M`), and `cpd` must be **the same identity**.

---

## Three ADI backends (pick one)

| Backend | Typical port | ADI identity | Use |
|---------|--------------|--------------|-----|
| **CoreADI Windows** (`AnisetteServer`) | 6969 | PC / AuthKitWin | `hybrid` SRP — **not** emulated akd |
| **Anisette.py iOS/akd** (emulated) | **6971** | akd + emulated ARM | `authMode: iphone` (to be validated) |
| **dadoum Docker** | 6969 Mac | Mac/Xcode | hybrid post-login only |

---

## Recommended setup: Anisette.py akd profile

Emulates provisioning + ADI + HTTP server like real akd (software-only):

```powershell
# Terminal 1 — emulated server (first run: ~3 MB lib download + provision)
.\scripts\setup-emulated-ios-anisette.ps1 -Port 6971

# Terminal 2 — app config
.\scripts\configure-emulated-ios-anisette.ps1 -Port 6971

# Test
curl http://127.0.0.1:6971/
```

Check:

- `X-MMe-Client-Info` contains `com.apple.akd`
- `X-Apple-I-MD-M` **≠** MD-M from CoreADI Windows (`AnisetteCapability` probe)
- `X-Apple-I-MD-RINFO` = `17106176`
- `X-Apple-I-MD-LU` = 16 hex characters

Then login with `authMode: iphone` and verify `GsService2 complete` → `ec=0`.

### Re-provisioning

```powershell
.\scripts\setup-emulated-ios-anisette.ps1 -Port 6971 -Reset
```

Or `POST http://127.0.0.1:6971/provision`.

Persistent state: `%AppData%\iCloudKitExtractor\anisette-py-ios\`.

---

## Split architecture (like SideStore v3)

```
┌─────────────────────────────────────────┐
│ iCloudKitExtractor                       │
│  AdiProvisioningService (Ios) — HTTP     │  ← optional if worker does everything
│  GsaGrandSlamAuthService (iphone)        │
│  RemoteAnisetteProvider → :6971         │
└──────────────────┬──────────────────────┘
                   │
┌──────────────────▼──────────────────────┐
│ ios_akd_server.py (Anisette.py)          │
│  ProvisioningSession (akd headers)        │
│  Unicorn → libCoreADI.so (ARM64)        │
│  GET / → MD, MD-M, clientInfo            │
└─────────────────────────────────────────┘
```

Anisette.py implements the **full internal flow** in one process (like Dadoum/Provision), with customizable `AnisetteDeviceConfig` for akd.

---

## Why CoreADI Windows is not enough

`CoreADI64.dll` (iCloud Store) provisions as **PC**. Even with akd headers on MidService, `MD-M` stays bound to Windows → `ec=-22410` on complete.

ARM emulation (Anisette.py) uses the **same** `.so` files from the Dadoum Apple Music APK, but with **iPhone/akd** `clientInfo` before the first provision — closer to real akd flow.

**Known limit:** not guaranteed identical to proprietary forensic stacks. Validate with MD-M probe and SRP complete.

---

## References

- [APPLE_MIDSERVICE_PROVISIONING.md](APPLE_MIDSERVICE_PROVISIONING.md) — HTTP protocol
- [EMULATED_AKD.md](EMULATED_AKD.md) — emulated akd architecture and roadmap
- [Anisette.py](https://github.com/malmeloo/Anisette.py) — `AnisetteDeviceConfig`, `ProvisioningSession`
- Reference traffic: `MD-M` `SzhEUGjn…`, `com.apple.akd/1.0`
