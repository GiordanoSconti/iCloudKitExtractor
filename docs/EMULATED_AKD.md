# Emulated akd — architecture and roadmap

Goal: **reconstruct akd in software** on Windows, generating identity and provisioning **from scratch**, with a **real iPhone** profile (not commercial forensic captures, not Mac, not iCloud CoreADI64).

Live device or reference captures from commercial forensic tools are used only for the **protocol** (request order, cpd fields, HTTP headers). Do not reuse `MD-M`, serial numbers, or other values from those captures.

---

## What akd does on iPhone

```
akd
 ├── MidService HTTP  →  lookup, startMachineProvisioning, finishMachineProvisioning
 ├── CoreADI (iOS)    →  spim→cpim, ptm/tk→adi.pb, OTP (MD / MD-M)
 └── device identity  →  com.apple.akd, iPhone9,3, MD-LU hex, serial
```

Apple binds `MD-M` to the **iOS ADI implementation** used at provisioning time. Correct akd headers are not enough if crypto comes from Windows/Mac/Android.

---

## iCloudKitExtractor architecture (target)

```
┌─────────────────────────────────────────────────────────────┐
│ iCloudKitExtractor — authMode: iphone                        │
│  • GsService2 init/complete (anisette only in cpd, like akd) │
│  • MidService HTTP with akd headers (C# AdiProvisioningService) │
│  • identity in device-ios.json (freshly generated)           │
└──────────────────────────┬──────────────────────────────────┘
                           │ OTP via AnisetteServer :6971
┌──────────────────────────▼──────────────────────────────────┐
│ AnisetteServer (backend=akd-emulated)                        │
│  • No CoreADI64.dll                                          │
│  • HttpAdiCryptoClient → :6973                               │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│ akd_adi_worker.py (:6973) — ADI crypto only                   │
│  • Reads device-ios.json (same identity as C# MidService)     │
│  • Unicorn + libCoreADI (today: Android; target: iOS)         │
└─────────────────────────────────────────────────────────────┘
```

**Rule:** a single identity in `device-ios.json` — used for both MidService (C#) and ADI (worker).

---

## Why Anisette.py on :6971 is not enough

`ios_akd_server.py` (monolithic) uses Anisette.py which:

1. Downloads `libCoreADI.so` / `libstoreservicescore.so` from the **Apple Music Android APK**
2. Explicitly calls `ADISetAndroidID` (does not exist on iOS akd)
3. Runs MidService internally **without** `X-Apple-I-SRL-NO` that C# sends on real akd

Observed result: **init ok, complete `-22410`** — ADI identity is not iPhone class.

---

## Gap to close: iOS ADI libraries

| Stack | Format | Provisioning identity | akd complete |
|-------|---------|----------------------|--------------|
| CoreADI64.dll (iCloud Win) | PE | PC / AuthKitWin | ❌ |
| dadoum / Anisette.py Android | ELF ARM | Android Music | ❌ (init yes) |
| CoreADI.framework (Mac) | Mach-O | Mac | ❌ with akd cpd |
| **CoreADI iOS** (akd) | Mach-O in dyld cache | **iPhone** | ✅ (target) |
| Proprietary forensic binaries | — | tool-specific | ✅ (not a project goal) |

**Next technical step:** replace Android `.so` files in the worker with **CoreADI + StoreServices extracted from an iOS IPSW** (or Xcode Simulator runtime), and a Mach-O loader in Unicorn — or fork Anisette.py with an iOS backend.

Anisette.py today supports **ELF** only (`pyelftools`), not Mach-O.

### iOS library extraction (implemented)

**On Mac** (recommended if you have a Mac):

```bash
# In the repo (clone or copy the folder to Mac)
cd iCloudKitExtractor

# 1) dyld from IPSW (~10–20 min) — copy the IPSW to Mac or mount the Windows folder
bash scripts/mac/extract-dyld-from-ipsw.sh ~/Downloads/iPhone18_2_26.5.2_23F84_Restore.ipsw

# 2a) dyld only → copy dyld_shared_cache_arm64 to Windows, then:
#     .\scripts\extract-ios-adi-libs.ps1 -DscPath "C:\path\dyld_shared_cache_arm64"

# 2b) Full CoreADI extraction on Mac (LIEF), then copy the folder to Windows:
bash scripts/mac/extract-ios-adi-libs.sh ~/ipsw_dyld/.../dyld_shared_cache_arm64
# → copy ~/Library/Application Support/iCloudKitExtractor/ios-adi-libs/
#   to %AppData%\iCloudKitExtractor\ios-adi-libs\
```

**On Windows** (requires `dyld_shared_cache_arm64` already extracted on Mac/Linux/WSL):

```powershell
pip install -r scripts\akd-adi-worker\requirements.txt
.\scripts\extract-ios-adi-libs.ps1 -DscPath "C:\path\dyld_shared_cache_arm64"
```

The `-IpswPath` option on **native Windows does not work** (APFS DMG). Use Mac or WSL2 (`scripts\extract-dyld-via-wsl.ps1`).

**CoreADI not in the main DSC (iOS 18+ / 26):** Apple uses multiple caches (system + Cryptex). `ipsw extract --dyld` must extract **all** `dyld_shared_cache*` files; search with `scripts/mac/find-coreadi-everywhere.sh`. Alternative: **iOS Simulator** from Xcode (CoreADI as a single file in RuntimeRoot).

Output: `%AppData%\iCloudKitExtractor\ios-adi-libs\` with `coreadi.dylib`, `storeservices.dylib`, `manifest.json` (symbol analysis vs Android).

Worker:

| `--backend` | Behavior |
|-------------|---------------|
| `android` (default) | Anisette.py ELF — init ok, complete often `-22410` |
| `ios` | Load Mach-O in Unicorn; bridge blocked until `IOS_ADI_RUNTIME_READY` |
| `auto` | `ios` if manifest present, otherwise `android` |

Files: `scripts/akd-adi-worker/ios_macho_backend.py`, `extract_ios_adi_libs.py`.

**Current blockers (2026-10-13):**

1. **Libraries missing on this PC** — `%AppData%\iCloudKitExtractor\ios-adi-libs` does not exist.
2. **DSC extraction** — `ipsw download --dyld` on Windows downloads the DMG but requires `apfs-fuse` → **WSL2**. WSL is installing; a **reboot** is needed (and firmware virtualization if still off).
3. **Runtime** — `ios_macho_backend.py` now has cdecl invoke + Android-style symbol mapping; `IOS_ADI_RUNTIME_READY` activates only if exports are complete **and** Unicorn init does not crash (Foundation dependencies still need stubbing).

### ADI class fingerprint (reference traffic vs Android worker)

Reference capture `epb_http_20261012_221025` (live iPhone/akd traffic): `MD` = `…AAAAAw==` (trailer **3**), `MD-RINFO` = `17106176`, provisioning client-info = AuthKit/akd iPhone.

| Field | Reference (real iPhone) | Android worker (aligned) |
|-------|-------------------------|----------------------------|
| `MD` trailer u32be | **`3`** | **`3`** (default `AKD_FORCE_OTP_TRAILER`; `native` → 4) |
| `MD-RINFO` | `17106176` | `17106176` |
| Client-Info (ADI) | AuthKit/akd iPhone | same (`IPHONE_AKD_CLIENT_INFO` / `device-*.json`) |
| `MD-M` prefix | `cKAa…` (iOS UID) | still Android prefix (MidService crypto) |

Trailer/RINFO/client-info are aligned on the worker side. The `MD-M` prefix stays tied to Android ADI crypto until MidService uses the iOS/UID path.

### Path A — native Android MidService (`AKD_OWNS_MIDSERVICE=1`) — 2026-10-13

Experiment: MidService again **inside** the Anisette.py lib (no C# SPIM/PTM), trailer `native`, fresh ADI wipe.

| Step | Outcome |
|------|--------|
| `POST /provision` → `anisette-provision` | **FAIL** `KeyError: 'ptm'` (MidService response without PTM; Apple rejects / 433-class) |
| `is-provisioned` | `false` |
| `request-otp` | fail (not provisioned) |

**Conclusion A (first attempt, same identity):** in-lib soft MidService failed with `'ptm'`/433.

**Recovery 2026-10-13:** `AKD_OWNS_MIDSERVICE=1` + `POST /provision?newIdentity=1` → **OK**. OTP alive: `MD-M` Android prefix (`hIFz…`, not `cKAa`), trailer u32be **4**, Client-Info AuthKit iPhone9,3. Soft on the old identity remained burned; `newIdentity` was required.

Android ADI lib source (Anisette.py): `https://anisette.dl.mikealmel.ooo/libs?arch=arm64-v8a` ([malmeloo/Anisette.py](https://github.com/malmeloo/Anisette.py)); alternative Apple Music APK.

### Path B — UID oracle from reference captures → Unicorn iOS

- Env: `AKD_UID_ORACLE_PATH` → 16/32 B key (see `ios_macho_backend._fp_uid_aes_key`).
- Helper: `scripts/akd-adi-worker/harvest_epb_uid_oracle.py` (+ `epb_uid_oracle.x64dbg.txt`).
- Ref capture (non-UID): `%AppData%\iCloudKitExtractor\ios-adi-libs\mdm_epb_ref.bin` / `md_epb_ref.bin`.

### Path B smoke — worker `--backend ios` (2026-10-13)

| Step | Outcome |
|------|--------|
| `ios_runtime_ready` | **true** (Unicorn + StoreServices + FairPlayIOKit_macOS) |
| midStart + `provisioning_start` | OK (CPIM produced) |
| midFinish | **FAIL** HTTP 401 / `ec=-29003` (fake SHA256 UID, oracle absent) |
| `request-otp` | fail `otp_request → 4294922280` (not provisioned on Apple side) |


### Bootstrap (after WSL reboot)

```powershell
# 1) Verify WSL
wsl -e true

# 2) IPSW (already downloading under ios-adi-libs\_work\ipsw\) + dyld + CoreADI
.\scripts\bootstrap-ios-adi.ps1

# 3) If analyze shows android_symbol_hits with rsegvyrt87/qi864985u0:
python scripts\akd-adi-worker\akd_adi_worker.py --backend ios --port 6973
```


---

## Current setup (split C# + worker)

Two processes — akd MidService in C#, crypto in the worker:

```powershell
# Terminal 1 — ADI crypto (6973)
python scripts\akd-adi-worker\akd_adi_worker.py --port 6973

# Terminal 2 — Anisette HTTP for the app (6971)
$env:AKD_ADI_WORKER_URL = "http://127.0.0.1:6973"
$env:ANISETTE_SERVER_BACKEND = "akd-emulated"
dotnet run --project src\AnisetteServer\AnisetteServer.csproj -c Release -- --port 6971

# Terminal 3 — app config
.\scripts\configure-emulated-ios-anisette.ps1 -Port 6971 -AuthMode iphone
```

Or:

```powershell
.\scripts\setup-emulated-akd.ps1
```

Reset provisioning:

```powershell
curl -X POST http://127.0.0.1:6973/provision
Remove-Item -Recurse "$env:APPDATA\iCloudKitExtractor\adi-ios" -ErrorAction SilentlyContinue
```

---

## What NOT to use for this goal

| Path | Reason |
|----------|--------|
| CoreADI64 + spoofed iOS profile | ADI remains Windows |
| dadoum Docker Mac | Mac/Xcode MD-M |
| AOSKit / iTunes ADI Windows | PC / iTunes pairing identity |
| Remote Mac bridge | Mac hardware dependency |
| Copying `MD-M` from forensic captures | tool-specific identity, not generic iPhone |

`authMode: hybrid` remains useful for CloudKit development, but is **not** end-to-end emulated akd.

---

## Emulated iPhone identity checklist

1. `device-ios.json` created fresh (`ProvisioningClientInfo` with `com.apple.akd`)
2. MidService from C# with `X-Apple-I-SRL-NO`, `X-MMe-Client-Info` akd
3. Worker `MD-M` ≠ CoreADI Windows `MD-M`
4. GsService2 POST **without** `X-Apple-I-MD*` on HTTP (cpd only)
5. `GsService2 complete` → `ec=0` (final validation)

---

## Files

| File | Role |
|------|--------|
| `AdiProvisioningService.cs` | akd MidService (C#) |
| `HttpAdiCryptoClient.cs` | bridge to worker |
| `EmulatedAkdAnisetteProvider.cs` | anisette without CoreADI64 |
| `akd_adi_worker.py` | ADI crypto |
| `extract_ios_adi_libs.py` | CoreADI/StoreServices from dyld cache |
| `ios_macho_backend.py` | Unicorn Mach-O loader (WIP) |
| `GsaGrandSlamAuthService.cs` | SRP + akd cpd |
| [APPLE_MIDSERVICE_PROVISIONING.md](APPLE_MIDSERVICE_PROVISIONING.md) | HTTP protocol |
