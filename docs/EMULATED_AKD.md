# akd emulato — architettura e roadmap

Obiettivo: **ricostruire akd in software** su Windows, generando identità e provisioning **da zero**, con profilo **iPhone reale** (non EPB, non Mac, non CoreADI64 iCloud).

Le capture EPB servono solo per il **protocollo** (ordine richieste, campi cpd, header HTTP). Non vanno riusati `MD-M`, serial o altri valori di EPB.

---

## Cosa fa akd su iPhone

```
akd
 ├── MidService HTTP  →  lookup, startMachineProvisioning, finishMachineProvisioning
 ├── CoreADI (iOS)    →  spim→cpim, ptm/tk→adi.pb, OTP (MD / MD-M)
 └── identità device  →  com.apple.akd, iPhone9,3, MD-LU hex, serial
```

Apple lega `MD-M` alla **implementazione ADI iOS** usata al provisioning. Header akd corretti non bastano se la crypto viene da Windows/Mac/Android.

---

## Architettura iCloudKitExtractor (target)

```
┌─────────────────────────────────────────────────────────────┐
│ iCloudKitExtractor — authMode: iphone                        │
│  • GsService2 init/complete (anisette solo nel cpd, come EPB) │
│  • MidService HTTP con header akd (C# AdiProvisioningService) │
│  • identità in device-ios.json (generata fresh)               │
└──────────────────────────┬──────────────────────────────────┘
                           │ OTP via AnisetteServer :6971
┌──────────────────────────▼──────────────────────────────────┐
│ AnisetteServer (backend=akd-emulated)                        │
│  • Nessun CoreADI64.dll                                      │
│  • HttpAdiCryptoClient → :6973                               │
└──────────────────────────┬──────────────────────────────────┘
                           │
┌──────────────────────────▼──────────────────────────────────┐
│ akd_adi_worker.py (:6973) — solo crypto ADI                   │
│  • Legge device-ios.json (stessa identità del MidService C#)  │
│  • Unicorn + libCoreADI (oggi: Android; target: iOS)          │
└─────────────────────────────────────────────────────────────┘
```

**Regola:** una sola identità in `device-ios.json` — usata sia per MidService (C#) sia per ADI (worker).

---

## Perché Anisette.py su :6971 non basta

`ios_akd_server.py` (monolitico) usa Anisette.py che:

1. Scarica `libCoreADI.so` / `libstoreservicescore.so` dall’**APK Apple Music Android**
2. Chiama esplicitamente `ADISetAndroidID` (non esiste su akd iOS)
3. Fa MidService internamente **senza** `X-Apple-I-SRL-NO` che C# invia su akd reale

Risultato osservato: **init ok, complete `-22410`** — identità ADI non è classe iPhone.

---

## Gap da colmare: lib ADI iOS

| Stack | Formato | Identità provisioning | complete akd |
|-------|---------|----------------------|--------------|
| CoreADI64.dll (iCloud Win) | PE | PC / AuthKitWin | ❌ |
| dadoum / Anisette.py Android | ELF ARM | Android Music | ❌ (init sì) |
| CoreADI.framework (Mac) | Mach-O | Mac | ❌ con cpd akd |
| **CoreADI iOS** (akd) | Mach-O in dyld cache | **iPhone** | ✅ (target) |
| EPB binari proprietari | — | emulato EPB | ✅ (non obiettivo) |

**Prossimo passo tecnico:** sostituire le `.so` Android nel worker con **CoreADI + StoreServices estratti da IPSW iOS** (o runtime Simulator Xcode), e un loader Mach-O in Unicorn — oppure fork Anisette.py con backend iOS.

Anisette.py oggi supporta solo **ELF** (`pyelftools`), non Mach-O.

### Estrazione lib iOS (implementato)

**Su Mac** (consigliato se hai il Mac):

```bash
# Nel repo (clona o copia la cartella su Mac)
cd iCloudKitExtractor

# 1) dyld dall'IPSW (~10–20 min) — copia l'IPSW su Mac o monta la cartella Windows
bash scripts/mac/extract-dyld-from-ipsw.sh ~/Downloads/iPhone18_2_26.5.2_23F84_Restore.ipsw

# 2a) Solo dyld → copia dyld_shared_cache_arm64 su Windows, poi:
#     .\scripts\extract-ios-adi-libs.ps1 -DscPath "C:\path\dyld_shared_cache_arm64"

# 2b) Estrazione completa CoreADI su Mac (LIEF), poi copia la cartella su Windows:
bash scripts/mac/extract-ios-adi-libs.sh ~/ipsw_dyld/.../dyld_shared_cache_arm64
# → copia ~/Library/Application Support/iCloudKitExtractor/ios-adi-libs/
#   in %AppData%\iCloudKitExtractor\ios-adi-libs\
```

**Su Windows** (serve già il file `dyld_shared_cache_arm64` estratto su Mac/Linux/WSL):

```powershell
pip install -r scripts\akd-adi-worker\requirements.txt
.\scripts\extract-ios-adi-libs.ps1 -DscPath "C:\path\dyld_shared_cache_arm64"
```

L'opzione `-IpswPath` su **Windows nativo non funziona** (DMG APFS). Usa Mac o WSL2 (`scripts\extract-dyld-via-wsl.ps1`).

**CoreADI non nel DSC principale (iOS 18+ / 26):** Apple usa più cache (system + Cryptex). `ipsw extract --dyld` deve estrarre **tutti** i file `dyld_shared_cache*`; cercare con `scripts/mac/find-coreadi-everywhere.sh`. Alternativa: **iOS Simulator** da Xcode (CoreADI come file singolo nel RuntimeRoot).

Output: `%AppData%\iCloudKitExtractor\ios-adi-libs\` con `coreadi.dylib`, `storeservices.dylib`, `manifest.json` (analisi simboli vs Android).

Worker:

| `--backend` | Comportamento |
|-------------|---------------|
| `android` (default) | Anisette.py ELF — init ok, complete spesso `-22410` |
| `ios` | Carica Mach-O in Unicorn; bridge bloccato finché `IOS_ADI_RUNTIME_READY` |
| `auto` | `ios` se manifest presente, altrimenti `android` |

File: `scripts/akd-adi-worker/ios_macho_backend.py`, `extract_ios_adi_libs.py`.

**Blocco attuale (2026-10-13):**

1. **Lib assenti su questo PC** — `%AppData%\iCloudKitExtractor\ios-adi-libs` non esiste.
2. **Estrazione DSC** — `ipsw download --dyld` su Windows scarica il DMG ma richiede `apfs-fuse` → **WSL2**. WSL è in installazione; serve **riavvio** (e virtualizzazione firmware se ancora off).
3. **Runtime** — `ios_macho_backend.py` ora ha invoke cdecl + mapping simboli Android-style; `IOS_ADI_RUNTIME_READY` si attiva solo se export completi **e** init Unicorn non crasha (dipendenze Foundation ancora da stubbare).

### Fingerprint classe ADI (EPB vs Android worker)

Capture EPB `epb_http_20261012_221025`: `MD` = `…AAAAAw==` (trailer **3**), `MD-RINFO` = `17106176`, provisioning client-info = AuthKit/akd iPhone.

| Campo | EPB RealMobile | Worker Android (allineato) |
|-------|----------------|----------------------------|
| `MD` trailer u32be | **`3`** | **`3`** (default `AKD_FORCE_OTP_TRAILER`; `native` → 4) |
| `MD-RINFO` | `17106176` | `17106176` |
| Client-Info (ADI) | AuthKit/akd iPhone | stesso (`IPHONE_AKD_CLIENT_INFO` / `device-*.json`) |
| `MD-M` prefix | `cKAa…` (UID iOS) | ancora prefisso Android (crypto MidService) |

Il trailer/RINFO/client-info sono allineati lato worker. Il prefisso `MD-M` resta legato alla crypto ADI Android finché MidService non usa path iOS/UID.

### Path A — MidService Android nativo (`AKD_OWNS_MIDSERVICE=1`) — 2026-10-13

Esperimento: MidService di nuovo **nella lib** Anisette.py (no C# SPIM/PTM), trailer `native`, wipe ADI fresco.

| Step | Esito |
|------|--------|
| `POST /provision` → `anisette-provision` | **FAIL** `KeyError: 'ptm'` (risposta MidService senza PTM; Apple rifiuta / 433-class) |
| `is-provisioned` | `false` |
| `request-otp` | fail (non provisionata) |

**Conclusione A (primo tentativo, stessa identity):** soft MidService in-lib falliva con `'ptm'`/433.

**Ripristino 2026-10-13:** `AKD_OWNS_MIDSERVICE=1` + `POST /provision?newIdentity=1` → **OK**. OTP vivo: `MD-M` prefisso Android (`hIFz…`, non `cKAa`), trailer u32be **4**, Client-Info AuthKit iPhone9,3. Soft sulla identity vecchia restava bruciata; serviva newIdentity.

Origine lib Android ADI (Anisette.py): `https://anisette.dl.mikealmel.ooo/libs?arch=arm64-v8a` ([malmeloo/Anisette.py](https://github.com/malmeloo/Anisette.py)); alternativa APK Apple Music.

### Path B — UID oracle EPB → Unicorn iOS

- Env: `AKD_UID_ORACLE_PATH` → 16/32 B chiave (vedi `ios_macho_backend._fp_uid_aes_key`).
- Helper: `scripts/akd-adi-worker/harvest_epb_uid_oracle.py` (+ `epb_uid_oracle.x64dbg.txt`).
- Ref capture (non-UID): `%AppData%\iCloudKitExtractor\ios-adi-libs\mdm_epb_ref.bin` / `md_epb_ref.bin`.

### Path B smoke — worker `--backend ios` (2026-10-13)

| Step | Esito |
|------|--------|
| `ios_runtime_ready` | **true** (Unicorn + StoreServices + FairPlayIOKit_macOS) |
| midStart + `provisioning_start` | OK (CPIM prodotto) |
| midFinish | **FAIL** HTTP 401 / `ec=-29003` (UID fake SHA256, oracle assente) |
| `request-otp` | fail `otp_request → 4294922280` (non provisionata lato Apple) |


### Bootstrap (dopo reboot WSL)

```powershell
# 1) Verifica WSL
wsl -e true

# 2) IPSW (già in download sotto ios-adi-libs\_work\ipsw\) + dyld + CoreADI
.\scripts\bootstrap-ios-adi.ps1

# 3) Se analyze mostra android_symbol_hits con rsegvyrt87/qi864985u0:
python scripts\akd-adi-worker\akd_adi_worker.py --backend ios --port 6973
```


---

## Setup attuale (split C# + worker)

Due processi — MidService akd in C#, crypto nel worker:

```powershell
# Terminale 1 — ADI crypto (6973)
python scripts\akd-adi-worker\akd_adi_worker.py --port 6973

# Terminale 2 — Anisette HTTP per l'app (6971)
$env:AKD_ADI_WORKER_URL = "http://127.0.0.1:6973"
$env:ANISETTE_SERVER_BACKEND = "akd-emulated"
dotnet run --project src\AnisetteServer\AnisetteServer.csproj -c Release -- --port 6971

# Terminale 3 — config app
.\scripts\configure-emulated-ios-anisette.ps1 -Port 6971 -AuthMode iphone
```

Oppure:

```powershell
.\scripts\setup-emulated-akd.ps1
```

Reset provisioning:

```powershell
curl -X POST http://127.0.0.1:6973/provision
Remove-Item -Recurse "$env:APPDATA\iCloudKitExtractor\adi-ios" -ErrorAction SilentlyContinue
```

---

## Cosa NON usare per questo obiettivo

| Percorso | Motivo |
|----------|--------|
| CoreADI64 + profilo iOS spoof | ADI resta Windows |
| dadoum Docker Mac | MD-M Mac/Xcode |
| AOSKit / iTunes adi Windows | identità PC/collegamento iTunes |
| Bridge Mac remoto | dipendenza hardware Mac |
| Copiare MD-M da EPB | identità EPB, non iPhone generico |

`authMode: hybrid` resta utile per sviluppo CloudKit, ma **non** è akd emulato end-to-end.

---

## Checklist identità iPhone emulata

1. `device-ios.json` creato fresh (`ProvisioningClientInfo` con `com.apple.akd`)
2. MidService da C# con `X-Apple-I-SRL-NO`, `X-MMe-Client-Info` akd
3. `MD-M` worker ≠ `MD-M` CoreADI Windows
4. GsService2 POST **senza** `X-Apple-I-MD*` su HTTP (solo cpd)
5. `GsService2 complete` → `ec=0` (validazione finale)

---

## File

| File | Ruolo |
|------|--------|
| `AdiProvisioningService.cs` | MidService akd (C#) |
| `HttpAdiCryptoClient.cs` | bridge verso worker |
| `EmulatedAkdAnisetteProvider.cs` | anisette senza CoreADI64 |
| `akd_adi_worker.py` | crypto ADI |
| `extract_ios_adi_libs.py` | CoreADI/StoreServices da dyld cache |
| `ios_macho_backend.py` | loader Mach-O Unicorn (WIP) |
| `GsaGrandSlamAuthService.cs` | SRP + cpd akd |
| [APPLE_MIDSERVICE_PROVISIONING.md](APPLE_MIDSERVICE_PROVISIONING.md) | protocollo HTTP |
