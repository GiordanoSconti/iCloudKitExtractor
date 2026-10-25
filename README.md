# iCloudKit Extractor

**Fase sperimentale pubblica** — WPF (.NET 10) per login iCloud, elenco backup dispositivi e download tramite CloudKit/MMCS.

> Progetto di ricerca / laboratorio. Non è un prodotto finito: API Apple non documentate, rischio di ban account, assenza di garanzia. Usalo solo sul **tuo** Apple ID e a tuo rischio.

## Cosa include

- App principale `src/iCloudKitExtractor`
- `AnisetteServer` (+ bridge opzionali) per OTP / ADI
- Script di setup emulazione akd / bridge
- Documentazione in `docs/`

## Cosa non include (di proposito)

- Dump binari Apple / `ios-adi-split`
- Backend anisette di terze parti commerciali
- Artefatti di build, probe e capture di laboratorio

## Requisiti

- Windows + .NET 10 SDK
- iCloud / Apple Music / iTunes (DLL CoreADI, dove necessario)
- Account Apple ID di test

## Build

```powershell
dotnet build src/iCloudKitExtractor/iCloudKitExtractor.csproj -c Release
dotnet run --project src/iCloudKitExtractor/iCloudKitExtractor.csproj -c Release
```

Anisette (esempio akd emulato):

```powershell
.\scripts\setup-emulated-akd.ps1
```

Vedi anche `docs/EMULATED_AKD.md`, `docs/MAC_ANISETTE.md`, `docs/ANISETTE_BRIDGE.md`.

## Licenza

MIT — vedi `LICENSE`.

## Disclaimer

Questo software interagisce con servizi Apple in modi non ufficialmente supportati. Apple può modificare gli endpoint in qualsiasi momento. Gli autori non sono responsabili di perdite di dati, sospensioni account o altri danni.
