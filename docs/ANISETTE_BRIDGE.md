# Anisette Bridge (CGNAT → IP pubblico Windows)

Quando il Mac è dietro **CGNAT** (Vodafone Station) e Windows ha **IP pubblico + port forwarding**, il Mac non può ricevere connessioni in entrata. Il **client bridge** sul Mac si connette in **uscita** al server bridge su Windows; l’app parla solo con `http://127.0.0.1:6970` in locale.

```
iCloudKitExtractor ──HTTP──► Bridge Server (Windows :6970 locale)
                                    │
                              TCP :6971 (IP pubblico, port-forward)
                                    │
                                    ▼ (connessione in uscita)
                            Bridge Client (Mac)
                                    │
                              HTTP :6969
                                    ▼
                         Docker anisette-v3
```

Windows **non** usa CoreADI né AnisetteServer locale in questo scenario.

## 1. Sul Mac — Docker anisette

```bash
sed -i '' $'s/\r$//' setup-anisette-v3.sh   # se copiato da Windows
bash ./setup-anisette-v3.sh
curl -s http://127.0.0.1:6969/ | head -c 200
```

## 2. Sul Windows — bridge server

```powershell
.\scripts\start-anisette-bridge-server.ps1
```

Alla prima esecuzione crea `%AppData%\iCloudKitExtractor\bridge-token.txt`.

**Router (port forwarding):**

| Esterno | Interno | Protocollo |
|---------|---------|------------|
| `6971` | IP PC Windows `:6971` | TCP |

Firewall Windows: consenti inbound TCP **6971**.

Il server espone:

| Porta | Bind | Uso |
|-------|------|-----|
| `6971` | `0.0.0.0` | Client Mac (internet) |
| `6970` | `127.0.0.1` | Solo app locale |

## 3. Sul Mac — bridge client

Copia il token da Windows (`%AppData%\iCloudKitExtractor\bridge-token.txt`).

**Se hai copiato gli script dal PC (errore `bash\r` o `pipefail^M`):**

```bash
sed -i '' $'s/\r$//' setup-anisette-v3.sh start-anisette-bridge-client.sh
chmod +x *.sh
```

Oppure: `bash fix-line-endings.sh setup-anisette-v3.sh start-anisette-bridge-client.sh`

```bash
export ANISETTE_BRIDGE_SERVER_HOST="IP_PUBBLICO_STATICO_WINDOWS"
export ANISETTE_BRIDGE_TOKEN="incolla-token-da-bridge-token.txt"
bash start-anisette-bridge-client.sh
```

Output atteso: `Registrato — in attesa di comandi fetch…`

## 4. Configura l’app

```powershell
.\scripts\configure-bridge-anisette.ps1 -AuthMode iphone
```

Oppure `%AppData%\iCloudKitExtractor\anisette.json`:

```json
{
  "serverUrl": "http://127.0.0.1:6970",
  "authMode": "iphone"
}
```

## 5. Verifica

```powershell
Invoke-RestMethod http://127.0.0.1:6970/health
# clientConnected: true

.\scripts\configure-bridge-anisette.ps1 -TestOnly
```

All’avvio iCloudKitExtractor: `MD-M remoto` diverso da `MD-M Windows`, flow iPhone attivo.

## Protocollo (TCP newline JSON)

1. Mac → `register` + token + `anisetteUrl`
2. Windows → `registered` ok
3. Windows → `fetch` + id (su richiesta HTTP GET `/`)
4. Mac → GET docker locale → `fetchResult` + body JSON anisette

## Troubleshooting

| Problema | Soluzione |
|----------|-----------|
| `Nessun client Mac connesso` | Client non avviato, token errato, port-forward 6971 |
| `Token non valido` | Allinea `ANISETTE_BRIDGE_TOKEN` Mac/Windows |
| `Timeout 30s` | Docker anisette spento sul Mac |
| Probe MD-M uguale a Windows | Stai ancora usando `:6969` locale, usa `:6970` bridge |

## Variabili d’ambiente

**Server (Windows):**

- `ANISETTE_BRIDGE_TOKEN` — obbligatorio
- `ANISETTE_BRIDGE_TCP_PORT` — default `6971`
- `ANISETTE_BRIDGE_HTTP_PORT` — default `6970`

**Client (Mac):**

- `ANISETTE_BRIDGE_SERVER_HOST` — IP pubblico Windows
- `ANISETTE_BRIDGE_SERVER_PORT` — default `6971`
- `ANISETTE_BRIDGE_TOKEN` — uguale al server
- `ANISETTE_LOCAL_URL` — default `http://127.0.0.1:6969/`

## Pubblicazione client Mac (opzionale)

```bash
dotnet publish src/AnisetteBridge.Client/AnisetteBridge.Client.csproj -c Release -r osx-arm64 --self-contained
# bin in src/AnisetteBridge.Client/bin/Release/net10.0/osx-arm64/publish/
```
