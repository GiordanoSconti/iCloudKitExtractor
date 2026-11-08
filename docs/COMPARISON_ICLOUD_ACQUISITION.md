# Matrice acquisizione iCloud (Windows)

**Data:** 8 novembre 2026 · **Autore:** Giordano Sconti (Experimental Lab / Forensis-Lab)  
**Scopo:** confrontare cosa fanno davvero gli strumenti rispetto alla pipeline di **iCloudKit Extractor (IKE)** — non una brochure marketing.

## Metro di misura (IKE)

| Step | Cosa significa |
|------|----------------|
| Auth | Apple ID + HSA2/2FA con identità Anisette coerente |
| CloudKit | Autorizzazione container/zone backup (non solo web UI) |
| MMCS | Download chunk backup e ricostruzione layout iTunes-like |
| ADP / Octagon | Percorsi PIN trusted device / Recovery Key → TLKShares / PCS |
| Sync Data | Zone CloudKit sincronizzate (Photos, Notes, …) oltre al device backup |
| Lab / OSS | Codice ispezionabile, build Windows, senza licenza LE |

## Legenda

| Simbolo | Significato |
|---------|-------------|
| **Sì** | Supporto dichiarato **e** documentato / verificabile su Windows |
| **Parziale** | Funziona su subset (iOS più vecchi, no ADP, solo sync, ecc.) |
| **Claim** | Feature di prodotto dichiarata; dettaglio protocollo non pubblico |
| **No** | Assente o esplicitamente non disponibile |
| **Lab** | Sperimentale / fragile / dipende da Anisette o chiavi in possesso |
| **?** | Non verificato in lab indipendente a questa data |

> Apple cambia i protocolli spesso. Questa matrice è uno **snapshot**. Rivedere dopo ogni major iOS.

## Matrice

| Capacità | **IKE** (OSS) | **Elcomsoft Phone Breaker Forensic** | **Magnet AXIOM / Cyber** | **Cellebrite UFED Cloud / PA** | **Oxygen Cloud Extractor** |
|----------|---------------|--------------------------------------|---------------------------|--------------------------------|------------------------------|
| Piattaforma Windows | **Sì** | **Sì** | **Sì** | **Sì** | **Sì** |
| Licenza / modello | MIT · lab | Commerciale Forensic | Commerciale LE/eDisc | Commerciale LE | Commerciale |
| Codice / protocollo pubblico | **Sì** | No | No | No | No |
| Download **device backup** iCloud | **Lab** (CloudKit→MMCS) | **Sì** (pipeline proprietaria; iOS 26 preliminare in EPB 11.2) | **Claim** / Parziale storico | **Claim** | **Claim** |
| Ricostruzione backup tipo iTunes | **Sì** (obiettivo IKE) | **Sì** | **Claim** | **Claim** | **Claim** |
| Backup post-cambio iOS 26+ | **Lab** (in evoluzione col protocollo) | **Sì** preliminare (unico vendor che lo documenta in pubblico, giu 2026) | **?** | **?** | **?** |
| ADP-enabled backup | **Lab** (serve PIN Octagon o Recovery Key) | **Parziale / ?** (E2EE sync spesso “n/a”; backup ADP dipende da edizione/release) | **Claim** (Cyber: passcode trusted device) | **Claim** (credenziali / Account Package; no Security Keys) | **?** |
| Anisette / identità device-like | **Lab** (Frida/akd o middleware) | Interno proprietario | Interno | Interno | Interno |
| Escrow bottle / Octagon / TLKShares | **Lab** (esposto in UI/tooling) | Non documentato come API aperte | Non documentato | Non documentato | Non documentato |
| iCloud Photos | **Parziale** (Sync Data / PhotosViewer) | **Sì** | **Sì** (artifact) | **Claim** | **Claim** |
| iCloud Drive / file extra | **Parziale** (probe) | **Sì** (Forensic) | **Claim** | **Claim** | **Claim** |
| Messages / Health E2EE sync | **Lab / Parziale** | **No** (EPB: currently n/a) | **?** | **?** | **?** |
| Keychain iCloud | **Lab / limitato** | **No** (currently n/a su EPB) | **?** | **?** | **?** |
| Token auth da iCloud for Windows | Non focus IKE | **Sì** | **?** | **?** | **?** |
| Parsing artifact post-acquisizione | BackupViewer / PhotosViewer (lab) | Integrato + export | **Forte** (AXIOM Analyze) | **Forte** (PA) | **Forte** |
| Reportistica case LE | No (lab) | Media | **Forte** | **Forte** | **Forte** |
| Costo tipico | Gratis (runtime/lab) | Licenza Forensic | Licenza suite | Licenza LE alta | Licenza suite |

## Lettura operativa

1. **Se ti serve un prodotto LE “chiavi in mano”** con supporto e report: Elcomsoft / Magnet / Cellebrite / Oxygen — non IKE.
2. **Se ti serve capire e pilotare CloudKit → MMCS su Windows**, con ADP quando hai PIN/RK: IKE è oggi l’unico stack **open** in quella nicchia; EPB è il riferimento **commerciale** più vicino e l’unico che ha scritto pubblicamente la riscrittura post-iOS 26.
3. **“iCloud backup” in brochure ≠ CloudKit/MMCS completo.** Chiedi sempre: iOS target, ADP on/off, Windows host, esito su backup multi-GB, e se il risultato è un tree iTunes utilizzabile.
4. **Open source storico** (`iloot`, script MBS): legacy pre-CloudKit moderno — non va in questa matrice come peer di IKE/EPB.

## Fonti pubbliche (non esaustive)

- Elcomsoft Phone Breaker product / editions: https://www.elcomsoft.com/eppb.html/
- Elcomsoft — iOS 26 backups (18 giu 2026): https://blog.elcomsoft.com/2026/06/downloading-ios-26-icloud-backups/
- Magnet AXIOM Cyber 8.7 ADP backups: https://www.magnetforensics.com/blog/magnet-axiom-cyber-8-7-icloud-adp-and-more/
- Cellebrite UFED Cloud 7.61 ADP note: https://cellebrite.com/en/productupdates/now-available-cellebrite-physical-analyzer-logical-analyzer-reader-and-ufed-cloud-v7-61/
- IKE docs / diary: https://giordanosconti.github.io/iCloudKitExtractor/

## Disclaimer

Uso solo su account/dispositivi autorizzati. IKE è software sperimentale. Le celle **Claim** / **?** non sono accuse: sono limiti di trasparenza del mercato chiuso. Aggiornare questa pagina quando un vendor pubblica dettagli verificabili o quando IKE cambia capacità.
