# LinkedIn — Italiano

**Media da allegare (già pronti in `docs/press/assets/`):**

1. `linkedin-github-repo.png` — repo pubblico GitHub  
2. `linkedin-app-ike.png` — eseguibile WPF avviato (scheda Accesso / Non autenticato)

Ordine consigliato nel post: prima GitHub, poi l’app.

---

**Titolo suggerito (prima riga opzionale):**  
Sette mesi da un backup ADP che non riuscivamo a scaricare — a un toolkit forense sperimentale pubblico.

---

A marzo 2026 avevamo un’esigenza concreta: recuperare un **backup iCloud di dispositivo protetto da Advanced Data Protection (ADP)**. I tool forensi commerciali, in quel momento, non ci bastavano.

Da lì, insieme a un collega e nel contesto di **Forensis-Lab**, ho iniziato a trattare le API private Apple non come una scatola nera, ma come superficie da osservare. È nato così **iCloudKit Extractor**: prima una domanda operativa (“come parlano davvero le API dietro la sezione iCloud di Impostazioni?”), poi mesi di reverse engineering.

Ho aperto una **fase sperimentale pubblica** su GitHub (licenza MIT, attribuzione a Forensis-Lab). È software di ricerca .NET/WPF per autenticazione iCloud, download CloudKit/MMCS e percorsi Octagon/PCS quando si dispone del PIN dispositivo o della Recovery Key. **Non** è un prodotto finito: le API private di Apple possono cambiare da un giorno all’altro.

Sul sito del progetto ho pubblicato un diario di ricerca (Notes). L’arco, in sintesi:

1. **25 mar** — Necessità ADP; EPB + iPhone jailbroken; idmsa vs GrandSlam mobile; la zona vera è `mbksync` in `com.apple.backup.ios`.
2. **11 apr** — Lista snapshot; EPB con iOS 26 ma ancora **403** con ADP; `backupProperties` / UDID ancora opachi.
3. **29 apr** — Prepare Restore Session e **Lock** CloudKit; Foreground hw/sha; Frida + “fossili” EPB; `Invalid lock id`.
4. **24 mag** — Primi passi in **MMCS** e range su edge-content (chiavi Ford vs chunk data).
5. **16 giu** — **IKM** da `contents.protectionInfo` (zone master) prima che Ford abbia senso.
6. **10 lug** — Ford vs ChunkInfo: forzature, poi cache `.chunks`/checksum21 quando i dati arrivano dopo.
7. **4 ago** — Il fulcro `0x04` vs `0xC4`; file orfani CloudKit; modelli (es. Mozilla) cifrati fuori protocollo Apple.
8. **28 ago** — Layout stile iTunes: `Backup/xx/fileID`, `Manifest.db`, sidecars.
9. **5 ott** — **Octagon**: bottle iCDP legate ai PIN dei device già trusted → KeySet.
10. **24 ott** — Recovery Key → peer Octagon → dump **TLKShares** quando la bottle PIN non c’è.

Se lavori in informatica forense / mobile extraction e vuoi ispezionare, criticare o testare con attenzione: star e issue motivate valgono più dei like.

Repo: https://github.com/GiordanoSconti/iCloudKitExtractor  
Notes: https://giordanosconti.github.io/iCloudKitExtractor/blog/  
Release firmata (Forensis-Lab Trusted Signing): https://github.com/GiordanoSconti/iCloudKitExtractor/releases  
Contatto: giordano.sconti@gruppoinformaticiforensi.it

#informaticaforense #ios #icloud #cloudkit #octagon #opensource #forensics #dotnet #ForensisLab

---

## Checklist pubblicazione

- [ ] Copia il testo sopra (senza questa checklist) nel composer LinkedIn  
- [ ] Allega `linkedin-github-repo.png` e `linkedin-app-ike.png`  
- [ ] Tagga Forensis-Lab se esiste la page aziendale  
- [ ] Nei commenti pinna Day 1: https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-03-25-day-01-adp-necessity.html  
- [ ] (Opzionale) Secondo post IT più corto che punta solo a Notes + release
