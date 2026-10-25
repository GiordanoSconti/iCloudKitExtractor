# LinkedIn — Italiano

**Titolo suggerito (prima riga opzionale):**  
Sette mesi da un backup ADP che non riuscivamo a scaricare — a un toolkit forense sperimentale pubblico.

---

A marzo 2026 avevamo un’esigenza concreta: recuperare un **backup iCloud di dispositivo protetto da Advanced Data Protection (ADP)**. I tool forensi commerciali, in quel momento, non ci bastavano.

Da lì, insieme a un collega e nel contesto di **Forensis-Lab**, ho iniziato a trattare le API private Apple non come una scatola nera, ma come superficie da osservare. È nato così **iCloudKit Extractor**: prima una domanda operativa (“come parlano davvero le API dietro la sezione iCloud di Impostazioni?”), poi mesi di reverse engineering.

Ho aperto una **fase sperimentale pubblica** su GitHub (licenza MIT, attribuzione a Forensis-Lab). È software di ricerca .NET/WPF per autenticazione iCloud, download CloudKit/MMCS e percorsi Octagon/PCS quando si dispone del PIN dispositivo o della Recovery Key. **Non** è un prodotto finito: le API private di Apple possono cambiare da un giorno all’altro.

Sul sito del progetto ho iniziato anche un diario di ricerca. Le prime quattro giornate:

1. **25 mar** — Necessità ADP; EPB + iPhone jailbroken; idmsa vs GrandSlam mobile; la zona vera è `mbksync` in `com.apple.backup.ios`.
2. **11 apr** — Lista snapshot; EPB con iOS 26 ma ancora **403** con ADP; `backupProperties` / UDID ancora opachi.
3. **29 apr** — Prepare Restore Session e **Lock** CloudKit; Foreground hw/sha; Frida + “fossili” EPB; `Invalid lock id`.
4. **24 mag** — Primi passi in **MMCS** e range su edge-content (chiavi Ford vs chunk data); più avanti l’assurdo di un nibble (`0x04` vs `0xC4`).

Se lavori in informatica forense / mobile extraction e vuoi ispezionare, criticare o testare con attenzione: star e issue motivate valgono più dei like.

Repo: https://github.com/GiordanoSconti/iCloudKitExtractor  
Notes: https://giordanosconti.github.io/iCloudKitExtractor/blog/  
Contatto: giordano.sconti@gruppoinformaticiforensi.it

#informaticaforense #ios #icloud #cloudkit #opensource #forensics #dotnet

---

**Suggerimenti:** allega uno screenshot della pagina Notes o delle Release firmate; tagga Forensis-Lab se esiste la page aziendale; nei commenti pinna il link al Day 1.
