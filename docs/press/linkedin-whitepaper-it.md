# LinkedIn — Whitepaper (Italiano)

**Media da allegare (ordine):**

1. `../whitepaper/figures/fig01-catena-end-to-end.png` — catena protocollare  
2. `../whitepaper/figures/fig11-seq-filelist.png` — UML Domain fileList  
3. (opzionale) screenshot prima pagina del PDF  

Link canonici:

- Landing: https://giordanosconti.github.io/iCloudKitExtractor/whitepaper/  
- PDF: https://github.com/GiordanoSconti/iCloudKitExtractor/blob/main/docs/whitepaper/whitepaper-protocolli-backup-octagon-pcs.pdf  
- Release: https://github.com/GiordanoSconti/iCloudKitExtractor/releases/tag/whitepaper-v1.11  
- DOI Zenodo: *(incolla quando disponibile)*  

---

**Prima riga suggerita:**  
Con ADP attivo, «scaricare il backup iCloud» non è una chiamata API: è una catena di protocolli.

---

Ho pubblicato un **technical note** in inglese (whitepaper v1.11) che mappa i **protocolli privati Apple** usati per acquisire i **backup dispositivo iCloud**, con e senza **Advanced Data Protection (ADP)**.

Gli strumenti commerciali spesso si fermano quando **iCloud.com è disabilitato**, c’è **ADP**, o **Lockdown Mode** restringe le superfici client. In quei casi non sei più sull’API web: stai componendo

**GrandSlam / GsService2 → EscrowProxy e/o Octagon–Cuttlefish → CKKS (Manatee / TLKShare) → CloudKit `mbksync` (Lock + Domain `N:` / fileList) → MMCS / PCSMMCS2**

Il documento è descrittivo e orientato alla forensics: tassonomia dei percorsi di recupero (PCS Escrow `dsid:dsid` vs iCDP vs Recovery Key), regole di identità MidService/Anisette, come si recuperano e leggono i **file list** dopo il Lock, disciplina Ford / ChunkInfo. L’Appendice A descrive il metodo senza procedure di elusione.

Nasce dal lavoro di laboratorio su **iCloudKit Extractor** (account autorizzati / mandato).

Leggi / cita:  
Landing → https://giordanosconti.github.io/iCloudKitExtractor/whitepaper/  
PDF + Markdown su GitHub → release `whitepaper-v1.11`  
DOI Zenodo → *(quando live)*

Feedback da colleghi di digital forensics benvenuti.

#digitalforensics #mobileforensics #icloud #ADP #CloudKit #Octagon #opensource #ForensisLab

---

## Checklist

- [ ] Incolla il post (senza checklist)  
- [ ] Allega fig01 + fig11  
- [ ] Commento fissato con landing + DOI  
- [ ] Tag Forensis-Lab se applicabile  
