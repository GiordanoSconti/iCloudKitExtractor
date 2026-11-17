# LinkedIn — Whitepaper (English)

**Media to attach (order):**

1. `../whitepaper/figures/fig01-catena-end-to-end.png` — protocol chain  
2. `../whitepaper/figures/fig11-seq-filelist.png` — Domain fileList UML  
3. (optional) PDF cover / first page screenshot from the whitepaper PDF  

Canonical links after publish:

- Landing: https://giordanosconti.github.io/iCloudKitExtractor/whitepaper/  
- PDF: https://github.com/GiordanoSconti/iCloudKitExtractor/blob/main/docs/whitepaper/whitepaper-protocolli-backup-octagon-pcs.pdf  
- Release: https://github.com/GiordanoSconti/iCloudKitExtractor/releases/tag/whitepaper-v1.11  
- Zenodo DOI: *(paste when available)*  

---

**Suggested first line:**  
When ADP is on, “download the iCloud backup” is not one API call — it is a protocol chain.

---

I just published an English **technical note** (whitepaper v1.11) mapping the modern Apple private path used to acquire **iCloud device backups**, with and without **Advanced Data Protection (ADP)**.

Commercial tools often stall when **iCloud.com is disabled**, **ADP** is enabled, or **Lockdown Mode** shrinks the client surface. In those cases you are no longer on the web API — you are composing:

**GrandSlam / GsService2 → EscrowProxy &/or Octagon–Cuttlefish → CKKS (Manatee / TLKShare) → CloudKit `mbksync` (Lock + Domain `N:` / fileList) → MMCS / PCSMMCS2**

The paper is descriptive and forensic-oriented: recovery-path taxonomy (PCS Escrow `dsid:dsid` vs iCDP vs Recovery Key), MidService/Anisette identity rules, how **file lists** are retrieved and turned into SQLite inventories after Lock, and the Ford / ChunkInfo discipline. Appendix A covers methodology without publishing bypass recipes.

Built alongside the open-source **iCloudKit Extractor** lab work (authorized accounts / mandate).

Read / cite:  
Landing → https://giordanosconti.github.io/iCloudKitExtractor/whitepaper/  
PDF + Markdown on GitHub → release `whitepaper-v1.11`  
DOI (Zenodo) → *(add when live)*

Feedback from digital forensics practitioners welcome.

#digitalforensics #mobileforensics #icloud #ADP #CloudKit #Octagon #opensource #ForensisLab

---

## Checklist

- [ ] Paste post (without checklist)  
- [ ] Attach fig01 + fig11  
- [ ] Pin comment with landing URL + DOI when ready  
- [ ] Tag Forensis-Lab if applicable  
