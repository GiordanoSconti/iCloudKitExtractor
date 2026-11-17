# Whitepaper v1.11

**From GrandSlam to MMCS: A Description of Modern Apple Private Protocols for Authentication, Escrow/PCS, Octagon/CKKS, and iCloud Device Backup Acquisition**

English technical note (digital forensics) on the modern iCloud device-backup protocol chain, including ADP-era recovery paths and Domain `fileList` inventory after Lock.

## Assets

| File | Description |
|------|-------------|
| [PDF](../whitepaper/whitepaper-protocolli-backup-octagon-pcs.pdf) | Camera-ready build |
| [Markdown](../whitepaper-protocolli-backup-octagon-pcs.md) | Source |
| [Landing page](https://giordanosconti.github.io/iCloudKitExtractor/whitepaper/) | Abstract + figures |
| Figures | `docs/whitepaper/figures/` (incl. UML fig06–fig11) |

## Highlights in v1.11

- MidService / Anisette identity consistency  
- Escrow paths A/B/C and Octagon/CKKS (Manatee)  
- Domain `N:` / fileList → SQLite → per-file `authorizeGet`  
- MMCS Ford / `PCSMMCS2`  
- Keychain Wi‑Fi note; Sync Data / Voice Memos practitioner note  

## Cite

Prefer the Zenodo DOI once published; until then use the landing URL above.

Contact: giordano.sconti@gruppoinformaticiforensi.it
