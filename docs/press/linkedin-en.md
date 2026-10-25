# LinkedIn — English

**Media to attach (ready under `docs/press/assets/`):**

1. `linkedin-github-repo.png` — public GitHub repository  
2. `linkedin-app-ike.png` — running WPF build (Access tab / Not authenticated)

Suggested order in the post: GitHub first, then the app UI.

---

**Suggested headline (optional first line):**  
Seven months from an ADP backup we could not pull — to a public experimental forensic toolkit.

---

In March 2026 we needed something commercial tools would not give us at the time: a full recovery path for an **iCloud device backup protected by Advanced Data Protection (ADP)**.

That gap pushed me—working with a colleague, under **Forensis-Lab**—to stop treating Apple’s private surfaces as a black box. What became **iCloudKit Extractor** started as a forced question: how do the APIs behind the iCloud section of iOS Settings actually behave?

I have opened a **public experimental phase** on GitHub (MIT, attribution to Forensis-Lab). The software is .NET/WPF research tooling for iCloud auth, CloudKit/MMCS download, and Octagon/PCS paths when you hold the device PIN or Recovery Key. It is **not** a finished product. Apple’s private APIs can change overnight.

On our lab site I also published a research diary (Notes). The arc, in short:

1. **25 Mar** — ADP necessity; EPB + jailbroken iPhone; idmsa vs mobile GrandSlam; the real backup zone is `mbksync` in `com.apple.backup.ios`.
2. **11 Apr** — Snapshot listing; EPB could do iOS 26 but still **403** with ADP; `backupProperties` / UDID still opaque.
3. **29 Apr** — Prepare Restore Session and CloudKit **Lock**; Foreground hw/sha; Frida + EPB fossils; `Invalid lock id`.
4. **24 May** — First steps into **MMCS** and edge-content byte ranges (Ford keys vs chunk data).
5. **16 Jun** — **IKM** from `contents.protectionInfo` (zone master) before Ford makes sense.
6. **10 Jul** — Ford vs ChunkInfo: force paths, then `.chunks`/checksum21 caching when data arrives late.
7. **4 Aug** — Fulcrum `0x04` vs `0xC4`; orphaned CloudKit files; non-Apple ciphertext (e.g. Mozilla models).
8. **28 Aug** — iTunes-style layout: `Backup/xx/fileID`, `Manifest.db`, sidecars.
9. **5 Oct** — **Octagon**: iCDP bottles tied to trusted-device PINs → KeySet.
10. **24 Oct** — Recovery Key → Octagon peer → **TLKShare** dump when no bottle PIN is available.

If you work digital forensics / mobile extraction and want to inspect, critique, or test carefully: stars and careful issues help more than applause.

Repo: https://github.com/GiordanoSconti/iCloudKitExtractor  
Notes: https://giordanosconti.github.io/iCloudKitExtractor/blog/  
Signed release (Forensis-Lab Trusted Signing): https://github.com/GiordanoSconti/iCloudKitExtractor/releases  
Contact: giordano.sconti@gruppoinformaticiforensi.it

#digitalforensics #ios #icloud #cloudkit #octagon #opensource #forensics #dotnet #ForensisLab

---

## Publishing checklist

- [ ] Paste the text above (without this checklist) into LinkedIn  
- [ ] Attach `linkedin-github-repo.png` and `linkedin-app-ike.png`  
- [ ] Tag Forensis-Lab if the company page exists  
- [ ] Pin a comment with Day 1: https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-03-25-day-01-adp-necessity.html  
- [ ] (Optional) Shorter EN follow-up pointing only at Notes + release
