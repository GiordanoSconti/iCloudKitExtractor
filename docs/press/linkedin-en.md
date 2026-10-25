# LinkedIn — English

**Suggested headline (optional first line):**  
Seven months from an ADP backup we could not pull — to a public experimental forensic toolkit.

---

In March 2026 we needed something commercial tools would not give us at the time: a full recovery path for an **iCloud device backup protected by Advanced Data Protection (ADP)**.

That gap pushed me—working with a colleague, under **Forensis-Lab**—to stop treating Apple’s private surfaces as a black box. What became **iCloudKit Extractor** started as a forced question: how do the APIs behind the iCloud section of iOS Settings actually behave?

I have opened a **public experimental phase** on GitHub (MIT, attribution to Forensis-Lab). The software is .NET/WPF research tooling for iCloud auth, CloudKit/MMCS download, and Octagon/PCS paths when you hold the device PIN or Recovery Key. It is **not** a finished product. Apple’s private APIs can change overnight.

On our lab site I also started a research diary. The first four days:

1. **25 Mar** — ADP necessity; EPB + jailbroken iPhone; idmsa vs mobile GrandSlam; the real backup zone is `mbksync` in `com.apple.backup.ios`.
2. **11 Apr** — Snapshot listing; EPB could do iOS 26 but still **403** with ADP; `backupProperties` / UDID still opaque.
3. **29 Apr** — Prepare Restore Session and CloudKit **Lock**; Foreground hw/sha; Frida + EPB fossils; `Invalid lock id`.
4. **24 May** — First steps into **MMCS** and edge-content byte ranges (Ford keys vs chunk data); later, a one-nibble absurdity (`0x04` vs `0xC4`).

If you work digital forensics / mobile extraction and want to inspect, critique, or test carefully: stars and careful issues help more than applause.

Repo: https://github.com/GiordanoSconti/iCloudKitExtractor  
Notes: https://giordanosconti.github.io/iCloudKitExtractor/blog/  
Contact: giordano.sconti@gruppoinformaticiforensi.it

#digitalforensics #ios #icloud #cloudkit #opensource #forensics #dotnet

---

**Posting tips:** attach a screenshot of the Notes page or the signed Releases page; tag Forensis-Lab if the company page exists; pin comments with the Day 1 URL.
