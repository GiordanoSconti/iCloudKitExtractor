# Medium — English

**Title:** iCloudKit Extractor: seven months from an ADP dead end to a public experimental toolkit  
**Subtitle:** A Forensis-Lab research diary — project overview and the first four days (March–May 2026)  
**Tags:** Digital Forensics, iOS, iCloud, CloudKit, Open Source, Reverse Engineering  

---

## Why this exists

In late March 2026 we had a concrete forensic need: download an **iCloud device backup** protected by **Advanced Data Protection (ADP)**. The commercial products we used were not delivering that path at the time.

That failure mode is uncomfortable in a lab. You can escalate licenses, open tickets, wait for a vendor release—or you can ask a harder question: *what are the private Apple surfaces behind the iCloud section of iOS Settings actually doing?*

I am **Giordano Sconti**, software researcher and technical consultant collaborating with **Forensis-Lab**. Over roughly seven months—often late nights or spare windows during work—that question became **iCloudKit Extractor**: a .NET / WPF experimental toolkit for iCloud authentication, CloudKit / MMCS backup download, and Octagon / PCS recovery when you already hold the device Octagon PIN or the Recovery Key.

The project is now in a **public experimental phase** on GitHub under the **MIT** license, with ownership and attribution remaining with **Forensis-Lab**. It is research software. Apple’s private APIs can change overnight. Use it only on accounts and devices you are authorized to examine.

- Repository: [github.com/GiordanoSconti/iCloudKitExtractor](https://github.com/GiordanoSconti/iCloudKitExtractor)  
- Research notes: [Notes / blog on GitHub Pages](https://giordanosconti.github.io/iCloudKitExtractor/blog/)  
- Contact: [giordano.sconti@gruppoinformaticiforensi.it](mailto:giordano.sconti@gruppoinformaticiforensi.it)

Windows x64 builds are published as signed GitHub Releases (Authenticode via Forensis-Lab / Microsoft Trusted Signing). Prefer building from source when you audit forensic tooling.

---

## What the toolkit aims at

At a high level:

- **CloudKit / MMCS** — list devices and pull backup payloads through CloudKit authorization and MMCS edge flows.  
- **Octagon / PCS** — Recovery Key and PIN paths toward Manatee / PCS keysets for ADP-protected zones.  
- **Anisette** — optional jailbroken-iPhone Frida backend for coherent iPhone / akd identity during GrandSlam auth (preview access to a maintainer server is invite-only).

Unlike treating a commercial GUI as the only interface, the point of this work was to make the *protocol spine* inspectable—so that extreme recoveries are not blocked solely by vendor coverage gaps.

---

## Day 1 — 25 March 2026: ADP on the table

Commercial suites were not enough. A colleague and I started from two practical observation channels: a **jailbroken iPhone** and **Elcomsoft Phone Breaker** (I held both a license and a device).

Early pain clustered around **GrandSlam / GsService2**. EPB was broken for the flows we needed; Elcomsoft fixed it in a later release the following month. I did not wait: I worked **iCloud.com** (idmsa-style web tokens—useful for the browser surface, not native mobile clients) and the jailbroken phone in parallel.

Those sessions still paid off: authentication endpoints around **trusted devices** and **SMS**, plus a clearer view of metadata around deleted media in **iCloud Photos**. On the device side, mobile GrandSlam and the first backup-relevant CloudKit names appeared—especially the **`mbksync`** zone inside **`com.apple.backup.ios`** (backupd / Mobile Backup), not a vague “MobileSync” label.

*In the code today*, that binding is still explicit:

```csharp
public static CloudKitContainerBinding Backup { get; } =
    new("com.apple.backup.ios", "com.apple.backupd");

public static readonly string[] BackupZones =
    { "_defaultZone", "mbksync" };
```

Full note: [Day 1](https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-03-25-day-01-adp-necessity.html)

---

## Day 2 — 11 April 2026: snapshots, still not the mountain

I resumed on 11 April. Reaching snapshot-recovery endpoints was brutal in a different way: every attempt seemed to rewrite the surrounding tree as the coding agent pulled in fragments that resembled online material.

Meanwhile Elcomsoft shipped a build that could download **iOS 26** backups. Worth trying. With **ADP** still on: **HTTP 403**. So I used their release as a lab oracle for *how* snapshot access had been unblocked at all. Captures were messy; enough of them got me past **snapshot enumeration**.

What I could not decrypt yet was **`backupProperties`**—where the hardware **UDID** lives. I barely knew the field existed.

*In the code today*, that field is a first-class decrypt path (ShareProtection → CUWK label `backupProperties` → PCSFP-GCM), feeding Lockdown identity including UniqueDeviceID.

Full note: [Day 2](https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-04-11-day-02-snapshots-epb-403.html)

---

## Day 3 — 29 April 2026: Prepare Restore and the Lock wall

Listing snapshots is not preparing a restore. On iOS you see a “preparing” phase; on the wire that is a CloudKit state machine that ends in a **Lock** on `mbksync` before the big post-Lock file catalog (`N:`) opens.

The order we still document in the extractor:

**zones → BackupAccount → `D:` → `S:` → (optional mbs) → Lock → `N:`**

The Lock is a private modify-records operation writing `{deviceSha}:Lock`. Fail the **Foreground Restore** hw/sha identity (or even wrap a protobuf field name the wrong way) and MobileBackupServerExtension answers with **`Invalid lock id`**.

Help came from an ugly coalition: **Frida** on the jailbroken iPhone, plus a few **malformed EPB** request/response pairs that were wrong for a clean download but useful as fossils.

Full note: [Day 3](https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-04-29-day-03-prepare-restore-lock.html)

---

## Day 4 — 24 May 2026: MMCS opens

After another month of reverse engineering past Lock, I finally stepped into **MMCS**—edge-content hosts, ranged GETs, and blobs that refuse to be only one species of bytes. The same range plan can carry **Ford key material** or **chunk ciphertext** for the same logical file. Mis-classify them and MAC checks fail with perfect confidence.

By then I no longer needed the phone or EPB as a daily crutch for the *next* problems. Coding agents—and older public fragments that pointed at **Octagon**—opened paths the commercial “normal restore” road does not advertise. EPB remained relevant as an oracle for **MMCS caching** and **chunk reassembly**; even so, through the summer both sides left files behind. Side-by-side, IKE often held on the order of **~3000 more decrypted files**.

A September coda (foreshadowed in the May note): not every Ford key blob leads with **`0x04`**; some use **`0xC4`**. One nibble. Absurd. Decisive.

Full note: [Day 4](https://giordanosconti.github.io/iCloudKitExtractor/blog/posts/2026-05-24-day-04-mmcs-edge.html)

---

## How to follow along

I will keep filling the seven-month diary on the project Notes page. The entries are drafted with help from an AI coding assistant to speed up the writing; if you spot inconsistencies, email me.

Contributors who want to test, review, or send careful pull requests are welcome—review generated code, do not land unlicensed third-party material, and keep attribution to **Forensis-Lab**.

If you found this useful, the most helpful signal is not a coffee: it is recognition for the lab, careful testing, and technical feedback.

---

*Giordano Sconti — Forensis-Lab*
