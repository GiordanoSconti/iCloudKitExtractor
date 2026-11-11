# NOTICE — third-party references and dependencies

Copyright © Giordano Sconti. iCloudKit Extractor (IKE) is licensed under the
**MIT License** — see [`LICENSE`](LICENSE).

This file documents (1) **NuGet / package dependencies** redistributed with
builds, and (2) **external projects consulted as protocol references**. Unless
stated otherwise, IKE does **not** vendor, fork, or redistribute the source
trees of those reference projects. IKE is a separate .NET implementation.

This is an attribution / hygiene notice, not legal advice.

---

## Package dependencies (NuGet)

Typical Core / Desktop / related package references (see each `.csproj` for the
exact set and versions):

| Package | Typical license (upstream) |
|---------|----------------------------|
| BouncyCastle.Cryptography | MIT |
| LzfseSharp | (see package / upstream) |
| MailKit / MimeKit | MIT |
| MetadataExtractor | Apache-2.0 |
| Microsoft.Data.Sqlite | MIT |
| SQLitePCLRaw.bundle_e_sqlite3 | Apache-2.0 / related |
| Avalonia (Desktop) | MIT |
| LibVLCSharp / VideoLAN.LibVLC (BackupViewer) | LGPL / related — see upstream |

Redistribute those packages only under their own license terms. Binary builds
may include their copyright notices as required by each package.

---

## Protocol references (not vendored)

IKE reimplements undocumented Apple private protocols in C#. The following
projects were **studied or cited in comments / `refImpl` metadata** as wire-
format or flow references. **No copy of their source trees is included** in
this repository.

| Project | License (upstream, as published) | Role for IKE |
|---------|----------------------------------|--------------|
| [Laky-64/appleservices](https://github.com/Laky-64/appleservices) | MIT | Escrow iCDP SRP / OTBottle / CKKS OpenVault naming and flow cross-check |
| [Sank6/iCloud-Keychain-for-Linux](https://github.com/Sank6/iCloud-Keychain-for-Linux) | MIT | Escrow KeyVault messages, bottle / Cuttlefish notes |
| [OpenBubbles/rustpush](https://github.com/OpenBubbles/rustpush) | **SSPL** | PCS, Messages protobuf, Octagon join/voucher, Find My container notes |
| [JJTech0130/pypush](https://github.com/JJTech0130/pypush) | **SSPL** | APS / Albert / IDS / Madrid / anisette–NAC patterns |
| [beeper/mac-registration-provider](https://github.com/beeper/mac-registration-provider) | **AGPL-3.0** | Mentioned for Absinthe/NAC-style approach — not embedded |
| Belenko / CloudServices (historical public RE notes) | n/a (historical) | Escrow club-cert / classic PCS SRP notes in comments |
| Apple open-source Security / TrustedPeersHelper | Apple OSS | Recovery Key KDF / `TPPB.*` domain-separation signing |

**SSPL / AGPL:** IKE does not redistribute those codebases. Independent
clean-room reimplementation of network protocols is not a conveyance of those
programs. Do not paste SSPL/AGPL source into this tree; that would create
separate compliance obligations.

**macless-haystack / pyicloud / related:** occasional GrandSlam / SMS UI flow
comments only.

---

## Lab observation (not open source)

Early EscrowProxy / restore / MMCS orientation used **lab observation** of
commercial tooling (notably **Elcomsoft Phone Breaker**) and a jailbroken
device under authorized lab conditions. That is **not** an OSS dependency and
IKE does not include EPB binaries or source. See the project Notes diary for
the research narrative.

---

## Own lab captures

Areas such as **iCloud Drive**, **WhatsApp CloudDocs**, and much of the
**backup / MMCS** pipeline are driven primarily by IKE lab captures and
protocol work (e.g. Drive capture ids in code comments), not by a cited
third-party OSS implementation.

---

## How to keep this accurate

- Prefer citing a reference in code comments or `refImpl` **and** listing it here.
- Never add third-party source without an explicit license review and, if
  required, a dedicated `third_party/` notice.
- Contributors: see [`CONTRIBUTING.md`](CONTRIBUTING.md) — do not land
  unlicensed or incompatible third-party material in PRs.
