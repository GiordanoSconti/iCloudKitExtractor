#!/usr/bin/env python3
"""UML-style sequence diagrams for the whitepaper (request/response flows)."""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle

OUT = Path(__file__).resolve().parent / "figures"
OUT.mkdir(parents=True, exist_ok=True)

EDGE = "#2C3E50"
ACCENT = "#1A5276"
TEXT = "#1C2833"
MUTED = "#566573"
BOX = "#EEF2F6"
REQ = "#1A5276"
RESP = "#1E8449"
NOTE = "#F5EDE6"


def save(fig, name: str) -> None:
    fig.patch.set_facecolor("white")
    for ext in ("pdf", "png"):
        p = OUT / f"{name}.{ext}"
        fig.savefig(p, dpi=220, bbox_inches="tight", facecolor="white", pad_inches=0.18)
        print("wrote", p)
    plt.close(fig)


def draw_seq(actors: list[str], messages: list[tuple], notes: list[tuple] | None = None, figsize=(11.2, 7.2), title: str = ""):
    """
    messages: (from_idx, to_idx, label, kind) kind in {'req','resp','note'}
    notes: optional (y_frac, text) absolute annotations
    """
    n = len(actors)
    fig, ax = plt.subplots(figsize=figsize)
    ax.set_xlim(0, n + 0.2)
    # vertical space: header + messages
    msg_h = 0.55
    top = 1.15 + len(messages) * msg_h + 0.35
    ax.set_ylim(0, top)
    ax.axis("off")
    if title:
        ax.set_title(title, fontsize=10.5, color=ACCENT, weight="bold", pad=8, loc="left")

    xs = [0.7 + i * ((n) / max(n - 1, 1)) * 0.95 for i in range(n)]
    if n == 1:
        xs = [2.5]
    elif n == 2:
        xs = [1.4, 4.8]
    elif n == 3:
        xs = [1.1, 3.6, 6.2]
    elif n == 4:
        xs = [0.9, 2.9, 4.9, 7.0]
    elif n == 5:
        xs = [0.75, 2.4, 4.1, 5.8, 7.5]
    else:
        span = 7.4
        xs = [0.7 + i * span / (n - 1) for i in range(n)]

    # rescale xlim to fit
    ax.set_xlim(0, max(xs) + 1.1)

    head_y = top - 0.55
    for i, (x, name) in enumerate(zip(xs, actors)):
        w = min(1.55, 1.9 if n <= 3 else 1.35)
        box = FancyBboxPatch(
            (x - w / 2, head_y - 0.28),
            w,
            0.56,
            boxstyle="round,pad=0.02,rounding_size=0.05",
            facecolor=BOX,
            edgecolor=EDGE,
            linewidth=1.1,
            zorder=3,
        )
        ax.add_patch(box)
        ax.text(x, head_y, name, ha="center", va="center", fontsize=7.2, weight="bold", color=TEXT, zorder=4)
        ax.plot([x, x], [0.25, head_y - 0.28], color="#95A5A6", lw=1.0, ls="--", zorder=1)

    y = head_y - 0.55
    for fr, to, label, kind in messages:
        x0, x1 = xs[fr], xs[to]
        if kind == "note" or fr == to:
            # Self/local processing note under the actor lifeline
            ax.add_patch(
                FancyBboxPatch(
                    (x0 - 0.95, y - 0.18),
                    1.9,
                    0.42,
                    boxstyle="round,pad=0.02,rounding_size=0.04",
                    facecolor=NOTE,
                    edgecolor=EDGE,
                    linewidth=0.9,
                    zorder=3,
                )
            )
            ax.text(x0, y + 0.03, label, ha="center", va="center", fontsize=5.9, color=TEXT, zorder=4)
            y -= msg_h
            continue
        color = REQ if kind == "req" else RESP
        ax.annotate(
            "",
            xy=(x1, y),
            xytext=(x0, y),
            arrowprops=dict(arrowstyle="-|>", color=color, lw=1.25),
            zorder=2,
        )
        mid = (x0 + x1) / 2
        ax.text(
            mid,
            y + 0.12,
            label,
            ha="center",
            va="bottom",
            fontsize=6.3,
            color=color,
            zorder=5,
            bbox=dict(boxstyle="round,pad=0.15", facecolor="white", edgecolor="none", alpha=0.92),
        )
        y -= msg_h

    if notes:
        for ny, txt in notes:
            ax.text(0.15, ny, txt, fontsize=6.2, color=MUTED, style="italic", va="bottom")

    return fig, ax


def fig06_grandslam():
    actors = ["Client IKE", "gsa.apple.com\nGsService2", "setup.icloud.com"]
    messages = [
        (0, 1, "POST /grandslam/GsService2  init {A2k,u,cpd,ps}", "req"),
        (1, 0, "200 plist {i,s,B,sp,c, Status.ec=0}", "resp"),
        (0, 1, "POST /grandslam/GsService2  complete {u,c,M1,cpd}", "req"),
        (1, 0, "200 plist {M2, spd*, au?}  (*SRP-encrypted)", "resp"),
        (0, 1, "(opt.) GET/POST MFA trusteddevice | SMS OTP", "req"),
        (1, 0, "header X-Apple-*-Token / PE-Token", "resp"),
        (0, 2, "GET /setup/authenticate/{appleId}  Basic", "req"),
        (2, 0, "account settings + mmeAuthToken / dsid", "resp"),
    ]
    fig, _ = draw_seq(actors, messages, figsize=(11.0, 7.0))
    save(fig, "fig06-seq-grandslam")


def fig07_escrow():
    actors = ["Client IKE", "pXX-escrowproxy\n.icloud.com", "Cuttlefish\n(ckcoderouter)"]
    messages = [
        (0, 1, "POST …/escrowproxy/api/get_records\nGETRECORDS + label", "req"),
        (1, 0, "200 plist metadata records\n(PCS and/or com.apple.icdp.record.*)", "resp"),
        (0, 1, "POST …/srp_init  {blob=A, command, label, version}", "req"),
        (1, 0, "200 {blob=B+salt…}  (SRP challenge)", "resp"),
        (0, 1, "POST …/recover  {blob=session‖M1, label}", "req"),
        (1, 0, "200 EscrowedKeys | EscrowBottle\n→ BottledPeerEntropy", "resp"),
        (0, 2, "(iCDP only) code/invoke fetchViableBottles", "req"),
        (2, 0, "OTBottle Contents → AES-GCM → peer keys", "resp"),
    ]
    fig, _ = draw_seq(actors, messages, figsize=(11.2, 7.4))
    save(fig, "fig07-seq-escrow")


def fig08_octagon_rk():
    actors = ["Client IKE", "ckdatabase\nckAppInit", "ckcoderouter\nCuttlefish", "CKKS views"]
    messages = [
        (0, 1, "ckAppInit container=\ncom.apple.security.keychain", "req"),
        (1, 0, "DB URL / tokens CloudKit", "resp"),
        (0, 2, "code/invoke fetchRecoverableTLKShares\nforPeer=RK-…", "req"),
        (2, 0, "ECIES-encrypted TLKShares per view", "resp"),
        (0, 3, "record sync tlkshare / synckey / item", "req"),
        (3, 0, "record CKKS (Manatee, Passwords, …)", "resp"),
        (0, 0, "local: unwrap ECIES → TLK → class keys → PCS", "note"),
    ]
    fig, _ = draw_seq(actors, messages, figsize=(11.2, 6.8))
    save(fig, "fig08-seq-octagon-ckks")


def fig09_mbksync():
    actors = ["Client IKE", "pXX-ckdatabase\ncom.apple.backup.ios", "MMCS content\nhost"]
    messages = [
        (0, 1, "record/retrieve  zones mbksync\n+ BackupAccount", "req"),
        (1, 0, "zone + account records", "resp"),
        (0, 1, "record/retrieve  D:<sha> → S:<uuid>", "req"),
        (1, 0, "device + snapshot (+ :CN:)", "resp"),
        (0, 1, "record/save  {deviceSha}:Lock\n(Foreground Restore, 48h)", "req"),
        (1, 0, "Lock OK (owner/expiration)", "resp"),
        (0, 1, "record/retrieve  N:uuid:cs=:0\n(+ K: keybag)", "req"),
        (1, 0, "Domain records + fileList\nCKAsset handles", "resp"),
        (0, 1, "query/retrieve PrivilegedBatch\n(A:… → MmcsAuth)", "req"),
        (1, 0, "auth tokens f2/f5/f17", "resp"),
        (0, 2, "POST /{dsid}/authorizeGet\n(FL + Backup files)", "req"),
        (2, 0, "FileGroups → Ford/ChunkInfo bytes", "resp"),
    ]
    fig, _ = draw_seq(actors, messages, figsize=(11.2, 8.4))
    save(fig, "fig09-seq-mbksync-mmcs")


def fig10_mmcs_detail():
    actors = ["Client IKE", "MMCS\nauthorizeGet", "Edge storage\n(GET range)"]
    messages = [
        (0, 1, "POST /{dsid}/authorizeGet\nMIME ubchunk+protobuf\nHeader x-apple-mmcs-auth", "req"),
        (1, 0, "FileGroups: host template,\nChunkInfo, ownership refs", "resp"),
        (0, 2, "GET host?content-byte-range=a-b\n(Ford @ offset 0)", "req"),
        (2, 0, "blob Ford lead‖nonce‖SIV", "resp"),
        (0, 2, "GET host?content-byte-range=c-d\n(data chunk)", "req"),
        (2, 0, "ciphertext chunk", "resp"),
        (0, 0, "local: IKM(protectionInfo)→HKDF PCSMMCS2→AES-SIV→VerifyDigest", "note"),
    ]
    fig, _ = draw_seq(actors, messages, figsize=(11.0, 7.2))
    save(fig, "fig10-seq-mmcs-detail")


def fig11_filelist():
    actors = [
        "Client IKE",
        "ckdatabase\n_defaultZone",
        "MMCS\nauthorizeGet",
        "Local\nSQLite flist",
    ]
    messages = [
        (0, 1, "S: → :CN:uuid:checksum\n→ build N:uuid:cs=:0", "note"),
        (0, 1, "record/retrieve batch\nN:…=:0 (Domain)", "req"),
        (1, 0, "Domain fields +\nfileList CKAsset (+auth)", "resp"),
        (0, 0, "opt. PCS-GCM field decrypt\n(AAD = field name)", "note"),
        (0, 2, "authorizeGet FL:{sig}\nx-apple-mmcs-auth(fileList)", "req"),
        (2, 0, "FileGroups → Ford/chunks\n→ LZFSE → SQLite magic", "resp"),
        (0, 3, "Assets ⋈ FileMetadata\n(rid, sig, path, ek, …)", "note"),
        (0, 1, "PrivilegedBatch A:/KA:/MA:\nif flist row lacks auth", "req"),
        (1, 0, "mmcs-auth tokens", "resp"),
        (0, 2, "authorizeGet batch ≤12\nf1=assetSignature, f2=CAog", "req"),
        (2, 0, "FileGroups → edge GET\n→ Backup/{fileID}/…", "resp"),
    ]
    fig, _ = draw_seq(actors, messages, figsize=(11.4, 9.0))
    save(fig, "fig11-seq-filelist")


if __name__ == "__main__":
    fig06_grandslam()
    fig07_escrow()
    fig08_octagon_rk()
    fig09_mbksync()
    fig10_mmcs_detail()
    fig11_filelist()
    print("DONE")
