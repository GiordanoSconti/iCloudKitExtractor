#!/usr/bin/env python3
"""Generate protocol diagrams for the whitepaper (PDF+PNG) with clipped, wrapped text."""
from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, Rectangle

OUT = Path(__file__).resolve().parent / "figures"
OUT.mkdir(parents=True, exist_ok=True)

C = {
    "box": "#EEF2F6",
    "box2": "#E8F0EA",
    "box3": "#F5EDE6",
    "box4": "#E8EEF5",
    "edge": "#2C3E50",
    "accent": "#1A5276",
    "text": "#1C2833",
    "muted": "#566573",
}


def save(fig, name: str) -> None:
    fig.patch.set_facecolor("white")
    for ext in ("pdf", "png"):
        p = OUT / f"{name}.{ext}"
        fig.savefig(p, dpi=220, bbox_inches="tight", facecolor="white", pad_inches=0.15)
        print("wrote", p)
    plt.close(fig)


def box(
    ax,
    xy,
    w,
    h,
    text: str,
    *,
    fc=None,
    fontsize: float = 7.5,
    weight: str = "normal",
    pad: float = 0.08,
):
    """Rounded box with text clipped to interior padding."""
    fc = fc or C["box"]
    p = FancyBboxPatch(
        xy,
        w,
        h,
        boxstyle="round,pad=0.015,rounding_size=0.06",
        facecolor=fc,
        edgecolor=C["edge"],
        linewidth=1.15,
        zorder=2,
        clip_on=True,
    )
    ax.add_patch(p)
    # Invisible clip rect slightly inside the box
    clip = Rectangle(
        (xy[0] + pad * 0.35, xy[1] + pad * 0.35),
        w - pad * 0.7,
        h - pad * 0.7,
        transform=ax.transData,
        visible=False,
    )
    ax.add_patch(clip)
    t = ax.text(
        xy[0] + w / 2,
        xy[1] + h / 2,
        text,
        ha="center",
        va="center",
        fontsize=fontsize,
        color=C["text"],
        weight=weight,
        zorder=3,
        linespacing=1.28,
        clip_on=True,
    )
    t.set_clip_path(clip)
    return p


def arrow(ax, a, b, rad: float = 0.0) -> None:
    ax.annotate(
        "",
        xy=b,
        xytext=a,
        arrowprops=dict(
            arrowstyle="-|>",
            color=C["edge"],
            lw=1.3,
            connectionstyle=f"arc3,rad={rad}",
            shrinkA=1,
            shrinkB=1,
        ),
        zorder=1,
        clip_on=False,
    )


def fig01() -> None:
    fig, ax = plt.subplots(figsize=(11.0, 7.6))
    ax.set_xlim(0, 11.0)
    ax.set_ylim(0, 7.2)
    ax.axis("off")
    # Title omitted: document caption supplies "Figure 1"

    box(ax, (3.05, 6.55), 4.9, 0.72, "Anisette / ADI", fc=C["box"], fontsize=8.5, weight="bold")
    box(
        ax,
        (2.6, 5.5),
        5.8,
        0.85,
        "GrandSlam GsService2 (SRP-6a)\nPET · mmeAuthToken · dsid · altDSID",
        fc=C["box4"],
        fontsize=8,
        weight="bold",
    )
    arrow(ax, (5.5, 6.55), (5.5, 6.35))
    arrow(ax, (5.5, 5.5), (5.5, 5.28))

    doors = [
        (0.35, 4.15, "Path A\nEscrow PCS\ndsid:dsid", C["box3"]),
        (3.95, 4.15, "Path B\nEscrow iCDP\ndevice passcode", C["box2"]),
        (7.55, 4.15, "Path C\nRecovery Key\nwithout Escrow RECOVER", C["box4"]),
    ]
    for x, y, t, fc in doors:
        box(ax, (x, y), 3.1, 1.0, t, fc=fc, fontsize=7.5, weight="bold")
    arrow(ax, (3.7, 5.5), (1.9, 5.15), rad=0.18)
    arrow(ax, (5.5, 5.5), (5.5, 5.15))
    arrow(ax, (7.3, 5.5), (9.1, 5.15), rad=-0.18)

    outs = [
        (0.35, 2.95, "EscrowedKeys /\nBackupBagPassword", C["box3"]),
        (3.95, 2.95, "BottledPeerEntropy\n→ OTBottle (Cuttlefish)", C["box2"]),
        (7.55, 2.95, "Peer RK-…\n→ TLKShares", C["box4"]),
    ]
    for x, y, t, fc in outs:
        box(ax, (x, y), 3.1, 0.95, t, fc=fc, fontsize=7.2)
        arrow(ax, (x + 1.55, 4.15), (x + 1.55, 3.9))

    box(
        ax,
        (2.2, 1.85),
        6.6,
        0.85,
        "CKKS view open / session PCS material\n(Manatee ∪ Escrow KeySet)",
        fc="#D5F5E3",
        fontsize=8,
        weight="bold",
    )
    arrow(ax, (1.9, 2.95), (3.8, 2.7), rad=0.18)
    arrow(ax, (5.5, 2.95), (5.5, 2.7))
    arrow(ax, (9.1, 2.95), (7.2, 2.7), rad=-0.18)

    box(
        ax,
        (2.2, 0.95),
        6.6,
        0.72,
        "CloudKit mbksync\nzones → D: → S: → Lock → N: → K:",
        fc=C["box4"],
        fontsize=7.5,
        weight="bold",
    )
    arrow(ax, (5.5, 1.85), (5.5, 1.67))

    box(
        ax,
        (2.2, 0.12),
        6.6,
        0.72,
        "MMCS: authorizeGet → FileGroups → Ford / ChunkInfo\n(PCSMMCS2) → iTunes-format tree",
        fc="#FCF3CF",
        fontsize=7.5,
        weight="bold",
    )
    arrow(ax, (5.5, 0.95), (5.5, 0.84))
    save(fig, "fig01-catena-end-to-end")


def fig02() -> None:
    fig, ax = plt.subplots(figsize=(11.2, 5.8))
    ax.set_xlim(0, 11.2)
    ax.set_ylim(0, 5.5)
    ax.axis("off")
    # Title omitted: document caption supplies "Figure 2"

    box(
        ax,
        (3.4, 4.75),
        4.4,
        0.75,
        "EscrowProxy\nget_records · SRP_INIT · RECOVER",
        fc=C["box4"],
        fontsize=8,
        weight="bold",
    )

    cols = [
        (
            0.25,
            "#FADBD8",
            "A — PCS (Escrow)",
            "Label:\nProtectedCloudStorage\n\nSRP secret:\ndsid:dsid\n\n→ EscrowedKeys\n→ BackupBagPassword\n→ KeySet PCS\n\nOctagon/CKKS: no",
        ),
        (
            3.95,
            "#D5F5E3",
            "B — iCDP (Escrow)",
            "Label:\ncom.apple.icdp.record.*\n\nSecret:\ndevice passcode\n\n→ BottledPeerEntropy\n→ OTBottle (AES-GCM)\n→ peer keys\n\nOctagon/CKKS: yes",
        ),
        (
            7.65,
            "#D6EAF8",
            "C — Recovery Key",
            "Does not use Escrow RECOVER\n\nHKDF-SHA384\n(RK, altDSID)\n\n→ Peer RK-…\n→ TLKShares\n→ unwrap ECIES\n\nOctagon/CKKS: yes",
        ),
    ]
    for x, fc, title, body in cols:
        box(ax, (x, 3.75), 3.3, 0.58, title, fc=fc, fontsize=8, weight="bold")
        box(ax, (x, 0.35), 3.3, 3.25, body, fc="#FBFCFC", fontsize=6.6)
        arrow(ax, (5.6, 4.75), (x + 1.65, 4.33), rad=0.04 if x != 3.95 else 0)

    ax.text(
        5.6,
        0.08,
        "Note: path C does not go through EscrowProxy; A and B share the Escrow transport.",
        ha="center",
        fontsize=6.8,
        color=C["muted"],
        style="italic",
    )
    save(fig, "fig02-escrow-porte")


def fig03() -> None:
    fig, ax = plt.subplots(figsize=(11.0, 6.2))
    ax.set_xlim(0, 11.0)
    ax.set_ylim(0, 6.2)
    ax.axis("off")
    # Title omitted: document caption supplies "Figure 3"

    box(
        ax,
        (0.35, 4.85),
        3.2,
        0.95,
        "Peer identity\niCDP bottle or\nRecovery Key",
        fc=C["box2"],
        fontsize=7.5,
        weight="bold",
    )
    box(
        ax,
        (3.9, 4.85),
        3.2,
        0.95,
        "Cuttlefish\ncom.apple.security\n.keychain",
        fc=C["box4"],
        fontsize=7.5,
        weight="bold",
    )
    box(
        ax,
        (7.45, 4.85),
        3.2,
        0.95,
        "View CKKS\nManatee · PCS\nPasswords …",
        fc=C["box3"],
        fontsize=7.5,
        weight="bold",
    )
    arrow(ax, (3.55, 5.32), (3.9, 5.32))
    arrow(ax, (7.1, 5.32), (7.45, 5.32))

    box(
        ax,
        (1.1, 3.45),
        8.8,
        0.95,
        "tlkshare → unwrap ECIES (chiave peer)\n→ TLK per view → class keys → decifratura item",
        fc="#EBF5FB",
        fontsize=7.8,
        weight="bold",
    )
    arrow(ax, (5.5, 4.85), (5.5, 4.4))

    box(
        ax,
        (0.45, 1.95),
        4.7,
        1.1,
        "Manatee\nPCS material for CloudKit zones\nand ADP-protected backups",
        fc="#D5F5E3",
        fontsize=7.5,
        weight="bold",
    )
    box(
        ax,
        (5.85, 1.95),
        4.7,
        1.1,
        "Engram\nMessages / iMessage\nfuori dal percorso backup",
        fc="#F5B7B1",
        fontsize=7.5,
        weight="bold",
    )
    arrow(ax, (3.5, 3.45), (2.8, 3.05), rad=0.08)
    arrow(ax, (7.5, 3.45), (8.2, 3.05), rad=-0.08)

    box(
        ax,
        (2.0, 0.35),
        7.0,
        1.05,
        "Session PCS material\n(Escrow KeySet ∪ Manatee keys)",
        fc="#FCF3CF",
        fontsize=8.2,
        weight="bold",
    )
    arrow(ax, (2.8, 1.95), (4.4, 1.4), rad=0.12)
    save(fig, "fig03-octagon-ckks")


def fig04() -> None:
    fig, ax = plt.subplots(figsize=(10.8, 7.4))
    ax.set_xlim(0, 10.8)
    ax.set_ylim(0, 7.4)
    ax.axis("off")
    # Title omitted: document caption supplies "Figure 4"

    steps = [
        (6.35, "1. CloudKit zones / BackupAccount", C["box4"], 0.72),
        (5.45, "2. D:<device> → S:<snapshot> (+ :CN:)", C["box4"], 0.72),
        (4.55, "3. Lock ({deviceSha}:Lock, 48 h)", C["box3"], 0.72),
        (3.65, "4. N: Domains → fileList FL + K: keybag", C["box3"], 0.72),
        (2.55, "5. MMCS authorizeGet (FL then files)\nx-apple-mmcs-auth · ubchunk+protobuf", "#D6EAF8", 0.9),
        (1.5, "6. FileGroups → GET edge\ncontent-byte-range", "#D6EAF8", 0.85),
        (
            0.25,
            "7. IKM(protectionInfo) → HKDF salt=PCSMMCS2\n→ Ford AES-SIV → ChunkDecrypt → iTunes-format tree",
            "#D5F5E3",
            1.05,
        ),
    ]
    for i, (y, t, fc, h) in enumerate(steps):
        box(ax, (1.55, y), 7.7, h, t, fc=fc, fontsize=8 if i >= 4 else 7.8, weight="bold" if i in (4, 6) else "normal")
        if i < len(steps) - 1:
            ny, _, _, nh = steps[i + 1]
            arrow(ax, (5.4, y), (5.4, ny + nh + 0.02))

    ax.text(0.35, 4.55, "CloudKit\ninventory", rotation=90, va="center", ha="center", fontsize=7, color=C["muted"])
    ax.text(0.35, 1.75, "MMCS\ntransport", rotation=90, va="center", ha="center", fontsize=7, color=C["muted"])
    save(fig, "fig04-mbksync-mmcs")


def fig05() -> None:
    fig, ax = plt.subplots(figsize=(11.0, 5.2))
    ax.set_xlim(0, 11.0)
    ax.set_ylim(0, 5.2)
    ax.axis("off")
    # Title omitted: document caption supplies "Figure 5"

    paths = [
        (0.35, "#FADBD8", "A", "PCS Escrow", "Escrow dsid:dsid\n→ KeySet"),
        (3.85, "#D5F5E3", "B", "iCDP", "Passcode + OTBottle\n→ view CKKS"),
        (7.35, "#D6EAF8", "C", "Recovery Key", "RK → TLKShares\n→ view CKKS"),
    ]
    for x, fc, letter, title, body in paths:
        box(
            ax,
            (x, 2.95),
            3.3,
            1.65,
            f"Path {letter} — {title}\n\n{body}",
            fc=fc,
            fontsize=8,
            weight="bold",
        )

    box(ax, (2.0, 1.55), 7.0, 0.75, "Session PCS material", fc="#FCF3CF", fontsize=9, weight="bold")
    for x, *_ in paths:
        arrow(ax, (x + 1.65, 2.95), (5.5, 2.3), rad=0.04 if x != 3.85 else 0)

    box(
        ax,
        (2.0, 0.3),
        7.0,
        0.85,
        "mbksync Lock → MMCS\n→ materialize iTunes-format tree",
        fc=C["box4"],
        fontsize=8,
        weight="bold",
    )
    arrow(ax, (5.5, 1.55), (5.5, 1.15))
    save(fig, "fig05-tre-cammini")


if __name__ == "__main__":
    fig01()
    fig02()
    fig03()
    fig04()
    fig05()
    print("DONE", sorted(p.name for p in OUT.iterdir() if not p.name.startswith("._")))
