#!/usr/bin/env python3
"""
Crea manifest.json da CoreADI / StoreServices già estratti a mano (ipsw split, ecc.).

Uso:
  python create_ios_adi_manifest.py --scan ~/ios-adi-split
  python create_ios_adi_manifest.py --list ~/ios-adi-split
  python create_ios_adi_manifest.py \\
    --coreadi /path/CoreADI --storeservices /path/StoreServices
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from extract_ios_adi_libs import (  # noqa: E402
    ANDROID_ADI_SYMBOLS,
    analyze_symbols,
    default_out_dir,
)

MIN_SIZE = 4096


def resolve_path(p: Path) -> Path:
    return p.expanduser().resolve()


def is_valid_adi_binary(path: Path, role: str) -> bool:
    """Evita falsi positivi (es. TextToSpeech* con solo punteggio per dimensione)."""
    if not path.is_file() or path.stat().st_size < MIN_SIZE:
        return False
    if path.name.endswith(".tbd"):
        return False

    name = path.name
    low = name.lower()
    full = str(path).lower()

    if role == "coreadi":
        return low == "coreadi" and "coreadi.framework" in full

    if role == "storeservices":
        return low == "storeservices" and "storeservices.framework" in full

    return False


def find_in_tree(root: Path, role: str) -> Path | None:
    root = resolve_path(root)
    if not root.is_dir():
        return None

    patterns = {
        "coreadi": [
            "**/CoreADI.framework/CoreADI",
            "**/CoreADI.framework/Versions/A/CoreADI",
            "**/CoreADI.framework/Versions/Current/CoreADI",
        ],
        "storeservices": [
            "**/StoreServices.framework/StoreServices",
            "**/StoreServices.framework/Versions/A/StoreServices",
            "**/StoreServices.framework/Versions/Current/StoreServices",
        ],
    }
    for pattern in patterns.get(role, []):
        hits = sorted(root.glob(pattern), key=lambda p: p.stat().st_size, reverse=True)
        for hit in hits:
            if is_valid_adi_binary(hit, role):
                return hit

    # Fallback: solo nome esatto + framework corretto (mai per dimensione sola)
    exact_names = {"coreadi": "CoreADI", "storeservices": "StoreServices"}
    want = exact_names.get(role, "")
    for path in root.rglob(want):
        if is_valid_adi_binary(path, role):
            return path

    return None


def list_candidates(root: Path) -> None:
    root = resolve_path(root)
    print(f"Scansione: {root}")
    if not root.exists():
        print("  (cartella inesistente — controlla il percorso)")
        return
    if not root.is_dir():
        print("  (non è una cartella)")
        return

    top = sorted(root.iterdir(), key=lambda p: p.name.lower())[:30]
    print(f"\nContenuto primo livello ({len(list(root.iterdir()))} voci):")
    for p in top:
        kind = "dir" if p.is_dir() else "file"
        extra = f"  {p.stat().st_size} bytes" if p.is_file() else ""
        print(f"  [{kind}] {p.name}{extra}")

    print("\nCandidati ADI (match rigoroso):")
    found_any = False
    for role in ("coreadi", "storeservices"):
        hit = find_in_tree(root, role)
        if hit:
            found_any = True
            print(f"  [{role}] {hit.stat().st_size:>10}  {hit}")
        else:
            print(f"  [{role}] NON TROVATO")

    print("\nAltri file con 'coreadi' / 'storeservices' nel nome (solo info):")
    for path in sorted(root.rglob("*"), key=lambda p: str(p).lower()):
        if not path.is_file() or path.stat().st_size < MIN_SIZE:
            continue
        low = path.name.lower()
        if "coreadi" in low or "storeservices" in low:
            ok = is_valid_adi_binary(path, "coreadi") or is_valid_adi_binary(path, "storeservices")
            tag = "OK" if ok else "skip"
            print(f"  [{tag}] {path.stat().st_size:>10}  {path}")

    if not found_any:
        print("\n  CoreADI / StoreServices assenti nello split.")
        print("  ipsw dyld split spesso non basta — usa extract dal DSC:")
        print('    ipsw dyld extract "$DSC" /System/Library/PrivateFrameworks/CoreADI.framework/CoreADI -o ~/ios-adi-extract --slide --force')
        print('    ipsw dyld extract "$DSC" /System/Library/PrivateFrameworks/StoreServices.framework/StoreServices -o ~/ios-adi-extract --slide --force')


def main() -> int:
    parser = argparse.ArgumentParser(description="Crea manifest.json da lib ADI già estratte")
    parser.add_argument("--coreadi", type=Path, help="Percorso binario CoreADI")
    parser.add_argument("--storeservices", type=Path, help="Percorso binario StoreServices")
    parser.add_argument("--scan", type=Path, help="Cerca CoreADI/StoreServices sotto questa cartella")
    parser.add_argument("--list", type=Path, metavar="DIR", help="Elenca candidati senza creare manifest")
    parser.add_argument("--out", type=Path, default=None, help="Cartella ios-adi-libs (default AppData)")
    parser.add_argument("--source-dsc", type=Path, default=None, help="dyld_shared_cache sorgente (opzionale)")
    parser.add_argument(
        "--skip-analysis",
        action="store_true",
        help="Salta analisi LIEF (consigliato per binari da ipsw dyld split)",
    )
    args = parser.parse_args()

    if args.list:
        list_candidates(args.list)
        return 0

    if not args.scan and not (args.coreadi and args.storeservices):
        parser.error("Specifica --scan, --list, oppure --coreadi + --storeservices")

    out_dir = resolve_path(args.out) if args.out else default_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    core = resolve_path(args.coreadi) if args.coreadi else None
    ss = resolve_path(args.storeservices) if args.storeservices else None
    if args.scan:
        scan_root = resolve_path(args.scan)
        core = core or find_in_tree(scan_root, "coreadi")
        ss = ss or find_in_tree(scan_root, "storeservices")

    if not core or not core.is_file():
        print("ERRORE: CoreADI non trovato.", file=sys.stderr)
        if args.scan:
            list_candidates(args.scan)
        return 1
    if not ss or not ss.is_file():
        print("ERRORE: StoreServices non trovato.", file=sys.stderr)
        if args.scan:
            list_candidates(args.scan)
        return 1

    extracted: dict[str, str] = {}
    analysis: dict[str, object] = {}
    for role, src in (("coreadi", core), ("storeservices", ss)):
        dest = out_dir / f"{role}.dylib"
        dest.write_bytes(src.read_bytes())
        extracted[role] = str(dest)
        if args.skip_analysis:
            analysis[role] = {"path": str(dest), "size": dest.stat().st_size, "skipped": True}
        else:
            info = analyze_symbols(dest)
            analysis[role] = info
            if info.get("error"):
                print(f"  avviso {role}: {info['error']}")
        print(f"OK {role}: {src} → {dest} ({dest.stat().st_size} bytes)")

    note = "Creato da create_ios_adi_manifest.py (estrazione manuale ipsw)"
    if args.skip_analysis:
        note += "; symbol_analysis saltata (split binaries)"

    manifest = {
        "source_dsc": str(resolve_path(args.source_dsc)) if args.source_dsc else "",
        "extracted": extracted,
        "extractor": "manual",
        "android_reference_symbols": ANDROID_ADI_SYMBOLS,
        "symbol_analysis": analysis,
        "status": "ready",
        "note": note,
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"\nmanifest.json: {manifest_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
