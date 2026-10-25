#!/usr/bin/env python3
"""Rianalizza simboli export nelle lib iOS già estratte (manifest.json)."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from extract_ios_adi_libs import ANDROID_ADI_SYMBOLS, analyze_symbols, app_data_root  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--libs-dir", type=Path, default=None)
    args = parser.parse_args()

    libs = args.libs_dir or (app_data_root() / "ios-adi-libs")
    manifest_path = libs / "manifest.json"
    if not manifest_path.exists():
        print(f"Manifest assente: {manifest_path}")
        print("Esegui: .\\scripts\\extract-ios-adi-libs.ps1 -DscPath <dyld_shared_cache_arm64>")
        return 1

    data = json.loads(manifest_path.read_text(encoding="utf-8"))
    extracted = data.get("extracted") or {}

    print(f"Source DSC: {data.get('source_dsc')}")
    print(f"Android reference symbols: {ANDROID_ADI_SYMBOLS}")
    print()

    for role, path in extracted.items():
        p = Path(path)
        if not p.exists():
            print(f"[{role}] FILE MISSING: {p}")
            continue
        info = analyze_symbols(p)
        print(f"=== {role} ({p.name}) ===")
        print(f"  exports: {info.get('export_count')}")
        print(f"  android hits: {info.get('android_symbol_hits')}")
        adi = info.get("adi_like_exports") or []
        if adi:
            print(f"  adi-like: {adi[:20]}")
        sample = info.get("sample_exports") or []
        if sample:
            print(f"  sample: {sample[:15]}")
        print()

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
