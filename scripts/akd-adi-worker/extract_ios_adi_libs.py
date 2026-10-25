#!/usr/bin/env python3
"""
Estrae CoreADI + StoreServices da dyld_shared_cache iOS (Mach-O).

Uso:
  python extract_ios_adi_libs.py --dsc "C:\\path\\dyld_shared_cache_arm64"
  python extract_ios_adi_libs.py --ipsw "C:\\path\\iPhone16,1_18.x_Restore.ipsw"  # richiede CLI ipsw

Output: %AppData%\\iCloudKitExtractor\\ios-adi-libs\\
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import platform
import re
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path
from urllib.request import urlretrieve

IPSW_WIN_URL = (
    "https://github.com/blacktop/ipsw/releases/download/v3.1.700/ipsw_3.1.700_windows_x86_64.zip"
)

# Nomi Android (Anisette.py) — per confronto simboli
ANDROID_ADI_SYMBOLS = [
    "kq56gsgHG6",  # ADILoadLibraryWithPath
    "Sph98paBcz",  # ADISetAndroidID
    "nf92ngaK92",  # ADISetProvisioningPath
    "p435tmhbla",  # ADIProvisioningErase
    "tn46gtiuhw",  # ADISynchronize
    "fy34trz2st",  # ADIProvisioningDestroy
    "uv5t6nhkui",  # ADIProvisioningEnd
    "rsegvyrt87",  # ADIProvisioningStart
    "aslgmuibau",  # ADIGetLoginCode
    "jk24uiwqrg",  # ADIDispose
    "qi864985u0",  # ADIOTPRequest
]

IOS_LIB_PATTERNS = (
    "coreadi",
    "storeservices",
    "storeservicescore",
)

KNOWN_IOS_ADI_PATHS: dict[str, list[str]] = {
    "coreadi": [
        "/System/Library/PrivateFrameworks/CoreADI.framework/CoreADI",
    ],
    "storeservices": [
        "/System/Library/PrivateFrameworks/StoreServices.framework/StoreServices",
    ],
}


def app_data_root() -> Path:
    if sys.platform == "win32":
        return Path.home() / "AppData" / "Roaming" / "iCloudKitExtractor"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "iCloudKitExtractor"
    return Path.home() / ".config" / "iCloudKitExtractor"


def default_out_dir() -> Path:
    return app_data_root() / "ios-adi-libs"


def find_dsc_in_tree(root: Path) -> list[Path]:
    found: list[Path] = []
    for p in root.rglob("dyld_shared_cache*"):
        if p.is_file() and "symbols" not in p.name.lower():
            found.append(p)
    return sorted(found)


def tools_dir() -> Path:
    return app_data_root() / "tools"


def resolve_ipsw_cli() -> Path | None:
    """Trova ipsw in PATH o in %AppData%\\iCloudKitExtractor\\tools\\."""
    found = shutil.which("ipsw")
    if found:
        return Path(found)
    bundled = tools_dir() / "ipsw.exe"
    if bundled.is_file():
        return bundled
    return None


def ensure_ipsw_cli_windows() -> Path | None:
    """Scarica ipsw.exe Windows (utile per --dsc / analisi, non per --dyld)."""
    if platform.system() != "Windows":
        return resolve_ipsw_cli()
    existing = resolve_ipsw_cli()
    if existing:
        return existing
    dest = tools_dir()
    dest.mkdir(parents=True, exist_ok=True)
    exe = dest / "ipsw.exe"
    if exe.is_file():
        return exe
    zip_path = dest / "ipsw_win.zip"
    logging.info("Download ipsw CLI Windows (~27 MB)…")
    try:
        urlretrieve(IPSW_WIN_URL, zip_path)  # noqa: S310
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if name.endswith("ipsw.exe"):
                    zf.extract(name, dest)
                    extracted = dest / name
                    if extracted != exe:
                        shutil.move(str(extracted), str(exe))
                    break
    except OSError as ex:
        logging.warning("Download ipsw fallito: %s", ex)
        return None
    return exe if exe.is_file() else None


def windows_ipsw_limitation_message(ipsw: Path) -> str:
    ipsw_wsl = str(ipsw).replace("\\", "/")
    if len(ipsw_wsl) > 1 and ipsw_wsl[1] == ":":
        ipsw_wsl = f"/mnt/{ipsw_wsl[0].lower()}{ipsw_wsl[2:]}"
    out_wsl = "/mnt/c/Users/$USER/AppData/Roaming/iCloudKitExtractor/ios-adi-libs/_work/ipsw_dyld"
    return f"""
Su Windows NON si può estrarre dyld_shared_cache dall'IPSW:
  • il dyld è dentro DMG APFS criptati
  • ipsw su Windows non supporta --dyld né il mount APFS (manca apfs-fuse)

Il tuo IPSW è valido ({ipsw.name}, ~{ipsw.stat().st_size // (1024**3)} GB).
Serve uno di questi passaggi:

── Opzione 1: WSL2 (consigliata su questo PC) ──
  wsl --install
  # Riavvia, poi in Ubuntu:
  curl -sL https://github.com/blacktop/ipsw/releases/download/v3.1.700/ipsw_3.1.700_linux_amd64.tar.gz | tar xz
  sudo mv ipsw /usr/local/bin/
  ipsw extract --dyld "{ipsw_wsl}" -o "{out_wsl}"
  # Poi su Windows (PowerShell):
  .\\scripts\\extract-ios-adi-libs.ps1 -DscPath "$env:APPDATA\\iCloudKitExtractor\\ios-adi-libs\\_work\\ipsw_dyld\\**\\dyld_shared_cache_arm64"

── Opzione 2: Mac ──
  brew install blacktop/tap/ipsw   # oppure scarica release
  ipsw extract --dyld "{ipsw}" -o ~/ipsw_dyld
  Copia dyld_shared_cache_arm64* su Windows e usa -DscPath

── Opzione 3: dyld già estratto ──
  .\\scripts\\extract-ios-adi-libs.ps1 -DscPath "C:\\path\\dyld_shared_cache_arm64"

Script WSL automatico: .\\scripts\\extract-dyld-via-wsl.ps1 -IpswPath "{ipsw}"
""".strip()


def extract_dyld_from_ipsw(ipsw: Path, work_dir: Path) -> Path | None:
    """Estrae dyld da IPSW via CLI ipsw (Mac/Linux/WSL). Su Windows nativo non supportato."""
    ipsw = ipsw.resolve()
    work_dir.mkdir(parents=True, exist_ok=True)

    if platform.system() == "Windows":
        ensure_ipsw_cli_windows()
        logging.error(windows_ipsw_limitation_message(ipsw))
        return None

    cli = resolve_ipsw_cli()
    if cli:
        logging.info("Estrazione dyld con %s extract --dyld …", cli)
        out = work_dir / "ipsw_dyld"
        out.mkdir(exist_ok=True)
        proc = subprocess.run(
            [str(cli), "extract", "--dyld", str(ipsw), "-o", str(out)],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            logging.error("ipsw extract fallito (exit %s): %s", proc.returncode, err[:2000])
        dsc = find_dsc_in_tree(out)
        if dsc:
            return dsc[0]

    logging.info("Fallback: cerco dyld_shared_cache nello zip IPSW …")
    zip_dir = work_dir / "ipsw_zip"
    if zip_dir.exists():
        shutil.rmtree(zip_dir, ignore_errors=True)
    zip_dir.mkdir(parents=True)

    with zipfile.ZipFile(ipsw, "r") as zf:
        zf.extractall(zip_dir)

    dsc = find_dsc_in_tree(zip_dir)
    return dsc[0] if dsc else None


def list_candidate_dylibs(cache) -> list[tuple[str, str]]:
    """Ritorna (nome file, path in cache) per librerie ADI."""
    hits: list[tuple[str, str]] = []
    for lib in cache.libraries:
        if lib is None:
            continue
        path = getattr(lib, "path", "") or ""
        name = Path(path).name.lower()
        full = path.lower()
        if any(p in name or p in full for p in IOS_LIB_PATTERNS):
            hits.append((Path(path).name, path))
    return hits


def extract_macho(cache, lib_path: str, out_file: Path) -> bool:
    import lief

    dylib = cache.find_lib_from_path(lib_path)
    if dylib is None:
        dylib = cache.find_lib_from_name(Path(lib_path).name)
    if dylib is None:
        logging.warning("Dylib non trovata: %s", lib_path)
        return False

    opt = lief.dsc.Dylib.extract_opt_t()
    opt.fix_branches = True
    opt.fix_memory = True
    opt.fix_relocations = True

    macho = dylib.get(opt)
    if macho is None:
        logging.warning("get() fallito: %s", lib_path)
        return False

    out_file.parent.mkdir(parents=True, exist_ok=True)
    macho.write(str(out_file))
    logging.info("Scritto %s (%s bytes)", out_file, out_file.stat().st_size)
    return True


def _macho_arm64_slice(parsed):
    import lief

    if parsed is None:
        return None
    if isinstance(parsed, lief.MachO.FatBinary):
        try:
            return parsed.at(0)
        except Exception:  # noqa: BLE001
            return None
    if hasattr(parsed, "at"):
        try:
            return parsed.at(0)
        except Exception:  # noqa: BLE001
            pass
    return parsed


def analyze_symbols(macho_path: Path) -> dict:
    import lief

    base: dict = {
        "path": str(macho_path),
        "size": macho_path.stat().st_size,
    }
    try:
        parsed = lief.MachO.parse(str(macho_path))
    except Exception as ex:  # noqa: BLE001
        return {**base, "error": f"parse exception: {ex}"}

    if parsed is None:
        return {**base, "error": "parse failed"}

    binary = _macho_arm64_slice(parsed)
    if binary is None:
        return {**base, "error": "no arm64 slice"}

    symbols = getattr(binary, "symbols", None)
    if symbols is None:
        return {
            **base,
            "error": "no symbol table (tipico di ipsw dyld split — preferisci ipsw dyld extract --slide)",
        }

    exports: list[str] = []
    try:
        for sym in symbols:
            if sym.exported and sym.name:
                exports.append(sym.name)
    except Exception as ex:  # noqa: BLE001
        return {**base, "error": f"symbol iteration: {ex}", "export_count": len(exports)}

    android_hits = [s for s in ANDROID_ADI_SYMBOLS if s in exports]
    adi_like = [s for s in exports if "adi" in s.lower() or "ADI" in s]

    return {
        **base,
        "export_count": len(exports),
        "android_symbol_hits": android_hits,
        "adi_like_exports": adi_like[:40],
        "sample_exports": sorted(exports)[:30],
    }


def pick_primary_libs(candidates: list[tuple[str, str]]) -> dict[str, str]:
    """Sceglie CoreADI e StoreServices migliori."""
    chosen: dict[str, str] = {}
    for name, path in candidates:
        low = name.lower()
        if "coreadi" in low and "coreadi" not in chosen:
            chosen["coreadi"] = path
        if "storeservices" in low and "storeservices" not in chosen:
            chosen["storeservices"] = path
    return chosen


def _run_ipsw(args: list[str], dsc_dir: Path | None = None) -> subprocess.CompletedProcess[str]:
    env = os.environ.copy()
    if dsc_dir is not None:
        env["IPSW_DSC_PATH"] = str(dsc_dir)
    return subprocess.run(args, capture_output=True, text=True, env=env)


def discover_adi_paths_ipsw(cli: Path, dsc_path: Path) -> dict[str, str]:
    """Trova path in-cache di CoreADI / StoreServices via ipsw dyld image."""
    chosen = {role: paths[0] for role, paths in KNOWN_IOS_ADI_PATHS.items()}
    proc = _run_ipsw([str(cli), "dyld", "image", str(dsc_path)], dsc_path.parent)
    if proc.returncode != 0:
        logging.debug("ipsw dyld image: %s", (proc.stderr or proc.stdout)[:500])
        return chosen

    text = proc.stdout or ""
    for line in text.splitlines():
        low = line.lower()
        if "coreadi" in low and "/coreadi.framework/" in low:
            m = re.search(r"/System/Library/PrivateFrameworks/CoreADI\.framework/CoreADI", line)
            if m:
                chosen["coreadi"] = m.group(0)
        if "storeservices" in low and ".framework/" in low:
            m = re.search(
                r"/System/Library/PrivateFrameworks/StoreServices\.framework/StoreServices",
                line,
            )
            if m:
                chosen["storeservices"] = m.group(0)
    return chosen


def _pick_extracted_macho(work_dir: Path, hint: str) -> Path | None:
    hint_low = hint.lower()
    candidates = [
        p
        for p in work_dir.rglob("*")
        if p.is_file() and p.stat().st_size > 4096 and not p.name.endswith(".tbd")
    ]
    for p in sorted(candidates, key=lambda x: x.stat().st_size, reverse=True):
        name = p.name.lower()
        if hint_low in name or hint_low in str(p).lower():
            return p
    return candidates[0] if candidates else None


def ipsw_extract_dylib(cli: Path, dsc_path: Path, lib_path: str, out_file: Path) -> bool:
    """Estrae un dylib dal DSC con ipsw (extract → macho --extract)."""
    work = out_file.parent / f"_ipsw_{out_file.stem}"
    if work.exists():
        shutil.rmtree(work, ignore_errors=True)
    work.mkdir(parents=True, exist_ok=True)

    attempts = [
        [str(cli), "dyld", "extract", str(dsc_path), lib_path, "-o", str(work), "--slide", "--force"],
        [
            str(cli),
            "dyld",
            "macho",
            str(dsc_path),
            lib_path,
            "--extract",
            "--output",
            str(work),
            "--force",
        ],
    ]
    hint = Path(lib_path).name
    for args in attempts:
        logging.info("ipsw: %s", " ".join(args[2:6]))
        proc = _run_ipsw(args, dsc_path.parent)
        if proc.returncode != 0:
            err = (proc.stderr or proc.stdout or "").strip()
            if err:
                logging.debug("ipsw fallito: %s", err[:800])
            continue
        found = _pick_extracted_macho(work, hint)
        if found and found.stat().st_size > 4096:
            out_file.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(found, out_file)
            logging.info("Scritto %s (%s bytes) via ipsw", out_file, out_file.stat().st_size)
            shutil.rmtree(work, ignore_errors=True)
            return True

    shutil.rmtree(work, ignore_errors=True)
    return False


def ipsw_split_dsc(cli: Path, dsc_path: Path, split_root: Path) -> Path | None:
    """Split completo DSC (macOS + Xcode dsc_extractor)."""
    if platform.system() != "Darwin":
        return None
    if split_root.exists():
        shutil.rmtree(split_root, ignore_errors=True)
    split_root.mkdir(parents=True, exist_ok=True)

    args = [str(cli), "dyld", "split", str(dsc_path), "-o", str(split_root)]
    xcode = os.environ.get("XCODE_PATH", "/Applications/Xcode.app")
    if Path(xcode).exists():
        args.extend(["-x", xcode])

    logging.info("ipsw dyld split (richiede Xcode iPhoneOS platform)…")
    proc = _run_ipsw(args, dsc_path.parent)
    if proc.returncode != 0:
        err = (proc.stderr or proc.stdout or "").strip()
        logging.warning("ipsw dyld split fallito: %s", err[:1200])
        logging.warning(
            "Prova: sudo xcode-select -s /Applications/Xcode.app "
            "oppure export XCODE_PATH=/Applications/Xcode.app"
        )
        return None
    return split_root


def find_split_dylibs(split_root: Path) -> dict[str, Path]:
    found: dict[str, Path] = {}
    patterns = {
        "coreadi": ["**/CoreADI.framework/CoreADI", "**/CoreADI"],
        "storeservices": ["**/StoreServices.framework/StoreServices", "**/StoreServices"],
    }
    for role, globs in patterns.items():
        for pattern in globs:
            hits = sorted(split_root.glob(pattern), key=lambda p: p.stat().st_size, reverse=True)
            for hit in hits:
                if hit.is_file() and hit.stat().st_size > 4096:
                    found[role] = hit
                    break
            if role in found:
                break
    return found


def run_extraction_ipsw(dsc_path: Path, out_dir: Path) -> int:
    cli = resolve_ipsw_cli()
    if cli is None:
        logging.error(
            "LIEF pip non apre questo dyld_shared_cache (serve LIEF Extended).\n"
            "Installa ipsw: brew install blacktop/tap/ipsw"
        )
        return 1

    logging.info("Fallback ipsw — LIEF DSC non disponibile nella build pip gratuita")
    lib_paths = discover_adi_paths_ipsw(cli, dsc_path)
    logging.info("Path target: %s", lib_paths)

    extracted: dict[str, str] = {}
    analysis: dict[str, object] = {}

    for role, lib_path in lib_paths.items():
        out_file = out_dir / f"{role}.dylib"
        if ipsw_extract_dylib(cli, dsc_path, lib_path, out_file):
            extracted[role] = str(out_file)
            analysis[role] = analyze_symbols(out_file)

    if len(extracted) < 2:
        split_root = out_dir / "_ipsw_split"
        split_dir = ipsw_split_dsc(cli, dsc_path, split_root)
        if split_dir:
            for role, src in find_split_dylibs(split_dir).items():
                if role in extracted:
                    continue
                out_file = out_dir / f"{role}.dylib"
                shutil.copy2(src, out_file)
                extracted[role] = str(out_file)
                analysis[role] = analyze_symbols(out_file)

    if not extracted:
        logging.error(
            "Estrazione fallita. Su Mac serve Xcode completo (non solo Command Line Tools):\n"
            "  sudo xcode-select -s /Applications/Xcode.app\n"
            "  export XCODE_PATH=/Applications/Xcode.app\n"
            "Poi rilancia extract-ios-adi-libs.sh"
        )
        return 1

    status = "ready" if len(extracted) >= 2 else "partial"
    manifest = {
        "source_dsc": str(dsc_path),
        "extracted": extracted,
        "extractor": "ipsw",
        "android_reference_symbols": ANDROID_ADI_SYMBOLS,
        "symbol_analysis": analysis,
        "status": status,
        "note": "Mach-O iOS via ipsw — LIEF Extended non richiesto per l'estrazione",
    }
    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logging.info("Manifest: %s", manifest_path)
    return 0 if extracted else 1


def run_extraction_lief(cache, dsc_path: Path, out_dir: Path) -> int:
    cache_dir = out_dir / ".lief_cache"
    cache_dir.mkdir(parents=True, exist_ok=True)

    try:
        cache.enable_caching(str(cache_dir))
    except Exception:  # noqa: BLE001
        pass

    candidates = list_candidate_dylibs(cache)
    logging.info("Candidati ADI: %d", len(candidates))
    for name, path in candidates[:20]:
        logging.info("  %s → %s", name, path)

    if not candidates:
        logging.error("Nessuna libreria CoreADI/StoreServices nel cache")
        return 1

    primary = pick_primary_libs(candidates)
    if "coreadi" not in primary or "storeservices" not in primary:
        logging.warning("Set incompleto, uso primi match: %s", primary)

    extracted: dict[str, str] = {}
    analysis: dict[str, object] = {}

    for role, lib_path in primary.items():
        out_name = f"{role}.dylib"
        out_file = out_dir / out_name
        if extract_macho(cache, lib_path, out_file):
            extracted[role] = str(out_file)
            analysis[role] = analyze_symbols(out_file)

    manifest = {
        "source_dsc": str(dsc_path),
        "extracted": extracted,
        "extractor": "lief",
        "android_reference_symbols": ANDROID_ADI_SYMBOLS,
        "symbol_analysis": analysis,
        "status": "ready" if len(extracted) >= 2 else "partial",
        "note": "Mach-O iOS — richiede ios_macho_backend (non ELF Anisette.py)",
    }

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logging.info("Manifest: %s", manifest_path)

    for role, info in analysis.items():
        if isinstance(info, dict):
            hits = info.get("android_symbol_hits", [])
            logging.info("[%s] export=%s android_hits=%s", role, info.get("export_count"), hits)

    return 0 if extracted else 1


def run_extraction(dsc_path: Path, out_dir: Path) -> int:
    import lief

    dsc_path = dsc_path.resolve()
    if not dsc_path.is_file():
        logging.error("DSC non trovato: %s", dsc_path)
        return 1

    logging.info("Caricamento DSC (può richiedere minuti)… %s", dsc_path)
    cache = None
    try:
        cache = lief.dsc.load(str(dsc_path))
    except Exception as ex:  # noqa: BLE001
        logging.warning("lief.dsc.load eccezione: %s", ex)

    if cache is None:
        logging.warning(
            "LIEF pip non apre questo dyld_shared_cache (iOS recenti → LIEF Extended)."
        )
        return run_extraction_ipsw(dsc_path, out_dir)

    return run_extraction_lief(cache, dsc_path, out_dir)


def print_usage_help() -> None:
    print(
        """
Estrazione CoreADI + StoreServices da iOS (Mach-O)

Serve UNO di questi input:

  1) dyld_shared_cache già estratto (consigliato se lo hai da Mac/ipsw):
     python extract_ios_adi_libs.py --dsc "C:\\path\\dyld_shared_cache_arm64"

  2) file IPSW (.ipsw = zip firmware iPhone):
     python extract_ios_adi_libs.py --ipsw "C:\\path\\iPhone16,1_18.5_22F76_Restore.ipsw"

Oppure da PowerShell nella root del repo:
  .\\scripts\\extract-ios-adi-libs.ps1 -DscPath "C:\\path\\dyld_shared_cache_arm64"
  .\\scripts\\extract-ios-adi-libs.ps1 -IpswPath "C:\\path\\file.ipsw"

Come ottenere il dyld_shared_cache su Windows
---------------------------------------------
L'IPSW contiene DMG APFS criptati: su Windows NATIVO non si può estrarre il dyld.

A) WSL2 (consigliato):
   wsl --install
   .\\scripts\\extract-dyld-via-wsl.ps1 -IpswPath "C:\\path\\file.ipsw"
   Poi riesegui questo script con -DscPath sul dyld estratto.

B) Mac / Linux:
   ipsw extract --dyld file.ipsw -o ./ipsw_dyld
   Copia dyld_shared_cache_arm64* su Windows → --dsc

C) dyld già estratto:
   python extract_ios_adi_libs.py --dsc "C:\\path\\dyld_shared_cache_arm64"

Output: %AppData%\\iCloudKitExtractor\\ios-adi-libs\\
Vedi docs\\EMULATED_AKD.md
""".strip()
    )


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(
        description="Estrai lib ADI iOS da dyld shared cache",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Esegui senza argomenti per la guida completa.",
    )
    parser.add_argument("--dsc", type=Path, help="Percorso dyld_shared_cache_arm64*")
    parser.add_argument("--ipsw", type=Path, help="File IPSW (richiede ipsw CLI o dyld nello zip)")
    parser.add_argument("--out", type=Path, default=None)
    parser.add_argument("--work", type=Path, default=None, help="Directory temporanea IPSW")
    args = parser.parse_args()

    if not args.dsc and not args.ipsw:
        print_usage_help()
        return 1

    out_dir = args.out or default_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    dsc: Path | None = args.dsc
    if args.ipsw:
        if not args.ipsw.is_file():
            logging.error("IPSW non trovato: %s", args.ipsw)
            return 1
        work = args.work or (out_dir / "_work")
        dsc = extract_dyld_from_ipsw(args.ipsw, work)
        if dsc is None:
            if platform.system() == "Windows":
                return 1
            logging.error(
                "dyld_shared_cache non trovato nell'IPSW. "
                "Installa ipsw: https://github.com/blacktop/ipsw/releases"
            )
            return 1

    if dsc is None:
        print_usage_help()
        return 1

    if not dsc.is_file():
        logging.error("DSC non trovato: %s", dsc)
        return 1

    return run_extraction(dsc, out_dir)


if __name__ == "__main__":
    raise SystemExit(main())
