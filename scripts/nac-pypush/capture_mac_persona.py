#!/usr/bin/env python3
"""
Capture a Mac NAC persona (data.plist) from IOKit via `ioreg`.

Run on a real Mac that already has working iMessage (lab Apple ID):

  python3 capture_mac_persona.py -o ./my-mac-data.plist

Then on Windows, in iCloudKitExtractor Trusted devices → "Load Mac persona…"
and select that file. NAC validation-data + Madrid id-register will use it.

Note: iPhone Frida Anisette is separate; this dump is Mac-shaped (MLB/ROM/serial).
"""
from __future__ import annotations

import argparse
import base64
import plistlib
import re
import subprocess
import sys
import uuid


IOKIT_GUID = "4D1EDE05-38C7-4A6A-9CC6-4BCCA8B38C14"


def _ioreg_platform() -> str:
    return subprocess.check_output(
        ["ioreg", "-c", "IOPlatformExpertDevice", "-d", "2", "-a"],
        text=False,
    )


def _ioreg_options() -> str:
    # DeviceTree options hold MLB / ROM
    try:
        return subprocess.check_output(
            ["ioreg", "-p", "IODeviceTree", "-n", "options", "-r", "-a"],
            text=False,
        )
    except subprocess.CalledProcessError:
        return b""


def _find_key(blob: bytes, key: str):
    """Best-effort extract from ioreg -a (XML plist)."""
    try:
        root = plistlib.loads(blob)
    except Exception:
        return None

    def walk(obj):
        if isinstance(obj, dict):
            if key in obj:
                return obj[key]
            for v in obj.values():
                found = walk(v)
                if found is not None:
                    return found
        elif isinstance(obj, list):
            for v in obj:
                found = walk(v)
                if found is not None:
                    return found
        return None

    return walk(root)


def _as_data(val) -> bytes | None:
    if val is None:
        return None
    if isinstance(val, bytes):
        return val
    if isinstance(val, str):
        return val.encode("utf-8")
    return None


def build_data_plist() -> dict:
    plat = _ioreg_platform()
    opt = _ioreg_options()

    serial = _find_key(plat, "IOPlatformSerialNumber")
    platform_uuid = _find_key(plat, "IOPlatformUUID")
    board_id = _as_data(_find_key(plat, "board-id"))
    product = _as_data(_find_key(plat, "model") or _find_key(plat, "product-name"))
    mac = _as_data(_find_key(plat, "IOMACAddress"))

    mlb = _as_data(_find_key(opt, f"{IOKIT_GUID}:MLB")) or _as_data(_find_key(opt, "MLB"))
    rom = _as_data(_find_key(opt, f"{IOKIT_GUID}:ROM")) or _as_data(_find_key(opt, "ROM"))

    if not serial:
        raise SystemExit("IOPlatformSerialNumber missing — run on macOS with ioreg.")

    # Encrypted gibberish keys (Gq3489ugfi etc.) are produced by XNU on real Macs.
    # When missing, keep empty placeholders — prefer a full dump from nacserver extractor
    # if Apple still returns 6009 with this partial persona.
    iokit = {
        "IOPlatformSerialNumber": str(serial),
        "IOPlatformUUID": str(platform_uuid or uuid.uuid4()).upper(),
    }
    if mlb:
        iokit[f"{IOKIT_GUID}:MLB"] = mlb
    if rom:
        iokit[f"{IOKIT_GUID}:ROM"] = rom
    if board_id:
        iokit["board-id"] = board_id if board_id.endswith(b"\x00") else board_id + b"\x00"
    if product:
        iokit["product-name"] = product if product.endswith(b"\x00") else product + b"\x00"
    if mac:
        iokit["IOMACAddress"] = mac

    root_disk = str(uuid.uuid4()).upper()
    # Try diskutil for real volume UUID
    try:
        out = subprocess.check_output(
            ["diskutil", "info", "-plist", "/"], text=False
        )
        info = plistlib.loads(out)
        root_disk = info.get("VolumeUUID") or info.get("DiskUUID") or root_disk
    except Exception:
        pass

    return {"iokit": iokit, "root_disk_uuid": str(root_disk)}


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture Mac NAC data.plist via ioreg")
    ap.add_argument("-o", "--output", default="data.plist", help="Output data.plist path")
    args = ap.parse_args()

    if sys.platform != "darwin":
        print("This capture script must run on macOS.", file=sys.stderr)
        print("On Windows: copy a data.plist from your Mac, then use Load Mac persona.", file=sys.stderr)
        return 2

    data = build_data_plist()
    with open(args.output, "wb") as f:
        plistlib.dump(data, f, fmt=plistlib.FMT_XML)
    serial = data["iokit"]["IOPlatformSerialNumber"]
    print(f"Wrote {args.output} serial={serial}")
    print("Copy to Windows and import via Trusted devices → Load Mac persona.")
    if f"{IOKIT_GUID}:MLB" not in data["iokit"] or f"{IOKIT_GUID}:ROM" not in data["iokit"]:
        print("WARNING: MLB/ROM missing — Apple may still return 6009. Prefer nacserver full extractor.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
