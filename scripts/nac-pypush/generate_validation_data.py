#!/usr/bin/env python3
"""CLI: genera validation-data NAC (pypush emulated/nac.py) → stdout base64."""
from __future__ import annotations

import base64
import json
import logging
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(levelname)s %(message)s")


def main() -> int:
    from emulated import nac as nac_mod

    # Optional: --data-plist PATH  (also IKE_NAC_DATA_PLIST)
    data_plist = None
    if "--data-plist" in sys.argv:
        i = sys.argv.index("--data-plist")
        if i + 1 >= len(sys.argv):
            print("NAC_ERROR: --data-plist requires a path", file=sys.stderr)
            return 2
        data_plist = sys.argv[i + 1]
    if data_plist:
        nac_mod.reload_fake_data(data_plist)

    data = nac_mod.generate_validation_data()
    b64 = base64.b64encode(bytes(data)).decode("ascii")
    serial = None
    try:
        serial = nac_mod.FAKE_DATA.get("iokit", {}).get("IOPlatformSerialNumber")
    except Exception:
        pass
    if "--json" in sys.argv:
        print(json.dumps({
            "validation_data_b64": b64,
            "length": len(data),
            "serial": serial,
            "data_plist": data_plist or os.environ.get("IKE_NAC_DATA_PLIST") or "bundled",
        }))
    else:
        print(b64)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as ex:
        print(f"NAC_ERROR: {ex}", file=sys.stderr)
        raise SystemExit(1)
