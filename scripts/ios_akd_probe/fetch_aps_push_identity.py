#!/usr/bin/env python3
"""Dump iPhone APSClientIdentity (push cert+key) via Frida → madrid-persona.

  python fetch_aps_push_identity.py -H PHONE_IP:27042

Writes:
  %AppData%/iCloudKitExtractor/madrid-persona/iphone-push.cert.pem
  %AppData%/iCloudKitExtractor/madrid-persona/iphone-push.key.pem

Then Enroll Madrid can sign x-push-sig with the same identity as Frida
validation-data / iPhone push token (needed to clear 6009 Albert mismatch).
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).with_name("frida_aps_push_identity.js")
DEFAULT_PORT = 27042
MARKER = "__APS_PUSH_JSON__"


def parse_host(value: str) -> str:
    value = value.strip()
    if ":" not in value:
        return f"{value}:{DEFAULT_PORT}"
    return value


def persona_dir() -> Path:
    appdata = os.environ.get("APPDATA") or str(Path.home())
    d = Path(appdata) / "iCloudKitExtractor" / "madrid-persona"
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_pems(cert_pem: str, key_pem: str) -> dict[str, Any]:
    d = persona_dir()
    cert_path = d / "iphone-push.cert.pem"
    key_path = d / "iphone-push.key.pem"
    meta_path = d / "iphone-push.json"
    cert_path.write_text(cert_pem if cert_pem.endswith("\n") else cert_pem + "\n", encoding="utf-8")
    key_path.write_text(key_pem if key_pem.endswith("\n") else key_pem + "\n", encoding="utf-8")
    meta = {
        "savedUtc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "cert_path": str(cert_path),
        "key_path": str(key_path),
        "cert_chars": len(cert_pem),
        "key_chars": len(key_pem),
        "source": "frida_aps_push_identity",
    }
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    print(f"[+] wrote {cert_path}", flush=True)
    print(f"[+] wrote {key_path}", flush=True)
    return {"ok": True, **meta}


def capture(*, host: str | None, usb: bool, name: str, timeout: float) -> dict[str, Any]:
    if not SCRIPT_PATH.is_file():
        return {"ok": False, "error": f"missing {SCRIPT_PATH}"}

    cmd = [sys.executable, "-m", "frida_tools.repl"]
    # Prefer frida CLI if available
    frida_bin = None
    for cand in ("frida", "frida.exe"):
        from shutil import which

        frida_bin = which(cand)
        if frida_bin:
            break

    if frida_bin:
        cmd = [frida_bin]
        if usb:
            cmd += ["-U"]
        elif host:
            cmd += ["-H", parse_host(host)]
        else:
            return {"ok": False, "error": "pass -H or --usb"}
        # -t keeps session alive long enough for setTimeout dump; -q quiet banner
        cmd += [
            "-n",
            name,
            "-l",
            str(SCRIPT_PATH.resolve()),
            "-q",
            "-t",
            str(max(15, int(timeout))),
        ]
    else:
        return {
            "ok": False,
            "error": "frida CLI not on PATH (pip install frida-tools)",
        }

    print(f"[*] {' '.join(cmd)}", flush=True)
    print("[*] dumping APSClientIdentity from apsd (may take a few seconds)…", flush=True)

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"spawn failed: {exc}"}

    deadline = time.time() + timeout
    last_payload: dict[str, Any] | None = None
    try:
        assert proc.stdout is not None
        while time.time() < deadline:
            if proc.poll() is not None:
                # drain remaining
                rest = proc.stdout.read() or ""
                for line in rest.splitlines():
                    sys.stderr.write(line + "\n")
                    if MARKER in line:
                        raw = line[line.index(MARKER) + len(MARKER) :].strip()
                        try:
                            last_payload = json.loads(raw)
                        except json.JSONDecodeError:
                            pass
                break

            line = proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            sys.stderr.write(line)
            sys.stderr.flush()
            if MARKER in line:
                raw = line[line.index(MARKER) + len(MARKER) :].strip()
                try:
                    last_payload = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                if last_payload.get("ok") and last_payload.get("cert_pem") and last_payload.get("key_pem"):
                    try:
                        proc.terminate()
                    except Exception:
                        pass
                    return save_pems(last_payload["cert_pem"], last_payload["key_pem"])
        try:
            proc.terminate()
        except Exception:
            pass
    finally:
        try:
            if proc.poll() is None:
                proc.kill()
        except Exception:
            pass

    if last_payload:
        notes = last_payload.get("notes") or []
        return {
            "ok": False,
            "error": "APS dump incomplete (key non-exportable / SecItem miss)",
            "notes": notes,
            "partial": {
                "has_cert": bool(last_payload.get("cert_pem")),
                "has_key": bool(last_payload.get("key_pem")),
            },
        }
    return {"ok": False, "error": "No __APS_PUSH_JSON__ before timeout"}


def main() -> int:
    ap = argparse.ArgumentParser(description="Dump iPhone APS push cert+key via Frida (apsd)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-H", "--host", help="frida-server HOST or HOST:PORT")
    g.add_argument("-U", "--usb", action="store_true")
    ap.add_argument("-n", "--name", default="apsd", help="process name (default apsd)")
    ap.add_argument("--timeout", type=float, default=45.0)
    args = ap.parse_args()

    r = capture(host=args.host, usb=args.usb, name=args.name, timeout=args.timeout)
    print(json.dumps(r, indent=2))
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
