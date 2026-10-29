#!/usr/bin/env python3
"""Fetch anisette JSON via the same path that works interactively:

  python -m frida_tools.repl -H IP:27042 -n akd -l frida_anisette.js

Frida 17's session.create_script() has no ObjC bridge (REPL does). This tool
spawns frida_tools.repl, reads the marked JSON line, then kills the REPL.

CLI:
  python fetch_anisette.py -H 192.168.1.158:27042

From code:
  from fetch_anisette import fetch_anisette
  data = fetch_anisette(host="192.168.1.158:27042")
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).with_name("frida_anisette.js")
LITE_SCRIPT_PATH = Path(__file__).with_name("frida_anisette_lite.js")
DEFAULT_PORT = 27042
MARKER = "__ANISETTE_JSON__"


def parse_host(value: str) -> str:
    value = value.strip()
    if not value:
        raise ValueError("empty host")
    if ":" not in value:
        return f"{value}:{DEFAULT_PORT}"
    host, _, port = value.rpartition(":")
    if not host or not port.isdigit():
        raise ValueError("use HOST or HOST:PORT")
    return value


def _kill(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        if os.name == "nt":
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
        else:
            proc.send_signal(signal.SIGTERM)
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def fetch_anisette(
    *,
    host: str | None = None,
    usb: bool = False,
    name: str = "akd",
    pid: int | None = None,
    script: Path | None = None,
    timeout: float = 60.0,
    lite: bool = False,
) -> dict[str, Any]:
    """Run frida_tools.repl -l -q and return the anisette dict."""
    default = LITE_SCRIPT_PATH if lite else SCRIPT_PATH
    # Prefer lite automatically if full missing; otherwise honour flag/path
    if script is None and lite and LITE_SCRIPT_PATH.is_file():
        script_path = LITE_SCRIPT_PATH.resolve()
    elif script is None and not SCRIPT_PATH.is_file() and LITE_SCRIPT_PATH.is_file():
        script_path = LITE_SCRIPT_PATH.resolve()
    else:
        script_path = (script or default).resolve()
    if not script_path.is_file():
        return {"ok": False, "error": f"script not found: {script_path}"}

    cmd = [sys.executable, "-m", "frida_tools.repl"]
    if usb:
        cmd += ["-U"]
    elif host:
        cmd += ["-H", parse_host(host)]
    else:
        return {"ok": False, "error": "pass host=... or usb=True"}

    if pid is not None:
        cmd += ["-p", str(pid)]
    else:
        cmd += ["-n", name]

    # -q: no interactive prompt, exit after -l; -t: load/run budget (accountsd needs this)
    cmd += ["-l", str(script_path), "-q", "-t", str(max(5, int(timeout)))]

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
        return {"ok": False, "error": f"failed to start frida_tools.repl: {exc}"}

    deadline = time.monotonic() + timeout
    buf: list[str] = []
    payload: dict[str, Any] | None = None

    try:
        assert proc.stdout is not None
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                # drain remaining
                rest = proc.stdout.read() or ""
                if rest:
                    buf.append(rest)
                break
            line = proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            buf.append(line)
            # Marker may appear mid-line after Frida prefixes
            idx = line.find(MARKER)
            if idx >= 0:
                raw = line[idx + len(MARKER) :].strip()
                try:
                    payload = json.loads(raw)
                    break
                except json.JSONDecodeError as exc:
                    return {
                        "ok": False,
                        "error": f"bad JSON after marker: {exc}; raw={raw[:200]!r}",
                    }
        else:
            return {
                "ok": False,
                "error": (
                    f"timeout after {timeout}s waiting for {MARKER}; "
                    f"tail={''.join(buf)[-500:]!r}"
                ),
            }
    finally:
        _kill(proc)

    if payload is None:
        return {
            "ok": False,
            "error": f"no {MARKER} in REPL output; tail={''.join(buf)[-500:]!r}",
        }
    if not isinstance(payload, dict):
        return {"ok": False, "error": f"unexpected payload type: {type(payload)}"}
    return payload


def main() -> int:
    ap = argparse.ArgumentParser(description="Fetch anisette OTP JSON via frida_tools.repl")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-H", "--host", help="Wi‑Fi frida-server HOST or HOST:PORT")
    g.add_argument("-U", "--usb", action="store_true")
    ap.add_argument("-n", "--name", default="akd")
    ap.add_argument("-p", "--pid", type=int, default=None)
    ap.add_argument("-s", "--script", type=Path, default=None)
    ap.add_argument("--lite", action="store_true", help="use frida_anisette_lite.js (faster inject)")
    ap.add_argument("-o", "--output", type=Path, default=None)
    ap.add_argument("--timeout", type=float, default=60.0)
    args = ap.parse_args()

    out = fetch_anisette(
        host=args.host,
        usb=args.usb,
        name=args.name,
        pid=args.pid,
        script=args.script,
        timeout=args.timeout,
        lite=args.lite,
    )

    print(json.dumps(out, separators=(",", ":"), ensure_ascii=False), flush=True)
    if args.output is not None:
        args.output.write_text(json.dumps(out, indent=2) + "\n", encoding="utf-8")
    return 0 if out.get("ok") is True else 1


if __name__ == "__main__":
    raise SystemExit(main())
