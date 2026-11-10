#!/usr/bin/env python3
"""Capture ALL IDS HTTP from iPhone identityservicesd via Frida.

  python fetch_ids_http_capture.py -H PHONE_IP:27042 --timeout 600

Saves under %APPDATA%/iCloudKitExtractor/madrid-persona/ids-http-capture/<run>/
  NNN_req.json / NNN_req.bin
  NNN_resp.json / NNN_resp.bin
  index.jsonl
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).with_name("frida_ids_http_capture.js")
DEFAULT_PORT = 27042
REQ_MARKER = "__IDS_REQ__"
RESP_MARKER = "__IDS_RESP__"
HTTP_MARKER = "__IDS_HTTP__"


def parse_host(value: str) -> str:
    value = value.strip()
    if ":" not in value:
        return f"{value}:{DEFAULT_PORT}"
    return value


def default_out_dir() -> Path:
    appdata = os.environ.get("APPDATA") or str(Path.home())
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    d = (
        Path(appdata)
        / "iCloudKitExtractor"
        / "madrid-persona"
        / "ids-http-capture"
        / stamp
    )
    d.mkdir(parents=True, exist_ok=True)
    return d


def _kill(proc: subprocess.Popen[str]) -> None:
    if proc.poll() is not None:
        return
    try:
        proc.terminate()
        proc.wait(timeout=2)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _maybe_gunzip(raw: bytes) -> bytes:
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    return raw


def _save_event(out_dir: Path, payload: dict[str, Any]) -> None:
    eid = int(payload.get("id") or 0)
    direction = payload.get("dir") or "evt"
    stem = f"{eid:04d}_{direction}"

    body_b64 = payload.pop("body_b64", "") or ""
    meta = dict(payload)
    meta_path = out_dir / f"{stem}.json"
    meta_path.write_text(json.dumps(meta, indent=2), encoding="utf-8")

    raw = b""
    if body_b64:
        try:
            raw = base64.b64decode(body_b64)
        except Exception:
            raw = b""
    if raw:
        (out_dir / f"{stem}.bin").write_bytes(raw)
        plain = _maybe_gunzip(raw)
        if plain is not raw:
            (out_dir / f"{stem}.gunzip.bin").write_bytes(plain)
        # Best-effort text preview
        if plain[:1] in (b"<", b"{") or plain[:6] == b"bplist" or b"plist" in plain[:80]:
            try:
                preview = plain[:200_000]
                (out_dir / f"{stem}.preview.txt").write_bytes(preview)
            except Exception:
                pass

    with (out_dir / "index.jsonl").open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(meta, ensure_ascii=False) + "\n")

    url = str(meta.get("url") or "")[:100]
    if direction == "req":
        print(
            f"[req #{eid}] {meta.get('method')} {url} "
            f"body={meta.get('body_len')} magic={meta.get('magic')}",
            flush=True,
        )
    else:
        print(
            f"[resp #{eid}] status={meta.get('status')} {url} "
            f"body={meta.get('body_len')} magic={meta.get('magic')}",
            flush=True,
        )


def _one_attach(
    *,
    host: str | None,
    usb: bool,
    name: str,
    pid: int | None,
    budget: int,
) -> subprocess.Popen[str]:
    cmd = [sys.executable, "-m", "frida_tools.repl"]
    if usb:
        cmd += ["-U"]
    elif host:
        cmd += ["-H", parse_host(host)]
    else:
        raise SystemExit("pass -H or --usb")
    if pid is not None:
        cmd += ["-p", str(pid)]
    else:
        cmd += ["-n", name]
    cmd += ["-l", str(SCRIPT_PATH.resolve()), "-q", "-t", str(budget)]
    print(f"[*] attach: {' '.join(cmd)}", file=sys.stderr, flush=True)
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        encoding="utf-8",
        errors="replace",
        bufsize=1,
    )


def _handle_line(line: str, out_dir: Path) -> None:
    for marker in (REQ_MARKER, RESP_MARKER):
        if marker not in line:
            continue
        raw = line[line.index(marker) + len(marker) :].strip()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            print(f"[!] bad {marker} json", file=sys.stderr)
            return
        _save_event(out_dir, payload)
        return
    # Pass through short HTTP lines / frida noise
    if HTTP_MARKER in line or line.startswith("[") or line.startswith("[http]"):
        sys.stderr.write(line if line.endswith("\n") else line + "\n")
        sys.stderr.flush()


def capture(
    *,
    host: str | None = None,
    usb: bool = False,
    name: str = "identityservicesd",
    pid: int | None = None,
    timeout: float = 600.0,
    out_dir: Path | None = None,
) -> int:
    if not SCRIPT_PATH.is_file():
        print(f"script missing: {SCRIPT_PATH}", file=sys.stderr)
        return 2

    out_dir = out_dir or default_out_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    print(f"[*] saving to {out_dir}", flush=True)
    print(
        "[*] Toggle iMessage (sign out/in), FaceTime, or trigger a lookup on the phone.\n"
        "    Captures id-register / initializeValidation / query / auth — full bodies.",
        flush=True,
    )

    deadline = time.monotonic() + timeout
    stop = {"flag": False}

    def _sig(_a: int, _b: Any) -> None:
        stop["flag"] = True

    signal.signal(signal.SIGINT, _sig)

    attempt = 0
    while time.monotonic() < deadline and not stop["flag"]:
        attempt += 1
        remaining = max(30, int(deadline - time.monotonic()))
        try:
            proc = _one_attach(
                host=host, usb=usb, name=name, pid=pid, budget=remaining
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[!] attach failed: {exc}", file=sys.stderr)
            return 1

        try:
            assert proc.stdout is not None
            while time.monotonic() < deadline and not stop["flag"]:
                if proc.poll() is not None:
                    rest = proc.stdout.read() or ""
                    for line in rest.splitlines():
                        _handle_line(line, out_dir)
                    print(
                        f"[!] session ended (code={proc.returncode}) — "
                        f"re-attach #{attempt + 1} in 2s…",
                        file=sys.stderr,
                        flush=True,
                    )
                    break
                line = proc.stdout.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                _handle_line(line, out_dir)
            else:
                _kill(proc)
                break
        finally:
            _kill(proc)
        time.sleep(2.0)

    print(f"[*] done. files in {out_dir}", flush=True)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Full IDS HTTP capture via Frida")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-H", "--host", help="frida-server HOST or HOST:PORT")
    g.add_argument("-U", "--usb", action="store_true")
    ap.add_argument("-n", "--name", default="identityservicesd")
    ap.add_argument("-p", "--pid", type=int, default=None)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("-o", "--out", type=Path, default=None)
    args = ap.parse_args()
    return capture(
        host=args.host,
        usb=args.usb,
        name=args.name,
        pid=args.pid,
        timeout=args.timeout,
        out_dir=args.out,
    )


if __name__ == "__main__":
    raise SystemExit(main())
