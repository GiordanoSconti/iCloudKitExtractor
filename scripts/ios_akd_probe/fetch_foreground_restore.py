#!/usr/bin/env python3
"""Fetch Foreground Restore MMCS identity via frida_tools.repl.

Looks for:
  - hardware-id (64 hex)  → CloudKit header field 22
  - x-apple-mmcs-plist-sha256 (Base64) → f30 MMCS metadata

Important: ``backupd`` is often NOT running at idle. This tool lists live
processes first, attaches by PID to the best match, and falls back to
cloudd / akd / Preferences.

Examples:
  python fetch_foreground_restore.py -H 192.168.1.158:27042 --list
  python fetch_foreground_restore.py -H 192.168.1.158:27042
  python fetch_foreground_restore.py -H 192.168.1.158 --wait 120
  python fetch_foreground_restore.py -U -p 1234 --wait 90

With --wait, trigger Prepare Restore on the phone while attached
(Settings → iCloud → Manage Account Storage → Backups → Download).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).with_name("frida_foreground_restore.js")
DEFAULT_PORT = 27042
MARKER = "__FG_RESTORE_JSON__"

# Ordered preference for live process matching (substring, case-insensitive).
PROCESS_PREFERENCE = (
    "backupd",
    "BackupAgent",
    "MobileBackup",
    "cloudd",
    "syncdefaultsd",
    "accountsd",
    "akd",
    "Preferences",  # Settings host — sometimes holds restore UI traffic
    "SpringBoard",
)


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


def _frida_conn_args(*, host: str | None, usb: bool) -> list[str]:
    if usb:
        return ["-U"]
    if host:
        return ["-H", parse_host(host)]
    raise ValueError("pass host=... or usb=True")


def list_processes(*, host: str | None = None, usb: bool = False) -> list[dict[str, Any]]:
    """Return [{pid, name}, ...] via ``frida-ps -a`` (applications) + plain list."""
    # -a = applications (UI), default = all processes. We want both.
    rows: list[dict[str, Any]] = []
    seen: set[int] = set()

    for extra in ([], ["-a"]):
        cmd = [sys.executable, "-m", "frida_tools.ps", *_frida_conn_args(host=host, usb=usb), *extra]
        # Fallback binary name if module path differs
        try:
            out = subprocess.check_output(
                cmd,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=25,
                stderr=subprocess.STDOUT,
            )
        except FileNotFoundError:
            cmd = ["frida-ps", *_frida_conn_args(host=host, usb=usb), *extra]
            try:
                out = subprocess.check_output(
                    cmd,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                    timeout=25,
                    stderr=subprocess.STDOUT,
                )
            except Exception as exc:  # noqa: BLE001
                return [{"pid": 0, "name": f"(frida-ps failed: {exc})"}]
        except Exception as exc:  # noqa: BLE001
            # Try frida Python API once
            try:
                return _list_processes_frida_api(host=host, usb=usb)
            except Exception as exc2:  # noqa: BLE001
                return [{"pid": 0, "name": f"(list failed: {exc} / {exc2})"}]

        for line in out.splitlines():
            line = line.strip()
            # Formats: "12345  backupd" or "PID  Name" header
            m = re.match(r"^(\d+)\s+(.+)$", line)
            if not m:
                continue
            pid = int(m.group(1))
            name = m.group(2).strip()
            if name.lower() in {"name", "identifier"}:
                continue
            if pid in seen:
                continue
            seen.add(pid)
            rows.append({"pid": pid, "name": name})

    if not rows:
        try:
            return _list_processes_frida_api(host=host, usb=usb)
        except Exception as exc:  # noqa: BLE001
            return [{"pid": 0, "name": f"(empty list: {exc})"}]
    return rows


def _list_processes_frida_api(*, host: str | None, usb: bool) -> list[dict[str, Any]]:
    import frida  # type: ignore

    if usb:
        mgr = frida.get_usb_device(timeout=5)
    else:
        mgr = frida.get_device_manager().add_remote_device(parse_host(host or ""))
    procs = mgr.enumerate_processes()
    return [{"pid": p.pid, "name": p.name} for p in procs]


def rank_processes(procs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort live processes by PROCESS_PREFERENCE relevance."""
    scored: list[tuple[int, int, dict[str, Any]]] = []
    for p in procs:
        name = str(p.get("name") or "")
        low = name.lower()
        score = 10_000
        for i, pref in enumerate(PROCESS_PREFERENCE):
            if pref.lower() in low:
                score = i
                break
        if score == 10_000:
            continue
        scored.append((score, int(p.get("pid") or 0), p))
    scored.sort(key=lambda t: (t[0], t[1]))
    return [t[2] for t in scored]


def _parse_marker_line(line: str) -> dict[str, Any] | None:
    idx = line.find(MARKER)
    if idx < 0:
        return None
    raw = line[idx + len(MARKER) :].strip()
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return data if isinstance(data, dict) else None


def _is_complete(data: dict[str, Any]) -> bool:
    hw = data.get("hardwareIdHex")
    sha = data.get("plistSha256Base64")
    return isinstance(hw, str) and len(hw) == 64 and isinstance(sha, str) and len(sha) >= 40


def fetch_foreground_restore(
    *,
    host: str | None = None,
    usb: bool = False,
    name: str | None = None,
    pid: int | None = None,
    script: Path | None = None,
    timeout: float = 45.0,
    wait: float = 0.0,
) -> dict[str, Any]:
    """Attach via frida_tools.repl and return recovered FG identity."""
    script_path = (script or SCRIPT_PATH).resolve()
    if not script_path.is_file():
        return {"ok": False, "error": f"script not found: {script_path}"}

    cmd = [sys.executable, "-m", "frida_tools.repl", *_frida_conn_args(host=host, usb=usb)]

    if pid is not None:
        cmd += ["-p", str(pid)]
    elif name:
        cmd += ["-n", name]
    else:
        return {"ok": False, "error": "pass name=... or pid=..."}

    budget = max(15, int(timeout + wait + 5))
    # Attach only — never imply spawn for system daemons
    cmd += ["-l", str(script_path), "-q", "-t", str(budget)]

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

    deadline = time.monotonic() + timeout + max(0.0, wait)
    best: dict[str, Any] | None = None
    log_tail: list[str] = []

    assert proc.stdout is not None
    try:
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                for line in proc.stdout:
                    log_tail.append(line.rstrip())
                    parsed = _parse_marker_line(line)
                    if parsed and not parsed.get("heartbeat"):
                        best = parsed
                        if _is_complete(parsed):
                            return parsed
                break

            line = proc.stdout.readline()
            if not line:
                time.sleep(0.05)
                continue
            log_tail.append(line.rstrip())
            if len(log_tail) > 100:
                log_tail = log_tail[-100:]

            # Detect classic attach failures early
            low = line.lower()
            if "unable to find process" in low or "failed to spawn" in low or "failed to attach" in low:
                _kill(proc)
                return {
                    "ok": False,
                    "error": line.strip(),
                    "hint": (
                        "backupd often is not running until a backup/restore starts. "
                        "Use --list, attach to cloudd/akd, or open iCloud Backups UI "
                        "then re-run with --wait."
                    ),
                    "target": name if pid is None else f"pid:{pid}",
                    "log_tail": log_tail[-20:],
                }

            parsed = _parse_marker_line(line)
            if not parsed:
                continue
            if parsed.get("heartbeat"):
                if best is None:
                    best = parsed
                continue
            best = parsed
            if _is_complete(parsed):
                return parsed
    finally:
        _kill(proc)

    if best is not None:
        if not best.get("ok"):
            best.setdefault("log_tail", log_tail[-20:])
        return best

    return {
        "ok": False,
        "error": "no FG JSON from Frida (process missing or script failed)",
        "target": name if pid is None else f"pid:{pid}",
        "log_tail": log_tail[-30:],
        "hint": (
            "If log says process missing: backupd is on-demand. "
            "Run with --list, pick cloudd/akd, or start a restore and --wait."
        ),
    }


def fetch_auto(
    *,
    host: str | None = None,
    usb: bool = False,
    timeout: float = 35.0,
    wait: float = 0.0,
) -> dict[str, Any]:
    procs = list_processes(host=host, usb=usb)
    ranked = rank_processes(procs)
    print(f"[*] live processes: {len(procs)}; FG candidates: {len(ranked)}", file=sys.stderr)
    for p in ranked[:12]:
        print(f"    candidate pid={p['pid']} name={p['name']}", file=sys.stderr)

    if not ranked:
        # Show a few process names to help debugging
        sample = [f"{p['pid']}:{p['name']}" for p in procs[:25]]
        return {
            "ok": False,
            "error": "no backupd/cloudd/akd-like process currently running",
            "hint": (
                "On the phone open Settings → Apple Account → iCloud → "
                "Manage Account Storage → Backups (this often launches backupd), "
                "then re-run with --wait 120."
            ),
            "sample_processes": sample,
        }

    attempts: list[dict[str, Any]] = []
    for i, p in enumerate(ranked[:6]):
        pid = int(p["pid"])
        name = str(p["name"])
        print(f"[*] attach pid={pid} ({name})…", file=sys.stderr)
        w = wait if i == 0 else min(wait, 15.0) if wait else 0.0
        data = fetch_foreground_restore(
            host=host, usb=usb, pid=pid, timeout=timeout, wait=w
        )
        data["attached"] = {"pid": pid, "name": name}
        attempts.append({"target": f"{name}:{pid}", "result": data})
        if _is_complete(data):
            data["tried"] = [a["target"] for a in attempts]
            return data
        err = data.get("error") or data.get("reason") or "incomplete"
        print(f"    → {err}", file=sys.stderr)

    return {
        "ok": False,
        "error": "no complete FG identity from live candidates",
        "attempts": attempts,
        "hint": (
            "Values usually appear only during Prepare Restore / MMCS. "
            "Keep --wait high and trigger Download backup on device while attached."
        ),
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="Recover Foreground Restore hardware-id + mmcs-plist-sha256 via Frida"
    )
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-H", "--host", help="Wi‑Fi frida-server HOST or HOST:PORT")
    g.add_argument("-U", "--usb", action="store_true", help="USB frida")
    ap.add_argument(
        "--list",
        action="store_true",
        help="only list processes (and FG candidates), then exit",
    )
    ap.add_argument(
        "-n",
        "--name",
        default=None,
        help="attach by process name (may fail if not running)",
    )
    ap.add_argument("-p", "--pid", type=int, default=None, help="attach by PID")
    ap.add_argument(
        "--timeout",
        type=float,
        default=35.0,
        help="seconds to wait for first JSON (default 35)",
    )
    ap.add_argument(
        "--wait",
        type=float,
        default=0.0,
        help="extra seconds to stay attached waiting for restore/MMCS traffic",
    )
    ap.add_argument(
        "-o",
        "--out",
        type=Path,
        default=None,
        help="write JSON result to file",
    )
    args = ap.parse_args()

    if args.list:
        procs = list_processes(host=args.host, usb=args.usb)
        ranked = rank_processes(procs)
        payload = {
            "ok": True,
            "count": len(procs),
            "candidates": ranked,
            "all": procs,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    if args.pid is not None or args.name:
        data = fetch_foreground_restore(
            host=args.host,
            usb=args.usb,
            name=args.name,
            pid=args.pid,
            timeout=args.timeout,
            wait=args.wait,
        )
    else:
        data = fetch_auto(
            host=args.host,
            usb=args.usb,
            timeout=args.timeout,
            wait=args.wait,
        )

    text = json.dumps(data, indent=2, ensure_ascii=False)
    print(text)
    if args.out:
        args.out.write_text(text + "\n", encoding="utf-8")
        print(f"[*] wrote {args.out}", file=sys.stderr)

    return 0 if _is_complete(data) else 1


if __name__ == "__main__":
    raise SystemExit(main())
