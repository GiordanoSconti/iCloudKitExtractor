#!/usr/bin/env python3
"""Capture IDS validation-data from iPhone via Frida (re-attach + gzip decode).

  python fetch_ids_validation.py -H 192.168.x.x:27042 --timeout 300

Stays attached; if identityservicesd dies, re-attaches until timeout.
Decodes __IDS_GZIP__ bodies offline and extracts validation-data from XML plist.
"""
from __future__ import annotations

import argparse
import base64
import gzip
import json
import os
import plistlib
import re
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).with_name("frida_ids_validation.js")
DEFAULT_PORT = 27042
MARKER = "__IDS_VALIDATION_JSON__"
GZIP_MARKER = "__IDS_GZIP__"
HTTP_MARKER = "__IDS_HTTP__"
HEADERS_MARKER = "__IDS_HEADERS__"


def parse_host(value: str) -> str:
    value = value.strip()
    if ":" not in value:
        return f"{value}:{DEFAULT_PORT}"
    return value


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


def default_out_path() -> Path:
    appdata = os.environ.get("APPDATA") or str(Path.home())
    d = Path(appdata) / "iCloudKitExtractor" / "madrid-persona"
    d.mkdir(parents=True, exist_ok=True)
    return d / "validation-data.b64"


def _maybe_gunzip(raw: bytes) -> bytes:
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    return raw


def extract_validation_from_bytes(raw: bytes) -> bytes | None:
    """Pull validation-data from gzip/xml/bplist register body."""
    raw = _maybe_gunzip(raw)

    # XML plist
    if raw[:5].lstrip().startswith(b"<?xml") or b"<plist" in raw[:200]:
        try:
            text = raw.decode("utf-8", errors="replace")
            m = re.search(
                r"<key>\s*validation-data\s*</key>\s*<data>\s*([^<]+)\s*</data>",
                text,
                re.I | re.S,
            )
            if m:
                return base64.b64decode(re.sub(r"\s+", "", m.group(1)))
        except Exception:
            pass
        try:
            pl = plistlib.loads(raw)
            vd = pl.get("validation-data")
            if isinstance(vd, bytes) and len(vd) > 16:
                return vd
        except Exception:
            pass

    # bplist
    if raw[:6] == b"bplist":
        try:
            pl = plistlib.loads(raw)
            vd = pl.get("validation-data")
            if isinstance(vd, bytes) and len(vd) > 16:
                return vd
        except Exception:
            pass

    return None


def extract_iphone_identity_from_register(raw: bytes) -> dict[str, Any]:
    """Serial / hardware / private-device-data from iPhone id-register body."""
    plain = _maybe_gunzip(raw)
    info: dict[str, Any] = {}
    try:
        pl = plistlib.loads(plain)
    except Exception as exc:
        return {"error": f"plist parse: {exc}"}

    if not isinstance(pl, dict):
        return {"error": "root not dict"}

    for k in ("device-name", "hardware-version", "os-version", "software-version", "language"):
        if k in pl:
            info[k] = pl[k]

    pdd = pl.get("private-device-data")
    if isinstance(pdd, dict):
        info["private-device-data"] = {
            kk: (base64.b64encode(vv).decode("ascii") if isinstance(vv, (bytes, bytearray)) else vv)
            for kk, vv in pdd.items()
        }
        if isinstance(pdd.get("s"), str):
            info["serial"] = pdd["s"]

    vd = pl.get("validation-data")
    if isinstance(vd, (bytes, bytearray)):
        info["validation_data_len"] = len(vd)

    services = pl.get("services") if isinstance(pl.get("services"), list) else []
    service_names: list[str] = []
    uris: list[str] = []
    user_ids: list[str] = []
    for svc in services:
        if not isinstance(svc, dict):
            continue
        name = svc.get("service")
        if isinstance(name, str):
            service_names.append(name)
        for user in svc.get("users") or []:
            if not isinstance(user, dict):
                continue
            uid = user.get("user-id")
            if isinstance(uid, str) and uid not in user_ids:
                user_ids.append(uid)
            for row in user.get("uris") or []:
                if isinstance(row, dict):
                    uri = row.get("uri")
                    if isinstance(uri, str) and uri not in uris:
                        uris.append(uri)

    info["services"] = service_names
    info["uris"] = uris
    info["user_ids"] = user_ids
    info["has_madrid"] = "com.apple.madrid" in service_names
    info["top_keys"] = sorted(str(k) for k in pl.keys())
    return info


def save_iphone_identity(update: dict[str, Any]) -> Path:
    appdata = os.environ.get("APPDATA") or str(Path.home())
    path = Path(appdata) / "iCloudKitExtractor" / "madrid-persona" / "iphone-ids-identity.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    cur: dict[str, Any] = {}
    if path.is_file():
        try:
            cur = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            cur = {}
    cur.update(update)
    cur["updatedUtc"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    path.write_text(json.dumps(cur, indent=2), encoding="utf-8")
    print(f"[*] wrote iPhone IDS identity → {path}", file=sys.stderr)
    return path


def save_blob(blob: bytes, source: str, out: Path | None) -> dict[str, Any]:
    out_path = out or default_out_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    b64 = base64.b64encode(blob).decode("ascii")
    out_path.write_text(b64 + "\n", encoding="utf-8")
    meta = {
        "ok": True,
        "path": str(out_path),
        "length": len(blob),
        "source": source,
        "validation_data_b64": b64[:32] + "…",
    }
    out_path.with_suffix(".json").write_text(
        json.dumps({**meta, "validation_data_b64": b64}, indent=2),
        encoding="utf-8",
    )
    print(json.dumps(meta), file=sys.stderr)
    print(MARKER + json.dumps({"validation_data_b64": b64, "length": len(blob), "source": source}))
    return meta


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
        raise ValueError("host or usb required")
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


def capture(
    *,
    host: str | None = None,
    usb: bool = False,
    name: str = "identityservicesd",
    pid: int | None = None,
    timeout: float = 300.0,
    out: Path | None = None,
) -> dict[str, Any]:
    if not SCRIPT_PATH.is_file():
        return {"ok": False, "error": f"script missing: {SCRIPT_PATH}"}

    deadline = time.monotonic() + timeout
    print(
        f"[*] Listening up to {int(timeout)}s on '{name}' (re-attach if process dies).\n"
        f"    Toggle iMessage while attached. idsGetHandles is normal; "
        f"validation-data comes on register.\n"
        f"    Look for __IDS_GZIP__ / __IDS_VALIDATION_JSON__.",
        file=sys.stderr,
        flush=True,
    )

    attempt = 0
    while time.monotonic() < deadline:
        attempt += 1
        remaining = max(30, int(deadline - time.monotonic()))
        try:
            proc = _one_attach(host=host, usb=usb, name=name, pid=pid, budget=remaining)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "error": str(exc)}

        try:
            assert proc.stdout is not None
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    rest = proc.stdout.read() or ""
                    if rest:
                        sys.stderr.write(rest)
                        # Parse trailing markers
                        for line in rest.splitlines():
                            got = _handle_line(line, out)
                            if got:
                                _kill(proc)
                                return got
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
                sys.stderr.write(line)
                sys.stderr.flush()
                got = _handle_line(line, out)
                if got:
                    _kill(proc)
                    return got
            else:
                _kill(proc)
                break
        finally:
            _kill(proc)

        time.sleep(2.0)

    return {
        "ok": False,
        "error": (
            "No validation-data before timeout. If you only saw idsGetHandles, "
            "iMessage may not have reached id-register (already registered / "
            "activation aborted). Force re-register: sign out of iMessage, wait, sign in."
        ),
    }


def _handle_line(line: str, out: Path | None) -> dict[str, Any] | None:
    if MARKER in line:
        raw = line[line.index(MARKER) + len(MARKER) :].strip()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        b64 = payload.get("validation_data_b64")
        if not b64:
            return None
        # Skip experimental whole-body dumps unless they decode as real blob
        if payload.get("experimental"):
            try:
                blob = base64.b64decode(b64)
                vd = extract_validation_from_bytes(blob)
                if vd:
                    return save_blob(vd, "experimental-unwrap", out)
            except Exception:
                return None
            return None
        try:
            blob = base64.b64decode(b64)
            return save_blob(blob, payload.get("source") or "frida", out)
        except Exception:
            return None

    if HEADERS_MARKER in line:
        raw = line[line.index(HEADERS_MARKER) + len(HEADERS_MARKER) :].strip()
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            return None
        hdrs = payload.get("headers") or {}
        push = None
        for k, v in hdrs.items():
            if str(k).lower() in ("x-push-token", "x-apple-push-token"):
                push = v
                break
        update: dict[str, Any] = {"headers": hdrs, "headers_url": payload.get("url")}
        if push:
            update["push_token_b64"] = push
            try:
                update["push_token_hex"] = base64.b64decode(push).hex().upper()
                print(
                    f"[+] iPhone push token hex={update['push_token_hex'][:16]}… "
                    f"({len(base64.b64decode(push))} B)",
                    file=sys.stderr,
                )
            except Exception:
                pass
        save_iphone_identity(update)
        return None

    if GZIP_MARKER in line:
        raw = line[line.index(GZIP_MARKER) + len(GZIP_MARKER) :].strip()
        try:
            payload = json.loads(raw)
            gz = base64.b64decode(payload["gzip_b64"])
        except Exception as exc:
            print(f"[!] bad gzip marker: {exc}", file=sys.stderr)
            return None
        url = payload.get("url") or ""
        print(f"[*] gunzip offline {len(gz)} B from {url[:80]}", file=sys.stderr)

        if "register" in url.lower():
            ident = extract_iphone_identity_from_register(gz)
            print(f"[*] register identity: {json.dumps(ident)[:400]}", file=sys.stderr)
            save_iphone_identity({"register": ident, "register_url": url})
            # Keep raw gzip for later (push-cert experiments)
            appdata = os.environ.get("APPDATA") or str(Path.home())
            raw_path = (
                Path(appdata)
                / "iCloudKitExtractor"
                / "madrid-persona"
                / "last-iphone-register.gz"
            )
            raw_path.write_bytes(gz)
            if not ident.get("has_madrid"):
                print(
                    "[!] this register has NO com.apple.madrid — "
                    f"services={ident.get('services')} uris={ident.get('uris')}. "
                    "Keeping listening for a Madrid register…",
                    file=sys.stderr,
                    flush=True,
                )
                # Still extract valdata below, but do not accept it as final
                # unless Madrid is present (validation-data from FaceTime/alloy
                # re-register is the wrong blob for Enroll Madrid).
                vd_non = extract_validation_from_bytes(gz)
                if vd_non:
                    print(
                        f"[*] ignoring non-Madrid validation-data ({len(vd_non)} B)",
                        file=sys.stderr,
                        flush=True,
                    )
                return None
            print(
                f"[+] Madrid register uris={ident.get('uris')} "
                f"user_ids={ident.get('user_ids')}",
                file=sys.stderr,
                flush=True,
            )

        vd = extract_validation_from_bytes(gz)
        if vd:
            print(f"[+] validation-data {len(vd)} B from gzip body", file=sys.stderr)
            return save_blob(vd, "gzip:" + url[:80], out)
        try:
            plain = _maybe_gunzip(gz)
            if plain[:6] == b"bplist" or b"<plist" in plain[:80]:
                pl = plistlib.loads(plain)
                keys = list(pl) if isinstance(pl, dict) else type(pl)
                print(f"[*] gunzipped plist keys={keys}", file=sys.stderr)
        except Exception as exc:
            print(f"[*] gunzip parse: {exc}", file=sys.stderr)
        return None

    return None


def list_candidate_processes(*, host: str | None = None, usb: bool = False) -> int:
    cmd = [sys.executable, "-m", "frida_tools.ps"]
    if usb:
        cmd += ["-U"]
    elif host:
        cmd += ["-H", parse_host(host)]
    else:
        print("pass -H or --usb", file=sys.stderr)
        return 2
    cmd += ["-a"]
    try:
        out = subprocess.check_output(cmd, text=True, encoding="utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        print(f"frida-ps failed: {exc}", file=sys.stderr)
        return 1
    keys = ("identityservicesd", "imagent", "IMTransferAgent", "apsd", "akd")
    for line in out.splitlines():
        if any(k.lower() in line.lower() for k in keys):
            print(line)
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Capture iPhone IDS validation-data via Frida")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-H", "--host", help="frida-server HOST or HOST:PORT")
    g.add_argument("-U", "--usb", action="store_true")
    ap.add_argument("-n", "--name", default="identityservicesd")
    ap.add_argument("-p", "--pid", type=int, default=None)
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--timeout", type=float, default=300.0)
    ap.add_argument("-o", "--out", type=Path, default=None)
    args = ap.parse_args()

    if args.list:
        return list_candidate_processes(host=args.host, usb=args.usb)

    r = capture(
        host=args.host,
        usb=args.usb,
        name=args.name,
        pid=args.pid,
        timeout=args.timeout,
        out=args.out,
    )
    if not r.get("ok"):
        print(json.dumps(r), file=sys.stderr)
    return 0 if r.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
