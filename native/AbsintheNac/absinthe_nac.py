#!/usr/bin/env python3
"""
Native Absinthe / NAC validation-data on macOS via identityservicesd.

Calls NACInit / NACKeyEstablishment / NACSign (Beeper-style), using offsets
for the local identityservicesd build. Emits the same JSON contract as
scripts/nac-pypush/generate_validation_data.py.
"""
from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import plistlib
import ssl
import struct
import sys
import urllib.request
from pathlib import Path

# Match pypush nac.py: IDS TLS often fails with stock Python CA stores on macOS.
_SSL_CTX = ssl._create_unverified_context()

IDS_PATH = (
    "/System/Library/PrivateFrameworks/IDS.framework/"
    "identityservicesd.app/Contents/MacOS/identityservicesd"
)
REF_SYM = b"IDSProtoKeyTransparencyTrustedServiceReadFrom"

# sha256 → (ref_file_va, init_va, key_va, sign_va|None)
# sign_va may be None → discovered at runtime after KeyEst.
OFFSETS: dict[str, tuple[int, int, int, int | None]] = {
    # macOS 27.2 (26B123) arm64e — Mini (Giordano)
    "cb97f17df6dfccad1a07f91b87dfe764d8fabeeaf2e9b760ea8892a391986f04": (
        0x1002AEF94,  # IDSProtoKeyTransparencyTrustedServiceReadFrom
        0x10080CD50,  # NACInit (sanity -44023; xref "Calling NACInit with")
        0x100803720,  # NACKeyEstablishment candidate (also -44023 as init-style)
        None,         # NACSign — discovered
    ),
}

CERT_URL = "http://static.ess.apple.com/identity/validation/cert-1.0.plist"
INIT_URL = (
    "https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation"
)
UA = "com.apple.invitation-registration [macOS,27.2,26B123,Mac]"


class AbsintheError(RuntimeError):
    pass


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _load_nac():
    if sys.platform != "darwin":
        raise AbsintheError("native Absinthe requires macOS")
    digest = _sha256_file(IDS_PATH)
    offs = OFFSETS.get(digest)
    if offs is None:
        raise AbsintheError(
            f"no Absinthe offsets for identityservicesd sha256={digest}. "
            "Add an entry to OFFSETS in absinthe_nac.py."
        )
    ref_va, init_va, key_va, sign_va = offs

    lib = ctypes.CDLL(None)
    dlopen = lib.dlopen
    dlopen.restype = ctypes.c_void_p
    dlopen.argtypes = [ctypes.c_char_p, ctypes.c_int]
    dlsym = lib.dlsym
    dlsym.restype = ctypes.c_void_p
    dlsym.argtypes = [ctypes.c_void_p, ctypes.c_char_p]

    handle = dlopen(IDS_PATH.encode(), 1)  # RTLD_LAZY
    if not handle:
        raise AbsintheError("dlopen identityservicesd failed")
    ref = dlsym(handle, REF_SYM)
    if not ref:
        raise AbsintheError(f"dlsym {REF_SYM!r} failed")
    slide = ref - ref_va

    def fn(va, restype, argtypes):
        f = ctypes.CFUNCTYPE(restype, *argtypes)(va + slide)
        return f

    nac_init = fn(
        init_va,
        ctypes.c_int,
        [ctypes.c_void_p, ctypes.c_int,
         ctypes.POINTER(ctypes.c_void_p),
         ctypes.POINTER(ctypes.c_void_p),
         ctypes.POINTER(ctypes.c_int)],
    )
    nac_key = fn(
        key_va,
        ctypes.c_int,
        [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int],
    )
    nac_sign = None
    if sign_va is not None:
        nac_sign = fn(
            sign_va,
            ctypes.c_int,
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
             ctypes.POINTER(ctypes.c_void_p),
             ctypes.POINTER(ctypes.c_int)],
        )

    # Sanity
    ctx = ctypes.c_void_p()
    req = ctypes.c_void_p()
    req_len = ctypes.c_int(0)
    rc = nac_init(None, 0, ctypes.byref(ctx), ctypes.byref(req), ctypes.byref(req_len))
    if rc != -44023:
        raise AbsintheError(f"NACInit sanity rc={rc} (want -44023) — offsets mismatch")

    return {
        "digest": digest,
        "slide": slide,
        "init_va": init_va,
        "key_va": key_va,
        "sign_va": sign_va,
        "nac_init": nac_init,
        "nac_key": nac_key,
        "nac_sign": nac_sign,
        "make_sign": lambda va: fn(
            va,
            ctypes.c_int,
            [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int,
             ctypes.POINTER(ctypes.c_void_p),
             ctypes.POINTER(ctypes.c_int)],
        ),
    }


def _http_get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:
        return resp.read()


def _http_post_plist(url: str, body: bytes) -> bytes:
    req = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": UA, "Content-Type": "application/x-apple-plist"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30, context=_SSL_CTX) as resp:
        return resp.read()


def _fetch_cert() -> bytes:
    raw = _http_get(CERT_URL)
    pl = plistlib.loads(raw)
    cert = pl.get("cert")
    if not isinstance(cert, (bytes, bytearray)):
        raise AbsintheError("validation cert missing in plist")
    return bytes(cert)


def _initialize_validation(request: bytes) -> bytes:
    body = plistlib.dumps({"session-info-request": request}, fmt=plistlib.FMT_XML)
    raw = _http_post_plist(INIT_URL, body)
    pl = plistlib.loads(raw)
    info = pl.get("session-info")
    if not isinstance(info, (bytes, bytearray)):
        raise AbsintheError(f"initializeValidation missing session-info: {pl!r}")
    return bytes(info)


def _pacibsp_candidates(lo: int, hi: int) -> list[int]:
    """File VAs of PACIBSP prologues in [lo, hi) of the arm64e slice."""
    thin = Path("/tmp/identityservicesd.arm64e")
    if not thin.is_file():
        import subprocess
        subprocess.check_call(
            ["lipo", "-thin", "arm64e", IDS_PATH, "-output", str(thin)]
        )
    data = thin.read_bytes()
    # parse __text
    import struct
    ncmds = struct.unpack_from("<I", data, 16)[0]
    off = 32
    text_vm = text_file = text_size = None
    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == 0x19:
            nsects = struct.unpack_from("<I", data, off + 64)[0]
            so = off + 72
            for _s in range(nsects):
                name = data[so : so + 16].split(b"\0", 1)[0]
                addr, size = struct.unpack_from("<QQ", data, so + 32)
                offset = struct.unpack_from("<I", data, so + 48)[0]
                if name == b"__text":
                    text_vm, text_file, text_size = addr, offset, size
                so += 80
        off += cmdsize
    assert text_vm is not None
    text = data[text_file : text_file + text_size]
    out = []
    for pc in range(lo & ~3, hi, 4):
        o = pc - text_vm
        if 0 <= o < len(text) and struct.unpack_from("<I", text, o)[0] == 0xD503237F:
            out.append(pc)
    return out


def _discover_sign_with_ctx(nac, ctx_value: int, cands: list[int], log) -> tuple[int, bytes] | None:
    """
    After KeyEst in this process, fork() per candidate so crashes stay in the child.
    The child inherits the Absinthe ctx pointer.
    """
    r_fd, w_fd = os.pipe()
    for i, va in enumerate(cands):
        pid = os.fork()
        if pid == 0:
            # child
            os.close(r_fd)
            try:
                fn = nac["make_sign"](va)
                out = ctypes.c_void_p()
                out_len = ctypes.c_int(0)
                rc = fn(ctypes.c_void_p(ctx_value), None, 0, ctypes.byref(out), ctypes.byref(out_len))
                if rc == 0 and out.value and out_len.value > 32:
                    blob = ctypes.string_at(out.value, out_len.value)
                    payload = struct.pack("<QI", va, len(blob)) + blob
                    os.write(w_fd, payload)
                    os._exit(0)
            except Exception:
                pass
            os._exit(1)
        # parent
        _, status = os.waitpid(pid, 0)
        if os.WIFEXITED(status) and os.WEXITSTATUS(status) == 0:
            hdr = os.read(r_fd, 12)
            if len(hdr) == 12:
                found_va, n = struct.unpack("<QI", hdr)
                blob = os.read(r_fd, n)
                if len(blob) == n:
                    os.close(r_fd)
                    os.close(w_fd)
                    log(f"NACSign discovered at {hex(found_va)} ({n} B) after {i+1} tries")
                    return found_va, blob
        if (i + 1) % 100 == 0:
            log(f"NACSign discovery… {i+1}/{len(cands)}")
    os.close(r_fd)
    os.close(w_fd)
    return None


def generate_validation_data(log=lambda m: print(m, file=sys.stderr)) -> tuple[bytes, dict]:
    nac = _load_nac()
    log(f"Absinthe native: sha256={nac['digest'][:16]}… slide=0x{nac['slide']:x}")
    log(f"  offsets init=0x{nac['init_va']:x} key=0x{nac['key_va']:x} sign={nac['sign_va'] and hex(nac['sign_va'])}")

    cert = _fetch_cert()
    log(f"cert {len(cert)} B")

    cert_buf = ctypes.create_string_buffer(cert)
    ctx = ctypes.c_void_p()
    req = ctypes.c_void_p()
    req_len = ctypes.c_int(0)
    rc = nac["nac_init"](
        ctypes.cast(cert_buf, ctypes.c_void_p), len(cert),
        ctypes.byref(ctx), ctypes.byref(req), ctypes.byref(req_len),
    )
    if rc != 0 or not ctx.value or not req.value or req_len.value <= 0:
        raise AbsintheError(f"NACInit failed rc={rc}")
    request = ctypes.string_at(req.value, req_len.value)
    log(f"NACInit OK request {len(request)} B")

    session = _initialize_validation(request)
    log(f"initializeValidation OK session {len(session)} B")

    sess_buf = ctypes.create_string_buffer(session)
    rc = nac["nac_key"](ctx, ctypes.cast(sess_buf, ctypes.c_void_p), len(session))
    if rc != 0:
        raise AbsintheError(f"NACKeyEstablishment failed rc={rc}")
    log("NACKeyEstablishment OK")

    out_ptr = ctypes.c_void_p()
    out_len = ctypes.c_int(0)

    def try_sign(fn, label: str) -> bytes | None:
        op = ctypes.c_void_p()
        ol = ctypes.c_int(0)
        r = fn(ctx, None, 0, ctypes.byref(op), ctypes.byref(ol))
        if r == 0 and op.value and ol.value > 32:
            log(f"NACSign OK via {label} → {ol.value} B")
            return ctypes.string_at(op.value, ol.value)
        return None

    data = None
    used_sign = nac["sign_va"]
    if nac["nac_sign"] is not None:
        data = try_sign(nac["nac_sign"], hex(nac["sign_va"]))
    if data is None and os.environ.get("IKE_ABSINTHE_DISCOVER_SIGN", "").strip() in ("1", "true"):
        lo = nac["key_va"] - 0x50000
        hi = nac["init_va"]
        cands = sorted(
            c for c in _pacibsp_candidates(lo, hi)
            if c not in (nac["init_va"], nac["key_va"])
        )
        log(f"NACSign discovery: {len(cands)} candidates (fork-after-KeyEst)")
        found = _discover_sign_with_ctx(nac, int(ctx.value), cands, log)
        if found is not None:
            used_sign, data = found
    if data is None:
        raise AbsintheError(
            "NACSign offset unknown for this identityservicesd build "
            f"(init={hex(nac['init_va'])} key={hex(nac['key_va'])}). "
            "Set OFFSETS[sha256].sign or IKE_ABSINTHE_DISCOVER_SIGN=1. "
            "Relay will fall back to pypush Unicorn."
        )

    meta = {
        "source": "absinthe-native",
        "digest": nac["digest"],
        "offsets": {
            "init": hex(nac["init_va"]),
            "key": hex(nac["key_va"]),
            "sign": hex(used_sign) if used_sign else None,
        },
    }
    return data, meta


def main() -> int:
    ap = argparse.ArgumentParser(description="Native Absinthe NAC validation-data")
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args()
    try:
        data, meta = generate_validation_data()
    except Exception as ex:
        if args.json:
            print(json.dumps({"ok": False, "error": str(ex), "source": "absinthe-native"}))
        else:
            print(f"ABSINTHE_ERROR: {ex}", file=sys.stderr)
        return 1

    import base64
    b64 = base64.b64encode(data).decode("ascii")
    if args.json:
        print(json.dumps({
            "ok": True,
            "validation_data_b64": b64,
            "length": len(data),
            "serial": None,
            "source": meta["source"],
            "offsets": meta["offsets"],
        }))
    else:
        print(b64)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
