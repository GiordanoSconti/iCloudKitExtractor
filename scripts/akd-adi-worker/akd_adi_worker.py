#!/usr/bin/env python3
"""
Worker ADI per akd emulato — solo crypto (spim/cpim/OTP).

MidService HTTP (lookup, start/finish) resta in C# con header akd reali.
Legge identità condivisa da %AppData%\\iCloudKitExtractor\\device-ios.json.

NOTA: Anisette.py usa lib Android (ADISetAndroidID). Per identità iPhone reale
serve sostituire le lib con CoreADI iOS (Mach-O da IPSW) — vedi docs/EMULATED_AKD.md.
"""

from __future__ import annotations

import argparse
import base64
import json
import logging
import os
import secrets
import shutil
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

_SCRIPT_DIR = Path(__file__).resolve().parent
if str(_SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPT_DIR))

from anisette import Anisette
from anisette._adi import ADI, ClientProvisioningIntermediateMetadata
from anisette._device import AnisetteDeviceConfig

import ios_macho_backend as ios_macho
from ios_macho_backend import (
    IosAdiBackend,
    app_data_ios_libs_dir,
    ios_libs_available,
)


def _ios_runtime_ready() -> bool:
    # Non usare "from ... import IOS_ADI_RUNTIME_READY": il bool resta stale dopo initialize().
    return bool(ios_macho.IOS_ADI_RUNTIME_READY)

IPHONE_AKD_CLIENT_INFO = (
    "<iPhone9,3> <iPhone OS;12.4.1;16G102> <com.apple.AuthKit/1 (com.apple.akd/1.0)>"
)
# EPB RealMobile (capture 2026-10-12): MD = u32be(5)|u32be(16)|16B|u32be(3)
EPB_OTP_TRAILER = 3
ANDROID_NATIVE_OTP_TRAILER = 4
DSID_DEFAULT = -2
# MD-RINFO iOS/EPB (GrandSlamCpdBuilder.IosMdRinfo)
IOS_MD_RINFO = "17106176"
# Anisette.py Android spesso espone 4294967295
ANDROID_MD_RINFO = "4294967295"


def _env_truthy(name: str) -> bool:
    raw = (os.environ.get(name) or "").strip().lower()
    return raw in ("1", "true", "yes", "on")


def _android_native_mid() -> bool:
    """Path A: MidService nella lib Android (AKD_OWNS_MIDSERVICE / AKD_ANDROID_NATIVE)."""
    return _env_truthy("AKD_OWNS_MIDSERVICE") or _env_truthy("AKD_ANDROID_NATIVE")


def headers_rinfo_native() -> str:
    return (os.environ.get("AKD_MD_RINFO") or "").strip() or ANDROID_MD_RINFO

_lock = threading.Lock()
_sessions: dict[str, tuple[Anisette, ADI]] = {}
_pending_cpim: dict[str, ClientProvisioningIntermediateMetadata] = {}
_backend_mode = "android"
_ios_backend: IosAdiBackend | None = None


def resolve_otp_trailer() -> int | None:
    """Trailer OTP u32be: default EPB=3. `native`/`off`/`-` → nessun rewrite."""
    raw = (os.environ.get("AKD_FORCE_OTP_TRAILER") or "").strip().lower()
    if raw in ("native", "off", "-", "no", "false"):
        return None
    if not raw:
        return EPB_OTP_TRAILER
    try:
        trailer = int(raw, 0)
    except ValueError:
        logging.warning("AKD_FORCE_OTP_TRAILER non valido %r — uso EPB=%s", raw, EPB_OTP_TRAILER)
        return EPB_OTP_TRAILER
    if trailer < 0 or trailer > 0xFFFFFFFF:
        return EPB_OTP_TRAILER
    return trailer


def force_otp_trailer(otp: bytes) -> bytes:
    """Allinea l'u32be finale dell'OTP a EPB (default 3; Android nativo=4).

    Controllato da AKD_FORCE_OTP_TRAILER. Non tocca MD-M.
    """
    trailer = resolve_otp_trailer()
    if trailer is None or len(otp) < 8:
        return otp
    patched = bytearray(otp)
    patched[-4:] = int(trailer).to_bytes(4, "big")
    if bytes(patched) != otp:
        logging.info(
            "OTP trailer forzato %s → %s (EPB align)",
            int.from_bytes(otp[-4:], "big"),
            trailer,
        )
    return bytes(patched)


def app_data_root() -> Path:
    if sys.platform == "win32":
        return Path.home() / "AppData" / "Roaming" / "iCloudKitExtractor"
    return Path.home() / ".config" / "iCloudKitExtractor"


def worker_data_dir() -> Path:
    return app_data_root() / "akd-adi-worker"


def device_json_path() -> Path:
    # Allineato a AdiDeviceProfile.ResolveIdentityMode() (C# default = iphone-coherent).
    #   iphone-coherent → device-iphone-coherent.json
    #   provision       → device-provision.json
    #   akd / ios       → device-ios.json
    mode = (os.environ.get("AKD_IDENTITY_MODE") or "iphone-coherent").strip().lower()
    name = {
        "provision": "device-provision.json",
        "mac": "device-provision.json",
        "xcode": "device-provision.json",
        "akd": "device-ios.json",
        "ios": "device-ios.json",
        "ios-akd": "device-ios.json",
        "iphone-coherent": "device-iphone-coherent.json",
    }.get(mode, "device-iphone-coherent.json")
    return app_data_root() / name


def load_csharp_device() -> dict[str, Any]:
    path = device_json_path()
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {}


def make_device_config(
    meta: dict[str, Any],
    payload: dict[str, Any] | None = None,
    adi_id: str = "",
) -> AnisetteDeviceConfig:
    """Identità ADI = payload bridge (C#) > device-*.json > random.

    Se il worker leggeva device-ios.json vuoto mentre MidService usava
    device-iphone-coherent.json, cpim e header divergevano → HTTP 433.
    """
    p = payload or {}

    def pick(*keys: str, default: str = "") -> str:
        for key in keys:
            raw = p.get(key)
            if raw is not None and str(raw).strip():
                return str(raw).strip()
        for key in keys:
            # PascalCase da device-*.json
            alt = {
                "device_uuid": "DeviceUuid",
                "local_user_uuid": "LocalUserUuid",
                "client_info": "ProvisioningClientInfo",
                "adi_id": "AdiIdentifier",
            }.get(key, key)
            raw = meta.get(alt) if alt != key else meta.get(key)
            if raw is None and alt != key:
                raw = meta.get(key)
            if raw is not None and str(raw).strip():
                return str(raw).strip()
        return default

    resolved_adi = (adi_id or pick("adi_id", "adiId", "AdiIdentifier") or secrets.token_hex(8)).lower()
    # Fallback AuthKit/akd (anche path A: MidService in-lib con stesso CI = stack che
    # storicamente provisionava; il 433 nasce dal MidService C# + SRL-NO, non dal CI).
    fallback_ci = (
        (os.environ.get("AKD_FALLBACK_CLIENT_INFO") or "").strip() or IPHONE_AKD_CLIENT_INFO
    )
    return AnisetteDeviceConfig(
        server_friendly_description=pick(
            "client_info", "ProvisioningClientInfo", default=fallback_ci
        ),
        unique_device_id=pick("device_uuid", "DeviceUuid", default=secrets.token_hex(16).upper()),
        adi_id=resolved_adi,
        local_user_uuid=pick("local_user_uuid", "LocalUserUuid", default=secrets.token_hex(32)),
    )


def session_key(adi_id: str) -> str:
    return adi_id.lower()


def _wipe_ani_files(libs_path: Path, prov_path: Path) -> None:
    for path in (libs_path, prov_path):
        if not path.exists():
            continue
        try:
            path.unlink()
        except OSError:
            stale = path.with_name(path.name + ".stale")
            if stale.exists():
                stale.unlink()
            path.replace(stale)


def _init_fresh_ani(device_cfg: AnisetteDeviceConfig, libs_path: Path) -> Anisette:
    ani = Anisette.init(default_device_config=device_cfg)
    ani.save_libs(libs_path)
    return ani


def _open_ani(
    libs_path: Path,
    prov_path: Path,
    device_cfg: AnisetteDeviceConfig,
) -> Anisette:
    regen_libs = libs_path.with_name("libs.regen.bin")
    regen_prov = prov_path.with_name("session.regen.prov")

    def open_from_paths(lp: Path, pp: Path) -> Anisette:
        if pp.exists() and lp.exists():
            return Anisette.load(lp, pp)
        if lp.exists():
            return Anisette.init(lp, default_device_config=device_cfg)
        return _init_fresh_ani(device_cfg, lp)

    for lp, pp in ((regen_libs, regen_prov), (libs_path, prov_path)):
        if not lp.exists() and not pp.exists() and lp is not libs_path:
            continue
        try:
            ani = open_from_paths(lp, pp)
            _ = ani._ani_provider.adi  # noqa: SLF001
            return ani
        except RuntimeError as ex:
            if "missing library file" not in str(ex):
                raise
            logging.warning("archivio ADI corrotto (%s)", lp)

    logging.warning("rigenero lib ADI in %s", regen_libs)
    _wipe_ani_files(regen_libs, regen_prov)
    ani = _init_fresh_ani(device_cfg, regen_libs)
    _ = ani._ani_provider.adi  # noqa: SLF001
    return ani


def handle_bridge(payload: dict[str, Any]) -> dict[str, Any]:
    blocked = _ios_bridge_blocked()
    if blocked:
        return blocked

    command = str(payload.get("command") or payload.get("Command") or "").strip()
    adi_id = resolve_adi_id(payload)
    if not command:
        return {
            "ok": False,
            "error": f"comando mancante nel payload (chiavi: {sorted(payload.keys())})",
        }
    if not adi_id:
        return {"ok": False, "error": "adi_id mancante (payload o device-ios.json)"}

    dsid = int(payload.get("dsid", DSID_DEFAULT))

    # Unicorn/ADI non è thread-safe: serializza TUTTA la crypto (non solo get_or_create).
    # Dopo PrivilegedBatch 401 molti refresh paralleli → race → crash/hang worker.
    with _lock:
        return _handle_bridge_locked(command, adi_id, dsid, payload)


def _handle_bridge_locked(
    command: str, adi_id: str, dsid: int, payload: dict[str, Any]
) -> dict[str, Any]:
    # #region agent log
    t0 = __import__("time").time()
    # #endregion

    try:
        if _backend_mode == "ios" and _ios_backend is not None and _ios_runtime_ready():
            result = _handle_bridge_ios(command, adi_id, dsid, payload)
        else:
            result = _handle_bridge_android(command, adi_id, dsid, payload)
    except Exception as ex:  # noqa: BLE001
        logging.exception("bridge cmd=%s adi=%s", command, adi_id[:12])
        err = str(ex).strip() or f"{type(ex).__name__} (ADI crypto fallito su {command})"
        # #region agent log
        _agent_log(
            "H-ADI-CRYPTO",
            "akd_adi_worker.handle_bridge",
            "bridge_exception",
            {
                "command": command,
                "error": err[:300],
                "ms": int((__import__("time").time() - t0) * 1000),
            },
        )
        # #endregion
        return {"ok": False, "error": err}

    if not result.get("ok"):
        return result

    # #region agent log
    _agent_log(
        "H-ADI-CRYPTO",
        "akd_adi_worker.handle_bridge",
        "bridge_ok",
        {
            "command": command,
            "backend": _backend_mode,
            "ms": int((__import__("time").time() - t0) * 1000),
        },
    )
    # #endregion
    return result


_pending_ios_sessions: dict[str, int] = {}


def _handle_bridge_ios(
    command: str, adi_id: str, dsid: int, payload: dict[str, Any]
) -> dict[str, Any]:
    assert _ios_backend is not None
    adi_dir = worker_data_dir() / session_key(adi_id)
    adi_dir.mkdir(parents=True, exist_ok=True)
    try:
        _ios_backend.set_provisioning_path(str(adi_dir))
    except Exception:  # noqa: BLE001
        pass

    if command == "is-provisioned":
        return {"ok": True, "provisioned": _ios_backend.is_machine_provisioned(dsid)}
    if command == "get-routing":
        fn = _ios_backend._symbols.get("get_routing")  # noqa: SLF001
        if fn is None:
            return {"ok": True, "routing": 0}
        out = _ios_backend._loader.temp_alloc(8)  # noqa: SLF001
        ret = _ios_backend._loader.invoke_cdecl(  # noqa: SLF001
            fn, [dsid & 0xFFFFFFFFFFFFFFFF, out]
        )
        routing = int.from_bytes(_ios_backend._loader.uc.mem_read(out, 8), "little")  # noqa: SLF001
        _ios_backend._loader.temp_free(out)  # noqa: SLF001
        sret = ret if ret < 0x80000000 else ret - 0x100000000
        return {"ok": sret == 0, "routing": routing, "ret": sret}
    if command == "start-provisioning":
        spim = base64.b64decode(payload.get("spim") or "")
        cpim, session = _ios_backend.start_provisioning(dsid, spim)
        _pending_ios_sessions[session_key(adi_id)] = session
        return {
            "ok": True,
            "session": session,
            "cpim": base64.b64encode(cpim).decode(),
        }
    if command == "end-provisioning":
        session = int(payload.get("session") or _pending_ios_sessions.get(session_key(adi_id), 0))
        ptm = base64.b64decode(payload.get("ptm", ""))
        tk = base64.b64decode(payload.get("tk", ""))
        _ios_backend.end_provisioning(session, ptm, tk)
        _pending_ios_sessions.pop(session_key(adi_id), None)
        return {"ok": True}
    if command == "destroy-session":
        _pending_ios_sessions.pop(session_key(adi_id), None)
        return {"ok": True}
    if command == "set-routing":
        return {"ok": True}
    if command == "request-otp":
        otp, mid = _ios_backend.request_otp(dsid)
        otp = force_otp_trailer(otp)
        return {
            "ok": True,
            "X-Apple-I-MD": base64.b64encode(otp).decode(),
            "X-Apple-I-MD-M": base64.b64encode(mid).decode(),
            "X-Apple-I-MD-RINFO": IOS_MD_RINFO,
        }
    if command == "reset-adi":
        key = session_key(adi_id)
        _pending_ios_sessions.pop(key, None)
        if adi_dir.exists():
            shutil.rmtree(adi_dir, ignore_errors=True)
        return {"ok": True, "reset": True, "adi_id": key}
    if command in ("anisette-provision", "get-headers"):
        return {
            "ok": False,
            "error": "backend ios: usa MidService C# + start/end-provisioning/request-otp",
        }
    return {"ok": False, "error": f"comando sconosciuto: {command}"}


def _handle_bridge_android(
    command: str, adi_id: str, dsid: int, payload: dict[str, Any]
) -> dict[str, Any]:
    ani, adi = get_or_create_ani_unlocked(adi_id, payload)

    if command == "is-provisioned":
        return {"ok": True, "provisioned": adi.is_machine_provisioned(dsid)}
    if command == "start-provisioning":
        spim = base64.b64decode(payload.get("spim") or "")
        try:
            cpim = adi.start_provisioning(dsid, spim)
        except AssertionError:
            return {
                "ok": False,
                "error": (
                    "start-provisioning ADI ret≠0 (archivio corrotto o SPIM rifiutato). "
                    "POST /provision sul worker o reset-adi, poi soft MidService C#."
                ),
            }
        _pending_cpim[session_key(adi_id)] = cpim
        return {
            "ok": True,
            "session": cpim.session,
            "cpim": base64.b64encode(cpim.cpim).decode(),
        }
    if command == "end-provisioning":
        session = int(payload.get("session", 0))
        ptm = base64.b64decode(payload.get("ptm", ""))
        tk = base64.b64decode(payload.get("tk", ""))
        try:
            adi.end_provisioning(session, ptm, tk)
        except AssertionError:
            return {
                "ok": False,
                "error": "end-provisioning ADI ret≠0 (ptm/tk rifiutati o sessione invalida)",
            }
        save_ani_unlocked(adi_id)
        _pending_cpim.pop(session_key(adi_id), None)
        return {"ok": True}
    if command == "destroy-session":
        _pending_cpim.pop(session_key(adi_id), None)
        return {"ok": True}
    if command == "set-routing":
        return {"ok": True}
    if command == "request-otp":
        try:
            otp = adi.request_otp(dsid)
        except AssertionError:
            return {
                "ok": False,
                "error": "request-otp fallito (macchina non provisionata o stato ADI invalido)",
            }
        save_ani_unlocked(adi_id)
        md = force_otp_trailer(bytes(otp.otp))
        return {
            "ok": True,
            "X-Apple-I-MD": base64.b64encode(md).decode(),
            "X-Apple-I-MD-M": base64.b64encode(bytes(otp.machine_id)).decode(),
            "X-Apple-I-MD-RINFO": (
                headers_rinfo_native() if _android_native_mid() else IOS_MD_RINFO
            ),
        }
    if command == "reset-adi":
        key = session_key(adi_id)
        _sessions.pop(key, None)
        _pending_cpim.pop(key, None)
        data_dir = worker_data_dir() / key
        if data_dir.exists():
            shutil.rmtree(data_dir, ignore_errors=True)
        return {"ok": True, "reset": True, "adi_id": key}
    if command == "anisette-provision":
        # Path A: MidService nella lib (AKD_OWNS_MIDSERVICE=1 → ProvisionViaLibraryAsync).
        # Path iPhone: C# non chiama questo comando (OwnsMidServiceHttp=false).
        if ani.is_provisioned or adi.is_machine_provisioned(dsid):
            return {"ok": True, "provisioned": True, "already": True}
        logging.info("Anisette.provision() (MidService Android nativo) adi=%s…", adi_id[:8])
        try:
            ani.provision()
        except AssertionError:
            return {
                "ok": False,
                "error": "anisette-provision AssertionError (MidService/ADI ret≠0)",
            }
        except Exception as ex:  # noqa: BLE001
            return {"ok": False, "error": f"anisette-provision: {ex}"}
        save_ani_unlocked(adi_id)
        return {
            "ok": True,
            "provisioned": bool(ani.is_provisioned or adi.is_machine_provisioned(dsid)),
            "already": False,
        }
    if command == "get-headers":
        # Preferisci OTP diretto (no auto MidService). Overlay CI/RINFO solo se non native.
        native = _android_native_mid()
        if not adi.is_machine_provisioned(dsid) and not ani.is_provisioned:
            return {
                "ok": False,
                "error": (
                    "non provisionata: "
                    + (
                        "anisette-provision / POST /provision (OwnsMidService)"
                        if native
                        else "soft MidService C# (POST /provision su :6971)"
                    )
                ),
            }
        try:
            otp = adi.request_otp(dsid)
        except AssertionError:
            return {
                "ok": False,
                "error": "get-headers: request-otp fallito (stato ADI invalido)",
            }
        save_ani_unlocked(adi_id)
        md = force_otp_trailer(bytes(otp.otp))
        headers = {
            "ok": True,
            "X-Apple-I-MD": base64.b64encode(md).decode(),
            "X-Apple-I-MD-M": base64.b64encode(bytes(otp.machine_id)).decode(),
            "X-Apple-I-MD-RINFO": (
                headers_rinfo_native() if native else IOS_MD_RINFO
            ),
        }
        if not native:
            meta = load_csharp_device()
            cfg = make_device_config(meta, payload, adi_id)
            headers["X-MMe-Client-Info"] = cfg.server_friendly_description
        return headers
    return {"ok": False, "error": f"comando sconosciuto: {command}"}


def _agent_log(hypothesis_id: str, location: str, message: str, data: dict[str, Any]) -> None:
    try:
        path = Path(r"c:\Users\Giordano\Desktop\PROGRAMMAZIONE\Projects\iCloudDownloader\debug-7dabb5.log")
        line = json.dumps(
            {
                "sessionId": "7dabb5",
                "runId": "adi-worker",
                "hypothesisId": hypothesis_id,
                "location": location,
                "message": message,
                "timestamp": int(__import__("time").time() * 1000),
                "data": data,
            },
            ensure_ascii=False,
        )
        with path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:  # noqa: BLE001
        pass


def get_or_create_ani_unlocked(
    adi_id: str, payload: dict[str, Any] | None = None
) -> tuple[Anisette, ADI]:
    """Come get_or_create_ani ma caller deve già tenere _lock."""
    key = session_key(adi_id)
    if key in _sessions:
        return _sessions[key]

    data_dir = worker_data_dir() / key
    data_dir.mkdir(parents=True, exist_ok=True)
    libs_path = data_dir / "libs.bin"
    prov_path = data_dir / "session.prov"
    meta = load_csharp_device()
    device_cfg = make_device_config(meta, payload, adi_id)
    logging.info(
        "ADI session adi=%s… uuid=%s… device_json=%s",
        adi_id[:8],
        (device_cfg.unique_device_id or "")[:8],
        device_json_path().name,
    )

    ani = _open_ani(libs_path, prov_path, device_cfg)
    adi = ani._ani_provider.adi  # noqa: SLF001
    _sessions[key] = (ani, adi)
    return ani, adi


def save_ani_unlocked(adi_id: str) -> None:
    key = session_key(adi_id)
    if key not in _sessions:
        return
    ani, _ = _sessions[key]
    data_dir = worker_data_dir() / key
    prov_path = data_dir / "session.prov"
    regen_prov = prov_path.with_name("session.regen.prov")
    target = regen_prov if regen_prov.parent.joinpath("libs.regen.bin").exists() else prov_path
    ani.save_provisioning(target)


def get_or_create_ani(adi_id: str, payload: dict[str, Any] | None = None) -> tuple[Anisette, ADI]:
    with _lock:
        return get_or_create_ani_unlocked(adi_id, payload)


def save_ani(adi_id: str) -> None:
    with _lock:
        save_ani_unlocked(adi_id)


def _ios_bridge_blocked() -> dict[str, Any] | None:
    if _backend_mode != "ios":
        return None
    if _ios_backend is None or not _ios_runtime_ready():
        return {
            "ok": False,
            "error": (
                "backend ios: lib Mach-O estratte ma invocazione ADI non ancora implementata. "
                "Esegui extract-ios-adi-libs.ps1; usa --backend android fino al mapping simboli."
            ),
        }
    return None


def resolve_adi_id(payload: dict[str, Any]) -> str:
    for key in ("adi_id", "adiId", "AdiIdentifier"):
        raw = payload.get(key)
        if raw is not None and str(raw).strip():
            return str(raw).strip().lower()
    meta = load_csharp_device()
    raw = meta.get("AdiIdentifier") or meta.get("adiIdentifier")
    if raw is not None and str(raw).strip():
        return str(raw).strip().lower()
    return ""


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args: Any) -> None:  # noqa: ANN401
        logging.debug(fmt, *args)

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/health", "/"):
            ios_probe = None
            if _ios_backend is not None:
                try:
                    ios_probe = _ios_backend.probe()
                except Exception:  # noqa: BLE001
                    ios_probe = {"error": "probe failed"}
            otp_tr = resolve_otp_trailer()
            body = json.dumps(
                {
                    "ok": True,
                    "backend": _backend_mode,
                    "ios_libs": ios_libs_available(),
                    "ios_runtime_ready": _ios_runtime_ready(),
                    "ios_probe": ios_probe,
                    "device_json": str(device_json_path()),
                    "otp_trailer": otp_tr,
                    "otp_trailer_epb_default": EPB_OTP_TRAILER,
                    "md_rinfo": IOS_MD_RINFO,
                    "note": "MidService C# + crypto ADI; OTP trailer default EPB=3",
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_error(404)

    def do_POST(self) -> None:  # noqa: N802
        if self.path == "/provision":
            shutil.rmtree(worker_data_dir(), ignore_errors=True)
            with _lock:
                _sessions.clear()
                _pending_cpim.clear()
            self._json_response(200, {"ok": True, "reset": True})
            return

        if self.path != "/v1/bridge":
            self.send_error(404)
            return

        raw = self._read_post_json_bytes()
        try:
            payload = json.loads(raw.decode("utf-8") if raw else "{}")
            result = handle_bridge(payload)
            status = 200 if result.get("ok") else 400
            self._json_response(status, result)
        except Exception as ex:  # noqa: BLE001
            logging.exception("bridge")
            self._json_response(500, {"ok": False, "error": str(ex)})

    def _read_post_json_bytes(self) -> bytes:
        length_hdr = self.headers.get("Content-Length")
        if length_hdr is not None:
            length = int(length_hdr)
            return self.rfile.read(length) if length > 0 else b""
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            chunks: list[bytes] = []
            while True:
                line = self.rfile.readline()
                if not line:
                    break
                size = int(line.strip().split(b";", 1)[0], 16)
                if size == 0:
                    self.rfile.readline()
                    break
                chunks.append(self.rfile.read(size))
                self.rfile.readline()
            return b"".join(chunks)
        return b""

    def _json_response(self, status: int, obj: dict[str, Any]) -> None:
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(body)


def resolve_backend(mode: str, libs_dir: Path | None) -> str:
    global _backend_mode, _ios_backend  # noqa: PLW0603

    if mode == "auto":
        mode = "ios" if ios_libs_available(libs_dir) else "android"

    if mode == "ios":
        root = libs_dir or app_data_ios_libs_dir()
        if not ios_libs_available(root):
            raise SystemExit(
                f"backend ios richiede lib in {root} — esegui scripts\\extract-ios-adi-libs.ps1"
            )
        _ios_backend = IosAdiBackend(root)
        _ios_backend.initialize()
        _backend_mode = "ios"
        if not _ios_runtime_ready():
            logging.warning(
                "iOS Mach-O caricato ma smoke ADI non READY - bridge iOS limitato"
            )
        else:
            logging.info("iOS ADI runtime READY (Unicorn + StoreServices)")
        return _backend_mode

    _backend_mode = "android"
    _ios_backend = None
    return _backend_mode


def main() -> int:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    parser = argparse.ArgumentParser(description="akd ADI worker (Anisette.py MidService + crypto)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=6973)
    parser.add_argument(
        "--backend",
        choices=("android", "ios", "auto"),
        default="android",
        help="android=Anisette.py ELF; ios=Mach-O da IPSW (sperimentale)",
    )
    parser.add_argument("--ios-libs-dir", type=Path, default=None)
    args = parser.parse_args()

    backend = resolve_backend(args.backend, args.ios_libs_dir)
    logging.info("Backend ADI: %s", backend)
    logging.info("Data: %s", worker_data_dir())
    logging.info("Device identity: %s", device_json_path())
    otp_tr = resolve_otp_trailer()
    logging.info(
        "OTP trailer align: %s (EPB=%s; set AKD_FORCE_OTP_TRAILER=native per Android grezzo)",
        otp_tr if otp_tr is not None else "native",
        EPB_OTP_TRAILER,
    )
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    logging.info("akd ADI worker — http://%s:%s/", args.host, args.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
